use std::path::{Path, PathBuf};
use std::process::Stdio;

use anyhow::{Context as _, Result, bail};
use tokio::process::{Child, Command};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use crate::executor;

mod io;

pub(super) use io::{IoLine, RunEvent, StreamKind};
use io::{open_log, spawn_stdin_writer, spawn_stream_reader};

const OUTPUT_DRAIN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);

pub(crate) struct LiveProcess {
    pub(crate) files: Vec<String>,
    pub(crate) env: Vec<(String, String)>,
    pub(crate) events: mpsc::UnboundedReceiver<RunEvent>,
    pub(crate) stdin_tx: mpsc::UnboundedSender<Vec<u8>>,
    child: Option<Child>,
    tasks: Vec<JoinHandle<()>>,
    stdin_task: Option<JoinHandle<()>>,
    exit_status: Option<std::process::ExitStatus>,
}

impl LiveProcess {
    pub(crate) fn try_kill(&mut self) {
        if let Some(child) = self.child.as_mut() {
            let _ = child.start_kill();
        }
    }

    pub(crate) fn poll_exit(&mut self) -> Result<Option<std::process::ExitStatus>> {
        if let Some(child) = self.child.as_mut()
            && let Some(status) = child.try_wait()?
        {
            self.exit_status = Some(status);
            self.child = None;
            if let Some(task) = self.stdin_task.take() {
                task.abort();
            }
        }
        Ok(self.exit_status)
    }

    pub(crate) async fn shutdown(mut self) -> Result<std::process::ExitStatus> {
        if let Some(task) = self.stdin_task.take() {
            task.abort();
            let _ = task.await;
        }
        if let Some(child) = self.child.as_mut() {
            if child.try_wait()?.is_none() {
                child.start_kill()?;
            }
            self.exit_status = Some(child.wait().await?);
        }
        self.child = None;
        // Let readers drain the final output; descendants may keep pipes open.
        let deadline = tokio::time::Instant::now() + OUTPUT_DRAIN_TIMEOUT;
        for task in &mut self.tasks {
            if tokio::time::timeout_at(deadline, &mut *task).await.is_err() {
                task.abort();
                let _ = task.await;
            }
        }
        self.exit_status
            .context("Process exit status is unavailable")
    }
}

impl Drop for LiveProcess {
    fn drop(&mut self) {
        self.try_kill();
        if let Some(task) = &self.stdin_task {
            task.abort();
        }
        for task in &self.tasks {
            task.abort();
        }
    }
}

pub(crate) fn collect_env_pairs() -> Vec<(String, String)> {
    let mut pairs: Vec<(String, String)> = std::env::vars_os()
        .map(|(k, v)| {
            (
                k.to_string_lossy().into_owned(),
                v.to_string_lossy().into_owned(),
            )
        })
        .collect();
    pairs.sort_by(|a, b| a.0.cmp(&b.0));
    pairs
}

pub(crate) fn list_session_files(session_path: &Path) -> Vec<String> {
    let files_dir = session_path.join("files");
    let mut entries = Vec::new();
    collect_relative_files(&files_dir, Path::new(""), &mut entries);
    entries.sort();
    entries
}

fn collect_relative_files(root: &Path, relative: &Path, out: &mut Vec<String>) {
    let Ok(read_dir) = std::fs::read_dir(root) else {
        return;
    };
    for entry in read_dir.flatten() {
        let path = entry.path();
        let name = entry.file_name();
        let rel = relative.join(&name);
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        if file_type.is_dir() {
            collect_relative_files(&path, &rel, out);
        } else {
            out.push(rel.to_string_lossy().replace('\\', "/"));
        }
    }
}

pub(crate) async fn start_live_process(
    args: &crate::RunArgs,
    session_dir: PathBuf,
) -> Result<LiveProcess> {
    if args.cmd.is_empty() {
        bail!("No command provided to execute");
    }
    let input_file = match &args.stdin {
        Some(path) => Some(
            tokio::fs::File::open(path)
                .await
                .with_context(|| format!("Failed to open stdin file {}", path.display()))?,
        ),
        None => None,
    };

    let io_dir = session_dir.join("io");
    tokio::fs::create_dir_all(&io_dir)
        .await
        .with_context(|| format!("Failed to create IO directory {}", io_dir.display()))?;

    let stdout_file = open_log(&io_dir.join("stdout.log"))?;
    let stderr_file = open_log(&io_dir.join("stderr.log"))?;
    let stdin_file = open_log(&io_dir.join("stdin.log"))?;

    let mut command = match executor::prepare_shell_invocation(&args.cmd) {
        Ok(Some(invocation)) => {
            let mut cmd = Command::new(&invocation.program);
            cmd.args(&invocation.args);
            cmd
        }
        Ok(None) | Err(_) => {
            let mut cmd = Command::new(&args.cmd[0]);
            cmd.args(&args.cmd[1..]);
            cmd
        }
    };
    command.current_dir(&args.cwd);
    command.kill_on_drop(true);
    command.stdin(Stdio::piped());
    command.stdout(Stdio::piped());
    command.stderr(Stdio::piped());
    #[cfg(windows)]
    {
        command.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
    }

    let mut child = command
        .spawn()
        .with_context(|| format!("Failed to spawn command {:?}", args.cmd))?;

    let (events_tx, events_rx) = mpsc::unbounded_channel();
    let (stdin_tx, stdin_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let mut tasks = Vec::new();
    let mut stdin_task = None;

    if let Some(stdout) = child.stdout.take() {
        tasks.push(spawn_stream_reader(
            stdout,
            StreamKind::Stdout,
            stdout_file,
            events_tx.clone(),
        ));
    }
    if let Some(stderr) = child.stderr.take() {
        tasks.push(spawn_stream_reader(
            stderr,
            StreamKind::Stderr,
            stderr_file,
            events_tx.clone(),
        ));
    }
    if let Some(stdin) = child.stdin.take() {
        stdin_task = Some(spawn_stdin_writer(
            stdin, input_file, stdin_rx, stdin_file, events_tx,
        ));
    }

    let files = list_session_files(&session_dir);
    let env = collect_env_pairs();

    Ok(LiveProcess {
        files,
        env,
        events: events_rx,
        stdin_tx,
        child: Some(child),
        tasks,
        stdin_task,
        exit_status: None,
    })
}

#[cfg(test)]
mod tests;
