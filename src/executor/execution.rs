#[cfg(unix)]
use std::sync::atomic::{AtomicBool, Ordering};
use std::path::PathBuf;
use std::sync::Arc;
#[cfg(any(unix, windows))]
use std::time::Duration;

use anyhow::{Context as _, Result, bail};
use tokio::fs as async_fs;
use tokio::fs::File as TokioFile;
use tokio::io::{self as tokio_io, AsyncRead};
use tokio::process::Command;
use tokio::signal::ctrl_c;
use tokio::sync::Notify;
use tokio::task::JoinHandle;
use tokio::time::timeout;
use tracing::{info, warn};

use super::shell::prepare_shell_invocation;
use super::io_async::{spawn_reader_task, spawn_writer_task, join_stream_task};
#[cfg(unix)]
use super::io_blocking::{spawn_reader_thread, stdin_is_tty};
#[cfg(windows)]
use super::io_blocking::spawn_reader_thread;
#[cfg(windows)]
use super::guards::stdin_is_console;
#[cfg(any(unix, windows))]
use super::io_blocking::BlockingStdinThreadHandle;
#[cfg(unix)]
use super::pty_unix::execute_command_with_unix_pty;
#[cfg(windows)]
use super::conpty::execute_command_with_conpty;
use super::toml_writer::write_execution_toml;

pub(crate) enum StdinInput<R> {
    Console,
    Reader(R),
}

enum StdinForwardHandle {
    None,
    Async(JoinHandle<Result<()>>),
    #[cfg(any(unix, windows))]
    Thread(BlockingStdinThreadHandle),
}

impl StdinForwardHandle {
    fn signal_shutdown(&self) {
        match self {
            StdinForwardHandle::None => {}
            StdinForwardHandle::Async(_) => {}
            #[cfg(any(unix, windows))]
            StdinForwardHandle::Thread(handle) => handle.signal_shutdown(),
        }
    }

    async fn finish(self) -> Result<()> {
        match self {
            StdinForwardHandle::None => Ok(()),
            StdinForwardHandle::Async(handle) => join_stream_task(handle).await,
            #[cfg(any(unix, windows))]
            StdinForwardHandle::Thread(handle) => handle.join().await,
        }
    }
}

pub(crate) async fn execute_command(
    args: &crate::RunArgs,
    context: &crate::Context,
    stdin_file: Option<PathBuf>,
) -> Result<()> {
    if let Some(stdin_path) = stdin_file {
        assert!(
            stdin_path.is_file(),
            "Stdin path not exists or is not a file"
        );
        let file = TokioFile::open(&stdin_path)
            .await
            .with_context(|| format!("Failed to open stdin file {}", stdin_path.display()))?;
        execute_command_with_stdin(args, context, StdinInput::Reader(file)).await
    } else {
        #[cfg(unix)]
        {
            if args.use_pty && stdin_is_tty() {
                return execute_command_with_unix_pty(args, context).await;
            }
        }
        #[cfg(windows)]
        {
            if args.use_pty && stdin_is_console()? {
                return execute_command_with_conpty(args, context).await;
            }
        }
        execute_command_with_stdin(args, context, StdinInput::<tokio_io::Stdin>::Console).await
    }
}

pub(crate) async fn execute_command_with_stdin<R>(
    args: &crate::RunArgs,
    context: &crate::Context,
    stdin_input: StdinInput<R>,
) -> Result<()>
where
    R: AsyncRead + Unpin + Send + 'static,
{
    if args.cmd.is_empty() {
        bail!("No command provided to execute");
    }

    let session_dir = context
        .session_dir
        .as_ref()
        .context("Recording session directory is not available")?;

    let io_dir = session_dir.join("io");
    async_fs::create_dir_all(&io_dir)
        .await
        .with_context(|| format!("Failed to create IO directory {}", io_dir.display()))?;

    let stdout_log_path = io_dir.join("stdout.log");
    let stderr_log_path = io_dir.join("stderr.log");
    let stdin_log_path = io_dir.join("stdin.log");

    info!("Executing command {:?} in {}", args.cmd, args.cwd.display());

    let mut command = match prepare_shell_invocation(&args.cmd) {
        Ok(Some(invocation)) => {
            tracing::debug!(
                shell = %invocation.description,
                "Launching command via detected shell"
            );
            let mut cmd = Command::new(&invocation.program);
            cmd.args(&invocation.args);
            cmd
        }
        Ok(None) => {
            tracing::debug!("No suitable shell detected, executing command directly");
            let mut cmd = Command::new(&args.cmd[0]);
            cmd.args(&args.cmd[1..]);
            cmd
        }
        Err(error) => {
            warn!(%error, "Failed to prepare shell invocation, executing command directly");
            let mut cmd = Command::new(&args.cmd[0]);
            cmd.args(&args.cmd[1..]);
            cmd
        }
    };
    command.current_dir(&args.cwd);
    command.stdin(std::process::Stdio::piped());
    command.stdout(std::process::Stdio::piped());
    command.stderr(std::process::Stdio::piped());

    let mut child = command
        .spawn()
        .with_context(|| format!("Failed to spawn command {:?}", args.cmd))?;

    let shutdown = Arc::new(Notify::new());

    let stdin_forwarder = match stdin_input {
        StdinInput::Console => {
            #[cfg(unix)]
            {
                match spawn_reader_thread(child.stdin.take(), stdin_log_path.clone())? {
                    Some(handle) => StdinForwardHandle::Thread(handle),
                    None => StdinForwardHandle::None,
                }
            }
            #[cfg(windows)]
            {
                if stdin_is_console()? {
                    match spawn_reader_thread(child.stdin.take(), stdin_log_path.clone())? {
                        Some(handle) => StdinForwardHandle::Thread(handle),
                        None => StdinForwardHandle::None,
                    }
                } else {
                    match spawn_writer_task(
                        child.stdin.take(),
                        stdin_log_path.clone(),
                        tokio_io::stdin(),
                        Arc::clone(&shutdown),
                    )? {
                        Some(handle) => StdinForwardHandle::Async(handle),
                        None => StdinForwardHandle::None,
                    }
                }
            }
            #[cfg(all(not(unix), not(windows)))]
            {
                match spawn_writer_task(
                    child.stdin.take(),
                    stdin_log_path.clone(),
                    tokio_io::stdin(),
                    Arc::clone(&shutdown),
                )? {
                    Some(handle) => StdinForwardHandle::Async(handle),
                    None => StdinForwardHandle::None,
                }
            }
        }
        StdinInput::Reader(reader) => {
            match spawn_writer_task(
                child.stdin.take(),
                stdin_log_path.clone(),
                reader,
                Arc::clone(&shutdown),
            )? {
                Some(handle) => StdinForwardHandle::Async(handle),
                None => StdinForwardHandle::None,
            }
        }
    };
    let stdout_handle = spawn_reader_task(
        child.stdout.take(),
        stdout_log_path.clone(),
        tokio_io::stdout,
    )?;
    let stderr_handle = spawn_reader_task(
        child.stderr.take(),
        stderr_log_path.clone(),
        tokio_io::stderr,
    )?;

    let status = tokio::select! {
        result = child.wait() => {
            result.with_context(|| format!("Failed to wait for command {:?}", args.cmd))?
        }
        _ = ctrl_c() => {
            info!("Received Ctrl+C, shutting down gracefully...");

            // Notify input forwarders to stop
            shutdown.notify_waiters();
            stdin_forwarder.signal_shutdown();

            #[cfg(unix)]
            {
                if let Some(pid) = child.id() {
                    unsafe {
                        libc::kill(pid as i32, libc::SIGTERM);
                    }
                }
            }
            #[cfg(windows)]
            {
                let _ = child.kill().await;
            }

            match timeout(Duration::from_secs(3), child.wait()).await {
                Ok(result) => result.with_context(|| format!("Failed to wait for command {:?}", args.cmd))?,
                Err(_) => {
                    warn!("Child did not exit gracefully within timeout, terminating...");
                    let _ = child.kill().await;
                    child.wait().await.with_context(|| format!("Failed to wait for command {:?}", args.cmd))?
                }
            }
        }
    };

    shutdown.notify_waiters();
    stdin_forwarder.signal_shutdown();

    if let Some(handle) = stdout_handle
        && let Err(_) = timeout(Duration::from_secs(5), join_stream_task(handle)).await
    {
        warn!("Stdout stream task timed out");
    }

    if let Some(handle) = stderr_handle
        && let Err(_) = timeout(Duration::from_secs(5), join_stream_task(handle)).await
    {
        warn!("Stderr stream task timed out");
    }

    if (timeout(Duration::from_secs(5), stdin_forwarder.finish()).await).is_err() {
        warn!("Stdin forwarder timed out");
    }

    write_execution_toml(session_dir, args, status.success(), status.code()).await?;

    if !status.success() {
        bail!("Command {:?} exited with status {}", args.cmd, status);
    }

    Ok(())
}
