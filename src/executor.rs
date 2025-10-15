use std::io::ErrorKind;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context as _, Result, bail};
use tokio::fs as async_fs;
use tokio::fs::File as TokioFile;
use tokio::io::{self as tokio_io, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::process::Command;
use tokio::sync::Notify;
use tokio::task::JoinHandle;
use toml::Value;
use toml::value::Table as TomlTable;
use tracing::info;

#[allow(dead_code)]
/// Execute a command in a subprocess, record and redirect its stdin, stdout, stderr for replay.
pub async fn execute_command(args: &crate::RunArgs, context: &crate::Context) -> Result<()> {
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

    let mut command = Command::new(&args.cmd[0]);
    command.args(&args.cmd[1..]);
    command.current_dir(&args.cwd);
    command.stdin(std::process::Stdio::piped());
    command.stdout(std::process::Stdio::piped());
    command.stderr(std::process::Stdio::piped());

    let mut child = command
        .spawn()
        .with_context(|| format!("Failed to spawn command {:?}", args.cmd))?;

    let shutdown = Arc::new(Notify::new());

    let stdin_handle = spawn_writer_task(
        child.stdin.take(),
        stdin_log_path.clone(),
        Arc::clone(&shutdown),
    )?;
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

    let status = child
        .wait()
        .await
        .with_context(|| format!("Failed to wait for command {:?}", args.cmd))?;

    shutdown.notify_waiters();

    if let Some(handle) = stdout_handle {
        join_stream_task(handle).await?;
    }

    if let Some(handle) = stderr_handle {
        join_stream_task(handle).await?;
    }

    if let Some(handle) = stdin_handle {
        join_stream_task(handle).await?;
    }

    let execution_info = session_dir.join("execution.toml");

    let mut root = TomlTable::new();
    let command_values = args
        .cmd
        .iter()
        .map(|part| Value::String(part.clone()))
        .collect::<Vec<_>>();
    root.insert("command".to_string(), Value::Array(command_values));
    root.insert(
        "cwd".to_string(),
        Value::String(args.cwd.display().to_string()),
    );

    let mut status_table = TomlTable::new();
    status_table.insert("success".to_string(), Value::Boolean(status.success()));
    if let Some(code) = status.code() {
        status_table.insert("code".to_string(), Value::Integer(code.into()));
    } else {
        status_table.insert(
            "detail".to_string(),
            Value::String("terminated_by_signal".to_string()),
        );
    }
    root.insert("status".to_string(), Value::Table(status_table));

    let env_snapshot = capture_environment();
    root.insert("environment".to_string(), Value::Table(env_snapshot));

    let metadata = Value::Table(root);
    let serialized =
        toml::to_string(&metadata).context("Failed to serialise execution metadata to TOML")?;
    async_fs::write(&execution_info, serialized)
        .await
        .with_context(|| {
            format!(
                "Failed to write execution metadata {}",
                execution_info.display()
            )
        })?;

    if !status.success() {
        bail!("Command {:?} exited with status {}", args.cmd, status);
    }

    Ok(())
}

fn spawn_writer_task<W>(
    child_input: Option<W>,
    log_path: PathBuf,
    shutdown: Arc<Notify>,
) -> Result<Option<JoinHandle<Result<()>>>>
where
    W: AsyncWrite + Unpin + Send + 'static,
{
    let Some(mut child_input) = child_input else {
        return Ok(None);
    };

    let handle = tokio::spawn(async move {
        let mut log_file = TokioFile::create(&log_path)
            .await
            .with_context(|| format!("Failed to create stdin log file {}", log_path.display()))?;

        let mut input = tokio_io::stdin();
        let mut buffer = [0u8; 8192];

        loop {
            tokio::select! {
                _ = shutdown.notified() => {
                    break;
                }
                read_result = input.read(&mut buffer) => {
                    match read_result {
                        Ok(0) => break,
                        Ok(n) => {
                            log_file.write_all(&buffer[..n]).await?;
                            log_file.flush().await?;
                            match child_input.write_all(&buffer[..n]).await {
                                Ok(_) => {
                                    if let Err(err) = child_input.flush().await {
                                        if err.kind() == ErrorKind::BrokenPipe {
                                            break;
                                        }
                                        return Err(err.into());
                                    }
                                }
                                Err(err) if err.kind() == ErrorKind::BrokenPipe => break,
                                Err(err) => return Err(err.into()),
                            }
                        }
                        Err(err) if err.kind() == ErrorKind::Interrupted => continue,
                        Err(err) => return Err(err.into()),
                    }
                }
            }
        }

        log_file.flush().await?;
        Ok(())
    });

    Ok(Some(handle))
}

fn spawn_reader_task<R, F, W>(
    reader: Option<R>,
    log_path: PathBuf,
    console_factory: F,
) -> Result<Option<JoinHandle<Result<()>>>>
where
    R: AsyncRead + Unpin + Send + 'static,
    F: FnOnce() -> W + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    let Some(mut reader) = reader else {
        return Ok(None);
    };

    let handle = tokio::spawn(async move {
        let mut log_file = TokioFile::create(&log_path)
            .await
            .with_context(|| format!("Failed to create log file {}", log_path.display()))?;
        let mut console = console_factory();
        let mut buffer = [0u8; 8192];

        loop {
            match reader.read(&mut buffer).await {
                Ok(0) => break,
                Ok(n) => {
                    console.write_all(&buffer[..n]).await?;
                    console.flush().await?;
                    log_file.write_all(&buffer[..n]).await?;
                    log_file.flush().await?;
                }
                Err(err) if err.kind() == ErrorKind::Interrupted => continue,
                Err(err) => return Err(err.into()),
            }
        }

        console.flush().await?;
        log_file.flush().await?;
        Ok(())
    });

    Ok(Some(handle))
}

async fn join_stream_task(handle: JoinHandle<Result<()>>) -> Result<()> {
    match handle.await {
        Ok(result) => result,
        Err(err) => {
            if err.is_panic() {
                let panic = err.into_panic();
                if let Some(message) = panic.downcast_ref::<&str>() {
                    bail!("Execution stream task panicked: {}", message);
                } else if let Some(message) = panic.downcast_ref::<String>() {
                    bail!("Execution stream task panicked: {}", message);
                } else {
                    bail!("Execution stream task panicked");
                }
            } else {
                bail!("Execution stream task was aborted");
            }
        }
    }
}

fn capture_environment() -> TomlTable {
    let mut env_table = TomlTable::new();
    for (key, value) in std::env::vars_os() {
        let key = key.to_string_lossy().into_owned();
        let value = value.to_string_lossy().into_owned();
        env_table.insert(key, Value::String(value));
    }
    env_table
}
