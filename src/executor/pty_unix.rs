#[cfg(unix)]
use std::ffi::CString;
#[cfg(unix)]
use std::ffi::OsString;
#[cfg(unix)]
use std::io::ErrorKind;
#[cfg(unix)]
use std::io::Read;
#[cfg(unix)]
use std::io::Write;
#[cfg(unix)]
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
#[cfg(unix)]
use std::os::unix::ffi::OsStrExt;
#[cfg(unix)]
use std::path::{Path, PathBuf};
#[cfg(unix)]
use std::sync::Arc;
#[cfg(unix)]
use std::sync::atomic::{AtomicBool, Ordering};
#[cfg(unix)]
use std::time::Duration;

#[cfg(unix)]
use anyhow::{Context as _, Result, bail};
#[cfg(unix)]
use tokio::fs as async_fs;
#[cfg(unix)]
use tokio::signal::ctrl_c;
#[cfg(unix)]
use tokio::time::timeout;
#[cfg(unix)]
use tracing::{info, warn};

#[cfg(unix)]
use super::shell::prepare_shell_invocation;
#[cfg(unix)]
use super::io_blocking::{write_child_input, WriteState, join_blocking_thread};
#[cfg(unix)]
use super::guards::{FdFlagGuard, UnixTerminalModeGuard};
#[cfg(unix)]
use super::toml_writer::write_execution_toml;

#[cfg(unix)]
struct UnixPtyExecPlan {
    argv: Vec<CString>,
    argv_ptrs: Vec<*const libc::c_char>,
    description: String,
}

#[cfg(unix)]
struct UnixPtyProcess {
    pid: libc::pid_t,
    master_fd: RawFd,
}

#[cfg(unix)]
fn build_unix_pty_exec_plan(command: &[String]) -> Result<UnixPtyExecPlan> {
    let (argv_os, description) = match prepare_shell_invocation(command) {
        Ok(Some(invocation)) => {
            let mut argv = Vec::with_capacity(invocation.args.len() + 1);
            argv.push(invocation.program);
            argv.extend(invocation.args);
            (argv, invocation.description)
        }
        Ok(None) => (
            command
                .iter()
                .map(OsString::from)
                .collect::<Vec<OsString>>(),
            command.join(" "),
        ),
        Err(error) => {
            warn!(%error, "Failed to prepare shell invocation, executing command directly");
            (
                command
                    .iter()
                    .map(OsString::from)
                    .collect::<Vec<OsString>>(),
                command.join(" "),
            )
        }
    };

    if argv_os.is_empty() {
        bail!("No command provided to execute");
    }

    let mut argv = Vec::with_capacity(argv_os.len());
    for (index, part) in argv_os.iter().enumerate() {
        let bytes = part.as_os_str().as_bytes();
        let arg = CString::new(bytes).with_context(|| {
            format!("Argument {} for PTY command contains a NUL byte", index + 1)
        })?;
        argv.push(arg);
    }

    let mut argv_ptrs = argv.iter().map(|arg| arg.as_ptr()).collect::<Vec<_>>();
    argv_ptrs.push(std::ptr::null());

    Ok(UnixPtyExecPlan {
        argv,
        argv_ptrs,
        description,
    })
}

#[cfg(unix)]
fn current_unix_winsize() -> libc::winsize {
    let mut winsize = libc::winsize {
        ws_row: 24,
        ws_col: 80,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };

    let result = unsafe { libc::ioctl(libc::STDOUT_FILENO, libc::TIOCGWINSZ, &mut winsize) };
    if result == 0 && winsize.ws_col > 0 && winsize.ws_row > 0 {
        winsize
    } else {
        libc::winsize {
            ws_row: 24,
            ws_col: 80,
            ws_xpixel: 0,
            ws_ypixel: 0,
        }
    }
}

#[cfg(unix)]
fn spawn_unix_pty_process(plan: &UnixPtyExecPlan, cwd: &Path) -> Result<UnixPtyProcess> {
    let cwd_arg = CString::new(cwd.as_os_str().as_bytes())
        .with_context(|| format!("Working directory {} contains a NUL byte", cwd.display()))?;
    let mut master_fd: RawFd = -1;
    let mut winsize = current_unix_winsize();

    let pid = unsafe {
        libc::forkpty(
            &mut master_fd,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut winsize,
        )
    };

    if pid < 0 {
        return Err(std::io::Error::last_os_error()).context("forkpty failed");
    }

    if pid == 0 {
        unsafe {
            if libc::chdir(cwd_arg.as_ptr()) != 0 {
                libc::_exit(127);
            }
            libc::execvp(plan.argv[0].as_ptr(), plan.argv_ptrs.as_ptr());
            libc::_exit(127);
        }
    }

    Ok(UnixPtyProcess { pid, master_fd })
}

#[cfg(unix)]
fn run_unix_pty_output_reader(
    pty_reader: std::fs::File,
    stdout_log_path: PathBuf,
) -> std::thread::JoinHandle<Result<()>> {
    std::thread::Builder::new()
        .name("unix-pty-output".to_string())
        .spawn(move || {
            let mut pty_reader = pty_reader;
            let mut log_file = std::fs::File::create(&stdout_log_path).with_context(|| {
                format!(
                    "Failed to create stdout log file {}",
                    stdout_log_path.display()
                )
            })?;
            let stdout = std::io::stdout();
            let mut stdout = stdout.lock();
            let mut buffer = [0u8; 8192];

            loop {
                match pty_reader.read(&mut buffer) {
                    Ok(0) => break,
                    Ok(n) => {
                        let chunk = &buffer[..n];
                        stdout
                            .write_all(chunk)
                            .context("Failed to write PTY output to stdout")?;
                        stdout.flush().context("Failed to flush stdout")?;
                        log_file
                            .write_all(chunk)
                            .context("Failed to write stdout log")?;
                        log_file.flush().context("Failed to flush stdout log")?;
                    }
                    Err(err) if err.kind() == ErrorKind::Interrupted => continue,
                    Err(err) if err.raw_os_error() == Some(libc::EIO) => break,
                    Err(err) => return Err(err).context("Failed to read PTY output"),
                }
            }

            let _ = stdout.flush();
            let _ = log_file.flush();
            Ok(())
        })
        .expect("Failed to spawn unix PTY output reader thread")
}

#[cfg(unix)]
fn run_unix_pty_input_forwarder(
    pty_writer: std::fs::File,
    stdin_log_path: PathBuf,
    shutdown: Arc<AtomicBool>,
) -> std::thread::JoinHandle<Result<()>> {
    std::thread::Builder::new()
        .name("unix-pty-input".to_string())
        .spawn(move || {
            let mut pty_writer = pty_writer;
            let mut log_file = std::fs::File::create(&stdin_log_path).with_context(|| {
                format!(
                    "Failed to create stdin log file {}",
                    stdin_log_path.display()
                )
            })?;

            let stdin = std::io::stdin();
            let fd = stdin.as_raw_fd();
            let mode_guard = UnixTerminalModeGuard::new_for_pty_input(fd)
                .context("Failed to configure terminal mode for PTY input")?;
            let fd_guard =
                FdFlagGuard::new(fd).context("Failed to configure stdin for non-blocking reads")?;
            let mut reader = stdin.lock();
            let mut buffer = [0u8; 8192];

            loop {
                if shutdown.load(Ordering::SeqCst) {
                    break;
                }

                match reader.read(&mut buffer) {
                    Ok(0) => break,
                    Ok(n) => {
                        let chunk = &buffer[..n];
                        log_file
                            .write_all(chunk)
                            .context("Failed to record stdin chunk")?;
                        log_file.flush().context("Failed to flush stdin log")?;

                        match write_child_input(&mut pty_writer, chunk) {
                            Ok(WriteState::StillOpen) => {}
                            Ok(WriteState::BrokenPipe) => break,
                            Err(err) => {
                                return Err(err).context("Failed to forward stdin into PTY");
                            }
                        }
                    }
                    Err(err) if err.kind() == ErrorKind::Interrupted => continue,
                    Err(err) if err.kind() == ErrorKind::WouldBlock => {
                        if shutdown.load(Ordering::SeqCst) {
                            break;
                        }
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    Err(err) => return Err(err).context("Failed to read from stdin"),
                }
            }

            drop(fd_guard);
            drop(mode_guard);
            let _ = log_file.flush();
            let _ = pty_writer.flush();
            Ok(())
        })
        .expect("Failed to spawn unix PTY input forwarder thread")
}

#[cfg(unix)]
fn wait_for_unix_pid(pid: libc::pid_t) -> std::io::Result<i32> {
    loop {
        let mut status = 0;
        let wait_result = unsafe { libc::waitpid(pid, &mut status, 0) };
        if wait_result < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == ErrorKind::Interrupted {
                continue;
            }
            return Err(err);
        }
        return Ok(status);
    }
}

#[cfg(unix)]
fn decode_unix_wait_status(wait_status: i32) -> (bool, Option<i32>, String) {
    if libc::WIFEXITED(wait_status) {
        let code = libc::WEXITSTATUS(wait_status) as i32;
        return (code == 0, Some(code), format!("code {}", code));
    }

    if libc::WIFSIGNALED(wait_status) {
        let signal = libc::WTERMSIG(wait_status);
        return (false, None, format!("signal {}", signal));
    }

    (false, None, format!("status {}", wait_status))
}

#[cfg(unix)]
fn send_signal_if_running(pid: libc::pid_t, signal: libc::c_int) {
    if unsafe { libc::kill(pid, signal) } != 0 {
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() != Some(libc::ESRCH) {
            warn!("Failed to send signal {} to pid {}: {}", signal, pid, err);
        }
    }
}

#[cfg(unix)]
pub(super) async fn execute_command_with_unix_pty(
    args: &crate::RunArgs,
    context: &crate::Context,
) -> Result<()> {
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

    // PTY mode merges stdout and stderr.
    async_fs::write(&stderr_log_path, b"")
        .await
        .with_context(|| {
            format!(
                "Failed to create stderr log file {}",
                stderr_log_path.display()
            )
        })?;

    let exec_plan = build_unix_pty_exec_plan(&args.cmd)?;

    info!(
        "Executing command {:?} in {} (Unix PTY via {})",
        args.cmd,
        args.cwd.display(),
        exec_plan.description
    );

    let process = spawn_unix_pty_process(&exec_plan, &args.cwd)?;
    let child_pid = process.pid;

    let pty_writer = unsafe { std::fs::File::from_raw_fd(process.master_fd) };
    let pty_reader = pty_writer
        .try_clone()
        .context("Failed to clone PTY master handle")?;

    let input_shutdown = Arc::new(AtomicBool::new(false));
    let output_thread = run_unix_pty_output_reader(pty_reader, stdout_log_path.clone());
    let input_thread = run_unix_pty_input_forwarder(
        pty_writer,
        stdin_log_path.clone(),
        Arc::clone(&input_shutdown),
    );

    let wait_task = tokio::task::spawn_blocking(move || wait_for_unix_pid(child_pid));
    tokio::pin!(wait_task);

    let wait_status = tokio::select! {
        result = &mut wait_task => {
            result.context("PTY wait task panicked")?
                .context("waitpid failed for PTY process")?
        }
        _ = ctrl_c() => {
            info!("Received Ctrl+C, shutting down gracefully...");
            send_signal_if_running(child_pid, libc::SIGTERM);

            match timeout(Duration::from_secs(3), &mut wait_task).await {
                Ok(result) => {
                    result.context("PTY wait task panicked")?
                        .context("waitpid failed for PTY process")?
                }
                Err(_) => {
                    warn!("PTY child did not exit gracefully within timeout, terminating...");
                    send_signal_if_running(child_pid, libc::SIGKILL);
                    wait_task
                        .await
                        .context("PTY wait task panicked after SIGKILL")?
                        .context("waitpid failed for PTY process after SIGKILL")?
                }
            }
        }
    };

    input_shutdown.store(true, Ordering::SeqCst);

    if let Err(_) = timeout(Duration::from_secs(5), join_blocking_thread(output_thread)).await {
        warn!("PTY output reader thread timed out");
    }

    if let Err(_) = timeout(Duration::from_secs(5), join_blocking_thread(input_thread)).await {
        warn!("PTY input forwarder thread timed out");
    }

    let (success, exit_code, status_detail) = decode_unix_wait_status(wait_status);
    write_execution_toml(session_dir, args, success, exit_code).await?;

    if !success {
        bail!("Command {:?} exited with {}", args.cmd, status_detail);
    }

    Ok(())
}
