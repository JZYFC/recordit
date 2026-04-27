#[cfg(unix)]
use std::io::Read;
use std::io::Write;
use std::io::ErrorKind;
#[cfg(unix)]
use std::os::unix::io::{AsRawFd, FromRawFd};
use std::path::PathBuf;
#[cfg(unix)]
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
#[cfg(any(unix, windows))]
use std::time::Duration;

#[cfg(windows)]
use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
#[cfg(windows)]
use windows_sys::Win32::System::Console::{GetStdHandle, STD_INPUT_HANDLE};

use anyhow::Result;
use tokio::process::ChildStdin;

#[cfg(unix)]
use super::guards::FdFlagGuard;
#[cfg(windows)]
use super::guards::{ConsoleInputHandle, ConsoleModeGuard, WindowsEvent};

#[cfg(unix)]
pub(super) type BlockingStdinThreadHandle = UnixStdinThreadHandle;
#[cfg(windows)]
pub(super) type BlockingStdinThreadHandle = WindowsStdinThreadHandle;

#[cfg(unix)]
pub(super) struct UnixStdinThreadHandle {
    pub(super) shutdown: Arc<AtomicBool>,
    pub(super) handle: std::thread::JoinHandle<Result<()>>,
}

#[cfg(unix)]
impl UnixStdinThreadHandle {
    pub(super) fn signal_shutdown(&self) {
        self.shutdown.store(true, Ordering::SeqCst);
    }

    pub(super) async fn join(self) -> Result<()> {
        self.shutdown.store(true, Ordering::SeqCst);
        join_blocking_thread(self.handle).await
    }
}

#[cfg(windows)]
pub(super) struct WindowsStdinThreadHandle {
    pub(super) shutdown: Arc<WindowsEvent>,
    pub(super) handle: std::thread::JoinHandle<Result<()>>,
}

#[cfg(windows)]
impl WindowsStdinThreadHandle {
    pub(super) fn signal_shutdown(&self) {
        let _ = self.shutdown.set();
    }

    pub(super) async fn join(self) -> Result<()> {
        let _ = self.shutdown.set();
        join_blocking_thread(self.handle).await
    }
}

#[cfg(unix)]
pub(super) fn spawn_reader_thread(
    child_input: Option<ChildStdin>,
    log_path: PathBuf,
) -> Result<Option<UnixStdinThreadHandle>> {
    let Some(child_input) = child_input else {
        return Ok(None);
    };

    let shutdown = Arc::new(AtomicBool::new(false));
    let thread_shutdown = Arc::clone(&shutdown);
    let handle = std::thread::Builder::new()
        .name("recordit-stdin".to_string())
        .spawn(move || run_unix_stdin_forwarder(child_input, log_path, thread_shutdown))
        .context("Failed to spawn stdin reader thread")?;

    Ok(Some(UnixStdinThreadHandle { shutdown, handle }))
}

#[cfg(unix)]
fn run_unix_stdin_forwarder(
    child_input: ChildStdin,
    log_path: PathBuf,
    shutdown: Arc<AtomicBool>,
) -> Result<()> {
    use anyhow::Context as _;

    let mut log_file = std::fs::File::create(&log_path)
        .with_context(|| format!("Failed to create stdin log file {}", log_path.display()))?;

    let mut child_file = convert_child_stdin(child_input)
        .context("Failed to convert child stdin to blocking pipe")?;

    let stdin = std::io::stdin();
    let fd = stdin.as_raw_fd();
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
                log_file
                    .write_all(&buffer[..n])
                    .context("Failed to record stdin chunk")?;
                log_file.flush().context("Failed to flush stdin log")?;

                match write_child_input(&mut child_file, &buffer[..n]) {
                    Ok(WriteState::StillOpen) => {}
                    Ok(WriteState::BrokenPipe) => break,
                    Err(err) => return Err(err).context("Failed to forward stdin to child"),
                }
            }
            Err(err) if err.kind() == ErrorKind::Interrupted => continue,
            Err(err) if err.kind() == ErrorKind::WouldBlock => {
                if shutdown.load(Ordering::SeqCst) {
                    break;
                }
                std::thread::sleep(Duration::from_millis(10));
                continue;
            }
            Err(err) => return Err(err).context("Failed to read from stdin"),
        }
    }

    drop(fd_guard);
    log_file.flush().ok();
    let _ = child_file.flush();
    Ok(())
}

#[cfg(windows)]
pub(super) fn spawn_reader_thread(
    child_input: Option<ChildStdin>,
    log_path: PathBuf,
) -> Result<Option<WindowsStdinThreadHandle>> {
    use anyhow::Context as _;

    let Some(child_input) = child_input else {
        return Ok(None);
    };

    let shutdown_event =
        WindowsEvent::new(true, false).context("Failed to create shutdown event")?;
    let shutdown = Arc::new(shutdown_event);
    let thread_shutdown = Arc::clone(&shutdown);
    let handle = std::thread::Builder::new()
        .name("recordit-stdin".to_string())
        .spawn(move || run_windows_stdin_forwarder(child_input, log_path, thread_shutdown))
        .context("Failed to spawn stdin reader thread")?;

    Ok(Some(WindowsStdinThreadHandle { shutdown, handle }))
}

#[cfg(windows)]
fn run_windows_stdin_forwarder(
    child_input: ChildStdin,
    log_path: PathBuf,
    shutdown: Arc<WindowsEvent>,
) -> Result<()> {
    use anyhow::Context as _;

    let mut log_file = std::fs::File::create(&log_path)
        .with_context(|| format!("Failed to create stdin log file {}", log_path.display()))?;

    let mut child_file = convert_child_stdin(child_input)
        .context("Failed to convert child stdin to blocking handle")?;

    let console_input =
        ConsoleInputHandle::open().context("Failed to open console input handle")?;
    let std_handle = unsafe { GetStdHandle(STD_INPUT_HANDLE) };
    if std_handle == INVALID_HANDLE_VALUE {
        return Err(std::io::Error::last_os_error())
            .context("Failed to acquire standard input handle");
    }
    if std_handle == 0 {
        return Ok(());
    }
    let _mode_guard =
        ConsoleModeGuard::new(std_handle).context("Failed to configure console input mode")?;

    let result = super::guards::console_io_read_loop(console_input.handle(), &shutdown, |chunk| {
        log_file
            .write_all(chunk)
            .context("Failed to record stdin chunk")?;
        log_file.flush().context("Failed to flush stdin log")?;

        match write_child_input(&mut child_file, chunk) {
            Ok(WriteState::StillOpen) => Ok(false),
            Ok(WriteState::BrokenPipe) => Ok(true),
            Err(err) => Err(err).context("Failed to forward stdin to child"),
        }
    });

    log_file.flush().ok();
    let _ = child_file.flush();
    result
}

#[cfg(unix)]
fn convert_child_stdin(child_input: ChildStdin) -> Result<std::fs::File> {
    use anyhow::Context as _;

    let owned_fd = child_input
        .into_owned_fd()
        .context("Failed to obtain owned file descriptor for child stdin")?;
    let file = std::fs::File::from(owned_fd);

    let fd = file.as_raw_fd();
    let flags = super::guards::get_fd_flags(fd)?;
    super::guards::set_fd_flags(fd, flags & !libc::O_NONBLOCK)?;

    Ok(file)
}

#[cfg(windows)]
fn convert_child_stdin(child_input: ChildStdin) -> Result<std::fs::File> {
    use anyhow::Context as _;

    let owned_handle = child_input
        .into_owned_handle()
        .context("Failed to obtain owned handle for child stdin")?;

    Ok(std::fs::File::from(owned_handle))
}

pub(super) enum WriteState {
    StillOpen,
    BrokenPipe,
}

pub(super) fn write_child_input(
    file: &mut std::fs::File,
    mut buf: &[u8],
) -> std::io::Result<WriteState> {
    while !buf.is_empty() {
        match file.write(buf) {
            Ok(0) => {
                return Err(std::io::Error::new(
                    ErrorKind::WriteZero,
                    "Failed to write to child stdin",
                ));
            }
            Ok(written) => {
                buf = &buf[written..];
            }
            Err(err) if err.kind() == ErrorKind::Interrupted => continue,
            Err(err) if err.kind() == ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(1));
                continue;
            }
            Err(err) if err.kind() == ErrorKind::BrokenPipe => return Ok(WriteState::BrokenPipe),
            Err(err) => return Err(err),
        }
    }

    Ok(WriteState::StillOpen)
}

pub(super) async fn join_blocking_thread(handle: std::thread::JoinHandle<Result<()>>) -> Result<()> {
    use anyhow::anyhow;

    match tokio::task::spawn_blocking(move || handle.join()).await {
        Ok(Ok(result)) => result,
        Ok(Err(panic)) => {
            if let Some(message) = panic.downcast_ref::<&str>() {
                Err(anyhow!("stdin reader thread panicked: {}", message))
            } else if let Some(message) = panic.downcast_ref::<String>() {
                Err(anyhow!("stdin reader thread panicked: {}", message))
            } else {
                Err(anyhow!("stdin reader thread panicked"))
            }
        }
        Err(join_err) => Err(anyhow!(
            "stdin reader thread join task failed: {}",
            join_err
        )),
    }
}
