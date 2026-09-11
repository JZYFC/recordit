#[cfg(windows)]
use std::ffi::OsStr;
#[cfg(windows)]
use std::io::Write;
#[cfg(windows)]
use std::os::windows::ffi::OsStrExt;
#[cfg(windows)]
use std::path::{Path, PathBuf};
#[cfg(windows)]
use std::sync::Arc;
#[cfg(windows)]
use std::time::Duration;

#[cfg(windows)]
use windows::Win32::Foundation::{CloseHandle, ERROR_BROKEN_PIPE, HANDLE};
#[cfg(windows)]
use windows::Win32::Storage::FileSystem::{ReadFile, WriteFile};
#[cfg(windows)]
use windows::Win32::System::Console::{
    CONSOLE_SCREEN_BUFFER_INFO, COORD, ClosePseudoConsole, CreatePseudoConsole,
    GetConsoleScreenBufferInfo, GetStdHandle, HPCON, PSEUDOCONSOLE_INHERIT_CURSOR,
    STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
};
#[cfg(windows)]
use windows::Win32::System::Pipes::CreatePipe;
#[cfg(windows)]
use windows::Win32::System::Threading::{
    CreateProcessW, DeleteProcThreadAttributeList, EXTENDED_STARTUPINFO_PRESENT,
    GetExitCodeProcess, INFINITE, InitializeProcThreadAttributeList, LPPROC_THREAD_ATTRIBUTE_LIST,
    PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE, PROCESS_INFORMATION, STARTUPINFOEXW, TerminateProcess,
    UpdateProcThreadAttribute, WaitForSingleObject,
};

#[cfg(windows)]
use anyhow::{Context as _, Result, bail};
#[cfg(windows)]
use tokio::fs as async_fs;
#[cfg(windows)]
use tokio::signal::ctrl_c;
#[cfg(windows)]
use tokio::sync::Notify;
#[cfg(windows)]
use tokio::time::timeout;
#[cfg(windows)]
use tracing::info;

#[cfg(windows)]
use super::guards::{ConsoleInputHandle, ConsoleModeGuard, WindowsEvent};
#[cfg(windows)]
use super::shell::prepare_shell_invocation;
#[cfg(windows)]
use super::toml_writer::write_execution_toml;

#[cfg(windows)]
fn win_err(e: windows::core::Error) -> std::io::Error {
    std::io::Error::from_raw_os_error(e.code().0)
}

#[cfg(windows)]
struct SafePipe {
    handle: HANDLE,
}

#[cfg(windows)]
impl SafePipe {
    fn new(handle: HANDLE) -> Self {
        Self { handle }
    }

    fn handle(&self) -> HANDLE {
        self.handle
    }
}

#[cfg(windows)]
impl Drop for SafePipe {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.handle);
        }
    }
}

#[cfg(windows)]
fn create_pipe() -> Result<(SafePipe, SafePipe)> {
    let mut read_handle = HANDLE::default();
    let mut write_handle = HANDLE::default();
    unsafe { CreatePipe(&mut read_handle, &mut write_handle, None, 0) }
        .map_err(win_err)
        .context("CreatePipe failed")?;
    Ok((SafePipe::new(read_handle), SafePipe::new(write_handle)))
}

#[cfg(windows)]
struct ConPtyHandle {
    handle: HPCON,
}

#[cfg(windows)]
impl ConPtyHandle {
    fn new(cols: i16, rows: i16, input_read: HANDLE, output_write: HANDLE) -> Result<Self> {
        let size = COORD { X: cols, Y: rows };
        let handle = unsafe {
            CreatePseudoConsole(size, input_read, output_write, PSEUDOCONSOLE_INHERIT_CURSOR)
        }
        .map_err(|e| {
            anyhow::anyhow!("CreatePseudoConsole failed with HRESULT 0x{:08X}", e.code().0)
        })?;
        Ok(Self { handle })
    }
}

#[cfg(windows)]
impl Drop for ConPtyHandle {
    fn drop(&mut self) {
        unsafe {
            ClosePseudoConsole(self.handle);
        }
    }
}

#[cfg(windows)]
struct ProcThreadAttributeList {
    buffer: Vec<u8>,
}

#[cfg(windows)]
impl ProcThreadAttributeList {
    fn new(conpty: &ConPtyHandle) -> Result<Self> {
        let mut size: usize = 0;
        unsafe {
            let _ = InitializeProcThreadAttributeList(None, 1, None, &mut size);
        }
        if size == 0 {
            bail!("InitializeProcThreadAttributeList returned zero size");
        }
        let mut buffer = vec![0u8; size];
        let list = LPPROC_THREAD_ATTRIBUTE_LIST(buffer.as_mut_ptr().cast());
        unsafe { InitializeProcThreadAttributeList(Some(list), 1, None, &mut size) }
            .map_err(win_err)
            .context("InitializeProcThreadAttributeList failed")?;
        unsafe {
            UpdateProcThreadAttribute(
                list,
                0,
                PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE as usize,
                Some(std::ptr::from_ref(&conpty.handle).cast()),
                std::mem::size_of::<HPCON>(),
                None,
                None,
            )
        }
        .map_err(win_err)
        .context("UpdateProcThreadAttribute failed")?;
        Ok(Self { buffer })
    }

    fn as_ptr(&self) -> LPPROC_THREAD_ATTRIBUTE_LIST {
        LPPROC_THREAD_ATTRIBUTE_LIST(self.buffer.as_ptr().cast_mut().cast())
    }

    fn as_mut_ptr(&mut self) -> LPPROC_THREAD_ATTRIBUTE_LIST {
        LPPROC_THREAD_ATTRIBUTE_LIST(self.buffer.as_mut_ptr().cast())
    }
}

#[cfg(windows)]
impl Drop for ProcThreadAttributeList {
    fn drop(&mut self) {
        unsafe {
            DeleteProcThreadAttributeList(self.as_mut_ptr());
        }
    }
}

#[cfg(windows)]
struct Win32Process {
    process_handle: HANDLE,
    thread_handle: HANDLE,
}

#[cfg(windows)]
struct SendHandle(usize);
#[cfg(windows)]
impl SendHandle {
    fn new(handle: HANDLE) -> Self {
        Self(handle.0 as usize)
    }
    fn get(&self) -> HANDLE {
        HANDLE(self.0 as *mut _)
    }
}

#[cfg(windows)]
impl Win32Process {
    fn process_handle(&self) -> HANDLE {
        self.process_handle
    }
}

#[cfg(windows)]
impl Drop for Win32Process {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.thread_handle);
            let _ = CloseHandle(self.process_handle);
        }
    }
}

#[cfg(windows)]
fn get_console_size() -> (i16, i16) {
    unsafe {
        let handle = match GetStdHandle(STD_OUTPUT_HANDLE) {
            Ok(h) if !h.is_invalid() => h,
            _ => return (80, 24),
        };
        let mut info: CONSOLE_SCREEN_BUFFER_INFO = std::mem::zeroed();
        if GetConsoleScreenBufferInfo(handle, &mut info).is_err() {
            return (80, 24);
        }
        let cols = info.srWindow.Right - info.srWindow.Left + 1;
        let rows = info.srWindow.Bottom - info.srWindow.Top + 1;
        (cols, rows)
    }
}

#[cfg(windows)]
pub(crate) fn build_command_line(args: &[String]) -> Result<Vec<u16>> {
    let invocation = match prepare_shell_invocation(args) {
        Ok(Some(inv)) => {
            let mut parts = vec![inv.program.to_string_lossy().into_owned()];
            for a in &inv.args {
                parts.push(a.to_string_lossy().into_owned());
            }
            parts
        }
        _ => args.to_vec(),
    };

    // Build a command line string suitable for CreateProcessW
    let cmd_line = invocation
        .iter()
        .map(|arg| {
            if arg.is_empty() || arg.contains(' ') || arg.contains('"') {
                // Quote the argument
                let mut quoted = String::from('"');
                let mut backslashes = 0usize;
                for ch in arg.chars() {
                    match ch {
                        '\\' => backslashes += 1,
                        '"' => {
                            quoted.extend(std::iter::repeat_n('\\', backslashes * 2 + 1));
                            quoted.push('"');
                            backslashes = 0;
                        }
                        _ => {
                            quoted.extend(std::iter::repeat_n('\\', backslashes));
                            quoted.push(ch);
                            backslashes = 0;
                        }
                    }
                }
                quoted.extend(std::iter::repeat_n('\\', backslashes * 2));
                quoted.push('"');
                quoted
            } else {
                arg.clone()
            }
        })
        .collect::<Vec<_>>()
        .join(" ");

    let wide: Vec<u16> = OsStr::new(&cmd_line)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    Ok(wide)
}

#[cfg(windows)]
fn spawn_conpty_process(
    cmd: &[String],
    cwd: &Path,
    attr_list: &ProcThreadAttributeList,
) -> Result<Win32Process> {
    let mut cmd_line = build_command_line(cmd)?;

    let cwd_wide: Vec<u16> = OsStr::new(&cwd.as_os_str())
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    let mut si: STARTUPINFOEXW = unsafe { std::mem::zeroed() };
    si.StartupInfo.cb = std::mem::size_of::<STARTUPINFOEXW>() as u32;
    si.lpAttributeList = attr_list.as_ptr();

    let mut pi: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };

    unsafe {
        CreateProcessW(
            None,
            Some(windows::core::PWSTR(cmd_line.as_mut_ptr())),
            None,
            None,
            false,
            EXTENDED_STARTUPINFO_PRESENT,
            None,
            windows::core::PCWSTR(cwd_wide.as_ptr()),
            &si.StartupInfo,
            &mut pi,
        )
    }
    .map_err(win_err)
    .context("CreateProcessW failed")?;

    Ok(Win32Process {
        process_handle: pi.hProcess,
        thread_handle: pi.hThread,
    })
}

#[cfg(windows)]
fn run_conpty_output_reader(
    pty_output_read: HANDLE,
    stdout_log_path: PathBuf,
    _shutdown: Arc<Notify>,
) -> std::thread::JoinHandle<Result<()>> {
    let pipe = SendHandle::new(pty_output_read);
    std::thread::Builder::new()
        .name("conpty-output".to_string())
        .spawn(move || {
            let pty_output_read = pipe.get();
            let mut log_file = std::fs::File::create(&stdout_log_path).with_context(|| {
                format!(
                    "Failed to create stdout log file {}",
                    stdout_log_path.display()
                )
            })?;

            let stdout_handle = unsafe { GetStdHandle(STD_OUTPUT_HANDLE) }.unwrap_or_default();
            let mut buffer = [0u8; 8192];

            loop {
                let mut bytes_read: u32 = 0;
                let read_result = unsafe {
                    ReadFile(
                        pty_output_read,
                        Some(&mut buffer),
                        Some(&mut bytes_read),
                        None,
                    )
                };

                if let Err(e) = read_result {
                    if e.code().0 == ERROR_BROKEN_PIPE.0 as i32 {
                        break;
                    }
                    return Err(win_err(e)).context("ReadFile on PTY output pipe failed");
                }

                if bytes_read == 0 {
                    break;
                }

                let chunk = &buffer[..bytes_read as usize];

                // Write to real console
                if !stdout_handle.is_invalid() {
                    unsafe {
                        let _ = WriteFile(stdout_handle, Some(chunk), None, None);
                    }
                }

                // Write to log
                log_file
                    .write_all(chunk)
                    .context("Failed to write stdout log")?;
                log_file.flush().context("Failed to flush stdout log")?;
            }

            log_file.flush().ok();
            Ok(())
        })
        .expect("Failed to spawn conpty output reader thread")
}

#[cfg(windows)]
fn run_conpty_input_forwarder(
    pty_input_write: HANDLE,
    stdin_log_path: PathBuf,
    shutdown: Arc<WindowsEvent>,
) -> std::thread::JoinHandle<Result<()>> {
    let pipe = SendHandle::new(pty_input_write);
    std::thread::Builder::new()
        .name("conpty-input".to_string())
        .spawn(move || {
            let pty_input_write = pipe.get();
            let mut log_file = std::fs::File::create(&stdin_log_path).with_context(|| {
                format!(
                    "Failed to create stdin log file {}",
                    stdin_log_path.display()
                )
            })?;

            let console_input =
                ConsoleInputHandle::open().context("Failed to open console input handle")?;
            let std_input = unsafe { GetStdHandle(STD_INPUT_HANDLE) }
                .map_err(win_err)
                .context("Failed to acquire standard input handle")?;
            if std_input.is_invalid() {
                return Ok(());
            }
            let _mode_guard = ConsoleModeGuard::new_for_pty_input(std_input)
                .context("Failed to configure console mode for PTY input")?;

            let result = super::guards::console_io_read_loop(
                console_input.handle(),
                &shutdown,
                |chunk| {
                    log_file
                        .write_all(chunk)
                        .context("Failed to record stdin chunk")?;
                    log_file.flush().context("Failed to flush stdin log")?;

                    // Write to PTY input pipe using WriteFile
                    let mut total_written = 0u32;
                    let bytes_read = chunk.len() as u32;
                    while total_written < bytes_read {
                        let slice = &chunk[total_written as usize..];
                        let write_result = unsafe {
                            WriteFile(pty_input_write, Some(slice), None, None)
                        };
                        if let Err(e) = write_result {
                            if e.code().0 == ERROR_BROKEN_PIPE.0 as i32 {
                                return Ok(true);
                            }
                            return Err(win_err(e)).context("Failed to write to PTY input pipe");
                        }
                        // Without an out-param we can't know partial writes; assume full.
                        total_written = bytes_read;
                    }
                    Ok(false)
                },
            );

            log_file.flush().ok();
            result
        })
        .expect("Failed to spawn conpty input forwarder thread")
}

#[cfg(windows)]
pub(super) async fn execute_command_with_conpty(
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

    // ConPTY merges stdout+stderr, so stderr.log will be empty
    async_fs::write(&stderr_log_path, b"")
        .await
        .with_context(|| {
            format!(
                "Failed to create stderr log file {}",
                stderr_log_path.display()
            )
        })?;

    info!(
        "Executing command {:?} in {} (ConPTY)",
        args.cmd,
        args.cwd.display()
    );

    // Create pipes for ConPTY
    let (pty_input_read, pty_input_write) =
        create_pipe().context("Failed to create PTY input pipe")?;
    let (pty_output_read, pty_output_write) =
        create_pipe().context("Failed to create PTY output pipe")?;

    // Create ConPTY
    let (cols, rows) = get_console_size();
    let conpty = ConPtyHandle::new(
        cols,
        rows,
        pty_input_read.handle(),
        pty_output_write.handle(),
    )
    .context("Failed to create pseudo console")?;

    // Drop the pipe ends that ConPTY now owns internally
    drop(pty_input_read);
    drop(pty_output_write);

    // Create process with ConPTY
    let attr_list =
        ProcThreadAttributeList::new(&conpty).context("Failed to create attribute list")?;
    let process = spawn_conpty_process(&args.cmd, &args.cwd, &attr_list)
        .context("Failed to spawn process")?;

    // Spawn output reader thread
    let output_shutdown = Arc::new(Notify::new());
    let output_thread = run_conpty_output_reader(
        pty_output_read.handle(),
        stdout_log_path.clone(),
        Arc::clone(&output_shutdown),
    );

    // Spawn input forwarder thread
    let input_shutdown_event =
        WindowsEvent::new(true, false).context("Failed to create input shutdown event")?;
    let input_shutdown = Arc::new(input_shutdown_event);
    let input_thread = run_conpty_input_forwarder(
        pty_input_write.handle(),
        stdin_log_path.clone(),
        Arc::clone(&input_shutdown),
    );

    // Wait for process exit via oneshot + blocking wait thread
    let process_handle = process.process_handle();
    let (exit_tx, exit_rx) = tokio::sync::oneshot::channel::<u32>();
    let wait_handle = SendHandle::new(process_handle);
    let wait_thread = std::thread::Builder::new()
        .name("conpty-wait".to_string())
        .spawn(move || {
            let handle = wait_handle.get();
            unsafe {
                WaitForSingleObject(handle, INFINITE);
            }
            let mut exit_code: u32 = 1;
            unsafe {
                let _ = GetExitCodeProcess(handle, &mut exit_code);
            }
            let _ = exit_tx.send(exit_code);
        })
        .context("Failed to spawn process wait thread")?;

    let exit_code = tokio::select! {
        result = exit_rx => {
            result.unwrap_or(1)
        }
        _ = ctrl_c() => {
            info!("Received Ctrl+C, shutting down gracefully...");

            // Terminate the process
            unsafe {
                let _ = TerminateProcess(process.process_handle(), 1);
            }

            // Wait briefly for the process to actually exit
            tokio::task::spawn_blocking({
                let ph = SendHandle::new(process.process_handle());
                move || unsafe {
                    let handle = ph.get();
                    WaitForSingleObject(handle, 3000);
                    let mut code: u32 = 1;
                    let _ = GetExitCodeProcess(handle, &mut code);
                    code
                }
            })
            .await
            .unwrap_or(1)
        }
    };

    // Cleanup: signal shutdown, drop ConPTY, close pipes, join threads
    let _ = input_shutdown.set();
    drop(conpty);
    drop(pty_input_write);
    drop(pty_output_read);
    drop(process);
    drop(attr_list);

    // Join threads with timeout
    let _ = tokio::task::spawn_blocking(move || {
        let _ = wait_thread.join();
    })
    .await;

    let _ = timeout(
        Duration::from_secs(5),
        tokio::task::spawn_blocking(move || {
            let _ = output_thread.join();
        }),
    )
    .await;

    let _ = timeout(
        Duration::from_secs(5),
        tokio::task::spawn_blocking(move || {
            let _ = input_thread.join();
        }),
    )
    .await;

    // Write execution.toml
    let success = exit_code == 0;
    write_execution_toml(session_dir, args, success, Some(exit_code as i32)).await?;

    if !success {
        bail!("Command {:?} exited with code {}", args.cmd, exit_code);
    }

    Ok(())
}
