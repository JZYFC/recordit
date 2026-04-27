#[cfg(unix)]
use libc;
#[cfg(unix)]
use std::ffi::CString;
#[cfg(windows)]
use std::ffi::OsStr;
use std::ffi::OsString;
use std::io::ErrorKind;
#[cfg(unix)]
use std::io::Read;
use std::io::Write;
#[cfg(windows)]
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
#[cfg(unix)]
use std::sync::atomic::{AtomicBool, Ordering};
#[cfg(any(unix, windows))]
use std::time::Duration;
#[cfg(windows)]
use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_BROKEN_PIPE, ERROR_IO_PENDING, ERROR_OPERATION_ABORTED, FALSE, HANDLE,
    INVALID_HANDLE_VALUE, WAIT_FAILED, WAIT_OBJECT_0,
};
#[cfg(windows)]
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_FLAG_OVERLAPPED, FILE_GENERIC_READ,
    FILE_GENERIC_WRITE, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_TYPE_CHAR, GetFileType,
    OPEN_EXISTING, ReadFile, WriteFile,
};
#[cfg(windows)]
use windows_sys::Win32::System::Console::{
    CONSOLE_SCREEN_BUFFER_INFO, COORD, ENABLE_ECHO_INPUT, ENABLE_EXTENDED_FLAGS, ENABLE_LINE_INPUT,
    GetConsoleMode, GetConsoleScreenBufferInfo, GetStdHandle, HPCON, STD_INPUT_HANDLE,
    STD_OUTPUT_HANDLE, SetConsoleMode,
};
#[cfg(windows)]
use windows_sys::Win32::System::Console::{
    ClosePseudoConsole, CreatePseudoConsole, PSEUDOCONSOLE_INHERIT_CURSOR,
};
#[cfg(windows)]
use windows_sys::Win32::System::IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED};
#[cfg(windows)]
use windows_sys::Win32::System::Pipes::CreatePipe;
#[cfg(windows)]
use windows_sys::Win32::System::Threading::{
    CreateEventW, CreateProcessW, DeleteProcThreadAttributeList, EXTENDED_STARTUPINFO_PRESENT,
    GetExitCodeProcess, INFINITE, InitializeProcThreadAttributeList, LPPROC_THREAD_ATTRIBUTE_LIST,
    PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE, PROCESS_INFORMATION, STARTUPINFOEXW, SetEvent,
    TerminateProcess, UpdateProcThreadAttribute, WaitForMultipleObjects, WaitForSingleObject,
};

use anyhow::{Context as _, Result, anyhow, bail};
use tokio::fs as async_fs;
use tokio::fs::File as TokioFile;
use tokio::io::{self as tokio_io, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::process::ChildStdin;
use tokio::process::Command;
use tokio::signal::ctrl_c;
use tokio::sync::Notify;
use tokio::task::JoinHandle;
use tokio::time::timeout;
use toml::Value;
use toml::value::Table as TomlTable;
use tracing::{info, warn};

#[cfg(unix)]
use std::os::unix::ffi::OsStrExt;
#[cfg(unix)]
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};

use sysinfo::{Pid, Process, System};

#[allow(dead_code)]
/// Execute a command in a subprocess, record and redirect its stdin, stdout, stderr for replay.
pub async fn execute_command(
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

enum StdinInput<R> {
    Console,
    Reader(R),
}

async fn execute_command_with_stdin<R>(
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

struct ShellInvocation {
    program: OsString,
    args: Vec<OsString>,
    description: String,
}

#[derive(Clone, Debug)]
struct ShellInfo {
    program: PathBuf,
    kind: ShellKind,
}

#[derive(Clone, Copy, Debug)]
enum ShellKind {
    Posix,
    PowerShell,
    Cmd,
}

fn prepare_shell_invocation(command: &[String]) -> Result<Option<ShellInvocation>> {
    let Some(shell) = detect_user_shell()? else {
        return Ok(None);
    };

    let description = shell.program.display().to_string();
    let invocation = match shell.kind {
        ShellKind::Posix => ShellInvocation {
            program: shell.program.clone().into_os_string(),
            args: build_posix_args(command),
            description,
        },
        ShellKind::PowerShell => ShellInvocation {
            program: shell.program.clone().into_os_string(),
            args: build_powershell_args(command),
            description,
        },
        ShellKind::Cmd => ShellInvocation {
            program: shell.program.clone().into_os_string(),
            args: build_cmd_args(command),
            description,
        },
    };

    Ok(Some(invocation))
}

fn detect_user_shell() -> Result<Option<ShellInfo>> {
    if let Some(shell) = shell_from_env("RECORDIT_SHELL")? {
        return Ok(Some(shell));
    }
    if let Some(shell) = shell_from_env("SHELL")? {
        return Ok(Some(shell));
    }
    if let Some(shell) = detect_shell_from_process_tree() {
        return Ok(Some(shell));
    }
    #[cfg(windows)]
    {
        if let Some(shell) = shell_from_env("ComSpec")? {
            return Ok(Some(shell));
        }
        if let Some(shell) = fallback_windows_shell() {
            return Ok(Some(shell));
        }
    }
    #[cfg(not(windows))]
    {
        if let Some(shell) = fallback_unix_shell() {
            return Ok(Some(shell));
        }
    }
    Ok(None)
}

fn shell_from_env(var: &str) -> Result<Option<ShellInfo>> {
    let Some(value) = std::env::var_os(var) else {
        return Ok(None);
    };
    if value.is_empty() {
        return Ok(None);
    }

    let path = PathBuf::from(&value);
    if let Some(kind) = classify_shell_path(&path) {
        return Ok(Some(ShellInfo {
            program: path,
            kind,
        }));
    }

    if let Some(name) = Path::new(value.as_os_str())
        .file_name()
        .and_then(|n| n.to_str())
        && let Some(kind) = classify_shell_name(name)
    {
        return Ok(Some(ShellInfo {
            program: PathBuf::from(name),
            kind,
        }));
    }

    warn!(
        "Environment variable {} points to an unsupported shell: {:?}",
        var, value
    );
    Ok(None)
}

fn detect_shell_from_process_tree() -> Option<ShellInfo> {
    let mut system = System::new_all();
    let mut current_pid = Pid::from(std::process::id() as usize);
    let mut hops = 0usize;

    while let Some(pid) = system
        .process(current_pid)
        .and_then(|process| process.parent())
    {
        let parent_pid = pid;

        if system.process(parent_pid).is_none() {
            system.refresh_process(parent_pid);
        }

        if let Some(parent_process) = system.process(parent_pid)
            && let Some(shell) = shell_info_from_process(parent_process)
        {
            return Some(shell);
        }

        current_pid = parent_pid;
        hops += 1;

        if hops > 32 {
            tracing::debug!("Shell detection aborted after traversing process tree");
            break;
        }
    }

    None
}

fn shell_info_from_process(process: &Process) -> Option<ShellInfo> {
    if let Some(exe) = process.exe()
        && let Some(kind) = classify_shell_path(exe)
    {
        return Some(ShellInfo {
            program: exe.to_path_buf(),
            kind,
        });
    }

    let name = process.name();
    classify_shell_name(name).map(|kind| ShellInfo {
        program: PathBuf::from(name),
        kind,
    })
}

fn classify_shell_path(path: &Path) -> Option<ShellKind> {
    path.file_name()
        .and_then(|name| name.to_str())
        .and_then(classify_shell_name)
}

fn classify_shell_name(name: &str) -> Option<ShellKind> {
    let normalized = name.trim_matches('"').to_ascii_lowercase();
    if normalized.contains("pwsh") || normalized.contains("powershell") {
        return Some(ShellKind::PowerShell);
    }
    if normalized == "cmd" || normalized == "cmd.exe" {
        return Some(ShellKind::Cmd);
    }

    let posix_shells = [
        "sh",
        "sh.exe",
        "bash",
        "bash.exe",
        "zsh",
        "zsh.exe",
        "fish",
        "fish.exe",
        "ksh",
        "ksh.exe",
        "tcsh",
        "tcsh.exe",
        "csh",
        "csh.exe",
        "dash",
        "dash.exe",
        "ash",
        "ash.exe",
        "elvish",
        "elvish.exe",
        "xonsh",
        "xonsh.exe",
        "nu",
        "nu.exe",
    ];

    if posix_shells.contains(&normalized.as_str()) {
        return Some(ShellKind::Posix);
    }

    None
}

fn build_posix_args(command: &[String]) -> Vec<OsString> {
    vec![
        OsString::from("-l"),
        OsString::from("-c"),
        OsString::from(join_posix_arguments(command)),
    ]
}

fn join_posix_arguments(command: &[String]) -> String {
    command
        .iter()
        .map(|arg| quote_posix_argument(arg))
        .collect::<Vec<_>>()
        .join(" ")
}

fn quote_posix_argument(argument: &str) -> String {
    if argument.is_empty() {
        return "''".to_string();
    }

    let mut quoted = String::from("'");
    for ch in argument.chars() {
        if ch == '\'' {
            quoted.push_str("'\\''");
        } else {
            quoted.push(ch);
        }
    }
    quoted.push('\'');
    quoted
}

fn build_powershell_args(command: &[String]) -> Vec<OsString> {
    let invocation = join_powershell_arguments(command);
    let expression = if invocation.is_empty() {
        String::new()
    } else {
        format!("& {}", invocation)
    };
    vec![OsString::from("-Command"), OsString::from(expression)]
}

fn join_powershell_arguments(command: &[String]) -> String {
    command
        .iter()
        .map(|arg| quote_powershell_argument(arg))
        .collect::<Vec<_>>()
        .join(" ")
}

fn quote_powershell_argument(argument: &str) -> String {
    if argument.is_empty() {
        return "''".to_string();
    }

    if !argument.contains(|ch: char| ch.is_whitespace() || "'\"`$".contains(ch)) {
        return argument.to_string();
    }

    let escaped = argument.replace('\'', "''");
    format!("'{escaped}'")
}

fn build_cmd_args(command: &[String]) -> Vec<OsString> {
    let command_string = join_cmd_arguments(command);
    vec![OsString::from("/c"), OsString::from(command_string)]
}

fn join_cmd_arguments(command: &[String]) -> String {
    command
        .iter()
        .map(|arg| quote_cmd_argument(arg))
        .collect::<Vec<_>>()
        .join(" ")
}

fn quote_cmd_argument(argument: &str) -> String {
    let mut processed = String::new();
    for ch in argument.chars() {
        if ch == '%' {
            processed.push('%');
            processed.push('%');
        } else {
            processed.push(ch);
        }
    }

    let needs_quotes = processed.is_empty()
        || processed.chars().any(|ch| {
            ch.is_whitespace() || matches!(ch, '"' | '^' | '&' | '|' | '(' | ')' | '<' | '>')
        });

    if !needs_quotes {
        return processed;
    }

    let mut quoted = String::with_capacity(processed.len() + 2);
    quoted.push('"');

    let mut backslashes = 0;
    for ch in processed.chars() {
        match ch {
            '\\' => {
                backslashes += 1;
            }
            '"' => {
                quoted.extend(std::iter::repeat_n('\\', backslashes * 2 + 1));
                quoted.push('"');
                backslashes = 0;
            }
            _ => {
                if backslashes > 0 {
                    quoted.extend(std::iter::repeat_n('\\', backslashes));
                    backslashes = 0;
                }
                quoted.push(ch);
            }
        }
    }

    if backslashes > 0 {
        quoted.extend(std::iter::repeat_n('\\', backslashes * 2));
    }

    quoted.push('"');
    quoted
}

#[cfg(windows)]
fn fallback_windows_shell() -> Option<ShellInfo> {
    if let Some(pwsh) = find_program_in_path(&["pwsh.exe", "pwsh"]) {
        return Some(ShellInfo {
            program: pwsh,
            kind: ShellKind::PowerShell,
        });
    }
    if let Some(powershell) = find_program_in_path(&["powershell.exe", "powershell"]) {
        return Some(ShellInfo {
            program: powershell,
            kind: ShellKind::PowerShell,
        });
    }
    if let Some(comspec) = std::env::var_os("ComSpec") {
        let path = PathBuf::from(comspec);
        if let Some(kind) = classify_shell_path(&path) {
            return Some(ShellInfo {
                program: path,
                kind,
            });
        }
    }
    None
}

#[cfg(not(windows))]
fn fallback_unix_shell() -> Option<ShellInfo> {
    let path = PathBuf::from("/bin/sh");
    Some(ShellInfo {
        program: path,
        kind: ShellKind::Posix,
    })
}

#[cfg(windows)]
fn find_program_in_path(candidates: &[&str]) -> Option<PathBuf> {
    for candidate in candidates {
        let candidate_path = PathBuf::from(candidate);
        if candidate_path.is_absolute() && candidate_path.exists() {
            return Some(candidate_path);
        }
    }

    let paths = std::env::var_os("PATH")?;
    #[cfg(windows)]
    let pathext_values: Vec<String> = std::env::var_os("PATHEXT")
        .map(|pathext| {
            pathext
                .to_string_lossy()
                .split(';')
                .filter(|entry| !entry.is_empty())
                .map(|entry| entry.trim_start_matches('.').to_ascii_lowercase())
                .collect()
        })
        .unwrap_or_default();

    for dir in std::env::split_paths(&paths) {
        for candidate in candidates {
            let path = dir.join(candidate);
            if path.exists() && is_executable(&path) {
                return Some(path);
            }
            #[cfg(windows)]
            {
                if path.extension().is_none() {
                    for ext in &pathext_values {
                        let mut path_with_ext = path.clone();
                        path_with_ext.set_extension(ext);
                        if path_with_ext.exists() && is_executable(&path_with_ext) {
                            return Some(path_with_ext);
                        }
                    }
                }
            }
        }
    }

    None
}

#[cfg(windows)]
fn is_executable(path: &Path) -> bool {
    match std::fs::metadata(path) {
        Ok(metadata) => {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                metadata.is_file() && (metadata.permissions().mode() & 0o111 != 0)
            }
            #[cfg(windows)]
            {
                metadata.is_file()
            }
        }
        Err(_) => false,
    }
}

#[cfg(unix)]
type BlockingStdinThreadHandle = UnixStdinThreadHandle;
#[cfg(windows)]
type BlockingStdinThreadHandle = WindowsStdinThreadHandle;

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

#[cfg(unix)]
struct UnixStdinThreadHandle {
    shutdown: Arc<AtomicBool>,
    handle: std::thread::JoinHandle<Result<()>>,
}

#[cfg(unix)]
impl UnixStdinThreadHandle {
    fn signal_shutdown(&self) {
        self.shutdown.store(true, Ordering::SeqCst);
    }

    async fn join(self) -> Result<()> {
        self.shutdown.store(true, Ordering::SeqCst);
        join_blocking_thread(self.handle).await
    }
}

#[cfg(windows)]
struct WindowsStdinThreadHandle {
    shutdown: Arc<WindowsEvent>,
    handle: std::thread::JoinHandle<Result<()>>,
}

#[cfg(windows)]
impl WindowsStdinThreadHandle {
    fn signal_shutdown(&self) {
        let _ = self.shutdown.set();
    }

    async fn join(self) -> Result<()> {
        let _ = self.shutdown.set();
        join_blocking_thread(self.handle).await
    }
}

#[cfg(unix)]
/// Spawn a blocking helper thread for piping interactive terminal input into the child while
/// logging every chunk that goes through stdin.
fn spawn_reader_thread(
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
/// Spawn a blocking helper thread that uses Win32 console APIs to relay interactive input into the
/// child while journaling all bytes that pass through stdin.
fn spawn_reader_thread(
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

    let overlapped_event =
        WindowsEvent::new(false, false).context("Failed to create overlapped read event")?;
    let mut buffer = [0u8; 8192];

    loop {
        let mut overlapped: OVERLAPPED = unsafe { std::mem::zeroed() };
        overlapped.hEvent = overlapped_event.handle();

        let read_result = unsafe {
            ReadFile(
                console_input.handle(),
                buffer.as_mut_ptr().cast(),
                buffer.len() as u32,
                std::ptr::null_mut(),
                &mut overlapped,
            )
        };

        if read_result == 0 {
            let err = std::io::Error::last_os_error();
            match err.raw_os_error() {
                Some(code) if code == ERROR_IO_PENDING as i32 => {}
                Some(code) if code == ERROR_OPERATION_ABORTED as i32 => continue,
                _ => {
                    return Err(err).context("Failed to initiate console read");
                }
            }
        }

        let handles = [overlapped_event.handle(), shutdown.handle()];
        let wait_result = unsafe {
            WaitForMultipleObjects(handles.len() as u32, handles.as_ptr(), FALSE, INFINITE)
        };

        if wait_result == WAIT_OBJECT_0 {
            let mut bytes_read: u32 = 0;
            let completed = unsafe {
                GetOverlappedResult(console_input.handle(), &overlapped, &mut bytes_read, FALSE)
            };
            if completed == 0 {
                let err = std::io::Error::last_os_error();
                if err.raw_os_error() == Some(ERROR_OPERATION_ABORTED as i32) {
                    continue;
                }
                return Err(err).context("Failed to complete console read");
            }

            if bytes_read == 0 {
                break;
            }

            let chunk = &buffer[..bytes_read as usize];
            log_file
                .write_all(chunk)
                .context("Failed to record stdin chunk")?;
            log_file.flush().context("Failed to flush stdin log")?;

            match write_child_input(&mut child_file, chunk) {
                Ok(WriteState::StillOpen) => {}
                Ok(WriteState::BrokenPipe) => break,
                Err(err) => return Err(err).context("Failed to forward stdin to child"),
            }
        } else if wait_result == WAIT_OBJECT_0 + 1 {
            unsafe {
                CancelIoEx(console_input.handle(), &overlapped);
            }
            let mut _bytes: u32 = 0;
            unsafe {
                GetOverlappedResult(console_input.handle(), &overlapped, &mut _bytes, FALSE);
            }
            break;
        } else if wait_result == WAIT_FAILED {
            let err = std::io::Error::last_os_error();
            return Err(err).context("Waiting on console read failed");
        } else {
            continue;
        }
    }

    log_file.flush().ok();
    let _ = child_file.flush();
    Ok(())
}

#[cfg(unix)]
fn stdin_is_tty() -> bool {
    unsafe { libc::isatty(libc::STDIN_FILENO) == 1 }
}

#[cfg(windows)]
fn stdin_is_console() -> Result<bool> {
    use anyhow::Context as _;

    unsafe {
        let handle = GetStdHandle(STD_INPUT_HANDLE);
        if handle == INVALID_HANDLE_VALUE {
            let err = std::io::Error::last_os_error();
            return Err(err).context("Failed to acquire standard input handle");
        }
        if handle == 0 {
            return Ok(false);
        }
        if GetFileType(handle) != FILE_TYPE_CHAR {
            return Ok(false);
        }
        let mut mode = 0u32;
        if GetConsoleMode(handle, &mut mode) == 0 {
            return Ok(false);
        }
        Ok(true)
    }
}

#[cfg(windows)]
struct ConsoleInputHandle {
    handle: HANDLE,
}

#[cfg(windows)]
impl ConsoleInputHandle {
    fn open() -> std::io::Result<Self> {
        let name: Vec<u16> = OsStr::new("CONIN$")
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        let handle = unsafe {
            CreateFileW(
                name.as_ptr(),
                FILE_GENERIC_READ | FILE_GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                std::ptr::null_mut(),
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,
                0,
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(Self { handle })
        }
    }

    fn handle(&self) -> HANDLE {
        self.handle
    }
}

#[cfg(windows)]
impl Drop for ConsoleInputHandle {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.handle);
        }
    }
}

#[cfg(windows)]
struct ConsoleModeGuard {
    handle: HANDLE,
    original_mode: u32,
    modified: bool,
}

#[cfg(windows)]
impl ConsoleModeGuard {
    fn new(handle: HANDLE) -> std::io::Result<Self> {
        Self::new_with_options(handle, false, false)
    }

    fn new_for_pty_input(handle: HANDLE) -> std::io::Result<Self> {
        Self::new_with_options(handle, true, true)
    }

    fn new_with_options(
        handle: HANDLE,
        disable_echo: bool,
        disable_line_input: bool,
    ) -> std::io::Result<Self> {
        let mut original = 0u32;
        if unsafe { GetConsoleMode(handle, &mut original) } == 0 {
            return Err(std::io::Error::last_os_error());
        }

        let mut new_mode = original | ENABLE_EXTENDED_FLAGS;
        let mut modified = new_mode != original;

        if disable_line_input && (new_mode & ENABLE_LINE_INPUT) != 0 {
            new_mode &= !ENABLE_LINE_INPUT;
            modified = true;
        }

        if disable_echo && (new_mode & ENABLE_ECHO_INPUT) != 0 {
            new_mode &= !ENABLE_ECHO_INPUT;
            modified = true;
        }

        if modified {
            if unsafe { SetConsoleMode(handle, new_mode) } == 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(Self {
                handle,
                original_mode: original,
                modified: true,
            })
        } else {
            Ok(Self {
                handle,
                original_mode: original,
                modified: false,
            })
        }
    }
}

#[cfg(windows)]
impl Drop for ConsoleModeGuard {
    fn drop(&mut self) {
        if self.modified {
            unsafe {
                SetConsoleMode(self.handle, self.original_mode);
            }
        }
    }
}

#[cfg(windows)]
struct WindowsEvent {
    handle: HANDLE,
}

#[cfg(windows)]
impl WindowsEvent {
    fn new(manual_reset: bool, initial_state: bool) -> std::io::Result<Self> {
        let handle = unsafe {
            CreateEventW(
                std::ptr::null_mut(),
                if manual_reset { 1 } else { 0 },
                if initial_state { 1 } else { 0 },
                std::ptr::null(),
            )
        };
        if handle == 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(Self { handle })
        }
    }

    fn set(&self) -> std::io::Result<()> {
        if unsafe { SetEvent(self.handle) } == 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    fn handle(&self) -> HANDLE {
        self.handle
    }
}

#[cfg(windows)]
impl Drop for WindowsEvent {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.handle);
        }
    }
}

#[cfg(unix)]
fn convert_child_stdin(child_input: ChildStdin) -> Result<std::fs::File> {
    use anyhow::Context as _;

    let owned_fd = child_input
        .into_owned_fd()
        .context("Failed to obtain owned file descriptor for child stdin")?;
    let file = std::fs::File::from(owned_fd);

    let fd = file.as_raw_fd();
    let flags = get_fd_flags(fd)?;
    set_fd_flags(fd, flags & !libc::O_NONBLOCK)?;

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

#[cfg(any(unix, windows))]
enum WriteState {
    StillOpen,
    BrokenPipe,
}

#[cfg(any(unix, windows))]
fn write_child_input(file: &mut std::fs::File, mut buf: &[u8]) -> std::io::Result<WriteState> {
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

#[cfg(unix)]
struct FdFlagGuard {
    fd: RawFd,
    original: libc::c_int,
}

#[cfg(unix)]
impl FdFlagGuard {
    fn new(fd: RawFd) -> std::io::Result<Self> {
        let original = get_fd_flags(fd)?;
        set_fd_flags(fd, original | libc::O_NONBLOCK)?;
        Ok(Self { fd, original })
    }
}

#[cfg(unix)]
impl Drop for FdFlagGuard {
    fn drop(&mut self) {
        let _ = set_fd_flags(self.fd, self.original);
    }
}

#[cfg(unix)]
struct UnixTerminalModeGuard {
    fd: RawFd,
    original: libc::termios,
    modified: bool,
}

#[cfg(unix)]
impl UnixTerminalModeGuard {
    fn new_for_pty_input(fd: RawFd) -> std::io::Result<Self> {
        let mut original = unsafe { std::mem::zeroed::<libc::termios>() };
        if unsafe { libc::tcgetattr(fd, &mut original) } != 0 {
            return Err(std::io::Error::last_os_error());
        }

        let mut mode = original;
        mode.c_lflag &= !(libc::ECHO | libc::ICANON);
        mode.c_cc[libc::VMIN] = 1;
        mode.c_cc[libc::VTIME] = 0;

        let modified = mode.c_lflag != original.c_lflag
            || mode.c_cc[libc::VMIN] != original.c_cc[libc::VMIN]
            || mode.c_cc[libc::VTIME] != original.c_cc[libc::VTIME];

        if modified && unsafe { libc::tcsetattr(fd, libc::TCSANOW, &mode) } != 0 {
            return Err(std::io::Error::last_os_error());
        }

        Ok(Self {
            fd,
            original,
            modified,
        })
    }
}

#[cfg(unix)]
impl Drop for UnixTerminalModeGuard {
    fn drop(&mut self) {
        if self.modified {
            let _ = unsafe { libc::tcsetattr(self.fd, libc::TCSANOW, &self.original) };
        }
    }
}

#[cfg(unix)]
fn get_fd_flags(fd: RawFd) -> std::io::Result<libc::c_int> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(flags)
    }
}

#[cfg(unix)]
fn set_fd_flags(fd: RawFd, flags: libc::c_int) -> std::io::Result<()> {
    let result = unsafe { libc::fcntl(fd, libc::F_SETFL, flags) };
    if result < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(any(unix, windows))]
async fn join_blocking_thread(handle: std::thread::JoinHandle<Result<()>>) -> Result<()> {
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

/// Spawn an async task that forwards a non-terminal `AsyncRead` source into the child's stdin while
/// recording the forwarded bytes.
fn spawn_writer_task<W, R>(
    child_input: Option<W>,
    log_path: PathBuf,
    input: R,
    shutdown: Arc<Notify>,
) -> Result<Option<JoinHandle<Result<()>>>>
where
    W: AsyncWrite + Unpin + Send + 'static,
    R: AsyncRead + Unpin + Send + 'static,
{
    let Some(mut child_input) = child_input else {
        return Ok(None);
    };

    let handle = tokio::spawn(async move {
        let mut log_file = TokioFile::create(&log_path)
            .await
            .with_context(|| format!("Failed to create stdin log file {}", log_path.display()))?;

        let mut input = input;
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

/// Spawn an async task that relays the child's stdout or stderr to the current console and captures
/// the same bytes in a log file.
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

async fn write_execution_toml(
    session_dir: &Path,
    args: &crate::RunArgs,
    success: bool,
    exit_code: Option<i32>,
) -> Result<()> {
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
    status_table.insert("success".to_string(), Value::Boolean(success));
    if let Some(code) = exit_code {
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

    Ok(())
}

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
async fn execute_command_with_unix_pty(
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

// ── ConPTY support (Windows only) ──────────────────────────────────────────

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
            CloseHandle(self.handle);
        }
    }
}

#[cfg(windows)]
fn create_pipe() -> Result<(SafePipe, SafePipe)> {
    let mut read_handle: HANDLE = 0;
    let mut write_handle: HANDLE = 0;
    let ok = unsafe { CreatePipe(&mut read_handle, &mut write_handle, std::ptr::null(), 0) };
    if ok == 0 {
        return Err(std::io::Error::last_os_error()).context("CreatePipe failed");
    }
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
        let mut handle: HPCON = 0;
        let hr = unsafe {
            CreatePseudoConsole(
                size,
                input_read,
                output_write,
                PSEUDOCONSOLE_INHERIT_CURSOR,
                &mut handle,
            )
        };
        if hr != 0 {
            bail!(
                "CreatePseudoConsole failed with HRESULT 0x{:08X}",
                hr as u32
            );
        }
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
            InitializeProcThreadAttributeList(std::ptr::null_mut(), 1, 0, &mut size);
        }
        if size == 0 {
            bail!("InitializeProcThreadAttributeList returned zero size");
        }
        let mut buffer = vec![0u8; size];
        let list = buffer.as_mut_ptr() as LPPROC_THREAD_ATTRIBUTE_LIST;
        let ok = unsafe { InitializeProcThreadAttributeList(list, 1, 0, &mut size) };
        if ok == 0 {
            return Err(std::io::Error::last_os_error())
                .context("InitializeProcThreadAttributeList failed");
        }
        let ok = unsafe {
            UpdateProcThreadAttribute(
                list,
                0,
                PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE as usize,
                conpty.handle as *const std::ffi::c_void,
                std::mem::size_of::<HPCON>(),
                std::ptr::null_mut(),
                std::ptr::null(),
            )
        };
        if ok == 0 {
            unsafe {
                DeleteProcThreadAttributeList(list);
            }
            return Err(std::io::Error::last_os_error())
                .context("UpdateProcThreadAttribute failed");
        }
        Ok(Self { buffer })
    }

    fn as_ptr(&self) -> LPPROC_THREAD_ATTRIBUTE_LIST {
        self.buffer.as_ptr() as LPPROC_THREAD_ATTRIBUTE_LIST
    }

    fn as_mut_ptr(&mut self) -> LPPROC_THREAD_ATTRIBUTE_LIST {
        self.buffer.as_mut_ptr() as LPPROC_THREAD_ATTRIBUTE_LIST
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
impl Win32Process {
    fn process_handle(&self) -> HANDLE {
        self.process_handle
    }
}

#[cfg(windows)]
impl Drop for Win32Process {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.thread_handle);
            CloseHandle(self.process_handle);
        }
    }
}

#[cfg(windows)]
fn get_console_size() -> (i16, i16) {
    unsafe {
        let handle = GetStdHandle(STD_OUTPUT_HANDLE);
        if handle == INVALID_HANDLE_VALUE || handle == 0 {
            return (80, 24);
        }
        let mut info: CONSOLE_SCREEN_BUFFER_INFO = std::mem::zeroed();
        if GetConsoleScreenBufferInfo(handle, &mut info) == 0 {
            return (80, 24);
        }
        let cols = info.srWindow.Right - info.srWindow.Left + 1;
        let rows = info.srWindow.Bottom - info.srWindow.Top + 1;
        (cols, rows)
    }
}

#[cfg(windows)]
fn build_command_line(args: &[String]) -> Result<Vec<u16>> {
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

    let ok = unsafe {
        CreateProcessW(
            std::ptr::null(),
            cmd_line.as_mut_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            FALSE,
            EXTENDED_STARTUPINFO_PRESENT,
            std::ptr::null(),
            cwd_wide.as_ptr(),
            &si.StartupInfo,
            &mut pi,
        )
    };

    if ok == 0 {
        return Err(std::io::Error::last_os_error()).context("CreateProcessW failed");
    }

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
    std::thread::Builder::new()
        .name("conpty-output".to_string())
        .spawn(move || {
            let mut log_file = std::fs::File::create(&stdout_log_path).with_context(|| {
                format!(
                    "Failed to create stdout log file {}",
                    stdout_log_path.display()
                )
            })?;

            let stdout_handle = unsafe { GetStdHandle(STD_OUTPUT_HANDLE) };
            let mut buffer = [0u8; 8192];

            loop {
                let mut bytes_read: u32 = 0;
                let ok = unsafe {
                    ReadFile(
                        pty_output_read,
                        buffer.as_mut_ptr().cast(),
                        buffer.len() as u32,
                        &mut bytes_read,
                        std::ptr::null_mut(),
                    )
                };

                if ok == 0 {
                    let err = std::io::Error::last_os_error();
                    if err.raw_os_error() == Some(ERROR_BROKEN_PIPE as i32) {
                        break;
                    }
                    return Err(err).context("ReadFile on PTY output pipe failed");
                }

                if bytes_read == 0 {
                    break;
                }

                let chunk = &buffer[..bytes_read as usize];

                // Write to real console
                if stdout_handle != INVALID_HANDLE_VALUE && stdout_handle != 0 {
                    let mut written: u32 = 0;
                    unsafe {
                        WriteFile(
                            stdout_handle,
                            chunk.as_ptr().cast(),
                            chunk.len() as u32,
                            &mut written,
                            std::ptr::null_mut(),
                        );
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
    std::thread::Builder::new()
        .name("conpty-input".to_string())
        .spawn(move || {
            let mut log_file = std::fs::File::create(&stdin_log_path).with_context(|| {
                format!(
                    "Failed to create stdin log file {}",
                    stdin_log_path.display()
                )
            })?;

            let console_input =
                ConsoleInputHandle::open().context("Failed to open console input handle")?;
            let std_input = unsafe { GetStdHandle(STD_INPUT_HANDLE) };
            if std_input == INVALID_HANDLE_VALUE {
                return Err(std::io::Error::last_os_error())
                    .context("Failed to acquire standard input handle");
            }
            if std_input == 0 {
                return Ok(());
            }
            let _mode_guard = ConsoleModeGuard::new_for_pty_input(std_input)
                .context("Failed to configure console mode for PTY input")?;

            let overlapped_event = WindowsEvent::new(false, false)
                .context("Failed to create overlapped read event")?;
            let mut buffer = [0u8; 8192];

            loop {
                let mut overlapped: OVERLAPPED = unsafe { std::mem::zeroed() };
                overlapped.hEvent = overlapped_event.handle();

                let read_result = unsafe {
                    ReadFile(
                        console_input.handle(),
                        buffer.as_mut_ptr().cast(),
                        buffer.len() as u32,
                        std::ptr::null_mut(),
                        &mut overlapped,
                    )
                };

                if read_result == 0 {
                    let err = std::io::Error::last_os_error();
                    match err.raw_os_error() {
                        Some(code) if code == ERROR_IO_PENDING as i32 => {}
                        Some(code) if code == ERROR_OPERATION_ABORTED as i32 => continue,
                        _ => {
                            return Err(err).context("Failed to initiate console read");
                        }
                    }
                }

                let handles = [overlapped_event.handle(), shutdown.handle()];
                let wait_result = unsafe {
                    WaitForMultipleObjects(handles.len() as u32, handles.as_ptr(), FALSE, INFINITE)
                };

                if wait_result == WAIT_OBJECT_0 {
                    let mut bytes_read: u32 = 0;
                    let completed = unsafe {
                        GetOverlappedResult(
                            console_input.handle(),
                            &overlapped,
                            &mut bytes_read,
                            FALSE,
                        )
                    };
                    if completed == 0 {
                        let err = std::io::Error::last_os_error();
                        if err.raw_os_error() == Some(ERROR_OPERATION_ABORTED as i32) {
                            continue;
                        }
                        return Err(err).context("Failed to complete console read");
                    }

                    if bytes_read == 0 {
                        break;
                    }

                    let chunk = &buffer[..bytes_read as usize];

                    // Write to log
                    log_file
                        .write_all(chunk)
                        .context("Failed to record stdin chunk")?;
                    log_file.flush().context("Failed to flush stdin log")?;

                    // Write to PTY input pipe using WriteFile
                    let mut total_written = 0u32;
                    while total_written < bytes_read {
                        let mut written: u32 = 0;
                        let ok = unsafe {
                            WriteFile(
                                pty_input_write,
                                chunk[total_written as usize..].as_ptr().cast(),
                                bytes_read - total_written,
                                &mut written,
                                std::ptr::null_mut(),
                            )
                        };
                        if ok == 0 {
                            let err = std::io::Error::last_os_error();
                            if err.raw_os_error() == Some(ERROR_BROKEN_PIPE as i32) {
                                return Ok(());
                            }
                            return Err(err).context("Failed to write to PTY input pipe");
                        }
                        total_written += written;
                    }
                } else if wait_result == WAIT_OBJECT_0 + 1 {
                    // Shutdown signalled
                    unsafe {
                        CancelIoEx(console_input.handle(), &overlapped);
                    }
                    let mut _bytes: u32 = 0;
                    unsafe {
                        GetOverlappedResult(
                            console_input.handle(),
                            &overlapped,
                            &mut _bytes,
                            FALSE,
                        );
                    }
                    break;
                } else if wait_result == WAIT_FAILED {
                    let err = std::io::Error::last_os_error();
                    return Err(err).context("Waiting on console read failed");
                } else {
                    continue;
                }
            }

            log_file.flush().ok();
            Ok(())
        })
        .expect("Failed to spawn conpty input forwarder thread")
}

#[cfg(windows)]
async fn execute_command_with_conpty(
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
    let wait_thread = std::thread::Builder::new()
        .name("conpty-wait".to_string())
        .spawn(move || {
            unsafe {
                WaitForSingleObject(process_handle, INFINITE);
            }
            let mut exit_code: u32 = 1;
            unsafe {
                GetExitCodeProcess(process_handle, &mut exit_code);
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
                TerminateProcess(process.process_handle(), 1);
            }

            // Wait briefly for the process to actually exit
            tokio::task::spawn_blocking({
                let ph = process.process_handle();
                move || unsafe {
                    WaitForSingleObject(ph, 3000);
                    let mut code: u32 = 1;
                    GetExitCodeProcess(ph, &mut code);
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

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::task::JoinHandle;

    #[tokio::test]
    async fn spawn_reader_task_redirects_output() -> Result<()> {
        let temp = TempDir::new().expect("tempdir");
        let log_path = temp.path().join("reader.log");

        let (mut writer, reader) = tokio::io::duplex(64);
        let (mut console_reader, console_writer) = tokio::io::duplex(64);

        let handle = spawn_reader_task(Some(reader), log_path.clone(), move || console_writer)?
            .expect("reader handle");

        writer.write_all(b"hello world").await?;
        writer.shutdown().await?;

        join_stream_task(handle).await?;

        let mut captured = Vec::new();
        console_reader.read_to_end(&mut captured).await?;
        assert_eq!(captured, b"hello world");

        let logged = tokio::fs::read(&log_path).await?;
        assert_eq!(logged, b"hello world");
        Ok(())
    }

    #[test]
    fn capture_environment_includes_set_variables() {
        unsafe {
            std::env::set_var("RECORDIT_TEST_ENV", "present");
        }
        let env = capture_environment();

        assert_eq!(
            env.get("RECORDIT_TEST_ENV"),
            Some(&Value::String("present".to_string()))
        );
    }

    #[test]
    fn quote_cmd_argument_preserves_trailing_backslashes() {
        assert_eq!(
            quote_cmd_argument(r"C:\Program Files\RecordIt\"),
            r#""C:\Program Files\RecordIt\\""#,
        );
    }

    #[cfg(windows)]
    #[test]
    fn build_command_line_preserves_trailing_backslashes() -> Result<()> {
        let previous_shell = std::env::var_os("RECORDIT_SHELL");
        unsafe {
            std::env::set_var("RECORDIT_SHELL", r"C:\Windows\System32\cmd.exe");
        }

        let result = (|| -> Result<()> {
            let encoded = build_command_line(&[
            "echo".to_string(),
            r"C:\Program Files\RecordIt\".to_string(),
            ])?;
            let nul_pos = encoded
                .iter()
                .position(|&unit| unit == 0)
                .expect("nul terminator");
            let command_line = String::from_utf16(&encoded[..nul_pos]).expect("utf16 command line");

            assert_eq!(
                command_line,
                r#"C:\Windows\System32\cmd.exe /c "echo \"C:\Program Files\RecordIt\\\\\"""#,
            );

            Ok(())
        })();

        unsafe {
            if let Some(value) = previous_shell {
                std::env::set_var("RECORDIT_SHELL", value);
            } else {
                std::env::remove_var("RECORDIT_SHELL");
            }
        }

        result
    }

    #[tokio::test]
    async fn join_stream_task_propagates_panics() {
        let handle: JoinHandle<Result<()>> = tokio::spawn(async move {
            panic!("expected panic");
        });

        let err = join_stream_task(handle).await.expect_err("should fail");
        let message = format!("{err}");
        assert!(message.contains("expected panic"));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn execute_command_records_command_output() -> Result<()> {
        use tokio::fs;

        let temp = TempDir::new().expect("tempdir");
        let session_dir = temp.path().join("session");
        let context = crate::Context {
            git_root: None,
            session_dir: Some(session_dir.clone()),
        };

        let args = crate::RunArgs {
            cwd: temp.path().to_path_buf(),
            record_base: temp.path().join("records"),
            version_name: "test".to_string(),
            message: String::new(),
            record: Vec::new(),
            stdin: None,
            use_pty: false,
            cmd: vec![
                "/bin/sh".to_string(),
                "-c".to_string(),
                "printf stdout && printf stderr >&2".to_string(),
            ],
        };

        super::execute_command_with_stdin(
            &args,
            &context,
            super::StdinInput::Reader(tokio::io::empty()),
        )
        .await?;

        let stdout = fs::read(session_dir.join("io").join("stdout.log")).await?;
        let stderr = fs::read(session_dir.join("io").join("stderr.log")).await?;
        let stdin = fs::read(session_dir.join("io").join("stdin.log")).await?;
        let metadata = fs::read_to_string(session_dir.join("execution.toml")).await?;

        assert_eq!(stdout, b"stdout");
        assert_eq!(stderr, b"stderr");
        assert!(stdin.is_empty());
        assert!(metadata.contains("command"));
        assert!(metadata.contains("cwd"));
        assert!(metadata.contains("status"));
        Ok(())
    }
}
