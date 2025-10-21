use std::ffi::OsString;
use std::io::ErrorKind;
#[cfg(unix)]
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
#[cfg(unix)]
use std::sync::atomic::{AtomicBool, Ordering};
#[cfg(unix)]
use std::time::Duration;

use anyhow::{anyhow, Context as _, Result, bail};
use tokio::fs as async_fs;
use tokio::fs::File as TokioFile;
use tokio::io::{self as tokio_io, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::process::Command;
use tokio::process::ChildStdin;
use tokio::sync::Notify;
use tokio::task::JoinHandle;
use toml::Value;
use toml::value::Table as TomlTable;
use tracing::{info, warn};

#[cfg(unix)]
use std::os::unix::io::{AsRawFd, RawFd};

use sysinfo::{Pid, Process, System};

#[allow(dead_code)]
/// Execute a command in a subprocess, record and redirect its stdin, stdout, stderr for replay.
pub async fn execute_command(args: &crate::RunArgs, context: &crate::Context) -> Result<()> {
    execute_command_with_stdin(
        args,
        context,
        StdinInput::<tokio_io::Stdin>::Console,
    )
    .await
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
            #[cfg(not(unix))]
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

    let status = child
        .wait()
        .await
        .with_context(|| format!("Failed to wait for command {:?}", args.cmd))?;

    shutdown.notify_waiters();
    stdin_forwarder.signal_shutdown();

    if let Some(handle) = stdout_handle {
        join_stream_task(handle).await?;
    }

    if let Some(handle) = stderr_handle {
        join_stream_task(handle).await?;
    }

    stdin_forwarder.finish().await?;

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
    {
        if let Some(kind) = classify_shell_name(name) {
            return Ok(Some(ShellInfo {
                program: PathBuf::from(name),
                kind,
            }));
        }
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

    loop {
        let parent_pid = match system
            .process(current_pid)
            .and_then(|process| process.parent())
        {
            Some(pid) => pid,
            None => break,
        };

        if system.process(parent_pid).is_none() {
            system.refresh_process(parent_pid);
        }

        if let Some(parent_process) = system.process(parent_pid) {
            if let Some(shell) = shell_info_from_process(parent_process) {
                return Some(shell);
            }
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
    if let Some(exe) = process.exe() {
        if let Some(kind) = classify_shell_path(exe) {
            return Some(ShellInfo {
                program: exe.to_path_buf(),
                kind,
            });
        }
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
                quoted.extend(std::iter::repeat('\\').take(backslashes * 2 + 1));
                quoted.push('"');
                backslashes = 0;
            }
            _ => {
                if backslashes > 0 {
                    quoted.extend(std::iter::repeat('\\').take(backslashes));
                    backslashes = 0;
                }
                quoted.push(ch);
            }
        }
    }

    if backslashes > 0 {
        quoted.extend(std::iter::repeat('\\').take(backslashes * 2));
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

enum StdinForwardHandle {
    None,
    Async(JoinHandle<Result<()>>),
    #[cfg(unix)]
    Thread(StdinThreadHandle),
}

impl StdinForwardHandle {
    fn signal_shutdown(&self) {
        match self {
            StdinForwardHandle::None => {}
            StdinForwardHandle::Async(_) => {}
            #[cfg(unix)]
            StdinForwardHandle::Thread(handle) => handle.signal_shutdown(),
        }
    }

    async fn finish(self) -> Result<()> {
        match self {
            StdinForwardHandle::None => Ok(()),
            StdinForwardHandle::Async(handle) => join_stream_task(handle).await,
            #[cfg(unix)]
            StdinForwardHandle::Thread(handle) => handle.join().await,
        }
    }
}

#[cfg(unix)]
struct StdinThreadHandle {
    shutdown: Arc<AtomicBool>,
    handle: std::thread::JoinHandle<Result<()>>,
}

#[cfg(unix)]
impl StdinThreadHandle {
    fn signal_shutdown(&self) {
        self.shutdown.store(true, Ordering::SeqCst);
    }

    async fn join(self) -> Result<()> {
        self.shutdown.store(true, Ordering::SeqCst);
        join_blocking_thread(self.handle).await
    }
}

#[cfg(unix)]
/// Spawn a blocking helper thread for piping interactive terminal input into the child while
/// logging every chunk that goes through stdin.
fn spawn_reader_thread(
    child_input: Option<ChildStdin>,
    log_path: PathBuf,
) -> Result<Option<StdinThreadHandle>> {
    let Some(child_input) = child_input else {
        return Ok(None);
    };

    let shutdown = Arc::new(AtomicBool::new(false));
    let thread_shutdown = Arc::clone(&shutdown);
    let handle = std::thread::Builder::new()
        .name("recordit-stdin".to_string())
        .spawn(move || run_stdin_forwarder(child_input, log_path, thread_shutdown))
        .context("Failed to spawn stdin reader thread")?;

    Ok(Some(StdinThreadHandle { shutdown, handle }))
}

#[cfg(unix)]
fn run_stdin_forwarder(
    child_input: ChildStdin,
    log_path: PathBuf,
    shutdown: Arc<AtomicBool>,
) -> Result<()> {
    use anyhow::Context as _;

    let mut log_file = std::fs::File::create(&log_path).with_context(|| {
        format!("Failed to create stdin log file {}", log_path.display())
    })?;

    let mut child_file = convert_child_stdin(child_input)
        .context("Failed to convert child stdin to blocking pipe")?;

    let stdin = std::io::stdin();
    let fd = stdin.as_raw_fd();
    let fd_guard = FdFlagGuard::new(fd).context("Failed to configure stdin for non-blocking reads")?;
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

#[cfg(unix)]
enum WriteState {
    StillOpen,
    BrokenPipe,
}

#[cfg(unix)]
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

#[cfg(unix)]
async fn join_blocking_thread(
    handle: std::thread::JoinHandle<Result<()>>,
) -> Result<()> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use tokio::io::{self, AsyncReadExt, AsyncWriteExt};
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
            cmd: vec![
                "/bin/sh".to_string(),
                "-c".to_string(),
                "printf stdout && printf stderr >&2".to_string(),
            ],
        };

        super::execute_command_with_stdin(
            &args,
            &context,
            super::StdinInput::Reader(io::empty()),
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
