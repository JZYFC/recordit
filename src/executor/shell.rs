use std::ffi::OsString;
use std::path::{Path, PathBuf};

use anyhow::Result;
use tracing::warn;

use sysinfo::{Pid, Process, System};

pub(super) struct ShellInvocation {
    pub(super) program: OsString,
    pub(super) args: Vec<OsString>,
    pub(super) description: String,
}

#[derive(Clone, Debug)]
pub(super) struct ShellInfo {
    pub(super) program: PathBuf,
    pub(super) kind: ShellKind,
}

#[derive(Clone, Copy, Debug)]
pub(super) enum ShellKind {
    Posix,
    PowerShell,
    Cmd,
}

pub(super) fn prepare_shell_invocation(command: &[String]) -> Result<Option<ShellInvocation>> {
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

    if let Some(name) = std::path::Path::new(value.as_os_str())
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

pub(crate) fn quote_cmd_argument(argument: &str) -> String {
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
        Ok(metadata) => metadata.is_file(),
        Err(_) => false,
    }
}
