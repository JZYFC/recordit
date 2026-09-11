use anyhow::{Result, bail};

/// Tokenize a command line typed into the TUI prompt.
/// Supports quotes; on Windows backslashes are literal path separators.
pub(super) fn tokenize_command(input: &str) -> Result<Vec<String>> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut chars = input.chars().peekable();
    let mut in_single = false;
    let mut in_double = false;
    let mut has_token = false;

    while let Some(ch) = chars.next() {
        match ch {
            '\\' if !cfg!(windows) && !in_single => {
                if let Some(next) = chars.next() {
                    current.push(next);
                    has_token = true;
                } else {
                    bail!("Trailing escape in command");
                }
            }
            '\'' if !in_double => {
                in_single = !in_single;
                has_token = true;
            }
            '"' if !in_single => {
                in_double = !in_double;
                has_token = true;
            }
            c if c.is_whitespace() && !in_single && !in_double => {
                if has_token || !current.is_empty() {
                    tokens.push(std::mem::take(&mut current));
                    has_token = false;
                }
            }
            c => {
                current.push(c);
                has_token = true;
            }
        }
    }

    if in_single || in_double {
        bail!("Unbalanced quotes in command");
    }
    if has_token || !current.is_empty() {
        tokens.push(current);
    }
    if tokens.is_empty() {
        bail!("Command is empty");
    }
    Ok(tokens)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(windows)]
    #[test]
    fn tokenize_command_preserves_windows_paths() {
        assert_eq!(
            tokenize_command(r#"C:\Tools\app.exe "C:\Program Files\data\" \\server\share\input"#)
                .unwrap(),
            vec![
                r"C:\Tools\app.exe",
                r"C:\Program Files\data\",
                r"\\server\share\input"
            ]
        );
    }

    #[cfg(not(windows))]
    #[test]
    fn tokenize_command_preserves_posix_escapes() {
        assert_eq!(
            tokenize_command(r"echo hello\ world").unwrap(),
            vec!["echo", "hello world"]
        );
        assert!(tokenize_command("echo trailing\\").is_err());
    }

    #[test]
    fn tokenize_command_splits_simple() {
        assert_eq!(
            tokenize_command("cargo test -- --nocapture").unwrap(),
            vec!["cargo", "test", "--", "--nocapture"]
        );
    }

    #[test]
    fn tokenize_command_handles_quotes() {
        assert_eq!(
            tokenize_command(r#"echo "hello world""#).unwrap(),
            vec!["echo", "hello world"]
        );
        assert_eq!(
            tokenize_command("echo 'a b' c").unwrap(),
            vec!["echo", "a b", "c"]
        );
    }

    #[test]
    fn tokenize_command_rejects_empty_and_unbalanced() {
        assert!(tokenize_command("   ").is_err());
        assert!(tokenize_command("\"unclosed").is_err());
    }
}
