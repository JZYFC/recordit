#[cfg(test)]
use anyhow::Result;
#[cfg(test)]
use tempfile::TempDir;
#[cfg(test)]
use tokio::io::{AsyncReadExt, AsyncWriteExt};
#[cfg(test)]
use toml::Value;

#[cfg(test)]
use super::io_async::{spawn_reader_task, join_stream_task};
#[cfg(test)]
use super::toml_writer::capture_environment;
#[cfg(test)]
use super::shell::quote_cmd_argument;
#[cfg(unix)]
#[cfg(test)]
use super::execution::{execute_command_with_stdin, StdinInput};

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
    use super::conpty::build_command_line;

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
    let handle: tokio::task::JoinHandle<Result<()>> = tokio::spawn(async move {
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

    execute_command_with_stdin(
        &args,
        &context,
        StdinInput::Reader(tokio::io::empty()),
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
