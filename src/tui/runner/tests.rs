use super::*;
use std::io::Write as _;
use tokio::io::AsyncWriteExt;

// Run directly as a child test binary to test lifecycle without a shell
// wrapper or a dependency on external interpreters.
#[test]
fn process_fixture() {
    let Ok(mode) = std::env::var("RECORDIT_TEST_PROCESS_FIXTURE") else {
        return;
    };
    std::io::stdout().write_all(b"ready\r\n").unwrap();
    std::io::stdout().flush().unwrap();
    if mode == "wait" {
        std::thread::sleep(std::time::Duration::from_secs(30));
    }
    std::process::exit(7);
}

async fn fixture_process(session: &Path, mode: &str) -> LiveProcess {
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "tui::runner::tests::process_fixture",
            "--nocapture",
        ])
        .env("RECORDIT_TEST_PROCESS_FIXTURE", mode)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let (tx, events) = mpsc::unbounded_channel();
    let (stdin_tx, mut stdin_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let mut stdin = child.stdin.take().unwrap();
    let stdin_task = tokio::spawn(async move {
        while let Some(bytes) = stdin_rx.recv().await {
            let _ = stdin.write_all(&bytes).await;
        }
    });
    let reader = spawn_stream_reader(
        child.stdout.take().unwrap(),
        StreamKind::Stdout,
        open_log(&session.join("stdout.log")).unwrap(),
        tx,
    );
    LiveProcess {
        files: vec![],
        env: vec![],
        events,
        stdin_tx,
        child: Some(child),
        tasks: vec![reader],
        stdin_task: Some(stdin_task),
        exit_status: None,
    }
}

#[tokio::test]
async fn shutdown_writes_metadata_for_running_and_exited_processes() {
    for mode in ["wait", "exit"] {
        let temp = tempfile::TempDir::new().unwrap();
        let args = crate::RunArgs {
            cwd: temp.path().to_path_buf(),
            record_base: temp.path().join(".recordit"),
            version_name: "test".into(),
            message: String::new(),
            record: vec![],
            stdin: None,
            use_pty: false,
            cmd: vec!["fixture".into()],
        };
        let mut process = fixture_process(temp.path(), mode).await;
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                if let Some(RunEvent::Line(line)) = process.events.recv().await
                    && line.text == "ready"
                {
                    break;
                }
            }
        })
        .await
        .unwrap();
        if mode == "exit" {
            tokio::time::timeout(std::time::Duration::from_secs(5), async {
                while process.poll_exit().unwrap().is_none() {
                    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                }
            })
            .await
            .unwrap();
            // The status must survive repeated polling and finalization.
            assert_eq!(process.poll_exit().unwrap().unwrap().code(), Some(7));
        } else {
            assert!(process.poll_exit().unwrap().is_none());
        }
        let stdin_tx = process.stdin_tx.clone();
        super::super::run::finish_run(process, temp.path(), &args)
            .await
            .unwrap();
        assert!(stdin_tx.is_closed());
        let serialized = std::fs::read_to_string(temp.path().join("execution.toml")).unwrap();
        let metadata: toml::Value = toml::from_str(&serialized)
            .unwrap_or_else(|err| panic!("Invalid execution metadata: {}", err.message()));
        assert_eq!(metadata["command"][0].as_str(), Some("fixture"));
        assert_eq!(metadata["status"]["success"].as_bool(), Some(false));
        assert!(metadata["environment"].is_table());
        if mode == "exit" {
            assert_eq!(metadata["status"]["code"].as_integer(), Some(7));
        }
        assert!(
            std::fs::read(temp.path().join("stdout.log"))
                .unwrap()
                .windows(7)
                .any(|s| s == b"ready\r\n")
        );
    }
}

#[tokio::test]
async fn file_stdin_is_forwarded_and_closed_at_eof() {
    let temp = tempfile::TempDir::new().unwrap();
    let input = temp.path().join("input.txt");
    let bytes = b"beta\r\nalpha\r\n";
    std::fs::write(&input, bytes).unwrap();
    let args = crate::RunArgs {
        cwd: temp.path().to_path_buf(),
        record_base: temp.path().join(".recordit"),
        version_name: "test".into(),
        message: String::new(),
        record: Vec::new(),
        stdin: Some(input),
        use_pty: false,
        cmd: vec![if cfg!(windows) { "sort.exe" } else { "sort" }.into()],
    };
    let session = temp.path().join("session");
    let mut process = start_live_process(&args, session.clone()).await.unwrap();
    let status = tokio::time::timeout(std::time::Duration::from_secs(10), async {
        loop {
            if let Some(status) = process.poll_exit().unwrap() {
                break status;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("sort must receive EOF and exit");
    assert!(status.success());
    assert!(process.stdin_tx.is_closed());
    process.shutdown().await.unwrap();
    assert_eq!(std::fs::read(session.join("io/stdin.log")).unwrap(), bytes);
    let output = std::fs::read_to_string(session.join("io/stdout.log")).unwrap();
    assert_eq!(output.lines().collect::<Vec<_>>(), vec!["alpha", "beta"]);
}

#[tokio::test]
async fn start_live_process_captures_stdout() {
    let temp = tempfile::TempDir::new().unwrap();
    let session = temp.path().join("s");
    tokio::fs::create_dir_all(session.join("files"))
        .await
        .unwrap();

    let cmd = if cfg!(windows) {
        vec!["cmd".into(), "/C".into(), "echo live-ok".into()]
    } else {
        vec!["echo".into(), "live-ok".into()]
    };
    let args = crate::RunArgs {
        cwd: temp.path().to_path_buf(),
        record_base: temp.path().join(".recordit"),
        version_name: "t".into(),
        message: String::new(),
        record: Vec::new(),
        stdin: None,
        use_pty: false,
        cmd,
    };

    let mut proc = start_live_process(&args, session.clone()).await.unwrap();
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        if proc.poll_exit().unwrap().is_some() {
            break;
        }
        if tokio::time::Instant::now() > deadline {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    proc.shutdown().await.unwrap();
    let got = std::fs::read_to_string(session.join("io/stdout.log")).unwrap();
    assert!(got.contains("live-ok"), "stdout was: {got:?}");
}
