//! Byte-preserving logs and display events. Process ownership stays in runner.
use std::fs::{File, OpenOptions};
use std::io::Write as _;
use std::path::Path;

use anyhow::{Context as _, Result};
use chrono::{DateTime, Local};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StreamKind {
    Stdin,
    Stdout,
    Stderr,
}

impl StreamKind {
    pub(crate) fn tag(self) -> &'static str {
        match self {
            StreamKind::Stdin => "in ",
            StreamKind::Stdout => "out",
            StreamKind::Stderr => "err",
        }
    }

    pub(crate) fn label(self) -> &'static str {
        match self {
            StreamKind::Stdin => "stdin",
            StreamKind::Stdout => "stdout",
            StreamKind::Stderr => "stderr",
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct IoLine {
    pub(crate) stream: StreamKind,
    pub(crate) timestamp: DateTime<Local>,
    pub(crate) text: String,
}

impl IoLine {
    pub(crate) fn format_timestamp(&self) -> String {
        self.timestamp.format("%H:%M:%S%.3f").to_string()
    }
}

#[derive(Debug)]
pub(crate) enum RunEvent {
    Line(IoLine),
    ReplaceLine(IoLine),
    Error(String),
}

pub(super) fn open_log(path: &Path) -> Result<File> {
    OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(path)
        .with_context(|| format!("Failed to create log file {}", path.display()))
}

pub(super) fn spawn_stream_reader<R>(
    mut reader: R,
    stream: StreamKind,
    mut log_file: File,
    tx: mpsc::UnboundedSender<RunEvent>,
) -> JoinHandle<()>
where
    R: AsyncRead + Unpin + Send + 'static,
{
    tokio::spawn(async move {
        let mut buffer = [0u8; 8192];
        let mut display = OutputDecoder::new(stream);
        loop {
            let count = match reader.read(&mut buffer).await {
                Ok(count) => count,
                Err(err) => {
                    let _ = tx.send(RunEvent::Error(format!(
                        "{} read failed: {err}",
                        stream.label()
                    )));
                    break;
                }
            };
            if let Err(err) = log_file
                .write_all(&buffer[..count])
                .and_then(|_| log_file.flush())
            {
                let _ = tx.send(RunEvent::Error(format!(
                    "{} log write failed: {err}",
                    stream.label()
                )));
            }
            for event in display.push(&buffer[..count], count == 0) {
                let _ = tx.send(event);
            }
            if count == 0 {
                break;
            }
        }
    })
}

/// Stateful display projection of a single byte stream. A partial line is
/// replaced until a newline arrives; log bytes never pass through this decoder.
struct OutputDecoder {
    stream: StreamKind,
    pending: Vec<u8>,
    current: String,
    replace: bool,
    timestamp: DateTime<Local>,
}

impl OutputDecoder {
    fn new(stream: StreamKind) -> Self {
        Self {
            stream,
            pending: Vec::new(),
            current: String::new(),
            replace: false,
            timestamp: Local::now(),
        }
    }

    fn push(&mut self, bytes: &[u8], eof: bool) -> Vec<RunEvent> {
        self.pending.extend_from_slice(bytes);
        let text = decode_output(&mut self.pending, eof);
        let mut events = Vec::new();
        for part in text.split_inclusive('\n') {
            if !self.replace {
                self.timestamp = Local::now();
            }
            self.current.push_str(part.trim_end_matches('\n'));
            let line = IoLine {
                stream: self.stream,
                timestamp: self.timestamp,
                text: self.current.trim_end_matches('\r').to_string(),
            };
            events.push(if self.replace {
                RunEvent::ReplaceLine(line)
            } else {
                RunEvent::Line(line)
            });
            self.replace = !part.ends_with('\n');
            if !self.replace {
                self.current.clear();
            }
        }
        events
    }
}

// Preserve incomplete UTF-8 between reads. Invalid bytes affect display only.
fn decode_output(pending: &mut Vec<u8>, eof: bool) -> String {
    let mut output = String::new();
    let mut consumed = 0;
    while consumed < pending.len() {
        match std::str::from_utf8(&pending[consumed..]) {
            Ok(text) => {
                output.push_str(text);
                consumed = pending.len();
            }
            Err(err) => {
                let valid_end = consumed + err.valid_up_to();
                output.push_str(std::str::from_utf8(&pending[consumed..valid_end]).unwrap());
                consumed = valid_end;
                if let Some(len) = err.error_len() {
                    output.push('\u{fffd}');
                    consumed += len;
                } else if eof {
                    output.push('\u{fffd}');
                    consumed = pending.len();
                } else {
                    break;
                }
            }
        }
    }
    pending.drain(..consumed);
    output
}

pub(super) fn spawn_stdin_writer(
    mut stdin: tokio::process::ChildStdin,
    input_file: Option<tokio::fs::File>,
    mut stdin_rx: mpsc::UnboundedReceiver<Vec<u8>>,
    stdin_file: File,
    events_tx: mpsc::UnboundedSender<RunEvent>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut log = stdin_file;
        let result: Result<()> = async {
            if let Some(mut input) = input_file {
                // File mode owns stdin and closes it at EOF.
                stdin_rx.close();
                let mut buffer = [0u8; 8192];
                loop {
                    let count = input.read(&mut buffer).await?;
                    if count == 0 {
                        break;
                    }
                    stdin.write_all(&buffer[..count]).await?;
                    log.write_all(&buffer[..count])?;
                    log.flush()?;
                }
            } else {
                while let Some(bytes) = stdin_rx.recv().await {
                    stdin.write_all(&bytes).await?;
                    stdin.flush().await?;
                    log.write_all(&bytes)?;
                    log.flush()?;
                }
            }
            Ok(())
        }
        .await;
        if let Err(err) = result {
            let _ = events_tx.send(RunEvent::Error(format!("stdin forwarding failed: {err}")));
        }
        let _ = stdin.shutdown().await;
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_decoder_tracks_partial_lines_across_reads() {
        let mut decoder = OutputDecoder::new(StreamKind::Stdout);
        let first = decoder.push(b"pro", false);
        assert!(matches!(&first[..], [RunEvent::Line(line)] if line.text == "pro"));
        let next = decoder.push(b"mpt\r\nnext", false);
        assert!(
            matches!(&next[..], [RunEvent::ReplaceLine(first), RunEvent::Line(second)]
            if first.text == "prompt" && second.text == "next")
        );
        let end = decoder.push(b"\n", true);
        assert!(matches!(&end[..], [RunEvent::ReplaceLine(line)] if line.text == "next"));
        assert!(decoder.push(b"", true).is_empty());
    }

    #[tokio::test]
    async fn reader_preserves_bytes_and_displays_partial_output() {
        let temp = tempfile::TempDir::new().unwrap();
        let log = temp.path().join("stdout.log");
        let (mut writer, reader) = tokio::io::duplex(64);
        let (tx, mut rx) = mpsc::unbounded_channel();
        let task = spawn_stream_reader(reader, StreamKind::Stdout, open_log(&log).unwrap(), tx);

        writer.write_all(b"Prompt: ").await.unwrap();
        let event = tokio::time::timeout(std::time::Duration::from_secs(2), rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(event, RunEvent::Line(line) if line.text == "Prompt: "));
        // Split a UTF-8 character across reads and include malformed bytes,
        // CRLF, and an unterminated last line.
        writer.write_all(&[0xe4]).await.unwrap();
        tokio::task::yield_now().await;
        writer
            .write_all(&[0xb8, 0xad, b'\r', b'\n', 0xff, b'!', b'\n', b'z'])
            .await
            .unwrap();
        writer.shutdown().await.unwrap();
        task.await.unwrap();
        let mut lines = Vec::new();
        while let Some(event) = rx.recv().await {
            match event {
                RunEvent::Line(line) | RunEvent::ReplaceLine(line) => lines.push(line.text),
                RunEvent::Error(err) => panic!("{err}"),
            }
        }
        assert!(lines.contains(&"Prompt: 中".to_string()), "{lines:?}");
        assert!(lines.contains(&"�!".to_string()), "{lines:?}");
        assert_eq!(lines.last().unwrap(), "z");
        assert_eq!(
            std::fs::read(log).unwrap(),
            b"Prompt: \xe4\xb8\xad\r\n\xff!\nz"
        );
    }

    #[test]
    fn decoder_retains_incomplete_utf8_until_next_read_or_eof() {
        let mut pending = vec![0xe4];
        assert_eq!(decode_output(&mut pending, false), "");
        assert_eq!(pending, vec![0xe4]);
        pending.extend_from_slice(&[0xb8, 0xad]);
        assert_eq!(decode_output(&mut pending, false), "中");
        pending.push(0xe4);
        assert_eq!(decode_output(&mut pending, true), "�");
        assert!(pending.is_empty());
    }
}
