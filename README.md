# RecordIt

RecordIt is a command-line helper that snapshots the files you care about before
running another command. It copies the inputs to a versioned archive, captures
stdin/stdout/stderr, and stores execution metadata so you can revisit what
happened later.

The tool is built for reproducibility: you can archive the exact workspace state
that produced a test failure or bug without committing anything to git.

## Features

- Detects the current git repository and records every tracked file referenced
  by the index.
- Adds extra files or symlinks via the `--record` flag (absolute or relative
  paths).
- Stores each session under a timestamped (or custom named) directory with an
  optional message attached.
- Logs process stdin, stdout, stderr, and environment variables alongside the
  executed command.
- Includes a `clean` subcommand to remove existing archives.

## Installation

RecordIt is distributed as a Rust crate. Install it from source with Cargo:

```bash
cargo install --path .
```

Alternatively, build an ad-hoc binary:

```bash
cargo build --release
target/release/recordit --help
```

## Quick Start

```bash
# Record all tracked files plus Cargo.lock, then run tests
recordit run --record Cargo.lock -- cargo test
```

This creates a new session directory underneath `.recordit` in the repository
root (or the current directory when no git repo is present). The directory name
defaults to `YYYYMMDD-HHMMSS`, but you can override it with `--version-name` and
attach a message with `--message`.

## Command Reference

### `recordit run`

```
recordit run [OPTIONS] -- <command> [args...]
```

- `--cwd <path>`: Working directory for recording and command execution. Defaults
  to the current directory when `recordit` starts.
- `--record-base <path>`: Directory used to store all sessions. Relative paths
  are resolved against the git root if one exists, otherwise against `--cwd`.
- `-n, --version-name <name>`: Custom directory name for the session. The value
  is sanitized and must not collide with an existing session.
- `-m, --message <msg>`: Optional session note stored in `MESSAGE.txt`.
- `--record <path>`: Additional files or symlinks to snapshot. Repeat the flag
  to add multiple paths.
- `--`: Required before the command you want to run. Everything after `--` is
  executed verbatim.

Recording rules:

- Git tracked files are copied according to the repository index. New files that
  are not yet staged will be omitted unless supplied via `--record`.
- Directories are skipped; record individual files or symlinks instead.
- Paths outside the git root or working directory are mirrored under
  `__external__/…` in the session so naming remains deterministic.

### Session Layout

Each session contains:

```
<record-base>/<version-name>[-<message>]/ 
├── MESSAGE.txt        # optional, only when --message was set
├── execution.toml     # command, cwd, exit status, environment snapshot
├── files/             # recorded files, mirrored relative to git root or cwd
└── io/
    ├── stdin.log
    ├── stdout.log
    └── stderr.log
```

`execution.toml` follows a stable TOML structure so it can be parsed or diffed.
Logs are captured exactly as the subprocess produced them, while still streaming
to your terminal in real time.

### `recordit clean`

```
recordit clean [--cwd <path>] [--record-base <path>]
```

Deletes every entry inside the resolved recording directory. If nothing exists,
the command is a no-op.

### `recordit tui`

```
recordit tui [--cwd <path>] [--record-base <path>]
```

Opens an interactive terminal UI for browsing recorded sessions. The left pane
lists sessions (newest first) with status and command; the right pane shows
overview metadata plus recorded files, stdout, stderr, and stdin. Use `j`/`k`
to move, `Tab`/`Shift-Tab` (or `1`-`5`) to switch panes, `←`/`→` to pan the
detail body horizontally, and `q` to quit.

Press `R` to open a command prompt and launch a live monitored run without
leaving the browser flow. After the run finishes you return to the browser.
On Windows, backslashes in the command prompt are literal path separators;
quote paths containing spaces.

### `recordit tui run`

```
recordit tui run [OPTIONS] -- <command> [args...]
```

Same options as `recordit run`, but opens a live monitor TUI instead of
streaming straight to your terminal:

- Left column: recorded files, environment variables, and an interactive stdin
  panel (`i` or `Enter` to type, `Esc` to leave).
- Middle column: stdout with timestamps.
- Right column: stderr with timestamps.
- `b` toggles stdin line-buffer mode (send on Enter) vs raw mode (each key is
  forwarded immediately, like a terminal).
- `x` toggles merging stdout/stderr into one chronological view.
- `w` toggles word wrap for the stream panes (scroll uses visual rows).
- `←`/`→` pan horizontally: files/env always; stdout/stderr/stdin when wrap is
  off. Pane titles show `↑↓←→` when more content exists in that direction.
- Vertical auto-follow only pins to the bottom after the output overflows the
  pane; short output stays top-aligned.
- `t` toggles auto-follow of the latest output.
- `Esc` leaves stdin typing, or kills a running process; `q` quits the monitor.
- stdin is closed automatically after the process exits.
- `--stdin <path>` supplies input from a file and closes stdin at EOF; interactive
  typing is disabled in this mode.

IO logs preserve the original bytes, including line endings and non-UTF-8 output.
The live view displays incomplete lines immediately and substitutes invalid UTF-8
only for display. Quitting an active monitor saves the terminated process status.

The session is still written under the record base (files, IO logs, and
`execution.toml`), so it remains available in `recordit tui` afterwards.

## Tracing and Diagnostics

RecordIt uses `tracing` for diagnostics. Set `RUST_LOG` to control verbosity:

```bash
RUST_LOG=recordit=debug recordit run -- cargo test
```

Debug builds default to `debug` level, while release builds default to `info`.

## Development

- Run the automated tests with `cargo test`.
- The project targets the 2024 Rust edition and requires tokio with multi-thread
  runtime support.

Contributions and bug reports are welcome—open an issue describing your use case
or attach a session archive that reproduces the problem.
