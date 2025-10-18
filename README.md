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
