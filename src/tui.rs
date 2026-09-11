//! Browser and live-monitor entry points.
//!
//! `run` owns monitor state and input handling; `run::view` renders it.
//! `runner` owns child processes and task cleanup; `runner::io` records raw
//! bytes and emits decoded display events. `command_line` parses browser input.
//! Both screens use `viewport` for scroll bounds and `term` for terminal ownership.

mod browse;
mod command_line;
mod run;
mod runner;
mod term;
mod viewport;

use anyhow::Result;

pub(crate) async fn run_browser(
    cwd: std::path::PathBuf,
    record_base: std::path::PathBuf,
) -> Result<()> {
    browse::run_browser(cwd, record_base).await
}

pub(crate) async fn run_command(args: crate::RunArgs) -> Result<()> {
    run::run_live(args).await
}
