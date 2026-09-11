mod shell;
mod io_async;
mod io_blocking;
mod pty_unix;
mod conpty;
mod guards;
mod execution;
mod toml_writer;

#[cfg(test)]
mod tests;

// Re-export for main and the TUI runner.
pub(crate) use execution::execute_command;
pub(crate) use shell::prepare_shell_invocation;
pub(crate) use toml_writer::write_execution_toml;
