use anyhow::{Context as _, Result, bail};
use clap::{Parser, Subcommand};
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use tokio::fs as async_fs;

mod executor;
mod recorder;

#[derive(Parser)]
#[command(author, version, about, propagate_version = true)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Record files and run a command.
    Run(RunArgs),
    /// Remove recorded sessions.
    Clean(CleanArgs),
}

#[derive(clap::Args)]
#[command(trailing_var_arg = true)]
pub(crate) struct RunArgs {
    /// Current working directory. Default to current working directory.
    #[arg(long, default_value_os_t = std::env::current_dir().unwrap())]
    pub(crate) cwd: PathBuf,
    /// Base directory to store recordings. Default to .recordit in the git repository root or current working directory.
    #[arg(long, default_value_os_t = PathBuf::from(".recordit"))]
    pub(crate) record_base: PathBuf,
    /// Version name for this recording session. Default to YYYYMMDD-HHMMSS.
    #[arg(short = 'n', long, default_value_t = chrono::Local::now().format("%Y%m%d-%H%M%S").to_string())]
    pub(crate) version_name: String,
    /// Opitonal message for this recording session.
    #[arg(short = 'm', long, default_value_t = String::from(""))]
    pub(crate) message: String,
    /// Additional files to record besides git tracked files.
    #[arg(long, value_name = "PATH", num_args = 1.., action = clap::ArgAction::Append)]
    pub(crate) record: Vec<String>,
    /// Command to execute and record.
    #[arg(required = true)]
    pub(crate) cmd: Vec<String>,
}

#[derive(clap::Args)]
pub(crate) struct CleanArgs {
    /// Current working directory. Default to current working directory.
    #[arg(long, default_value_os_t = std::env::current_dir().unwrap())]
    pub(crate) cwd: PathBuf,
    /// Base directory that stores recordings. Default to .recordit in the git repository root or current working directory.
    #[arg(long, default_value_os_t = PathBuf::from(".recordit"))]
    pub(crate) record_base: PathBuf,
}

pub(crate) struct Context {
    pub(crate) git_root: Option<PathBuf>,
    pub(crate) session_dir: Option<PathBuf>,
}

fn init_tracing() {
    use tracing_subscriber::prelude::*;
    use tracing_subscriber::{EnvFilter, fmt};

    #[cfg(debug_assertions)]
    let fmt_layer = fmt::layer().pretty().with_file(true).with_line_number(true);
    #[cfg(not(debug_assertions))]
    let fmt_layer = fmt::layer().pretty();

    #[cfg(debug_assertions)]
    let filter_layer = EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_new("debug"))
        .unwrap();
    #[cfg(not(debug_assertions))]
    let filter_layer = EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_new("info"))
        .unwrap();

    tracing_subscriber::registry()
        .with(filter_layer)
        .with(fmt_layer)
        .init();
}

fn resolve_record_base(cwd: &Path, record_base: &Path, context: &mut Context) -> PathBuf {
    use git2;

    let repo = git2::Repository::discover(cwd).ok();
    let mut base_dir = record_base.to_path_buf();

    if let Some(repo) = repo {
        if let Some(root) = repo.workdir() {
            let root = root.to_path_buf();
            context.git_root = Some(root.clone());

            if !base_dir.is_absolute() {
                base_dir = root.join(base_dir);
            }

            tracing::info!(
                "Using git repository root as record base: {}",
                base_dir.display()
            );
        } else {
            tracing::warn!(
                "Bare repository detected, using current working directory as record base"
            );
            if !base_dir.is_absolute() {
                base_dir = cwd.join(base_dir);
            }
            tracing::info!("Recording directory resolved to: {}", base_dir.display());
        }
    } else {
        if !base_dir.is_absolute() {
            base_dir = cwd.join(base_dir);
        }
        tracing::info!("Using current working directory as record base");
        tracing::info!("Recording directory resolved to: {}", base_dir.display());
    }

    base_dir
}

async fn ensure_record_base(record_base: &Path) -> Result<()> {
    match async_fs::metadata(record_base).await {
        Ok(_) => Ok(()),
        Err(err) if err.kind() == ErrorKind::NotFound => {
            async_fs::create_dir_all(record_base)
                .await
                .with_context(|| {
                    format!(
                        "Failed to create record base directory {}",
                        record_base.display()
                    )
                })?;
            tracing::info!("Created record base directory: {}", record_base.display());
            Ok(())
        }
        Err(_) => bail!(
            "Cannot read {}. Check permissions and try again.",
            record_base.display()
        ),
    }
}

async fn handle_run(mut args: RunArgs) -> Result<()> {
    tracing::debug!("cwd: {}", args.cwd.display());

    let mut context = Context {
        git_root: None,
        session_dir: None,
    };

    let record_base = resolve_record_base(&args.cwd, &args.record_base, &mut context);
    ensure_record_base(&record_base).await?;
    args.record_base = record_base;

    tracing::debug!("record_base: {}", args.record_base.display());

    recorder::record_files(&args, &mut context).await?;

    if let Some(session_dir) = &context.session_dir {
        tracing::info!("Recorded files stored at {}", session_dir.display());
    } else {
        tracing::warn!("Recording completed but session directory was not captured");
    }

    tracing::debug!("version name: {}", args.version_name);
    tracing::debug!("commands: {:?}", args.cmd);

    executor::execute_command(&args, &context).await?;

    Ok(())
}

async fn handle_clean(args: CleanArgs) -> Result<()> {
    let mut context = Context {
        git_root: None,
        session_dir: None,
    };

    let record_base = resolve_record_base(&args.cwd, &args.record_base, &mut context);

    match async_fs::metadata(&record_base).await {
        Ok(meta) => {
            if !meta.is_dir() {
                bail!(
                    "{} exists but is not a directory. Aborting clean.",
                    record_base.display()
                );
            }
        }
        Err(err) if err.kind() == ErrorKind::NotFound => {
            tracing::info!(
                "No recording directory found at {}, nothing to clean",
                record_base.display()
            );
            return Ok(());
        }
        Err(err) => bail!("Failed to read {}: {}", record_base.display(), err),
    }

    let mut removed_entries = 0usize;
    let mut dir = async_fs::read_dir(&record_base)
        .await
        .with_context(|| format!("Failed to read {}", record_base.display()))?;
    while let Some(entry) = dir
        .next_entry()
        .await
        .with_context(|| format!("Failed to read {}", record_base.display()))?
    {
        let path = entry.path();
        let file_type = entry
            .file_type()
            .await
            .with_context(|| format!("Failed to inspect {}", path.display()))?;
        if file_type.is_dir() {
            async_fs::remove_dir_all(&path)
                .await
                .with_context(|| format!("Failed to remove directory {}", path.display()))?;
        } else {
            async_fs::remove_file(&path)
                .await
                .with_context(|| format!("Failed to remove file {}", path.display()))?;
        }
        removed_entries += 1;
    }

    if removed_entries == 0 {
        tracing::info!(
            "Recording directory {} was already empty",
            record_base.display()
        );
    } else {
        tracing::info!(
            "Removed {} entr{} from {}",
            removed_entries,
            if removed_entries == 1 { "y" } else { "ies" },
            record_base.display()
        );
    }

    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();

    let cli = Cli::parse();

    match cli.command {
        Commands::Run(args) => handle_run(args).await,
        Commands::Clean(args) => handle_clean(args).await,
    }
}
