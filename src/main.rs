use anyhow::Result;
use clap::Parser;

mod executor;
mod recorder;

#[derive(clap::Parser)]
#[command(trailing_var_arg = true)]
pub(crate) struct Args {
    /// Current working directory. Default to current working directory.
    #[arg(long, default_value_t = std::env::current_dir().unwrap().to_string_lossy().to_string())]
    pub(crate) cwd: String,
    /// Base directory to store recordings. Default to .recordit in the git repository root or current working directory.
    #[arg(long, default_value_t = String::from(".recordit"))]
    pub(crate) record_base: String,
    /// Version name for this recording session. Default to YYYYMMDD-HHMMSS.
    #[arg(short = 'n', long, default_value_t = chrono::Local::now().format("%Y%m%d-%H%M%S").to_string())]
    pub(crate) version_name: String,
    /// Opitonal message for this recording session.
    #[arg(short = 'm', long, default_value_t = String::from(""))]
    pub(crate) message: String,
    /// Command to execute and record.
    #[arg(required = true)]
    pub(crate) cmd: Vec<String>,
}

pub(crate) struct Context {
    pub(crate) git_root: Option<String>,
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

fn search_record_base(args: &mut Args, context: &mut Context) {
    use git2;
    let repo = git2::Repository::discover(".").ok();
    if let Some(repo) = repo {
        let root = repo.workdir();
        if let Some(root) = root {
            tracing::info!(
                "Using git repository root as record base: {}",
                root.display()
            );
            let root = root.to_string_lossy().into_owned();
            args.record_base = root.clone();
            context.git_root = Some(root);
        } else {
            tracing::warn!(
                "Bare repository detected, using current working directory as record base"
            );
        }
    } else {
        tracing::info!("Using current working directory as record base");
    }
}

fn main() -> Result<()> {
    init_tracing();

    let mut args = Args::parse();

    tracing::debug!("cwd: {}", args.cwd);

    let mut context = Context {
        git_root: None,
    };
    search_record_base(&mut args, &mut context);

    tracing::debug!("record_base: {}", args.record_base);

    if let Ok(exists) = std::fs::exists(&args.record_base) {
        if !exists {
            std::fs::create_dir_all(&args.record_base).unwrap();
            tracing::info!("Created record base directory: {}", args.record_base);
        }
    } else {
        tracing::error!("Cannot read {}.", args.record_base);
        tracing::error!("Check permissions and try again.");
        std::process::exit(1);
    }

    tracing::debug!("version name: {}", args.version_name);
    tracing::debug!("commands: {:?}", args.cmd);

    Ok(())
}
