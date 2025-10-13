use std::collections::BTreeMap;
use std::fs;
use std::path::{Component, Path, PathBuf};

use anyhow::{Context as _, Result, bail};
use tracing::warn;

/// Record specified files into the session directory and store its path inside the context.
pub fn record_files(args: &crate::RunArgs, context: &mut crate::Context) -> Result<()> {
    let base_dir = args.record_base.clone();
    let session_dir = prepare_session_directory(&base_dir, &args.version_name, &args.message)?;
    let files_dir = session_dir.join("files");
    fs::create_dir_all(&files_dir)
        .with_context(|| format!("Failed to create files directory {}", files_dir.display()))?;

    if !args.message.trim().is_empty() {
        fs::write(session_dir.join("MESSAGE.txt"), args.message.as_bytes()).with_context(|| {
            format!(
                "Failed to write message file under {}",
                session_dir.display()
            )
        })?;
    }

    let mut files_to_copy: BTreeMap<PathBuf, PathBuf> = BTreeMap::new();

    if let Some(git_root) = &context.git_root {
        collect_git_tracked_files(git_root, &mut files_to_copy)?;
    }

    collect_explicit_files(args, context, &mut files_to_copy);

    for (relative_destination, source) in &files_to_copy {
        let destination = files_dir.join(relative_destination);
        if let Some(parent) = destination.parent() {
            fs::create_dir_all(parent).with_context(|| {
                format!("Failed to create parent directory {}", parent.display())
            })?;
        }

        copy_entry(source, &destination)?;
    }

    context.session_dir = Some(session_dir);

    Ok(())
}

fn prepare_session_directory(base: &Path, version_name: &str, message: &str) -> Result<PathBuf> {
    let mut directory_name = sanitize_for_path(version_name)
        .context("Version name cannot be empty after sanitization")?;
    if directory_name == "." || directory_name == ".." {
        bail!("Version name cannot be '.' or '..'");
    }
    let sanitized_message = sanitize_for_path(message);
    if let Some(extra) = sanitized_message {
        directory_name.push('-');
        directory_name.push_str(&extra);
    }

    let session_dir = base.join(directory_name);
    if session_dir.exists() {
        bail!(
            "Recording directory {} already exists",
            session_dir.display()
        );
    }

    fs::create_dir_all(&session_dir).with_context(|| {
        format!(
            "Failed to create recording directory {}",
            session_dir.display()
        )
    })?;

    Ok(session_dir)
}

fn collect_git_tracked_files(
    git_root: &Path,
    files_to_copy: &mut BTreeMap<PathBuf, PathBuf>,
) -> Result<()> {
    let repo = git2::Repository::open(git_root)?;
    let index = repo.index()?;

    for entry in index.iter() {
        if let Some(relative_path) = index_entry_path(&entry) {
            let source = git_root.join(&relative_path);
            let metadata = match fs::symlink_metadata(&source) {
                Ok(metadata) => metadata,
                Err(err) => {
                    warn!(
                        "Could not read metadata for tracked file {}: {err}",
                        source.display()
                    );
                    continue;
                }
            };
            if metadata.is_dir() && !metadata.file_type().is_symlink() {
                warn!(
                    "Tracked entry {} is a directory, skipping",
                    source.display()
                );
                continue;
            }

            files_to_copy
                .entry(relative_path)
                .or_insert_with(|| source.clone());
        }
    }

    Ok(())
}

fn collect_explicit_files(
    args: &crate::RunArgs,
    context: &crate::Context,
    files_to_copy: &mut BTreeMap<PathBuf, PathBuf>,
) {
    for raw_path in &args.record {
        let candidate = PathBuf::from(raw_path);
        let source = if candidate.is_absolute() {
            candidate
        } else {
            args.cwd.join(&candidate)
        };

        let metadata = match fs::symlink_metadata(&source) {
            Ok(metadata) => metadata,
            Err(err) => {
                warn!(
                    "Explicit record target {} is not accessible: {err}, skipping",
                    source.display()
                );
                continue;
            }
        };
        if metadata.is_dir() && !metadata.file_type().is_symlink() {
            warn!(
                "Explicit record target {} is a directory, skipping",
                source.display()
            );
            continue;
        }

        let relative_destination = compute_relative_destination(&source, context, args);
        files_to_copy
            .entry(relative_destination)
            .or_insert_with(|| source.clone());
    }
}

fn copy_entry(source: &Path, destination: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(source)
        .with_context(|| format!("Failed to read metadata for {}", source.display()))?;

    if metadata.file_type().is_symlink() {
        copy_symlink(source, destination)?;
        return Ok(());
    }

    if metadata.is_file() {
        fs::copy(source, destination).with_context(|| {
            format!(
                "Failed to copy {} to {}",
                source.display(),
                destination.display()
            )
        })?;
        return Ok(());
    }

    bail!(
        "Unsupported entry type for {}. Only files and symlinks are recorded.",
        source.display()
    );
}

fn copy_symlink(source: &Path, destination: &Path) -> Result<()> {
    let target = fs::read_link(source)
        .with_context(|| format!("Failed to read symlink target for {}", source.display()))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;

        symlink(&target, destination).with_context(|| {
            format!(
                "Failed to create symlink {} -> {}",
                destination.display(),
                target.display()
            )
        })?;
    }

    #[cfg(windows)]
    {
        use std::io::ErrorKind;
        use std::os::windows::fs::{symlink_dir, symlink_file};

        if let Ok(meta) = fs::metadata(source) {
            if meta.is_dir() {
                symlink_dir(&target, destination).with_context(|| {
                    format!(
                        "Failed to create directory symlink {} -> {}",
                        destination.display(),
                        target.display()
                    )
                })?;
                return Ok(());
            }
        }

        match symlink_file(&target, destination) {
            Ok(()) => {}
            Err(err) if err.kind() == ErrorKind::InvalidInput => {
                symlink_dir(&target, destination).with_context(|| {
                    format!(
                        "Failed to create directory symlink {} -> {}",
                        destination.display(),
                        target.display()
                    )
                })?;
            }
            Err(err) => {
                bail!(
                    "Failed to create file symlink {} -> {}: {err}",
                    destination.display(),
                    target.display()
                );
            }
        }
    }

    #[cfg(not(any(unix, windows)))]
    {
        warn!(
            "Symlink recording is not supported on this platform; writing placeholder for {}",
            destination.display()
        );
        fs::write(
            destination,
            format!("recordit_symlink_target: {}\n", target.display()),
        )
        .with_context(|| {
            format!(
                "Failed to serialise symlink {} -> {}",
                destination.display(),
                target.display()
            )
        })?;
    }

    Ok(())
}

fn compute_relative_destination(
    source: &Path,
    context: &crate::Context,
    args: &crate::RunArgs,
) -> PathBuf {
    if let Some(git_root) = &context.git_root {
        if let Ok(relative) = source.strip_prefix(git_root) {
            return relative.to_path_buf();
        }
    }

    let cwd = &args.cwd;
    if let Ok(relative) = source.strip_prefix(cwd) {
        return relative.to_path_buf();
    }

    let mut sanitized = PathBuf::from("__external__");
    for component in source.components() {
        if let Component::Normal(part) = component {
            if let Some(component) = sanitize_component(part) {
                sanitized.push(component);
            }
        }
    }

    if sanitized == Path::new("__external__") {
        sanitized.push("unknown");
    }

    sanitized
}

#[cfg(unix)]
fn sanitize_component(part: &std::ffi::OsStr) -> Option<PathBuf> {
    use std::os::unix::ffi::OsStrExt;
    let lossy = String::from_utf8_lossy(part.as_bytes());
    let sanitized = sanitize_string(&lossy);
    let trimmed = sanitized.trim_matches('_');
    if trimmed.is_empty() {
        None
    } else {
        Some(PathBuf::from(trimmed))
    }
}

#[cfg(not(unix))]
fn sanitize_component(part: &std::ffi::OsStr) -> Option<PathBuf> {
    let lossy = part.to_string_lossy();
    let sanitized = sanitize_string(&lossy);
    let trimmed = sanitized.trim_matches('_');
    if trimmed.is_empty() {
        None
    } else {
        Some(PathBuf::from(trimmed))
    }
}

fn sanitize_string(input: &str) -> String {
    input
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '.' || ch == '-' || ch == '_' {
                ch
            } else {
                '_'
            }
        })
        .collect()
}

fn sanitize_for_path(message: &str) -> Option<String> {
    let trimmed = message.trim();
    if trimmed.is_empty() {
        return None;
    }

    let sanitized = sanitize_string(trimmed);
    let trimmed = sanitized.trim_matches('_');
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

fn index_entry_path(entry: &git2::IndexEntry) -> Option<PathBuf> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStringExt;
        Some(std::ffi::OsString::from_vec(entry.path.clone()).into())
    }
    #[cfg(not(unix))]
    {
        use std::str;
        str::from_utf8(&entry.path).ok().map(PathBuf::from)
    }
}
