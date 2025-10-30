use std::collections::BTreeMap;
use std::io::ErrorKind;
use std::path::{Component, Path, PathBuf};

use anyhow::{Context as _, Result, bail};
use tokio::fs as async_fs;
#[cfg(any(unix, windows))]
use tokio::task::spawn_blocking;
use tracing::warn;

/// Record specified files into the session directory and store its path inside the context.
pub async fn record_files(args: &crate::RunArgs, context: &mut crate::Context) -> Result<()> {
    let base_dir = args.record_base.clone();
    let session_dir =
        prepare_session_directory(&base_dir, &args.version_name, &args.message).await?;
    let files_dir = session_dir.join("files");
    async_fs::create_dir_all(&files_dir)
        .await
        .with_context(|| format!("Failed to create files directory {}", files_dir.display()))?;

    if !args.message.trim().is_empty() {
        async_fs::write(session_dir.join("MESSAGE.txt"), args.message.as_bytes())
            .await
            .with_context(|| {
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

    collect_explicit_files(args, context, &mut files_to_copy).await;

    for (relative_destination, source) in &files_to_copy {
        let destination = files_dir.join(relative_destination);
        if let Some(parent) = destination.parent() {
            async_fs::create_dir_all(parent).await.with_context(|| {
                format!("Failed to create parent directory {}", parent.display())
            })?;
        }

        copy_entry(source, &destination).await?;
    }

    context.session_dir = Some(session_dir);

    Ok(())
}

async fn prepare_session_directory(
    base: &Path,
    version_name: &str,
    message: &str,
) -> Result<PathBuf> {
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
    match async_fs::metadata(&session_dir).await {
        Ok(_) => {
            bail!(
                "Recording directory {} already exists",
                session_dir.display()
            );
        }
        Err(err) if err.kind() == ErrorKind::NotFound => {
            async_fs::create_dir_all(&session_dir)
                .await
                .with_context(|| {
                    format!(
                        "Failed to create recording directory {}",
                        session_dir.display()
                    )
                })?;
        }
        Err(err) => bail!(
            "Failed to inspect recording directory {}: {}",
            session_dir.display(),
            err
        ),
    }

    Ok(session_dir)
}

/// Note: git2 offers blocking APIs only, and at this stage there are no competing async tasks,
/// so we keep this logic synchronous.
fn collect_git_tracked_files(
    git_root: &Path,
    files_to_copy: &mut BTreeMap<PathBuf, PathBuf>,
) -> Result<()> {
    let repo = git2::Repository::open(git_root)?;
    let index = repo.index()?;

    for entry in index.iter() {
        if let Some(relative_path) = index_entry_path(&entry) {
            let source = git_root.join(&relative_path);
            let metadata = match std::fs::symlink_metadata(&source) {
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

async fn collect_explicit_files(
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

        let metadata = match async_fs::symlink_metadata(&source).await {
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

async fn copy_entry(source: &Path, destination: &Path) -> Result<()> {
    let metadata = async_fs::symlink_metadata(source)
        .await
        .with_context(|| format!("Failed to read metadata for {}", source.display()))?;

    if metadata.file_type().is_symlink() {
        copy_symlink(source, destination).await?;
        return Ok(());
    }

    if metadata.is_file() {
        async_fs::copy(source, destination).await.with_context(|| {
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

async fn copy_symlink(source: &Path, destination: &Path) -> Result<()> {
    let target = async_fs::read_link(source)
        .await
        .with_context(|| format!("Failed to read symlink target for {}", source.display()))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;

        let dest_clone = destination.to_path_buf();
        let target_clone = target.clone();
        spawn_blocking(move || symlink(&target_clone, &dest_clone))
            .await
            .context("Failed to join symlink creation task")?
            .with_context(|| {
                format!(
                    "Failed to create symlink {} -> {}",
                    destination.display(),
                    target.display()
                )
            })?;
    }

    #[cfg(windows)]
    {
        use std::os::windows::fs::{symlink_dir, symlink_file};

        let mut treat_as_dir = false;
        if let Ok(meta) = async_fs::metadata(source).await {
            if meta.is_dir() {
                treat_as_dir = true;
            }
        }

        let dest_clone = destination.to_path_buf();
        let target_clone = target.clone();
        spawn_blocking(move || -> std::io::Result<()> {
            if treat_as_dir {
                symlink_dir(&target_clone, &dest_clone)
            } else {
                match symlink_file(&target_clone, &dest_clone) {
                    Ok(()) => Ok(()),
                    Err(err) if err.kind() == ErrorKind::InvalidInput => {
                        symlink_dir(&target_clone, &dest_clone)
                    }
                    Err(err) => Err(err),
                }
            }
        })
        .await
        .context("Failed to join symlink creation task")?
        .with_context(|| {
            format!(
                "Failed to create symlink {} -> {}",
                destination.display(),
                target.display()
            )
        })?;
    }

    #[cfg(not(any(unix, windows)))]
    {
        warn!(
            "Symlink recording is not supported on this platform; writing placeholder for {}",
            destination.display()
        );
        async_fs::write(
            destination,
            format!("recordit_symlink_target: {}\n", target.display()),
        )
        .await
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
    if let Some(git_root) = &context.git_root
        && let Ok(relative) = source.strip_prefix(git_root) {
            return relative.to_path_buf();
        }

    let cwd = &args.cwd;
    if let Ok(relative) = source.strip_prefix(cwd) {
        return relative.to_path_buf();
    }

    let mut sanitized = PathBuf::from("__external__");
    for component in source.components() {
        if let Component::Normal(part) = component
            && let Some(component) = sanitize_component(part) {
                sanitized.push(component);
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

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn new_context() -> crate::Context {
        crate::Context {
            git_root: None,
            session_dir: None,
        }
    }

    #[tokio::test]
    async fn prepare_session_directory_creates_unique_directory() -> Result<()> {
        let base = TempDir::new().expect("tempdir");
        let session = prepare_session_directory(base.path(), "v1", "My Note").await?;

        assert!(session.exists());
        let name = session.file_name().unwrap().to_string_lossy();
        assert!(name.contains("v1"));
        assert!(name.contains("My_Note"));

        let err = prepare_session_directory(base.path(), "v1", "My Note")
            .await
            .expect_err("should conflict");
        assert!(format!("{err:?}").contains("already exists"));
        Ok(())
    }

    #[test]
    fn collect_git_tracked_files_stages_index_entries() -> Result<()> {
        let repo_dir = TempDir::new().expect("tempdir");
        let repo = git2::Repository::init(repo_dir.path())?;
        let tracked_path = repo_dir.path().join("tracked.txt");
        std::fs::write(&tracked_path, b"tracked")?;

        let mut index = repo.index()?;
        index.add_path(Path::new("tracked.txt"))?;
        index.write()?;

        let mut files = BTreeMap::new();
        collect_git_tracked_files(repo.workdir().unwrap(), &mut files)?;

        let key = PathBuf::from("tracked.txt");
        assert_eq!(files.get(&key), Some(&tracked_path));
        Ok(())
    }

    #[tokio::test]
    async fn collect_explicit_files_honours_relative_and_absolute_paths() -> Result<()> {
        let project = TempDir::new().expect("tempdir");
        let cwd = project.path().join("workspace");
        tokio::fs::create_dir_all(&cwd).await?;
        let relative_file = cwd.join("note.txt");
        tokio::fs::write(&relative_file, b"hello").await?;

        let external_dir = TempDir::new().expect("external");
        let external_file = external_dir.path().join("external.txt");
        tokio::fs::write(&external_file, b"outside").await?;

        let args = crate::RunArgs {
            cwd: cwd.clone(),
            record_base: PathBuf::from(".recordit"),
            version_name: "v1".to_string(),
            message: String::new(),
            record: vec![
                "note.txt".to_string(),
                external_file.to_string_lossy().to_string(),
            ],
            stdin: None,
            cmd: vec!["echo".to_string()],
        };
        let context = new_context();
        let mut files = BTreeMap::new();

        collect_explicit_files(&args, &context, &mut files).await;

        let expected_relative = PathBuf::from("note.txt");
        assert_eq!(files.get(&expected_relative), Some(&relative_file));

        let external_key = compute_relative_destination(&external_file, &context, &args);
        assert_eq!(files.get(&external_key), Some(&external_file));

        Ok(())
    }

    #[tokio::test]
    async fn copy_entry_copies_regular_files() -> Result<()> {
        let temp = TempDir::new().expect("tempdir");
        let source = temp.path().join("source.txt");
        tokio::fs::write(&source, b"contents").await?;
        let destination = temp.path().join("destination.txt");

        copy_entry(&source, &destination).await?;

        let copied = tokio::fs::read(&destination).await?;
        assert_eq!(copied, b"contents");
        Ok(())
    }

    #[tokio::test]
    async fn copy_entry_rejects_directories() -> Result<()> {
        let temp = TempDir::new().expect("tempdir");
        let source_dir = temp.path().join("dir");
        tokio::fs::create_dir_all(&source_dir).await?;
        let destination = temp.path().join("destination");

        let err = copy_entry(&source_dir, &destination)
            .await
            .expect_err("should fail");
        assert!(format!("{err}").contains("Unsupported entry type"));
        Ok(())
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn copy_entry_preserves_symlinks() -> Result<()> {
        use std::os::unix::fs::symlink;

        let temp = TempDir::new().expect("tempdir");
        let target = temp.path().join("target.txt");
        tokio::fs::write(&target, b"link target").await?;
        let source = temp.path().join("source.lnk");
        symlink(&target, &source).expect("create symlink");
        let destination = temp.path().join("copied.lnk");

        copy_entry(&source, &destination).await?;

        let copied_target = tokio::fs::read_link(&destination).await?;
        assert_eq!(copied_target, target);
        Ok(())
    }

    #[test]
    fn compute_relative_destination_prefers_git_root() {
        let repo_dir = TempDir::new().expect("tempdir");
        let file = repo_dir.path().join("src").join("main.rs");
        std::fs::create_dir_all(file.parent().unwrap()).expect("create dir");
        std::fs::write(&file, b"fn main() {}").expect("write file");

        let context = crate::Context {
            git_root: Some(repo_dir.path().to_path_buf()),
            session_dir: None,
        };
        let args = crate::RunArgs {
            cwd: repo_dir.path().join("workspace"),
            record_base: PathBuf::from(".recordit"),
            version_name: String::new(),
            message: String::new(),
            record: Vec::new(),
            stdin: None,
            cmd: vec!["echo".to_string()],
        };

        let relative = compute_relative_destination(&file, &context, &args);
        assert_eq!(relative, PathBuf::from("src").join("main.rs"));
    }

    #[test]
    fn compute_relative_destination_uses_cwd_when_no_git() {
        let project = TempDir::new().expect("tempdir");
        let cwd = project.path().join("cwd");
        std::fs::create_dir_all(&cwd).expect("create cwd");
        let file = cwd.join("file.txt");
        std::fs::write(&file, b"content").expect("write file");

        let context = new_context();
        let args = crate::RunArgs {
            cwd: cwd.clone(),
            record_base: PathBuf::from(".recordit"),
            version_name: String::new(),
            message: String::new(),
            record: Vec::new(),
            stdin: None,
            cmd: vec!["echo".to_string()],
        };

        let relative = compute_relative_destination(&file, &context, &args);
        assert_eq!(relative, PathBuf::from("file.txt"));
    }

    #[test]
    fn sanitize_for_path_discards_empty_names() {
        assert_eq!(sanitize_for_path("   "), None);
        assert_eq!(sanitize_for_path("$$"), None);
        assert_eq!(
            sanitize_for_path("Hello World"),
            Some("Hello_World".to_string())
        );
    }

    #[tokio::test]
    async fn record_files_copies_tracked_and_explicit_files() -> Result<()> {
        let project = TempDir::new().expect("tempdir");
        let repo = git2::Repository::init(project.path())?;

        let tracked_path = project.path().join("tracked.txt");
        tokio::fs::write(&tracked_path, b"tracked").await?;
        let mut index = repo.index()?;
        index.add_path(Path::new("tracked.txt"))?;
        index.write()?;

        let extra_path = project.path().join("extra.txt");
        tokio::fs::write(&extra_path, b"extra").await?;

        let record_base = project.path().join("records");
        let args = crate::RunArgs {
            cwd: project.path().to_path_buf(),
            record_base: record_base.clone(),
            version_name: "version".to_string(),
            message: "memo".to_string(),
            record: vec!["extra.txt".to_string()],
            stdin: None,
            cmd: vec!["echo".to_string()],
        };
        let mut context = crate::Context {
            git_root: Some(project.path().to_path_buf()),
            session_dir: None,
        };

        record_files(&args, &mut context).await?;

        let session_dir = context
            .session_dir
            .as_ref()
            .expect("session directory should be recorded");
        let files_dir = session_dir.join("files");
        let tracked_copy = tokio::fs::read(files_dir.join("tracked.txt")).await?;
        assert_eq!(tracked_copy, b"tracked");
        let extra_copy = tokio::fs::read(files_dir.join("extra.txt")).await?;
        assert_eq!(extra_copy, b"extra");
        let message = tokio::fs::read_to_string(session_dir.join("MESSAGE.txt")).await?;
        assert_eq!(message, "memo");

        Ok(())
    }
}
