use crate::secure_fs::hex_sha256;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::ffi::{OsStr, OsString};
use std::fs::{self, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

const MAX_FILES: usize = 100_000;
const MAX_TOTAL: u64 = 5 * 1024 * 1024 * 1024;
const MAX_FILE: u64 = 512 * 1024 * 1024;
static SNAPSHOT_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Serialize)]
pub struct Snapshot {
    pub root: PathBuf,
    pub manifest_sha256: String,
    pub file_count: usize,
    pub total_bytes: u64,
    pub git_head: Option<String>,
    pub git_diff: GitDiffMetadata,
    pub entries: Vec<SnapshotEntry>,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct GitDiffMetadata {
    pub staged_files: usize,
    pub unstaged_files: usize,
    pub untracked_files: usize,
}

#[derive(Debug, Serialize)]
pub struct SnapshotEntry {
    pub path_hex: String,
    pub kind: String,
    pub mode: u32,
    pub content_sha256: String,
}

#[derive(Debug)]
struct SourceEntry {
    path: PathBuf,
    path_bytes: Vec<u8>,
    kind: EntryKind,
    mode: u32,
    size: u64,
    content_sha256: String,
    symlink_target: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Copy)]
enum EntryKind {
    File,
    Symlink,
}

impl EntryKind {
    fn label(self) -> &'static str {
        match self {
            Self::File => "file",
            Self::Symlink => "symlink",
        }
    }
}

pub fn create_snapshot(repo: &Path, output_parent: &Path) -> io::Result<Snapshot> {
    let repo = repo.canonicalize()?;
    let output_parent = output_parent.canonicalize()?;
    if output_parent.starts_with(&repo) {
        return Err(io::Error::other(
            "snapshot output must be outside the repository",
        ));
    }
    verify_repo_root(&repo)?;
    reject_submodules(&repo)?;
    let listed = git_output(
        &repo,
        &[
            "ls-files",
            "-z",
            "--cached",
            "--others",
            "--exclude-standard",
        ],
    )?;
    let paths = listed
        .split(|byte| *byte == 0)
        .filter(|value| !value.is_empty())
        .map(|value| {
            validate_relative_bytes(value)?;
            Ok(PathBuf::from(OsString::from_vec(value.to_vec())))
        })
        .collect::<io::Result<Vec<_>>>()?;
    if paths.len() > MAX_FILES {
        return Err(io::Error::other("snapshot has too many files"));
    }
    let selected = paths
        .iter()
        .map(|path| path.as_os_str().as_bytes().to_vec())
        .collect::<BTreeSet<_>>();
    let mut entries = Vec::new();
    let mut total = 0u64;
    for relative in paths {
        let absolute = repo.join(&relative);
        let metadata = fs::symlink_metadata(&absolute)?;
        let mode = metadata.permissions().mode() & 0o111;
        if metadata.file_type().is_symlink() {
            let target = fs::read_link(&absolute)?;
            validate_internal_symlink(&relative, &target, &selected)?;
            let content = target.as_os_str().as_bytes().to_vec();
            total = total
                .checked_add(content.len() as u64)
                .ok_or_else(|| io::Error::other("snapshot size overflow"))?;
            entries.push(SourceEntry {
                path_bytes: relative.as_os_str().as_bytes().to_vec(),
                path: relative,
                kind: EntryKind::Symlink,
                mode,
                size: content.len() as u64,
                content_sha256: hex_sha256(&content),
                symlink_target: Some(content),
            });
        } else if metadata.is_file() {
            if metadata.len() > MAX_FILE {
                return Err(io::Error::other("snapshot file is too large"));
            }
            let (content_sha256, size) = hash_regular_nofollow(&absolute, MAX_FILE)?;
            total = total
                .checked_add(size)
                .ok_or_else(|| io::Error::other("snapshot size overflow"))?;
            entries.push(SourceEntry {
                path_bytes: relative.as_os_str().as_bytes().to_vec(),
                path: relative,
                kind: EntryKind::File,
                mode,
                size,
                content_sha256,
                symlink_target: None,
            });
        } else {
            return Err(io::Error::other("snapshot contains a special file"));
        }
        if total > MAX_TOTAL {
            return Err(io::Error::other("snapshot is too large"));
        }
    }
    entries.sort_by(|left, right| left.path_bytes.cmp(&right.path_bytes));
    let manifest_bytes = manifest_bytes(&entries);
    let manifest_sha256 = hex_sha256(&manifest_bytes);
    let run = output_parent.join(format!(
        "snapshot-{}-{}",
        std::process::id(),
        SNAPSHOT_COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir(&run)?;
    fs::set_permissions(&run, fs::Permissions::from_mode(0o700))?;
    let snapshot_root = run.join("tree");
    fs::create_dir(&snapshot_root)?;
    for entry in &entries {
        let destination = snapshot_root.join(&entry.path);
        if let Some(parent) = destination.parent() {
            fs::create_dir_all(parent)?;
        }
        match entry.kind {
            EntryKind::File => {
                copy_regular_nofollow(
                    &repo.join(&entry.path),
                    &destination,
                    entry.mode,
                    entry.size,
                    &entry.content_sha256,
                )?;
            }
            EntryKind::Symlink => {
                let target = entry
                    .symlink_target
                    .as_deref()
                    .ok_or_else(|| io::Error::other("symlink target is missing"))?;
                std::os::unix::fs::symlink(OsStr::from_bytes(target), &destination)?;
            }
        }
    }
    verify_frozen_copy(&snapshot_root, &entries)?;
    verify_sources_unchanged(&repo, &entries)?;
    let relisted = git_output(
        &repo,
        &[
            "ls-files",
            "-z",
            "--cached",
            "--others",
            "--exclude-standard",
        ],
    )?;
    let relisted = relisted
        .split(|byte| *byte == 0)
        .filter(|value| !value.is_empty())
        .map(|value| value.to_vec())
        .collect::<BTreeSet<_>>();
    if relisted != selected {
        return Err(io::Error::other(
            "repository file set changed while the snapshot was created",
        ));
    }
    let result_entries = entries
        .iter()
        .map(|entry| SnapshotEntry {
            path_hex: bytes_hex(&entry.path_bytes),
            kind: entry.kind.label().into(),
            mode: entry.mode,
            content_sha256: entry.content_sha256.clone(),
        })
        .collect();
    let git_head = git_head(&repo)?;
    let git_diff = git_diff_metadata(&repo)?;
    Ok(Snapshot {
        root: snapshot_root,
        manifest_sha256,
        file_count: entries.len(),
        total_bytes: total,
        git_head,
        git_diff,
        entries: result_entries,
    })
}

pub(crate) fn verify_snapshot(snapshot: &Snapshot) -> io::Result<()> {
    let mut manifest = Vec::new();
    let mut expected_files = BTreeSet::new();
    let mut expected_directories = BTreeSet::new();
    for entry in &snapshot.entries {
        let path_bytes = decode_hex(&entry.path_hex)?;
        expected_files.insert(path_bytes.clone());
        let relative = PathBuf::from(OsString::from_vec(path_bytes.clone()));
        let mut parent = relative.parent();
        while let Some(value) = parent.filter(|value| !value.as_os_str().is_empty()) {
            expected_directories.insert(value.as_os_str().as_bytes().to_vec());
            parent = value.parent();
        }
        validate_relative_bytes(&path_bytes)?;
        let path = snapshot.root.join(relative);
        let metadata = fs::symlink_metadata(&path)?;
        let expected_kind_matches = match entry.kind.as_str() {
            "file" => metadata.is_file(),
            "symlink" => metadata.file_type().is_symlink(),
            _ => false,
        };
        if !expected_kind_matches || metadata.permissions().mode() & 0o111 != entry.mode {
            return Err(io::Error::other("snapshot metadata changed after freezing"));
        }
        let content_sha256 = match entry.kind.as_str() {
            "file" => hash_regular_nofollow(&path, MAX_FILE)?.0,
            "symlink" => hex_sha256(fs::read_link(path)?.as_os_str().as_bytes()),
            _ => return Err(io::Error::other("snapshot manifest has an invalid kind")),
        };
        if content_sha256 != entry.content_sha256 {
            return Err(io::Error::other("snapshot changed after freezing"));
        }
        push_field(&mut manifest, entry.kind.as_bytes());
        push_field(&mut manifest, &entry.mode.to_be_bytes());
        push_field(&mut manifest, &path_bytes);
        push_field(&mut manifest, entry.content_sha256.as_bytes());
    }
    if hex_sha256(&manifest) != snapshot.manifest_sha256 {
        return Err(io::Error::other("snapshot manifest changed"));
    }
    let mut actual_files = BTreeSet::new();
    let mut actual_directories = BTreeSet::new();
    collect_snapshot_nodes(
        &snapshot.root,
        Path::new(""),
        &mut actual_files,
        &mut actual_directories,
    )?;
    if actual_files != expected_files || actual_directories != expected_directories {
        return Err(io::Error::other("snapshot file set changed after freezing"));
    }
    Ok(())
}

fn collect_snapshot_nodes(
    root: &Path,
    relative: &Path,
    files: &mut BTreeSet<Vec<u8>>,
    directories: &mut BTreeSet<Vec<u8>>,
) -> io::Result<()> {
    for entry in fs::read_dir(root.join(relative))? {
        let entry = entry?;
        let child = relative.join(entry.file_name());
        let metadata = fs::symlink_metadata(entry.path())?;
        if metadata.is_dir() {
            directories.insert(child.as_os_str().as_bytes().to_vec());
            collect_snapshot_nodes(root, &child, files, directories)?;
        } else if metadata.is_file() || metadata.file_type().is_symlink() {
            files.insert(child.as_os_str().as_bytes().to_vec());
        } else {
            return Err(io::Error::other("snapshot contains a special file"));
        }
    }
    Ok(())
}

fn verify_repo_root(repo: &Path) -> io::Result<()> {
    let output = git_output(repo, &["rev-parse", "--show-toplevel"])?;
    let reported = PathBuf::from(OsString::from_vec(
        output.strip_suffix(b"\n").unwrap_or(&output).to_vec(),
    ));
    if reported.canonicalize()? != repo {
        return Err(io::Error::other("repository path must be the Git root"));
    }
    Ok(())
}

fn reject_submodules(repo: &Path) -> io::Result<()> {
    let output = git_output(repo, &["ls-files", "--stage"])?;
    if output
        .split(|byte| *byte == b'\n')
        .any(|line| line.starts_with(b"160000 "))
    {
        return Err(io::Error::other("submodules are not supported"));
    }
    Ok(())
}

fn git_head(repo: &Path) -> io::Result<Option<String>> {
    let output = git_command()
        .args([
            "-c",
            "core.fsmonitor=false",
            "-c",
            "core.hooksPath=/dev/null",
        ])
        .arg("-C")
        .arg(repo)
        .args(["rev-parse", "--verify", "HEAD"])
        .output()?;
    if !output.status.success() {
        return Ok(None);
    }
    let value = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if value.len() == 40 && value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        Ok(Some(value))
    } else {
        Err(io::Error::other("Git returned an invalid head"))
    }
}

fn git_diff_metadata(repo: &Path) -> io::Result<GitDiffMetadata> {
    let output = git_output(
        repo,
        &["status", "--porcelain=v2", "-z", "--untracked-files=all"],
    )?;
    let mut result = GitDiffMetadata {
        staged_files: 0,
        unstaged_files: 0,
        untracked_files: 0,
    };
    for record in output.split(|byte| *byte == 0) {
        if record.starts_with(b"? ") {
            result.untracked_files += 1;
            continue;
        }
        if !(record.starts_with(b"1 ") || record.starts_with(b"2 ") || record.starts_with(b"u "))
            || record.len() < 4
        {
            continue;
        }
        let staged = record[2];
        let unstaged = record[3];
        if !matches!(staged, b'.' | b' ') {
            result.staged_files += 1;
        }
        if !matches!(unstaged, b'.' | b' ') {
            result.unstaged_files += 1;
        }
    }
    Ok(result)
}

fn git_output(repo: &Path, arguments: &[&str]) -> io::Result<Vec<u8>> {
    let output = git_command()
        .args([
            "-c",
            "core.fsmonitor=false",
            "-c",
            "core.hooksPath=/dev/null",
        ])
        .arg("-C")
        .arg(repo)
        .args(arguments)
        .output()?;
    if !output.status.success() {
        return Err(io::Error::other(format!(
            "Git command failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    Ok(output.stdout)
}

fn git_command() -> Command {
    let mut command = Command::new("/usr/bin/git");
    command
        .env_clear()
        .env("HOME", "/var/empty")
        .env("PATH", "/usr/bin:/bin")
        .env("LANG", "C")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_LITERAL_PATHSPECS", "1");
    command
}

fn validate_relative_bytes(path: &[u8]) -> io::Result<()> {
    let path = Path::new(OsStr::from_bytes(path));
    if path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
        || path.starts_with(".git")
    {
        return Err(io::Error::other("Git returned an unsafe path"));
    }
    Ok(())
}

fn validate_internal_symlink(
    relative: &Path,
    target: &Path,
    selected: &BTreeSet<Vec<u8>>,
) -> io::Result<()> {
    if target.is_absolute() {
        return Err(io::Error::other("snapshot symlink escapes the repository"));
    }
    let mut normalized = Vec::<OsString>::new();
    let parent = relative.parent().unwrap_or_else(|| Path::new(""));
    for component in parent.components().chain(target.components()) {
        match component {
            Component::Normal(value) => normalized.push(value.to_os_string()),
            Component::ParentDir => {
                if normalized.pop().is_none() {
                    return Err(io::Error::other("snapshot symlink escapes the repository"));
                }
            }
            Component::CurDir => {}
            _ => return Err(io::Error::other("snapshot symlink is unsafe")),
        }
    }
    let normalized = normalized.iter().collect::<PathBuf>();
    if !selected.contains(normalized.as_os_str().as_bytes()) {
        return Err(io::Error::other("snapshot symlink target is not included"));
    }
    Ok(())
}

fn hash_regular_nofollow(path: &Path, limit: u64) -> io::Result<(String, u64)> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW_ANY)
        .open(path)?;
    let before = file.metadata()?;
    if !before.is_file() || before.len() > limit {
        return Err(io::Error::other("snapshot source is not a regular file"));
    }
    let mut digest = Sha256::new();
    let mut total = 0u64;
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        total = total
            .checked_add(read as u64)
            .ok_or_else(|| io::Error::other("snapshot size overflow"))?;
        if total > limit {
            return Err(io::Error::other("snapshot file is too large"));
        }
        digest.update(&buffer[..read]);
    }
    let after = file.metadata()?;
    if before.len() != total || before.len() != after.len() {
        return Err(io::Error::other("snapshot file changed while it was read"));
    }
    Ok((format!("{:x}", digest.finalize()), total))
}

fn copy_regular_nofollow(
    source: &Path,
    destination: &Path,
    executable_mode: u32,
    expected_size: u64,
    expected_sha256: &str,
) -> io::Result<()> {
    let mut source = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW_ANY)
        .open(source)?;
    if !source.metadata()?.is_file() {
        return Err(io::Error::other("snapshot source is not a regular file"));
    }
    let mut destination = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600 | executable_mode)
        .open(destination)?;
    let mut digest = Sha256::new();
    let mut total = 0u64;
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = source.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        total = total
            .checked_add(read as u64)
            .ok_or_else(|| io::Error::other("snapshot size overflow"))?;
        if total > expected_size {
            return Err(io::Error::other("snapshot source grew while copying"));
        }
        digest.update(&buffer[..read]);
        destination.write_all(&buffer[..read])?;
    }
    if total != expected_size || format!("{:x}", digest.finalize()) != expected_sha256 {
        return Err(io::Error::other("snapshot source changed while copying"));
    }
    destination.set_permissions(fs::Permissions::from_mode(0o600 | executable_mode))?;
    destination.sync_all()
}

fn manifest_bytes(entries: &[SourceEntry]) -> Vec<u8> {
    let mut manifest = Vec::new();
    for entry in entries {
        push_field(&mut manifest, entry.kind.label().as_bytes());
        push_field(&mut manifest, &entry.mode.to_be_bytes());
        push_field(&mut manifest, &entry.path_bytes);
        push_field(&mut manifest, entry.content_sha256.as_bytes());
    }
    manifest
}

fn push_field(output: &mut Vec<u8>, value: &[u8]) {
    output.extend_from_slice(&(value.len() as u64).to_be_bytes());
    output.extend_from_slice(value);
}

fn verify_frozen_copy(root: &Path, entries: &[SourceEntry]) -> io::Result<()> {
    for entry in entries {
        let path = root.join(&entry.path);
        let current_sha256 = match entry.kind {
            EntryKind::File => hash_regular_nofollow(&path, MAX_FILE)?.0,
            EntryKind::Symlink => hex_sha256(fs::read_link(path)?.as_os_str().as_bytes()),
        };
        if current_sha256 != entry.content_sha256 {
            return Err(io::Error::other("snapshot copy verification failed"));
        }
    }
    Ok(())
}

fn verify_sources_unchanged(repo: &Path, entries: &[SourceEntry]) -> io::Result<()> {
    for entry in entries {
        let path = repo.join(&entry.path);
        let metadata = fs::symlink_metadata(&path)?;
        let kind_matches = match entry.kind {
            EntryKind::File => metadata.is_file(),
            EntryKind::Symlink => metadata.file_type().is_symlink(),
        };
        if !kind_matches || metadata.permissions().mode() & 0o111 != entry.mode {
            return Err(io::Error::other(
                "repository metadata changed while the snapshot was created",
            ));
        }
        let current_sha256 = match entry.kind {
            EntryKind::File => hash_regular_nofollow(&path, MAX_FILE)?.0,
            EntryKind::Symlink => hex_sha256(fs::read_link(path)?.as_os_str().as_bytes()),
        };
        if current_sha256 != entry.content_sha256 {
            return Err(io::Error::other(
                "repository changed while the snapshot was created",
            ));
        }
    }
    Ok(())
}

fn bytes_hex(value: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(value.len() * 2);
    for byte in value {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

fn decode_hex(value: &str) -> io::Result<Vec<u8>> {
    if !value.len().is_multiple_of(2) {
        return Err(io::Error::other("invalid hex path"));
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = hex_digit(pair[0])?;
            let low = hex_digit(pair[1])?;
            Ok((high << 4) | low)
        })
        .collect()
}

fn hex_digit(value: u8) -> io::Result<u8> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err(io::Error::other("invalid hex path")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn git(repo: &Path, arguments: &[&str]) {
        let status = Command::new("/usr/bin/git")
            .arg("-C")
            .arg(repo)
            .args(arguments)
            .status()
            .unwrap();
        assert!(status.success());
    }

    #[test]
    fn snapshot_includes_untracked_and_keeps_hostile_config_as_data() {
        let temp = tempfile::tempdir().unwrap();
        let repo = temp.path().join("repo");
        let output = temp.path().join("output");
        fs::create_dir(&repo).unwrap();
        fs::create_dir(&output).unwrap();
        git(&repo, &["init", "-q"]);
        fs::write(repo.join("tracked"), "one").unwrap();
        fs::write(repo.join("untracked"), "two").unwrap();
        fs::write(repo.join("AGENTS.md"), "hostile instruction").unwrap();
        fs::create_dir(repo.join(".codex")).unwrap();
        fs::write(repo.join(".codex/config.toml"), "model = \"hostile\"").unwrap();
        git(
            &repo,
            &["add", "tracked", "AGENTS.md", ".codex/config.toml"],
        );
        let snapshot = create_snapshot(&repo, &output).unwrap();
        assert_eq!(snapshot.file_count, 4);
        assert_eq!(snapshot.git_diff.staged_files, 3);
        assert_eq!(snapshot.git_diff.unstaged_files, 0);
        assert_eq!(snapshot.git_diff.untracked_files, 1);
        assert_eq!(
            fs::read_to_string(snapshot.root.join("untracked")).unwrap(),
            "two"
        );
        assert!(snapshot.root.join("AGENTS.md").is_file());
        assert!(snapshot.root.join(".codex/config.toml").is_file());
        assert!(!snapshot.root.join(".git").exists());
        assert!(verify_snapshot(&snapshot).is_ok());
        fs::write(snapshot.root.join("added-after-freeze"), "change").unwrap();
        assert!(verify_snapshot(&snapshot).is_err());
    }

    #[test]
    fn snapshot_rejects_escaping_symlinks() {
        let temp = tempfile::tempdir().unwrap();
        let repo = temp.path().join("repo");
        let output = temp.path().join("output");
        fs::create_dir(&repo).unwrap();
        fs::create_dir(&output).unwrap();
        git(&repo, &["init", "-q"]);
        std::os::unix::fs::symlink("../outside", repo.join("escape")).unwrap();
        git(&repo, &["add", "escape"]);
        assert!(create_snapshot(&repo, &output).is_err());
    }

    #[test]
    fn snapshot_keeps_internal_links_and_executable_bits_but_not_ignored_files() {
        let temp = tempfile::tempdir().unwrap();
        let repo = temp.path().join("repo");
        let output = temp.path().join("output");
        fs::create_dir(&repo).unwrap();
        fs::create_dir(&output).unwrap();
        git(&repo, &["init", "-q"]);
        fs::write(repo.join(".gitignore"), "ignored\n").unwrap();
        fs::write(repo.join("tool"), "run").unwrap();
        fs::set_permissions(repo.join("tool"), fs::Permissions::from_mode(0o755)).unwrap();
        fs::write(repo.join("ignored"), "skip").unwrap();
        std::os::unix::fs::symlink("tool", repo.join("tool-link")).unwrap();
        git(&repo, &["add", ".gitignore", "tool", "tool-link"]);

        let snapshot = create_snapshot(&repo, &output).unwrap();

        assert_eq!(snapshot.file_count, 3);
        assert!(!snapshot.root.join("ignored").exists());
        assert_eq!(
            fs::metadata(snapshot.root.join("tool"))
                .unwrap()
                .permissions()
                .mode()
                & 0o111,
            0o111
        );
        assert_eq!(
            fs::read_link(snapshot.root.join("tool-link")).unwrap(),
            Path::new("tool")
        );
    }
}
