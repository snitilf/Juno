use sha2::{Digest, Sha256};
use std::ffi::CString;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Component, Path};
use std::sync::atomic::{AtomicU64, Ordering};

static STAGE_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize, PartialEq, Eq)]
pub struct FileState {
    pub sha256: String,
    pub size: u64,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub links: u64,
    pub kind: String,
}

pub struct SecureRoot {
    fd: OwnedFd,
}

#[derive(Debug)]
pub struct SecureLock {
    file: File,
}

impl Drop for SecureLock {
    fn drop(&mut self) {
        unsafe {
            libc::flock(self.file.as_raw_fd(), libc::LOCK_UN);
        }
    }
}

impl SecureRoot {
    pub fn create(path: &Path) -> io::Result<Self> {
        let fd = open_absolute_directory(path, true)?;
        validate_trusted_directory(fd.as_raw_fd())?;
        Ok(Self { fd })
    }

    pub fn open(path: &Path) -> io::Result<Self> {
        let fd = open_absolute_directory(path, false)?;
        validate_trusted_directory(fd.as_raw_fd())?;
        Ok(Self { fd })
    }

    pub fn inspect(&self, relative: &Path) -> io::Result<Option<FileState>> {
        let (parent, name) = match self.parent(relative, false) {
            Ok(value) => value,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error),
        };
        let Some(metadata) = metadata_at(parent.as_raw_fd(), &name)? else {
            return Ok(None);
        };
        validate_regular(&metadata)?;
        let mut file = open_file_at(parent.as_raw_fd(), &name, libc::O_RDONLY, 0)?;
        let state = state_from_file(&mut file)?;
        Ok(Some(state))
    }

    pub fn ensure_directory(&self, relative: &Path, mode: u32) -> io::Result<()> {
        if relative.is_absolute() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "path must be relative",
            ));
        }
        let directory_mode = libc::mode_t::try_from(mode)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "mode is too large"))?;
        let duplicate = unsafe { libc::dup(self.fd.as_raw_fd()) };
        if duplicate < 0 {
            return Err(io::Error::last_os_error());
        }
        let mut directory = unsafe { OwnedFd::from_raw_fd(duplicate) };
        let mut found = false;
        for component in relative.components() {
            let Component::Normal(value) = component else {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "path contains an unsafe component",
                ));
            };
            found = true;
            let name = CString::new(value.as_bytes()).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidInput, "path component contains NUL")
            })?;
            let made =
                unsafe { libc::mkdirat(directory.as_raw_fd(), name.as_ptr(), directory_mode) };
            if made < 0 && io::Error::last_os_error().kind() != io::ErrorKind::AlreadyExists {
                return Err(io::Error::last_os_error());
            }
            if made == 0 {
                fsync_fd(directory.as_raw_fd())?;
            }
            let next = unsafe {
                libc::openat(
                    directory.as_raw_fd(),
                    name.as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                )
            };
            if next < 0 {
                return Err(io::Error::last_os_error());
            }
            let next = unsafe { OwnedFd::from_raw_fd(next) };
            let changed = unsafe { libc::fchmod(next.as_raw_fd(), directory_mode) };
            if changed < 0 {
                return Err(io::Error::last_os_error());
            }
            directory = next;
        }
        if !found {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "path is empty"));
        }
        fsync_fd(directory.as_raw_fd())
    }

    pub fn read(&self, relative: &Path) -> io::Result<Option<Vec<u8>>> {
        let (parent, name) = match self.parent(relative, false) {
            Ok(value) => value,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error),
        };
        if metadata_at(parent.as_raw_fd(), &name)?.is_none() {
            return Ok(None);
        }
        let mut file = open_file_at(parent.as_raw_fd(), &name, libc::O_RDONLY, 0)?;
        validate_regular(&file.metadata()?)?;
        let mut content = Vec::new();
        file.read_to_end(&mut content)?;
        Ok(Some(content))
    }

    pub fn read_bounded(&self, relative: &Path, limit: u64) -> io::Result<Option<Vec<u8>>> {
        let (parent, name) = match self.parent(relative, false) {
            Ok(value) => value,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error),
        };
        if metadata_at(parent.as_raw_fd(), &name)?.is_none() {
            return Ok(None);
        }
        let mut file = open_file_at(parent.as_raw_fd(), &name, libc::O_RDONLY, 0)?;
        let metadata = file.metadata()?;
        validate_regular(&metadata)?;
        if metadata.len() > limit {
            return Err(io::Error::other("file exceeds the read limit"));
        }
        let mut content = Vec::new();
        Read::by_ref(&mut file)
            .take(limit + 1)
            .read_to_end(&mut content)?;
        if content.len() as u64 > limit {
            return Err(io::Error::other("file grew past the read limit"));
        }
        Ok(Some(content))
    }

    pub fn write_atomic(
        &self,
        relative: &Path,
        content: &[u8],
        mode: u32,
        expected: Option<&FileState>,
    ) -> io::Result<FileState> {
        let (parent, name) = self.parent(relative, true)?;
        let stage = CString::new(format!(
            ".juno-stage-{}-{}",
            std::process::id(),
            STAGE_COUNTER.fetch_add(1, Ordering::Relaxed)
        ))
        .expect("stage name has no NUL");
        let mut staged = open_file_at(
            parent.as_raw_fd(),
            &stage,
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
            0o600,
        )?;
        let stage_cleanup = StageCleanup {
            parent: parent.as_raw_fd(),
            name: stage.clone(),
        };
        staged.write_all(content)?;
        if let Some(expected) = expected {
            let changed = unsafe {
                libc::fchown(
                    staged.as_raw_fd(),
                    expected.uid as libc::uid_t,
                    expected.gid as libc::gid_t,
                )
            };
            if changed < 0 {
                return Err(io::Error::last_os_error());
            }
        }
        staged.set_permissions(fs::Permissions::from_mode(mode))?;
        staged.sync_all()?;
        drop(staged);
        if !self.parent_is_current(relative, parent.as_raw_fd())? {
            return Err(io::Error::other(
                "destination directory changed before atomic replacement",
            ));
        }

        let had_preimage = expected.is_some();
        match expected {
            Some(expected) => {
                let current = state_at(parent.as_raw_fd(), &name)?
                    .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "target disappeared"))?;
                if &current != expected {
                    return Err(io::Error::other("target changed after plan approval"));
                }
                rename_swap(parent.as_raw_fd(), &stage, &name)?;
                let displaced = self
                    .read_stage(parent.as_raw_fd(), &stage)?
                    .ok_or_else(|| io::Error::other("displaced file missing"))?;
                if &displaced != expected {
                    if rename_swap(parent.as_raw_fd(), &stage, &name).is_err() {
                        std::mem::forget(stage_cleanup);
                        return Err(io::Error::other(
                            "target changed and atomic restoration failed",
                        ));
                    }
                    return Err(io::Error::other("target changed during atomic replacement"));
                }
            }
            None => rename_exclusive(parent.as_raw_fd(), &stage, &name)?,
        }
        if !matches!(
            self.parent_is_current(relative, parent.as_raw_fd()),
            Ok(true)
        ) {
            if restore_failed_write(parent.as_raw_fd(), &name, &stage, had_preimage).is_err() {
                std::mem::forget(stage_cleanup);
                return Err(io::Error::other(
                    "destination directory changed and atomic restoration failed",
                ));
            }
            fsync_fd(parent.as_raw_fd())?;
            return Err(io::Error::other(
                "destination directory changed during atomic replacement",
            ));
        }
        let installed = state_at(parent.as_raw_fd(), &name);
        let valid = installed
            .as_ref()
            .ok()
            .and_then(Option::as_ref)
            .is_some_and(|state| {
                state.sha256 == hex_sha256(content)
                    && state.mode == mode
                    && state.links == 1
                    && state.kind == "regular"
                    && expected.is_none_or(|preimage| {
                        state.uid == preimage.uid && state.gid == preimage.gid
                    })
            });
        if !valid {
            if restore_failed_write(parent.as_raw_fd(), &name, &stage, had_preimage).is_err() {
                std::mem::forget(stage_cleanup);
                return Err(io::Error::other(
                    "installed file validation and atomic restoration failed",
                ));
            }
            fsync_fd(parent.as_raw_fd())?;
            return Err(io::Error::other("installed file validation failed"));
        }
        fsync_fd(parent.as_raw_fd())?;
        drop(stage_cleanup);
        installed?.ok_or_else(|| io::Error::other("written target missing"))
    }

    pub fn remove_atomic(&self, relative: &Path, expected: &FileState) -> io::Result<()> {
        let (parent, name) = self.parent(relative, false)?;
        let current = state_at(parent.as_raw_fd(), &name)?
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "target disappeared"))?;
        if &current != expected {
            return Err(io::Error::other("target changed after plan approval"));
        }
        if !self.parent_is_current(relative, parent.as_raw_fd())? {
            return Err(io::Error::other(
                "destination directory changed before atomic removal",
            ));
        }
        let stage = CString::new(format!(
            ".juno-remove-{}-{}",
            std::process::id(),
            STAGE_COUNTER.fetch_add(1, Ordering::Relaxed)
        ))
        .expect("stage name has no NUL");
        rename_exclusive_names(parent.as_raw_fd(), &name, &stage)?;
        let stage_cleanup = StageCleanup {
            parent: parent.as_raw_fd(),
            name: stage.clone(),
        };
        if !matches!(
            self.parent_is_current(relative, parent.as_raw_fd()),
            Ok(true)
        ) {
            if restore_failed_write(parent.as_raw_fd(), &name, &stage, true).is_err() {
                std::mem::forget(stage_cleanup);
                return Err(io::Error::other(
                    "destination directory changed and atomic restoration failed",
                ));
            }
            fsync_fd(parent.as_raw_fd())?;
            return Err(io::Error::other(
                "destination directory changed during atomic removal",
            ));
        }
        let displaced = self
            .read_stage(parent.as_raw_fd(), &stage)?
            .ok_or_else(|| io::Error::other("removed file missing"))?;
        if &displaced != expected {
            if rename_exclusive_names(parent.as_raw_fd(), &stage, &name).is_err() {
                std::mem::forget(stage_cleanup);
                return Err(io::Error::other(
                    "target changed and atomic restoration failed",
                ));
            }
            return Err(io::Error::other("target changed during atomic removal"));
        }
        if metadata_at(parent.as_raw_fd(), &name)?.is_some() {
            if rename_swap(parent.as_raw_fd(), &stage, &name).is_err() {
                std::mem::forget(stage_cleanup);
                return Err(io::Error::other(
                    "removed target was recreated and atomic restoration failed",
                ));
            }
            fsync_fd(parent.as_raw_fd())?;
            return Err(io::Error::other(
                "removed target was recreated before validation",
            ));
        }
        drop(stage_cleanup);
        fsync_fd(parent.as_raw_fd())?;
        Ok(())
    }

    pub fn lock(&self, relative: &Path) -> io::Result<SecureLock> {
        let (parent, name) = self.parent(relative, true)?;
        let file = open_file_at(
            parent.as_raw_fd(),
            &name,
            libc::O_RDWR | libc::O_CREAT,
            0o600,
        )?;
        validate_regular(&file.metadata()?)?;
        let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if result < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(SecureLock { file })
    }

    fn read_stage(&self, parent: RawFd, name: &CString) -> io::Result<Option<FileState>> {
        if metadata_at(parent, name)?.is_none() {
            return Ok(None);
        }
        let mut file = open_file_at(parent, name, libc::O_RDONLY, 0)?;
        validate_regular(&file.metadata()?)?;
        state_from_file(&mut file).map(Some)
    }

    fn parent(&self, relative: &Path, create: bool) -> io::Result<(OwnedFd, CString)> {
        if relative.is_absolute() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "path must be relative",
            ));
        }
        let mut pieces = Vec::new();
        for component in relative.components() {
            match component {
                Component::Normal(value) => pieces.push(value.as_bytes().to_vec()),
                _ => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "path contains an unsafe component",
                    ));
                }
            }
        }
        let (name, parents) = pieces
            .split_last()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path is empty"))?;
        let duplicate = unsafe { libc::dup(self.fd.as_raw_fd()) };
        if duplicate < 0 {
            return Err(io::Error::last_os_error());
        }
        let mut directory = unsafe { OwnedFd::from_raw_fd(duplicate) };
        for part in parents {
            let part = CString::new(part.as_slice()).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidInput, "path component contains NUL")
            })?;
            if create {
                let result = unsafe { libc::mkdirat(directory.as_raw_fd(), part.as_ptr(), 0o700) };
                if result < 0 && io::Error::last_os_error().kind() != io::ErrorKind::AlreadyExists {
                    return Err(io::Error::last_os_error());
                }
                if result == 0 {
                    fsync_fd(directory.as_raw_fd())?;
                }
            }
            let next = unsafe {
                libc::openat(
                    directory.as_raw_fd(),
                    part.as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                )
            };
            if next < 0 {
                return Err(io::Error::last_os_error());
            }
            directory = unsafe { OwnedFd::from_raw_fd(next) };
        }
        let name = CString::new(name.as_slice())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "name contains NUL"))?;
        Ok((directory, name))
    }

    fn parent_is_current(&self, relative: &Path, held: RawFd) -> io::Result<bool> {
        let fresh = match self.parent(relative, false) {
            Ok((directory, _)) => directory,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(error),
        };
        Ok(fd_identity(held)? == fd_identity(fresh.as_raw_fd())?)
    }
}

struct StageCleanup {
    parent: RawFd,
    name: CString,
}

impl Drop for StageCleanup {
    fn drop(&mut self) {
        unsafe {
            libc::unlinkat(self.parent, self.name.as_ptr(), 0);
        }
    }
}

fn open_file_at(parent: RawFd, name: &CString, flags: i32, mode: u32) -> io::Result<File> {
    let fd = unsafe {
        libc::openat(
            parent,
            name.as_ptr(),
            flags | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            mode,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn metadata_at(parent: RawFd, name: &CString) -> io::Result<Option<fs::Metadata>> {
    let fd = unsafe {
        libc::openat(
            parent,
            name.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if fd < 0 {
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::NotFound {
            return Ok(None);
        }
        return Err(error);
    }
    let file = unsafe { File::from_raw_fd(fd) };
    let metadata = file.metadata()?;
    drop(file);
    Ok(Some(metadata))
}

fn state_at(parent: RawFd, name: &CString) -> io::Result<Option<FileState>> {
    if metadata_at(parent, name)?.is_none() {
        return Ok(None);
    }
    let mut file = open_file_at(parent, name, libc::O_RDONLY, 0)?;
    validate_regular(&file.metadata()?)?;
    state_from_file(&mut file).map(Some)
}

fn open_absolute_directory(path: &Path, create: bool) -> io::Result<OwnedFd> {
    if !path.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "trusted root must be absolute",
        ));
    }
    let slash = CString::new("/").unwrap();
    let fd = unsafe {
        libc::open(
            slash.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut directory = unsafe { OwnedFd::from_raw_fd(fd) };
    for component in path.components() {
        let Component::Normal(value) = component else {
            continue;
        };
        let name = CString::new(value.as_bytes()).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "root component contains NUL")
        })?;
        if create {
            let made = unsafe { libc::mkdirat(directory.as_raw_fd(), name.as_ptr(), 0o700) };
            if made < 0 && io::Error::last_os_error().kind() != io::ErrorKind::AlreadyExists {
                return Err(io::Error::last_os_error());
            }
            if made == 0 {
                fsync_fd(directory.as_raw_fd())?;
            }
        }
        let next = unsafe {
            libc::openat(
                directory.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        };
        if next < 0 {
            return Err(io::Error::last_os_error());
        }
        directory = unsafe { OwnedFd::from_raw_fd(next) };
    }
    Ok(directory)
}

fn validate_regular(metadata: &fs::Metadata) -> io::Result<()> {
    if !metadata.is_file() {
        return Err(io::Error::other("target is not a regular file"));
    }
    if metadata.nlink() > 1 {
        return Err(io::Error::other("target has multiple hard links"));
    }
    Ok(())
}

fn state_from_file(file: &mut File) -> io::Result<FileState> {
    let metadata = file.metadata()?;
    validate_regular(&metadata)?;
    let mut digest = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    Ok(FileState {
        sha256: format!("{:x}", digest.finalize()),
        size: metadata.len(),
        mode: metadata.mode() & 0o7777,
        uid: metadata.uid(),
        gid: metadata.gid(),
        links: metadata.nlink(),
        kind: "regular".into(),
    })
}

pub fn hex_sha256(content: &[u8]) -> String {
    format!("{:x}", Sha256::digest(content))
}

fn rename_swap(parent: RawFd, source: &CString, target: &CString) -> io::Result<()> {
    let result = unsafe {
        libc::renameatx_np(
            parent,
            source.as_ptr(),
            parent,
            target.as_ptr(),
            libc::RENAME_SWAP,
        )
    };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn rename_exclusive(parent: RawFd, source: &CString, target: &CString) -> io::Result<()> {
    rename_exclusive_names(parent, source, target)
}

fn rename_exclusive_names(parent: RawFd, source: &CString, target: &CString) -> io::Result<()> {
    let result = unsafe {
        libc::renameatx_np(
            parent,
            source.as_ptr(),
            parent,
            target.as_ptr(),
            libc::RENAME_EXCL,
        )
    };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn restore_failed_write(
    parent: RawFd,
    target: &CString,
    stage: &CString,
    had_preimage: bool,
) -> io::Result<()> {
    if had_preimage {
        if metadata_at(parent, target)?.is_some() {
            rename_swap(parent, stage, target)
        } else {
            rename_exclusive_names(parent, stage, target)
        }
    } else if metadata_at(parent, target)?.is_some() {
        rename_exclusive_names(parent, target, stage)
    } else {
        Ok(())
    }
}

fn fsync_fd(fd: RawFd) -> io::Result<()> {
    let result = unsafe { libc::fsync(fd) };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn fd_identity(fd: RawFd) -> io::Result<(libc::dev_t, libc::ino_t)> {
    let mut metadata = std::mem::MaybeUninit::<libc::stat>::uninit();
    let result = unsafe { libc::fstat(fd, metadata.as_mut_ptr()) };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    let metadata = unsafe { metadata.assume_init() };
    Ok((metadata.st_dev, metadata.st_ino))
}

fn validate_trusted_directory(fd: RawFd) -> io::Result<()> {
    let mut metadata = std::mem::MaybeUninit::<libc::stat>::uninit();
    let result = unsafe { libc::fstat(fd, metadata.as_mut_ptr()) };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    let metadata = unsafe { metadata.assume_init() };
    let current_uid = unsafe { libc::geteuid() };
    if metadata.st_uid != current_uid || metadata.st_mode & 0o022 != 0 {
        return Err(io::Error::other(
            "trusted root has unsafe ownership or permissions",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn writes_and_replaces_by_expected_state() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().canonicalize().unwrap();
        let root = SecureRoot::create(&path).unwrap();
        let first = root
            .write_atomic(Path::new("nested/file"), b"one", 0o600, None)
            .unwrap();
        assert_eq!(
            root.read(Path::new("nested/file")).unwrap().unwrap(),
            b"one"
        );
        root.write_atomic(Path::new("nested/file"), b"two", 0o600, Some(&first))
            .unwrap();
        assert_eq!(
            root.read(Path::new("nested/file")).unwrap().unwrap(),
            b"two"
        );
    }

    #[test]
    fn rejects_symlink_and_hardlink_targets() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().canonicalize().unwrap();
        let root = SecureRoot::create(&path).unwrap();
        fs::write(path.join("real"), "value").unwrap();
        std::os::unix::fs::symlink("real", path.join("link")).unwrap();
        assert!(root.inspect(Path::new("link")).is_err());
        fs::hard_link(path.join("real"), path.join("hard")).unwrap();
        assert!(root.inspect(Path::new("real")).is_err());
        fs::create_dir(path.join("directory")).unwrap();
        std::os::unix::fs::symlink("directory", path.join("directory-link")).unwrap();
        assert!(
            root.ensure_directory(Path::new("directory-link/child"), 0o700)
                .is_err()
        );
    }

    #[test]
    fn lifecycle_lock_is_reusable_after_release() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().canonicalize().unwrap();
        let root = SecureRoot::create(&path).unwrap();
        let first = root.lock(Path::new("lock")).unwrap();
        assert_eq!(
            root.lock(Path::new("lock")).unwrap_err().raw_os_error(),
            Some(libc::EWOULDBLOCK)
        );
        drop(first);
        root.lock(Path::new("lock")).unwrap();
    }

    #[test]
    fn detects_a_replaced_destination_directory() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().canonicalize().unwrap();
        let root = SecureRoot::create(&path).unwrap();
        fs::create_dir(path.join("nested")).unwrap();
        let (held, _) = root.parent(Path::new("nested/file"), false).unwrap();
        fs::rename(path.join("nested"), path.join("displaced")).unwrap();
        fs::create_dir(path.join("nested")).unwrap();
        assert!(
            !root
                .parent_is_current(Path::new("nested/file"), held.as_raw_fd())
                .unwrap()
        );
    }

    #[test]
    fn rejects_a_group_writable_trusted_root() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().canonicalize().unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o770)).unwrap();
        assert!(SecureRoot::create(&path).is_err());
    }
}
