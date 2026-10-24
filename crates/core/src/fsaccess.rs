//! Shared helpers for confined filesystem access.
//!
//! All scanner reads go through a [`cap_std::fs::Dir`] handle opened on the
//! authorized scan root. Paths are resolved relative to that handle by the
//! operating system (`openat2` with `RESOLVE_BENEATH` on Linux where available,
//! otherwise a component-by-component walk that never follows a link out of
//! the handle). A symlink, `..`, or rename race therefore cannot make a read
//! land outside the root, whatever happens to the tree while the scan runs.

use std::io;

use cap_std::fs::{File, OpenOptions};

use crate::IncompleteKind;

/// Whether this build has a verified confined-access backend.
///
/// Only Linux has been tested. Other platforms fail closed with
/// `ScanError::UnsupportedPlatform` instead of falling back to path-based
/// opening.
pub(crate) const CONFINEMENT_VERIFIED: bool = cfg!(target_os = "linux");

/// Options for opening a file for reading without blocking on special files.
///
/// `O_NONBLOCK` makes opening a named pipe return immediately. The caller must
/// still check the opened handle's type with [`File::metadata`] before reading.
pub(crate) fn read_options() -> OpenOptions {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use cap_std::fs::OpenOptionsExt;
        options.custom_flags(rustix::fs::OFlags::NONBLOCK.bits() as i32);
    }
    options
}

/// True when `err` is cap-std refusing a path that would leave the root.
pub(crate) fn is_escape(err: &io::Error) -> bool {
    err.kind() == io::ErrorKind::PermissionDenied
        && err.to_string().contains("outside of the filesystem")
}

/// Maps an open error to the reason recorded in the report.
pub(crate) fn classify(err: &io::Error) -> IncompleteKind {
    if is_escape(err) {
        IncompleteKind::OutsideRoot
    } else {
        IncompleteKind::Unreadable
    }
}

pub(crate) fn describe(err: &io::Error) -> String {
    if is_escape(err) {
        "path resolves outside the scan root and was not followed".to_string()
    } else {
        err.to_string()
    }
}

/// Reads at most `limit` bytes from `file`. Returns `None` if the file holds
/// more than `limit` bytes.
pub(crate) fn read_bounded(file: File, limit: u64) -> io::Result<Option<Vec<u8>>> {
    use std::io::Read;
    let mut bytes = Vec::new();
    file.take(limit.saturating_add(1)).read_to_end(&mut bytes)?;
    Ok((bytes.len() as u64 <= limit).then_some(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use cap_std::ambient_authority;
    use cap_std::fs::Dir;
    use std::fs;

    #[test]
    fn bounded_read_accepts_a_file_at_the_limit_and_rejects_one_over() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a"), [b'x'; 10]).unwrap();
        fs::write(dir.path().join("b"), [b'x'; 11]).unwrap();
        let root = Dir::open_ambient_dir(dir.path(), ambient_authority()).unwrap();
        let at_limit = read_bounded(root.open("a").unwrap(), 10).unwrap();
        assert_eq!(at_limit.map(|b| b.len()), Some(10));
        assert_eq!(read_bounded(root.open("b").unwrap(), 10).unwrap(), None);
    }

    #[test]
    fn escape_errors_are_recognized() {
        let outside = tempfile::tempdir().unwrap();
        fs::write(outside.path().join("f"), "x").unwrap();
        let dir = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(outside.path().join("f"), dir.path().join("link")).unwrap();
        let root = Dir::open_ambient_dir(dir.path(), ambient_authority()).unwrap();
        #[cfg(unix)]
        {
            let err = root.open_with("link", &read_options()).unwrap_err();
            assert!(is_escape(&err), "{err}");
            assert_eq!(classify(&err), IncompleteKind::OutsideRoot);
        }
        let missing = root.open_with("nope", &read_options()).unwrap_err();
        assert!(!is_escape(&missing));
        assert_eq!(classify(&missing), IncompleteKind::Unreadable);
    }
}
