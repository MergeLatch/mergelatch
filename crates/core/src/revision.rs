use std::fs::{self, File};
use std::io::Read;
use std::path::Path;

use crate::{Revision, sanitize_text};

const MAX_REVISION_FILE_BYTES: u64 = 1024 * 1024;

/// Reads the checked-out revision of `root` by parsing files in `.git`.
///
/// Git is never run, so hooks, filters, and repository configuration cannot
/// execute. Symlinked `.git` entries are not followed. Returns `None` when the
/// directory is not a plain Git checkout or the files cannot be understood.
/// Revision data is metadata only: failing to read it does not affect the scan
/// outcome.
pub fn read_revision(root: &Path) -> Option<Revision> {
    let git_dir = root.join(".git");
    if !fs::symlink_metadata(&git_dir).ok()?.is_dir() {
        return None;
    }
    let head = read_regular_file(&git_dir.join("HEAD"))?;
    let head = head.trim();

    if let Some(reference) = head.strip_prefix("ref:") {
        let reference = reference.trim();
        if !is_valid_ref_name(reference) {
            return None;
        }
        let commit = resolve_loose_ref(&git_dir, reference)
            .or_else(|| resolve_packed_ref(&git_dir, reference));
        return Some(Revision {
            commit,
            reference: Some(sanitize_text(reference, 200)),
        });
    }

    if is_object_id(head) {
        return Some(Revision {
            commit: Some(head.to_string()),
            reference: None,
        });
    }
    None
}

fn read_regular_file(path: &Path) -> Option<String> {
    let meta = fs::symlink_metadata(path).ok()?;
    if !meta.is_file() || meta.len() > MAX_REVISION_FILE_BYTES {
        return None;
    }
    let mut text = String::new();
    File::open(path)
        .ok()?
        .take(MAX_REVISION_FILE_BYTES)
        .read_to_string(&mut text)
        .ok()?;
    Some(text)
}

fn is_object_id(s: &str) -> bool {
    matches!(s.len(), 40 | 64) && s.bytes().all(|b| b.is_ascii_hexdigit())
}

fn is_valid_ref_name(name: &str) -> bool {
    name.starts_with("refs/")
        && !name.contains("..")
        && !name.contains('\\')
        && !name.chars().any(char::is_control)
        && name.split('/').all(|part| !part.is_empty() && part != ".")
}

fn resolve_loose_ref(git_dir: &Path, reference: &str) -> Option<String> {
    let contents = read_regular_file(&git_dir.join(reference))?;
    let id = contents.trim();
    is_object_id(id).then(|| id.to_string())
}

fn resolve_packed_ref(git_dir: &Path, reference: &str) -> Option<String> {
    let packed = read_regular_file(&git_dir.join("packed-refs"))?;
    packed
        .lines()
        .filter(|line| !line.starts_with('#') && !line.starts_with('^'))
        .find_map(|line| {
            let (id, name) = line.split_once(' ')?;
            (name == reference && is_object_id(id)).then(|| id.to_string())
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: &str = "0123456789abcdef0123456789abcdef01234567";

    fn checkout(head: &str) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir_all(dir.path().join(".git/refs/heads")).unwrap();
        fs::write(dir.path().join(".git/HEAD"), head).unwrap();
        dir
    }

    #[test]
    fn not_a_checkout_has_no_revision() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(read_revision(dir.path()), None);
    }

    #[test]
    fn loose_branch_ref_is_resolved() {
        let dir = checkout("ref: refs/heads/main\n");
        fs::write(dir.path().join(".git/refs/heads/main"), format!("{ID}\n")).unwrap();
        let rev = read_revision(dir.path()).unwrap();
        assert_eq!(rev.commit.as_deref(), Some(ID));
        assert_eq!(rev.reference.as_deref(), Some("refs/heads/main"));
    }

    #[test]
    fn packed_ref_is_resolved() {
        let dir = checkout("ref: refs/heads/main\n");
        fs::write(
            dir.path().join(".git/packed-refs"),
            format!("# pack-refs\n{ID} refs/heads/main\n"),
        )
        .unwrap();
        assert_eq!(
            read_revision(dir.path()).unwrap().commit.as_deref(),
            Some(ID)
        );
    }

    #[test]
    fn detached_head_records_commit_only() {
        let dir = checkout(&format!("{ID}\n"));
        let rev = read_revision(dir.path()).unwrap();
        assert_eq!(rev.commit.as_deref(), Some(ID));
        assert_eq!(rev.reference, None);
    }

    #[test]
    fn unborn_branch_has_reference_but_no_commit() {
        let dir = checkout("ref: refs/heads/main\n");
        let rev = read_revision(dir.path()).unwrap();
        assert_eq!(rev.commit, None);
        assert_eq!(rev.reference.as_deref(), Some("refs/heads/main"));
    }

    #[test]
    fn traversal_in_ref_name_is_rejected() {
        let dir = checkout("ref: refs/../../etc/passwd\n");
        assert_eq!(read_revision(dir.path()), None);
    }

    #[test]
    fn garbage_head_is_rejected() {
        let dir = checkout("not a revision\n");
        assert_eq!(read_revision(dir.path()), None);
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_git_dir_is_not_followed() {
        let real = checkout(&format!("{ID}\n"));
        let dir = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(real.path().join(".git"), dir.path().join(".git")).unwrap();
        assert_eq!(read_revision(dir.path()), None);
    }
}
