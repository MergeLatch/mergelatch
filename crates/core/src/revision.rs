use std::path::Path;

use cap_std::ambient_authority;
use cap_std::fs::Dir;

use crate::fsaccess::{read_bounded, read_options};
use crate::{Revision, sanitize_text};

const MAX_REVISION_FILE_BYTES: u64 = 1024 * 1024;

/// Reads the checked-out revision of `root` by parsing files in `.git`.
///
/// Git is never run, so hooks, filters, and repository configuration cannot
/// execute. See [`read_revision_from`] for the confinement rules. Returns
/// `None` when the directory cannot be opened.
pub fn read_revision(root: &Path) -> Option<Revision> {
    let root = Dir::open_ambient_dir(root, ambient_authority()).ok()?;
    read_revision_from(&root)
}

/// Reads the revision through an open handle on the scan root.
///
/// `.git` must be a real directory, and every file under it is opened through
/// a handle on that directory, so a link inside `.git` cannot lead outside it.
/// Only regular files up to 1 MiB are read. Returns `None` when the directory
/// is not a plain Git checkout or the files cannot be understood.
///
/// The result is what the `.git` files in the scanned directory claim. It is
/// not verified: anyone who controls the directory controls those files. A
/// missing or unreadable revision is `None`, never a placeholder.
pub(crate) fn read_revision_from(root: &Dir) -> Option<Revision> {
    if !root.symlink_metadata(".git").ok()?.is_dir() {
        return None;
    }
    let git = root.open_dir(".git").ok()?;
    let head = read_regular_file(&git, "HEAD")?;
    let head = head.trim();

    if let Some(reference) = head.strip_prefix("ref:") {
        let reference = reference.trim();
        if !is_valid_ref_name(reference) {
            return None;
        }
        let commit =
            resolve_loose_ref(&git, reference).or_else(|| resolve_packed_ref(&git, reference));
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

/// Reads a small regular file through `dir`. The type and size come from the
/// opened handle. Named pipes and devices are never read.
fn read_regular_file(dir: &Dir, path: &str) -> Option<String> {
    let file = dir.open_with(path, &read_options()).ok()?;
    let meta = file.metadata().ok()?;
    if !meta.is_file() || meta.len() > MAX_REVISION_FILE_BYTES {
        return None;
    }
    let bytes = read_bounded(file, MAX_REVISION_FILE_BYTES).ok()??;
    String::from_utf8(bytes).ok()
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

fn resolve_loose_ref(git: &Dir, reference: &str) -> Option<String> {
    let contents = read_regular_file(git, reference)?;
    let id = contents.trim();
    is_object_id(id).then(|| id.to_string())
}

fn resolve_packed_ref(git: &Dir, reference: &str) -> Option<String> {
    let packed = read_regular_file(git, "packed-refs")?;
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
    use std::fs;

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

    #[cfg(unix)]
    mod confinement {
        use super::*;
        use std::os::unix::fs::symlink;

        const OUTSIDE_ID: &str = "ffffffffffffffffffffffffffffffffffffffff";

        fn outside_file(contents: &str) -> (tempfile::TempDir, std::path::PathBuf) {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("outside");
            fs::write(&path, contents).unwrap();
            (dir, path)
        }

        #[test]
        fn head_symlinked_outside_is_not_read() {
            let (_keep, outside) = outside_file(&format!("{OUTSIDE_ID}\n"));
            let dir = checkout("placeholder");
            fs::remove_file(dir.path().join(".git/HEAD")).unwrap();
            symlink(&outside, dir.path().join(".git/HEAD")).unwrap();
            assert_eq!(read_revision(dir.path()), None);
        }

        #[test]
        fn ref_file_symlinked_outside_gives_no_commit() {
            let (_keep, outside) = outside_file(&format!("{OUTSIDE_ID}\n"));
            let dir = checkout("ref: refs/heads/main\n");
            symlink(&outside, dir.path().join(".git/refs/heads/main")).unwrap();
            let rev = read_revision(dir.path()).unwrap();
            assert_eq!(rev.commit, None, "an outside file supplied a commit");
        }

        #[test]
        fn refs_directory_symlinked_outside_gives_no_commit() {
            let outside = tempfile::tempdir().unwrap();
            fs::create_dir(outside.path().join("heads")).unwrap();
            fs::write(outside.path().join("heads/main"), format!("{OUTSIDE_ID}\n")).unwrap();
            let dir = checkout("ref: refs/heads/main\n");
            fs::remove_dir_all(dir.path().join(".git/refs")).unwrap();
            symlink(outside.path(), dir.path().join(".git/refs")).unwrap();
            assert_eq!(read_revision(dir.path()).unwrap().commit, None);
        }

        #[test]
        fn relative_link_leaving_dot_git_is_refused_even_inside_the_root() {
            let dir = checkout("ref: refs/heads/main\n");
            fs::write(dir.path().join("elsewhere"), format!("{ID}\n")).unwrap();
            symlink(
                "../../../elsewhere",
                dir.path().join(".git/refs/heads/main"),
            )
            .unwrap();
            assert_eq!(read_revision(dir.path()).unwrap().commit, None);
        }

        #[test]
        fn packed_refs_symlinked_outside_gives_no_commit() {
            let (_keep, outside) = outside_file(&format!("{OUTSIDE_ID} refs/heads/main\n"));
            let dir = checkout("ref: refs/heads/main\n");
            symlink(&outside, dir.path().join(".git/packed-refs")).unwrap();
            assert_eq!(read_revision(dir.path()).unwrap().commit, None);
        }

        #[test]
        fn oversized_head_is_ignored() {
            let dir = checkout(&"a".repeat(2 * 1024 * 1024));
            assert_eq!(read_revision(dir.path()), None);
        }

        #[test]
        fn named_pipe_head_is_not_read_and_does_not_block() {
            let dir = checkout("placeholder");
            fs::remove_file(dir.path().join(".git/HEAD")).unwrap();
            let made = std::process::Command::new("mkfifo")
                .arg(dir.path().join(".git/HEAD"))
                .status()
                .map(|s| s.success())
                .unwrap_or(false);
            if !made {
                eprintln!("skipped: mkfifo is unavailable");
                return;
            }
            assert_eq!(read_revision(dir.path()), None);
        }

        #[test]
        fn git_file_pointing_elsewhere_gives_no_revision() {
            // Worktrees and submodules use a `.git` file. It is not followed.
            let dir = tempfile::tempdir().unwrap();
            fs::write(dir.path().join(".git"), "gitdir: /somewhere/else\n").unwrap();
            assert_eq!(read_revision(dir.path()), None);
        }
    }
}
