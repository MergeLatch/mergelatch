use std::ffi::{OsStr, OsString};
use std::io::ErrorKind;
use std::path::Path;
use std::time::Instant;

use cap_std::fs::Dir;

use crate::fsaccess::{classify, describe, read_bounded, read_options};
use crate::{Incomplete, IncompleteKind, ScanLimits, sanitize_text};

const WORKFLOWS_DIR: &str = ".github/workflows";

/// A workflow file read as text. Its content is data and is never executed.
#[derive(Debug)]
pub(crate) struct WorkflowFile {
    /// Path relative to the scan root, using `/` separators.
    pub path: String,
    pub content: String,
}

#[derive(Debug, Default)]
pub(crate) struct Discovery {
    pub files: Vec<WorkflowFile>,
    pub incomplete: Vec<Incomplete>,
}

impl Discovery {
    fn gap(&mut self, path: Option<&str>, kind: IncompleteKind, detail: impl Into<String>) {
        self.incomplete.push(Incomplete {
            path: path.map(str::to_string),
            kind,
            detail: detail.into(),
        });
    }
}

/// Points in discovery where tests can change the filesystem, to prove that
/// a change at exactly that moment cannot redirect a read outside the root.
#[derive(Debug, Clone, Copy)]
#[allow(dead_code, reason = "only tests observe the steps")]
pub(crate) enum Step<'a> {
    BeforeOpenGithub,
    BeforeOpenWorkflows,
    AfterListing,
    BeforeOpenFile(&'a OsStr),
}

pub(crate) trait Hooks {
    fn at(&self, step: Step<'_>);
}

struct NoHooks;

impl Hooks for NoHooks {
    fn at(&self, _step: Step<'_>) {}
}

/// Finds and reads `.github/workflows/*.yml` and `*.yaml` under `root`.
///
/// Every path is resolved relative to the `root` handle, so nothing can be
/// opened outside it even if the tree changes during the scan. Absolute
/// symlinks are refused, and relative links may not climb above the root. Anything that
/// cannot be read, is too large, is not a regular file, or would leave the
/// root is recorded as incomplete instead of being skipped silently. Files are
/// opened and read, never run.
pub(crate) fn discover_workflows(root: &Dir, limits: &ScanLimits, deadline: Instant) -> Discovery {
    discover_with(root, limits, deadline, &NoHooks)
}

pub(crate) fn discover_with(
    root: &Dir,
    limits: &ScanLimits,
    deadline: Instant,
    hooks: &dyn Hooks,
) -> Discovery {
    let mut found = Discovery::default();

    hooks.at(Step::BeforeOpenGithub);
    // `.github` is opened only to learn whether it exists and is usable; the
    // handle is not reused, because every later path is resolved from `root`.
    if open_subdir(root, ".github", &mut found).is_none() {
        return found;
    }
    hooks.at(Step::BeforeOpenWorkflows);
    let Some(workflows) = open_subdir(root, WORKFLOWS_DIR, &mut found) else {
        return found;
    };

    let Some(names) = list_dir(&workflows, limits, &mut found) else {
        return found;
    };
    hooks.at(Step::AfterListing);

    let mut total_bytes: u64 = 0;
    for name in names {
        if Instant::now() >= deadline {
            found.gap(
                None,
                IncompleteKind::Timeout,
                "time limit reached before all workflow files were inspected",
            );
            break;
        }
        if !has_workflow_extension(&name) {
            continue;
        }
        let rel = format!(
            "{WORKFLOWS_DIR}/{}",
            sanitize_text(&name.to_string_lossy(), 200)
        );
        hooks.at(Step::BeforeOpenFile(&name));
        if !read_one(root, &name, &rel, limits, &mut total_bytes, &mut found) {
            break;
        }
    }
    found
}

/// Opens a directory by its path relative to the root handle. Returns `None` when it does
/// not exist (nothing to inspect) or cannot be opened safely (recorded as
/// incomplete).
fn open_subdir(root: &Dir, rel: &str, found: &mut Discovery) -> Option<Dir> {
    match root.open_dir(rel) {
        Ok(dir) => Some(dir),
        Err(e) if e.kind() == ErrorKind::NotFound => {
            // Missing is fine. A link whose target is missing is not.
            if root.symlink_metadata(rel).is_ok() {
                found.gap(
                    Some(rel),
                    IncompleteKind::Unreadable,
                    "symbolic link target does not exist",
                );
            }
            None
        }
        // A plain file where a directory is expected: GitHub ignores it too.
        Err(e) if e.kind() == ErrorKind::NotADirectory => None,
        Err(e) => {
            found.gap(Some(rel), classify(&e), describe(&e));
            None
        }
    }
}

fn list_dir(dir: &Dir, limits: &ScanLimits, found: &mut Discovery) -> Option<Vec<OsString>> {
    let entries = match dir.entries() {
        Ok(entries) => entries,
        Err(e) => {
            found.gap(Some(WORKFLOWS_DIR), classify(&e), describe(&e));
            return None;
        }
    };
    let mut names = Vec::new();
    for entry in entries {
        if names.len() >= limits.max_entries {
            found.gap(
                Some(WORKFLOWS_DIR),
                IncompleteKind::LimitExceeded,
                format!("more than {} directory entries", limits.max_entries),
            );
            break;
        }
        match entry {
            Ok(entry) => names.push(entry.file_name()),
            Err(e) => found.gap(
                Some(WORKFLOWS_DIR),
                IncompleteKind::Unreadable,
                e.to_string(),
            ),
        }
    }
    names.sort();
    Some(names)
}

fn has_workflow_extension(name: &OsString) -> bool {
    Path::new(name)
        .extension()
        .and_then(|ext| ext.to_str())
        .is_some_and(|ext| ext.eq_ignore_ascii_case("yml") || ext.eq_ignore_ascii_case("yaml"))
}

/// Reads one candidate file. Returns `false` when the scan should stop.
///
/// The file is opened once through the root handle, and its type and size
/// are taken from that open handle, not from an earlier lookup by name.
fn read_one(
    root: &Dir,
    name: &OsString,
    rel: &str,
    limits: &ScanLimits,
    total_bytes: &mut u64,
    found: &mut Discovery,
) -> bool {
    // Resolved from the root handle on every call, never from the path of an
    // earlier lookup. A link anywhere on the path that leads outside the root
    // is refused by the operating system call itself.
    let path = Path::new(WORKFLOWS_DIR).join(name);
    let file = match root.open_with(&path, &read_options()) {
        Ok(file) => file,
        Err(e) if e.kind() == ErrorKind::NotFound => {
            let detail = if root.symlink_metadata(&path).is_ok() {
                "symbolic link target does not exist".to_string()
            } else {
                "file disappeared during the scan".to_string()
            };
            found.gap(Some(rel), IncompleteKind::Unreadable, detail);
            return true;
        }
        Err(e) => {
            found.gap(Some(rel), classify(&e), describe(&e));
            return true;
        }
    };
    let meta = match file.metadata() {
        Ok(meta) => meta,
        Err(e) => {
            found.gap(Some(rel), IncompleteKind::Unreadable, e.to_string());
            return true;
        }
    };
    if meta.is_dir() {
        return true;
    }
    if !meta.is_file() {
        found.gap(
            Some(rel),
            IncompleteKind::NotRegularFile,
            "not a regular file; it was not read",
        );
        return true;
    }
    if meta.len() > limits.max_file_bytes {
        found.gap(
            Some(rel),
            IncompleteKind::FileTooLarge,
            format!(
                "{} bytes exceeds the {} byte limit",
                meta.len(),
                limits.max_file_bytes
            ),
        );
        return true;
    }
    if total_bytes.saturating_add(meta.len()) > limits.max_total_bytes {
        found.gap(
            Some(rel),
            IncompleteKind::LimitExceeded,
            format!(
                "total read limit of {} bytes reached",
                limits.max_total_bytes
            ),
        );
        return false;
    }

    // Read at most one byte past the limit so a file that grew after the
    // size check is still caught.
    let bytes = match read_bounded(file, limits.max_file_bytes) {
        Ok(Some(bytes)) => bytes,
        Ok(None) => {
            found.gap(
                Some(rel),
                IncompleteKind::FileTooLarge,
                format!("file exceeds the {} byte limit", limits.max_file_bytes),
            );
            return true;
        }
        Err(e) => {
            found.gap(Some(rel), IncompleteKind::Unreadable, e.to_string());
            return true;
        }
    };
    *total_bytes += bytes.len() as u64;

    match String::from_utf8(bytes) {
        Ok(text) => found.files.push(WorkflowFile {
            path: rel.to_string(),
            content: text.strip_prefix('\u{feff}').unwrap_or(&text).to_string(),
        }),
        Err(_) => found.gap(
            Some(rel),
            IncompleteKind::InvalidUtf8,
            "file is not valid UTF-8",
        ),
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::time::Duration;

    use cap_std::ambient_authority;

    fn far_deadline() -> Instant {
        Instant::now() + Duration::from_secs(60)
    }

    fn repo_with(files: &[(&str, &str)]) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        for (name, content) in files {
            let path = dir.path().join(".github/workflows").join(name);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, content).unwrap();
        }
        dir
    }

    fn discover(dir: &tempfile::TempDir) -> Discovery {
        let root = Dir::open_ambient_dir(dir.path(), ambient_authority()).unwrap();
        discover_workflows(&root, &ScanLimits::default(), far_deadline())
    }

    #[test]
    fn repository_without_workflows_has_nothing_to_inspect() {
        let dir = tempfile::tempdir().unwrap();
        let found = discover(&dir);
        assert!(found.files.is_empty());
        assert!(found.incomplete.is_empty());
    }

    #[test]
    fn yml_and_yaml_files_are_read_in_name_order() {
        let dir = repo_with(&[("b.yaml", "b"), ("a.yml", "a"), ("notes.txt", "x")]);
        let found = discover(&dir);
        let paths: Vec<_> = found.files.iter().map(|f| f.path.as_str()).collect();
        assert_eq!(
            paths,
            [".github/workflows/a.yml", ".github/workflows/b.yaml"]
        );
        assert!(found.incomplete.is_empty());
    }

    #[test]
    fn byte_order_mark_is_removed() {
        let dir = repo_with(&[("a.yml", "\u{feff}name: x")]);
        assert_eq!(discover(&dir).files[0].content, "name: x");
    }
}
