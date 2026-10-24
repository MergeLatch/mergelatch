use std::ffi::OsString;
use std::fs::{self, File};
use std::io::{ErrorKind, Read};
use std::path::{Path, PathBuf};
use std::time::Instant;

use crate::{Incomplete, IncompleteKind, ScanLimits, sanitize_text};

const WORKFLOWS_DIR: &str = ".github/workflows";

/// A workflow file read as text. Its content is data and is never executed.
#[derive(Debug)]
#[cfg_attr(
    not(test),
    expect(dead_code, reason = "read by the rule engine added in a later commit")
)]
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

/// Finds and reads `.github/workflows/*.yml` and `*.yaml` under `root`.
///
/// `root` must already be canonical. Every path that is read is canonicalized
/// and must stay inside `root`; anything that cannot be read, is too large, or
/// lies outside the root is recorded as incomplete instead of being skipped
/// silently. Files are opened and read, never run.
pub(crate) fn discover_workflows(root: &Path, limits: &ScanLimits, deadline: Instant) -> Discovery {
    let mut found = Discovery::default();

    let Some(dir) = workflows_dir(root, &mut found) else {
        return found;
    };

    let names = match list_dir(&dir, limits, &mut found) {
        Some(names) => names,
        None => return found,
    };

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
        if !read_one(
            root,
            &dir.join(&name),
            &rel,
            limits,
            &mut total_bytes,
            &mut found,
        ) {
            break;
        }
    }
    found
}

/// Resolves `.github/workflows`, returning `None` when it does not exist or
/// cannot be inspected safely (the latter is recorded as incomplete).
fn workflows_dir(root: &Path, found: &mut Discovery) -> Option<PathBuf> {
    let github = root.join(".github");
    match fs::symlink_metadata(&github) {
        Err(e) if e.kind() == ErrorKind::NotFound => return None,
        Err(e) => {
            found.gap(Some(".github"), IncompleteKind::Unreadable, e.to_string());
            return None;
        }
        Ok(_) => {}
    }
    let github = resolve_within(root, &github, ".github", found)?;
    if !github.is_dir() {
        return None;
    }

    let workflows = github.join("workflows");
    match fs::symlink_metadata(&workflows) {
        Err(e) if e.kind() == ErrorKind::NotFound => return None,
        Err(e) => {
            found.gap(
                Some(WORKFLOWS_DIR),
                IncompleteKind::Unreadable,
                e.to_string(),
            );
            return None;
        }
        Ok(_) => {}
    }
    let workflows = resolve_within(root, &workflows, WORKFLOWS_DIR, found)?;
    workflows.is_dir().then_some(workflows)
}

/// Canonicalizes `path` and requires the result to be inside `root`.
fn resolve_within(root: &Path, path: &Path, rel: &str, found: &mut Discovery) -> Option<PathBuf> {
    match fs::canonicalize(path) {
        Ok(real) if real.starts_with(root) => Some(real),
        Ok(_) => {
            found.gap(
                Some(rel),
                IncompleteKind::OutsideRoot,
                "path resolves outside the scan root and was not followed",
            );
            None
        }
        Err(e) => {
            found.gap(
                Some(rel),
                IncompleteKind::Unreadable,
                format!("cannot resolve path: {e}"),
            );
            None
        }
    }
}

fn list_dir(dir: &Path, limits: &ScanLimits, found: &mut Discovery) -> Option<Vec<OsString>> {
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) => {
            found.gap(
                Some(WORKFLOWS_DIR),
                IncompleteKind::Unreadable,
                e.to_string(),
            );
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
fn read_one(
    root: &Path,
    path: &Path,
    rel: &str,
    limits: &ScanLimits,
    total_bytes: &mut u64,
    found: &mut Discovery,
) -> bool {
    let link = match fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(e) => {
            found.gap(Some(rel), IncompleteKind::Unreadable, e.to_string());
            return true;
        }
    };
    let real = if link.file_type().is_symlink() {
        match resolve_within(root, path, rel, found) {
            Some(real) => real,
            None => return true,
        }
    } else {
        path.to_path_buf()
    };
    let meta = match fs::metadata(&real) {
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
            "not a regular file; it was not opened",
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
    let mut bytes = Vec::new();
    let read =
        File::open(&real).and_then(|f| f.take(limits.max_file_bytes + 1).read_to_end(&mut bytes));
    if let Err(e) = read {
        found.gap(Some(rel), IncompleteKind::Unreadable, e.to_string());
        return true;
    }
    if bytes.len() as u64 > limits.max_file_bytes {
        found.gap(
            Some(rel),
            IncompleteKind::FileTooLarge,
            format!("file exceeds the {} byte limit", limits.max_file_bytes),
        );
        return true;
    }
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
    use std::time::Duration;

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
        let root = fs::canonicalize(dir.path()).unwrap();
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
