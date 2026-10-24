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

    // ---- Race tests -------------------------------------------------------
    //
    // Each test changes the filesystem at one exact step of discovery, using a
    // hook, and checks that nothing outside the root is read. The outside file
    // carries a unique marker and a `write-all` setting, so a leak would show
    // up as file content or as a finding.

    #[cfg(unix)]
    mod races {
        use super::*;
        use std::os::unix::fs::symlink;
        use std::sync::atomic::{AtomicUsize, Ordering};

        const MARKER: &str = "MERGELATCH_OUTSIDE_MARKER";
        const OUTSIDE_YAML: &str =
            "# MERGELATCH_OUTSIDE_MARKER\npermissions: write-all\njobs: {}\n";

        impl<F: Fn(Step<'_>)> Hooks for F {
            fn at(&self, step: Step<'_>) {
                self(step)
            }
        }

        struct Fixture {
            repo: tempfile::TempDir,
            outside: tempfile::TempDir,
        }

        impl Fixture {
            fn new() -> Self {
                let repo = repo_with(&[("ci.yml", "permissions:\n  contents: read\n")]);
                let outside = tempfile::tempdir().unwrap();
                fs::write(outside.path().join("evil.yml"), OUTSIDE_YAML).unwrap();
                fs::create_dir_all(outside.path().join("fake/workflows")).unwrap();
                fs::write(outside.path().join("fake/workflows/ci.yml"), OUTSIDE_YAML).unwrap();
                Self { repo, outside }
            }

            fn workflows(&self) -> std::path::PathBuf {
                self.repo.path().join(".github/workflows")
            }

            /// Runs discovery with `act` called whenever `trigger` is reached.
            /// Returns the result and how many times the action ran.
            fn run(&self, trigger: fn(&Step<'_>) -> bool, act: impl Fn()) -> (Discovery, usize) {
                let fired = AtomicUsize::new(0);
                let root = Dir::open_ambient_dir(self.repo.path(), ambient_authority()).unwrap();
                let hook = |step: Step<'_>| {
                    if trigger(&step) && fired.fetch_add(1, Ordering::SeqCst) == 0 {
                        act();
                    }
                };
                let found = discover_with(&root, &ScanLimits::default(), far_deadline(), &hook);
                (found, fired.load(Ordering::SeqCst))
            }
        }

        fn assert_no_leak(found: &Discovery) {
            for file in &found.files {
                assert!(!file.content.contains(MARKER), "outside content was read");
            }
            let dump = format!("{found:?}");
            assert!(!dump.contains(MARKER));
        }

        fn kinds(found: &Discovery) -> Vec<IncompleteKind> {
            found.incomplete.iter().map(|i| i.kind).collect()
        }

        #[test]
        fn without_interference_the_safe_file_is_read() {
            let fx = Fixture::new();
            let (found, _) = fx.run(|_| false, || {});
            assert_eq!(found.files.len(), 1);
            assert!(found.incomplete.is_empty());
        }

        fn swap_file_for_outside_link(fx: &Fixture) {
            let target = fx.workflows().join("ci.yml");
            fs::remove_file(&target).unwrap();
            symlink(fx.outside.path().join("evil.yml"), &target).unwrap();
        }

        #[test]
        fn file_replaced_by_outside_symlink_just_before_open() {
            let fx = Fixture::new();
            let (found, fired) = fx.run(
                |s| matches!(s, Step::BeforeOpenFile(_)),
                || swap_file_for_outside_link(&fx),
            );
            assert_eq!(fired, 1, "the race point must have been reached");
            assert_no_leak(&found);
            assert!(found.files.is_empty());
            assert_eq!(kinds(&found), [IncompleteKind::OutsideRoot]);
        }

        #[test]
        fn file_replaced_by_outside_symlink_after_listing() {
            let fx = Fixture::new();
            let (found, fired) = fx.run(
                |s| matches!(s, Step::AfterListing),
                || swap_file_for_outside_link(&fx),
            );
            assert_eq!(fired, 1);
            assert_no_leak(&found);
            assert_eq!(kinds(&found), [IncompleteKind::OutsideRoot]);
        }

        #[test]
        fn relative_symlink_climbing_out_of_the_root_is_refused() {
            let fx = Fixture::new();
            let (found, _) = fx.run(
                |s| matches!(s, Step::BeforeOpenFile(_)),
                || {
                    let target = fx.workflows().join("ci.yml");
                    fs::remove_file(&target).unwrap();
                    // Enough `..` components to reach the filesystem root,
                    // then down to the outside file.
                    let up = "../".repeat(40);
                    let link = format!("{up}{}", fx.outside.path().join("evil.yml").display());
                    symlink(link.replace("//", "/"), &target).unwrap();
                },
            );
            assert_no_leak(&found);
            assert!(found.files.is_empty());
            assert_eq!(kinds(&found), [IncompleteKind::OutsideRoot]);
        }

        #[test]
        fn workflows_directory_replaced_by_outside_symlink() {
            let fx = Fixture::new();
            let (found, fired) = fx.run(
                |s| matches!(s, Step::BeforeOpenWorkflows),
                || {
                    let wf = fx.workflows();
                    fs::rename(&wf, wf.with_file_name("workflows.bak")).unwrap();
                    symlink(fx.outside.path().join("fake/workflows"), &wf).unwrap();
                },
            );
            assert_eq!(fired, 1);
            assert_no_leak(&found);
            assert!(found.files.is_empty());
            assert_eq!(kinds(&found), [IncompleteKind::OutsideRoot]);
        }

        #[test]
        fn dot_github_replaced_by_outside_symlink_after_it_was_checked() {
            let fx = Fixture::new();
            let (found, fired) = fx.run(
                |s| matches!(s, Step::BeforeOpenWorkflows),
                || {
                    let gh = fx.repo.path().join(".github");
                    fs::rename(&gh, fx.repo.path().join("github.bak")).unwrap();
                    symlink(fx.outside.path().join("fake"), &gh).unwrap();
                },
            );
            assert_eq!(fired, 1);
            assert_no_leak(&found);
            assert!(found.files.is_empty());
            assert_eq!(kinds(&found), [IncompleteKind::OutsideRoot]);
        }

        #[test]
        fn workflows_directory_swapped_for_another_inside_the_root_stays_inside() {
            let fx = Fixture::new();
            let (found, _) = fx.run(
                |s| matches!(s, Step::AfterListing),
                || {
                    let wf = fx.workflows();
                    fs::rename(&wf, wf.with_file_name("workflows.old")).unwrap();
                    fs::create_dir(&wf).unwrap();
                    fs::write(wf.join("ci.yml"), "permissions: read-all\n").unwrap();
                },
            );
            assert_no_leak(&found);
            // Whatever is read came from inside the root.
            assert!(
                found
                    .files
                    .iter()
                    .all(|f| f.content == "permissions: read-all\n")
            );
        }

        #[test]
        fn file_replaced_by_named_pipe_is_not_read_and_does_not_block() {
            let fx = Fixture::new();
            let made = std::cell::Cell::new(true);
            let (found, _) = fx.run(
                |s| matches!(s, Step::BeforeOpenFile(_)),
                || {
                    let target = fx.workflows().join("ci.yml");
                    fs::remove_file(&target).unwrap();
                    let ok = std::process::Command::new("mkfifo")
                        .arg(&target)
                        .status()
                        .map(|s| s.success())
                        .unwrap_or(false);
                    made.set(ok);
                },
            );
            if !made.get() {
                eprintln!("skipped: mkfifo is unavailable");
                return;
            }
            assert!(found.files.is_empty());
            assert_eq!(kinds(&found), [IncompleteKind::NotRegularFile]);
        }

        #[test]
        fn file_replaced_by_device_symlink_is_not_read() {
            let fx = Fixture::new();
            let (found, _) = fx.run(
                |s| matches!(s, Step::BeforeOpenFile(_)),
                || {
                    let target = fx.workflows().join("ci.yml");
                    fs::remove_file(&target).unwrap();
                    symlink("/dev/zero", &target).unwrap();
                },
            );
            assert!(found.files.is_empty());
            assert_eq!(found.incomplete.len(), 1);
        }

        #[test]
        fn file_removed_before_open_is_incomplete() {
            let fx = Fixture::new();
            let (found, _) = fx.run(
                |s| matches!(s, Step::BeforeOpenFile(_)),
                || fs::remove_file(fx.workflows().join("ci.yml")).unwrap(),
            );
            assert!(found.files.is_empty());
            assert_eq!(kinds(&found), [IncompleteKind::Unreadable]);
        }

        /// Positive control: the previous design (canonicalize, check the
        /// prefix, then open by path) loses exactly this race. If this test
        /// stops reading the marker, the race tests above prove nothing.
        #[test]
        fn path_based_check_then_open_is_vulnerable_to_the_same_swap() {
            let fx = Fixture::new();
            let root = fs::canonicalize(fx.repo.path()).unwrap();
            let path = root.join(".github/workflows/ci.yml");

            // Time of check: the file resolves inside the root.
            let resolved = fs::canonicalize(&path).unwrap();
            assert!(resolved.starts_with(&root));

            // The swap lands between the check and the open.
            swap_file_for_outside_link(&fx);

            // Time of use: opening by path now follows the link out of the root.
            let content = fs::read_to_string(&path).unwrap();
            assert!(content.contains(MARKER));
        }

        #[test]
        fn unusual_file_names_are_handled() {
            use std::ffi::OsStr;
            use std::os::unix::ffi::OsStrExt;

            let dir = repo_with(&[]);
            let wf = dir.path().join(".github/workflows");
            fs::create_dir_all(&wf).unwrap();
            let long = format!("{}.yml", "a".repeat(200));
            let names: Vec<&OsStr> = vec![
                OsStr::new("with space.yml"),
                OsStr::new("-leading-dash.yml"),
                OsStr::new("back\\slash.yml"),
                OsStr::new("new\nline.yml"),
                OsStr::new("unicod\u{e9}-\u{4e2d}.yml"),
                OsStr::new(&long),
                OsStr::from_bytes(b"bad-\xff-utf8.yml"),
                OsStr::new("..yml"),
                OsStr::new(".yml"),
            ];
            for name in &names {
                fs::write(wf.join(name), "permissions: read-all\n").unwrap();
            }
            let found = discover(&dir);
            assert!(found.incomplete.is_empty(), "{:?}", found.incomplete);
            // `.yml` has no extension in std's view, so it is not a workflow.
            assert_eq!(found.files.len(), names.len() - 1);
            for file in &found.files {
                assert!(!file.path.chars().any(char::is_control), "{:?}", file.path);
                assert!(file.path.starts_with(".github/workflows/"));
            }
        }
    }
}
