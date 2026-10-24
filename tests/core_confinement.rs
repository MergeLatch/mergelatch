//! Concurrent-modification tests for the confined filesystem access.
//!
//! A background thread keeps changing the scanned tree while scans run. The
//! outside directory holds a file with a unique marker and `permissions:
//! write-all`; the legitimate workflow is read-only. Any finding, or any trace
//! of the marker in a report, therefore means a read crossed the root.
//!
//! These runs are stress tests and cannot prove the absence of a race. The
//! deterministic proof of each swap point is in the unit tests in
//! `crates/core/src/discover.rs`.

#![cfg(target_os = "linux")]

use std::fs;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::thread;

use mergelatch_core::{Report, ScanLimits, ScanStatus, scan_directory};

const MARKER: &str = "MERGELATCH_OUTSIDE_MARKER";
const OUTSIDE_YAML: &str = "# MERGELATCH_OUTSIDE_MARKER\npermissions: write-all\njobs: {}\n";
const SAFE_YAML: &str = "on: push\npermissions:\n  contents: read\njobs: {}\n";
const ID: &str = "0123456789abcdef0123456789abcdef01234567";
const OUTSIDE_ID: &str = "ffffffffffffffffffffffffffffffffffffffff";
const SCANS: usize = 300;

#[derive(Clone)]
struct Paths {
    repo: PathBuf,
    outside: PathBuf,
}

struct World {
    repo: tempfile::TempDir,
    outside: tempfile::TempDir,
}

impl World {
    fn new() -> Self {
        let repo = tempfile::tempdir().unwrap();
        let wf = repo.path().join(".github/workflows");
        fs::create_dir_all(&wf).unwrap();
        fs::write(wf.join("ci.yml"), SAFE_YAML).unwrap();
        fs::write(wf.join("other.yml"), SAFE_YAML).unwrap();
        fs::create_dir_all(repo.path().join(".git/refs/heads")).unwrap();
        fs::write(repo.path().join(".git/HEAD"), "ref: refs/heads/main\n").unwrap();
        fs::write(repo.path().join(".git/refs/heads/main"), format!("{ID}\n")).unwrap();

        let outside = tempfile::tempdir().unwrap();
        fs::write(outside.path().join("evil.yml"), OUTSIDE_YAML).unwrap();
        fs::create_dir_all(outside.path().join("fake/workflows")).unwrap();
        fs::write(outside.path().join("fake/workflows/ci.yml"), OUTSIDE_YAML).unwrap();
        fs::write(
            outside.path().join("head"),
            format!("ref: refs/heads/{MARKER}\n"),
        )
        .unwrap();
        fs::write(outside.path().join("ref"), format!("{OUTSIDE_ID}\n")).unwrap();
        Self { repo, outside }
    }

    fn paths(&self) -> Paths {
        Paths {
            repo: self.repo.path().to_path_buf(),
            outside: self.outside.path().to_path_buf(),
        }
    }
}

/// Replaces `path` with a symlink to `target`, or restores it from `restore`.
/// Errors are ignored: the scanner may be mid-read, and the point is the churn.
fn swap_file(path: &Path, target: &Path, restore: &str, use_link: bool) {
    let tmp = path.with_extension("tmp");
    let _ = fs::remove_file(&tmp);
    if use_link {
        let _ = symlink(target, &tmp);
    } else {
        let _ = fs::write(&tmp, restore);
    }
    // rename is atomic, so the scanner sees either the old or the new entry.
    let _ = fs::rename(&tmp, path);
}

fn swap_dir(path: &Path, target: &Path, backup: &Path, use_link: bool) {
    // Directories cannot be renamed over symlinks atomically, so use two steps.
    if use_link {
        if fs::rename(path, backup).is_ok() {
            let _ = symlink(target, path);
        }
    } else if fs::symlink_metadata(path)
        .map(|m| m.file_type().is_symlink())
        .unwrap_or(false)
    {
        let _ = fs::remove_file(path);
        let _ = fs::rename(backup, path);
    }
}

/// Runs `flip` repeatedly on another thread while `SCANS` scans run.
fn scan_while(world: &World, flip: impl Fn(&Paths, usize) + Send + 'static) -> Vec<Report> {
    let paths = world.paths();
    let stop = Arc::new(AtomicBool::new(false));
    let flips = Arc::new(AtomicUsize::new(0));
    let worker = {
        let (paths, stop, flips) = (paths.clone(), Arc::clone(&stop), Arc::clone(&flips));
        thread::spawn(move || {
            let mut i = 0;
            while !stop.load(Ordering::Relaxed) {
                flip(&paths, i);
                flips.fetch_add(1, Ordering::Relaxed);
                i += 1;
            }
        })
    };
    // Keep scanning until the flipper has actually run, so a fast scan loop
    // cannot finish before the other thread gets scheduled.
    let mut reports = Vec::new();
    while reports.len() < SCANS || (flips.load(Ordering::Relaxed) < 50 && reports.len() < 20_000) {
        reports.push(scan_directory(&paths.repo, &ScanLimits::default()).expect("scan should run"));
    }
    stop.store(true, Ordering::Relaxed);
    worker.join().unwrap();
    assert!(
        flips.load(Ordering::Relaxed) > 10,
        "the tree was barely modified"
    );
    reports
}

fn assert_nothing_leaked(reports: &[Report]) {
    for report in reports {
        let json = report.to_json();
        assert!(!json.contains(MARKER), "marker leaked:\n{json}");
        assert!(!json.contains(OUTSIDE_ID), "outside commit leaked:\n{json}");
        assert!(
            report.findings.is_empty(),
            "a finding can only come from the outside file:\n{json}"
        );
        assert_ne!(report.status, ScanStatus::Findings);
    }
}

#[test]
fn workflow_file_flipping_between_real_and_outside_symlink() {
    let world = World::new();
    let reports = scan_while(&world, |p, i| {
        let file = p.repo.join(".github/workflows/ci.yml");
        swap_file(&file, &p.outside.join("evil.yml"), SAFE_YAML, i % 2 == 0);
    });
    assert_nothing_leaked(&reports);
}

#[test]
fn many_workflow_files_flipping_at_once() {
    let world = World::new();
    let reports = scan_while(&world, |p, i| {
        for name in ["ci.yml", "other.yml"] {
            let file = p.repo.join(".github/workflows").join(name);
            swap_file(
                &file,
                &p.outside.join("evil.yml"),
                SAFE_YAML,
                (i + name.len()) % 2 == 0,
            );
        }
    });
    assert_nothing_leaked(&reports);
}

#[test]
fn workflows_directory_flipping_between_real_and_outside_symlink() {
    let world = World::new();
    let reports = scan_while(&world, |p, i| {
        swap_dir(
            &p.repo.join(".github/workflows"),
            &p.outside.join("fake/workflows"),
            &p.repo.join(".github/workflows.bak"),
            i % 2 == 0,
        );
    });
    assert_nothing_leaked(&reports);
}

#[test]
fn dot_github_directory_flipping_between_real_and_outside_symlink() {
    let world = World::new();
    let reports = scan_while(&world, |p, i| {
        swap_dir(
            &p.repo.join(".github"),
            &p.outside.join("fake"),
            &p.repo.join("github.bak"),
            i % 2 == 0,
        );
    });
    assert_nothing_leaked(&reports);
}

#[test]
fn git_metadata_flipping_between_real_and_outside_symlink() {
    let world = World::new();
    let reports = scan_while(&world, |p, i| {
        let head = p.repo.join(".git/HEAD");
        swap_file(
            &head,
            &p.outside.join("head"),
            "ref: refs/heads/main\n",
            i % 2 == 0,
        );
        let reference = p.repo.join(".git/refs/heads/main");
        swap_file(
            &reference,
            &p.outside.join("ref"),
            &format!("{ID}\n"),
            i % 3 == 0,
        );
    });
    assert_nothing_leaked(&reports);
    // Revision data is either the real one or absent, never the outside one.
    for report in &reports {
        if let Some(rev) = &report.target.revision {
            assert!(rev.commit.as_deref().is_none_or(|c| c == ID));
        }
    }
}

#[test]
fn quiet_tree_still_scans_clean_with_a_revision() {
    // Control: the same repository without interference is clean and carries
    // the real revision, so the tests above are not passing by failing every scan.
    let world = World::new();
    let report = scan_directory(&world.paths().repo, &ScanLimits::default()).unwrap();
    assert_eq!(report.status, ScanStatus::Clean);
    assert_eq!(report.summary.files_inspected, 2);
    assert_eq!(report.target.revision.unwrap().commit.as_deref(), Some(ID));
}
