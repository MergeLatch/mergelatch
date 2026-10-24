//! Safety properties of the scanner: it treats input as data, stays inside
//! the scan root, enforces limits, and never reports a gap as clean.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use mergelatch_core::{IncompleteKind, Report, ScanError, ScanLimits, ScanStatus, scan_directory};

const WRITE_ALL: &str = "on: push\npermissions: write-all\njobs: {}\n";
const SAFE: &str = "on: push\npermissions:\n  contents: read\njobs: {}\n";

fn repo() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    fs::create_dir_all(dir.path().join(".github/workflows")).unwrap();
    dir
}

fn workflow(dir: &tempfile::TempDir, name: &str) -> PathBuf {
    dir.path().join(".github/workflows").join(name)
}

fn scan(dir: &Path) -> Report {
    scan_directory(dir, &ScanLimits::default()).expect("scan should run")
}

fn kinds(report: &Report) -> Vec<IncompleteKind> {
    report.incomplete.iter().map(|i| i.kind).collect()
}

#[test]
fn missing_target_is_an_error() {
    let dir = tempfile::tempdir().unwrap();
    let result = scan_directory(&dir.path().join("nope"), &ScanLimits::default());
    assert!(matches!(result, Err(ScanError::InvalidTarget(_))));
}

#[test]
fn file_target_is_an_error() {
    let dir = repo();
    fs::write(workflow(&dir, "ci.yml"), SAFE).unwrap();
    let result = scan_directory(&workflow(&dir, "ci.yml"), &ScanLimits::default());
    assert!(matches!(result, Err(ScanError::InvalidTarget(_))));
}

#[test]
fn repository_without_workflows_is_clean() {
    let dir = tempfile::tempdir().unwrap();
    let report = scan(dir.path());
    assert_eq!(report.status, ScanStatus::Clean);
    assert_eq!(report.summary.files_inspected, 0);
}

#[test]
fn oversized_file_is_incomplete() {
    let dir = repo();
    fs::write(workflow(&dir, "ci.yml"), SAFE).unwrap();
    let limits = ScanLimits {
        max_file_bytes: 10,
        ..ScanLimits::default()
    };
    let report = scan_directory(dir.path(), &limits).unwrap();
    assert_eq!(report.status, ScanStatus::Incomplete);
    assert_eq!(kinds(&report), [IncompleteKind::FileTooLarge]);
    assert_eq!(report.summary.files_inspected, 0);
}

#[test]
fn total_read_limit_is_enforced() {
    let dir = repo();
    fs::write(workflow(&dir, "a.yml"), SAFE).unwrap();
    fs::write(workflow(&dir, "b.yml"), SAFE).unwrap();
    let limits = ScanLimits {
        max_total_bytes: SAFE.len() as u64 + 1,
        ..ScanLimits::default()
    };
    let report = scan_directory(dir.path(), &limits).unwrap();
    assert_eq!(report.status, ScanStatus::Incomplete);
    assert_eq!(kinds(&report), [IncompleteKind::LimitExceeded]);
    assert_eq!(report.summary.files_inspected, 1);
}

#[test]
fn entry_limit_is_enforced() {
    let dir = repo();
    for i in 0..5 {
        fs::write(workflow(&dir, &format!("w{i}.yml")), SAFE).unwrap();
    }
    let limits = ScanLimits {
        max_entries: 3,
        ..ScanLimits::default()
    };
    let report = scan_directory(dir.path(), &limits).unwrap();
    assert_eq!(report.status, ScanStatus::Incomplete);
    assert_eq!(kinds(&report), [IncompleteKind::LimitExceeded]);
}

#[test]
fn expired_time_limit_is_incomplete() {
    let dir = repo();
    fs::write(workflow(&dir, "ci.yml"), WRITE_ALL).unwrap();
    let limits = ScanLimits {
        timeout: Duration::ZERO,
        ..ScanLimits::default()
    };
    let report = scan_directory(dir.path(), &limits).unwrap();
    assert_eq!(report.status, ScanStatus::Incomplete);
    assert!(kinds(&report).contains(&IncompleteKind::Timeout));
}

#[test]
fn scan_finishing_after_the_deadline_is_never_clean() {
    // With a zero limit the deadline has passed before any work completes.
    // Every shape of repository must come back incomplete, not clean.
    let limits = ScanLimits {
        timeout: Duration::ZERO,
        ..ScanLimits::default()
    };

    let empty = tempfile::tempdir().unwrap();
    let report = scan_directory(empty.path(), &limits).unwrap();
    assert_eq!(report.status, ScanStatus::Incomplete);
    assert_eq!(kinds(&report), [IncompleteKind::Timeout]);

    let safe = repo();
    fs::write(workflow(&safe, "ci.yml"), SAFE).unwrap();
    let report = scan_directory(safe.path(), &limits).unwrap();
    assert_eq!(report.status, ScanStatus::Incomplete);
    assert_eq!(kinds(&report), [IncompleteKind::Timeout]);
}

#[test]
fn timeout_is_reported_once_and_findings_are_kept() {
    let dir = repo();
    for name in ["a.yml", "b.yml", "c.yml"] {
        fs::write(workflow(&dir, name), WRITE_ALL).unwrap();
    }
    let limits = ScanLimits {
        timeout: Duration::ZERO,
        ..ScanLimits::default()
    };
    let report = scan_directory(dir.path(), &limits).unwrap();
    assert_eq!(report.status, ScanStatus::Incomplete);
    let timeouts = kinds(&report)
        .into_iter()
        .filter(|k| *k == IncompleteKind::Timeout)
        .count();
    assert_eq!(timeouts, 1);
}

#[test]
fn generous_time_limit_does_not_change_results() {
    let dir = repo();
    fs::write(workflow(&dir, "ci.yml"), WRITE_ALL).unwrap();
    let limits = ScanLimits {
        timeout: Duration::from_secs(3600),
        ..ScanLimits::default()
    };
    let report = scan_directory(dir.path(), &limits).unwrap();
    assert_eq!(report.status, ScanStatus::Findings);
}

#[test]
fn unrepresentable_time_limit_does_not_panic() {
    let dir = repo();
    fs::write(workflow(&dir, "ci.yml"), SAFE).unwrap();
    let limits = ScanLimits {
        timeout: Duration::MAX,
        ..ScanLimits::default()
    };
    assert_eq!(
        scan_directory(dir.path(), &limits).unwrap().status,
        ScanStatus::Clean
    );
}

#[test]
fn deeply_nested_yaml_is_incomplete() {
    let dir = repo();
    let deep = format!("a: {}{}\n", "[".repeat(200), "]".repeat(200));
    fs::write(workflow(&dir, "ci.yml"), deep).unwrap();
    let report = scan(dir.path());
    assert_eq!(report.status, ScanStatus::Incomplete);
    assert_eq!(kinds(&report), [IncompleteKind::LimitExceeded]);
}

#[test]
fn large_alias_structure_does_not_expand() {
    let dir = repo();
    let mut yaml = String::from("a: &a [x, x, x, x, x, x, x, x, x]\n");
    for (prev, next) in ["b", "c", "d", "e", "f", "g", "h", "i"]
        .iter()
        .scan("a", |p, n| {
            let pair = (*p, n);
            *p = n;
            Some(pair)
        })
    {
        yaml.push_str(&format!(
            "{next}: &{next} [*{prev}, *{prev}, *{prev}, *{prev}, *{prev}, *{prev}, *{prev}, *{prev}, *{prev}]\n"
        ));
    }
    fs::write(workflow(&dir, "ci.yml"), yaml).unwrap();
    let report = scan(dir.path());
    assert_eq!(report.status, ScanStatus::Clean);
    assert_eq!(report.summary.files_inspected, 1);
}

#[test]
fn invalid_utf8_is_incomplete() {
    let dir = repo();
    fs::write(workflow(&dir, "ci.yml"), [0x6f, 0x6e, 0x3a, 0xff, 0xfe]).unwrap();
    let report = scan(dir.path());
    assert_eq!(report.status, ScanStatus::Incomplete);
    assert_eq!(kinds(&report), [IncompleteKind::InvalidUtf8]);
}

#[test]
fn other_extensions_and_subdirectories_are_ignored() {
    let dir = repo();
    fs::write(workflow(&dir, "notes.txt"), WRITE_ALL).unwrap();
    fs::create_dir(workflow(&dir, "nested")).unwrap();
    fs::write(workflow(&dir, "nested/ci.yml"), WRITE_ALL).unwrap();
    fs::create_dir(workflow(&dir, "dir.yml")).unwrap();
    let report = scan(dir.path());
    assert_eq!(report.status, ScanStatus::Clean);
    assert_eq!(report.summary.files_inspected, 0);
}

#[cfg(unix)]
mod unix {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::process::Command;
    use std::sync::mpsc;

    #[test]
    fn symlinked_workflow_outside_root_is_not_followed() {
        let outside = tempfile::tempdir().unwrap();
        fs::write(outside.path().join("secret.yml"), WRITE_ALL).unwrap();
        let dir = repo();
        symlink(outside.path().join("secret.yml"), workflow(&dir, "ci.yml")).unwrap();
        let report = scan(dir.path());
        assert_eq!(report.status, ScanStatus::Incomplete);
        assert_eq!(kinds(&report), [IncompleteKind::OutsideRoot]);
        assert!(
            report.findings.is_empty(),
            "outside content must not be read"
        );
    }

    #[test]
    fn symlinked_workflows_directory_outside_root_is_not_followed() {
        let outside = tempfile::tempdir().unwrap();
        fs::write(outside.path().join("ci.yml"), WRITE_ALL).unwrap();
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir(dir.path().join(".github")).unwrap();
        symlink(outside.path(), dir.path().join(".github/workflows")).unwrap();
        let report = scan(dir.path());
        assert_eq!(report.status, ScanStatus::Incomplete);
        assert_eq!(kinds(&report), [IncompleteKind::OutsideRoot]);
        assert!(report.findings.is_empty());
    }

    #[test]
    fn symlinked_dot_github_outside_root_is_not_followed() {
        let outside = tempfile::tempdir().unwrap();
        fs::create_dir(outside.path().join("workflows")).unwrap();
        fs::write(outside.path().join("workflows/ci.yml"), WRITE_ALL).unwrap();
        let dir = tempfile::tempdir().unwrap();
        symlink(outside.path(), dir.path().join(".github")).unwrap();
        let report = scan(dir.path());
        assert_eq!(report.status, ScanStatus::Incomplete);
        assert!(report.findings.is_empty());
    }

    #[test]
    fn relative_symlink_to_a_file_inside_root_is_read() {
        let dir = repo();
        fs::write(dir.path().join("shared.yml"), WRITE_ALL).unwrap();
        symlink("../../shared.yml", workflow(&dir, "ci.yml")).unwrap();
        let report = scan(dir.path());
        assert_eq!(report.status, ScanStatus::Findings);
    }

    #[test]
    fn absolute_symlink_is_not_followed_even_when_it_points_inside_root() {
        // Behavior change from the path-based scanner: confinement cannot
        // follow an absolute link, so it is reported instead of being read.
        let dir = repo();
        fs::write(dir.path().join("shared.yml"), WRITE_ALL).unwrap();
        symlink(dir.path().join("shared.yml"), workflow(&dir, "ci.yml")).unwrap();
        let report = scan(dir.path());
        assert_eq!(report.status, ScanStatus::Incomplete);
        assert_eq!(kinds(&report), [IncompleteKind::OutsideRoot]);
        assert!(report.findings.is_empty());
    }

    #[test]
    fn dangling_symlink_is_incomplete() {
        let dir = repo();
        symlink("../../missing.yml", workflow(&dir, "ci.yml")).unwrap();
        let report = scan(dir.path());
        assert_eq!(report.status, ScanStatus::Incomplete);
        assert_eq!(kinds(&report), [IncompleteKind::Unreadable]);
    }

    #[test]
    fn symlink_loop_is_incomplete() {
        let dir = repo();
        symlink(workflow(&dir, "b.yml"), workflow(&dir, "a.yml")).unwrap();
        symlink(workflow(&dir, "a.yml"), workflow(&dir, "b.yml")).unwrap();
        let report = scan(dir.path());
        assert_eq!(report.status, ScanStatus::Incomplete);
    }

    #[test]
    fn unreadable_file_is_incomplete() {
        let dir = repo();
        let path = workflow(&dir, "ci.yml");
        fs::write(&path, WRITE_ALL).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o000)).unwrap();
        if fs::File::open(&path).is_ok() {
            eprintln!("skipped: permissions are not enforced for this user");
            return;
        }
        let report = scan(dir.path());
        assert_eq!(report.status, ScanStatus::Incomplete);
        assert_eq!(kinds(&report), [IncompleteKind::Unreadable]);
    }

    #[test]
    fn named_pipe_is_not_opened() {
        let dir = repo();
        let made = Command::new("mkfifo")
            .arg(workflow(&dir, "ci.yml"))
            .status();
        if !matches!(made, Ok(s) if s.success()) {
            eprintln!("skipped: mkfifo is unavailable");
            return;
        }
        let root = dir.path().to_path_buf();
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(scan_directory(&root, &ScanLimits::default()));
        });
        let report = rx
            .recv_timeout(Duration::from_secs(20))
            .expect("scan must not block on a named pipe")
            .unwrap();
        assert_eq!(report.status, ScanStatus::Incomplete);
        assert_eq!(kinds(&report), [IncompleteKind::NotRegularFile]);
    }

    #[test]
    fn scanned_content_is_never_executed() {
        let dir = repo();
        let marker = dir.path().join("EXECUTED_MARKER");
        let touch = format!("touch '{}'", marker.display());
        let script = format!("#!/bin/sh\n{touch}\n");

        // Commands that would run if anything executed or interpreted the content.
        fs::write(
            workflow(&dir, "ci.yml"),
            format!("on: push\npermissions: write-all\njobs:\n  a:\n    steps:\n      - run: \"{touch}\"\n"),
        )
        .unwrap();
        let hooks = dir.path().join(".git/hooks");
        fs::create_dir_all(&hooks).unwrap();
        fs::write(dir.path().join(".git/HEAD"), "ref: refs/heads/main\n").unwrap();
        fs::write(
            dir.path().join(".git/config"),
            format!(
                "[core]\n\tfsmonitor = {touch}\n\thooksPath = hooks\n[filter \"x\"]\n\tclean = {touch}\n"
            ),
        )
        .unwrap();
        for hook in [
            "pre-commit",
            "post-checkout",
            "post-merge",
            "fsmonitor-watchman",
        ] {
            let path = hooks.join(hook);
            fs::write(&path, &script).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
        }
        fs::write(dir.path().join(".gitattributes"), "* filter=x\n").unwrap();
        fs::write(
            dir.path().join("package.json"),
            format!("{{\"scripts\":{{\"postinstall\":\"{touch}\",\"test\":\"{touch}\"}}}}"),
        )
        .unwrap();
        fs::write(dir.path().join("Makefile"), format!("all:\n\t{touch}\n")).unwrap();
        fs::write(dir.path().join("build.rs"), format!("fn main() {{ std::process::Command::new(\"sh\").arg(\"-c\").arg(\"{touch}\").status().unwrap(); }}")).unwrap();
        let exe = dir.path().join("run.sh");
        fs::write(&exe, &script).unwrap();
        fs::set_permissions(&exe, fs::Permissions::from_mode(0o755)).unwrap();

        let report = scan(dir.path());

        assert!(!marker.exists(), "scanned content was executed");
        assert_eq!(report.status, ScanStatus::Findings);
        assert!(report.target.revision.is_some());
    }

    #[test]
    fn control_characters_in_repository_text_are_escaped() {
        let dir = repo();
        let yaml = "on: push\njobs:\n  \"a\\e[2Jb\":\n    permissions: write-all\n";
        fs::write(workflow(&dir, "ci.yml"), yaml).unwrap();
        fs::write(workflow(&dir, "x\u{1b}[31m.yml"), "permissions: [\n").unwrap();
        let report = scan(dir.path());
        let finding = &report.findings[0];
        assert!(!finding.location.chars().any(char::is_control));
        assert!(!finding.message.chars().any(char::is_control));
        assert!(finding.location.contains("\\u{1b}"));
        for gap in &report.incomplete {
            assert!(
                !gap.path
                    .as_deref()
                    .unwrap_or("")
                    .chars()
                    .any(char::is_control)
            );
        }
    }
}

#[test]
fn reports_are_deterministic_regardless_of_creation_order() {
    let names = ["c.yml", "a.yaml", "b.yml", "d.yml"];
    let build = |order: &[&str]| {
        let dir = repo();
        for name in order {
            let body = if name.starts_with('a') || name.starts_with('d') {
                WRITE_ALL
            } else {
                SAFE
            };
            fs::write(workflow(&dir, name), body).unwrap();
        }
        let report = scan(dir.path());
        (
            report.to_json().replace(&report.target.path, "<root>"),
            report,
        )
    };
    let (first, report) = build(&names);
    let reversed: Vec<_> = names.iter().rev().copied().collect();
    let (second, _) = build(&reversed);
    assert_eq!(first, second);
    assert_eq!(first, build(&names).0);
    let files: Vec<_> = report.findings.iter().map(|f| f.file.as_str()).collect();
    assert_eq!(
        files,
        [".github/workflows/a.yaml", ".github/workflows/d.yml"]
    );
}

#[test]
fn json_report_is_valid_and_has_required_fields() {
    let dir = repo();
    fs::write(workflow(&dir, "ci.yml"), WRITE_ALL).unwrap();
    let value: serde_json::Value = serde_json::from_str(&scan(dir.path()).to_json()).unwrap();
    for field in [
        "schema_version",
        "scanner",
        "ruleset",
        "limits",
        "target",
        "status",
        "summary",
        "findings",
        "incomplete",
    ] {
        assert!(value.get(field).is_some(), "missing {field}");
    }
    assert_eq!(value["status"], "findings");
}
