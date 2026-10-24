//! End-to-end tests of the `mergelatch` binary.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn mergelatch(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_mergelatch"))
        .args(args)
        .output()
        .expect("binary should run")
}

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/gha-permissions")
        .join(name)
}

fn scan(name: &str, extra: &[&str]) -> Output {
    let path = fixture(name);
    let mut args = vec!["scan", path.to_str().unwrap()];
    args.extend_from_slice(extra);
    mergelatch(&args)
}

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

#[test]
fn help_describes_commands_and_exit_codes() {
    let out = mergelatch(&["--help"]);
    assert_eq!(out.status.code(), Some(0));
    let text = stdout(&out);
    for expected in ["scan", "rules", "Exit codes:", "not a pass"] {
        assert!(
            text.contains(expected),
            "help is missing {expected:?}:\n{text}"
        );
    }
}

#[test]
fn version_is_printed() {
    let out = mergelatch(&["--version"]);
    assert_eq!(out.status.code(), Some(0));
    assert!(stdout(&out).contains(env!("CARGO_PKG_VERSION")));
}

#[test]
fn clean_scan_exits_zero() {
    let out = scan("safe-read-only", &[]);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    let text = stdout(&out);
    assert!(text.contains("Result: clean"), "{text}");
    assert!(text.contains("Workflow files inspected: 1"));
}

#[test]
fn findings_exit_one_and_show_evidence() {
    let out = scan("workflow-write-all", &[]);
    assert_eq!(out.status.code(), Some(1));
    let text = stdout(&out);
    for expected in [
        "ML-GHA-001",
        ".github/workflows/ci.yml:3",
        "Evidence: permissions: write-all",
        "Fix:",
        "Exit code: 1",
    ] {
        assert!(text.contains(expected), "missing {expected:?}:\n{text}");
    }
}

#[test]
fn incomplete_scan_exits_two() {
    let out = scan("malformed", &[]);
    assert_eq!(out.status.code(), Some(2));
    let text = stdout(&out);
    assert!(text.contains("Incomplete inspections (1)"), "{text}");
    assert!(text.contains("this is not a pass"));
}

#[test]
fn json_output_is_machine_readable() {
    let out = scan("job-write-all", &["--format", "json"]);
    assert_eq!(out.status.code(), Some(1));
    let value: serde_json::Value = serde_json::from_str(&stdout(&out)).unwrap();
    assert_eq!(value["status"], "findings");
    assert_eq!(value["findings"][0]["rule_id"], "ML-GHA-001");
    assert_eq!(value["findings"][0]["location"], "jobs.publish.permissions");
    assert_eq!(value["ruleset"]["rules"][0], "ML-GHA-001");
}

#[test]
fn json_output_is_identical_across_runs() {
    let a = scan("job-write-all", &["--format", "json"]);
    let b = scan("job-write-all", &["--format", "json"]);
    assert_eq!(stdout(&a), stdout(&b));
}

#[test]
fn missing_directory_is_an_error() {
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("missing");
    let out = mergelatch(&["scan", missing.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(3));
    assert!(stderr(&out).contains("error: invalid scan target"));
    assert!(stdout(&out).is_empty());
}

#[test]
fn json_mode_reports_errors_as_json() {
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("missing");
    let out = mergelatch(&["scan", missing.to_str().unwrap(), "--format", "json"]);
    assert_eq!(out.status.code(), Some(3));
    let value: serde_json::Value = serde_json::from_str(&stdout(&out)).unwrap();
    assert_eq!(value["status"], "error");
}

#[test]
fn file_target_is_an_error() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("a.yml");
    fs::write(&file, "on: push\n").unwrap();
    let out = mergelatch(&["scan", file.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(3));
}

#[test]
fn usage_errors_exit_three() {
    for args in [
        &["scan"][..],
        &["bogus"][..],
        &[][..],
        &["scan", ".", "--format", "xml"][..],
    ] {
        let out = mergelatch(args);
        assert_eq!(out.status.code(), Some(3), "args {args:?}");
        assert!(!stderr(&out).is_empty());
    }
}

#[test]
fn rules_command_lists_the_builtin_rule() {
    let human = mergelatch(&["rules"]);
    assert_eq!(human.status.code(), Some(0));
    assert!(stdout(&human).contains("ML-GHA-001"));

    let json = mergelatch(&["rules", "--format", "json"]);
    let value: serde_json::Value = serde_json::from_str(&stdout(&json)).unwrap();
    assert_eq!(value[0]["id"], "ML-GHA-001");
}

#[test]
fn scan_does_not_modify_the_target() {
    let dir = tempfile::tempdir().unwrap();
    let wf = dir.path().join(".github/workflows");
    fs::create_dir_all(&wf).unwrap();
    fs::write(wf.join("ci.yml"), "permissions: write-all\n").unwrap();
    let before = fs::read(wf.join("ci.yml")).unwrap();
    let out = mergelatch(&["scan", dir.path().to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(fs::read(wf.join("ci.yml")).unwrap(), before);
    let entries: Vec<_> = fs::read_dir(&wf).unwrap().collect();
    assert_eq!(entries.len(), 1);
}
