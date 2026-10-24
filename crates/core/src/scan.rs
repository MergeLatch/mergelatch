use std::fmt;
use std::fs;
use std::path::Path;
use std::time::{Duration, Instant};

use cap_std::ambient_authority;
use cap_std::fs::Dir;

use crate::discover::discover_workflows;
use crate::fsaccess::CONFINEMENT_VERIFIED;
use crate::revision::read_revision_from;
use crate::rules::check_workflow;
use crate::{
    Incomplete, IncompleteKind, Report, Revision, RulesetInfo, ScanLimits, Target, builtin_rules,
};

pub const RULESET_ID: &str = "mergelatch-builtin";
pub const RULESET_VERSION: &str = "1";

/// The scan could not run. This is distinct from an incomplete scan, which
/// produces a [`Report`].
#[derive(Debug)]
pub enum ScanError {
    /// The target does not exist, is not a directory, or cannot be resolved.
    InvalidTarget(String),
    /// This platform has no verified confined-access backend, so the scan
    /// refuses to run rather than open paths unsafely.
    UnsupportedPlatform,
}

impl fmt::Display for ScanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ScanError::InvalidTarget(msg) => write!(f, "invalid scan target: {msg}"),
            ScanError::UnsupportedPlatform => write!(
                f,
                "unsupported platform: race-resistant filesystem confinement is only verified on Linux"
            ),
        }
    }
}

impl std::error::Error for ScanError {}

/// Scans an explicitly supplied directory.
///
/// Files are read as data. Nothing in the directory is executed, and Git is
/// not run.
pub fn scan_directory(root: &Path, limits: &ScanLimits) -> Result<Report, ScanError> {
    scan_with(root, limits, read_revision_from, Instant::now)
}

/// The scan itself, with the revision reader and clock supplied so tests can
/// control them. `now` is used for every deadline decision made in this
/// function, including the final one.
fn scan_with(
    root: &Path,
    limits: &ScanLimits,
    revision: impl FnOnce(&Dir) -> Option<Revision>,
    now: impl Fn() -> Instant,
) -> Result<Report, ScanError> {
    let started = now();
    // A timeout too large to represent is treated as effectively unlimited.
    let deadline = started
        .checked_add(limits.timeout)
        .unwrap_or_else(|| started + Duration::from_secs(60 * 60 * 24 * 365));
    if !CONFINEMENT_VERIFIED {
        return Err(ScanError::UnsupportedPlatform);
    }
    // The only ambient-authority operation: the user-supplied root is opened
    // once, and everything after this goes through the resulting handle.
    let root_dir = Dir::open_ambient_dir(root, ambient_authority())
        .map_err(|e| ScanError::InvalidTarget(format!("{}: {e}", root.display())))?;
    // The path is for display only; no file is opened through it.
    let root_path = fs::canonicalize(root)
        .map_err(|e| ScanError::InvalidTarget(format!("{}: {e}", root.display())))?;

    let discovery = discover_workflows(&root_dir, limits, deadline);
    let mut findings = Vec::new();
    let mut incomplete = discovery.incomplete;
    for file in &discovery.files {
        if now() >= deadline {
            incomplete.push(Incomplete {
                path: None,
                kind: IncompleteKind::Timeout,
                detail: "time limit reached before all workflow files were analyzed".to_string(),
            });
            break;
        }
        let result = check_workflow(file, limits, deadline);
        findings.extend(result.findings);
        let timed_out = result
            .incomplete
            .iter()
            .any(|i| i.kind == IncompleteKind::Timeout);
        incomplete.extend(result.incomplete);
        if timed_out {
            break;
        }
    }

    let target = Target {
        path: root_path.to_string_lossy().into_owned(),
        revision: revision(&root_dir),
    };
    let ruleset = RulesetInfo {
        id: RULESET_ID.to_string(),
        version: RULESET_VERSION.to_string(),
        rules: builtin_rules().iter().map(|r| r.id.to_string()).collect(),
    };
    // Deadlines are only noticed between operations, so a scan can finish
    // after the deadline without having noticed. Such a scan must not be
    // reported as clean: its result is incomplete by definition. This check
    // runs last, after revision collection, so it covers all scan work.
    if now() >= deadline && !incomplete.iter().any(|i| i.kind == IncompleteKind::Timeout) {
        incomplete.push(Incomplete {
            path: None,
            kind: IncompleteKind::Timeout,
            detail: format!(
                "scan finished after the {} second time limit",
                limits.timeout.as_secs()
            ),
        });
    }

    Ok(Report::assemble(
        ruleset,
        limits,
        target,
        discovery.files.len(),
        findings,
        incomplete,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ScanStatus;
    use std::cell::Cell;

    fn repo() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        let wf = dir.path().join(".github/workflows");
        fs::create_dir_all(&wf).unwrap();
        fs::write(wf.join("ci.yml"), "permissions:\n  contents: read\n").unwrap();
        dir
    }

    fn limits() -> ScanLimits {
        ScanLimits {
            timeout: Duration::from_secs(60),
            ..ScanLimits::default()
        }
    }

    /// A clock that jumps past the deadline once `late` is set, which the fake
    /// revision reader does. No real time passes or is waited for.
    fn scan_with_late_revision(dir: &Path, revision_is_slow: bool) -> Report {
        let base = Instant::now();
        let late = Cell::new(false);
        let report = scan_with(
            dir,
            &limits(),
            |_| {
                late.set(revision_is_slow);
                None
            },
            || {
                if late.get() {
                    base + Duration::from_secs(3600)
                } else {
                    base
                }
            },
        );
        report.unwrap()
    }

    #[test]
    fn slow_revision_read_makes_the_scan_incomplete() {
        let dir = repo();
        let report = scan_with_late_revision(dir.path(), true);
        assert_eq!(report.status, ScanStatus::Incomplete);
        assert_eq!(report.incomplete.len(), 1);
        assert_eq!(report.incomplete[0].kind, IncompleteKind::Timeout);
        assert_eq!(report.summary.files_inspected, 1);
    }

    #[test]
    fn fast_revision_read_stays_clean() {
        let dir = repo();
        assert_eq!(
            scan_with_late_revision(dir.path(), false).status,
            ScanStatus::Clean
        );
    }

    #[test]
    fn timeout_already_recorded_is_not_duplicated() {
        let dir = repo();
        let base = Instant::now();
        // The first reading sets the deadline; every later reading is past it,
        // so the analysis loop records a timeout and the final check must not
        // add a second one.
        let calls = Cell::new(0);
        let report = scan_with(
            dir.path(),
            &limits(),
            |_| None,
            || {
                calls.set(calls.get() + 1);
                if calls.get() == 1 {
                    base
                } else {
                    base + Duration::from_secs(3600)
                }
            },
        )
        .unwrap();
        let timeouts = report
            .incomplete
            .iter()
            .filter(|i| i.kind == IncompleteKind::Timeout)
            .count();
        assert_eq!(report.status, ScanStatus::Incomplete);
        assert_eq!(timeouts, 1);
    }
}
