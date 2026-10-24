use std::fmt;
use std::fs;
use std::path::Path;
use std::time::{Duration, Instant};

use crate::discover::discover_workflows;
use crate::rules::check_workflow;
use crate::{
    Incomplete, IncompleteKind, Report, RulesetInfo, ScanLimits, Target, builtin_rules,
    read_revision,
};

pub const RULESET_ID: &str = "mergelatch-builtin";
pub const RULESET_VERSION: &str = "1";

/// The scan could not run. This is distinct from an incomplete scan, which
/// produces a [`Report`].
#[derive(Debug)]
pub enum ScanError {
    /// The target does not exist, is not a directory, or cannot be resolved.
    InvalidTarget(String),
}

impl fmt::Display for ScanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ScanError::InvalidTarget(msg) => write!(f, "invalid scan target: {msg}"),
        }
    }
}

impl std::error::Error for ScanError {}

/// Scans an explicitly supplied directory.
///
/// Files are read as data. Nothing in the directory is executed, and Git is
/// not run.
pub fn scan_directory(root: &Path, limits: &ScanLimits) -> Result<Report, ScanError> {
    let started = Instant::now();
    // A timeout too large to represent is treated as effectively unlimited.
    let deadline = started
        .checked_add(limits.timeout)
        .unwrap_or_else(|| started + Duration::from_secs(60 * 60 * 24 * 365));
    let meta = fs::metadata(root)
        .map_err(|e| ScanError::InvalidTarget(format!("{}: {e}", root.display())))?;
    if !meta.is_dir() {
        return Err(ScanError::InvalidTarget(format!(
            "{} is not a directory",
            root.display()
        )));
    }
    let root = fs::canonicalize(root)
        .map_err(|e| ScanError::InvalidTarget(format!("{}: {e}", root.display())))?;

    let discovery = discover_workflows(&root, limits, deadline);
    let mut findings = Vec::new();
    let mut incomplete = discovery.incomplete;
    for file in &discovery.files {
        if Instant::now() >= deadline {
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

    // Deadlines are only noticed between operations, so a scan can finish
    // after the deadline without having noticed. Such a scan must not be
    // reported as clean: its result is incomplete by definition.
    if Instant::now() >= deadline && !incomplete.iter().any(|i| i.kind == IncompleteKind::Timeout) {
        incomplete.push(Incomplete {
            path: None,
            kind: IncompleteKind::Timeout,
            detail: format!(
                "scan finished after the {} second time limit",
                limits.timeout.as_secs()
            ),
        });
    }

    let target = Target {
        path: root.to_string_lossy().into_owned(),
        revision: read_revision(&root),
    };
    let ruleset = RulesetInfo {
        id: RULESET_ID.to_string(),
        version: RULESET_VERSION.to_string(),
        rules: builtin_rules().iter().map(|r| r.id.to_string()).collect(),
    };
    Ok(Report::assemble(
        ruleset,
        limits,
        target,
        discovery.files.len(),
        findings,
        incomplete,
    ))
}
