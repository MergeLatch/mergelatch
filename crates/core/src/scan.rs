use std::fmt;
use std::fs;
use std::path::Path;
use std::time::Instant;

use crate::discover::discover_workflows;
use crate::{Report, RulesetInfo, ScanLimits, Target, read_revision};

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
    let deadline = Instant::now() + limits.timeout;
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

    let target = Target {
        path: root.to_string_lossy().into_owned(),
        revision: read_revision(&root),
    };
    let ruleset = RulesetInfo {
        id: RULESET_ID.to_string(),
        version: RULESET_VERSION.to_string(),
        rules: Vec::new(),
    };
    Ok(Report::assemble(
        ruleset,
        limits,
        target,
        discovery.files.len(),
        Vec::new(),
        discovery.incomplete,
    ))
}
