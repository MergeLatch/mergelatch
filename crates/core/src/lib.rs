//! MergeLatch scanning engine.
//!
//! The engine reads repository files as data. It never executes scanned
//! content, and it never reports an incomplete inspection as clean.

mod discover;
mod fsaccess;
mod limits;
mod model;
mod revision;
mod rules;
mod scan;
mod text;
mod yaml;

pub use limits::ScanLimits;
pub use model::{
    ErrorReport, Finding, Incomplete, IncompleteKind, Report, Revision, RulesetInfo,
    SCHEMA_VERSION, ScanStatus, ScannerInfo, Severity, Summary, Target,
};
pub use revision::read_revision;
pub use rules::{RULE_WRITE_ALL, RuleInfo, builtin_rules};
pub use scan::{RULESET_ID, RULESET_VERSION, ScanError, scan_directory};
pub use text::sanitize_text;
