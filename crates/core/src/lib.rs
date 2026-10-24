//! MergeLatch scanning engine.
//!
//! The engine reads repository files as data. It never executes scanned
//! content, and it never reports an incomplete inspection as clean.

mod limits;
mod model;
mod revision;
mod text;

pub use limits::ScanLimits;
pub use model::{
    ErrorReport, Finding, Incomplete, IncompleteKind, Report, Revision, RulesetInfo,
    SCHEMA_VERSION, ScanStatus, ScannerInfo, Severity, Summary, Target,
};
pub use revision::read_revision;
pub use text::sanitize_text;
