use std::time::Duration;

/// Resource limits applied to a scan.
///
/// Exceeding any limit makes the scan incomplete. It is never treated as clean.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanLimits {
    /// Largest file that will be read, in bytes.
    pub max_file_bytes: u64,
    /// Total bytes that will be read across all files.
    pub max_total_bytes: u64,
    /// Directory entries that will be examined.
    pub max_entries: usize,
    /// Deepest YAML nesting that will be analyzed.
    pub max_yaml_depth: usize,
    /// Wall-clock time allowed for the whole scan.
    ///
    /// The deadline is detected, not strictly enforced. It is checked between
    /// files and every few hundred YAML parser events. A single blocking
    /// operation, such as reading from a slow filesystem, is not interrupted
    /// and can run past the deadline. A scan that finishes after the deadline
    /// is reported as incomplete with a `timeout` entry, never as clean.
    pub timeout: Duration,
}

impl Default for ScanLimits {
    fn default() -> Self {
        Self {
            max_file_bytes: 1024 * 1024,
            max_total_bytes: 16 * 1024 * 1024,
            max_entries: 1000,
            max_yaml_depth: 64,
            timeout: Duration::from_secs(30),
        }
    }
}
