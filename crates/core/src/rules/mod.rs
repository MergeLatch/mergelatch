use std::time::Instant;

use serde::Serialize;

mod injection;
mod permissions;
mod pinning;
mod workflow;

pub use injection::RULE_SCRIPT_INJECTION;
pub use permissions::RULE_WRITE_ALL;
pub use pinning::RULE_UNPINNED;

use crate::discover::WorkflowFile;
use crate::yaml::{Node, ParseFailure, parse_document};
use crate::{Finding, Incomplete, IncompleteKind, ScanLimits, Severity, sanitize_text};

/// Public description of a rule, for listing and documentation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RuleInfo {
    pub id: &'static str,
    pub severity: Severity,
    pub title: &'static str,
    pub description: &'static str,
}

/// The rules in the built-in ruleset, in identifier order.
pub fn builtin_rules() -> Vec<RuleInfo> {
    vec![permissions::INFO, pinning::INFO, injection::INFO]
}

/// Result of analyzing one workflow file.
#[derive(Debug, Default)]
pub(crate) struct FileResult {
    pub findings: Vec<Finding>,
    pub incomplete: Vec<Incomplete>,
}

/// Parses `file` as YAML and applies every rule to it.
pub(crate) fn check_workflow(
    file: &WorkflowFile,
    limits: &ScanLimits,
    deadline: Instant,
) -> FileResult {
    let mut result = FileResult::default();
    let gap = |kind: IncompleteKind, detail: String| Incomplete {
        path: Some(file.path.clone()),
        kind,
        detail: sanitize_text(&detail, 300),
    };

    let root = match parse_document(&file.content, limits.max_yaml_depth, deadline) {
        Ok(Some(root)) => root,
        Ok(None) => return result,
        Err(failure) => {
            let incomplete = match failure {
                ParseFailure::Invalid(msg) => gap(IncompleteKind::InvalidYaml, msg),
                ParseFailure::Unsupported(msg) => gap(IncompleteKind::UnsupportedYaml, msg),
                ParseFailure::Timeout => gap(
                    IncompleteKind::Timeout,
                    "time limit reached while parsing".to_string(),
                ),
                ParseFailure::TooDeep(max) => gap(
                    IncompleteKind::LimitExceeded,
                    format!("YAML nesting is deeper than {max} levels"),
                ),
            };
            result.incomplete.push(incomplete);
            return result;
        }
    };

    let Node::Map(top) = &root else {
        result.incomplete.push(gap(
            IncompleteKind::UnsupportedYaml,
            "top level of the workflow is not a mapping".into(),
        ));
        return result;
    };

    let mut ctx = Context {
        file,
        result: &mut result,
    };
    let wf = workflow::Workflow::build(top, &mut ctx);
    permissions::check(&mut ctx, &wf);
    pinning::check(&mut ctx, &wf);
    injection::check(&mut ctx, &wf);
    result
}

/// Shared state for the rules analyzing one file.
pub(crate) struct Context<'a> {
    file: &'a WorkflowFile,
    result: &'a mut FileResult,
}

impl Context<'_> {
    fn gap(&mut self, kind: IncompleteKind, detail: String) {
        self.result.incomplete.push(Incomplete {
            path: Some(self.file.path.clone()),
            kind,
            detail: sanitize_text(&detail, 300),
        });
    }

    /// Valid YAML that the analysis does not expand or handle.
    pub(crate) fn unsupported(&mut self, detail: String) {
        self.gap(IncompleteKind::UnsupportedYaml, detail);
    }

    /// A construct the rules cannot analyze reliably. Makes the scan
    /// incomplete rather than treating the construct as safe.
    pub(crate) fn limit(&mut self, detail: String) {
        self.gap(IncompleteKind::AnalysisLimit, detail);
    }

    /// YAML merge keys (`<<`) can inject settings from elsewhere in the file.
    /// They are not expanded, so their presence means the inspection is partial.
    pub(crate) fn reject_merge_keys(&mut self, entries: &[(Node, Node)], scope: &str) {
        if entries.iter().any(|(k, _)| k.as_str() == Some("<<")) {
            self.unsupported(format!("merge key `<<` in {scope} is not expanded"));
        }
    }

    pub(crate) fn finding(
        &mut self,
        info: &RuleInfo,
        line: usize,
        location: &str,
        message: String,
        evidence: String,
        remediation: &str,
    ) {
        self.result.findings.push(Finding {
            rule_id: info.id.to_string(),
            severity: info.severity,
            title: info.title.to_string(),
            file: self.file.path.clone(),
            line: Some(line),
            location: location.to_string(),
            message,
            evidence,
            remediation: remediation.to_string(),
        });
    }
}

/// Notes in evidence that a value came from a YAML alias.
pub(crate) fn with_alias(evidence: String, alias_of: Option<usize>) -> String {
    match alias_of {
        Some(defined) => format!("{evidence} (alias; value defined on line {defined})"),
        None => evidence,
    }
}
