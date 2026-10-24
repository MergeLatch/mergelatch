use serde::Serialize;

use crate::discover::WorkflowFile;
use crate::yaml::{Node, ParseFailure, parse_document};
use crate::{Finding, Incomplete, IncompleteKind, ScanLimits, Severity, sanitize_text};

pub const RULE_WRITE_ALL: &str = "ML-GHA-001";

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
    vec![RuleInfo {
        id: RULE_WRITE_ALL,
        severity: Severity::Medium,
        title: "Workflow grants write-all permissions to GITHUB_TOKEN",
        description: "Detects an explicit `permissions: write-all` setting at the workflow level or on a job in .github/workflows/*.yml and *.yaml.",
    }]
}

/// Result of analyzing one workflow file.
#[derive(Debug, Default)]
pub(crate) struct FileResult {
    pub findings: Vec<Finding>,
    pub incomplete: Vec<Incomplete>,
}

/// Parses `file` as YAML and applies every rule to it.
pub(crate) fn check_workflow(file: &WorkflowFile, limits: &ScanLimits) -> FileResult {
    let mut result = FileResult::default();
    let gap = |kind: IncompleteKind, detail: String| Incomplete {
        path: Some(file.path.clone()),
        kind,
        detail: sanitize_text(&detail, 300),
    };

    let root = match parse_document(&file.content, limits.max_yaml_depth) {
        Ok(Some(root)) => root,
        Ok(None) => return result,
        Err(failure) => {
            let incomplete = match failure {
                ParseFailure::Invalid(msg) => gap(IncompleteKind::InvalidYaml, msg),
                ParseFailure::Unsupported(msg) => gap(IncompleteKind::UnsupportedYaml, msg),
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
    ctx.reject_merge_keys(top, "the workflow");
    for (key, value) in top {
        match key.as_str() {
            Some("permissions") => ctx.check_permissions(value, "permissions", None),
            Some("jobs") => ctx.check_jobs(value),
            _ => {}
        }
    }
    result
}

struct Context<'a> {
    file: &'a WorkflowFile,
    result: &'a mut FileResult,
}

impl Context<'_> {
    fn unsupported(&mut self, detail: String) {
        self.result.incomplete.push(Incomplete {
            path: Some(self.file.path.clone()),
            kind: IncompleteKind::UnsupportedYaml,
            detail,
        });
    }

    /// YAML merge keys (`<<`) can inject settings from elsewhere in the file.
    /// They are not expanded, so their presence means the inspection is partial.
    fn reject_merge_keys(&mut self, entries: &[(Node, Node)], scope: &str) {
        if entries.iter().any(|(k, _)| k.as_str() == Some("<<")) {
            self.unsupported(format!("merge key `<<` in {scope} is not expanded"));
        }
    }

    fn check_jobs(&mut self, jobs: &Node) {
        match jobs {
            Node::Map(entries) => {
                self.reject_merge_keys(entries, "`jobs`");
                for (id, job) in entries {
                    let Some(id) = id.as_str() else { continue };
                    let id = sanitize_text(id, 100);
                    match job {
                        Node::Map(fields) => {
                            self.reject_merge_keys(fields, &format!("job `{id}`"));
                            for (key, value) in fields {
                                if key.as_str() == Some("permissions") {
                                    let location = format!("jobs.{id}.permissions");
                                    self.check_permissions(value, &location, Some(&id));
                                }
                            }
                        }
                        Node::CollectionAlias => {
                            self.unsupported(format!("job `{id}` is an alias that is not expanded"))
                        }
                        _ => {}
                    }
                }
            }
            Node::CollectionAlias => {
                self.unsupported("`jobs` is an alias that is not expanded".into())
            }
            _ => {}
        }
    }

    fn check_permissions(&mut self, value: &Node, location: &str, job: Option<&str>) {
        match value {
            Node::Scalar { line, alias_of, .. } if value.as_str() == Some("write-all") => {
                self.result.findings.push(write_all_finding(
                    self.file, *line, *alias_of, location, job,
                ));
            }
            Node::CollectionAlias => {
                self.unsupported(format!("`{location}` is an alias that is not expanded"))
            }
            _ => {}
        }
    }
}

fn write_all_finding(
    file: &WorkflowFile,
    line: usize,
    alias_of: Option<usize>,
    location: &str,
    job: Option<&str>,
) -> Finding {
    let scope = match job {
        Some(id) => format!("Job `{id}`"),
        None => "The workflow".to_string(),
    };
    // Built from the matched setting only. The source line is not copied, so
    // comments, other keys, and values on the same line are never disclosed.
    let key = location.rsplit('.').next().unwrap_or(location);
    let evidence = match alias_of {
        Some(defined) => format!("{key}: write-all (alias; value defined on line {defined})"),
        None => format!("{key}: write-all"),
    };
    Finding {
        rule_id: RULE_WRITE_ALL.to_string(),
        severity: Severity::Medium,
        title: "Workflow grants write-all permissions to GITHUB_TOKEN".to_string(),
        file: file.path.clone(),
        line: Some(line),
        location: location.to_string(),
        message: format!(
            "{scope} sets `permissions: write-all`, which gives the GITHUB_TOKEN write access \
             to every permission scope. Any step that runs compromised or untrusted code can \
             use that access."
        ),
        evidence,
        remediation: "Remove `write-all`. Set workflow-level permissions to the minimum needed, \
                      for example `contents: read`, and grant individual write scopes only to \
                      the jobs that need them."
            .to_string(),
    }
}
