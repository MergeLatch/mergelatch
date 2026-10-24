//! ML-GHA-001: explicit `permissions: write-all`.

use super::workflow::{Workflow, field};
use super::{Context, RuleInfo};
use crate::Severity;
use crate::yaml::Node;

pub const RULE_WRITE_ALL: &str = "ML-GHA-001";

pub(super) const INFO: RuleInfo = RuleInfo {
    id: RULE_WRITE_ALL,
    severity: Severity::Medium,
    title: "Workflow grants write-all permissions to GITHUB_TOKEN",
    description: "Detects an explicit `permissions: write-all` setting at the workflow level or on a job in .github/workflows/*.yml and *.yaml.",
};

pub(super) fn check(ctx: &mut Context<'_>, wf: &Workflow<'_>) {
    for value in field(wf.top, "permissions") {
        check_value(ctx, value, "permissions", None);
    }
    for job in &wf.jobs {
        for value in field(job.fields, "permissions") {
            let location = format!("jobs.{}.permissions", job.id);
            check_value(ctx, value, &location, Some(&job.id));
        }
    }
}

fn check_value(ctx: &mut Context<'_>, value: &Node, location: &str, job: Option<&str>) {
    match value {
        Node::Scalar { line, alias_of, .. } if value.as_str() == Some("write-all") => {
            let scope = match job {
                Some(id) => format!("Job `{id}`"),
                None => "The workflow".to_string(),
            };
            // Built from the matched setting only, so comments, other keys and
            // values on the same source line are never disclosed.
            let evidence = super::with_alias("permissions: write-all".to_string(), *alias_of);
            ctx.finding(
                &INFO,
                *line,
                location,
                format!(
                    "{scope} sets `permissions: write-all`, which gives the GITHUB_TOKEN write \
                     access to every permission scope. Any step that runs compromised or \
                     untrusted code can use that access."
                ),
                evidence,
                "Remove `write-all`. Set workflow-level permissions to the minimum needed, for \
                 example `contents: read`, and grant individual write scopes only to the jobs \
                 that need them.",
            );
        }
        Node::CollectionAlias => {
            ctx.unsupported(format!("`{location}` is an alias that is not expanded"))
        }
        _ => {}
    }
}
