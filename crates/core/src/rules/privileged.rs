//! ML-GHA-004: pull request code checked out and run in a `pull_request_target`
//! workflow.
//!
//! `pull_request_target` runs in the context of the base repository, with its
//! secrets available and a token that may have write access. That is safe as
//! long as the workflow does not run code from the pull request. This rule
//! looks for a recognized checkout of pull request code followed, in the same
//! job, by a step that builds, installs, tests, or runs repository files.
//!
//! It only analyzes `pull_request_target`. `workflow_run` has a similar risk
//! and is not analyzed yet.

use std::collections::BTreeSet;

use super::shell::{self, Cmd, UNTRUSTED_MARK};
use super::workflow::{Job, Workflow, field};
use super::{Context, RuleInfo};
use crate::expr::{PathMatch, find_expressions, match_path};
use crate::yaml::Node;
use crate::{Severity, sanitize_text};

pub const RULE_PRIVILEGED_PR_CODE: &str = "ML-GHA-004";

pub(super) const INFO: RuleInfo = RuleInfo {
    id: RULE_PRIVILEGED_PR_CODE,
    severity: Severity::High,
    title: "Pull request code is checked out and run in a pull_request_target workflow",
    description: "Detects a job in a `pull_request_target` workflow that checks out pull request code (actions/checkout with a PR head ref or fork repository, a refs/pull ref, `gh pr checkout`, or a git fetch of a pull ref) and then runs a build, install, test, or repository script. `pull_request_target` alone is not flagged, and neither is a checkout of the base branch. `workflow_run` is not analyzed.",
};

/// References that select code written by the pull request author.
const UNTRUSTED_REFS: &[&str] = &[
    "github.event.pull_request.head.**",
    "github.head_ref",
    "github.event.pull_request.merge_commit_sha",
];

/// Expressions that, used alone as `with.repository`, name the repository the
/// workflow runs in (the base repository for `pull_request_target`).
const TRUSTED_REPOSITORIES: &[&str] = &[
    "github.repository",
    "github.event.repository.full_name",
    "github.event.pull_request.base.repo.full_name",
];

/// References known to select the base repository's own code.
const TRUSTED_REFS: &[&str] = &[
    "github.sha",
    "github.ref",
    "github.ref_name",
    "github.base_ref",
    "github.repository",
    "github.event.repository.**",
    "github.event.pull_request.base.**",
    "github.event.number",
    "github.event.pull_request.number",
];

pub(super) fn check(ctx: &mut Context<'_>, wf: &Workflow<'_>) {
    if !triggers(ctx, wf).contains("pull_request_target") {
        return;
    }
    for job in &wf.jobs {
        check_job(ctx, wf, job);
    }
}

/// Event names listed under `on`, lowercased.
fn triggers(ctx: &mut Context<'_>, wf: &Workflow<'_>) -> BTreeSet<String> {
    let mut events = BTreeSet::new();
    for node in field(wf.top, "on") {
        match node {
            Node::Scalar { value, .. } => {
                events.insert(value.to_ascii_lowercase());
            }
            Node::Seq(items) => {
                for item in items {
                    match item.as_str() {
                        Some(name) => {
                            events.insert(name.to_ascii_lowercase());
                        }
                        None => ctx.limit("an entry under `on` is not a plain string".into()),
                    }
                }
            }
            Node::Map(entries) => {
                for (key, _) in entries {
                    match key.as_str() {
                        Some(name) => {
                            events.insert(name.to_ascii_lowercase());
                        }
                        None => ctx.limit("a key under `on` is not a plain string".into()),
                    }
                }
            }
            Node::CollectionAlias => {
                ctx.unsupported("`on` is an alias that is not expanded".into())
            }
        }
    }
    events
}

/// How a `with:` value of actions/checkout selects code.
enum Verdict {
    Trusted,
    Untrusted,
    Unknown(String),
}

/// Judges a `with.ref` value. A literal branch or tag name is trusted because
/// it can only select something inside the repository chosen by `repository`,
/// which is judged separately.
fn judge_ref(text: &str) -> Verdict {
    if text.trim().is_empty() {
        return Verdict::Unknown("it is empty, so the ref used depends on the action".into());
    }
    let Ok(expressions) = find_expressions(text) else {
        return Verdict::Unknown("it has a `${{` with no closing `}}`".into());
    };
    if names_pull_ref(text) {
        return Verdict::Untrusted;
    }
    let mut unknown = None;
    for expr in &expressions {
        if !expr.dynamic.is_empty() {
            unknown.get_or_insert("it uses a computed property access".to_string());
        }
        for path in &expr.paths {
            if is_untrusted_path(path) {
                return Verdict::Untrusted;
            }
            let trusted = TRUSTED_REFS
                .iter()
                .any(|p| matches!(match_path(path, p), Some(PathMatch::Exact)));
            if !trusted {
                unknown.get_or_insert(format!(
                    "it uses `{}`, whose value cannot be determined statically",
                    sanitize_text(&path.join("."), 80)
                ));
            }
        }
    }
    match unknown {
        Some(reason) => Verdict::Unknown(reason),
        None => Verdict::Trusted,
    }
}

/// Judges a `with.repository` value.
///
/// actions/checkout can fetch any repository, so a value is trusted only when
/// it is exactly one expression that names the workflow's own repository. A
/// literal such as `owner/repo` cannot be shown to be the base repository from
/// the workflow file alone, so it is reported as unresolved instead of trusted.
fn judge_repository(text: &str) -> Verdict {
    if text.trim().is_empty() {
        return Verdict::Unknown(
            "it is empty, so the repository used depends on the action".into(),
        );
    }
    let Ok(expressions) = find_expressions(text) else {
        return Verdict::Unknown("it has a `${{` with no closing `}}`".into());
    };
    if expressions
        .iter()
        .flat_map(|e| &e.paths)
        .any(|p| is_untrusted_path(p))
    {
        return Verdict::Untrusted;
    }
    if expressions.is_empty() {
        return Verdict::Unknown(
            "it names a literal repository, which cannot be shown to be the base repository              from the workflow file alone"
                .into(),
        );
    }
    // Only the plain dotted form is accepted: no operators, functions, or
    // bracket syntax, so the value cannot differ from the named property.
    if let [expr] = expressions.as_slice()
        && text.trim() == expr.text
    {
        let inner = expr.text["${{".len()..expr.text.len() - "}}".len()]
            .trim()
            .to_ascii_lowercase();
        if TRUSTED_REPOSITORIES.contains(&inner.as_str()) {
            return Verdict::Trusted;
        }
    }
    Verdict::Unknown(
        "it is not a single expression naming the workflow's own repository, so what it selects          cannot be determined statically"
            .into(),
    )
}

/// Whether `path` reaches into pull request head data. A path naming only an
/// enclosing object (`github.event`) is not trusted either, but it is
/// unresolved rather than known to be untrusted.
fn is_untrusted_path(path: &[String]) -> bool {
    UNTRUSTED_REFS
        .iter()
        .any(|p| matches!(match_path(path, p), Some(PathMatch::Exact)))
}

/// A literal ref that selects a pull request's code.
fn names_pull_ref(text: &str) -> bool {
    text.contains("refs/pull/") || shell::is_pull_ref(text)
}

struct Origin {
    step: usize,
    line: usize,
    location: String,
    evidence: String,
    how: String,
}

struct Exec {
    step: usize,
    line: usize,
    command: String,
}

fn check_job(ctx: &mut Context<'_>, wf: &Workflow<'_>, job: &Job<'_>) {
    let mut origin: Option<Origin> = None;
    let mut execs: Vec<Exec> = Vec::new();

    for step in &job.steps {
        // Steps that use an action.
        for uses in field(step.fields, "uses") {
            let Some(text) = uses.as_str() else { continue };
            let name = text.split('@').next().unwrap_or("").to_ascii_lowercase();
            if name == "actions/checkout" {
                if let Some(found) = judge_checkout(ctx, job, step.index, step.fields)
                    && origin.is_none()
                {
                    origin = Some(found);
                }
            } else if text.starts_with("./") && origin.is_some() {
                // A local action is code from the checked-out workspace.
                execs.push(Exec {
                    step: step.index,
                    line: uses.line().unwrap_or(0),
                    command: format!("local action {}", sanitize_text(text, 60)),
                });
            }
        }

        // Steps that run a script.
        for run in field(step.fields, "run") {
            let (Some(text), Some(line)) = (run.text(), run.line()) else {
                continue;
            };
            for cmd in shell::analyze(&mask(text)) {
                match cmd {
                    Cmd::UntrustedCheckout(kind) if origin.is_none() => {
                        origin = Some(Origin {
                            step: step.index,
                            line,
                            location: format!("jobs.{}.steps[{}].run", job.id, step.index),
                            evidence: kind.clone(),
                            how: format!("`{kind}` in a run step"),
                        });
                    }
                    Cmd::Exec(command) if origin.is_some() => execs.push(Exec {
                        step: step.index,
                        line,
                        command,
                    }),
                    Cmd::Unknown(command) if origin.is_some() => ctx.limit(format!(
                        "step {} of job `{}` runs `{}` after pull request code was checked out; \
                         it is not recognized as safe or as running repository code",
                        step.index,
                        job.id,
                        sanitize_text(&command, 60)
                    )),
                    _ => {}
                }
            }
        }
    }

    // Execution is only recorded once a checkout of pull request code has
    // been seen, so everything in `execs` comes after it.
    let (Some(origin), Some(first)) = (origin, execs.first()) else {
        return;
    };
    let more = match execs.len() - 1 {
        0 => String::new(),
        n => format!(" and {n} more step(s)"),
    };
    let risk = risk_context(wf, job);
    ctx.finding(
        &INFO,
        origin.line,
        &origin.location,
        format!(
            "On `pull_request_target`, the workflow runs in the context of the base repository, \
             with its secrets available and a GITHUB_TOKEN that may have write access. Job `{}` \
             checks out pull request code ({}) at step {} and then runs `{}` at step {} (line \
             {}){}, which can execute that code. {}",
            job.id,
            origin.how,
            origin.step,
            sanitize_text(&first.command, 60),
            first.step,
            first.line,
            more,
            risk
        ),
        sanitize_text(
            &format!(
                "{}; step {} runs {}",
                origin.evidence, first.step, first.command
            ),
            200,
        ),
        "Do not run pull request code in a `pull_request_target` workflow. Build and test \
         untrusted changes in a `pull_request` workflow, which runs without secrets and with a \
         read-only token for forks. If a privileged follow-up step is needed, put it in a \
         separate job or workflow that treats the build output as data and never checks out or \
         runs pull request code, and set `permissions` to the minimum required.",
    );
}

fn judge_checkout(
    ctx: &mut Context<'_>,
    job: &Job<'_>,
    index: usize,
    step_fields: &super::workflow::Fields,
) -> Option<Origin> {
    for with in field(step_fields, "with") {
        let Node::Map(inputs) = with else {
            if matches!(with, Node::CollectionAlias) {
                ctx.unsupported(format!(
                    "`with` of step {index} in job `{}` is an alias that is not expanded",
                    job.id
                ));
            }
            continue;
        };
        for (key, value) in inputs {
            let Some(key) = key.as_str() else { continue };
            if key != "ref" && key != "repository" {
                continue;
            }
            let location = format!("jobs.{}.steps[{index}].with.{key}", job.id);
            let (Some(text), Some(line)) = (value.as_str(), value.line()) else {
                ctx.limit(format!(
                    "`{location}` is not a plain string, so it was not analyzed"
                ));
                continue;
            };
            let verdict = if key == "repository" {
                judge_repository(text)
            } else {
                judge_ref(text)
            };
            match verdict {
                Verdict::Trusted => {}
                Verdict::Untrusted => {
                    return Some(Origin {
                        step: index,
                        line,
                        evidence: super::with_alias(
                            sanitize_text(&format!("{key}: {text}"), 160),
                            value.alias_of(),
                        ),
                        how: format!("actions/checkout with `{key}`"),
                        location,
                    });
                }
                Verdict::Unknown(reason) => {
                    ctx.limit(format!("`{location}` was not analyzed because {reason}"))
                }
            }
        }
    }
    None
}

/// Replaces `${{ }}` expressions so the shell reader sees plain words, marking
/// those that refer to pull request head code.
fn mask(text: &str) -> String {
    let Ok(expressions) = find_expressions(text) else {
        return text.to_string();
    };
    let mut out = String::new();
    let mut last = 0;
    for expr in expressions {
        out.push_str(&text[last..expr.offset]);
        let untrusted = expr.paths.iter().any(|p| is_untrusted_path(p));
        out.push_str(if untrusted { UNTRUSTED_MARK } else { "EXPR" });
        last = expr.offset + expr.text.len();
    }
    out.push_str(&text[last..]);
    out
}

fn risk_context(wf: &Workflow<'_>, job: &Job<'_>) -> String {
    let explicit_write = field(wf.top, "permissions")
        .into_iter()
        .chain(field(job.fields, "permissions"))
        .any(grants_write);
    let secrets = job.fields.iter().any(|(_, v)| mentions_secrets(v));
    let mut parts = Vec::new();
    if explicit_write {
        parts.push("The token permissions include write access.");
    }
    if secrets {
        parts.push("The job references secrets.");
    }
    if parts.is_empty() {
        parts.push(
            "No explicit write permission or secret reference was found in this job, but the \
             token and checkout credentials may still be reachable by the executed code, \
             depending on repository settings.",
        );
    }
    parts.join(" ")
}

fn grants_write(node: &Node) -> bool {
    match node {
        Node::Scalar { value, .. } => value == "write-all",
        Node::Map(entries) => entries
            .iter()
            .any(|(_, v)| matches!(v.as_str(), Some("write") | Some("write-all"))),
        _ => false,
    }
}

fn mentions_secrets(node: &Node) -> bool {
    match node {
        Node::Scalar { value, .. } => find_expressions(value).is_ok_and(|exprs| {
            exprs.iter().any(|e| {
                e.paths.iter().any(|p| {
                    p.first().is_some_and(|s| s == "secrets")
                        && p.get(1).is_none_or(|n| n != "github_token")
                })
            })
        }),
        Node::Map(entries) => entries.iter().any(|(_, v)| mentions_secrets(v)),
        Node::Seq(items) => items.iter().any(mentions_secrets),
        Node::CollectionAlias => false,
    }
}
