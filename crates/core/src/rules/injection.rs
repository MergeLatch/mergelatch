//! ML-GHA-003: attacker-controllable context expressions placed directly in a
//! `run:` script.

use super::workflow::{Workflow, field};
use super::{Context, RuleInfo};
use crate::expr::{PathMatch, dynamic_could_reach, find_expressions, match_path};
use crate::yaml::Node;
use crate::{Severity, sanitize_text};

pub const RULE_SCRIPT_INJECTION: &str = "ML-GHA-003";

pub(super) const INFO: RuleInfo = RuleInfo {
    id: RULE_SCRIPT_INJECTION,
    severity: Severity::High,
    title: "Attacker-controllable value is expanded directly into a shell script",
    description: "Detects `${{ ... }}` expressions in `run:` scripts that reference documented attacker-controllable context fields, such as pull request and issue titles and bodies, comment bodies, commit messages, and branch names. Expressions are read statically and never evaluated.",
};

/// Context fields that can contain text chosen by someone who does not need
/// write access to the repository. `*` matches any index; see GitHub's
/// "Security hardening for GitHub Actions".
const SOURCES: &[&str] = &[
    "github.head_ref",
    "github.event.issue.title",
    "github.event.issue.body",
    "github.event.pull_request.title",
    "github.event.pull_request.body",
    "github.event.pull_request.head.ref",
    "github.event.pull_request.head.label",
    "github.event.pull_request.head.repo.default_branch",
    "github.event.comment.body",
    "github.event.review.body",
    "github.event.review_comment.body",
    "github.event.discussion.title",
    "github.event.discussion.body",
    "github.event.pages.*.page_name",
    "github.event.commits.*.message",
    "github.event.commits.*.author.email",
    "github.event.commits.*.author.name",
    "github.event.head_commit.message",
    "github.event.head_commit.author.email",
    "github.event.head_commit.author.name",
    "github.event.head_commit.committer.email",
    "github.event.head_commit.committer.name",
    "github.event.workflow_run.head_branch",
    "github.event.workflow_run.head_commit.message",
    "github.event.workflow_run.head_commit.author.email",
    "github.event.workflow_run.head_commit.author.name",
];

pub(super) fn check(ctx: &mut Context<'_>, wf: &Workflow<'_>) {
    for job in &wf.jobs {
        for step in &job.steps {
            for node in field(step.fields, "run") {
                let location = format!("jobs.{}.steps[{}].run", job.id, step.index);
                check_run(ctx, node, &location);
            }
        }
    }
}

fn check_run(ctx: &mut Context<'_>, node: &Node, location: &str) {
    let (Some(text), Some(line)) = (node.text(), node.line()) else {
        if matches!(node, Node::CollectionAlias) {
            ctx.unsupported(format!("`{location}` is an alias that is not expanded"));
        } else {
            ctx.limit(format!(
                "`{location}` is not a string, so it was not analyzed"
            ));
        }
        return;
    };
    let expressions = match find_expressions(text) {
        Ok(expressions) => expressions,
        Err(_) => {
            ctx.limit(format!(
                "`{location}` has a `${{{{` with no closing `}}}}`, so it was not analyzed"
            ));
            return;
        }
    };
    // Exact line numbers are known only for literal block scalars; elsewhere
    // the scalar's first line is used.
    let first_line = node.literal_first_line();

    for expr in expressions {
        // A computed accessor may select an attacker-controllable property.
        for prefix in &expr.dynamic {
            if SOURCES.iter().any(|s| dynamic_could_reach(prefix, s)) {
                ctx.limit(format!(
                    "`{location}` uses a computed property access on `{}`, which cannot be \
                     resolved statically",
                    prefix.join(".")
                ));
            }
        }
        if expr.boolean {
            continue;
        }
        let hit = expr.paths.iter().find_map(|path| {
            SOURCES
                .iter()
                .find_map(|s| match_path(path, s).map(|m| (*s, m)))
        });
        let Some((source, kind)) = hit else { continue };

        let at = match first_line {
            Some(first) => first + text[..expr.offset].matches('\n').count(),
            None => line,
        };
        let shown = sanitize_text(&expr.text, 160);
        let what = match kind {
            PathMatch::Exact => format!("references `{source}`"),
            PathMatch::Whole => format!("references an object that includes `{source}`"),
        };
        ctx.finding(
            &INFO,
            at,
            location,
            format!(
                "The expression {what}, which can contain text chosen by someone outside the \
                 project. GitHub substitutes the value into the script text before the shell \
                 runs, so it can add commands. Whether this can be exploited depends on the \
                 workflow's trigger and who can start it."
            ),
            super::with_alias(shown, node.alias_of()),
            "Pass the value through an environment variable and read it as a shell variable: \
             set `env: NAME: ${{ ... }}` on the step and use \"$NAME\" in the script. Quoting \
             the expression inside the script does not help, because the substitution happens \
             before the shell parses the quotes.",
        );
    }
}
