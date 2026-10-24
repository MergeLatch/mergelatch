//! ML-GHA-002: external actions and reusable workflows not pinned to a full
//! commit SHA.

use super::workflow::{Workflow, field};
use super::{Context, RuleInfo};
use crate::yaml::Node;
use crate::{Severity, sanitize_text};

pub const RULE_UNPINNED: &str = "ML-GHA-002";

pub(super) const INFO: RuleInfo = RuleInfo {
    id: RULE_UNPINNED,
    severity: Severity::Medium,
    title: "External reference is not pinned to an immutable revision",
    description: "Detects `uses:` references to external actions (steps) and reusable workflows (jobs) that name a tag or branch instead of a full commit SHA, and Docker images without a sha256 digest. Local `./` references are ignored.",
};

#[derive(Debug, PartialEq, Eq)]
enum Reference<'a> {
    /// `./path`: part of the same repository.
    Local,
    Pinned,
    /// `owner/repo[/path]@ref` with a mutable ref.
    Mutable {
        name: &'a str,
        rf: &'a str,
    },
    /// `docker://image` without a digest.
    DockerUnpinned,
    /// Something this rule does not understand.
    Unrecognized(&'static str),
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Action,
    ReusableWorkflow,
}

fn is_full_sha(s: &str) -> bool {
    matches!(s.len(), 40 | 64) && s.bytes().all(|b| b.is_ascii_hexdigit())
}

fn classify(value: &str, kind: Kind) -> Reference<'_> {
    if value.contains("${{") {
        return Reference::Unrecognized(
            "it contains an expression, which cannot be resolved statically",
        );
    }
    if value.is_empty() || value.chars().any(char::is_whitespace) {
        return Reference::Unrecognized("it is empty or contains whitespace");
    }
    if value.starts_with("./") || value.starts_with("../") {
        return Reference::Local;
    }
    if let Some(image) = value.strip_prefix("docker://") {
        if kind == Kind::ReusableWorkflow || image.is_empty() {
            return Reference::Unrecognized("it is not a valid reusable workflow reference");
        }
        return match image.rsplit_once("@sha256:") {
            Some((_, digest))
                if digest.len() == 64 && digest.bytes().all(|b| b.is_ascii_hexdigit()) =>
            {
                Reference::Pinned
            }
            _ => Reference::DockerUnpinned,
        };
    }
    let Some((name, rf)) = value.split_once('@') else {
        return Reference::Unrecognized("it has no `@ref` suffix");
    };
    let mut parts = name.split('/');
    let valid_name = matches!(
        (parts.next(), parts.next()),
        (Some(owner), Some(repo)) if !owner.is_empty() && !repo.is_empty()
    ) && !name.ends_with('/')
        && !name.contains("//");
    if !valid_name || rf.is_empty() {
        return Reference::Unrecognized("it is not in `owner/repo[/path]@ref` form");
    }
    if is_full_sha(rf) {
        Reference::Pinned
    } else {
        Reference::Mutable { name, rf }
    }
}

pub(super) fn check(ctx: &mut Context<'_>, wf: &Workflow<'_>) {
    for job in &wf.jobs {
        for node in field(job.fields, "uses") {
            let location = format!("jobs.{}.uses", job.id);
            check_uses(ctx, node, Kind::ReusableWorkflow, &location);
        }
        for step in &job.steps {
            for node in field(step.fields, "uses") {
                let location = format!("jobs.{}.steps[{}].uses", job.id, step.index);
                check_uses(ctx, node, Kind::Action, &location);
            }
        }
    }
}

fn check_uses(ctx: &mut Context<'_>, node: &Node, kind: Kind, location: &str) {
    let (Some(text), Some(line)) = (node.as_str(), node.line()) else {
        if matches!(node, Node::CollectionAlias) {
            ctx.unsupported(format!("`{location}` is an alias that is not expanded"));
        } else {
            ctx.limit(format!(
                "`{location}` is not a plain string, so it was not analyzed"
            ));
        }
        return;
    };
    let value = text.trim();
    let shown = sanitize_text(value, 200);
    let what = match kind {
        Kind::Action => "action",
        Kind::ReusableWorkflow => "reusable workflow",
    };
    let remediation = "Pin to the full commit SHA of a release you have reviewed and keep the \
                       version in a trailing comment, for example \
                       `uses: owner/repo@<40-character sha> # v1.2.3`. Update pins with a tool \
                       such as Dependabot. Pinning stops a moved tag or branch from changing \
                       the code that runs; it does not make the pinned code safe.";
    match classify(value, kind) {
        Reference::Local | Reference::Pinned => {}
        Reference::Mutable { name, rf } => ctx.finding(
            &INFO,
            line,
            location,
            format!(
                "The {what} `{}` is referenced by `{}`, which can be a tag or branch. The \
                 owner can move it, changing the code that runs in this workflow without any \
                 change to this repository. Repository or organization policies that require \
                 SHA pinning are not evaluated by this rule.",
                sanitize_text(name, 120),
                sanitize_text(rf, 80)
            ),
            super::with_alias(format!("uses: {shown}"), node.alias_of()),
            remediation,
        ),
        Reference::DockerUnpinned => ctx.finding(
            &INFO,
            line,
            location,
            "This Docker image reference has no sha256 digest. A tag can be re-pointed at a \
             different image."
                .to_string(),
            super::with_alias(format!("uses: {shown}"), node.alias_of()),
            "Reference the image by digest, for example `docker://image@sha256:<64 hex digits>`.",
        ),
        Reference::Unrecognized(why) => {
            ctx.limit(format!("`{location}` was not analyzed because {why}"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SHA: &str = "3d3c42e5aac5ba805825da76410c181273ba90b1";

    fn action(v: &str) -> Reference<'_> {
        classify(v, Kind::Action)
    }

    #[test]
    fn full_sha_is_pinned_including_subpaths() {
        assert_eq!(
            action(&format!("actions/checkout@{SHA}")),
            Reference::Pinned
        );
        assert_eq!(
            action(&format!("owner/repo/sub/path@{SHA}")),
            Reference::Pinned
        );
        assert_eq!(
            action(&format!("actions/checkout@{}", SHA.to_uppercase())),
            Reference::Pinned
        );
        assert_eq!(
            action(&format!("o/r@{}", "a".repeat(64))),
            Reference::Pinned
        );
    }

    #[test]
    fn tags_branches_and_short_shas_are_mutable() {
        for rf in [
            "v1",
            "v1.2.3",
            "main",
            "feature/x",
            "3d3c42e",
            &SHA[..39],
            &format!("{SHA}0"),
        ] {
            let value = format!("owner/repo@{rf}");
            assert!(
                matches!(action(&value), Reference::Mutable { .. }),
                "{value}"
            );
        }
        assert!(matches!(
            action("owner/repo/path@v2"),
            Reference::Mutable {
                name: "owner/repo/path",
                rf: "v2"
            }
        ));
    }

    #[test]
    fn local_references_are_not_external() {
        assert_eq!(action("./.github/actions/x"), Reference::Local);
        assert_eq!(action("../shared"), Reference::Local);
    }

    #[test]
    fn docker_references_are_classified_separately() {
        assert_eq!(action("docker://alpine:3.19"), Reference::DockerUnpinned);
        assert_eq!(action("docker://alpine"), Reference::DockerUnpinned);
        assert_eq!(
            action(&format!("docker://alpine@sha256:{}", "ab".repeat(32))),
            Reference::Pinned
        );
        assert_eq!(
            action("docker://alpine@sha256:abc"),
            Reference::DockerUnpinned
        );
        assert!(matches!(
            classify("docker://alpine:3", Kind::ReusableWorkflow),
            Reference::Unrecognized(_)
        ));
    }

    #[test]
    fn expressions_and_odd_formats_are_not_treated_as_pinned() {
        for v in [
            "owner/repo@${{ matrix.ref }}",
            "${{ inputs.action }}",
            "owner",
            "owner/repo",
            "/repo@v1",
            "owner/@v1",
            "owner/repo@",
            "a b/c@v1",
            "",
        ] {
            assert!(matches!(action(v), Reference::Unrecognized(_)), "{v:?}");
        }
    }

    #[test]
    fn reusable_workflow_references_use_the_same_pinning_rule() {
        assert!(matches!(
            classify(
                "owner/repo/.github/workflows/ci.yml@main",
                Kind::ReusableWorkflow
            ),
            Reference::Mutable { .. }
        ));
        assert_eq!(
            classify(
                &format!("owner/repo/.github/workflows/ci.yml@{SHA}"),
                Kind::ReusableWorkflow
            ),
            Reference::Pinned
        );
        assert_eq!(
            classify("./.github/workflows/ci.yml", Kind::ReusableWorkflow),
            Reference::Local
        );
    }
}
