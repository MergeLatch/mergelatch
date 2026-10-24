//! A light structural view of a workflow, built once and shared by the rules.
//!
//! Anything the view cannot represent faithfully, such as aliases to
//! collections or merge keys in places that matter, is recorded as an
//! incomplete inspection so that no rule silently skips it.

use super::Context;
use crate::sanitize_text;
use crate::yaml::Node;

pub(crate) type Fields = [(Node, Node)];

pub(crate) struct Step<'a> {
    /// Zero-based position in the job's `steps` list.
    pub index: usize,
    pub fields: &'a Fields,
}

pub(crate) struct Job<'a> {
    /// Job identifier, sanitized for display.
    pub id: String,
    pub fields: &'a Fields,
    pub steps: Vec<Step<'a>>,
}

pub(crate) struct Workflow<'a> {
    pub top: &'a Fields,
    pub jobs: Vec<Job<'a>>,
}

/// Every value stored under `key`. Duplicate keys are all returned so that a
/// later duplicate cannot hide an earlier one.
pub(crate) fn field<'a>(fields: &'a Fields, key: &str) -> Vec<&'a Node> {
    fields
        .iter()
        .filter(|(k, _)| k.as_str() == Some(key))
        .map(|(_, v)| v)
        .collect()
}

impl<'a> Workflow<'a> {
    pub(crate) fn build(top: &'a Fields, ctx: &mut Context<'_>) -> Self {
        ctx.reject_merge_keys(top, "the workflow");
        let mut jobs = Vec::new();
        for jobs_node in field(top, "jobs") {
            match jobs_node {
                Node::Map(entries) => {
                    ctx.reject_merge_keys(entries, "`jobs`");
                    for (id, job) in entries {
                        let Some(id) = id.as_str() else { continue };
                        let id = sanitize_text(id, 100);
                        match job {
                            Node::Map(fields) => jobs.push(build_job(id, fields, ctx)),
                            Node::CollectionAlias => ctx.unsupported(format!(
                                "job `{id}` is an alias that is not expanded"
                            )),
                            _ => {}
                        }
                    }
                }
                Node::CollectionAlias => {
                    ctx.unsupported("`jobs` is an alias that is not expanded".into())
                }
                _ => {}
            }
        }
        Workflow { top, jobs }
    }
}

fn build_job<'a>(id: String, fields: &'a Fields, ctx: &mut Context<'_>) -> Job<'a> {
    ctx.reject_merge_keys(fields, &format!("job `{id}`"));
    let mut steps = Vec::new();
    for node in field(fields, "steps") {
        match node {
            Node::Seq(items) => {
                for (index, item) in items.iter().enumerate() {
                    match item {
                        Node::Map(step_fields) => {
                            ctx.reject_merge_keys(
                                step_fields,
                                &format!("step {index} of job `{id}`"),
                            );
                            steps.push(Step {
                                index,
                                fields: step_fields,
                            });
                        }
                        Node::CollectionAlias => ctx.unsupported(format!(
                            "step {index} of job `{id}` is an alias that is not expanded"
                        )),
                        _ => {}
                    }
                }
            }
            Node::CollectionAlias => ctx.unsupported(format!(
                "`steps` of job `{id}` is an alias that is not expanded"
            )),
            _ => {}
        }
    }
    Job { id, fields, steps }
}
