use std::collections::HashMap;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::time::Instant;

use yaml_rust2::parser::{Event, Parser};
use yaml_rust2::scanner::TScalarStyle;

/// A YAML value with the source line of each scalar.
///
/// Aliases to scalars are replaced by a copy of the scalar. Aliases to
/// collections are not expanded, which avoids alias-expansion blowups; they
/// become [`Node::CollectionAlias`] so callers can report them as unsupported.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Node {
    Scalar {
        value: String,
        line: usize,
        /// Literal (`|`) or folded (`>`) block scalar.
        block: bool,
        /// For a scalar that came from an alias: the line where the anchored
        /// value is defined. `line` is then the line where the alias is used.
        alias_of: Option<usize>,
    },
    Map(Vec<(Node, Node)>),
    Seq(Vec<Node>),
    CollectionAlias,
}

impl Node {
    /// The text of a non-block scalar.
    pub(crate) fn as_str(&self) -> Option<&str> {
        match self {
            Node::Scalar {
                value,
                block: false,
                ..
            } => Some(value),
            _ => None,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ParseFailure {
    /// The text is not valid YAML.
    Invalid(String),
    /// Valid YAML that this analysis does not handle.
    Unsupported(String),
    /// Nesting deeper than the configured limit.
    TooDeep(usize),
    /// The scan deadline passed while parsing.
    Timeout,
}

enum Frame {
    Map {
        entries: Vec<(Node, Node)>,
        key: Option<Node>,
    },
    Seq(Vec<Node>),
}

/// Parses a single-document YAML file into a [`Node`] tree.
///
/// The text is only parsed. Tags such as `!!python/object` are not
/// interpreted, so no constructors run. A panic inside the parser is caught
/// and reported as invalid input.
///
/// The deadline is checked every [`DEADLINE_CHECK_EVENTS`] parser events. This
/// is cooperative: a single event that blocks cannot be interrupted.
pub(crate) fn parse_document(
    text: &str,
    max_depth: usize,
    deadline: Instant,
) -> Result<Option<Node>, ParseFailure> {
    catch_unwind(AssertUnwindSafe(|| parse(text, max_depth, deadline))).unwrap_or_else(|_| {
        Err(ParseFailure::Invalid(
            "the YAML parser failed on this input".into(),
        ))
    })
}

fn place(node: Node, stack: &mut [Frame], root: &mut Option<Node>) {
    match stack.last_mut() {
        None => *root = Some(node),
        Some(Frame::Seq(items)) => items.push(node),
        Some(Frame::Map { entries, key }) => match key.take() {
            None => *key = Some(node),
            Some(k) => entries.push((k, node)),
        },
    }
}

/// Number of parser events between deadline checks.
const DEADLINE_CHECK_EVENTS: usize = 256;

fn parse(text: &str, max_depth: usize, deadline: Instant) -> Result<Option<Node>, ParseFailure> {
    let mut parser = Parser::new_from_str(text);
    let mut stack: Vec<Frame> = Vec::new();
    let mut root = None;
    let mut documents = 0;
    let mut events = 0usize;
    let mut scalar_anchors: HashMap<usize, Node> = HashMap::new();

    loop {
        let (event, mark) = parser
            .next_token()
            .map_err(|e| ParseFailure::Invalid(e.to_string()))?;
        events += 1;
        if events.is_multiple_of(DEADLINE_CHECK_EVENTS) && Instant::now() >= deadline {
            return Err(ParseFailure::Timeout);
        }
        match event {
            Event::Nothing | Event::StreamStart | Event::DocumentEnd => {}
            Event::StreamEnd => break,
            Event::DocumentStart => {
                documents += 1;
                if documents > 1 {
                    return Err(ParseFailure::Unsupported("multiple YAML documents".into()));
                }
            }
            Event::Scalar(value, style, anchor, _tag) => {
                let node = Node::Scalar {
                    value,
                    line: mark.line(),
                    block: matches!(style, TScalarStyle::Literal | TScalarStyle::Folded),
                    alias_of: None,
                };
                if anchor > 0 {
                    scalar_anchors.insert(anchor, node.clone());
                }
                place(node, &mut stack, &mut root);
            }
            Event::Alias(id) => {
                // Keep the position where the alias is used; remember where the
                // value was defined.
                let node = match scalar_anchors.get(&id) {
                    Some(Node::Scalar {
                        value, block, line, ..
                    }) => Node::Scalar {
                        value: value.clone(),
                        line: mark.line(),
                        block: *block,
                        alias_of: Some(*line),
                    },
                    _ => Node::CollectionAlias,
                };
                place(node, &mut stack, &mut root);
            }
            Event::SequenceStart(..) | Event::MappingStart(..) => {
                if stack.len() >= max_depth {
                    return Err(ParseFailure::TooDeep(max_depth));
                }
                stack.push(if matches!(event, Event::SequenceStart(..)) {
                    Frame::Seq(Vec::new())
                } else {
                    Frame::Map {
                        entries: Vec::new(),
                        key: None,
                    }
                });
            }
            Event::SequenceEnd | Event::MappingEnd => {
                let node = match stack.pop() {
                    Some(Frame::Seq(items)) => Node::Seq(items),
                    Some(Frame::Map { entries, .. }) => Node::Map(entries),
                    None => return Err(ParseFailure::Invalid("unbalanced collection".into())),
                };
                place(node, &mut stack, &mut root);
            }
        }
    }
    Ok(root)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn far() -> Instant {
        Instant::now() + Duration::from_secs(60)
    }

    fn scalar(value: &str, line: usize) -> Node {
        Node::Scalar {
            value: value.into(),
            line,
            block: false,
            alias_of: None,
        }
    }

    #[test]
    fn mapping_keeps_scalar_lines() {
        let node = parse_document("a: 1\nb: two\n", 64, far())
            .unwrap()
            .unwrap();
        assert_eq!(
            node,
            Node::Map(vec![
                (scalar("a", 1), scalar("1", 1)),
                (scalar("b", 2), scalar("two", 2)),
            ])
        );
    }

    #[test]
    fn comments_are_not_content() {
        let node = parse_document("# permissions: write-all\na: 1\n", 64, far())
            .unwrap()
            .unwrap();
        assert_eq!(node, Node::Map(vec![(scalar("a", 2), scalar("1", 2))]));
    }

    #[test]
    fn empty_input_has_no_document() {
        assert_eq!(parse_document("", 64, far()), Ok(None));
        assert_eq!(parse_document("# only a comment\n", 64, far()), Ok(None));
    }

    #[test]
    fn malformed_yaml_is_invalid() {
        assert!(matches!(
            parse_document("a: [unclosed\n", 64, far()),
            Err(ParseFailure::Invalid(_))
        ));
    }

    #[test]
    fn multiple_documents_are_unsupported() {
        assert!(matches!(
            parse_document("a: 1\n---\nb: 2\n", 64, far()),
            Err(ParseFailure::Unsupported(_))
        ));
    }

    #[test]
    fn expired_deadline_stops_a_large_document() {
        let big = (0..2000).map(|i| format!("k{i}: v\n")).collect::<String>();
        let past = Instant::now() - Duration::from_secs(1);
        assert_eq!(parse_document(&big, 64, past), Err(ParseFailure::Timeout));
        assert!(parse_document(&big, 64, far()).is_ok());
    }

    #[test]
    fn deep_nesting_is_rejected() {
        let deep = "[".repeat(100) + &"]".repeat(100);
        assert_eq!(
            parse_document(&deep, 64, far()),
            Err(ParseFailure::TooDeep(64))
        );
    }

    #[test]
    fn scalar_alias_is_copied_and_collection_alias_is_not_expanded() {
        let node = parse_document("a: &x write-all\nb: *x\nc: &m {k: v}\nd: *m\n", 64, far())
            .unwrap()
            .unwrap();
        let Node::Map(entries) = node else {
            panic!("expected a mapping")
        };
        assert_eq!(entries[1].1.as_str(), Some("write-all"));
        assert_eq!(entries[3].1, Node::CollectionAlias);
    }

    #[test]
    fn alias_keeps_its_own_line_and_records_the_definition_line() {
        let node = parse_document("x: &v write-all\np: *v\nq: *v\n", 64, far())
            .unwrap()
            .unwrap();
        let Node::Map(entries) = node else {
            panic!("expected a mapping")
        };
        let alias = |i: usize| match &entries[i].1 {
            Node::Scalar { line, alias_of, .. } => (*line, *alias_of),
            other => panic!("unexpected {other:?}"),
        };
        assert_eq!(alias(0), (1, None));
        assert_eq!(alias(1), (2, Some(1)));
        assert_eq!(alias(2), (3, Some(1)));
    }

    #[test]
    fn python_object_tag_is_just_text() {
        let node = parse_document(
            "a: !!python/object/apply:os.system [\"echo hi\"]\n",
            64,
            far(),
        );
        assert!(node.is_ok());
    }
}
