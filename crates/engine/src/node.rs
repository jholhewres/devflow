//! A YAML or JSON document as one small tree, each node knowing the line it
//! came from: the schema is checked once, over either, and a YAML mistake is
//! answered with where it is.

use yaml_rust2::parser::{Event, MarkedEventReceiver, Parser};
use yaml_rust2::scanner::{Marker, TScalarStyle};

use crate::config::Invalid;

/// Where a scalar sits in the text: the line (from 1) and the column in
/// characters (from 0), which is what an edit in place needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct At {
    pub line: usize,
    pub col: usize,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Value {
    Map(Vec<(Key, Node)>),
    Seq(Vec<Node>),
    /// Its text, and whether it was plain: a quoted `"true"` is a word.
    Scalar(String, bool),
    Null,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Key {
    pub name: String,
    pub line: Option<usize>,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Node {
    pub value: Value,
    /// `None` for a node built from JSON, which has no lines.
    pub at: Option<At>,
}

impl Node {
    pub(crate) fn line(&self) -> Option<usize> {
        self.at.map(|at| at.line)
    }
}

/// The tree of a YAML text: one document, no anchors or aliases.
pub(crate) fn from_yaml(text: &str) -> Result<Node, Invalid> {
    let mut built = Built::default();
    // Every document read, so a second one is refused rather than ignored.
    Parser::new_from_str(text)
        .load(&mut built, true)
        .map_err(|err| Invalid::at(Some(err.marker().line()), "", err.info()))?;
    if let Some(invalid) = built.invalid {
        return Err(invalid);
    }
    Ok(built.root.unwrap_or(Node {
        value: Value::Null,
        at: None,
    }))
}

/// The tree of a JSON value, for a change made through a tool.
pub(crate) fn from_json(value: &serde_json::Value) -> Node {
    use serde_json::Value as Json;
    let value = match value {
        Json::Null => Value::Null,
        Json::Bool(yes) => Value::Scalar(yes.to_string(), true),
        Json::Number(number) => Value::Scalar(number.to_string(), true),
        Json::String(text) => Value::Scalar(text.clone(), false),
        Json::Array(items) => Value::Seq(items.iter().map(from_json).collect()),
        Json::Object(fields) => Value::Map(
            fields
                .iter()
                .map(|(name, value)| {
                    (
                        Key {
                            name: name.clone(),
                            line: None,
                        },
                        from_json(value),
                    )
                })
                .collect(),
        ),
    };
    Node { value, at: None }
}

enum Open {
    Map(At, Vec<(Key, Node)>, Option<Key>),
    Seq(At, Vec<Node>),
}

#[derive(Default)]
struct Built {
    open: Vec<Open>,
    root: Option<Node>,
    documents: usize,
    invalid: Option<Invalid>,
}

fn at(mark: Marker) -> At {
    At {
        line: mark.line(),
        col: mark.col(),
    }
}

impl Built {
    fn refuse(&mut self, line: usize, why: &str) {
        if self.invalid.is_none() {
            self.invalid = Some(Invalid::at(Some(line), "", why));
        }
    }

    fn place(&mut self, node: Node) {
        let line = node.line().unwrap_or_default();
        match self.open.last_mut() {
            None => self.root = Some(node),
            Some(Open::Seq(_, items)) => items.push(node),
            Some(Open::Map(_, items, key)) => match key.take() {
                Some(key) => items.push((key, node)),
                None => {
                    let Value::Scalar(name, _) = node.value else {
                        return self.refuse(line, "a key is a plain word");
                    };
                    if items.iter().any(|(given, _)| given.name == name) {
                        return self.refuse(line, &format!("`{name}` is given twice"));
                    }
                    *key = Some(Key {
                        name,
                        line: Some(line),
                    });
                }
            },
        }
    }
}

impl MarkedEventReceiver for Built {
    fn on_event(&mut self, event: Event, mark: Marker) {
        if self.invalid.is_some() {
            return;
        }
        match event {
            Event::DocumentStart => {
                self.documents += 1;
                if self.documents > 1 {
                    self.refuse(mark.line(), "devflow.yaml is one document");
                }
            }
            // An alias can make a small file large; nothing here needs one.
            Event::Alias(_) => self.refuse(mark.line(), "anchors and aliases are not read here"),
            Event::Scalar(_, _, anchor, _)
            | Event::SequenceStart(anchor, _)
            | Event::MappingStart(anchor, _)
                if anchor != 0 =>
            {
                self.refuse(mark.line(), "anchors and aliases are not read here");
            }
            Event::Scalar(text, style, _, _) => {
                let plain = style == TScalarStyle::Plain;
                let value = if plain && matches!(text.as_str(), "" | "~" | "null" | "Null" | "NULL")
                {
                    Value::Null
                } else {
                    Value::Scalar(text, plain)
                };
                self.place(Node {
                    value,
                    at: Some(at(mark)),
                });
            }
            Event::SequenceStart(..) => self.open.push(Open::Seq(at(mark), Vec::new())),
            Event::MappingStart(..) => self.open.push(Open::Map(at(mark), Vec::new(), None)),
            Event::SequenceEnd | Event::MappingEnd => match self.open.pop() {
                Some(Open::Seq(at, items)) => self.place(Node {
                    value: Value::Seq(items),
                    at: Some(at),
                }),
                Some(Open::Map(at, items, _)) => self.place(Node {
                    value: Value::Map(items),
                    at: Some(at),
                }),
                None => {}
            },
            _ => {}
        }
    }
}
