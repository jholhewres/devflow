//! Work items: what devpit's board held as cards — a brief's epic, a plan's
//! slices, any piece of work a gate is asked about — kept by default as one
//! Markdown file each under `<folder>/work/`, where a person reads and edits
//! them like any other file of the project.
//!
//! A file is a frontmatter of plain fields, the body, and the comments after
//! a marker line, newest last:
//!
//! ```text
//! ---
//! id: 3
//! title: "[devflow] Rename a card"
//! kind: item
//! state: open
//! parent: 1
//! depends_on: [2]
//! created: 20261023T150000Z
//! ---
//! ## Acceptance criteria
//! - [ ] rename changes the title
//!
//! <!-- devflow:comments -->
//! ### agent · 20261023T151200Z
//! The handoff note.
//! ```

use std::path::{Path, PathBuf};
use std::time::SystemTime;

use serde::Serialize;
use serde_json::{json, Value};
use yaml_rust2::{Yaml, YamlLoader};

/// The folder work items are kept in, under the project's devflow folder.
pub const FOLDER: &str = "work";

/// The line the comments start after.
pub const COMMENTS: &str = "<!-- devflow:comments -->";

/// The most of one item's file read.
pub const MOST_BYTES: u64 = 512 * 1024;

/// The most items a project's folder is read for.
pub const MOST_ITEMS: usize = 5000;

const LONGEST_TITLE: usize = 300;
const LONGEST_COMMENT: usize = 64 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    /// A brief: what the slices under it are for.
    Epic,
    Item,
}

impl Kind {
    pub fn word(self) -> &'static str {
        match self {
            Kind::Epic => "epic",
            Kind::Item => "item",
        }
    }

    pub fn of(word: &str) -> Option<Kind> {
        match word {
            "epic" => Some(Kind::Epic),
            "item" => Some(Kind::Item),
            _ => None,
        }
    }
}

/// Where an item stands: devpit's backlog, doing and done columns.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum State {
    Open,
    Doing,
    Done,
}

impl State {
    pub fn word(self) -> &'static str {
        match self {
            State::Open => "open",
            State::Doing => "doing",
            State::Done => "done",
        }
    }

    pub fn of(word: &str) -> Option<State> {
        match word {
            "open" => Some(State::Open),
            "doing" => Some(State::Doing),
            "done" => Some(State::Done),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct WorkItem {
    pub id: String,
    pub title: String,
    pub kind: Kind,
    pub state: State,
    /// The epic it is a slice of.
    pub parent: Option<String>,
    /// The items it waits on.
    pub depends_on: Vec<String>,
    /// When it was made, as a run's name is written.
    pub created: String,
    pub body: String,
}

impl WorkItem {
    /// What a tool answers about it, the comments left out.
    pub fn to_json(&self) -> Value {
        json!({
            "id": self.id,
            "title": self.title,
            "kind": self.kind,
            "state": self.state,
            "parent": self.parent,
            "depends_on": self.depends_on,
            "created": self.created,
            "body": self.body,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Comment {
    pub by: String,
    pub at: String,
    pub text: String,
}

/// An item to make.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct New {
    pub title: String,
    pub kind: Kind,
    pub parent: Option<String>,
    pub depends_on: Vec<String>,
    pub body: String,
}

/// Where the work items of a project are kept. The file backend is
/// [`Files`]; a tracker is another implementation of the same.
pub trait WorkItems {
    fn get(&self, id: &str) -> Result<Option<WorkItem>, String>;
    /// Every item, oldest first.
    fn list(&self) -> Result<Vec<WorkItem>, String>;
    fn create(&self, new: &New, at: SystemTime) -> Result<WorkItem, String>;
    fn update_body(&self, id: &str, body: &str) -> Result<WorkItem, String>;
    fn set_state(&self, id: &str, state: State) -> Result<WorkItem, String>;
    fn comment(&self, id: &str, by: &str, text: &str, at: SystemTime) -> Result<(), String>;
    fn comments(&self, id: &str) -> Result<Vec<Comment>, String>;
}

/// Work items as files under `<root>/<folder>/work/`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Files {
    root: PathBuf,
    relative: String,
}

impl Files {
    /// `root`'s work items, in the folder it keeps devflow in.
    pub fn of(root: &Path) -> Files {
        Files {
            root: root.to_path_buf(),
            relative: format!("{}/{FOLDER}", crate::folder::dir(root)),
        }
    }

    /// The folder, relative to the project's root.
    pub fn relative(&self) -> &str {
        &self.relative
    }

    fn folder(&self) -> Result<Option<PathBuf>, String> {
        if self.root.join(&self.relative).symlink_metadata().is_err() {
            return Ok(None);
        }
        crate::fsguard::resolve(&self.root, &self.relative)
            .map(Some)
            .map_err(|err| format!("{}: {err}", self.relative))
    }

    fn made_folder(&self) -> Result<PathBuf, String> {
        crate::setup::folders(&self.root, &self.relative)?;
        crate::fsguard::resolve(&self.root, &self.relative)
            .map_err(|err| format!("{}: {err}", self.relative))
    }

    /// The files of the folder, `<id>.md` each.
    fn files(&self) -> Result<Vec<(String, PathBuf)>, String> {
        let Some(folder) = self.folder()? else {
            return Ok(Vec::new());
        };
        let entries =
            std::fs::read_dir(&folder).map_err(|err| format!("{}: {err}", self.relative))?;
        let mut found: Vec<(String, PathBuf)> = entries
            .filter_map(Result::ok)
            // A link is not an item of ours, whatever it points at.
            .filter(|entry| entry.file_type().is_ok_and(|kind| kind.is_file()))
            .filter_map(|entry| {
                let name = entry.file_name().into_string().ok()?;
                let id = name.strip_suffix(".md")?;
                plain_id(id).then(|| (id.to_owned(), entry.path()))
            })
            .take(MOST_ITEMS)
            .collect();
        found.sort_by(|a, b| order(&a.0).cmp(&order(&b.0)));
        Ok(found)
    }

    fn path_of(&self, id: &str) -> Result<PathBuf, String> {
        if !plain_id(id) {
            return Err(format!("`{id}` is not a work item's id"));
        }
        let folder = self.made_folder()?;
        crate::fsguard::resolve_new(&folder, &format!("{id}.md"))
            .map_err(|err| format!("{id}: {err}"))
    }

    fn read_file(&self, id: &str) -> Result<Option<(WorkItem, Vec<Comment>)>, String> {
        if !plain_id(id) {
            return Err(format!("`{id}` is not a work item's id"));
        }
        let Some(folder) = self.folder()? else {
            return Ok(None);
        };
        let name = format!("{id}.md");
        if folder.join(&name).symlink_metadata().is_err() {
            return Ok(None);
        }
        let path = crate::fsguard::resolve(&folder, &name).map_err(|err| format!("{id}: {err}"))?;
        let file = std::fs::File::open(&path).map_err(|err| format!("{id}: {err}"))?;
        let raw = crate::fsguard::read_within(file, MOST_BYTES)
            .map_err(|err| format!("{id}: {err}"))?
            .ok_or_else(|| format!("{id} is larger than {} KB", MOST_BYTES / 1024))?;
        let text = String::from_utf8(raw).map_err(|_| format!("{id} is not UTF-8 text"))?;
        parse(id, &text).map(Some)
    }

    fn write_file(&self, item: &WorkItem, comments: &[Comment]) -> Result<(), String> {
        let path = self.path_of(&item.id)?;
        let folder = path.parent().unwrap_or(Path::new("."));
        let name = format!("{}.md", item.id);
        crate::fsguard::replace(folder, &name, written(item, comments).as_bytes())
            .map_err(|err| format!("{}: {err}", item.id))
    }

    fn changed(
        &self,
        id: &str,
        change: impl FnOnce(&mut WorkItem, &mut Vec<Comment>),
    ) -> Result<WorkItem, String> {
        let (mut item, mut comments) = self
            .read_file(id)?
            .ok_or_else(|| format!("there is no work item `{id}`"))?;
        change(&mut item, &mut comments);
        self.write_file(&item, &comments)?;
        Ok(item)
    }

    /// The id the next item gets: one past the highest number there.
    fn next_id(&self) -> Result<u64, String> {
        Ok(self
            .files()?
            .iter()
            .filter_map(|(id, _)| id.parse::<u64>().ok())
            .max()
            .unwrap_or(0)
            + 1)
    }
}

impl WorkItems for Files {
    fn get(&self, id: &str) -> Result<Option<WorkItem>, String> {
        Ok(self.read_file(id)?.map(|(item, _)| item))
    }

    fn list(&self) -> Result<Vec<WorkItem>, String> {
        self.files()?
            .into_iter()
            .filter_map(|(id, _)| self.read_file(&id).transpose())
            .map(|read| read.map(|(item, _)| item))
            .collect()
    }

    fn create(&self, new: &New, at: SystemTime) -> Result<WorkItem, String> {
        let title = one_line(&new.title);
        if title.is_empty() || title.chars().count() > LONGEST_TITLE {
            return Err(format!(
                "a work item's title is one line of 1 to {LONGEST_TITLE} characters"
            ));
        }
        for id in new.parent.iter().chain(&new.depends_on) {
            if self.get(id)?.is_none() {
                return Err(format!("there is no work item `{id}`"));
            }
        }
        let folder = self.made_folder()?;
        let mut number = self.next_id()?;
        // `create_new`: two sessions making an item at once never share a file.
        for _ in 0..100 {
            let id = number.to_string();
            let item = WorkItem {
                id: id.clone(),
                title: title.clone(),
                kind: new.kind,
                state: State::Open,
                parent: new.parent.clone(),
                depends_on: new.depends_on.clone(),
                created: crate::runs::stamp(at),
                body: new.body.trim_end_matches('\n').to_owned(),
            };
            let path = crate::fsguard::resolve_new(&folder, &format!("{id}.md"))
                .map_err(|err| format!("{id}: {err}"))?;
            match std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
            {
                Ok(mut file) => {
                    use std::io::Write as _;
                    file.write_all(written(&item, &[]).as_bytes())
                        .map_err(|err| format!("{id}: {err}"))?;
                    return Ok(item);
                }
                Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => number += 1,
                Err(err) => return Err(format!("{id}: {err}")),
            }
        }
        Err("no free work item id after a hundred tries".to_owned())
    }

    fn update_body(&self, id: &str, body: &str) -> Result<WorkItem, String> {
        if body.contains(COMMENTS) {
            return Err(format!("a body never holds the line {COMMENTS}"));
        }
        self.changed(id, |item, _| {
            item.body = body.trim_end_matches('\n').to_owned()
        })
    }

    fn set_state(&self, id: &str, state: State) -> Result<WorkItem, String> {
        self.changed(id, |item, _| item.state = state)
    }

    fn comment(&self, id: &str, by: &str, text: &str, at: SystemTime) -> Result<(), String> {
        let text = text.trim();
        if text.is_empty() || text.len() > LONGEST_COMMENT {
            return Err(format!(
                "a comment is 1 to {} KB of text",
                LONGEST_COMMENT / 1024
            ));
        }
        if text.contains(COMMENTS) {
            return Err(format!("a comment never holds the line {COMMENTS}"));
        }
        let by = one_line(by);
        self.changed(id, |_, comments| {
            comments.push(Comment {
                by: if by.is_empty() {
                    "agent".to_owned()
                } else {
                    by
                },
                at: crate::runs::stamp(at),
                text: text.to_owned(),
            })
        })
        .map(|_| ())
    }

    fn comments(&self, id: &str) -> Result<Vec<Comment>, String> {
        Ok(self
            .read_file(id)?
            .map(|(_, comments)| comments)
            .unwrap_or_default())
    }
}

/// An id the folder makes a file of: letters, digits, `-` and `_`.
pub fn plain_id(id: &str) -> bool {
    crate::runs::plain_card(id)
}

/// Numbers in their order, then the rest by name.
fn order(id: &str) -> (u64, String) {
    (id.parse::<u64>().unwrap_or(u64::MAX), id.to_owned())
}

fn one_line(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// The file's text for `item` and its comments.
pub fn written(item: &WorkItem, comments: &[Comment]) -> String {
    let quoted = |text: &str| Value::String(text.to_owned()).to_string();
    let mut out = String::from("---\n");
    out.push_str(&format!("id: {}\n", quoted(&item.id)));
    out.push_str(&format!("title: {}\n", quoted(&item.title)));
    out.push_str(&format!("kind: {}\n", item.kind.word()));
    out.push_str(&format!("state: {}\n", item.state.word()));
    if let Some(parent) = &item.parent {
        out.push_str(&format!("parent: {}\n", quoted(parent)));
    }
    if !item.depends_on.is_empty() {
        let ids: Vec<String> = item.depends_on.iter().map(|id| quoted(id)).collect();
        out.push_str(&format!("depends_on: [{}]\n", ids.join(", ")));
    }
    out.push_str(&format!("created: {}\n", quoted(&item.created)));
    out.push_str("---\n");
    out.push_str(item.body.trim_end_matches('\n'));
    out.push('\n');
    if !comments.is_empty() {
        out.push('\n');
        out.push_str(COMMENTS);
        out.push('\n');
        for comment in comments {
            out.push_str(&format!("\n### {} · {}\n\n", comment.by, comment.at));
            out.push_str(comment.text.trim_end_matches('\n'));
            out.push('\n');
        }
    }
    out
}

/// An item's file read back. `id` is the file's name, which wins over what
/// the frontmatter says.
pub fn parse(id: &str, text: &str) -> Result<(WorkItem, Vec<Comment>), String> {
    let text = text.replace("\r\n", "\n");
    let rest = text
        .strip_prefix("---\n")
        .ok_or_else(|| format!("{id}.md does not start with its frontmatter"))?;
    let (front, after) = rest
        .split_once("\n---\n")
        .or_else(|| rest.strip_suffix("\n---").map(|front| (front, "")))
        .ok_or_else(|| format!("{id}.md's frontmatter has no end"))?;
    let docs = YamlLoader::load_from_str(front)
        .map_err(|err| format!("{id}.md's frontmatter does not read: {err}"))?;
    let fields = docs.first().cloned().unwrap_or(Yaml::Null);
    let word = |key: &str| -> Option<String> {
        match &fields[key] {
            Yaml::String(text) => Some(text.clone()),
            Yaml::Integer(number) => Some(number.to_string()),
            _ => None,
        }
    };
    let title = word("title").ok_or_else(|| format!("{id}.md has no title"))?;
    let kind = match word("kind") {
        None => Kind::Item,
        Some(kind) => {
            Kind::of(&kind).ok_or_else(|| format!("{id}.md's kind `{kind}` is not epic or item"))?
        }
    };
    let state = match word("state") {
        None => State::Open,
        Some(state) => State::of(&state)
            .ok_or_else(|| format!("{id}.md's state `{state}` is not open, doing or done"))?,
    };
    let depends_on = match &fields["depends_on"] {
        Yaml::Array(ids) => ids
            .iter()
            .filter_map(|one| match one {
                Yaml::String(text) => Some(text.clone()),
                Yaml::Integer(number) => Some(number.to_string()),
                _ => None,
            })
            .collect(),
        _ => Vec::new(),
    };
    let (body, comments) = match after.split_once(&format!("\n{COMMENTS}\n")) {
        Some((body, comments)) => (body, read_comments(comments)),
        None => match after.strip_prefix(&format!("{COMMENTS}\n")) {
            Some(comments) => ("", read_comments(comments)),
            None => (after, Vec::new()),
        },
    };
    Ok((
        WorkItem {
            id: id.to_owned(),
            title,
            kind,
            state,
            parent: word("parent"),
            depends_on,
            created: word("created").unwrap_or_default(),
            body: body.trim_end_matches('\n').to_owned(),
        },
        comments,
    ))
}

fn read_comments(text: &str) -> Vec<Comment> {
    let mut comments: Vec<Comment> = Vec::new();
    for line in text.split('\n') {
        let head = line
            .strip_prefix("### ")
            .and_then(|head| head.rsplit_once(" · "));
        match (head, comments.last_mut()) {
            (Some((by, at)), _) => comments.push(Comment {
                by: by.to_owned(),
                at: at.to_owned(),
                text: String::new(),
            }),
            (None, Some(comment)) => {
                comment.text.push_str(line);
                comment.text.push('\n');
            }
            (None, None) => {}
        }
    }
    for comment in &mut comments {
        comment.text = comment.text.trim().to_owned();
    }
    comments
}

#[cfg(test)]
#[path = "work_tests.rs"]
mod tests;
