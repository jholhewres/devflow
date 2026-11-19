//! The flow's skills — one per stage, and one for its setup — as a project
//! resolves them: its own `.devpit/devflow/skills/<name>/SKILL.md`, else the
//! person's under devpit's home, else the one built into the app from
//! flow/skills/. A layer replaces a skill by its name; none adds one.
//!
//! Each is described the way the MCP Skills extension (SEP-2640) does: a
//! `skill://` URI, its frontmatter, and its file with digest and size.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::dialect::Dialect;
use crate::folder;
use crate::layers::Team;

/// A project's own skills, relative to its root.
pub const DIR: &str = ".devflow/skills";

/// [`DIR`] in `root`'s own folder.
pub fn dir(root: &Path) -> String {
    format!("{}/skills", crate::folder::dir(root))
}

/// The most of a SKILL.md read, checked before reading: far past what a
/// context should take whole.
pub const MOST_BYTES: u64 = 128 * 1024;

/// Each skill's name, its stage (none for the setup's), and its text as this
/// build ships it.
const BUILT_IN: &[(&str, Option<&str>, &str)] = Dialect::DEVFLOW.assets.skills;

/// The words a built-in skill's text is said in. flow/skills/ names each
/// tool by devflow's own name (`{{tool:evidence}}`), and marks each phrase a
/// host says otherwise (`[[work item]]`, or `[[key::devflow's words]]`);
/// what a host does not say is said as devflow says it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Words {
    /// By devflow's tool name: the host's tool, with its backticks.
    pub tools: BTreeMap<String, String>,
    /// By phrase key: the host's words.
    pub phrases: BTreeMap<String, String>,
}

/// The most a host's word for a tool, or its phrase, may take.
const MOST_WORD: usize = 200;
const MOST_PHRASE: usize = 4096;

/// The hosts whose words devflow ships, in flow/hosts/.
pub const HOSTS: [(&str, &str); 1] = [("devpit", include_str!("../../../flow/hosts/devpit.json"))];

impl Words {
    /// A host's dialect as JSON: the words devflow ships for `host`, then
    /// its own `tools` and `phrases` over them. What is not a short text is
    /// left out.
    pub fn of_json(dialect: &Value) -> Words {
        let mut words = dialect["host"]
            .as_str()
            .and_then(Words::shipped)
            .unwrap_or_default();
        words.tools.extend(texts(&dialect["tools"], MOST_WORD));
        words
            .phrases
            .extend(texts(&dialect["phrases"], MOST_PHRASE));
        words
    }

    /// The words devflow ships for `host`, when it ships them.
    pub fn shipped(host: &str) -> Option<Words> {
        let (_, text) = HOSTS.iter().find(|(name, _)| *name == host)?;
        let json: Value = serde_json::from_str(text).ok()?;
        Some(Words {
            tools: texts(&json["tools"], MOST_WORD),
            phrases: texts(&json["phrases"], MOST_PHRASE),
        })
    }
}

fn texts(map: &Value, most: usize) -> BTreeMap<String, String> {
    map.as_object()
        .into_iter()
        .flatten()
        .filter_map(|(name, said)| {
            let said = said.as_str().filter(|said| said.len() <= most)?;
            Some((name.clone(), said.to_owned()))
        })
        .collect()
}

/// A phrase's key and devflow's words for it: `[[key::words]]`, or
/// `[[words]]`, keyed by the words with their spacing made one space.
pub fn phrase_key(inner: &str) -> (String, &str) {
    match inner.split_once("::") {
        Some((key, said)) => (key.to_owned(), said),
        None => (
            inner.split_whitespace().collect::<Vec<_>>().join(" "),
            inner,
        ),
    }
}

/// `text` with each phrase and each tool said in `words`.
pub fn rendered(text: &str, words: &Words) -> String {
    let mut said = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(at) = rest.find("[[") {
        let Some(end) = rest[at + 2..].find("]]") else {
            break;
        };
        said.push_str(&rest[..at]);
        let inner = &rest[at + 2..at + 2 + end];
        let (key, devflows) = phrase_key(inner);
        said.push_str(words.phrases.get(&key).map_or(devflows, String::as_str));
        rest = &rest[at + 2 + end + 2..];
    }
    said.push_str(rest);
    tools_said(&said, words)
}

/// `text` with each `{{tool:<name>}}` said in `words`.
fn tools_said(text: &str, words: &Words) -> String {
    const OPEN: &str = "{{tool:";
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(at) = rest.find(OPEN) {
        out.push_str(&rest[..at]);
        let after = &rest[at + OPEN.len()..];
        let name = after
            .find("}}")
            .map(|end| &after[..end])
            .filter(|name| !name.is_empty() && name.bytes().all(|b| b.is_ascii_lowercase()));
        match name {
            Some(name) => {
                match words.tools.get(name) {
                    Some(said) => out.push_str(said),
                    None => out.push_str(&format!("`{name}`")),
                }
                rest = &after[name.len() + 2..];
            }
            None => {
                out.push_str(OPEN);
                rest = after;
            }
        }
    }
    out.push_str(rest);
    out
}

/// What made a record: this devpit's version, which every crate shares with
/// the app, and the digest of each built-in skill named, as this build ships
/// it — so a run says which text of the flow it followed.
pub fn made_by(skills: &[&str]) -> Value {
    made_by_in(&Dialect::DEVFLOW, skills)
}

/// [`made_by`] in `dialect`: its version, and the digests of its skills.
pub fn made_by_in(dialect: &Dialect, skills: &[&str]) -> Value {
    let digest = |text: &str| {
        let text = rendered(text, &Words::default());
        Value::from(format!("sha256:{:x}", Sha256::digest(text.as_bytes())))
    };
    let mut digests: serde_json::Map<String, Value> = dialect
        .assets
        .skills
        .iter()
        .filter(|(name, _, _)| skills.contains(name))
        .map(|(name, _, text)| ((*name).to_owned(), digest(text)))
        .collect();
    // Each part a skill loads is named too, by `<skill>/<part>`.
    for (skill, part, text) in dialect.assets.parts {
        if skills.contains(skill) {
            digests.insert(format!("{skill}/{part}"), digest(text));
        }
    }
    json!({ "version": dialect.version, "skills": digests })
}

/// Where a skill was found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Layer {
    Project,
    /// A team layer the project extends, at its approved commit.
    Team,
    Personal,
    BuiltIn,
}

impl Layer {
    pub fn word(self) -> &'static str {
        match self {
            Layer::Project => "project",
            Layer::Team => "team",
            Layer::Personal => "personal",
            Layer::BuiltIn => "built-in",
        }
    }
}

/// One skill, resolved.
#[derive(Debug, Clone, PartialEq)]
pub struct Skill {
    pub name: &'static str,
    pub stage: Option<&'static str>,
    pub layer: Layer,
    /// The file it was read from; none when built in.
    pub file: Option<PathBuf>,
    pub text: String,
    /// The SKILL.md frontmatter as JSON.
    pub frontmatter: Value,
}

/// Every skill devpit has, in the order the work reaches them.
pub fn names() -> impl Iterator<Item = &'static str> {
    BUILT_IN.iter().map(|(name, ..)| *name)
}

/// What an active project is offered: the skills of the stages switched on,
/// and the setup's.
pub fn offered(stages_on: &[&str]) -> Vec<&'static str> {
    BUILT_IN
        .iter()
        .filter(|(_, stage, _)| stage.is_none_or(|stage| stages_on.contains(&stage)))
        .map(|(name, ..)| *name)
        .collect()
}

/// Each built-in skill's name, stage and the `description` its frontmatter
/// gives: what a plugin's pointer to it says.
pub fn described() -> Vec<(&'static str, Option<&'static str>, String)> {
    described_in(&Dialect::DEVFLOW)
}

/// [`described`] from `dialect`'s skills.
pub fn described_in(dialect: &Dialect) -> Vec<(&'static str, Option<&'static str>, String)> {
    described_with(dialect, &Words::default())
}

/// [`described_in`], said in a host's `words`.
pub fn described_with(
    dialect: &Dialect,
    words: &Words,
) -> Vec<(&'static str, Option<&'static str>, String)> {
    dialect
        .assets
        .skills
        .iter()
        .map(|(name, stage, text)| {
            let said = said_whole(text, words, name)
                .ok()
                .and_then(|(_, front)| front.get("description")?.as_str().map(str::to_owned))
                .unwrap_or_default();
            (*name, *stage, said)
        })
        .collect()
}

/// The resource URI of a skill's SKILL.md: `devflow` the prefix, the name the
/// last segment, as the extension requires.
pub fn uri(name: &str) -> String {
    format!("skill://devflow/{name}/SKILL.md")
}

/// The skill a name or its URI stands for, when it is one of devpit's.
pub fn named(name_or_uri: &str) -> Option<&'static str> {
    names().find(|name| *name == name_or_uri || uri(name) == name_or_uri)
}

/// `name` from the first layer that has it: the project's, a team's, the
/// person's (`personal`), the built-in one. A file that is there but cannot
/// be used — outside its folder, too large, not UTF-8, another name in its
/// frontmatter — is refused, never passed over for the next layer.
pub fn resolve(project: &Path, personal: &Path, name: &str) -> Result<Skill, String> {
    resolve_with(project, personal, &[], name)
}

/// [`resolve`], with the team layers that apply.
pub fn resolve_with(
    project: &Path,
    personal: &Path,
    teams: &[Team],
    name: &str,
) -> Result<Skill, String> {
    resolve_with_in(&Dialect::DEVFLOW, project, personal, teams, name)
}

/// [`resolve_with`], the built-in skill being `dialect`'s.
pub fn resolve_with_in(
    dialect: &Dialect,
    project: &Path,
    personal: &Path,
    teams: &[Team],
    name: &str,
) -> Result<Skill, String> {
    resolve_said(dialect, &Words::default(), project, personal, teams, name)
}

/// [`resolve_with_in`], the built-in skill said in a host's `words`.
pub fn resolve_said(
    dialect: &Dialect,
    words: &Words,
    project: &Path,
    personal: &Path,
    teams: &[Team],
    name: &str,
) -> Result<Skill, String> {
    let (name, stage, built_in) = dialect
        .assets
        .skills
        .iter()
        .find(|(one, ..)| *one == name)
        .copied()
        .ok_or_else(|| {
            format!(
                "`{name}` is not a Devflow skill: {}",
                names().collect::<Vec<_>>().join(", ")
            )
        })?;
    let places = Layers {
        project,
        personal,
        teams,
    };
    let Some((layer, file, text, at)) = places.file(name, "SKILL.md")? else {
        let (text, frontmatter) = said_whole(built_in, words, name)?;
        return Ok(Skill {
            name,
            stage,
            layer: Layer::BuiltIn,
            file: None,
            frontmatter,
            text,
        });
    };
    let frontmatter = frontmatter(&text, name).map_err(|why| format!("{at}: {why}"))?;
    Ok(Skill {
        name,
        stage,
        layer,
        file,
        text,
        frontmatter,
    })
}

/// A skill's file as a layer had it: the layer, where it was read, its
/// text, and how a refusal names it.
type InLayer = (Layer, Option<PathBuf>, String, String);

/// Where a skill's files are looked for, the first that has one winning.
struct Layers<'a> {
    project: &'a Path,
    personal: &'a Path,
    teams: &'a [Team],
}

impl Layers<'_> {
    /// `<name>/<file>` from the project's skills, a team's, then the
    /// person's: its layer, where it was read and its text. A file that is
    /// there but cannot be used is refused, never passed over.
    fn file(&self, name: &str, file: &str) -> Result<Option<InLayer>, String> {
        let mine = |layer: Layer, base: &Path, relative: String| {
            let at = format!("the {} {relative}", layer.word());
            read_in(base, &relative)
                .map_err(|why| format!("{at}: {why}"))
                .map(|read| read.map(|(path, text)| (layer, Some(path), text, at.clone())))
        };
        let project = format!("{}/{name}/{file}", dir(self.project));
        if let Some(found) = mine(Layer::Project, self.project, project)? {
            return Ok(Some(found));
        }
        for team in self.teams {
            let relative = format!("skills/{name}/{file}");
            if let Some(text) = team.read(&relative)? {
                let at = format!("{}'s {relative}", team.name);
                return Ok(Some((Layer::Team, None, text, at)));
            }
        }
        mine(Layer::Personal, self.personal, format!("{name}/{file}"))
    }
}

/// A part a skill loads only when asked, resolved.
#[derive(Debug, Clone, PartialEq)]
pub struct Part {
    pub skill: &'static str,
    pub part: &'static str,
    pub layer: Layer,
    pub file: Option<PathBuf>,
    pub text: String,
}

/// The parts `skill` has, by name.
pub fn parts(skill: &str) -> Vec<&'static str> {
    Dialect::DEVFLOW
        .assets
        .parts
        .iter()
        .filter(|(one, ..)| *one == skill)
        .map(|(_, part, _)| *part)
        .collect()
}

/// The resource URI of a skill's part, beside its SKILL.md.
pub fn part_uri(skill: &str, part: &str) -> String {
    format!("skill://devflow/{skill}/{part}.md")
}

/// The skill and part a URI stands for, when it is one.
pub fn part_named(uri: &str) -> Option<(&'static str, &'static str)> {
    Dialect::DEVFLOW
        .assets
        .parts
        .iter()
        .find(|(skill, part, _)| part_uri(skill, part) == uri)
        .map(|(skill, part, _)| (*skill, *part))
}

/// `part` of `skill` from the first layer that has it, else built in, said
/// in a host's `words`.
pub fn resolve_part(
    dialect: &Dialect,
    words: &Words,
    places: (&Path, &Path, &[Team]),
    skill: &str,
    part: &str,
) -> Result<Part, String> {
    let (skill, part, built_in) = dialect
        .assets
        .parts
        .iter()
        .find(|(one, other, _)| *one == skill && *other == part)
        .copied()
        .ok_or_else(|| {
            let has = parts(skill);
            if has.is_empty() {
                format!("`{skill}` has no parts")
            } else {
                format!("`{skill}` has no part `{part}`: {}", has.join(", "))
            }
        })?;
    let (project, personal, teams) = places;
    let layers = Layers {
        project,
        personal,
        teams,
    };
    let (layer, file, text, _) = layers
        .file(skill, &format!("{part}.md"))?
        .unwrap_or_else(|| {
            (
                Layer::BuiltIn,
                None,
                rendered(built_in, words),
                String::new(),
            )
        });
    Ok(Part {
        skill,
        part,
        layer,
        file,
        text,
    })
}

/// Where an own stage's skill is looked for.
pub struct Places<'a> {
    pub project: &'a Path,
    /// The person's skills, under devpit's home.
    pub personal: &'a Path,
    pub teams: &'a [Team],
    /// The skills the agent CLI already has installed, for `skills/<name>`.
    pub installed: Option<&'a Path>,
}

/// An own stage's skill, read where it is and never copied.
#[derive(Debug, Clone, PartialEq)]
pub struct Found {
    pub uses: String,
    /// `project`, `personal`, `installed` or the team's name.
    pub layer: String,
    pub file: Option<PathBuf>,
    pub text: String,
}

/// The skill `uses` points at: `project/<name>` in `.devpit/devflow/skills/`,
/// `personal/<name>` in the person's, `skills/<name>` among those already
/// installed — the project's `.claude/skills/`, then the CLI's own — or
/// `<team>/<name>` in a team layer that applies.
pub fn own(uses: &str, places: &Places) -> Result<Found, String> {
    let (place, name) = uses
        .split_once('/')
        .ok_or_else(|| format!("`{uses}` is not <where>/<skill>"))?;
    let at = |layer: &str, found: Option<(PathBuf, String)>| {
        found.map(|(file, text)| (layer.to_owned(), Some(file), text))
    };
    let found = match place {
        "project" => at(
            "project",
            read_in(
                places.project,
                &format!("{}/{name}/SKILL.md", dir(places.project)),
            )?,
        ),
        "personal" => at(
            "personal",
            read_in(places.personal, &format!("{name}/SKILL.md"))?,
        ),
        "skills" => match read_in(places.project, &format!(".claude/skills/{name}/SKILL.md"))? {
            Some(found) => Some(("project".to_owned(), Some(found.0), found.1)),
            None => match places.installed {
                Some(installed) => at(
                    "installed",
                    read_in(installed, &format!("{name}/SKILL.md"))?,
                ),
                None => None,
            },
        },
        team => {
            let layer = places
                .teams
                .iter()
                .find(|one| one.name == team)
                .ok_or_else(|| {
                    format!("no layer called `{team}` applies to this project: see its extends")
                })?;
            layer
                .read(&format!("skills/{name}/SKILL.md"))?
                .map(|text| (team.to_owned(), None, text))
        }
    };
    let (layer, file, text) =
        found.ok_or_else(|| format!("{uses}: there is no SKILL.md where it points"))?;
    frontmatter(&text, name).map_err(|why| format!("{uses}: {why}"))?;
    Ok(Found {
        uses: uses.to_owned(),
        layer,
        file,
        text,
    })
}

/// The text of `relative` under `base`, or none when nothing is there. Read
/// through symlinks, only from inside `base`, and only up to the ceiling.
fn read_in(base: &Path, relative: &str) -> Result<Option<(PathBuf, String)>, String> {
    let path = base.join(relative);
    if path.symlink_metadata().is_err() {
        return Ok(None);
    }
    let resolved = crate::fsguard::resolve(base, relative).map_err(|err| match err {
        crate::fsguard::TreeError::Outside { .. } => "it leads outside its folder".to_owned(),
        _ => "it could not be read".to_owned(),
    })?;
    match std::fs::metadata(&resolved) {
        Ok(meta) if !meta.is_file() => return Err("it is not a file".to_owned()),
        Ok(_) => {}
        Err(_) => return Err("it could not be read".to_owned()),
    }
    let too_large = || format!("it is larger than {} KB", MOST_BYTES / 1024);
    let file = std::fs::File::open(&resolved).map_err(|_| "it could not be read".to_owned())?;
    let raw = crate::fsguard::read_within(file, MOST_BYTES)
        .map_err(|_| "it could not be read".to_owned())?
        .ok_or_else(too_large)?;
    let text = String::from_utf8(raw).map_err(|_| "it is not UTF-8 text".to_owned())?;
    Ok(Some((path, text)))
}

/// The frontmatter of a SKILL.md, which must name it `name` and say when it
/// is for: the extension's entry carries it, and a host checks it.
fn frontmatter(text: &str, name: &str) -> Result<Value, String> {
    let yaml = fenced(text).ok_or("it does not begin with a --- frontmatter")?;
    let front = folder::as_json(yaml)
        .filter(Value::is_object)
        .ok_or("its frontmatter is not YAML fields")?;
    match front.get("name").and_then(Value::as_str) {
        Some(said) if said == name => {}
        Some(said) => return Err(format!("its frontmatter names it `{said}`, not `{name}`")),
        None => return Err("its frontmatter has no name".to_owned()),
    }
    if front
        .get("description")
        .and_then(Value::as_str)
        .is_none_or(str::is_empty)
    {
        return Err("its frontmatter has no description".to_owned());
    }
    Ok(front)
}

/// A built-in SKILL.md said in `words`, and its frontmatter. A host's words
/// that would not read as a plain YAML value are put in quotes, so its
/// description is what the host said, never cut short or refused.
fn said_whole(template: &str, words: &Words, name: &str) -> Result<(String, Value), String> {
    let text = rendered(template, words);
    let line = fenced(template).and_then(|yaml| {
        yaml.lines()
            .find_map(|line| line.strip_prefix("description: "))
    });
    let Some(line) = line else {
        return frontmatter(&text, name).map(|front| (text, front));
    };
    let wanted = rendered(line, words);
    if let Ok(front) = frontmatter(&text, name) {
        if front["description"] == wanted.as_str() {
            return Ok((text, front));
        }
    }
    let plain = format!("description: {wanted}\n");
    let quoted = format!(
        "description: {}\n",
        serde_json::to_string(&wanted).unwrap_or_default()
    );
    let text = text.replacen(&plain, &quoted, 1);
    let front = frontmatter(&text, name)
        .map_err(|why| format!("`{name}` said in the host's words: {why}"))?;
    Ok((text, front))
}

/// The YAML between the opening `---` and the next line that is only `---`.
fn fenced(text: &str) -> Option<&str> {
    let body = text
        .strip_prefix("---\n")
        .or_else(|| text.strip_prefix("---\r\n"))?;
    let mut at = 0;
    for line in body.split_inclusive('\n') {
        if line.trim_end() == "---" {
            return Some(&body[..at]);
        }
        at += line.len();
    }
    None
}

impl Skill {
    /// SHA-256 of the file's bytes, as the extension writes it.
    pub fn digest(&self) -> String {
        format!("sha256:{:x}", Sha256::digest(self.text.as_bytes()))
    }

    /// The extension's entry: what `skills/list` and `skills/get` will answer
    /// once hosts ask for them. Its SKILL.md; a part is a resource of its own.
    pub fn entry(&self) -> Value {
        let uri = uri(self.name);
        json!({
            "uri": uri,
            "frontmatter": self.frontmatter,
            "resources": [{ "uri": uri, "digest": self.digest(), "size": self.text.len() }],
        })
    }

    /// The entry, with where it came from.
    pub fn to_json(&self) -> Value {
        json!({
            "name": self.name,
            "stage": self.stage,
            "layer": self.layer.word(),
            "file": self.file.as_ref().map(|file| file.display().to_string()),
            "skill": self.entry(),
        })
    }
}

#[cfg(test)]
#[path = "skills_tests.rs"]
mod tests;
