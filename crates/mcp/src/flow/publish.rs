//! `publish`: a review without a work item drafted for its pull request,
//! and posted there with `gh` once the person said yes to that draft.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use devflow_engine::adhoc;
use devflow_engine::publish::{self, Destination, Event, Host, Inline};
use devflow_engine::review::Personas;
use serde_json::{json, Value};

use crate::project::{self, Project};
use crate::server::Server;

/// How long one call to GitHub may take before it is given up on.
const GIVE_UP: Duration = Duration::from_secs(20);
/// Far past what any answer of these calls holds.
const MOST_ANSWER: u64 = 4 * 1024 * 1024;

/// Where a review is posted: a pull request of the project's repository.
pub type Hosting<'a> = &'a dyn Fn(&Path, u64) -> Box<dyn Host>;

pub fn publish(server: &Server, params: Value) -> Result<Value, String> {
    let project = server.project();
    respond_with(&project, &params, &|root, pr| {
        Box::new(Gh {
            root: root.to_path_buf(),
            pr,
        })
    })
}

pub fn respond_with(project: &Project, params: &Value, hosting: Hosting) -> Result<Value, String> {
    let asked = publish::asked(params)?;
    let reviews = project.reviews(&project.root).home;
    let folder = devflow_engine::fsguard::resolve(&reviews, &asked.review())
        .ok()
        .filter(|folder| folder.is_dir())
        .ok_or_else(|| {
            format!(
                "no review {} of this project: pass its folder and run as `review` answered them",
                asked.review()
            )
        })?;
    let config = super::review::config_of(&project.read())?;
    let teams = project.teams();
    let personal = project::personal_reviewers();
    let template = publish::template(
        &project.root,
        Personas {
            personal: personal.as_deref(),
            teams: &teams,
        },
        asked.destination,
    )?;
    let host = match (asked.destination, adhoc::pr_of(&asked.label)) {
        (Destination::GitHub, Some(pr)) => Ok(hosting(&project.root, pr)),
        (Destination::GitHub, None) => {
            Err("a range has no pull request to post on: its draft is publish.json".to_owned())
        }
        (other, _) => Err(format!(
            "devflow posts to GitHub only: the {} draft is publish.json, to paste",
            other.word()
        )),
    };
    publish::respond(
        &folder,
        &asked,
        &template,
        config.review.verify,
        host.as_deref().map_err(String::as_str),
    )
}

/// A pull request on GitHub, through `gh api`: the person's own sign-in,
/// never a prompt for one.
struct Gh {
    root: PathBuf,
    pr: u64,
}

impl Gh {
    /// One call; `body` goes on gh's stdin, never on its command line.
    fn api(&self, method: &str, path: &str, body: Option<&Value>) -> Result<Value, String> {
        let mut command = devflow_engine::env::command("gh");
        command
            .args(["api", "--method", method, path])
            .current_dir(&self.root)
            .env("GH_PROMPT_DISABLED", "1")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if body.is_some() {
            command.args(["--input", "-"]);
        }
        let mut child = command.spawn().map_err(|_| {
            "gh is not installed: publishing needs gh signed in to GitHub".to_owned()
        })?;
        let input = body.map(Value::to_string).unwrap_or_default();
        let mut stdin = child.stdin.take();
        let mut stdout = child.stdout.take();
        let mut stderr = child.stderr.take();
        let (tell, hear) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            if let Some(mut stdin) = stdin.take() {
                let _ = stdin.write_all(input.as_bytes());
            }
            let read = |pipe: Option<&mut dyn Read>| {
                let mut said = Vec::new();
                if let Some(pipe) = pipe {
                    let _ = pipe.take(MOST_ANSWER).read_to_end(&mut said);
                }
                said
            };
            let out = read(stdout.as_mut().map(|pipe| pipe as &mut dyn Read));
            let err = read(stderr.as_mut().map(|pipe| pipe as &mut dyn Read));
            let _ = tell.send((out, err, child.wait()));
        });
        let (out, err, status) = hear
            .recv_timeout(GIVE_UP)
            .map_err(|_| format!("gh api {path} did not answer in time"))?;
        if !status.is_ok_and(|status| status.success()) {
            let why = String::from_utf8_lossy(&err);
            let why: String = why
                .lines()
                .next()
                .unwrap_or("failed")
                .chars()
                .take(300)
                .collect();
            return Err(format!("gh api {path}: {why}"));
        }
        if out.iter().all(u8::is_ascii_whitespace) {
            return Ok(Value::Null);
        }
        serde_json::from_slice(&out)
            .map_err(|err| format!("gh api {path} answered something else: {err}"))
    }

    fn repo(&self, rest: &str) -> String {
        format!("repos/{{owner}}/{{repo}}/{rest}")
    }
}

/// Each comment of `wanted` matched to the one GitHub kept for it, by file
/// and line: the ids in `wanted`'s order.
pub fn ids_of(wanted: &[Inline], kept: &[Value]) -> Result<Vec<u64>, String> {
    let mut taken = vec![false; kept.len()];
    wanted
        .iter()
        .map(|one| {
            let at = kept.iter().enumerate().position(|(at, had)| {
                let line = had["line"]
                    .as_u64()
                    .or_else(|| had["original_line"].as_u64());
                !taken[at] && had["path"] == one.file.as_str() && line == Some(one.line)
            });
            let at = at.ok_or_else(|| {
                format!(
                    "GitHub did not keep the comment on {}:{}",
                    one.file, one.line
                )
            })?;
            taken[at] = true;
            kept[at]["id"]
                .as_u64()
                .ok_or_else(|| "GitHub answered a comment without an id".to_owned())
        })
        .collect()
}

impl Host for Gh {
    fn review(
        &self,
        commit: &str,
        event: Event,
        body: &str,
        comments: &[Inline],
    ) -> Result<Vec<u64>, String> {
        let asked = json!({
            "commit_id": commit,
            "event": event.api(),
            "body": body,
            "comments": comments.iter().map(|one| json!({
                "path": one.file, "line": one.line, "side": "RIGHT", "body": one.body,
            })).collect::<Vec<_>>(),
        });
        let review = self.api(
            "POST",
            &self.repo(&format!("pulls/{}/reviews", self.pr)),
            Some(&asked),
        )?;
        if comments.is_empty() {
            return Ok(Vec::new());
        }
        let id = review["id"]
            .as_u64()
            .ok_or("GitHub answered a review without an id")?;
        let kept = self.api(
            "GET",
            &self.repo(&format!(
                "pulls/{}/reviews/{id}/comments?per_page=100",
                self.pr
            )),
            None,
        )?;
        ids_of(comments, kept.as_array().map_or(&[][..], Vec::as_slice))
    }

    fn edit_inline(&self, id: u64, body: &str) -> Result<(), String> {
        let path = self.repo(&format!("pulls/comments/{id}"));
        self.api("PATCH", &path, Some(&json!({ "body": body })))
            .map(|_| ())
    }

    fn comment(&self, body: &str) -> Result<u64, String> {
        let path = self.repo(&format!("issues/{}/comments", self.pr));
        self.api("POST", &path, Some(&json!({ "body": body })))?["id"]
            .as_u64()
            .ok_or_else(|| "GitHub answered a comment without an id".to_owned())
    }

    fn edit_comment(&self, id: u64, body: &str) -> Result<(), String> {
        let path = self.repo(&format!("issues/comments/{id}"));
        self.api("PATCH", &path, Some(&json!({ "body": body })))
            .map(|_| ())
    }
}
