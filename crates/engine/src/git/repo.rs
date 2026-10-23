//! What review, gate and evidence ask of the project's repository.

use std::path::Path;

use super::GitError;

/// git in `root`, strict: a non-zero exit is an error. `core.quotepath=false`
/// so a path with bytes past 0x7f comes back as written.
pub(crate) fn run(root: &Path, args: &[&str]) -> Result<String, GitError> {
    let output = crate::env::command("git")
        .arg("-c")
        .arg("core.quotepath=false")
        .arg("-C")
        .arg(root)
        .args(args)
        .output()
        .map_err(|err| match err.kind() {
            std::io::ErrorKind::NotFound => GitError::Missing,
            _ => GitError::Failed {
                command: args.join(" "),
                stderr: err.to_string(),
            },
        })?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
        if stderr.contains("not a git repository") {
            return Err(GitError::NotARepository {
                path: root.to_path_buf(),
            });
        }
        return Err(GitError::Failed {
            command: args.join(" "),
            stderr,
        });
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// git over the network, which never asks for a credential: with nobody at a
/// terminal a prompt hangs.
fn talk(root: &Path, args: &[&str]) -> Result<(), GitError> {
    let output = crate::env::command("git")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_ASKPASS", "")
        .env("GIT_SSH_COMMAND", "ssh -o BatchMode=yes")
        .arg("-C")
        .arg(root)
        .args(args)
        .output()
        .map_err(|err| match err.kind() {
            std::io::ErrorKind::NotFound => GitError::Missing,
            _ => GitError::Failed {
                command: args.join(" "),
                stderr: err.to_string(),
            },
        })?;
    if !output.status.success() {
        return Err(GitError::Failed {
            command: args.join(" "),
            stderr: String::from_utf8_lossy(&output.stderr).trim().to_owned(),
        });
    }
    Ok(())
}

fn names(raw: &str) -> Vec<String> {
    raw.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

/// The repository's top folder, for a folder inside it.
pub fn toplevel(at: &Path) -> Result<String, GitError> {
    Ok(run(at, &["rev-parse", "--show-toplevel"])?
        .trim()
        .to_owned())
}

/// The commit `HEAD` is.
pub fn head_of(root: &Path) -> Result<String, GitError> {
    Ok(run(root, &["rev-parse", "HEAD"])?.trim().to_owned())
}

/// The branch a checkout is on, empty when `HEAD` is detached.
pub fn branch_at(root: &Path) -> Result<String, GitError> {
    Ok(run(root, &["branch", "--show-current"])?.trim().to_owned())
}

/// Every local branch's name.
pub fn branches(root: &Path) -> Result<Vec<String>, GitError> {
    Ok(names(&run(
        root,
        &["for-each-ref", "--format=%(refname:short)", "refs/heads/"],
    )?))
}

/// The subjects of the newest `limit` commits: nothing in a repository with
/// no commit yet.
pub fn subjects(root: &Path, limit: u32) -> Vec<String> {
    run(root, &["log", &format!("-n{limit}"), "--format=%s"])
        .map(|raw| names(&raw))
        .unwrap_or_default()
}

/// Where a review's diff starts: the merge base of `HEAD` and `base`, or of
/// `HEAD` and the default branch — origin's, else `main`, else `master`.
pub fn review_base(root: &Path, base: Option<&str>) -> Result<String, GitError> {
    let tried: Vec<String> = match base {
        Some(base) if !super::plain_revision(base) => {
            return Err(GitError::Refused(format!(
                "`{base}` is not a branch or a commit"
            )))
        }
        Some(base) => vec![base.to_owned()],
        None => run(
            root,
            &["symbolic-ref", "--short", "refs/remotes/origin/HEAD"],
        )
        .ok()
        .map(|said| said.trim().to_owned())
        .into_iter()
        .chain(["main".to_owned(), "master".to_owned()])
        .collect(),
    };
    tried
        .iter()
        .find_map(|one| run(root, &["merge-base", "HEAD", one]).ok())
        .map(|sha| sha.trim().to_owned())
        .ok_or_else(|| {
            GitError::Refused(format!(
                "no common commit between HEAD and {}: pass the base branch as `base`",
                tried.join(" or ")
            ))
        })
}

/// The files changed against `base_ref`, work not committed yet included.
pub fn changed_since(root: &Path, base_ref: &str) -> Result<Vec<String>, GitError> {
    if !super::plain_revision(base_ref) {
        return Err(GitError::Refused(format!("`{base_ref}` is not a commit")));
    }
    Ok(names(&run(root, &["diff", "--name-only", base_ref])?))
}

/// The paths `git status` names: changed, staged or untracked.
pub fn dirty(root: &Path) -> Result<Vec<String>, GitError> {
    let raw = run(
        root,
        &["status", "--porcelain=v1", "-z", "--untracked-files=all"],
    )?;
    let mut paths = Vec::new();
    let mut records = raw.split('\0').filter(|record| !record.is_empty());
    while let Some(record) = records.next() {
        let Some(path) = record.get(3..) else {
            continue;
        };
        paths.push(path.to_owned());
        // A rename's original path is its own record.
        if record.starts_with('R') || record.starts_with('C') {
            records.next();
        }
    }
    Ok(paths)
}

/// Every file a commit since `since` (seconds since the epoch) touched.
pub fn touched_since(root: &Path, since: u64) -> Vec<String> {
    let after = format!("--since=@{since}");
    let Ok(raw) = run(root, &["log", &after, "--name-only", "--format=", "-z"]) else {
        return Vec::new();
    };
    let mut touched: Vec<String> = raw
        .split(['\0', '\n'])
        .map(str::trim)
        .filter(|path| !path.is_empty())
        .map(str::to_owned)
        .collect();
    touched.sort();
    touched.dedup();
    touched
}

/// The files and the diff a review of `base..head` reads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reviewed {
    pub files: Vec<String>,
    pub diff: String,
    /// The commits in `base..head`.
    pub commits: u32,
}

/// The heading the work not yet committed is put under, after the commits.
pub const UNCOMMITTED: &str = "# Not committed yet: the working tree against HEAD";

/// The commits `base..head`, a submodule's as its log, and then what the
/// tracked files hold that `HEAD` does not.
pub fn review_diff(root: &Path, base: &str, head: &str) -> Result<Reviewed, GitError> {
    for revision in [base, head] {
        if !super::plain_revision(revision) {
            return Err(GitError::Refused(format!("`{revision}` is not a commit")));
        }
    }
    let range = format!("{base}..{head}");
    let mut files = names(&run(root, &["diff", "--name-only", &range])?);
    let mut diff = run(root, &["diff", "--submodule=log", &range])?;
    let loose = run(root, &["diff", "--submodule=log", "HEAD"])?;
    if !loose.trim().is_empty() {
        for name in names(&run(root, &["diff", "--name-only", "HEAD"])?) {
            if !files.contains(&name) {
                files.push(name);
            }
        }
        diff.push_str(&format!("\n{UNCOMMITTED}\n\n{loose}"));
    }
    let commits = run(root, &["rev-list", "--count", &range])?
        .trim()
        .parse()
        .unwrap_or(0);
    Ok(Reviewed {
        files,
        diff,
        commits,
    })
}

/// Whether code changed from `from` to `to`, leaving devflow's folders aside:
/// what devflow writes about a work item is not its code.
pub fn code_changed_between(root: &Path, from: &str, to: &str) -> Result<bool, GitError> {
    for revision in [from, to] {
        if !super::plain_revision(revision) {
            return Err(GitError::Refused(format!("`{revision}` is not a commit")));
        }
    }
    let raw = run(
        root,
        &[
            "diff",
            "--name-only",
            from,
            to,
            "--",
            ".",
            ":(exclude).devflow",
            ":(exclude).devpit",
        ],
    )?;
    Ok(!names(&raw).is_empty())
}

/// How many lines `path` has at `commit`: `None` when the commit has no such
/// file. Refused past `most` bytes before it is read.
pub fn lines_at(
    root: &Path,
    commit: &str,
    path: &str,
    most: u64,
) -> Result<Option<usize>, GitError> {
    if !super::plain_revision(commit)
        || path.starts_with('/')
        || path.split('/').any(|part| part == "..")
    {
        return Err(GitError::Refused(format!(
            "`{commit}:{path}` is not a file of a commit"
        )));
    }
    let object = format!("{commit}:{path}");
    if run(root, &["cat-file", "-e", &object]).is_err() {
        return Ok(None);
    }
    let size: u64 = run(root, &["cat-file", "-s", &object])?
        .trim()
        .parse()
        .unwrap_or(u64::MAX);
    if size > most {
        return Err(GitError::Refused(format!(
            "{path} is larger than {} KB",
            most / 1024
        )));
    }
    let text = run(root, &["cat-file", "blob", &object])?;
    Ok(Some(text.lines().count()))
}

/// A full commit id.
fn full_commit(said: &str) -> bool {
    matches!(said.len(), 40 | 64) && said.bytes().all(|byte| byte.is_ascii_hexdigit())
}

/// The commit `revision` names here, refused when it names none.
pub fn commit_of(root: &Path, revision: &str) -> Result<String, GitError> {
    if !super::plain_revision(revision) {
        return Err(GitError::Refused(format!(
            "`{revision}` is not a branch or a commit"
        )));
    }
    let asked = format!("{revision}^{{commit}}");
    run(root, &["rev-parse", "--verify", "--quiet", &asked])
        .map(|sha| sha.trim().to_owned())
        .map_err(|_| GitError::Refused(format!("`{revision}` names no commit here")))
}

/// Where `a` and `b` meet.
pub fn merge_base(root: &Path, a: &str, b: &str) -> Result<String, GitError> {
    let (a, b) = (commit_of(root, a)?, commit_of(root, b)?);
    Ok(run(root, &["merge-base", &a, &b])?.trim().to_owned())
}

/// Pull request `number`'s head from `origin`, into the object store and
/// `FETCH_HEAD` only: no checkout moves.
pub fn fetch_pull(root: &Path, number: u64) -> Result<(), GitError> {
    let reference = format!("refs/pull/{number}/head");
    talk(root, &["fetch", "-q", "--no-tags", "origin", &reference])
}

/// `commit` checked out, detached, in a new worktree at `at`: never the
/// person's checkout, never a branch anyone is on.
pub fn add_detached(root: &Path, at: &Path, commit: &str) -> Result<(), GitError> {
    if !full_commit(commit) {
        return Err(GitError::Refused(format!("`{commit}` is not a commit id")));
    }
    if at.exists() {
        return Err(GitError::Refused(format!(
            "{} is not a new folder",
            at.display()
        )));
    }
    if let Some(parent) = at.parent() {
        std::fs::create_dir_all(parent).map_err(|err| GitError::Refused(err.to_string()))?;
    }
    let target = at.to_string_lossy();
    run(
        root,
        &["worktree", "add", "-q", "--detach", &target, commit],
    )
    .map(|_| ())
}

/// The worktree [`add_detached`] made, gone, and git's record of it with it.
pub fn remove_detached(root: &Path, at: &Path) {
    let target = at.to_string_lossy();
    if run(root, &["worktree", "remove", "--force", &target]).is_err() {
        let _ = std::fs::remove_dir_all(at);
        let _ = run(root, &["worktree", "prune"]);
    }
}

/// The worktrees of the repository, by path.
pub fn worktrees(root: &Path) -> Result<Vec<String>, GitError> {
    Ok(run(root, &["worktree", "list", "--porcelain"])?
        .lines()
        .filter_map(|line| line.strip_prefix("worktree "))
        .map(str::to_owned)
        .collect())
}

#[cfg(test)]
#[path = "repo_tests.rs"]
mod tests;
