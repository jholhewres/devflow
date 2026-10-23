//! git, shelled out to: what devflow asks of a repository.

use std::path::PathBuf;

pub mod pinned;
mod repo;

pub use repo::*;

#[derive(Debug)]
pub enum GitError {
    Missing,
    NotARepository {
        path: PathBuf,
    },
    Failed {
        command: String,
        stderr: String,
    },
    Unreadable {
        command: String,
        detail: String,
    },
    /// Refused before git was asked, so the message names what is in the way.
    Refused(String),
}

impl std::fmt::Display for GitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GitError::Missing => write!(f, "git is not installed, or not on PATH"),
            GitError::NotARepository { path } => {
                write!(f, "{} is not a git repository", path.display())
            }
            GitError::Failed { command, stderr } => write!(f, "git {command} failed: {stderr}"),
            GitError::Unreadable { command, detail } => write!(
                f,
                "git {command} answered something this build cannot read: {detail}"
            ),
            GitError::Refused(why) => write!(f, "{why}"),
        }
    }
}

impl std::error::Error for GitError {}

/// A revision an agent named, as git is given it: never an option to git.
pub fn plain_revision(said: &str) -> bool {
    !said.is_empty()
        && said.len() <= 200
        && !said.starts_with('-')
        && !said.chars().any(|ch| ch.is_whitespace() || ch.is_control())
}

#[cfg(test)]
pub(crate) mod fixture {
    use std::path::Path;

    /// A real repository in a tempdir.
    pub fn repo(dir: &Path) {
        for args in [
            vec!["init", "--initial-branch=main", "-q"],
            vec!["config", "user.email", "test@example.invalid"],
            vec!["config", "user.name", "Test"],
            vec!["config", "commit.gpgsign", "false"],
        ] {
            let ok = crate::env::command("git")
                .arg("-C")
                .arg(dir)
                .args(&args)
                .output()
                .expect("run git")
                .status
                .success();
            assert!(ok, "git {args:?} failed");
        }
    }

    pub fn commit(dir: &Path, message: &str) {
        for args in [vec!["add", "-A"], vec!["commit", "-q", "-m", message]] {
            crate::env::command("git")
                .arg("-C")
                .arg(dir)
                .args(&args)
                .output()
                .expect("run git");
        }
    }
}
