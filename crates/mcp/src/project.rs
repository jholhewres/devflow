//! The project a call stands in: its root, its devflow.yaml read over its
//! layers, and where its runs, reviews and work items are kept.

use std::path::{Path, PathBuf};

use devflow_engine::folder::{self, Layout, State};
use devflow_engine::layers::{self, Home, Layered, Team};
use devflow_engine::runs::Runs;
use devflow_engine::work;

/// Where a project keeps the runs of its checks and reviews, under its own
/// devflow folder, which a setup's `.gitignore` keeps out of git.
pub const RUNS: &str = "runs";

#[derive(Debug, Clone)]
pub struct Project {
    pub root: PathBuf,
}

impl Project {
    /// The repository `cwd` is in, else `cwd` itself.
    pub fn at(cwd: &Path) -> Project {
        let here = cwd.canonicalize().unwrap_or_else(|_| cwd.to_path_buf());
        let root = devflow_engine::git::toplevel(&here)
            .ok()
            .map(PathBuf::from)
            .and_then(|top| top.canonicalize().ok())
            .unwrap_or(here);
        Project { root }
    }

    pub fn layout(&self) -> Layout {
        Layout::of(&self.root)
    }

    /// The project's devflow.yaml read over its layers — the person's own and
    /// the teams it extends at their approved commits.
    pub fn read(&self) -> State {
        match folder::read(&self.root) {
            State::Valid(text, _) => match layers::layered(&self.root, &text, &home()) {
                Ok(layered) => State::Valid(text, Box::new(layered.config)),
                Err(invalid) => State::Invalid(Some(text), invalid),
            },
            other => other,
        }
    }

    /// The layers as they stand, when the project's file reads.
    pub fn layered(&self) -> Option<Layered> {
        match folder::read(&self.root) {
            State::Valid(text, _) => layers::layered(&self.root, &text, &home()).ok(),
            _ => None,
        }
    }

    /// The team layers that apply.
    pub fn teams(&self) -> Vec<Team> {
        self.layered()
            .map(|layered| layered.applied)
            .unwrap_or_default()
    }

    /// The project's folder, relative to its root.
    pub fn dir(&self) -> &'static str {
        folder::dir(&self.root)
    }

    /// Where a work item's runs are: `<dir>/runs/`, and devpit's older
    /// folder in the checkout, still read.
    pub fn runs(&self) -> Runs {
        Runs {
            home: self.root.join(self.dir()).join(RUNS),
            checkout: self.root.clone(),
        }
    }

    /// What devflow keeps of this project outside it, so a review on demand
    /// leaves nothing in a repository that has no devflow folder:
    /// `$XDG_CACHE_HOME/devflow/projects/<name>-<hash>/`.
    pub fn cache(&self) -> PathBuf {
        use sha2::{Digest, Sha256};
        let digest = Sha256::digest(self.root.to_string_lossy().as_bytes());
        let hash: String = digest
            .iter()
            .take(6)
            .map(|byte| format!("{byte:02x}"))
            .collect();
        devflow_engine::home::cache_dir()
            .unwrap_or_else(|| self.root.join(self.dir()).join(RUNS))
            .join("projects")
            .join(format!("{}-{hash}", self.name()))
    }

    /// Where reviews without a work item are kept.
    pub fn reviews(&self, checkout: &Path) -> Runs {
        Runs {
            home: self.cache().join("reviews"),
            checkout: checkout.to_path_buf(),
        }
    }

    /// Where a review reads a pull request or a range, detached.
    pub fn review_trees(&self) -> PathBuf {
        self.cache().join("trees")
    }

    /// The checks' `exclusive` locks.
    pub fn locks(&self) -> PathBuf {
        self.root.join(self.dir()).join(RUNS).join("locks")
    }

    pub fn items(&self) -> work::Files {
        work::Files::of(&self.root)
    }

    /// The project's name, as a check's environment carries it.
    pub fn name(&self) -> String {
        self.root
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default()
    }
}

/// The person's layers: their own and the teams' cache, under XDG.
pub fn home() -> Home {
    Home::of_user().unwrap_or_else(|| Home {
        personal: PathBuf::from(".devflow-home"),
        teams: PathBuf::from(".devflow-home/teams"),
    })
}

/// The person's own skills.
pub fn personal_skills() -> PathBuf {
    devflow_engine::home::config_dir()
        .map(|config| devflow_engine::home::skills(&config))
        .unwrap_or_default()
}

/// The person's own reviewer personas.
pub fn personal_reviewers() -> Option<PathBuf> {
    devflow_engine::home::config_dir().map(|config| devflow_engine::home::reviewers(&config))
}

/// Where Claude Code keeps the skills already installed for it.
pub fn installed_skills_folder() -> Option<PathBuf> {
    let config = std::env::var_os("CLAUDE_CONFIG_DIR")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".claude")))?;
    Some(config.join("skills"))
}

#[cfg(test)]
#[path = "project_tests.rs"]
mod tests;
