//! `review.scale`: a review sized to its change. A small diff that touches no
//! sensitive path is read once, every axis in one reading, by `devflow-all`;
//! anything else gets the configured reviewers. Off unless devflow.yaml asks:
//! the security persona alone has brought a real PR's only blocking findings.

use serde::Serialize;

use crate::config::{Review, Reviewer};

/// The persona that covers spec, standards and security in one reading.
pub const ALL_AXES: &str = "devflow-all";

/// At most this many changed lines is a small diff, unless the file says.
pub const SMALL_LINES: u32 = 80;

/// The paths a change to which always gets every reviewer: auth, routes,
/// migrations, dependency manifests and lockfiles, secrets, CI. A pattern
/// without `/` is matched against each part of the path.
pub const SENSITIVE: &[&str] = &[
    "*auth*",
    "*login*",
    "*password*",
    "*permission*",
    "*crypto*",
    "*secret*",
    "*credential*",
    "*route*",
    "urls.py",
    "*middleware*",
    "*migration*",
    "*migrate*",
    "*.sql",
    "Cargo.toml",
    "*.lock",
    "package.json",
    "package-lock.json",
    "pnpm-lock.yaml",
    "go.mod",
    "go.sum",
    "requirements*.txt",
    "pyproject.toml",
    "Pipfile",
    "Gemfile",
    "composer.json",
    "pom.xml",
    "build.gradle*",
    ".env*",
    "*.pem",
    "*.key",
    ".github/workflows/**",
    ".gitlab-ci.yml",
    ".circleci/**",
    "Jenkinsfile",
    ".devpit/devflow/**",
];

/// `review.scale` as devflow.yaml sets it.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Scale {
    pub small_lines: u32,
    /// Globs; the built-in [`SENSITIVE`] when the file names none.
    pub sensitive: Vec<String>,
}

impl Default for Scale {
    fn default() -> Self {
        Scale {
            small_lines: SMALL_LINES,
            sensitive: SENSITIVE.iter().map(|one| (*one).to_owned()).collect(),
        }
    }
}

/// Which way a scaled review went, and why, as the reply says it.
#[derive(Debug, Clone, PartialEq)]
pub struct Sized {
    /// One `devflow-all` reviewer instead of `review.reviewers`.
    pub one: bool,
    pub why: String,
}

/// Whether this change is read by one reviewer or by the configured ones.
pub fn sized(scale: &Scale, files: &[String], diff: &str) -> Sized {
    let all = "→ the configured reviewers";
    if let Some((file, pattern)) = files.iter().find_map(|file| {
        scale
            .sensitive
            .iter()
            .find(|pattern| matches(pattern, file))
            .map(|pattern| (file, pattern))
    }) {
        return Sized {
            one: false,
            why: format!("not scaled: {file} is a sensitive path ({pattern}) {all}"),
        };
    }
    let Some(lines) = changed_lines(diff) else {
        return Sized {
            one: false,
            why: format!("not scaled: a binary or submodule change no line count measures {all}"),
        };
    };
    if lines > u64::from(scale.small_lines) {
        return Sized {
            one: false,
            why: format!(
                "not scaled: {lines} changed lines, past {} {all}",
                scale.small_lines
            ),
        };
    }
    Sized {
        one: true,
        why: format!(
            "scaled: small diff ({lines} changed lines), no sensitive path → one reviewer ({ALL_AXES})"
        ),
    }
}

/// Who runs: the first configured reviewer's CLI and model on `devflow-all`
/// when scaled, else `review.reviewers` as they are.
pub fn reviewers(review: &Review, one: bool) -> Vec<Reviewer> {
    if !one {
        return review.reviewers.clone();
    }
    review
        .reviewers
        .first()
        .map(|first| Reviewer {
            agent: first.agent,
            persona: ALL_AXES.to_owned(),
            model: first.model.clone(),
        })
        .into_iter()
        .collect()
}

/// The lines a unified diff adds and removes, counted through each hunk so
/// a removed `-- comment` is not taken for a header. `None` when part of it
/// is binary or a submodule, which no count of lines measures.
pub fn changed_lines(diff: &str) -> Option<u64> {
    let (mut changed, mut old, mut new) = (0u64, 0u64, 0u64);
    for line in diff.lines() {
        if old > 0 || new > 0 {
            match line.chars().next() {
                Some('+') => {
                    (changed, new) = (changed + 1, new.saturating_sub(1));
                    continue;
                }
                Some('-') => {
                    (changed, old) = (changed + 1, old.saturating_sub(1));
                    continue;
                }
                Some(' ') | None => {
                    (old, new) = (old.saturating_sub(1), new.saturating_sub(1));
                    continue;
                }
                Some('\\') => continue,
                _ => (old, new) = (0, 0),
            }
        }
        if line.starts_with("Binary files ")
            || line.starts_with("GIT binary patch")
            || line.starts_with("Submodule ")
        {
            return None;
        }
        if let Some((_, from, to)) = crate::findings::new_side(line) {
            (old, new) = (from, to);
        }
    }
    Some(changed)
}

/// A glob over a repo-relative path, ignoring case: `*` and `?` stay within
/// a part, `**` spans parts, and a pattern without `/` matches any one part.
pub fn matches(pattern: &str, path: &str) -> bool {
    let pattern = pattern.to_ascii_lowercase();
    let path = path.to_ascii_lowercase();
    let parts: Vec<&str> = path.split('/').collect();
    if !pattern.contains('/') {
        return parts.iter().any(|part| part_matches(&pattern, part));
    }
    let globs: Vec<&str> = pattern.split('/').collect();
    parts_match(&globs, &parts)
}

fn parts_match(globs: &[&str], parts: &[&str]) -> bool {
    match globs.split_first() {
        None => parts.is_empty(),
        Some((&"**", rest)) => (0..=parts.len()).any(|skip| parts_match(rest, &parts[skip..])),
        Some((glob, rest)) => parts
            .split_first()
            .is_some_and(|(part, after)| part_matches(glob, part) && parts_match(rest, after)),
    }
}

fn part_matches(glob: &str, part: &str) -> bool {
    let glob: Vec<char> = glob.chars().collect();
    let part: Vec<char> = part.chars().collect();
    // Where the last `*` was, and the part's position it was tried at.
    let (mut g, mut p, mut star) = (0, 0, None);
    while p < part.len() {
        if g < glob.len() && (glob[g] == '?' || glob[g] == part[p]) {
            (g, p) = (g + 1, p + 1);
        } else if g < glob.len() && glob[g] == '*' {
            star = Some((g, p));
            g += 1;
        } else if let Some((at, from)) = star {
            (g, p) = (at + 1, from + 1);
            star = Some((at, from + 1));
        } else {
            return false;
        }
    }
    glob[g..].iter().all(|ch| *ch == '*')
}

#[cfg(test)]
#[path = "scale_tests.rs"]
mod tests;
