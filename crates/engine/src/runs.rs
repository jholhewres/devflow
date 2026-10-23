//! Where a card's evidence is kept: a folder per run, `<card>/<time>/`,
//! under devpit's own folder for the project, never in the repository; and
//! the files attached to the card among the project's artifacts, linked
//! rather than copied where the disk allows. Only the newest [`KEPT`] runs
//! stay in either. An older devpit kept runs in the checkout's [`RUNS`]:
//! they are still read, and nothing new is written there.

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::config::Evidence;

/// Where an older devpit kept the runs, relative to the checkout's root.
pub const RUNS: &str = ".devpit/devflow/runs";

/// How many runs a card keeps, in devpit's folder and among its artifacts.
pub const KEPT: usize = 5;

/// Where a card's runs are attached among the project's artifacts.
pub fn attached_under(card: &str) -> String {
    format!("devflow/{card}")
}

/// Where a project's runs are: `home`, devpit's own folder for them, where
/// every run is written; and the checkout's [`RUNS`], still read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Runs {
    pub home: PathBuf,
    pub checkout: PathBuf,
}

impl Runs {
    /// A fresh folder for a run of `card`, never through a link out of
    /// devpit's folder.
    pub fn fresh(&self, card: &str, at: SystemTime) -> Result<PathBuf, String> {
        let parent = self.made(card, card)?;
        let base = stamp(at);
        for again in 0..100 {
            let name = match again {
                0 => base.clone(),
                again => format!("{base}-{again}"),
            };
            let path = crate::fsguard::resolve_new(&self.home, &format!("{card}/{name}"))
                .map_err(|err| format!("{}: {err}", parent.join(&name).display()))?;
            match std::fs::create_dir(&path) {
                Ok(()) => return Ok(path),
                Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(err) => return Err(format!("{}: {err}", path.display())),
            }
        }
        Err(format!(
            "{} already has a hundred runs from this second",
            parent.display()
        ))
    }

    /// Where `file` of a card's runs is written: inside run `run`, or beside
    /// the runs when there is none yet. A run an older devpit left in the
    /// checkout is written where it is; anything else goes to devpit's folder.
    pub fn file_in(&self, card: &str, run: Option<&str>, file: &str) -> Result<PathBuf, String> {
        let folder = inner(card, run)?;
        let older = format!("{RUNS}/{folder}");
        let has = |base: &Path, folder: &str| match run {
            Some(_) => crate::fsguard::resolve(base, folder).is_ok_and(|at| at.is_dir()),
            None => crate::fsguard::resolve(base, &format!("{folder}/{file}"))
                .is_ok_and(|at| at.is_file()),
        };
        if !has(&self.home, &folder) && has(&self.checkout, &older) {
            return crate::fsguard::resolve_new(&self.checkout, &format!("{older}/{file}"))
                .map_err(|err| format!("{older}/{file}: {err}"));
        }
        let at = self.made(card, &folder)?;
        crate::fsguard::resolve_new(&self.home, &format!("{folder}/{file}"))
            .map_err(|err| format!("{}: {err}", at.join(file).display()))
    }

    /// `file` of a card's run, or beside its runs, where it is: devpit's
    /// folder first, then the checkout's. Never through a link out of either.
    pub fn found(&self, card: &str, run: Option<&str>, file: &str) -> Option<PathBuf> {
        let relative = format!("{}/{file}", inner(card, run).ok()?);
        crate::fsguard::resolve(&self.home, &relative)
            .or_else(|_| crate::fsguard::resolve(&self.checkout, &format!("{RUNS}/{relative}")))
            .ok()
            .filter(|path| path.is_file())
    }

    /// The newest run of `card` that holds `file`, in either place: its name,
    /// and where the file is.
    pub fn newest_with(&self, card: &str, file: &str) -> Option<(String, PathBuf)> {
        if !plain_card(card) {
            return None;
        }
        let home = crate::fsguard::resolve(&self.home, card).ok();
        let older = crate::fsguard::resolve(&self.checkout, &format!("{RUNS}/{card}")).ok();
        let name = [home, older]
            .into_iter()
            .flatten()
            .filter_map(|folder| newest_with(&folder, file))
            .max_by(|a, b| order_of(a).cmp(&order_of(b)))?;
        let at = self.found(card, Some(&name), file)?;
        Some((name, at))
    }

    /// devpit's folder for `card`, and `relative` under it, made when missing.
    fn made(&self, card: &str, relative: &str) -> Result<PathBuf, String> {
        if !plain_card(card) {
            return Err(format!(
                "`{card}` is not a card id devflow makes a folder of"
            ));
        }
        std::fs::create_dir_all(&self.home)
            .map_err(|err| format!("{}: {err}", self.home.display()))?;
        crate::setup::folders(&self.home, relative)?;
        Ok(self.home.join(relative))
    }
}

/// `card`, or its run `run`, as a folder under the runs.
fn inner(card: &str, run: Option<&str>) -> Result<String, String> {
    if !plain_card(card) {
        return Err(format!(
            "`{card}` is not a card id devflow makes a folder of"
        ));
    }
    match run {
        Some(run) if order_of(run).is_some() => Ok(format!("{card}/{run}")),
        Some(run) => Err(format!("`{run}` is not a run of the card")),
        None => Ok(card.to_owned()),
    }
}

/// The most pictures, and the most videos, one check keeps.
const MOST_MEDIA: usize = 50;
/// How deep under a check's folder its pictures and videos are looked for.
const DEEPEST: usize = 8;
/// The most one file attached may weigh, and one run's files together.
const MOST_ATTACHED: u64 = 200 * 1024 * 1024;
const MOST_RUN_ATTACHED: u64 = 500 * 1024 * 1024;

const PICTURES: [&str; 3] = ["png", "jpg", "jpeg"];
const VIDEOS: [&str; 2] = ["webm", "mp4"];

/// A card id devpit can make a folder of.
pub fn plain_card(id: &str) -> bool {
    (1..=64).contains(&id.len())
        && id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_-".contains(&byte))
}

/// `at` as a run's name, `20261011T143005Z`: UTC, so names sort as times do.
pub fn stamp(at: SystemTime) -> String {
    let seconds = at
        .duration_since(UNIX_EPOCH)
        .map(|since| since.as_secs())
        .unwrap_or_default();
    let (year, month, day) = civil((seconds / 86_400) as i64);
    let time = seconds % 86_400;
    format!(
        "{year:04}{month:02}{day:02}T{:02}{:02}{:02}Z",
        time / 3600,
        time % 3600 / 60,
        time % 60
    )
}

/// The date `days` after 1970-01-01 (Howard Hinnant's `civil_from_days`).
fn civil(days: i64) -> (i64, u32, u32) {
    let shifted = days + 719_468;
    let era = shifted.div_euclid(146_097);
    let of_era = shifted.rem_euclid(146_097);
    let year_of_era = (of_era - of_era / 1460 + of_era / 36_524 - of_era / 146_096) / 365;
    let of_year = of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let shifted_month = (5 * of_year + 2) / 153;
    let day = (of_year - (153 * shifted_month + 2) / 5 + 1) as u32;
    let month = if shifted_month < 10 {
        shifted_month + 3
    } else {
        shifted_month - 9
    } as u32;
    (year_of_era + era * 400 + i64::from(month <= 2), month, day)
}

/// The second a run's name stands for, since the epoch: [`stamp`] undone.
pub fn seconds_of(name: &str) -> Option<u64> {
    let (stamp, _) = order_of(name)?;
    let number = |range: std::ops::Range<usize>| stamp[range].parse::<i64>().ok();
    let (year, month, day) = (number(0..4)?, number(4..6)?, number(6..8)?);
    // Hinnant's `days_from_civil`, the inverse of `civil`.
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let of_era = year - era * 400;
    let of_year = (153 * ((month + 9) % 12) + 2) / 5 + day - 1;
    let days = era * 146_097 + of_era * 365 + of_era / 4 - of_era / 100 + of_year - 719_468;
    let time = number(9..11)? * 3600 + number(11..13)? * 60 + number(13..15)?;
    u64::try_from(days * 86_400 + time).ok()
}

/// A run's place in time: its stamp, then the count a second run started in
/// the same second takes (`…Z-1`). `None` for a name no run has.
fn order_of(name: &str) -> Option<(&str, u32)> {
    let (stamp, again) = match name.split_once('-') {
        Some((stamp, again)) => (stamp, again.parse().ok()?),
        None => (name, 0),
    };
    let bytes = stamp.as_bytes();
    let digits = |range: std::ops::Range<usize>| bytes[range].iter().all(u8::is_ascii_digit);
    (bytes.len() == 16 && digits(0..8) && bytes[8] == b'T' && digits(9..15) && bytes[15] == b'Z')
        .then_some((stamp, again))
}

/// Removes every run in `folder` but the newest `keep`, answering what went.
/// Only folders named as runs are touched: a link, a file or `local/` stays.
pub fn prune(folder: &Path, keep: usize) -> Vec<String> {
    let Ok(entries) = std::fs::read_dir(folder) else {
        return Vec::new();
    };
    let mut runs: Vec<String> = entries
        .filter_map(Result::ok)
        .filter(|entry| entry.file_type().is_ok_and(|kind| kind.is_dir()))
        .filter_map(|entry| entry.file_name().into_string().ok())
        .filter(|name| order_of(name).is_some())
        .collect();
    runs.sort_by(|a, b| order_of(b).cmp(&order_of(a)));
    runs.into_iter()
        .skip(keep)
        .filter(|name| std::fs::remove_dir_all(folder.join(name)).is_ok())
        .collect()
}

/// The newest run in `folder` that holds `file`: the checks' runs and the
/// review's are folders of one kind, and each reader looks for its own.
pub fn newest_with(folder: &Path, file: &str) -> Option<String> {
    std::fs::read_dir(folder)
        .ok()?
        .filter_map(Result::ok)
        .filter(|entry| entry.file_type().is_ok_and(|kind| kind.is_dir()))
        .filter_map(|entry| entry.file_name().into_string().ok())
        .filter(|name| order_of(name).is_some() && folder.join(name).join(file).is_file())
        .max_by(|a, b| order_of(a).cmp(&order_of(b)))
}

/// The pictures and videos a check left, moved beside the run's other evidence.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Media {
    /// Relative to the run's folder: `screenshots/…` and `video/…`.
    pub screenshots: Vec<String>,
    pub video: Vec<String>,
}

/// Moves what the check's folder holds of each kind `kept` names into the
/// run's `screenshots/` and `video/`, each named after where it was found.
pub fn gather(run: &Path, check: &str, kept: &[Evidence]) -> Media {
    let mut media = Media::default();
    let mut found = walk(&run.join(check));
    found.sort();
    for relative in found {
        let Some(kind) = kind_of(&relative) else {
            continue;
        };
        let (folder, into) = match kind {
            Evidence::Screenshots => ("screenshots", &mut media.screenshots),
            Evidence::Video => ("video", &mut media.video),
        };
        if !kept.contains(&kind) || into.len() >= MOST_MEDIA {
            continue;
        }
        let name = format!("{folder}/{}", flat(&format!("{check}-{relative}")));
        if std::fs::create_dir_all(run.join(folder)).is_ok()
            && !run.join(&name).exists()
            && std::fs::rename(run.join(check).join(&relative), run.join(&name)).is_ok()
        {
            into.push(name);
        }
    }
    media
}

/// Entries one walk looks at, at most: a test run's output, not a disk.
const MOST_LOOKED: usize = 10_000;

/// The pictures and videos under `folder`, relative to it. Links are not
/// followed, and no more than [`MOST_LOOKED`] entries are looked at.
fn walk(folder: &Path) -> Vec<String> {
    let (mut found, mut looked) = (Vec::new(), 0);
    walk_counting(folder, "", 0, &mut found, &mut looked);
    found
}

fn walk_counting(
    folder: &Path,
    under: &str,
    depth: usize,
    into: &mut Vec<String>,
    looked: &mut usize,
) {
    if depth > DEEPEST {
        return;
    }
    let Ok(entries) = std::fs::read_dir(folder) else {
        return;
    };
    for entry in entries.filter_map(Result::ok) {
        *looked += 1;
        if *looked > MOST_LOOKED || into.len() >= 2 * MOST_MEDIA {
            return;
        }
        let (Ok(kind), Ok(name)) = (entry.file_type(), entry.file_name().into_string()) else {
            continue;
        };
        let relative = if under.is_empty() {
            name
        } else {
            format!("{under}/{name}")
        };
        if kind.is_dir() {
            walk_counting(&entry.path(), &relative, depth + 1, into, looked);
        } else if kind.is_file() && kind_of(&relative).is_some() {
            into.push(relative);
        }
    }
}

/// Which kind of evidence a file is, by its extension.
fn kind_of(path: &str) -> Option<Evidence> {
    let (_, extension) = path.rsplit_once('.')?;
    let extension = extension.to_ascii_lowercase();
    if PICTURES.contains(&extension.as_str()) {
        Some(Evidence::Screenshots)
    } else if VIDEOS.contains(&extension.as_str()) {
        Some(Evidence::Video)
    } else {
        None
    }
}

/// A path as one file name: letters, digits, `.`, `_` and `-`.
fn flat(path: &str) -> String {
    let mut name: String = path
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || "._-".contains(ch) {
                ch
            } else {
                '-'
            }
        })
        .collect();
    if name.len() > 120 {
        name = name.split_off(name.len() - 120);
    }
    name
}

/// What attaching a run did: the artifacts' names, and what was left out.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Attached {
    pub names: Vec<String>,
    pub left_out: Vec<String>,
}

/// Puts `files` of the run at `run` into `artifacts` under `under`, keeping
/// their paths. A file past the ceiling is left out and said so.
pub fn attach(run: &Path, files: &[String], artifacts: &Path, under: &str) -> Attached {
    let mut attached = Attached::default();
    let mut weight = 0;
    for file in files {
        let from = run.join(file);
        let size = std::fs::symlink_metadata(&from)
            .ok()
            .filter(|meta| meta.is_file())
            .map(|meta| meta.len());
        let Some(size) =
            size.filter(|size| *size <= MOST_ATTACHED && weight + size <= MOST_RUN_ATTACHED)
        else {
            attached.left_out.push(file.clone());
            continue;
        };
        let name = format!("{under}/{file}");
        let to = artifacts.join(&name);
        let copied = to
            .parent()
            .is_some_and(|parent| std::fs::create_dir_all(parent).is_ok())
            && linked(&from, &to);
        if copied {
            weight += size;
            attached.names.push(name);
        } else {
            attached.left_out.push(file.clone());
        }
    }
    attached
}

/// `to` made the same file as `from`: a hard link, so a run and its
/// attachment are one copy on disk, else a copy where links cannot go.
pub fn linked(from: &Path, to: &Path) -> bool {
    let _ = std::fs::remove_file(to);
    std::fs::hard_link(from, to).is_ok() || std::fs::copy(from, to).is_ok()
}

#[cfg(test)]
#[path = "runs_tests.rs"]
mod tests;
