//! The binary keeping itself current. Each `devflow mcp` start asks GitHub,
//! on a thread of its own, which release is the latest; a newer one is
//! downloaded, checked against the release's `checksums.txt`, run once and
//! renamed over this binary, the old one kept beside it as `.prev`. The
//! running server keeps its image; the next start runs the new one. The
//! Claude Code plugin is then brought to the same version.
//!
//! `DEVFLOW_NO_UPDATE=1` switches it off. A build from a checkout never
//! replaces itself: only the release workflow's builds carry the mark.

use std::fs::{self, OpenOptions};
use std::io::{ErrorKind, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};
use std::time::{Duration, Instant, SystemTime};

use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::register::{Machine, NAME, REPO};

/// Set to `1`, nothing is checked or replaced.
pub const OFF: &str = "DEVFLOW_NO_UPDATE";

/// Whether the release workflow built this binary: `DEVFLOW_RELEASE=1` at
/// build time, which only it sets.
pub fn released() -> bool {
    option_env!("DEVFLOW_RELEASE") == Some("1")
}

const PLUGIN: &str = "devflow@devflow";
const MOST_ARCHIVE: u64 = 64 << 20;
const MOST_BINARY: u64 = 128 << 20;
const MOST_CHECKSUMS: u64 = 1 << 20;
const MOST_ENTRIES: usize = 64;
const WAIT_LOOKUP: Duration = Duration::from_secs(10);
const WAIT_DOWNLOAD: Duration = Duration::from_secs(120);
const WAIT_RUN: Duration = Duration::from_secs(10);
/// A lock or a staged file older than this was left by a start that died.
const STALE: Duration = Duration::from_secs(600);
const STAGED: &str = ".devflow-new-";
/// In devflow's state folder: the lock one update holds, and the version the
/// Claude Code plugin was last checked at.
pub const LOCK: &str = "update.lock";
const PLUGIN_CHECKED: &str = "plugin-checked";

/// Where releases are published: GitHub, or a local server in the tests.
pub struct Source {
    pub base: String,
}

impl Source {
    pub fn github() -> Source {
        Source {
            base: format!("https://github.com/{REPO}"),
        }
    }

    fn agent(&self, redirects: u32, wait: Duration) -> ureq::Agent {
        ureq::Agent::config_builder()
            .timeout_global(Some(wait))
            .http_status_as_error(false)
            // A release asked for over https is never followed to plain http.
            .https_only(self.base.starts_with("https://"))
            .max_redirects(redirects)
            .user_agent(concat!("devflow/", env!("CARGO_PKG_VERSION")))
            .build()
            .into()
    }

    /// The latest release's version, read off the redirect `releases/latest`
    /// answers with: no API, no rate limit.
    pub fn latest(&self) -> Result<String, String> {
        let url = format!("{}/releases/latest", self.base);
        let reply = self
            .agent(0, WAIT_LOOKUP)
            .get(&url)
            .call()
            .map_err(|err| format!("{url}: {err}"))?;
        let to = reply
            .headers()
            .get("location")
            .and_then(|to| to.to_str().ok())
            .filter(|_| reply.status().is_redirection())
            .ok_or_else(|| format!("{url} answered {} with no release", reply.status()))?;
        let tag = to
            .trim_end_matches('/')
            .rsplit('/')
            .next()
            .unwrap_or_default();
        version_of(tag).ok_or_else(|| format!("the latest release's tag is not a version: {tag}"))
    }

    fn fetch(&self, url: &str, most: u64) -> Result<Vec<u8>, String> {
        let mut reply = self
            .agent(10, WAIT_DOWNLOAD)
            .get(url)
            .call()
            .map_err(|err| format!("{url}: {err}"))?;
        if !reply.status().is_success() {
            return Err(format!("{url} answered {}", reply.status()));
        }
        reply
            .body_mut()
            .with_config()
            .limit(most)
            .read_to_vec()
            .map_err(|err| format!("{url}: {err}"))
    }
}

/// The binary that runs, and what decides whether it may be replaced.
pub struct Here {
    pub version: String,
    pub bin: PathBuf,
    pub released: bool,
    pub off: bool,
    pub os: &'static str,
    pub arch: &'static str,
}

impl Here {
    pub fn now() -> Result<Here, String> {
        let bin = std::env::current_exe()
            .and_then(|path| path.canonicalize())
            .map_err(|err| format!("where this binary is: {err}"))?;
        Ok(Here {
            version: env!("CARGO_PKG_VERSION").to_owned(),
            bin,
            released: released(),
            off: is_off(std::env::var(OFF).ok().as_deref()),
            os: std::env::consts::OS,
            arch: std::env::consts::ARCH,
        })
    }
}

/// Whether the switch's value turns updates off: `1`, `true`, `yes`, `on`.
pub fn is_off(value: Option<&str>) -> bool {
    value.is_some_and(|value| {
        ["1", "true", "yes", "on"].contains(&value.trim().to_ascii_lowercase().as_str())
    })
}

/// Why the binary is not replaced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refused {
    Off,
    Checkout,
    Unsupported,
    Unwritable(String),
    Current,
}

/// What a check found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Found {
    pub current: String,
    pub latest: Option<String>,
    pub bin: PathBuf,
    pub refused: Option<Refused>,
}

/// Whether the binary may and should be replaced. Every local refusal comes
/// before the network, so a build that is never replaced never asks. `asked`
/// is the person's own `devflow update`, which the switch does not hold.
pub fn check(source: &Source, here: &Here, asked: bool) -> Result<Found, String> {
    let mut found = Found {
        current: here.version.clone(),
        latest: None,
        bin: here.bin.clone(),
        refused: None,
    };
    found.refused = if here.off && !asked {
        Some(Refused::Off)
    } else if !here.released {
        Some(Refused::Checkout)
    } else if archive(&here.version, here.os, here.arch).is_none() {
        Some(Refused::Unsupported)
    } else {
        writable(&here.bin).err().map(Refused::Unwritable)
    };
    if found.refused.is_some() {
        return Ok(found);
    }
    let latest = source.latest()?;
    if !newer(&latest, &here.version) {
        found.refused = Some(Refused::Current);
    }
    found.latest = Some(latest);
    Ok(found)
}

/// Installs the release `found` names over `found.bin`: its archive checked
/// against `checksums.txt`, the binary in it run once and then renamed into
/// place. Nothing is replaced unless every step holds.
pub fn apply(source: &Source, found: &Found, here: &Here) -> Result<(), String> {
    let latest = found.latest.as_deref().ok_or("no release was found")?;
    let name = archive(latest, here.os, here.arch).ok_or("no release build for this machine")?;
    let base = format!("{}/releases/download/v{latest}", source.base);
    let sums = source.fetch(&format!("{base}/checksums.txt"), MOST_CHECKSUMS)?;
    let want = digest_in(&String::from_utf8_lossy(&sums), &name)
        .ok_or_else(|| format!("checksums.txt does not list {name}"))?;
    let bytes = source.fetch(&format!("{base}/{name}"), MOST_ARCHIVE)?;
    if hex(&Sha256::digest(&bytes)) != want {
        return Err(format!("{name} does not match its checksum"));
    }
    let binary = binary_in(&bytes, MOST_BINARY)?;
    let staged = staged(&found.bin, &binary)?;
    if let Err(why) = runs_as(&staged, latest) {
        let _ = fs::remove_file(&staged);
        return Err(why);
    }
    swap(&staged, &found.bin)
}

/// `vX.Y.Z[-pre]` or `X.Y.Z[-pre]` as `X.Y.Z[-pre]`, when it is one: the
/// version becomes a URL's path segment and a file's name.
pub fn version_of(tag: &str) -> Option<String> {
    let bare = tag.strip_prefix('v').unwrap_or(tag);
    let (core, pre) = match bare.split_once('-') {
        Some((core, pre)) => (core, Some(pre)),
        None => (bare, None),
    };
    let parts: Vec<&str> = core.split('.').collect();
    let numeric = parts.len() == 3
        && parts
            .iter()
            .all(|part| (1..=9).contains(&part.len()) && part.bytes().all(|b| b.is_ascii_digit()));
    let pre_ok = pre.is_none_or(|pre| {
        !pre.is_empty() && pre.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'.')
    });
    (numeric && pre_ok).then(|| bare.to_owned())
}

/// Whether `latest` is a later version than `current`; a release is later
/// than its own pre-releases.
pub fn newer(latest: &str, current: &str) -> bool {
    fn parts(version: &str) -> ([u64; 3], Option<&str>) {
        let (core, pre) = match version.split_once('-') {
            Some((core, pre)) => (core, Some(pre)),
            None => (version, None),
        };
        let mut numbers = [0; 3];
        for (at, part) in core.split('.').take(3).enumerate() {
            numbers[at] = part.parse().unwrap_or(0);
        }
        (numbers, pre)
    }
    let (a, a_pre) = parts(latest);
    let (b, b_pre) = parts(current);
    if a != b {
        return a > b;
    }
    match (a_pre, b_pre) {
        (None, Some(_)) => true,
        (Some(a), Some(b)) => a > b,
        _ => false,
    }
}

/// The release archive for this machine, as the release workflow names it.
pub fn archive(version: &str, os: &str, arch: &str) -> Option<String> {
    let os = match os {
        "linux" => "linux",
        "macos" => "darwin",
        _ => return None,
    };
    let arch = match arch {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        _ => return None,
    };
    Some(format!("devflow_{version}_{os}_{arch}.tar.gz"))
}

/// The sha256 `checksums.txt` lists for `name`, in sha256sum's format.
pub fn digest_in(checksums: &str, name: &str) -> Option<String> {
    checksums.lines().find_map(|line| {
        let mut fields = line.split_whitespace();
        let digest = fields.next()?;
        let file = fields.next()?.trim_start_matches('*');
        (file == name && digest.len() == 64 && digest.bytes().all(|b| b.is_ascii_hexdigit()))
            .then(|| digest.to_ascii_lowercase())
    })
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// The `devflow` file at the top of a release's tar.gz. Read only after the
/// archive matched its checksum; bounded all the same.
pub fn binary_in(archive: &[u8], most: u64) -> Result<Vec<u8>, String> {
    let mut tar = tar::Archive::new(flate2::read::GzDecoder::new(archive));
    let entries = tar
        .entries()
        .map_err(|err| format!("the archive does not read: {err}"))?;
    let mut budget = most;
    for (count, entry) in entries.enumerate() {
        if count >= MOST_ENTRIES {
            break;
        }
        let entry = entry.map_err(|err| format!("the archive does not read: {err}"))?;
        let size = entry.header().size().unwrap_or(u64::MAX);
        if size > budget {
            return Err("the archive holds more than a devflow binary".to_owned());
        }
        budget -= size;
        let path = entry
            .path()
            .map_err(|err| format!("the archive does not read: {err}"))?
            .into_owned();
        let top = path.file_name().is_some_and(|name| name == "devflow")
            && path
                .parent()
                .is_none_or(|parent| parent.as_os_str().is_empty() || parent == Path::new("."));
        if !(top && entry.header().entry_type().is_file()) {
            continue;
        }
        let mut binary = Vec::with_capacity(size as usize);
        entry
            .take(size)
            .read_to_end(&mut binary)
            .map_err(|err| format!("the archive does not read: {err}"))?;
        if binary.len() as u64 != size {
            return Err("the archive's devflow is cut short".to_owned());
        }
        return Ok(binary);
    }
    Err("the archive holds no devflow".to_owned())
}

/// Whether the binary's folder takes a new file: what the rename needs.
pub fn writable(bin: &Path) -> Result<(), String> {
    let dir = bin.parent().ok_or("the binary has no folder")?;
    let probe = dir.join(format!("{STAGED}probe-{}", std::process::id()));
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&probe)
        .map_err(|err| format!("{} is not writable: {err}", dir.display()))?;
    fs::remove_file(&probe).map_err(|err| format!("{}: {err}", probe.display()))
}

/// `binary` written beside `bin` under a name no other start holds,
/// runnable; staged files a dead start left are cleared first.
fn staged(bin: &Path, binary: &[u8]) -> Result<PathBuf, String> {
    let dir = bin.parent().ok_or("the binary has no folder")?;
    clear_stale(dir);
    let nanos = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |since| since.subsec_nanos());
    let path = dir.join(format!("{STAGED}{}-{nanos}", std::process::id()));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .map_err(|err| format!("{}: {err}", path.display()))?;
    let written = file
        .write_all(binary)
        .and_then(|()| file.sync_all())
        .and_then(|()| runnable(&path));
    drop(file);
    if let Err(err) = written {
        let _ = fs::remove_file(&path);
        return Err(format!("{}: {err}", path.display()));
    }
    Ok(path)
}

#[cfg(unix)]
fn runnable(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o755))
}

#[cfg(not(unix))]
fn runnable(_path: &Path) -> std::io::Result<()> {
    Ok(())
}

fn clear_stale(dir: &Path) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let ours = entry.file_name().to_string_lossy().starts_with(STAGED);
        let old = entry
            .metadata()
            .and_then(|meta| meta.modified())
            .ok()
            .and_then(|at| at.elapsed().ok())
            .is_some_and(|age| age > STALE);
        if ours && old {
            let _ = fs::remove_file(entry.path());
        }
    }
}

/// Whether the staged binary runs on this machine and says it is `version`.
pub fn runs_as(path: &Path, version: &str) -> Result<(), String> {
    let mut child = None;
    // A file just written can be "busy" for an instant while a fork holds it.
    for _ in 0..5 {
        match Command::new(path)
            .arg("--version")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
        {
            Ok(started) => {
                child = Some(started);
                break;
            }
            Err(err) if err.raw_os_error() == Some(26) => {
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(err) => return Err(format!("the new binary does not run here: {err}")),
        }
    }
    let mut child = child.ok_or("the new binary stayed busy")?;
    let started = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if started.elapsed() < WAIT_RUN => {
                std::thread::sleep(Duration::from_millis(20));
            }
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return Err("the new binary did not answer --version".to_owned());
            }
        }
    }
    let mut said = String::new();
    if let Some(mut out) = child.stdout.take() {
        let _ = out.by_ref().take(4096).read_to_string(&mut said);
    }
    let want = format!("devflow {version}");
    if said.trim() == want {
        Ok(())
    } else {
        Err(format!(
            "the new binary says `{}`, not `{want}`",
            said.trim()
        ))
    }
}

/// Where the replaced binary is kept, one rename from undoing an update.
pub fn prev_of(bin: &Path) -> PathBuf {
    let mut name = bin.as_os_str().to_owned();
    name.push(".prev");
    PathBuf::from(name)
}

/// `staged` put at `bin` by one rename, `bin` kept as `.prev` first: by a
/// hard link, else a copy, so `bin` is never missing, even when the process
/// is killed half way.
pub fn swap(staged: &Path, bin: &Path) -> Result<(), String> {
    let prev = prev_of(bin);
    let undo = |why: String| {
        let _ = fs::remove_file(staged);
        Err(why)
    };
    if let Err(err) = fs::remove_file(&prev) {
        if err.kind() != ErrorKind::NotFound {
            return undo(format!("{}: {err}", prev.display()));
        }
    }
    if bin.exists() && fs::hard_link(bin, &prev).is_err() {
        if let Err(err) = fs::copy(bin, &prev) {
            return undo(format!("{} could not be kept: {err}", prev.display()));
        }
    }
    if let Err(err) = fs::rename(staged, bin) {
        return undo(format!("{}: {err}", bin.display()));
    }
    Ok(())
}

/// Held while one start updates, so starts at the same moment do not all
/// download; dropped, it is removed. It holds its holder's pid.
#[derive(Debug)]
pub struct Lock(PathBuf);

/// Why a lock was not taken.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Untaken {
    /// Another update holds it.
    Busy,
    /// It could not be made, a full disk or a folder that cannot be written
    /// to: why.
    Failed(String),
}

impl Lock {
    pub fn take(path: &Path) -> Result<Lock, Untaken> {
        let failed = |err: std::io::Error| Untaken::Failed(format!("{}: {err}", path.display()));
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(failed)?;
        }
        for _ in 0..2 {
            match OpenOptions::new().write(true).create_new(true).open(path) {
                Ok(mut file) => {
                    use std::io::Write;
                    if let Err(err) = write!(file, "{}", std::process::id()) {
                        let _ = fs::remove_file(path);
                        return Err(failed(err));
                    }
                    return Ok(Lock(path.to_path_buf()));
                }
                Err(err) if err.kind() == ErrorKind::AlreadyExists => {
                    if !left_behind(path) {
                        return Err(Untaken::Busy);
                    }
                    let _ = fs::remove_file(path);
                }
                Err(err) => return Err(failed(err)),
            }
        }
        Err(Untaken::Busy)
    }
}

/// Whether a lock is one no update holds any more: its holder's process is
/// gone, it is older than [`STALE`], or it is dated in the future. One with
/// no pid (an older devflow's, or one just made) is judged by its age.
pub fn left_behind(path: &Path) -> bool {
    let Ok(at) = fs::metadata(path).and_then(|meta| meta.modified()) else {
        return true;
    };
    match at.elapsed() {
        Err(_) => true,
        Ok(age) if age > STALE => true,
        Ok(_) => fs::read_to_string(path)
            .ok()
            .and_then(|text| text.trim().parse::<u32>().ok())
            .is_some_and(|pid| !alive(pid)),
    }
}

/// Whether a process of this user runs as `pid`.
fn alive(pid: u32) -> bool {
    if pid <= 1 {
        return true;
    }
    if cfg!(target_os = "linux") {
        return Path::new(&format!("/proc/{pid}")).exists();
    }
    Command::new("kill")
        .args(["-0", &pid.to_string()])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

impl Drop for Lock {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

/// The person's own install of the Claude Code plugin, `devflow register`'s,
/// in a listing that has one entry per scope.
fn user_plugin(listing: &str) -> Option<Value> {
    let listed: Value = serde_json::from_str(listing).ok()?;
    listed
        .as_array()?
        .iter()
        .find(|one| one["id"] == PLUGIN && one["scope"].as_str().unwrap_or("user") == "user")
        .cloned()
}

/// Whether the person's own install of the Claude Code plugin is older than
/// `version`. A project's install is that project's to update.
pub fn plugin_behind(listing: &str, version: &str) -> bool {
    user_plugin(listing)
        .and_then(|plugin| {
            plugin["version"]
                .as_str()
                .map(|installed| newer(version, installed))
        })
        .unwrap_or(false)
}

/// The Claude Code plugin brought up to `version`: the marketplace read
/// again, then the plugin updated. Nothing when Claude Code or the plugin is
/// not installed, or it is already there.
pub fn refresh_plugin(machine: &Machine, version: &str) -> Option<Result<String, String>> {
    if !(machine.has)("claude") {
        return None;
    }
    let listing = (machine.ask)(&["claude", "plugin", "list", "--json"])?;
    if !plugin_behind(&listing, version) {
        return None;
    }
    if (machine.ask)(&["claude", "plugin", "marketplace", "update", NAME]).is_none() {
        return Some(Err(
            "the Claude Code plugin was not updated: its marketplace did not refresh".to_owned(),
        ));
    }
    if (machine.ask)(&["claude", "plugin", "update", PLUGIN, "--scope", "user"]).is_none() {
        return Some(Err("the Claude Code plugin did not update".to_owned()));
    }
    let now = (machine.ask)(&["claude", "plugin", "list", "--json"])
        .and_then(|listing| installed_plugin(&listing))
        .unwrap_or_else(|| "?".to_owned());
    Some(Ok(format!(
        "the Claude Code plugin is now {now}; restart Claude Code to load it"
    )))
}

fn installed_plugin(listing: &str) -> Option<String> {
    user_plugin(listing)?["version"].as_str().map(str::to_owned)
}

/// Starts the update on a thread of its own: the server answers at once,
/// whatever the network does.
pub fn on_load() {
    let _ = std::thread::Builder::new()
        .name("devflow-update".to_owned())
        .spawn(|| {
            let Ok(here) = Here::now() else {
                return;
            };
            let Some(state) = devflow_engine::home::state_dir() else {
                return;
            };
            for line in background(&Source::github(), &here, &Machine::here(), &state) {
                eprintln!("devflow: {line}");
            }
        });
}

/// One start's update, as the lines it leaves in the agent CLI's log. Says
/// nothing when updates are off, on a checkout's build, or when all is
/// current.
pub fn background(source: &Source, here: &Here, machine: &Machine, state: &Path) -> Vec<String> {
    if here.off || !here.released {
        return Vec::new();
    }
    let Ok(_held) = Lock::take(&state.join(LOCK)) else {
        return Vec::new();
    };
    let mut said = Vec::new();
    let found = match check(source, here, false) {
        Ok(found) => found,
        Err(why) => return vec![format!("could not check for an update: {why}")],
    };
    let version = match &found.refused {
        None => {
            let latest = found.latest.clone().unwrap_or_default();
            match apply(source, &found, here) {
                Ok(()) => {
                    said.push(updated(&found, &latest));
                    latest
                }
                Err(why) => {
                    said.push(format!("the update to {latest} was not installed: {why}"));
                    found.current.clone()
                }
            }
        }
        Some(Refused::Current | Refused::Unwritable(_)) => found.current.clone(),
        Some(_) => return said,
    };
    // The plugin is asked about once per version, not at every start.
    let stamp = state.join(PLUGIN_CHECKED);
    if fs::read_to_string(&stamp).ok().as_deref() == Some(version.as_str()) {
        return said;
    }
    match refresh_plugin(machine, &version) {
        Some(Err(line)) => said.push(line),
        done => {
            if let Some(Ok(line)) = done {
                said.push(line);
            }
            let _ = fs::write(&stamp, &version);
        }
    }
    said
}

fn updated(found: &Found, latest: &str) -> String {
    format!(
        "updated {} → {latest} at {} (the previous one kept as {}); the next start runs it",
        found.current,
        found.bin.display(),
        prev_of(&found.bin).display()
    )
}

/// What `devflow update` did, as a person reads it or as one JSON line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Done {
    Current(String),
    Out {
        from: String,
        to: String,
    },
    Updated {
        from: String,
        to: String,
        bin: PathBuf,
    },
}

/// `devflow update [--check] [--json]`: the person's own update, or a
/// host's, which `DEVFLOW_NO_UPDATE` does not hold and which never asks.
pub fn command(only_check: bool, json: bool) -> ExitCode {
    let state = devflow_engine::home::state_dir().unwrap_or_else(|| PathBuf::from(".devflow-home"));
    let held = Lock::take(&state.join(LOCK));
    let done = match held {
        Ok(_) => Here::now().and_then(|here| asked(&Source::github(), &here, only_check)),
        Err(Untaken::Busy) => Err("another devflow update is running".to_owned()),
        Err(Untaken::Failed(why)) => Err(format!("the update's lock could not be made: {why}")),
    };
    let plugin = match &done {
        Ok(Done::Current(version) | Done::Updated { to: version, .. }) if !only_check => {
            refresh_plugin(&Machine::here(), version)
        }
        _ => None,
    };
    if json {
        println!("{}", as_json(&done, plugin.as_ref()));
    } else {
        match &done {
            Ok(Done::Current(version)) => println!("devflow {version} is the latest release."),
            Ok(Done::Out { from, to }) => {
                println!("devflow {to} is out; this is {from}. `devflow update` installs it.")
            }
            Ok(Done::Updated { from, to, bin }) => println!(
                "Updated {from} → {to} at {}.\nRestart your agent CLIs so their devflow server \
                 runs it.",
                bin.display()
            ),
            Err(why) => eprintln!("devflow: {why}"),
        }
        match &plugin {
            Some(Ok(line)) => println!("{line}"),
            Some(Err(line)) => eprintln!("devflow: {line}"),
            None => {}
        }
    }
    if done.is_ok() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

/// The update a person or a host asked for.
pub fn asked(source: &Source, here: &Here, only_check: bool) -> Result<Done, String> {
    let found =
        check(source, here, true).map_err(|why| format!("could not check for an update: {why}"))?;
    match &found.refused {
        Some(Refused::Checkout) => Err(format!(
            "devflow {} was built from a checkout and never replaces itself: install.sh \
             installs a release",
            here.version
        )),
        Some(Refused::Unsupported) => {
            Err(format!("no release build for {}/{}", here.os, here.arch))
        }
        Some(Refused::Unwritable(why)) => Err(format!("cannot update: {why}")),
        Some(Refused::Off) => Err("updates are off".to_owned()),
        Some(Refused::Current) => Ok(Done::Current(here.version.clone())),
        None => {
            let to = found.latest.clone().unwrap_or_default();
            let from = here.version.clone();
            if only_check {
                return Ok(Done::Out { from, to });
            }
            apply(source, &found, here).map_err(|why| format!("{to} was not installed: {why}"))?;
            Ok(Done::Updated {
                from,
                to,
                bin: here.bin.clone(),
            })
        }
    }
}

/// The JSON line a host reads.
pub fn as_json(done: &Result<Done, String>, plugin: Option<&Result<String, String>>) -> Value {
    let mut said = match done {
        Ok(Done::Current(version)) => {
            serde_json::json!({ "updated": false, "from": version, "to": version })
        }
        Ok(Done::Out { from, to }) => {
            serde_json::json!({ "updated": false, "from": from, "to": to, "available": true })
        }
        Ok(Done::Updated { from, to, .. }) => {
            serde_json::json!({ "updated": true, "from": from, "to": to })
        }
        Err(why) => serde_json::json!({ "error": why }),
    };
    if let Some(plugin) = plugin {
        said["plugin"] = match plugin {
            Ok(line) => serde_json::json!({ "said": line }),
            Err(why) => serde_json::json!({ "error": why }),
        };
    }
    said
}

#[cfg(test)]
#[path = "update_tests.rs"]
mod tests;
