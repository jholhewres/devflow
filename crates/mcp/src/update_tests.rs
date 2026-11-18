use std::cell::RefCell;
use std::collections::HashMap;
use std::io::{BufRead, BufReader};
use std::net::TcpListener;
use std::rc::Rc;

use super::*;

/// A release server on localhost: each path answers with a status, a
/// `location` when it redirects, and a body.
fn serve(routes: Vec<(String, u16, Option<String>, Vec<u8>)>) -> Source {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let routes: HashMap<String, (u16, Option<String>, Vec<u8>)> = routes
        .into_iter()
        .map(|(path, status, to, body)| (path, (status, to, body)))
        .collect();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut first = String::new();
            let _ = reader.read_line(&mut first);
            loop {
                let mut header = String::new();
                if reader.read_line(&mut header).unwrap_or(0) == 0 || header.trim().is_empty() {
                    break;
                }
            }
            let path = first.split_whitespace().nth(1).unwrap_or_default();
            let (status, to, body) =
                routes
                    .get(path)
                    .cloned()
                    .unwrap_or((404, None, b"no".to_vec()));
            let mut head = format!(
                "HTTP/1.1 {status} X\r\ncontent-length: {}\r\nconnection: close\r\n",
                body.len()
            );
            if let Some(to) = to {
                head.push_str(&format!("location: {to}\r\n"));
            }
            head.push_str("\r\n");
            let _ = stream.write_all(head.as_bytes());
            let _ = stream.write_all(&body);
        }
    });
    Source { base }
}

fn tarball(files: &[(&str, &[u8])]) -> Vec<u8> {
    let encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    let mut builder = tar::Builder::new(encoder);
    for (name, body) in files {
        let mut header = tar::Header::new_gnu();
        header.set_size(body.len() as u64);
        header.set_mode(0o755);
        header.set_cksum();
        builder.append_data(&mut header, name, *body).unwrap();
    }
    builder.into_inner().unwrap().finish().unwrap()
}

fn script(says: &str) -> Vec<u8> {
    format!("#!/bin/sh\necho 'devflow {says}'\n").into_bytes()
}

/// A release of `version` on a local server, its archive built from `files`
/// and listed in checksums.txt with `digest` (the real one when `None`).
fn release(version: &str, files: &[(&str, &[u8])], digest: Option<&str>) -> Source {
    let name = archive(version, "linux", "x86_64").unwrap();
    let archive = tarball(files);
    let sum = digest.map_or_else(|| hex(&Sha256::digest(&archive)), str::to_owned);
    let at = format!("/releases/download/v{version}");
    serve(vec![
        (
            "/releases/latest".to_owned(),
            302,
            Some(format!("https://github.com/{REPO}/releases/tag/v{version}")),
            Vec::new(),
        ),
        (
            format!("{at}/checksums.txt"),
            200,
            None,
            format!("{sum}  {name}\n").into_bytes(),
        ),
        (format!("{at}/{name}"), 200, None, archive),
    ])
}

fn installed(dir: &Path, version: &str) -> Here {
    let bin = dir.join("devflow");
    fs::write(&bin, "old").unwrap();
    Here {
        version: version.to_owned(),
        bin,
        released: true,
        off: false,
        os: "linux",
        arch: "x86_64",
    }
}

/// A source that fails any request: a check that reaches it asked the network.
fn nowhere() -> Source {
    Source {
        base: "http://127.0.0.1:1".to_owned(),
    }
}

fn leftovers(dir: &Path) -> Vec<String> {
    fs::read_dir(dir)
        .unwrap()
        .flatten()
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .filter(|name| name.starts_with(STAGED))
        .collect()
}

#[test]
fn a_tag_is_a_version_only_when_shaped_as_one() {
    assert_eq!(version_of("v0.4.0").as_deref(), Some("0.4.0"));
    assert_eq!(version_of("1.2.3-rc.1").as_deref(), Some("1.2.3-rc.1"));
    for bad in [
        "latest",
        "v1.2",
        "v1.2.3.4",
        "../v1.2.3",
        "v1.2.x",
        "v1.2.3-",
        "v1.2.3-a/b",
        "",
    ] {
        assert_eq!(version_of(bad), None, "{bad}");
    }
}

#[test]
fn a_later_version_is_newer_and_a_release_beats_its_pre_releases() {
    assert!(newer("0.10.0", "0.9.9"));
    assert!(newer("1.0.0", "1.0.0-rc.1"));
    assert!(!newer("0.4.0", "0.4.0"));
    assert!(!newer("0.3.9", "0.4.0"));
    assert!(!newer("1.0.0-rc.1", "1.0.0"));
}

#[test]
fn the_archive_is_named_as_the_release_workflow_names_it() {
    assert_eq!(
        archive("0.4.0", "linux", "x86_64").as_deref(),
        Some("devflow_0.4.0_linux_amd64.tar.gz")
    );
    assert_eq!(
        archive("0.4.0", "macos", "aarch64").as_deref(),
        Some("devflow_0.4.0_darwin_arm64.tar.gz")
    );
    assert_eq!(archive("0.4.0", "windows", "x86_64"), None);
}

#[test]
fn checksums_are_read_as_sha256sum_writes_them() {
    let sum = "a".repeat(64);
    let text = format!(
        "{}  other.tar.gz\n{}  *devflow.tar.gz\n",
        "b".repeat(64),
        sum
    );
    assert_eq!(digest_in(&text, "devflow.tar.gz"), Some(sum));
    assert_eq!(digest_in(&text, "missing.tar.gz"), None);
    assert_eq!(digest_in("short  devflow.tar.gz", "devflow.tar.gz"), None);
}

#[test]
fn the_switch_is_off_for_any_value_but_zero_or_empty() {
    assert!(is_off(Some("1")));
    assert!(is_off(Some("yes")));
    assert!(is_off(Some("TRUE")));
    assert!(!is_off(Some("0")));
    assert!(!is_off(Some("false")));
    assert!(!is_off(Some("")));
    assert!(!is_off(None));
}

#[test]
fn a_refused_update_never_reaches_the_network() {
    let dir = tempfile::tempdir().unwrap();
    let mut here = installed(dir.path(), "0.4.0");
    here.off = true;
    assert_eq!(
        check(&nowhere(), &here, false).unwrap().refused,
        Some(Refused::Off)
    );
    here.off = false;
    here.released = false;
    assert_eq!(
        check(&nowhere(), &here, false).unwrap().refused,
        Some(Refused::Checkout)
    );
    here.released = true;
    here.os = "windows";
    assert_eq!(
        check(&nowhere(), &here, false).unwrap().refused,
        Some(Refused::Unsupported)
    );
    here.os = "linux";
    assert!(
        check(&nowhere(), &here, false).is_err(),
        "a check that may go on asks"
    );
}

#[test]
fn the_persons_own_update_is_not_held_by_the_switch() {
    let dir = tempfile::tempdir().unwrap();
    let mut here = installed(dir.path(), "0.4.0");
    here.off = true;
    let found = check(&release("0.4.0", &[], None), &here, true).unwrap();
    assert_eq!(found.refused, Some(Refused::Current));
}

#[test]
fn a_newer_release_is_checked_run_and_swapped_in_keeping_the_old_one() {
    let dir = tempfile::tempdir().unwrap();
    let here = installed(dir.path(), "0.4.0");
    let new = script("0.5.0");
    let source = release("0.5.0", &[("devflow", &new), ("LICENSE", b"text")], None);
    let found = check(&source, &here, false).unwrap();
    assert_eq!(found.refused, None);
    assert_eq!(found.latest.as_deref(), Some("0.5.0"));
    apply(&source, &found, &here).unwrap();
    assert_eq!(fs::read(&here.bin).unwrap(), new);
    assert_eq!(fs::read_to_string(prev_of(&here.bin)).unwrap(), "old");
    assert!(leftovers(dir.path()).is_empty());
}

#[test]
fn the_current_release_is_not_downloaded() {
    let dir = tempfile::tempdir().unwrap();
    let here = installed(dir.path(), "0.5.0");
    let found = check(&release("0.5.0", &[], None), &here, false).unwrap();
    assert_eq!(found.refused, Some(Refused::Current));
}

#[test]
fn an_archive_that_does_not_match_its_checksum_is_never_installed() {
    let dir = tempfile::tempdir().unwrap();
    let here = installed(dir.path(), "0.4.0");
    let new = script("0.5.0");
    let source = release("0.5.0", &[("devflow", &new)], Some(&"0".repeat(64)));
    let found = check(&source, &here, false).unwrap();
    let why = apply(&source, &found, &here).unwrap_err();
    assert!(why.contains("does not match its checksum"), "{why}");
    assert_eq!(fs::read_to_string(&here.bin).unwrap(), "old");
    assert!(!prev_of(&here.bin).exists());
    assert!(leftovers(dir.path()).is_empty());
}

#[test]
fn a_binary_that_does_not_say_the_release_is_never_installed() {
    let dir = tempfile::tempdir().unwrap();
    let here = installed(dir.path(), "0.4.0");
    let wrong = script("0.4.9");
    let source = release("0.5.0", &[("devflow", &wrong)], None);
    let found = check(&source, &here, false).unwrap();
    let why = apply(&source, &found, &here).unwrap_err();
    assert!(why.contains("not `devflow 0.5.0`"), "{why}");
    assert_eq!(fs::read_to_string(&here.bin).unwrap(), "old");
    assert!(leftovers(dir.path()).is_empty());
}

#[test]
fn an_archive_without_a_devflow_at_its_top_is_refused() {
    let nested = tarball(&[("bin/devflow", b"x"), ("README.md", b"y")]);
    assert_eq!(
        binary_in(&nested, 1 << 20).unwrap_err(),
        "the archive holds no devflow"
    );
    let big = tarball(&[("devflow", &[0u8; 64])]);
    assert!(binary_in(&big, 10).is_err());
    assert_eq!(
        binary_in(&tarball(&[("devflow", b"bin")]), 1 << 20).unwrap(),
        b"bin"
    );
}

#[test]
fn a_redirect_to_something_not_a_version_is_refused() {
    let source = serve(vec![(
        "/releases/latest".to_owned(),
        302,
        Some("https://github.com/x/y/releases/tag/../../evil".to_owned()),
        Vec::new(),
    )]);
    assert!(source.latest().unwrap_err().contains("not a version"));
}

#[test]
fn one_start_at_a_time_holds_the_lock() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state/update.lock");
    let held = Lock::take(&path).unwrap();
    assert!(Lock::take(&path).is_none());
    drop(held);
    assert!(!path.exists());
    assert!(Lock::take(&path).is_some());
}

#[test]
fn a_lock_a_dead_start_left_is_taken_over() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("update.lock");
    fs::write(&path, "").unwrap();
    let old = SystemTime::now() - STALE - Duration::from_secs(5);
    fs::File::options()
        .write(true)
        .open(&path)
        .unwrap()
        .set_modified(old)
        .unwrap();
    assert!(Lock::take(&path).is_some());
}

#[test]
fn the_swap_keeps_the_binary_in_place_and_the_old_one_beside_it() {
    let dir = tempfile::tempdir().unwrap();
    let bin = dir.path().join("devflow");
    fs::write(&bin, "old").unwrap();
    fs::write(prev_of(&bin), "older").unwrap();
    let staged = dir.path().join(".devflow-new-1");
    fs::write(&staged, "new").unwrap();
    swap(&staged, &bin).unwrap();
    assert_eq!(fs::read_to_string(&bin).unwrap(), "new");
    assert_eq!(fs::read_to_string(prev_of(&bin)).unwrap(), "old");
    assert!(!staged.exists());
}

#[test]
fn only_the_persons_own_install_of_the_plugin_is_behind() {
    let listing = r#"[{"id":"other@x","version":"0.1.0"},
        {"id":"devflow@devflow","version":"0.1.0","scope":"project","projectPath":"/elsewhere"},
        {"id":"devflow@devflow","version":"0.2.2","scope":"user"}]"#;
    assert!(plugin_behind(listing, "0.4.0"));
    assert!(!plugin_behind(listing, "0.2.2"));
    let elsewhere = r#"[{"id":"devflow@devflow","version":"0.1.0","scope":"project"}]"#;
    assert!(!plugin_behind(elsewhere, "0.4.0"));
    assert!(!plugin_behind(
        r#"[{"id":"other@x","version":"0.1.0"}]"#,
        "0.4.0"
    ));
    assert!(!plugin_behind("not json", "0.4.0"));
}

fn claude(listings: Vec<&'static str>) -> (Machine, Rc<RefCell<Vec<String>>>) {
    let asked = Rc::new(RefCell::new(Vec::new()));
    let seen = asked.clone();
    let listings = RefCell::new(listings.into_iter());
    let machine = Machine {
        home: PathBuf::new(),
        config: PathBuf::new(),
        mac: false,
        has: Box::new(|program| program == "claude"),
        ask: Box::new(move |argv| {
            let line = argv.join(" ");
            seen.borrow_mut().push(line.clone());
            if line == "claude plugin list --json" {
                listings.borrow_mut().next().map(str::to_owned)
            } else {
                Some(String::new())
            }
        }),
    };
    (machine, asked)
}

#[test]
fn a_plugin_behind_the_binary_is_refreshed_then_updated_in_its_scope() {
    let (machine, asked) = claude(vec![
        r#"[{"id":"devflow@devflow","version":"0.2.2","scope":"user"}]"#,
        r#"[{"id":"devflow@devflow","version":"0.4.0","scope":"user"}]"#,
    ]);
    let said = refresh_plugin(&machine, "0.4.0").unwrap().unwrap();
    assert!(said.contains("now 0.4.0"), "{said}");
    assert_eq!(
        *asked.borrow(),
        [
            "claude plugin list --json",
            "claude plugin marketplace update devflow",
            "claude plugin update devflow@devflow --scope user",
            "claude plugin list --json",
        ]
    );
}

#[test]
fn a_current_plugin_is_left_alone() {
    let (machine, asked) = claude(vec![
        r#"[{"id":"devflow@devflow","version":"0.4.0","scope":"user"}]"#,
    ]);
    assert_eq!(refresh_plugin(&machine, "0.4.0"), None);
    assert_eq!(asked.borrow().len(), 1);
}

#[test]
fn a_start_with_updates_off_or_on_a_checkout_does_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path().join("state");
    let lock = state.join("update.lock");
    let (machine, asked) = claude(vec![]);
    let mut here = installed(dir.path(), "0.4.0");
    here.off = true;
    assert!(background(&nowhere(), &here, &machine, &state).is_empty());
    here.off = false;
    here.released = false;
    assert!(background(&nowhere(), &here, &machine, &state).is_empty());
    assert!(asked.borrow().is_empty());
    assert!(!lock.exists());
}

#[test]
fn a_start_offline_says_so_once_and_changes_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path().join("state");
    let lock = state.join("update.lock");
    let (machine, asked) = claude(vec![]);
    let here = installed(dir.path(), "0.4.0");
    let said = background(&nowhere(), &here, &machine, &state);
    assert_eq!(said.len(), 1);
    assert!(
        said[0].starts_with("could not check for an update"),
        "{}",
        said[0]
    );
    assert_eq!(fs::read_to_string(&here.bin).unwrap(), "old");
    assert!(asked.borrow().is_empty());
    assert!(!lock.exists());
}

#[test]
fn a_start_updates_the_binary_then_the_plugin_to_the_same_version() {
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path().join("state");
    let lock = state.join("update.lock");
    let (machine, asked) = claude(vec![
        r#"[{"id":"devflow@devflow","version":"0.4.0","scope":"user"}]"#,
        r#"[{"id":"devflow@devflow","version":"0.5.0","scope":"user"}]"#,
    ]);
    let here = installed(dir.path(), "0.4.0");
    let new = script("0.5.0");
    let said = background(
        &release("0.5.0", &[("devflow", &new)], None),
        &here,
        &machine,
        &state,
    );
    assert!(said[0].starts_with("updated 0.4.0 → 0.5.0"), "{said:?}");
    assert!(said[1].contains("now 0.5.0"), "{said:?}");
    assert_eq!(fs::read(&here.bin).unwrap(), new);
    assert!(asked
        .borrow()
        .iter()
        .any(|line| line.contains("--scope user")));
    assert!(!lock.exists());
    assert_eq!(
        fs::read_to_string(state.join(PLUGIN_CHECKED)).unwrap(),
        "0.5.0"
    );
}

#[test]
fn a_host_reads_what_the_update_did_as_one_json_line() {
    let current = Ok(Done::Current("0.4.0".to_owned()));
    assert_eq!(
        as_json(&current, None),
        serde_json::json!({ "updated": false, "from": "0.4.0", "to": "0.4.0" })
    );
    let updated = Ok(Done::Updated {
        from: "0.4.0".to_owned(),
        to: "0.4.1".to_owned(),
        bin: PathBuf::from("/x/devflow"),
    });
    let plugin = Err("the Claude Code plugin did not update".to_owned());
    assert_eq!(
        as_json(&updated, Some(&plugin)),
        serde_json::json!({ "updated": true, "from": "0.4.0", "to": "0.4.1",
                            "plugin": { "error": "the Claude Code plugin did not update" } })
    );
    assert_eq!(
        as_json(&Err("offline".to_owned()), None),
        serde_json::json!({ "error": "offline" })
    );
}

#[test]
fn the_persons_update_installs_and_says_from_and_to() {
    let dir = tempfile::tempdir().unwrap();
    let here = installed(dir.path(), "0.4.0");
    let new = script("0.4.1");
    let source = release("0.4.1", &[("devflow", &new)], None);
    assert_eq!(
        asked(&source, &here, true).unwrap(),
        Done::Out {
            from: "0.4.0".to_owned(),
            to: "0.4.1".to_owned()
        }
    );
    assert_eq!(fs::read_to_string(&here.bin).unwrap(), "old");
    assert!(matches!(
        asked(&source, &here, false).unwrap(),
        Done::Updated { .. }
    ));
    assert_eq!(fs::read(&here.bin).unwrap(), new);
    let mut checkout = installed(dir.path(), "0.4.0");
    checkout.released = false;
    assert!(asked(&nowhere(), &checkout, false)
        .unwrap_err()
        .contains("checkout"));
}

#[test]
fn the_plugin_is_asked_about_once_per_version() {
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path().join("state");
    let current = r#"[{"id":"devflow@devflow","version":"0.5.0","scope":"user"}]"#;
    let (machine, asked) = claude(vec![current]);
    let here = installed(dir.path(), "0.5.0");
    let source = release("0.5.0", &[], None);
    assert!(background(&source, &here, &machine, &state).is_empty());
    assert_eq!(asked.borrow().len(), 1);
    assert!(background(&source, &here, &machine, &state).is_empty());
    assert_eq!(asked.borrow().len(), 1, "{:?}", asked.borrow());
}

#[test]
fn a_plugin_that_did_not_update_is_asked_about_again() {
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path().join("state");
    let behind = r#"[{"id":"devflow@devflow","version":"0.4.0","scope":"user"}]"#;
    let asked = Rc::new(RefCell::new(0));
    let seen = asked.clone();
    let machine = Machine {
        home: PathBuf::new(),
        config: PathBuf::new(),
        mac: false,
        has: Box::new(|program| program == "claude"),
        ask: Box::new(move |argv| {
            *seen.borrow_mut() += 1;
            (argv.join(" ") == "claude plugin list --json").then(|| behind.to_owned())
        }),
    };
    let here = installed(dir.path(), "0.5.0");
    let source = release("0.5.0", &[], None);
    let said = background(&source, &here, &machine, &state);
    assert!(said[0].contains("marketplace did not refresh"), "{said:?}");
    background(&source, &here, &machine, &state);
    assert_eq!(*asked.borrow(), 4);
}
