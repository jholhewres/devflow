//! `devflow payloads`: the repertoire's tables, and a case an attack proposed
//! kept only by a person's yes on a terminal.

use std::path::Path;
use std::process::{Command, Output, Stdio};

fn devflow(root: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_devflow"))
        .arg("--root")
        .arg(root)
        .args(args)
        .env("HOME", root.join("home"))
        .env("XDG_CONFIG_HOME", root.join("home/config"))
        .env("XDG_CACHE_HOME", root.join("home/cache"))
        .env("DEVFLOW_NO_UPDATE", "1")
        .stdin(Stdio::null())
        .output()
        .unwrap()
}

fn git(root: &Path, args: &[&str]) {
    let done = Command::new("git")
        .args([
            "-c",
            "user.name=t",
            "-c",
            "user.email=t@t.test",
            "-c",
            "commit.gpgsign=false",
        ])
        .args(args)
        .current_dir(root)
        .output()
        .unwrap();
    assert!(
        done.status.success(),
        "{}",
        String::from_utf8_lossy(&done.stderr)
    );
}

#[test]
fn a_proposed_case_is_not_kept_without_a_terminal_and_a_table_is_printed() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    git(root, &["init", "-q"]);
    let run = root.join(".devflow/runs/card_1/20261119T120000Z");
    std::fs::create_dir_all(&run).unwrap();
    std::fs::write(
        run.join("attack.json"),
        serde_json::json!({ "item": "card_1", "hypotheses": [], "proposed_cases": [
            { "id": "c1", "class": "traversal", "input": "..%2f..%2fetc%2fhostname", "want": "rejected", "why": "encoded slashes" },
            { "id": "c2", "class": "ssrf", "input": "http://[::]:1/", "want": "rejected", "why": "a URL" },
        ] })
        .to_string(),
    )
    .unwrap();

    let refused = devflow(root, &["payloads", "add", "card_1", "c1"]);
    assert!(!refused.status.success());
    let said = String::from_utf8_lossy(&refused.stderr);
    assert!(said.contains("on a terminal"), "{said}");
    assert!(
        String::from_utf8_lossy(&refused.stdout).contains("input: \"..%2f..%2fetc%2fhostname\"")
    );
    // A case that could not be kept is refused before anyone is asked.
    let unkeepable = devflow(root, &["payloads", "add", "card_1", "c2"]);
    let said = String::from_utf8_lossy(&unkeepable.stderr);
    assert!(
        said.contains("IPv6") && !said.contains("on a terminal"),
        "{said}"
    );
    assert!(
        !root.join(".devflow/payloads/traversal.json").exists(),
        "nothing kept"
    );

    let missing = devflow(root, &["payloads", "add", "card_1", "c9"]);
    assert!(String::from_utf8_lossy(&missing.stderr).contains("proposes no case `c9`"));
    // The same report, once the repository carries it, proposes nothing.
    git(root, &["add", "-f", ".devflow/runs"]);
    git(root, &["commit", "-qm", "planted"]);
    let planted = devflow(root, &["payloads", "add", "card_1", "c1"]);
    let said = String::from_utf8_lossy(&planted.stderr);
    assert!(said.contains("part of the repository"), "{said}");
    assert!(!String::from_utf8_lossy(&planted.stdout).contains("input:"));

    let table = devflow(root, &["payloads", "table", "ssrf", "--runner", "pytest"]);
    assert!(table.status.success());
    let table = String::from_utf8_lossy(&table.stdout);
    assert!(
        table.contains("def test_payloads_ssrf(case_id, given, want):"),
        "{table}"
    );
    assert!(table.contains("(\"loopback-decimal\", \"http://2130706433:1/\", \"rejected\"),"));
    assert!(
        !devflow(root, &["payloads", "table", "ssrf", "--runner", "mocha"])
            .status
            .success()
    );

    let listed = devflow(root, &["payloads", "list"]);
    let listed = String::from_utf8_lossy(&listed.stdout);
    for class in [
        "ssrf",
        "redos",
        "traversal",
        "sqli",
        "nosqli",
        "xxe",
        "deserialization",
    ] {
        assert!(
            listed
                .lines()
                .any(|line| line.starts_with(&format!("{class}\t"))),
            "{listed}"
        );
    }
}
