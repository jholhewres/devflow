use serde_json::json;

use super::*;

/// Every shipped case reads, is held to what a kept one is, and names no
/// real host, address or person; SSRF and ReDoS are among the classes.
#[test]
fn the_repertoire_names_no_project_or_client() {
    assert!(names().contains(&"ssrf") && names().contains(&"redos"));
    for name in names() {
        let class = shipped(name).expect(name);
        assert_eq!(class.class, name);
        assert!(!class.cases.is_empty(), "{name}");
        neutral(&class.about).unwrap_or_else(|why| panic!("{name}: {why}"));
        let mut ids: Vec<&str> = class.cases.iter().map(|case| case.id.as_str()).collect();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), class.cases.len(), "{name}: ids are unique");
        for case in &class.cases {
            checked(case).unwrap_or_else(|why| panic!("{name}: {why}"));
        }
    }
    assert!(shipped("redos")
        .expect("redos")
        .cases
        .iter()
        .all(|case| case.want == "fast"));
}

#[test]
fn a_real_host_or_address_is_never_neutral() {
    for named in [
        "http://api.someone.com/",
        "https://8.8.8.8/",
        "http://169.254.169.254/latest/",
        "http://[fd00:ec2::254]:1/",
        "write to ops@someone.com.br",
        "internal.someone.io",
        "http://someone.example.com.evil.net/",
        "http:/169.254.169.254/latest/meta-data/",
        "http:\\\\169.254.169.254\\latest",
        "169.254.169.254",
        "http:/8.8.8.8/",
        "HTTP://8.8.8.8/",
        "http://169.254.170.2/v2/credentials",
        "gopher://127.0.0.1:6379/_FLUSHALL",
        "http://10.0.0.5:8080/admin",
        "http://127.0.0.1/",
        "http://metadata.google.internal/",
        "http://example.com/",
        "fetch 8.8.4.4 then",
        "file://intranet.someone/share",
    ] {
        assert!(neutral(named).is_err(), "{named}");
    }
    for fine in [
        "http://127.0.0.1:1/",
        "http://2130706433:1/",
        "http://0x7f000001:1/",
        "http://0177.0.0.1:1/",
        "http://127.1:1/",
        "http://[::ffff:127.0.0.1]:1/",
        "http://example.com@127.0.0.1:1/",
        "http://api.test/",
        "file:///etc/hostname",
        "<?xml version=\"1.0\"?><x xmlns:xi=\"http://www.w3.org/2001/XInclude\"/>",
        "!!python/object/apply:os.system [\"true\"]",
    ] {
        assert!(neutral(fine).is_ok(), "{fine}: {:?}", neutral(fine));
    }
}

#[test]
fn a_table_is_written_for_jest_vitest_go_and_pytest() {
    let redos = shipped("redos").expect("redos");
    let jest = table(&redos, Runner::Jest);
    assert!(jest.contains("async function check(input)"));
    assert!(jest.contains("[\"letters-then-bang\", \"a\".repeat(50000) + \"!\", \"fast\"],"));
    assert!(jest.contains("toBeLessThan(1000)"));
    assert!(!jest.contains("from \"vitest\""));
    let vitest = table(&redos, Runner::Vitest);
    assert!(vitest.contains("import { describe, test, expect } from \"vitest\";"));
    let go = table(&redos, Runner::Go);
    assert!(go.contains("func TestPayloadsRedos(t *testing.T) {"));
    assert!(
        go.contains("\t\t{\"letters-then-bang\", strings.Repeat(\"a\", 50000) + \"!\", \"fast\"},")
    );
    let pytest = table(&redos, Runner::Pytest);
    assert!(pytest.contains("def test_payloads_redos(case_id, given, want):"));
    assert!(pytest.contains("    (\"letters-then-bang\", \"a\" * 50000 + \"!\", \"fast\"),"));
    let ssrf = table(&shipped("ssrf").expect("ssrf"), Runner::Pytest);
    assert!(ssrf.contains("(\"loopback\", \"http://127.0.0.1:1/\", \"rejected\"),"));
    assert_eq!(Runner::of("go"), Some(Runner::Go));
    assert_eq!(Runner::of("mocha"), None);
}

/// Each table compiles in its own language, where that language is here.
#[test]
fn every_table_is_a_program_its_language_reads() {
    let dir = tempfile::tempdir().expect("dir");
    let have = |tool: &str| {
        std::process::Command::new(tool)
            .arg("--version")
            .output()
            .is_ok_and(|out| out.status.success())
    };
    for name in names() {
        let class = shipped(name).expect(name);
        if have("python3") {
            let at = dir.path().join(format!("test_{name}.py"));
            std::fs::write(&at, table(&class, Runner::Pytest)).expect("py");
            let out = std::process::Command::new("python3")
                .args(["-m", "py_compile"])
                .arg(&at)
                .output()
                .expect("python3");
            assert!(
                out.status.success(),
                "{name}: {}",
                String::from_utf8_lossy(&out.stderr)
            );
        }
        if have("node") {
            let at = dir.path().join(format!("{name}.test.js"));
            std::fs::write(&at, table(&class, Runner::Jest)).expect("js");
            let out = std::process::Command::new("node")
                .arg("--check")
                .arg(&at)
                .output()
                .expect("node");
            assert!(
                out.status.success(),
                "{name}: {}",
                String::from_utf8_lossy(&out.stderr)
            );
        }
        let at = dir.path().join(format!("{name}_test.go"));
        std::fs::write(&at, table(&class, Runner::Go)).expect("go");
        // gofmt has no --version: one that is not here does not start.
        if let Ok(out) = std::process::Command::new("gofmt")
            .arg("-e")
            .arg(&at)
            .output()
        {
            assert!(
                out.status.success(),
                "{name}: {}",
                String::from_utf8_lossy(&out.stderr)
            );
        }
    }
}

#[test]
fn a_proposed_case_is_kept_only_when_kept_and_only_if_neutral() {
    let dir = tempfile::tempdir().expect("dir");
    let root = dir.path();
    let answer = json!({ "cases": [
        { "class": "ssrf", "input": "http://[::]:1/", "want": "rejected", "why": "the guard reads only dotted IPv4" },
        { "class": "ssrf", "input": "http://intranet.someone.com/", "want": "rejected", "why": "a real host" },
        { "class": "nope", "input": "x", "want": "rejected" },
    ] });
    let proposed = proposed_of(&answer);
    assert_eq!(proposed.len(), 1, "{proposed:?}");
    assert_eq!(proposed[0]["id"], "c1");
    assert!(
        kept(root, "ssrf").expect("none yet").is_empty(),
        "proposing keeps nothing"
    );
    let at = keep(root, &proposed[0]).expect("kept");
    assert!(at.ends_with("payloads/ssrf.json"), "{at}");
    let ssrf = class(root, "ssrf").expect("ssrf");
    let last = ssrf.cases.last().expect("kept last");
    assert_eq!(
        (last.id.as_str(), last.input.as_str()),
        ("kept-1", "http://[::]:1/")
    );
    assert!(keep(root, &proposed[0]).is_err(), "never twice");
    let shipped_again =
        json!({ "class": "ssrf", "input": "http://127.0.0.1:1/", "want": "rejected" });
    assert!(keep(root, &shipped_again).is_err());
}

#[test]
fn a_row_is_indented_by_its_table_never_by_its_input() {
    let class = Class {
        class: "sqli".to_owned(),
        about: "a".to_owned(),
        within_ms: None,
        cases: vec![Case {
            id: "k".to_owned(),
            input: "1) OR (1=1  (x".to_owned(),
            times: None,
            then: None,
            want: "inert".to_owned(),
        }],
    };
    let pytest = table(&class, Runner::Pytest);
    assert!(
        pytest.contains("    (\"k\", \"1) OR (1=1  (x\", \"inert\"),"),
        "{pytest}"
    );
}
