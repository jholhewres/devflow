//! A static analyser's SARIF is read as evidence: each result a finding at
//! its file and line, and the check judged by its report, never its exit
//! code. The fixture is semgrep 1.185.0's own output over a small Flask
//! file, its rules cut to the five it reported.

use std::path::Path;
use std::time::Duration;

use devflow_engine::config::{self, Report, Severity};
use devflow_engine::evidence;
use devflow_engine::runner::report::{self, ToolFinding};
use devflow_engine::runner::Context;
use devflow_engine::verdict::Verdict;

const SEMGREP: &str = include_str!("fixtures/sarif/semgrep.sarif");

/// A checkout holding the file semgrep read, and a report folder beside it.
fn checkout() -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().expect("dir");
    let root = dir.path().join("project");
    std::fs::create_dir_all(root.join("src/web")).expect("src");
    std::fs::write(root.join("src/web/views.py"), "x\n".repeat(20)).expect("views");
    (dir, root)
}

fn found(root: &Path, sarif: &str) -> Vec<ToolFinding> {
    let reports = root.parent().expect("parent").join("reports");
    std::fs::create_dir_all(&reports).expect("reports");
    std::fs::write(reports.join("semgrep.sarif"), sarif).expect("report");
    report::read_cases(Some(&reports), None, root)
        .expect("a SARIF report is read")
        .found
}

#[test]
fn a_semgrep_sarif_becomes_a_finding_at_its_line() {
    let (_dir, root) = checkout();
    let found = found(&root, SEMGREP);
    assert_eq!(found.len(), 5, "{found:#?}");
    let injection = &found[0];
    assert_eq!(injection.tool, "Semgrep OSS");
    assert_eq!(
        injection.rule,
        "python.flask.security.injection.subprocess-injection.subprocess-injection"
    );
    assert_eq!(
        (injection.file.as_str(), injection.line),
        ("src/web/views.py", 11)
    );
    // No level on the result: the rule's default, `error`, says it.
    assert_eq!(injection.severity, Severity::High);
    let eval = found
        .iter()
        .find(|one| one.rule.ends_with("user-eval.user-eval"))
        .expect("the eval");
    assert_eq!((eval.line, eval.severity), (16, Severity::Medium));
    assert_eq!(
        injection.said(),
        "`src/web/views.py:11` python.flask.security.injection.subprocess-injection.subprocess-injection (high, Semgrep OSS)"
    );
}

#[test]
fn a_location_outside_the_checkout_is_never_read() {
    let (dir, root) = checkout();
    std::fs::write(dir.path().join("secret.txt"), "s").expect("outside");
    let outside = format!("file://{}", dir.path().join("secret.txt").display());
    let inside = format!(
        "file://{}",
        root.canonicalize()
            .expect("root")
            .join("src/web/views.py")
            .display()
    );
    for (uri, kept) in [
        ("../secret.txt", false),
        ("src/../../secret.txt", false),
        ("/etc/passwd", false),
        (outside.as_str(), false),
        ("https://example.com/src/web/views.py", false),
        ("src%2F..%2F..%2Fsecret.txt", false),
        ("src/web/missing.py", false),
        (inside.as_str(), true),
        ("./src/web/views.py", true),
    ] {
        let sarif = SEMGREP.replace(
            "\"uri\": \"src/web/views.py\"",
            &format!("\"uri\": {uri:?}"),
        );
        let found = found(&root, &sarif);
        assert_eq!(!found.is_empty(), kept, "{uri}: {found:?}");
        if kept {
            assert_eq!(found[0].file, "src/web/views.py", "{uri}");
        }
    }
}

#[cfg(unix)]
#[test]
fn a_link_out_of_the_checkout_is_never_read() {
    let (dir, root) = checkout();
    std::fs::write(dir.path().join("secret.txt"), "s").expect("outside");
    std::os::unix::fs::symlink(dir.path().join("secret.txt"), root.join("src/web/link.py"))
        .expect("link");
    let sarif = SEMGREP.replace(
        "\"uri\": \"src/web/views.py\"",
        "\"uri\": \"src/web/link.py\"",
    );
    assert!(found(&root, &sarif).is_empty());
}

#[test]
fn a_sarif_check_is_judged_by_its_report_not_its_exit_code() {
    let (dir, root) = checkout();
    let fixture = dir.path().join("fixture.sarif");
    std::fs::write(&fixture, SEMGREP).expect("fixture");
    let check = |run: String| config::Check {
        name: "semgrep".to_owned(),
        run,
        report: Report::Sarif,
        evidence: Vec::new(),
        requires: None,
        exclusive: None,
    };
    let ran = |name: &str, check: &config::Check| {
        let run = dir.path().join(name);
        std::fs::create_dir_all(&run).expect("run");
        evidence::run_check(
            check,
            &root,
            &run,
            &dir.path().join("locks"),
            &Context::default(),
            Duration::from_secs(30),
            &|text: &str| text.to_owned(),
        )
    };
    // `semgrep --error` exits 1 for the findings it was asked for.
    let found = ran(
        "found",
        &check(format!(
            "cp '{}' \"$DEVFLOW_REPORT_DIR/semgrep.sarif\"; exit 1",
            fixture.display()
        )),
    );
    assert_eq!(found.verdict, Verdict::Passed, "{found:?}");
    assert_eq!(
        found.reported.as_ref().map(|read| read.found.len()),
        Some(5)
    );
    assert_eq!(found.reports, ["semgrep/semgrep.sarif"]);
    // Kept without the code each result quotes, where a secret scanner
    // would put the secret.
    assert!(SEMGREP.contains("\"snippet\""));
    let kept =
        std::fs::read_to_string(dir.path().join("found/semgrep/semgrep.sarif")).expect("kept");
    assert!(!kept.contains("\"snippet\""), "{kept}");
    assert!(kept.contains("\"startLine\": 11"));

    let silent = ran("silent", &check("exit 0".to_owned()));
    assert_eq!(silent.verdict, Verdict::Inconclusive);

    let broken = SEMGREP.replace(
        "\"executionSuccessful\": true",
        "\"executionSuccessful\": false",
    );
    std::fs::write(&fixture, broken).expect("broken");
    let failed = ran(
        "failed",
        &check(format!(
            "cp '{}' \"$DEVFLOW_REPORT_DIR/semgrep.sarif\"",
            fixture.display()
        )),
    );
    assert_eq!(failed.verdict, Verdict::Failed);
}

#[test]
fn findings_past_the_ceiling_are_not_kept() {
    let (_dir, root) = checkout();
    let mut sarif: serde_json::Value = serde_json::from_str(SEMGREP).expect("json");
    let one = sarif["runs"][0]["results"][0].clone();
    sarif["runs"][0]["results"] = serde_json::Value::Array(vec![one; 500]);
    assert_eq!(found(&root, &sarif.to_string()).len(), 200);
}

#[test]
fn what_semgrep_found_is_kept_in_the_evidence_and_named_in_the_review_packet() {
    use devflow_engine::{evidence::Card, review, runs::Runs, Dialect};
    use std::time::SystemTime;
    let (dir, root) = checkout();
    let fixture = dir.path().join("fixture.sarif");
    std::fs::write(&fixture, SEMGREP).expect("fixture");
    let config = config::parse(&format!(
        "version: 2\nstages:\n  - uses: builtin/execution\n    checks:\n      - {{ name: semgrep, run: \"cp '{}' \\\"$DEVFLOW_REPORT_DIR/semgrep.sarif\\\"; exit 1\", report: sarif }}\n",
        fixture.display()
    ))
    .expect("config");
    let runs = Runs {
        dialect: &Dialect::DEVFLOW,
        home: dir.path().join("runs"),
        checkout: root.clone(),
    };
    let asked = evidence::asked(&serde_json::json!({ "card": "card_1" })).expect("asked");
    let found = evidence::gathered(&evidence::Given {
        dialect: &Dialect::DEVFLOW,
        root: &root,
        runs: &runs,
        locks: &dir.path().join("locks"),
        config: &config,
        asked: &asked,
        card: Card {
            id: "card_1",
            title: "Ping",
            body: "",
        },
        context: &Context::default(),
        budget: Duration::from_secs(60),
        redact: &|text: &str| text.to_owned(),
        at: SystemTime::now(),
    })
    .expect("gathered");
    let kept: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(Path::new(&found.folder).join("evidence.json")).expect("kept"),
    )
    .expect("json");
    let check = &kept["checks"][0];
    assert_eq!(check["result"], "passed", "{kept:#}");
    assert_eq!(check["findings"].as_array().map(Vec::len), Some(5));
    assert_eq!(check["findings"][0]["file"], "src/web/views.py");
    assert_eq!(check["findings"][0]["line"], 11);

    let files = vec!["src/web/views.py".to_owned()];
    let packet = review::packet(&review::Packet {
        dialect: &Dialect::DEVFLOW,
        card: Card {
            id: "card_1",
            title: "Ping",
            body: "",
        },
        git: review::Git {
            base: "b4se",
            head: "he4d",
            files: &files,
            diff: "",
        },
        criteria: &[],
        brief: None,
        standards: &[],
        evidence: Some(&kept),
        previous: None,
        retro: false,
    });
    assert!(packet.contains("## Static analysis"), "{packet}");
    assert!(
        packet.contains("`src/web/views.py:11` python.flask.security.injection.subprocess-injection.subprocess-injection (high, Semgrep OSS)"),
        "{packet}"
    );
}

#[test]
fn a_kept_report_quotes_none_of_the_code_it_read() {
    use devflow_engine::runner::report::sarif::without_snippets;
    let quoting = serde_json::json!({
        "version": "2.1.0",
        "runs": [{
            "tool": { "driver": { "name": "gitleaks" } },
            "artifacts": [{ "location": { "uri": "src/.env" }, "contents": { "text": "TOKEN=s3cr3t" } }],
            "results": [{
                "ruleId": "generic-api-key",
                "locations": [{ "physicalLocation": {
                    "artifactLocation": { "uri": "src/.env" },
                    "region": { "startLine": 3, "snippet": { "text": "TOKEN=s3cr3t" } },
                    "contextRegion": { "startLine": 2, "snippet": { "text": "# keys\nTOKEN=s3cr3t" } }
                } }],
                "codeFlows": [{ "threadFlows": [{ "locations": [{ "location": { "physicalLocation": {
                    "region": { "startLine": 3, "snippet": { "text": "TOKEN=s3cr3t" } }
                } } }] }] }]
            }]
        }]
    })
    .to_string();
    let kept = without_snippets(&quoting).expect("it quoted code");
    assert!(!kept.contains("s3cr3t"), "{kept}");
    assert!(kept.contains("\"startLine\": 3"));
    // A report that quotes nothing is kept as it was written.
    assert_eq!(without_snippets(&kept), None);
    assert_eq!(without_snippets("{\"testResults\": []}"), None);
}
