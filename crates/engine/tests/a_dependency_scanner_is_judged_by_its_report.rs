//! A check whose report is npm audit's or govulncheck's is judged by its
//! report, never its exit code: `npm audit` exits 1 when it found something.

use std::time::Duration;

use devflow_engine::config::{self, Report};
use devflow_engine::evidence;
use devflow_engine::runner::Context;
use devflow_engine::verdict::Verdict;

const NPM: &str = r#"{ "auditReportVersion": 2, "vulnerabilities": { "example-parser": {
  "name": "example-parser", "severity": "high",
  "via": [{ "title": "Prototype pollution in parse", "url": "https://github.com/advisories/GHSA-aaaa-bbbb-cccc" }],
  "range": "<2.1.0", "fixAvailable": { "name": "example-parser", "version": "2.1.0" } } } }"#;

#[test]
fn an_npm_audit_check_is_judged_by_its_report_not_its_exit_code() {
    let dir = tempfile::tempdir().expect("dir");
    let root = dir.path().join("project");
    std::fs::create_dir_all(&root).expect("project");
    std::fs::write(root.join("package-lock.json"), "{}").expect("lock");
    let fixture = dir.path().join("audit.json");
    std::fs::write(&fixture, NPM).expect("fixture");
    let ran = |name: &str, run: String, report: Report| {
        let check = config::Check {
            name: "audit".to_owned(),
            run,
            report,
            evidence: Vec::new(),
            requires: None,
            exclusive: None,
        };
        let at = dir.path().join(name);
        std::fs::create_dir_all(&at).expect("run");
        evidence::run_check(
            &check,
            &root,
            &at,
            &dir.path().join("locks"),
            &Context::default(),
            Duration::from_secs(30),
            &|text: &str| text.to_owned(),
        )
    };
    let copy = format!(
        "cp '{}' \"$DEVFLOW_REPORT_DIR/audit.json\"; exit 1",
        fixture.display()
    );
    for report in [Report::NpmAudit, Report::Govulncheck] {
        let found = ran(&format!("found-{}", report.word()), copy.clone(), report);
        assert_eq!(found.verdict, Verdict::Passed, "{found:?}");
        let read = found.reported.as_ref().expect("read");
        assert_eq!(read.found[0].package.as_deref(), Some("example-parser"));
        let silent = ran(
            &format!("silent-{}", report.word()),
            "exit 0".to_owned(),
            report,
        );
        assert_eq!(
            silent.verdict,
            Verdict::Inconclusive,
            "no report is no pass"
        );
    }
}
