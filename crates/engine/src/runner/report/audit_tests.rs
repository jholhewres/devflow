use super::*;

const NPM: &str = r#"{
  "auditReportVersion": 2,
  "vulnerabilities": {
    "example-parser": {
      "name": "example-parser", "severity": "high", "isDirect": true,
      "via": [{ "source": 1001, "name": "example-parser", "title": "Prototype pollution in parse",
                "url": "https://github.com/advisories/GHSA-aaaa-bbbb-cccc", "severity": "high", "range": "<2.1.0" }],
      "range": "<2.1.0", "nodes": ["node_modules/example-parser"],
      "fixAvailable": { "name": "example-parser", "version": "2.1.0", "isSemVerMajor": false }
    },
    "example-wrapper": {
      "name": "example-wrapper", "severity": "moderate", "isDirect": false,
      "via": ["example-parser"], "range": "1.0.0 - 1.4.2", "nodes": ["node_modules/example-wrapper"],
      "fixAvailable": true
    }
  },
  "metadata": { "vulnerabilities": { "high": 1, "moderate": 1, "total": 2 } }
}"#;

const GOVULN: &str = r#"{"config":{"protocol_version":"v1.0.0","scanner_name":"govulncheck"}}
{"osv":{"id":"GO-2099-0001","summary":"Unbounded read in example.test/lib/codec"}}
{"osv":{"id":"GO-2099-0002","summary":"Weak default in example.test/lib/tls"}}
{"finding":{"osv":"GO-2099-0001","fixed_version":"v1.4.1","trace":[{"module":"example.test/lib","version":"v1.3.0"}]}}
{"finding":{"osv":"GO-2099-0001","fixed_version":"v1.4.1","trace":[{"module":"example.test/lib","version":"v1.3.0","package":"example.test/lib/codec","function":"Decode","position":{"filename":"codec/decode.go","line":40}},{"module":"example.test/app","package":"example.test/app/api","function":"Handle","position":{"filename":"api/handle.go","line":12}}]}}
{"finding":{"osv":"GO-2099-0002","fixed_version":"v1.5.0","trace":[{"module":"example.test/lib","version":"v1.3.0","package":"example.test/lib/tls"}]}}
"#;

fn checkout() -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("dir");
    std::fs::create_dir_all(dir.path().join("api")).expect("api");
    std::fs::write(dir.path().join("api/handle.go"), "x\n".repeat(20)).expect("go");
    std::fs::write(dir.path().join("package-lock.json"), "{}").expect("lock");
    dir
}

#[test]
fn an_npm_audit_report_is_a_finding_per_package_at_the_lockfile_with_its_fix() {
    let dir = checkout();
    let read = npm_audit(NPM, dir.path()).expect("read");
    assert_eq!(read.tested.read_from, [NPM_AUDIT]);
    assert_eq!(read.tested.passed, 0, "a scanner passes no test");
    let parser = read
        .found
        .iter()
        .find(|one| one.package.as_deref() == Some("example-parser"))
        .expect("parser");
    assert_eq!(parser.rule, "GHSA-aaaa-bbbb-cccc");
    assert_eq!(parser.file, "package-lock.json");
    assert_eq!(parser.severity, Severity::High);
    assert_eq!(
        parser.fix.as_deref(),
        Some("upgrade example-parser to 2.1.0")
    );
    assert!(parser.message.contains("Prototype pollution"));
    let wrapper = read
        .found
        .iter()
        .find(|one| one.package.as_deref() == Some("example-wrapper"))
        .expect("wrapper");
    assert_eq!(wrapper.severity, Severity::Medium);
    assert_eq!(wrapper.fix.as_deref(), Some("npm audit fix"));
    assert!(
        npm_audit("{\"testResults\": []}", dir.path()).is_none(),
        "another JSON is not one"
    );
}

#[test]
fn a_govulncheck_report_keeps_each_advisory_at_its_most_precise_trace() {
    let dir = checkout();
    let read = govulncheck(GOVULN, dir.path()).expect("read");
    assert_eq!(read.tested.read_from, [GOVULNCHECK]);
    assert_eq!(read.found.len(), 2, "{:#?}", read.found);
    let called = &read.found[0];
    assert_eq!(called.rule, "GO-2099-0001");
    assert_eq!(
        (called.file.as_str(), called.line),
        ("api/handle.go", 12),
        "where the checkout calls in"
    );
    assert_eq!(called.severity, Severity::High);
    assert_eq!(called.package.as_deref(), Some("example.test/lib/codec"));
    assert_eq!(
        called.fix.as_deref(),
        Some("upgrade example.test/lib to v1.4.1")
    );
    assert!(called
        .message
        .contains("calls example.test/lib/codec.Decode"));
    let imported = &read.found[1];
    assert_eq!(
        (imported.file.as_str(), imported.severity),
        ("go.mod", Severity::Low)
    );
    assert!(
        govulncheck("{\"Action\":\"pass\"}", dir.path()).is_none(),
        "go test's stream is not one"
    );
}

#[test]
fn a_scanner_report_is_read_by_its_content_like_sarif() {
    let dir = checkout();
    let reports = dir.path().join("reports");
    std::fs::create_dir_all(&reports).expect("reports");
    std::fs::write(reports.join("audit.json"), NPM).expect("npm");
    std::fs::write(reports.join("govuln.json"), GOVULN).expect("go");
    let read = super::super::read_cases(Some(&reports), None, dir.path()).expect("read");
    assert!(read.read_sarif(), "read as a scanner's");
    assert_eq!(read.found.len(), 4);
}

#[test]
fn a_check_says_its_report_is_npm_audit_or_govulncheck() {
    use crate::config::Report;
    assert_eq!(Report::of("npm-audit"), Some(Report::NpmAudit));
    assert_eq!(Report::of("govulncheck"), Some(Report::Govulncheck));
}
