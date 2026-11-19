use serde_json::json;

use super::*;

#[test]
fn secrets_tokens_addresses_and_phones_are_taken_out_and_the_rest_stays() {
    let said = scrub(
        "sent password=hunter2hunter and Authorization: Bearer abc.def.ghi to admin@example.com, \
         token ghp_0123456789abcdefABCDEF, key AKIAABCDEFGHIJKLMNOP, call +55 (11) 98765-4321; \
         http://user:pw@localhost:8080/x at commit 0123456789abcdef0123456789abcdef01234567 \
         line 42 run 20261119T120000Z",
        &[],
    );
    for gone in [
        "hunter2hunter",
        "abc.def.ghi",
        "admin@example.com",
        "ghp_0123456789abcdefABCDEF",
        "AKIAABCDEFGHIJKLMNOP",
        "98765-4321",
        "user:pw",
    ] {
        assert!(!said.contains(gone), "{gone} in: {said}");
    }
    for kept in [
        "0123456789abcdef0123456789abcdef01234567",
        "line 42",
        "20261119T120000Z",
        "localhost:8080",
    ] {
        assert!(said.contains(kept), "{kept} lost: {said}");
    }
}

#[test]
fn what_an_exploit_sends_is_a_payload_kept_out_of_every_text() {
    let code = "test('reaches metadata', async () => { await fetch(\"http://169.254.169.254/latest/meta-data/\"); })";
    let payloads = payloads_in(code);
    assert!(
        payloads.contains(&"http://169.254.169.254/latest/meta-data/".to_owned()),
        "{payloads:?}"
    );
    let said = scrub(
        "it fetched http://169.254.169.254/latest/meta-data/ and got 200",
        &payloads,
    );
    assert!(!said.contains("169.254.169.254"), "{said}");
    assert!(said.contains("<payload>"));
}

fn report() -> Value {
    json!({
        "item": "item_1", "run": "20261119T120000Z", "base": "aaaa", "head": "bbbb",
        "verdict": "request_changes", "counts": { "confirmed": 1, "refuted": 1, "tried": 0, "not_run": 0 },
        "hypotheses": [
            { "id": "h1", "status": "confirmed", "severity": "high", "class": "ssrf", "file": "src/fetch.ts", "line": 45,
              "title": "the tool posts to any stored URL", "reason": "it posted to http://10.0.0.5/admin with token=abcdef1234567890abcdef",
              "impact": "reads internal services", "fix": "validate the URL against the allow list",
              "verified": { "by": "sandbox" }, "exploit": { "test": "posts anywhere", "saved": "exploits/h1/a.test.ts" } },
            { "id": "h2", "status": "refuted", "severity": "medium", "file": "src/b.ts", "line": 3,
              "title": "redirects followed", "reason": "the client follows none" },
        ],
    })
}

#[test]
fn one_issue_draft_per_confirmed_hypothesis_with_no_secret_or_payload() {
    let payloads = vec!["http://10.0.0.5/admin".to_owned()];
    let drafts = drafts(&report(), &payloads);
    assert_eq!(drafts.len(), 1, "only the confirmed one");
    let body = drafts[0]["body"].as_str().expect("body");
    assert_eq!(
        drafts[0]["title"],
        "[security] the tool posts to any stored URL"
    );
    for said in [
        "high",
        "src/fetch.ts:45",
        "reads internal services",
        "validate the URL",
        "20261119T120000Z",
    ] {
        assert!(body.contains(said), "{said} missing: {body}");
    }
    assert!(
        !body.contains("abcdef1234567890abcdef"),
        "a token reached a draft: {body}"
    );
    assert!(
        !body.contains("10.0.0.5"),
        "a payload reached a draft: {body}"
    );
}

#[test]
fn the_sarif_is_2_1_0_with_each_confirmed_hypothesis_at_its_line() {
    let said = sarif(&report(), &[]);
    assert_eq!(said["version"], "2.1.0");
    let results = said["runs"][0]["results"].as_array().expect("results");
    assert_eq!(results.len(), 1);
    assert_eq!(results[0]["ruleId"], "attack/ssrf");
    assert_eq!(results[0]["level"], "error");
    let at = &results[0]["locations"][0]["physicalLocation"];
    assert_eq!(at["artifactLocation"]["uri"], "src/fetch.ts");
    assert_eq!(at["region"]["startLine"], 45);
}

#[test]
fn the_report_is_written_as_md_json_sarif_and_its_drafts() {
    let dir = tempfile::tempdir().expect("dir");
    let folder = dir.path();
    std::fs::create_dir_all(folder.join("exploits/h1")).expect("exploits");
    std::fs::write(
        folder.join("exploits/h1/a.test.ts"),
        "fetch('http://10.0.0.5/admin')",
    )
    .expect("code");
    let files = written(folder, &report()).expect("written");
    assert_eq!(files, [MARKDOWN, JSON, SARIF, "drafts/h1.md"]);
    let md = std::fs::read_to_string(folder.join(MARKDOWN)).expect("md");
    assert!(
        md.contains("| confirmed | high | `src/fetch.ts:45` |"),
        "{md}"
    );
    for file in &files {
        let said = std::fs::read_to_string(folder.join(file)).expect("file");
        assert!(
            !said.contains("10.0.0.5"),
            "the exploit's payload in {file}"
        );
        assert!(!said.contains("fetch('"), "the exploit's code in {file}");
    }
}

#[test]
fn tokens_in_urls_headers_and_cookies_are_taken_out_too() {
    let said = scrub(
        "GET /api?access_token=abc123xyz&page=2 with X-API-Key: k-123456 and pwd=hunter22, \
         Cookie: sid=s3cr3tvalue; theme=dark\nnext line stays",
        &[],
    );
    for gone in [
        "abc123xyz",
        "k-123456",
        "hunter22",
        "s3cr3tvalue",
        "theme=dark",
    ] {
        assert!(!said.contains(gone), "{gone} in: {said}");
    }
    for kept in ["page=2", "next line stays", "access_token=<redacted>"] {
        assert!(said.contains(kept), "{kept} lost: {said}");
    }
}

#[test]
fn an_apostrophe_or_a_shell_line_never_hides_a_payload() {
    let code = "// don't follow redirects\nit('reads the internal admin', () => get(\"http://10.0.0.5/admin\"))\ncurl -s http://169.254.169.254/latest/ ../../etc/passwd";
    let found = payloads_in(code);
    for want in [
        "http://10.0.0.5/admin",
        "http://169.254.169.254/latest/",
        "../../etc/passwd",
    ] {
        assert!(found.iter().any(|one| one == want), "{want}: {found:?}");
    }
}

#[cfg(unix)]
#[test]
fn a_report_is_never_written_through_a_link_out_of_its_run() {
    let dir = tempfile::tempdir().expect("dir");
    let folder = dir.path().join("run");
    std::fs::create_dir_all(&folder).expect("run");
    let outside = dir.path().join("outside.md");
    std::fs::write(&outside, "kept").expect("outside");
    std::os::unix::fs::symlink(&outside, folder.join(MARKDOWN)).expect("link");
    std::os::unix::fs::symlink(dir.path(), folder.join(DRAFTS)).expect("link");
    assert!(written(&folder, &report()).is_err());
    assert_eq!(std::fs::read_to_string(&outside).expect("outside"), "kept");
    assert!(!dir.path().join("h1.md").exists(), "no draft outside");
}
