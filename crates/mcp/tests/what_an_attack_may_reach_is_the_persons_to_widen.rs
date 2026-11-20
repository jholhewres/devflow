//! What an attack may reach is the person's: no tool writes
//! `security.targets`, a target listed by hand is not in force until the
//! person confirmed it on this machine, a name confirmed before devflow kept
//! the addresses it resolved to is confirmed again, and a plan's boundary
//! item that names no abuse case is flagged.

mod common;

use std::path::Path;

use common::Mcp;

use serde_json::{json, Value};

#[test]
fn what_an_attack_may_reach_is_the_persons_to_widen() {
    let repo = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    let root = repo.path().canonicalize().unwrap();
    let mut mcp = Mcp::start(&root, home.path());
    mcp.ask("initialize", json!({ "protocolVersion": "2025-06-18" }));

    let (refused, said) = mcp.answer(
        "setup",
        json!({ "preset": "custom", "set": { "security.targets": ["http://localhost:8080"] } }),
    );
    assert!(
        refused
            && said
                .as_str()
                .unwrap()
                .contains("devflow config set security.targets"),
        "{said}"
    );
    // A check that says which targets it was given.
    let set = json!({ "stages.execution.checks": [{
        "name": "targets", "run": "echo \"$DEVFLOW_SECURITY_TARGETS\" > \"$DEVFLOW_REPORT_DIR/targets.txt\""
    }] });
    let (refused, _) = mcp.answer("setup", json!({ "preset": "custom", "set": set }));
    assert!(!refused);
    let (refused, applied) = mcp.answer(
        "setup",
        json!({ "preset": "custom", "set": set, "apply": true }),
    );
    assert!(!refused && applied["applied"] == true, "{applied}");
    for path in ["security.targets", "security", "security.targets.0"] {
        let (refused, said) = mcp.answer(
            "set",
            json!({ "path": path, "value": ["http://localhost:8080"], "apply": true }),
        );
        assert!(refused, "{path}: {said}");
        assert!(said.as_str().unwrap().contains("in a terminal"), "{said}");
    }
    // Nor is a stack the attack starts.
    let (refused, said) = mcp.answer(
        "setup",
        json!({ "preset": "custom", "set": { "security.stack": "compose.yaml" } }),
    );
    assert!(refused, "{said}");
    let (refused, said) = mcp.answer(
        "set",
        json!({ "path": "security.stack", "value": "compose.yaml", "apply": true }),
    );
    assert!(
        refused && said.as_str().unwrap().contains("in a terminal"),
        "{said}"
    );
    let yaml = root.join(".devflow/devflow.yaml");
    assert!(!std::fs::read_to_string(&yaml).unwrap().contains("security"));

    // An agent's hand edit lists them; none is in force until confirmed.
    let text = std::fs::read_to_string(&yaml).unwrap();
    std::fs::write(
        &yaml,
        format!(
            "{}\nsecurity:\n  targets:\n    - http://localhost:8080\n    - http://127.0.0.1:9000\n",
            text.replace("enabled: false", "enabled: true")
        ),
    )
    .unwrap();
    let key = root.display().to_string();
    let consent = |targets: Value| {
        std::fs::create_dir_all(home.path().join("config/devflow")).unwrap();
        std::fs::write(
            home.path().join("config/devflow/consent.json"),
            json!({ "enabled": [key], "targets": targets }).to_string(),
        )
        .unwrap();
    };
    consent(json!({}));
    let (_, status) = mcp.answer("status", json!({}));
    assert_eq!(status["state"], "active", "{status}");
    assert_eq!(status["targets"]["in_force"], json!([]), "{status}");
    assert_eq!(status["targets"]["left_out"].as_array().unwrap().len(), 2);

    let poc = |target: &str| {
        json!({ "item": "x", "run": "r", "verified": [
            { "finding": 0, "result": "confirmed", "evidence": "401 expected", "target": target }
        ] })
    };
    let (refused, said) = mcp.answer("review", poc("http://127.0.0.1:9000"));
    assert!(
        refused && said.as_str().unwrap().contains("not a target in force"),
        "{said}"
    );

    // A check is given the targets in force: none yet.
    let (refused, item) = mcp.answer("item", json!({ "title": "Sessions expire" }));
    assert!(!refused, "{item}");
    let item = item["item"]
        .as_str()
        .or(item["id"].as_str())
        .unwrap()
        .to_owned();
    let (refused, said) = mcp.answer("start", json!({ "item": item }));
    assert!(!refused, "{said}");
    let given = |mcp: &mut Mcp| {
        let (refused, run) = mcp.answer("evidence", json!({ "item": item, "fresh": true }));
        assert!(!refused, "{run}");
        let file = Path::new(run["run"].as_str().unwrap()).join("targets/targets.txt");
        std::fs::read_to_string(&file).unwrap().trim().to_owned()
    };
    assert_eq!(given(&mut mcp), "");

    // `localhost` as an older consent.json kept it, with no addresses.
    consent(json!({ key.clone(): ["http://127.0.0.1:9000", "http://localhost:8080"] }));
    let (_, status) = mcp.answer("status", json!({}));
    assert_eq!(
        status["targets"]["in_force"],
        json!(["http://127.0.0.1:9000"]),
        "{status}"
    );
    let left = status["targets"]["left_out"][0].as_str().unwrap();
    assert!(
        left.contains("`localhost`") && left.contains("again"),
        "{status}"
    );
    assert_eq!(given(&mut mcp), "http://127.0.0.1:9000");
    let (refused, said) = mcp.answer("review", poc("http://127.0.0.1:9000/me"));
    assert!(
        refused && !said.as_str().unwrap().contains("not a target in force"),
        "{said}"
    );
    let (refused, said) = mcp.answer("review", poc("http://localhost:8080"));
    assert!(
        refused && said.as_str().unwrap().contains("not a target in force"),
        "{said}"
    );

    // A plan's boundary item that names no abuse case is flagged, not refused.
    let (refused, plan) = mcp.answer(
        "plan",
        json!({ "items": [
            { "key": "s1", "title": "Sessions expire", "criteria": ["an old session is refused"], "files": ["src/auth/session.rs"] },
            { "key": "s2", "title": "Uploads are kept", "criteria": ["a file is stored"], "boundary": true,
              "abuse": ["a file named ../../etc/passwd is refused"] }
        ] }),
    );
    assert!(!refused, "{plan}");
    let flagged = plan["unguarded"].as_array().unwrap();
    assert_eq!(flagged.len(), 1, "{plan}");
    assert!(flagged[0].as_str().unwrap().starts_with("s1:"), "{plan}");
}
