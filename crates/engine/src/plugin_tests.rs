use serde_json::{json, Value};

use super::*;

const EXE: &str = "/opt/devpit";

fn file<'a>(files: &'a [(String, String)], path: &str) -> &'a str {
    files
        .iter()
        .find(|(at, _)| at == path)
        .map(|(_, text)| text.as_str())
        .unwrap_or_else(|| panic!("no {path} in {files:?}"))
}

/// Codex keys its trust by a SHA-256 of the hook's normal form. These two
/// were computed the way Codex computes them, a way checked against the
/// trust Codex itself recorded for hooks on a real machine.
#[test]
fn a_hook_is_trusted_by_the_hash_codex_computes_for_it() {
    assert_eq!(
        trust_hash(
            "Stop",
            &json!({ "type": "command", "command": "echo hi", "timeout": 600 })
        ),
        "sha256:f2aa169c7a1cf9b7cc9b61ce5ecec0315e0f7d13ac35935b1aa74440f9a839f8"
    );
    let (_, start) = handlers(EXE, Cli::Codex)
        .into_iter()
        .find(|(event, _)| *event == "SessionStart")
        .expect("the session start");
    assert_eq!(
        trust_hash("SessionStart", &start),
        "sha256:84ffb211d2b6aff7888189db4377f1856a2d306ca3d70150038e9bb09e2ea851"
    );
}

/// Each hook on the Codex line comes with the trust for exactly it, keyed
/// where Codex files a hook given with `-c`.
#[test]
fn the_codex_line_trusts_exactly_the_hooks_it_brings() {
    let flags = codex_flags(EXE).expect("flags");
    assert!(flags.starts_with("-c 'hooks={"), "{flags}");
    assert!(flags.ends_with("}'"), "{flags}");
    for (event, handler) in handlers(EXE, Cli::Codex) {
        let key = format!("\"{SESSION_FLAGS}:{}:0:0\"", label(event));
        let trusted = format!("{key}={{trusted_hash=\"{}\"}}", trust_hash(event, &handler));
        assert!(flags.contains(&trusted), "{event}: {flags}");
        assert!(
            flags.contains(&format!("{event}=[{{hooks=[{{")),
            "{event}: {flags}"
        );
    }
    assert!(flags.contains(r#"tool="`gate`""#));
    assert!(flags.contains(r#"command="\"/opt/devpit\" agent devflow-context --agent codex""#));
    assert_eq!(codex_flags("/opt/it's/devpit"), None);
}

#[test]
fn the_stops_call_the_gate_on_devpits_server_and_the_start_asks_for_the_card() {
    let hooks = hooks(EXE, Cli::Claude);
    let one = |event: &str| hooks["hooks"][event][0]["hooks"][0].clone();
    for event in ["Stop", "SubagentStop"] {
        let handler = one(event);
        assert_eq!(handler["type"], "mcp_tool");
        assert_eq!(handler["server"], SERVER);
        assert_eq!(handler["tool"], GATE_TOOL);
        assert_eq!(handler["input"]["event"], event);
        assert_eq!(handler["input"]["stop_hook_active"], "${stop_hook_active}");
    }
    assert_eq!(
        one("SubagentStop")["input"]["transcript"],
        "${agent_transcript_path}"
    );
    let start = one("SessionStart");
    assert_eq!(start["type"], "command", "a tool call is skipped at launch");
    assert_eq!(
        start["command"],
        "\"/opt/devpit\" agent devflow-context --agent claude"
    );
    // What the hooks send is what the gate reads.
    for event in ["Stop", "SubagentStop"] {
        let input = one(event)["input"].clone();
        for key in input.as_object().expect("input").keys() {
            assert!(crate::gate::FIELDS.contains(&key.as_str()), "{key}");
        }
        let asked = crate::gate::asked(&input).expect("the gate reads it");
        assert!(asked.hook.is_some());
    }
}

#[test]
fn claude_codes_plugin_is_named_devflow_with_a_skill_per_stage() {
    let files = claude(EXE);
    let manifest: Value =
        serde_json::from_str(file(&files, ".claude-plugin/plugin.json")).expect("manifest");
    assert_eq!(manifest["name"], "devflow");
    let hooks: Value = serde_json::from_str(file(&files, "hooks/hooks.json")).expect("hooks");
    assert_eq!(hooks, super::hooks(EXE, Cli::Claude));
    for stage in crate::config::STAGES.iter().chain(&["setup"]) {
        let skill = file(&files, &format!("skills/{stage}/SKILL.md"));
        assert!(
            skill.starts_with(&format!("---\nname: {stage}\ndescription: \"")),
            "{skill}"
        );
        assert!(skill.contains("`skill`"), "{skill}");
    }
    assert!(file(&files, "skills/completion/SKILL.md").contains("\"devflow-completion\""));
}

#[test]
fn codexs_plugin_is_a_marketplace_with_the_skills_and_no_hooks() {
    let files = codex(EXE);
    assert!(files.iter().all(|(path, _)| !path.contains("hooks")));
    for name in crate::skills::names() {
        let skill = file(&files, &format!("devflow/skills/{name}/SKILL.md"));
        assert!(
            skill.starts_with(&format!("---\nname: {name}\n")),
            "{skill}"
        );
        assert!(skill.contains(&crate::skills::uri(name)), "{skill}");
    }
    let manifest: Value =
        serde_json::from_str(file(&files, "devflow/plugin.json")).expect("manifest");
    assert_eq!(manifest["name"], "devflow");
    let market: Value =
        serde_json::from_str(file(&files, ".agents/plugins/marketplace.json")).expect("market");
    assert_eq!(market["plugins"][0]["name"], "devflow");
    assert_eq!(market["plugins"][0]["source"]["path"], "./devflow");
}
