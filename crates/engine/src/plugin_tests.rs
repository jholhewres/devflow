use serde_json::Value;

use super::*;

fn file<'a>(files: &'a [(String, String)], path: &str) -> &'a str {
    files
        .iter()
        .find(|(at, _)| at == path)
        .map(|(_, text)| text.as_str())
        .unwrap_or_else(|| panic!("no {path} in the plugin"))
}

#[test]
fn every_stage_is_a_skill_that_sends_the_agent_to_the_projects_own() {
    let files = claude();
    for stage in crate::config::STAGES
        .iter()
        .chain(std::iter::once(&"setup"))
    {
        let text = file(&files, &format!("skills/{stage}/SKILL.md"));
        assert!(
            text.starts_with(&format!("---\nname: {stage}\ndescription: \"")),
            "{text}"
        );
        assert!(
            text.contains(&format!("{{ \"name\": \"devflow-{stage}\" }}")),
            "{text}"
        );
        assert!(text.contains(&format!("skill://devflow/devflow-{stage}/SKILL.md")));
    }
}

#[test]
fn the_hooks_run_the_gate_and_the_sessions_context_as_commands() {
    let hooks: Value =
        serde_json::from_str(file(&claude(), "hooks/hooks.json")).expect("hooks.json");
    for (event, said) in [
        ("Stop", "devflow hook stop --agent claude"),
        ("SubagentStop", "devflow hook subagent-stop --agent claude"),
        ("SessionStart", "devflow hook session-start --agent claude"),
    ] {
        let handler = &hooks["hooks"][event][0]["hooks"][0];
        assert_eq!(handler["type"], "command", "{event}");
        assert_eq!(handler["command"], said, "{event}");
        assert!(handler["timeout"].as_u64().is_some_and(|wait| wait > 0));
    }
}

#[test]
fn the_personas_are_subagents_and_the_commands_do_not_shadow_a_skill() {
    let files = claude();
    for (name, _) in PERSONAS {
        let text = file(&files, &format!("agents/{name}.md"));
        assert!(text.starts_with(&format!("---\nname: {name}\n")), "{name}");
        assert!(text.contains("\ntools: "), "{name} names its tools");
    }
    for (name, text) in commands() {
        assert!(
            !crate::config::STAGES.contains(&name) && name != "setup",
            "{name} would shadow a skill"
        );
        assert!(text.starts_with("---\ndescription: \""), "{name}");
    }
}

#[test]
fn every_tool_without_a_plugin_reads_the_same_context() {
    let files = contexts();
    assert_eq!(file(&files, "GEMINI.md"), CONTEXT);
    assert_eq!(file(&files, "integrations/codex/AGENTS.md"), CONTEXT);
    let rule = file(&files, "integrations/cursor/rules/devflow.mdc");
    assert!(rule.starts_with("---\ndescription: "));
    assert!(rule.contains("alwaysApply: true"));
    assert!(rule.contains("Call `status` first"));
}
