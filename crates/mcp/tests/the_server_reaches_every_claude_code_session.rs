//! devflow's server reaches a Claude Code session through the devflow
//! plugin, which another plugin named devflow hides (`claude --plugin-dir`,
//! as devpit starts its sessions). `status` tells Claude Code so and, on the
//! person's yes to the question asked through the client, puts the server in
//! their Claude Code user config, which every session reads. A tool's
//! arguments never put it there.

mod common;

use std::path::{Path, PathBuf};

use common::Mcp;
use serde_json::{json, Value};

/// A fake `claude` in `bin` that only writes down how it was run.
#[cfg(unix)]
fn fake_claude(bin: &Path) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    std::fs::create_dir_all(bin).unwrap();
    let log = bin.join("claude.log");
    let script = bin.join("claude");
    std::fs::write(
        &script,
        format!("#!/bin/sh\necho \"$*\" >> '{}'\n", log.display()),
    )
    .unwrap();
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
    log
}

fn hello(asks: bool) -> Value {
    let capabilities = if asks {
        json!({ "elicitation": { "form": {} } })
    } else {
        json!({})
    };
    json!({ "protocolVersion": "2025-11-25", "capabilities": capabilities,
        "clientInfo": { "name": "claude-code", "title": "Claude Code", "version": "2.1.329" } })
}

#[cfg(unix)]
#[test]
fn a_yes_puts_devflows_server_in_claude_codes_user_config_once() {
    let repo = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    let bin = home.path().join("bin");
    let log = fake_claude(&bin);
    let config = home.path().join("claude-config");
    let config_dir = config.display().to_string();
    let env = [("CLAUDE_CONFIG_DIR", config_dir.as_str())];

    let mut mcp = Mcp::start_env(repo.path(), home.path(), Some(&bin), &env);
    mcp.ask("initialize", hello(true));
    let (result, questions) = mcp.call_asking(
        "status",
        json!({}),
        &mut |_| json!({ "action": "accept", "content": { "add": true } }),
    );
    assert_eq!(questions.len(), 1);
    let asked = questions[0]["message"].as_str().unwrap();
    assert!(asked.contains("another plugin named devflow"), "{asked}");
    let claude = &result["structuredContent"]["claude_code"];
    assert_eq!(claude["asked"], "added", "{claude}");
    let ran = std::fs::read_to_string(&log).unwrap();
    assert_eq!(ran.trim(), "mcp add --scope user devflow -- devflow mcp");

    // Once in a session.
    let (result, questions) = mcp.call_asking("status", json!({}), &mut |_| {
        panic!("asked again");
    });
    assert!(questions.is_empty());
    assert!(result["structuredContent"]["claude_code"]
        .get("asked")
        .is_none());

    // With it in the user config, a session hears nothing of it.
    std::fs::create_dir_all(&config).unwrap();
    std::fs::write(
        config.join(".claude.json"),
        json!({ "mcpServers": { "devflow": { "type": "stdio", "command": "devflow", "args": ["mcp"], "env": {} } } })
            .to_string(),
    )
    .unwrap();
    let mut mcp = Mcp::start_env(repo.path(), home.path(), Some(&bin), &env);
    mcp.ask("initialize", hello(true));
    let status = mcp.call("status", json!({}));
    assert!(status.get("claude_code").is_none(), "{status}");
}

#[cfg(unix)]
#[test]
fn a_tools_arguments_never_put_it_there() {
    let repo = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    let bin = home.path().join("bin");
    let log = fake_claude(&bin);
    let mut mcp = Mcp::start_with(repo.path(), home.path(), Some(&bin));
    // A client that cannot ask the person, and a model that answers for them.
    mcp.ask("initialize", hello(false));
    let status = mcp.call(
        "status",
        json!({ "add": true, "consent": true,
            "answer": { "action": "accept", "content": { "add": true } } }),
    );
    let claude = &status["claude_code"];
    assert!(
        claude["asked"].as_str().unwrap().starts_with("not asked"),
        "{claude}"
    );
    assert_eq!(claude["fix"], "devflow register --tools=claude");
    assert!(!log.exists(), "claude was run");
    assert!(!home.path().join(".claude.json").exists());
}
