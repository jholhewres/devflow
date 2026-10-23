use super::*;

#[test]
fn each_cli_is_asked_in_its_own_print_mode_and_read_only() {
    let claude = argv(Cli::Claude, Some("opus"), "the packet");
    assert_eq!(claude[..3], ["-p", "--output-format", "json"]);
    assert!(claude.windows(2).any(|pair| pair == ["--model", "opus"]));
    assert!(claude.contains(&"Bash(git diff:*)".to_owned()));
    assert!(!claude.contains(&"the packet".to_owned()), "on stdin");

    let codex = argv(Cli::Codex, None, "the packet");
    assert_eq!(codex[..3], ["exec", "--sandbox", "read-only"]);
    assert_eq!(codex.last().map(String::as_str), Some("-"));

    let cursor = argv(Cli::Cursor, None, "the packet");
    assert_eq!(cursor.last().map(String::as_str), Some("the packet"));
    let gemini = argv(Cli::Gemini, None, "the packet");
    assert!(gemini.ends_with(&["-p".to_owned(), "the packet".to_owned()]));

    assert!(on_stdin(Cli::Claude) && on_stdin(Cli::Codex));
    assert!(!on_stdin(Cli::Cursor) && !on_stdin(Cli::Gemini));
    assert_eq!(Cli::Cursor.program(), "cursor-agent");
    assert_eq!(Cli::of("codex"), Some(Cli::Codex));
    assert_eq!(Cli::of("aider"), None);
    let opencode = argv(Cli::OpenCode, Some("anthropic/claude"), "the packet");
    assert_eq!(
        opencode,
        [
            "run",
            "--agent",
            "plan",
            "--model",
            "anthropic/claude",
            "--",
            "the packet"
        ]
    );
    assert!(!on_stdin(Cli::OpenCode));
    assert_eq!(Cli::of("opencode"), Some(Cli::OpenCode));
}

#[test]
fn the_answer_and_its_cost_are_read_from_each_clis_shape() {
    let claude =
        r#"{"type":"result","is_error":false,"result":"{\"version\":1}","total_cost_usd":0.25}"#;
    assert_eq!(
        answer_of(Cli::Claude, claude),
        Ok(("{\"version\":1}".to_owned(), Some(0.25)))
    );
    let cursor = r#"{"type":"result","is_error":false,"result":"{}"}"#;
    assert_eq!(answer_of(Cli::Cursor, cursor), Ok(("{}".to_owned(), None)));
    let gemini = r#"{"response":"{}","stats":{}}"#;
    assert_eq!(answer_of(Cli::Gemini, gemini), Ok(("{}".to_owned(), None)));
    let codex = "{\"version\":1}\n";
    assert_eq!(answer_of(Cli::Codex, codex), Ok((codex.to_owned(), None)));

    let failed =
        r#"{"type":"result","is_error":true,"result":"Invalid API key · Please run /login"}"#;
    let why = answer_of(Cli::Claude, failed).expect_err("an error");
    assert!(signed_out(&why), "{why}");
}

/// `"verbose": true` in the person's settings: every event of the run, the
/// result last. Read as one result, it was "invalid JSON" on every review.
#[test]
fn a_verbose_run_is_read_from_its_last_result() {
    let verbose = r#"[
        {"type":"system","subtype":"init","tools":["Read"]},
        {"type":"assistant","message":{"content":[{"type":"text","text":"looking"}]}},
        {"type":"result","is_error":false,"result":"{\"version\":1}","total_cost_usd":0.5}
    ]"#;
    assert_eq!(
        answer_of(Cli::Claude, verbose),
        Ok(("{\"version\":1}".to_owned(), Some(0.5)))
    );
    let unfinished = r#"[{"type":"system","subtype":"init"}]"#;
    assert!(answer_of(Cli::Claude, unfinished).is_err());
}

#[test]
fn a_cli_that_is_not_signed_in_is_told_from_one_that_failed() {
    assert!(signed_out("Error: Not logged in. Run `codex login`."));
    assert!(signed_out("Please run /login"));
    assert!(!signed_out("error: unexpected argument '--sandbox'"));
}

/// A script written by a child process: a file this process held open for
/// writing is inherited by whatever another test forks meanwhile, and
/// running it then fails with "text file busy".
#[cfg(unix)]
fn written_apart(path: &Path, text: &str) {
    let done = std::process::Command::new("sh")
        .args([
            "-c",
            "printf '%s' \"$1\" > \"$2\" && chmod 755 \"$2\"",
            "sh",
            text,
        ])
        .arg(path)
        .status()
        .expect("sh");
    assert!(done.success(), "{done}");
}

#[cfg(unix)]
fn fake(dir: &Path, name: &str, body: &str) -> String {
    let path = dir.join(name);
    written_apart(&path, &format!("#!/bin/sh\n{body}\n"));
    path.display().to_string()
}

#[cfg(unix)]
#[test]
fn a_review_reads_its_prompt_from_stdin_and_its_context_from_the_environment() {
    let dir = tempfile::tempdir().expect("tempdir");
    let program = fake(
        dir.path(),
        "reads-stdin",
        r#"prompt=$(cat); printf '{"type":"result","is_error":false,"result":"%s on %s","total_cost_usd":0.5}' "$prompt" "$DEVFLOW_ITEM""#,
    );
    let env = [("DEVFLOW_ITEM".to_owned(), "item_1".to_owned())];
    let said = review(&Review {
        agent: &Cli::Claude,
        program: &program,
        prompt: "reviewed",
        cwd: dir.path(),
        model: None,
        env: &env,
        deadline: Duration::from_secs(20),
    })
    .expect("an answer");
    assert_eq!(said.text, "reviewed on item_1");
    assert_eq!(said.cost_usd, Some(0.5));
}

#[cfg(unix)]
#[test]
fn a_missing_cli_a_signed_out_one_and_a_hung_one_each_say_why() {
    let dir = tempfile::tempdir().expect("tempdir");
    let asked = |program: &str, deadline: Duration| {
        review(&Review {
            agent: &Cli::Codex,
            program,
            prompt: "p",
            cwd: dir.path(),
            model: None,
            env: &[],
            deadline,
        })
    };
    let missing = dir.path().join("no-such-cli").display().to_string();
    assert_eq!(
        asked(&missing, Duration::from_secs(5)),
        Err(Unreviewed::Missing)
    );
    let signed_out = fake(dir.path(), "signed-out", "echo 'Not logged in' >&2; exit 1");
    assert!(matches!(
        asked(&signed_out, Duration::from_secs(20)),
        Err(Unreviewed::SignedOut(_))
    ));
    let hung = fake(dir.path(), "hung", "sleep 30");
    assert_eq!(
        asked(&hung, Duration::from_millis(300)),
        Err(Unreviewed::TimedOut)
    );
}

/// A headless security reviewer cost US$ 8.54 on three PRs: every MCP server
/// of the person's loaded, and no end to its turns.
#[test]
fn a_claude_reviewer_loads_no_mcp_server_and_has_a_last_turn() {
    let claude = argv(Cli::Claude, None, "the packet");
    assert!(claude.contains(&"--strict-mcp-config".to_owned()));
    let turns = CLAUDE_TURNS.to_string();
    assert!(claude
        .windows(2)
        .any(|pair| pair[0] == "--max-turns" && pair[1] == turns));
    // --allowedTools takes every argument after it.
    let allowed = claude
        .iter()
        .position(|one| one == "--allowedTools")
        .expect("listed");
    assert!(claude[allowed + 1..]
        .iter()
        .all(|one| !one.starts_with("--")));

    let ran_out =
        r#"{"type":"result","subtype":"error_max_turns","is_error":false,"num_turns":61}"#;
    let why = answer_of(Cli::Claude, ran_out).expect_err("no answer");
    assert!(why.contains("turns"), "{why}");
}
