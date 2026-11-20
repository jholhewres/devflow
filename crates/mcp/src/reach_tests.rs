use std::cell::RefCell;
use std::path::Path;
use std::rc::Rc;
use std::sync::mpsc;
use std::sync::{Arc, Mutex};

use serde_json::{json, Value};

use super::*;
use crate::consent::Consent;
use crate::person::{Incoming, Person};

/// What the server wrote to the client, shared with the test.
#[derive(Clone, Default)]
struct Written(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for Written {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Written {
    fn questions(&self) -> usize {
        String::from_utf8(self.0.lock().unwrap().clone())
            .unwrap()
            .lines()
            .filter(|line| line.contains("elicitation/create"))
            .count()
    }
}

/// A session of `client`, which can ask the person or not, whose replies
/// are `from_client`; its consent kept under `home`.
fn session(home: &Path, client: &str, asks: bool, from_client: &[Value]) -> (Server, Written) {
    let (send, inbox) = mpsc::channel();
    for message in from_client {
        send.send(Incoming::Message(message.to_string())).unwrap();
    }
    drop(send);
    let written = Written::default();
    let server = Server {
        cwd: home.to_path_buf(),
        consent: Consent::at(&home.join("devflow")),
        preview: Mutex::new(None),
        person: Person::on(inbox, Box::new(written.clone())).counted(),
    };
    let capabilities = if asks {
        json!({ "elicitation": {} })
    } else {
        json!({})
    };
    server.person.initialized(&capabilities);
    server
        .person
        .introduced(&json!({ "name": client, "version": "2.1.329" }));
    (server, written)
}

/// Claude Code with its user config under `home`, its commands recorded.
fn claude(home: &Path) -> (Claude, Rc<RefCell<Vec<Vec<String>>>>) {
    let ran = Rc::new(RefCell::new(Vec::new()));
    let kept = ran.clone();
    let claude = Claude {
        dir: home.to_path_buf(),
        run: Box::new(move |argv| {
            kept.borrow_mut().push(argv.to_vec());
            Ok(())
        }),
    };
    (claude, ran)
}

fn reply(content: Value) -> Value {
    json!({ "jsonrpc": "2.0", "id": "devflow-ask-1", "result": { "action": "accept", "content": content } })
}

const ADD: [&str; 9] = [
    "claude", "mcp", "add", "--scope", "user", "devflow", "--", "devflow", "mcp",
];

#[test]
fn claude_code_without_the_server_in_its_user_config_is_offered_it_once_and_a_yes_puts_it_there() {
    let home = tempfile::tempdir().unwrap();
    let (server, written) = session(home.path(), CLIENT, true, &[reply(json!({ "add": true }))]);
    let (claude, ran) = claude(home.path());

    let said = offered(&server, &claude).expect("said to Claude Code");
    assert_eq!(said["asked"], "added", "{said}");
    assert_eq!(said["user_config"], true);
    assert_eq!(*ran.borrow(), vec![ADD.map(str::to_owned).to_vec()]);
    assert_eq!(written.questions(), 1);

    // Once in a session: the next status says it and asks nothing.
    let said = offered(&server, &claude).expect("still said");
    assert!(said.get("asked").is_none(), "{said}");
    assert_eq!(said["fix"], CLAUDE_FIX);
    assert_eq!(written.questions(), 1);
    assert_eq!(ran.borrow().len(), 1);
}

#[test]
fn a_no_is_kept_on_the_machine_and_the_offer_is_not_made_again() {
    let home = tempfile::tempdir().unwrap();
    for no in [
        json!({ "jsonrpc": "2.0", "id": "devflow-ask-1", "result": { "action": "decline" } }),
        reply(json!({ "add": false })),
    ] {
        let _ = std::fs::remove_dir_all(home.path().join("devflow"));
        let (server, _) = session(home.path(), CLIENT, true, &[no]);
        let (claude, ran) = claude(home.path());
        let said = offered(&server, &claude).unwrap();
        assert!(
            said["asked"].as_str().unwrap().starts_with("declined"),
            "{said}"
        );
        assert!(ran.borrow().is_empty());
        assert!(server.consent.declined(OFFER));

        // A later session says it, and asks nothing.
        let (later, written) = session(home.path(), CLIENT, true, &[reply(json!({ "add": true }))]);
        let said = offered(&later, &claude).unwrap();
        assert!(said.get("asked").is_none(), "{said}");
        assert_eq!(written.questions(), 0);
        assert!(ran.borrow().is_empty());
    }
}

#[test]
fn nothing_is_put_there_without_the_persons_yes_through_the_client() {
    let home = tempfile::tempdir().unwrap();
    let (claude, ran) = claude(home.path());
    // A client that cannot ask the person: said, never done.
    let (server, written) = session(home.path(), CLIENT, false, &[]);
    let said = offered(&server, &claude).unwrap();
    assert!(
        said["asked"].as_str().unwrap().starts_with("not asked"),
        "{said}"
    );
    assert_eq!(written.questions(), 0);
    // Dismissed: asked again in another session, never done.
    let (server, _) = session(
        home.path(),
        CLIENT,
        true,
        &[json!({ "jsonrpc": "2.0", "id": "devflow-ask-1", "result": { "action": "cancel" } })],
    );
    assert_eq!(offered(&server, &claude).unwrap()["asked"], "dismissed");
    assert!(!server.consent.declined(OFFER));
    // A reply to a question never asked answers nothing.
    let forged = json!({ "jsonrpc": "2.0", "id": "devflow-ask-9", "result": { "action": "accept", "content": { "add": true } } });
    let (server, _) = session(home.path(), CLIENT, true, &[forged]);
    assert_eq!(offered(&server, &claude).unwrap()["asked"], "dismissed");
    assert!(ran.borrow().is_empty());
}

#[test]
fn another_client_or_the_server_already_there_hears_nothing_of_it() {
    let home = tempfile::tempdir().unwrap();
    let (claude, ran) = claude(home.path());
    let (server, written) = session(home.path(), "codex-mcp-client", true, &[]);
    assert_eq!(offered(&server, &claude), None);
    assert_eq!(written.questions(), 0);

    std::fs::write(
        home.path().join(".claude.json"),
        json!({ "mcpServers": { "devflow": { "type": "stdio", "command": "devflow", "args": ["mcp"], "env": {} } } }).to_string(),
    )
    .unwrap();
    let (server, written) = session(home.path(), CLIENT, true, &[]);
    assert_eq!(offered(&server, &claude), None);
    assert_eq!(written.questions(), 0);
    assert!(ran.borrow().is_empty());
}

#[test]
fn a_server_that_runs_something_else_is_replaced_on_a_yes() {
    let home = tempfile::tempdir().unwrap();
    std::fs::write(
        home.path().join(".claude.json"),
        json!({ "mcpServers": { "devflow": { "command": "/opt/bin/devflow", "args": ["mcp"] } } })
            .to_string(),
    )
    .unwrap();
    let (server, _) = session(home.path(), CLIENT, true, &[reply(json!({ "add": true }))]);
    let (claude, ran) = claude(home.path());
    let said = offered(&server, &claude).unwrap();
    assert_eq!(said["asked"], "added", "{said}");
    let ran = ran.borrow();
    assert_eq!(
        ran[0],
        ["claude", "mcp", "remove", "--scope", "user", "devflow"]
            .map(str::to_owned)
            .to_vec()
    );
    assert_eq!(ran[1], ADD.map(str::to_owned).to_vec());
}

#[test]
fn a_failed_add_after_the_old_server_was_taken_out_says_so() {
    let home = tempfile::tempdir().unwrap();
    std::fs::write(
        home.path().join(".claude.json"),
        json!({ "mcpServers": { "devflow": { "command": "/opt/bin/devflow", "args": ["mcp"] } } })
            .to_string(),
    )
    .unwrap();
    let (server, _) = session(home.path(), CLIENT, true, &[reply(json!({ "add": true }))]);
    let claude = Claude {
        dir: home.path().to_path_buf(),
        run: Box::new(|argv| match argv[2].as_str() {
            "remove" => Ok(()),
            _ => Err("`claude mcp add` failed".to_owned()),
        }),
    };
    let said = offered(&server, &claude).unwrap();
    let asked = said["asked"].as_str().unwrap();
    assert!(asked.starts_with("failed:"), "{asked}");
    assert!(
        asked.contains("/opt/bin/devflow mcp") && asked.contains(CLAUDE_FIX),
        "{asked}"
    );
    assert_eq!(said["user_config"], false);
}
