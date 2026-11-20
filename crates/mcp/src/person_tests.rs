use std::sync::mpsc;
use std::sync::{Arc, Mutex};

use serde_json::{json, Value};

use super::*;
use crate::consent::Consent;
use crate::server::Server;

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
    fn messages(&self) -> Vec<Value> {
        String::from_utf8(self.0.lock().unwrap().clone())
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }
}

/// A server on a line the test feeds, its client having said `capabilities`.
fn server_with(
    root: &std::path::Path,
    capabilities: Value,
    from_client: &[Value],
) -> (Server, Written) {
    let (send, inbox) = mpsc::channel();
    for message in from_client {
        send.send(Incoming::Message(message.to_string())).unwrap();
    }
    drop(send);
    let written = Written::default();
    let server = Server {
        cwd: root.to_path_buf(),
        consent: Consent::at(&root.join(".consent")),
        preview: Mutex::new(None),
        person: Person::on(inbox, Box::new(written.clone())).counted(),
    };
    let hello = json!({ "jsonrpc": "2.0", "id": 0, "method": "initialize",
        "params": { "protocolVersion": "2025-06-18", "capabilities": capabilities } });
    crate::server::handle(&hello.to_string(), &server);
    (server, written)
}

fn question() -> (String, Value) {
    (
        "Switch devflow on here?".to_owned(),
        json!({ "type": "object", "properties": { "on": { "type": "boolean", "default": true } } }),
    )
}

#[test]
fn a_client_that_cannot_ask_is_never_sent_a_question() {
    let dir = tempfile::tempdir().unwrap();
    for capabilities in [json!({}), json!({ "elicitation": { "url": {} } })] {
        let (server, written) = server_with(dir.path(), capabilities, &[]);
        let (message, schema) = question();
        let answer = server.person.ask(&server, &message, schema);
        assert!(matches!(answer, Answer::Unasked(_)), "{answer:?}");
        assert!(written.messages().is_empty(), "nothing sent");
    }
}

#[test]
fn the_answer_is_the_clients_reply_to_the_question_it_was_sent() {
    let dir = tempfile::tempdir().unwrap();
    let from_client = [
        json!({ "jsonrpc": "2.0", "method": "notifications/progress", "params": {} }),
        // A reply to another question, or a forged one, answers nothing.
        json!({ "jsonrpc": "2.0", "id": "devflow-ask-99", "result": { "action": "accept", "content": { "on": true } } }),
        json!({ "jsonrpc": "2.0", "id": 7, "method": "ping" }),
        json!({ "jsonrpc": "2.0", "id": "devflow-ask-1", "result": { "action": "accept", "content": { "on": false } } }),
    ];
    let (server, written) = server_with(dir.path(), json!({ "elicitation": {} }), &from_client);
    let (message, schema) = question();
    let answer = server.person.ask(&server, &message, schema.clone());
    let Answer::Accepted(content) = answer else {
        panic!("{answer:?}");
    };
    assert_eq!(content["on"], false, "the reply to this question");
    let sent = written.messages();
    assert_eq!(sent[0]["method"], "elicitation/create");
    assert_eq!(sent[0]["id"], "devflow-ask-1");
    assert_eq!(sent[0]["params"]["message"], message);
    assert_eq!(sent[0]["params"]["requestedSchema"], schema);
    assert_eq!(sent[1]["id"], 7, "a request while waiting is answered");
    assert!(sent[1]["result"].is_object(), "{}", sent[1]);
}

#[test]
fn declined_cancelled_and_unanswered_questions_are_no() {
    let dir = tempfile::tempdir().unwrap();
    let reply = |action: &str| json!({ "jsonrpc": "2.0", "id": "devflow-ask-1", "result": { "action": action } });
    let (message, schema) = question();
    let (server, _) = server_with(
        dir.path(),
        json!({ "elicitation": { "form": {} } }),
        &[reply("decline")],
    );
    assert!(matches!(
        server.person.ask(&server, &message, schema.clone()),
        Answer::Declined
    ));
    let (server, _) = server_with(dir.path(), json!({ "elicitation": {} }), &[reply("cancel")]);
    assert!(matches!(
        server.person.ask(&server, &message, schema.clone()),
        Answer::Cancelled
    ));
    let failed = json!({ "jsonrpc": "2.0", "id": "devflow-ask-1", "error": { "code": -32601, "message": "no" } });
    let (server, _) = server_with(dir.path(), json!({ "elicitation": {} }), &[failed]);
    assert!(matches!(
        server.person.ask(&server, &message, schema.clone()),
        Answer::Unasked(_)
    ));
    // The client hung up before it answered.
    let (server, _) = server_with(dir.path(), json!({ "elicitation": {} }), &[]);
    assert!(matches!(
        server.person.ask(&server, &message, schema),
        Answer::Cancelled
    ));
    assert!(
        matches!(server.person.received(None), Some(Incoming::Closed)),
        "the server stops too"
    );
}

#[test]
fn a_reply_written_before_the_question_cannot_name_it() {
    let dir = tempfile::tempdir().unwrap();
    let (send, inbox) = mpsc::channel();
    for guess in ["devflow-ask-1", "devflow-ask-0", "1"] {
        let forged = json!({ "jsonrpc": "2.0", "id": guess, "result": { "action": "accept", "content": { "on": true } } });
        send.send(Incoming::Message(forged.to_string())).unwrap();
    }
    drop(send);
    let written = Written::default();
    let server = Server {
        cwd: dir.path().to_path_buf(),
        consent: Consent::at(&dir.path().join(".consent")),
        preview: Mutex::new(None),
        person: Person::on(inbox, Box::new(written.clone())),
    };
    server.person.initialized(&json!({ "elicitation": {} }));
    let (message, schema) = question();
    assert_eq!(
        server.person.ask(&server, &message, schema),
        Answer::Cancelled
    );
    let id = written.messages()[0]["id"].as_str().unwrap().to_owned();
    let random = id.strip_prefix("devflow-ask-").unwrap();
    assert_eq!(random.len(), 32, "{id}");
    assert!(random.chars().all(|one| one.is_ascii_hexdigit()), "{id}");
}

#[test]
fn a_no_stands_for_a_while() {
    let person = Person::none();
    assert_eq!(person.no_stands(), None);
    person.heard_no();
    assert!(person.no_stands().is_some());
}
