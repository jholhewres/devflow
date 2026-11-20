//! The person, asked through the client: MCP's `elicitation/create`. The
//! client shows the question to the person and sends back what they
//! answered. Only that reply, to the question this server sent under an id
//! no one could know before, answers it: a tool's arguments, the
//! environment, the model's text and a reply sent ahead never do.

use std::io::{BufRead, Read, Write};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde_json::{json, Map, Value};

use crate::server::Server;

/// A line longer than this is refused unread: a message is a few kilobytes.
pub const MOST_LINE_BYTES: usize = 8 * 1024 * 1024;
/// How long a question waits for the person before it counts as unanswered.
const WAIT: Duration = Duration::from_secs(15 * 60);
/// What the ids of devflow's questions start with.
const ASKED: &str = "devflow-ask-";
/// How many lines wait read ahead while a tool runs: past that, the client
/// waits, as a pipe makes it.
const AHEAD: usize = 64;
/// How long a no stands in this session: the model cannot ask again and
/// again until the person gives in.
pub const NO_STANDS: Duration = Duration::from_secs(5 * 60);

/// What the client sent, a line at a time.
#[derive(Debug)]
pub enum Incoming {
    Message(String),
    /// A line past [`MOST_LINE_BYTES`], dropped unread.
    TooLong,
    /// The client hung up.
    Closed,
}

/// What the person answered.
#[derive(Debug, Clone, PartialEq)]
pub enum Answer {
    /// Yes, with what they filled in.
    Accepted(Map<String, Value>),
    Declined,
    /// Dismissed, or never answered.
    Cancelled,
    /// The client cannot ask them: why.
    Unasked(String),
}

/// The line to the client, both ways, and whether it can ask the person.
pub struct Person {
    line: Option<Line>,
    /// Set by `initialize`: the client asks the person a form.
    can_ask: AtomicBool,
    asking: AtomicBool,
    closed: AtomicBool,
    next: AtomicU64,
    /// Ids no one can know before the question is sent; counted ones in a
    /// test that feeds the replies ahead.
    random: bool,
    /// When the person last said no, in this session.
    said_no: Mutex<Option<Instant>>,
}

struct Line {
    inbox: Mutex<Receiver<Incoming>>,
    out: Mutex<Box<dyn Write + Send>>,
}

impl Person {
    /// No line: a host's call or a hook, which never asks.
    pub fn none() -> Person {
        Person {
            line: None,
            can_ask: AtomicBool::new(false),
            asking: AtomicBool::new(false),
            closed: AtomicBool::new(false),
            next: AtomicU64::new(1),
            random: true,
            said_no: Mutex::new(None),
        }
    }

    /// The line `inbox` and `out` are.
    pub fn on(inbox: Receiver<Incoming>, out: Box<dyn Write + Send>) -> Person {
        Person {
            line: Some(Line {
                inbox: Mutex::new(inbox),
                out: Mutex::new(out),
            }),
            ..Person::none()
        }
    }

    /// stdin, read on a thread of its own so a question can wait with a
    /// deadline, and stdout.
    pub fn on_stdio() -> Person {
        let (send, inbox) = mpsc::sync_channel(AHEAD);
        std::thread::spawn(move || {
            let mut stdin = std::io::stdin().lock();
            let mut line = String::new();
            loop {
                line.clear();
                let incoming = match (&mut stdin)
                    .take(MOST_LINE_BYTES as u64 + 1)
                    .read_line(&mut line)
                {
                    Ok(0) | Err(_) => Incoming::Closed,
                    Ok(read) if read > MOST_LINE_BYTES && line.ends_with('\n') => Incoming::TooLong,
                    Ok(read) if read > MOST_LINE_BYTES => {
                        // The rest of the line is dropped, not read as the next message.
                        let mut sink = Vec::new();
                        match stdin.read_until(b'\n', &mut sink) {
                            Ok(0) | Err(_) => Incoming::Closed,
                            Ok(_) => Incoming::TooLong,
                        }
                    }
                    Ok(_) => Incoming::Message(line.clone()),
                };
                let last = matches!(incoming, Incoming::Closed);
                if send.send(incoming).is_err() || last {
                    return;
                }
            }
        });
        Person::on(inbox, Box::new(std::io::stdout()))
    }

    /// What the client said it can do, from its `initialize`: a form.
    pub fn initialized(&self, capabilities: &Value) {
        let form = match capabilities.get("elicitation") {
            Some(Value::Object(modes)) => modes.is_empty() || modes.contains_key("form"),
            _ => false,
        };
        self.can_ask.store(form, Ordering::SeqCst);
    }

    /// The next message from the client, waiting at most `wait`; `None`
    /// when nothing came in time.
    pub fn received(&self, wait: Option<Duration>) -> Option<Incoming> {
        let Some(line) = &self.line else {
            return Some(Incoming::Closed);
        };
        if self.closed.load(Ordering::SeqCst) {
            return Some(Incoming::Closed);
        }
        let Ok(inbox) = line.inbox.lock() else {
            return Some(Incoming::Closed);
        };
        let got = match wait {
            None => inbox.recv().map_err(|_| RecvTimeoutError::Disconnected),
            Some(wait) => inbox.recv_timeout(wait),
        };
        match got {
            Ok(Incoming::Closed) | Err(RecvTimeoutError::Disconnected) => {
                self.closed.store(true, Ordering::SeqCst);
                Some(Incoming::Closed)
            }
            Ok(incoming) => Some(incoming),
            Err(RecvTimeoutError::Timeout) => None,
        }
    }

    /// One message to the client, whole.
    pub fn send(&self, message: &str) -> bool {
        let Some(line) = &self.line else {
            return false;
        };
        let Ok(mut out) = line.out.lock() else {
            return false;
        };
        writeln!(out, "{message}")
            .and_then(|()| out.flush())
            .is_ok()
    }

    /// Asks the person `message` with the form `schema`, through the client,
    /// and waits for its reply to this question. A request that comes
    /// meanwhile is answered by `server`; a reply to anything else answers
    /// nothing.
    pub fn ask(&self, server: &Server, message: &str, schema: Value) -> Answer {
        if self.line.is_none() || !self.can_ask.load(Ordering::SeqCst) {
            return Answer::Unasked(
                "this client cannot ask the person (it has no MCP elicitation)".to_owned(),
            );
        }
        if self.asking.swap(true, Ordering::SeqCst) {
            return Answer::Unasked("another question is waiting for the person".to_owned());
        }
        let answer = self.asked(server, message, schema);
        self.asking.store(false, Ordering::SeqCst);
        answer
    }

    /// When the person said no in this session, if it still stands.
    pub fn no_stands(&self) -> Option<Duration> {
        let said = (*self.said_no.lock().ok()?)?;
        let since = said.elapsed();
        (since < NO_STANDS).then_some(since)
    }

    /// The person said no: it stands for [`NO_STANDS`].
    pub fn heard_no(&self) {
        if let Ok(mut said) = self.said_no.lock() {
            *said = Some(Instant::now());
        }
    }

    fn asked(&self, server: &Server, message: &str, schema: Value) -> Answer {
        let counted = self.next.fetch_add(1, Ordering::SeqCst);
        let id = if self.random {
            format!("{ASKED}{}", unguessable())
        } else {
            format!("{ASKED}{counted}")
        };
        let question = json!({
            "jsonrpc": "2.0", "id": id, "method": "elicitation/create",
            "params": { "message": message, "requestedSchema": schema },
        });
        if !self.send(&question.to_string()) {
            return Answer::Unasked("the client cannot be written to".to_owned());
        }
        let until = Instant::now() + WAIT;
        loop {
            let left = until.saturating_duration_since(Instant::now());
            let line = match self.received(Some(left)) {
                None | Some(Incoming::Closed) => return Answer::Cancelled,
                Some(Incoming::TooLong) => {
                    self.send(&crate::server::error(
                        Value::Null,
                        -32600,
                        "that message is too long",
                    ));
                    continue;
                }
                Some(Incoming::Message(line)) => line,
            };
            let Ok(message) = serde_json::from_str::<Value>(&line) else {
                self.send(&crate::server::error(
                    Value::Null,
                    -32700,
                    "that is not JSON",
                ));
                continue;
            };
            if message.get("method").is_some() {
                if let Some(reply) = crate::server::handle(&line, server) {
                    self.send(&reply);
                }
                continue;
            }
            if message.get("id").and_then(Value::as_str) != Some(id.as_str()) {
                continue;
            }
            return replied(&message);
        }
    }
}

/// 128 bits from the system's random source: an id a reply cannot be
/// written for before the question is out. Without that source, a digest of
/// what differs from one moment to the next.
fn unguessable() -> String {
    let mut bytes = [0u8; 16];
    let read = std::fs::File::open("/dev/urandom").and_then(|mut file| file.read_exact(&mut bytes));
    if read.is_err() {
        use sha2::Digest;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        let seed = format!("{now:?} {} {:p}", std::process::id(), &bytes);
        bytes.copy_from_slice(&sha2::Sha256::digest(seed.as_bytes())[..16]);
    }
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// The client's reply to a question, as the person's answer.
fn replied(message: &Value) -> Answer {
    if let Some(failed) = message.get("error") {
        let why = failed["message"].as_str().unwrap_or("it failed");
        return Answer::Unasked(format!("the client could not ask the person: {why}"));
    }
    let result = &message["result"];
    match result["action"].as_str() {
        Some("accept") => {
            Answer::Accepted(result["content"].as_object().cloned().unwrap_or_default())
        }
        Some("decline") => Answer::Declined,
        _ => Answer::Cancelled,
    }
}

#[cfg(test)]
impl Person {
    /// Counted ids, for a test that feeds the client's replies ahead.
    fn counted(self) -> Person {
        Person {
            random: false,
            ..self
        }
    }
}

#[cfg(test)]
#[path = "person_tests.rs"]
mod tests;
