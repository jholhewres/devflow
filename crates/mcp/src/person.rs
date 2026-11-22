//! The person, asked through the client: MCP's `elicitation/create`. The
//! client shows the question to the person and sends back what they
//! answered. Only that reply, to the question this server sent under an id
//! no one could know before, answers it: a tool's arguments, the
//! environment, the model's text and a reply sent ahead never do.

use std::io::{BufRead, Read, Write};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::sync::{Arc, Mutex};
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
    /// Who the client said it is, in its `initialize`.
    client: Mutex<Option<String>>,
    /// An offer was made in this session.
    offered: AtomicBool,
}

/// What writes to the client, shared with the thread that reads it.
type Out = Arc<Mutex<Box<dyn Write + Send>>>;

struct Line {
    inbox: Mutex<Receiver<Incoming>>,
    out: Out,
    /// The id of the tool call running now, which a cancellation names.
    running: Arc<Mutex<Option<String>>>,
}

/// One message to the client, whole, on `out`.
fn write_to(out: &Out, message: &str) -> bool {
    let Ok(mut out) = out.lock() else {
        return false;
    };
    writeln!(out, "{message}")
        .and_then(|()| out.flush())
        .is_ok()
}

/// A message the reading thread answers itself, the moment it comes, even
/// while a tool runs: `ping`, and a cancellation of the call running now.
/// Whether it was one.
fn at_once(line: &str, out: &Out, running: &Mutex<Option<String>>) -> bool {
    let Ok(message) = serde_json::from_str::<Value>(line) else {
        return false;
    };
    match message.get("method").and_then(Value::as_str) {
        Some("ping") => match message.get("id") {
            Some(id) => {
                write_to(
                    out,
                    &json!({ "jsonrpc": "2.0", "id": id, "result": {} }).to_string(),
                );
                true
            }
            None => false,
        },
        Some("notifications/cancelled") => {
            let named = message["params"]["requestId"].to_string();
            if running
                .lock()
                .is_ok_and(|now| now.as_deref() == Some(named.as_str()))
            {
                devflow_engine::call::cancel();
            }
            true
        }
        _ => false,
    }
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
            client: Mutex::new(None),
            offered: AtomicBool::new(false),
        }
    }

    /// The line `inbox` and `out` are.
    #[cfg(test)]
    pub fn on(inbox: Receiver<Incoming>, out: Box<dyn Write + Send>) -> Person {
        Person::on_shared(inbox, Arc::new(Mutex::new(out)), Arc::new(Mutex::new(None)))
    }

    fn on_shared(
        inbox: Receiver<Incoming>,
        out: Out,
        running: Arc<Mutex<Option<String>>>,
    ) -> Person {
        Person {
            line: Some(Line {
                inbox: Mutex::new(inbox),
                out,
                running,
            }),
            ..Person::none()
        }
    }

    /// stdin, read on a thread of its own so a question can wait with a
    /// deadline, and a ping or a cancellation is heard while a tool runs;
    /// and stdout.
    pub fn on_stdio() -> Person {
        let (send, inbox) = mpsc::sync_channel(AHEAD);
        let out: Out = Arc::new(Mutex::new(Box::new(std::io::stdout())));
        let running = Arc::new(Mutex::new(None));
        let (to_client, call) = (Arc::clone(&out), Arc::clone(&running));
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
                    Ok(_) if at_once(&line, &to_client, &call) => continue,
                    Ok(_) => Incoming::Message(line.clone()),
                };
                let last = matches!(incoming, Incoming::Closed);
                if send.send(incoming).is_err() || last {
                    return;
                }
            }
        });
        Person::on_shared(inbox, out, running)
    }

    /// The tool call running now, by its id; `None` once it ended.
    pub fn running(&self, id: Option<&Value>) {
        if let Some(line) = &self.line {
            if let Ok(mut now) = line.running.lock() {
                *now = id.map(Value::to_string);
            }
        }
    }

    /// What says a call's progress to the client, as MCP's
    /// `notifications/progress` under the `token` its request gave.
    pub fn progress_to(&self, token: &Value) -> Option<devflow_engine::call::Progress> {
        let out = Arc::clone(&self.line.as_ref()?.out);
        let token = token.clone();
        let done = AtomicU64::new(0);
        Some(Box::new(move |step: &str| {
            let progress = done.fetch_add(1, Ordering::SeqCst) + 1;
            let note = json!({ "jsonrpc": "2.0", "method": "notifications/progress",
                "params": { "progressToken": token, "progress": progress, "message": step } });
            write_to(&out, &note.to_string());
        }))
    }

    /// What the client said it can do, from its `initialize`: a form.
    pub fn initialized(&self, capabilities: &Value) {
        let form = match capabilities.get("elicitation") {
            Some(Value::Object(modes)) => modes.is_empty() || modes.contains_key("form"),
            _ => false,
        };
        self.can_ask.store(form, Ordering::SeqCst);
    }

    /// Who the client is, from the `clientInfo` of its `initialize`.
    pub fn introduced(&self, client_info: &Value) {
        let name = client_info
            .get("name")
            .and_then(Value::as_str)
            .map(str::to_owned);
        if let Ok(mut client) = self.client.lock() {
            *client = name;
        }
    }

    /// The client's name, as it gave it.
    pub fn client(&self) -> Option<String> {
        self.client.lock().ok()?.clone()
    }

    /// True the first time only: an offer is made once in a session.
    pub fn offer_once(&self) -> bool {
        !self.offered.swap(true, Ordering::SeqCst)
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
        self.line
            .as_ref()
            .is_some_and(|line| write_to(&line.out, message))
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
            // A cancelled call stops waiting for the person.
            if devflow_engine::call::cancelled() {
                return Answer::Cancelled;
            }
            let left = until.saturating_duration_since(Instant::now());
            let line = match self.received(Some(left.min(Duration::from_secs(1)))) {
                None if !left.is_zero() => continue,
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
    pub(crate) fn counted(self) -> Person {
        Person {
            random: false,
            ..self
        }
    }
}

#[cfg(test)]
#[path = "person_tests.rs"]
mod tests;
