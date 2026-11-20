//! The `devflow mcp` server driven over stdio, as an agent CLI drives it,
//! for the tests that need the whole server.
#![allow(dead_code)]

use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

use serde_json::{json, Value};

pub struct Mcp {
    child: Child,
    input: ChildStdin,
    output: BufReader<ChildStdout>,
    next: u64,
}

impl Mcp {
    pub fn start(repo: &Path, home: &Path) -> Mcp {
        Mcp::start_with(repo, home, None)
    }

    /// [`Mcp::start`], with `bin` first on the PATH: the agent CLIs a test
    /// fakes.
    pub fn start_with(repo: &Path, home: &Path, bin: Option<&Path>) -> Mcp {
        Mcp::start_env(repo, home, bin, &[])
    }

    /// [`Mcp::start_with`], with variables of its own set.
    pub fn start_env(repo: &Path, home: &Path, bin: Option<&Path>, env: &[(&str, &str)]) -> Mcp {
        let mut command = Command::new(env!("CARGO_BIN_EXE_devflow"));
        command.envs(env.iter().copied());
        if let Some(bin) = bin {
            let path = std::env::var_os("PATH").unwrap_or_default();
            let mut paths = vec![bin.to_path_buf()];
            paths.extend(std::env::split_paths(&path));
            command.env("PATH", std::env::join_paths(paths).unwrap());
        }
        let mut child = command
            .arg("mcp")
            .current_dir(repo)
            .env("HOME", home)
            .env("XDG_CONFIG_HOME", home.join("config"))
            .env("XDG_CACHE_HOME", home.join("cache"))
            .env_remove("OPENROUTER_API_KEY")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let input = child.stdin.take().unwrap();
        let output = BufReader::new(child.stdout.take().unwrap());
        Mcp {
            child,
            input,
            output,
            next: 1,
        }
    }

    pub fn ask(&mut self, method: &str, params: Value) -> Value {
        let id = self.next;
        self.next += 1;
        let line = json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params });
        writeln!(self.input, "{line}").unwrap();
        let mut answer = String::new();
        self.output.read_line(&mut answer).unwrap();
        serde_json::from_str(&answer).unwrap()
    }

    /// A tool's answer, which must not be an error.
    pub fn call(&mut self, name: &str, arguments: Value) -> Value {
        let said = self.ask(
            "tools/call",
            json!({ "name": name, "arguments": arguments }),
        );
        let result = &said["result"];
        assert_eq!(
            result["isError"], false,
            "{name} failed: {}",
            result["content"][0]["text"]
        );
        result["structuredContent"].clone()
    }

    /// A tool's refusal, as text.
    pub fn refused(&mut self, name: &str, arguments: Value) -> String {
        let said = self.ask(
            "tools/call",
            json!({ "name": name, "arguments": arguments }),
        );
        assert_eq!(said["result"]["isError"], true, "{name} did not refuse");
        said["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .to_owned()
    }

    /// One line to the server, as it is: a client's stray message.
    pub fn say(&mut self, message: Value) {
        writeln!(self.input, "{message}").unwrap();
    }

    /// A tool call during which the server may ask the person: each question
    /// (`elicitation/create`) goes to `person`, whose reply goes back. The
    /// call's result, and the questions it asked.
    pub fn call_asking(
        &mut self,
        name: &str,
        arguments: Value,
        person: &mut dyn FnMut(&Value) -> Value,
    ) -> (Value, Vec<Value>) {
        self.call_asking_after(name, arguments, &[], person)
    }

    /// [`Mcp::call_asking`], with `after` written right behind the call,
    /// before any question comes out: a client's lines sent ahead.
    pub fn call_asking_after(
        &mut self,
        name: &str,
        arguments: Value,
        after: &[Value],
        person: &mut dyn FnMut(&Value) -> Value,
    ) -> (Value, Vec<Value>) {
        let id = self.next;
        self.next += 1;
        let line = json!({ "jsonrpc": "2.0", "id": id, "method": "tools/call",
            "params": { "name": name, "arguments": arguments } });
        writeln!(self.input, "{line}").unwrap();
        for one in after {
            writeln!(self.input, "{one}").unwrap();
        }
        let mut questions = Vec::new();
        loop {
            let mut said = String::new();
            assert!(
                self.output.read_line(&mut said).unwrap() > 0,
                "the server hung up"
            );
            let message: Value = serde_json::from_str(&said).unwrap();
            if message["method"] == "elicitation/create" {
                let reply = person(&message["params"]);
                questions.push(message["params"].clone());
                let answer = json!({ "jsonrpc": "2.0", "id": message["id"], "result": reply });
                writeln!(self.input, "{answer}").unwrap();
                continue;
            }
            if message["id"] == id {
                return (message["result"].clone(), questions);
            }
        }
    }

    pub fn answer(&mut self, name: &str, arguments: Value) -> (bool, Value) {
        let said = self.ask(
            "tools/call",
            json!({ "name": name, "arguments": arguments }),
        );
        let result = &said["result"];
        let refused = result["isError"] == true;
        let body = if refused {
            result["content"][0]["text"].clone()
        } else {
            result["structuredContent"].clone()
        };
        (refused, body)
    }
}

impl Drop for Mcp {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
