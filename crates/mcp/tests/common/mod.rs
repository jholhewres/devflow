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
        let mut command = Command::new(env!("CARGO_BIN_EXE_devflow"));
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
