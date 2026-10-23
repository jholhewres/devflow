//! `cargo xtask version-sync`: every manifest carries the version in
//! `VERSION`; `cargo xtask plugin-sync`: the plugin's files are the flow's.
//!
//! Without flags it rewrites them; with `--check` it writes nothing and fails
//! when one disagrees, or, given `--tag`, when the release tag does. The
//! release runs the check before building, so the binaries and the plugin
//! never ship different versions.

use std::path::Path;
use std::process::ExitCode;

use serde_json::Value;

mod plugin;
mod sync;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some((task, rest)) = args.split_first() else {
        eprintln!(
            "usage: cargo xtask version-sync [--check [--tag vX.Y.Z]] | plugin-sync [--check]"
        );
        return ExitCode::from(2);
    };
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    if task == "plugin-sync" {
        return plugin_sync(&root, rest.iter().any(|arg| arg == "--check"));
    }
    if task != "version-sync" {
        eprintln!("xtask: no task `{task}`");
        return ExitCode::from(2);
    }
    let check = rest.iter().any(|arg| arg == "--check");
    let tag = rest
        .iter()
        .position(|arg| arg == "--tag")
        .and_then(|at| rest.get(at + 1));
    if tag.is_some() && !check {
        eprintln!("version-sync: --tag only applies with --check");
        return ExitCode::from(2);
    }
    let result = if check {
        sync::check(&root, tag.map(String::as_str)).map(|version| {
            println!("versions agree: v{version}");
        })
    } else {
        sync::write(&root).map(|version| println!("synced manifests to v{version}"))
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(why) => {
            eprintln!("version-sync: {why}");
            ExitCode::FAILURE
        }
    }
}

fn plugin_sync(root: &Path, check: bool) -> ExitCode {
    let files = devflow_engine::plugin::claude();
    if check {
        let drifted = plugin::drift(root, &files);
        if drifted.is_empty() {
            println!("the plugin's {} files are the flow's", files.len());
            return ExitCode::SUCCESS;
        }
        for one in &drifted {
            eprintln!("plugin-sync: {one}");
        }
        eprintln!("plugin-sync: run `cargo xtask plugin-sync`");
        return ExitCode::FAILURE;
    }
    match plugin::write(root, &files) {
        Ok(written) => {
            println!("wrote {written} of the plugin's {} files", files.len());
            ExitCode::SUCCESS
        }
        Err(why) => {
            eprintln!("plugin-sync: {why}");
            ExitCode::FAILURE
        }
    }
}

/// A JSON file's text as a value, named in the error.
fn read_json(path: &Path) -> Result<Value, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    serde_json::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))
}
