//! A host that embeds the engine starts its programs its own way: devpit
//! finds them on the login shell's `PATH` and keeps its AppImage out of
//! them. Its own process, since the spawner is set once for the process.

use std::ffi::OsStr;
use std::process::Command;

fn marked(program: &OsStr) -> Command {
    let mut command = Command::new(program);
    command.env("STARTED_BY", "the host");
    command
}

#[cfg(unix)]
#[test]
fn every_program_the_engine_starts_goes_through_the_hosts_spawner() {
    devflow_engine::env::spawn_with(marked).expect("set once");
    assert!(
        devflow_engine::env::spawn_with(marked).is_err(),
        "set twice"
    );
    let said = devflow_engine::env::command("sh")
        .args(["-c", "printf %s \"$STARTED_BY\""])
        .output()
        .expect("sh ran");
    assert_eq!(String::from_utf8_lossy(&said.stdout), "the host");
}
