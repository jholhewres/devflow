use std::process::Command;

use super::*;

/// What `kill(-1)` or `kill(0)` would reach, and a group this process does
/// not lead, are refused before any signal is sent.
#[test]
fn a_group_is_signalled_only_when_a_spawn_of_ours_leads_it() {
    // Signal 0 checks and sends nothing, so a guard that failed would
    // still harm no one.
    for group in [i32::MIN, -1, 0, 1] {
        assert!(signal_group(group, 0).is_err(), "{group}");
    }
    // SAFETY: plain syscall.
    let own = unsafe { libc::getpgrp() };
    assert!(signal_group(own, 0).is_err(), "this process's own group");
    let mut in_ours = Command::new("sleep").arg("30").spawn().expect("sleep");
    let refused = signal_group(in_ours.id() as i32, 0).expect_err("leads nothing");
    assert!(refused.contains("leads no process group"), "{refused}");
    let _ = in_ours.kill();
    let _ = in_ours.wait();
}

#[test]
fn ending_a_run_ends_its_whole_group_and_only_it() {
    let mut neighbour = Command::new("sleep").arg("30").spawn().expect("sleep");
    let mut run = Command::new("sh");
    run.args(["-c", "sleep 30 & sleep 30"]);
    let mut run = in_a_session_of_its_own(&mut run).spawn().expect("run");
    let group = run.id() as i32;
    assert!(signal_group(group, 0).is_ok(), "its own group, signal 0");
    end_it_all(&mut run);
    let _ = run.wait();
    std::thread::sleep(Duration::from_millis(100));
    // Signal 0 to the group itself: ESRCH once no member is left.
    // SAFETY: a check, no signal is sent; the group is one we made.
    let left = unsafe { libc::kill(-group, 0) };
    assert_eq!(left, -1, "every member of the group is gone");
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(libc::ESRCH)
    );
    assert!(
        neighbour.try_wait().expect("looked").is_none(),
        "a neighbour lives on"
    );
    let _ = neighbour.kill();
    let _ = neighbour.wait();
}
