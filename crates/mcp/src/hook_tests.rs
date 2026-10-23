use std::sync::Mutex;

use super::*;
use crate::consent::Consent;

fn server(root: &Path) -> Server {
    Server {
        cwd: root.to_path_buf(),
        consent: Consent::at(&root.join(".consent")),
        preview: Mutex::new(None),
    }
}

#[test]
fn where_devflow_is_off_a_hook_says_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let server = server(dir.path());
    let stop = json!({ "hook_event_name": "Stop", "session_id": "s1" });
    assert_eq!(answered(&server, Event::Stop, "claude", &stop), None);
    assert_eq!(
        answered(&server, Event::SessionStart, "claude", &json!({})),
        None
    );
}
