use super::*;

#[cfg(unix)]
#[test]
fn the_key_is_kept_for_the_person_only_and_read_back() {
    use std::os::unix::fs::PermissionsExt;
    let folder = tempfile::tempdir().expect("folder");
    let file = folder.path().join("credentials");
    std::fs::write(&file, "other = 1\nopenrouter_api_key = old\n").expect("write");
    write_key(&file, " sk-or-new ").expect("written");
    let mode = std::fs::metadata(&file).expect("meta").permissions().mode();
    assert_eq!(mode & 0o777, 0o600);
    assert_eq!(read_key(&file).as_deref(), Some("sk-or-new"));
    let text = std::fs::read_to_string(&file).expect("read");
    assert!(text.contains("other = 1"));
    assert_eq!(text.matches(KEY).count(), 1);
}

#[cfg(unix)]
#[test]
fn the_key_is_read_from_its_line() {
    use std::os::unix::fs::PermissionsExt;
    let folder = tempfile::tempdir().expect("folder");
    let file = folder.path().join("credentials");
    std::fs::write(&file, "other = 1\nopenrouter_api_key = \"sk-or-x\"\n").expect("write");
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).expect("mode");
    assert_eq!(read_key(&file).as_deref(), Some("sk-or-x"));
}

#[cfg(unix)]
#[test]
fn a_credentials_file_others_can_read_is_not_used() {
    use std::os::unix::fs::PermissionsExt;
    let folder = tempfile::tempdir().expect("folder");
    let file = folder.path().join("credentials");
    std::fs::write(&file, "openrouter_api_key = sk-or-x\n").expect("write");
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).expect("mode");
    assert_eq!(read_key(&file), None);
}

#[cfg(unix)]
#[test]
fn a_forgotten_key_leaves_the_rest_of_the_file() {
    let folder = tempfile::tempdir().expect("folder");
    let file = folder.path().join("credentials");
    write_key(&file, "sk-or-x").expect("written");
    assert!(forget_key(&file).expect("forgot"));
    assert!(!file.exists(), "nothing else was in it");
    assert!(!forget_key(&file).expect("again"));
}
