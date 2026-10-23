use super::*;

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
