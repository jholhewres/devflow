use std::fs;

use super::*;

fn write(root: &Path, relative: &str) {
    let path = root.join(relative);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, "version: 2\n").unwrap();
}

#[test]
fn a_project_with_no_file_has_no_configuration() {
    let dir = tempfile::tempdir().unwrap();
    assert_eq!(config_in(dir.path()), None);
}

#[test]
fn the_root_file_wins_over_the_folder_and_devpit() {
    let dir = tempfile::tempdir().unwrap();
    write(dir.path(), DEVPIT);
    write(dir.path(), ".devflow/devflow.yaml");
    write(dir.path(), FILE);

    assert_eq!(config_in(dir.path()).unwrap().origin, Origin::Root);
}

#[test]
fn the_folder_wins_over_devpit() {
    let dir = tempfile::tempdir().unwrap();
    write(dir.path(), DEVPIT);
    write(dir.path(), ".devflow/devflow.yaml");

    assert_eq!(config_in(dir.path()).unwrap().origin, Origin::Folder);
}

#[test]
fn a_devpit_project_is_read_where_it_is() {
    let dir = tempfile::tempdir().unwrap();
    write(dir.path(), DEVPIT);

    let found = config_in(dir.path()).unwrap();
    assert_eq!(found.origin, Origin::Devpit);
    assert!(found.path.ends_with(DEVPIT));
}

#[test]
fn a_folder_named_like_the_file_is_not_a_configuration() {
    let dir = tempfile::tempdir().unwrap();
    fs::create_dir(dir.path().join(FILE)).unwrap();

    assert_eq!(config_in(dir.path()), None);
}

#[cfg(unix)]
#[test]
fn a_symlink_out_of_the_root_is_not_the_projects() {
    let outside = tempfile::tempdir().unwrap();
    write(outside.path(), FILE);
    let dir = tempfile::tempdir().unwrap();
    std::os::unix::fs::symlink(outside.path().join(FILE), dir.path().join(FILE)).unwrap();

    assert_eq!(config_in(dir.path()), None);
}
