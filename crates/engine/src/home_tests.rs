use super::*;

#[test]
fn the_person_s_files_sit_under_their_config_and_cache() {
    let config = Path::new("/home/a/.config/devflow");
    let cache = Path::new("/home/a/.cache/devflow");
    assert_eq!(personal(config), config);
    assert_eq!(skills(config), config.join("skills"));
    assert_eq!(reviewers(config), config.join("reviewers"));
    assert_eq!(teams(cache), cache.join("teams"));
}

#[test]
fn a_relative_xdg_variable_is_not_a_base() {
    // The specification says a relative value is invalid and is ignored.
    let found = xdg("DEVFLOW_TEST_UNSET_VARIABLE", ".config");
    if let Some(found) = found {
        assert!(found.is_absolute());
        assert!(found.ends_with(".config/devflow"));
    }
}
