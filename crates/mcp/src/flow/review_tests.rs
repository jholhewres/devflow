#[test]
fn a_review_without_an_item_gives_its_readers_no_target() {
    let env = super::standalone_env();
    for name in ["DEVFLOW_SECURITY_TARGETS", "DEVPIT_SECURITY_TARGETS"] {
        assert!(
            env.iter()
                .any(|(said, value)| said == name && value.is_empty()),
            "{env:?}"
        );
    }
}
