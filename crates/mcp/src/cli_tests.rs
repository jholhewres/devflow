use super::*;

#[test]
fn a_value_is_json_when_it_reads_as_json() {
    assert_eq!(value_of("true"), Value::Bool(true));
    assert_eq!(value_of("[\"high\"]"), serde_json::json!(["high"]));
    assert_eq!(value_of("enforce"), Value::String("enforce".to_owned()));
}

#[test]
fn only_switching_on_and_enforce_are_the_persons_switches() {
    assert_eq!(ask_of("enabled", &Value::Bool(true)), Some(Ask::Enable));
    assert_eq!(ask_of("enabled", &Value::Bool(false)), None);
    assert_eq!(
        ask_of("decisions.mode", &value_of("enforce")),
        Some(Ask::Enforce)
    );
    assert_eq!(ask_of("decisions.mode", &value_of("shadow")), None);
}

#[test]
fn without_a_terminal_nothing_is_written() {
    let dir = tempfile::tempdir().expect("dir");
    std::fs::write(dir.path().join("devflow.yaml"), "version: 2\n").expect("yaml");
    let consent = Consent::at(&dir.path().join(".consent"));
    // `cargo test` gives the tests no terminal on stdin.
    if std::io::stdin().is_terminal() {
        return;
    }
    let refused = setting(dir.path(), "enabled", &Value::Bool(true), &consent);
    assert!(refused.is_err());
    assert!(!consent.made(dir.path(), Ask::Enable));
    assert_eq!(
        std::fs::read_to_string(dir.path().join("devflow.yaml")).expect("read"),
        "version: 2\n"
    );
}
