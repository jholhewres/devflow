use super::*;

#[test]
fn the_defaults_are_openrouter_and_jev_with_a_dollar_a_day() {
    let settings = Settings::default();
    assert_eq!(settings.base(), OPENROUTER);
    assert_eq!(settings.model(), OPENROUTER_MODEL);
    assert_eq!(settings.daily_cap_usd, DEFAULT_CAP_USD);
    assert!(settings.checked().is_ok());
}

#[test]
fn a_key_goes_only_to_https_or_this_machine() {
    let plain = Settings {
        url: "http://example.com/v1".to_owned(),
        ..Settings::default()
    };
    assert!(plain.checked().is_err());
    let local = Settings {
        url: "http://127.0.0.1:8080/v1/".to_owned(),
        ..Settings::default()
    };
    assert!(local.checked().is_ok());
    assert_eq!(local.base(), "http://127.0.0.1:8080/v1");
    let spend = Settings {
        daily_cap_usd: 5000.0,
        ..Settings::default()
    };
    assert!(spend.checked().is_err());
}

#[test]
fn settings_are_written_and_read_back() {
    let folder = tempfile::tempdir().unwrap();
    let file = folder.path().join(FILE);
    assert_eq!(Settings::read_at(&file), Settings::default());
    let mine = Settings {
        model: "typesafe/jev-2".to_owned(),
        daily_cap_usd: 2.5,
        ..Settings::default()
    };
    mine.write_at(&file).unwrap();
    assert_eq!(Settings::read_at(&file), mine);
}
