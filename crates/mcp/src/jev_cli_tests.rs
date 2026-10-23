use super::*;

#[test]
fn a_key_is_one_word() {
    assert!(plain_key("sk-or-v1-abc"));
    assert!(!plain_key(""));
    assert!(!plain_key("sk or"));
    assert!(!plain_key(&"k".repeat(600)));
}
