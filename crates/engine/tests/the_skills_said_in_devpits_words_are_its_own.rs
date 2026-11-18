//! devflow's skills said in the words it ships for devpit read as devpit's
//! own flow/ did, with devflow's newer text in devpit's words: the golden in
//! tests/fixtures/devpit/, compared word by word, line wrapping aside.

use std::path::Path;

use devflow_engine::skills::{phrase_key, rendered, Words};
use devflow_engine::Dialect;

/// Every built-in text: each skill's SKILL.md, and each part.
fn shipped() -> Vec<(String, &'static str)> {
    let assets = Dialect::DEVFLOW.assets;
    let skills = assets
        .skills
        .iter()
        .map(|(name, _, text)| (format!("{name}/SKILL.md"), *text));
    let parts = assets
        .parts
        .iter()
        .map(|(skill, part, text)| (format!("{skill}/{part}.md"), *text));
    skills.chain(parts).collect()
}

fn words_of(text: &str) -> Vec<&str> {
    text.split_whitespace().collect()
}

#[test]
fn every_skill_said_in_devpits_words_is_the_golden() {
    let devpit = Words::shipped("devpit").expect("devflow ships devpit's words");
    let golden = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/devpit");
    for (file, text) in shipped() {
        let want = std::fs::read_to_string(golden.join(&file)).expect(&file);
        let said = rendered(text, &devpit);
        assert_eq!(
            words_of(&said),
            words_of(&want),
            "{file} said in devpit's words"
        );
    }
}

#[test]
fn devpits_words_say_every_phrase_and_only_those() {
    let devpit = Words::shipped("devpit").expect("devflow ships devpit's words");
    let mut used = std::collections::BTreeSet::new();
    for (file, text) in shipped() {
        for (at, _) in text.match_indices("[[") {
            let end = text[at..].find("]]").expect("each phrase is closed");
            let (key, _) = phrase_key(&text[at + 2..at + end]);
            assert!(
                devpit.phrases.contains_key(&key),
                "{file}: devpit has no words for {key:?}"
            );
            used.insert(key);
        }
    }
    let unused: Vec<&String> = devpit
        .phrases
        .keys()
        .filter(|key| !used.contains(*key))
        .collect();
    assert!(
        unused.is_empty(),
        "devpit's words no skill says: {unused:?}"
    );
}

#[test]
fn devflows_own_words_leave_no_mark_behind() {
    for (file, text) in shipped() {
        let said = rendered(text, &Words::default());
        assert!(!said.contains("[[") && !said.contains("{{tool:"), "{file}");
    }
}
