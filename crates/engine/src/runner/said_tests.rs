//! What a command said, read back.

use super::*;

fn read(bytes: &str, channel: Channel) -> Vec<Said> {
    let mut lines = Vec::new();
    each_line(std::io::BufReader::new(bytes.as_bytes()), channel, |said| {
        lines.push(said)
    });
    lines
}

#[test]
fn every_line_carries_the_mouth_that_said_it() {
    let lines = read("one\ntwo\n", Channel::Err);
    assert_eq!(
        lines
            .iter()
            .map(|said| said.text.as_str())
            .collect::<Vec<_>>(),
        ["one", "two"]
    );
    assert!(lines.iter().all(|said| said.channel == Channel::Err));
    assert!(lines.iter().all(|said| !said.cut));
}

/// A command that ends without a newline still said its last line.
#[test]
fn a_last_line_with_no_newline_is_still_a_line() {
    assert_eq!(
        read("done", Channel::Out),
        [Said {
            channel: Channel::Out,
            text: "done".to_owned(),
            cut: false
        }]
    );
}

/// Windows tooling run through `sh` writes CRLF, and a trailing `\r` drawn in
/// a terminal moves the cursor rather than showing anything.
#[test]
fn a_carriage_return_before_the_newline_is_not_part_of_the_line() {
    assert_eq!(read("one\r\n", Channel::Out)[0].text, "one");
}

/// A blank line is a line: a build log's paragraphs are how it is read.
#[test]
fn a_blank_line_is_kept() {
    assert_eq!(read("one\n\ntwo\n", Channel::Out).len(), 3);
}

/// The ceiling holds and says it held. Sabotage: take the `room` clamp out of
/// `keep` and the text comes back whole with `cut` false.
#[test]
fn a_line_past_the_ceiling_is_cut_and_says_so() {
    let long = "x".repeat(LONGEST_LINE + 500);
    let lines = read(&format!("{long}\nshort\n"), Channel::Out);

    assert_eq!(lines[0].text.len(), LONGEST_LINE);
    assert!(lines[0].cut, "a cut line did not say it was cut");
    assert_eq!(lines[1].text, "short");
    assert!(!lines[1].cut, "the cut leaked into the next line");
}

/// Bytes that are no text at all are a log to keep reading, not a line to
/// lose — a linker error carrying a stray byte still names the symbol.
#[test]
fn bytes_that_are_not_text_do_not_lose_the_line() {
    let mut bytes = b"before\xff".to_vec();
    bytes.extend_from_slice(b"after\n");
    let mut lines = Vec::new();
    each_line(std::io::BufReader::new(&bytes[..]), Channel::Out, |said| {
        lines.push(said)
    });

    assert_eq!(lines.len(), 1);
    assert!(lines[0].text.starts_with("before"));
    assert!(lines[0].text.ends_with("after"));
}
