use clap::Parser;

use super::{Cli, Command};

/// An attack's item, `--promote` and `--run`.
type Read = (Option<String>, Option<String>, Option<String>);

/// What `devflow attack` reads from `args`.
fn attack(args: &[&str]) -> Result<Read, String> {
    let mut argv = vec!["devflow", "attack"];
    argv.extend(args);
    match Cli::try_parse_from(argv)
        .map_err(|err| err.to_string())?
        .command
    {
        Command::Attack {
            item, promote, run, ..
        } => Ok((item, promote, run)),
        _ => Err("not attack".to_owned()),
    }
}

#[test]
fn promote_is_a_flag_and_an_item_named_promote_is_attacked() {
    let some = |text: &str| Some(text.to_owned());
    assert_eq!(attack(&["promote"]), Ok((some("promote"), None, None)));
    assert_eq!(
        attack(&["abc-def", "--promote", "h1", "--run", "r1"]),
        Ok((some("abc-def"), some("h1"), some("r1")))
    );
    assert_eq!(
        attack(&["card_1", "--promote", "h2"]),
        Ok((some("card_1"), some("h2"), None))
    );
    let stray = attack(&["card_1", "--run", "r1"]).expect_err("--run needs --promote");
    assert!(stray.contains("--promote"), "{stray}");
    assert!(
        attack(&["promote", "abc-def", "h1"]).is_err(),
        "the form before 0.7.0 is not read"
    );
    assert!(attack(&["card_1", "--promote", "h1", "--prove", "r1"]).is_err());
}
