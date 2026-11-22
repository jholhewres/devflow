//! `devflow register` and `devflow unregister`: devflow added to, or taken
//! out of, each agent CLI and IDE found here or named.

use std::process::ExitCode;

use crate::{register, Registering};

pub fn registering(how: &Registering, on: bool) -> ExitCode {
    let machine = register::Machine::here();
    let tools = match register::chosen(how.tools.as_deref(), &machine) {
        Ok(tools) => tools,
        Err(why) => {
            eprintln!("devflow: {why}");
            return ExitCode::from(2);
        }
    };
    if tools.is_empty() {
        println!("No agent CLI or IDE found here; name one with --tools.");
        return ExitCode::SUCCESS;
    }
    // Configs read without the shell's PATH get the binary whole.
    let bin = how
        .bin
        .clone()
        .map(Ok)
        .unwrap_or_else(std::env::current_exe)
        .and_then(|path| path.canonicalize().or(Ok(path)))
        .map(|path| path.display().to_string())
        .unwrap_or_else(|_| register::NAME.to_owned());
    let mut failed = false;
    for tool in tools {
        let steps = if on {
            register::register(tool, &bin, &machine)
        } else {
            register::unregister(tool, &machine)
        };
        for step in steps {
            match register::carry(&step, how.dry_run) {
                Ok(said) => println!("{}: {said}", tool.id()),
                Err(why) => {
                    failed = true;
                    eprintln!("{}: {why}", tool.id());
                }
            }
        }
    }
    if failed {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}
