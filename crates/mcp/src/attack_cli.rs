//! `devflow attack`: an item attacked, a release range attacked headless as
//! CI runs it, a run's report printed, and an exploit an attack kept copied
//! into the repository.

use std::process::ExitCode;

use crate::{flow, project, server};

/// `devflow attack <item> --report <run>`: the run's report in `format`,
/// written beside it with its drafts, and printed.
pub fn reporting(root: &std::path::Path, item: &str, run: &str, format: &str) -> ExitCode {
    use devflow_engine::attack_report::{self, Format};
    let Some(format) = Format::of(format) else {
        eprintln!("devflow attack: --format is md, json or sarif");
        return ExitCode::FAILURE;
    };
    let project = project::Project::at(root);
    let runs = project.runs();
    let Some(at) = runs.found(item, Some(run), devflow_engine::attack::REPORT) else {
        eprintln!("devflow attack: run {run} of {item} has no attack report");
        return ExitCode::FAILURE;
    };
    let Some(report) = flow::json_at(&at) else {
        eprintln!("devflow attack: {} does not read", at.display());
        return ExitCode::FAILURE;
    };
    let folder = at.parent().unwrap_or(&at);
    if let Err(why) = attack_report::written(folder, &report) {
        eprintln!("devflow attack: {why}");
        return ExitCode::FAILURE;
    }
    let Ok(said) = std::fs::read_to_string(folder.join(format.file())) else {
        eprintln!("devflow attack: {} does not read", format.file());
        return ExitCode::FAILURE;
    };
    print!("{said}");
    ExitCode::SUCCESS
}

/// `devflow attack <item|range> --promote <hypothesis>`: an exploit an
/// attack kept, in the vault or in an item's run, copied into the
/// repository at its path.
pub fn promoting(
    root: &std::path::Path,
    subject: &str,
    hypothesis: &str,
    run: Option<&str>,
) -> ExitCode {
    use devflow_engine::{attack, vault};
    let failed = |why: String| {
        eprintln!("devflow attack --promote: {why}");
        ExitCode::FAILURE
    };
    let project = project::Project::at(root);
    let mut places = Vec::new();
    if let Ok(home) = vault::home(&project.cache(), &project.root) {
        places.push(vault::runs(home, &project.root));
    }
    places.push(project.runs());
    let found = places.iter().find_map(|runs| match run {
        Some(run) => runs.found(subject, Some(run), attack::REPORT),
        None => runs.newest_with(subject, attack::REPORT).map(|(_, at)| at),
    });
    let Some(at) = found else {
        return failed(format!("{subject} has no attack report"));
    };
    // A report the repository carries never brings an exploit in.
    if let Ok(relative) = at.strip_prefix(&project.root) {
        if devflow_engine::git::tracked(&project.root, &relative.display().to_string())
            .unwrap_or(true)
        {
            return failed(format!(
                "{} is part of the repository, or git cannot say",
                relative.display()
            ));
        }
    }
    let Some(report) = flow::json_at(&at) else {
        return failed(format!("{} does not read", at.display()));
    };
    let folder = at.parent().unwrap_or(&at);
    match vault::promote(&project.root, folder, &report, hypothesis) {
        Ok(path) => {
            println!("{hypothesis}'s exploit copied to {path}");
            ExitCode::SUCCESS
        }
        Err(why) => failed(why),
    }
}

/// A release range's two ends: `A..B` or `A...B`.
fn range_ends(range: &str) -> Option<(&str, &str)> {
    let (base, head) = range.split_once("...").or_else(|| range.split_once(".."))?;
    (!base.is_empty() && !head.is_empty() && !head.contains("..")).then_some((base, head))
}

/// `devflow attack --range A..B`: the range attacked headless, as CI runs
/// it. Its report's SARIF and JUnit are written to `sarif` and `junit`;
/// the exit code is 1 when a confirmed exploit is in review.block_on, 2
/// when the attack could not run (a budget spent, no attacker answered),
/// and each hypothesis no sandbox ran is warned of, never passed quietly.
pub fn ranging(
    root: &std::path::Path,
    range: &str,
    sarif: &std::path::Path,
    junit: &std::path::Path,
) -> ExitCode {
    use devflow_engine::{attack, attack_report};
    let could_not = |why: String| {
        eprintln!("devflow attack: {why}");
        ExitCode::from(2)
    };
    let Some((base, head)) = range_ends(range) else {
        return could_not(format!("`{range}` is not a range: give it as A..B"));
    };
    let server = server::Server::new(root);
    let project = project::Project::at(root);
    let state = project.read();
    let block_on = match flow::config_for(&project, &state, &server.consent, "attack") {
        Ok(config) => config.review.block_on.clone(),
        Err(why) => return could_not(why),
    };
    let asked = serde_json::json!({ "base": base, "head": head });
    let said = match flow::attack::attack(&server, asked) {
        Ok(said) => said,
        Err(why) => return could_not(why),
    };
    let folder = std::path::PathBuf::from(said["vault"].as_str().unwrap_or_default());
    let Some(report) = flow::json_at(&folder.join(attack::REPORT)) else {
        return could_not(format!(
            "{} does not read",
            folder.join(attack::REPORT).display()
        ));
    };
    if attack::failed(&report).is_some() {
        // Their reasons are theirs: the log names where they are.
        return could_not(format!(
            "no attacker answered: why is in {}",
            folder.join(attack::REPORT).display()
        ));
    }
    let known = attack_report::Known::of(&report);
    let written = [
        (
            sarif,
            serde_json::to_string_pretty(&attack_report::sarif(&report, &known))
                .unwrap_or_default()
                + "\n",
        ),
        (junit, attack_report::junit(&report, &block_on)),
    ];
    for (at, text) in written {
        // A link planted at the path would carry the write elsewhere.
        if std::fs::symlink_metadata(at).is_ok_and(|meta| meta.file_type().is_symlink()) {
            return could_not(format!("{} is a link: name a file", at.display()));
        }
        if let Err(err) = std::fs::write(at, text) {
            return could_not(format!("{}: {err}", at.display()));
        }
    }
    // The job's log says what devflow sets, never the attack's own words.
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "run": said["run"], "verdict": report["verdict"], "counts": report["counts"],
            "vault": folder, "sarif": sarif, "junit": junit,
        }))
        .unwrap_or_default()
    );
    let not_run = attack_report::not_run(&report);
    let annotate = std::env::var("GITHUB_ACTIONS").is_ok_and(|on| on == "true");
    for (id, why) in &not_run {
        let said = format!(
            "{id} was not run, so it proves nothing either way: {why}. Set stages.attack.test and a sandbox (bwrap or docker) the runner has."
        );
        eprintln!("warning: devflow attack: {said}");
        if annotate {
            println!("::warning title=devflow attack::{said}");
        }
    }
    let held = attack_report::held(&report, &block_on);
    for one in &held {
        let said = format!(
            "{} {} confirmed at {}:{}",
            one["severity"].as_str().unwrap_or("?"),
            one["class"].as_str().unwrap_or("other"),
            one["file"].as_str().unwrap_or("<…>"),
            one["line"]
        );
        eprintln!("devflow attack: {said}");
        if annotate {
            println!("::error title=devflow attack::{said}");
        }
    }
    for one in attack_report::env_held(&report, &block_on) {
        let said = format!(
            "{} {} could not run (env_error) at {}:{}: fix stages.attack.test, or run it in the session",
            one["severity"].as_str().unwrap_or("?"),
            one["class"].as_str().unwrap_or("other"),
            one["file"].as_str().unwrap_or("<…>"),
            one["line"].as_u64().unwrap_or_default()
        );
        eprintln!("devflow attack: {said}");
        if annotate {
            println!("::error title=devflow attack::{said}");
        }
    }
    ExitCode::from(ci_exit(&report, &block_on))
}

/// A CI run's exit code: 1 when a confirmed exploit is in `block_on`, or
/// one that could not run holds as it would, else 0.
fn ci_exit(report: &serde_json::Value, block_on: &[devflow_engine::config::Severity]) -> u8 {
    u8::from(
        !devflow_engine::attack_report::held(report, block_on).is_empty()
            || !devflow_engine::attack::env_held(report, block_on).is_empty(),
    )
}

/// `devflow attack`: the attack tool's answer, printed as JSON.
pub fn attacking(
    root: &std::path::Path,
    item: &str,
    base: Option<&str>,
    prove: Option<&str>,
    flow: Option<&str>,
) -> ExitCode {
    let server = server::Server::new(root);
    let mut asked = serde_json::json!({ "item": item });
    if let Some(flow) = flow {
        asked["flow"] = serde_json::json!(flow);
    }
    if let Some(base) = base {
        asked["base"] = serde_json::json!(base);
    }
    if let Some(run) = prove {
        asked["run"] = serde_json::json!(run);
        asked["prove"] = serde_json::json!(true);
    }
    match flow::attack::attack(&server, asked) {
        Ok(said) => {
            println!(
                "{}",
                serde_json::to_string_pretty(&said).unwrap_or_default()
            );
            ExitCode::SUCCESS
        }
        Err(why) => {
            eprintln!("devflow attack: {why}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
#[path = "attack_cli_tests.rs"]
mod tests;
