//! `devflow payloads`: the attack's payload repertoire, its tables, and a
//! case an attack proposed kept by the project on the person's yes.

use std::process::ExitCode;

use crate::{cli, flow, project, Payloads};

/// `devflow payloads`: the repertoire, its tables, and keeping a case.
pub fn payloads(root: &std::path::Path, action: Payloads) -> ExitCode {
    use devflow_engine::payloads;
    let failed = |why: String| {
        eprintln!("devflow payloads: {why}");
        ExitCode::FAILURE
    };
    let project = project::Project::at(root);
    match action {
        Payloads::List => {
            for name in payloads::names() {
                match payloads::class(&project.root, name) {
                    Ok(class) => println!("{name}\t{} cases\t{}", class.cases.len(), class.about),
                    Err(why) => return failed(why),
                }
            }
            ExitCode::SUCCESS
        }
        Payloads::Table { class, runner } => {
            let Some(runner) = payloads::Runner::of(&runner) else {
                return failed("--runner is jest, vitest, go or pytest".to_owned());
            };
            match payloads::class(&project.root, &class) {
                Ok(class) => {
                    print!("{}", payloads::table(&class, runner));
                    ExitCode::SUCCESS
                }
                Err(why) => failed(why),
            }
        }
        Payloads::Add { item, case, run } => {
            let runs = project.runs();
            let found = match run.as_deref() {
                Some(run) => runs.found(&item, Some(run), devflow_engine::attack::REPORT),
                None => runs
                    .newest_with(&item, devflow_engine::attack::REPORT)
                    .map(|(_, at)| at),
            };
            let Some((at, report)) =
                found.and_then(|at| flow::json_at(&at).map(|report| (at, report)))
            else {
                return failed(format!("{item} has no attack report to take a case from"));
            };
            // A report the repository carries never proposes a case.
            let relative = at
                .strip_prefix(&project.root)
                .ok()
                .map(|rest| rest.display().to_string());
            if let Some(relative) = relative {
                match devflow_engine::git::tracked(&project.root, &relative) {
                    Ok(false) => {}
                    Ok(true) => {
                        return failed(format!(
                            "{relative} is part of the repository: a report it carries proposes nothing"
                        ))
                    }
                    Err(why) => return failed(format!("{relative}: {why}")),
                }
            }
            println!("from: {}", at.display());
            let Some(proposed) = report["proposed_cases"]
                .as_array()
                .into_iter()
                .flatten()
                .find(|one| one["id"] == case.as_str())
                .cloned()
            else {
                return failed(format!("the attack report proposes no case `{case}`"));
            };
            let class = proposed["class"].as_str().unwrap_or_default();
            if !payloads::names().contains(&class) {
                return failed(format!("the case `{case}` is of no class devflow ships"));
            }
            // Refused before anyone is asked when it could not be kept.
            let case_kept = match payloads::keepable(&project.root, &proposed) {
                Ok((_, case_kept)) => case_kept,
                Err(why) => return failed(why),
            };
            if let Some(from) = &case_kept.from {
                println!(
                    "written by: {}",
                    serde_json::to_string(from).unwrap_or_default()
                );
            }
            println!(
                "class: {}\ninput: {}\nwant: {}\nwhy: {}",
                serde_json::to_string(&proposed["class"]).unwrap_or_default(),
                serde_json::to_string(&proposed["input"]).unwrap_or_default(),
                serde_json::to_string(&proposed["want"]).unwrap_or_default(),
                serde_json::to_string(&proposed["why"]).unwrap_or_default()
            );
            let question = format!("Keep it in {}?", payloads::kept_path(&project.root, class));
            match cli::confirmed(&question) {
                Ok(true) => match payloads::keep(&project.root, &proposed) {
                    Ok(at) => {
                        println!("kept in {at}");
                        ExitCode::SUCCESS
                    }
                    Err(why) => failed(why),
                },
                Ok(false) => {
                    println!("not kept");
                    ExitCode::SUCCESS
                }
                Err(why) => failed(why),
            }
        }
    }
}
