//! The engine's stable surface: the modules devpit links, as docs/plan.md
//! lists them. Every path devpit names compiles here, so one that goes away
//! fails the build; and lib.rs keeps every other module out of it, hidden
//! from the docs or private.
#![allow(unused_imports)]

mod paths {
    mod adhoc {
        use devflow_engine::adhoc::{standalone, standalone_in};
    }
    mod brief {
        use devflow_engine::brief::{read, Brief};
    }
    mod config {
        use devflow_engine::config::{
            parse, unread, Agent, Check, Consolidate, Extend, Mode, UnblockOn,
        };
    }
    mod criteria {
        use devflow_engine::criteria::{criteria, ticked, unread, HEADING};
    }
    mod detect {
        use devflow_engine::detect::{detected_in, Hints};
    }
    mod dialect {
        use devflow_engine::dialect::Assets;
    }
    mod env {
        use devflow_engine::env::spawn_with;
    }
    mod evidence {
        use devflow_engine::evidence::{asked, rechecked, Card};
    }
    mod findings {
        use devflow_engine::findings::{person_said, standing, verdict};
    }
    mod folder {
        use devflow_engine::folder::{default_file, pin, read, Layout, State, LEGACY};
    }
    mod fresh {
        use devflow_engine::fresh::changed_at;
    }
    mod gate {
        use devflow_engine::gate::{asked, CAP_ENV, FIELDS};
    }
    mod git {
        use devflow_engine::git::toplevel;
    }
    mod jev {
        use devflow_engine::jev::{capped, rubric_for};
    }
    mod layers {
        use devflow_engine::layers::{Layered, Team};
    }
    mod locate {
        use devflow_engine::locate::DEVPIT;
    }
    mod pinning {
        use devflow_engine::pinning::{approve, fetched};
    }
    mod plan {
        use devflow_engine::plan::{Slice, PREFIX};
    }
    mod plugin {
        use devflow_engine::plugin::launch;
    }
    mod preset {
        use devflow_engine::preset::Preset;
    }
    mod proposal {
        use devflow_engine::proposal::switched;
    }
    mod review {
        use devflow_engine::review::{asked, Personas, FIELDS};
    }
    mod runner {
        use devflow_engine::runner::Context;
    }
    mod runs {
        use devflow_engine::runs::{stamp, RUNS};
    }
    mod security {
        use devflow_engine::security::{
            in_force, persons_only, refused, resolved_here, with_targets,
        };
    }
    mod setup {
        use devflow_engine::setup::write;
    }
    mod stage {
        use devflow_engine::stage::file_of;
    }
    mod started {
        use devflow_engine::started::{keep_start, start_of};
    }
    mod work {
        use devflow_engine::work::{Kind, New, WorkItems};
    }
    mod root {
        use devflow_engine::{
            calibrate, publish, skills, Ask, Config, Dialect, Invalid, Proposal, State,
        };
    }
}

/// The modules docs/plan.md calls stable.
fn stable_in_the_plan() -> Vec<String> {
    let plan = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../../docs/plan.md"))
        .expect("plan");
    let line = plan
        .lines()
        .find(|line| line.starts_with("- **Stable modules**:"))
        .expect("the plan lists the stable modules");
    line.split('`')
        .skip(1)
        .step_by(2)
        .map(str::to_owned)
        .collect()
}

/// lib.rs's public modules, each with whether it is hidden from the docs.
fn public_in_lib() -> Vec<(String, bool)> {
    let lib = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/lib.rs"))
        .expect("lib.rs");
    let lines: Vec<&str> = lib.lines().collect();
    lines
        .iter()
        .enumerate()
        .filter_map(|(at, line)| {
            let name = line.strip_prefix("pub mod ")?.strip_suffix(';')?;
            let hidden = at > 0 && lines[at - 1].trim() == "#[doc(hidden)]";
            Some((name.to_owned(), hidden))
        })
        .collect()
}

#[test]
fn the_stable_modules_are_the_plans_and_every_other_is_internal() {
    let stable = stable_in_the_plan();
    let public = public_in_lib();
    let shown: Vec<&str> = public
        .iter()
        .filter(|(_, hidden)| !hidden)
        .map(|(name, _)| name.as_str())
        .collect();
    assert_eq!(
        shown, stable,
        "lib.rs shows exactly the plan's stable modules"
    );
    assert!(
        public
            .iter()
            .any(|(name, hidden)| name == "attack" && *hidden),
        "the attack is internal"
    );
}
