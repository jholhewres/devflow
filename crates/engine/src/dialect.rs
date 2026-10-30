//! The words the engine says to agents and people, and the texts it serves:
//! its own, or a host's. A host that keeps its own names — devpit calls a
//! work item a card and its tools `devpit_devflow_*` — passes its dialect
//! where the engine makes text; [`Dialect::DEVFLOW`] is the engine's own.
//!
//! Where a sentence differs in more than a word the dialect holds the whole
//! phrase, never a rule that would derive it.

/// The tools as a sentence names them: `` `evidence` `` here, a bare
/// `devpit_devflow_evidence` in devpit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tools {
    pub evidence: &'static str,
    pub gate: &'static str,
    pub set: &'static str,
    pub stage: &'static str,
    pub review: &'static str,
    pub publish: &'static str,
    pub handoff: &'static str,
    pub finish: &'static str,
}

/// The flow's texts: the skills, the reviewer personas, the rubrics, the
/// findings schema and the publish templates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Assets {
    /// Each skill's name, its stage (none for the setup's) and its text.
    pub skills: [(&'static str, Option<&'static str>, &'static str); 7],
    /// Each persona's name and text.
    pub personas: [(&'static str, &'static str); 4],
    /// Each rubric's name and text: finding, brief, plan.
    pub rubrics: [(&'static str, &'static str); 3],
    pub schema: &'static str,
    /// The publish templates: GitHub's, GitLab's, Bitbucket's.
    pub publish: [&'static str; 3],
}

impl Assets {
    /// What this build ships in `flow/`.
    pub const DEVFLOW: Assets = Assets {
        skills: [
            (
                "devflow-briefing",
                Some("briefing"),
                include_str!("../../../flow/skills/devflow-briefing/SKILL.md"),
            ),
            (
                "devflow-context",
                Some("context"),
                include_str!("../../../flow/skills/devflow-context/SKILL.md"),
            ),
            (
                "devflow-plan",
                Some("plan"),
                include_str!("../../../flow/skills/devflow-plan/SKILL.md"),
            ),
            (
                "devflow-execution",
                Some("execution"),
                include_str!("../../../flow/skills/devflow-execution/SKILL.md"),
            ),
            (
                "devflow-review",
                Some("review"),
                include_str!("../../../flow/skills/devflow-review/SKILL.md"),
            ),
            (
                "devflow-completion",
                Some("completion"),
                include_str!("../../../flow/skills/devflow-completion/SKILL.md"),
            ),
            (
                "devflow-setup",
                None,
                include_str!("../../../flow/skills/devflow-setup/SKILL.md"),
            ),
        ],
        personas: [
            (
                "devflow-spec",
                include_str!("../../../flow/personas/devflow-spec.md"),
            ),
            (
                "devflow-standards",
                include_str!("../../../flow/personas/devflow-standards.md"),
            ),
            (
                "devflow-security",
                include_str!("../../../flow/personas/devflow-security.md"),
            ),
            // Every axis in one reading, for a review `review.scale` sized down.
            (
                "devflow-all",
                include_str!("../../../flow/personas/devflow-all.md"),
            ),
        ],
        rubrics: [
            (
                crate::jev::FINDING,
                include_str!("../../../flow/rubrics/devflow-finding.json"),
            ),
            (
                crate::jev::BRIEF,
                include_str!("../../../flow/rubrics/devflow-brief.json"),
            ),
            (
                crate::jev::PLAN,
                include_str!("../../../flow/rubrics/devflow-plan.json"),
            ),
        ],
        schema: include_str!("../../../flow/schemas/devflow-findings.schema.json"),
        publish: [
            include_str!("../../../flow/publish/github.md"),
            include_str!("../../../flow/publish/gitlab.md"),
            include_str!("../../../flow/publish/bitbucket.md"),
        ],
    };
}

/// A host's words.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Dialect {
    /// Who reads reports, writes files and runs reviewers: `devflow`.
    /// Also the key that marks evidence.json and findings.json, and a
    /// reviewer's `by` when it ran headless.
    pub product: &'static str,
    /// The version a record says made it.
    pub version: &'static str,
    /// The prefix of the variables a check and a reviewer read:
    /// `<env>_REPORT_DIR`, `<env>_REVIEW_BASE`.
    pub env: &'static str,
    /// The folder devflow.yaml's comments point at for skills and rubrics.
    pub folder: &'static str,
    /// The piece of work, in a sentence: `item`, `items`, `an item`.
    pub item: &'static str,
    pub items: &'static str,
    pub an_item: &'static str,
    /// The same where it stands alone: `work item`, `a work item`.
    pub work_item: &'static str,
    pub a_work_item: &'static str,
    /// The field the tools take it as.
    pub item_field: &'static str,
    pub tools: Tools,
    /// What a comment lists its files under, and how it says the rest.
    pub files_label: &'static str,
    pub files_more: &'static str,
    /// The review packet's heading for the work: `Work item`.
    pub packet_heading: &'static str,
    /// What becomes of a plan published to the board, after "the plan's".
    pub plan_board: &'static str,
    /// Why a plan's `depends_on` is neither a key nor work that exists.
    pub plan_outside: &'static str,
    /// The first lines of devflow.yaml, and its `enabled` comment.
    pub yaml_header: &'static str,
    pub yaml_enabled: &'static str,
    /// Who sets Decisions' enforce, and its provider, in devflow.yaml.
    pub yaml_enforce: &'static str,
    pub yaml_provider: &'static str,
    /// Why Decisions is off for a project that opted out, and with no key.
    pub decisions_opted_out: &'static str,
    pub decisions_no_key: &'static str,
    pub assets: &'static Assets,
}

impl Dialect {
    /// The engine's own.
    pub const DEVFLOW: Dialect = Dialect {
        product: "devflow",
        version: env!("CARGO_PKG_VERSION"),
        env: "DEVFLOW",
        folder: ".devflow",
        item: "item",
        items: "items",
        an_item: "an item",
        work_item: "work item",
        a_work_item: "a work item",
        item_field: "item",
        tools: Tools {
            evidence: "`evidence`",
            gate: "`gate`",
            set: "`set`",
            stage: "`stage`",
            review: "`review`",
            publish: "`publish`",
            handoff: "`handoff`",
            finish: "`finish`",
        },
        files_label: "Files",
        files_more: "in the run",
        packet_heading: "Work item",
        plan_board: "slices are made as work items in .devflow/work/.",
        plan_outside:
            "is not another item of this plan, nor a work item that exists, named as `#42`",
        yaml_header: "# Devflow: briefing → context → plan → execution → review → completion,\n\
                      # served by devflow's MCP. This file is the source of truth: devflow edits\n\
                      # it and never commits it.\n",
        yaml_enabled: "# Switched on by the person with `devflow config set`, never by an agent.\n",
        yaml_enforce: "only the person sets it, in a terminal",
        yaml_provider: "the provider `devflow jev setup` chose",
        decisions_opted_out:
            "this project's state is not sent to Decisions — `devflow jev send` sends it again",
        decisions_no_key: "no key — set one with `devflow jev setup`",
        assets: &Assets::DEVFLOW,
    };

    /// The folder a check writes its reports to, as a variable.
    pub fn report_dir(&self) -> String {
        format!("{}_REPORT_DIR", self.env)
    }

    /// A persona's text as this dialect ships it.
    pub fn persona(&self, name: &str) -> Option<&'static str> {
        self.assets
            .personas
            .iter()
            .find(|(one, _)| *one == name)
            .map(|(_, text)| *text)
    }

    /// A rubric's text as this dialect ships it.
    pub fn rubric(&self, name: &str) -> Option<&'static str> {
        self.assets
            .rubrics
            .iter()
            .find(|(one, _)| *one == name)
            .map(|(_, text)| *text)
    }
}
