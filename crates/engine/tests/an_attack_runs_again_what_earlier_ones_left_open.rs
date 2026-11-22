//! An attack runs again, at HEAD and before its attacker, the exploits
//! earlier attacks left open: confirmed, or tried (a red run that did not
//! name its test among them). A hole once shown is shown again whether or
//! not the attacker finds it this time, and the attacker is told what was
//! settled so it covers the rest.
#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use devflow_engine::config::{self, Config};
use devflow_engine::{attack, Dialect};
use serde_json::{json, Value};

const SESSION: &str = "src/auth/session.rs";
const DIFF: &str = "diff --git a/src/auth/session.rs b/src/auth/session.rs\n--- a/src/auth/session.rs\n+++ b/src/auth/session.rs\n@@ -1,1 +1,2 @@\n fn a() {}\n+let claims = decode_unverified(cookie);\n";

/// An exploit that fails on its own assertion the way jest prints it.
const JEST_RED: &str = "echo 'FAIL tests/security/session.exploit.test.ts'\necho '  \u{25cf} forged sessions \u{203a} accepts a cookie signed with any key'\necho '    Expected: false'\necho '    Received: true'\nexit 1\n";

fn git(repo: &Path, args: &[&str]) -> String {
    let out = std::process::Command::new("git")
        .args(args)
        .current_dir(repo)
        .output()
        .expect("git");
    assert!(out.status.success(), "git {args:?}");
    String::from_utf8(out.stdout)
        .expect("utf-8")
        .trim()
        .to_owned()
}

fn fake_claude(dir: &Path, answer: &Value) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let envelope = json!({ "type": "result", "result": answer.to_string(), "total_cost_usd": 0.1 });
    std::fs::write(dir.join("answer.json"), envelope.to_string()).expect("answer");
    let script = dir.join("claude");
    std::fs::write(
        &script,
        format!(
            "#!/bin/sh\ncat > '{0}/prompt.txt'\ncat '{0}/answer.json'\n",
            dir.display()
        ),
    )
    .expect("script");
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).expect("mode");
    script
}

struct Project {
    _dir: tempfile::TempDir,
    root: PathBuf,
    checkout: PathBuf,
    first: String,
    second: String,
}

/// A checkout of two commits; the runs' home outside it.
fn project() -> Project {
    let dir = tempfile::tempdir().expect("dir");
    let root = dir.path().canonicalize().expect("root");
    let checkout = root.join("checkout");
    std::fs::create_dir_all(checkout.join("src/auth")).expect("checkout");
    git(&checkout, &["init", "-q"]);
    git(&checkout, &["config", "user.email", "test@example.invalid"]);
    git(&checkout, &["config", "user.name", "Test"]);
    git(&checkout, &["config", "commit.gpgsign", "false"]);
    std::fs::write(checkout.join(SESSION), "fn a() {}\n").expect("code");
    git(&checkout, &["add", "-A"]);
    git(&checkout, &["commit", "-q", "-m", "first"]);
    let first = git(&checkout, &["rev-parse", "HEAD"]);
    std::fs::write(checkout.join(SESSION), "fn a() {}\nfn b() {}\n").expect("code");
    git(&checkout, &["commit", "-q", "-am", "second"]);
    let second = git(&checkout, &["rev-parse", "HEAD"]);
    Project {
        _dir: dir,
        root,
        checkout,
        first,
        second,
    }
}

impl Project {
    fn runs(&self) -> devflow_engine::runs::Runs {
        devflow_engine::runs::Runs {
            dialect: &Dialect::DEVFLOW,
            home: self.root.join("home"),
            checkout: self.checkout.clone(),
        }
    }

    /// An earlier attack of `card` at `head` that kept `hypotheses`, each
    /// exploit's code in its run.
    fn earlier(&self, card: &str, head: &str, hypotheses: &[(Value, &str)]) -> String {
        self.earlier_at(card, head, hypotheses, 1_791_000_000)
    }

    fn earlier_at(&self, card: &str, head: &str, hypotheses: &[(Value, &str)], at: u64) -> String {
        let run = self
            .runs()
            .fresh(card, SystemTime::UNIX_EPOCH + Duration::from_secs(at))
            .expect("earlier run");
        let mut kept = Vec::new();
        for (at, (one, code)) in hypotheses.iter().enumerate() {
            let saved = format!("{}/h{}/exploit.sh", attack::EXPLOITS, at + 1);
            std::fs::create_dir_all(run.join(&saved).parent().expect("folder")).expect("folder");
            std::fs::write(run.join(&saved), code).expect("exploit");
            let mut one = one.clone();
            one["id"] = json!(format!("h{}", at + 1));
            one["exploit"]["saved"] = json!(saved);
            kept.push(one);
        }
        std::fs::write(
            run.join(attack::REPORT),
            json!({ "head": head, "hypotheses": kept }).to_string(),
        )
        .expect("earlier report");
        run.file_name()
            .expect("name")
            .to_string_lossy()
            .into_owned()
    }

    /// An attack of `card` from `base` to `head` whose attacker answers
    /// `hypotheses`: its report, and the prompt the attacker read.
    fn attack(
        &self,
        card: &str,
        base: &str,
        head: &str,
        yaml: &str,
        hypotheses: Value,
    ) -> (Value, String) {
        self.attack_answered(
            card,
            base,
            head,
            yaml,
            json!({ "version": 1, "hypotheses": hypotheses }),
        )
    }

    /// [`Project::attack`], its attacker answering `answer` whole.
    fn attack_answered(
        &self,
        card: &str,
        base: &str,
        head: &str,
        yaml: &str,
        answer: Value,
    ) -> (Value, String) {
        self.attack_answered_at(card, base, head, yaml, answer, 1_792_000_000)
    }

    /// [`Project::attack_answered`], its run made at `at`.
    fn attack_answered_at(
        &self,
        card: &str,
        base: &str,
        head: &str,
        yaml: &str,
        answer: Value,
        at: u64,
    ) -> (Value, String) {
        let bin = self.root.join(format!("bin-{card}"));
        std::fs::create_dir_all(&bin).expect("bin");
        let claude = fake_claude(&bin, &answer);
        let reach =
            move |_: config::Agent| -> Result<String, String> { Ok(claude.display().to_string()) };
        let redact = |text: &str| text.to_owned();
        let config: Config = config::parse(yaml).expect("config");
        let files = vec![SESSION.to_owned()];
        let scratch = self.root.join("trees");
        let runs = self.runs();
        let done = attack::attacked(&attack::Given {
            root: &self.checkout,
            runs: &runs,
            config: &config,
            card: devflow_engine::evidence::Card {
                id: card,
                title: "Sessions",
                body: "",
            },
            git: devflow_engine::review::Git {
                base,
                head,
                files: &files,
                diff: DIFF,
            },
            brief: None,
            evidence: None,
            review: None,
            env: &[],
            at: SystemTime::UNIX_EPOCH + Duration::from_secs(at),
            budget: Duration::from_secs(60),
            reach: &reach,
            redact: &redact,
            personas: devflow_engine::review::Personas::default(),
            retro: false,
            scratch: Some(&scratch),
            flow: None,
            stack: None,
            ledger: None,
        })
        .expect("attacked");
        let prompt = std::fs::read_to_string(bin.join("prompt.txt")).expect("prompt");
        (done.report, prompt)
    }
}

fn confirmed_before() -> Value {
    json!({ "title": "a cookie signed with any key is accepted", "class": "authn", "file": SESSION,
        "line": 1, "severity": "high", "status": "confirmed", "reason": "the signature is never checked",
        "exploit": { "path": "tests/security/session.exploit.test.ts",
                     "test": "forged sessions accepts a cookie signed with any key" } })
}

fn short(sha: &str) -> String {
    sha.chars().take(12).collect()
}

#[test]
fn an_exploit_left_open_is_run_again_and_the_attacker_told_without_a_sandbox() {
    let project = project();
    let card = "card_1";
    let refuted = json!({ "title": "a replayed cookie is accepted", "file": SESSION, "status": "refuted",
        "exploit": { "path": "tests/replay.sh", "test": "replay" } });
    let run = project.earlier(
        card,
        &project.first,
        &[(confirmed_before(), JEST_RED), (refuted, "exit 0")],
    );
    let yaml = "version: 1\nstages:\n  attack: { run: sensitive, test: 'sh \"$DEVFLOW_EXPLOIT\"', sandbox: off }\n";
    // The attacker finds nothing this time.
    let (report, prompt) = project.attack(card, &project.first, &project.second, yaml, json!([]));
    assert_eq!(report["run_again"], 1, "{report:#}");
    assert_eq!(report["mode"], "item");
    assert_eq!(report["run_on"], "sensitive");
    let hypotheses = report["hypotheses"].as_array().expect("hypotheses");
    assert_eq!(
        hypotheses.len(),
        1,
        "only what was left open: {hypotheses:#?}"
    );
    let again = &hypotheses[0];
    assert_eq!(again["again"]["run"], run.as_str());
    assert_eq!(again["again"]["was"], "confirmed");
    assert_eq!(again["status"], "tried");
    assert!(again["ran"]["reason"]
        .as_str()
        .expect("why")
        .contains("the session runs it"));
    // Kept in this run too, so the next attack runs it again.
    let folder = project
        .runs()
        .home
        .join(card)
        .join(report["run"].as_str().expect("run"));
    let saved = again["exploit"]["saved"].as_str().expect("saved");
    assert_eq!(
        std::fs::read_to_string(folder.join(saved)).expect("kept"),
        JEST_RED
    );
    assert!(
        prompt.contains("## Run again at HEAD by devflow while you work, from earlier attacks"),
        "{prompt}"
    );
    // One its earlier run did not settle is the attacker's to show its way.
    assert!(
        prompt.contains("but for one listed `was: tried`"),
        "{prompt}"
    );
    // Where the time went, by phase.
    let profile = &report["profile"];
    for phase in [
        "prepare_ms",
        "run_again_ms",
        "attackers_ms",
        "proof_ms",
        "timing_ms",
        "total_ms",
    ] {
        assert!(profile[phase].is_u64(), "{phase}: {report:#}");
    }
    let md = devflow_engine::attack_report::markdown(&report, &Default::default());
    assert!(md.contains("Time: "), "{md}");
    assert!(md.contains(" run again (while the attack ran)"), "{md}");
    assert!(
        prompt.contains("a cookie signed with any key is accepted"),
        "{prompt}"
    );
    assert!(
        !prompt.contains("a replayed cookie"),
        "a refuted one is not run again"
    );
}

/// The attacker's own exploit for a hole that ran again unsettled is kept:
/// it may still show it.
#[test]
fn the_attackers_own_exploit_stands_beside_one_that_ran_again_unsettled() {
    let project = project();
    let card = "card_1";
    project.earlier(card, &project.first, &[(confirmed_before(), JEST_RED)]);
    let yaml = "version: 1\nstages:\n  attack: { run: sensitive, test: 'sh \"$DEVFLOW_EXPLOIT\"', sandbox: off }\n";
    let found_again = json!([
        { "id": "h1", "title": "A cookie signed with any key is accepted", "file": SESSION, "line": 1,
          "severity": "high", "status": "tried", "reason": "again",
          "exploit": { "path": "tests/other.sh", "test": "other", "code": "exit 1" } },
        { "id": "h2", "title": "a token is logged", "file": SESSION, "line": 2, "severity": "low",
          "status": "tried", "reason": "new", "exploit": { "path": "tests/log.sh", "test": "log", "code": "exit 1" } },
    ]);
    let (report, _) = project.attack(card, &project.first, &project.second, yaml, found_again);
    let hypotheses = report["hypotheses"].as_array().expect("hypotheses");
    let ids: Vec<&str> = hypotheses
        .iter()
        .filter_map(|one| one["id"].as_str())
        .collect();
    assert_eq!(ids, ["h1", "h2", "h3"]);
    assert!(
        hypotheses[2]["again"].is_object(),
        "the one run again comes last"
    );
    assert!(hypotheses[2]["reason"]
        .as_str()
        .expect("why")
        .starts_with("its exploit, kept by run "));
}

#[test]
fn an_exploit_kept_outside_its_run_is_never_read() {
    let project = project();
    let card = "card_1";
    let run = project
        .runs()
        .fresh(
            card,
            SystemTime::UNIX_EPOCH + Duration::from_secs(1_791_000_000),
        )
        .expect("earlier run");
    std::fs::write(project.root.join("secret.sh"), "echo planted; exit 1\n").expect("outside");
    let mut one = confirmed_before();
    one["id"] = json!("h1");
    one["exploit"]["saved"] = json!("../../../secret.sh");
    std::fs::write(
        run.join(attack::REPORT),
        json!({ "head": project.first, "hypotheses": [one] }).to_string(),
    )
    .expect("report");
    let yaml = "version: 1\nstages:\n  attack: { run: sensitive, test: 'sh \"$DEVFLOW_EXPLOIT\"', sandbox: off }\n";
    let (report, prompt) = project.attack(card, &project.first, &project.second, yaml, json!([]));
    assert_eq!(report["run_again"], 0, "{report:#}");
    assert!(!prompt.contains("planted"), "{prompt}");
    // The hole it confirmed is not lost: it is carried, said why.
    let carried = report["carried"].as_array().expect("carried");
    assert_eq!(carried.len(), 1, "{report:#}");
    assert_eq!(carried[0]["carried"], "no_exploit");
    assert_eq!(carried[0]["status"], "confirmed");
    assert!(carried[0]["exploit"]["saved"].is_null(), "{report:#}");
    assert!(!report.to_string().contains("planted"), "{report:#}");
}

#[test]
fn a_range_runs_again_what_a_range_its_history_holds_left_open() {
    let project = project();
    let earlier = format!("{}-{}", short(&project.first), short(&project.first));
    project.earlier(&earlier, &project.first, &[(confirmed_before(), JEST_RED)]);
    // A range whose head is in no history of this one counts for nothing.
    let elsewhere = format!("{}-{}", short(&project.first), "abcdefabcdef");
    project.earlier(
        &elsewhere,
        &"ab".repeat(20),
        &[(
            json!({ "title": "elsewhere", "file": SESSION,
        "status": "confirmed", "exploit": { "path": "tests/e.sh", "test": "e" } }),
            "exit 1",
        )],
    );
    let card = format!("{}-{}", short(&project.first), short(&project.second));
    let yaml = "version: 1\nstages:\n  attack: { run: sensitive, test: 'sh \"$DEVFLOW_EXPLOIT\"', sandbox: off }\n";
    let (report, _) = project.attack(&card, &project.first, &project.second, yaml, json!([]));
    let titles: Vec<&str> = report["hypotheses"]
        .as_array()
        .expect("hypotheses")
        .iter()
        .filter_map(|one| one["title"].as_str())
        .collect();
    assert_eq!(titles, ["a cookie signed with any key is accepted"]);
    assert_eq!(report["hypotheses"][0]["again"]["item"], earlier.as_str());
    // A range's attack is asked by name: no item's run policy said it.
    assert_eq!(report["mode"], "range");
    assert_eq!(report["run_on"], "asked");
}

/// Where a sandbox is (bwrap, or docker with `DEVFLOW_SANDBOX_IMAGE`), the
/// exploit kept from an earlier run that went red, as jest says it, comes
/// back confirmed by the sandbox with no exploit written by the attacker.
#[test]
fn in_the_sandbox_an_exploit_kept_red_comes_back_confirmed_with_nothing_written() {
    let image = std::env::var("DEVFLOW_SANDBOX_IMAGE").unwrap_or_default();
    let path = std::env::var_os("PATH").unwrap_or_default();
    if let Err(why) =
        devflow_engine::sandbox::found(config::SandboxChoice::Auto, Some(&image), &path)
    {
        eprintln!("not run here: {why}");
        return;
    }
    let project = project();
    let card = "card_1";
    // Filed tried before: red, but its run's name was not read then.
    let mut tried = confirmed_before();
    tried["status"] = json!("tried");
    project.earlier(card, &project.first, &[(tried, JEST_RED)]);
    let yaml = format!(
        "version: 1\nstages:\n  attack: {{ run: sensitive, test: 'sh \"$DEVFLOW_EXPLOIT\"', image: '{image}' }}\n"
    );
    // The attacker writes nothing new; what it says of the same hole stands
    // as the run again showed it.
    let same = json!([{ "id": "h1", "title": "a cookie signed with any key is accepted", "file": SESSION,
        "line": 1, "severity": "high", "status": "tried", "reason": "again",
        "exploit": { "path": "tests/other.sh", "test": "other", "code": "exit 0" } }]);
    let (report, prompt) = project.attack(card, &project.first, &project.second, &yaml, same);
    assert_eq!(
        report["hypotheses"].as_array().expect("hypotheses").len(),
        1,
        "{report:#}"
    );
    let again = &report["hypotheses"][0];
    assert_eq!(again["status"], "confirmed", "{again:#}");
    assert_eq!(again["verified"]["by"], "sandbox");
    assert_eq!(again["verified"]["test"], again["exploit"]["test"]);
    assert_eq!(again["verified"]["path"], again["exploit"]["path"]);
    assert_eq!(report["exploits"][0]["held_by"], "proof", "{report:#}");
    assert_eq!(report["verdict"], "request_changes");
    // Run beside the attacker's turn: it is told the hole and how it ended
    // in the run that kept it.
    assert!(prompt.contains("\"was\":\"tried\""), "{prompt}");
}

/// As on a real project: a run whose exploit went red was filed tried with
/// `ran` not_run (its test's name not read then), and a later run whose
/// attacker wrote nothing does not hide it.
#[test]
fn a_red_run_filed_not_run_is_run_again_past_a_later_run_that_wrote_nothing() {
    let project = project();
    let card = "card_1";
    let mut filed = confirmed_before();
    filed["status"] = json!("tried");
    filed["ran"] = json!({ "result": "not_run", "reason": "it failed before its assertion: the output names no failing test of it, or a harness error" });
    let red_run = project.earlier_at(card, &project.first, &[(filed, JEST_RED)], 1_790_000_000);
    let refuted =
        json!({ "title": "read only", "file": SESSION, "status": "refuted", "reason": "read" });
    let later = project.earlier_at(card, &project.first, &[], 1_791_000_000);
    std::fs::write(
        project
            .runs()
            .home
            .join(card)
            .join(&later)
            .join(attack::REPORT),
        json!({ "head": project.first, "hypotheses": [refuted] }).to_string(),
    )
    .expect("a later run with no exploit");
    let yaml = "version: 1\nstages:\n  attack: { run: sensitive, test: 'sh \"$DEVFLOW_EXPLOIT\"', sandbox: off }\n";
    let (report, _) = project.attack(card, &project.first, &project.second, yaml, json!([]));
    assert_eq!(report["run_again"], 1, "{report:#}");
    assert_eq!(report["hypotheses"][0]["again"]["run"], red_run.as_str());
}

/// One hole earlier runs each named their own way, with an exploit of
/// their own, is run again once: from the run that confirmed it.
#[test]
fn one_hole_several_runs_kept_is_run_again_once() {
    let project = project();
    let card = "card_1";
    let at = |title: &str, line: u64, status: &str, test: &str| {
        json!({ "title": title, "class": "tls", "file": SESSION, "line": line,
            "severity": "high", "status": status, "reason": "the server certificate is not checked",
            "exploit": { "path": format!("tests/security/{test}.test.ts"), "test": test } })
    };
    let confirmed = project.earlier_at(
        card,
        &project.first,
        &[(
            at("database TLS skips verification", 3, "confirmed", "verify"),
            JEST_RED,
        )],
        1_789_000_000,
    );
    project.earlier_at(
        card,
        &project.first,
        &[(
            at("Postgres accepts any certificate", 5, "tried", "any cert"),
            "exit 2",
        )],
        1_790_000_000,
    );
    project.earlier_at(
        card,
        &project.first,
        &[
            (
                at("rejectUnauthorized is false", 1, "tried", "unauthorized"),
                "exit 3",
            ),
            // Another class at the same place is another hole.
            (
                json!({ "title": "the password is logged", "class": "secrets", "file": SESSION,
                    "line": 2, "severity": "medium", "status": "tried",
                    "exploit": { "path": "tests/security/log.test.ts", "test": "log" } }),
                "exit 4",
            ),
        ],
        1_791_000_000,
    );
    let yaml = "version: 1\nstages:\n  attack: { run: sensitive, test: 'sh \"$DEVFLOW_EXPLOIT\"', sandbox: off }\n";
    let (report, _) = project.attack(card, &project.first, &project.second, yaml, json!([]));
    let again: Vec<(&str, &str)> = report["hypotheses"]
        .as_array()
        .expect("hypotheses")
        .iter()
        .map(|one| {
            (
                one["class"].as_str().unwrap_or_default(),
                one["again"]["run"].as_str().unwrap_or_default(),
            )
        })
        .collect();
    assert_eq!(report["run_again"], 2, "{report:#}");
    // Kept by devflow's name for its class.
    assert!(
        again.contains(&("transport", confirmed.as_str())),
        "{again:?}"
    );
    assert!(
        again.iter().any(|(class, _)| *class == "secrets"),
        "{again:?}"
    );
}

#[test]
fn a_hole_one_run_names_crypto_and_another_tls_is_run_again_once() {
    let project = project();
    let card = "card_1";
    let hole = |title: &str, class: &str, line: u64, status: &str, test: &str| {
        json!({ "title": title, "class": class, "file": SESSION, "line": line,
            "severity": "high", "status": status, "reason": "the server certificate is not checked",
            "exploit": { "path": format!("tests/security/{test}.test.ts"), "test": test } })
    };
    let confirmed = project.earlier_at(
        card,
        &project.first,
        &[(
            hole(
                "Postgres skips certificate checks",
                "crypto",
                2,
                "confirmed",
                "pg cert",
            ),
            JEST_RED,
        )],
        1_789_000_000,
    );
    let tls = project.earlier_at(
        card,
        &project.first,
        &[
            (
                hole(
                    "database TLS accepts any certificate",
                    "TLS",
                    2,
                    "tried",
                    "db tls",
                ),
                "exit 2",
            ),
            // Who may act is another family: on the same line, another hole.
            (
                hole(
                    "any user reads another's session",
                    "authz",
                    2,
                    "tried",
                    "owner",
                ),
                "exit 3",
            ),
        ],
        1_790_000_000,
    );
    let yaml = "version: 1\nstages:\n  attack: { run: sensitive, test: 'sh \"$DEVFLOW_EXPLOIT\"', sandbox: off }\n";
    let (report, _) = project.attack(card, &project.first, &project.second, yaml, json!([]));
    let again: Vec<(&str, &str)> = report["hypotheses"]
        .as_array()
        .expect("hypotheses")
        .iter()
        .map(|one| {
            (
                one["class"].as_str().unwrap_or_default(),
                one["again"]["run"].as_str().unwrap_or_default(),
            )
        })
        .collect();
    assert_eq!(report["run_again"], 2, "{again:?}");
    assert!(again.contains(&("crypto", confirmed.as_str())), "{again:?}");
    assert!(
        again.iter().any(|(class, _)| *class == "authz"),
        "{again:?}"
    );
    // The one kept says which it took in, by the run that kept it.
    let kept = report["hypotheses"]
        .as_array()
        .expect("hypotheses")
        .iter()
        .find(|one| one["class"] == "crypto")
        .expect("kept");
    assert_eq!(kept["merged"][0]["class"], "transport", "{kept:#}");
    assert!(kept["merged"][0]["again"]["run"].is_string(), "{kept:#}");
    // Named by the run that kept it and the id it had there, never null.
    assert_eq!(kept["merged"][0]["id"], "h1", "{kept:#}");
    assert_eq!(kept["merged"][0]["run"], tls.as_str(), "{kept:#}");
    assert_eq!(report["budget"]["run_cap_hit"], false);
    // The JSON report says the same, and whether a cap ended a turn.
    let shown = devflow_engine::attack_report::json_of(&report, &Default::default());
    assert_eq!(shown["run_cap_hit"], false, "{shown:#}");
    let at = report["hypotheses"]
        .as_array()
        .expect("hypotheses")
        .iter()
        .position(|one| one["class"] == "crypto")
        .expect("kept");
    let merged = &shown["hypotheses"][at]["merged"][0];
    assert_eq!(merged["id"], "h1", "{shown:#}");
    assert_eq!(merged["run"], tls.as_str(), "{shown:#}");
    let md = devflow_engine::attack_report::markdown(&report, &Default::default());
    assert!(md.contains(&format!("took in 1: h1 of run {tls}")), "{md}");
}

/// The attacker names what is at fault in each hypothesis run again, by
/// the id it was shown; a cause devflow does not name, or an id it never
/// showed, is dropped. A cause an earlier run kept comes back with it.
#[test]
fn the_attacker_names_the_cause_of_what_ran_again_and_it_is_kept() {
    let project = project();
    let card = "card_1";
    let mut named = confirmed_before();
    named["title"] = json!("a cookie of another user is accepted");
    named["line"] = json!(40);
    named["cause"] = json!("unverified-token");
    named["exploit"]["test"] = json!("other user");
    project.earlier(
        card,
        &project.first,
        &[(confirmed_before(), JEST_RED), (named, "exit 1\n")],
    );
    let yaml = "version: 1\nstages:\n  attack: { run: sensitive, test: 'sh \"$DEVFLOW_EXPLOIT\"', sandbox: off }\n";
    let answer = json!({ "version": 1, "hypotheses": [],
        "causes": { "again-1": "Unverified Token", "again-2": "made-up", "again-9": "unbounded-input" } });
    let (report, prompt) =
        project.attack_answered(card, &project.first, &project.second, yaml, answer);
    assert!(prompt.contains("\"id\":\"again-1\""), "{prompt}");
    assert!(
        prompt.contains("Name in `causes` the cause of each"),
        "{prompt}"
    );
    let causes: Vec<&str> = report["hypotheses"]
        .as_array()
        .expect("hypotheses")
        .iter()
        .map(|one| one["cause"].as_str().unwrap_or("-"))
        .collect();
    assert_eq!(
        causes,
        ["unverified-token", "unverified-token"],
        "{report:#}"
    );
}

/// A denial of service an earlier run proved only by time comes back with
/// its attacker asked, with an example, to prove it by count; the count
/// proof the attacker writes is run as its own, not folded into the timing
/// one, and no clock is read in it.
#[test]
fn a_hole_proven_by_time_is_asked_again_by_count_and_the_count_is_run() {
    let project = project();
    let card = "card_1";
    let timed = json!({ "title": "a page of unclosed tags is scanned in quadratic time", "class": "redos",
        "file": SESSION, "line": 1, "severity": "medium", "status": "confirmed", "reason": "slow",
        "exploit": { "path": "tests/security/scan.exploit.test.ts", "test": "scan is slow", "timing": true } });
    project.earlier(
        card,
        &project.first,
        &[(
            timed,
            "const t = Date.now(); scan(page); expect(Date.now() - t).toBeLessThan(1000)\n",
        )],
    );
    let yaml = "version: 1\nstages:\n  attack: { run: sensitive, test: 'sh \"$DEVFLOW_EXPLOIT\"', sandbox: off }\n";
    let count = json!([{ "id": "h1", "title": "A page of unclosed tags is scanned in quadratic time",
        "class": "dos", "file": SESSION, "line": 1, "severity": "medium", "status": "tried",
        "reason": "the steps grow with the square of the tags", "cause": "super-linear-work",
        "exploit": { "path": "tests/security/scan.count.test.ts", "test": "scan steps grow linearly",
                     "code": "expect(steps(2000)).toBeLessThanOrEqual(2.5 * steps(1000))\n" } }]);
    let (report, prompt) = project.attack(card, &project.first, &project.second, yaml, count);
    assert!(prompt.contains("1,000 and then 2,000 copies"), "{prompt}");
    let asked = prompt
        .split("## Proven by time only")
        .nth(1)
        .expect("the timing proof asked again by count");
    assert!(
        asked.contains("a page of unclosed tags is scanned in quadratic time"),
        "{asked}"
    );
    let hypotheses = report["hypotheses"].as_array().expect("hypotheses");
    assert_eq!(hypotheses.len(), 2, "{report:#}");
    let own = &hypotheses[0];
    assert_eq!(own["exploit"]["test"], "scan steps grow linearly");
    assert!(own["exploit"].get("timing").is_none(), "{own:#}");
    assert_eq!(hypotheses[1]["exploit"]["timing"], true);
}

/// Run again on the same range, an attack does not refute again what an
/// earlier one refuted, though the file is in the change: no new code is in
/// its path since. The attacker is told each by its run and id; one it
/// names again stays in `refuted_before`, and one an earlier attack did not
/// run carries `again`. New code in the path tries it again.
#[test]
fn what_was_refuted_is_not_refuted_again_without_new_code_in_its_path() {
    let project = project();
    let card = "card_1";
    let refuted = json!({ "title": "a forged cookie is replayed", "class": "authn", "file": SESSION,
        "line": 2, "severity": "high", "status": "refuted", "control": SESSION,
        "reason": "each cookie is used once" });
    let not_run = json!({ "title": "a deleted user keeps a session", "class": "authz",
        "file": "src/auth/users.rs", "line": 5, "severity": "medium", "status": "not_run",
        "reason": "needs a running instance" });
    let run = project.earlier(
        card,
        &project.second,
        &[(refuted, "exit 0\n"), (not_run, "exit 0\n")],
    );
    let yaml = "version: 1\nstages:\n  attack: { run: sensitive, test: 'sh \"$DEVFLOW_EXPLOIT\"', sandbox: off }\n";
    let answered = json!([
        { "id": "h1", "title": "A replayed cookie is taken again", "class": "session", "file": SESSION,
          "line": 3, "severity": "high", "status": "refuted", "control": SESSION, "reason": "used once" },
        { "id": "h2", "title": "Sessions outlive their user", "class": "authz", "file": SESSION,
          "line": 30, "severity": "medium", "status": "not_run", "reason": "needs an instance",
          "same_as": format!("{run}/h2") },
    ]);
    let (report, prompt) = project.attack(
        card,
        &project.first,
        &project.second,
        yaml,
        answered.clone(),
    );
    let listed = prompt
        .split("## Refuted before, no new code in their path since")
        .nth(1)
        .expect("refuted section");
    assert!(
        listed.contains(&format!("\"run\":\"{run}\"")) && listed.contains("\"id\":\"h1\""),
        "{listed}"
    );
    assert!(prompt.contains("## Not run before"), "{prompt}");
    // Nothing changed since that attack: the attacker looks only past it.
    assert!(
        prompt.contains(&format!(
            "## No code changed since run {run} attacked this head"
        )),
        "{prompt}"
    );
    assert_eq!(report["not_tried_again"], 1, "{report:#}");
    assert_eq!(report["named_again"], 1);
    assert_eq!(report["refuted_before"][0]["run"], run.as_str());
    assert_eq!(report["refuted_before"][0]["id"], "h1");
    assert_eq!(report["refuted_before"][0]["named_again"], true);
    let hypotheses = report["hypotheses"].as_array().expect("hypotheses");
    assert_eq!(hypotheses.len(), 1, "{hypotheses:#?}");
    assert_eq!(hypotheses[0]["status"], "not_run");
    assert_eq!(
        hypotheses[0]["again"],
        json!({ "item": card, "run": run, "id": "h2", "was": "not_run" })
    );
    assert_eq!(report["counts"]["refuted"], 0);

    // New code in its path, not committed yet: it is tried again.
    std::fs::write(
        project.checkout.join(SESSION),
        "fn a() {}\nfn b() {}\nfn c() {}\n",
    )
    .expect("code");
    let (report, prompt) = project.attack(
        card,
        &project.first,
        &project.second,
        yaml,
        answered.clone(),
    );
    assert_eq!(report["not_tried_again"], 0, "{report:#}");
    assert_eq!(report["counts"]["refuted"], 1);
    assert!(!prompt.contains("## No code changed since"), "{prompt}");

    // Committed, it is still tried again.
    git(&project.checkout, &["commit", "-q", "-am", "third"]);
    let third = git(&project.checkout, &["rev-parse", "HEAD"]);
    let (report, prompt) = project.attack(card, &project.first, &third, yaml, answered);
    assert_eq!(report["not_tried_again"], 0, "{report:#}");
    assert_eq!(report["refuted_before"], json!([]));
    assert!(
        prompt.contains("no new code in their path since: not to be tried again; one you name again carries `same_as`, its run/id as listed (data)\nnone"),
        "{prompt}"
    );
    assert_eq!(report["counts"]["refuted"], 1);
}

/// A hypothesis run again keeps what it took in by then, each named by the
/// run that kept it; a hole an older run kept that it had already taken in
/// is not said twice.
#[test]
fn a_hypothesis_run_again_keeps_what_it_took_in() {
    let project = project();
    let card = "card_1";
    let hole = |title: &str, status: &str, test: &str| {
        json!({ "title": title, "class": "tls", "file": SESSION, "line": 3, "severity": "low",
            "status": status, "reason": "the certificate is not checked",
            "exploit": { "path": format!("tests/security/{test}.test.ts"), "test": test } })
    };
    let older = project.earlier_at(
        card,
        &project.first,
        &[(
            hole("Postgres accepts any certificate", "tried", "any cert"),
            "exit 2\n",
        )],
        1_789_000_000,
    );
    let mut kept = hole("database TLS skips verification", "confirmed", "verify");
    kept["merged"] = json!([
        { "id": "h1", "run": older, "class": "tls", "file": SESSION, "line": 3,
          "title": "Postgres accepts any certificate" },
        { "id": "h4", "run": null, "class": "ssl", "file": SESSION, "line": 4,
          "title": "pg ssl off", "found_by": ["codex/default"] },
    ]);
    let newer = project.earlier_at(card, &project.first, &[(kept, JEST_RED)], 1_790_000_000);
    let yaml = "version: 1\nstages:\n  attack: { run: sensitive, test: 'sh \"$DEVFLOW_EXPLOIT\"', sandbox: off }\n";
    let (report, _) = project.attack(card, &project.first, &project.second, yaml, json!([]));
    assert_eq!(report["run_again"], 1, "{report:#}");
    let again = &report["hypotheses"][0];
    assert_eq!(again["again"]["run"], newer.as_str());
    let merged: Vec<(&str, &str, &str)> = again["merged"]
        .as_array()
        .expect("merged kept")
        .iter()
        .map(|one| {
            (
                one["id"].as_str().unwrap_or("-"),
                one["said_as"].as_str().unwrap_or("-"),
                one["run"].as_str().unwrap_or("-"),
            )
        })
        .collect();
    // An older report's attacker's own, named by `id` then, is said by the
    // id its attacker gave it, apart from the ids of any run.
    assert_eq!(
        merged,
        [("h1", "-", older.as_str()), ("-", "h4", newer.as_str())],
        "{again:#}"
    );
}

const SANDBOX_OFF: &str = "version: 1\nstages:\n  attack: { run: sensitive, test: 'sh \"$DEVFLOW_EXPLOIT\"', sandbox: off }\n";

/// Each hypothesis's `again` as `id of run`, in the report's order.
fn again_of(report: &Value) -> Vec<String> {
    report["hypotheses"]
        .as_array()
        .expect("hypotheses")
        .iter()
        .map(|one| format!("{} of {}", one["again"]["id"], one["again"]["run"]))
        .collect()
}

/// Fourteen holes an earlier run confirmed, past the cap of twelve run
/// again: the most severe run first, the two left are carried to the next
/// run, said so in the report, and run first there. No hole is lost.
#[test]
fn fourteen_confirmed_with_a_cap_of_twelve_carry_two_that_come_back_next_run() {
    let project = project();
    let card = "card_1";
    let hole = |n: u64, severity: &str| {
        (
            json!({ "title": format!("hole {n}"), "class": "authn", "file": SESSION, "line": n * 10,
                "severity": severity, "status": "confirmed", "reason": "shown",
                "exploit": { "path": format!("tests/security/h{n}.test.ts"), "test": format!("hole {n}") } }),
            format!("exit 1 # hole {n}\n"),
        )
    };
    let mut kept: Vec<(Value, String)> = (1..=12).map(|n| hole(n, "low")).collect();
    kept.push(hole(13, "high"));
    kept.push(hole(14, "medium"));
    let listed: Vec<(Value, &str)> = kept
        .iter()
        .map(|(one, code)| (one.clone(), code.as_str()))
        .collect();
    let first = project.earlier(card, &project.first, &listed);
    let (report, prompt) = project.attack(
        card,
        &project.first,
        &project.second,
        SANDBOX_OFF,
        json!([]),
    );
    assert_eq!(report["run_again"], 12, "{report:#}");
    assert_eq!(report["run_again_cap"], 12, "{report:#}");
    assert_eq!(report["run_again_capped"], 2, "{report:#}");
    let ran = again_of(&report);
    let quoted = |id: &str, run: &str| format!("\"{id}\" of \"{run}\"");
    assert!(
        ran.contains(&quoted("h13", &first)),
        "the most severe first: {ran:?}"
    );
    assert!(ran.contains(&quoted("h14", &first)), "{ran:?}");
    let carried = report["carried"].as_array().expect("carried");
    let ids: Vec<&str> = carried
        .iter()
        .filter_map(|one| one["again"]["id"].as_str())
        .collect();
    assert_eq!(ids, ["h11", "h12"], "{report:#}");
    let folder = project
        .runs()
        .home
        .join(card)
        .join(report["run"].as_str().expect("run"));
    for one in carried {
        assert_eq!(one["carried"], "cap");
        assert_eq!(one["status"], "confirmed");
        assert_eq!(one["severity"], "low");
        assert_eq!(one["again"]["run"], first.as_str());
        assert_eq!(one["again"]["was"], "confirmed");
        // Its exploit is kept in this run, so the next one can run it.
        let saved = one["exploit"]["saved"].as_str().expect("saved");
        assert!(std::fs::read_to_string(folder.join(saved))
            .expect("kept")
            .starts_with("exit 1 # hole 1"));
    }
    assert_eq!(report["counts"]["carried"], 2, "{report:#}");
    // The attacker is told, so it does not look for them again.
    let told = prompt.split("## Carried").nth(1).expect("carried told");
    assert!(
        told.contains("hole 11") && told.contains("hole 12"),
        "{told}"
    );
    // The reports say it in devflow's words.
    let shown = devflow_engine::attack_report::json_of(&report, &Default::default());
    assert_eq!(shown["run_again_capped"], 2, "{shown:#}");
    assert_eq!(shown["carried"][0]["id"], "h11", "{shown:#}");
    assert_eq!(shown["carried"][0]["run"], first.as_str(), "{shown:#}");
    assert_eq!(shown["carried"][0]["carried"], "cap", "{shown:#}");
    assert_eq!(shown["carried"][0]["was"], "confirmed", "{shown:#}");
    let md = devflow_engine::attack_report::markdown(&report, &Default::default());
    assert!(md.contains("## Carried to the next run"), "{md}");
    assert!(md.contains(&format!("- h11 of run {first}")), "{md}");
    assert!(md.contains("past the cap of 12 run again"), "{md}");

    // The next run: the two carried run first, by the run that confirmed
    // them; two others are carried in their place.
    let (next, _) = project.attack_answered_at(
        card,
        &project.first,
        &project.second,
        SANDBOX_OFF,
        json!({ "version": 1, "hypotheses": [] }),
        1_793_000_000,
    );
    let ran = again_of(&next);
    assert!(ran.contains(&quoted("h11", &first)), "{ran:?}");
    assert!(ran.contains(&quoted("h12", &first)), "{ran:?}");
    let carried = next["carried"].as_array().expect("carried");
    assert_eq!(carried.len(), 2, "{next:#}");
    // Run or carried, each of the fourteen is there once.
    let mut titles: Vec<String> = next["hypotheses"]
        .as_array()
        .expect("hypotheses")
        .iter()
        .chain(carried)
        .filter_map(|one| one["title"].as_str().map(str::to_owned))
        .collect();
    titles.sort();
    titles.dedup();
    assert_eq!(titles.len(), 14, "{titles:?}");
}

/// A hypothesis an earlier attack did not run, which the attacker does not
/// name again, is carried with its run and id, and listed to the next
/// attacker, where naming it carries `again` back to that run.
#[test]
fn a_not_run_hypothesis_not_named_again_is_carried_and_listed_next_run() {
    let project = project();
    let card = "card_1";
    let not_run = json!({ "title": "a deleted user keeps a session", "class": "authz",
        "file": "src/auth/users.rs", "line": 5, "severity": "medium", "status": "not_run",
        "reason": "needs a running instance" });
    let first = project.earlier(card, &project.first, &[(not_run, "exit 0\n")]);
    let (report, _) = project.attack(
        card,
        &project.first,
        &project.second,
        SANDBOX_OFF,
        json!([]),
    );
    let carried = report["carried"].as_array().expect("carried");
    assert_eq!(carried.len(), 1, "{report:#}");
    assert_eq!(carried[0]["carried"], "not_named");
    assert_eq!(carried[0]["status"], "not_run");
    assert_eq!(
        carried[0]["again"],
        json!({ "item": card, "run": first, "id": "h1", "was": "not_run" })
    );
    let md = devflow_engine::attack_report::markdown(&report, &Default::default());
    assert!(md.contains(&format!("- h1 of run {first}")), "{md}");

    let named = json!({ "version": 1, "hypotheses": [
        { "id": "h1", "title": "Sessions outlive their user", "class": "authz", "file": "src/auth/users.rs",
          "line": 40, "severity": "medium", "status": "not_run", "reason": "needs an instance",
          "same_as": format!("{first}/h1") } ] });
    let (next, prompt) = project.attack_answered_at(
        card,
        &project.first,
        &project.second,
        SANDBOX_OFF,
        named,
        1_793_000_000,
    );
    let listed = prompt.split("## Not run before").nth(1).expect("listed");
    assert!(
        listed.contains(&format!("\"run\":\"{first}\"")) && listed.contains("\"id\":\"h1\""),
        "{listed}"
    );
    assert_eq!(
        next["hypotheses"][0]["again"],
        json!({ "item": card, "run": first, "id": "h1", "was": "not_run" }),
        "{next:#}"
    );
    assert_eq!(next["carried"], json!([]), "{next:#}");
}

/// Thirteen high holes an earlier run confirmed, each exploit its own: the
/// thirteenth is past the cap.
fn thirteen_high(project: &Project, card: &str, at: u64) -> String {
    let codes: Vec<String> = (1..=13).map(|n| format!("exit 1 # hole {n}\n")).collect();
    let kept: Vec<(Value, &str)> = (1..=13u64)
        .map(|n| (high_hole(n), codes[n as usize - 1].as_str()))
        .collect();
    project.earlier_at(card, &project.first, &kept, at)
}

fn high_hole(n: u64) -> Value {
    json!({ "title": format!("hole {n}"), "class": "authn", "file": SESSION, "line": n * 10,
        "severity": "high", "status": "confirmed", "reason": "shown",
        "exploit": { "path": format!("tests/security/h{n}.test.ts"), "test": format!("hole {n}") } })
}

/// A carried hole stays carried, holding, when what the attacker says at its
/// place does not show it: only an attacker's confirmed exploit takes it in.
#[test]
fn a_carried_hole_is_taken_in_only_by_a_hypothesis_that_shows_it() {
    let project = project();
    let card = "card_1";
    thirteen_high(&project, card, 1_791_000_000);
    let nearby = json!([{ "id": "h1", "title": "something else nearby", "class": "authn", "file": SESSION,
        "line": 131, "severity": "low", "status": "not_run", "reason": "could not try" }]);
    let (report, _) = project.attack(card, &project.first, &project.second, SANDBOX_OFF, nearby);
    let carried = report["carried"].as_array().expect("carried");
    assert_eq!(carried.len(), 1, "{report:#}");
    assert_eq!(carried[0]["again"]["id"], "h13");
    assert_eq!(report["run_again_capped"], 1);
    assert_eq!(report["verdict"], "request_changes", "{report:#}");
    let own = report["hypotheses"]
        .as_array()
        .expect("hypotheses")
        .iter()
        .find(|one| one["status"] == "not_run")
        .expect("the attacker's own");
    assert!(own["again"].is_null(), "{own:#}");
}

/// A hole a newer run ran again green is shut: an older run that confirmed
/// it does not bring it back, run again or carried.
#[test]
fn a_hole_a_newer_run_showed_shut_is_not_brought_back_by_an_older_one() {
    let project = project();
    let card = "card_1";
    let first = thirteen_high(&project, card, 1_791_000_000);
    let codes: Vec<String> = (1..=13).map(|n| format!("exit 1 # hole {n}\n")).collect();
    let shut: Vec<(Value, &str)> = (1..=13u64)
        .map(|n| {
            let mut one = high_hole(n);
            one["status"] = json!("refuted");
            one["ran"] = json!({ "result": "refuted", "reason": "green: the hole is not there" });
            one["again"] =
                json!({ "item": card, "run": first, "id": format!("h{n}"), "was": "confirmed" });
            (one, codes[n as usize - 1].as_str())
        })
        .collect();
    project.earlier_at(card, &project.second, &shut, 1_791_500_000);
    let (report, _) = project.attack(
        card,
        &project.first,
        &project.second,
        SANDBOX_OFF,
        json!([]),
    );
    assert_eq!(report["run_again"], 0, "{report:#}");
    assert_eq!(report["carried"], json!([]), "{report:#}");
    assert_eq!(report["verdict"], "approve");
}

/// An earlier attack whose attackers gave no answer settles nothing: an
/// attack again at its head is not told that nothing is left to look at.
#[test]
fn an_attack_that_failed_does_not_say_nothing_changed_since() {
    let project = project();
    let card = "card_1";
    let run = project.earlier(card, &project.second, &[]);
    std::fs::write(
        project.runs().home.join(card).join(&run).join(attack::REPORT),
        json!({ "head": project.second, "hypotheses": [],
            "attackers": [{ "agent": "claude", "reason": "its time ran out", "result": "not_run", "cap_hit": true }] })
        .to_string(),
    )
    .expect("a failed attack");
    let (_, prompt) = project.attack(
        card,
        &project.first,
        &project.second,
        SANDBOX_OFF,
        json!([]),
    );
    assert!(!prompt.contains("## No code changed since"), "{prompt}");
}

fn variant(line: u64, status: &str) -> Value {
    json!({ "title": format!("variant at {line}"), "class": "authn", "file": SESSION,
        "line": line, "severity": "high", "status": status, "reason": "shown",
        "exploit": { "path": format!("tests/security/v{line}.test.ts"), "test": format!("variant {line}") } })
}

/// A variant shown shut beside a confirmed one of the same hole, in the same
/// run, shuts only itself: the confirmed one is run again.
#[test]
fn a_variant_shown_shut_does_not_hide_a_confirmed_one_beside_it() {
    let project = project();
    let card = "card_1";
    let mut green = variant(12, "refuted");
    green["ran"] = json!({ "result": "refuted", "reason": "green: the hole is not there" });
    green["verified"] = json!({ "result": "refuted", "by": "sandbox" });
    project.earlier(
        card,
        &project.first,
        &[(variant(10, "confirmed"), "exit 1\n"), (green, "exit 0\n")],
    );
    let (report, _) = project.attack(
        card,
        &project.first,
        &project.second,
        SANDBOX_OFF,
        json!([]),
    );
    assert_eq!(report["run_again"], 1, "{report:#}");
    assert_eq!(report["hypotheses"][0]["title"], "variant at 10");
}

/// A refutation in the attacker's word alone, though it names again what was
/// not run, shuts nothing: what a newer run confirmed again is run again.
#[test]
fn a_refutation_no_run_showed_shuts_nothing() {
    let project = project();
    let card = "card_1";
    let first = project.earlier_at(
        card,
        &project.first,
        &[(variant(10, "confirmed"), "exit 1\n")],
        1_791_000_000,
    );
    let mut again = variant(10, "confirmed");
    again["again"] = json!({ "item": card, "run": first, "id": "h1", "was": "confirmed" });
    let mut word = variant(13, "refuted");
    word["again"] = json!({ "item": card, "run": first, "id": "h9", "was": "not_run" });
    project.earlier_at(
        card,
        &project.second,
        &[(again, "exit 1\n"), (word, "exit 0\n")],
        1_791_500_000,
    );
    let (report, _) = project.attack(
        card,
        &project.first,
        &project.second,
        SANDBOX_OFF,
        json!([]),
    );
    assert_eq!(report["run_again"], 1, "{report:#}");
    assert_eq!(
        report["verdict"], "approve",
        "sandbox off: run again, tried"
    );
    assert_eq!(report["carried"], json!([]));
}

/// A hole a sibling range's newer run showed shut is not brought back by
/// this range's own older run: every folder's shut holes are known first.
#[test]
fn a_hole_a_sibling_range_showed_shut_stays_shut() {
    let project = project();
    let card = format!("{}-{}", short(&project.first), short(&project.second));
    let own = project.earlier_at(
        &card,
        &project.first,
        &[(variant(10, "confirmed"), "exit 1\n")],
        1_791_000_000,
    );
    let mut green = variant(10, "refuted");
    green["ran"] = json!({ "result": "refuted", "reason": "green: the hole is not there" });
    green["again"] = json!({ "item": card, "run": own, "id": "h1", "was": "confirmed" });
    let sibling = format!("{}-{}", short(&project.first), short(&project.first));
    project.earlier_at(
        &sibling,
        &project.first,
        &[(green, "exit 1\n")],
        1_791_500_000,
    );
    let (report, _) = project.attack(
        &card,
        &project.first,
        &project.second,
        SANDBOX_OFF,
        json!([]),
    );
    assert_eq!(report["run_again"], 0, "{report:#}");
    assert_eq!(report["carried"], json!([]));
}

/// A proof shown shut that took in an older one, written another way (a
/// count proof that took in a timing one), shuts that older one too.
#[test]
fn a_proof_shown_shut_shuts_what_it_took_in() {
    let project = project();
    let card = "card_1";
    let timed = project.earlier_at(
        card,
        &project.first,
        &[(variant(10, "confirmed"), "exit 1 # by time\n")],
        1_791_000_000,
    );
    let mut count = variant(10, "refuted");
    count["exploit"] = json!({ "path": "tests/security/count.test.ts", "test": "counts" });
    count["ran"] = json!({ "result": "refuted", "reason": "green: the hole is not there" });
    count["again"] =
        json!({ "item": card, "run": "20260901T000000Z", "id": "h4", "was": "confirmed" });
    count["merged"] = json!([{ "id": "h1", "run": timed, "class": "authn", "line": 10 }]);
    project.earlier_at(
        card,
        &project.second,
        &[(count, "exit 1 # by count\n")],
        1_791_500_000,
    );
    let (report, _) = project.attack(
        card,
        &project.first,
        &project.second,
        SANDBOX_OFF,
        json!([]),
    );
    assert_eq!(report["run_again"], 0, "{report:#}");
}
