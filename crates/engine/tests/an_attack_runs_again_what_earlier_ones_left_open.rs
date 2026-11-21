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
        let bin = self.root.join(format!("bin-{card}"));
        std::fs::create_dir_all(&bin).expect("bin");
        let claude = fake_claude(&bin, &json!({ "version": 1, "hypotheses": hypotheses }));
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
            at: SystemTime::UNIX_EPOCH + Duration::from_secs(1_792_000_000),
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
        prompt.contains("## Run again at HEAD before you, from earlier attacks"),
        "{prompt}"
    );
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
    let (report, _) = project.attack(card, &project.first, &project.second, yaml, json!([]));
    assert_eq!(report["run_again"], 0, "{report:#}");
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
    assert_eq!(report["verdict"], "request_changes");
    assert!(prompt.contains("\"status\":\"confirmed\""), "{prompt}");
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
    assert!(again.contains(&("tls", confirmed.as_str())), "{again:?}");
    assert!(
        again.iter().any(|(class, _)| *class == "secrets"),
        "{again:?}"
    );
}
