//! The attack is a stage after review: read as `stages.attack` in either
//! version, `review.attack` its older name, `sensitive` unless said. It keeps
//! a report of hypotheses with their exploits out of the checkout, and the
//! gate holds an item it is due on until it ran and what it confirmed is
//! shut.

use devflow_engine::config::{self, AttackRun, Config};
use devflow_engine::gate::{checked, Looked, Run};
use devflow_engine::{attack, models, Dialect};
use serde_json::{json, Value};

const SENSITIVE: &str = "src/auth/session.rs";
const DIFF: &str = "diff --git a/src/auth/session.rs b/src/auth/session.rs\n--- a/src/auth/session.rs\n+++ b/src/auth/session.rs\n@@ -1,1 +1,2 @@\n fn a() {}\n+let claims = decode_unverified(cookie);\n";

fn parsed(text: &str) -> Config {
    config::parse(text).expect(text)
}

#[test]
fn the_attack_stage_reads_in_either_version_with_review_attack_as_its_older_name() {
    for silent in [
        "version: 1\n",
        "version: 2\nstages:\n  - uses: builtin/review\n",
    ] {
        // A file that names no attack stage runs none, as 0.5.x did.
        let config = parsed(silent);
        assert_eq!(config.stages.attack.run, AttackRun::Off, "{silent}");
        assert!(!config.stages_on().contains(&"attack"), "{silent}");
    }
    // Named with no `run`, it is sensitive.
    let named = parsed(
        "version: 2
stages:
  - uses: builtin/attack
    model: large
",
    );
    assert_eq!(named.stages.attack.run, AttackRun::Sensitive);
    let v1 = parsed("version: 1\nstages:\n  attack: { run: per-item, model: large }\n");
    assert_eq!(v1.stages.attack.run, AttackRun::PerItem);
    assert_eq!(
        models::stage_model(&v1, models::ATTACK).as_deref(),
        Some("large")
    );
    let v2 = parsed(
        "version: 2\nstages:\n  - uses: builtin/review\n  - uses: builtin/attack\n    run: release\n  - uses: builtin/completion\n",
    );
    assert_eq!(v2.stages.attack.run, AttackRun::Release);
    let off = parsed("version: 2\nstages:\n  - uses: builtin/attack\n    enabled: false\n");
    assert!(!off.stages_on().contains(&"attack"));

    let older =
        parsed("version: 2\nreview:\n  attack: { run: per-item, model: claude-opus-5-5 }\n");
    assert_eq!(older.stages.attack.run, AttackRun::PerItem);
    assert_eq!(
        models::stage_model(&older, models::ATTACK).as_deref(),
        Some("claude-opus-5-5")
    );
    let written = devflow_engine::render::render(&older);
    assert!(written.contains("builtin/attack") && !written.contains("review:\n  attack"));
    assert_eq!(parsed(&written).stages, older.stages, "{written}");
    let twice = config::parse("version: 1\nstages:\n  attack: per-item\nreview:\n  attack: off\n")
        .expect_err("said twice, apart");
    assert_eq!(twice.field, "review.attack");
    let explicit =
        config::parse("version: 1\nstages:\n  attack: sensitive\nreview:\n  attack: off\n")
            .expect_err("said twice, apart, even at the default");
    assert_eq!(explicit.field, "review.attack");

    let sandboxed = parsed(
        "version: 2\nstages:\n  - uses: builtin/attack\n    run: per-item\n    test: npx jest \"$DEVFLOW_EXPLOIT\"\n    sandbox: docker\n    image: node:22\n",
    );
    assert_eq!(
        sandboxed.stages.attack.sandbox,
        Some(config::SandboxChoice::Docker)
    );
    assert_eq!(sandboxed.stages.attack.image.as_deref(), Some("node:22"));
    let written = devflow_engine::render::render(&sandboxed);
    assert_eq!(
        parsed(&written).stages.attack,
        sandboxed.stages.attack,
        "{written}"
    );

    let set = devflow_engine::preset::with_set(&older, "review.attack", &json!("off"))
        .expect("the older name is set where it is in force");
    assert_eq!(set.stages.attack.run, AttackRun::Off);
    let set = devflow_engine::preset::with_set(&v1, "stages.attack.run", &json!("release"))
        .expect("set by its name");
    assert_eq!(set.stages.attack.run, AttackRun::Release);
}

#[test]
fn the_attack_is_due_by_its_run_and_the_review_reads_no_attack() {
    let small = vec!["README.md".to_owned()];
    let readme = "diff --git a/README.md b/README.md\n--- a/README.md\n+++ b/README.md\n@@ -1 +1 @@\n-a\n+b\n";
    let sensitive = vec![SENSITIVE.to_owned()];
    let with = |run: &str| parsed(&format!("version: 2\nreview:\n  attack: {run}\n"));
    let due =
        |config: &Config, files: &[String], diff: &str| models::attack_on(config, files, diff);
    assert!(
        !due(&Config::default(), &sensitive, DIFF),
        "off unless said"
    );
    let sensitive_run = with("sensitive");
    assert!(due(&sensitive_run, &sensitive, DIFF), "sensitive when said");
    assert!(!due(&sensitive_run, &small, readme));
    assert!(due(&with("per-item"), &small, readme));
    assert!(
        !due(&with("release"), &sensitive, DIFF),
        "a release's is asked by name"
    );
    assert!(!due(&with("off"), &sensitive, DIFF));
    let asked = models::attack_asked(&with("release")).expect("asked by name");
    assert!(due(&asked, &small, readme));
    assert!(models::attack_asked(&with("off")).is_err());
    for config in [with("per-item"), Config::default()] {
        assert!(
            models::readers(&config, false, &sensitive, DIFF)
                .iter()
                .all(|reader| reader.stage != models::ATTACK),
            "the review reads; the attack is its own stage"
        );
    }
    assert_eq!(
        models::stage_model(&Config::default(), models::ATTACK).as_deref(),
        Some("large")
    );
}

/// A Claude Code that answers with `answer`, in its envelope.
#[cfg(unix)]
fn fake_claude(dir: &std::path::Path, answer: &Value) -> std::path::PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let envelope =
        json!({ "type": "result", "result": answer.to_string(), "total_cost_usd": 0.42 });
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

#[cfg(unix)]
#[test]
fn the_attack_keeps_each_hypothesis_and_its_exploits_out_of_the_checkout() {
    use std::time::{Duration, SystemTime};
    let dir = tempfile::tempdir().expect("dir");
    let root = dir.path().canonicalize().expect("root");
    let checkout = root.join("checkout");
    std::fs::create_dir_all(&checkout).expect("checkout");
    let code = "test('a cookie signed with another key is refused', () => {})";
    let claude = fake_claude(
        &root,
        &json!({ "version": 1, "hypotheses": [
            { "id": "h1", "title": "a cookie signed with any key is accepted", "class": "authn",
              "file": SENSITIVE, "line": 2, "severity": "high", "status": "confirmed",
              "reason": "the signature is never checked", "from": "r0",
              "exploit": { "path": "tests/session.exploit.test.ts", "test": "a cookie signed with another key is refused", "code": code } },
            { "id": "h2", "title": "the cookie is read over plain http", "file": SENSITIVE, "line": 1,
              "severity": "medium", "status": "refuted", "reason": "the server only listens on TLS" },
            { "id": "h3", "title": "a replayed cookie after logout", "file": SENSITIVE, "line": 2,
              "severity": "medium", "status": "not_run", "reason": "needs the running app and no target is in force" },
        ] }),
    );
    let reach =
        move |_: config::Agent| -> Result<String, String> { Ok(claude.display().to_string()) };
    let redact = |text: &str| text.to_owned();
    let runs = devflow_engine::runs::Runs {
        dialect: &Dialect::DEVFLOW,
        home: root.join("home"),
        checkout: checkout.clone(),
    };
    let config = Config::default();
    let files = vec![SENSITIVE.to_owned()];
    let review = json!({ "findings": [
        { "axis": "security", "title": "unsigned cookie", "file": SENSITIVE, "line": 2, "severity": "high", "description": "d", "poc": "p" },
        { "axis": "spec", "title": "not security", "file": "a.rs", "line": 1, "severity": "high" },
    ] });
    assert_eq!(attack::from_review(Some(&review)).len(), 1);
    let done = attack::attacked(&attack::Given {
        root: &checkout,
        runs: &runs,
        config: &config,
        card: devflow_engine::evidence::Card {
            id: "card_1",
            title: "Sessions",
            body: "",
        },
        git: devflow_engine::review::Git {
            base: "b4se",
            head: "he4d",
            files: &files,
            diff: DIFF,
        },
        brief: None,
        evidence: None,
        review: Some(&review),
        env: &[],
        at: SystemTime::UNIX_EPOCH + Duration::from_secs(1_792_000_000),
        budget: Duration::from_secs(60),
        reach: &reach,
        redact: &redact,
        personas: devflow_engine::review::Personas::default(),
        retro: false,
        scratch: None,
        flow: None,
        stack: None,
        ledger: None,
    })
    .expect("attacked");
    let report = &done.report;
    let statuses: Vec<&str> = report["hypotheses"]
        .as_array()
        .expect("hypotheses")
        .iter()
        .filter_map(|one| one["status"].as_str())
        .collect();
    assert_eq!(
        statuses,
        ["tried", "refuted", "not_run"],
        "only a run confirms"
    );
    assert!(report["hypotheses"][0]["reason"]
        .as_str()
        .expect("reason")
        .starts_with("only a run"));
    assert_eq!(report["hypotheses"][0]["from"], "r0");
    assert_eq!(report["verdict"], "approve");
    assert_eq!(report["attackers"][0]["cost_usd"], 0.42);
    assert_eq!(
        report["metrics"]["cost_usd"], 0.42,
        "the report keeps its numbers"
    );
    assert_eq!(report["metrics"]["refuted"], 1);
    assert_eq!(report["budget"]["run_capped_by"], "time", "its cap is said");
    let saved = report["hypotheses"][0]["exploit"]["saved"]
        .as_str()
        .expect("saved");
    let folder = std::path::Path::new(&done.folder);
    assert_eq!(
        std::fs::read_to_string(folder.join(saved)).expect("kept"),
        code
    );
    assert!(
        !report.to_string().contains(code),
        "the report names the file, not the code"
    );
    assert!(folder.join(attack::REPORT).is_file());
    let written: Vec<_> = std::fs::read_dir(&checkout)
        .expect("checkout")
        .filter_map(Result::ok)
        .map(|entry| entry.file_name())
        .collect();
    assert!(written.is_empty(), "nothing in the checkout: {written:?}");

    let refused = attack::verified(
        folder,
        &config,
        &[
            json!({ "hypothesis": "h1", "result": "confirmed", "evidence": "red" , "target": "http://example.com" }),
        ],
    );
    assert!(
        refused.is_err(),
        "a run against a host not in force is refused"
    );
    let report = attack::verified(
        folder,
        &config,
        &[json!({ "hypothesis": "h1", "result": "confirmed", "evidence": "red in run r2" })],
    )
    .expect("confirmed");
    assert_eq!(report["verdict"], "request_changes");
    assert_eq!(report["counts"]["confirmed"], 1);
    assert_eq!(
        attack::exploits(&report)[0]["test"],
        "a cookie signed with another key is refused"
    );
}

#[test]
fn an_attackers_answer_is_held_to_its_shape() {
    let refused = |answer: Value| attack::read_answer(&answer.to_string()).expect_err("refused");
    assert!(refused(json!({ "nothing": [] })).contains("hypotheses"));
    assert!(refused(json!({ "hypotheses": [{ "title": "t", "severity": "high", "status": "tried", "reason": "r" }] }))
        .contains("exploit"));
    assert!(refused(
        json!({ "hypotheses": [{ "title": "t", "severity": "high", "status": "tried", "reason": "r",
        "exploit": { "path": "../outside.test.ts", "test": "t", "code": "c" } }] })
    )
    .contains("no `..`"));
    assert!(refused(json!({ "hypotheses": [{ "title": "t", "severity": "grave", "status": "refuted", "reason": "r" }] }))
        .contains("severity"));
}

fn looked_with<'a>(
    config: &'a Config,
    evidence: &'a Value,
    stages: &'a [(String, Option<(String, Value)>)],
    changed: Option<&'a str>,
) -> Looked<'a> {
    Looked {
        dialect: &Dialect::DEVFLOW,
        config,
        card: "card_1",
        criteria: &[],
        run: Some(Run {
            name: "20261119T120000Z",
            evidence,
        }),
        review: None,
        changed,
        stages,
        unreviewed: None,
        no_code: true,
    }
}

#[test]
fn the_gate_holds_an_item_the_attack_is_due_on_until_it_ran_and_its_holes_are_shut() {
    let config = parsed("version: 2\nstages:\n  - uses: builtin/execution\n    checks:\n      - { name: unit, run: make test, report: junit }\n");
    let evidence = |green: bool| {
        json!({ "checks": [{ "name": "unit", "result": "passed" }], "red": if green {
            json!([{ "test": "exploit", "now": "passed" }])
        } else { json!([]) } })
    };
    let missing =
        |stages: &[(String, Option<(String, Value)>)], green: bool, changed: Option<&str>| {
            let evidence = evidence(green);
            checked(&looked_with(&config, &evidence, stages, changed)).missing
        };
    let attack = |stages: &str| stages.contains("attack stage");
    let due_not_run = vec![(config::ATTACK.to_owned(), None)];
    assert!(missing(&due_not_run, true, None)
        .iter()
        .any(|said| attack(said)));
    assert!(
        !missing(&[], true, None).iter().any(|said| attack(said)),
        "not due, not held"
    );

    let report = json!({ "hypotheses": [{ "id": "h1", "status": "confirmed", "severity": "high",
        "file": SENSITIVE, "line": 2, "title": "unsigned cookie", "exploit": { "test": "exploit" } }] });
    let ran = vec![(
        config::ATTACK.to_owned(),
        Some(("20261119T110000Z".to_owned(), report)),
    )];
    let red = missing(&ran, false, None);
    assert!(
        red.iter()
            .any(|said| said.contains("the exploit test `exploit`")),
        "{red:?}"
    );
    let green = missing(&ran, true, Some("20261119T115959Z"));
    assert!(
        green
            .iter()
            .all(|said| !said.contains("exploit") && !attack(said)),
        "{green:?}"
    );

    let gave_nothing = vec![(
        config::ATTACK.to_owned(),
        Some((
            "20261119T110000Z".to_owned(),
            json!({ "attackers": [{ "agent": "claude", "reason": "not installed" }], "hypotheses": [] }),
        )),
    )];
    let failed = missing(&gave_nothing, true, None);
    assert!(
        failed.iter().any(|said| said.contains("did not run")),
        "{failed:?}"
    );

    let sandboxed = |proof: Value| {
        vec![(
            config::ATTACK.to_owned(),
            Some((
                "20261119T110000Z".to_owned(),
                json!({ "hypotheses": [{ "id": "h1", "status": "confirmed", "severity": "high",
                    "file": SENSITIVE, "line": 2, "title": "unsigned cookie",
                    "verified": { "by": "sandbox", "result": "confirmed" },
                    "exploit": { "test": "exploit-x" }, "proof": proof }] }),
            )),
        )]
    };
    let unproven = missing(&sandboxed(Value::Null), true, None);
    assert!(
        unproven.iter().any(|said| said.contains("no proof")),
        "{unproven:?}"
    );
    let open = missing(
        &sandboxed(
            json!({ "base": { "commit": "a", "result": "red" }, "head": { "commit": "b", "result": "red" }, "ran_at": "20261119T115000Z" }),
        ),
        true,
        None,
    );
    assert!(
        open.iter().any(|said| said.contains("still open")),
        "{open:?}"
    );
    let shut = json!({ "base": { "commit": "a", "result": "red" }, "head": { "commit": "b", "result": "green" }, "ran_at": "20261119T115000Z" });
    let proven = missing(&sandboxed(shut.clone()), true, Some("20261119T114000Z"));
    assert!(
        proven.iter().all(|said| !said.contains("hypothesis")),
        "{proven:?}"
    );
    let stale = missing(&sandboxed(shut), true, Some("20261119T115959Z"));
    assert!(
        stale.iter().any(|said| said.contains("prove it again")),
        "{stale:?}"
    );
    let many = |severity: &str| {
        let hypotheses: Vec<Value> = (0..7)
            .map(|at| json!({ "id": format!("h{at}"), "status": "confirmed", "severity": severity,
                "file": SENSITIVE, "line": at + 1, "title": format!("hole {at}"),
                "verified": { "by": "sandbox", "result": "confirmed" }, "exploit": { "test": "t" } }))
            .collect();
        vec![(
            config::ATTACK.to_owned(),
            Some((
                "20261119T110000Z".to_owned(),
                json!({ "hypotheses": hypotheses }),
            )),
        )]
    };
    let seven = missing(&many("high"), true, None);
    assert!(
        seven.iter().any(|said| said.contains("and 1 more")),
        "every one is checked: {seven:?}"
    );
    let below = missing(&many("medium"), true, None);
    assert!(
        below.iter().all(|said| !said.contains("hypothes")),
        "below block_on is followed up: {below:?}"
    );

    let per_item = parsed("version: 1\nstages:\n  attack: per-item\n");
    let evidence = evidence(true);
    let older = checked(&looked_with(
        &per_item,
        &evidence,
        &ran,
        Some("20261119T115959Z"),
    ))
    .missing;
    assert!(
        older
            .iter()
            .any(|said| said.contains("older than the last change")),
        "{older:?}"
    );
}

fn git(repo: &std::path::Path, args: &[&str]) {
    let ok = std::process::Command::new("git")
        .args(args)
        .current_dir(repo)
        .status()
        .is_ok_and(|status| status.success());
    assert!(ok, "git {args:?}");
}

/// The attack in a repository, its answer `hypotheses`, its config `yaml`.
#[cfg(unix)]
fn attacked_with(hypotheses: Value, yaml: &str) -> Value {
    use std::time::{Duration, SystemTime};
    let dir = tempfile::tempdir().expect("dir");
    let root = dir.path().canonicalize().expect("root");
    let checkout = root.join("checkout");
    std::fs::create_dir_all(checkout.join("src/auth")).expect("checkout");
    git(&checkout, &["init", "-q"]);
    git(&checkout, &["config", "user.email", "test@example.invalid"]);
    git(&checkout, &["config", "user.name", "Test"]);
    git(&checkout, &["config", "commit.gpgsign", "false"]);
    std::fs::write(checkout.join("src/auth/session.rs"), "fn a() {}\n").expect("code");
    git(&checkout, &["add", "-A"]);
    git(&checkout, &["commit", "-q", "-m", "first"]);
    let head = devflow_engine::git::head_of(&checkout).expect("head");
    let bin = root.join("bin");
    std::fs::create_dir_all(&bin).expect("bin");
    let claude = fake_claude(&bin, &json!({ "version": 1, "hypotheses": hypotheses }));
    let reach =
        move |_: config::Agent| -> Result<String, String> { Ok(claude.display().to_string()) };
    let redact = |text: &str| text.to_owned();
    let runs = devflow_engine::runs::Runs {
        dialect: &Dialect::DEVFLOW,
        home: root.join("home"),
        checkout: checkout.clone(),
    };
    let config = parsed(yaml);
    let files = vec![SENSITIVE.to_owned()];
    let scratch = root.join("trees");
    let done = attack::attacked(&attack::Given {
        root: &checkout,
        runs: &runs,
        config: &config,
        card: devflow_engine::evidence::Card {
            id: "card_1",
            title: "Sessions",
            body: "",
        },
        git: devflow_engine::review::Git {
            base: &head,
            head: &head,
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
    assert_eq!(
        std::fs::read_to_string(checkout.join("src/auth/session.rs")).expect("code"),
        "fn a() {}\n",
        "the checkout is never written"
    );
    done.report
}

#[cfg(unix)]
fn two_exploits() -> Value {
    json!([
        { "id": "h1", "title": "a forged cookie is accepted", "file": SENSITIVE, "line": 1, "severity": "high",
          "status": "tried", "reason": "never checked",
          "exploit": { "path": "tests/forged.sh", "test": "forged-cookie", "code": "echo 'FAIL forged-cookie'; exit 1" } },
        { "id": "h2", "title": "a replayed cookie is accepted", "file": SENSITIVE, "line": 1, "severity": "high",
          "status": "tried", "reason": "maybe",
          "exploit": { "path": "tests/replayed.sh", "test": "replayed-cookie", "code": "exit 0" } },
    ])
}

/// Without a sandbox the engine runs nothing: each exploit stays tried for
/// the session, saying why under `ran`.
#[cfg(unix)]
#[test]
fn without_a_sandbox_each_exploit_waits_for_the_session_saying_why() {
    let report = attacked_with(
        two_exploits(),
        "version: 1\nstages:\n  attack: { run: sensitive, test: 'sh \"$DEVFLOW_EXPLOIT\"', sandbox: off }\n",
    );
    for one in report["hypotheses"].as_array().expect("hypotheses") {
        assert_eq!(one["status"], "tried", "{one}");
        assert_eq!(one["ran"]["result"], "not_run");
        assert!(one["ran"]["reason"]
            .as_str()
            .expect("why")
            .contains("the session runs it"));
    }
    let untold = attacked_with(two_exploits(), "version: 1\n");
    assert!(untold["hypotheses"][0]["ran"]["reason"]
        .as_str()
        .expect("why")
        .contains("stages.attack.test"));
}

/// Where a sandbox is, the engine runs each exploit and the report says
/// confirmed or refuted with no step of the session. Run where the machine
/// has one: bwrap with a network namespace, or docker with the image
/// `DEVFLOW_SANDBOX_IMAGE` names.
#[cfg(unix)]
#[test]
fn in_the_sandbox_each_exploit_comes_back_confirmed_or_refuted() {
    let image = std::env::var("DEVFLOW_SANDBOX_IMAGE").unwrap_or_default();
    let path = std::env::var_os("PATH").unwrap_or_default();
    if let Err(why) =
        devflow_engine::sandbox::found(config::SandboxChoice::Auto, Some(&image), &path)
    {
        eprintln!("not run here: {why}");
        return;
    }
    let yaml = format!(
        "version: 1\nstages:\n  attack: {{ run: sensitive, test: 'sh \"$DEVFLOW_EXPLOIT\"', image: '{image}' }}\n"
    );
    let report = attacked_with(two_exploits(), &yaml);
    let hypotheses = report["hypotheses"].as_array().expect("hypotheses");
    assert_eq!(hypotheses[0]["status"], "confirmed", "{:#}", hypotheses[0]);
    assert_eq!(hypotheses[0]["verified"]["by"], "sandbox");
    assert_eq!(hypotheses[1]["status"], "refuted", "{:#}", hypotheses[1]);
    assert_eq!(report["verdict"], "request_changes");
    assert!(
        attack::exploits(&report).is_empty(),
        "the sandbox's confirmation is held by its proof"
    );
    assert!(attack::unproven(&hypotheses[0]).is_some());
}

/// A repository whose first commit has the hole the exploit shows and whose
/// second shuts it, with the exploit kept in an attack's run as confirmed.
#[cfg(unix)]
fn fixed_repo() -> (tempfile::TempDir, std::path::PathBuf, String, String) {
    let dir = tempfile::tempdir().expect("dir");
    let root = dir.path().canonicalize().expect("root").join("checkout");
    std::fs::create_dir_all(root.join("src/auth")).expect("checkout");
    git(&root, &["init", "-q"]);
    git(&root, &["config", "user.email", "test@example.invalid"]);
    git(&root, &["config", "user.name", "Test"]);
    git(&root, &["config", "commit.gpgsign", "false"]);
    std::fs::write(root.join("src/auth/session.rs"), "accept any key\n").expect("hole");
    git(&root, &["add", "-A"]);
    git(&root, &["commit", "-q", "-m", "hole"]);
    let holed = devflow_engine::git::head_of(&root).expect("head");
    std::fs::write(root.join("src/auth/session.rs"), "check the key\n").expect("fix");
    git(&root, &["commit", "-q", "-am", "fix"]);
    let fixed = devflow_engine::git::head_of(&root).expect("head");
    (dir, root, holed, fixed)
}

/// An attack's report confirmed on the commit with the hole, or on the one
/// already fixed, proven at HEAD (the fixed one) where a sandbox is.
#[cfg(unix)]
fn proven_report(on_fixed: bool) -> (tempfile::TempDir, std::path::PathBuf, Value) {
    use std::time::{Duration, SystemTime};
    let (dir, root, holed, fixed) = fixed_repo();
    let confirmed_on = if on_fixed { &fixed } else { &holed };
    let folder = dir.path().join("run");
    std::fs::create_dir_all(folder.join("exploits/h1")).expect("run");
    std::fs::write(
        folder.join("exploits/h1/forged.sh"),
        "grep -q 'check the key' src/auth/session.rs && exit 0; echo 'FAIL forged-cookie'; exit 1\n",
    )
    .expect("exploit");
    let report = json!({ "version": 1, "head": confirmed_on, "mode": "item", "hypotheses": [{
        "id": "h1", "title": "a forged cookie is accepted", "file": SENSITIVE, "line": 1, "severity": "high",
        "status": "confirmed", "reason": "never checked", "verified": { "by": "sandbox", "result": "confirmed", "evidence": "red" },
        "exploit": { "path": "tests/forged.sh", "test": "forged-cookie", "saved": "exploits/h1/forged.sh" } }] });
    std::fs::write(folder.join(attack::REPORT), report.to_string()).expect("report");
    let image = std::env::var("DEVFLOW_SANDBOX_IMAGE").unwrap_or_default();
    let config = parsed(&format!(
        "version: 1\nstages:\n  attack: {{ run: sensitive, test: 'sh \"$DEVFLOW_EXPLOIT\"', image: '{image}' }}\n"
    ));
    let scratch = dir.path().join("trees");
    let proved = attack::prove(&attack::Proving {
        root: &root,
        folder: &folder,
        config: &config,
        head: &fixed,
        scratch: &scratch,
        at: SystemTime::UNIX_EPOCH + Duration::from_secs(1_792_000_000),
        stack: None,
    })
    .expect("proved");
    (dir, scratch, proved)
}

/// Proven where a sandbox is: the exploit red at the commit it was
/// confirmed on and green at HEAD closes it; green at its base, it does not
/// reproduce and goes back to the hypotheses. Every worktree is gone after.
#[cfg(unix)]
#[test]
fn a_confirmed_exploit_is_proven_red_at_its_base_and_green_at_head() {
    let image = std::env::var("DEVFLOW_SANDBOX_IMAGE").unwrap_or_default();
    let path = std::env::var_os("PATH").unwrap_or_default();
    if let Err(why) =
        devflow_engine::sandbox::found(config::SandboxChoice::Auto, Some(&image), &path)
    {
        eprintln!("not run here: {why}");
        return;
    }
    let (_dir, scratch, proved) = proven_report(false);
    let one = &proved["hypotheses"][0];
    assert_eq!(one["proof"]["base"]["result"], "red", "{one:#}");
    assert_eq!(one["proof"]["head"]["result"], "green", "{one:#}");
    assert!(attack::unproven(one).is_none());
    let left: Vec<_> = std::fs::read_dir(&scratch)
        .into_iter()
        .flatten()
        .filter_map(Result::ok)
        .flat_map(|entry| std::fs::read_dir(entry.path()).into_iter().flatten())
        .collect();
    assert!(
        left.is_empty(),
        "the throwaway worktrees are gone: {left:?}"
    );

    let (_dir, _, not_shown) = proven_report(true);
    let one = &not_shown["hypotheses"][0];
    assert_eq!(one["status"], "tried", "{one:#}");
    assert!(one["reason"]
        .as_str()
        .expect("reason")
        .contains("does not reproduce"));
    assert!(one.get("verified").is_none());
}

/// The proof runs at HEAD's commit: a fix left uncommitted is refused
/// before any sandbox is looked for.
#[cfg(unix)]
#[test]
fn a_proof_waits_for_the_fix_to_be_committed() {
    use std::time::SystemTime;
    let (dir, root, holed, fixed) = fixed_repo();
    std::fs::write(
        root.join("src/auth/session.rs"),
        "check the key, and more\n",
    )
    .expect("edit");
    let folder = dir.path().join("run");
    std::fs::create_dir_all(&folder).expect("run");
    std::fs::write(
        folder.join(attack::REPORT),
        json!({ "head": holed, "hypotheses": [] }).to_string(),
    )
    .expect("report");
    let refused = attack::prove(&attack::Proving {
        root: &root,
        folder: &folder,
        config: &Config::default(),
        head: &fixed,
        scratch: &dir.path().join("trees"),
        at: SystemTime::now(),
        stack: None,
    })
    .expect_err("dirty");
    assert!(refused.contains("commit the fix first"), "{refused}");
}

#[test]
fn a_budget_reads_in_dollars_and_refuses_what_is_no_amount() {
    let said = parsed("version: 1\nstages:\n  attack:\n    run: sensitive\n    budget: { run_usd: 3, month_usd: 40.5 }\n");
    assert_eq!(said.stages.attack.budget.run_cents, Some(300));
    assert_eq!(said.stages.attack.budget.month_cents, Some(4050));
    let written = devflow_engine::render::render(&said);
    assert_eq!(
        parsed(&written).stages.attack,
        said.stages.attack,
        "{written}"
    );
    for wrong in ["0", "-5", "lots", "1e9"] {
        let refused = config::parse(&format!(
            "version: 1\nstages:\n  attack:\n    run: sensitive\n    budget: {{ run_usd: {wrong} }}\n"
        ))
        .expect_err(wrong);
        assert!(refused.field.ends_with("run_usd"), "{wrong}: {refused}");
    }
}

/// The month's runs spent what it may: the next one is refused before the
/// attacker is asked anything.
#[cfg(unix)]
#[test]
fn a_run_past_the_months_budget_is_refused_before_it_starts() {
    use std::time::{Duration, SystemTime};
    let dir = tempfile::tempdir().expect("dir");
    let root = dir.path().canonicalize().expect("root");
    let home = root.join("home");
    let at = SystemTime::UNIX_EPOCH + Duration::from_secs(1_792_000_000);
    let stamp = devflow_engine::runs::stamp(at);
    devflow_engine::attack_metrics::record(
        &home,
        "card_0",
        &stamp,
        &json!({ "attackers": [{ "cost_usd": 40.0 }], "hypotheses": [] }),
    )
    .expect("spent");
    let asked = std::sync::atomic::AtomicBool::new(false);
    let reach = |_: config::Agent| -> Result<String, String> {
        asked.store(true, std::sync::atomic::Ordering::SeqCst);
        Err("never asked".to_owned())
    };
    let redact = |text: &str| text.to_owned();
    let runs = devflow_engine::runs::Runs {
        dialect: &Dialect::DEVFLOW,
        home: home.clone(),
        checkout: root.clone(),
    };
    let config = parsed(
        "version: 1\nstages:\n  attack:\n    run: sensitive\n    budget: { month_usd: 40 }\n",
    );
    let files = vec![SENSITIVE.to_owned()];
    let refused = attack::attacked(&attack::Given {
        root: &root,
        runs: &runs,
        config: &config,
        card: devflow_engine::evidence::Card {
            id: "card_1",
            title: "Sessions",
            body: "",
        },
        git: devflow_engine::review::Git {
            base: "b4se",
            head: "he4d",
            files: &files,
            diff: DIFF,
        },
        brief: None,
        evidence: None,
        review: None,
        env: &[],
        at,
        budget: Duration::from_secs(60),
        reach: &reach,
        redact: &redact,
        personas: devflow_engine::review::Personas::default(),
        retro: false,
        scratch: None,
        flow: None,
        stack: None,
        ledger: None,
    })
    .expect_err("past the month's budget");
    assert!(refused.contains("month budget"), "{refused}");
    assert!(
        !asked.load(std::sync::atomic::Ordering::SeqCst),
        "the attacker was never asked"
    );
    assert!(!home.join("card_1").exists(), "no run was made");
}

/// The month's budget is a guard that never fails open: a ledger it cannot
/// read refuses the run, and a turn that never answered counts its cap.
#[cfg(unix)]
#[test]
fn the_months_budget_never_counts_what_it_cannot_read_as_nothing() {
    use std::time::{Duration, SystemTime};
    let dir = tempfile::tempdir().expect("dir");
    let root = dir.path().canonicalize().expect("root");
    let home = root.join("home");
    std::fs::create_dir_all(&home).expect("home");
    let redact = |text: &str| text.to_owned();
    let files = vec![SENSITIVE.to_owned()];
    let runs = devflow_engine::runs::Runs {
        dialect: &Dialect::DEVFLOW,
        home: home.clone(),
        checkout: root.clone(),
    };
    let unreachable =
        |_: config::Agent| -> Result<String, String> { Err("not installed".to_owned()) };
    let attack = |config: &Config| {
        attack::attacked(&attack::Given {
            root: &root,
            runs: &runs,
            config,
            card: devflow_engine::evidence::Card {
                id: "card_1",
                title: "Sessions",
                body: "",
            },
            git: devflow_engine::review::Git {
                base: "b4se",
                head: "he4d",
                files: &files,
                diff: DIFF,
            },
            brief: None,
            evidence: None,
            review: None,
            env: &[],
            at: SystemTime::UNIX_EPOCH + Duration::from_secs(1_792_000_000),
            budget: Duration::from_secs(60),
            reach: &unreachable,
            redact: &redact,
            personas: devflow_engine::review::Personas::default(),
            retro: false,
            scratch: None,
            flow: None,
            stack: None,
            ledger: None,
        })
    };
    let capped = parsed("version: 1\nstages:\n  attack:\n    run: sensitive\n    budget: { run_usd: 3, month_usd: 40 }\n");
    let failed = attack(&capped).expect("a run with no answer");
    assert_eq!(
        failed.report["attackers"][0]["cost_usd"], 3.0,
        "its cap stands for it"
    );
    assert_eq!(failed.report["attackers"][0]["cost_estimated"], true);
    let spent = devflow_engine::attack_metrics::ledger(&home);
    assert_eq!(
        devflow_engine::attack_metrics::spent_in(
            &spent,
            devflow_engine::attack_metrics::month_of(&failed.stamp)
        ),
        3.0
    );

    let outside = root.join("elsewhere.jsonl");
    std::fs::write(&outside, "").expect("outside");
    std::fs::remove_file(home.join(devflow_engine::attack_metrics::LEDGER)).expect("moved");
    std::os::unix::fs::symlink(&outside, home.join(devflow_engine::attack_metrics::LEDGER))
        .expect("link");
    let refused = attack(&capped).expect_err("unreadable");
    assert!(refused.contains("cannot be read"), "{refused}");
    // A project whose runs' home is not there yet has spent nothing.
    let fresh = devflow_engine::attack_metrics::read_ledger(&root.join("never"));
    assert_eq!(fresh.expect("nothing yet").len(), 0);
}

/// The attack reads the project's threat model and its overlay, proposes the
/// threat model's update as a diff, and does not run again what it refuted
/// before while that control is unchanged.
#[cfg(unix)]
#[test]
fn the_attack_reads_the_threat_model_and_keeps_what_it_refuted_refuted() {
    use std::time::{Duration, SystemTime};
    let dir = tempfile::tempdir().expect("dir");
    let root = dir.path().canonicalize().expect("root");
    let checkout = root.join("checkout");
    let folder = checkout.join(devflow_engine::folder::DIR);
    std::fs::create_dir_all(folder.join("reviewers")).expect("folder");
    std::fs::write(folder.join("threat-model.md"), "assets:\n- uploads\n").expect("threat model");
    std::fs::write(
        folder.join("reviewers/devflow-security.overlay.md"),
        "Uploads are customers' files.",
    )
    .expect("overlay");
    let runs = devflow_engine::runs::Runs {
        dialect: &Dialect::DEVFLOW,
        home: root.join("home"),
        checkout: checkout.clone(),
    };
    let before = runs
        .fresh(
            "card_1",
            SystemTime::UNIX_EPOCH + Duration::from_secs(1_791_000_000),
        )
        .expect("earlier run");
    std::fs::write(
        before.join(attack::REPORT),
        json!({ "hypotheses": [{ "title": "redirect to an internal host", "class": "ssrf",
            "file": SENSITIVE, "status": "refuted", "control": "src/url_guard.rs", "reason": "guarded" }] })
        .to_string(),
    )
    .expect("earlier report");
    let bin = root.join("bin");
    std::fs::create_dir_all(&bin).expect("bin");
    let claude = fake_claude(
        &bin,
        &json!({ "version": 1, "threat_model": "assets:\n- uploads\n- session keys\n", "hypotheses": [
            { "id": "h1", "title": "redirect to an internal host", "class": "ssrf", "file": SENSITIVE, "line": 1,
              "severity": "high", "status": "tried", "reason": "again",
              "exploit": { "path": "tests/r.sh", "test": "r", "code": "exit 1" } },
            { "id": "h2", "title": "token replay", "class": "authz", "file": SENSITIVE, "line": 2,
              "severity": "high", "status": "tried", "reason": "replayed",
              "exploit": { "path": "tests/t.sh", "test": "t", "code": "exit 1" } },
        ] }),
    );
    // A report the repository carries, newer than any, is not what ran.
    let planted = checkout
        .join(devflow_engine::runs::RUNS)
        .join("card_1/29991231T000000Z");
    std::fs::create_dir_all(&planted).expect("planted");
    std::fs::write(
        planted.join(attack::REPORT),
        json!({ "hypotheses": [{ "title": "token replay", "status": "refuted",
            "control": "src/never_touched.rs", "reason": "planted" }] })
        .to_string(),
    )
    .expect("planted report");
    let reach =
        move |_: config::Agent| -> Result<String, String> { Ok(claude.display().to_string()) };
    let redact = |text: &str| text.to_owned();
    let files = vec![SENSITIVE.to_owned()];
    let attack_at = |later: u64| {
        attack::attacked(&attack::Given {
            root: &checkout,
            runs: &runs,
            config: &Config::default(),
            card: devflow_engine::evidence::Card {
                id: "card_1",
                title: "Sessions",
                body: "",
            },
            git: devflow_engine::review::Git {
                base: "b4se",
                head: "he4d",
                files: &files,
                diff: DIFF,
            },
            brief: None,
            evidence: None,
            review: None,
            env: &[],
            at: SystemTime::UNIX_EPOCH + Duration::from_secs(1_792_000_000 + later),
            budget: Duration::from_secs(60),
            reach: &reach,
            redact: &redact,
            personas: devflow_engine::review::Personas::default(),
            retro: false,
            scratch: None,
            flow: None,
            stack: None,
            ledger: None,
        })
    };
    let done = attack_at(0).expect("attacked");
    let hypotheses = done.report["hypotheses"].as_array().expect("hypotheses");
    assert_eq!(
        hypotheses.len(),
        1,
        "the one named again is the refutation, not tried again: {hypotheses:#?}"
    );
    let replay = &hypotheses[0];
    assert_eq!(replay["title"], "token replay");
    assert_ne!(
        replay["status"], "refuted",
        "a planted report suppresses nothing: {replay:#}"
    );
    assert_eq!(done.report["refuted_before"][0]["named_again"], true);
    assert_eq!(done.report["named_again"], 1);
    let threat = &done.report["threat_model"];
    assert_eq!(threat["diff"], " assets:\n - uploads\n+- session keys\n");
    let run = std::path::Path::new(&done.folder);
    assert!(run.join("threat-model.proposed.md").is_file());
    let context = std::fs::read_to_string(run.join(attack::PACKET)).expect("context");
    assert!(
        context.contains("## Personas") && context.contains("devflow-security.overlay.md"),
        "{context}"
    );
    // The refutation is in the report, and the next run carries it on though
    // its attacker never names it again.
    assert_eq!(done.report["not_tried_again"], 1, "{:#}", done.report);
    assert_eq!(
        done.report["refuted_before"][0]["title"],
        "redirect to an internal host"
    );
    fake_claude(
        &bin,
        &json!({ "version": 1, "hypotheses": [
            { "id": "h1", "title": "token replay", "class": "authz", "file": SENSITIVE, "line": 2,
              "severity": "high", "status": "tried", "reason": "replayed",
              "exploit": { "path": "tests/t.sh", "test": "t", "code": "exit 1" } },
        ] }),
    );
    let next = attack_at(60).expect("attacked again");
    assert_eq!(
        next.report["refuted_before"][0]["title"], "redirect to an internal host",
        "{:#}",
        next.report
    );
}

/// `stages.attack.regression` names payload classes: every attack is given
/// their cases, and a case the attacker proposes stays in its report until a
/// person keeps it.
#[cfg(unix)]
#[test]
fn a_regression_class_goes_to_every_attack_and_a_proposed_case_waits_for_a_person() {
    use std::time::{Duration, SystemTime};
    let said = parsed(
        "version: 1\nstages:\n  attack:\n    run: per-item\n    regression: [ssrf, redos, ssrf]\n",
    );
    assert_eq!(said.stages.attack.regression, ["ssrf", "redos"]);
    let written = devflow_engine::render::render(&said);
    assert_eq!(
        parsed(&written).stages.attack,
        said.stages.attack,
        "{written}"
    );
    let refused = config::parse(
        "version: 1\nstages:\n  attack:\n    run: per-item\n    regression: [ssrf, lfi]\n",
    )
    .expect_err("no such class");
    assert!(refused.field.ends_with("regression.1"), "{refused}");

    let dir = tempfile::tempdir().expect("dir");
    let root = dir.path().canonicalize().expect("root");
    let checkout = root.join("checkout");
    std::fs::create_dir_all(&checkout).expect("checkout");
    let runs = devflow_engine::runs::Runs {
        dialect: &Dialect::DEVFLOW,
        home: root.join("home"),
        checkout: checkout.clone(),
    };
    let bin = root.join("bin");
    std::fs::create_dir_all(&bin).expect("bin");
    let claude = fake_claude(
        &bin,
        &json!({ "version": 1, "hypotheses": [], "cases": [
            { "class": "traversal", "input": "..;/..;/..;/etc/hostname", "want": "rejected", "why": "a ;-split path" },
            { "class": "ssrf", "input": "http:127.0.0.1:6379/", "want": "rejected", "why": "no slashes" },
        ] }),
    );
    let reach =
        move |_: config::Agent| -> Result<String, String> { Ok(claude.display().to_string()) };
    let redact = |text: &str| text.to_owned();
    let files = vec![SENSITIVE.to_owned()];
    let done = attack::attacked(&attack::Given {
        root: &checkout,
        runs: &runs,
        config: &said,
        card: devflow_engine::evidence::Card {
            id: "card_1",
            title: "Sessions",
            body: "",
        },
        git: devflow_engine::review::Git {
            base: "b4se",
            head: "he4d",
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
        scratch: None,
        flow: None,
        stack: None,
        ledger: None,
    })
    .expect("attacked");
    let prompt = std::fs::read_to_string(bin.join("prompt.txt")).expect("prompt");
    assert!(
        prompt.contains("## Regression cases"),
        "the classes' cases are given"
    );
    assert!(prompt.contains("http://2130706433:1/") && prompt.contains("letters-then-bang"));
    assert_eq!(done.report["regression"], json!(["ssrf", "redos"]));
    let proposed = &done.report["proposed_cases"];
    assert_eq!(proposed[0]["id"], "c1", "{proposed}");
    assert_eq!(proposed[0]["input"], "..;/..;/..;/etc/hostname");
    let dropped = &done.report["dropped_cases"][0];
    assert!(
        dropped["reason"]
            .as_str()
            .is_some_and(|why| why.contains("port")),
        "{dropped}"
    );
    assert!(
        devflow_engine::payloads::kept(&checkout, "traversal")
            .expect("kept")
            .is_empty(),
        "an attack keeps nothing itself"
    );
    assert!(attack::summary(&done)["proposed_cases"]
        .as_str()
        .is_some_and(|said| said.contains("devflow payloads add card_1")));
}

/// What the evidence's scanners found is given to the attacker, which says
/// of each whether untrusted input reaches it; the report lists the
/// reachable ones with their fix apart from the rest.
#[cfg(unix)]
#[test]
fn a_scanner_finding_is_called_reachable_or_not_and_the_reachable_stand_apart() {
    use std::time::{Duration, SystemTime};
    let dir = tempfile::tempdir().expect("dir");
    let root = dir.path().canonicalize().expect("root");
    let checkout = root.join("checkout");
    std::fs::create_dir_all(&checkout).expect("checkout");
    let runs = devflow_engine::runs::Runs {
        dialect: &Dialect::DEVFLOW,
        home: root.join("home"),
        checkout: checkout.clone(),
    };
    let evidence = json!({ "checks": [{ "name": "audit", "findings": [
        { "tool": "npm audit", "rule": "GHSA-aaaa-bbbb-cccc", "package": "example-parser", "file": "package-lock.json",
          "line": 1, "severity": "high", "message": "example-parser <2.1.0: Prototype pollution", "fix": "upgrade example-parser to 2.1.0" },
        { "tool": "govulncheck", "rule": "GO-2099-0002", "package": "example.test/lib/tls", "file": "go.mod",
          "line": 1, "severity": "low", "message": "Weak default (imports example.test/lib/tls)" },
    ] }] });
    let bin = root.join("bin");
    std::fs::create_dir_all(&bin).expect("bin");
    let claude = fake_claude(
        &bin,
        &json!({ "version": 1, "hypotheses": [], "scanner": [
            { "id": "s1", "reachable": true, "path": "src/api.ts:12 parse(req.body) → example-parser.parse", "fix": "upgrade example-parser to 2.1.0" },
            { "id": "s2", "reachable": false, "path": "only its types are imported" },
        ] }),
    );
    let reach =
        move |_: config::Agent| -> Result<String, String> { Ok(claude.display().to_string()) };
    let redact = |text: &str| text.to_owned();
    let files = vec![SENSITIVE.to_owned()];
    let done = attack::attacked(&attack::Given {
        root: &checkout,
        runs: &runs,
        config: &Config::default(),
        card: devflow_engine::evidence::Card {
            id: "card_1",
            title: "Sessions",
            body: "",
        },
        git: devflow_engine::review::Git {
            base: "b4se",
            head: "he4d",
            files: &files,
            diff: DIFF,
        },
        brief: None,
        evidence: Some(&evidence),
        review: None,
        env: &[],
        at: SystemTime::UNIX_EPOCH + Duration::from_secs(1_792_000_000),
        budget: Duration::from_secs(60),
        reach: &reach,
        redact: &redact,
        personas: devflow_engine::review::Personas::default(),
        retro: false,
        scratch: None,
        flow: None,
        stack: None,
        ledger: None,
    })
    .expect("attacked");
    let prompt = std::fs::read_to_string(bin.join("prompt.txt")).expect("prompt");
    assert!(
        prompt.contains("## Scanner findings") && prompt.contains("\"id\":\"s1\""),
        "given to the attacker"
    );
    let scanner = done.report["scanner"].as_array().expect("scanner");
    assert_eq!(scanner[0]["reachable"], true);
    assert_eq!(
        scanner[0]["path"],
        "src/api.ts:12 parse(req.body) → example-parser.parse"
    );
    assert_eq!(scanner[1]["reachable"], false);
    assert_eq!(
        attack::summary(&done)["scanner"],
        json!({ "reachable": 1, "rest": 1 })
    );
    let markdown = devflow_engine::attack_report::markdown(&done.report, &Default::default());
    let reachable = markdown
        .find("## Scanner findings untrusted input reaches")
        .expect("its own section");
    let rest = markdown
        .find("The other 1 scanner findings")
        .expect("the rest apart");
    let fix = markdown
        .find("Fix: upgrade example-parser to 2.1.0")
        .expect("the fix");
    assert!(reachable < fix && fix < rest, "{markdown}");
    let json = devflow_engine::attack_report::json_of(&done.report, &Default::default());
    assert_eq!(json["scanner"]["reachable"][0]["package"], "example-parser");
    assert_eq!(json["scanner"]["rest"][0]["rule"], "GO-2099-0002");
}

/// The attack's packet holds the criteria under a heading the project names,
/// as the review's does.
#[cfg(unix)]
#[test]
fn the_attacks_packet_reads_criteria_under_the_projects_headings() {
    use std::time::{Duration, SystemTime};
    let dir = tempfile::tempdir().expect("dir");
    let root = dir.path().canonicalize().expect("root");
    let checkout = root.join("checkout");
    std::fs::create_dir_all(&checkout).expect("checkout");
    let runs = devflow_engine::runs::Runs {
        dialect: &Dialect::DEVFLOW,
        home: root.join("home"),
        checkout: checkout.clone(),
    };
    let bin = root.join("bin");
    std::fs::create_dir_all(&bin).expect("bin");
    let claude = fake_claude(&bin, &json!({ "version": 1, "hypotheses": [] }));
    let reach =
        move |_: config::Agent| -> Result<String, String> { Ok(claude.display().to_string()) };
    let redact = |text: &str| text.to_owned();
    let files = vec![SENSITIVE.to_owned()];
    let config = parsed("version: 1\ncriteria:\n  headings: [Critérios de aceite]\n");
    let done = attack::attacked(&attack::Given {
        root: &checkout,
        runs: &runs,
        config: &config,
        card: devflow_engine::evidence::Card {
            id: "card_1",
            title: "Sessions",
            body: "## Critérios de aceite\n- [ ] a forged cookie is refused\n",
        },
        git: devflow_engine::review::Git {
            base: "b4se",
            head: "he4d",
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
        scratch: None,
        flow: None,
        stack: None,
        ledger: None,
    })
    .expect("attacked");
    let packet = std::fs::read_to_string(std::path::Path::new(&done.folder).join(attack::PACKET))
        .expect("packet");
    assert!(packet.contains("a forged cookie is refused"), "{packet}");
}

/// Two declared attackers: their hypotheses are one list naming who found
/// each, and one that fails leaves its part not run, with nothing switched
/// in its place.
#[cfg(unix)]
#[test]
fn declared_attackers_are_consolidated_and_a_failed_one_is_not_replaced() {
    use std::os::unix::fs::PermissionsExt;
    use std::time::{Duration, SystemTime};
    let said = parsed("version: 1\nstages:\n  attack:\n    run: per-item\n    attackers:\n      - agent: claude\n        model: large\n      - agent: claude\n        model: small\n      - agent: codex\n");
    assert_eq!(said.stages.attack.attackers.len(), 3);
    let written = devflow_engine::render::render(&said);
    assert_eq!(
        parsed(&written).stages.attack,
        said.stages.attack,
        "{written}"
    );
    let five = "version: 1\nstages:\n  attack:\n    run: per-item\n    attackers:\n".to_owned()
        + &["m", "a", "b", "c"]
            .iter()
            .map(|model| format!("      - agent: claude\n        model: {model}\n"))
            .collect::<String>()
        + "      - agent: codex\n";
    assert!(config::parse(&five).is_err(), "at most four");

    let dir = tempfile::tempdir().expect("dir");
    let root = dir.path().canonicalize().expect("root");
    let checkout = root.join("checkout");
    std::fs::create_dir_all(&checkout).expect("checkout");
    let runs = devflow_engine::runs::Runs {
        dialect: &Dialect::DEVFLOW,
        home: root.join("home"),
        checkout: checkout.clone(),
    };
    let bin = root.join("bin");
    std::fs::create_dir_all(&bin).expect("bin");
    let envelope = |answer: Value| {
        json!({ "type": "result", "result": answer.to_string(), "total_cost_usd": 0.3 }).to_string()
    };
    let large = envelope(json!({ "version": 1, "hypotheses": [
        { "id": "h1", "title": "fetch follows redirects", "class": "ssrf", "file": SENSITIVE, "line": 1,
          "severity": "high", "status": "refuted", "reason": "the guard resolves first" } ] }));
    let small = envelope(json!({ "version": 1, "hypotheses": [
        { "id": "h1", "title": "redirect to an internal host", "class": "ssrf", "file": SENSITIVE, "line": 3,
          "severity": "high", "status": "refuted", "reason": "same guard" },
        { "id": "h2", "title": "no owner check", "class": "authz", "file": SENSITIVE, "line": 2,
          "severity": "medium", "status": "refuted", "reason": "the owner is checked" } ] }));
    std::fs::write(bin.join("large.json"), large).expect("large");
    std::fs::write(bin.join("small.json"), small).expect("small");
    let script = bin.join("claude");
    std::fs::write(
        &script,
        format!(
            "#!/bin/sh\ncat > /dev/null\necho \"$*\" >> '{0}/calls'\ncase \"$*\" in *sonnet*) cat '{0}/small.json';; *) cat '{0}/large.json';; esac\n",
            bin.display()
        ),
    )
    .expect("script");
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).expect("mode");
    let reach = move |agent: config::Agent| -> Result<String, String> {
        match agent {
            config::Agent::Claude => Ok(script.display().to_string()),
            _ => Err("not installed".to_owned()),
        }
    };
    let redact = |text: &str| text.to_owned();
    let files = vec![SENSITIVE.to_owned()];
    let done = attack::attacked(&attack::Given {
        root: &checkout,
        runs: &runs,
        config: &said,
        card: devflow_engine::evidence::Card {
            id: "card_1",
            title: "Sessions",
            body: "",
        },
        git: devflow_engine::review::Git {
            base: "b4se",
            head: "he4d",
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
        scratch: None,
        flow: None,
        stack: None,
        ledger: None,
    })
    .expect("attacked");
    let hypotheses = done.report["hypotheses"].as_array().expect("hypotheses");
    assert_eq!(hypotheses.len(), 2, "{hypotheses:#?}");
    assert_eq!(
        hypotheses[0]["found_by"],
        json!(["claude/large", "claude/small"])
    );
    assert_eq!(hypotheses[1]["found_by"], json!(["claude/small"]));
    let attackers = done.report["attackers"].as_array().expect("attackers");
    assert_eq!(attackers.len(), 3);
    assert_eq!(attackers[2]["agent"], "codex");
    assert_eq!(attackers[2]["result"], "not_run");
    assert_eq!(attackers[2]["reason"], "not installed");
    let comment = attack::comment(&done);
    assert!(
        comment.contains("The attacker codex gave no hypotheses: not installed"),
        "{comment}"
    );
    assert_eq!(attackers[0]["capped_by"], "time");
    let calls = std::fs::read_to_string(bin.join("calls")).expect("calls");
    assert_eq!(
        calls.lines().count(),
        2,
        "no other attacker took the failed one's place: {calls}"
    );
}

/// An attack given a workspace flow reads both sides and the contract, and
/// a hole across the repositories names the fix on each side.
#[cfg(unix)]
#[test]
fn an_attack_on_a_flow_reads_both_sides_and_names_each_sides_fix() {
    use std::time::{Duration, SystemTime};
    let dir = tempfile::tempdir().expect("dir");
    let root = dir.path().canonicalize().expect("root");
    for (repo, file, text) in [
        (
            "api",
            "src/publish.ts",
            "queue.send({ path: req.query.file })",
        ),
        ("api", "schemas/job.json", "{ \"path\": \"string\" }"),
        ("worker", "src/consume.ts", "fs.readFile(job.path)"),
    ] {
        let at = root.join(repo).join(file);
        std::fs::create_dir_all(at.parent().expect("parent")).expect("dirs");
        std::fs::create_dir_all(root.join(repo).join(".git")).expect("git");
        std::fs::write(at, text).expect("file");
    }
    let checkout = root.join("api");
    // The project's own checkout is a repository whose commit is attacked;
    // a file written into it after that commit is not one of its files.
    std::fs::remove_dir_all(checkout.join(".git")).expect("no fake git");
    git(&checkout, &["init", "-q"]);
    git(&checkout, &["config", "user.email", "test@example.invalid"]);
    git(&checkout, &["config", "user.name", "Test"]);
    git(&checkout, &["config", "commit.gpgsign", "false"]);
    git(&checkout, &["add", "-A"]);
    git(&checkout, &["commit", "-q", "-m", "first"]);
    let head = std::process::Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(&checkout)
        .output()
        .expect("head");
    let head = String::from_utf8(head.stdout)
        .expect("utf-8")
        .trim()
        .to_owned();
    std::fs::write(checkout.join("src/written-later.ts"), "x").expect("later");
    let manifest = json!({ "root": "..", "repositories": { "api": "api", "worker": "worker" },
        "flows": [{ "name": "jobs",
            "writer": { "repo": "api", "path": "src/publish.ts" },
            "reader": { "repo": "worker", "path": "src/consume.ts" },
            "contract": { "repo": "api", "path": "schemas/job.json" } }] });
    let workspace =
        devflow_engine::workspace::parsed(&checkout, &manifest.to_string()).expect("workspace");
    let flowed = devflow_engine::workspace::flowed(&workspace, "jobs").expect("flowed");
    let runs = devflow_engine::runs::Runs {
        dialect: &Dialect::DEVFLOW,
        home: root.join("home"),
        checkout: checkout.clone(),
    };
    let bin = root.join("bin");
    std::fs::create_dir_all(&bin).expect("bin");
    let claude = fake_claude(
        &bin,
        &json!({ "version": 1, "hypotheses": [
            { "id": "h1", "title": "a job's path reads any file", "class": "traversal", "file": "src/publish.ts", "line": 1,
              "severity": "high", "status": "refuted", "reason": "shown on paper",
              "fixes": [
                  { "repo": "api", "fix": "send the upload's id, never a path" },
                  { "repo": "worker", "fix": "read only under the jobs folder" },
                  { "repo": "elsewhere", "fix": "nothing" } ] },
            { "id": "h2", "title": "a file the attack wrote", "class": "traversal", "file": "src/written-later.ts", "line": 1,
              "severity": "low", "status": "refuted", "reason": "shown on paper" } ] }),
    );
    let reach =
        move |_: config::Agent| -> Result<String, String> { Ok(claude.display().to_string()) };
    let redact = |text: &str| text.to_owned();
    let files = vec!["src/publish.ts".to_owned()];
    let done = attack::attacked(&attack::Given {
        root: &checkout,
        runs: &runs,
        config: &Config::default(),
        card: devflow_engine::evidence::Card {
            id: "card_1",
            title: "Jobs",
            body: "",
        },
        git: devflow_engine::review::Git {
            base: "b4se",
            head: &head,
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
        scratch: None,
        flow: Some(&flowed),
        stack: None,
        ledger: None,
    })
    .expect("attacked");
    let prompt = std::fs::read_to_string(bin.join("prompt.txt")).expect("prompt");
    for part in [
        "### The writer: api/src/publish.ts",
        "### The reader: worker/src/consume.ts",
        "fs.readFile(job.path)",
        "### The contract: api/schemas/job.json",
    ] {
        assert!(prompt.contains(part), "{part}");
    }
    let fixes = done.report["hypotheses"][0]["fixes"]
        .as_array()
        .expect("fixes");
    let repos: Vec<&str> = fixes
        .iter()
        .filter_map(|fix| fix["repo"].as_str())
        .collect();
    assert_eq!(repos, ["api", "worker"], "each side, and only the flow's");
    assert_eq!(done.report["flow"]["name"], "jobs");
    assert_eq!(
        done.report["in_repo"],
        json!(["src/publish.ts"]),
        "the files of the commit attacked, not one written since"
    );
    let known = devflow_engine::attack_report::Known::of(&done.report);
    assert!(known.files.contains("src/publish.ts"));
    let markdown = devflow_engine::attack_report::markdown(&done.report, &known);
    assert!(
        markdown.contains("## Fixes on each side of the flow"),
        "{markdown}"
    );
    // The report names the repositories each fix touches; the fixes, the
    // attack's own words, stay in attack.json.
    assert!(markdown.contains("- h1: api, worker\n"), "{markdown}");
    assert!(!markdown.contains("send the upload's id"), "{markdown}");
}
