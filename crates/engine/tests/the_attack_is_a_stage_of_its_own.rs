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
        let config = parsed(silent);
        assert_eq!(config.stages.attack.run, AttackRun::Sensitive, "{silent}");
        assert!(config.stages_on().contains(&"attack"), "{silent}");
    }
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
        due(&Config::default(), &sensitive, DIFF),
        "sensitive unless said"
    );
    assert!(!due(&Config::default(), &small, readme));
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
            "#!/bin/sh\ncat > /dev/null\ncat '{}/answer.json'\n",
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
    })
    .expect_err("dirty");
    assert!(refused.contains("commit the fix first"), "{refused}");
}
