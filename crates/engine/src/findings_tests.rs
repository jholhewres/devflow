use serde_json::{json, Value};

use super::*;

pub(crate) fn finding(file: &str, line: u64, severity: &str, title: &str) -> Value {
    let mut finding = json!({
        "file": file, "line": line, "severity": severity, "axis": "security",
        "title": title, "description": "why it matters", "evidence": "the quoted line",
        "agent": "claude", "persona": "devflow-security",
    });
    if matches!(severity, "critical" | "high") {
        finding["poc"] = json!("curl -d '<script>' /x");
    }
    finding
}

pub(crate) fn answer(agent: &str, persona: &str, findings: Vec<Value>) -> Value {
    let findings: Vec<Value> = findings
        .into_iter()
        .map(|mut finding| {
            finding["agent"] = json!(agent);
            finding["persona"] = json!(persona);
            finding
        })
        .collect();
    json!({
        "version": 1, "card": "card_1", "base": "b", "head": "h",
        "reviewers": [{ "agent": agent, "persona": persona }],
        "verdict": "approve",
        "findings": findings,
        "done_well": [format!("{agent} liked the tests")],
        "verification": { "tests": "ran them", "evidence": "the checks are green" },
    })
}

fn sorted(list: &Value) -> Vec<String> {
    let mut names: Vec<String> = match list {
        Value::Array(items) => items
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_owned)
            .collect(),
        Value::Object(fields) => fields.keys().cloned().collect(),
        _ => Vec::new(),
    };
    names.sort();
    names
}

/// The validator is written by hand: these are the places it must say what
/// the schema file says, read from the file itself.
#[test]
fn the_rules_here_are_the_schemas_own() {
    let schema: Value = serde_json::from_str(SCHEMA).expect("the schema is JSON");
    let finding = &schema["$defs"]["finding"];
    let mut required: Vec<String> = REQUIRED.iter().map(|one| (*one).to_owned()).collect();
    required.sort();
    assert_eq!(sorted(&finding["required"]), required);
    let mut fields: Vec<String> = FIELDS.iter().map(|one| (*one).to_owned()).collect();
    fields.sort();
    assert_eq!(sorted(&finding["properties"]), fields);
    let severities: Vec<&str> = Severity::ALL.iter().map(|one| one.word()).collect();
    assert_eq!(finding["properties"]["severity"]["enum"], json!(severities));
    assert_eq!(finding["properties"]["axis"]["enum"], json!(AXES));
    assert_eq!(
        sorted(&schema["required"]),
        [
            "done_well",
            "findings",
            "reviewers",
            "verdict",
            "verification",
            "version"
        ]
    );
}

#[test]
fn a_reviewers_answer_is_read_through_prose_and_a_fence() {
    let said = format!(
        "Here is the review:\n```json\n{}\n```\n",
        answer(
            "codex",
            "devflow-security",
            vec![finding("a.rs", 3, "low", "a name")]
        )
    );
    let read = read_answer(&said).expect("a good answer");
    assert_eq!(read["findings"][0]["file"], "a.rs");
}

/// Each answer breaks one rule of the schema, and each is refused saying so.
#[test]
fn output_that_breaks_the_schema_is_refused_with_what_breaks_it() {
    let good = answer(
        "claude",
        "devflow-security",
        vec![finding("a.rs", 3, "high", "xss")],
    );
    assert!(problems(&good).is_empty(), "{:?}", problems(&good));
    let broken = |change: &dyn Fn(&mut Value)| {
        let mut said = good.clone();
        change(&mut said);
        read_answer(&said.to_string()).expect_err("refused")
    };
    let no_poc = broken(&|said| {
        said["findings"][0]
            .as_object_mut()
            .expect("finding")
            .remove("poc");
    });
    assert!(no_poc.contains("needs a `poc`"), "{no_poc}");
    let severity = broken(&|said| said["findings"][0]["severity"] = json!("blocker"));
    assert!(severity.contains("severity"), "{severity}");
    let extra = broken(&|said| said["findings"][0]["confidence"] = json!(0.9));
    assert!(extra.contains("confidence"), "{extra}");
    let line = broken(&|said| said["findings"][0]["line"] = json!(0));
    assert!(line.contains("line"), "{line}");
    let well = broken(&|said| said["done_well"] = json!([]));
    assert!(well.contains("done_well"), "{well}");
    let axis = broken(&|said| said["findings"][0]["axis"] = json!("style"));
    assert!(axis.contains("axis"), "{axis}");
    assert!(read_answer("I found nothing worth saying.").is_err());
    assert!(read_answer("{ \"version\": 1, ").is_err());
}

#[test]
fn an_answer_is_signed_by_who_gave_it_and_carries_nothing_devpit_sets() {
    let mut said = answer(
        "claude",
        "devflow-security",
        vec![finding("a.rs", 3, "low", "x")],
    );
    said["findings"][0]["agent"] = json!("someone else");
    said["findings"][0]["false_positive"] = json!(true);
    said["findings"][0]["anchor"] = json!("added");
    let signed = signed(said, "codex", "devflow-security");
    assert_eq!(
        signed["reviewers"],
        json!([{ "agent": "codex", "persona": "devflow-security" }])
    );
    assert_eq!(signed["findings"][0]["agent"], "codex");
    assert!(signed["findings"][0].get("false_positive").is_none());
    assert!(signed["findings"][0].get("anchor").is_none());
}

/// A headless reviewer that left out the names devpit fills was refused, and
/// its whole review was lost (B15).
#[test]
fn a_reviewer_devpit_ran_is_not_refused_for_the_names_devpit_fills() {
    let mut said = answer(
        "claude",
        "devflow-security",
        vec![finding("a.rs", 3, "medium", "fails open")],
    );
    for key in ["agent", "persona"] {
        said["findings"][0]
            .as_object_mut()
            .expect("finding")
            .remove(key);
    }
    said.as_object_mut().expect("answer").remove("reviewers");
    let read = read_signed(&said.to_string(), "claude", "devflow-security").expect("accepted");
    assert_eq!(read["findings"][0]["persona"], "devflow-security");
    said["findings"][0]["severity"] = json!("blocker");
    let refused = read_signed(&said.to_string(), "claude", "devflow-security")
        .expect_err("another break is still refused");
    assert!(refused.contains("severity"), "{refused}");
    assert!(read_signed("not json", "claude", "devflow-security").is_err());
}

fn all_of(answers: &[Value]) -> (Vec<Value>, Vec<Source>) {
    let all = answers
        .iter()
        .flat_map(|answer| answer["findings"].as_array().cloned().unwrap_or_default())
        .collect();
    let sources = answers
        .iter()
        .map(|answer| Source {
            agent: answer["reviewers"][0]["agent"]
                .as_str()
                .unwrap_or_default()
                .to_owned(),
            persona: answer["reviewers"][0]["persona"]
                .as_str()
                .unwrap_or_default()
                .to_owned(),
        })
        .collect();
    (all, sources)
}

/// Three reviewers on one axis: the problem two of them found is kept once,
/// the worse of its two severities, saying 2 of 3; the one only the third
/// found says 1 of 3.
#[test]
fn the_same_problem_from_two_of_three_reviewers_is_kept_once_saying_so() {
    let persona = "devflow-security";
    let answers = [
        answer(
            "claude",
            persona,
            vec![finding("src/app.rs", 10, "high", "Shell injection in open")],
        ),
        answer(
            "codex",
            persona,
            vec![{
                let mut one = finding(
                    "src/app.rs",
                    9,
                    "critical",
                    "Shell injection when opening a link",
                );
                one["end_line"] = json!(12);
                one
            }],
        ),
        answer(
            "cursor",
            persona,
            vec![finding("src/store.rs", 40, "low", "Unused import")],
        ),
    ];
    let (all, sources) = all_of(&answers);
    let groups = grouped(&all, &|one, other| alike(&all[one], &all[other]));
    let merged = merged(&all, &groups, &sources);
    assert_eq!(merged.len(), 2, "{merged:#?}");
    assert_eq!(merged[0]["severity"], "critical");
    assert_eq!(merged[0]["agreement"], "2 of 3");
    assert_eq!(
        merged[0]["found_by"],
        json!([
            { "agent": "claude", "persona": persona },
            { "agent": "codex", "persona": persona }
        ])
    );
    assert_eq!(merged[1]["agreement"], "1 of 3");
    for finding in &merged {
        let mut wrapped = answer("x", persona, Vec::new());
        wrapped["findings"] = json!([finding]);
        assert!(problems(&wrapped).is_empty(), "{:?}", problems(&wrapped));
    }
}

#[test]
fn findings_are_one_only_in_the_same_file_and_axis_on_lines_that_meet() {
    let one = finding("a.rs", 10, "high", "Shell injection");
    let mut other_axis = one.clone();
    other_axis["axis"] = json!("spec");
    let mut far = one.clone();
    far["line"] = json!(30);
    let mut elsewhere = one.clone();
    elsewhere["file"] = json!("b.rs");
    for other in [other_axis, far, elsewhere] {
        assert!(!candidates(&one, &other), "{other}");
        assert!(!alike(&one, &other));
    }
    let worded_apart = finding("a.rs", 10, "high", "Missing test for rename");
    assert!(candidates(&one, &worded_apart));
    assert!(!alike(&one, &worded_apart), "the titles share nothing");
}

#[test]
fn jev_consolidates_only_where_decisions_answers_and_a_model_pass_needs_two_answers() {
    assert_eq!(consolidation(Consolidate::Jev, true, 1), Consolidate::Jev);
    assert_eq!(
        consolidation(Consolidate::Jev, false, 3),
        Consolidate::Agent
    );
    assert_eq!(
        consolidation(Consolidate::Jev, false, 1),
        Consolidate::Nothing
    );
    assert_eq!(
        consolidation(Consolidate::Agent, true, 2),
        Consolidate::Agent
    );
    assert_eq!(
        consolidation(Consolidate::Agent, true, 1),
        Consolidate::Nothing
    );
    assert_eq!(
        consolidation(Consolidate::Nothing, true, 3),
        Consolidate::Nothing
    );
}

#[test]
fn the_model_pass_answers_which_findings_are_one_and_nothing_out_of_range() {
    let same = agent_same("Sure: {\"same\": [[0, 2], [1, 3]]}", 4).expect("read");
    assert_eq!(same.len(), 2);
    assert!(same[0].contains(&2));
    assert_eq!(agent_same("{\"same\": [[0, 9]]}", 4), None);
    assert_eq!(agent_same("no idea", 4), None);
    let all = [
        finding("a.rs", 1, "low", "x"),
        finding("a.rs", 1, "low", "y"),
        finding("b.rs", 1, "low", "z"),
    ];
    let asked = agent_prompt(&all);
    assert!(asked.contains("0. [security] low a.rs:1-1"), "{asked}");
    assert!(
        !asked.contains("b.rs"),
        "a finding alone is not asked about"
    );
}

#[test]
fn a_critical_finding_blocks_until_the_person_calls_it_a_false_positive() {
    let block_on = [Severity::Critical, Severity::High];
    let mut list = vec![
        finding("a.rs", 1, "critical", "x"),
        finding("a.rs", 9, "low", "y"),
    ];
    assert_eq!(verdict(&list, &block_on, Verify::Off), "request_changes");
    assert_eq!(blocking(&list, &block_on, Verify::Off).len(), 1);
    list[0]["false_positive"] = json!(true);
    assert_eq!(verdict(&list, &block_on, Verify::Off), "approve");
    assert_eq!(
        verdict(
            &[finding("a.rs", 1, "high", "x")],
            &[Severity::Critical],
            Verify::Off
        ),
        "approve"
    );
}

#[test]
fn the_persons_false_positive_stays_on_the_finding_when_the_list_is_made_again() {
    let mut before = finding("a.rs", 4, "high", "x");
    before["false_positive"] = json!(true);
    let mut again = vec![
        finding("a.rs", 4, "high", "x"),
        finding("a.rs", 4, "high", "y"),
    ];
    carried(&mut again, &[before]);
    assert_eq!(again[0]["false_positive"], true);
    assert!(again[1].get("false_positive").is_none());
}

/// A re-review read only the delta: what blocked before is the reviewers'
/// to find again, the rest still stands and says where it came from.
#[test]
fn a_rereview_carries_what_did_not_block_and_names_the_run_it_was_found_in() {
    let block_on = [Severity::Critical, Severity::High];
    let mut called_off = finding("a.rs", 2, "high", "called off");
    called_off["false_positive"] = json!(true);
    let mut older = finding("c.rs", 3, "info", "older");
    older["carried_from"] = json!("20261001T000000Z");
    let previous = vec![
        finding("a.rs", 1, "critical", "shell injection"),
        finding("a.rs", 9, "low", "a long name"),
        finding("b.rs", 5, "medium", "said again"),
        called_off,
        older,
    ];
    let mut merged = vec![finding("b.rs", 5, "medium", "said again here")];
    carried_over(
        &mut merged,
        &previous,
        &block_on,
        Verify::Off,
        "20261014T120000Z",
    );
    let titles: Vec<&str> = merged
        .iter()
        .filter_map(|one| one["title"].as_str())
        .collect();
    assert_eq!(
        titles,
        ["said again here", "a long name", "called off", "older"]
    );
    assert!(merged[0].get("carried_from").is_none());
    assert_eq!(merged[1]["carried_from"], "20261014T120000Z");
    assert_eq!(merged[3]["carried_from"], "20261001T000000Z");
    assert_eq!(verdict(&merged, &block_on, Verify::Off), "approve");
    assert!(line_of(&merged[1], Verify::Off).ends_with(" — carried from run 20261014T120000Z"));
    let report = json!({
        "version": 1, "reviewers": [{ "agent": "claude", "persona": "devflow-spec" }],
        "verdict": "approve", "findings": merged, "done_well": ["small"],
        "verification": { "tests": "t", "evidence": "e" },
    });
    assert!(problems(&report).is_empty(), "{:?}", problems(&report));
    let signed = signed(report, "claude", "devflow-spec");
    assert!(
        signed["findings"][1].get("carried_from").is_none(),
        "devpit's to say, never a reviewer's"
    );
}

#[test]
fn the_headline_counts_what_still_stands() {
    let mut list = vec![
        finding("a.rs", 1, "critical", "x"),
        finding("a.rs", 9, "high", "y"),
    ];
    list[1]["false_positive"] = json!(true);
    let said = json!({ "verdict": "request_changes", "findings": list });
    assert_eq!(
        headline(&said),
        "[devflow] review: 1 findings (1 critical, 0 high) · verdict: request_changes"
    );
}

fn signed_one(finding: Value) -> Value {
    let said = answer("claude", "devflow-spec", vec![finding]);
    read_signed(&said.to_string(), "claude", "devflow-spec").expect("accepted")["findings"][0]
        .clone()
}

/// A missing test, a written rule or a style point cannot block a card on its
/// own: the ecopar review held a card for a test helper's panic.
#[test]
fn what_is_short_of_a_defect_is_held_to_its_ceiling_saying_why() {
    let mut missing = finding("src/pay.go", 40, "high", "no test for the mixed day");
    missing["kind"] = json!("missing_test");
    let read = signed_one(missing);
    assert_eq!(read["severity"], "medium");
    assert_eq!(read["capped"]["from"], "high");
    assert!(text(&read["capped"], "why").contains("missing test"));

    for file in [
        "pay/premiacao_test.go",
        "tests/PayTest.php",
        "web/src/pay.test.ts",
    ] {
        let read = signed_one(finding(file, 89, "high", "panics in a helper"));
        assert_eq!(read["severity"], "low", "{file}");
    }
    let mut defect = finding(
        "pay/premiacao_test.go",
        89,
        "high",
        "the test can never fail",
    );
    defect["kind"] = json!("defect");
    assert_eq!(signed_one(defect)["severity"], "high");

    let mut grep = finding("src/a.rs", 3, "high", "rule broken");
    grep["poc"] = json!("git grep -n unwrap src/");
    assert_eq!(signed_one(grep)["severity"], "medium");
}

#[test]
fn a_finding_without_a_kind_keeps_its_severity() {
    let read = signed_one(finding("src/a.rs", 3, "high", "xss"));
    assert_eq!(read["severity"], "high");
    assert!(read.get("capped").is_none());
    let mut low = finding("src/a.rs", 3, "low", "a name");
    low["kind"] = json!("style");
    assert!(signed_one(low).get("capped").is_none());
}

#[test]
fn a_kind_the_schema_does_not_name_is_refused() {
    let mut odd = finding("src/a.rs", 3, "low", "a name");
    odd["kind"] = json!("nit");
    let said = answer("claude", "devflow-spec", vec![odd]);
    let refused = read_signed(&said.to_string(), "claude", "devflow-spec").expect_err("refused");
    assert!(refused.contains("kind"), "{refused}");
}

/// Two changed files, one added, one deleted and one binary: what the
/// anchors below are read against.
const DIFF: &str = "diff --git a/src/app.rs b/src/app.rs
index 1111111..2222222 100644
--- a/src/app.rs
+++ b/src/app.rs
@@ -1,3 +1,4 @@ fn main() {
 fn main() {
-    old();
+    open(link);
+    log(link);
 }
@@ -20,3 +21,3 @@ fn other() {
 a
-b
+c
 d
diff --git a/src/new.rs b/src/new.rs
new file mode 100644
--- /dev/null
+++ b/src/new.rs
@@ -0,0 +1,2 @@
+++ x
+fn x() {}
diff --git a/src/gone.rs b/src/gone.rs
deleted file mode 100644
--- a/src/gone.rs
+++ /dev/null
@@ -1,2 +0,0 @@
-a
-b
diff --git a/logo.png b/logo.png
Binary files a/logo.png and b/logo.png differ
";

#[test]
fn a_diff_is_read_into_its_hunks_and_the_lines_it_added() {
    let read = diffed(DIFF);
    assert_eq!(
        read.keys().collect::<Vec<_>>(),
        ["logo.png", "src/app.rs", "src/new.rs"],
        "a deleted file is not on the new side"
    );
    assert_eq!(read["src/app.rs"].hunks, [(1, 4), (21, 23)]);
    assert_eq!(read["src/app.rs"].added, [(2, 3), (22, 22)]);
    // `+++ x` is an added line inside a hunk, not a file header.
    assert_eq!(read["src/new.rs"].added, [(1, 2)]);
    assert_eq!(read["logo.png"], Diffed::default());
}

/// The line counts at HEAD the fixture's findings are held to.
fn at_head(file: &str) -> Result<Option<usize>, String> {
    match file {
        "src/app.rs" => Ok(Some(30)),
        "src/new.rs" => Ok(Some(2)),
        "src/other.rs" => Ok(Some(50)),
        "src/gone.rs" => Ok(None),
        _ => Err("larger than 8192 KB".to_owned()),
    }
}

#[test]
fn findings_are_anchored_where_the_diff_and_head_put_them() {
    let cases = [
        ("src/app.rs", 2, "added"),
        ("src/app.rs", 3, "added"),
        ("src/app.rs", 22, "added"),
        ("src/new.rs", 1, "added"),
        ("src/app.rs", 1, "context"),
        ("src/app.rs", 23, "context"),
        ("src/app.rs", 10, "outside_hunk"),
        ("logo.png", 1, "outside_hunk"),
        ("src/other.rs", 7, "not_in_diff"),
        ("src/huge.rs", 99_999, "not_in_diff"),
        ("src/app.rs", 31, "beyond_eof"),
        ("src/other.rs", 51, "beyond_eof"),
        ("src/gone.rs", 1, "beyond_eof"),
    ];
    let mut list: Vec<Value> = cases
        .iter()
        .map(|(file, line, _)| finding(file, *line, "low", &format!("{file}:{line}")))
        .collect();
    let asked = std::cell::RefCell::new(Vec::new());
    let lines_at = |file: &str| {
        asked.borrow_mut().push(file.to_owned());
        at_head(file)
    };
    let dropped = anchored(&mut list, &diffed(DIFF), &lines_at);

    let kept: Vec<(String, u64, String)> = list
        .iter()
        .map(|one| {
            (
                text(one, "file").to_owned(),
                one["line"].as_u64().unwrap_or_default(),
                text(one, "anchor").to_owned(),
            )
        })
        .collect();
    let expected: Vec<(String, u64, String)> = cases
        .iter()
        .filter(|(_, _, anchor)| *anchor != "beyond_eof")
        .map(|(file, line, anchor)| ((*file).to_owned(), *line, (*anchor).to_owned()))
        .collect();
    assert_eq!(kept, expected);
    let reasons: Vec<&str> = dropped.iter().map(|one| text(one, "reason")).collect();
    assert_eq!(
        reasons,
        [
            "line 31 is past the end of src/app.rs, which has 30 lines at HEAD",
            "line 51 is past the end of src/other.rs, which has 50 lines at HEAD",
            "src/gone.rs is not a file at HEAD",
        ]
    );
    assert_eq!(dropped[2]["title"], "src/gone.rs:1");
    assert_eq!(dropped[2]["agent"], "claude");
    let mut asked = asked.into_inner();
    let all = asked.len();
    asked.dedup();
    assert_eq!(all, asked.len(), "HEAD is asked once per file: {asked:?}");
    assert!(
        !asked.iter().any(|file| file == "src/new.rs"),
        "a line in a hunk needs no count"
    );
}

#[test]
fn a_finding_beyond_the_end_of_its_file_is_taken_out_with_why() {
    let mut list = vec![
        finding("src/app.rs", 200, "high", "past the end"),
        finding("src/other.rs", 7, "low", "elsewhere"),
    ];
    let dropped = anchored(&mut list, &diffed(DIFF), &at_head);
    assert_eq!(list.len(), 1);
    assert_eq!(list[0]["anchor"], "not_in_diff");
    assert_eq!(dropped.len(), 1);
    assert!(text(&dropped[0], "reason").contains("past the end of src/app.rs"));
    let held = answer("claude", "devflow-spec", list);
    assert!(problems(&held).is_empty(), "{:?}", problems(&held));
}

#[test]
fn an_anchor_is_one_devpit_names() {
    let mut odd = finding("src/a.rs", 3, "low", "a name");
    odd["anchor"] = json!("nearby");
    assert!(problems(&answer("claude", "devflow-spec", vec![odd]))
        .iter()
        .any(|wrong| wrong.contains("anchor")));
}

#[test]
fn the_comment_names_one_place_once_across_its_axes() {
    let on = |axis: &str, file: &str, line: u64, title: &str| {
        let mut one = finding(file, line, "low", title);
        one["axis"] = json!(axis);
        one
    };
    let list = [
        on("spec", "a.rs", 3, "not what the card asks"),
        on("spec", "a.rs", 3, "and a second spec problem"),
        on("standards", "a.rs", 3, "breaks the rule"),
        on("security", "a.rs", 3, "injects"),
        on("standards", "a.rs", 9, "a name"),
        on("security", "b.rs", 1, "a secret"),
    ];
    let items = listed(&list, Verify::Off);
    assert_eq!(
        items,
        [
            vec![
                "- low `a.rs:3` [spec+standards+security] not what the card asks",
                "- low `a.rs:3` and a second spec problem",
            ],
            vec!["- low `a.rs:9` a name"],
            vec!["- low `b.rs:1` a secret"],
        ]
    );
}

/// The person's word is kept beside Jev's, so calibration compares the two;
/// bringing back a finding Jev set aside overrules it.
#[test]
fn the_persons_word_on_a_finding_is_kept_beside_jevs() {
    let mut judged = finding("src/a.rs", 3, "low", "x");
    judged["jev"] = json!({ "decision": "dcn_1", "outcome": "fail", "set_aside": true });
    person_said(&mut judged, true);
    assert_eq!(judged["false_positive"], true);
    assert_eq!(judged["jev"]["person_verdict"], "fail");
    person_said(&mut judged, false);
    assert!(judged.get("false_positive").is_none());
    assert_eq!(judged["jev"]["person_verdict"], "pass");
    assert_eq!(judged["jev"]["set_aside"], false);
    assert_eq!(judged["jev"]["overruled"], true);
    assert!(standing(&judged));

    let mut unjudged = finding("src/a.rs", 3, "low", "x");
    person_said(&mut unjudged, true);
    assert!(
        unjudged.get("jev").is_none(),
        "nothing of Jev's to sit beside"
    );
}

fn ran(mut finding: Value, result: &str) -> Value {
    finding["verified"] = json!({ "result": result, "evidence": "staging: curl answered 500" });
    finding
}

#[test]
fn with_verify_required_an_unconfirmed_high_counts_as_medium_and_says_why() {
    let block_on = [Severity::Critical, Severity::High];
    let unverified = finding("a.rs", 1, "high", "x");
    for high in [unverified.clone(), ran(unverified.clone(), "not_run")] {
        let list = [high];
        assert_eq!(verdict(&list, &block_on, Verify::Required), "approve");
        assert_eq!(
            weighed(&list[0], Verify::Required).0,
            Some(Severity::Medium)
        );
        let said = line_of(&list[0], Verify::Required);
        assert!(said.contains("so it counts as medium"), "{said}");
    }
    assert!(line_of(&unverified, Verify::Required).contains("— not verified —"));
    // A critical needs no PoC run to keep blocking.
    let critical = [finding("a.rs", 1, "critical", "x")];
    assert_eq!(
        verdict(&critical, &block_on, Verify::Required),
        "request_changes"
    );
}

#[test]
fn with_verify_required_a_refuted_high_is_cleared_and_a_confirmed_one_blocks() {
    let block_on = [Severity::Critical, Severity::High, Severity::Medium];
    let high = finding("a.rs", 1, "high", "x");
    let refuted = [ran(high.clone(), "refuted")];
    assert_eq!(verdict(&refuted, &block_on, Verify::Required), "approve");
    assert!(line_of(&refuted[0], Verify::Required).contains("refuted in staging"));
    let confirmed = [ran(high, "confirmed")];
    assert_eq!(
        verdict(&confirmed, &block_on, Verify::Required),
        "request_changes"
    );
    let said = line_of(&confirmed[0], Verify::Required);
    assert!(
        said.contains("— confirmed in staging: curl answered 500"),
        "{said}"
    );
    assert!(!said.contains("counts as"), "{said}");
}

#[test]
fn with_verify_off_or_advise_the_verdict_is_todays() {
    let block_on = [Severity::Critical, Severity::High];
    let high = finding("a.rs", 1, "high", "x");
    for verify in [Verify::Off, Verify::Advise] {
        for list in [[high.clone()], [ran(high.clone(), "refuted")]] {
            assert_eq!(verdict(&list, &block_on, verify), "request_changes");
        }
    }
    assert!(!line_of(&high, Verify::Off).contains("verified"));
    assert!(line_of(&high, Verify::Advise).ends_with("— not verified"));
}

#[test]
fn a_poc_run_is_kept_only_on_a_critical_or_high_and_carried_with_it() {
    let mut list = vec![
        finding("a.rs", 1, "high", "x"),
        finding("a.rs", 9, "low", "y"),
    ];
    let run = |finding: u64, result: &str| json!({ "finding": finding, "result": result, "evidence": "local" });
    verified_on(&mut list, &[run(0, "confirmed")]).expect("a high");
    assert_eq!(list[0]["verified"]["result"], "confirmed");
    assert!(verified_on(&mut list, &[run(1, "confirmed")])
        .expect_err("a low")
        .contains("only a critical or high"));
    assert!(verified_on(&mut list, &[run(2, "confirmed")])
        .expect_err("past the end")
        .contains("from 0 to 1"));
    let mut wrong = list[0].clone();
    wrong["verified"]["result"] = json!("maybe");
    let mut problems = Vec::new();
    finding_problems(&wrong, "findings.0", &mut problems);
    assert!(
        problems[0].contains("`findings.0.verified`"),
        "{problems:?}"
    );
    let mut again = vec![finding("a.rs", 1, "high", "x")];
    carried(&mut again, &list);
    assert_eq!(again[0]["verified"], list[0]["verified"]);
}
