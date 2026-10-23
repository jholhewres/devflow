use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;

use serde_json::{json, Value};

use super::*;
use crate::findings::Diffed;

const HEAD: &str = "c0ffee00c0ffee00c0ffee00c0ffee00c0ffee00";
const RUN: &str = "pr-1193/20261014T120000Z";

/// A hunk: its first line, how many lines, and the lines it added; the rest
/// of it is context.
type Hunk<'a> = (u64, u64, &'a [u64]);

/// A unified diff of `files`, each with its hunks.
fn diff_of(files: &[(&str, &[Hunk])]) -> String {
    let mut diff = String::new();
    for (file, hunks) in files {
        diff.push_str(&format!(
            "diff --git a/{file} b/{file}\n--- a/{file}\n+++ b/{file}\n"
        ));
        for (start, count, added) in *hunks {
            let old = count - added.len() as u64;
            diff.push_str(&format!("@@ -{start},{old} +{start},{count} @@\n"));
            for line in *start..start + count {
                let mark = if added.contains(&line) { '+' } else { ' ' };
                diff.push_str(&format!("{mark}line {line}\n"));
            }
        }
    }
    diff
}

/// The synthetic change the fixture reviews: four files, seven of whose
/// lines the findings below land on.
fn change() -> BTreeMap<String, Diffed> {
    findings::diffed(&diff_of(&[
        ("src/billing/charge.rs", &[(40, 25, &[41, 42, 43, 50])]),
        ("src/billing/refund.rs", &[(1, 15, &[3, 12])]),
        ("src/api/routes.rs", &[(85, 20, &[88, 90, 101])]),
        ("src/jobs/settle.rs", &[(28, 20, &[30])]),
    ]))
}

fn finding(file: &str, line: u64, severity: &str, axis: &str, title: &str) -> Value {
    let mut finding = json!({
        "file": file, "line": line, "severity": severity, "axis": axis,
        "title": title, "description": format!("{title}: why it matters."),
        "evidence": format!("{file}:{line}"), "suggestion": format!("Fix: {title}."),
        "agent": "claude", "persona": format!("devflow-{axis}"),
    });
    if matches!(severity, "critical" | "high") {
        finding["poc"] = json!("a request that shows it");
    }
    finding
}

/// A review shaped like a real one: seven lines worth a comment (one of
/// them found on two axes), three nits, one severe finding in a file the
/// change does not touch, one medium outside its hunks, a false positive
/// and a PoC that refuted its finding.
fn review_like_a_real_one() -> Value {
    let mut list = vec![
        finding(
            "src/billing/charge.rs",
            42,
            "high",
            "security",
            "Amount trusted from the client",
        ),
        finding(
            "src/billing/charge.rs",
            42,
            "high",
            "spec",
            "Partial capture not handled",
        ),
        finding(
            "src/billing/charge.rs",
            57,
            "medium",
            "standards",
            "Retry loop has no ceiling",
        ),
        finding(
            "src/billing/refund.rs",
            12,
            "medium",
            "spec",
            "Refund of a voided charge",
        ),
        finding(
            "src/api/routes.rs",
            88,
            "critical",
            "security",
            "Route skips the auth guard",
        ),
        finding(
            "src/api/routes.rs",
            101,
            "medium",
            "standards",
            "Handler answers a bare list",
        ),
        finding(
            "src/jobs/settle.rs",
            30,
            "medium",
            "spec",
            "Settlement date in local time",
        ),
        finding(
            "src/jobs/settle.rs",
            44,
            "high",
            "spec",
            "Settlement runs twice on retry",
        ),
        finding(
            "src/api/routes.rs",
            90,
            "low",
            "standards",
            "Name says what, not why",
        ),
        finding(
            "src/billing/refund.rs",
            3,
            "info",
            "spec",
            "The refund path is new",
        ),
        finding(
            "src/jobs/settle.rs",
            12,
            "low",
            "standards",
            "Unused import",
        ),
        finding(
            "src/billing/ledger.rs",
            200,
            "high",
            "security",
            "Ledger write outside a transaction",
        ),
        finding(
            "src/billing/charge.rs",
            5,
            "medium",
            "standards",
            "Constant defined twice",
        ),
        finding(
            "src/jobs/settle.rs",
            31,
            "medium",
            "spec",
            "Said twice by mistake",
        ),
        finding("src/api/routes.rs", 95, "high", "security", "Open redirect"),
    ];
    list[0]["verified"] =
        json!({ "result": "confirmed", "evidence": "staging, the PoC charged 1 cent" });
    list[4]["verified"] = json!({ "result": "not_run", "evidence": "no staging for routes" });
    list[13]["false_positive"] = json!(true);
    list[14]["verified"] =
        json!({ "result": "refuted", "evidence": "the redirect is allow-listed" });
    let dropped = findings::anchored(&mut list, &change(), &|_| Ok(Some(1_000)));
    assert!(dropped.is_empty(), "{dropped:?}");
    let kept = json!({
        "version": 1, "card": "pr-1193", "base": "b0b0", "head": HEAD,
        "reviewers": [{ "agent": "claude", "persona": "devflow-spec" }],
        "verdict": "request_changes", "findings": list,
        "done_well": ["Charges are idempotent by key"],
        "verification": { "tests": "unit tests of the charge path", "evidence": "CI green" },
        "pending": [],
    });
    assert!(
        findings::problems(&kept).is_empty(),
        "{:?}",
        findings::problems(&kept)
    );
    kept
}

fn asked_for(params: Value) -> Asked {
    let mut params = params;
    params["review"] = json!(RUN);
    asked(&params).expect("asked")
}

fn run_with(kept: &Value) -> tempfile::TempDir {
    let folder = tempfile::tempdir().expect("run");
    std::fs::write(
        folder.path().join(review::FINDINGS),
        serde_json::to_string(kept).expect("json"),
    )
    .expect("findings");
    folder
}

/// GitHub as a test sees it: it refuses a comment on a line no hunk of
/// the pull request shows, as the real one answers 422.
#[derive(Default)]
struct FakeGitHub {
    diffed: BTreeMap<String, Diffed>,
    next: Cell<u64>,
    reviews: RefCell<Vec<(String, String)>>,
    inline: RefCell<BTreeMap<u64, Inline>>,
    comments: RefCell<BTreeMap<u64, String>>,
    edits: Cell<usize>,
}

impl FakeGitHub {
    fn of(diffed: BTreeMap<String, Diffed>) -> Self {
        FakeGitHub {
            diffed,
            ..FakeGitHub::default()
        }
    }

    fn id(&self) -> u64 {
        self.next.set(self.next.get() + 1);
        self.next.get()
    }

    fn calls(&self) -> usize {
        self.reviews.borrow().len() + self.comments.borrow().len() + self.edits.get()
    }
}

impl Host for FakeGitHub {
    fn review(
        &self,
        commit: &str,
        event: Event,
        _body: &str,
        comments: &[Inline],
    ) -> Result<Vec<u64>, String> {
        for one in comments {
            let shown = self.diffed.get(&one.file).is_some_and(|file| {
                file.hunks
                    .iter()
                    .any(|(first, last)| (*first..=*last).contains(&one.line))
            });
            if !shown {
                return Err(format!(
                    "422: {}:{} could not be resolved",
                    one.file, one.line
                ));
            }
        }
        self.reviews
            .borrow_mut()
            .push((commit.to_owned(), event.api().to_owned()));
        Ok(comments
            .iter()
            .map(|one| {
                let id = self.id();
                self.inline.borrow_mut().insert(id, one.clone());
                id
            })
            .collect())
    }

    fn edit_inline(&self, id: u64, body: &str) -> Result<(), String> {
        let mut inline = self.inline.borrow_mut();
        let one = inline.get_mut(&id).ok_or("404")?;
        one.body = body.to_owned();
        self.edits.set(self.edits.get() + 1);
        Ok(())
    }

    fn comment(&self, body: &str) -> Result<u64, String> {
        let id = self.id();
        self.comments.borrow_mut().insert(id, body.to_owned());
        Ok(id)
    }

    fn edit_comment(&self, id: u64, body: &str) -> Result<(), String> {
        let mut comments = self.comments.borrow_mut();
        *comments.get_mut(&id).ok_or("404")? = body.to_owned();
        self.edits.set(self.edits.get() + 1);
        Ok(())
    }
}

fn github() -> String {
    Destination::GitHub.shipped().to_owned()
}

#[test]
fn a_review_shaped_like_a_real_one_drafts_seven_inline_its_nits_in_general_and_one_ticket() {
    let kept = review_like_a_real_one();

    let drafted = draft(&kept, &asked_for(json!({})), &github(), Verify::Advise);

    let inline = drafted["inline"].as_array().expect("inline");
    assert_eq!(inline.len(), 7, "{inline:#?}");
    let first = &inline[0];
    assert_eq!(first["file"], "src/api/routes.rs");
    let charge = inline
        .iter()
        .find(|one| one["file"] == "src/billing/charge.rs" && one["line"] == 42)
        .expect("one comment for line 42");
    assert_eq!(charge["axes"], json!(["spec", "security"]));
    let body = charge["body"].as_str().expect("body");
    assert!(body.contains("Partial capture") && body.contains("Amount trusted"));
    assert!(body.contains("confirmed in staging"), "{body}");
    let general = &drafted["general"];
    assert_eq!(general["nits"].as_array().map(Vec::len), Some(3));
    let elsewhere = general["elsewhere"].as_array().expect("elsewhere");
    assert_eq!(elsewhere.len(), 2);
    let tickets: Vec<&Value> = elsewhere
        .iter()
        .filter(|one| one["ticket"] == true)
        .collect();
    assert_eq!(tickets.len(), 1);
    assert_eq!(tickets[0]["file"], "src/billing/ledger.rs");
    let said = general["body"].as_str().expect("general");
    assert_eq!(said.matches("Worth a separate ticket").count(), 1, "{said}");
    for part in [
        "Nits",
        "Outside the diff",
        "### Verification",
        "### Good",
        "CI green",
    ] {
        assert!(said.contains(part), "{part} in {said}");
    }
    // A refuted PoC is said under the verification, never as a comment.
    assert!(
        said.contains("refuted in the redirect is allow-listed"),
        "{said}"
    );
    let everything = drafted.to_string();
    assert!(!everything.contains("Said twice by mistake"));
    assert!(!inline.iter().any(|one| one["body"]
        .as_str()
        .unwrap_or_default()
        .contains("Open redirect")));
}

#[test]
fn publishing_without_the_yes_is_refused() {
    let kept = review_like_a_real_one();
    let host = FakeGitHub::of(change());

    // Asked without apply, it only drafts.
    let run = run_with(&kept);
    let said = respond(
        run.path(),
        &asked_for(json!({})),
        &github(),
        Verify::Advise,
        Ok(&host),
    )
    .expect("drafted");
    assert_eq!(said["applied"], false);
    assert!(run.path().join(DRAFT).is_file());
    assert_eq!(host.calls(), 0);

    // Applied with no draft shown: that draft is what to show first.
    let unseen = run_with(&kept);
    let said = respond(
        unseen.path(),
        &asked_for(json!({ "apply": true })),
        &github(),
        Verify::Advise,
        Ok(&host),
    )
    .expect("answered");
    assert_eq!(said["applied"], false, "{said}");
    assert_eq!(host.calls(), 0);

    // The draft changed after the person saw it: their yes was not to this one.
    let mut changed = kept.clone();
    changed["findings"][2]["false_positive"] = json!(true);
    std::fs::write(
        run.path().join(review::FINDINGS),
        serde_json::to_string(&changed).expect("json"),
    )
    .expect("findings");
    let said = respond(
        run.path(),
        &asked_for(json!({ "apply": true })),
        &github(),
        Verify::Advise,
        Ok(&host),
    )
    .expect("answered");
    assert_eq!(said["applied"], false, "{said}");
    assert_eq!(host.calls(), 0);
    assert!(!run.path().join(PUBLISHED).exists());
}

/// Shown, then applied: the person's yes.
fn shown_then_applied(run: &Path, host: &FakeGitHub) -> Value {
    respond(
        run,
        &asked_for(json!({})),
        &github(),
        Verify::Advise,
        Ok(host),
    )
    .expect("drafted");
    respond(
        run,
        &asked_for(json!({ "apply": true })),
        &github(),
        Verify::Advise,
        Ok(host),
    )
    .expect("published")
}

#[test]
fn publishing_again_edits_the_comments_instead_of_duplicating_them() {
    let mut kept = review_like_a_real_one();
    let run = run_with(&kept);
    let host = FakeGitHub::of(change());

    let first = shown_then_applied(run.path(), &host);
    assert_eq!(first["applied"], true, "{first}");
    assert_eq!(
        (first["posted"].as_u64(), first["general"].as_str()),
        (Some(7), Some("posted"))
    );

    let again = shown_then_applied(run.path(), &host);
    assert_eq!(
        (again["posted"].as_u64(), again["edited"].as_u64()),
        (Some(0), Some(0))
    );
    assert_eq!(again["general"], "unchanged");

    kept["findings"][6]["suggestion"] = json!("Use UTC for the settlement date.");
    kept["done_well"] = json!(["Charges are idempotent by key", "Small handlers"]);
    std::fs::write(
        run.path().join(review::FINDINGS),
        serde_json::to_string(&kept).expect("json"),
    )
    .expect("findings");
    let edited = shown_then_applied(run.path(), &host);
    assert_eq!(
        (edited["posted"].as_u64(), edited["edited"].as_u64()),
        (Some(0), Some(1))
    );
    assert_eq!(edited["general"], "edited");

    assert_eq!(host.reviews.borrow().len(), 1, "a second review was posted");
    assert_eq!(host.inline.borrow().len(), 7);
    assert_eq!(host.comments.borrow().len(), 1);
    assert!(host
        .inline
        .borrow()
        .values()
        .any(|one| one.body.contains("Use UTC")));
    let kept_ids: Value = serde_json::from_str(
        &std::fs::read_to_string(run.path().join(PUBLISHED)).expect("published.json"),
    )
    .expect("json");
    assert_eq!(kept_ids["inline"].as_array().map(Vec::len), Some(7));
}

#[test]
fn a_fake_github_takes_every_inline_comment_and_none_is_off_the_diff() {
    let run = run_with(&review_like_a_real_one());
    let host = FakeGitHub::of(change());

    let said = shown_then_applied(run.path(), &host);

    assert_eq!(said["posted"], 7, "{said}");
    assert_eq!(
        host.reviews.borrow()[0],
        (HEAD.to_owned(), "COMMENT".to_owned())
    );
    // The fake refuses what GitHub refuses, so its yes means something.
    let off = Inline {
        file: "src/billing/ledger.rs".into(),
        line: 200,
        body: "x".into(),
    };
    assert!(host.review(HEAD, Event::Comment, "", &[off]).is_err());
}

#[test]
fn a_review_asks_for_a_comment_unless_the_person_asked_for_more() {
    assert_eq!(asked_for(json!({})).event, Event::Comment);
    assert_eq!(
        asked_for(json!({ "event": "approve" })).event,
        Event::Approve
    );
    assert!(asked(&json!({ "review": RUN, "event": "merge" })).is_err());
    for review in [
        "../pr-1/20261014T120000Z",
        "pr-1/../../x",
        "pr-1",
        "pr-1/today",
    ] {
        assert!(asked(&json!({ "review": review })).is_err(), "{review}");
    }
}

#[test]
fn a_draft_for_a_host_devpit_does_not_post_to_is_never_posted() {
    let run = run_with(&review_like_a_real_one());
    let bitbucket = asked_for(json!({ "destination": "bitbucket" }));
    let template = Destination::Bitbucket.shipped();

    let shown = respond(
        run.path(),
        &bitbucket,
        template,
        Verify::Advise,
        Err("no pull request"),
    )
    .expect("drafted");
    assert_eq!(shown["posts"], "no pull request");
    assert!(shown["general"]
        .as_str()
        .is_some_and(|said| said.contains("**Nits**") && !said.contains("<details>")));
    let mut apply = bitbucket.clone();
    apply.apply = true;
    let refused = respond(
        run.path(),
        &apply,
        template,
        Verify::Advise,
        Err("no pull request"),
    );
    assert_eq!(refused, Err("no pull request".to_owned()));
    assert!(!run.path().join(PUBLISHED).exists());
}

#[test]
fn a_projects_template_replaces_devpits_and_says_nothing_it_was_not_given() {
    let root = tempfile::tempdir().expect("root");
    assert_eq!(
        template(root.path(), Personas::default(), Destination::GitHub),
        Ok(github())
    );
    let folder = root.path().join(".devflow/reviewers/publish");
    std::fs::create_dir_all(&folder).expect("folder");
    std::fs::write(
        folder.join("github.md"),
        "Ours. {{summary}}\n{{#nits}}Nits: {{nits}}{{/nits}}{{#elsewhere}}Off: {{elsewhere}}{{/elsewhere}}",
    )
    .expect("template");
    let ours = template(root.path(), Personas::default(), Destination::GitHub).expect("template");
    assert!(ours.starts_with("Ours."));

    let mut sections = BTreeMap::new();
    sections.insert("summary", "{{nits}} as a title".to_owned());
    sections.insert("nits", "1. one".to_owned());
    let said = rendered(&ours, &sections);
    assert_eq!(said, "Ours. {{nits}} as a title\nNits: 1. one\n");
}

/// The fixture as a retro review would keep it: merged, in production, each
/// defect it follows up with the query that shows what it touched.
fn retro_like_a_real_one() -> Value {
    let mut kept = review_like_a_real_one();
    kept["mode"] = json!("retro");
    kept["verdict"] = json!("follow_up");
    for finding in kept["findings"].as_array_mut().expect("findings") {
        if findings::followed_up(finding) {
            finding["impact"] = json!(format!(
                "SELECT count(*) FROM audit WHERE source = '{}' AND at > :deployed",
                finding["file"].as_str().unwrap_or_default()
            ));
        }
    }
    assert!(findings::problems(&kept).is_empty());
    assert!(findings::retro_problems(&kept).is_empty());
    kept
}

#[test]
fn a_retro_draft_carries_one_ticket_per_medium_or_worse_each_with_its_impact_query() {
    let kept = retro_like_a_real_one();

    let drafted = draft(&kept, &asked_for(json!({})), &github(), Verify::Advise);

    // The seven lines' eight findings, the ledger's high and the medium
    // outside the hunks; the false positive and the refuted one are not.
    let tickets = drafted["tickets"].as_array().expect("tickets");
    assert_eq!(tickets.len(), 10, "{tickets:#?}");
    let list = kept["findings"].as_array().expect("findings");
    for ticket in tickets {
        let finding = list
            .iter()
            .find(|one| one["title"] == ticket["title"])
            .expect("its finding");
        assert_eq!(ticket["impact"], finding["impact"], "{ticket}");
        let impact = finding["impact"].as_str().expect("impact");
        assert!(ticket["body"]
            .as_str()
            .is_some_and(|body| body.contains(impact)));
    }
    let general = drafted["general"]["body"].as_str().expect("general");
    assert!(
        general.contains("### Follow-up tickets") && general.contains("10 tickets"),
        "{general}"
    );
    let not_retro = draft(
        &review_like_a_real_one(),
        &asked_for(json!({})),
        &github(),
        Verify::Advise,
    );
    assert!(not_retro.get("tickets").is_none());
    assert!(!not_retro["general"]["body"]
        .as_str()
        .unwrap_or_default()
        .contains("Follow-up"));
}

#[test]
fn a_retro_review_is_never_published_as_asking_for_changes() {
    let run = run_with(&retro_like_a_real_one());
    let host = FakeGitHub::of(change());

    let refused = respond(
        run.path(),
        &asked_for(json!({ "event": "request_changes" })),
        &github(),
        Verify::Advise,
        Ok(&host),
    );

    assert!(refused.is_err_and(|why| why.contains("never requests changes")));
    assert_eq!(host.calls(), 0);
}
