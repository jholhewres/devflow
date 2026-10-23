use std::time::Duration;

use super::*;

fn at(seconds: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(seconds)
}

fn names_in(folder: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(folder)
        .expect("read")
        .filter_map(Result::ok)
        .filter_map(|entry| entry.file_name().into_string().ok())
        .collect();
    names.sort();
    names
}

/// devpit's folder for the runs, and a checkout, under `base`.
fn runs_in(base: &Path) -> Runs {
    // As devpit resolves its folders: a temporary dir under a symlink on macOS.
    let base = base.canonicalize().expect("base");
    let checkout = base.join("checkout");
    std::fs::create_dir_all(&checkout).expect("checkout");
    Runs {
        home: base.join("home/devflow/runs"),
        checkout,
    }
}

#[test]
fn a_run_is_named_by_its_time_in_utc() {
    assert_eq!(stamp(at(1_791_729_005)), "20261011T143005Z");
    assert_eq!(stamp(at(0)), "19700101T000000Z");
    assert_eq!(stamp(at(951_782_400)), "20000229T000000Z");
    assert_eq!(stamp(at(1_798_761_599)), "20261231T235959Z");
}

#[test]
fn a_second_run_in_the_same_second_gets_a_folder_of_its_own() {
    let base = tempfile::tempdir().expect("base");
    let runs = runs_in(base.path());
    let first = runs.fresh("card_1", at(1_791_729_005)).expect("first");
    assert_eq!(first, runs.home.join("card_1/20261011T143005Z"));
    assert!(first.is_dir());
    let second = runs.fresh("card_1", at(1_791_729_005)).expect("second");
    assert_eq!(second, runs.home.join("card_1/20261011T143005Z-1"));
    assert!(runs.fresh("../card", at(0)).is_err());
}

#[cfg(unix)]
#[test]
fn a_cards_folder_that_leads_outside_devpits_is_refused() {
    let base = tempfile::tempdir().expect("base");
    let elsewhere = tempfile::tempdir().expect("elsewhere");
    let runs = runs_in(base.path());
    std::fs::create_dir_all(&runs.home).expect("home");
    std::os::unix::fs::symlink(elsewhere.path(), runs.home.join("card_1")).expect("link");
    assert!(runs.fresh("card_1", at(0)).is_err());
    assert!(names_in(elsewhere.path()).is_empty());
}

#[test]
fn only_the_newest_runs_are_kept_and_nothing_else_is_touched() {
    let folder = tempfile::tempdir().expect("folder");
    let runs = [
        "20261011T143005Z",
        "20261011T143005Z-1",
        "20261011T143005Z-10",
        "20261011T143005Z-2",
        "20261012T090000Z",
        "20250101T000000Z",
    ];
    for name in runs.iter().chain(&["local"]) {
        std::fs::create_dir(folder.path().join(name)).expect("run");
    }
    std::fs::write(folder.path().join("20200101T000000Z.log"), "x").expect("file");

    let mut gone = prune(folder.path(), 3);
    gone.sort();
    assert_eq!(
        gone,
        ["20250101T000000Z", "20261011T143005Z", "20261011T143005Z-1"]
    );
    assert_eq!(
        names_in(folder.path()),
        [
            "20200101T000000Z.log",
            "20261011T143005Z-10",
            "20261011T143005Z-2",
            "20261012T090000Z",
            "local"
        ]
    );
}

#[test]
fn a_checks_pictures_and_videos_join_the_run_when_its_evidence_keeps_them() {
    let run = tempfile::tempdir().expect("run");
    let results = run.path().join("e2e/test-results/rename-chromium");
    std::fs::create_dir_all(&results).expect("results");
    std::fs::write(results.join("test-finished-1.png"), "png").expect("shot");
    std::fs::write(results.join("video.webm"), "webm").expect("video");
    std::fs::write(results.join("trace.zip"), "zip").expect("trace");

    let media = gather(run.path(), "e2e", &[Evidence::Screenshots]);
    assert_eq!(
        media.screenshots,
        ["screenshots/e2e-test-results-rename-chromium-test-finished-1.png"]
    );
    assert!(media.video.is_empty(), "video is not kept: {media:?}");
    assert!(run.path().join(&media.screenshots[0]).is_file());

    let video = gather(run.path(), "e2e", &[Evidence::Video]);
    assert_eq!(
        video.video,
        ["video/e2e-test-results-rename-chromium-video.webm"]
    );
    assert!(results.join("trace.zip").is_file());
}

#[test]
fn attaching_puts_the_runs_files_among_the_artifacts_under_the_card_as_one_copy() {
    let run = tempfile::tempdir().expect("run");
    let artifacts = tempfile::tempdir().expect("artifacts");
    std::fs::create_dir_all(run.path().join("e2e")).expect("e2e");
    std::fs::write(run.path().join("e2e/report.xml"), "<testsuites/>").expect("report");
    std::fs::write(run.path().join("evidence.json"), "{}").expect("evidence");

    let under = format!("{}/20261011T143005Z", attached_under("card_1"));
    let files = [
        "e2e/report.xml".to_owned(),
        "evidence.json".to_owned(),
        "gone.png".to_owned(),
    ];
    let attached = attach(run.path(), &files, artifacts.path(), &under);
    assert_eq!(
        attached.names,
        [
            "devflow/card_1/20261011T143005Z/e2e/report.xml",
            "devflow/card_1/20261011T143005Z/evidence.json"
        ]
    );
    assert_eq!(attached.left_out, ["gone.png"]);
    assert_eq!(
        std::fs::read_to_string(artifacts.path().join(&attached.names[0])).expect("copied"),
        "<testsuites/>"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let inode = |path: &Path| std::fs::metadata(path).expect("there").ino();
        assert_eq!(
            inode(&artifacts.path().join(&attached.names[1])),
            inode(&run.path().join("evidence.json")),
            "attached as a second copy"
        );
    }
    // Attached again, as gate.json is once it is rewritten: still one file.
    let again = attach(run.path(), &files[1..2], artifacts.path(), &under);
    assert_eq!(again.names, attached.names[1..2]);
}

#[test]
fn a_run_leaves_nothing_in_the_repository() {
    let base = tempfile::tempdir().expect("base");
    let runs = runs_in(base.path());
    let git = |args: &[&str]| {
        std::process::Command::new("git")
            .args(args)
            .current_dir(&runs.checkout)
            .output()
            .expect("git runs")
    };
    assert!(git(&["init", "-q"]).status.success());
    let run = runs.fresh("card_1", at(1_791_729_005)).expect("run");
    std::fs::write(run.join("evidence.json"), "{}").expect("evidence");
    let gate = runs.file_in("card_1", None, "gate.json").expect("beside");
    std::fs::write(gate, "{}").expect("gate");

    let status = git(&["status", "--porcelain", "--untracked-files=all"]);
    assert_eq!(String::from_utf8_lossy(&status.stdout), "");
    assert!(run.starts_with(&runs.home));
}

#[test]
fn a_file_of_the_runs_goes_inside_its_run_or_beside_the_runs_and_nowhere_else() {
    let base = tempfile::tempdir().expect("base");
    let runs = runs_in(base.path());
    let inside = runs
        .file_in("card_1", Some("20261011T143005Z"), "gate.json")
        .expect("in a run");
    assert_eq!(inside, runs.home.join("card_1/20261011T143005Z/gate.json"));
    assert!(inside.parent().expect("its run").is_dir());
    let beside = runs.file_in("card_1", None, "gate.json").expect("beside");
    assert_eq!(beside, runs.home.join("card_1/gate.json"));
    assert!(runs.file_in("card_1", Some("../x"), "gate.json").is_err());
    assert!(runs.file_in("../card", None, "gate.json").is_err());
}

#[test]
fn an_older_devpits_runs_in_the_checkout_are_still_read_and_finished_where_they_are() {
    let base = tempfile::tempdir().expect("base");
    let runs = runs_in(base.path());
    let older = runs.checkout.join(RUNS).join("card_1/20261011T120000Z");
    std::fs::create_dir_all(&older).expect("older run");
    std::fs::write(older.join("findings.json"), "{}").expect("findings");
    std::fs::write(runs.checkout.join(RUNS).join("card_1/start.json"), "{}").expect("start");

    let (name, path) = runs.newest_with("card_1", "findings.json").expect("found");
    assert_eq!(name, "20261011T120000Z");
    assert_eq!(
        path,
        older.join("findings.json").canonicalize().expect("real")
    );
    // A review an older devpit began is answered in its own run.
    let record = runs
        .file_in("card_1", Some("20261011T120000Z"), "review.json")
        .expect("its run");
    assert!(
        record.starts_with(older.canonicalize().expect("real")),
        "{record:?}"
    );
    // The start it kept is still the card's start.
    assert!(runs
        .file_in("card_1", None, "start.json")
        .expect("start")
        .starts_with(runs.checkout.canonicalize().expect("real")));

    // A newer run, in devpit's folder, is the newest.
    let newer = runs.fresh("card_1", at(1_791_729_005)).expect("newer");
    std::fs::write(newer.join("findings.json"), "{}").expect("findings");
    let (name, _) = runs.newest_with("card_1", "findings.json").expect("found");
    assert_eq!(name, "20261011T143005Z");
}

#[test]
fn a_runs_name_reads_back_as_the_second_it_was_made() {
    for seconds in [0, 951_782_400, 1_791_729_005, 4_102_444_799] {
        assert_eq!(seconds_of(&stamp(at(seconds))), Some(seconds), "{seconds}");
    }
    assert_eq!(
        seconds_of("20261011T143005Z-2"),
        seconds_of("20261011T143005Z")
    );
    assert_eq!(seconds_of("local"), None);
}

#[test]
fn the_newest_run_holding_a_file_is_found_and_a_newer_one_without_it_skipped() {
    let folder = tempfile::tempdir().expect("folder");
    for (name, file) in [
        ("20261011T120000Z", "evidence.json"),
        ("20261011T120000Z-1", "evidence.json"),
        ("20261011T130000Z", "findings.json"),
        ("not-a-run", "evidence.json"),
    ] {
        std::fs::create_dir_all(folder.path().join(name)).expect("run");
        std::fs::write(folder.path().join(name).join(file), "{}").expect("file");
    }
    assert_eq!(
        newest_with(folder.path(), "evidence.json").as_deref(),
        Some("20261011T120000Z-1")
    );
    assert_eq!(
        newest_with(folder.path(), "findings.json").as_deref(),
        Some("20261011T130000Z")
    );
    assert_eq!(newest_with(folder.path(), "gate.json"), None);
}
