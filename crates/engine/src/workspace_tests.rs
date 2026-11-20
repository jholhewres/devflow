use serde_json::json;

use super::*;

/// A workspace of two git repositories beside the project, one flow between
/// them; the manifest in the project's folder.
fn workspace() -> (tempfile::TempDir, PathBuf) {
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
    (dir, root.join("api"))
}

fn manifest(repos: serde_json::Value, writer: &str) -> String {
    json!({
        "root": "..",
        "repositories": repos,
        "flows": [{ "name": "jobs",
            "writer": { "repo": "api", "path": writer },
            "reader": { "repo": "worker", "path": "src/consume.ts" },
            "contract": { "repo": "api", "path": "schemas/job.json" } }],
    })
    .to_string()
}

#[test]
fn a_manifest_declares_repositories_and_flows_each_path_checked() {
    let (_dir, project) = workspace();
    let read = parsed(
        &project,
        &manifest(
            json!({ "api": "api", "worker": "worker" }),
            "src/publish.ts",
        ),
    )
    .expect("read");
    assert_eq!(read.repositories.len(), 2);
    assert_eq!(read.flows[0].reader.repo, "worker");
    assert!(read.flows[0].writer.at.ends_with("api/src/publish.ts"));
}

#[test]
fn a_flow_is_one_packet_with_both_sides_and_the_contract() {
    let (_dir, project) = workspace();
    let read = parsed(
        &project,
        &manifest(
            json!({ "api": "api", "worker": "worker" }),
            "src/publish.ts",
        ),
    )
    .expect("read");
    let flowed = flowed(&read, "jobs").expect("flowed");
    assert_eq!(flowed.repos, ["api", "worker"]);
    for part in [
        "### The writer: api/src/publish.ts",
        "req.query.file",
        "### The reader: worker/src/consume.ts",
        "fs.readFile(job.path)",
        "### The contract: api/schemas/job.json",
        "`fixes`",
    ] {
        assert!(flowed.section.contains(part), "{part}: {}", flowed.section);
    }
    assert!(super::flowed(&read, "nope").is_err());
    let one = json!({ "fixes": [
        { "repo": "api", "fix": "send an id, never a path" },
        { "repo": "worker", "fix": "read only under the jobs folder" },
        { "repo": "elsewhere", "fix": "x" },
    ] });
    let fixes = fixes_in(&one, &flowed);
    assert_eq!(fixes.len(), 2, "one per side of the flow: {fixes:?}");
}

#[test]
fn a_path_out_of_the_workspace_or_its_repository_is_refused() {
    let (dir, project) = workspace();
    std::fs::create_dir_all(dir.path().join("plain")).expect("plain");
    for (repos, writer, why) in [
        (
            json!({ "api": "api", "worker": "../../etc" }),
            "src/publish.ts",
            "not under",
        ),
        (
            json!({ "api": "api", "worker": "worker", "plain": "plain" }),
            "src/publish.ts",
            "not a git repository",
        ),
        (
            json!({ "api": "api", "worker": "worker" }),
            "../worker/src/consume.ts",
            "not a file of",
        ),
        (
            json!({ "api": "api", "worker": "worker" }),
            ".git/config",
            "hidden",
        ),
    ] {
        let refused = parsed(&project, &manifest(repos, writer)).expect_err(why);
        assert!(refused.contains(why), "{why}: {refused}");
    }
    let far = manifest(json!({ "api": "api" }), "src/publish.ts").replace("\"..\"", "\"../..\"");
    let refused = parsed(&project, &far).expect_err("root too far");
    assert!(
        refused.contains("neither the project nor the folder above it"),
        "{refused}"
    );
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink("/etc", project.join("src/linked")).expect("link");
        let linked = parsed(
            &project,
            &manifest(
                json!({ "api": "api", "worker": "worker" }),
                "src/linked/hostname",
            ),
        );
        assert!(linked.is_err(), "no side through a link out");
    }
}
