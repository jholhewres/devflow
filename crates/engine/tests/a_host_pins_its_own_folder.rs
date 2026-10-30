//! A host with a folder of its own (devpit keeps `.devpit/devflow/`) pins it,
//! and every project is read and set up there, its E2E specs included —
//! even a project that has none yet, and one with a `.devflow/` beside it.
//! Its own process, since the folder is pinned once for the process.

use devflow_engine::detect::{detected, Machine};
use devflow_engine::folder::{self, Layout, State};
use devflow_engine::preset::Preset;
use devflow_engine::proposal;

#[test]
fn a_pinned_folder_is_the_only_one_read_and_the_one_a_setup_writes() {
    folder::pin(folder::LEGACY).expect("pinned once");
    assert!(folder::pin(".elsewhere").is_err(), "pinned twice");

    let empty = tempfile::tempdir().expect("a project");
    assert_eq!(folder::dir(empty.path()), ".devpit/devflow");
    assert_eq!(folder::file(empty.path()), ".devpit/devflow/devflow.yaml");
    let found = detected(empty.path(), Machine::default());
    let made = proposal::setup(
        &State::Missing,
        Preset::Recommended,
        &serde_json::Map::new(),
        &found,
    )
    .expect("a setup");
    let paths: Vec<&str> = made.files.iter().map(|file| file.path.as_str()).collect();
    assert!(paths.contains(&".devpit/devflow/devflow.yaml"), "{paths:?}");
    assert!(
        paths
            .iter()
            .all(|path| path.starts_with(".devpit/devflow/")),
        "{paths:?}"
    );
    assert_eq!(made.config.stages.execution.e2e_dir, ".devpit/devflow/e2e");
    assert!(!made.yaml.contains("e2e_dir"), "{}", made.yaml);
    assert_eq!(Layout::default().dir, ".devpit/devflow");

    let both = tempfile::tempdir().expect("a project");
    let write = |path: &str, text: &str| {
        let at = both.path().join(path);
        std::fs::create_dir_all(at.parent().expect("a folder")).expect("folders");
        std::fs::write(at, text).expect("written");
    };
    write(".devflow/devflow.yaml", "version: 2\nenabled: false\n");
    write(
        ".devpit/devflow/devflow.yaml",
        "version: 2\nenabled: true\n",
    );
    match folder::read(both.path()) {
        State::Valid(_, config) => {
            assert!(config.enabled, "read devpit's, not .devflow's");
            assert_eq!(config.stages.execution.e2e_dir, ".devpit/devflow/e2e");
        }
        other => panic!("{other:?}"),
    }
}
