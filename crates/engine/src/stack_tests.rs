use serde_json::json;

use super::*;

fn config(service: serde_json::Value) -> serde_json::Value {
    json!({
        "name": "p",
        "networks": { "default": { "name": "p-net", "internal": true } },
        "services": { "web": service },
    })
}

#[test]
fn a_stack_kept_on_its_private_network_names_its_services_as_targets() {
    let dir = tempfile::tempdir().expect("dir");
    let services = checked(
        &config(json!({ "image": "x", "expose": ["8080", "9090/tcp"] })),
        dir.path(),
    )
    .expect("kept");
    assert_eq!(targets(&services), ["http://web:8080", "http://web:9090"]);
    assert_eq!(
        override_yaml("devflow-stack-1-net", &[]),
        "networks:\n  default:\n    name: devflow-stack-1-net\n    internal: true\n"
    );
    let pinned = override_yaml("n", &[("web".to_owned(), "sha256:abc".to_owned())]);
    assert!(
        pinned.ends_with("services:\n  web:\n    image: sha256:abc\n"),
        "{pinned}"
    );
}

#[test]
fn what_would_leave_the_private_network_is_refused_before_anything_starts() {
    let dir = tempfile::tempdir().expect("dir");
    let inside = dir.path().join("data");
    std::fs::create_dir_all(&inside).expect("data");
    let kept = config(
        json!({ "image": "x", "volumes": [{ "type": "bind", "source": inside.display().to_string(), "target": "/data" }] }),
    );
    assert!(
        checked(&kept, dir.path()).is_ok(),
        "a bind inside the project is kept"
    );
    for (service, why) in [
        (
            json!({ "image": "x", "network_mode": "host" }),
            "`network_mode`",
        ),
        (
            json!({ "image": "x", "ports": [{ "target": 80, "published": "8080" }] }),
            "`ports`",
        ),
        (json!({ "image": "x", "privileged": true }), "`privileged`"),
        (
            json!({ "image": "x", "cap_add": ["NET_ADMIN"] }),
            "`cap_add`",
        ),
        (json!({ "image": "x", "pid": "host" }), "`pid`"),
        (
            json!({ "image": "x", "devices": ["/dev/sda"] }),
            "`devices`",
        ),
        (
            json!({ "image": "x", "build": { "context": ".", "network": "host" } }),
            "`build`",
        ),
        (json!({ "build": { "context": "." } }), "`build`"),
        (json!({ "image": "x", "secrets": ["key"] }), "`secrets`"),
        (
            json!({ "image": "x", "networks": { "out": {} } }),
            "joins network `out`",
        ),
        (
            json!({ "image": "x", "volumes": [{ "type": "bind", "source": "/var/run/docker.sock", "target": "/s" }] }),
            "outside the project",
        ),
        (
            json!({ "image": "x", "volumes": [{ "type": "npipe", "source": "x", "target": "/s" }] }),
            "mounts a npipe",
        ),
    ] {
        let refused = checked(&config(service), dir.path()).expect_err(why);
        assert!(refused.contains(why), "{why}: {refused}");
    }
    for (key, network) in [
        ("outside", json!({ "name": "o", "internal": true })),
        (
            "default",
            json!({ "name": "o", "internal": true, "external": true }),
        ),
        ("default", json!({ "name": "o" })),
    ] {
        let mut open = config(json!({ "image": "x" }));
        open["networks"][key] = network;
        let refused = checked(&open, dir.path()).expect_err("not devflow's");
        assert!(refused.contains("not devflow's internal one"), "{refused}");
    }
    let mut kept_by_docker = config(json!({ "image": "x" }));
    kept_by_docker["volumes"] =
        json!({ "data": { "driver_opts": { "type": "none", "o": "bind", "device": "/etc" } } });
    assert!(
        checked(&kept_by_docker, dir.path()).is_err(),
        "a volume backed by a host folder"
    );
    let mut top = config(json!({ "image": "x" }));
    top["secrets"] = json!({ "key": { "file": "/etc/hostname" } });
    assert!(checked(&top, dir.path())
        .expect_err("secrets")
        .contains("`secrets`"));
}
