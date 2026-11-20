use std::net::IpAddr;

use serde_json::json;

use super::*;

fn refused(url: &str) -> String {
    target(url).expect_err(url)
}

#[test]
fn the_projects_own_hosts_are_targets() {
    for (url, origin) in [
        ("http://localhost:8080", "http://localhost:8080"),
        ("http://localhost", "http://localhost:80"),
        ("HTTPS://LocalHost/api?x=1", "https://localhost:443"),
        ("http://127.0.0.1:3000/", "http://127.0.0.1:3000"),
        ("http://127.10.0.200", "http://127.10.0.200:80"),
        ("http://[::1]:8443/", "http://[::1]:8443"),
        (
            "http://host.docker.internal:5432",
            "http://host.docker.internal:5432",
        ),
        ("http://api:8000/health", "http://api:8000"),
        ("http://web_1", "http://web_1:80"),
    ] {
        assert_eq!(target(url).expect(url).origin(), origin, "{url}");
    }
}

#[test]
fn a_user_before_the_host_is_refused() {
    assert!(refused("http://localhost@evil.com").contains("`@`"));
    assert!(refused("http://localhost:80@evil.com/").contains("`@`"));
    assert!(refused("http://user:pass@localhost").contains("`@`"));
}

#[test]
fn a_name_that_only_looks_local_is_refused() {
    for url in [
        "http://localhost.evil.com",
        "http://127.0.0.1.nip.io",
        "http://host.docker.internal.evil.com",
        "http://localhost./",
        "http://evil.com",
    ] {
        refused(url);
    }
}

#[test]
fn an_address_in_an_odd_form_is_refused() {
    for url in [
        "http://0x7f000001",
        "http://2130706433",
        "http://127.1",
        "http://0177.0.0.1",
        "http://127.0.0.01",
        "http://[::ffff:127.0.0.1]",
        "http://[::ffff:7f00:1]",
        "http://[0:0:0:0:0:0:0:1]",
        "http://%6c%6fcalhost",
    ] {
        refused(url);
    }
}

#[test]
fn an_address_off_loopback_is_refused() {
    for url in [
        "http://10.0.0.5",
        "http://169.254.169.254/latest/meta-data",
        "http://0.0.0.0",
        "http://[fe80::1]",
    ] {
        refused(url);
    }
}

#[test]
fn only_http_and_a_plain_port_are_read() {
    for url in [
        "file:///etc/passwd",
        "gopher://localhost",
        "localhost:8080",
        "http://localhost:0",
        "http://localhost:65536",
        "http://localhost:+80",
        "http://local host",
        "http://",
    ] {
        refused(url);
    }
}

fn resolving(to: &'static [&'static str]) -> impl Fn(&str, u16) -> Vec<IpAddr> {
    move |_, _| to.iter().map(|one| one.parse().expect("ip")).collect()
}

fn ips(to: &[&str]) -> Vec<IpAddr> {
    to.iter().map(|one| one.parse().expect("ip")).collect()
}

/// A resolver that answers `to` for every host it is asked.
fn all(to: &'static [&'static str]) -> impl Fn(&[(String, u16)]) -> Vec<Vec<IpAddr>> {
    move |hosts| hosts.iter().map(|_| ips(to)).collect()
}

/// Each of `urls` confirmed while it resolved to `to`.
fn pinned(urls: &[String], to: &[&str]) -> Pins {
    urls.iter()
        .filter_map(|url| target(url).ok())
        .map(|one| (one.origin(), ips(to)))
        .collect()
}

#[test]
fn a_one_label_name_the_resolver_completes_elsewhere_is_refused() {
    let api = target("http://api:8000").expect("a docker service's name");
    // The resolver's search domains made `api` someone's `api.corp.example`.
    let why = reachable(&api, &resolving(&["93.184.216.34"])).expect_err("public");
    assert!(why.contains("93.184.216.34"), "{why}");
    assert!(reachable(&api, &resolving(&["fd00::1"])).is_ok());
    assert!(reachable(&api, &resolving(&["172.18.0.3"])).is_ok());
    assert!(reachable(&api, &resolving(&["169.254.169.254"])).is_err());
    assert!(reachable(&api, &resolving(&[])).is_err());
    assert!(reachable(&api, &resolving(&["172.18.0.3", "8.8.8.8"])).is_err());
    let loopback = target("http://127.0.0.1").expect("loopback");
    assert!(reachable(&loopback, &resolving(&["8.8.8.8"])).is_ok());
}

#[test]
fn only_what_is_listed_and_confirmed_is_in_force() {
    let declared = vec![
        "http://localhost:8080".to_owned(),
        "http://api:8000".to_owned(),
        "http://db:5432".to_owned(),
    ];
    let confirmed = vec![
        "http://localhost:8080/".to_owned(),
        "http://api:8000".to_owned(),
    ];
    let pins = pinned(&confirmed, &["172.18.0.3"]);
    let (kept, left) = in_force(&declared, &confirmed, &pins, &all(&["172.18.0.3"]));
    assert_eq!(kept, ["http://localhost:8080", "http://api:8000"]);
    assert_eq!(left.len(), 1);
    assert!(
        left[0].contains("db:5432") && left[0].contains("not confirmed"),
        "{left:?}"
    );
}

#[test]
fn the_targets_reach_a_command_through_its_environment_alone() {
    let mut env = vec![
        ("PATH".to_owned(), "/bin".to_owned()),
        (
            "DEVFLOW_SECURITY_TARGETS".to_owned(),
            "http://evil.com".to_owned(),
        ),
    ];
    with_targets(&mut env, &["http://localhost:8080".to_owned()]);
    assert_eq!(
        env,
        [
            ("PATH".to_owned(), "/bin".to_owned()),
            (
                "DEVFLOW_SECURITY_TARGETS".to_owned(),
                "http://localhost:8080".to_owned()
            ),
            (
                "DEVPIT_SECURITY_TARGETS".to_owned(),
                "http://localhost:8080".to_owned()
            ),
        ]
    );
}

#[test]
fn a_poc_said_to_reach_a_target_outside_the_list_is_refused() {
    let allowed = vec!["http://localhost:8080".to_owned()];
    let ran = |target: &str| json!([{ "finding": 0, "result": "confirmed", "evidence": "x", "target": target }]);
    let list = ran("http://localhost:8080/login");
    assert!(super::refused(list.as_array().expect("list"), &allowed).is_ok());
    let untargeted = json!([{ "finding": 0 }]);
    assert!(super::refused(untargeted.as_array().expect("list"), &allowed).is_ok());
    for outside in [
        "http://localhost:9090",
        "https://evil.com",
        "http://localhost@evil.com",
    ] {
        let list = ran(outside);
        let why = super::refused(list.as_array().expect("list"), &allowed).expect_err(outside);
        assert!(why.contains("verified.0.target"), "{why}");
    }
    let list = ran("http://localhost:8080");
    let none = super::refused(list.as_array().expect("list"), &[]).expect_err("none in force");
    assert!(none.contains("none is"), "{none}");
}

#[test]
fn a_clouds_metadata_service_is_never_a_private_address() {
    for metadata in ["fd00:ec2::254", "fd20:ce::254", "169.254.169.254"] {
        assert!(!private(metadata.parse().expect("ip")), "{metadata}");
    }
    assert!(private("fd00:ec2::253".parse().expect("ip")));
}

#[test]
fn a_name_the_person_never_confirmed_is_not_sent_to_the_resolver() {
    let asked = std::cell::RefCell::new(Vec::new());
    let resolve = |hosts: &[(String, u16)]| -> Vec<Vec<IpAddr>> {
        asked
            .borrow_mut()
            .extend(hosts.iter().map(|(host, _)| host.clone()));
        hosts.iter().map(|_| ips(&["172.18.0.3"])).collect()
    };
    let declared = vec!["http://api:8000".to_owned(), "http://db:5432".to_owned()];
    let confirmed = ["http://db:5432".to_owned()];
    let pins = pinned(&declared, &["172.18.0.3"]);
    let (kept, _) = in_force(&declared, &confirmed, &pins, &resolve);
    assert_eq!(kept, ["http://db:5432"]);
    assert_eq!(*asked.borrow(), ["db"]);
}

#[test]
fn the_refusal_reads_as_one_sentence() {
    assert!(!PERSONS_ONLY.contains("  "), "{PERSONS_ONLY}");
}

#[test]
fn a_name_is_looked_up_as_a_check_would_and_a_one_label_one_also_alone() {
    assert_eq!(asked_as("api"), ["api", "api."]);
    assert_eq!(asked_as("api."), ["api", "api."]);
    // Kept as written: `/etc/hosts` matches them only so (docker's extra_hosts).
    assert_eq!(asked_as("host.docker.internal"), ["host.docker.internal"]);
    assert_eq!(asked_as("localhost"), ["localhost"]);
}

fn answers(name: &str, _: u16) -> Vec<IpAddr> {
    match name {
        "api" => vec!["172.18.0.3".parse().expect("ip")],
        "api." => vec![
            "172.18.0.3".parse().expect("ip"),
            "10.0.0.9".parse().expect("ip"),
        ],
        _ => {
            std::thread::sleep(std::time::Duration::from_secs(5));
            vec!["8.8.8.8".parse().expect("ip")]
        }
    }
}

#[test]
fn every_name_asked_answers_and_a_slow_one_adds_nothing_past_the_limit() {
    let limit = std::time::Duration::from_millis(300);
    let started = std::time::Instant::now();
    let found = resolved_within(answers, &asked_as("api"), 80, limit);
    assert_eq!(
        found,
        [
            "10.0.0.9".parse::<IpAddr>().expect("ip"),
            "172.18.0.3".parse().expect("ip")
        ]
    );
    let slow = resolved_within(answers, &["slow".to_owned(), "api".to_owned()], 80, limit);
    assert_eq!(slow, ["172.18.0.3".parse::<IpAddr>().expect("ip")]);
    assert!(started.elapsed() < std::time::Duration::from_secs(2));
}

#[test]
fn a_metadata_address_another_cloud_embeds_is_not_private() {
    assert!(!private("fd00:c1::a9fe:a9fe".parse().expect("ip")));
}

#[test]
fn a_path_spelled_with_spaces_around_its_dots_is_still_the_persons() {
    for path in [
        "security.targets",
        "security .targets",
        " security. targets",
        "security",
    ] {
        assert!(persons_only(path), "{path:?}");
    }
    assert!(!persons_only("securityx.targets"));
}

#[test]
fn a_confirmed_name_keeps_its_addresses_and_a_later_answer_elsewhere_is_refused() {
    let declared = vec![
        "http://api:8000".to_owned(),
        "http://127.0.0.1:9000".to_owned(),
    ];
    let pins = pinned(&declared[..1], &["172.18.0.3"]);
    let (kept, _) = in_force(&declared, &declared, &pins, &all(&["172.18.0.3"]));
    assert_eq!(kept, declared);
    const MOVED: [(&[&str], &str); 2] = [
        (&["172.18.0.9"], "172.18.0.9"),
        (&["172.18.0.3", "10.0.0.9"], "10.0.0.9"),
    ];
    for (answers, elsewhere) in MOVED {
        let (kept, left) = in_force(&declared, &declared, &pins, &all(answers));
        assert_eq!(kept, ["http://127.0.0.1:9000"], "{answers:?}");
        assert!(
            left[0].contains(elsewhere) && left[0].contains("again"),
            "{left:?}"
        );
    }

    // Confirmed before its addresses were kept: out of force, and not even
    // sent to the resolver, until the person confirms it again.
    let asked = std::cell::Cell::new(0);
    let counted = |hosts: &[(String, u16)]| -> Vec<Vec<IpAddr>> {
        asked.set(asked.get() + hosts.len());
        hosts.iter().map(|_| ips(&["172.18.0.3"])).collect()
    };
    let (kept, left) = in_force(&declared, &declared, &Pins::new(), &counted);
    assert_eq!(kept, ["http://127.0.0.1:9000"]);
    assert!(
        left[0].contains("`api`") && left[0].contains("again"),
        "{left:?}"
    );
    assert_eq!(asked.get(), 0);
}

fn slow_or_fast(name: &str, _: u16) -> Vec<IpAddr> {
    if name.starts_with("fast") {
        return ips(&["172.18.0.3"]);
    }
    std::thread::sleep(std::time::Duration::from_secs(5));
    ips(&["172.18.0.4"])
}

#[test]
fn every_target_resolves_under_one_deadline_not_one_per_name() {
    let limit = std::time::Duration::from_millis(250);
    let mut hosts: Vec<(String, u16)> = (0..8).map(|at| (format!("slow{at}"), 80)).collect();
    hosts.push(("fast".to_owned(), 80));
    let started = std::time::Instant::now();
    let found = resolved_all(slow_or_fast, &hosts, limit);
    assert!(
        started.elapsed() < std::time::Duration::from_secs(1),
        "{:?}",
        started.elapsed()
    );
    assert_eq!(found.len(), hosts.len());
    assert_eq!(found[8], ips(&["172.18.0.3"]));
    assert!(found[..8].iter().all(Vec::is_empty), "{found:?}");

    // `in_force` asks for every confirmed name in one call.
    let calls = std::cell::RefCell::new(Vec::new());
    let once = |hosts: &[(String, u16)]| -> Vec<Vec<IpAddr>> {
        calls.borrow_mut().push(hosts.len());
        hosts.iter().map(|_| ips(&["172.18.0.3"])).collect()
    };
    let declared = vec!["http://api:8000".to_owned(), "http://db:5432".to_owned()];
    let pins = pinned(&declared, &["172.18.0.3"]);
    let (kept, _) = in_force(&declared, &declared, &pins, &once);
    assert_eq!(kept, declared);
    assert_eq!(*calls.borrow(), [2]);
}

#[test]
fn a_name_that_resolves_to_a_public_address_after_it_was_confirmed_is_refused() {
    let declared = vec!["http://api:8000".to_owned()];
    let private = pinned(&declared, &["172.18.0.3"]);
    let (kept, left) = in_force(&declared, &declared, &private, &all(&["93.184.216.34"]));
    assert!(kept.is_empty());
    assert!(left[0].contains("93.184.216.34"), "{left:?}");
    // A pin never says yes to a public address: a consent.json edited to
    // keep one puts nothing in force.
    let public = pinned(&declared, &["93.184.216.34"]);
    let (kept, left) = in_force(&declared, &declared, &public, &all(&["93.184.216.34"]));
    assert!(kept.is_empty());
    assert!(
        left[0].contains("neither this machine nor a private network"),
        "{left:?}"
    );
}

#[test]
fn a_name_with_more_addresses_than_a_pin_keeps_says_so_not_that_it_moved() {
    let target = Target {
        scheme: "http".to_owned(),
        host: "api.test".to_owned(),
        port: 8080,
        named: true,
    };
    let found: Vec<IpAddr> = (1..=17).map(|at| IpAddr::from([10, 0, 0, at])).collect();
    let pinned: Vec<IpAddr> = found[..MOST_PINNED].to_vec();
    let refused = pinned_to(&target, &found, Some(&pinned)).expect_err("too many");
    assert!(refused.contains("17 addresses"), "{refused}");
    assert!(!refused.contains("not to what it resolved"), "{refused}");
}
