//! `security.targets`: the running instances of the project an attack may
//! send a request to. Only the project's own, on this machine: a loopback
//! address, `localhost`, `host.docker.internal`, or a docker service's
//! one-label name. A target is in force only when devflow.yaml lists it and
//! the person confirmed it on a terminal; it reaches a check or a reader
//! only through `DEVFLOW_SECURITY_TARGETS`. A third party's host is never a
//! target, whatever trick spells it.

use std::net::IpAddr;

use serde_json::Value;

/// The variable the targets in force reach a command through, after the
/// prefix (`DEVFLOW_`, and devpit's `DEVPIT_` for a check written for it).
pub const VARIABLE: &str = "SECURITY_TARGETS";
/// The prefixes the variable is set under.
const PREFIXES: [&str; 2] = ["DEVFLOW_", "DEVPIT_"];
/// The most targets a project lists.
pub const MOST_TARGETS: usize = 20;
/// The longest target, in characters.
pub const LONGEST: usize = 200;

/// One target, read: its scheme, host and port, and the origin it is
/// compared by.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    pub scheme: String,
    pub host: String,
    pub port: u16,
    /// Whether `host` is a name, which is resolved before it is trusted.
    pub named: bool,
}

impl Target {
    /// `scheme://host:port`, the port always said: what two targets are
    /// compared by, so `http://localhost` and `http://localhost:80` are one.
    pub fn origin(&self) -> String {
        let host = if self.host.contains(':') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };
        format!("{}://{host}:{}", self.scheme, self.port)
    }
}

/// A target as written, read and held to what may be one: `http` or
/// `https`, no user or password, a host that is the project's own on this
/// machine, and a port when said in digits. Why not, otherwise.
pub fn target(url: &str) -> Result<Target, String> {
    let refused = |why: &str| Err(format!("`{url}` is not a target: {why}"));
    if url.chars().count() > LONGEST {
        return refused(&format!("longer than {LONGEST} characters"));
    }
    if url.chars().any(|ch| ch.is_whitespace() || ch.is_control()) {
        return refused("it holds a space or a control character");
    }
    let Some((scheme, rest)) = url.split_once("://") else {
        return refused("it starts with http:// or https://");
    };
    let scheme = scheme.to_ascii_lowercase();
    let default_port = match scheme.as_str() {
        "http" => 80,
        "https" => 443,
        _ => return refused("it starts with http:// or https://"),
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    if authority.contains('@') {
        return refused("a user or password before `@` hides the host it goes to");
    }
    if authority.contains(['%', '\\']) {
        return refused("an escaped host is not read");
    }
    let (host, port) = if let Some(bracketed) = authority.strip_prefix('[') {
        let Some((inside, after)) = bracketed.split_once(']') else {
            return refused("an IPv6 address closes with `]`");
        };
        (inside.to_ascii_lowercase(), after)
    } else {
        match authority.find(':') {
            Some(at) => (authority[..at].to_ascii_lowercase(), &authority[at..]),
            None => (authority.to_ascii_lowercase(), ""),
        }
    };
    let port = match port {
        "" => default_port,
        said => match said.strip_prefix(':') {
            Some(digits)
                if !digits.is_empty()
                    && digits.len() <= 5
                    && digits.bytes().all(|byte| byte.is_ascii_digit()) =>
            {
                match digits.parse::<u16>() {
                    Ok(port) if port > 0 => port,
                    _ => return refused("its port is 1 to 65535"),
                }
            }
            _ => return refused("its port is 1 to 65535, in digits"),
        },
    };
    let named = match own_host(&host) {
        Ok(named) => named,
        Err(why) => return refused(&why),
    };
    Ok(Target {
        scheme,
        host,
        port,
        named,
    })
}

/// Whether `host` is one a target may name, and whether it is a name; why
/// not, otherwise.
fn own_host(host: &str) -> Result<bool, String> {
    if host.is_empty() {
        return Err("it names no host".to_owned());
    }
    if host == "::1" {
        return Ok(false);
    }
    if host.contains(':') {
        return Err("the only IPv6 address that is a target is ::1".to_owned());
    }
    if host.ends_with('.') {
        return Err("a name ending in `.` is a different name".to_owned());
    }
    if let Some(octets) = dotted_quad(host) {
        return if octets[0] == 127 {
            Ok(false)
        } else {
            Err("an IP address is a target only on loopback, 127.0.0.0/8".to_owned())
        };
    }
    if host == "localhost" || host == "host.docker.internal" {
        return Ok(true);
    }
    if host.contains('.') {
        return Err(
            "a name with a dot is someone's domain; the targets are localhost, \
             host.docker.internal, a loopback address or a docker service's name"
                .to_owned(),
        );
    }
    if host.bytes().all(|byte| byte.is_ascii_digit())
        || host
            .strip_prefix("0x")
            .is_some_and(|hex| hex.bytes().all(|byte| byte.is_ascii_hexdigit()))
    {
        return Err("a number for an address is read differently by each resolver".to_owned());
    }
    let label = host.len() <= 63
        && host
            .bytes()
            .next()
            .is_some_and(|first| first.is_ascii_alphanumeric())
        && host
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_');
    if label {
        Ok(true)
    } else {
        Err("a docker service's name is letters, digits, - and _".to_owned())
    }
}

/// An IPv4 address in its one plain form, four decimal parts with no
/// leading zero; any other form (`127.1`, `0177.0.0.1`) is not one.
fn dotted_quad(host: &str) -> Option<[u8; 4]> {
    let parts: Vec<&str> = host.split('.').collect();
    if parts.len() != 4 {
        return None;
    }
    let mut octets = [0u8; 4];
    for (at, part) in parts.iter().enumerate() {
        let plain = !part.is_empty()
            && part.len() <= 3
            && part.bytes().all(|byte| byte.is_ascii_digit())
            && (part.len() == 1 || !part.starts_with('0'));
        if !plain {
            return None;
        }
        octets[at] = part.parse().ok()?;
    }
    Some(octets)
}

/// The clouds' metadata services on IPv6, inside fc00::/7: AWS's and
/// Google Cloud's. Their IPv4 twin, 169.254.169.254, is link-local.
const METADATA: [[u16; 8]; 2] = [
    [0xfd00, 0x0ec2, 0, 0, 0, 0, 0, 0x0254],
    [0xfd20, 0x00ce, 0, 0, 0, 0, 0, 0x0254],
];

/// Whether an IPv6 address answers as a cloud's metadata service: one of
/// [`METADATA`], or any carrying 169.254.169.254 in its last 32 bits, the
/// way other clouds embed it.
fn metadata(segments: [u16; 8]) -> bool {
    METADATA.contains(&segments) || segments[6..] == [0xa9fe, 0xa9fe]
}

/// Whether an address is one of this machine's or a private network's, as
/// a docker service's is: loopback, 10/8, 172.16/12, 192.168/16, fc00::/7.
/// Never link-local, nor a cloud's metadata service, which answers there.
pub fn private(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(v4) => v4.is_loopback() || v4.is_private(),
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || ((v6.segments()[0] & 0xfe00) == 0xfc00 && !metadata(v6.segments()))
                || v6
                    .to_ipv4_mapped()
                    .is_some_and(|v4| v4.is_loopback() || v4.is_private())
        }
    }
}

/// What a name resolves to, as this machine's resolver answers.
pub type Resolve<'a> = &'a dyn Fn(&str, u16) -> Vec<IpAddr>;

/// How long a target's names have to resolve before they count as
/// resolving to nothing.
pub const RESOLVING: std::time::Duration = std::time::Duration::from_secs(3);

/// The names a target's host is looked up as: as written, which is what a
/// check or a reader's `curl` resolves (`/etc/hosts` first, then the search
/// domains for a one-label name); and a one-label name also with a final
/// `.`, the name alone, never completed. Every answer must be private.
pub fn asked_as(host: &str) -> Vec<String> {
    let host = host.trim_end_matches('.');
    if host.contains('.') || host == "localhost" {
        vec![host.to_owned()]
    } else {
        vec![host.to_owned(), format!("{host}.")]
    }
}

/// Every address `lookup` answers for `names`, each asked at once and all
/// within `limit`: a name still unanswered by then adds nothing, so a slow
/// resolver never stalls a tool.
pub fn resolved_within(
    lookup: fn(&str, u16) -> Vec<IpAddr>,
    names: &[String],
    port: u16,
    limit: std::time::Duration,
) -> Vec<IpAddr> {
    let (sent, said) = std::sync::mpsc::channel();
    for name in names {
        let (sent, name) = (sent.clone(), name.clone());
        std::thread::spawn(move || {
            let _ = sent.send(lookup(&name, port));
        });
    }
    drop(sent);
    let until = std::time::Instant::now() + limit;
    let mut found = Vec::new();
    for _ in names {
        let left = until.saturating_duration_since(std::time::Instant::now());
        match said.recv_timeout(left) {
            Ok(answer) => found.extend(answer),
            Err(_) => break,
        }
    }
    found.sort();
    found.dedup();
    found
}

/// This machine's resolver, as a check would call it.
fn looked_up(name: &str, port: u16) -> Vec<IpAddr> {
    use std::net::ToSocketAddrs;
    (name, port)
        .to_socket_addrs()
        .map(|found| found.map(|address| address.ip()).collect())
        .unwrap_or_default()
}

/// The resolver this machine uses, asked for each of [`asked_as`] within
/// [`RESOLVING`].
pub fn resolved_here(host: &str, port: u16) -> Vec<IpAddr> {
    resolved_within(looked_up, &asked_as(host), port, RESOLVING)
}

/// The origins of `urls` that read as targets, the rest left out: what two
/// lists of targets are compared by.
pub fn origins(urls: &[String]) -> Vec<String> {
    urls.iter()
        .filter_map(|url| target(url).ok().map(|one| one.origin()))
        .collect()
}

/// Whether a target's name leads only to this machine or a private
/// network, as [`Resolve`] answers for it; [`resolved_here`] asks for it
/// as a check would and as the name alone.
pub fn reachable(target: &Target, resolve: Resolve) -> Result<(), String> {
    if !target.named {
        return Ok(());
    }
    let found = resolve(&target.host, target.port);
    match found.iter().find(|address| !private(**address)) {
        _ if found.is_empty() => Err(format!(
            "`{}` resolves to nothing here, so it is not reached",
            target.host
        )),
        Some(address) => Err(format!(
            "`{}` resolves to {address}, which is neither this machine nor a private network",
            target.host
        )),
        None => Ok(()),
    }
}

/// The targets in force: those devflow.yaml lists that the person
/// confirmed, each read and its name resolved to this machine or a private
/// network, by origin. What was left out, with why, is the second list.
pub fn in_force(
    declared: &[String],
    confirmed: &[String],
    resolve: Resolve,
) -> (Vec<String>, Vec<String>) {
    let confirmed = origins(confirmed);
    let mut kept = Vec::new();
    let mut left = Vec::new();
    for url in declared.iter().take(MOST_TARGETS) {
        // Confirmed first: a name the person never agreed to is not even
        // sent to the network's resolver.
        let read = target(url).and_then(|one| {
            if confirmed.contains(&one.origin()) {
                reachable(&one, resolve)
            } else {
                Err(format!(
                    "`{url}` is not confirmed: the person runs `devflow config set security.targets` in a terminal"
                ))
            }
        });
        match read {
            Err(why) => left.push(why),
            Ok(()) => kept.push(url.clone()),
        }
    }
    (kept, left)
}

/// Whether a change of devflow.yaml at `path` is to what an attack may
/// reach: the person's alone, on a terminal, never a tool's.
/// The path is read part by part, each trimmed, as a change writes it.
pub fn persons_only(path: &str) -> bool {
    path.split('.').next().map(str::trim) == Some("security")
}

/// What a tool asked to change [`persons_only`] fields answers.
pub const PERSONS_ONLY: &str = "what an attack may reach is the person's to widen: they run \
     `devflow config set security.targets '[\"http://localhost:8080\"]'` in a terminal, which \
     shows each target and asks them to confirm it";

/// The variables the targets in force are said in, space-separated: set
/// even when there are none, so a command never reads one from elsewhere.
pub fn environment(targets: &[String]) -> Vec<(String, String)> {
    PREFIXES
        .iter()
        .map(|prefix| (format!("{prefix}{VARIABLE}"), targets.join(" ")))
        .collect()
}

/// `env` with the targets in force, and no other value of their variables:
/// what a host puts in a check's or a reader's environment.
pub fn with_targets(env: &mut Vec<(String, String)>, targets: &[String]) {
    env.retain(|(name, _)| {
        !PREFIXES
            .iter()
            .any(|prefix| *name == format!("{prefix}{VARIABLE}"))
    });
    env.extend(environment(targets));
}

/// A PoC run said to have reached a target outside `allowed` is refused:
/// `verified` entries name theirs in `target`. `allowed` is the list in
/// force, by URL.
pub fn refused(verified: &[Value], allowed: &[String]) -> Result<(), String> {
    let origins = origins(allowed);
    for (at, one) in verified.iter().enumerate() {
        let Some(said) = one.get("target") else {
            continue;
        };
        let Some(url) = said.as_str() else {
            return Err(format!(
                "`verified.{at}.target` is the URL the PoC ran against"
            ));
        };
        let read = target(url).map_err(|why| format!("`verified.{at}.target`: {why}"))?;
        if !origins.contains(&read.origin()) {
            return Err(format!(
                "`verified.{at}.target` `{url}` is not a target in force: only those devflow.yaml's \
                 security.targets lists and the person confirmed may be reached ({})",
                if allowed.is_empty() {
                    "none is".to_owned()
                } else {
                    allowed.join(", ")
                }
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "security_tests.rs"]
mod tests;
