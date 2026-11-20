//! A local stack the attack starts and attacks: the compose file named in
//! `security.stack`, which the person confirmed on a terminal. It runs on a
//! network of its own that docker makes internal, so nothing on it reaches
//! beyond it; the exploits run in containers attached only to it; and it is
//! taken down when the attack is done with it, whatever happened.
//!
//! What would leave the private network is refused before anything starts:
//! a host network mode, a published port, a privileged service or one with
//! added capabilities, the host's pid or ipc, a bind mount from outside the
//! project, and a network that is not internal.

use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;

/// One service of the stack and the ports it exposes on its network.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Service {
    pub name: String,
    pub ports: Vec<u16>,
}

/// What a stack may say at its top: anything else is refused.
const TOP_KEYS: [&str; 4] = ["name", "services", "networks", "volumes"];
/// What a service may say: anything else (a build, a published port, a
/// host's network, pid or ipc, privileges, capabilities, devices, secrets,
/// configs, extra hosts) is refused.
const SERVICE_KEYS: [&str; 20] = [
    "image",
    "command",
    "entrypoint",
    "environment",
    "expose",
    "healthcheck",
    "depends_on",
    "working_dir",
    "user",
    "labels",
    "restart",
    "tmpfs",
    "read_only",
    "stop_signal",
    "stop_grace_period",
    "networks",
    "volumes",
    "init",
    "pull_policy",
    "hostname",
];

/// The services of a stack as `docker compose config --format json` says
/// them with devflow's override, each held to what may stay on the private
/// network: only what is listed is kept, so a way out no one thought of is
/// refused too.
pub fn checked(config: &Value, project: &Path) -> Result<Vec<Service>, String> {
    let project = project
        .canonicalize()
        .map_err(|err| format!("{}: {err}", project.display()))?;
    let fields = config
        .as_object()
        .ok_or("the compose config is not an object")?;
    if let Some(key) = fields
        .keys()
        .find(|key| !TOP_KEYS.contains(&key.as_str()) && !key.starts_with("x-"))
    {
        return Err(format!("the stack says `{key}`, which a stack may not"));
    }
    // One network: devflow's internal one.
    for (name, network) in config["networks"].as_object().into_iter().flatten() {
        if name != "default" || network["internal"] != true || network.get("external").is_some() {
            return Err(format!(
                "network `{name}` is not devflow's internal one: a stack has only that"
            ));
        }
    }
    // Volumes docker keeps, never one backed by a folder of this machine.
    for (name, volume) in config["volumes"].as_object().into_iter().flatten() {
        let local = volume["driver"]
            .as_str()
            .is_none_or(|driver| driver == "local");
        if !local || volume.get("driver_opts").is_some() || volume.get("external").is_some() {
            return Err(format!(
                "volume `{name}` is not a plain volume docker keeps"
            ));
        }
    }
    let services = config["services"]
        .as_object()
        .ok_or("the compose file has no services")?;
    let mut found = Vec::new();
    for (name, service) in services {
        let refuse = |why: String| Err(format!("service `{name}` {why}"));
        let said = service
            .as_object()
            .ok_or_else(|| format!("service `{name}` is not a map"))?;
        if let Some(key) = said
            .keys()
            .find(|key| !SERVICE_KEYS.contains(&key.as_str()) && !key.starts_with("x-"))
        {
            return refuse(format!("says `{key}`, which a stack's service may not"));
        }
        if service["image"].as_str().is_none_or(str::is_empty) {
            return refuse("names no image: a stack runs images, never builds".to_owned());
        }
        for network in service["networks"]
            .as_object()
            .into_iter()
            .flatten()
            .map(|(name, _)| name)
        {
            if network != "default" {
                return refuse(format!("joins network `{network}`"));
            }
        }
        for volume in service["volumes"].as_array().into_iter().flatten() {
            match volume["type"].as_str() {
                Some("volume" | "tmpfs") => {}
                Some("bind") => {
                    let source = volume["source"].as_str().unwrap_or_default();
                    let inside = Path::new(source)
                        .canonicalize()
                        .is_ok_and(|real| real.starts_with(&project));
                    if !inside {
                        return refuse(format!("binds {source}, which is outside the project"));
                    }
                }
                other => {
                    return refuse(format!("mounts a {}", other.unwrap_or("volume of no type")))
                }
            }
        }
        let ports = service["expose"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|port| {
                let said = port
                    .as_str()
                    .map(str::to_owned)
                    .or_else(|| port.as_u64().map(|port| port.to_string()))?;
                said.split('/').next()?.parse().ok()
            })
            .collect();
        found.push(Service {
            name: name.clone(),
            ports,
        });
    }
    Ok(found)
}

/// The stack's services as targets on its network: `http://<service>:<port>`.
pub fn targets(services: &[Service]) -> Vec<String> {
    services
        .iter()
        .flat_map(|service| {
            service
                .ports
                .iter()
                .map(move |port| format!("http://{}:{port}", service.name))
        })
        .collect()
}

/// The override that puts every service on one internal network, each on
/// the image it was confirmed with, by its id: a tag moved since runs
/// nothing new.
pub fn override_yaml(network: &str, pins: &[(String, String)]) -> String {
    let mut yaml = format!("networks:\n  default:\n    name: {network}\n    internal: true\n");
    if !pins.is_empty() {
        yaml.push_str("services:\n");
        for (service, id) in pins {
            yaml.push_str(&format!("  {service}:\n    image: {id}\n"));
        }
    }
    yaml
}

/// Each service's image id on this machine; one not here is refused, so a
/// stack never runs an image its person did not see.
fn image_ids(docker: &Path, config: &Value) -> Result<Vec<(String, String)>, String> {
    let mut pins = Vec::new();
    for (name, service) in config["services"].as_object().into_iter().flatten() {
        let Some(image) = service["image"].as_str() else {
            continue;
        };
        let mut inspect = crate::env::command(docker);
        inspect.args(["image", "inspect", "--format", "{{.Id}}", image]);
        match ran(inspect)? {
            (true, raw, _) => {
                let id = String::from_utf8_lossy(&raw).trim().to_owned();
                if !id.starts_with("sha256:") {
                    return Err(format!("image {image} has no id docker says"));
                }
                pins.push((name.clone(), id));
            }
            _ => {
                return Err(format!(
                    "image {image} is not on this machine: pull it, then confirm the stack"
                ))
            }
        }
    }
    Ok(pins)
}

/// A started stack: taken down when dropped, whatever happened.
pub struct Up {
    docker: PathBuf,
    name: String,
    files: Vec<PathBuf>,
    cwd: PathBuf,
    /// The internal network the exploits attach to.
    pub network: String,
    /// Its services as targets on that network.
    pub targets: Vec<String>,
}

impl Up {
    fn compose(&self) -> Command {
        compose(&self.docker, &self.name, &self.files, &self.cwd)
    }
}

impl Drop for Up {
    fn drop(&mut self) {
        let _ = self
            .compose()
            .args(["down", "--volumes", "--remove-orphans", "--timeout", "5"])
            .output();
    }
}

fn compose(docker: &Path, name: &str, files: &[PathBuf], cwd: &Path) -> Command {
    let mut command = crate::env::command(docker);
    command.arg("compose").args(["--project-name", name]);
    for file in files {
        command.arg("--file").arg(file);
    }
    command.current_dir(cwd);
    command
}

/// The most of compose's output read: a stack's config, not a dump.
const MOST_OUTPUT: u64 = 4 * 1024 * 1024;

/// A compose command's status, its output read up to [`MOST_OUTPUT`], and
/// the last lines of what it said on stderr.
fn ran(mut command: Command) -> Result<(bool, Vec<u8>, String), String> {
    use std::io::Read;
    use std::process::Stdio;
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|err| format!("docker compose: {err}"))?;
    let stdout = child.stdout.take();
    let stderr = child.stderr.take();
    let reading = std::thread::spawn(move || {
        let mut raw = Vec::new();
        if let Some(out) = stdout {
            let mut out = out.take(MOST_OUTPUT);
            let _ = out.read_to_end(&mut raw);
            // Past the ceiling, drained so the command can end.
            let _ = std::io::copy(&mut out.into_inner(), &mut std::io::sink());
        }
        raw
    });
    let mut said = String::new();
    if let Some(err) = stderr {
        let _ = err.take(64 * 1024).read_to_string(&mut said);
    }
    let status = child
        .wait()
        .map_err(|err| format!("docker compose: {err}"))?;
    let raw = reading.join().unwrap_or_default();
    let tail = said.lines().rev().take(5).collect::<Vec<_>>().join(" / ");
    Ok((status.success(), raw, tail))
}

/// The stack as compose resolves it, without devflow's override, under a
/// fixed name: what the person confirms, and its SHA-256 over everything it
/// pulls in (includes, extends, env files), not only the file's bytes.
pub fn resolved(docker: &Path, root: &Path, file: &str) -> Result<(Value, String), String> {
    use sha2::{Digest, Sha256};
    let at = crate::fsguard::resolve(root, file)
        .map_err(|_| format!("security.stack: {file} is not a file of the project"))?;
    let mut command = compose(docker, "devflow-stack", &[at], root);
    command.args(["config", "--format", "json"]);
    let (done, raw, said) = ran(command)?;
    if !done {
        return Err(format!("docker compose config: {said}"));
    }
    if raw.len() as u64 >= MOST_OUTPUT {
        return Err("docker compose config says more than a stack's config".to_owned());
    }
    let config: Value =
        serde_json::from_slice(&raw).map_err(|err| format!("docker compose config: {err}"))?;
    // The images as they are here, not only their tags: a retagged image is
    // another stack.
    let pinned: String = image_ids(docker, &config)?
        .iter()
        .map(|(service, id)| format!("{service}={id}\n"))
        .collect();
    let digest = format!(
        "{:x}",
        Sha256::digest(format!("{config}\n{pinned}").as_bytes())
    );
    Ok((config, digest))
}

/// Starts the stack `file` of the project at `root` on an internal network,
/// its override written in `scratch`; refused before anything starts when
/// the stack would leave it.
pub fn up(
    docker: &Path,
    root: &Path,
    file: &str,
    scratch: &Path,
    stamp: &str,
) -> Result<Up, String> {
    let compose_file = crate::fsguard::resolve(root, file)
        .map_err(|_| format!("security.stack: {file} is not a file of the project"))?;
    let name = format!("devflow-stack-{}", stamp.to_ascii_lowercase());
    let network = format!("{name}-net");
    std::fs::create_dir_all(scratch).map_err(|err| format!("{}: {err}", scratch.display()))?;
    // Each service on the image it was confirmed with, by its id.
    let (plain, _) = resolved(docker, root, file)?;
    let pins = image_ids(docker, &plain)?;
    let overriding = scratch.join(format!("{name}.override.yaml"));
    std::fs::write(&overriding, override_yaml(&network, &pins))
        .map_err(|err| format!("{}: {err}", overriding.display()))?;
    let files = vec![compose_file, overriding];
    let mut read = compose(docker, &name, &files, root);
    read.args(["config", "--format", "json"]);
    let (done, raw, said) = ran(read)?;
    if !done {
        return Err(format!("docker compose config: {said}"));
    }
    let config: Value =
        serde_json::from_slice(&raw).map_err(|err| format!("docker compose config: {err}"))?;
    let services = checked(&config, root)?;
    let up = Up {
        docker: docker.to_path_buf(),
        name,
        files,
        cwd: root.to_path_buf(),
        network,
        targets: targets(&services),
    };
    // From here on, dropping `up` takes down whatever started.
    let mut start = up.compose();
    start.args(["up", "--detach", "--wait", "--wait-timeout", "120"]);
    let (started, _, said) = ran(start)?;
    if !started {
        return Err(format!("docker compose up: {said}"));
    }
    Ok(up)
}

#[cfg(test)]
#[path = "stack_tests.rs"]
mod tests;
