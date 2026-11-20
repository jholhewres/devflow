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

/// The services of a stack as `docker compose config --format json` says
/// them, each held to the private network; refused with why otherwise.
pub fn checked(config: &Value, project: &Path) -> Result<Vec<Service>, String> {
    let project = project
        .canonicalize()
        .map_err(|err| format!("{}: {err}", project.display()))?;
    for (name, network) in config["networks"].as_object().into_iter().flatten() {
        if network["internal"] != true {
            return Err(format!(
                "network `{name}` is not internal: it would reach beyond the stack"
            ));
        }
    }
    let services = config["services"]
        .as_object()
        .ok_or("the compose file has no services")?;
    let mut found = Vec::new();
    for (name, service) in services {
        let refuse = |why: &str| Err(format!("service `{name}` {why}"));
        if service.get("network_mode").is_some() {
            return refuse("sets network_mode, which leaves the private network");
        }
        if service["privileged"] == true {
            return refuse("is privileged");
        }
        if service["cap_add"]
            .as_array()
            .is_some_and(|caps| !caps.is_empty())
        {
            return refuse("adds capabilities");
        }
        if service["pid"] == "host" || service["ipc"] == "host" {
            return refuse("shares the host's pid or ipc");
        }
        if service["ports"]
            .as_array()
            .is_some_and(|ports| !ports.is_empty())
        {
            return refuse("publishes a port on this machine: use `expose`");
        }
        for volume in service["volumes"].as_array().into_iter().flatten() {
            if volume["type"] != "bind" {
                continue;
            }
            let source = volume["source"].as_str().unwrap_or_default();
            let inside = Path::new(source)
                .canonicalize()
                .is_ok_and(|real| real.starts_with(&project));
            if !inside {
                return refuse(&format!("binds {source}, which is outside the project"));
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

/// The override that puts every service on one internal network.
pub fn override_yaml(network: &str) -> String {
    format!("networks:\n  default:\n    name: {network}\n    internal: true\n")
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

fn said(output: &std::process::Output) -> String {
    let text = String::from_utf8_lossy(&output.stderr);
    text.lines().rev().take(5).collect::<Vec<_>>().join(" / ")
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
    let overriding = scratch.join(format!("{name}.override.yaml"));
    std::fs::write(&overriding, override_yaml(&network))
        .map_err(|err| format!("{}: {err}", overriding.display()))?;
    let files = vec![compose_file, overriding];
    let read = compose(docker, &name, &files, root)
        .args(["config", "--format", "json"])
        .output()
        .map_err(|err| format!("docker compose: {err}"))?;
    if !read.status.success() {
        return Err(format!("docker compose config: {}", said(&read)));
    }
    let config: Value = serde_json::from_slice(&read.stdout)
        .map_err(|err| format!("docker compose config: {err}"))?;
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
    let started = up
        .compose()
        .args(["up", "--detach", "--wait", "--wait-timeout", "120"])
        .output()
        .map_err(|err| format!("docker compose up: {err}"))?;
    if !started.status.success() {
        return Err(format!("docker compose up: {}", said(&started)));
    }
    Ok(up)
}

#[cfg(test)]
#[path = "stack_tests.rs"]
mod tests;
