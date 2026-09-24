use gnx_control_protocol::{NodeState, Progress};
use serde::Serialize;
use std::{fs, io, path::PathBuf};

const APP_STATUS_FILE: &str = "status.json";
use uuid::Uuid;

pub fn state_dir() -> PathBuf {
    if let Ok(p) = std::env::var("GNX_STATE_DIR") {
        return PathBuf::from(p);
    }
    if cfg!(windows) {
        std::env::var("ProgramData")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from(r"C:\ProgramData"))
            .join(r"GnX\Node\state")
    } else {
        PathBuf::from("target/gnx-state")
    }
}
pub fn load() -> io::Result<Progress> {
    let journal = state_dir().join("progress.jsonl");
    if let Ok(text) = fs::read_to_string(&journal) {
        if let Some(progress) = text
            .lines()
            .rev()
            .find_map(|line| serde_json::from_str::<Progress>(line).ok())
        {
            return Ok(progress);
        }
    }
    let p = state_dir().join("progress.json");
    match fs::read(&p) {
        Ok(bytes) => serde_json::from_slice(&bytes).map_err(io::Error::other),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(initial()),
        Err(e) => Err(e),
    }
}
pub fn save(progress: &Progress) -> io::Result<()> {
    let dir = state_dir();
    fs::create_dir_all(&dir)?;
    #[cfg(windows)]
    {
        // Protect the directory even when provisioning fails before the
        // managed account/profile exists. Once the account exists, the helper
        // preserves its read-only access needed by WSL; otherwise only
        // SYSTEM/Administrators are retained.
        if crate::dedicated_account::restrict_read_directory(&dir).is_err() {
            crate::dedicated_account::restrict_system_admin_directory(&dir)?;
        }
        let identity = dir.join("identity");
        if identity.is_dir() {
            crate::dedicated_account::restrict_system_admin_directory(&identity)?;
        }
        let staging = dir.join("staging");
        if staging.is_dir() && crate::dedicated_account::restrict_read_directory(&staging).is_err()
        {
            crate::dedicated_account::restrict_system_admin_directory(&staging)?;
        }
    }
    let tmp = dir.join("progress.json.tmp");
    let dst = dir.join("progress.json");
    let safe = sanitize(progress);
    let bytes = serde_json::to_vec_pretty(&safe).map_err(io::Error::other)?;
    fs::write(&tmp, bytes)?;
    fs::rename(tmp, dst).and_then(|_| {
        use std::io::Write;
        let mut journal = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(dir.join("progress.jsonl"))?;
        serde_json::to_writer(&mut journal, &safe).map_err(io::Error::other)?;
        journal.write_all(b"\n")
    })?;
    write_app_status(&dir, &safe, None)?;
    #[cfg(windows)]
    {
        // `verify.run` remains the canonical service check. Its bounded,
        // allowlisted results enrich only the browser projection; a missing
        // runtime must never prevent the durable control checkpoint.
        let runtime = crate::linux_node::runtime_checks(&dir).ok();
        if let Some(checks) = runtime.as_deref() {
            let _ = write_app_status(&dir, &safe, Some(checks));
        }
        let _ = crate::linux_node::publish_app_status(&dir.join(APP_STATUS_FILE));
    }
    Ok(())
}

/// Refresh the already-published view without changing the privileged
/// checkpoint. Called by the Windows service while the node is active.
#[cfg(windows)]
pub fn refresh_app_status() -> io::Result<()> {
    let dir = state_dir();
    let progress = sanitize(&load()?);
    // A recovered backend can remain at a blocked provisioning checkpoint
    // (for example, a runtime-version action). Keep publishing live health
    // whenever the node has already reported a runtime address.
    if progress.node_private_ip.is_none() {
        return Ok(());
    }
    let runtime = crate::linux_node::runtime_checks(&dir).ok();
    write_app_status(&dir, &progress, runtime.as_deref())?;
    crate::linux_node::publish_app_status(&dir.join(APP_STATUS_FILE))
}

#[derive(Serialize)]
struct AppStatus<'a> {
    version: u8,
    sequence: u64,
    state: String,
    phase: &'a str,
    message: &'a str,
    error_code: Option<&'a str>,
    percent: u8,
    checks: Vec<AppCheck>,
    #[serde(skip_serializing_if = "Option::is_none")]
    runtime_checks: Option<&'a [RuntimeCheck]>,
}

#[derive(Serialize)]
struct AppCheck {
    label: &'static str,
    result: &'static str,
}

/// A verified, allowlisted result from the Linux runtime. It never carries
/// verifier diagnostics, addresses, credentials, paths, or raw output.
#[derive(Clone, Serialize)]
pub(crate) struct RuntimeCheck {
    pub(crate) name: String,
    pub(crate) result: String,
}

fn write_app_status(
    dir: &std::path::Path,
    progress: &Progress,
    runtime: Option<&[RuntimeCheck]>,
) -> io::Result<()> {
    let status = AppStatus {
        version: 1,
        sequence: progress.sequence,
        state: format!("{:?}", progress.state),
        phase: &progress.phase,
        message: &progress.message,
        error_code: progress.error_code.as_deref(),
        percent: progress.percent.unwrap_or(0).min(100),
        checks: app_checks(progress, runtime),
        runtime_checks: runtime,
    };
    let tmp = dir.join(format!("{APP_STATUS_FILE}.tmp"));
    serde_json::to_writer(fs::File::create(&tmp)?, &status).map_err(io::Error::other)?;
    fs::rename(tmp, dir.join(APP_STATUS_FILE))
}

fn app_checks(progress: &Progress, runtime: Option<&[RuntimeCheck]>) -> Vec<AppCheck> {
    let mut checks = vec![
        AppCheck {
            label: "Windows y WSL",
            result: "pending",
        },
        AppCheck {
            label: "Podman 6+",
            result: "pending",
        },
        AppCheck {
            label: "Red del nodo",
            result: "pending",
        },
        AppCheck {
            label: "Gateway HTTPS",
            result: "pending",
        },
        AppCheck {
            label: "Compute",
            result: "pending",
        },
    ];
    match &progress.state {
        NodeState::NodeReady => {
            for check in &mut checks {
                check.result = "pass";
            }
        }
        NodeState::MeshPending => {
            checks[0].result = "pass";
            checks[2].result = "attention";
        }
        NodeState::WindowsReady | NodeState::WslReady | NodeState::RuntimeReady => {
            checks[0].result = "pass";
        }
        NodeState::Blocked | NodeState::Failed | NodeState::RecoveryRequired => {
            let index = match progress.phase.as_str() {
                "mesh" => 2,
                "runtime" | "gateway" => 3,
                "compute" => 4,
                _ => 0,
            };
            checks[index].result = "attention";
        }
        NodeState::New | NodeState::RebootRequired => {}
    }
    if let Some(runtime) = runtime {
        for (index, names) in [
            ["platform_target", "tun", "fuse", "kvm"].as_slice(),
            ["podman_6"].as_slice(),
            ["mesh", "mesh_authenticated"].as_slice(),
            ["gateway", "app_https"].as_slice(),
            ["compute", "compute_gateway_https", "compute_https"].as_slice(),
        ]
        .iter()
        .enumerate()
        {
            let results = names
                .iter()
                .filter_map(|name| runtime.iter().find(|check| check.name == *name))
                .map(|check| check.result.as_str())
                .collect::<Vec<_>>();
            checks[index].result = if results.iter().any(|result| *result == "fail") {
                "attention"
            } else if results.len() == names.len() && results.iter().all(|result| *result == "pass")
            {
                "pass"
            } else {
                "pending"
            };
        }
    }
    checks
}

fn sanitize(progress: &Progress) -> Progress {
    let mut safe = progress.clone();
    safe.phase = sanitize_text(&safe.phase);
    safe.message = sanitize_text(&safe.message);
    safe.error_code = safe.error_code.map(|value| sanitize_text(&value));
    safe.private_ca_certificate = safe
        .private_ca_certificate
        .map(|value| sanitize_text(&value));
    for action in &mut safe.required_actions {
        action.target = sanitize_text(&action.target);
        action.value = action.value.take().map(|value| sanitize_text(&value));
    }
    safe
}

fn sanitize_text(value: &str) -> String {
    let mut output = String::with_capacity(value.len());
    for c in value.chars() {
        if c.is_control() {
            output.push(' ');
            continue;
        }
        output.push(c);
    }
    let lower = output.to_ascii_lowercase();
    if lower.contains("tskey-auth-") {
        output = output
            .split_whitespace()
            .map(|part| {
                if part.to_ascii_lowercase().contains("tskey-auth-") {
                    "[redacted-key]"
                } else {
                    part
                }
            })
            .collect::<Vec<_>>()
            .join(" ");
    }
    for marker in ["password", "secret", "token"] {
        let mut redacted = String::new();
        let mut rest = output.as_str();
        while let Some(index) = rest.to_ascii_lowercase().find(marker) {
            redacted.push_str(&rest[..index]);
            redacted.push_str("[redacted]");
            rest = &rest[index + marker.len()..];
        }
        redacted.push_str(rest);
        output = redacted;
    }
    output.chars().take(1024).collect()
}
pub fn initial() -> Progress {
    Progress {
        request_id: None,
        operation_id: Uuid::nil(),
        sequence: 0,
        phase: "new".into(),
        state: NodeState::New,
        message: "Ready to begin GnX Node setup.".into(),
        error_code: None,
        retryable: false,
        requires_restart: false,
        percent: Some(0),
        node_private_ip: None,
        pihole_private_ip: None,
        tailscale_ip: None,
        pihole_ip: None,
        required_actions: Vec::new(),
        private_ca_certificate: None,
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_defaults_to_new() {
        assert_eq!(initial().state, NodeState::New);
    }

    #[test]
    fn persisted_text_is_sanitized() {
        let mut p = initial();
        p.message = "tskey-auth-secret password\nvalue".into();
        let safe = sanitize(&p);
        assert!(!safe.message.contains("tskey-auth-"));
        assert!(!safe.message.contains("password"));
        assert!(!safe.message.contains('\n'));
    }

    #[test]
    fn app_status_is_minimal_and_never_contains_private_state() {
        let root = std::env::temp_dir().join(format!("gnx-app-status-{}", Uuid::new_v4()));
        let mut progress = initial();
        progress.state = NodeState::NodeReady;
        progress.message = "Ready".into();
        progress.private_ca_certificate = Some("private-ca.key.pem".into());
        progress.node_private_ip = Some("100.64.0.1".into());
        write_app_status(&root, &progress, None).unwrap_err();
        fs::create_dir_all(&root).unwrap();
        write_app_status(&root, &progress, None).unwrap();
        let json = fs::read_to_string(root.join(APP_STATUS_FILE)).unwrap();
        assert!(json.contains("\"Compute\",\"result\":\"pass\""));
        assert!(!json.contains("private-ca"));
        assert!(!json.contains("100.64.0.1"));
        assert!(!json.contains("runtime_checks"));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn runtime_verifier_failure_overrides_a_ready_checkpoint() {
        let mut progress = initial();
        progress.state = NodeState::NodeReady;
        let runtime = vec![
            RuntimeCheck {
                name: "platform_target".into(),
                result: "pass".into(),
            },
            RuntimeCheck {
                name: "podman_6".into(),
                result: "pass".into(),
            },
            RuntimeCheck {
                name: "tun".into(),
                result: "pass".into(),
            },
            RuntimeCheck {
                name: "fuse".into(),
                result: "pass".into(),
            },
            RuntimeCheck {
                name: "kvm".into(),
                result: "pass".into(),
            },
            RuntimeCheck {
                name: "mesh".into(),
                result: "pass".into(),
            },
            RuntimeCheck {
                name: "mesh_authenticated".into(),
                result: "pass".into(),
            },
            RuntimeCheck {
                name: "gateway".into(),
                result: "pass".into(),
            },
            RuntimeCheck {
                name: "app_https".into(),
                result: "pass".into(),
            },
            RuntimeCheck {
                name: "compute".into(),
                result: "fail".into(),
            },
            RuntimeCheck {
                name: "compute_gateway_https".into(),
                result: "fail".into(),
            },
            RuntimeCheck {
                name: "compute_https".into(),
                result: "fail".into(),
            },
        ];
        let checks = app_checks(&progress, Some(&runtime));
        assert_eq!(checks[0].result, "pass");
        assert_eq!(checks[1].result, "pass");
        assert_eq!(checks[2].result, "pass");
        assert_eq!(checks[3].result, "pass");
        assert_eq!(checks[4].result, "attention");
    }
}
