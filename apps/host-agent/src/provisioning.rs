use gnx_control_protocol::{NodeState, Operation, Progress, Request};
use uuid::Uuid;

/// Apply an authorized request and advance one durable checkpoint at a time.
/// Platform hooks are Windows-only so protocol tests never mutate the host.
pub fn execute(req: &Request, current: &Progress) -> Progress {
    // GetProgress is a read-only snapshot. It must not advance sequence,
    // replace the last request, clear diagnostics, or create a journal entry.
    if req.operation == Operation::GetProgress {
        return current.clone();
    }
    let mut p = handle(req, current);
    if matches!(req.operation, Operation::Provision) && p.error_code.is_none() {
        #[cfg(windows)]
        let ca_result = account_then_ca(
            || crate::dedicated_account::ensure().map(|_| ()),
            || crate::ca::ensure(&crate::state::state_dir()),
        );
        #[cfg(not(windows))]
        let ca_result = crate::ca::ensure(&crate::state::state_dir());
        match ca_result {
            Ok(ca) => {
                p.private_ca_certificate = Some(ca.certificate_path.to_string_lossy().into());
                p.required_actions = required_actions(p.private_ca_certificate.as_deref());
            }
            Err(error) => {
                p.state = NodeState::Blocked;
                if let Some(account_error) = account_gate_source(&error) {
                    p.phase = "account".into();
                    p.message = "The managed Windows identity is not ready.".into();
                    p.error_code = Some(classify_error(account_error));
                } else {
                    p.phase = "ca".into();
                    p.message = "The node private CA could not be created or opened.".into();
                    p.error_code = Some(classify_error(&error));
                }
                p.retryable = true;
            }
        }
    }
    #[cfg(not(windows))]
    let _ = req;
    #[cfg(windows)]
    {
        if matches!(req.operation, Operation::Provision) && p.error_code.is_none() {
            if let Err(error) = provision_runtime(req) {
                p.state = NodeState::Blocked;
                p.phase = "windows".into();
                p.message = "Windows prerequisites need attention before WSL can continue.".into();
                p.error_code = Some(classify_error(&error));
                p.retryable = true;
                p.requires_restart = false;
            } else {
                p.state = NodeState::MeshPending;
                p.phase = "mesh".into();
                p.message = "Windows and WSL are ready; enter a temporary mesh credential.".into();
                p.percent = Some(60);
            }
        }
        if matches!(req.operation, Operation::JoinMesh) && p.error_code.is_none() {
            // MSI updates can leave an already-imported distro with stale
            // payload files. Refresh and verify the sealed payload on every
            // JoinMesh, not only during Provision.
            if let Err(error) =
                crate::linux_node::ensure_distro().and_then(|_| join_mesh(req, &mut p))
            {
                p.state = NodeState::Blocked;
                p.phase = "mesh".into();
                p.message = "Mesh enrollment did not complete; no ready state was reported.".into();
                p.error_code = Some(classify_error(&error));
                p.retryable = true;
            }
        }
        // A pipe client can disconnect or the service can restart after the
        // one-shot key was consumed but before NODE_READY was persisted. Retry
        // refreshes the installed payload and ingress policy without
        // credentials, then checks live readiness.
        if matches!(req.operation, Operation::Retry)
            && (current.state == NodeState::NodeReady
                || current.state == NodeState::MeshPending
                || (current.state == NodeState::Blocked && current.phase == "mesh"))
        {
            let state_dir = crate::state::state_dir();
            let readiness = crate::linux_node::reconcile_ingress()
                .and_then(|_| crate::linux_node::verify(&state_dir))
                .and_then(|_| crate::linux_node::private_ip());
            match readiness {
                Ok(ip) => mark_ready(&mut p, ip),
                Err(error) => {
                    p.state = NodeState::Blocked;
                    p.phase = "mesh".into();
                    p.message = "The enrolled runtime is not ready yet.".into();
                    p.error_code = Some(classify_error(&error));
                    p.retryable = true;
                }
            }
        }
    }
    p
}

fn required_actions(certificate: Option<&str>) -> Vec<gnx_control_protocol::RequiredAction> {
    vec![
        gnx_control_protocol::RequiredAction {
            kind: gnx_control_protocol::ActionKind::ConfigureSplitDns,
            target: "gnx".into(),
            value: None,
        },
        gnx_control_protocol::RequiredAction {
            kind: gnx_control_protocol::ActionKind::TrustPrivateCa,
            target: "app.gnx,compute.gnx".into(),
            value: certificate.map(str::to_owned),
        },
    ]
}

#[derive(Debug)]
struct AccountGateError(std::io::Error);

impl std::fmt::Display for AccountGateError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(formatter)
    }
}

impl std::error::Error for AccountGateError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.0)
    }
}

fn account_gate_source(error: &std::io::Error) -> Option<&std::io::Error> {
    error
        .get_ref()
        .and_then(|source| source.downcast_ref::<AccountGateError>())
        .map(|source| &source.0)
}

/// Keep the account/profile/credential gate ahead of CA ACL application. The
/// Windows CA files grant read access to the fixed account, so account setup
/// must complete before CA creation can succeed. Keeping the two operations in
/// one helper also makes retries idempotent and keeps onboarding secrets out of
/// this prerequisite path.
fn account_then_ca<Account, Ca>(account: Account, ca: Ca) -> std::io::Result<crate::ca::CaInfo>
where
    Account: FnOnce() -> std::io::Result<()>,
    Ca: FnOnce() -> std::io::Result<crate::ca::CaInfo>,
{
    account().map_err(|error| std::io::Error::new(error.kind(), AccountGateError(error)))?;
    ca()
}

#[cfg(windows)]
fn consume_secrets(
    req: &Request,
    operation: Operation,
) -> std::io::Result<crate::secret_store::SecretMaterial> {
    let mut material = if let Some(path) = &req.secret_file {
        crate::secret_store::consume(std::path::Path::new(path))?
    } else {
        crate::secret_store::SecretMaterial {
            tailscale_auth_key: req.tailscale_auth_key.clone(),
            proxmox_password: req.proxmox_password.clone(),
        }
    };
    if operation == Operation::Provision && material.proxmox_password.is_none() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "PROXMOX_CREDENTIAL_MISSING",
        ));
    }
    if operation == Operation::JoinMesh && material.tailscale_auth_key.is_none() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "MESH_CREDENTIAL_MISSING",
        ));
    }
    Ok(std::mem::take(&mut material))
}

#[cfg(windows)]
fn join_mesh(req: &Request, p: &mut Progress) -> std::io::Result<()> {
    let material = consume_secrets(req, Operation::JoinMesh)?;
    let mut material = material;
    let mut key = material.tailscale_auth_key.take().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "MESH_CREDENTIAL_MISSING")
    })?;
    let staging = crate::secret_store::staging_dir(&crate::state::state_dir());
    let path = staging.join(format!("mesh-{}.env", req.request_id));
    // The runtime contract has independent environment files so each value
    // is consumed by its owning Quadlet and never appears in argv.
    let compute_path = staging.join(format!("compute-{}.env", req.request_id));
    let result = (|| {
        crate::secret_store::stage_runtime_file(&path, "TS_AUTHKEY", &key)?;
        if let Some(password) = material.proxmox_password.as_deref() {
            crate::secret_store::stage_runtime_file(&compute_path, "PROXMOX_PASSWORD", password)?;
        }
        crate::linux_node::install_with_secrets(
            &crate::state::state_dir(),
            Some(&path),
            material
                .proxmox_password
                .as_ref()
                .map(|_| compute_path.as_path()),
        )
    })();
    crate::secret_store::clear_string(&mut key);
    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_file(&compute_path);
    result?;
    crate::linux_node::verify(&crate::state::state_dir())?;
    let ip = crate::linux_node::private_ip()?;
    mark_ready(p, ip);
    Ok(())
}

fn mark_ready(p: &mut Progress, ip: String) {
    p.state = NodeState::NodeReady;
    p.phase = "ready".into();
    p.message = "Node is ready; complete the displayed private-network actions.".into();
    p.error_code = None;
    p.retryable = false;
    p.node_private_ip = Some(ip.clone());
    p.pihole_private_ip = Some(ip);
    p.tailscale_ip = p.node_private_ip.clone();
    p.pihole_ip = p.pihole_private_ip.clone();
    p.percent = Some(100);
}

fn classify_error(error: &std::io::Error) -> String {
    let text = error.to_string();
    let code = text.split_once(':').map(|(code, _)| code).unwrap_or(&text);
    if !code.is_empty()
        && code.len() <= 80
        && code.chars().all(|character| {
            character.is_ascii_uppercase() || character.is_ascii_digit() || character == '_'
        })
    {
        return code.into();
    }
    match error.kind() {
        std::io::ErrorKind::NotFound => "PAYLOAD_MISSING".into(),
        std::io::ErrorKind::PermissionDenied => "ACCESS_DENIED".into(),
        _ => "PROVISIONING_FAILED".into(),
    }
}

#[cfg(windows)]
fn provision_runtime(req: &Request) -> std::io::Result<()> {
    let material = consume_secrets(req, Operation::Provision)?;
    // This gate must precede every install.run invocation.  A missing or
    // unverified sealed image is an actionable release/installation blocker;
    // never silently use another registered distro or an arbitrary payload.
    crate::linux_node::ensure_distro()?;
    // The install path owns dependency installation before its strict KVM
    // ioctl gate. A pristine rootfs can contain the KVM modules without kmod,
    // so running the non-mutating check first would deadlock provisioning.
    let staging = crate::secret_store::staging_dir(&crate::state::state_dir());
    let mesh_path = staging.join(format!("mesh-{}.env", req.request_id));
    let compute_path = staging.join(format!("compute-{}.env", req.request_id));
    let result = (|| {
        if let Some(key) = material.tailscale_auth_key.as_deref() {
            crate::secret_store::stage_runtime_file(&mesh_path, "TS_AUTHKEY", key)?;
        }
        let password = material.proxmox_password.as_deref().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "PROXMOX_CREDENTIAL_MISSING",
            )
        })?;
        crate::secret_store::stage_runtime_file(&compute_path, "PROXMOX_PASSWORD", password)?;
        crate::linux_node::install_with_secrets(
            &crate::state::state_dir(),
            material
                .tailscale_auth_key
                .as_ref()
                .map(|_| mesh_path.as_path()),
            Some(&compute_path),
        )
    })();
    let _ = std::fs::remove_file(&mesh_path);
    let _ = std::fs::remove_file(&compute_path);
    result.map(|_| ())
}

pub fn handle(req: &Request, current: &Progress) -> Progress {
    let mut p = current.clone();
    p.operation_id = Uuid::new_v4();
    p.sequence += 1;
    p.error_code = None;
    p.retryable = false;
    p.requires_restart = false;
    if req.operation != Operation::GetProgress && current.request_id == Some(req.request_id) {
        p.state = NodeState::RecoveryRequired;
        p.phase = "replay".into();
        p.message = "The request was already applied; submit a new request to continue.".into();
        p.error_code = Some("REPLAYED_REQUEST".into());
        p.retryable = false;
        return p;
    }
    p.request_id = Some(req.request_id);
    if req.validate().is_err() {
        p.state = NodeState::Failed;
        p.phase = "protocol".into();
        p.message = "The request was rejected by the control protocol.".into();
        p.error_code = Some("INVALID_REQUEST".into());
        return p;
    }
    if !allowed(req.operation.clone(), &current.state) {
        // An invalid request must not destroy the last known-safe checkpoint.
        // Keep the real state/phase so a follow-up can choose the right
        // operation instead of recovering from a fabricated checkpoint.
        p.state = current.state.clone();
        p.phase = current.phase.clone();
        p.message = format!(
            "{:?} is not valid at the current checkpoint ({:?}); submit a supported operation.",
            req.operation, current.state,
        );
        p.error_code = Some("INVALID_TRANSITION".into());
        p.retryable = false;
        return p;
    }
    match req.operation {
        Operation::GetProgress => p,
        Operation::Provision => {
            p.state = NodeState::WindowsReady;
            p.phase = "windows".into();
            p.message = "Windows prerequisites are ready; continuing with WSL.".into();
            p.percent = Some(20);
            p
        }
        Operation::JoinMesh => {
            p.state = NodeState::MeshPending;
            p.phase = "mesh".into();
            p.message =
                "Mesh enrollment accepted; runtime will consume the temporary credential.".into();
            p.percent = Some(80);
            p
        }
        Operation::Retry => {
            // Retry carries no secret by design. Never report a scheduled
            // operation when the next runtime step needs a one-shot value.
            let (code, message) = match (&current.state, current.phase.as_str()) {
                (NodeState::MeshPending, _) | (NodeState::Blocked, "mesh") => (
                    "MESH_CREDENTIAL_MISSING",
                    "Retry needs a new one-shot mesh credential; submit JoinMesh.",
                ),
                (NodeState::Blocked, _) | (NodeState::RecoveryRequired, _) => (
                    "PROXMOX_CREDENTIAL_MISSING",
                    "Retry needs the one-shot provisioning credential; submit Provision.",
                ),
                _ => (
                    "RETRY_UNSUPPORTED",
                    "Retry cannot resume work at this checkpoint; submit a supported operation.",
                ),
            };
            p.state = current.state.clone();
            p.phase = current.phase.clone();
            p.message = message.into();
            p.error_code = Some(code.into());
            p.retryable = false;
            p
        }
        Operation::Cancel => {
            p.state = NodeState::RecoveryRequired;
            p.phase = "cancelled".into();
            p.message = "Operation cancelled at a safe checkpoint.".into();
            p
        }
    }
}

fn allowed(operation: Operation, state: &NodeState) -> bool {
    match operation {
        Operation::GetProgress | Operation::Cancel => true,
        Operation::Provision => matches!(
            state,
            NodeState::New
                | NodeState::Blocked
                | NodeState::Failed
                | NodeState::RecoveryRequired
                | NodeState::RebootRequired
        ),
        Operation::JoinMesh => matches!(
            state,
            NodeState::RuntimeReady | NodeState::MeshPending | NodeState::Blocked
        ),
        Operation::Retry => matches!(
            state,
            NodeState::Blocked
                | NodeState::Failed
                | NodeState::RecoveryRequired
                | NodeState::MeshPending
                | NodeState::NodeReady
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use gnx_control_protocol::PROTOCOL_VERSION;

    fn request(operation: Operation) -> Request {
        let key = (operation == Operation::JoinMesh).then(|| "tskey-auth-test".to_string());
        Request {
            version: PROTOCOL_VERSION,
            request_id: Uuid::new_v4(),
            operation,
            tailscale_auth_key: key,
            proxmox_password: None,
            secret_file: None,
        }
    }

    #[test]
    fn rejects_invalid_transition_without_mutating_checkpoint() {
        let mut current = crate::state::initial();
        current.state = NodeState::MeshPending;
        current.phase = "mesh".into();
        current.percent = Some(60);
        let next = handle(&request(Operation::Provision), &current);
        assert_eq!(next.state, NodeState::MeshPending);
        assert_eq!(next.phase, "mesh");
        assert_eq!(next.percent, Some(60));
        assert_eq!(next.error_code.as_deref(), Some("INVALID_TRANSITION"));
    }

    #[test]
    fn retry_requests_mesh_credential_instead_of_claiming_scheduled_work() {
        let mut current = crate::state::initial();
        current.state = NodeState::MeshPending;
        current.phase = "mesh".into();
        let next = handle(&request(Operation::Retry), &current);
        assert_eq!(next.state, NodeState::MeshPending);
        assert_eq!(next.error_code.as_deref(), Some("MESH_CREDENTIAL_MISSING"));
        assert!(!next.retryable);
        assert!(!next.message.contains("scheduled"));
    }

    #[test]
    fn retry_ambiguous_recovery_requests_provision_credential() {
        let mut current = crate::state::initial();
        current.state = NodeState::RecoveryRequired;
        current.phase = "checkpoint".into();
        let next = handle(&request(Operation::Retry), &current);
        assert_eq!(next.state, NodeState::RecoveryRequired);
        assert_eq!(next.phase, "checkpoint");
        assert_eq!(
            next.error_code.as_deref(),
            Some("PROXMOX_CREDENTIAL_MISSING")
        );
        assert!(!next.message.contains("JoinMesh"));
    }

    #[test]
    fn provision_starts_from_new() {
        let next = handle(&request(Operation::Provision), &crate::state::initial());
        assert_eq!(next.state, NodeState::WindowsReady);
        assert_eq!(next.sequence, 1);
    }

    #[test]
    fn get_progress_is_read_only() {
        let mut current = crate::state::initial();
        current.sequence = 7;
        current.error_code = Some("ACCOUNT_PROFILE_INVALID".into());
        current.retryable = true;
        let request = Request {
            version: PROTOCOL_VERSION,
            request_id: Uuid::new_v4(),
            operation: Operation::GetProgress,
            tailscale_auth_key: None,
            proxmox_password: None,
            secret_file: None,
        };
        assert_eq!(execute(&request, &current), current);
    }

    #[test]
    fn provision_account_gate_precedes_ca_without_consuming_secrets() {
        use std::cell::RefCell;

        let events = RefCell::new(Vec::new());
        let result = account_then_ca(
            || {
                events.borrow_mut().push("account");
                Ok(())
            },
            || {
                events.borrow_mut().push("ca");
                Ok(crate::ca::CaInfo {
                    certificate_path: std::path::PathBuf::from("ca.cert.pem"),
                })
            },
        );
        assert!(result.is_ok());
        assert_eq!(*events.borrow(), ["account", "ca"]);
    }

    #[test]
    fn classifies_bare_runtime_codes_without_erasing_diagnostics() {
        let error = std::io::Error::other("KVM_UNAVAILABLE");
        assert_eq!(classify_error(&error), "KVM_UNAVAILABLE");
        let wrapped = std::io::Error::other("DISTRO_IMPORT_FAILED: details");
        assert_eq!(classify_error(&wrapped), "DISTRO_IMPORT_FAILED");
    }

    #[test]
    fn account_gate_preserves_profile_error_and_phase_source() {
        let result = account_then_ca(
            || {
                Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "ACCOUNT_PROFILE_ACCESS_INVALID: denied",
                ))
            },
            || panic!("CA must not run after an account failure"),
        );
        let error = result.expect_err("account failure should stop the gate");
        let source = account_gate_source(&error).expect("account source should be retained");
        assert_eq!(classify_error(source), "ACCOUNT_PROFILE_ACCESS_INVALID");
    }

    #[test]
    fn rejects_replayed_request_id() {
        let current = crate::state::initial();
        let first = request(Operation::Provision);
        let mut checkpoint = handle(&first, &current);
        let replay = handle(&first, &checkpoint);
        assert_eq!(replay.error_code.as_deref(), Some("REPLAYED_REQUEST"));
        assert_eq!(replay.state, NodeState::RecoveryRequired);
        checkpoint.request_id = Some(first.request_id);
        assert_eq!(
            handle(&first, &checkpoint).error_code.as_deref(),
            Some("REPLAYED_REQUEST")
        );
    }

    #[cfg(not(windows))]
    #[test]
    fn provision_reports_ca_and_operator_actions() {
        let root = std::env::temp_dir().join(format!("gnx-progress-{}", Uuid::new_v4()));
        std::env::set_var("GNX_STATE_DIR", &root);
        let next = execute(&request(Operation::Provision), &crate::state::initial());
        assert!(next.private_ca_certificate.is_some());
        assert!(next
            .required_actions
            .iter()
            .any(|action| action.kind == gnx_control_protocol::ActionKind::ConfigureSplitDns));
        let _ = std::fs::remove_dir_all(root);
        std::env::remove_var("GNX_STATE_DIR");
    }
}
