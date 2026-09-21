use gnx_control_protocol::{NodeState, Operation, Progress, Request};
use uuid::Uuid;

/// Apply an authorized request and advance one durable checkpoint at a time.
/// Platform hooks are Windows-only so protocol tests never mutate the host.
pub fn execute(req: &Request, current: &Progress) -> Progress {
    let mut p = handle(req, current);
    #[cfg(windows)]
    {
        if matches!(req.operation, Operation::Provision) && p.error_code.is_none() {
            if let Err(error) = crate::dedicated_account::ensure()
                .and_then(|_| {
                    crate::linux_node::install_check(&crate::state::state_dir()).map(|_| ())
                })
                .and_then(|_| crate::linux_node::install(&crate::state::state_dir()).map(|_| ()))
            {
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
    }
    p
}

fn classify_error(error: &std::io::Error) -> String {
    match error.kind() {
        std::io::ErrorKind::NotFound => "PAYLOAD_MISSING".into(),
        std::io::ErrorKind::PermissionDenied => "ACCESS_DENIED".into(),
        _ => "PROVISIONING_FAILED".into(),
    }
}

pub fn handle(req: &Request, current: &Progress) -> Progress {
    let mut p = current.clone();
    p.operation_id = Uuid::new_v4();
    p.sequence += 1;
    p.error_code = None;
    p.retryable = false;
    p.requires_restart = false;
    if req.validate().is_err() {
        p.state = NodeState::Failed;
        p.phase = "protocol".into();
        p.message = "The request was rejected by the control protocol.".into();
        p.error_code = Some("INVALID_REQUEST".into());
        return p;
    }
    if !allowed(req.operation.clone(), &current.state) {
        p.state = NodeState::RecoveryRequired;
        p.phase = "checkpoint".into();
        p.message = "This operation is not valid at the current checkpoint.".into();
        p.error_code = Some("INVALID_TRANSITION".into());
        p.retryable = true;
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
            p.message = "Retry scheduled from the last safe checkpoint.".into();
            p.retryable = true;
            p
        }
        Operation::Cancel => {
            p.state = NodeState::RecoveryRequired;
            p.phase = "cancelled".into();
            p.message = "Operation cancelled at a safe checkpoint.".into();
            p
        }
        Operation::Deprovision => {
            p.state = NodeState::New;
            p.phase = "deprovisioned".into();
            p.message =
                "Node resources were released; confirmation is required before deleting data."
                    .into();
            p.percent = Some(0);
            p
        }
    }
}

fn allowed(operation: Operation, state: &NodeState) -> bool {
    match operation {
        Operation::GetProgress | Operation::Cancel | Operation::Deprovision => true,
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
            NodeState::Blocked | NodeState::Failed | NodeState::RecoveryRequired
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
        }
    }

    #[test]
    fn rejects_invalid_transition_without_mutating_checkpoint() {
        let current = crate::state::initial();
        let next = handle(&request(Operation::JoinMesh), &current);
        assert_eq!(next.state, NodeState::RecoveryRequired);
        assert_eq!(next.error_code.as_deref(), Some("INVALID_TRANSITION"));
    }

    #[test]
    fn provision_starts_from_new() {
        let next = handle(&request(Operation::Provision), &crate::state::initial());
        assert_eq!(next.state, NodeState::WindowsReady);
        assert_eq!(next.sequence, 1);
    }
}
