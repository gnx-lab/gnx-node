use gnx_control_protocol::{NodeState, Operation, Progress, Request};
use uuid::Uuid;

pub fn handle(req: &Request, current: &Progress) -> Progress {
    let mut p = current.clone();
    p.operation_id = Uuid::new_v4();
    p.sequence += 1;
    p.error_code = None;
    p.retryable = false;
    p.requires_restart = false;
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
