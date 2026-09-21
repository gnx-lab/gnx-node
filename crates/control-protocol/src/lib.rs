//! Versioned, deliberately small contract between Setup and the Windows host agent.
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

pub const PROTOCOL_VERSION: u16 = 1;
pub const MAX_FRAME_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub enum Operation {
    GetProgress,
    Provision,
    JoinMesh,
    Retry,
    Cancel,
    Deprovision,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum NodeState {
    New,
    WindowsReady,
    RebootRequired,
    WslReady,
    RuntimeReady,
    MeshPending,
    NodeReady,
    Blocked,
    Failed,
    RecoveryRequired,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Progress {
    pub operation_id: Uuid,
    pub sequence: u64,
    pub phase: String,
    pub state: NodeState,
    pub message: String,
    pub error_code: Option<String>,
    pub retryable: bool,
    pub requires_restart: bool,
    pub percent: Option<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Request {
    pub version: u16,
    pub request_id: Uuid,
    pub operation: Operation,
    /// Only JoinMesh may carry a secret, and it is never serialized into a response/state.
    #[serde(default, skip_serializing)]
    pub tailscale_auth_key: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Response {
    pub version: u16,
    pub request_id: Uuid,
    pub operation_id: Uuid,
    pub progress: Progress,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ProtocolError {
    #[error("unsupported protocol version")]
    UnsupportedVersion,
    #[error("frame exceeds maximum size")]
    FrameTooLarge,
    #[error("invalid request: {0}")]
    Invalid(String),
    #[error("malformed JSON: {0}")]
    Json(String),
}

impl Request {
    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.version != PROTOCOL_VERSION {
            return Err(ProtocolError::UnsupportedVersion);
        }
        if self.operation != Operation::JoinMesh && self.tailscale_auth_key.is_some() {
            return Err(ProtocolError::Invalid(
                "secret is only accepted by JoinMesh".into(),
            ));
        }
        if self.operation == Operation::JoinMesh && self.tailscale_auth_key.is_none() {
            return Err(ProtocolError::Invalid(
                "mesh credential is required for JoinMesh".into(),
            ));
        }
        if let Some(key) = &self.tailscale_auth_key {
            if !key.starts_with("tskey-auth-")
                || key.len() > 512
                || key.chars().any(|c| c.is_control() || c.is_whitespace())
            {
                return Err(ProtocolError::Invalid(
                    "invalid mesh credential format".into(),
                ));
            }
        }
        Ok(())
    }
    pub fn from_frame(frame: &[u8]) -> Result<Self, ProtocolError> {
        if frame.is_empty() || frame.len() > MAX_FRAME_BYTES {
            return Err(ProtocolError::FrameTooLarge);
        }
        let req: Self =
            serde_json::from_slice(frame).map_err(|e| ProtocolError::Json(e.to_string()))?;
        req.validate()?;
        Ok(req)
    }
    pub fn to_frame(&self) -> Result<Vec<u8>, ProtocolError> {
        self.validate()?;
        serde_json::to_vec(self).map_err(|e| ProtocolError::Json(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_secret_on_other_operation() {
        let r = Request {
            version: 1,
            request_id: Uuid::new_v4(),
            operation: Operation::Provision,
            tailscale_auth_key: Some("tskey-auth-a".into()),
        };
        assert!(matches!(r.validate(), Err(ProtocolError::Invalid(_))));
    }
    #[test]
    fn rejects_old_version() {
        let r = Request {
            version: 99,
            request_id: Uuid::new_v4(),
            operation: Operation::GetProgress,
            tailscale_auth_key: None,
        };
        assert_eq!(r.validate(), Err(ProtocolError::UnsupportedVersion));
    }
    #[test]
    fn secret_is_not_serialized() {
        let r = Request {
            version: 1,
            request_id: Uuid::new_v4(),
            operation: Operation::JoinMesh,
            tailscale_auth_key: Some("tskey-auth-a".into()),
        };
        assert!(!String::from_utf8(r.to_frame().unwrap())
            .unwrap()
            .contains("tskey"));
    }

    #[test]
    fn rejects_secret_with_control_characters() {
        let r = Request {
            version: PROTOCOL_VERSION,
            request_id: Uuid::new_v4(),
            operation: Operation::JoinMesh,
            tailscale_auth_key: Some("tskey-auth-a\n--bad".into()),
        };
        assert!(matches!(r.validate(), Err(ProtocolError::Invalid(_))));
    }

    #[test]
    fn rejects_join_without_credential() {
        let r = Request {
            version: PROTOCOL_VERSION,
            request_id: Uuid::new_v4(),
            operation: Operation::JoinMesh,
            tailscale_auth_key: None,
        };
        assert!(matches!(r.validate(), Err(ProtocolError::Invalid(_))));
    }

    #[test]
    fn rejects_empty_frames() {
        assert_eq!(Request::from_frame(b""), Err(ProtocolError::FrameTooLarge));
    }
}
