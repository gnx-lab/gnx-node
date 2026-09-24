//! Versioned, deliberately small contract between Setup and the Windows host agent.
use serde::{Deserialize, Serialize};
use std::fmt;
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

/// A bounded action which must be completed by the operator, not by a
/// privileged host command.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ActionKind {
    ConfigureSplitDns,
    TrustPrivateCa,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RequiredAction {
    pub kind: ActionKind,
    pub target: String,
    pub value: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Progress {
    #[serde(default)]
    pub request_id: Option<Uuid>,
    pub operation_id: Uuid,
    pub sequence: u64,
    pub phase: String,
    pub state: NodeState,
    pub message: String,
    pub error_code: Option<String>,
    pub retryable: bool,
    pub requires_restart: bool,
    pub percent: Option<u8>,
    #[serde(default)]
    pub node_private_ip: Option<String>,
    #[serde(default)]
    pub pihole_private_ip: Option<String>,
    /// Runtime-compatible aliases retained for the JSONL verifier contract.
    #[serde(default)]
    pub tailscale_ip: Option<String>,
    #[serde(default)]
    pub pihole_ip: Option<String>,
    #[serde(default)]
    pub required_actions: Vec<RequiredAction>,
    /// Public certificate path only; the private key is never returned.
    #[serde(default)]
    pub private_ca_certificate: Option<String>,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub version: u16,
    pub request_id: Uuid,
    pub operation: Operation,
    /// Inline values are accepted only in-process. Native Setup uses the
    /// one-shot secret_file reference so values never cross the JSON pipe.
    #[serde(default, skip_serializing)]
    pub tailscale_auth_key: Option<String>,
    #[serde(default, skip_serializing)]
    pub proxmox_password: Option<String>,
    /// A bounded local path to an ACL-protected, one-shot secret bundle.
    #[serde(default)]
    pub secret_file: Option<String>,
}

impl fmt::Debug for Request {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Request")
            .field("version", &self.version)
            .field("request_id", &self.request_id)
            .field("operation", &self.operation)
            .field(
                "tailscale_auth_key",
                &self.tailscale_auth_key.as_ref().map(|_| "[redacted]"),
            )
            .field(
                "proxmox_password",
                &self.proxmox_password.as_ref().map(|_| "[redacted]"),
            )
            .field("secret_file", &self.secret_file)
            .finish()
    }
}

impl Drop for Request {
    fn drop(&mut self) {
        if let Some(value) = &mut self.tailscale_auth_key {
            unsafe { value.as_mut_vec().fill(0) };
        }
        if let Some(value) = &mut self.proxmox_password {
            unsafe { value.as_mut_vec().fill(0) };
        }
    }
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
        if !matches!(self.operation, Operation::Provision | Operation::JoinMesh)
            && self.proxmox_password.is_some()
        {
            return Err(ProtocolError::Invalid(
                "Proxmox credential is only accepted by Provision or JoinMesh".into(),
            ));
        }
        if self.secret_file.is_some()
            && !matches!(self.operation, Operation::Provision | Operation::JoinMesh)
        {
            return Err(ProtocolError::Invalid(
                "secret reference is only accepted by Provision or JoinMesh".into(),
            ));
        }
        if let Some(path) = &self.secret_file {
            if !valid_secret_reference(path) {
                return Err(ProtocolError::Invalid("invalid secret reference".into()));
            }
        }
        if self.operation == Operation::JoinMesh
            && self.tailscale_auth_key.is_none()
            && self.secret_file.is_none()
        {
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
        if let Some(password) = &self.proxmox_password {
            if password.is_empty()
                || password.len() > 1024
                || password.chars().any(|c| c.is_control())
            {
                return Err(ProtocolError::Invalid(
                    "invalid Proxmox credential format".into(),
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
        if req.tailscale_auth_key.is_some() || req.proxmox_password.is_some() {
            return Err(ProtocolError::Invalid(
                "inline secrets are not accepted on the control pipe".into(),
            ));
        }
        req.validate()?;
        Ok(req)
    }
    pub fn to_frame(&self) -> Result<Vec<u8>, ProtocolError> {
        self.validate()?;
        serde_json::to_vec(self).map_err(|e| ProtocolError::Json(e.to_string()))
    }

    pub fn with_secret_file(mut self, secret_file: impl Into<String>) -> Self {
        self.secret_file = Some(secret_file.into());
        self.tailscale_auth_key = None;
        self.proxmox_password = None;
        self
    }
}

fn valid_secret_reference(path: &str) -> bool {
    if path.is_empty()
        || path.len() > 512
        || path.chars().any(|c| c.is_control())
        || path.starts_with("\\\\")
        || path.starts_with("//")
        || path.split(['/', '\\']).any(|part| part == "..")
    {
        return false;
    }
    let absolute = path.starts_with('/')
        || (path.len() >= 3
            && path.as_bytes()[1] == b':'
            && matches!(path.as_bytes()[2], b'/' | b'\\'));
    if !absolute {
        return false;
    }
    let Some(name) = path.rsplit(['/', '\\']).next() else {
        return false;
    };
    let Some(uuid) = name
        .strip_prefix("gnx-onboarding-")
        .and_then(|value| value.strip_suffix(".secret"))
    else {
        return false;
    };
    Uuid::parse_str(uuid).is_ok() && uuid == Uuid::parse_str(uuid).unwrap().to_string()
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
            proxmox_password: None,
            secret_file: None,
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
            proxmox_password: None,
            secret_file: None,
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
            proxmox_password: None,
            secret_file: None,
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
            proxmox_password: None,
            secret_file: None,
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
            proxmox_password: None,
            secret_file: None,
        };
        assert!(matches!(r.validate(), Err(ProtocolError::Invalid(_))));
    }

    #[test]
    fn rejects_empty_frames() {
        assert_eq!(Request::from_frame(b""), Err(ProtocolError::FrameTooLarge));
    }

    #[test]
    fn accepts_get_progress_control_frame() {
        let frame = serde_json::json!({
            "version": PROTOCOL_VERSION,
            "request_id": Uuid::new_v4(),
            "operation": "GetProgress"
        });
        let encoded = serde_json::to_vec(&frame).unwrap();
        assert!(Request::from_frame(&encoded).is_ok());
        assert!(Request::from_frame(&[encoded, b"\r".to_vec()].concat()).is_ok());
    }

    #[test]
    fn rejects_inline_secrets_from_control_frames() {
        let request = Request {
            version: PROTOCOL_VERSION,
            request_id: Uuid::new_v4(),
            operation: Operation::Provision,
            tailscale_auth_key: None,
            proxmox_password: None,
            secret_file: None,
        };
        let mut value = serde_json::to_value(request).unwrap();
        value["proxmox_password"] = serde_json::json!("should-not-cross-the-pipe");
        let frame = serde_json::to_vec(&value).unwrap();
        assert!(matches!(
            Request::from_frame(&frame),
            Err(ProtocolError::Invalid(message)) if message.contains("inline secrets")
        ));
    }

    #[test]
    fn native_secret_reference_serializes_but_values_do_not() {
        let r = Request {
            version: PROTOCOL_VERSION,
            request_id: Uuid::new_v4(),
            operation: Operation::Provision,
            tailscale_auth_key: None,
            proxmox_password: Some("correct horse battery staple".into()),
            secret_file: Some(
                r"C:\Users\mayas\AppData\Local\Temp\gnx-onboarding-550e8400-e29b-41d4-a716-446655440000.secret".into(),
            ),
        };
        let frame = String::from_utf8(r.to_frame().unwrap()).unwrap();
        assert!(frame.contains("secret_file"));
        assert!(!frame.contains("correct horse"));
        let debug = format!("{r:?}");
        assert!(!debug.contains("correct horse"));
        assert!(debug.contains("redacted"));
    }

    #[test]
    fn rejects_arbitrary_secret_paths() {
        for path in [
            r"C:\ProgramData\GnX\state\other.secret",
            r"C:\Users\mayas\AppData\Local\Temp\gnx-onboarding-550e8400-e29b-41d4-a716-446655440000.txt",
            r"C:\Users\mayas\AppData\Local\Temp\gnx-onboarding-550e8400-e29b-41d4-a716-446655440000.secret\..\other",
        ] {
            assert!(!valid_secret_reference(path));
        }
    }
}
