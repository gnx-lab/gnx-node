//! Windows identity boundary for the managed `gnxnodesvc` account.
//!
//! The account name is deliberately fixed and is never inferred from an existing
//! user.  All WSL work is scoped to this identity and to the `gnx-node` distro.

pub const ACCOUNT_NAME: &str = "gnxnodesvc";
pub const DISTRO_NAME: &str = "gnx-node";

pub fn account_name_is_managed(name: &str) -> bool {
    name.eq_ignore_ascii_case(ACCOUNT_NAME)
}

pub fn profile_path() -> std::path::PathBuf {
    if let Ok(root) = std::env::var("GNX_PROFILE_DIR") {
        return root.into();
    }
    if cfg!(windows) {
        std::env::var("ProgramData")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|_| std::path::PathBuf::from(r"C:\ProgramData"))
            .join("GnX")
            .join("Node")
            .join("identity")
    } else {
        std::path::PathBuf::from("target/gnx-identity")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnsureResult {
    Created,
    Existing,
}

#[cfg(not(windows))]
pub fn ensure() -> std::io::Result<EnsureResult> {
    // Development and protocol tests do not mutate the host account.
    Ok(EnsureResult::Existing)
}

#[cfg(windows)]
pub fn ensure() -> std::io::Result<EnsureResult> {
    use std::process::Command;

    // `net user` is used only for account discovery/creation.  No password is
    // passed on a command line; the service identity is provisioned by the
    // signed installer and may be disabled for interactive logon by policy.
    let existing = Command::new("net").args(["user", ACCOUNT_NAME]).output()?;
    if existing.status.success() {
        return Ok(EnsureResult::Existing);
    }
    let created = Command::new("net")
        .args([
            "user",
            ACCOUNT_NAME,
            "/add",
            "/passwordreq:no",
            "/passwordchg:no",
            "/expires:never",
        ])
        .output()?;
    if !created.status.success() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "managed Windows identity could not be created",
        ));
    }
    Ok(EnsureResult::Created)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_fixed_identity_is_managed() {
        assert!(account_name_is_managed("GNXNODESVC"));
        assert!(!account_name_is_managed("Administrator"));
        assert!(!account_name_is_managed("gnxnodesvc2"));
    }
}
