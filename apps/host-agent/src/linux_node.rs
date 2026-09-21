//! Narrow adapter for the external Linux runtime contract.
//!
//! Rust owns orchestration and checkpoints; `install.run` and `verify.run` own
//! Podman, Quadlets, networking and runtime configuration.

use std::io;
use std::path::{Path, PathBuf};

pub const DISTRO_NAME: &str = "gnx-node";

pub fn payload_dir() -> PathBuf {
    std::env::var_os("GNX_NODE_PAYLOAD")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("payload/node"))
}

pub fn validate_payload(root: &Path) -> io::Result<()> {
    for required in ["install.run", "verify.run"] {
        if !root.join(required).is_file() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("runtime payload missing {required}"),
            ));
        }
    }
    if !root.join("services").is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "runtime payload missing services directory",
        ));
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeResult {
    Checked,
    Installed,
    Ready,
}

#[cfg(not(windows))]
pub fn install_check(_state_dir: &Path) -> io::Result<RuntimeResult> {
    validate_payload(&payload_dir())?;
    Ok(RuntimeResult::Checked)
}

#[cfg(not(windows))]
pub fn install(_state_dir: &Path) -> io::Result<RuntimeResult> {
    validate_payload(&payload_dir())?;
    Ok(RuntimeResult::Installed)
}

#[cfg(not(windows))]
pub fn verify(_state_dir: &Path) -> io::Result<RuntimeResult> {
    validate_payload(&payload_dir())?;
    Ok(RuntimeResult::Ready)
}

#[cfg(windows)]
fn run_wsl(script: &str, args: &[&str]) -> io::Result<std::process::Output> {
    use std::process::Command;
    let mut command = Command::new("wsl.exe");
    command.args(["--distribution", DISTRO_NAME, "--", script]);
    command.args(args);
    command.output()
}

#[cfg(windows)]
pub fn install_check(state_dir: &Path) -> io::Result<RuntimeResult> {
    validate_payload(&payload_dir())?;
    let output = run_wsl(
        "/opt/gnx/payload/node/install.run",
        &[
            "check",
            "--payload-dir",
            "/opt/gnx/payload/node",
            "--state-dir",
            &path_arg(state_dir),
        ],
    )?;
    if !output.status.success() {
        return Err(runtime_error(&output));
    }
    Ok(RuntimeResult::Checked)
}

#[cfg(windows)]
pub fn install(state_dir: &Path) -> io::Result<RuntimeResult> {
    validate_payload(&payload_dir())?;
    let output = run_wsl(
        "/opt/gnx/payload/node/install.run",
        &[
            "install",
            "--payload-dir",
            "/opt/gnx/payload/node",
            "--state-dir",
            &path_arg(state_dir),
        ],
    )?;
    if !output.status.success() {
        return Err(runtime_error(&output));
    }
    Ok(RuntimeResult::Installed)
}

#[cfg(windows)]
pub fn verify(state_dir: &Path) -> io::Result<RuntimeResult> {
    let output = run_wsl(
        "/opt/gnx/payload/node/verify.run",
        &["--state-dir", &path_arg(state_dir)],
    )?;
    if !output.status.success() {
        return Err(runtime_error(&output));
    }
    Ok(RuntimeResult::Ready)
}

#[cfg(windows)]
fn path_arg(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

#[cfg(windows)]
fn runtime_error(output: &std::process::Output) -> io::Error {
    let stderr = String::from_utf8_lossy(&output.stderr);
    // Runtime diagnostics are JSONL and must never leak credentials into the
    // progress store. Keep only a short, non-secret classification here.
    let code = stderr
        .lines()
        .find_map(|line| line.split("\"code\":\"").nth(1))
        .and_then(|v| v.split('\"').next())
        .unwrap_or("RUNTIME_FAILED");
    io::Error::other(code.chars().take(80).collect::<String>())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payload_validation_rejects_missing_contract() {
        let root = std::env::temp_dir().join(format!("gnx-node-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        assert!(validate_payload(&root).is_err());
        let _ = std::fs::remove_dir_all(root);
    }
}
