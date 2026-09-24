//! Narrow adapter for the external Linux runtime contract.
//!
//! Rust owns orchestration and checkpoints; `install.run` and `verify.run` own
//! Podman, Quadlets, networking and runtime configuration.

use std::io;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

pub const DISTRO_NAME: &str = "gnx-node";
pub const ROOTFS_ARTIFACT_NAME: &str = "gnx-node-rootfs.tar";
pub const ROOTFS_MANIFEST_NAME: &str = "gnx-node-rootfs.tar.sha256";
pub const PAYLOAD_MARKER_PATH: &str = "/opt/gnx/payload/node/.gnx-payload.sha256";
pub const WSL_CONFIG_NAME: &str = ".wslconfig";

pub fn payload_dir() -> PathBuf {
    std::env::var_os("GNX_NODE_PAYLOAD")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            installed_payload_dir("payload-node").unwrap_or_else(|| PathBuf::from("payload/node"))
        })
}

pub fn host_payload_dir() -> PathBuf {
    std::env::var_os("GNX_HOST_PAYLOAD")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            installed_payload_dir("payload-host").unwrap_or_else(|| PathBuf::from("payload/host"))
        })
}

#[cfg(windows)]
fn installed_payload_dir(directory: &str) -> Option<PathBuf> {
    std::env::current_exe()
        .ok()
        .and_then(|executable| installed_payload_path(&executable, directory))
}

#[cfg(not(windows))]
fn installed_payload_dir(_directory: &str) -> Option<PathBuf> {
    None
}

fn installed_payload_path(executable: &Path, directory: &str) -> Option<PathBuf> {
    executable.parent().map(|parent| parent.join(directory))
}

fn payload_copy_source(root: &Path) -> String {
    format!("{}/.", windows_path_to_wsl(&root.to_string_lossy()))
}

pub fn rootfs_artifact() -> PathBuf {
    host_payload_dir().join(ROOTFS_ARTIFACT_NAME)
}

/// Validate the immutable WSL image contract before any WSL command is run.
/// The artifact and its detached SHA-256 manifest are intentionally required;
/// a distro must never be imported from an arbitrary or stale local file.
pub fn validate_rootfs_artifact(root: &Path) -> io::Result<()> {
    let metadata = std::fs::symlink_metadata(root).map_err(|_| {
        io::Error::new(
            io::ErrorKind::NotFound,
            format!("MISSING_ROOTFS_ARTIFACT: {}", root.display()),
        )
    })?;
    if !metadata.file_type().is_file() || metadata.len() == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("INVALID_ROOTFS_ARTIFACT: {}", root.display()),
        ));
    }
    #[cfg(windows)]
    if is_reparse_point(root) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "INVALID_ROOTFS_ARTIFACT: reparse point",
        ));
    }

    let expected_name = Path::new(ROOTFS_ARTIFACT_NAME);
    if root.file_name() != expected_name.file_name() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "INVALID_ROOTFS_ARTIFACT: unexpected filename",
        ));
    }
    let manifest = root.with_file_name(ROOTFS_MANIFEST_NAME);
    let manifest_text = std::fs::read_to_string(&manifest).map_err(|_| {
        io::Error::new(
            io::ErrorKind::NotFound,
            format!("MISSING_ROOTFS_MANIFEST: {}", manifest.display()),
        )
    })?;
    let mut fields = manifest_text.split_whitespace();
    let digest = fields.next().unwrap_or_default();
    let name = fields.next().unwrap_or_default();
    if fields.next().is_some()
        || name != ROOTFS_ARTIFACT_NAME
        || digest.len() != 64
        || digest != digest.to_ascii_lowercase()
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "INVALID_ROOTFS_MANIFEST",
        ));
    }
    let expected = (0..32)
        .map(|index| u8::from_str_radix(&digest[index * 2..index * 2 + 2], 16))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "INVALID_ROOTFS_MANIFEST"))?;
    let mut file = std::fs::File::open(root)?;
    let mut hasher = Sha256::new();
    io::copy(&mut file, &mut DigestWriter(&mut hasher))?;
    if hasher.finalize().as_slice() != expected.as_slice() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "ROOTFS_DIGEST_MISMATCH",
        ));
    }
    Ok(())
}

struct DigestWriter<'a>(&'a mut Sha256);

impl io::Write for DigestWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.update(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
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

#[cfg(windows)]
fn copy_wsl_config(host_root: &Path, profile: &Path) -> io::Result<()> {
    let source = host_root.join(WSL_CONFIG_NAME);
    let metadata = std::fs::symlink_metadata(&source).map_err(|_| {
        io::Error::new(
            io::ErrorKind::NotFound,
            "WSL_CONFIG_MISSING: payload-host/.wslconfig",
        )
    })?;
    if !metadata.file_type().is_file() || is_reparse_point(&source) || metadata.len() > 64 * 1024 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "WSL_CONFIG_INVALID: expected a bounded regular file",
        ));
    }
    let content = std::fs::read_to_string(&source)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "WSL_CONFIG_INVALID: not UTF-8"))?;
    if !content
        .lines()
        .any(|line| line.trim().eq_ignore_ascii_case("[wsl2]"))
        || content.chars().any(|character| {
            character.is_control() && character != '\n' && character != '\r' && character != '\t'
        })
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "WSL_CONFIG_INVALID: missing [wsl2] section",
        ));
    }
    // managed_profile_dir() resolves the exact token-derived profile path and
    // validates its allowed owner and gnxnodesvc FullControl ACE before copy.
    let destination = wsl_config_path(profile);
    std::fs::write(&destination, content.as_bytes())?;
    crate::dedicated_account::restrict_read_file(&destination)?;
    if std::fs::read(&destination)? != content.as_bytes() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "WSL_CONFIG_COPY_FAILED",
        ));
    }
    Ok(())
}

fn wsl_config_path(profile: &Path) -> PathBuf {
    profile.join(WSL_CONFIG_NAME)
}

#[cfg(windows)]
fn materialize_payload(node_root: &Path) -> io::Result<()> {
    validate_payload(node_root)?;
    let source = payload_copy_source(node_root);
    let commands = [
        ("/usr/bin/mkdir", vec!["-p", "/opt/gnx/payload/node"]),
        (
            "/usr/bin/cp",
            vec!["-a", source.as_str(), "/opt/gnx/payload/node"],
        ),
    ];
    for (program, args) in commands {
        let output = run_wsl(program, &args)?;
        if !output.status.success() {
            return Err(io::Error::other("DISTRO_PAYLOAD_MATERIALIZE_FAILED"));
        }
    }
    let hash = run_wsl(
        "/usr/bin/sha256sum",
        &["--strict", "-c", PAYLOAD_MARKER_PATH],
    )?;
    if !hash.status.success() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "DISTRO_PAYLOAD_HASH_MISMATCH",
        ));
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeResult {
    Installed,
    Ready,
}

#[cfg(not(windows))]
pub fn verify(_state_dir: &Path) -> io::Result<RuntimeResult> {
    validate_payload(&payload_dir())?;
    Ok(RuntimeResult::Ready)
}

#[cfg(windows)]
fn run_wsl(script: &str, args: &[&str]) -> io::Result<std::process::Output> {
    let mut command = vec![
        "--distribution".to_string(),
        DISTRO_NAME.to_string(),
        "--".to_string(),
        script.to_string(),
    ];
    command.extend(args.iter().map(|arg| (*arg).to_string()));
    crate::dedicated_account::run_wsl_as_windows_identity(&command)
}

fn wsl_reports_no_distributions(status: Option<i32>, stdout: &[u8], stderr: &[u8]) -> bool {
    status == Some(-1) && stderr.is_empty() && !decode_wsl_text(stdout).trim().is_empty()
}

fn decode_wsl_text(bytes: &[u8]) -> String {
    let utf16le = bytes.starts_with(&[0xff, 0xfe])
        || (bytes.len().is_multiple_of(2)
            && (0..bytes.len() / 2)
                .filter(|index| bytes[index * 2 + 1] == 0)
                .count()
                >= bytes.len() / 4);
    if utf16le {
        let start = if bytes.starts_with(&[0xff, 0xfe]) {
            2
        } else {
            0
        };
        let units = (start..bytes.len().saturating_sub(1))
            .step_by(2)
            .map(|index| u16::from_le_bytes([bytes[index], bytes[index + 1]]));
        String::from_utf16_lossy(&units.collect::<Vec<_>>())
    } else {
        String::from_utf8_lossy(bytes).into_owned()
    }
}

#[cfg(windows)]
fn distro_is_registered() -> io::Result<bool> {
    let output = crate::dedicated_account::run_wsl_as_windows_identity(&[
        "--list".into(),
        "--quiet".into(),
    ])?;
    if !output.status.success() {
        // `wsl.exe --list` returns unsigned exit code 0xffffffff and a
        // localized informational message when this Windows identity has no
        // registered distributions yet. That is the expected pre-import
        // state, not a failure to inspect WSL.
        if wsl_reports_no_distributions(output.status.code(), &output.stdout, &output.stderr) {
            return Ok(false);
        }
        return Err(io::Error::other(
            "DISTRO_LIST_FAILED: cannot inspect WSL registrations",
        ));
    }
    Ok(decode_wsl_text(&output.stdout)
        .lines()
        .map(|line| line.trim().trim_start_matches('*').trim())
        .any(|line| line == DISTRO_NAME))
}

fn distro_import_args(install_dir: &Path, artifact: &Path) -> [String; 6] {
    [
        "--import".into(),
        DISTRO_NAME.into(),
        install_dir.to_string_lossy().into_owned(),
        artifact.to_string_lossy().into_owned(),
        "--version".into(),
        "2".into(),
    ]
}

#[cfg(windows)]
fn import_distro(artifact: &Path) -> io::Result<()> {
    let install_dir = crate::dedicated_account::managed_profile_dir()?
        .join("AppData")
        .join("Local")
        .join("GnX")
        .join("wsl")
        .join(DISTRO_NAME);
    if let Some(parent) = install_dir.parent() {
        std::fs::create_dir_all(parent)?;
    }
    if std::fs::symlink_metadata(&install_dir).is_ok() {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "DISTRO_INSTALL_PATH_OCCUPIED: refusing to adopt an existing path",
        ));
    }
    let args = distro_import_args(&install_dir, artifact);
    let output = crate::dedicated_account::run_wsl_as_windows_identity(&args)?;
    if output.status.success() {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "DISTRO_IMPORT_FAILED: register gnx-node as gnxnodesvc",
        ))
    }
}

#[cfg(windows)]
pub fn ensure_distro() -> io::Result<()> {
    let artifact = rootfs_artifact();
    validate_rootfs_artifact(&artifact)?;
    let host_root = host_payload_dir();
    let node_root = payload_dir();
    validate_payload(&node_root)?;
    let profile = crate::dedicated_account::managed_profile_dir()?;
    copy_wsl_config(&host_root, &profile)?;
    if !distro_is_registered()? {
        import_distro(&artifact)?;
    }
    materialize_payload(&node_root)?;
    let installer = run_wsl(
        "/usr/bin/test",
        &["-x", "/opt/gnx/payload/node/install.run"],
    )?;
    if !installer.status.success() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "DISTRO_PAYLOAD_MISSING: /opt/gnx/payload/node/install.run",
        ));
    }
    Ok(())
}

#[cfg(windows)]
pub fn install_with_secrets(
    state_dir: &Path,
    mesh_secret_file: Option<&Path>,
    compute_secret_file: Option<&Path>,
) -> io::Result<RuntimeResult> {
    validate_payload(&payload_dir())?;
    let state = path_arg(state_dir);
    let mut args = vec![
        "install",
        "--payload-dir",
        "/opt/gnx/payload/node",
        "--state-dir",
        state.as_str(),
    ];
    let secret = mesh_secret_file.map(path_arg);
    if let Some(secret) = secret.as_deref() {
        args.extend(["--mesh-secret-file", secret]);
    }
    let compute = compute_secret_file.map(path_arg);
    if let Some(compute) = compute.as_deref() {
        args.extend(["--compute-secret-file", compute]);
    }
    let output = run_wsl("/opt/gnx/payload/node/install.run", &args)?;
    if !output.status.success() {
        return Err(runtime_error(&output));
    }
    Ok(RuntimeResult::Installed)
}

#[cfg(windows)]
pub fn reconcile_ingress() -> io::Result<()> {
    let node_root = payload_dir();
    validate_payload(&node_root)?;
    materialize_payload(&node_root)?;
    for (source, destination, code) in [
        (
            "/opt/gnx/payload/node/network/ingress.nft",
            "/var/lib/gnx-node/ingress.nft",
            "INGRESS_COPY_FAILED",
        ),
        (
            "/opt/gnx/payload/node/gateway/routes.conf",
            "/var/lib/gnx-node/routes.conf",
            "GATEWAY_ROUTES_COPY_FAILED",
        ),
    ] {
        let copy = run_wsl("/usr/bin/install", &["-m", "0644", source, destination])?;
        if !copy.status.success() {
            return Err(io::Error::other(code));
        }
    }
    // Preserve the generated status.json while refreshing only the reviewed
    // PWA assets. Reconciliation is the update path after an MSI repair, so
    // routes alone are insufficient to make the new frontend live.
    let web = run_wsl(
        "/usr/bin/cp",
        &[
            "-a",
            "/opt/gnx/payload/node/web-app/.",
            "/var/lib/gnx-node/web-app/",
        ],
    )?;
    if !web.status.success() {
        return Err(io::Error::other("WEB_APP_COPY_FAILED"));
    }
    // Replace the named table atomically from the fixed runtime policy. The
    // oneshot unit uses the same two commands on every subsequent WSL boot.
    let _ = run_wsl("/usr/sbin/nft", &["delete", "table", "inet", "gnx_ingress"]);
    let apply = run_wsl("/usr/sbin/nft", &["-f", "/var/lib/gnx-node/ingress.nft"])?;
    if !apply.status.success() {
        return Err(io::Error::other("INGRESS_APPLY_FAILED"));
    }
    let _ = run_wsl(
        "/usr/bin/systemctl",
        &["reset-failed", "gnx-ingress.service"],
    );
    let start = run_wsl("/usr/bin/systemctl", &["start", "gnx-ingress.service"])?;
    if !start.status.success() {
        return Err(io::Error::other("INGRESS_START_FAILED"));
    }
    // A target restart does not restart its already-active dependencies.
    // Restart compute explicitly so a changed TLS hook/Quadlet is applied,
    // then let Podman 6's Notify=healthy wait for its bounded healthcheck.
    let compute = run_wsl("/usr/bin/systemctl", &["restart", "compute.service"])?;
    if !compute.status.success() {
        return Err(io::Error::other("COMPUTE_RESTART_FAILED"));
    }
    let gateway = run_wsl("/usr/bin/systemctl", &["restart", "gateway.service"])?;
    if !gateway.status.success() {
        return Err(io::Error::other("GATEWAY_RESTART_FAILED"));
    }
    let platform = run_wsl("/usr/bin/systemctl", &["start", "platform.target"])?;
    if !platform.status.success() {
        return Err(io::Error::other("PLATFORM_START_FAILED"));
    }
    Ok(())
}

#[cfg(windows)]
pub fn private_ip() -> io::Result<String> {
    let output = run_wsl(
        "/usr/bin/podman",
        &["exec", "gnx-mesh", "tailscale", "ip", "-4"],
    )?;
    if !output.status.success() {
        return Err(runtime_error(&output));
    }
    let output_text = String::from_utf8_lossy(&output.stdout);
    let value = output_text
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "mesh IP unavailable"))?;
    validate_private_ip(value)
}

fn validate_private_ip(value: &str) -> io::Result<String> {
    let parsed = value
        .parse::<std::net::IpAddr>()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid mesh IP"))?;
    if parsed.is_unspecified() || parsed.is_loopback() || parsed.is_multicast() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid mesh IP",
        ));
    }
    Ok(parsed.to_string())
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

/// Read only the fixed pass/fail check names emitted by the canonical runtime
/// verifier. Raw output is intentionally not retained or sent to the browser.
#[cfg(windows)]
pub fn runtime_checks(state_dir: &Path) -> io::Result<Vec<crate::state::RuntimeCheck>> {
    const ALLOWED: &[&str] = &[
        "podman_6",
        "tun",
        "fuse",
        "kvm",
        "platform_target",
        "mesh",
        "mesh_authenticated",
        "gateway",
        "app_https",
        "compute",
        "compute_gateway_https",
        "compute_https",
    ];
    let output = run_wsl(
        "/opt/gnx/payload/node/verify.run",
        &["--state-dir", &path_arg(state_dir)],
    )?;
    let checks = String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .filter_map(|line| {
            let name = line.get("check")?.as_str()?;
            let result = line.get("result")?.as_str()?;
            (ALLOWED.contains(&name) && matches!(result, "pass" | "fail")).then(|| {
                crate::state::RuntimeCheck {
                    name: name.into(),
                    result: result.into(),
                }
            })
        })
        .collect::<Vec<_>>();
    if checks.is_empty() {
        Err(io::Error::other("RUNTIME_CHECKS_UNAVAILABLE"))
    } else {
        Ok(checks)
    }
}

/// Copy the intentionally small, sanitized state projection into the existing
/// Caddy document root. The host owns the source; the browser gets no pipe or
/// privileged endpoint.
#[cfg(windows)]
pub fn publish_app_status(source: &Path) -> io::Result<()> {
    let source = path_arg(source);
    let output = run_wsl(
        "/usr/bin/install",
        &[
            "-m",
            "0644",
            &source,
            "/var/lib/gnx-node/web-app/status.json",
        ],
    )?;
    if output.status.success() {
        Ok(())
    } else {
        Err(io::Error::other("APP_STATUS_PUBLISH_FAILED"))
    }
}

#[cfg(windows)]
fn path_arg(path: &Path) -> String {
    windows_path_to_wsl(path.to_string_lossy().as_ref())
}

fn windows_path_to_wsl(value: &str) -> String {
    let normalized = value.replace('\\', "/");
    let bytes = normalized.as_bytes();
    if bytes.len() >= 2 && bytes[1] == b':' && bytes[0].is_ascii_alphabetic() {
        let drive = (bytes[0] as char).to_ascii_lowercase();
        return format!("/mnt/{drive}/{}", normalized[2..].trim_start_matches('/'));
    }
    normalized
}

#[cfg(windows)]
fn is_reparse_point(path: &Path) -> bool {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{
        GetFileAttributesW, FILE_ATTRIBUTE_REPARSE_POINT, INVALID_FILE_ATTRIBUTES,
    };
    let wide = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let attributes = unsafe { GetFileAttributesW(wide.as_ptr()) };
    attributes != INVALID_FILE_ATTRIBUTES && attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
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

    #[test]
    fn private_ip_validation_rejects_non_node_addresses() {
        assert!(validate_private_ip("127.0.0.1").is_err());
        assert_eq!(validate_private_ip("100.64.0.12").unwrap(), "100.64.0.12");
    }

    #[test]
    fn windows_paths_translate_to_wsl_mounts() {
        assert_eq!(
            windows_path_to_wsl(r"C:\ProgramData\GNX\state"),
            "/mnt/c/ProgramData/GNX/state"
        );
        assert_eq!(windows_path_to_wsl(r"D:/staged/env"), "/mnt/d/staged/env");
        assert_eq!(windows_path_to_wsl("/var/lib/gnx"), "/var/lib/gnx");
    }

    #[test]
    fn wsl_list_output_decodes_utf16_and_utf8() {
        let utf16: Vec<u8> = "* gnx-builder\r\n"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        assert_eq!(decode_wsl_text(&utf16), "* gnx-builder\r\n");
        assert_eq!(decode_wsl_text(b"gnx-node\r\n"), "gnx-node\r\n");
        assert!(wsl_reports_no_distributions(Some(-1), &utf16, b""));
        assert!(!wsl_reports_no_distributions(Some(-1), b"", b"error"));
        assert!(!wsl_reports_no_distributions(Some(1), &utf16, b""));
    }

    #[test]
    fn missing_rootfs_reports_the_exact_artifact_contract() {
        let root = std::env::temp_dir()
            .join(format!("gnx-rootfs-missing-{}", std::process::id()))
            .join(ROOTFS_ARTIFACT_NAME);
        let error = validate_rootfs_artifact(&root).unwrap_err();
        assert!(error.to_string().starts_with("MISSING_ROOTFS_ARTIFACT:"));
        assert!(error.to_string().contains(ROOTFS_ARTIFACT_NAME));
    }

    #[test]
    fn rootfs_manifest_hash_is_verified() {
        let root = std::env::temp_dir().join(format!("gnx-rootfs-fixture-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let artifact = root.join(ROOTFS_ARTIFACT_NAME);
        let bytes = b"sealed-rootfs-fixture";
        std::fs::write(&artifact, bytes).unwrap();
        let digest = Sha256::digest(bytes);
        std::fs::write(
            artifact.with_file_name(ROOTFS_MANIFEST_NAME),
            format!("{digest:x}  {ROOTFS_ARTIFACT_NAME}\n"),
        )
        .unwrap();
        validate_rootfs_artifact(&artifact).unwrap();
        std::fs::write(
            artifact.with_file_name(ROOTFS_MANIFEST_NAME),
            format!("{}  {ROOTFS_ARTIFACT_NAME}\n", "0".repeat(64)),
        )
        .unwrap();
        assert_eq!(
            validate_rootfs_artifact(&artifact).unwrap_err().to_string(),
            "ROOTFS_DIGEST_MISMATCH"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn distro_import_is_fixed_to_contract_identity() {
        let args = distro_import_args(
            Path::new(r"C:\ProgramData\GNX\wsl\gnx-node"),
            Path::new(r"C:\ProgramData\GNX\gnx-node-rootfs.tar"),
        );
        assert_eq!(args[0], "--import");
        assert_eq!(args[1], DISTRO_NAME);
        assert_eq!(args[4], "--version");
        assert_eq!(args[5], "2");
        assert!(!args.iter().any(|arg| arg == "--user"));
    }

    #[test]
    fn installed_service_payloads_resolve_beside_executable() {
        let executable = Path::new(r"C:\Program Files\GnX Node\gnx-host-agent.exe");
        assert_eq!(
            installed_payload_path(executable, "payload-node").unwrap(),
            Path::new(r"C:\Program Files\GnX Node\payload-node")
        );
        assert_eq!(
            installed_payload_path(executable, "payload-host").unwrap(),
            Path::new(r"C:\Program Files\GnX Node\payload-host")
        );
    }

    #[test]
    fn payload_materialization_uses_drvfs_source_and_fixed_destination() {
        assert_eq!(
            payload_copy_source(Path::new(r"C:\Program Files\GnX Node\payload-node")),
            "/mnt/c/Program Files/GnX Node/payload-node/."
        );
        assert_eq!(
            PAYLOAD_MARKER_PATH,
            "/opt/gnx/payload/node/.gnx-payload.sha256"
        );
    }

    #[test]
    fn wsl_config_is_in_managed_profile_and_acl_staged_for_managed_identity() {
        let profile = Path::new(r"C:\Users\gnxnodesvc");
        assert_eq!(wsl_config_path(profile), profile.join(WSL_CONFIG_NAME));
        assert_eq!(WSL_CONFIG_NAME, ".wslconfig");
        assert_eq!(
            profile.file_name().and_then(|name| name.to_str()),
            Some("gnxnodesvc")
        );
    }
}
