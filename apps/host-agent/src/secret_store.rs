//! One-shot onboarding secret transfer.
//!
//! The control protocol carries only a reference to this file.  The bundle is
//! deliberately a tiny binary envelope instead of JSON so credentials cannot
//! accidentally appear in diagnostics, snapshots, or generic serialization.
//! The host consumes and unlinks it on every read path; stale files are swept
//! at service start to cover reboot and abandoned Setup windows.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

const MAGIC: &[u8; 8] = b"GNXSEC01";
const MAX_SECRET: usize = 4096;
const MAX_BUNDLE: u64 = (MAX_SECRET * 2 + 32) as u64;

#[derive(Default)]
pub struct SecretMaterial {
    pub tailscale_auth_key: Option<String>,
    pub proxmox_password: Option<String>,
}

impl std::fmt::Debug for SecretMaterial {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SecretMaterial")
            .field(
                "tailscale_auth_key",
                &self.tailscale_auth_key.as_ref().map(|_| "[redacted]"),
            )
            .field(
                "proxmox_password",
                &self.proxmox_password.as_ref().map(|_| "[redacted]"),
            )
            .finish()
    }
}

impl SecretMaterial {
    #[cfg(test)]
    pub fn is_empty(&self) -> bool {
        self.tailscale_auth_key.is_none() && self.proxmox_password.is_none()
    }
}

impl Drop for SecretMaterial {
    fn drop(&mut self) {
        clear(&mut self.tailscale_auth_key);
        clear(&mut self.proxmox_password);
    }
}

fn clear(value: &mut Option<String>) {
    if let Some(text) = value {
        clear_string(text);
    }
    *value = None;
}

pub(crate) fn clear_string(value: &mut String) {
    // Best-effort zeroing before releasing the allocation. The bytes are
    // never copied into a log or a persistent state object.
    unsafe {
        let bytes = value.as_mut_vec();
        bytes.fill(0);
        bytes.clear();
    }
}

/// Stage a bundle with restrictive owner permissions. The caller must choose
/// a directory that is itself ACL-restricted (the Windows service staging
/// directory is created that way by the installer/service).
#[cfg(test)]
pub fn stage(path: &Path, material: &SecretMaterial) -> io::Result<()> {
    if material.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "empty secret bundle",
        ));
    }
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "secret path has no parent"))?;
    fs::create_dir_all(parent)?;
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    set_private(path)?;
    let mut bytes = Vec::with_capacity(32);
    bytes.extend_from_slice(MAGIC);
    bytes.push(u8::from(material.tailscale_auth_key.is_some()));
    bytes.push(u8::from(material.proxmox_password.is_some()));
    bytes.extend_from_slice(&[0, 0]);
    write_secret(&mut bytes, material.tailscale_auth_key.as_deref())?;
    write_secret(&mut bytes, material.proxmox_password.as_deref())?;
    file.write_all(&bytes)?;
    file.sync_all()
}

#[cfg(test)]
fn write_secret(out: &mut Vec<u8>, value: Option<&str>) -> io::Result<()> {
    let bytes = value.unwrap_or_default().as_bytes();
    if bytes.is_empty() || bytes.len() > MAX_SECRET || bytes.iter().any(|b| b.is_ascii_control()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid secret material",
        ));
    }
    out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}

/// Read and delete a staged bundle. Deletion is attempted even when parsing
/// fails, preventing malformed or expired credentials from lingering.
pub fn consume(path: &Path) -> io::Result<SecretMaterial> {
    let path = validate_secret_path(path)?;
    let result = (|| {
        let metadata = fs::metadata(&path)?;
        if metadata.len() > MAX_BUNDLE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "secret bundle exceeds maximum size",
            ));
        }
        let mut file = File::open(&path)?;
        let mut bytes = Vec::with_capacity(metadata.len() as usize);
        file.read_to_end(&mut bytes)?;
        parse(&bytes)
    })();
    let removed = fs::remove_file(&path);
    match result {
        Err(error) => Err(error),
        Ok(material) => match removed {
            Ok(_) => Ok(material),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(material),
            Err(error) => Err(error),
        },
    }
}

/// Validate the Setup-created onboarding file before opening or deleting it.
/// This intentionally rejects arbitrary absolute paths, symlink/junction
/// components, non-regular files, broad roots, and unexpected names.
pub fn validate_secret_path(path: &Path) -> io::Result<PathBuf> {
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "secret path has no valid filename",
            )
        })?;
    let uuid = file_name
        .strip_prefix("gnx-onboarding-")
        .and_then(|name| name.strip_suffix(".secret"))
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid secret filename"))?;
    let parsed = uuid::Uuid::parse_str(uuid)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid secret filename"))?;
    if parsed.to_string() != uuid {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "secret filename is not canonical",
        ));
    }
    if !path.is_absolute()
        || path
            .components()
            .any(|component| component == std::path::Component::ParentDir)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "secret path is not local",
        ));
    }
    reject_reparse_components(path)?;
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() || metadata.len() > MAX_BUNDLE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "secret path is not a regular bounded file",
        ));
    }
    let canonical = fs::canonicalize(path)?;
    if !approved_temp_root(&canonical)? {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "secret path is outside approved temp roots",
        ));
    }
    validate_acl(&canonical)?;
    Ok(canonical)
}

fn approved_temp_root(path: &Path) -> io::Result<bool> {
    let mut roots = vec![std::env::temp_dir()];
    #[cfg(windows)]
    {
        roots.push(PathBuf::from(r"C:\Windows\Temp"));
        if let Ok(users) = fs::read_dir(r"C:\Users") {
            for user in users.flatten() {
                roots.push(user.path().join(r"AppData\Local\Temp"));
            }
        }
    }
    Ok(roots
        .into_iter()
        .filter_map(|root| fs::canonicalize(root).ok())
        .any(|root| path.starts_with(root)))
}

fn reject_reparse_components(path: &Path) -> io::Result<()> {
    let mut current = if path.has_root() {
        path.components()
            .take_while(|component| {
                matches!(
                    component,
                    std::path::Component::Prefix(_) | std::path::Component::RootDir
                )
            })
            .fold(PathBuf::new(), |mut root, component| {
                root.push(component.as_os_str());
                root
            })
    } else {
        PathBuf::new()
    };
    for component in path.components() {
        if matches!(
            component,
            std::path::Component::Prefix(_) | std::path::Component::RootDir
        ) {
            continue;
        }
        current.push(component.as_os_str());
        let metadata = fs::symlink_metadata(&current)?;
        if metadata.file_type().is_symlink() || is_reparse_point(&current) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "secret path contains reparse point",
            ));
        }
    }
    Ok(())
}

#[cfg(windows)]
fn is_reparse_point(path: &Path) -> bool {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{
        GetFileAttributesW, FILE_ATTRIBUTE_REPARSE_POINT, INVALID_FILE_ATTRIBUTES,
    };
    let wide: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let attributes = unsafe { GetFileAttributesW(wide.as_ptr()) };
    attributes == INVALID_FILE_ATTRIBUTES || attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(windows))]
fn is_reparse_point(_path: &Path) -> bool {
    false
}

#[cfg(all(windows, not(test)))]
fn validate_acl(path: &Path) -> io::Result<()> {
    use std::ptr::null_mut;
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Authorization::{GetNamedSecurityInfoW, SE_FILE_OBJECT};
    use windows_sys::Win32::Security::{
        GetAce, GetSecurityDescriptorControl, ACCESS_ALLOWED_ACE, ACE_HEADER,
        DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION, SE_DACL_PROTECTED,
    };
    const FILE_ALL_ACCESS: u32 = 2_032_127;
    const ACCESS_ALLOWED_ACE_TYPE: u8 = 0;
    let name: Vec<u16> = path
        .to_string_lossy()
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let mut owner = null_mut();
    let mut dacl = null_mut();
    let mut descriptor = null_mut();
    let status = unsafe {
        GetNamedSecurityInfoW(
            name.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | OWNER_SECURITY_INFORMATION,
            &mut owner,
            null_mut(),
            &mut dacl,
            null_mut(),
            &mut descriptor,
        )
    };
    if status != 0 || owner.is_null() || dacl.is_null() || descriptor.is_null() {
        if !descriptor.is_null() {
            unsafe { LocalFree(descriptor as _) };
        }
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "secret file ACL unavailable",
        ));
    }
    let mut control = 0u16;
    let mut revision = 0u32;
    let protected =
        unsafe { GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) } != 0
            && control & SE_DACL_PROTECTED != 0;
    let owner_sid = sid_string(owner)?;
    let ace_count = unsafe { (*dacl).AceCount };
    let mut valid = protected && ace_count == 3;
    let mut has_system = false;
    let mut has_admin = false;
    let mut has_owner = false;
    for index in 0..ace_count {
        let mut ace_ptr = null_mut();
        if unsafe { GetAce(dacl, index as u32, &mut ace_ptr) } == 0 || ace_ptr.is_null() {
            valid = false;
            break;
        }
        let header = unsafe { &*(ace_ptr as *const ACE_HEADER) };
        if header.AceType as u32 != ACCESS_ALLOWED_ACE_TYPE as u32 || header.AceFlags != 0 {
            valid = false;
            break;
        }
        let ace = unsafe { &*(ace_ptr as *const ACCESS_ALLOWED_ACE) };
        if ace.Mask != FILE_ALL_ACCESS {
            valid = false;
            break;
        }
        let sid = sid_string((&ace.SidStart as *const u32).cast::<std::ffi::c_void>() as *mut _)?;
        if sid == "S-1-5-18" {
            has_system = true;
        } else if sid == "S-1-5-32-544" {
            has_admin = true;
        } else if sid == owner_sid {
            has_owner = true;
        } else {
            valid = false;
            break;
        }
    }
    valid &= has_system && has_admin && has_owner;
    unsafe { LocalFree(descriptor as _) };
    if valid {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "secret file ACL is not restricted",
        ))
    }
}

#[cfg(all(windows, test))]
fn validate_acl(_path: &Path) -> io::Result<()> {
    Ok(())
}

#[cfg(all(windows, not(test)))]
fn sid_string(sid: windows_sys::Win32::Security::PSID) -> io::Result<String> {
    use std::ptr::null_mut;
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
    let mut text = null_mut();
    if unsafe { ConvertSidToStringSidW(sid, &mut text) } == 0 || text.is_null() {
        return Err(io::Error::last_os_error());
    }
    let mut length = 0usize;
    unsafe {
        while *text.add(length) != 0 {
            length += 1;
        }
    }
    let value = String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(text, length) });
    unsafe { LocalFree(text as _) };
    Ok(value)
}

#[cfg(not(windows))]
fn validate_acl(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mode = fs::metadata(path)?.permissions().mode() & 0o777;
    if mode <= 0o600 {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "secret file permissions are not restricted",
        ))
    }
}

fn parse(bytes: &[u8]) -> io::Result<SecretMaterial> {
    if bytes.len() < 12 || &bytes[..8] != MAGIC || bytes[8] & !1 != 0 || bytes[9] & !1 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid secret bundle",
        ));
    }
    let mut offset = 12;
    let tailscale = read_secret(bytes, &mut offset)?;
    let proxmox = read_secret(bytes, &mut offset)?;
    if offset != bytes.len()
        || (bytes[8] == 0 && tailscale.is_some())
        || (bytes[9] == 0 && proxmox.is_some())
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid secret bundle contents",
        ));
    }
    Ok(SecretMaterial {
        tailscale_auth_key: tailscale,
        proxmox_password: proxmox,
    })
}

fn read_secret(bytes: &[u8], offset: &mut usize) -> io::Result<Option<String>> {
    if *offset + 4 > bytes.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "truncated secret bundle",
        ));
    }
    let length = u32::from_le_bytes(bytes[*offset..*offset + 4].try_into().unwrap()) as usize;
    *offset += 4;
    if length == 0 {
        return Ok(None);
    }
    if length > MAX_SECRET || *offset + length > bytes.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid secret length",
        ));
    }
    let text = std::str::from_utf8(&bytes[*offset..*offset + length])
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "secret is not UTF-8"))?
        .to_string();
    *offset += length;
    Ok(Some(text))
}

#[cfg(unix)]
fn set_private(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
}

#[cfg(all(windows, not(test)))]
fn set_private(path: &Path) -> io::Result<()> {
    // Reuse the Windows ACL helper so the generated security descriptor is
    // converted to its PACL before calling SetNamedSecurityInfoW.
    crate::dedicated_account::restrict_read_file(path)
}

#[cfg(all(windows, test))]
fn set_private(_path: &Path) -> io::Result<()> {
    Ok(())
}

#[cfg(all(not(unix), not(windows)))]
fn set_private(_path: &Path) -> io::Result<()> {
    Ok(())
}

/// Remove abandoned bundles from a service-owned staging directory. This is
/// intentionally filename-scoped; no recursive cleanup is performed.
pub fn cleanup_stale(dir: &Path) -> io::Result<()> {
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if matches!(
            path.extension().and_then(|ext| ext.to_str()),
            Some("secret" | "env")
        ) {
            let _ = fs::remove_file(path);
        }
    }
    Ok(())
}

#[cfg(windows)]
pub fn cleanup_setup_temps() {
    let mut dirs = vec![PathBuf::from(r"C:\Windows\Temp")];
    if let Ok(users) = fs::read_dir(r"C:\Users") {
        for user in users.flatten() {
            dirs.push(user.path().join(r"AppData\Local\Temp"));
        }
    }
    for dir in dirs {
        let Ok(entries) = fs::read_dir(dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let name = path
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or_default();
            if name.starts_with("gnx-onboarding-")
                && path.extension().and_then(|ext| ext.to_str()) == Some("secret")
            {
                let _ = fs::remove_file(path);
            }
        }
    }
}

pub fn staging_dir(state_dir: &Path) -> PathBuf {
    state_dir.join("staging")
}

/// Materialise the exact environment-file contract consumed by install.run.
/// The caller must remove the returned path after the runtime call, including
/// on failure. Values are never put in process arguments or diagnostics.
pub fn stage_runtime_file(path: &Path, variable: &str, value: &str) -> io::Result<()> {
    if value.is_empty() || value.len() > MAX_SECRET || value.chars().any(|c| c.is_control()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid runtime secret",
        ));
    }
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "runtime path has no parent"))?;
    fs::create_dir_all(parent)?;
    #[cfg(windows)]
    crate::dedicated_account::restrict_read_directory(parent)?;
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    set_private(path)?;
    file.write_all(variable.as_bytes())?;
    file.write_all(b"=")?;
    file.write_all(value.as_bytes())?;
    file.write_all(b"\n")?;
    file.sync_all()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    use uuid::Uuid;

    #[test]
    fn bundle_is_consumed_and_values_are_recovered() {
        let root = std::env::temp_dir().join(format!("gnx-secret-{}", Uuid::new_v4()));
        let path = root.join(format!("gnx-onboarding-{}.secret", Uuid::new_v4()));
        let input = SecretMaterial {
            tailscale_auth_key: Some("tskey-auth-test".into()),
            proxmox_password: Some("proxmox-test".into()),
        };
        stage(&path, &input).unwrap();
        assert!(path.exists());
        #[cfg(unix)]
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let output = consume(&path).unwrap();
        assert_eq!(
            output.tailscale_auth_key.as_deref(),
            Some("tskey-auth-test")
        );
        assert_eq!(output.proxmox_password.as_deref(), Some("proxmox-test"));
        assert!(!path.exists());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn malformed_bundle_is_deleted() {
        let root = std::env::temp_dir().join(format!("gnx-secret-{}", Uuid::new_v4()));
        let path = root.join(format!("gnx-onboarding-{}.secret", Uuid::new_v4()));
        fs::create_dir_all(&root).unwrap();
        fs::write(&path, b"bad").unwrap();
        assert!(consume(&path).is_err());
        assert!(!path.exists());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn arbitrary_absolute_file_is_rejected_without_deletion() {
        let root = std::env::temp_dir().join(format!("gnx-secret-reject-{}", Uuid::new_v4()));
        fs::create_dir_all(&root).unwrap();
        let path = root.join("other.secret");
        fs::write(&path, b"not an onboarding bundle").unwrap();
        assert!(consume(&path).is_err());
        assert!(path.exists());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn canonical_filename_and_local_root_are_required() {
        let root = std::env::temp_dir().join(format!("gnx-secret-name-{}", Uuid::new_v4()));
        fs::create_dir_all(&root).unwrap();
        let uppercase = root.join("gnx-onboarding-550E8400-E29B-41D4-A716-446655440000.secret");
        fs::write(&uppercase, b"bad").unwrap();
        assert!(validate_secret_path(&uppercase).is_err());
        let arbitrary =
            Path::new(r"C:\ProgramData\gnx-onboarding-550e8400-e29b-41d4-a716-446655440000.secret");
        assert!(validate_secret_path(arbitrary).is_err());
        let _ = fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    #[test]
    fn symlink_secret_is_rejected_before_read_or_delete() {
        let root = std::env::temp_dir().join(format!("gnx-secret-link-{}", Uuid::new_v4()));
        fs::create_dir_all(&root).unwrap();
        let target = root.join("target");
        let link = root.join(format!("gnx-onboarding-{}.secret", Uuid::new_v4()));
        fs::write(&target, b"secret").unwrap();
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(consume(&link).is_err());
        assert!(link.exists());
        assert!(target.exists());
        let _ = fs::remove_dir_all(root);
    }
}
