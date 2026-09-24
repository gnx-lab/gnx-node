//! Product-owned private CA lifecycle.
//!
//! The private key is durable only for the lifetime of the installed node and
//! is ACL/mode restricted. The public certificate is the only CA material ever
//! exposed through Progress, as a bounded operator action for client trust.

use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair, KeyUsagePurpose};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

const CA_DIR: &str = "ca";
const KEY_NAME: &str = "private-ca.key.pem";
const CERT_NAME: &str = "private-ca.cert.pem";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaInfo {
    pub certificate_path: PathBuf,
}

pub fn ensure(state_dir: &Path) -> io::Result<CaInfo> {
    let dir = state_dir.join(CA_DIR);
    fs::create_dir_all(&dir)?;
    #[cfg(windows)]
    {
        crate::dedicated_account::restrict_read_directory(state_dir)?;
        crate::dedicated_account::restrict_read_directory(&dir)?;
    }
    let key_path = dir.join(KEY_NAME);
    let cert_path = dir.join(CERT_NAME);
    if key_path.is_file() && cert_path.is_file() {
        set_permissions(&key_path, 0o600)?;
        set_permissions(&cert_path, 0o644)?;
        return Ok(CaInfo {
            certificate_path: cert_path,
        });
    }
    // Never overwrite a half-created or externally supplied key. An operator
    // must repair that state explicitly instead of silently rotating trust.
    if key_path.exists() || cert_path.exists() {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "private CA is incomplete",
        ));
    }
    let mut params = CertificateParams::new(vec!["app.gnx".into(), "compute.gnx".into()])
        .map_err(|error| io::Error::other(error.to_string()))?;
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "GnX Node Private CA");
    let key = KeyPair::generate().map_err(|error| io::Error::other(error.to_string()))?;
    let certificate = params
        .self_signed(&key)
        .map_err(|error| io::Error::other(error.to_string()))?;
    let key_pem = key.serialize_pem();
    let cert_pem = certificate.pem();
    write_new_private(&key_path, key_pem.as_bytes(), 0o600)?;
    if let Err(error) = write_new_private(&cert_path, cert_pem.as_bytes(), 0o644) {
        let _ = fs::remove_file(&key_path);
        return Err(error);
    }
    Ok(CaInfo {
        certificate_path: cert_path,
    })
}

fn write_new_private(path: &Path, bytes: &[u8], mode: u32) -> io::Result<()> {
    use std::io::Write;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    set_permissions(path, mode)?;
    file.write_all(bytes)?;
    file.sync_all()
}

#[cfg(unix)]
fn set_permissions(path: &Path, mode: u32) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
}

#[cfg(windows)]
fn set_permissions(path: &Path, _mode: u32) -> io::Result<()> {
    // Both CA files are required by install.run through drvfs. The private key
    // remains read-only to gnxnodesvc; SYSTEM and Administrators retain full
    // control through the protected DACL applied by restrict_read_file.
    crate::dedicated_account::restrict_read_file(path)
}

#[cfg(all(not(unix), not(windows)))]
fn set_permissions(_path: &Path, _mode: u32) -> io::Result<()> {
    Ok(())
}

#[cfg(all(test, not(windows)))]
mod tests {
    use super::*;
    use uuid::Uuid;

    #[test]
    fn generates_idempotent_ca() {
        let root = std::env::temp_dir().join(format!("gnx-ca-{}", Uuid::new_v4()));
        let first = ensure(&root).unwrap();
        assert!(first.certificate_path.is_file());
        assert!(
            String::from_utf8(fs::read(&first.certificate_path).unwrap())
                .unwrap()
                .contains("BEGIN CERTIFICATE")
        );
        let second = ensure(&root).unwrap();
        assert_eq!(first, second);
        let _ = fs::remove_dir_all(root);
    }
}
