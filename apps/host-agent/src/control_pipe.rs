use crate::{provisioning, state};
use gnx_control_protocol::{Request, Response, PROTOCOL_VERSION};
use std::io;
#[cfg(not(windows))]
use std::io::{BufRead, Write};
use std::sync::atomic::{AtomicBool, Ordering};

pub const PIPE_NAME: &str = r"\\.\pipe\GnX.Platform.Control";
const PIPE_MAX_INSTANCES: u32 = 1;
// Not exposed by every windows-sys release; this is the documented
// PIPE_REJECT_REMOTE_CLIENTS dwPipeMode bit.
const PIPE_REJECT_REMOTE_CLIENTS: u32 = 0x0000_0008;
const PIPE_SECURITY_DESCRIPTOR: &str = "D:P(A;;GA;;;SY)(A;;GA;;;BA)";
static STOP: AtomicBool = AtomicBool::new(false);

#[cfg(windows)]
pub fn request_stop() {
    STOP.store(true, Ordering::Release);
    // Wake a blocking ConnectNamedPipe so SCM stop cannot hang awaiting a client.
    let _ = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(PIPE_NAME);
}
#[cfg(not(windows))]
pub fn request_stop() {}

pub fn run() -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(windows)]
    {
        run_windows()
    }
    #[cfg(not(windows))]
    {
        let stdin = io::stdin();
        let mut out = io::BufWriter::new(io::stdout());
        let mut p = state::load()?;
        for line in stdin.lock().lines() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            if line.len() <= gnx_control_protocol::MAX_FRAME_BYTES {
                if let Ok(req) = Request::from_frame(line.as_bytes()) {
                    p = provisioning::execute(&req, &p);
                    if req.operation != gnx_control_protocol::Operation::GetProgress {
                        state::save(&p)?;
                    }
                    let r = Response {
                        version: PROTOCOL_VERSION,
                        request_id: req.request_id,
                        operation_id: p.operation_id,
                        progress: p.clone(),
                    };
                    serde_json::to_writer(&mut out, &r)?;
                    out.write_all(b"\n")?;
                    out.flush()?;
                }
            }
        }
        Ok(())
    }
}

#[derive(Debug, PartialEq, Eq)]
enum FrameState {
    Incomplete,
    TooLarge,
    Complete(Vec<u8>),
}

fn frame_state(bytes: &[u8]) -> FrameState {
    if let Some(position) = bytes.iter().position(|byte| *byte == b'\n') {
        if position >= gnx_control_protocol::MAX_FRAME_BYTES {
            FrameState::TooLarge
        } else {
            FrameState::Complete(bytes[..position].to_vec())
        }
    } else if bytes.len() >= gnx_control_protocol::MAX_FRAME_BYTES {
        FrameState::TooLarge
    } else {
        FrameState::Incomplete
    }
}

#[cfg(windows)]
fn run_windows() -> Result<(), Box<dyn std::error::Error>> {
    use std::mem::zeroed;
    use std::ptr::null_mut;
    use windows_sys::Win32::Foundation::{
        CloseHandle, GetLastError, LocalFree, ERROR_PIPE_CONNECTED, INVALID_HANDLE_VALUE,
    };
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
    };
    use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
    use windows_sys::Win32::Storage::FileSystem::PIPE_ACCESS_DUPLEX;
    use windows_sys::Win32::System::Pipes::{
        ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, PIPE_READMODE_BYTE,
        PIPE_TYPE_BYTE, PIPE_WAIT,
    };
    STOP.store(false, Ordering::Release);
    let name: Vec<u16> = PIPE_NAME.encode_utf16().chain(std::iter::once(0)).collect();
    let sddl: Vec<u16> = PIPE_SECURITY_DESCRIPTOR
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let mut descriptor = null_mut();
    let mut attrs: SECURITY_ATTRIBUTES = unsafe { zeroed() };
    attrs.nLength = std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32;
    attrs.bInheritHandle = 0;
    attrs.lpSecurityDescriptor = unsafe {
        if ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut descriptor,
            null_mut(),
        ) == 0
        {
            null_mut()
        } else {
            descriptor
        }
    };
    if attrs.lpSecurityDescriptor.is_null() {
        return Err(io::Error::last_os_error().into());
    }
    let mut current = state::load()?;
    // Setup may be closed or Windows may reboot after staging credentials.
    // Remove only known one-shot bundle files before accepting a client.
    let _ =
        crate::secret_store::cleanup_stale(&crate::secret_store::staging_dir(&state::state_dir()));
    crate::secret_store::cleanup_setup_temps();
    while !STOP.load(Ordering::Acquire) {
        let pipe = unsafe {
            CreateNamedPipeW(
                name.as_ptr(),
                PIPE_ACCESS_DUPLEX,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                PIPE_MAX_INSTANCES,
                gnx_control_protocol::MAX_FRAME_BYTES as u32,
                gnx_control_protocol::MAX_FRAME_BYTES as u32,
                0,
                &attrs,
            )
        };
        if pipe == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error().into());
        }
        if unsafe {
            ConnectNamedPipe(pipe, null_mut()) != 0 || GetLastError() == ERROR_PIPE_CONNECTED
        } {
            // ImpersonateNamedPipeClient needs client data/read context. Read
            // exactly one bounded frame before authorization; parsing and all
            // state-changing work remain behind the authorization decision.
            if let Some(frame) = read_client_frame(pipe) {
                if authorize_client(pipe) {
                    serve_client_frame(pipe, &frame, &mut current)?;
                }
            }
        }
        unsafe {
            DisconnectNamedPipe(pipe);
            CloseHandle(pipe);
        }
    }
    unsafe {
        // ConvertStringSecurityDescriptorToSecurityDescriptorW allocates this
        // descriptor with LocalAlloc; release it after all pipe instances die.
        LocalFree(descriptor as _);
    }
    Ok(())
}

#[cfg(windows)]
fn authorize_client(pipe: windows_sys::Win32::Foundation::HANDLE) -> bool {
    use windows_sys::Win32::Security::{
        AllocateAndInitializeSid, CheckTokenMembership, FreeSid, RevertToSelf,
        SECURITY_NT_AUTHORITY,
    };
    use windows_sys::Win32::System::Pipes::ImpersonateNamedPipeClient;
    use windows_sys::Win32::System::SystemServices::{
        DOMAIN_ALIAS_RID_ADMINS, SECURITY_BUILTIN_DOMAIN_RID,
    };
    let impersonated = unsafe { ImpersonateNamedPipeClient(pipe) } != 0;
    if !impersonated {
        return false;
    }
    let mut admin_sid = std::ptr::null_mut();
    let authorized = (|| {
        // NULL explicitly asks Windows to evaluate the effective impersonated
        // client token. Passing a server/opened token here can accidentally
        // check the service identity instead of the caller. The protected
        // pipe DACL grants only SYSTEM/Administrators, and this enabled SID
        // check rejects a UAC-filtered token whose Administrators SID is
        // deny-only; no separate process-token elevation check is needed.
        let sid_allocated = unsafe {
            AllocateAndInitializeSid(
                &SECURITY_NT_AUTHORITY,
                2,
                SECURITY_BUILTIN_DOMAIN_RID as u32,
                DOMAIN_ALIAS_RID_ADMINS as u32,
                0,
                0,
                0,
                0,
                0,
                0,
                &mut admin_sid,
            )
        } != 0;
        if !sid_allocated {
            return false;
        }
        let mut is_member = 0;
        let membership_check =
            unsafe { CheckTokenMembership(std::ptr::null_mut(), admin_sid, &mut is_member) } != 0;
        membership_check && is_member != 0
    })();

    // Cleanup is mandatory but never part of the authorization result. A
    // failed cleanup must not turn an authorized request into a privileged
    // operation, nor can a successful cleanup authorize a bad caller.
    unsafe {
        if !admin_sid.is_null() {
            FreeSid(admin_sid);
        }
        RevertToSelf();
    }
    authorized
}

#[cfg(windows)]
fn read_client_frame(pipe: windows_sys::Win32::Foundation::HANDLE) -> Option<Vec<u8>> {
    use windows_sys::Win32::Storage::FileSystem::ReadFile;
    let mut bytes = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        let mut read = 0u32;
        if unsafe {
            ReadFile(
                pipe,
                buf.as_mut_ptr().cast(),
                buf.len() as u32,
                &mut read,
                std::ptr::null_mut(),
            )
        } == 0
            || read == 0
        {
            return None;
        }
        bytes.extend_from_slice(&buf[..read as usize]);
        match frame_state(&bytes) {
            FrameState::Incomplete => {}
            FrameState::TooLarge => return None,
            FrameState::Complete(frame) => return Some(frame),
        }
    }
}

#[cfg(windows)]
fn serve_client_frame(
    pipe: windows_sys::Win32::Foundation::HANDLE,
    frame: &[u8],
    current: &mut gnx_control_protocol::Progress,
) -> io::Result<()> {
    use windows_sys::Win32::Storage::FileSystem::{FlushFileBuffers, WriteFile};
    if let Ok(req) = Request::from_frame(frame) {
        *current = provisioning::execute(&req, current);
        if req.operation != gnx_control_protocol::Operation::GetProgress {
            state::save(current)?;
        }
        let mut output = serde_json::to_vec(&Response {
            version: PROTOCOL_VERSION,
            request_id: req.request_id,
            operation_id: current.operation_id,
            progress: current.clone(),
        })
        .map_err(io::Error::other)?;
        output.push(b'\n');
        let mut written = 0u32;
        if unsafe {
            WriteFile(
                pipe,
                output.as_ptr().cast(),
                output.len() as u32,
                &mut written,
                std::ptr::null_mut(),
            )
        } == 0
            || written != output.len() as u32
        {
            return Err(io::Error::last_os_error());
        }
        // A fast read-only request can otherwise be lost when
        // DisconnectNamedPipe runs before the client has drained the pipe.
        // FlushFileBuffers is the documented server-side handoff barrier.
        if unsafe { FlushFileBuffers(pipe) } == 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pipe_policy_requires_local_admin_and_rejects_remote_clients() {
        assert_eq!(PIPE_SECURITY_DESCRIPTOR, "D:P(A;;GA;;;SY)(A;;GA;;;BA)");
        assert_eq!(PIPE_REJECT_REMOTE_CLIENTS, 0x0000_0008);
        assert!(!PIPE_SECURITY_DESCRIPTOR.contains("WD"));
        assert!(!PIPE_SECURITY_DESCRIPTOR.contains("AN"));
    }

    #[test]
    fn frame_must_be_complete_before_authorization() {
        assert_eq!(
            frame_state(b"{\"operation\":\"GetProgress\"}"),
            FrameState::Incomplete
        );
        assert_eq!(
            frame_state(b"{\"operation\":\"GetProgress\"}\n"),
            FrameState::Complete(b"{\"operation\":\"GetProgress\"}".to_vec())
        );
        let oversized = vec![b'x'; gnx_control_protocol::MAX_FRAME_BYTES];
        assert_eq!(frame_state(&oversized), FrameState::TooLarge);
    }
}
