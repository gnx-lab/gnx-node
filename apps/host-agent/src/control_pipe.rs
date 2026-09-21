use crate::{provisioning, state};
use gnx_control_protocol::{Request, Response, PROTOCOL_VERSION};
use std::io::{self, BufRead, Write};
use std::sync::atomic::{AtomicBool, Ordering};

pub const PIPE_NAME: &str = r"\\.\pipe\GnX.Platform.Control";
static STOP: AtomicBool = AtomicBool::new(false);

#[cfg(windows)]
pub fn request_stop() {
    STOP.store(true, Ordering::Release);
    // Wake a blocking ConnectNamedPipe so SCM stop cannot hang awaiting a client.
    let _ = std::fs::OpenOptions::new().read(true).write(true).open(PIPE_NAME);
}
#[cfg(not(windows))]
pub fn request_stop() {}

pub fn run() -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(windows)]
    {
        return run_windows();
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
                    p = provisioning::handle(&req, &p);
                    state::save(&p)?;
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
    }
    Ok(())
}

#[cfg(windows)]
fn run_windows() -> Result<(), Box<dyn std::error::Error>> {
    use std::mem::zeroed;
    use std::ptr::{null, null_mut};
    use windows_sys::Win32::Foundation::{
        CloseHandle, GetLastError, ERROR_PIPE_CONNECTED, INVALID_HANDLE_VALUE,
    };
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
    };
    use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
    use windows_sys::Win32::Storage::FileSystem::PIPE_ACCESS_DUPLEX;
    use windows_sys::Win32::System::Pipes::{
        ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, PIPE_READMODE_BYTE,
        PIPE_TYPE_BYTE, PIPE_UNLIMITED_INSTANCES, PIPE_WAIT,
    };
    STOP.store(false, Ordering::Release);
    let name: Vec<u16> = PIPE_NAME.encode_utf16().chain(std::iter::once(0)).collect();
    let sddl: Vec<u16> = "D:P(A;;GA;;;SY)(A;;GA;;;BA)"
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let mut descriptor = null_mut();
    let mut attrs: SECURITY_ATTRIBUTES = unsafe { zeroed() };
    attrs.nLength = std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32;
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
    while !STOP.load(Ordering::Acquire) {
        let pipe = unsafe {
            CreateNamedPipeW(
                name.as_ptr(),
                PIPE_ACCESS_DUPLEX,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
                PIPE_UNLIMITED_INSTANCES,
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
            serve_client(pipe, &mut current)?;
        }
        unsafe {
            DisconnectNamedPipe(pipe);
            CloseHandle(pipe);
        }
    }
    Ok(())
}

#[cfg(windows)]
fn serve_client(
    pipe: windows_sys::Win32::Foundation::HANDLE,
    current: &mut gnx_control_protocol::Progress,
) -> io::Result<()> {
    use windows_sys::Win32::Storage::FileSystem::{ReadFile, WriteFile};
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
            break;
        }
        bytes.extend_from_slice(&buf[..read as usize]);
        if bytes.len() > gnx_control_protocol::MAX_FRAME_BYTES {
            break;
        }
        while let Some(pos) = bytes.iter().position(|b| *b == b'\n') {
            let frame: Vec<u8> = bytes.drain(..=pos).collect();
            if let Ok(req) = Request::from_frame(&frame[..frame.len() - 1]) {
                *current = provisioning::handle(&req, current);
                state::save(current)?;
                let mut output = serde_json::to_vec(&Response {
                    version: PROTOCOL_VERSION,
                    request_id: req.request_id,
                    operation_id: current.operation_id,
                    progress: current.clone(),
                })
                .map_err(io::Error::other)?;
                output.push(b'\n');
                let mut written = 0u32;
                unsafe {
                    WriteFile(
                        pipe,
                        output.as_ptr().cast(),
                        output.len() as u32,
                        &mut written,
                        std::ptr::null_mut(),
                    );
                }
            }
        }
    }
    Ok(())
}
