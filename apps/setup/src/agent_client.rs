use gnx_control_protocol::PROTOCOL_VERSION;
pub fn pipe_name() -> &'static str {
    r"\\.\pipe\GnX.Platform.Control"
}
pub fn protocol_version() -> u16 {
    PROTOCOL_VERSION
}

#[cfg(windows)]
pub fn request(
    request: &gnx_control_protocol::Request,
) -> std::io::Result<gnx_control_protocol::Response> {
    use std::io::{Read, Write};
    use std::os::windows::io::FromRawHandle;
    use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_GENERIC_READ, FILE_GENERIC_WRITE, OPEN_EXISTING,
    };
    use windows_sys::Win32::System::Pipes::{GetNamedPipeServerProcessId, WaitNamedPipeW};
    use windows_sys::Win32::System::ProcessStatus::GetModuleBaseNameW;
    use windows_sys::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};
    let path: Vec<u16> = pipe_name()
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let mut frame = request
        .to_frame()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
    frame.push(b'\n');
    if unsafe { WaitNamedPipeW(path.as_ptr(), 5_000) } == 0 {
        return Err(std::io::Error::last_os_error());
    }
    let handle = unsafe {
        CreateFileW(
            path.as_ptr(),
            FILE_GENERIC_READ | FILE_GENERIC_WRITE,
            0,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            std::ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(std::io::Error::last_os_error());
    }
    let mut server_pid = 0u32;
    if unsafe { GetNamedPipeServerProcessId(handle, &mut server_pid) } == 0 || server_pid == 0 {
        unsafe { CloseHandle(handle) };
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "named-pipe server identity unavailable",
        ));
    }
    let server = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, server_pid) };
    if server.is_null() {
        unsafe { CloseHandle(handle) };
        return Err(std::io::Error::last_os_error());
    }
    let mut module = [0u16; 260];
    let module_len = unsafe {
        GetModuleBaseNameW(
            server,
            std::ptr::null_mut(),
            module.as_mut_ptr(),
            module.len() as u32,
        )
    };
    unsafe { CloseHandle(server) };
    let module_name = String::from_utf16_lossy(&module[..module_len as usize]);
    if !module_name.eq_ignore_ascii_case("gnx-host-agent.exe") {
        unsafe { CloseHandle(handle) };
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "named-pipe endpoint is not the GnX host agent",
        ));
    }
    let mut pipe = unsafe { std::fs::File::from_raw_handle(handle as _) };
    pipe.write_all(&frame)?;
    pipe.flush()?;
    let mut response = Vec::new();
    let mut byte = [0u8; 1];
    while pipe.read(&mut byte)? == 1 {
        if byte[0] == b'\n' {
            break;
        }
        response.push(byte[0]);
        if response.len() > gnx_control_protocol::MAX_FRAME_BYTES {
            break;
        }
    }
    let parsed: gnx_control_protocol::Response =
        serde_json::from_slice(&response).map_err(std::io::Error::other)?;
    if parsed.version != gnx_control_protocol::PROTOCOL_VERSION
        || parsed.request_id != request.request_id
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "named-pipe response does not match request",
        ));
    }
    Ok(parsed)
}
