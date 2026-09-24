use gnx_control_protocol::PROTOCOL_VERSION;
pub fn pipe_name() -> &'static str {
    r"\\.\pipe\GnX.Platform.Control"
}
pub fn protocol_version() -> u16 {
    PROTOCOL_VERSION
}

/// Stage onboarding values in a one-shot owner-readable file and send only
/// its bounded path through the named pipe. The host agent consumes and
/// unlinks it on every terminal path; Setup also unlinks it if the pipe call
/// fails before the agent can see it.
#[cfg(windows)]
pub fn request_with_secrets(
    input: &gnx_control_protocol::Request,
    tailscale_auth_key: Option<&str>,
    proxmox_password: Option<&str>,
) -> std::io::Result<gnx_control_protocol::Response> {
    use std::fs::{self, OpenOptions};
    use std::io::Write;
    use std::os::windows::fs::OpenOptionsExt;
    use uuid::Uuid;

    if tailscale_auth_key.is_none() && proxmox_password.is_none() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "empty onboarding secret bundle",
        ));
    }
    let path = std::env::temp_dir().join(format!("gnx-onboarding-{}.secret", Uuid::new_v4()));
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            // FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_DELETE_ON_CLOSE is not
            // used: the host agent must be able to open the file separately.
            .custom_flags(0)
            .open(&path)?;
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"GNXSEC01");
        bytes.push(u8::from(tailscale_auth_key.is_some()));
        bytes.push(u8::from(proxmox_password.is_some()));
        bytes.extend_from_slice(&[0, 0]);
        write_secret(&mut bytes, tailscale_auth_key)?;
        write_secret(&mut bytes, proxmox_password)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        drop(file);
        restrict_secret_file(&path)?;
        // `%TEMP%` inherits the interactive user's SYSTEM/Administrators ACL;
        // the explicit protected DACL retains the creator SID so Setup can
        // unlink it if the pipe fails before delivery.
        self_request(input, &path)
    })();
    let _ = fs::remove_file(&path);
    result
}

#[cfg(windows)]
fn restrict_secret_file(path: &std::path::Path) -> std::io::Result<()> {
    use std::ptr::null_mut;
    use windows_sys::Win32::Foundation::{CloseHandle, LocalFree};
    use windows_sys::Win32::Security::Authorization::{
        ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
        SetNamedSecurityInfoW, SDDL_REVISION_1, SE_FILE_OBJECT,
    };
    use windows_sys::Win32::Security::{
        GetSecurityDescriptorDacl, GetTokenInformation, TokenUser, DACL_SECURITY_INFORMATION,
        PROTECTED_DACL_SECURITY_INFORMATION, TOKEN_QUERY, TOKEN_USER,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    let mut token = null_mut();
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(std::io::Error::last_os_error());
    }
    let mut size = 0u32;
    unsafe {
        GetTokenInformation(token, TokenUser, null_mut(), 0, &mut size);
    }
    let mut buffer = vec![0u8; size as usize];
    let result = unsafe {
        GetTokenInformation(
            token,
            TokenUser,
            buffer.as_mut_ptr().cast(),
            buffer.len() as u32,
            &mut size,
        )
    };
    unsafe { CloseHandle(token) };
    if result == 0 {
        return Err(std::io::Error::last_os_error());
    }
    let user = unsafe { &*(buffer.as_ptr() as *const TOKEN_USER) };
    let mut sid_text = null_mut();
    if unsafe { ConvertSidToStringSidW(user.User.Sid, &mut sid_text) } == 0 {
        return Err(std::io::Error::last_os_error());
    }
    let mut sid_len = 0usize;
    unsafe {
        while *sid_text.add(sid_len) != 0 {
            sid_len += 1;
        }
    }
    let sid = String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(sid_text, sid_len) });
    unsafe { LocalFree(sid_text as _) };

    let name: Vec<u16> = path
        .to_string_lossy()
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let sddl = format!("D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;{sid})");
    let descriptor_text: Vec<u16> = sddl.encode_utf16().chain(std::iter::once(0)).collect();
    let mut descriptor = null_mut();
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            descriptor_text.as_ptr(),
            SDDL_REVISION_1,
            &mut descriptor,
            null_mut(),
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error());
    }
    let mut dacl = null_mut();
    let mut present = 0;
    let mut defaulted = 0;
    if unsafe { GetSecurityDescriptorDacl(descriptor, &mut present, &mut dacl, &mut defaulted) }
        == 0
        || present == 0
        || dacl.is_null()
    {
        unsafe { LocalFree(descriptor as _) };
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "generated secret ACL has no DACL",
        ));
    }
    let status = unsafe {
        SetNamedSecurityInfoW(
            name.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            null_mut(),
            null_mut(),
            dacl.cast(),
            null_mut(),
        )
    };
    unsafe { LocalFree(descriptor as _) };
    if status == 0 {
        Ok(())
    } else {
        Err(std::io::Error::from_raw_os_error(status as i32))
    }
}

#[cfg(windows)]
fn self_request(
    input: &gnx_control_protocol::Request,
    path: &std::path::Path,
) -> std::io::Result<gnx_control_protocol::Response> {
    request(&input.clone().with_secret_file(path.to_string_lossy()))
}

#[cfg(windows)]
fn write_secret(out: &mut Vec<u8>, value: Option<&str>) -> std::io::Result<()> {
    let Some(value) = value else {
        out.extend_from_slice(&0u32.to_le_bytes());
        return Ok(());
    };
    let bytes = value.as_bytes();
    if bytes.is_empty() || bytes.len() > 4096 || bytes.iter().any(|b| b.is_ascii_control()) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "invalid onboarding secret",
        ));
    }
    out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}

#[cfg(windows)]
fn is_installed_host_agent(image_path: &str) -> bool {
    let Ok(setup_path) = std::env::current_exe() else {
        return false;
    };
    let Some(parent) = setup_path.parent() else {
        return false;
    };
    let expected = std::fs::canonicalize(parent.join("gnx-host-agent.exe"));
    let actual = std::fs::canonicalize(std::path::Path::new(image_path));
    match (expected, actual) {
        (Ok(expected), Ok(actual)) => {
            normalized_windows_path(&expected) == normalized_windows_path(&actual)
        }
        _ => false,
    }
}

#[cfg(windows)]
fn normalized_windows_path(path: &std::path::Path) -> String {
    let mut text = path.to_string_lossy().replace('/', "\\");
    if let Some(rest) = text.strip_prefix("\\\\?\\") {
        text = rest.to_owned();
    }
    text.trim_end_matches('\\').to_ascii_lowercase()
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
    use windows_sys::Win32::System::Threading::{
        OpenProcess, QueryFullProcessImageNameW, PROCESS_QUERY_LIMITED_INFORMATION,
    };
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
    let mut image = [0u16; 32_768];
    let mut image_len = image.len() as u32;
    let queried =
        unsafe { QueryFullProcessImageNameW(server, 0, image.as_mut_ptr(), &mut image_len) };
    unsafe { CloseHandle(server) };
    if queried == 0 || image_len == 0 || image_len as usize > image.len() {
        unsafe { CloseHandle(handle) };
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "named-pipe server image could not be verified",
        ));
    }
    let image_path = String::from_utf16_lossy(&image[..image_len as usize]);
    if !is_installed_host_agent(&image_path) {
        unsafe { CloseHandle(handle) };
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "named-pipe endpoint is not the installed GnX host agent",
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
    if parsed.version != protocol_version() || parsed.request_id != request.request_id {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "named-pipe response does not match request",
        ));
    }
    Ok(parsed)
}
