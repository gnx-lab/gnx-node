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
    use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_GENERIC_READ, FILE_GENERIC_WRITE, OPEN_EXISTING,
    };
    let path: Vec<u16> = pipe_name()
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
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
    let mut pipe = unsafe { std::fs::File::from_raw_handle(handle as _) };
    let mut frame = request
        .to_frame()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
    frame.push(b'\n');
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
    serde_json::from_slice(&response).map_err(std::io::Error::other)
}
