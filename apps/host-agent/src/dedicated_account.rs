//! Windows identity boundary for the managed `gnxnodesvc` account.

pub const ACCOUNT_NAME: &str = "gnxnodesvc";

#[cfg(windows)]
const PASSWORD_BLOB: &str = "identity/password.dpapi";

#[cfg_attr(not(windows), allow(dead_code))]
pub fn account_name_is_managed(name: &str) -> bool {
    name.eq_ignore_ascii_case(ACCOUNT_NAME)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnsureResult {
    Created,
    Existing,
}

#[cfg(not(windows))]
pub fn ensure() -> std::io::Result<EnsureResult> {
    Ok(EnsureResult::Existing)
}

#[cfg(windows)]
pub fn ensure() -> std::io::Result<EnsureResult> {
    use std::process::Command;

    debug_assert!(account_name_is_managed(ACCOUNT_NAME));
    let existing = Command::new("net").args(["user", ACCOUNT_NAME]).output()?;
    if existing.status.success() {
        ensure_profile_and_credential(None)?;
        return Ok(EnsureResult::Existing);
    }
    // This password is passed directly to NetUserAdd, never put in argv or
    // process output, then retained only as a machine-protected DPAPI blob.
    let mut password = format!("Gnx-{}-{}", uuid::Uuid::new_v4(), uuid::Uuid::new_v4());
    let result = (|| {
        create_account(&password)?;
        ensure_profile_and_credential(Some(&password))
    })();
    unsafe { password.as_mut_vec().fill(0) };
    result?;
    Ok(EnsureResult::Created)
}

#[cfg(windows)]
fn create_account(password: &str) -> std::io::Result<()> {
    use std::ptr::null_mut;
    use windows_sys::Win32::NetworkManagement::NetManagement::{
        NetUserAdd, USER_INFO_1, USER_PRIV_USER,
    };

    let mut name = ACCOUNT_NAME
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let mut secret = password
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let mut info = USER_INFO_1 {
        usri1_name: name.as_mut_ptr(),
        usri1_password: secret.as_mut_ptr(),
        usri1_password_age: 0,
        usri1_priv: USER_PRIV_USER,
        usri1_home_dir: null_mut(),
        usri1_comment: null_mut(),
        usri1_flags: managed_account_flags(),
        usri1_script_path: null_mut(),
    };
    let mut parameter_error = 0u32;
    let status = unsafe {
        NetUserAdd(
            null_mut(),
            1,
            (&mut info as *mut USER_INFO_1).cast(),
            &mut parameter_error,
        )
    };
    name.fill(0);
    secret.fill(0);
    if status == 0 {
        Ok(())
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "ACCOUNT_CREATE_FAILED",
        ))
    }
}

#[cfg(windows)]
fn managed_account_flags() -> u32 {
    use windows_sys::Win32::NetworkManagement::NetManagement::{
        UF_DONT_EXPIRE_PASSWD, UF_NORMAL_ACCOUNT, UF_PASSWD_CANT_CHANGE, UF_SCRIPT,
    };
    UF_NORMAL_ACCOUNT | UF_SCRIPT | UF_DONT_EXPIRE_PASSWD | UF_PASSWD_CANT_CHANGE
}

#[cfg(windows)]
fn ensure_profile_and_credential(password: Option<&str>) -> std::io::Result<()> {
    let (sid, sid_text) = account_sid()?;
    let path = crate::state::state_dir().join(PASSWORD_BLOB);
    let profile = if let Some(password) = password {
        // Persist and ACL the machine-protected credential before bootstrapping
        // the profile so a retry can recover from a process-launch failure.
        std::fs::create_dir_all(path.parent().expect("identity has a parent"))?;
        let mut protected = protect_password(password)?;
        let write_result = std::fs::write(&path, &protected);
        protected.fill(0);
        write_result?;
        restrict_credential_file(&path)?;
        bootstrap_profile(password)?
    } else if !path.is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "ACCOUNT_CREDENTIAL_MISSING",
        ));
    } else {
        let mut password = decrypt_password_file(&path)?;
        let profile = bootstrap_profile(&password);
        unsafe { password.as_mut_vec().fill(0) };
        profile?
    };
    let metadata = std::fs::symlink_metadata(&profile).map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::NotFound, "ACCOUNT_PROFILE_MISSING")
    })?;
    if !metadata.is_dir()
        || profile.file_name().and_then(|name| name.to_str()) != Some(ACCOUNT_NAME)
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "ACCOUNT_PROFILE_INVALID",
        ));
    }
    let expected_profile = profile_path(&sid_text)?;
    let same_path = profile
        .to_string_lossy()
        .trim_end_matches(['\\', '/'])
        .eq_ignore_ascii_case(
            expected_profile
                .to_string_lossy()
                .trim_end_matches(['\\', '/']),
        );
    if !same_path {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "ACCOUNT_PROFILE_PATH_INVALID",
        ));
    }
    validate_profile_security(&profile, &sid)?;
    Ok(())
}

#[cfg(windows)]
fn profile_bootstrap_error(error: std::io::Error) -> std::io::Error {
    // Keep the OS diagnostic for local/service logs while exposing only this
    // stable, credential-free classification through Progress.
    std::io::Error::new(
        error.kind(),
        format!("ACCOUNT_PROFILE_BOOTSTRAP_FAILED: {error}"),
    )
}

/// A token, loaded profile, and environment owned by one managed process.
///
/// The service runs as LocalSystem. `CreateProcessWithLogonW` is unavailable to
/// LocalSystem because it has no logon SID, so every managed process must use a
/// token obtained with `LogonUserW` and `CreateProcessAsUserW` instead.
#[cfg(windows)]
struct ManagedIdentity {
    token: windows_sys::Win32::Foundation::HANDLE,
    profile: windows_sys::Win32::Foundation::HANDLE,
    environment: *mut std::ffi::c_void,
}

#[cfg(windows)]
impl Drop for ManagedIdentity {
    fn drop(&mut self) {
        use windows_sys::Win32::Foundation::CloseHandle;
        use windows_sys::Win32::System::Environment::DestroyEnvironmentBlock;
        use windows_sys::Win32::UI::Shell::UnloadUserProfile;
        unsafe {
            if !self.environment.is_null() {
                DestroyEnvironmentBlock(self.environment);
            }
            if !self.profile.is_null() {
                UnloadUserProfile(self.token, self.profile);
            }
            if !self.token.is_null() {
                CloseHandle(self.token);
            }
        }
    }
}

#[cfg(windows)]
fn logon_managed_identity(password: &str) -> std::io::Result<ManagedIdentity> {
    use std::ptr::null_mut;
    use windows_sys::Win32::Security::{
        LogonUserW, LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT,
    };
    use windows_sys::Win32::System::Environment::CreateEnvironmentBlock;
    use windows_sys::Win32::UI::Shell::{LoadUserProfileW, PROFILEINFOW};

    let mut username = ACCOUNT_NAME
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let mut domain = "."
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let mut password_wide = password
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let mut token = null_mut();
    let logged_on = unsafe {
        LogonUserW(
            username.as_ptr(),
            domain.as_ptr(),
            password_wide.as_ptr(),
            LOGON32_LOGON_INTERACTIVE,
            LOGON32_PROVIDER_DEFAULT,
            &mut token,
        ) != 0
    };
    password_wide.fill(0);
    if !logged_on {
        username.fill(0);
        domain.fill(0);
        return Err(std::io::Error::last_os_error());
    }

    let mut profile_info: PROFILEINFOW = unsafe { std::mem::zeroed() };
    profile_info.dwSize = std::mem::size_of::<PROFILEINFOW>() as u32;
    profile_info.lpUserName = username.as_mut_ptr();
    let loaded = unsafe { LoadUserProfileW(token, &mut profile_info) != 0 };
    username.fill(0);
    domain.fill(0);
    if !loaded {
        unsafe { windows_sys::Win32::Foundation::CloseHandle(token) };
        return Err(std::io::Error::last_os_error());
    }

    let mut environment = null_mut();
    if unsafe { CreateEnvironmentBlock(&mut environment, token, 0) } == 0 {
        unsafe {
            windows_sys::Win32::UI::Shell::UnloadUserProfile(token, profile_info.hProfile);
            windows_sys::Win32::Foundation::CloseHandle(token);
        }
        return Err(std::io::Error::last_os_error());
    }
    Ok(ManagedIdentity {
        token,
        profile: profile_info.hProfile,
        environment,
    })
}

#[cfg(windows)]
fn bootstrap_profile(password: &str) -> std::io::Result<std::path::PathBuf> {
    use std::ptr::null_mut;
    use windows_sys::Win32::Foundation::{CloseHandle, WAIT_OBJECT_0, WAIT_TIMEOUT};
    use windows_sys::Win32::System::Threading::{
        CreateProcessAsUserW, GetExitCodeProcess, WaitForSingleObject, CREATE_NO_WINDOW,
        CREATE_UNICODE_ENVIRONMENT, PROCESS_INFORMATION, STARTF_USESHOWWINDOW, STARTUPINFOW,
    };

    let identity = logon_managed_identity(password).map_err(profile_bootstrap_error)?;
    let profile = profile_directory(identity.token).map_err(profile_bootstrap_error)?;
    let mut command = "C:\\Windows\\System32\\cmd.exe /c exit 0"
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let startup = STARTUPINFOW {
        cb: std::mem::size_of::<STARTUPINFOW>() as u32,
        dwFlags: STARTF_USESHOWWINDOW,
        ..unsafe { std::mem::zeroed() }
    };
    let mut process: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
    let launched = unsafe {
        CreateProcessAsUserW(
            identity.token,
            null_mut(),
            command.as_mut_ptr(),
            null_mut(),
            null_mut(),
            0,
            CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT,
            identity.environment,
            null_mut(),
            &startup,
            &mut process,
        )
    } != 0;
    command.fill(0);
    if !launched {
        return Err(profile_bootstrap_error(std::io::Error::last_os_error()));
    }
    let wait = unsafe { WaitForSingleObject(process.hProcess, 30_000) };
    let mut exit_code = 1u32;
    unsafe { GetExitCodeProcess(process.hProcess, &mut exit_code) };
    unsafe {
        CloseHandle(process.hThread);
        CloseHandle(process.hProcess);
    }
    if wait == WAIT_TIMEOUT {
        return Err(profile_bootstrap_error(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "no-op process timed out",
        )));
    }
    if wait != WAIT_OBJECT_0 || exit_code != 0 {
        return Err(profile_bootstrap_error(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!("no-op process exited with status {exit_code}"),
        )));
    }
    Ok(profile)
}

#[cfg(windows)]
fn profile_directory(
    token: windows_sys::Win32::Foundation::HANDLE,
) -> std::io::Result<std::path::PathBuf> {
    use std::ptr::null_mut;
    use windows_sys::Win32::UI::Shell::GetUserProfileDirectoryW;
    let mut size = 0u32;
    unsafe { GetUserProfileDirectoryW(token, null_mut(), &mut size) };
    if size == 0 {
        return Err(std::io::Error::last_os_error());
    }
    let mut buffer = vec![0u16; size as usize];
    if unsafe { GetUserProfileDirectoryW(token, buffer.as_mut_ptr(), &mut size) } == 0 {
        return Err(std::io::Error::last_os_error());
    }
    let length = buffer
        .iter()
        .position(|character| *character == 0)
        .unwrap_or(size as usize);
    Ok(std::path::PathBuf::from(String::from_utf16_lossy(
        &buffer[..length],
    )))
}

#[cfg(windows)]
fn decrypt_password_file(path: &std::path::Path) -> std::io::Result<String> {
    use std::ptr::null_mut;
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Cryptography::{CryptUnprotectData, CRYPT_INTEGER_BLOB};
    let mut encrypted = std::fs::read(path)?;
    if encrypted.is_empty() || encrypted.len() > 64 * 1024 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "ACCOUNT_CREDENTIAL_INVALID",
        ));
    }
    let input = CRYPT_INTEGER_BLOB {
        cbData: encrypted.len() as u32,
        pbData: encrypted.as_mut_ptr(),
    };
    let mut output = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: null_mut(),
    };
    let ok = unsafe {
        CryptUnprotectData(
            &input,
            null_mut(),
            null_mut(),
            null_mut(),
            null_mut(),
            0,
            &mut output,
        )
    } != 0;
    encrypted.fill(0);
    if !ok || output.pbData.is_null() {
        return Err(std::io::Error::last_os_error());
    }
    let plain = unsafe { std::slice::from_raw_parts(output.pbData, output.cbData as usize) };
    let result = std::str::from_utf8(plain).map(str::to_owned).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "ACCOUNT_CREDENTIAL_INVALID",
        )
    });
    unsafe { std::slice::from_raw_parts_mut(output.pbData, output.cbData as usize).fill(0) };
    unsafe { LocalFree(output.pbData.cast()) };
    result
}

/// Execute a fixed WSL command under the dedicated *Windows* account token.
/// The command line contains only the allowlisted executable and arguments;
/// the DPAPI credential is decrypted only long enough to obtain a primary
/// token with `LogonUserW`; the child is created from that token.
#[cfg(windows)]
pub(crate) fn run_wsl_as_windows_identity(
    args: &[String],
) -> std::io::Result<std::process::Output> {
    use std::os::windows::process::ExitStatusExt;
    use std::ptr::null_mut;
    use windows_sys::Win32::Foundation::{
        CloseHandle, SetHandleInformation, HANDLE, HANDLE_FLAG_INHERIT, WAIT_OBJECT_0, WAIT_TIMEOUT,
    };
    use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
    use windows_sys::Win32::System::Pipes::CreatePipe;
    use windows_sys::Win32::System::Threading::{
        CreateProcessAsUserW, GetExitCodeProcess, TerminateProcess, WaitForSingleObject,
        CREATE_NO_WINDOW, CREATE_UNICODE_ENVIRONMENT, PROCESS_INFORMATION, STARTF_USESTDHANDLES,
        STARTUPINFOW,
    };

    let blob_path = crate::state::state_dir().join(PASSWORD_BLOB);
    let mut password = decrypt_password_file(&blob_path)?;
    let identity_result = logon_managed_identity(&password);
    // Keep the decrypted credential memory-only and erase it before any
    // process launch or output handling.
    unsafe { password.as_mut_vec().fill(0) };
    let identity = identity_result?;

    let mut stdout_read: HANDLE = null_mut();
    let mut stdout_write: HANDLE = null_mut();
    let mut stderr_read: HANDLE = null_mut();
    let mut stderr_write: HANDLE = null_mut();
    let security = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: null_mut(),
        bInheritHandle: 1,
    };
    let pipes_ok = unsafe {
        CreatePipe(&mut stdout_read, &mut stdout_write, &security, 0) != 0
            && CreatePipe(&mut stderr_read, &mut stderr_write, &security, 0) != 0
    };
    if !pipes_ok {
        if !stdout_read.is_null() {
            unsafe { CloseHandle(stdout_read) };
        }
        if !stdout_write.is_null() {
            unsafe { CloseHandle(stdout_write) };
        }
        if !stderr_read.is_null() {
            unsafe { CloseHandle(stderr_read) };
        }
        if !stderr_write.is_null() {
            unsafe { CloseHandle(stderr_write) };
        }
        return Err(std::io::Error::last_os_error());
    }
    if unsafe { SetHandleInformation(stdout_read, HANDLE_FLAG_INHERIT, 0) == 0 }
        || unsafe { SetHandleInformation(stderr_read, HANDLE_FLAG_INHERIT, 0) == 0 }
    {
        unsafe {
            CloseHandle(stdout_read);
            CloseHandle(stdout_write);
            CloseHandle(stderr_read);
            CloseHandle(stderr_write);
        }
        return Err(std::io::Error::last_os_error());
    }

    let command = windows_command_line(args);
    let mut command_wide = command
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let startup = STARTUPINFOW {
        cb: std::mem::size_of::<STARTUPINFOW>() as u32,
        lpReserved: null_mut(),
        lpDesktop: null_mut(),
        lpTitle: null_mut(),
        dwX: 0,
        dwY: 0,
        dwXSize: 0,
        dwYSize: 0,
        dwXCountChars: 0,
        dwYCountChars: 0,
        dwFillAttribute: 0,
        dwFlags: STARTF_USESTDHANDLES,
        wShowWindow: 0,
        cbReserved2: 0,
        lpReserved2: null_mut(),
        hStdInput: null_mut(),
        hStdOutput: stdout_write,
        hStdError: stderr_write,
    };
    let mut process = PROCESS_INFORMATION {
        hProcess: null_mut(),
        hThread: null_mut(),
        dwProcessId: 0,
        dwThreadId: 0,
    };
    let launched = unsafe {
        CreateProcessAsUserW(
            identity.token,
            null_mut(),
            command_wide.as_mut_ptr(),
            null_mut(),
            null_mut(),
            1,
            CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT,
            identity.environment,
            null_mut(),
            &startup,
            &mut process,
        )
    } != 0;
    command_wide.fill(0);
    unsafe {
        CloseHandle(stdout_write);
        CloseHandle(stderr_write);
    }
    if !launched {
        unsafe {
            CloseHandle(stdout_read);
            CloseHandle(stderr_read);
        }
        return Err(std::io::Error::last_os_error());
    }
    let stdout_handle = stdout_read as usize;
    let stderr_handle = stderr_read as usize;
    let stdout_thread = std::thread::spawn(move || read_pipe(stdout_handle as HANDLE));
    let stderr_thread = std::thread::spawn(move || read_pipe(stderr_handle as HANDLE));
    let result = unsafe { WaitForSingleObject(process.hProcess, 300_000) };
    let timed_out = result == WAIT_TIMEOUT;
    if timed_out {
        unsafe { TerminateProcess(process.hProcess, 1) };
    }
    let mut stdout = stdout_thread.join().unwrap_or_default();
    let mut stderr = stderr_thread.join().unwrap_or_default();
    let mut exit_code = 1u32;
    unsafe {
        GetExitCodeProcess(process.hProcess, &mut exit_code);
    }
    unsafe {
        CloseHandle(process.hThread);
        CloseHandle(process.hProcess);
    }
    if timed_out {
        return Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "WSL operation timed out",
        ));
    }
    if result != WAIT_OBJECT_0 {
        return Err(std::io::Error::last_os_error());
    }
    if stdout.len() > 1024 * 1024 {
        stdout.truncate(1024 * 1024);
    }
    if stderr.len() > 1024 * 1024 {
        stderr.truncate(1024 * 1024);
    }
    Ok(std::process::Output {
        status: std::process::ExitStatus::from_raw(exit_code),
        stdout,
        stderr,
    })
}

#[cfg(windows)]
fn append_windows_arg(command: &mut String, arg: &str) {
    if !arg.is_empty()
        && arg
            .chars()
            .all(|character| !character.is_whitespace() && character != '"')
    {
        command.push_str(arg);
        return;
    }
    command.push('"');
    let mut backslashes = 0usize;
    for character in arg.chars() {
        if character == '\\' {
            backslashes += 1;
        } else {
            if character == '"' {
                command.extend(std::iter::repeat_n('\\', backslashes * 2 + 1));
            } else {
                command.extend(std::iter::repeat_n('\\', backslashes));
            }
            command.push(character);
            backslashes = 0;
        }
    }
    command.extend(std::iter::repeat_n('\\', backslashes * 2));
    command.push('"');
}

#[cfg(windows)]
fn windows_command_line(args: &[String]) -> String {
    let mut command = String::from("wsl.exe");
    for arg in args {
        command.push(' ');
        append_windows_arg(&mut command, arg);
    }
    command
}

#[cfg(windows)]
fn read_pipe(handle: windows_sys::Win32::Foundation::HANDLE) -> Vec<u8> {
    use std::ptr::null_mut;
    use windows_sys::Win32::Storage::FileSystem::ReadFile;
    let mut result = Vec::new();
    let mut buffer = [0u8; 8192];
    loop {
        let mut read = 0u32;
        let ok = unsafe {
            ReadFile(
                handle,
                buffer.as_mut_ptr(),
                buffer.len() as u32,
                &mut read,
                null_mut(),
            )
        };
        if ok == 0 || read == 0 {
            break;
        }
        result.extend_from_slice(&buffer[..read as usize]);
        if result.len() >= 1024 * 1024 {
            break;
        }
    }
    result
}

#[cfg(windows)]
fn validate_profile_security(path: &std::path::Path, expected_sid: &[u8]) -> std::io::Result<()> {
    use std::ptr::null_mut;
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Authorization::{GetNamedSecurityInfoW, SE_FILE_OBJECT};
    use windows_sys::Win32::Security::{
        CreateWellKnownSid, EqualSid, GetAce, GetSecurityDescriptorDacl, IsValidSid,
        WinBuiltinAdministratorsSid, WinLocalSystemSid, ACCESS_ALLOWED_ACE,
        DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        GetFileAttributesW, FILE_ALL_ACCESS, FILE_ATTRIBUTE_REPARSE_POINT, INVALID_FILE_ATTRIBUTES,
    };
    use windows_sys::Win32::System::SystemServices::ACCESS_ALLOWED_ACE_TYPE;

    if expected_sid.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "ACCOUNT_PROFILE_SID_INVALID",
        ));
    }
    let name = path
        .to_string_lossy()
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let attributes = unsafe { GetFileAttributesW(name.as_ptr()) };
    if attributes == INVALID_FILE_ATTRIBUTES || attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "ACCOUNT_PROFILE_REPARSE_OR_MISSING",
        ));
    }
    let mut owner = null_mut();
    let mut dacl = null_mut();
    let mut descriptor = null_mut();
    let status = unsafe {
        GetNamedSecurityInfoW(
            name.as_ptr(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            null_mut(),
            &mut dacl,
            null_mut(),
            &mut descriptor,
        )
    };
    if status != 0 || owner.is_null() || descriptor.is_null() {
        if !descriptor.is_null() {
            unsafe { LocalFree(descriptor.cast()) };
        }
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "ACCOUNT_PROFILE_SECURITY_UNAVAILABLE",
        ));
    }

    let well_known_sid = |sid_type| {
        let mut size = 0u32;
        unsafe { CreateWellKnownSid(sid_type, null_mut(), null_mut(), &mut size) };
        if size == 0 {
            return Err(std::io::Error::last_os_error());
        }
        let mut sid = vec![0u8; size as usize];
        if unsafe { CreateWellKnownSid(sid_type, null_mut(), sid.as_mut_ptr().cast(), &mut size) }
            == 0
        {
            return Err(std::io::Error::last_os_error());
        }
        sid.truncate(size as usize);
        Ok(sid)
    };
    let system_sid = match well_known_sid(WinLocalSystemSid) {
        Ok(sid) => sid,
        Err(error) => {
            unsafe { LocalFree(descriptor.cast()) };
            return Err(error);
        }
    };
    let administrators_sid = match well_known_sid(WinBuiltinAdministratorsSid) {
        Ok(sid) => sid,
        Err(error) => {
            unsafe { LocalFree(descriptor.cast()) };
            return Err(error);
        }
    };
    let owner_allowed = unsafe {
        EqualSid(owner, expected_sid.as_ptr().cast_mut().cast()) != 0
            || EqualSid(owner, system_sid.as_ptr().cast_mut().cast()) != 0
            || EqualSid(owner, administrators_sid.as_ptr().cast_mut().cast()) != 0
    };
    if !owner_allowed {
        unsafe { LocalFree(descriptor.cast()) };
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "ACCOUNT_PROFILE_OWNER_INVALID",
        ));
    }

    let mut present = 0;
    let mut defaulted = 0;
    if unsafe { GetSecurityDescriptorDacl(descriptor, &mut present, &mut dacl, &mut defaulted) }
        == 0
        || present == 0
        || dacl.is_null()
    {
        unsafe { LocalFree(descriptor.cast()) };
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "ACCOUNT_PROFILE_DACL_UNAVAILABLE",
        ));
    }
    let mut service_has_full_access = false;
    let mut system_has_full_access = false;
    let mut administrators_have_full_access = false;
    for index in 0..unsafe { (*dacl).AceCount as u32 } {
        let mut ace = null_mut();
        if unsafe { GetAce(dacl, index, &mut ace) } == 0 || ace.is_null() {
            unsafe { LocalFree(descriptor.cast()) };
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "ACCOUNT_PROFILE_DACL_UNAVAILABLE",
            ));
        }
        let header = unsafe { &*ace.cast::<windows_sys::Win32::Security::ACE_HEADER>() };
        if header.AceType != ACCESS_ALLOWED_ACE_TYPE as u8
            || (header.AceSize as usize) < std::mem::size_of::<ACCESS_ALLOWED_ACE>()
        {
            continue;
        }
        let allowed = unsafe { &*ace.cast::<ACCESS_ALLOWED_ACE>() };
        let ace_sid = std::ptr::addr_of!(allowed.SidStart).cast_mut().cast();
        if unsafe { IsValidSid(ace_sid) } != 0 && allowed.Mask & FILE_ALL_ACCESS == FILE_ALL_ACCESS
        {
            service_has_full_access |=
                unsafe { EqualSid(ace_sid, expected_sid.as_ptr().cast_mut().cast()) != 0 };
            system_has_full_access |=
                unsafe { EqualSid(ace_sid, system_sid.as_ptr().cast_mut().cast()) != 0 };
            administrators_have_full_access |=
                unsafe { EqualSid(ace_sid, administrators_sid.as_ptr().cast_mut().cast()) != 0 };
        }
    }
    unsafe { LocalFree(descriptor.cast()) };
    if service_has_full_access && system_has_full_access && administrators_have_full_access {
        Ok(())
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "ACCOUNT_PROFILE_ACCESS_INVALID",
        ))
    }
}

#[cfg(windows)]
fn account_sid() -> std::io::Result<(Vec<u8>, String)> {
    use std::ptr::null_mut;
    use windows_sys::Win32::Foundation::{GetLastError, LocalFree, ERROR_INSUFFICIENT_BUFFER};
    use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
    use windows_sys::Win32::Security::{LookupAccountNameW, SID_NAME_USE};

    let account = ACCOUNT_NAME
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let mut sid_size = 0u32;
    let mut domain_size = 0u32;
    let mut use_type: SID_NAME_USE = 0;
    let first = unsafe {
        LookupAccountNameW(
            null_mut(),
            account.as_ptr(),
            null_mut(),
            &mut sid_size,
            null_mut(),
            &mut domain_size,
            &mut use_type,
        )
    };
    if first != 0 || unsafe { GetLastError() } != ERROR_INSUFFICIENT_BUFFER {
        return Err(std::io::Error::last_os_error());
    }
    let mut sid = vec![0u8; sid_size as usize];
    let mut domain = vec![0u16; domain_size as usize];
    if unsafe {
        LookupAccountNameW(
            null_mut(),
            account.as_ptr(),
            sid.as_mut_ptr().cast(),
            &mut sid_size,
            domain.as_mut_ptr(),
            &mut domain_size,
            &mut use_type,
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error());
    }
    let mut text = null_mut();
    if unsafe { ConvertSidToStringSidW(sid.as_mut_ptr().cast(), &mut text) } == 0 {
        return Err(std::io::Error::last_os_error());
    }
    let mut length = 0usize;
    unsafe {
        while *text.add(length) != 0 {
            length += 1;
        }
    }
    let sid_text = String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(text, length) });
    unsafe { LocalFree(text as _) };
    sid.truncate(sid_size as usize);
    Ok((sid, sid_text))
}

#[cfg(all(windows, not(test)))]
pub(crate) fn managed_account_sid_text() -> std::io::Result<String> {
    account_sid().map(|(_, text)| text)
}

#[cfg(all(windows, not(test)))]
pub(crate) fn managed_profile_dir() -> std::io::Result<std::path::PathBuf> {
    let (sid, sid_text) = account_sid()?;
    let profile = profile_path(&sid_text)?;
    let metadata = std::fs::symlink_metadata(&profile).map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::NotFound, "ACCOUNT_PROFILE_MISSING")
    })?;
    if !metadata.is_dir()
        || profile.file_name().and_then(|name| name.to_str()) != Some(ACCOUNT_NAME)
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "ACCOUNT_PROFILE_INVALID",
        ));
    }
    validate_profile_security(&profile, &sid)?;
    Ok(profile)
}

#[cfg(all(windows, test))]
pub(crate) fn managed_profile_dir() -> std::io::Result<std::path::PathBuf> {
    Ok(std::env::temp_dir().join("gnxnodesvc-profile-fixture"))
}

#[cfg(windows)]
fn profile_path(sid: &str) -> std::io::Result<std::path::PathBuf> {
    use std::ptr::null_mut;
    use windows_sys::Win32::System::Environment::ExpandEnvironmentStringsW;
    use windows_sys::Win32::System::Registry::{
        RegCloseKey, RegOpenKeyExW, RegQueryValueExW, HKEY_LOCAL_MACHINE, KEY_READ, REG_EXPAND_SZ,
        REG_SZ,
    };
    let key_path = format!(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\{sid}");
    let key_path = key_path
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let value_name = "ProfileImagePath"
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let mut key = null_mut();
    let status =
        unsafe { RegOpenKeyExW(HKEY_LOCAL_MACHINE, key_path.as_ptr(), 0, KEY_READ, &mut key) };
    if status != 0 {
        return Err(std::io::Error::from_raw_os_error(status as i32));
    }
    let result = (|| {
        let mut kind = 0;
        let mut size = 0u32;
        let status = unsafe {
            RegQueryValueExW(
                key,
                value_name.as_ptr(),
                null_mut(),
                &mut kind,
                null_mut(),
                &mut size,
            )
        };
        if status != 0 || (kind != REG_SZ && kind != REG_EXPAND_SZ) || size == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "ACCOUNT_PROFILE_PATH_UNAVAILABLE",
            ));
        }
        let mut bytes = vec![0u8; size as usize];
        let status = unsafe {
            RegQueryValueExW(
                key,
                value_name.as_ptr(),
                null_mut(),
                &mut kind,
                bytes.as_mut_ptr(),
                &mut size,
            )
        };
        if status != 0 || size < 2 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "ACCOUNT_PROFILE_PATH_UNAVAILABLE",
            ));
        }
        let raw =
            unsafe { std::slice::from_raw_parts(bytes.as_ptr().cast::<u16>(), size as usize / 2) };
        let raw = &raw[..raw
            .iter()
            .position(|character| *character == 0)
            .unwrap_or(raw.len())];
        let path = if kind == REG_EXPAND_SZ {
            let mut expanded = vec![0u16; 32768];
            let length = unsafe {
                ExpandEnvironmentStringsW(
                    raw.as_ptr(),
                    expanded.as_mut_ptr(),
                    expanded.len() as u32,
                )
            };
            if length == 0 || length > expanded.len() as u32 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "ACCOUNT_PROFILE_PATH_UNAVAILABLE",
                ));
            }
            expanded.truncate(length.saturating_sub(1) as usize);
            expanded
        } else {
            raw.to_vec()
        };
        Ok(std::path::PathBuf::from(String::from_utf16_lossy(&path)))
    })();
    unsafe { RegCloseKey(key) };
    result
}

#[cfg(windows)]
fn protect_password(password: &str) -> std::io::Result<Vec<u8>> {
    use std::ptr::null_mut;
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Cryptography::{
        CryptProtectData, CRYPTPROTECT_LOCAL_MACHINE, CRYPT_INTEGER_BLOB,
    };
    let mut plain = password.as_bytes().to_vec();
    let input = CRYPT_INTEGER_BLOB {
        cbData: plain.len() as u32,
        pbData: plain.as_mut_ptr(),
    };
    let mut output = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: null_mut(),
    };
    let ok = unsafe {
        CryptProtectData(
            &input,
            null_mut(),
            null_mut(),
            null_mut(),
            null_mut(),
            CRYPTPROTECT_LOCAL_MACHINE,
            &mut output,
        )
    } != 0;
    plain.fill(0);
    if !ok || output.pbData.is_null() {
        return Err(std::io::Error::last_os_error());
    }
    let result =
        unsafe { std::slice::from_raw_parts(output.pbData, output.cbData as usize) }.to_vec();
    unsafe { LocalFree(output.pbData.cast()) };
    Ok(result)
}

#[cfg(windows)]
fn restrict_credential_file(path: &std::path::Path) -> std::io::Result<()> {
    restrict_file_acl(path, None, "FA", false)
}

#[cfg(all(windows, not(test)))]
pub(crate) fn restrict_read_file(path: &std::path::Path) -> std::io::Result<()> {
    let account_sid = managed_account_sid_text()?;
    restrict_file_acl(path, Some(&account_sid), "FR", false)
}

#[cfg(all(windows, test))]
pub(crate) fn restrict_read_file(_path: &std::path::Path) -> std::io::Result<()> {
    Ok(())
}

#[cfg(all(windows, not(test)))]
pub(crate) fn restrict_read_directory(path: &std::path::Path) -> std::io::Result<()> {
    let account_sid = managed_account_sid_text()?;
    restrict_file_acl(path, Some(&account_sid), "FR", true)
}

#[cfg(all(windows, not(test)))]
pub(crate) fn restrict_system_admin_directory(path: &std::path::Path) -> std::io::Result<()> {
    restrict_file_acl(path, None, "FA", true)
}

#[cfg(all(windows, test))]
pub(crate) fn restrict_read_directory(_path: &std::path::Path) -> std::io::Result<()> {
    Ok(())
}

#[cfg(all(windows, test))]
pub(crate) fn restrict_system_admin_directory(_path: &std::path::Path) -> std::io::Result<()> {
    Ok(())
}

#[cfg(windows)]
fn managed_read_acl_sddl(account_sid: &str, inheritable: bool) -> String {
    let inheritance = if inheritable { "OICI" } else { "" };
    format!(
        "D:P(A;{inheritance};FA;;;SY)(A;{inheritance};FA;;;BA)(A;{inheritance};FR;;;{account_sid})"
    )
}

#[cfg(windows)]
fn system_admin_acl_sddl(inheritable: bool) -> String {
    let inheritance = if inheritable { "OICI" } else { "" };
    format!("D:P(A;{inheritance};FA;;;SY)(A;{inheritance};FA;;;BA)")
}

#[cfg(windows)]
fn restrict_file_acl(
    path: &std::path::Path,
    account_sid: Option<&str>,
    account_rights: &str,
    inheritable: bool,
) -> std::io::Result<()> {
    use std::ptr::{null, null_mut};
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SetNamedSecurityInfoW,
        SDDL_REVISION_1, SE_FILE_OBJECT,
    };
    use windows_sys::Win32::Security::{
        DACL_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
    };
    let sddl = match account_sid {
        Some(account_sid) if account_rights == "FR" => {
            managed_read_acl_sddl(account_sid, inheritable)
        }
        Some(account_sid) => {
            let inheritance = if inheritable { "OICI" } else { "" };
            format!(
                "D:P(A;{inheritance};FA;;;SY)(A;{inheritance};FA;;;BA)(A;{inheritance};{account_rights};;;{account_sid})"
            )
        }
        None => system_admin_acl_sddl(inheritable),
    };
    let descriptor_text = sddl
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let mut descriptor = null_mut();
    let mut size = 0u32;
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            descriptor_text.as_ptr(),
            SDDL_REVISION_1,
            &mut descriptor,
            &mut size,
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error());
    }
    let dacl = match extract_dacl(descriptor) {
        Ok(dacl) => dacl,
        Err(error) => {
            unsafe { LocalFree(descriptor.cast()) };
            return Err(error);
        }
    };
    let name = path
        .to_string_lossy()
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let status = unsafe {
        SetNamedSecurityInfoW(
            name.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            null_mut(),
            null_mut(),
            dacl.cast(),
            null(),
        )
    };
    unsafe { LocalFree(descriptor.cast()) };
    if status == 0 {
        Ok(())
    } else {
        Err(std::io::Error::from_raw_os_error(status as i32))
    }
}

#[cfg(windows)]
fn extract_dacl(
    descriptor: windows_sys::Win32::Security::PSECURITY_DESCRIPTOR,
) -> std::io::Result<*mut windows_sys::Win32::Security::ACL> {
    use std::ptr::null_mut;
    use windows_sys::Win32::Security::GetSecurityDescriptorDacl;

    let mut present = 0;
    let mut defaulted = 0;
    let mut dacl = null_mut();
    if unsafe { GetSecurityDescriptorDacl(descriptor, &mut present, &mut dacl, &mut defaulted) }
        == 0
        || present == 0
        || dacl.is_null()
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "generated ACL has no DACL",
        ));
    }
    Ok(dacl)
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

    #[cfg(windows)]
    #[test]
    fn managed_read_acl_grants_service_read_only_and_admin_full_control() {
        let acl = managed_read_acl_sddl("S-1-5-21-test", false);
        assert_eq!(acl, "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;S-1-5-21-test)");
        assert_eq!(
            managed_read_acl_sddl("S-1-5-21-test", true),
            "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FR;;;S-1-5-21-test)"
        );
        assert_eq!(system_admin_acl_sddl(false), "D:P(A;;FA;;;SY)(A;;FA;;;BA)");
        assert!(!system_admin_acl_sddl(false).contains("gnxnodesvc"));
    }

    #[cfg(windows)]
    #[test]
    fn dacl_extraction_returns_pacl_from_generated_descriptor() {
        use std::ptr::null_mut;
        use windows_sys::Win32::Foundation::LocalFree;
        use windows_sys::Win32::Security::Authorization::{
            ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
        };
        let text = "D:P(A;;FA;;;SY)(A;;FA;;;BA)"
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect::<Vec<_>>();
        let mut descriptor = null_mut();
        assert_ne!(
            unsafe {
                ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    text.as_ptr(),
                    SDDL_REVISION_1,
                    &mut descriptor,
                    null_mut(),
                )
            },
            0
        );
        let dacl = extract_dacl(descriptor).unwrap();
        assert!(!dacl.is_null());
        unsafe { LocalFree(descriptor.cast()) };
    }

    #[cfg(windows)]
    #[test]
    fn profile_lookup_uses_sid_profile_list_without_creating_a_profile() {
        // This synthetic SID must not exist; lookup failure proves the helper
        // is read-only and no longer delegates profile creation to CreateProfile.
        assert!(profile_path("S-1-5-21-0-0-0-0").is_err());
    }

    #[cfg(windows)]
    #[test]
    fn new_account_uses_normal_local_account_flag() {
        use windows_sys::Win32::NetworkManagement::NetManagement::UF_NORMAL_ACCOUNT;

        assert_ne!(managed_account_flags() & UF_NORMAL_ACCOUNT, 0);
    }

    #[cfg(windows)]
    #[test]
    fn profile_bootstrap_error_has_stable_sanitized_code() {
        let error = profile_bootstrap_error(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "access denied",
        ));
        assert_eq!(
            error.to_string(),
            "ACCOUNT_PROFILE_BOOTSTRAP_FAILED: access denied"
        );
    }

    #[cfg(windows)]
    #[test]
    fn wsl_command_boundary_uses_windows_identity_without_linux_user_switch() {
        let command = windows_command_line(&[
            "--distribution".into(),
            "gnx-node".into(),
            "--".into(),
            "/usr/bin/id".into(),
        ]);
        assert!(command.starts_with("wsl.exe --distribution gnx-node -- /usr/bin/id"));
        let with_space = windows_command_line(&[
            "--import".into(),
            r"C:\Program Files\GnX Node\payload.tar".into(),
        ]);
        assert!(with_space.contains(r#""C:\Program Files\GnX Node\payload.tar""#));
        assert!(!command.contains("--user"));
        assert!(!command.contains("password"));
    }

    #[test]
    fn managed_process_boundary_uses_logon_token_api() {
        let source = include_str!("dedicated_account.rs");
        assert!(source.contains("LogonUserW"));
        assert!(source.contains("CreateProcessAsUserW"));
        // LocalSystem cannot use the credential-bearing CreateProcessWithLogonW
        // boundary because it has no logon SID; no call site may return.
        let forbidden_call = ["CreateProcessWithLogonW", "("].concat();
        assert!(!source.contains(&forbidden_call));
        assert!(source.contains("LoadUserProfileW"));
        assert!(source.contains("CreateEnvironmentBlock"));
        assert!(source.contains("DestroyEnvironmentBlock"));
        assert!(source.contains("UnloadUserProfile"));
    }

    #[cfg(windows)]
    #[test]
    fn profile_security_accepts_standard_owner_and_requires_service_access() {
        let source = include_str!("dedicated_account.rs");
        let removed_owner_mutator = ["set_profile", "_owner"].concat();
        assert!(!source.contains(&removed_owner_mutator));
        assert!(source.contains("validate_profile_security(&profile, &sid)?"));
        assert!(source.contains("WinBuiltinAdministratorsSid"));
        assert!(source.contains("WinLocalSystemSid"));
        assert!(source.contains("GetAce"));
        assert!(source.contains("FILE_ALL_ACCESS"));
        assert!(source.contains("FILE_ATTRIBUTE_REPARSE_POINT"));
        assert!(source.contains("OWNER_SECURITY_INFORMATION"));
        assert!(source.contains("DACL_SECURITY_INFORMATION"));
    }
}
