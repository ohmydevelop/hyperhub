//! Validate the verifier through its already-open handle, avoiding path races.
use std::io;
use std::os::windows::io::AsRawHandle;
use windows_sys::Win32::{
    Foundation::{CloseHandle, LocalFree},
    Security::{
        Authorization::{GetSecurityInfo, SE_FILE_OBJECT},
        EqualSid, GetAce, GetTokenInformation, IsValidSid, TokenOwner, TokenUser,
        ACCESS_ALLOWED_ACE, ACE_HEADER, DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION,
        TOKEN_OWNER, TOKEN_QUERY, TOKEN_USER,
    },
    System::Threading::{GetCurrentProcess, OpenProcessToken},
};
pub(super) fn validate(file: &std::fs::File) -> io::Result<()> {
    unsafe {
        let mut token = std::ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return Err(io::Error::last_os_error());
        }
        let result = (|| {
            let mut size = 0;
            GetTokenInformation(token, TokenUser, std::ptr::null_mut(), 0, &mut size);
            if size < std::mem::size_of::<TOKEN_USER>() as u32 {
                return Err(super::invalid("cannot identify verifier owner"));
            }
            // usize alignment is required by TOKEN_USER on x64.
            let mut buffer = vec![0usize; (size as usize).div_ceil(std::mem::size_of::<usize>())];
            if GetTokenInformation(
                token,
                TokenUser,
                buffer.as_mut_ptr().cast(),
                size,
                &mut size,
            ) == 0
            {
                return Err(io::Error::last_os_error());
            }
            let user = &*buffer.as_ptr().cast::<TOKEN_USER>();
            let mut owner_size = 0;
            GetTokenInformation(token, TokenOwner, std::ptr::null_mut(), 0, &mut owner_size);
            if owner_size < std::mem::size_of::<TOKEN_OWNER>() as u32 {
                return Err(super::invalid("cannot identify token default owner"));
            }
            let mut owner_buffer =
                vec![0usize; (owner_size as usize).div_ceil(std::mem::size_of::<usize>())];
            if GetTokenInformation(
                token,
                TokenOwner,
                owner_buffer.as_mut_ptr().cast(),
                owner_size,
                &mut owner_size,
            ) == 0
            {
                return Err(io::Error::last_os_error());
            }
            let default_owner = &*owner_buffer.as_ptr().cast::<TOKEN_OWNER>();
            let mut owner = std::ptr::null_mut();
            let mut acl = std::ptr::null_mut();
            let mut descriptor = std::ptr::null_mut();
            let error = GetSecurityInfo(
                file.as_raw_handle(),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                &mut owner,
                std::ptr::null_mut(),
                &mut acl,
                std::ptr::null_mut(),
                &mut descriptor,
            );
            if error != 0 {
                return Err(io::Error::from_raw_os_error(error as i32));
            }
            let check = (|| {
                if owner.is_null()
                    || IsValidSid(owner) == 0
                    || (EqualSid(owner, user.User.Sid) == 0
                        && EqualSid(owner, default_owner.Owner) == 0)
                    || acl.is_null()
                {
                    return Err(super::invalid(
                        "attachment verifier owner or ACL is not private",
                    ));
                }
                for index in 0..u32::from((*acl).AceCount) {
                    let mut raw = std::ptr::null_mut();
                    if GetAce(acl, index, &mut raw) == 0 {
                        return Err(io::Error::last_os_error());
                    }
                    let header = &*raw.cast::<ACE_HEADER>();
                    // The writer installs only simple allow entries for this exact user.
                    // Unknown/object/callback entries are rejected rather than guessed at.
                    if header.AceType != 0
                        || usize::from(header.AceSize) < std::mem::size_of::<ACCESS_ALLOWED_ACE>()
                    {
                        return Err(super::invalid(
                            "attachment verifier has unsupported access entries",
                        ));
                    }
                    let entry = &*raw.cast::<ACCESS_ALLOWED_ACE>();
                    let sid = std::ptr::addr_of!(entry.SidStart).cast_mut().cast();
                    if IsValidSid(sid) == 0 || EqualSid(sid, user.User.Sid) == 0 {
                        return Err(super::invalid(
                            "attachment verifier grants another principal access",
                        ));
                    }
                }
                if (*acl).AceCount == 0 {
                    return Err(super::invalid("attachment verifier has an empty ACL"));
                }
                Ok(())
            })();
            LocalFree(descriptor);
            check
        })();
        CloseHandle(token);
        result
    }
}
