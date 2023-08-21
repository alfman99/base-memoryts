use napi::bindgen_prelude::*;
use napi_derive::napi;
use winapi::{
    shared::{minwindef::DWORD, ntdef::HANDLE},
    um::{
        errhandlingapi::GetLastError,
        handleapi::CloseHandle,
        processthreadsapi::{GetCurrentProcess, OpenProcessToken},
        securitybaseapi::GetTokenInformation,
        winbase::{
            FormatMessageW, LocalFree, FORMAT_MESSAGE_ALLOCATE_BUFFER, FORMAT_MESSAGE_FROM_SYSTEM,
        },
        winnt::{TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY},
    },
};

pub fn get_last_error() -> Result<String> {
    let error_code = unsafe { GetLastError() };

    println!("[DEBUG] Error code: {}", error_code);

    let mut buffer: *mut i8 = std::ptr::null_mut();

    let length = unsafe {
        FormatMessageW(
            FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_ALLOCATE_BUFFER,
            std::ptr::null_mut(),
            error_code,
            0,
            &mut buffer as *mut _ as *mut u16,
            0,
            std::ptr::null_mut(),
        )
    };

    if length == 0 {
        return Ok(String::from("Failed to get last error"));
    }

    let error_message =
        unsafe { std::slice::from_raw_parts(buffer as *const u16, length as usize) };
    let message = String::from_utf16_lossy(error_message).to_string();

    // Free buffer
    unsafe { LocalFree(buffer as *mut winapi::ctypes::c_void) };

    Ok(message)
}

#[napi]
pub fn is_elevated_process() -> bool {
    let mut is_elevated: bool = false;
    let mut token: HANDLE = std::ptr::null_mut();

    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } != 0 {
        let mut elevation: TOKEN_ELEVATION = TOKEN_ELEVATION { TokenIsElevated: 0 };
        let mut token_sz: DWORD = std::mem::size_of::<TOKEN_ELEVATION>() as DWORD;

        if unsafe {
            GetTokenInformation(
                token,
                TokenElevation,
                &mut elevation as *mut TOKEN_ELEVATION as *mut winapi::ctypes::c_void,
                token_sz,
                &mut token_sz,
            )
        } != 0
        {
            is_elevated = if elevation.TokenIsElevated != 0 {
                true
            } else {
                false
            };
        }
    }
    if !token.is_null() {
        unsafe {
            CloseHandle(token);
        }
    }
    is_elevated
}

#[napi]
pub fn is_64bit_process() -> bool {
    std::mem::size_of::<usize>() == 8
}
