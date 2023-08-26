use napi::bindgen_prelude::*;
use napi_derive::napi;

use crate::util::get_last_error;
use winapi::{
    ctypes::c_void,
    shared::basetsd::SIZE_T,
    um::{
        memoryapi::{ReadProcessMemory, VirtualProtectEx, WriteProcessMemory},
        winnt::HANDLE,
    },
};

#[napi(
    ts_args_type = "processHandle: ExternalObject<unknown>, address: number, size: number, protection: number"
)]
pub fn set_protection(
    process_handle: External<HANDLE>,
    address: i64,
    size: u32,
    protection: u32,
) -> Result<u32> {
    let mut old_protection: u32 = 0;

    let result = unsafe {
        VirtualProtectEx(
            *process_handle as *mut _,
            address as *mut _,
            size as SIZE_T,
            protection,
            &mut old_protection,
        )
    };

    if result == 0 {
        return Err(Error::new(Status::GenericFailure, get_last_error()?));
    }

    return Ok(old_protection);
}

#[napi(ts_args_type = "processHandle: ExternalObject<unknown>, address: number, size: number")]
pub fn read_buffer(process_handle: External<HANDLE>, address: i64, size: u32) -> Result<Buffer> {
    let mut buffer: Vec<u8> = vec![0; size as usize];
    let mut read_bytes: SIZE_T = 0;

    let result = unsafe {
        ReadProcessMemory(
            *process_handle,
            address as *const c_void,
            buffer.as_mut_ptr() as *mut _,
            size as usize,
            &mut read_bytes,
        )
    };

    if result == 0 {
        return Err(Error::new(Status::GenericFailure, get_last_error()?));
    }

    buffer.resize(read_bytes as usize, 0);

    Ok(buffer.into())
}

#[napi(ts_args_type = "processHandle: ExternalObject<unknown>, address: number, buffer: Buffer")]
pub fn write_buffer(process_handle: External<HANDLE>, address: i64, buffer: Buffer) -> Result<()> {
    let mut written_bytes: SIZE_T = 0;

    let result = unsafe {
        WriteProcessMemory(
            *process_handle,
            address as *mut _,
            buffer.as_ptr() as *mut _,
            buffer.len(),
            &mut written_bytes,
        )
    };

    if result == 0 {
        return Err(Error::new(Status::GenericFailure, get_last_error()?));
    }

    return Ok(());
}

// Scan for IDA style pattern in memory
#[napi]
pub fn pattern_scan(
    process_handle: External<HANDLE>,
    pattern: String,
    from_addr: i64,
    to_addr: i64,
) -> Result<i64> {
    // Pattern being: "6D 2E 61 ?? 6E 2E"
    // Where ?? is a wildcard byte
    let pattern_bytes: Vec<u8> = pattern
        .split(" ")
        .map(|byte| {
            if byte == "??" {
                return 0x3F; // Wildcard byte '?'
            }

            return u8::from_str_radix(byte, 16).unwrap();
        })
        .collect();

    let step_size = 0x50;

    for i in (from_addr..to_addr).step_by(step_size as usize) {
        let buffer = read_buffer(External::new(*process_handle), i, step_size)?;
        let mut found = true;

        for j in 0..pattern_bytes.len() {
            if pattern_bytes[j] != buffer[j] {
                found = false;
                break;
            }
        }

        if found {
            return Ok(i);
        }
    }
    return Err(Error::new(Status::GenericFailure, "Pattern not found"));
}

#[test]
fn test_set_protection() {
    let process_handle = super::process::open_process_name("Notepad.exe".to_string()).unwrap();
    let value = set_protection(process_handle, 0x7FFF33DB3930, 4, 0x40).unwrap();
    assert!(value == 4);
}

#[test]
fn test_read_4bytes_from_notepad() {
    let process_handle = super::process::open_process_name("Notepad.exe".to_string()).unwrap();
    let value = read_buffer(process_handle, 0x7FFF33DB3930, 4).unwrap();
    println!("Value: {}", char::from(value[0]));
    assert!(value[0] > 0);
}

#[test]
fn test_write_4bytes_to_notepad() {
    let process_handle = super::process::open_process_name("Notepad.exe".to_string()).unwrap();
    let value = write_buffer(
        process_handle,
        0x7FFF33DB3930,
        vec![b'm', b'.', b'a', b'.', b'n', b'.'].into(),
    )
    .unwrap();
    assert!(value == ());
}

#[test]
fn test_pattern_scanner() {
    let process_handle = super::process::open_process_name("Notepad.exe".to_string()).unwrap();
    let module_info = super::module::get_module_entry32(
        "Notepad.exe".to_string(),
        "textinputframework.dll".to_string(),
    )
    .unwrap();
    let value = pattern_scan(
        process_handle,
        "6D 00 61 00 6E 00 00 00".to_string(),
        module_info.mod_base_addr as i64,
        module_info.mod_base_addr as i64 + module_info.dw_size as i64,
    )
    .unwrap();
    assert!(value > 0);
}
