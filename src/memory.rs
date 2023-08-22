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

#[napi]
pub fn set_protection(
    process_handle: External<HANDLE>,
    address: i64,
    size: u32,
    protection: u32,
) -> Result<u32> {
    let mut old_protection: u32 = 0;

    let result = unsafe {
        VirtualProtectEx(
            *process_handle,
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

#[napi]
pub fn read_buffer(process_handle: External<HANDLE>, address: i64, size: u32) -> Result<Vec<u8>> {
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

    Ok(buffer)
}

#[napi]
pub fn write_buffer(process_handle: External<HANDLE>, address: i64, buffer: Vec<u8>) -> Result<()> {
    let mut written_bytes: SIZE_T = 0;

    let result = unsafe {
        WriteProcessMemory(
            *process_handle,
            address as *mut _,
            buffer.as_ptr() as *mut _,
            buffer.capacity(),
            &mut written_bytes,
        )
    };

    if result == 0 {
        return Err(Error::new(Status::GenericFailure, get_last_error()?));
    }

    return Ok(());
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
        vec![b'm', b'.', b'a', b'.', b'n', b'.'],
    )
    .unwrap();
    assert!(value == ());
}
