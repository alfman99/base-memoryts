use std::ptr;

use napi::bindgen_prelude::*;
use napi_derive::napi;

use crate::{process::open_process_name, util::get_last_error};
use winapi::{
    ctypes::c_void,
    shared::{basetsd::SIZE_T, minwindef::LPVOID},
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
pub fn read_byte(process_handle: External<HANDLE>, address: i64) -> Result<u8> {
    let mut value: u8 = 0;
    let mut read_bytes: SIZE_T = 0;

    let result = unsafe {
        ReadProcessMemory(
            *process_handle,
            address as usize as *mut _,
            ptr::addr_of_mut!(value) as *mut c_void,
            std::mem::size_of::<u8>(),
            &mut read_bytes,
        )
    };

    if result == 0 {
        return Err(Error::new(Status::GenericFailure, get_last_error()?));
    }

    return Ok(value);
}

#[napi]
pub fn write(
    process_handle: External<HANDLE>,
    address: i64,
    buffer: Vec<u8>,
    size: u32,
) -> Result<()> {
    let mut written_bytes: SIZE_T = 0;

    let result = unsafe {
        WriteProcessMemory(
            *process_handle,
            address as *mut _,
            buffer.as_ptr() as *mut _,
            size as usize,
            &mut written_bytes,
        )
    };

    if result == 0 || written_bytes != size as SIZE_T {
        return Err(Error::new(Status::GenericFailure, get_last_error()?));
    }

    return Ok(());
}

#[test]
fn test_read_byte_from_notepad() {
    let process_handle = open_process_name("Notepad.exe".to_string()).unwrap();
    let value = read_byte(process_handle, 0x7FF8041D3930).unwrap();
    println!("Value: {}", char::from(value));
    assert!(value > 0);
}
