use napi::bindgen_prelude::*;
use napi_derive::napi;

use winapi::shared::minwindef::DWORD;
use winapi::um::handleapi::{CloseHandle, INVALID_HANDLE_VALUE};
use winapi::um::processthreadsapi::OpenProcess;
use winapi::um::tlhelp32::{
    CreateToolhelp32Snapshot, Process32First, Process32Next, PROCESSENTRY32, TH32CS_SNAPPROCESS,
};
use winapi::um::winnt::{HANDLE, PROCESS_ALL_ACCESS};

use crate::util::get_last_error;

#[napi(constructor)]
pub struct ProcessInfo {
    pub process_name: String,
    pub process_id: DWORD,
}

#[napi]
pub fn list_processes() -> Result<Vec<ProcessInfo>> {
    let snapshot_result: HANDLE = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };

    let snapshot_handle = match snapshot_result {
        INVALID_HANDLE_VALUE => return Err(Error::new(Status::GenericFailure, get_last_error()?)),
        _ => snapshot_result,
    };

    let mut process_entry: PROCESSENTRY32 = unsafe { std::mem::zeroed() };

    process_entry.dwSize = std::mem::size_of::<PROCESSENTRY32>() as DWORD;

    if !unsafe { Process32First(snapshot_handle, &mut process_entry) != 0 } {
        unsafe { CloseHandle(snapshot_handle) };
        return Err(Error::new(Status::GenericFailure, get_last_error()?));
    }

    let mut process_list: Vec<ProcessInfo> = Vec::new();

    while unsafe { Process32Next(snapshot_handle, &mut process_entry) != 0 } {
        let process_name = unsafe { std::ffi::CStr::from_ptr(process_entry.szExeFile.as_ptr()) };
        let process_name_string = process_name.to_str().unwrap().to_string();
        process_list.push(ProcessInfo {
            process_name: process_name_string,
            process_id: process_entry.th32ProcessID,
        });
    }

    unsafe { CloseHandle(snapshot_handle) };

    return Ok(process_list);
}

#[napi]
pub fn open_process_pid(process_pid: u32) -> Result<External<HANDLE>> {
    let process_handle = unsafe { OpenProcess(PROCESS_ALL_ACCESS, 0, process_pid) };

    if process_handle == std::ptr::null_mut() {
        return Err(Error::new(Status::GenericFailure, get_last_error()?));
    }

    return Ok(External::new(process_handle));
}

#[napi]
pub fn open_process_name(process_name: String) -> Result<External<HANDLE>> {
    let processes = list_processes()?;

    let process = processes
        .iter()
        .find(|&process| process.process_name == process_name);

    if let Some(process) = process {
        let process_id = process.process_id;
        return open_process_pid(process_id);
    }

    return Err(Error::from_status(Status::Closing));
}

#[napi]
pub fn close_process(process_handle: External<HANDLE>) -> Result<()> {
    let result = unsafe { CloseHandle(*process_handle) };

    if result == 0 {
        return Err(Error::new(Status::GenericFailure, get_last_error()?));
    }

    return Ok(());
}
