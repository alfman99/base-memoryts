use napi::bindgen_prelude::*;
use napi_derive::napi;

use winapi::shared::minwindef::DWORD;
use winapi::um::handleapi::{CloseHandle, INVALID_HANDLE_VALUE};
use winapi::um::processthreadsapi::{GetProcessId, OpenProcess};
use winapi::um::psapi::GetProcessImageFileNameA;
use winapi::um::tlhelp32::{
    CreateToolhelp32Snapshot, Process32First, Process32Next, PROCESSENTRY32, TH32CS_SNAPPROCESS,
};
use winapi::um::winnt::{HANDLE, PROCESS_ALL_ACCESS};
use winapi::um::wow64apiset::IsWow64Process;

use crate::util::get_last_error;

#[napi(object)]
pub struct JSPROCESSENTRY32 {
    pub dw_size: u32,
    pub cnt_usage: u32,
    pub th32_process_id: u32,
    pub th32_default_heap_id: u32,
    pub th32_module_id: u32,
    pub cnt_threads: u32,
    pub th32_parent_process_id: u32,
    pub pc_pri_class_base: i32,
    pub dw_flags: u32,
    pub sz_exe_file: String,
}

#[napi]
pub fn list_all_running_processes() -> Result<Vec<JSPROCESSENTRY32>> {
    let snapshot_result: HANDLE = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };

    let snapshot_handle = match snapshot_result {
        INVALID_HANDLE_VALUE => return Err(Error::new(Status::GenericFailure, get_last_error()?)),
        _ => snapshot_result,
    };

    let mut process_entry = unsafe { std::mem::zeroed::<PROCESSENTRY32>() };

    process_entry.dwSize = std::mem::size_of::<PROCESSENTRY32>() as DWORD;

    if !unsafe { Process32First(snapshot_handle, &mut process_entry) != 0 } {
        unsafe { CloseHandle(snapshot_handle) };
        return Err(Error::new(Status::GenericFailure, get_last_error()?));
    }

    let mut process_list: Vec<JSPROCESSENTRY32> = Vec::new();

    while unsafe { Process32Next(snapshot_handle, &mut process_entry) != 0 } {
        let process_name = unsafe { std::ffi::CStr::from_ptr(process_entry.szExeFile.as_ptr()) };
        let process_name_string = process_name.to_str().unwrap().to_string();
        process_list.push(JSPROCESSENTRY32 {
            dw_size: process_entry.dwSize,
            cnt_usage: process_entry.cntUsage,
            th32_process_id: process_entry.th32ProcessID,
            th32_default_heap_id: process_entry.th32DefaultHeapID as u32,
            th32_module_id: process_entry.th32ModuleID,
            cnt_threads: process_entry.cntThreads,
            th32_parent_process_id: process_entry.th32ParentProcessID,
            pc_pri_class_base: process_entry.pcPriClassBase,
            dw_flags: process_entry.dwFlags,
            sz_exe_file: process_name_string,
        });
    }

    unsafe { CloseHandle(snapshot_handle) };

    return Ok(process_list);
}

#[napi(ts_return_type = "ExternalObject<HANDLE>")]
pub fn open_process_pid(process_pid: u32) -> Result<External<HANDLE>> {
    let process_handle = unsafe { OpenProcess(PROCESS_ALL_ACCESS, 0, process_pid) };

    if process_handle == std::ptr::null_mut() {
        return Err(Error::new(Status::GenericFailure, get_last_error()?));
    }

    return Ok(External::new(process_handle));
}

#[napi(ts_return_type = "ExternalObject<HANDLE>")]
pub fn open_process_name(process_name: String) -> Result<External<HANDLE>> {
    let processes = list_all_running_processes()?;

    let process = processes
        .iter()
        .find(|&process| process.sz_exe_file == process_name);

    if let Some(process) = process {
        let process_id = process.th32_process_id;
        return open_process_pid(process_id);
    }

    return Err(Error::from_status(Status::Closing));
}

#[napi]
pub fn get_process_pid(process_name: String) -> Result<u32> {
    let processes = list_all_running_processes()?;

    let process = processes
        .iter()
        .find(|&process| process.sz_exe_file == process_name);

    if let Some(process) = process {
        let process_id = process.th32_process_id;
        return Ok(process_id);
    }

    return Err(Error::from_status(Status::Closing));
}

#[napi(ts_args_type = "processHandle: ExternalObject<HANDLE>")]
pub fn close_process(process_handle: External<HANDLE>) -> Result<()> {
    let result = unsafe { CloseHandle(*process_handle) };

    if result == 0 {
        return Err(Error::new(Status::GenericFailure, get_last_error()?));
    }

    return Ok(());
}

#[napi(ts_args_type = "processHandle: ExternalObject<HANDLE>")]
pub fn is_process_x64(process_handle: External<HANDLE>) -> Result<bool> {
    let mut process_architecture = 0;

    let result = unsafe {
        IsWow64Process(
            *process_handle,
            &mut process_architecture as *mut i32 as *mut i32,
        )
    };

    if result == 0 {
        return Err(Error::new(Status::GenericFailure, get_last_error()?));
    }

    return Ok(process_architecture == 0);
}

#[napi(ts_args_type = "processHandle: ExternalObject<HANDLE>")]
pub fn process_handle_to_pid(process_handle: External<HANDLE>) -> Result<u32> {
    let process_id = unsafe { GetProcessId(*process_handle) };

    if process_id == 0 {
        return Err(Error::new(Status::GenericFailure, get_last_error()?));
    }

    return Ok(process_id);
}

#[napi(ts_args_type = "processName: string")]
pub fn process_name_to_pid(process_name: String) -> Result<u32> {
    let processes = list_all_running_processes()?;

    let process = processes
        .iter()
        .find(|&process| process.sz_exe_file == process_name);

    if let Some(process) = process {
        let process_id = process.th32_process_id;
        return Ok(process_id);
    }

    return Err(Error::from_status(Status::Closing));
}

#[napi(ts_args_type = "processHandle: ExternalObject<HANDLE>")]
pub fn process_handle_to_name(process_handle: External<HANDLE>) -> Result<String> {
    let mut process_name: [i8; 512] = [0; 512];

    let result = unsafe {
        GetProcessImageFileNameA(*process_handle, process_name.as_mut_ptr() as *mut i8, 512)
    };

    if result == 0 {
        return Err(Error::new(Status::GenericFailure, get_last_error()?));
    }

    let process_name = unsafe { std::ffi::CStr::from_ptr(process_name.as_ptr()) };
    let process_name_string = process_name.to_str().unwrap().to_string();

    return Ok(process_name_string);
}

#[napi(ts_args_type = "processPID: number")]
pub fn process_pid_to_name(process_pid: u32) -> Result<String> {
    let processes = list_all_running_processes()?;

    let process = processes
        .iter()
        .find(|&process| process.th32_process_id == process_pid);

    if let Some(process) = process {
        let process_name = &process.sz_exe_file;
        return Ok(process_name.to_string());
    }

    return Err(Error::from_status(Status::Closing));
}

#[test]
pub fn test_is_process_x64() {
    let process_handle = open_process_name("Notepad.exe".to_string()).unwrap();
    let is_process_x64 = is_process_x64(process_handle).unwrap();
    assert_eq!(is_process_x64, true);
}

#[test]
pub fn test_is_process_x86() {
    let process_handle = open_process_name("Spotify.exe".to_string()).unwrap();
    let is_process_x64 = is_process_x64(process_handle).unwrap();
    assert_eq!(is_process_x64, false);
}
