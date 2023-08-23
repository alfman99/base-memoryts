use std::mem;

use napi::bindgen_prelude::*;
use napi_derive::napi;

use winapi::shared::minwindef::MAX_PATH;
use winapi::um::tlhelp32::{
    CreateToolhelp32Snapshot, Module32First, Module32Next, MAX_MODULE_NAME32, MODULEENTRY32,
    TH32CS_SNAPMODULE,
};

use crate::process::get_process_pid;
use crate::util::get_last_error;

#[napi(constructor)]
pub struct JSMODULEENTRY32 {
    pub dw_size: u32,
    pub th32_module_id: u32,
    pub th32_process_id: u32,
    pub glblcnt_usage: u32,
    pub proccnt_usage: u32,
    pub mod_base_addr: i64,
    pub mod_base_size: u32,
    // pub hModule: External<HANDLE>,
    pub sz_module: String,
    pub sz_exe_path: String,
}

#[napi]
pub fn list_modules(process_pid: u32) -> Result<Vec<JSMODULEENTRY32>> {
    let h_module_snap = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, process_pid) };

    let mut module_entries = Vec::<MODULEENTRY32>::new();

    let mut module_entry: MODULEENTRY32 = MODULEENTRY32 {
        dwSize: mem::size_of::<MODULEENTRY32>() as u32,
        th32ModuleID: 0,
        th32ProcessID: 0,
        GlblcntUsage: 0,
        ProccntUsage: 0,
        modBaseAddr: std::ptr::null_mut(),
        modBaseSize: 0,
        hModule: std::ptr::null_mut(),
        szModule: [0; MAX_MODULE_NAME32 + 1],
        szExePath: [0; MAX_PATH],
    };

    let mut result = unsafe { Module32First(h_module_snap, &mut module_entry) };

    if result == 0 {
        return Err(Error::new(Status::GenericFailure, get_last_error()?));
    }

    module_entries.push(module_entry);

    loop {
        result = unsafe { Module32Next(h_module_snap, &mut module_entry as *mut _) };

        if result == 0 {
            break;
        }

        module_entries.push(module_entry);
    }

    let mut js_module_entries = Vec::<JSMODULEENTRY32>::new();

    module_entries.iter().for_each(|&module| {
        let module_name = unsafe { std::ffi::CStr::from_ptr(module.szModule.as_ptr()) };
        let module_name_string = module_name.to_str().unwrap().to_string();

        let module_path = unsafe { std::ffi::CStr::from_ptr(module.szExePath.as_ptr()) };
        let module_path_string = module_path.to_str().unwrap().to_string();

        js_module_entries.push(JSMODULEENTRY32 {
            dw_size: module.dwSize,
            th32_module_id: module.th32ModuleID,
            th32_process_id: module.th32ProcessID,
            glblcnt_usage: module.GlblcntUsage,
            proccnt_usage: module.ProccntUsage,
            mod_base_addr: module.modBaseAddr as i64,
            mod_base_size: module.modBaseSize,
            // hModule: External::new(module.hModule),
            sz_module: module_name_string,
            sz_exe_path: module_path_string,
        });
    });

    Ok(js_module_entries)
}

#[napi]
pub fn get_module(process_name: String, module_name: String) -> Result<JSMODULEENTRY32> {
    let process_id = get_process_pid(process_name)?;

    let module_entries = list_modules(process_id)?;

    for module in module_entries {
        if module.sz_module == module_name {
            return Ok(module);
        }
    }

    return Err(Error::from_status(Status::Closing));
}

#[test]
fn test_list_proces_modules() {
    let process_id = super::process::get_process_pid("Notepad.exe".to_string());

    let process_id = match process_id {
        Ok(process) => process,
        Err(_) => {
            return assert!(false);
        }
    };

    let modules = list_modules(process_id);

    let modules = match modules {
        Ok(module) => module,
        Err(_) => {
            return assert!(false);
        }
    };

    for module in modules {
        println!("Module name: {}", module.sz_module);
        println!("Module base: {}", module.mod_base_addr);
        println!("----");
    }

    assert!(true);
}

#[test]
pub fn test_get_module() {
    let module = get_module("Notepad.exe".to_string(), "Notepad.exe".to_string());

    let module = match module {
        Ok(module) => module,
        Err(_) => {
            return assert!(false);
        }
    };

    println!("Module name: {}", module.sz_module);
    println!("Module base: {}", module.mod_base_addr);
    println!("----");

    assert!(true);
}
