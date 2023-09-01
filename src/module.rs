use std::mem;

use napi::bindgen_prelude::*;
use napi_derive::napi;

use winapi::shared::minwindef::{HMODULE, MAX_PATH};
use winapi::um::psapi::MODULEINFO;
use winapi::um::tlhelp32::{
    CreateToolhelp32Snapshot, Module32First, Module32Next, MAX_MODULE_NAME32, MODULEENTRY32,
    TH32CS_SNAPMODULE,
};
use winapi::um::winnt::HANDLE;

use crate::process::get_process_pid;
use crate::util::get_last_error;

#[napi]
pub struct JSMODULEENTRY32 {
    pub dw_size: u32,
    pub th32_module_id: u32,
    pub th32_process_id: u32,
    pub glblcnt_usage: u32,
    pub proccnt_usage: u32,
    pub mod_base_addr: i64,
    pub mod_base_size: u32,
    h_module: External<HMODULE>,
    pub sz_module: String,
    pub sz_exe_path: String,
}

#[napi]
impl JSMODULEENTRY32 {
    pub fn new() -> Self {
        JSMODULEENTRY32 {
            dw_size: 0,
            th32_module_id: 0,
            th32_process_id: 0,
            glblcnt_usage: 0,
            proccnt_usage: 0,
            mod_base_addr: 0,
            mod_base_size: 0,
            h_module: External::new(std::ptr::null_mut()),
            sz_module: String::new(),
            sz_exe_path: String::new(),
        }
    }

    #[napi(getter)]
    pub fn get_module_handle(&self) -> External<HMODULE> {
        External::new(*self.h_module)
    }
}

#[napi(object)]
pub struct JSLPMODULEINFO {
    pub base_of_dll: i64,
    pub size_of_image: u32,
    pub entry_point: i64,
}

// Lists all modules in a process
#[napi]
pub fn list_process_modules(process_pid: u32) -> Result<Vec<JSMODULEENTRY32>> {
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
            h_module: External::new(module.hModule),
            sz_module: module_name_string,
            sz_exe_path: module_path_string,
        });
    });

    Ok(js_module_entries)
}

// Get a module from a process by name
#[napi]
pub fn get_process_module_entry32(
    process_name: String,
    module_name: String,
) -> Result<JSMODULEENTRY32> {
    let process_id = get_process_pid(process_name)?;

    let module_entries = list_process_modules(process_id)?;

    for module in module_entries {
        if module.sz_module == module_name {
            return Ok(module);
        }
    }

    return Err(Error::from_status(Status::Closing));
}

// Get a module handle from a process by name
#[napi]
pub fn get_module_handle(process_name: String, module_name: String) -> Result<External<HMODULE>> {
    let module = get_process_module_entry32(process_name, module_name)?;

    Ok(module.get_module_handle())
}

// Get module information from a process handle and module handle
#[napi]
pub fn get_module_information(
    process_handle: External<HANDLE>,
    module_handle: External<HMODULE>,
) -> Result<JSLPMODULEINFO> {
    let mut module_info = unsafe { std::mem::zeroed::<MODULEINFO>() };

    let result = unsafe {
        winapi::um::psapi::GetModuleInformation(
            *process_handle,
            *module_handle,
            &mut module_info,
            std::mem::size_of::<MODULEINFO>() as u32,
        )
    };

    if result == 0 {
        return Err(Error::new(Status::GenericFailure, get_last_error()?));
    }

    Ok(JSLPMODULEINFO {
        base_of_dll: module_info.lpBaseOfDll as i64,
        size_of_image: module_info.SizeOfImage,
        entry_point: module_info.EntryPoint as i64,
    })
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

    let modules = list_process_modules(process_id);

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
    let module = get_process_module_entry32("Notepad.exe".to_string(), "Notepad.exe".to_string());

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

#[test]
pub fn test_get_module_handle() {
    let module_handle = get_module_handle(
        "Notepad.exe".to_string(),
        "textinputframework.dll".to_string(),
    );

    let module_handle = match module_handle {
        Ok(module_handle) => module_handle,
        Err(_) => {
            return assert!(false);
        }
    };

    assert!(true);
}
