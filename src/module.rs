use napi::bindgen_prelude::*;
use napi_derive::napi;

use winapi::shared::minwindef::HMODULE;
use winapi::shared::ntdef::HANDLE;
use winapi::um::psapi::{EnumProcessModules, GetModuleFileNameExW};

#[napi(constructor)]
pub struct ModuleInfo {
    pub name: String,
    pub base_address: u32,
}

#[napi(ts_args_type = "process_handle: ExternalObject<unknown>")]
pub fn get_process_modules(process_handle: External<HANDLE>) -> Result<Vec<ModuleInfo>> {
    let mut module_handles = vec![0 as HMODULE; 1024];
    let mut needed: u32 = 0;

    let result = unsafe {
        EnumProcessModules(
            *process_handle,
            module_handles.as_mut_ptr() as *mut _,
            module_handles.capacity() as u32,
            &mut needed as *mut u32,
        )
    };

    if result == 0 {
        return Err(Error::from_status(Status::Closing));
    }

    let mut module_infos = Vec::<ModuleInfo>::new();

    for i in 0..(needed as usize / std::mem::size_of::<HMODULE>()) {
        let mut module_name: [u16; 260] = [0; 260];
        unsafe {
            GetModuleFileNameExW(
                *process_handle,
                module_handles[i],
                module_name.as_mut_ptr(),
                module_name.len() as u32,
            )
        };

        // Convert wide char array to a Rust String
        let module_full_path = String::from_utf16_lossy(&module_name);

        // Clean path by removing the null terminator, any trailing whitespace, and any trailing new lines
        let module_full_path = module_full_path
            .trim_matches(char::from(0))
            .trim_end()
            .trim_end_matches("\r\n")
            .to_string();

        // Clean name by removing the path, leaving only the module name and extension
        let module_name_str = module_full_path.split("\\").last().unwrap().to_string();

        module_infos.push(ModuleInfo {
            name: module_name_str,
            base_address: module_handles[i] as u32,
        });
    }

    Ok(module_infos)
}

#[test]
fn test_get_process_modules() {
    let process_handle = super::process::open_process_name("Notepad.exe".to_string());

    let process_handle = match process_handle {
        Ok(process) => process,
        Err(_) => {
            return assert!(false);
        }
    };

    let module_list = get_process_modules(process_handle);

    let module_list = match module_list {
        Ok(module) => module,
        Err(_) => {
            return assert!(false);
        }
    };

    for module in module_list {
        println!("Module name: {}", module.name);
        println!("Module base: {}", module.base_address);
        println!("----");
    }

    assert!(true);
}
