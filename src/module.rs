// use napi::bindgen_prelude::*;
// use napi_derive::napi;

// use winapi::shared::minwindef::HMODULE;
// use winapi::shared::{minwindef::DWORD, ntdef::HANDLE};
// use winapi::um::psapi::{EnumProcessModules, GetModuleFileNameExW};

// #[napi(constructor)]
// pub struct ModuleInfo {
//     pub module_name: String,
//     pub module_base: DWORD,
//     pub module_size: DWORD,
// }

// #[napi]
// pub fn get_process_modules(process_handle: External<HANDLE>) -> Result<Vec<ModuleInfo>> {
//     let mut module_handles = Vec::<HMODULE>::with_capacity(1024);
//     let mut needed: u32 = 0;

//     let result = unsafe {
//         EnumProcessModules(
//             *process_handle,
//             module_handles.as_mut_ptr(),
//             std::mem::size_of::<[HMODULE; 1024]>() as u32,
//             &mut needed as *mut u32,
//         )
//     };

//     if result == 0 {
//         return Err(Error::from_status(Status::Closing));
//     }

//     let mut module_infos = Vec::<ModuleInfo>::new();

//     for i in 0..(needed as usize / std::mem::size_of::<HMODULE>()) {
//         let mut module_name: [u16; 260] = [0; 260];
//         unsafe {
//             GetModuleFileNameExW(
//                 *process_handle,
//                 module_handles[i],
//                 module_name.as_mut_ptr(),
//                 module_name.len() as u32,
//             )
//         };

//         // Convert wide char array to a Rust String
//         let module_name_str = String::from_utf16_lossy(&module_name);

//         module_infos.push(ModuleInfo {
//             module_name: module_name_str,
//             module_base: module_handles[i] as DWORD,
//             module_size: 0,
//         });
//     }

//     Ok(module_infos)
// }

// #[test]
// fn test_get_process_modules() {
//     let process_list = super::process::list_processes().unwrap();
//     let process = process_list
//         .iter()
//         .find(|&process| process.process_name == "Notepad.exe")
//         .unwrap();

//     let process_handle = super::process::open_process_pid(process.process_id).unwrap();

//     let module_list = get_process_modules(process_handle);

//     assert!(true);
// }
