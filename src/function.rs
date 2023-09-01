// Credit to: https://github.com/Rob--/memoryjs/blob/master/lib/functions.h

use std::env::args;

use napi::{bindgen_prelude::*, NapiValue};
use napi_derive::napi;
use winapi::{
    shared::{minwindef::LPVOID, ntdef::HANDLE},
    um::{
        memoryapi::{VirtualAllocEx, VirtualFreeEx, WriteProcessMemory},
        processthreadsapi::{CreateRemoteThread, GetExitCodeThread},
        synchapi::WaitForSingleObject,
        winbase::INFINITE,
        winnt::{MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_EXECUTE_READWRITE},
    },
};

#[napi]
pub enum FnType {
    Void,
    String,
    Char,
    Bool,
    Int,
    Double,
    Float,
}

#[napi(object)]
pub struct FnReturnValue {
    pub return_value: u32,
    pub return_string: String,
    pub exit_code: u32,
}

#[napi(object)]
pub struct FnArgument {
    pub arg_type: FnType,
    pub arg_value: String,
}

fn reserve_string(process_handle: External<HANDLE>, value: String, size: usize) -> LPVOID {
    let memory_address = unsafe {
        VirtualAllocEx(
            *process_handle,
            std::ptr::null_mut(),
            size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        )
    };

    let value = value.as_bytes();

    unsafe {
        WriteProcessMemory(
            *process_handle,
            memory_address,
            value.as_ptr() as _,
            size,
            std::ptr::null_mut(),
        )
    };

    memory_address
}

// This module lets you run a function stored in an external process with the specified arguments.
#[napi]
pub fn call(
    process_handle: External<HANDLE>,
    args: Vec<FnArgument>,
    return_type: FnType,
    address: i64,
) -> Result<FnReturnValue> {
    let mut args_shellcode: Vec<u8> = Vec::new();

    // Reverse the arguments so that they are in the correct order.
    let mut args = args;
    args.reverse();

    // Push the arguments onto the stack.
    for arg in &args {
        match arg.arg_type {
            FnType::String => {
                let args_length = arg.arg_value.len();
                let memory_address = reserve_string(
                    External::new(*process_handle),
                    arg.arg_value.clone(),
                    args_length * std::mem::size_of::<u16>(),
                );
                args_shellcode.push(0x68);

                // Little endian representation
                for i in 0..4 {
                    let shifted = ((memory_address as i64 >> (i * 8)) & 0xFF) as u8;
                    args_shellcode.push(shifted);
                }
            }
            FnType::Char => {
                args_shellcode.push(0x6a);
                args_shellcode.push(arg.arg_value.chars().next().unwrap() as u8);
            }
            FnType::Bool => {
                args_shellcode.push(0x6a);
                args_shellcode.push(arg.arg_value.parse::<u8>().unwrap());
            }
            FnType::Int => {
                args_shellcode.push(0x68);
                args_shellcode
                    .extend_from_slice(&arg.arg_value.parse::<i32>().unwrap().to_le_bytes());
            }
            FnType::Double => {
                args_shellcode.push(0x68);
                args_shellcode
                    .extend_from_slice(&arg.arg_value.parse::<i64>().unwrap().to_le_bytes());
            }
            FnType::Float => {
                args_shellcode.push(0x68);
                args_shellcode
                    .extend_from_slice(&arg.arg_value.parse::<i32>().unwrap().to_le_bytes());
            }
            _ => {}
        }
    }

    let mut call_shellcode: Vec<u8> = Vec::new();

    let args_length = args.len().clone() as u8;

    let asm_stack = [0xE8, 0x00, 0x00, 0x00, 0x00, 0x83, 0xC4, args_length * 4];

    call_shellcode.extend_from_slice(&asm_stack);

    let asm_return = match return_type {
        FnType::Float => vec![0xD9, 0x1C, 0x25],
        FnType::Double => vec![0xDD, 0x1C, 0x25],
        _ => vec![0xA3],
    };

    call_shellcode.extend_from_slice(&asm_return);

    for i in 0..4 {
        let shifted = ((address >> (i * 8)) & 0xFF) as u8;
        call_shellcode.push(shifted);
    }

    call_shellcode.push(0xC3);

    // Concatenate teh arg shellcode and the call shellcode
    let mut shellcode = [args_shellcode.clone(), call_shellcode].concat();

    let address_shellcode_offset = args_shellcode.len() as u64 + 5;

    // Allocate space for the shellcode
    let size = shellcode.len() * std::mem::size_of::<u8>();

    let memory_address = unsafe {
        VirtualAllocEx(
            *process_handle,
            std::ptr::null_mut(),
            size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        )
    };

    let relative = address - memory_address as i64 - address_shellcode_offset as i64;

    // Write the relative address to the shellcode
    for i in 0..4 {
        let shifted = ((relative >> (i * 8)) & 0xFF) as u8;
        shellcode[args_shellcode.len() + i + 1] = shifted;
    }

    // Write the shellcode to the allocated memory
    unsafe {
        WriteProcessMemory(
            *process_handle,
            memory_address,
            shellcode.as_ptr() as _,
            size,
            std::ptr::null_mut(),
        )
    };

    // Execute the shellcode
    let thread = unsafe {
        CreateRemoteThread(
            *process_handle,
            std::ptr::null_mut(),
            0,
            std::mem::transmute(memory_address),
            memory_address, // Use memory_address as the thread parameter
            0,
            std::ptr::null_mut(),
        )
    };

    let mut return_value: FnReturnValue = FnReturnValue {
        return_value: 0,
        return_string: String::from(""),
        exit_code: 0,
    };

    if thread.is_null() {
        return_value.exit_code = 999;
        return Err(Error::new(
            Status::GenericFailure,
            "Failed to create remote thread",
        ));
    }

    unsafe { WaitForSingleObject(thread, INFINITE) };
    unsafe { GetExitCodeThread(thread, &mut return_value.exit_code) };

    // Handle return value

    // Free the allocated memory
    unsafe { VirtualFreeEx(*process_handle, memory_address, size, MEM_RELEASE) };

    Ok(return_value)
}

#[test]
fn test_call() {
    let args: Vec<FnArgument> = vec![
        FnArgument {
            arg_type: FnType::Int,
            arg_value: String::from("1"),
        },
        FnArgument {
            arg_type: FnType::Int,
            arg_value: String::from("2"),
        },
    ];

    let process_handle = super::process::open_process_name("Notepad.exe".to_string()).unwrap();

    let module_handle = super::module::get_module_handle(
        "Notepad.exe".to_string(),
        "textinputframework.dll".to_string(),
    )
    .unwrap();

    let module_info =
        super::module::get_module_information(External::new(*process_handle), module_handle)
            .unwrap();

    let address_function = super::memory::pattern_scan(
        External::new(*process_handle),
        "55 8B EC 83 EC 08 53 56 57 68".to_string(),
        module_info.base_of_dll,
        module_info.base_of_dll + module_info.size_of_image as i64,
    )
    .unwrap();

    let result = call(process_handle, args, FnType::Int, address_function);

    assert!(result.is_ok());
}
