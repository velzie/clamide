use std::{
    env,
    error::Error,
    ffi::{CStr, CString},
    io::{stdin, Read},
    num::ParseIntError,
    os::{raw::c_void, unix::process::parent_id},
    ptr::null,
    str::FromStr,
    usize,
};

use getopts::Options;

use clamide::{UserProcess, UserProcessMemory};
use nix::{
    libc::{user_regs_struct, MAP_ANONYMOUS, MAP_PRIVATE, PROT_READ, PROT_WRITE},
    sys::ptrace,
    unistd::Pid,
};
use sysinfo::{PidExt, ProcessExt, System, SystemExt};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum HostError {
    #[error("Process not found `{0}`")]
    ProcessNotFound(String),
    #[error("Nix Error `{0}`")]
    NixError(#[from] nix::errno::Errno),
}

type HostResult<T> = Result<T, HostError>;

fn main() -> HostResult<()> {
    pretty_env_logger::formatted_builder()
        .filter_level(log::LevelFilter::Trace)
        .init();

    let args: Vec<String> = env::args().collect();

    let mut opts = Options::new();
    opts.optopt("p", "process", "specify PID or the name of a proccess", "");
    opts.optopt("", "syscall", "specify syscall and arguments", "");
    opts.optopt("", "shellcode", "specify shellcode to inject", "");
    opts.optopt("", "mmap", "maps input onto the program", "");
    let matches = match opts.parse(&args[1..]) {
        Ok(m) => m,
        Err(f) => {
            panic!("{}", f.to_string())
        }
    };

    let pid = if let Some(pid_or_name) = matches.opt_str("p") {
        getpid(&pid_or_name).unwrap()
    } else {
        Pid::from_raw(parent_id() as i32)
    };
    let proc = UserProcess::attach(pid).unwrap();

    if let Some(input) = matches.opt_str("shellcode") {
        let shellcode = parse_shellcode(&input);

        proc.insert_shellcode(&shellcode).unwrap();
    } else if let Some(syscall_name) = matches.opt_str("syscall") {
        let syscall = syscalls::Sysno::from_str(&syscall_name).unwrap();

        let mut regs: Vec<u64> = vec![];

        for value in matches.free {
            regs.push(mmap_value(&proc, value).unwrap());
        }
        dbg!(&regs);

        // let addr = proc.put_cstr_vec(vec!["ls","-h"]);

        let p = proc
            .sys_call(
                syscall,
                regs.get(0).unwrap_or(&0).clone(),
                regs.get(1).unwrap_or(&0).clone(),
                regs.get(2).unwrap_or(&0).clone(),
                regs.get(3).unwrap_or(&0).clone(),
                regs.get(4).unwrap_or(&0).clone(),
                regs.get(5).unwrap_or(&0).clone(),
            )
            .unwrap();
        dbg!(syscalls::Errno::from_ret(p.rax as usize).unwrap());
    } else if let Some(value) = matches.opt_str("mmap") {
        let addr = mmap_value(&proc, value.clone()).unwrap();

        println!("mmapp'd {} to {}", value, addr);
    }

    // proc.sys_call(syscalls::Sysno::open, 0, 0, 0, r10, r8, r9)
    // proc.sys_call(syscalls::Sysno::execve, 44, 0, 0, 0, 0, 0);
    // unsafe {
    //     // let arg2 = proc.put_cstr_vec(vec!["/bin/sh"]).unwrap();
    //     //
    //
    //     dbg!(&args);
    //     let sycall = syscalls::Sysno::from_str(&args[1]).unwrap();
    //
    //     // let p = proc
    //     //     .sys_call(
    //     //         sycall,
    //     //         filepath_mem.address(),
    //     //         // 0,
    //     //         arg2.address(),
    //     //         0,
    //     //         0,
    //     //         0,
    //     //         0,
    //     //     )
    //     //     .unwrap();
    //     // dbg!(p);
    //     // dbg!(syscalls::Errno::from_ret(p.rax as usize).unwrap());
    // }

    Ok(())
}

fn mmap_value(proc: &UserProcess, value: String) -> Result<u64, HostError> {
    let (dtype, value) = value.split_at(value.find(":").unwrap());
    let (dtype, mut value): (String, String) = (dtype.into(), value.into());
    value.remove(0);

    dbg!(&dtype, &value);

    if dtype == "int" || dtype == "ptr" {
        Ok(value.parse().unwrap())
    } else if dtype == "str" || dtype == "string" {
        Ok(proc.put_cstr(&value).unwrap().address())
    } else if dtype == "array" || dtype == "arr" {
        let mut ptrs = vec![];
        for v in value.split(",") {
            dbg!(v);
            ptrs.push(mmap_value(&proc, v.to_string()));
        }
        dbg!(&ptrs);

        let (prefix, ints, suffix) = unsafe { ptrs.align_to() };

        dbg!(ints);

        Ok(proc.put_bytes(ints).unwrap().address())
    } else if dtype == "bytes" {
        let mut bytes: Vec<u8> = vec![];
        for v in value.split(",") {
            bytes.push(v.parse().unwrap());
        }
        Ok(proc.put_bytes(&bytes).unwrap().address())
    } else {
        panic!()
    }
}
fn parse_shellcode(input: &str) -> Vec<u8> {
    if input == "-" {
        let mut shellcode = String::new();
        stdin().read_to_string(&mut shellcode);
        return shellcode.as_bytes().to_vec();
    }

    return input
        .split("\\x")
        .skip(1)
        .map(|a| u8::from_str_radix(a, 16).unwrap())
        .collect();
}

fn getpid(pid: &str) -> Result<Pid, Box<dyn Error>> {
    match str::parse(pid) {
        Ok(pidn) => Ok(Pid::from_raw(pidn)),
        Err(_) => {
            // Create sysinfo object and refresh to collect current os state
            let mut sys = System::new_all();
            sys.refresh_all();

            // Find our target process or die
            let process = sys
                .processes_by_name(pid)
                .take(1)
                .next()
                .ok_or_else(|| HostError::ProcessNotFound(pid.to_string()))?;

            Ok(Pid::from_raw(process.pid().as_u32() as i32))
        }
    }
}
