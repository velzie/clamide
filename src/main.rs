use num_traits::Num;
use proc_maps::get_process_maps;
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
    opts.optopt(
        "",
        "alloc",
        "allocates the provided input onto the program's memory",
        "",
    );
    opts.optopt(
        "",
        "setregs",
        "specify the user_regs_struct to set. Ex: --setregs \"rip=3123789123,rax=32\". This can be used to jump program flow",
        "",
    );
    opts.optflag("", "getregs", "print registers");
    opts.optflag(
        "",
        "getstart",
        "prints the starting address of the targeted program",
    );
    opts.optflag("", "stop", "pause proccess");
    opts.optflag("", "resume", "resume paused proccess");
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

        for value in &matches.free {
            regs.push(mmap_value(&proc, value.clone()).unwrap());
        }

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

        match syscalls::Errno::from_ret(p.rax as usize) {
            Ok(result) => {
                log::info!("Success executing {}", syscall);
                println!("{}", result);
            }
            Err(errno) => {
                log::error!(
                    "Syscall returned errno {}. {}",
                    errno.name().unwrap_or_default(),
                    errno.description().unwrap_or_default(),
                );
            }
        }
    } else if let Some(value) = matches.opt_str("alloc") {
        let addr = mmap_value(&proc, value.clone()).unwrap();
        log::info!("alloc'd {} bytes of {} to {}", 0, value, addr);
        println!("{}", addr);
    }

    if matches.opt_present("getregs") {
        log::trace!("{:#?}", proc.getregs());
    }

    if let Some(regsstr) = matches.opt_str("setregs") {
        let mut regs = proc.getregs().unwrap();
        for regstr in regsstr.split(",") {
            let (name, valstr) = regstr.split_once("=").unwrap();
            let val = parse_int(&proc, valstr).unwrap();
            match name {
                "rax" => regs.rax = val,
                "rcx" => regs.rcx = val,
                "rdx" => regs.rdx = val,
                "rbx" => regs.rbx = val,
                "rsi" => regs.rsi = val,
                "rdi" => regs.rdi = val,
                "rsp" => regs.rsp = val,
                "rbp" => regs.rbp = val,

                "r8" => regs.r8 = val,
                "r9" => regs.r9 = val,
                "r11" => regs.r11 = val,
                "r12" => regs.r12 = val,
                "r13" => regs.r13 = val,
                "r14" => regs.r14 = val,
                "r15" => regs.r15 = val,
                "orig_rax" => regs.orig_rax = val,
                "cs" => regs.cs = val,
                "eflags" => regs.eflags = val,
                "ss" => regs.ss = val,
                "fs_base" => regs.fs_base = val,
                "gs_base" => regs.gs_base = val,

                "rip" => regs.rip = val,
                _ => panic!("{} isn't an implemented register on x86_64", name),
            }
        }
        proc.setregs(regs).unwrap();
    }
    if matches.opt_present("getstart") {
        println!("{}", proc.startptr);
    }

    if matches.opt_present("stop") {
        proc.stop().unwrap();
    }
    if matches.opt_present("resume") {
        proc.resume().unwrap();
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

    if dtype == "int" || dtype == "ptr" {
        Ok(parse_int(proc, &value).unwrap())
    } else if dtype == "str" || dtype == "string" {
        Ok(proc.put_cstr(&value).unwrap().address())
    } else if dtype == "array" || dtype == "arr" {
        let mut ptrs = vec![];
        log::trace!("{}", value);
        for v in value.split(",") {
            ptrs.push(mmap_value(&proc, v.to_string()).unwrap());
        }

        let (_, ints, _) = unsafe { ptrs.align_to() };

        Ok(proc.put_bytes(ints).unwrap().address())
    } else if dtype == "bytes" {
        let mut bytes: Vec<u8> = vec![];
        for v in value.split(",") {
            bytes.push(parse_byte(v).unwrap());
        }
        Ok(proc.put_bytes(&bytes).unwrap().address())
    } else {
        panic!()
    }
}
fn parse_int(proc: &UserProcess, inp: &str) -> Result<u64, Box<dyn Error>> {
    let mut input = inp.to_string();
    let mut offset = 0;
    let mut radix = 10;
    if input.chars().nth(0).unwrap() == 'r' {
        offset = proc.startptr;
        input.remove(0);
    }
    if input.chars().nth(0).unwrap() == 'x' {
        radix = 16;
        input.remove(0);
    }
    if input.len() > 1 && input.chars().nth(1).unwrap() == 'x' {
        radix = 16;
        input.remove(0);
        input.remove(0);
    }
    dbg!(&input);
    Ok(offset + u64::from_str_radix(&input, radix)?)
}
fn parse_byte(inp: &str) -> Result<u8, Box<dyn Error>> {
    let mut input = inp.to_string();
    let mut radix = 10;
    if input.chars().nth(0).unwrap() == 'x' {
        radix = 16;
        input.remove(0);
    }
    if input.chars().nth(1).unwrap() == 'x' {
        radix = 16;
        input.remove(0);
        input.remove(1);
    }
    Ok(u8::from_str_radix(&input, radix)?)
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
