use std::vec;

use nix::{
    libc::{user_regs_struct, MAP_ANONYMOUS, MAP_PRIVATE, PROT_READ, PROT_WRITE},
    sys::{
        ptrace,
        signal::Signal::{self, SIGTRAP},
        wait::{waitpid, WaitStatus},
    },
    unistd::Pid,
};
use proc_maps::{MapRange, get_process_maps};
use syscalls::Sysno;

use thiserror::Error;

#[derive(Error, Debug)]
pub enum HostError {
    #[error("Process not found `{0}`")]
    ProcessNotFound(String),
    #[error("Nix Error `{0}`")]
    NixError(#[from] nix::errno::Errno),
    #[error("Unexpected Wait Status `{0:#?}`")]
    UnexpectedWaitStatus(WaitStatus),
    #[error("StdIo Error `{0}`")]
    Io(#[from] std::io::Error),
    #[error("Mmap Error `{0:#?}`")]
    MmapBadAddress(u64),
    #[error("Munmap Error `{0:#?}`")]
    MunmapFailed(u64),
}

pub type HostResult<T> = Result<T, HostError>;

pub struct UserProcessMemory<'a> {
    address: u64,
    owner: &'a UserProcess,
    len: u64,
}

impl<'a> UserProcessMemory<'a> {
    /// Getter for UserProcessMemory's start address
    pub fn address(&self) -> u64 {
        self.address
    }

    /// Getter for UserProcessMemory's length
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> u64 {
        self.len
    }
}

impl<'a> Drop for UserProcessMemory<'a> {
    /// Munmap's the memory on drop
    fn drop(&mut self) {
        log::warn!("should have deallocated! didn't")
        // match self.owner.deallocate_memory(self.address, self.len) {
        //     Ok(()) => log::trace!(
        //         "Successfully deallocated memory {:#X} with length {}",
        //         self.address,
        //         self.len
        //     ),
        //     Err(err) => log::error!(
        //         "Failed to deallocate memory {:#X} with length {}, Error: {:#?}",
        //         self.address,
        //         self.len,
        //         err
        //     ),
        // }
    }
}

pub struct UserProcess {
    pub pid: Pid,
    pub maps: Vec<MapRange>,
    pub startptr: u64,
}

impl UserProcess {
    /// Initializes the UserProcess
    /// Given you have a UserProcess instance it means the attach must of succeeded.
    /// Attach should be the only way to acquire a UserProcess.
    pub fn attach(pid: Pid) -> HostResult<Self> {
        ptrace::attach(pid)?;

        log::trace!("New UserProcess successfully attached to pid: {}", pid);
        let maps = get_process_maps(pid.as_raw())?;
        assert!(!maps.is_empty());
        let startptr = maps[0].start();
        Ok(Self { pid,maps,startptr:startptr as u64 })
    }

    /// Getter for UserProcess actively connected pid
    pub fn pid(&self) -> Pid {
        self.pid
    }

    pub fn put_bytes(&self, bytes: &[u8]) -> Result<UserProcessMemory, HostError> {
        let mut user_memory = self.allocate_memory(
            0,
            bytes.len() as u64,
            (PROT_READ | PROT_WRITE) as u64,
            (MAP_PRIVATE | MAP_ANONYMOUS) as u64,
            u64::MAX,
            0,
        )?;

        self.write_user_memory(&mut user_memory, 0, bytes)?;
        Ok(user_memory)
    }
    pub fn put_cstr(&self, cstr: &str) -> Result<UserProcessMemory, HostError> {
        self.put_bytes(cstr.as_bytes())
    }
    pub fn put_cstr_vec(&self, strvec: Vec<&str>) -> Result<UserProcessMemory, HostError> {
        let mut heap = vec![];
        for cstr in &strvec {
            let mem = self.put_cstr(cstr)?;
            heap.push(mem);
        }

        let mut ptrs = vec![];
        for mem in &heap {
            ptrs.push(mem.address());
        }

        let (_prefix, ints, _suffix) = unsafe { ptrs.align_to() };

        self.put_bytes(ints)
    }

    /// Uses mmap syscall with ptrace to allocate user process memory
    pub fn allocate_memory(
        &self,
        address: u64,
        len: u64,
        prot: u64,
        flags: u64,
        fd: u64,
        offset: u64,
    ) -> HostResult<UserProcessMemory> {
        let mmap_result = self.sys_call(Sysno::mmap, address, len, prot, flags, fd, offset)?;
        let mmap_result = mmap_result.rax;

        // invalid address
        // TODO not quite right...
        if mmap_result == 0 {
            return Err(HostError::MmapBadAddress(address));
        }

        Ok(UserProcessMemory {
            address: mmap_result,
            owner: self,
            len,
        })
    }

    /// Uses munmap syscall with ptrace to deallocate user process memory
    fn deallocate_memory(&self, address: u64, len: u64) -> HostResult<()> {
        let munmap_result = self.sys_call(Sysno::munmap, address, len, 0, 0, 0, 0)?;
        let munmap_result = munmap_result.rax;

        // not a zero return value means a failure
        if munmap_result != 0 {
            return Err(HostError::MunmapFailed(address));
        }

        Ok(())
    }

    /// Write to the user process memory
    pub fn write_user_memory(
        &self,
        user_memory: &mut UserProcessMemory,
        offset: u64,
        bytes: &[u8],
    ) -> HostResult<usize> {
        self.write_memory(user_memory.address + offset, bytes)
    }

    /// Read from user process memory
    pub fn read_user_memory(
        &self,
        user_memory: &UserProcessMemory,
        len: usize,
    ) -> HostResult<Vec<u8>> {
        self.read_memory(user_memory.address, len)
    }

    /// String to the proc's memory file
    /// Reference: https://crates.io/crates/pete
    fn proc_mem_path(&self) -> String {
        format!("/proc/{}/mem", self.pid.as_raw() as u32)
    }

    /// Common wrapper around writing memory
    /// Returns the amount of bytes written
    /// Reference: https://crates.io/crates/pete
    fn write_memory(&self, addr: u64, data: &[u8]) -> HostResult<usize> {
        use std::os::unix::fs::FileExt;
        let mem = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(self.proc_mem_path())?;
        let len = mem.write_at(data, addr)?;
        Ok(len)
    }

    /// Common wrapper around reading memory
    /// Returns a vector to the memory bytes
    /// Reference: https://crates.io/crates/pete
    pub fn read_memory(&self, addr: u64, len: usize) -> HostResult<Vec<u8>> {
        use std::os::unix::fs::FileExt;

        let mut data = vec![0u8; len];
        let mem = std::fs::File::open(self.proc_mem_path())?;
        let len_read = mem.read_at(&mut data, addr)?;

        data.truncate(len_read);
        Ok(data)
    }

    /// Invokes a syscall in the userprocess
    /// Accepts up to six arguments
    #[allow(clippy::too_many_arguments)]
    pub fn sys_call(
        &self,
        sys_call: Sysno,
        rdi: u64,
        rsi: u64,
        rdx: u64,
        r10: u64,
        r8: u64,
        r9: u64,
    ) -> HostResult<user_regs_struct> {
        log::trace!("UserProcess {} Syscall: {:#?}", self.pid, sys_call);
        let syscall_instruction = [0x0Fu8, 0x05u8];

        // Cache original registers, original instruction pointer (rip), and the original instructions
        let original_registers = ptrace::getregs(self.pid)?;
        let original_ip = original_registers.rip;
        let original_instructions = self.read_memory(original_ip, syscall_instruction.len())?;

        // Write over our shell code 0x0F05 for sys call
        self.write_memory(original_ip, &syscall_instruction)?;

        // Create a copy of the original registers
        // Set the sys_call index and args[0..5] (six arguments)
        let mut new_registers = original_registers;
        new_registers.rax = sys_call as u64;
        new_registers.rdi = rdi;
        new_registers.rsi = rsi;
        new_registers.rdx = rdx;
        new_registers.r10 = r10;
        new_registers.r8 = r8;
        new_registers.r9 = r9;

        // Apply the new registers, and new instructions then single step waiting for SIG_TRAP
        ptrace::setregs(self.pid, new_registers)?;

        // Single step the process and wait for a SIGTRAP signal
        self.single_step()?;

        // Cache the resultant registers
        let result = ptrace::getregs(self.pid)?;

        // Restore original instructions, and original registers to continue normal program control flow
        self.write_memory(original_ip, &original_instructions)?;
        ptrace::setregs(self.pid, original_registers)?;

        Ok(result)
    }

    pub fn getregs(&self) -> HostResult<user_regs_struct> {
        Ok(ptrace::getregs(self.pid)?)
    }
    pub fn setregs(&self, regs: user_regs_struct) -> HostResult<()> {
        ptrace::setregs(self.pid, regs)?;
        Ok(())
    }
    pub fn stop(&self) -> HostResult<()> {
        ptrace::interrupt(self.pid)?;
        Ok(())
    }
    pub fn resume(&self) -> HostResult<()> {
        ptrace::cont(self.pid, Signal::SIGCONT)?;
        Ok(())
    }

    pub fn insert_shellcode(&self, shellcode: &[u8]) -> HostResult<user_regs_struct> {
        log::trace!(
            "UserProcess {} shellcode insertion {:?}",
            self.pid,
            shellcode
        );

        let original_registers = ptrace::getregs(self.pid)?;
        let original_ip = original_registers.rip;
        let original_instructions = self.read_memory(original_ip, shellcode.len())?;

        self.write_memory(original_ip, &shellcode)?;

        let mut new_registers = original_registers;
        new_registers.rax = 0;
        new_registers.rdi = 0;
        new_registers.rsi = 0;
        new_registers.rdx = 0;
        new_registers.r10 = 0;
        new_registers.r8 = 0;
        new_registers.r9 = 0;
        //
        ptrace::setregs(self.pid, new_registers)?;

        // Single step the process and wait for the magic value
        loop {
            self.single_step()?;

            let result = ptrace::getregs(self.pid)?;
            // dbg!(result);
            if result.rax == 70
                && result.rdi == 71
                && result.rsi == 72
                && result.rdx == 73
                && result.r10 == 74
                && result.r9 == 75
                && result.r8 == 76
            {
                break;
            }
        }
        //
        let result = ptrace::getregs(self.pid)?;
        //
        self.write_memory(original_ip, &original_instructions)?;
        ptrace::setregs(self.pid, original_registers)?;

        Ok(result)
        // panic!()
    }
    /// Single steps the process
    /// Fails if the next signal is not a SIGTRAP
    fn single_step(&self) -> HostResult<()> {
        ptrace::step(self.pid, None)?;
        self.wait_trap()
    }

    /// Waits for the next signal
    /// Returns an error if that signal is not a SIGTRAP
    fn wait_trap(&self) -> HostResult<()> {
        match self.wait()? {
            WaitStatus::Stopped(_, SIGTRAP) => Ok(()),
            status => Err(HostError::UnexpectedWaitStatus(status)),
        }
    }

    /// Waits on the current process
    fn wait(&self) -> HostResult<WaitStatus> {
        waitpid(self.pid, None).map_err(HostError::NixError)
    }
}

impl Drop for UserProcess {
    /// Drop implementation for the UserProcess
    /// Attempts to detach from the process, does not panic on error instead only logs
    fn drop(&mut self) {
        if let Err(err) = ptrace::detach(self.pid, None) {
            log::error!(
                "UserProcess failed to detach from: {}, with Err: {:#?}",
                self.pid,
                err
            );
        } else {
            log::trace!("UserProcess successfully detached from: {}", self.pid);
        }
    }
}
