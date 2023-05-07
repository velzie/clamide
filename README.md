# Clamide: let your shell access the kernel
### What is this?
Clamide is a tool I made in rust to learn about x86 syscalls and how linux internals. This really shouldn't be used in any production environment, but I hope that at least one person might find this useful or learn a thing or two
### What can it do?
The main focus of clamide is to let you execute syscalls from within the safe confines of bash, without needing to actually start programming anything. See the  [Linux Syscall Table](https://filippo.io/linux-syscall-table/) for all the things you can do with this. (note that structs are not yet supported)

## How does it work?
- First, it uses the ptrace syscall to attach to the target process. By default, the process is the shell that called clamide, but with -p you can use it on any process.
- Then, the process is frozen temporarily and the RIP instruction pointer that corresponds to the next binary instruction the CPU will execute during the processes runtime is saved
- PTRACE_POKETEXT is used to write the single byte 0x1B to the memory of the process, specifically at the instruction pointer that will be executed next. This byte corresponds to the syscall instruction for linux.
- The registers of the target program are set to the arguments specified, and the process is stepped forward a single step, causing it to execute the syscall instruction we slipped in
- The instruction pointer and the byte we changed are reset to the values they were before we changed them, the process is resumed and the control flow returns to normal

It also contains a basic shellcode injector with `--shellcode`, although that isn't the main focus
### How do I use it?
First, get the source code and build. You need cargo downloaded obviously
```sh
git clone https://github.com/CoolElectronics/clamide
cd clamide
cargo build --release
sudo cp target/release/clamide /usr/bin/clamide
```
See /examples to learn how to use the program.
Note that this will only function on x86_64 bit computers running linux. This is partially because I'm lazy, but also because the authors of the ptrace library are lazy as well and never implemented it upstream.

Depending on your kernel config, you may need to run `sudo bash -c 'echo 0 > /proc/sys/kernel/yama/ptrace_scope` to enable ptracing external programs
 
### Credits
This whole project is based on [this amazing blog post](https://itnext.io/using-rust-and-ptrace-to-invoke-syscalls-262dc585fcd3). I would not have been able to do any of this or learn about this stuff without it.
