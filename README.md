# Clamide: let your shell access the kernel
### What is this?
Clamide is a tool I made in rust to learn about x86 syscalls and how linux internals. This really shouldn't be used in any production environment, but I hope that at least one person might find this useful or learn a thing or two
### What can it do?
The main focus of clamide is to let you execute syscalls from within the safe confines of bash, without needing to actually start programming anything. See the  [Linux Syscall Table](https://filippo.io/linux-syscall-table/) for all the things you can do with this. (note that structs are not yet supported)

It also contains a basic shellcode injector, although that isn't the main focus
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
 
### Credits
This whole project is based on [this amazing blog post](https://itnext.io/using-rust-and-ptrace-to-invoke-syscalls-262dc585fcd3). I would not have been able to do any of this or learn about this stuff without it.
