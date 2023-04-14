target/debug/clamide --syscall open $"str:(realpath test)"
target/debug/clamide --syscall mmap int:0 int:15424 int:1 int:2 int:(fd)

