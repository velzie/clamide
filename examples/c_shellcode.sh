gcc -s assm_syscall.S main.c -o c_shellcode -fno-stack-protector -Wno-builtin-declaration-mismatch -nostartfiles -static
shellcode=$(for i in `objdump -d c_shellcode | tr '\t' ' ' | tr ' ' '\n' | grep -E '^[0-9a-f]{2}$' ` ; do echo -n "\\x$i" ; done)

echo "Generated shellcode $shellcode"

printf $shellcode >tmp
clamide --shellcodefile tmp
echo "done shellcoding"


rm shellcode_helloworld.o shellcode_helloworld.elf
