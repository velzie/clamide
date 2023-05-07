nasm -felf64 shellcode_helloworld.asm
ld shellcode_helloworld.o -o shellcode_helloworld.elf

shellcode=$(for i in `objdump -d shellcode_helloworld.elf | tr '\t' ' ' | tr ' ' '\n' | grep -E '^[0-9a-f]{2}$' ` ; do echo -n "\\x$i" ; done)

echo "Generated shellcode $shellcode"

clamide --shellcode "$shellcode"


rm shellcode_helloworld.o shellcode_helloworld.elf
