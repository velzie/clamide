nasm -felf64 test.asm
stty -isig
ld test.o -o shellcode_helloworld.elf
trap 'echo 1' SIGINT
shellcode=$(for i in `objdump -d shellcode_helloworld.elf | tr '\t' ' ' | tr ' ' '\n' | grep -E '^[0-9a-f]{2}$' ` ; do echo -n "\\x$i" ; done)

echo "Generated shellcode $shellcode"

clamide --shellcode "$shellcode"
echo "done shellcoding"

read 

rm shellcode_helloworld.o shellcode_helloworld.elf
