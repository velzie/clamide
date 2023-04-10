#!/bin/bash
nasm -felf64 $1 -o obj.o
ld obj.o -o a.out
shellcode=$(objdump -d ./a.out|grep '[0-9a-f]:'| \
grep -v 'file'|cut -f2 -d:|cut -f1-6 -d' '|tr -s \
' '|tr '\t' ' '|sed 's/ $//g'|sed 's/ /\\x/g'|\
paste -d '' -s |sed 's/^/"/'|sed 's/$/"/g')
printf "#include <stdio.h>\n" > main.c
printf "#include <string.h>\n" >> main.c
printf "int main(void)\n{\n" >> main.c
printf "unsigned char shellcode[] = " >> main.c
echo "$shellcode;" >> main.c
printf "(*(void (*)()) shellcode)();\n" >> main.c
printf "return 0;\n}" >> main.c
gcc main.c -o main -z execstack
# ./main
echo "$shellcode"
