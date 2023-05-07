
section .text
	global _start
_start:
	jmp short ending

	main_func:

	xor rax,rax	; zero rax
	xor rdi, rdi	; zero rdi
	xor rsi, rsi	; zero rsi
	xor rdx, rdx	; zero rdx
	
	mov al, 1	; set syscall to size_t sys_write(unsigned int fd, const char * buf, size_t count);
	mov dil, 1	; set file descriptor to 1; 0 = stdin, 1 = stdout, 2 = stderr

	pop rsi		; pop "Hello World!" from stack
	mov dl, 12	; set "Hello World!" size to 12
	syscall

	; set magic values to let clamide know that we're done executing shellcode and that the program can return to the default flow
   mov rax, 70
   mov rdi, 71
   mov rsi, 72
   mov rdx, 73
   mov r10, 74
   mov r9, 75
   mov r8, 76
	ending:
	call main_func
	db "Hello World!"
