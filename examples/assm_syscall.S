.intel_syntax noprefix
.text
    .globl _start, syscall,_init,_fini,_DYNAMIC

    _init:
    _fini:
    _DYNAMIC:

    _start:
        jmp short ending
	// _start function
	
      
    _main_func:
  xor rbp,rbp  /* xoring a value with itself = 0 */
        pop rdi      /* rdi = argc */
        	     /* the pop instruction already added 8 to rsp */
        mov rsi,rsp  /* rest of the stack as an array of char ptr */

        and rsp,-16
        call main    // call main function 
        mov rax, 70
        mov rdi, 71
        mov rsi, 72
        mov rdx, 73
        mov r10, 74
        mov r9, 75
        mov r8, 76

    syscall:
        mov rax,rdi
        mov rdi,rsi
        mov rsi,rdx
        mov rdx,rcx
        mov r10,r8
        mov r8,r9
        syscall
        ret
    ending:
        call _main_func

