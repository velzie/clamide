%define sys_signal     48
%define SIGINT            2
%define sys_time    13


section .text
    global _start

    _start:
        jmp short ending
    
    _sig_handler:

        ; call main_func
        mov rbx, end_time
        mov rax, sys_time
        int 0x80
        mov rax, qword [start_time]
        mov rbx, qword [end_time]
        sub rbx, rax
        mov ax, 100
        div rbx
        push rbx
        push 0x1
        mov rax, 1
        push rax
        int 0x80
	; mov rax, 60             ; sys call for exit
 ;        mov rdi, 42
 ;        syscall
 ;        ret
    main_func:
        mov rcx, _sig_handler
        mov rbx, 19
        mov rax, sys_signal
        int 0x80
        xor rdi, rdi
        mov rax, 70
        mov rdi, 71
        mov rsi, 72
        mov rdx, 73
        mov r10, 74
        mov r9, 75
        mov r8, 76

ending:
call main_func
section .bss
start_time    resd 1
end_time        resd 1
