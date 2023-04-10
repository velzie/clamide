void main() {
  __asm__(

      "mov rax, 4\n"
      "mov rbx, 1\n"
      "mov rcx, message\n"
      "mov rdx, 13; size\n"
      "int 0x80 \n"

      "message: .ascii \"Hello World!\\n\";");
}
