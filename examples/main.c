#include <stdio.h>
void *syscall(void *syscall_number, void *param1, void *param2, void *param3,
              void *param4, void *param5);

typedef unsigned long int uintptr; /* size_t */
typedef long int intptr;           /* ssize_t */

static intptr write(int fd, void const *data, uintptr nbytes) {
  return (intptr)syscall((void *)1, /* SYS_write */
                         (void *)(intptr)fd, (void *)data, (void *)nbytes,
                         0, /* ignored */
                         0  /* ignored */
  );
}
// int puts(char *str) { return write(0, str, sizeof(str)); }

int main(int argc, char *argv[]) {
  char cstr[3] = "hi!";
  puts(cstr);

  return 42;
}
