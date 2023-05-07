stdout_fd=0
length=12

bytes=$(clamide --syscall write int:$stdout_fd str:"Hello World!" int:$length)

echo "$bytes bytes written to stdout"
