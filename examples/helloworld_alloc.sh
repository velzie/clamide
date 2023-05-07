addr=$(clamide --alloc str:"Hello World!")
echo "Put string onto the memory of the parent program at address $addr"

stdout_fd=0
length=12

bytes=$(clamide --syscall write int:$stdout_fd int:$addr int:$length)

echo "$bytes bytes written to stdout"
