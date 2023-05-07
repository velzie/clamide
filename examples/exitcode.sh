tail -f /dev/null &
tailpid=$!
# normally "tail -f /dev/null" is a command that will never exit. We can force it to exit with a custom exit code with clamide


# note that in all other examples the syscall was being run in the parent shell. Here we run the syscall as the tail process
clamide -p $tailpid --syscall exit int:42 2>/dev/null

wait $tailpid
echo "tail process exited with exit code $?"
