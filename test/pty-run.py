# Runs a program with some of its stdin, stdout and stderr on a pseudo-terminal, for
# test/sandbox.test.mts (round 3, finding 34). Usage:
#   python3 -I test/pty-run.py <fds> <program> [args...]
# <fds> is a comma-separated list of 0, 1 and 2: those descriptors are the terminal, the others
# are pipes (stdin empty). With all three on the terminal it is also the controlling terminal.
# Prints a JSON object: the exit status and everything written to the terminal and the pipes.
import json
import os
import pty
import subprocess
import sys

fds = {int(x) for x in sys.argv[1].split(",") if x}
argv = sys.argv[2:]
master, slave = os.openpty()
kwargs = {}
for fd, name in ((0, "stdin"), (1, "stdout"), (2, "stderr")):
    kwargs[name] = slave if fd in fds else (subprocess.DEVNULL if fd == 0 else subprocess.PIPE)
proc = subprocess.Popen(argv, start_new_session=(fds == {0, 1, 2}), **kwargs)
os.close(slave)
out, err = (s.read().decode("utf-8", "replace") if s else "" for s in (proc.stdout, proc.stderr))
status = proc.wait()
tty = b""
while True:
    try:
        chunk = os.read(master, 4096)
    except OSError:
        break
    if not chunk:
        break
    tty += chunk
print(json.dumps({"status": status, "tty": tty.decode("utf-8", "replace"), "stdout": out, "stderr": err}))
