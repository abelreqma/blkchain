import json
import os
import resource
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time

request = json.loads(sys.stdin.buffer.read(131073))
stages = request["stages"]
limit = request["limit"]
timeout = request["timeout"]
if not 1 <= len(stages) <= 3 or not 1 <= limit <= 67108864 or not 1 <= timeout <= 1800:
    raise ValueError("invalid execution bounds")
# declared holds the environment variable names the operator declared for the
# foothold carrier, forwarded into this container by the worker arguments; their
# values are copied into every command's environment so a carrier can
# authenticate. The names are validated here rather than trusted, and a declared
# name that is unset in this container contributes nothing. Validation runs before
# the scratch home is created so a rejected request leaves nothing behind.
declared = request.get("env") or []
if not isinstance(declared, list) or len(declared) > 64:
    raise ValueError("invalid declared environment")
command_env = {}
for name in declared:
    if not isinstance(name, str) or not name or len(name) > 256 or not name.isascii():
        raise ValueError("invalid declared environment name")
    if not (name[0].isalpha() or name[0] == "_") or not all(c.isalnum() or c == "_" for c in name):
        raise ValueError("invalid declared environment name")
    if name in os.environ:
        command_env[name] = os.environ[name]
home = tempfile.mkdtemp(prefix="home-", dir="/work")
# The fixed base is applied last, so a declaration cannot redirect PATH or HOME.
command_env.update({"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "HOME": home, "LANG": "C"})
lock = threading.Lock()
used = 0
results = [{"stdout": bytearray(), "stderr": bytearray(), "dropped": 0, "exit_code": -1} for _ in stages]
processes = []
threads = []
started = time.monotonic()
timed_out = False
error = ""

def prepare():
    os.setsid()
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_NOFILE, (256, 256))
    resource.setrlimit(resource.RLIMIT_FSIZE, (67108864, 67108864))
    resource.setrlimit(resource.RLIMIT_CPU, (int(timeout) + 1, int(timeout) + 1))

def read_stream(pipe, index, channel, downstream=None):
    global used
    try:
        while True:
            data = pipe.read(4096)
            if not data:
                break
            with lock:
                accepted = min(len(data), max(0, limit - used))
                results[index][channel].extend(data[:accepted])
                results[index]["dropped"] += len(data) - accepted
                used += accepted
            if downstream is not None:
                try:
                    downstream.write(data)
                    downstream.flush()
                except BrokenPipeError:
                    downstream = None
    finally:
        pipe.close()
        if downstream is not None:
            downstream.close()

try:
    for index, stage in enumerate(stages):
        argv = [stage["binary"]] + stage.get("args", [])
        if len(argv) > 1025 or sum(len(value) for value in argv) > 65536:
            raise ValueError("command exceeds argument bounds")
        process = subprocess.Popen(argv, stdin=subprocess.DEVNULL if index == 0 else subprocess.PIPE,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd="/work",
                                   env=command_env,
                                   preexec_fn=prepare)
        processes.append(process)
    for index, process in enumerate(processes):
        downstream = processes[index + 1].stdin if index + 1 < len(processes) else None
        for channel, pipe, target in [("stdout", process.stdout, downstream), ("stderr", process.stderr, None)]:
            thread = threading.Thread(target=read_stream, args=(pipe, index, channel, target), daemon=True)
            thread.start()
            threads.append(thread)
    for index, process in enumerate(processes):
        remaining = max(0.001, timeout - (time.monotonic() - started))
        results[index]["exit_code"] = process.wait(timeout=remaining)
except subprocess.TimeoutExpired:
    timed_out = True
except Exception as exc:
    error = type(exc).__name__
finally:
    for process in processes:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    for index, process in enumerate(processes):
        results[index]["exit_code"] = process.wait()
    for thread in threads:
        thread.join(timeout=2)
    shutil.rmtree(home)
    for result in results:
        for channel in ("stdout", "stderr"):
            result[channel] = result[channel].decode("utf-8", errors="replace")
    print(json.dumps({"stages": results, "timed_out": timed_out, "error": error}, ensure_ascii=True))
