# SPDX-License-Identifier: BSD-3-Clause
"""Test-only bounded capture with isolated Linux descendant ownership."""

import ctypes
import io
import json
import os
import selectors
import signal
import subprocess
import time
from pathlib import Path


class ProcessCustody:
    """Only used inside a dedicated fork worker, never the importing process."""

    def __init__(self):
        self.libc = ctypes.CDLL(None, use_errno=True)
        self.held = {}
        self.events = {}
        self.failures = []
        self.complete = False
        if self.children(os.getpid()):
            raise RuntimeError("capture worker already has children")
        if self.libc.prctl(36, 1, 0, 0, 0) != 0:
            raise OSError(ctypes.get_errno(), "PR_SET_CHILD_SUBREAPER")

    @staticmethod
    def children(pid):
        return {
            int(value)
            for value in Path(f"/proc/{pid}/task/{pid}/children")
            .read_text()
            .split()
        }

    def error(self, operation, error):
        self.failures.append({"operation": operation, "error": str(error)})

    def track(self, pid, parent):
        if pid in self.held:
            return True
        descriptor = None
        try:
            if len(self.held) >= 512:
                raise RuntimeError("owned process bound")
            descriptor = os.pidfd_open(pid)
            signal.pidfd_send_signal(descriptor, 0)
            fields = (
                Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
            )
            if int(fields[1]) not in (parent, os.getpid()):
                raise RuntimeError("process ownership changed")
            signal.pidfd_send_signal(descriptor, 0)
            self.held[pid] = descriptor
            self.events[pid] = {
                "pid": pid,
                "start_ticks": int(fields[19]),
                "signals": [],
                "reaped": False,
                "exit_status": None,
            }
            return True
        except (ProcessLookupError, FileNotFoundError):
            return False
        except (OSError, RuntimeError, ValueError) as error:
            self.error("track:" + str(pid), error)
            return False
        finally:
            if descriptor is not None and pid not in self.held:
                os.close(descriptor)

    def send(self, pid, sig):
        try:
            signal.pidfd_send_signal(self.held[pid], sig)
            self.events[pid]["signals"].append(sig)
            return True
        except ProcessLookupError:
            return False
        except OSError as error:
            self.error("signal:" + str(pid), error)
            return False

    def collect_and_kill(self):
        pending = [(pid, os.getpid()) for pid in self.children(os.getpid())]
        seen = set()
        while pending:
            pid, parent = pending.pop()
            if pid in seen:
                continue
            seen.add(pid)
            if not self.track(pid, parent) or not self.send(
                pid, signal.SIGSTOP
            ):
                continue
            try:
                pending.extend((child, pid) for child in self.children(pid))
            except (FileNotFoundError, ProcessLookupError):
                pass
            except OSError as error:
                self.error("enumerate:" + str(pid), error)
        for pid in reversed(tuple(self.held)):
            if not self.events[pid]["reaped"]:
                self.send(pid, signal.SIGKILL)

    def finish(self, process):
        deadline = time.monotonic() + 5
        try:
            self.collect_and_kill()
            if process is not None:
                try:
                    status = process.wait(
                        timeout=max(0.001, deadline - time.monotonic())
                    )
                    if process.pid in self.events:
                        self.events[process.pid].update(
                            reaped=True, exit_status=status
                        )
                except (OSError, subprocess.SubprocessError) as error:
                    self.error("wait-original-process", error)
            while True:
                # Adoption also retains exited-parent/new-session descendants.
                self.collect_and_kill()
                remaining = False
                for pid in self.held:
                    if self.events[pid]["reaped"]:
                        continue
                    try:
                        waited, status = os.waitpid(pid, os.WNOHANG)
                        if waited == pid:
                            self.events[pid].update(
                                reaped=True,
                                exit_status=os.waitstatus_to_exitcode(status),
                            )
                        else:
                            remaining = True
                    except (ChildProcessError, OSError) as error:
                        self.error("reap:" + str(pid), error)
                        remaining = True
                if not remaining and not self.children(os.getpid()):
                    self.complete = True
                    break
                if time.monotonic() >= deadline:
                    raise RuntimeError("owned descendants not reaped")
                time.sleep(0.01)
        except (OSError, RuntimeError, ValueError) as error:
            self.error("cleanup", error)
        finally:
            for descriptor in self.held.values():
                try:
                    os.close(descriptor)
                except OSError as error:
                    self.error("close-pidfd", error)
        return {
            "complete": self.complete,
            "failures": self.failures,
            "processes": list(self.events.values()),
        }


def interrupted(signum, frame):
    raise RuntimeError("capture interrupted by signal " + str(signum))


def worker(command, cwd, environment, executable, seconds, limits, targets):
    process = None
    custody = None
    result = {
        "returncode": None,
        "failure": None,
        "overflow": [],
        "timeout": False,
        "captured": {"stdout": 0, "stderr": 0},
        "cleanup": {"complete": False, "failures": [], "processes": []},
    }
    streams = {
        name: target if target is not None else io.BytesIO()
        for name, target in targets.items()
    }
    try:
        signal.signal(signal.SIGTERM, interrupted)
        signal.signal(signal.SIGINT, interrupted)
        custody = ProcessCustody()
        process = subprocess.Popen(
            list(map(str, command)),
            executable="/proc/self/fd/" + str(executable),
            pass_fds=(executable,),
            cwd=cwd,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
        if not custody.track(process.pid, os.getpid()):
            raise RuntimeError("cannot retain original process ownership")
        deadline = time.monotonic() + seconds
        with selectors.DefaultSelector() as selector:
            for name in streams:
                pipe = getattr(process, name)
                os.set_blocking(pipe.fileno(), False)
                selector.register(pipe, selectors.EVENT_READ, name)
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    result["timeout"] = True
                    raise RuntimeError("command timed out")
                for key, _ in selector.select(min(remaining, 0.1)):
                    try:
                        chunk = os.read(key.fd, 65536)
                    except BlockingIOError:
                        continue
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    name = key.data
                    available = limits[name] - result["captured"][name]
                    kept = chunk[:available]
                    streams[name].write(kept)
                    result["captured"][name] += len(kept)
                    if len(chunk) > available:
                        result["overflow"].append(name)
                        raise RuntimeError(name + " overflow")
            try:
                process.wait(timeout=max(0.001, deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                result["timeout"] = True
                raise RuntimeError("command timed out") from None
        if custody.children(os.getpid()):
            raise RuntimeError("command left descendant processes")
    except (
        OSError,
        RuntimeError,
        ValueError,
        subprocess.SubprocessError,
        KeyboardInterrupt,
        SystemExit,
    ) as error:
        result["failure"] = str(error)
    finally:
        signal.pthread_sigmask(
            signal.SIG_BLOCK, {signal.SIGTERM, signal.SIGINT}
        )
        if custody is not None:
            result["cleanup"] = custody.finish(process)
        if process is not None:
            result["returncode"] = process.returncode
            result["cleanup"]["drained"] = {}
            # Kill/reap first; then drain only bounded pipe data, never retain it.
            for name in streams:
                pipe = getattr(process, name)
                drained = False
                try:
                    os.set_blocking(pipe.fileno(), False)
                    for _ in range(17):
                        if not os.read(pipe.fileno(), 65536):
                            drained = True
                            break
                except BlockingIOError:
                    pass
                except OSError as error:
                    result["cleanup"]["failures"].append(
                        {"operation": "drain-" + name, "error": str(error)}
                    )
                finally:
                    pipe.close()
                result["cleanup"]["drained"][name] = drained
                if not drained:
                    result["cleanup"]["failures"].append(
                        {
                            "operation": "drain-" + name,
                            "error": "EOF not reached",
                        }
                    )
        for name, stream in streams.items():
            try:
                stream.flush()
                if targets[name] is not None:
                    os.fsync(stream.fileno())
                else:
                    result[name] = stream.getvalue().hex()
            except OSError as error:
                result["cleanup"]["failures"].append(
                    {"operation": "flush-" + name, "error": str(error)}
                )
    return result


def execute(
    command,
    cwd,
    environment,
    executable,
    seconds,
    stdout_limit,
    stderr_limit,
    stdout=None,
    stderr=None,
):
    """A fork-local subreaper cannot adopt or signal the caller's other children."""
    limits = {"stdout": stdout_limit, "stderr": stderr_limit}
    if seconds <= 0 or any(
        type(v) is not int or v < 0 for v in limits.values()
    ):
        raise ValueError("invalid capture bounds")
    read_fd, write_fd = os.pipe2(os.O_CLOEXEC)
    try:
        pid = os.fork()
    except BaseException:
        os.close(read_fd)
        os.close(write_fd)
        raise
    if pid == 0:
        os.close(read_fd)
        try:
            result = worker(
                command,
                cwd,
                environment,
                executable,
                seconds,
                limits,
                {"stdout": stdout, "stderr": stderr},
            )
            raw = json.dumps(result, separators=(",", ":")).encode()
            with os.fdopen(write_fd, "wb") as stream:
                stream.write(raw)
            os._exit(0)
        finally:
            os._exit(1)
    os.close(write_fd)
    raw = bytearray()
    try:
        bound = 2 * (stdout_limit + stderr_limit) + 256 * 1024
        while chunk := os.read(read_fd, 65536):
            if len(raw) + len(chunk) > bound:
                raise RuntimeError("capture receipt overflow")
            raw.extend(chunk)
    except BaseException:
        # This unreaped fork PID is exclusively ours and cannot have been reused.
        os.kill(pid, signal.SIGTERM)
        while os.read(read_fd, 65536):
            pass
        raise
    finally:
        os.close(read_fd)
        _, status = os.waitpid(pid, 0)
    if status != 0:
        raise RuntimeError("capture worker failed; cleanup unconfirmed")
    result = json.loads(raw)
    for name in limits:
        if name in result:
            result[name] = bytes.fromhex(result[name])
    return result
