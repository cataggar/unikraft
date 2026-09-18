#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""One tiny native compute image; no cloud, hardware, or benchmark admission."""
import sys

sys.dont_write_bytecode = True

import argparse
import contextlib
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import selectors
import shutil
import signal
import stat
import struct
import subprocess
import time
import sysconfig

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
APP = REPO / "support/apps/wamr-aot"
LOCAL_BOOT = REPO / "support/tools/hyperv/local_boot"
REVISION = "a53205d77be3b880eb8f8b96679512ba58e2331a"
MARKER = "WAMR_NATIVE_AOT_OK answer=42 teardown=0"
LEGACY = "Using legacy xAPIC MMIO"
MODES = ("raw-x2apic", "raw-legacy-apic", "vpc-x2apic", "vpc-legacy-apic")
FORBIDDEN = ("HYPERV_ACCEPTANCE", "UK_HYPERV_IO_READY",
             "UK_HYPERV_NETWORK_APP_READY", "UK_HYPERV_PLATFORM_READY",
             "WAMR_NATIVE_WASI=", "WAMR_NATIVE_AOT_FAIL")
EFI = "wamr_hyperv-x86_64-efi"
MIB = 1024 * 1024
MIZ_REVISION = "669a27982b376311f558e820b69e9a692735b0cd"
MIZ_PACKAGE_HASH = "miz-0.2.0-Z3lHlD--2gAdGiguNwbjjdjBmv2f8QlAcwHYRw1De0Sx"
MIZ_URL = "git+https://github.com/cataggar/miz.git#" + MIZ_REVISION
SOURCE_MAX_ENTRIES = 40_000
SOURCE_MAX_BYTES = 2 * 1024 * MIB
SOURCE_MAX_FILE = 256 * MIB
SOURCE_DIAGNOSTIC_MAX_CHANGES = 64
SOURCE_DIAGNOSTIC_MAX_IGNORED = 128
SOURCE_DIAGNOSTIC_MAX_ROOT_ENTRIES = 128
SOURCE_IGNORED_MAX_ENTRIES = 128 * 1024
SOURCE_IGNORED_MAX_BYTES = 8 * 1024 * MIB
SOURCE_IGNORED_MAX_FILE = 512 * MIB
SOURCE_IGNORED_MAX_PATH = 1024
SOURCE_IGNORED_MAX_DEPTH = 64
SOURCE_IGNORED_GIT_MAX_BYTES = 8 * MIB
PACKAGE_MAX_ROOTS = 128
PACKAGE_MAX_ENTRIES = 16_384
PACKAGE_MAX_BYTES = 256 * MIB
PACKAGE_MAX_FILE = 64 * MIB
PACKAGE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,159}")
SOURCE_OUTPUT_ROLES = (
    ".d",
    ".zig-cache",
    "support/apps/wamr-aot/.config",
    "support/apps/wamr-aot/build",
)
SOURCE_OUTPUT_DIRECTORY_ROLES = (
    ".d",
    ".zig-cache",
    "support/apps/wamr-aot/build",
)
SOURCE_OUTPUT_FILE_ROLES = ("support/apps/wamr-aot/.config",)
SOURCE_OUTPUT_PREEXISTING_DESCENDANT_ROLES = (".d",)
HOST_TOOLS = ("zig", "make", "llvm-nm", "llvm-objcopy", "llvm-objdump",
              "llvm-readelf", "llvm-strip", "bison", "flex",
              "python3", "git", "bash", "m4", "timeout", "head")
SUBPROCESS_TERM_GRACE = 1.0
SUBPROCESS_KILL_GRACE = 1.0
SUBPROCESS_DRAIN_GRACE = 1.0
INPUT_TREE_MAX_ENTRIES = 100_000
INPUT_TREE_MAX_BYTES = 2 * 1024 * MIB
COMMAND_ENVIRONMENT = {}
ANSI_ESCAPE = re.compile(rb"\x1b\[[0-?]*[ -/]*[@-~]")
COMMAND_ERROR_MARKERS = (
    "AccessDenied", "BrokenPipe", "FileNotFound", "FileTooBig", "InputOutput",
    "InvalidEnumTag", "InvalidNativeMakeEnvironment", "InvalidNativeMakePath",
    "InvalidPath", "MissingField", "ModuleNotFound", "NameTooLong", "NoSpaceLeft",
    "NoncanonicalNativeMakeEnvironment", "NotDir", "OutOfMemory",
    "PathAlreadyExists", "PermissionDenied", "ReadOnlyFileSystem",
    "SystemResources", "TooManySymbolicLinkLevels", "UnexpectedToken",
    "UnsafeFile", "UnsafeNativeMakeTool", "UnsupportedNativeMakeHost",
    "UnsupportedTarget",
)
COMMAND_ERROR_PATTERN = re.compile(
    rb"\b(?:" + b"|".join(name.encode("ascii") for name in COMMAND_ERROR_MARKERS) + rb")\b")


class Refusal(ValueError):
    """Only fixed adapter-owned diagnostic text, never external exception text."""


def require(condition, reason):
    if not condition:
        raise Refusal(reason)


def canonical(path):
    try:
        return path.resolve(strict=True) == path
    except (OSError, RuntimeError):
        return False


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate JSON key")
        result[key] = value
    return result


def snapshot(info):
    return tuple(getattr(info, name) for name in (
        "st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_nlink",
        "st_size", "st_mtime_ns", "st_ctime_ns"))


def open_flags(directory=False):
    flags = os.O_RDONLY
    if directory:
        flags |= os.O_DIRECTORY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    return flags


def bind(hasher, value):
    raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii")
    hasher.update(len(raw).to_bytes(8, "big"))
    hasher.update(raw)


def read_descriptor(handle, expected, limit, reason):
    require(stat.S_ISREG(expected.st_mode) and not expected.st_mode & 0o022
            and expected.st_size <= limit, reason)
    require(snapshot(os.fstat(handle)) == snapshot(expected), reason)
    data = bytearray()
    while len(data) <= limit:
        chunk = os.read(handle, min(65536, limit + 1 - len(data)))
        if not chunk:
            break
        data.extend(chunk)
    require(len(data) == expected.st_size
            and snapshot(os.fstat(handle)) == snapshot(expected), reason)
    return bytes(data)


def read(path, limit):
    path = Path(path)
    try:
        info = path.lstat()
        handle = os.open(path, open_flags())
    except OSError as error:
        raise Refusal("unsafe or oversized file") from error
    try:
        data = read_descriptor(handle, info, limit, "unsafe or oversized file")
    finally:
        os.close(handle)
    require(snapshot(path.lstat()) == snapshot(info), "file changed")
    return data


def document(path):
    return json.loads(read(path, 64 * 1024), object_pairs_hook=unique)


def digest_descriptor(handle, expected, limit, reason, allow_empty=False):
    require(stat.S_ISREG(expected.st_mode) and not expected.st_mode & 0o022
            and (allow_empty or expected.st_size > 0)
            and expected.st_size <= limit, reason)
    require(snapshot(os.fstat(handle)) == snapshot(expected), reason)
    value = hashlib.sha256()
    position = 0
    while position < expected.st_size:
        chunk = os.pread(handle, min(65536, expected.st_size - position), position)
        require(chunk, reason)
        value.update(chunk)
        position += len(chunk)
    require(not os.pread(handle, 1, position)
            and snapshot(os.fstat(handle)) == snapshot(expected), reason)
    return value.hexdigest()


def digest(path, limit=256 * MIB + 512):
    path = Path(path)
    try:
        info = path.lstat()
        handle = os.open(path, open_flags())
    except OSError as error:
        raise Refusal("unsafe hash input") from error
    try:
        value = digest_descriptor(handle, info, limit, "unsafe hash input")
    finally:
        os.close(handle)
    # Reading may update atime; it is not a content/identity mutation.
    require(snapshot(path.lstat()) == snapshot(info), "hash input changed")
    return value


def save(path, value):
    with path.open("x", encoding="ascii") as stream:
        json.dump(value, stream, sort_keys=True, separators=(",", ":"))
        stream.write("\n")
    path.chmod(0o600)


def tool(name):
    path = shutil.which(name)
    require(path is not None, "required tool unavailable")
    return str(Path(path).resolve(strict=True))


def signal_process_group(process, process_signal):
    try:
        os.killpg(process.pid, process_signal)
    except ProcessLookupError:
        pass


def close_selector_stream(selector, stream):
    try:
        selector.unregister(stream)
    except (KeyError, ValueError):
        pass
    try:
        stream.close()
    except OSError:
        pass


def bounded_subprocess_output(args, cwd, limit, seconds, overflow_reason,
                              timeout_reason, failure_reason, env=None,
                              pass_fds=()):
    require(type(limit) is int and limit >= 0 and seconds > 0, failure_reason)
    try:
        process = subprocess.Popen(
            list(map(str, args)), cwd=cwd, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, start_new_session=True, env=env,
            pass_fds=tuple(pass_fds),
        )
    except (OSError, ValueError) as error:
        raise Refusal(failure_reason) from error
    stream = process.stdout
    require(stream is not None, failure_reason)
    selector = selectors.DefaultSelector()
    collected = bytearray()
    exceeded = False
    timed_out = False
    stopping = False
    killed = False
    drain_incomplete = False
    term_deadline = None
    kill_deadline = None
    drain_deadline = None
    exit_drain_deadline = None
    deadline = time.monotonic() + seconds
    try:
        os.set_blocking(stream.fileno(), False)
        selector.register(stream, selectors.EVENT_READ)
        while selector.get_map():
            now = time.monotonic()
            if process.poll() is not None and exit_drain_deadline is None:
                exit_drain_deadline = now + SUBPROCESS_DRAIN_GRACE
            if not stopping and now >= deadline:
                timed_out = True
                stopping = True
                term_deadline = now + SUBPROCESS_TERM_GRACE
                kill_deadline = term_deadline + SUBPROCESS_KILL_GRACE
                drain_deadline = kill_deadline + SUBPROCESS_DRAIN_GRACE
                signal_process_group(process, signal.SIGTERM)
            if stopping and not killed and now >= term_deadline:
                signal_process_group(process, signal.SIGKILL)
                killed = True
            pipe_deadline = drain_deadline if stopping else exit_drain_deadline
            if pipe_deadline is not None and now >= pipe_deadline:
                drain_incomplete = True
                close_selector_stream(selector, stream)
                break
            wake = deadline
            if stopping:
                wake = term_deadline if not killed else drain_deadline
            if exit_drain_deadline is not None:
                wake = min(wake, exit_drain_deadline)
            wait = max(0, min(0.1, wake - now))
            for key, _ in selector.select(wait):
                try:
                    chunk = os.read(key.fd, 65536)
                except BlockingIOError:
                    continue
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                if exceeded or timed_out:
                    continue
                remaining = limit + 1 - len(collected)
                collected.extend(chunk[:remaining])
                if len(collected) > limit:
                    exceeded = True
                    stopping = True
                    now = time.monotonic()
                    term_deadline = now + SUBPROCESS_TERM_GRACE
                    kill_deadline = term_deadline + SUBPROCESS_KILL_GRACE
                    drain_deadline = kill_deadline + SUBPROCESS_DRAIN_GRACE
                    signal_process_group(process, signal.SIGTERM)
        if process.poll() is None:
            try:
                process.wait(timeout=SUBPROCESS_TERM_GRACE)
            except subprocess.TimeoutExpired:
                signal_process_group(process, signal.SIGKILL)
                process.kill()
                process.wait(timeout=SUBPROCESS_KILL_GRACE)
        else:
            process.wait()
    except (OSError, subprocess.SubprocessError) as error:
        raise Refusal(failure_reason) from error
    finally:
        selector.close()
        if not stream.closed:
            stream.close()
        if process.poll() is None:
            try:
                signal_process_group(process, signal.SIGTERM)
                process.wait(timeout=SUBPROCESS_TERM_GRACE)
            except (OSError, subprocess.SubprocessError):
                signal_process_group(process, signal.SIGKILL)
                process.kill()
                try:
                    process.wait(timeout=SUBPROCESS_KILL_GRACE)
                except subprocess.TimeoutExpired as error:
                    raise Refusal(failure_reason) from error
    require(not exceeded, overflow_reason)
    require(not timed_out, timeout_reason)
    require(not drain_incomplete, failure_reason)
    require(process.returncode == 0, failure_reason)
    return bytes(collected)


def git_environment():
    return {
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_PAGER": "cat",
        "GIT_TERMINAL_PROMPT": "0",
        "HOME": "/",
        "LANG": "C",
        "LC_ALL": "C",
        "PAGER": "cat",
        "PATH": "/usr/bin:/bin",
    }


def git_command(*args):
    return [
        tool("git"), "--no-pager",
        "-c", "core.hooksPath=/dev/null",
        "-c", "credential.helper=",
        "-c", "core.pager=cat",
        *args,
    ]


def command_environment(root, input_records=None, extra=None):
    path_entries = ["/usr/bin", "/bin"]
    for path in (() if input_records is None else input_records):
        parent = str(Path(path).parent)
        if parent not in path_entries:
            path_entries.append(parent)
    environment = {
        "HOME": str(Path(root) / "private"),
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": os.pathsep.join(path_entries),
        "PYTHONDONTWRITEBYTECODE": "1",
        "TMPDIR": str(Path(root) / "private"),
        **COMMAND_ENVIRONMENT,
    }
    if extra is not None:
        environment.update(extra)
    return environment


def bounded_git_raw(repository, limit, *args, overflow_reason, timeout_reason,
                    failure_reason):
    return bounded_subprocess_output(
        git_command(*args), repository, limit, 60, overflow_reason,
        timeout_reason, failure_reason, env=git_environment(),
    )


def git(*args, repository=REPO):
    return bounded_git_raw(
        repository, 64 * 1024, *args,
        overflow_reason="Git output too large",
        timeout_reason="Git command timed out",
        failure_reason="Git command failed",
    ).decode().strip()


def git_raw(repository, *args):
    return bounded_git_raw(
        repository, 16 * MIB, *args,
        overflow_reason="Git output too large",
        timeout_reason="Git command timed out",
        failure_reason="Git command failed",
    )


@contextlib.contextmanager
def retained_absolute(path, directory=False, reason="unsafe input path"):
    path = Path(path)
    require(path.is_absolute() and path.parts[0] == "/", reason)
    handles = []
    directories = []
    try:
        current = os.open("/", open_flags(directory=True))
        handles.append(current)
        directories.append(("/", current, snapshot(os.fstat(current))))
        built = Path("/")
        for index, part in enumerate(path.parts[1:]):
            final = index == len(path.parts[1:]) - 1
            handle = os.open(
                part, open_flags(directory=directory if final else True),
                dir_fd=current,
            )
            handles.append(handle)
            built /= part
            if not final or directory:
                info = os.fstat(handle)
                require(stat.S_ISDIR(info.st_mode), reason)
                directories.append((str(built), handle, snapshot(info)))
            current = handle
        yield current, directories, handles[-2] if len(handles) > 1 else None
    except OSError as error:
        raise Refusal(reason) from error
    finally:
        for handle in reversed(handles):
            try:
                os.close(handle)
            except OSError:
                pass


def stable_directories(directories, reason):
    result = {}
    for path, handle, expected in directories:
        require(snapshot(os.fstat(handle)) == expected, reason)
        result[path] = list(expected)
    return result


def physical_file_record(path, maximum=512 * MIB, content=True,
                         expected_sha256=None):
    path = Path(path)
    with retained_absolute(path, reason="unsafe physical input") as (
            handle, directories, parent):
        info = os.fstat(handle)
        require(
            stat.S_ISREG(info.st_mode) and info.st_uid in (0, os.getuid())
            and info.st_nlink > 0 and not info.st_mode & 0o022
            and 0 < info.st_size <= maximum
            and (info.st_uid == 0 or info.st_nlink == 1),
            "unsafe physical input",
        )
        identity = snapshot(info)
        sha256 = (
            digest_descriptor(handle, info, maximum, "physical input changed")
            if content else expected_sha256
        )
        require(isinstance(sha256, str)
                and re.fullmatch(r"[0-9a-f]{64}", sha256),
                "invalid physical input identity")
        if parent is not None:
            try:
                named = os.open(path.name, open_flags(), dir_fd=parent)
            except OSError as error:
                raise Refusal("physical input replaced") from error
            try:
                require(snapshot(os.fstat(named)) == identity,
                        "physical input replaced")
            finally:
                os.close(named)
        directory_records = stable_directories(
            directories, "physical input directory changed")
        require(snapshot(os.fstat(handle)) == identity,
                "physical input changed")
    return {
        "path": str(path),
        "metadata": list(identity),
        "sha256": sha256,
    }, directory_records


def bind_tree_file(content_hash, physical_hash, relative, handle, info,
                   hash_content, expected_sha256=None):
    sha256 = (
        expected_sha256 if expected_sha256 is not None else
        digest_descriptor(
            handle, info, INPUT_TREE_MAX_BYTES, "physical input tree changed",
            allow_empty=True)
        if hash_content else "0" * 64
    )
    require(isinstance(sha256, str)
            and re.fullmatch(r"[0-9a-f]{64}", sha256),
            "invalid physical input tree identity")
    bind(content_hash, ["file", relative, info.st_size, sha256])
    bind(physical_hash, ["file", relative, snapshot(info)])
    return sha256


def physical_tree_record(root, content=True, expected_content_sha256=None):
    root = Path(root)
    content_hash = hashlib.sha256(b"uk.wamr.consumer-input-tree-content-v2\0")
    physical_hash = hashlib.sha256(b"uk.wamr.consumer-input-tree-physical-v2\0")
    files = 0
    directories_count = 0
    symlinks = 0
    total = 0
    hash_work = 0
    content_identities = {}
    require(content or (
        isinstance(expected_content_sha256, str)
        and re.fullmatch(r"[0-9a-f]{64}", expected_content_sha256)
    ), "invalid physical input tree identity")

    with retained_absolute(root, directory=True,
                           reason="unsafe physical input tree") as (
            root_handle, components, unused_parent):
        del unused_parent

        def collect(directory_handle, prefix, depth):
            nonlocal files, directories_count, symlinks, total, hash_work
            require(depth <= SOURCE_IGNORED_MAX_DEPTH,
                    "physical input tree depth exceeded")
            before = os.fstat(directory_handle)
            require(
                stat.S_ISDIR(before.st_mode)
                and before.st_uid in (0, os.getuid())
                and not before.st_mode & 0o022,
                "unsafe physical input tree",
            )
            directories_count += 1
            require(files + directories_count + symlinks
                    <= INPUT_TREE_MAX_ENTRIES,
                    "physical input tree entry limit exceeded")
            bind(physical_hash, ["directory", prefix, snapshot(before)])
            try:
                entries = []
                with os.scandir(directory_handle) as iterator:
                    for entry in iterator:
                        entries.append(entry)
                        require(
                            files + directories_count + symlinks
                            + len(entries) <= INPUT_TREE_MAX_ENTRIES,
                            "physical input tree entry limit exceeded",
                        )
                entries.sort(key=lambda entry: entry.name)
            except OSError as error:
                raise Refusal("physical input tree enumeration failed") from error
            for entry in entries:
                name = entry.name
                require(name not in ("", ".", "..") and "/" not in name
                        and "\0" not in name,
                        "unsafe physical input tree path")
                relative = name if not prefix else prefix + "/" + name
                require(len(relative.encode("utf-8")) <= SOURCE_IGNORED_MAX_PATH,
                        "physical input tree path too long")
                try:
                    info = os.stat(
                        name, dir_fd=directory_handle, follow_symlinks=False)
                except OSError as error:
                    raise Refusal("physical input tree changed") from error
                if stat.S_ISDIR(info.st_mode):
                    try:
                        child = os.open(
                            name, open_flags(directory=True),
                            dir_fd=directory_handle)
                    except OSError as error:
                        raise Refusal("physical input tree changed") from error
                    try:
                        require(snapshot(os.fstat(child)) == snapshot(info),
                                "physical input tree changed")
                        collect(child, relative, depth + 1)
                    finally:
                        os.close(child)
                elif stat.S_ISREG(info.st_mode):
                    require(
                        info.st_uid in (0, os.getuid())
                        and info.st_nlink > 0 and not info.st_mode & 0o022
                        and info.st_size <= 512 * MIB
                        and (info.st_uid == 0 or info.st_nlink == 1),
                        "unsafe physical input tree entry",
                    )
                    total += info.st_size
                    files += 1
                    require(total <= INPUT_TREE_MAX_BYTES
                            and files + directories_count + symlinks
                            <= INPUT_TREE_MAX_ENTRIES,
                            "physical input tree limit exceeded")
                    try:
                        handle = os.open(
                            name, open_flags(), dir_fd=directory_handle)
                    except OSError as error:
                        raise Refusal("physical input tree changed") from error
                    try:
                        require(snapshot(os.fstat(handle)) == snapshot(info),
                                "physical input tree changed")
                        identity = snapshot(info)
                        known_sha256 = content_identities.get(identity)
                        if content and known_sha256 is None:
                            require(
                                hash_work + info.st_size
                                <= INPUT_TREE_MAX_BYTES,
                                "physical input tree hash limit exceeded",
                            )
                            hash_work += info.st_size
                        sha256 = bind_tree_file(
                            content_hash, physical_hash, relative, handle, info,
                            content, known_sha256)
                        if content:
                            content_identities[identity] = sha256
                    finally:
                        os.close(handle)
                elif stat.S_ISLNK(info.st_mode):
                    require(info.st_uid in (0, os.getuid())
                            and 0 < info.st_size < 4096,
                            "unsafe physical input tree symlink")
                    try:
                        target = os.readlink(name, dir_fd=directory_handle)
                        resolved = (root / relative).resolve(strict=True)
                    except (OSError, RuntimeError) as error:
                        raise Refusal("unsafe physical input tree symlink") from error
                    with retained_absolute(
                            resolved, reason="unsafe physical input tree symlink") as (
                                target_handle, target_directories, target_parent):
                        target_info = os.fstat(target_handle)
                        require(
                            stat.S_ISREG(target_info.st_mode)
                            and target_info.st_uid in (0, os.getuid())
                            and target_info.st_nlink > 0
                            and not target_info.st_mode & 0o022
                            and target_info.st_size <= 512 * MIB
                            and (target_info.st_uid == 0
                                 or target_info.st_nlink == 1),
                            "unsafe physical input tree symlink",
                        )
                        target_identity = snapshot(target_info)
                        target_sha256 = content_identities.get(target_identity)
                        if content and target_sha256 is None:
                            require(
                                hash_work + target_info.st_size
                                <= INPUT_TREE_MAX_BYTES,
                                "physical input tree hash limit exceeded",
                            )
                            hash_work += target_info.st_size
                            target_sha256 = digest_descriptor(
                                target_handle, target_info,
                                INPUT_TREE_MAX_BYTES,
                                "physical input tree changed",
                                allow_empty=True,
                            )
                            content_identities[target_identity] = target_sha256
                        elif not content:
                            target_sha256 = "0" * 64
                        require(target_sha256 is not None,
                                "invalid physical input tree identity")
                        if target_parent is not None:
                            try:
                                named_target = os.open(
                                    resolved.name, open_flags(),
                                    dir_fd=target_parent)
                            except OSError as error:
                                raise Refusal(
                                    "physical input tree changed") from error
                            try:
                                require(
                                    snapshot(os.fstat(named_target))
                                    == target_identity,
                                    "physical input tree changed",
                                )
                            finally:
                                os.close(named_target)
                        target_components = stable_directories(
                            target_directories,
                            "physical input tree path changed",
                        )
                        require(
                            snapshot(os.fstat(target_handle))
                            == target_identity,
                            "physical input tree changed",
                        )
                    symlinks += 1
                    total += len(os.fsencode(target))
                    require(total <= INPUT_TREE_MAX_BYTES
                            and files + directories_count + symlinks
                            <= INPUT_TREE_MAX_ENTRIES,
                            "physical input tree limit exceeded")
                    bind(content_hash, [
                        "symlink", relative, target, target_sha256,
                    ])
                    bind(physical_hash, [
                        "symlink", relative, target, snapshot(info),
                        list(target_identity), target_components,
                    ])
                else:
                    raise Refusal("unsupported physical input tree entry")
            require(snapshot(os.fstat(directory_handle)) == snapshot(before),
                    "physical input tree directory changed")

        collect(root_handle, "", 0)
        component_records = stable_directories(
            components, "physical input tree path changed")
    record = {
        "path": str(root),
        "files": files,
        "directories": directories_count,
        "symlinks": symlinks,
        "bytes": total,
        "content_sha256": (
            content_hash.hexdigest() if content else expected_content_sha256),
        "physical_sha256": physical_hash.hexdigest(),
    }
    return record, component_records


def elf_interpreter(path):
    try:
        with retained_absolute(path, reason="unsafe executable input") as (
                handle, directories, parent):
            del directories, parent
            header = os.pread(handle, 64, 0)
            if len(header) < 52 or header[:4] != b"\x7fELF":
                return None
            if header[5] != 1:
                raise Refusal("unsupported executable byte order")
            if header[4] == 2:
                program_offset = struct.unpack_from("<Q", header, 32)[0]
                entry_size = struct.unpack_from("<H", header, 54)[0]
                entry_count = struct.unpack_from("<H", header, 56)[0]
                offset_index, size_index = 8, 32
                offset_format, size_format = "<Q", "<Q"
            elif header[4] == 1:
                program_offset = struct.unpack_from("<I", header, 28)[0]
                entry_size = struct.unpack_from("<H", header, 42)[0]
                entry_count = struct.unpack_from("<H", header, 44)[0]
                offset_index, size_index = 4, 16
                offset_format, size_format = "<I", "<I"
            else:
                raise Refusal("unsupported executable class")
            require(0 < entry_size <= 256 and entry_count <= 256,
                    "invalid executable program headers")
            for index in range(entry_count):
                entry = os.pread(
                    handle, entry_size, program_offset + index * entry_size)
                require(len(entry) == entry_size,
                        "invalid executable program headers")
                if struct.unpack_from("<I", entry, 0)[0] != 3:
                    continue
                offset = struct.unpack_from(offset_format, entry, offset_index)[0]
                size = struct.unpack_from(size_format, entry, size_index)[0]
                require(1 < size <= 4096, "invalid executable interpreter")
                raw = os.pread(handle, size, offset)
                require(len(raw) == size and raw.endswith(b"\0"),
                        "invalid executable interpreter")
                value = os.fsdecode(raw[:-1])
                interpreter = Path(value)
                require(interpreter.is_absolute(), "invalid executable interpreter")
                return interpreter.resolve(strict=True)
            return None
    except OSError as error:
        raise Refusal("invalid executable input") from error


def executable_runtime_paths(path):
    interpreter = elf_interpreter(path)
    if interpreter is None:
        return set()
    with retained_absolute(path, reason="unsafe executable input") as (
            executable, executable_directories, executable_parent), \
            retained_absolute(interpreter, reason="unsafe executable runtime") as (
                loader, loader_directories, loader_parent):
        del executable_directories, executable_parent
        del loader_directories, loader_parent
        output = bounded_subprocess_output(
            [f"/proc/self/fd/{loader}", "--list",
             f"/proc/self/fd/{executable}"],
            "/", MIB, 30,
            "executable runtime inventory too large",
            "executable runtime inventory timed out",
            "executable runtime inventory failed",
            env={"LC_ALL": "C"}, pass_fds=(loader, executable),
        )
        result = {interpreter}
        descriptor_paths = {
            f"/proc/self/fd/{loader}", f"/proc/self/fd/{executable}",
        }
        for raw in output.splitlines():
            match = re.search(rb"=> (/[^\s]+) \(", raw)
            if match is None:
                match = re.match(rb"\s*(/[^\s]+) \(", raw)
            if match is not None:
                value = os.fsdecode(match.group(1))
                if value in descriptor_paths:
                    continue
                try:
                    result.add(Path(value).resolve(strict=True))
                except (OSError, RuntimeError) as error:
                    raise Refusal(
                        "invalid executable runtime inventory") from error
    return result


def merge_directory_records(target, values):
    for path, metadata in values.items():
        require(path not in target or target[path] == metadata,
                "physical input directory identity changed")
        target[path] = metadata


def record_digest(value):
    raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii")
    return hashlib.sha256(raw).hexdigest()


def record_input_paths(file_paths, tree_paths, content=True, expected=None):
    files = {}
    trees = {}
    directories = {}
    if expected is not None:
        require(
            isinstance(expected, dict)
            and expected.get("schema") == "uk.wamr.consumer-input-custody"
            and expected.get("version") == 2
            and isinstance(expected.get("files"), dict)
            and isinstance(expected.get("trees"), dict)
            and isinstance(expected.get("directories"), dict),
            "invalid consumer input custody",
        )
        file_paths = {
            name: Path(record["path"])
            for name, record in expected["files"].items()
        }
        tree_paths = {
            name: Path(record["path"])
            for name, record in expected["trees"].items()
        }
    for name, path in sorted(file_paths.items()):
        prior = None if expected is None else expected["files"][name]
        record, components = physical_file_record(
            path, content=content,
            expected_sha256=None if prior is None else prior["sha256"])
        files[name] = record
        merge_directory_records(directories, components)
    for name, path in sorted(tree_paths.items()):
        prior = None if expected is None else expected["trees"][name]
        record, components = physical_tree_record(
            path, content=content,
            expected_content_sha256=(
                None if prior is None else prior["content_sha256"]))
        trees[name] = record
        merge_directory_records(directories, components)
    result = {
        "schema": "uk.wamr.consumer-input-custody",
        "version": 2,
        "files": files,
        "trees": trees,
        "directories": directories,
    }
    result["aggregate_sha256"] = record_digest(result)
    if expected is not None:
        require(result == expected, "consumer input custody changed")
    return result


def consumer_input_state(runtime, content=True, expected=None):
    runtime = Path(runtime)
    if expected is not None:
        return record_input_paths({}, {}, content=content, expected=expected)
    tool_paths = {name: Path(tool(name)) for name in HOST_TOOLS}
    runtime_paths = set()
    for path in tool_paths.values():
        runtime_paths.update(executable_runtime_paths(path))
    file_paths = {
        **{f"tool:{name}": path for name, path in tool_paths.items()},
        **{f"runtime:{path}": path for path in sorted(runtime_paths)},
    }
    tree_paths = {
        "bison": runtime / "bison",
        "python-stdlib": Path(sysconfig.get_paths()["stdlib"]).resolve(strict=True),
        "system-bin": Path("/usr/bin").resolve(strict=True),
        "zig": tool_paths["zig"].parent,
    }
    llvm = runtime / "llvm"
    if llvm.is_dir() and not llvm.is_symlink():
        tree_paths["llvm"] = llvm
    archive = runtime / "compute/custody/wamr-source.tar"
    if archive.is_file() and not archive.is_symlink():
        file_paths["wamr-source-archive"] = archive
    return record_input_paths(file_paths, tree_paths, content=content)


def boot_input_state(runtime, paths, content=True, expected=None):
    if expected is not None:
        return record_input_paths({}, {}, content=content, expected=expected)
    file_paths = dict(paths)
    runtime_paths = set()
    for path in paths.values():
        if os.access(path, os.X_OK):
            runtime_paths.update(executable_runtime_paths(path))
    file_paths.update({
        f"runtime:{path}": path for path in sorted(runtime_paths)
    })
    tree_paths = {}
    qemu_data = Path(runtime) / "bin/share"
    if qemu_data.is_dir() and not qemu_data.is_symlink():
        tree_paths["qemu-data"] = qemu_data
    return record_input_paths(file_paths, tree_paths, content=content)


def consumer_file_records(value):
    require(value.get("schema") == "uk.wamr.consumer-input-custody"
            and value.get("version") == 2,
            "invalid consumer input custody")
    return {
        record["path"]: record for record in value["files"].values()
    }


def normalized_repository_relative(value, reason, trailing_slash=False):
    if not isinstance(value, str):
        raise Refusal(reason)
    if trailing_slash and value.endswith("/"):
        value = value[:-1]
    path = PurePosixPath(value)
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError as error:
        raise Refusal(reason) from error
    require(
        value and value == path.as_posix() and not path.is_absolute()
        and "." not in path.parts and ".." not in path.parts
        and len(encoded) <= SOURCE_IGNORED_MAX_PATH
        and len(path.parts) <= SOURCE_IGNORED_MAX_DEPTH,
        reason,
    )
    return path


def source_output_policy():
    require(
        len(SOURCE_OUTPUT_ROLES) == len(set(SOURCE_OUTPUT_ROLES))
        and (
            set(SOURCE_OUTPUT_DIRECTORY_ROLES)
            | set(SOURCE_OUTPUT_FILE_ROLES)
        ) == set(SOURCE_OUTPUT_ROLES)
        and not (
            set(SOURCE_OUTPUT_DIRECTORY_ROLES)
            & set(SOURCE_OUTPUT_FILE_ROLES)
        )
        and set(SOURCE_OUTPUT_PREEXISTING_DESCENDANT_ROLES)
        <= set(SOURCE_OUTPUT_DIRECTORY_ROLES),
        "invalid source output role policy",
    )
    roles = []
    for value in SOURCE_OUTPUT_ROLES:
        path = normalized_repository_relative(
            value, "invalid source output role policy")
        require(
            not any(path in other.parents or other in path.parents
                    for other, _ in roles),
            "invalid source output role policy",
        )
        roles.append((
            path,
            "directory" if value in SOURCE_OUTPUT_DIRECTORY_ROLES else "file",
        ))
    return tuple(roles)


def source_output_role(relative, roles):
    matches = [
        (role, kind) for role, kind in roles
        if relative == role or role in relative.parents
    ]
    require(len(matches) == 1, "ignored source entry outside output roles")
    return matches[0]


def bounded_directory_paths(directory, parent, existing, limit, limit_reason,
                            path_reason):
    paths = []
    try:
        iterator = os.scandir(directory)
    except OSError as error:
        raise Refusal(path_reason) from error
    try:
        for entry in iterator:
            relative = entry.name if not parent else parent + "/" + entry.name
            path = normalized_repository_relative(relative, path_reason)
            require(existing + len(paths) < limit, limit_reason)
            paths.append((entry.name, path))
    except OSError as error:
        raise Refusal(path_reason) from error
    finally:
        iterator.close()
    return sorted(paths, key=lambda item: item[0])


def source_output_root(path, kind):
    try:
        info = path.lstat()
    except FileNotFoundError as error:
        raise Refusal("source output role unavailable") from error
    require(
        canonical(path) and info.st_uid == os.getuid()
        and not info.st_mode & 0o022
        and (
            stat.S_ISDIR(info.st_mode) if kind == "directory"
            else stat.S_ISREG(info.st_mode) and info.st_nlink == 1
            and info.st_size <= SOURCE_IGNORED_MAX_FILE
        ),
        "unsafe source output role",
    )
    return info


def source_output_roots(repository):
    roles = source_output_policy()
    result = []
    for relative, kind in roles:
        path = repository.joinpath(*relative.parts)
        result.append((relative, kind, path, source_output_root(path, kind)))
    return roles, result


def ignored_git_roots(repository, roles):
    raw = bounded_git_raw(
        repository, SOURCE_IGNORED_GIT_MAX_BYTES,
        "ls-files", "--others", "--ignored", "--exclude-standard",
        "--directory", "-z",
        overflow_reason="ignored source inventory too large",
        timeout_reason="ignored source inventory timed out",
        failure_reason="ignored source inventory failed",
    )
    require(not raw or raw.endswith(b"\0"), "invalid ignored source inventory")
    paths = []
    seen = set()
    for encoded in raw[:-1].split(b"\0") if raw else ():
        try:
            value = encoded.decode("utf-8")
        except UnicodeDecodeError as error:
            raise Refusal("invalid ignored source inventory") from error
        path = normalized_repository_relative(
            value, "invalid ignored source inventory", trailing_slash=True)
        require(
            path not in seen and len(paths) < SOURCE_IGNORED_MAX_ENTRIES,
            "invalid ignored source inventory",
        )
        source_output_role(path, roles)
        seen.add(path)
        paths.append(path.as_posix())
    return paths


def ignored_symlink_escape_reason(relative):
    parts = relative.parts
    if parts[:2] == (".d", "wamr-source"):
        return "ignored WAMR source symlink escapes repository"
    if parts[:2] == (".d", "wamr-native-runtime"):
        if len(parts) > 2 and parts[2] == "llvm":
            return "ignored LLVM runtime symlink escapes repository"
        lanes = {
            "apt-cache": "APT cache",
            "apt-lists": "APT lists",
            "bin": "QEMU runtime",
            "bison": "Bison data",
            "cache": "acquisition cache",
            "downloads": "acquisition download",
            "evidence": "acquisition evidence",
            "ghr-bin": "GHR binary",
            "ghr-tools": "GHR tool",
            "runtime": "QEMU library",
            "tmp": "acquisition temporary",
        }
        if len(parts) > 2 and parts[2] in lanes:
            return (
                "ignored native runtime " + lanes[parts[2]]
                + " symlink escapes repository"
            )
        return "ignored native runtime symlink escapes repository"
    if parts and parts[0] == ".d":
        return "ignored private output symlink escapes repository"
    if parts and parts[0] == ".zig-cache":
        return "ignored Zig cache symlink escapes repository"
    if parts[:3] == ("support", "apps", "wamr-aot"):
        return "ignored WAMR output symlink escapes repository"
    return "ignored source symlink escapes repository"


def require_safe_ignored_symlink_target(repository, role, target, reason):
    role_root = repository.joinpath(*role.parts)
    try:
        target.relative_to(role_root)
        return
    except ValueError:
        pass
    try:
        relative = target.relative_to(repository)
        encoded = relative.as_posix().encode("utf-8")
    except (UnicodeEncodeError, ValueError):
        raise Refusal(reason) from None
    require(target.is_file() and not target.is_symlink(),
            reason)
    try:
        tracked = bounded_git_raw(
            repository, SOURCE_IGNORED_MAX_PATH + 1,
            "ls-files", "--error-unmatch", "-z", "--", relative.as_posix(),
            overflow_reason="ignored source symlink target invalid",
            timeout_reason="ignored source symlink target timed out",
            failure_reason="ignored source symlink target invalid",
        )
    except Refusal:
        raise Refusal(reason) from None
    require(tracked == encoded + b"\0", reason)


def ignored_source_state(repository=REPO):
    repository = Path(repository)
    require(repository.is_absolute() and canonical(repository)
            and stat.S_ISDIR(repository.lstat().st_mode),
            "canonical source required")
    roles, roots = source_output_roots(repository)
    ignored = ignored_git_roots(repository, roles)
    physical = hashlib.sha256(b"uk.wamr.ignored-source-policy-v1\0")
    entries = 0
    total = 0

    def add(relative, kind, info, extra=None):
        nonlocal entries, total
        require(entries < SOURCE_IGNORED_MAX_ENTRIES,
                "ignored source entry limit exceeded")
        entries += 1
        if kind == "file":
            require(info.st_size <= SOURCE_IGNORED_MAX_FILE,
                    "ignored source file limit exceeded")
            total += info.st_size
        elif kind == "symlink":
            total += len(extra)
        require(total <= SOURCE_IGNORED_MAX_BYTES,
                "ignored source byte limit exceeded")
        bind(physical, [kind, relative.as_posix(), snapshot(info), extra])

    def collect(role, directory, relative):
        before = directory.lstat()
        require(
            stat.S_ISDIR(before.st_mode) and before.st_uid == os.getuid()
            and not before.st_mode & 0o022,
            "unsafe ignored source directory",
        )
        add(relative, "directory", before)
        paths = bounded_directory_paths(
            directory, relative.as_posix(), entries,
            SOURCE_IGNORED_MAX_ENTRIES,
            "ignored source entry limit exceeded",
            "invalid ignored source path",
        )
        for name, child_relative in paths:
            path = directory / name
            try:
                info = path.lstat()
            except FileNotFoundError as error:
                raise Refusal("ignored source entry changed") from error
            require(info.st_uid == os.getuid(), "unsafe ignored source entry")
            if stat.S_ISDIR(info.st_mode):
                require(not info.st_mode & 0o022,
                        "unsafe ignored source entry")
                collect(role, path, child_relative)
            elif stat.S_ISREG(info.st_mode):
                require(info.st_nlink == 1, "unsafe ignored source entry")
                add(child_relative, "file", info)
            elif stat.S_ISLNK(info.st_mode):
                require(info.st_nlink == 1 and 0 < info.st_size < 4096,
                        "unsafe ignored source symlink")
                raw = os.readlink(os.fsencode(path))
                require(len(raw) == info.st_size,
                        "ignored source symlink changed")
                reason = ignored_symlink_escape_reason(child_relative)
                try:
                    target = path.resolve(strict=False)
                except (OSError, RuntimeError, ValueError) as error:
                    raise Refusal(reason) from error
                require_safe_ignored_symlink_target(
                    repository, role, target, reason)
                add(child_relative, "symlink", info, os.fsdecode(raw))
            else:
                raise Refusal("unsupported ignored source entry type")
        require(snapshot(directory.lstat()) == snapshot(before),
                "ignored source directory changed")

    for relative, kind, path, before in roots:
        if kind == "directory":
            collect(relative, path, relative)
        else:
            add(relative, "file", before)
            require(snapshot(path.lstat()) == snapshot(before),
                    "ignored source entry changed")
    return {
        "ignored": ignored,
        "entries": entries,
        "bytes": total,
        "physical_sha256": physical.hexdigest(),
    }


def source_file(repository, relative, mode, oid, object_format):
    path = repository / relative
    try:
        before = path.lstat()
    except FileNotFoundError as error:
        raise Refusal("tracked source unavailable") from error
    if mode == "120000":
        require(stat.S_ISLNK(before.st_mode) and before.st_uid in (0, os.getuid())
                and 0 < before.st_size < 4096,
                "tracked source type changed")
        raw = os.readlink(os.fsencode(path))
        require(len(raw) == before.st_size and snapshot(path.lstat()) == snapshot(before),
                "tracked source changed")
        try:
            target = path.resolve(strict=True)
        except (OSError, RuntimeError) as error:
            raise Refusal("tracked source symlink target unavailable") from error
        require(target == repository or repository in target.parents,
                "tracked source symlink escapes repository")
    else:
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                and before.st_uid in (0, os.getuid()) and not before.st_mode & 0o022
                and bool(before.st_mode & 0o111) == (mode == "100755"),
                "tracked source type changed")
        raw = read(path, SOURCE_MAX_FILE)
        require(snapshot(path.lstat()) == snapshot(before), "tracked source changed")
    object_hash = hashlib.new(object_format)
    object_hash.update(f"blob {len(raw)}\0".encode("ascii"))
    object_hash.update(raw)
    require(object_hash.hexdigest() == oid, "tracked source content differs from Git")
    return raw, before


def tracked_source_map(repository, head, object_format):
    listing = bounded_git_raw(
        repository, 4 * MIB, "ls-tree", "-r", "-z", "--full-tree", head,
        overflow_reason="invalid tracked source map",
        timeout_reason="tracked source map timed out",
        failure_reason="invalid tracked source map",
    )
    require(0 < len(listing) <= 4 * MIB and listing.endswith(b"\0"),
            "invalid tracked source map")
    entries = []
    names = set()
    directories = {""}
    for raw in listing[:-1].split(b"\0"):
        try:
            header, encoded = raw.split(b"\t", 1)
            mode, kind, oid = header.decode("ascii").split(" ")
            relative = encoded.decode("utf-8")
        except (UnicodeDecodeError, ValueError) as error:
            raise Refusal("invalid tracked source map") from error
        path = PurePosixPath(relative)
        require(kind == "blob" and mode in ("100644", "100755", "120000")
                and len(oid) == hashlib.new(object_format).digest_size * 2
                and relative not in names and not path.is_absolute()
                and relative not in ("", ".", "..") and ".." not in path.parts
                and len(relative.encode()) <= 1024
                and len(entries) < SOURCE_MAX_ENTRIES,
                "invalid tracked source map")
        names.add(relative)
        entries.append((relative, mode, oid))
        for parent in path.parents:
            if str(parent) != ".":
                directories.add(parent.as_posix())
    return entries, directories


def source_metadata(repository=REPO):
    repository = Path(repository)
    head = git("rev-parse", "HEAD", repository=repository)
    object_format = git("rev-parse", "--show-object-format", repository=repository)
    entries, directories = tracked_source_map(repository, head, object_format)
    records = []
    for relative in sorted(directories):
        path = repository if not relative else repository / relative
        records.append(["directory", relative, list(snapshot(path.lstat()))])
    for relative, _, _ in entries:
        records.append([
            "file", relative, list(snapshot((repository / relative).lstat())),
        ])
    return records


def source_metadata_changes(before, after):
    expected = {(kind, path): metadata for kind, path, metadata in before}
    current = {(kind, path): metadata for kind, path, metadata in after}
    changed = []
    total = 0
    for kind, path in sorted(set(expected) | set(current)):
        old = expected.get((kind, path))
        new = current.get((kind, path))
        if old != new:
            total += 1
            if len(changed) < SOURCE_DIAGNOSTIC_MAX_CHANGES:
                changed.append({
                    "kind": kind, "path": path, "before": old, "after": new,
                })
    return {
        "schema": "uk.wamr.git-physical-source-diagnostic",
        "version": 1,
        "changed": changed,
        "changed_records": total,
        "truncated": total > len(changed),
    }


def source_metadata_document(path):
    try:
        value = json.loads(read(path, 4 * MIB), object_pairs_hook=unique)
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise Refusal("invalid source metadata baseline") from error
    require(
        isinstance(value, dict)
        and set(value) == {"schema", "version", "records"}
        and value["schema"] == "uk.wamr.git-physical-source-baseline"
        and value["version"] == 1
        and isinstance(value["records"], list)
        and len(value["records"]) <= 2 * SOURCE_MAX_ENTRIES,
        "invalid source metadata baseline",
    )
    for record in value["records"]:
        require(
            isinstance(record, list)
            and len(record) == 3
            and record[0] in ("directory", "file")
            and isinstance(record[1], str)
            and len(record[1].encode()) <= 1024
            and isinstance(record[2], list)
            and len(record[2]) == 9
            and all(isinstance(item, int) for item in record[2]),
            "invalid source metadata baseline",
        )
    return value


def ignored_status_diagnostic(repository):
    raw = bounded_git_raw(
        repository, MIB, "status", "--short", "--ignored",
        "--untracked-files=all", "-z",
        overflow_reason="ignored source inventory too large",
        timeout_reason="ignored source inventory timed out",
        failure_reason="ignored source inventory failed",
    )
    require(not raw or raw.endswith(b"\0"), "invalid ignored source inventory")
    paths = []
    total = 0
    for record in raw[:-1].split(b"\0") if raw else ():
        if not record.startswith(b"!! "):
            continue
        try:
            value = record[3:].decode("utf-8")
        except UnicodeDecodeError as error:
            raise Refusal("invalid ignored source inventory") from error
        path = normalized_repository_relative(
            value, "invalid ignored source inventory")
        total += 1
        if len(paths) < SOURCE_DIAGNOSTIC_MAX_IGNORED:
            paths.append("!! " + path.as_posix())
    return paths, total > len(paths)


def source_root_inventory(repository):
    before = repository.lstat()
    paths = bounded_directory_paths(
        repository, "", 0, SOURCE_DIAGNOSTIC_MAX_ROOT_ENTRIES,
        "source root inventory too large", "invalid source root inventory",
    )
    result = []
    for name, _ in paths:
        info = (repository / name).lstat()
        kind = (
            "directory" if stat.S_ISDIR(info.st_mode)
            else "symlink" if stat.S_ISLNK(info.st_mode)
            else "file"
        )
        result.append({"name": name, "kind": kind})
    require(snapshot(repository.lstat()) == snapshot(before),
            "source root inventory changed")
    return result


def source(repository=REPO):
    repository = Path(repository)
    require(repository.is_absolute() and canonical(repository)
            and stat.S_ISDIR(repository.lstat().st_mode), "canonical source required")
    ignored_before = ignored_source_state(repository)
    status = bounded_git_raw(
        repository, MIB, "status", "--porcelain=v2", "--untracked-files=all",
        "-z", overflow_reason="source status too large",
        timeout_reason="source status timed out",
        failure_reason="source status failed",
    )
    require(not status, "clean committed source required")
    head = git("rev-parse", "HEAD", repository=repository)
    tree = git("rev-parse", "HEAD^{tree}", repository=repository)
    if repository == REPO:
        require(head == os.environ.get("GITHUB_SHA", head), "unexpected source revision")
    object_format = git("rev-parse", "--show-object-format", repository=repository)
    require(object_format in ("sha1", "sha256"), "unsupported Git object format")
    entries, directories = tracked_source_map(repository, head, object_format)
    directory_state = {}
    for relative in sorted(directories, key=lambda item: (item.count("/"), item)):
        path = repository if not relative else repository / relative
        try:
            info = path.lstat()
        except FileNotFoundError as error:
            raise Refusal("tracked source directory unavailable") from error
        require(stat.S_ISDIR(info.st_mode) and info.st_uid in (0, os.getuid())
                and not info.st_mode & 0o022, "unsafe tracked source directory")
        directory_state[relative] = snapshot(info)
    content = hashlib.sha256(b"uk.wamr.git-source-content-v1\0")
    physical = hashlib.sha256(b"uk.wamr.git-source-physical-v1\0")
    for relative in sorted(directory_state):
        bind(physical, ["directory", relative, directory_state[relative]])
    total = 0
    for relative, mode, oid in entries:
        raw, info = source_file(repository, relative, mode, oid, object_format)
        total += len(raw)
        require(total <= SOURCE_MAX_BYTES, "tracked source byte limit exceeded")
        sha256 = hashlib.sha256(raw).hexdigest()
        bind(content, ["file", relative, mode, oid, len(raw), sha256])
        bind(physical, ["file", relative, mode, oid, len(raw), sha256, snapshot(info)])
    for relative, expected in directory_state.items():
        path = repository if not relative else repository / relative
        require(snapshot(path.lstat()) == expected, "tracked source directory changed")
    final_status = bounded_git_raw(
        repository, MIB, "status", "--porcelain=v2", "--untracked-files=all",
        "-z", overflow_reason="source status too large",
        timeout_reason="source status timed out",
        failure_reason="source status failed",
    )
    require(not final_status
            and git("rev-parse", "HEAD", repository=repository) == head
            and git("rev-parse", "HEAD^{tree}", repository=repository) == tree,
            "tracked source changed during inspection")
    require(ignored_source_state(repository) == ignored_before,
            "ignored source outputs changed during inspection")
    return {
        "revision": head,
        "tree": tree,
        "custody": {
            "schema": "uk.wamr.git-physical-source",
            "version": 1,
            "object_format": object_format,
            "files": len(entries),
            "directories": len(directory_state),
            "bytes": total,
            "content_sha256": content.hexdigest(),
            "physical_sha256": physical.hexdigest(),
            "role_excluded_outputs": list(SOURCE_OUTPUT_ROLES),
        },
    }


def require_source(expected, repository=REPO):
    require(source(repository) == expected, "immutable source custody changed")


def source_identity(value):
    return {"revision": value["revision"], "tree": value["tree"]}


def producer_inputs(runtime, expected_consumer=None, content=True):
    current_source = source()
    return {"source": source_identity(current_source),
            "source_custody": current_source["custody"],
            "tools": {name: digest(Path(tool(name))) for name in HOST_TOOLS},
            "bison_data": bison_inputs(runtime / "bison"),
            "dependencies": dependency_custody(runtime / "compute"),
            "consumer_inputs": consumer_input_state(
                runtime, content=content, expected=expected_consumer)}


def bison_inputs(root):
    require(root.is_absolute(), "absolute private Bison data required")
    require(canonical(root)
            and stat.S_ISDIR(root.lstat().st_mode)
            and root.stat().st_uid == os.getuid()
            and stat.S_IMODE(root.stat().st_mode) == 0o700,
            "private Bison directory required")
    files = {}
    total = 0
    for index, path in enumerate(root.rglob("*")):
        info = path.lstat()
        require(index < 512 and info.st_uid == os.getuid()
                and not info.st_mode & 0o7022, "unsafe Bison data input")
        if stat.S_ISDIR(info.st_mode):
            continue
        require(stat.S_ISREG(info.st_mode), "nonregular Bison data input")
        raw = read(path, 8 * MIB - total)
        total += len(raw)
        files[path.relative_to(root).as_posix()] = {
            "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
    require(files, "empty Bison data")
    encoded = json.dumps(files, sort_keys=True, separators=(",", ":")).encode("ascii")
    return {"files": len(files), "bytes": total,
            "sha256": hashlib.sha256(encoded).hexdigest()}


def command_error_markers(raw):
    observed = {match.group() for match in COMMAND_ERROR_PATTERN.finditer(raw)}
    return [name for name in COMMAND_ERROR_MARKERS if name.encode("ascii") in observed]


@contextlib.contextmanager
def retained_executables(paths, records):
    opened = {}
    try:
        for path in paths:
            path = str(Path(path))
            if path in opened:
                continue
            require(path in records, "unbound executable input")
            record = records[path]
            handle = os.open(path, open_flags())
            info = os.fstat(handle)
            require(
                list(snapshot(info)) == record["metadata"]
                and stat.S_ISREG(info.st_mode)
                and bool(info.st_mode & 0o111),
                "executable input changed",
            )
            opened[path] = handle
        yield {
            path: f"/proc/self/fd/{handle}"
            for path, handle in opened.items()
        }, tuple(opened.values())
    except OSError as error:
        raise Refusal("executable input changed") from error
    finally:
        for handle in reversed(tuple(opened.values())):
            try:
                os.close(handle)
            except OSError:
                pass


def execute(root, stage, args, seconds=600, limit=8 * MIB, cwd=REPO,
            evidence=True, input_records=None):
    """Fixed timeout/head ceiling; raw output stays private, never in Actions stdout."""
    output = root / "private" / (stage + ".log")
    timeout = tool("timeout")
    shell = tool("bash")
    head = tool("head")
    executable = str(Path(args[0]))
    context = (
        retained_executables(
            (timeout, shell, head, executable), input_records)
        if input_records is not None
        else contextlib.nullcontext(({}, ()))
    )
    with context as (retained, pass_fds), output.open("xb") as stream:
        environment = command_environment(root, input_records, {
            "WAMR_CI_CAPTURE_LIMIT": str(limit + 1),
            "WAMR_CI_HEAD": retained.get(head, head),
        })
        command = [
            retained.get(timeout, timeout),
            "--signal=TERM", "--kill-after=5s", str(seconds),
            retained.get(shell, shell),
            "--noprofile", "--norc", "-o", "pipefail", "-c",
            '"$@" 2>&1 | "$WAMR_CI_HEAD" -c "$WAMR_CI_CAPTURE_LIMIT"',
            "_", retained.get(executable, executable), *map(str, args[1:]),
        ]
        result = subprocess.run(
            command, cwd=cwd, stdout=stream, stderr=subprocess.STDOUT,
            env=environment,
            pass_fds=pass_fds, check=False,
        )
    size = output.stat().st_size
    markers = (command_error_markers(read(output, limit + 1))
               if size <= limit + 1 else None)
    record = {
        "scope": "command_diagnostic_not_acceptance", "stage": stage,
        "exit_code": result.returncode, "bytes": size,
        "sha256": digest(output) if size else hashlib.sha256(b"").hexdigest(),
        "over_limit": size > limit,
        "known_error_markers": markers,
    }
    if evidence:
        save(root / "evidence" / ("command-" + stage + ".json"), record)
    require(result.returncode == 0 and size <= limit, "bounded command failed")
    return output, record


def run(root, stage, args, seconds=600, limit=8 * MIB, input_records=None):
    output, _ = execute(
        root, stage, args, seconds, limit, input_records=input_records)
    return output


def zon_without_comments(raw):
    require(len(raw) <= 4 * MIB, "oversized package manifest")
    result = bytearray(raw)
    index = 0
    quote = False
    while index < len(raw):
        if quote:
            if raw[index] == 0x5c:
                index += 2
                continue
            if raw[index] == 0x22:
                quote = False
            index += 1
            continue
        if raw[index] == 0x22:
            quote = True
            index += 1
            continue
        if raw[index:index + 2] == b"//":
            end = raw.find(b"\n", index + 2)
            end = len(raw) if end < 0 else end
            result[index:end] = b" " * (end - index)
            index = end
            continue
        if raw[index:index + 2] == b"/*":
            depth = 1
            end = index + 2
            while end < len(raw) and depth:
                if raw[end:end + 2] == b"/*":
                    depth += 1
                    end += 2
                elif raw[end:end + 2] == b"*/":
                    depth -= 1
                    end += 2
                else:
                    end += 1
            require(depth == 0, "invalid package manifest")
            result[index:end] = b" " * (end - index)
            index = end
            continue
        index += 1
    require(not quote, "invalid package manifest")
    return bytes(result)


def zon_block(raw, field, required=True):
    clean = zon_without_comments(raw)
    marker = re.compile(
        rb"(?<![A-Za-z0-9_])\." + re.escape(field.encode("ascii"))
        + rb"\s*=\s*\.\s*\{")
    matches = list(marker.finditer(clean))
    if not matches and not required:
        return None
    require(len(matches) == 1, "ambiguous package manifest field")
    start = clean.find(b"{", matches[0].start())
    depth = 0
    quote = False
    index = start
    while index < len(clean):
        byte = clean[index]
        if quote:
            if byte == 0x5c:
                index += 2
                continue
            if byte == 0x22:
                quote = False
        elif byte == 0x22:
            quote = True
        elif byte == 0x7b:
            depth += 1
        elif byte == 0x7d:
            depth -= 1
            if depth == 0:
                return clean[start:index + 1]
        index += 1
    raise Refusal("invalid package manifest")


def zon_strings(raw, field):
    marker = re.compile(
        rb"(?<![A-Za-z0-9_])\." + re.escape(field.encode("ascii")) + rb"\b")
    values = re.findall(
        rb"(?<![A-Za-z0-9_])\." + re.escape(field.encode("ascii"))
        + rb'\s*=\s*"([A-Za-z0-9._+:/#-]+)"', raw)
    require(len(values) == len(marker.findall(raw)), "invalid package manifest string")
    return [value.decode("ascii") for value in values]


def validate_restore_manifest(raw):
    dependencies = zon_block(raw, "dependencies")
    miz = zon_block(dependencies, "miz_source")
    urls = zon_strings(miz, "url")
    hashes = zon_strings(miz, "hash")
    require(urls == [MIZ_URL] and hashes == [MIZ_PACKAGE_HASH]
            and zon_strings(dependencies, "hash") == [MIZ_PACKAGE_HASH],
            "wrong pinned Miz dependency")
    return {"url": MIZ_URL, "revision": MIZ_REVISION,
            "package_hash": MIZ_PACKAGE_HASH}


def git_directory_output(repository, limit, *args):
    repository = Path(repository)
    git_path = Path(tool("git"))
    try:
        with retained_absolute(
                repository, directory=True,
                reason="pinned source repository unavailable") as (
                    repository_handle, repository_directories, repository_parent), \
                retained_absolute(
                    git_path, reason="required Git executable unavailable") as (
                        git_handle, git_directories, git_parent):
            del repository_parent, git_parent
            result = bounded_subprocess_output(
                [f"/proc/self/fd/{git_handle}", "--no-pager",
                 "-c", "core.hooksPath=/dev/null",
                 "-c", "credential.helper=",
                 "-c", "core.pager=cat", *args],
                f"/proc/self/fd/{repository_handle}", limit, 60,
                "Git output too large", "Git command timed out",
                "Git command failed", env=git_environment(),
                pass_fds=(git_handle, repository_handle),
            )
            stable_directories(
                repository_directories,
                "pinned source repository changed")
            stable_directories(
                git_directories, "required Git executable changed")
            return result
    except Refusal:
        raise
    except (OSError, RuntimeError, ValueError) as error:
        raise Refusal("pinned source repository unavailable") from error


def seal_wamr_source(runtime, source):
    source = Path(source)
    root = Path(runtime) / "compute"
    custody = root / "custody"
    custody.mkdir(mode=0o700)
    require(source.is_absolute(), "pinned WAMR checkout required")
    revision = git_directory_output(
        source, 65, "rev-parse", "--verify", REVISION + "^{commit}").decode().strip()
    status = git_directory_output(
        source, MIB, "status", "--porcelain=v2",
        "--untracked-files=normal", "-z")
    require(revision == REVISION and not status,
            "pinned WAMR checkout required")
    archive = git_directory_output(
        source, 256 * MIB, "archive", "--format=tar", REVISION)
    require(0 < len(archive) <= 256 * MIB, "invalid WAMR source archive")
    path = custody / "wamr-source.tar"
    copied = create_exact_copy(path, archive)
    require(copied["sha256"] == hashlib.sha256(archive).hexdigest(),
            "WAMR source archive changed")
    return path


def tracked_manifest(relative, repository=None):
    repository = REPO if repository is None else Path(repository)
    encoded = relative.encode("utf-8")
    try:
        relative_path = normalized_repository_relative(
            relative, "pinned dependency manifest unavailable")
        with retained_absolute(
                repository, directory=True,
                reason="pinned dependency manifest unavailable") as (
                    root_handle, root_directories, root_parent):
            del root_parent
            raw = bounded_subprocess_output(
                [*git_command("ls-tree", "-z", "HEAD", "--", relative)],
                f"/proc/self/fd/{root_handle}", 2048, 60,
                "pinned dependency manifest unavailable",
                "pinned dependency manifest unavailable",
                "pinned dependency manifest unavailable",
                env=git_environment(), pass_fds=(root_handle,),
            )
            require(raw.endswith(b"\0") and raw.count(b"\0") == 1,
                    "pinned dependency manifest is not uniquely tracked")
            object_format = bounded_subprocess_output(
                [*git_command("rev-parse", "--show-object-format")],
                f"/proc/self/fd/{root_handle}", 16, 60,
                "invalid pinned dependency manifest identity",
                "invalid pinned dependency manifest identity",
                "invalid pinned dependency manifest identity",
                env=git_environment(), pass_fds=(root_handle,),
            ).decode().strip()
            opened = []
            current = root_handle
            component_state = []
            built = repository
            for part in relative_path.parts[:-1]:
                handle = os.open(
                    part, open_flags(directory=True), dir_fd=current)
                opened.append(handle)
                info = os.fstat(handle)
                require(stat.S_ISDIR(info.st_mode),
                        "pinned dependency manifest unavailable")
                built /= part
                component_state.append((str(built), handle, snapshot(info)))
                current = handle
            handle = os.open(relative_path.name, open_flags(), dir_fd=current)
            opened.append(handle)
            info = os.fstat(handle)
            require(
                stat.S_ISREG(info.st_mode) and info.st_nlink == 1
                and info.st_uid in (0, os.getuid())
                and not info.st_mode & 0o022,
                "invalid pinned dependency manifest identity",
            )
            identity = snapshot(info)
            data = read_descriptor(
                handle, info, MIB, "pinned dependency manifest changed")
            named = os.open(relative_path.name, open_flags(), dir_fd=current)
            try:
                require(snapshot(os.fstat(named)) == identity,
                        "pinned dependency manifest changed")
            finally:
                os.close(named)
            stable_directories(
                root_directories + component_state,
                "pinned dependency manifest path changed")
            require(snapshot(os.fstat(handle)) == identity,
                    "pinned dependency manifest changed")
        header, found = raw[:-1].split(b"\t", 1)
        mode, kind, oid = header.decode("ascii").split(" ")
        require(found == encoded and kind == "blob"
                and mode in ("100644", "100755")
                and object_format in ("sha1", "sha256"),
                "invalid pinned dependency manifest identity")
        object_hash = hashlib.new(object_format)
        object_hash.update(f"blob {len(data)}\0".encode("ascii"))
        object_hash.update(data)
        require(object_hash.hexdigest() == oid,
                "tracked source content differs from Git")
    except (OSError, RuntimeError, UnicodeDecodeError, ValueError):
        raise Refusal("pinned dependency manifest unavailable") from None
    finally:
        for descriptor in reversed(locals().get("opened", [])):
            try:
                os.close(descriptor)
            except OSError:
                pass
    return {
        "path": relative,
        "mode": mode,
        "bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "git_oid": oid,
        "metadata": list(snapshot(info)),
        "metadata_sha256": hashlib.sha256(
            json.dumps(snapshot(info), separators=(",", ":")).encode("ascii")).hexdigest(),
    }, data


def dependency_manifest_sources():
    require(
        Path(LOCAL_BOOT) == Path(REPO) / "support/tools/hyperv/local_boot",
        "pinned dependency manifest unavailable",
    )
    return tuple(
        (name, "support/tools/hyperv/local_boot/" + name)
        for name in ("build.zig", "build.zig.zon")
    )


def create_exact_copy(path, data):
    require(canonical(path.parent)
            and stat.S_ISDIR(path.parent.lstat().st_mode), "unsafe copy directory")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        handle = os.open(path, flags, 0o600)
    except FileExistsError as error:
        raise Refusal("dependency manifest target already exists") from error
    try:
        os.fchmod(handle, 0o600)
        offset = 0
        while offset < len(data):
            count = os.write(handle, data[offset:])
            require(count > 0, "dependency manifest copy failed")
            offset += count
        os.fsync(handle)
        copied = snapshot(os.fstat(handle))
    finally:
        os.close(handle)
    require(read(path, len(data)) == data and snapshot(path.lstat()) == copied,
            "dependency manifest copy changed")
    return {
        "bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "metadata": list(copied),
    }


def restored_manifest_state(restore, expected):
    try:
        before = restore.lstat()
    except FileNotFoundError as error:
        raise Refusal("dependency restore directory unavailable") from error
    require(canonical(restore)
            and stat.S_ISDIR(before.st_mode)
            and before.st_uid == os.getuid()
            and stat.S_IMODE(before.st_mode) == 0o700,
            "unsafe dependency restore directory")
    entries = sorted(entry.name for entry in os.scandir(restore))
    require(entries == ["build.zig", "build.zig.zon", "zig-pkg"],
            "unexpected dependency restore entry")
    packages = restore / "zig-pkg"
    package_info = packages.lstat()
    require(stat.S_ISDIR(package_info.st_mode) and package_info.st_uid == os.getuid()
            and stat.S_IMODE(package_info.st_mode) == 0o700,
            "unsafe dependency package directory")
    manifests = {}
    for name in ("build.zig", "build.zig.zon"):
        path = restore / name
        info = path.lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
                and info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o600,
                "unsafe copied dependency manifest")
        data = read(path, MIB)
        require(data == expected[name] and snapshot(path.lstat()) == snapshot(info),
                "copied dependency manifest differs from source")
        manifests[name] = {
            "bytes": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
            "metadata": list(snapshot(info)),
        }
    require(snapshot(restore.lstat()) == snapshot(before),
            "dependency restore directory changed")
    return {
        "directory": {"metadata": list(snapshot(before))},
        "manifests": manifests,
    }


def safe_package_name(name):
    require(PACKAGE_NAME.fullmatch(name) is not None
            and name not in (".", ".."), "unsafe package root name")
    return name


def safe_package_component(name):
    require(name not in ("", ".", "..") and "/" not in name and "\0" not in name
            and len(name.encode("utf-8")) <= 255,
            "unsafe dependency package path")
    return name


def package_tree_state(packages):
    try:
        root_before = packages.lstat()
    except FileNotFoundError as error:
        raise Refusal("private pinned dependency restore required") from error
    require(canonical(packages)
            and stat.S_ISDIR(root_before.st_mode)
            and root_before.st_uid == os.getuid()
            and stat.S_IMODE(root_before.st_mode) == 0o700,
            "private pinned dependency restore required")
    directories = {}
    files = {}
    roots = []

    def collect(directory, prefix, depth):
        require(depth <= 64, "dependency package depth exceeded")
        before = directory.lstat()
        require(stat.S_ISDIR(before.st_mode) and before.st_uid == os.getuid(),
                "unsafe dependency package directory")
        directories[prefix] = snapshot(before)
        require(len(files) + len(directories) - 1 <= PACKAGE_MAX_ENTRIES,
                "dependency package entry limit exceeded")
        try:
            entries = sorted(os.scandir(directory), key=lambda entry: entry.name)
        except OSError as error:
            raise Refusal("dependency package enumeration failed") from error
        if not prefix:
            require(0 < len(entries) <= PACKAGE_MAX_ROOTS,
                    "invalid dependency package roots")
        for entry in entries:
            if not prefix:
                safe_package_name(entry.name)
            else:
                safe_package_component(entry.name)
            relative = entry.name if not prefix else prefix + "/" + entry.name
            require(len(relative.encode()) <= 1024,
                    "dependency package path too long")
            path = directory / entry.name
            info = path.lstat()
            if stat.S_ISDIR(info.st_mode):
                if not prefix:
                    roots.append(entry.name)
                collect(path, relative, depth + 1)
                continue
            require(prefix and stat.S_ISREG(info.st_mode) and info.st_nlink == 1
                    and info.st_uid == os.getuid() and info.st_size <= PACKAGE_MAX_FILE,
                    "nonregular or unsafe dependency package entry")
            files[relative] = snapshot(info)
            require(len(files) + len(directories) - 1 <= PACKAGE_MAX_ENTRIES,
                    "dependency package entry limit exceeded")
        require(snapshot(directory.lstat()) == snapshot(before),
                "dependency package directory changed")

    collect(packages, "", -1)
    require(roots == sorted(set(roots)), "ambiguous dependency package roots")
    return {"roots": roots, "directories": directories, "files": files}


def package_file(path, expected):
    info = path.lstat()
    require(snapshot(info) == expected
            and stat.S_ISREG(info.st_mode) and info.st_nlink == 1
            and info.st_uid == os.getuid() and info.st_size <= PACKAGE_MAX_FILE,
            "dependency package file replaced")
    with path.open("rb") as stream:
        require(snapshot(os.fstat(stream.fileno())) == expected,
                "dependency package file replaced")
        data = stream.read(PACKAGE_MAX_FILE + 1)
    require(len(data) == info.st_size and snapshot(path.lstat()) == expected,
            "dependency package file changed")
    return data


def directory_inventory(packages, name, state):
    root = packages / name
    tree = hashlib.sha256(b"hyperv-native-tree-v1\0")
    physical = hashlib.sha256(b"hyperv-native-physical-v1\0")
    files = 0
    directories = 0
    total = 0
    seen_directories = set()
    seen_files = set()

    def collect(directory, prefix, depth):
        nonlocal files, directories, total
        require(depth <= 64, "dependency package depth exceeded")
        relative = name if not prefix else name + "/" + prefix
        require(relative in state["directories"], "unexpected dependency package directory")
        before = state["directories"][relative]
        require(snapshot(directory.lstat()) == before,
                "dependency package directory changed")
        seen_directories.add(relative)
        directories += 1
        require(files + directories <= PACKAGE_MAX_ENTRIES,
                "dependency package entry limit exceeded")
        bind(tree, ["directory", prefix, stat.S_IMODE(before[2])])
        bind(physical, ["directory", prefix, before])
        try:
            entries = sorted(os.scandir(directory), key=lambda entry: entry.name)
        except OSError as error:
            raise Refusal("dependency package enumeration failed") from error
        for entry in entries:
            safe_package_component(entry.name)
            relative = entry.name if not prefix else prefix + "/" + entry.name
            require(len(relative.encode()) <= 1024, "dependency package path too long")
            path = directory / entry.name
            global_relative = name + "/" + relative
            if global_relative in state["directories"]:
                collect(path, relative, depth + 1)
                continue
            require(global_relative in state["files"],
                    "unexpected dependency package entry")
            info = state["files"][global_relative]
            data = package_file(path, info)
            seen_files.add(global_relative)
            files += 1
            total += len(data)
            require(files + directories <= PACKAGE_MAX_ENTRIES
                    and total <= PACKAGE_MAX_BYTES,
                    "dependency package limit exceeded")
            sha256 = hashlib.sha256(data).hexdigest()
            bind(tree, ["file", relative, len(data), stat.S_IMODE(info[2]), sha256])
            bind(physical, ["file", relative, len(data), sha256, info])
        require(snapshot(directory.lstat()) == before,
                "dependency package directory changed")

    collect(root, "", 0)
    expected_directories = {
        relative for relative in state["directories"]
        if relative == name or relative.startswith(name + "/")
    }
    expected_files = {
        relative for relative in state["files"]
        if relative.startswith(name + "/")
    }
    require(files > 0 and seen_directories == expected_directories
            and seen_files == expected_files,
            "empty or changed dependency package")
    return {
        "files": files,
        "directories": directories,
        "bytes": total,
        "tree_sha256": tree.hexdigest(),
        "physical_sha256": physical.hexdigest(),
    }


def package_roots(packages):
    try:
        before = packages.lstat()
    except FileNotFoundError as error:
        raise Refusal("private pinned dependency restore required") from error
    require(canonical(packages)
            and stat.S_ISDIR(before.st_mode)
            and before.st_uid == os.getuid()
            and stat.S_IMODE(before.st_mode) == 0o700,
            "private pinned dependency restore required")
    entries = sorted(os.scandir(packages), key=lambda entry: entry.name)
    require(0 < len(entries) <= PACKAGE_MAX_ROOTS, "invalid dependency package roots")
    names = []
    for entry in entries:
        safe_package_name(entry.name)
        info = (packages / entry.name).lstat()
        require(stat.S_ISDIR(info.st_mode), "dependency package root must be a directory")
        names.append(entry.name)
    require(len(names) == len(set(names)) and snapshot(packages.lstat()) == snapshot(before),
            "ambiguous or changed dependency package roots")
    return names


def package_dependencies(raw):
    dependencies = zon_block(raw, "dependencies", required=False)
    if dependencies is None:
        return []
    hashes = zon_strings(dependencies, "hash")
    for value in hashes:
        safe_package_name(value)
    require(len(hashes) == len(set(hashes)), "ambiguous transitive package dependency")
    return sorted(hashes)


def command_record(path, stage, limit):
    raw = read(path, limit + 1)
    require(len(raw) <= limit, "dependency command capture exceeded")
    return {
        "scope": "command_diagnostic_not_acceptance",
        "stage": stage,
        "exit_code": 0,
        "bytes": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "over_limit": False,
        "known_error_markers": command_error_markers(raw),
    }


def dependency_custody(root):
    restore = root / "dependencies"
    require(canonical(restore)
            and stat.S_ISDIR(restore.lstat().st_mode)
            and restore.lstat().st_uid == os.getuid()
            and stat.S_IMODE(restore.lstat().st_mode) == 0o700,
            "private dependency restore directory required")
    manifests = {}
    manifest_data = {}
    for name, relative in dependency_manifest_sources():
        source_record, expected = tracked_manifest(relative)
        manifest_data[name] = expected
        manifests[name] = {"source": source_record}
    restored = restored_manifest_state(restore, manifest_data)
    for name in manifests:
        manifests[name]["copy"] = restored["manifests"][name]
    request = validate_restore_manifest(read(restore / "build.zig.zon", MIB))
    packages = restore / "zig-pkg"
    package_state = package_tree_state(packages)
    names = package_state["roots"]
    records = []
    manifest_digest = hashlib.sha256(b"uk.wamr.package-manifests-v1\0")
    manifest_count = 0
    manifest_bytes = 0
    dependencies = {}
    for name in names:
        package = packages / name
        inventory = directory_inventory(packages, name, package_state)
        manifest = package / "build.zig.zon"
        if manifest.exists():
            require(not manifest.is_symlink(), "unsafe transitive package manifest")
            raw = read(manifest, 4 * MIB)
            deps = package_dependencies(raw)
            manifest_record = {
                "bytes": len(raw),
                "sha256": hashlib.sha256(raw).hexdigest(),
                "dependencies": deps,
            }
            manifest_count += 1
            manifest_bytes += len(raw)
            bind(manifest_digest, [name, manifest_record])
        else:
            manifest_record = None
            deps = []
        dependencies[name] = deps
        records.append({"package_hash": name, "content": inventory,
                        "manifest": manifest_record})
    require(package_tree_state(packages) == package_state,
            "dependency package directory set changed")
    reachable = set()
    pending = [MIZ_PACKAGE_HASH]
    while pending:
        name = pending.pop()
        require(name in dependencies, "missing transitive dependency package")
        if name in reachable:
            continue
        reachable.add(name)
        pending.extend(dependencies[name])
        require(len(reachable) + len(pending) <= PACKAGE_MAX_ROOTS * 2,
                "transitive dependency closure limit exceeded")
    require(reachable == set(names), "unexpected transitive dependency package")
    hash_records = []
    for index, name in enumerate(names):
        path = root / "private" / f"dependency-hash-{index:03d}.log"
        raw = read(path, 512)
        require(raw == (name + "\n").encode("ascii"),
                "Zig package content hash mismatch")
        hash_records.append({"package_hash": name,
                             "sha256": hashlib.sha256(raw).hexdigest()})
    closure = hashlib.sha256(b"uk.wamr.package-closure-v1\0")
    for record in records:
        bind(closure, record)
    physical = hashlib.sha256(b"uk.wamr.package-physical-closure-v1\0")
    for record in records:
        bind(physical, [record["package_hash"], record["content"]["physical_sha256"]])
    root_info = package_state["directories"][""]
    record = {
        "schema": "uk.wamr.zig-dependency-custody",
        "version": 1,
        "request": request,
        "source_manifests": manifests,
        "restore_directory": restored["directory"],
        "restore": command_record(root / "private/dependency-restore.log",
                                  "dependency-restore", 8 * MIB),
        "packages": {
            "roots": len(records),
            "files": sum(item["content"]["files"] for item in records),
            "directories": sum(item["content"]["directories"] for item in records),
            "bytes": sum(item["content"]["bytes"] for item in records),
            "closure_sha256": closure.hexdigest(),
            "physical_sha256": physical.hexdigest(),
            "root_metadata": list(root_info),
            "root_metadata_sha256": hashlib.sha256(json.dumps(
                root_info, separators=(",", ":")).encode("ascii")).hexdigest(),
            "manifests": {
                "count": manifest_count,
                "bytes": manifest_bytes,
                "sha256": manifest_digest.hexdigest(),
            },
            "hash_verification": {
                "algorithm": "zig-0.16.0-fetch-path",
                "count": len(hash_records),
                "sha256": hashlib.sha256(json.dumps(
                    hash_records, sort_keys=True,
                    separators=(",", ":")).encode("ascii")).hexdigest(),
            },
            "records": records,
        },
    }
    require(record["packages"]["files"] <= PACKAGE_MAX_ENTRIES
            and record["packages"]["files"] + record["packages"]["directories"]
            <= PACKAGE_MAX_ENTRIES
            and record["packages"]["bytes"] <= PACKAGE_MAX_BYTES,
            "dependency closure limit exceeded")
    return record


def require_consumer_inputs(runtime, expected, content=False):
    consumer_input_state(
        runtime, content=content, expected=expected)


def verify_package_hashes(runtime, root, packages, expected_inputs):
    work = root / "dependency-hash-work"
    cache = root / "dependency-hash-cache"
    work.mkdir(mode=0o700)
    cache.mkdir(mode=0o700)
    expected = {}
    copies = {}
    for name in ("build.zig", "build.zig.zon"):
        data = read(root / "dependencies" / name, MIB)
        expected[name] = data
        copies[name] = create_exact_copy(work / name, data)
    (work / "zig-pkg").mkdir(mode=0o700)
    work_state = restored_manifest_state(work, expected)
    require(work_state["manifests"] == copies,
            "dependency hash workspace manifest identity changed")
    names = package_roots(packages)
    for index, name in enumerate(names):
        try:
            require_consumer_inputs(runtime, expected_inputs)
            output, _ = execute(
                root, f"dependency-hash-{index:03d}",
                [tool("zig"), "fetch", "--global-cache-dir", cache, packages / name],
                300, 511, cwd=work, evidence=False,
                input_records=consumer_file_records(expected_inputs))
            require_consumer_inputs(runtime, expected_inputs)
        except Refusal as error:
            raise Refusal("Zig package hash recomputation failed") from error
        require(read(output, 512) == (name + "\n").encode("ascii"),
                "Zig package content hash mismatch")
        require(restored_manifest_state(work, expected) == work_state,
                "dependency hash workspace manifest identity changed")


def restore_dependencies(runtime, root, expected_source, expected_inputs):
    manifest_sources = dependency_manifest_sources()
    restore = root / "dependencies"
    restore.mkdir(mode=0o700)
    require_source(expected_source)
    source_manifests = {}
    manifest_data = {}
    copied_manifests = {}
    for name, relative in manifest_sources:
        record, data = tracked_manifest(relative)
        source_manifests[name] = record
        manifest_data[name] = data
        copied_manifests[name] = create_exact_copy(restore / name, data)
    (restore / "zig-pkg").mkdir(mode=0o700)
    validate_restore_manifest(read(restore / "build.zig.zon", MIB))
    restored = restored_manifest_state(restore, manifest_data)
    require(restored["manifests"] == copied_manifests,
            "copied dependency manifest identity changed")
    require_source(expected_source)
    try:
        require_consumer_inputs(runtime, expected_inputs)
        _, command = execute(root, "dependency-restore", [
            tool("zig"), "build", "--build-file", restore / "build.zig",
            "--fetch=all", "--cache-dir", root / "cache",
            "--global-cache-dir", root / "global-cache", "-j2",
        ], 900, evidence=False,
            input_records=consumer_file_records(expected_inputs))
        require_consumer_inputs(runtime, expected_inputs)
    except Refusal as error:
        raise Refusal("pinned dependency restore command failed") from error
    require(command["known_error_markers"] == [], "dependency restore reported an error")
    require(restored_manifest_state(restore, manifest_data) == restored,
            "copied dependency manifest identity changed")
    packages = restore / "zig-pkg"
    require(any(os.scandir(packages)), "private pinned dependency restore required")
    package_roots(packages)
    verify_package_hashes(runtime, root, packages, expected_inputs)
    custody = dependency_custody(root)
    require(custody["source_manifests"] == {
        name: {
            "source": record,
            "copy": copied_manifests[name],
        }
        for name, record in source_manifests.items()
    } and custody["restore_directory"] == restored["directory"],
            "copied dependency manifest identity changed")
    require_source(expected_source)
    return packages


def require_build_custody(runtime, expected):
    current_source = source()
    source_matches = (
        source_identity(current_source) == expected["source"]
        and current_source["custody"] == expected["source_custody"]
    )
    if not source_matches:
        root = runtime / "compute"
        baseline = root / "private/source-metadata.json"
        failure = root / "evidence/source-custody-failure.json"
        if baseline.is_file() and not failure.exists():
            report = source_metadata_changes(
                source_metadata_document(baseline)["records"], source_metadata())
            report["source"] = source_identity(current_source)
            ignored_paths, truncated = ignored_status_diagnostic(REPO)
            report["ignored_paths"] = ignored_paths
            report["ignored_paths_truncated"] = truncated
            report["root_entries"] = source_root_inventory(REPO)
            save(failure, report)
    require(source_matches, "immutable source custody changed")
    require_dependency_custody(runtime / "compute", expected["dependencies"])
    require_consumer_inputs(runtime, expected["consumer_inputs"])


def require_dependency_custody(root, expected):
    require(dependency_custody(root) == expected, "dependency custody changed")


def run_custodied(runtime, expected, root, stage, args, seconds=600,
                  limit=8 * MIB, extra_inputs=None):
    require_build_custody(runtime, expected)
    if extra_inputs is not None:
        require_consumer_inputs(runtime, extra_inputs)
    records = consumer_file_records(expected["consumer_inputs"])
    if extra_inputs is not None:
        records.update(consumer_file_records(extra_inputs))
    output = run(
        root, stage, args, seconds, limit, input_records=records)
    if extra_inputs is not None:
        require_consumer_inputs(runtime, extra_inputs)
    require_build_custody(runtime, expected)
    return output


def check_build():
    identity = document(APP / "build/artifacts/identity.json")
    require(identity["wamr_revision"] == REVISION
            and identity.get("development_only", False) is False
            and identity.get("variant", "tiny") == "tiny"
            and identity.get("jit_mode") is None
            and identity["compiler_profile"] == "unikraft-x86_64"
            and identity["zig_version"] == "0.16.0"
            and identity["minimal_wasi"] is False, "not the pinned tiny producer")
    names = {"embedded.c", "identity.h", "libwamr-aot.a", "tiny.cwasm",
             "tiny.wasm", "wamr_aot.h", "wamrc"}
    require(set(identity["files"]) == names, "unexpected runtime artifacts")
    for name, expected in identity["files"].items():
        require(digest(APP / "build/artifacts" / name) == expected,
                "runtime artifact changed")
    current_source = source()
    image = document(APP / "build/image-identity.json")
    require(image["schema_version"] == 1
            and image["unikraft_revision"] == current_source["revision"]
            and image["unikraft_diff_sha256"] == hashlib.sha256(b"").hexdigest(),
            "dirty or different image source")
    require(image["runtime_inputs_sha256"] == digest(APP / "build/artifacts/identity.json"),
            "runtime manifest changed")
    require(image["solved_config_sha256"] == solved_config(), "config changed")
    require(set(image["files"]) == {EFI, EFI + ".dbg", EFI + ".bootinfo"},
            "unexpected final images")
    for name, expected in image["files"].items():
        require(digest(APP / "build" / name) == expected, "final image changed")
    actual_sources = {p.name: digest(p) for p in APP.iterdir()
                      if p.is_file() and not p.name.startswith(".")}
    require(image["application_sources"] == actual_sources, "application changed")
    require(set(image["tools"]) == {"zig", "make", "llvm-nm", "llvm-objcopy",
                                   "llvm-objdump", "llvm-readelf", "llvm-strip",
                                   "bison", "flex"}, "missing build tools")
    for name, expected in image["tools"].items():
        require(name in ("zig", "make", "llvm-nm", "llvm-objcopy", "llvm-objdump",
                         "llvm-readelf", "llvm-strip", "bison", "flex")
                and digest(Path(tool(name))) == expected, "build tool changed")
    config = read(APP / ".config", MIB).decode()
    for setting in ("CONFIG_APPWAMRAOT=y", "CONFIG_ARCH_X86_64=y",
                    "CONFIG_PLAT_HYPERV=y", "CONFIG_LIBUKVMEM=y",
                    "CONFIG_LIBUKPAGING=y", "CONFIG_UKPLAT_CPU_MAXCOUNT=1"):
        require(config.splitlines().count(setting) == 1, "wrong compute config")
    for symbol in ("APPHYPERVACCEPTANCE", "APPHYPERVSMPWORKLOAD", "LIBSTORVSC",
                   "LIBNETVSC", "LIBLWIP"):
        require("CONFIG_" + symbol + "=y" not in config.splitlines(),
                "hardware application configuration")
    return {"source": source_identity(current_source),
            "runtime": identity, "image": image}


def normalize_serial(raw):
    # Match local_boot/serial.zig; evidence identities remain over the raw bytes.
    require(0 < len(raw) < 4 * MIB, "serial bound")
    raw.decode("utf-8")
    normalized = ANSI_ESCAPE.sub(b"", raw).replace(b"\0", b"")
    require(all(byte >= 0x20 or byte in b"\n\r\t" for byte in normalized),
            "invalid serial control")
    require(all(len(line) <= 8192 for line in normalized.split(b"\n")),
            "serial line bound")
    return normalized.decode("utf-8").replace("\r\n", "\n")


def compute(raw, identity, legacy):
    text = normalize_serial(raw)
    lines = text.split("\n")
    require(lines.count(MARKER) == 1 and text.count(MARKER) == 1,
            "completion must be one exact line")
    require(text.count(LEGACY) == int(legacy), "wrong APIC observation")
    require(not any(marker in text for marker in FORBIDDEN), "unexpected acceptance")
    compute_lines = [line for line in lines if "WAMR_NATIVE_COMPUTE=" in line]
    require(len(compute_lines) == 1 and compute_lines[0].startswith("WAMR_NATIVE_COMPUTE="),
            "one anchored compute record required")
    start = text.index("Calling main(")
    record = text.index(compute_lines[0])
    done = text.index(MARKER)
    terminal = text.index("main returned")
    require(start < record < done < terminal, "compute envelope order")
    spec = importlib.util.spec_from_file_location("wamr_app_log", APP / "check-log.py")
    checker = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(checker)
    # The app-owned validator supplies independent exact answer/growth/trap and
    # native selftest/accounting expectations; the CLI already checked terminal/crash.
    checker.validate(text, identity)
    return json.loads(compute_lines[0].split("=", 1)[1], object_pairs_hook=unique)


def config_for(runtime, root, index):
    legacy = bool(index % 2)
    source_kind = "raw_disk" if index < 2 else "fixed_vhd"
    return {
        "source": {
            "kind": source_kind,
            "path": str(root / "package" / ("unikraft.raw" if index < 2 else "unikraft.vhd")),
        },
        "ovmf_code": str(runtime / "firmware/code.fd"),
        "ovmf_vars": str(runtime / "firmware/vars.fd"),
        "qemu": str(runtime / "bin/qemu-system-x86_64"),
        "work_dir": str(root / ("boot-" + MODES[index])),
        "expect": MARKER, "expect_main_return": 0,
        "required": [LEGACY] if legacy else [],
        "forbidden": list(FORBIDDEN) + ([] if legacy else [LEGACY]),
        "cpus": 1, "disable_x2apic": legacy, "timeout_ms": 60_000,
    }


def boot_args(cli, config):
    source = config["source"]
    args = [str(cli), "--" + source["kind"].replace("_", "-"), source["path"]]
    for key in ("qemu", "ovmf_code", "ovmf_vars", "work_dir", "expect",
                "expect_main_return", "cpus"):
        args += ["--" + key.replace("_", "-"), str(config[key])]
    args += ["--timeout", "60"]
    if config["disable_x2apic"]:
        args += ["--disable-x2apic"]
    for key, flag in (("required", "--require-marker"), ("forbidden", "--forbid-marker")):
        for marker in config[key]:
            args += [flag, marker]
    return args


def pin_from_record(record):
    metadata = record["metadata"]
    mtime_seconds, mtime_nanoseconds = divmod(metadata[7], 1_000_000_000)
    ctime_seconds, ctime_nanoseconds = divmod(metadata[8], 1_000_000_000)
    return {
        "device_major": os.major(metadata[0]),
        "device_minor": os.minor(metadata[0]),
        "inode": metadata[1],
        "mode": metadata[2],
        "uid": metadata[3],
        "gid": metadata[4],
        "nlink": metadata[5],
        "size": metadata[6],
        "mtime_seconds": mtime_seconds,
        "mtime_nanoseconds": mtime_nanoseconds,
        "ctime_seconds": ctime_seconds,
        "ctime_nanoseconds": ctime_nanoseconds,
        "sha256": list(bytes.fromhex(record["sha256"])),
    }


def check_boot(config, identity, boot_inputs=None):
    work = Path(config["work_dir"])
    request = document(work / "request.json")
    require(request["schema_version"] == 2 and request["config"] == config,
            "wrong boot request")
    paths = [
        ("source", Path(config["source"]["path"])),
        ("ovmf_code", Path(config["ovmf_code"])),
        ("ovmf_vars", Path(config["ovmf_vars"])),
        ("qemu", Path(config["qemu"])),
    ]
    require(len(request["pins"]) == 4, "missing physical pins")
    for (name, path), pin in zip(paths, request["pins"]):
        if name == "source" or boot_inputs is None:
            record, unused = physical_file_record(path)
            del unused
        else:
            require(name in boot_inputs["files"], "missing boot input custody")
            record = boot_inputs["files"][name]
            require(record["path"] == str(path), "wrong boot input path")
        require(pin == pin_from_record(record), "boot input changed")
    require(read(work / "launched", 1) == b"", "invalid launch")
    report = document(work / "report.json")
    require(report["schema_version"] == 1
            and report["scope"] == "public_local_qemu_only"
            and report["acceptance"] == "not_established", "wrong local report")
    for name in ("passed", "consumed", "cleanup_complete", "input_unchanged", "serial_valid"):
        require(report[name] is True, "incomplete local boot")
    require(report["serial_limit_reached"] is False
            and report["termination"] == {"exited": 0}
            and report["failures"] == {"primary": None, "cleanup": None, "recording": None},
            "local boot failed")
    raw = read(work / "hyperv-efi-boot.log", 4 * MIB)
    require(report["serial_bytes"] == len(raw)
            and report["serial_sha256"] == hashlib.sha256(raw).hexdigest(),
            "serial binding changed")
    return {"scope": "local_native_compute_only", "report": report,
            "input_pins": request["pins"],
            "request_sha256": digest(work / "request.json"),
            "report_sha256": digest(work / "report.json"),
            "compute": compute(raw, identity, config["disable_x2apic"])}


def prepare_source_outputs():
    require(APP == REPO / "support/apps/wamr-aot",
            "invalid source output role policy")
    output = REPO / "support/apps/wamr-aot/build"
    config = REPO / "support/apps/wamr-aot/.config"
    backup = APP / ".config.old"
    cache = REPO / ".zig-cache"
    runtime = REPO / ".d"
    source_output_root(runtime, "directory")
    require(not output.exists() and not output.is_symlink()
            and not config.exists() and not config.is_symlink()
            and not backup.exists() and not backup.is_symlink()
            and not cache.exists() and not cache.is_symlink(),
            "fresh precreated source output roots required")
    cache.mkdir(mode=0o700)
    output.mkdir(mode=0o700)
    definition = read(APP / "defconfig", MIB)
    create_exact_copy(output / ".config", definition)
    create_exact_copy(config, definition)
    source_output_roots(REPO)


def require_no_config_backup():
    backup = APP / ".config.old"
    require(not backup.exists() and not backup.is_symlink(),
            "unexpected configuration backup")


def retain_solved_config():
    source_path = APP / "build/.config"
    target = APP / ".config"
    data = read(source_path, MIB)
    parent = snapshot(APP.lstat())
    before = target.lstat()
    require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
            and before.st_uid == os.getuid() and stat.S_IMODE(before.st_mode) == 0o600,
            "unsafe solved configuration target")
    flags = os.O_WRONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    handle = os.open(target, flags)
    try:
        require(snapshot(os.fstat(handle)) == snapshot(before),
                "solved configuration target replaced")
        os.ftruncate(handle, 0)
        offset = 0
        while offset < len(data):
            count = os.write(handle, data[offset:])
            require(count > 0, "solved configuration copy failed")
            offset += count
        os.fsync(handle)
    finally:
        os.close(handle)
    require(read(target, MIB) == data and snapshot(APP.lstat()) == parent,
            "solved configuration publication changed source directory")


def solved_config():
    retained = read(APP / ".config", MIB)
    require(retained == read(APP / "build/.config", MIB),
            "solved build configuration changed")
    return hashlib.sha256(retained).hexdigest()


def build(runtime, wamr):
    root = runtime / "compute"
    root.mkdir(mode=0o700)
    for name in ("private", "evidence", "scratch", "cache", "global-cache",
                 "global-cache/tmp", "fixtures"):
        (root / name).mkdir(mode=0o700)
    prepare_source_outputs()
    bison_data = os.environ.get("BISON_PKGDATADIR")
    require(bison_data == str(runtime / "bison"),
            "Bison build environment differs from bound producer input")
    COMMAND_ENVIRONMENT.clear()
    COMMAND_ENVIRONMENT.update({
        "BISON_PKGDATADIR": bison_data,
        "KCONFIG_CONFIG": str(APP / "build/.config"),
        "KCONFIG_OVERWRITECONFIG": "1",
        "M4": tool("m4"),
        "MAKEFLAGS": "-j2",
        "TMPDIR": str(root / "scratch"),
        "ZIG_GLOBAL_CACHE_DIR": str(root / "global-cache"),
        "ZIG_LOCAL_CACHE_DIR": str(root / "cache"),
    })
    os.environ.update(COMMAND_ENVIRONMENT)
    source_archive = seal_wamr_source(runtime, wamr)
    consumer_inputs = consumer_input_state(runtime)
    initial_source = source()
    save(root / "private/source-metadata.json", {
        "schema": "uk.wamr.git-physical-source-baseline",
        "version": 1,
        "records": source_metadata(),
    })
    packages = restore_dependencies(
        runtime, root, initial_source, consumer_inputs)
    initial = producer_inputs(runtime, consumer_inputs)
    require(initial["source"] == source_identity(initial_source)
            and initial["source_custody"] == initial_source["custody"],
            "source changed during dependency restoration")
    save(root / "evidence/build-start.json", initial)
    zig = tool("zig")
    consumer_records = consumer_file_records(consumer_inputs)
    with retained_executables(
            (zig,), consumer_records) as (
                retained, pass_fds):
        version = bounded_subprocess_output(
            [retained[zig], "version"], REPO, 64, 30,
            "Zig version output too large", "Zig version check timed out",
            "Zig version check failed",
            env=command_environment(root, consumer_records),
            pass_fds=pass_fds)
    require(version.strip() == b"0.16.0", "Zig 0.16.0 required")
    run_custodied(runtime, initial, root, "adapter", [
        tool("zig"), "build", "--build-file", HERE / "build.zig",
        "--system", packages, "--prefix", root / "tools",
        "-Doptimize=ReleaseSafe", "-j2", "test", "install"], 900)
    run_custodied(runtime, initial, root, "local-boot-tool", [
        tool("zig"), "build", "--build-file", LOCAL_BOOT / "build.zig",
        "--system", packages, "--prefix", root / "tools",
        "-Doptimize=ReleaseSafe", "-j2", "install"], 900)
    os.environ["WAMR_CI_PACKAGE"] = str(root / "tools/bin/wamr-ci-package")
    run_custodied(runtime, initial, root, "fixtures", [
        sys.executable, "-m", "unittest", "discover", "-s", HERE / "tests", "-v"])
    run_custodied(runtime, initial, root, "prepare", [
        sys.executable, APP / "prepare.py", "prepare",
        "--source-archive", source_archive], 1800)
    run_custodied(runtime, initial, root, "config", [
        sys.executable, APP / "build-image.py", "olddefconfig"])
    require_no_config_backup()
    retain_solved_config()
    solved_config()
    require_build_custody(runtime, initial)
    # This target includes the unchanged final ELF IRQ/constructor/SMP proofs.
    run_custodied(runtime, initial, root, "native-image", [
        sys.executable, APP / "build-image.py", "native-images"], 1800)
    solved_config()
    require(producer_inputs(runtime, consumer_inputs) == initial,
            "source or producer tool changed during build")
    save(root / "evidence/build.json", check_build())


def boot(runtime):
    require(platform.machine() == "x86_64" and Path("/dev/kvm").is_char_device()
            and os.access("/dev/kvm", os.R_OK | os.W_OK),
            "x86 KVM runner required; no successful skip")
    root = runtime / "compute"
    initial = document(root / "evidence/build-start.json")
    consumer_inputs = initial["consumer_inputs"]
    require(producer_inputs(runtime, consumer_inputs) == initial,
            "producer inputs changed")
    require(check_build() == document(root / "evidence/build.json"), "build identity changed")
    efi = APP / "build" / EFI
    paths = {"package_tool": root / "tools/bin/wamr-ci-package",
             "local_boot_tool": root / "tools/bin/uk-hyperv-local-boot",
             "qemu": runtime / "bin/qemu-system-x86_64",
             "ovmf_code": runtime / "firmware/code.fd",
             "ovmf_vars": runtime / "firmware/vars.fd",
             "efi": efi}
    inputs = boot_input_state(runtime, paths)
    save(root / "evidence/boot-inputs.json", inputs)

    def verify_inputs(content=False):
        boot_input_state(
            runtime, paths, content=content, expected=inputs)

    verify_inputs()
    output = run_custodied(
        runtime, initial, root, "package",
        [paths["package_tool"], "package", efi, root / "package"],
        150, 64 * 1024, extra_inputs=inputs)
    package = document(output)
    require(package["image"]["efi"]["sha256"] == digest(efi)
            and package["producer_sha256"] == inputs["package_tool"],
            "package identity changed")
    save(root / "evidence/package.json", {
        "scope": package["scope"], "acceptance": package["acceptance"],
        "producer_sha256": package["producer_sha256"],
        "image": {key: package["image"][key] for key in (
            "schema_version", "miz_revision", "efi", "raw", "vhd",
            "footer_sha256", "packaging")},
    })
    identity = document(APP / "build/artifacts/identity.json")
    for index, mode in enumerate(MODES):
        config = config_for(runtime, root, index)
        Path(config["work_dir"]).mkdir(mode=0o700)
        run_custodied(
            runtime, initial, root, mode,
            boot_args(paths["local_boot_tool"], config), 90, 64 * 1024,
            extra_inputs=inputs)
        result = check_boot(config, identity, inputs)
        expected = package["image"]["raw" if index < 2 else "vhd"]["sha256"]
        require(digest(Path(config["source"]["path"])) == expected,
                "booted package changed")
        save(root / "evidence" / (mode + "-compute.json"), result)
    output = run_custodied(
        runtime, initial, root, "inspect",
        [paths["package_tool"], "inspect", efi, root / "package"],
        150, 64 * 1024, extra_inputs=inputs)
    require(document(output) == package, "physical package reload changed")
    verify_inputs(content=True)
    require(producer_inputs(runtime, consumer_inputs) == initial,
            "producer inputs changed after boot")
    require(check_build() == document(root / "evidence/build.json"), "source or image changed")
    # No self hash: this final record binds earlier immutable observations only.
    save(root / "evidence/result.json", {
        "schema_version": 1, "scope": "local_native_compute_only", "passed": True,
        "hardware_acceptance": "not_established", "cloud_authority": "not_admitted",
        "benchmark": "not_measured", "workload": "tiny", "modes": list(MODES),
        "records": {p.name: digest(p) for p in sorted((root / "evidence").glob("*.json"))},
    })


def diagnostics(runtime):
    """Allowlisted observations only. Raw serial/build/runtime logs stay private."""
    root = runtime / "compute"
    root.mkdir(mode=0o700, exist_ok=True)
    (root / "evidence").mkdir(mode=0o700, exist_ok=True)
    observations = {}
    for mode in MODES:
        entry = {"report": "unavailable", "serial": "unavailable"}
        work = root / ("boot-" + mode)
        try:
            report = document(work / "report.json")
            for key in ("passed", "cleanup_complete", "input_unchanged",
                        "serial_valid", "serial_limit_reached"):
                require(type(report[key]) is bool, "invalid diagnostic")
            entry["report"] = {key: report[key] for key in (
                "passed", "cleanup_complete", "input_unchanged",
                "serial_valid", "serial_limit_reached")}
            entry["failure_lanes"] = [key for key in ("primary", "cleanup", "recording")
                                     if report["failures"][key] is not None]
            if report["cleanup_complete"]:
                raw = read(work / "hyperv-efi-boot.log", 4 * MIB)
                entry["serial"] = {"bytes": len(raw),
                                   "sha256": hashlib.sha256(raw).hexdigest()}
        except (OSError, ValueError, KeyError, TypeError):
            pass
        observations[mode] = entry
    save(root / "evidence/diagnostics.json", {
        "scope": "diagnostics_not_acceptance",
        "redaction": "no_raw_serial_paths_environment_or_account_state",
        "boots": observations,
    })


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("build", "boot", "diagnostics"))
    parser.add_argument("--runtime", type=Path, required=True)
    parser.add_argument("--wamr-source", type=Path)
    args = parser.parse_args()
    runtime = args.runtime
    require(runtime.is_absolute() and canonical(runtime)
            and runtime.stat().st_uid == os.getuid()
            and stat.S_IMODE(runtime.stat().st_mode) == 0o700, "private runtime root required")
    os.umask(0o077)
    if args.command == "build":
        require(args.wamr_source is not None, "pinned WAMR checkout required")
        build(runtime, args.wamr_source.resolve(strict=True))
    elif args.command == "boot":
        boot(runtime)
    else:
        diagnostics(runtime)


if __name__ == "__main__":
    try:
        main()
    except Refusal as error:
        print("WAMR_CI_REFUSED: " + str(error), file=sys.stderr)
        sys.exit(1)
    except (OSError, RuntimeError, ValueError, KeyError, TypeError,
            subprocess.SubprocessError):
        print("WAMR native compute CI failed; bounded private logs and redacted diagnostics retained.",
              file=sys.stderr)
        sys.exit(1)
