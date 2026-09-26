#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""One tiny native compute image; no cloud, hardware, or benchmark admission."""
import sys

sys.dont_write_bytecode = True

import argparse
import base64
import contextlib
import hashlib
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
SIX_MODES = (
    "raw-x2apic", "raw-legacy-apic",
    "qcow2-x2apic", "qcow2-legacy-apic",
    "vpc-x2apic", "vpc-legacy-apic",
)
CURRENT_PROFILE = "qcow2-derived-vhd"
WAMR_AOT_BUILD_ROLE = "native:wamr-aot-build"
WAMR_AOT_BUILD_RELATIVE = "compute/tools/bin/uk-wamr-aot-build"
WAMR_LOG_VALIDATOR_ROLE = "native:wamr-log-validate"
WAMR_LOG_VALIDATOR_RELATIVE = "compute/tools/bin/uk-wamr-log-validate"
RECORDED_EXECUTABLE_TARGET = (
    "-Dtarget=x86_64-linux-gnu", "-Dcpu=x86_64_v2",
)
PRODUCTION_COMMAND_STAGES = frozenset({
    "adapter", "local-boot-tool", "fixtures", "prepare", "config",
    "native-image", "package", *SIX_MODES, "finalize-qcow2",
    "derive-fixed-vhd", "inspect",
    "public-validator-build", "handoff-inspect", "handoff-inspect-legacy",
    "supervisor-import-identity", "native-revalidation",
})
LOG_VALIDATOR_STAGES = {
    "log-validator-x2apic": "forbidden",
    "log-validator-legacy": "required",
}
STRICT_SUPERVISED_STAGES = PRODUCTION_COMMAND_STAGES.union(LOG_VALIDATOR_STAGES)
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
INDIRECT_HOST_TOOLS = ("dash", "cp", "env", "mkdir", "readlink", "uname")
HOST_TOOLS = (
    "git", "python3", "bash", *INDIRECT_HOST_TOOLS,
    "zig", "make", "llvm-nm", "llvm-objcopy", "llvm-objdump",
    "llvm-readelf", "llvm-strip", "bison", "flex", "m4",
)
SUBPROCESS_TERM_GRACE = 1.0
SUBPROCESS_KILL_GRACE = 1.0
SUBPROCESS_DRAIN_GRACE = 1.0
INPUT_TREE_MAX_ENTRIES = 100_000
INPUT_TREE_MAX_BYTES = 2 * 1024 * MIB
COMMAND_ENVIRONMENT = {}
COMMAND_TOOL_PATHS = {}
COMMAND_SUPERVISOR_PATH = None
COMMAND_SUPERVISOR_VERSION = "uk.wamr.command-supervisor/1 process-command/1"
COMMAND_BINDING_SCHEMA = "uk.wamr.supervised-command-binding"
COMMAND_BINDING_VERSION = 1
COMMAND_CLEANUP_SECONDS = 10
COMMAND_STREAM_MAX = 4 * MIB
COMMAND_RESULT_MAX = 12 * MIB
COMMAND_REQUEST_MAX = MIB
COMMAND_STRING_MAX = 4096
COMMAND_OUTPUT_COMMITMENT_DOMAIN = b"uk.wamr.command-output-v1\0"
COMMAND_CONTRACT = json.loads(
    (REPO / "support/tools/hyperv/process-command-v1.json").read_text(
        encoding="utf-8"))
if (set(COMMAND_CONTRACT) != {
        "complete_cleanup_events_min",
        "complete_primary_events_min",
        "pre_release_cleanup_events_min",
} or any(type(value) is not int or value < 1
         for value in COMMAND_CONTRACT.values())):
    raise RuntimeError("invalid process-command-v1 contract")
COMMAND_COMPLETE_PRIMARY_EVENTS_MIN = (
    COMMAND_CONTRACT["complete_primary_events_min"])
COMMAND_COMPLETE_CLEANUP_EVENTS_MIN = (
    COMMAND_CONTRACT["complete_cleanup_events_min"])
COMMAND_PRE_RELEASE_CLEANUP_EVENTS_MIN = (
    COMMAND_CONTRACT["pre_release_cleanup_events_min"])
EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()
BOOTSTRAP_STAGES = frozenset({
    "dependency-restore",
    "supervisor-build",
    *(f"dependency-hash-{index:03d}" for index in range(PACKAGE_MAX_ROOTS)),
})
SUPERVISOR_SOURCE_FILES = (
    "support/build/wamr-native-ci/build.zig.zon",
    "support/build/wamr-native-ci/run.py",
    "support/build/wamr-native-ci/supervisor.build.zig",
    "support/build/wamr-native-ci/supervisor.zig",
    "support/tools/hyperv/core.zig",
    "support/tools/hyperv/contracts.zig",
    "support/tools/hyperv/diagnostics.zig",
    "support/tools/hyperv/private_files.zig",
    "support/tools/hyperv/process-command-v1.json",
    "support/tools/hyperv/process.zig",
    "support/tools/hyperv/sensitive.zig",
    "support/tools/hyperv/sha256.zig",
    "support/tools/hyperv/sha256_clear_upper.S",
)
FAILURE_STAGE = "startup"
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
UNITTEST_FAILURE_PATTERN = re.compile(
    rb"^(test_[A-Za-z0-9_]+) \(([A-Za-z0-9_.]+)\).* \.\.\. "
    rb"(?:FAIL|ERROR)$",
    re.MULTILINE,
)


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


def validate_json_domain(value):
    if value is None or type(value) is bool:
        return
    if type(value) is int:
        require(-(1 << 63) <= value <= (1 << 64) - 1,
                "JSON integer is outside native range")
        return
    if isinstance(value, str):
        try:
            value.encode("utf-8")
        except UnicodeEncodeError as error:
            raise Refusal("JSON string is not valid Unicode") from error
        return
    if isinstance(value, (list, tuple)):
        for item in value:
            validate_json_domain(item)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            require(isinstance(key, str), "JSON object key is not a string")
            validate_json_domain(key)
            validate_json_domain(item)
        return
    raise Refusal("unsupported JSON value")


def compact_json(value, newline=False):
    validate_json_domain(value)
    try:
        text = json.dumps(
            value, ensure_ascii=False, allow_nan=False,
            sort_keys=True, separators=(",", ":"))
        return (text + ("\n" if newline else "")).encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError) as error:
        raise Refusal("invalid JSON value") from error


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
    raw = compact_json(value)
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
    with path.open("xb") as stream:
        stream.write(compact_json(value, newline=True))
    path.chmod(0o600)


def tool(name):
    selected = COMMAND_TOOL_PATHS.get(name)
    if selected is not None:
        return selected
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


def git_arguments(*args):
    return [
        "--no-pager",
        "-c", "core.hooksPath=/dev/null",
        "-c", "core.fsmonitor=false",
        "-c", "core.fsmonitorHookVersion=",
        "-c", "credential.helper=",
        "-c", "core.pager=cat",
        *args,
    ]


def git_command(*args):
    return [tool("git"), *git_arguments(*args)]


def command_environment(root, input_records=None, extra=None, *, stage=None):
    del input_records
    if stage in LOG_VALIDATOR_STAGES:
        require(not extra, "validator environment must be empty")
        return {}
    environment = {
        "HOME": str(Path(root) / "private"),
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin",
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


def bounded_scandir(directory, limit, limit_reason, failure_reason):
    require(type(limit) is int and limit >= 0, limit_reason)
    entries = []
    try:
        iterator = os.scandir(directory)
    except OSError as error:
        raise Refusal(failure_reason) from error
    try:
        for entry in iterator:
            require(len(entries) < limit, limit_reason)
            entries.append(entry)
    except OSError as error:
        raise Refusal(failure_reason) from error
    finally:
        iterator.close()
    entries.sort(key=lambda entry: entry.name)
    return entries


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


def missing_tree_symlink_target(path, reason):
    path = Path(path)
    require(
        path.is_absolute()
        and len(os.fsencode(str(path))) <= SOURCE_IGNORED_MAX_PATH
        and len(path.parts) - 1 <= SOURCE_IGNORED_MAX_DEPTH,
        reason,
    )
    missing = []
    probe = path
    while probe != Path("/"):
        try:
            with retained_absolute(
                    probe, directory=True, reason=reason) as (
                        handle, directories, unused_parent):
                del unused_parent
                info = os.fstat(handle)
                require(
                    missing and os.getuid() != 0 and info.st_uid == 0
                    and not info.st_mode & 0o022,
                    reason,
                )
                try:
                    os.stat(
                        missing[0], dir_fd=handle, follow_symlinks=False)
                except FileNotFoundError:
                    pass
                except OSError as error:
                    raise Refusal(reason) from error
                else:
                    raise Refusal(reason)
                identity = snapshot(info)
                component_records = stable_directories(directories, reason)
                require(snapshot(os.fstat(handle)) == identity, reason)
                return {
                    "ancestor": str(probe),
                    "missing": missing,
                    "metadata": list(identity),
                    "directories": component_records,
                }
        except Refusal:
            missing.insert(0, probe.name)
            probe = probe.parent
    raise Refusal(reason)


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
            entries = bounded_scandir(
                directory_handle,
                INPUT_TREE_MAX_ENTRIES
                - files - directories_count - symlinks,
                "physical input tree entry limit exceeded",
                "physical input tree enumeration failed",
            )
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
                    symlink_reason = (
                        "unsafe physical input tree symlink: " + relative)
                    require(info.st_uid in (0, os.getuid())
                            and 0 < info.st_size < 4096,
                            symlink_reason)
                    try:
                        target = os.readlink(name, dir_fd=directory_handle)
                    except OSError as error:
                        raise Refusal(symlink_reason) from error
                    try:
                        resolved = (root / relative).resolve(strict=True)
                        require(
                            len(os.fsencode(str(resolved)))
                            <= SOURCE_IGNORED_MAX_PATH
                            and len(resolved.parts) - 1
                            <= SOURCE_IGNORED_MAX_DEPTH,
                            symlink_reason,
                        )
                        target_is_directory = stat.S_ISDIR(
                            resolved.lstat().st_mode)
                    except FileNotFoundError:
                        try:
                            unresolved = (
                                (root / relative).parent / target
                            ).resolve(strict=False)
                            missing_target = missing_tree_symlink_target(
                                unresolved, symlink_reason)
                        except (OSError, RuntimeError) as error:
                            raise Refusal(symlink_reason) from error
                        symlinks += 1
                        total += len(os.fsencode(target))
                        require(
                            total <= INPUT_TREE_MAX_BYTES
                            and files + directories_count + symlinks
                            <= INPUT_TREE_MAX_ENTRIES,
                            "physical input tree limit exceeded",
                        )
                        bind(content_hash, [
                            "symlink-missing", relative, target,
                            missing_target["ancestor"],
                            missing_target["missing"],
                        ])
                        bind(physical_hash, [
                            "symlink-missing", relative, target, snapshot(info),
                            missing_target,
                        ])
                        continue
                    except (OSError, RuntimeError) as error:
                        raise Refusal(symlink_reason) from error
                    with retained_absolute(
                            resolved, directory=target_is_directory,
                            reason=symlink_reason + " target path") as (
                                target_handle, target_directories, target_parent):
                        target_info = os.fstat(target_handle)
                        if target_is_directory:
                            require(
                                stat.S_ISDIR(target_info.st_mode),
                                symlink_reason + " target type",
                            )
                            require(
                                target_info.st_uid in (0, os.getuid()),
                                symlink_reason + " target owner",
                            )
                            require(
                                not target_info.st_mode & 0o022,
                                symlink_reason + " writable target",
                            )
                            require(
                                resolved == root or root in resolved.parents,
                                symlink_reason + " external directory",
                            )
                        else:
                            require(
                                stat.S_ISREG(target_info.st_mode),
                                symlink_reason + " target type",
                            )
                            require(
                                target_info.st_uid in (0, os.getuid()),
                                symlink_reason + " target owner",
                            )
                            require(
                                target_info.st_nlink > 0
                                and (target_info.st_uid == 0
                                     or target_info.st_nlink == 1),
                                symlink_reason + " target links",
                            )
                            require(
                                not target_info.st_mode & 0o022,
                                symlink_reason + " writable target",
                            )
                            require(
                                target_info.st_size <= 512 * MIB,
                                symlink_reason + " target size",
                            )
                        target_identity = snapshot(target_info)
                        target_sha256 = (
                            "directory" if target_is_directory
                            else content_identities.get(target_identity)
                        )
                        if not target_is_directory:
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
                                    resolved.name,
                                    open_flags(directory=target_is_directory),
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
                        "symlink-directory" if target_is_directory
                        else "symlink",
                        relative, target, target_sha256,
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
    return hashlib.sha256(compact_json(value)).hexdigest()


def input_directory_custody_reason(kind, name):
    if kind == "file":
        if name.startswith("tool:"):
            tool_name = name.removeprefix("tool:")
            if tool_name in HOST_TOOLS:
                return f"consumer {tool_name} tool directory custody changed"
        if name.startswith("runtime:"):
            return "consumer runtime directory custody changed"
        if name == "wamr-source-archive":
            return "consumer archive directory custody changed"
        if name in {
                "efi", "local_boot_tool", "ovmf_code", "ovmf_vars",
                "package_tool", "qemu"}:
            return f"consumer {name} directory custody changed"
    elif kind == "tree" and name in {
            "bison", "llvm", "python-stdlib", "zig"}:
        return f"consumer {name} directory custody changed"
    return "consumer input directory custody changed"


def require_input_directories(components, expected, reason):
    for index, (path, metadata) in enumerate(components.items()):
        if expected.get(path) != metadata:
            distance = len(components) - index - 1
            raise Refusal(f"{reason} at ancestor-{distance}")


def canonical_input_paths(paths, reason):
    result = {}
    for name, path in paths.items():
        require(isinstance(name, str) and name, reason)
        path = Path(path)
        require(path.is_absolute() and canonical(path), reason)
        result[name] = path
    return result


def record_input_paths(file_paths, tree_paths, content=True, expected=None,
                       scope="consumer"):
    require(scope in ("consumer", "boot"), "invalid input custody scope")
    file_paths = canonical_input_paths(
        file_paths, "invalid consumer input file discovery")
    tree_paths = canonical_input_paths(
        tree_paths, "invalid consumer input tree discovery")
    files = {}
    trees = {}
    directories = {}
    if expected is not None:
        require(
            isinstance(expected, dict)
            and set(expected) == {
                "schema", "version", "files", "trees", "directories",
                "aggregate_sha256",
            }
            and expected.get("schema") == "uk.wamr.consumer-input-custody"
            and expected.get("version") == 2
            and isinstance(expected.get("files"), dict)
            and isinstance(expected.get("trees"), dict)
            and isinstance(expected.get("directories"), dict)
            and isinstance(expected.get("aggregate_sha256"), str)
            and all(
                isinstance(record, dict)
                and set(record) == {"path", "metadata", "sha256"}
                and isinstance(record["path"], str)
                for record in expected["files"].values()
            )
            and all(
                isinstance(record, dict)
                and set(record) == {
                    "path", "files", "directories", "symlinks", "bytes",
                    "content_sha256", "physical_sha256",
                }
                and isinstance(record["path"], str)
                for record in expected["trees"].values()
            ),
            "invalid consumer input custody",
        )
        actual_file_roles = set(file_paths)
        expected_file_roles = set(expected["files"])
        if actual_file_roles != expected_file_roles:
            added = actual_file_roles - expected_file_roles
            missing = expected_file_roles - actual_file_roles
            raise Refusal(
                f"{scope} input file roles changed "
                f"(direct -{sum(not role.startswith('runtime:') for role in missing)}"
                f"/+{sum(not role.startswith('runtime:') for role in added)}, "
                f"runtime -{sum(role.startswith('runtime:') for role in missing)}"
                f"/+{sum(role.startswith('runtime:') for role in added)})"
            )
        require(set(tree_paths) == set(expected["trees"]),
                f"{scope} input tree roles changed")
        require(all(
            expected["files"][name]["path"] == str(path)
            for name, path in file_paths.items()
        ), f"{scope} input file paths changed")
        require(all(
            expected["trees"][name]["path"] == str(path)
            for name, path in tree_paths.items()
        ), f"{scope} input tree paths changed")
    for name, path in sorted(file_paths.items()):
        prior = None if expected is None else expected["files"][name]
        record, components = physical_file_record(
            path, content=content,
            expected_sha256=None if prior is None else prior["sha256"])
        files[name] = record
        if expected is not None:
            require_input_directories(
                components, expected["directories"],
                input_directory_custody_reason("file", name))
        merge_directory_records(directories, components)
    for name, path in sorted(tree_paths.items()):
        prior = None if expected is None else expected["trees"][name]
        record, components = physical_tree_record(
            path, content=content,
            expected_content_sha256=(
                None if prior is None else prior["content_sha256"]))
        trees[name] = record
        if expected is not None:
            require_input_directories(
                components, expected["directories"],
                input_directory_custody_reason("tree", name))
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
        require(result["files"] == expected["files"],
                "consumer input file custody changed")
        require(result["trees"] == expected["trees"],
                "consumer input tree custody changed")
        require(result["directories"] == expected["directories"],
                "consumer input directory custody changed")
        require(result == expected, "consumer input custody changed")
    return result


def discover_consumer_input_paths(runtime, expected=None):
    runtime = Path(runtime)
    tool_paths = {name: Path(tool(name)) for name in HOST_TOOLS}
    runtime_paths = set()
    for path in tool_paths.values():
        runtime_paths.update(executable_runtime_paths(path))
    file_paths = {
        **{f"tool:{name}": path for name, path in tool_paths.items()},
        **{f"runtime:{path}": path for path in sorted(runtime_paths)},
    }
    supervisor = runtime / "compute/supervisor/bin/wamr-ci-supervisor"
    if supervisor.is_file() and not supervisor.is_symlink():
        supervisor = supervisor.resolve(strict=True)
        file_paths["command-supervisor"] = supervisor
        for path in executable_runtime_paths(supervisor):
            file_paths[f"runtime:{path}"] = path
    tree_paths = {
        "bison": runtime / "bison",
        "python-stdlib": Path(sysconfig.get_paths()["stdlib"]).resolve(strict=True),
        "zig": tool_paths["zig"].parent,
    }
    llvm = runtime / "llvm"
    if llvm.is_dir() and not llvm.is_symlink():
        tree_paths["llvm"] = llvm
    archive = runtime / "custody/wamr-source.tar"
    if archive.is_file() and not archive.is_symlink():
        file_paths["wamr-source-archive"] = archive
    for role, relative, label in (
            (WAMR_AOT_BUILD_ROLE, WAMR_AOT_BUILD_RELATIVE, "build"),
            (WAMR_LOG_VALIDATOR_ROLE, WAMR_LOG_VALIDATOR_RELATIVE, "log validator")):
        executable = runtime / relative
        expected_native = (
            expected is not None and role in expected.get("files", {})
        )
        if expected_native or (
                expected is None
                and (executable.exists() or executable.is_symlink())):
            require(executable.is_file() and not executable.is_symlink(),
                    f"installed native WAMR {label} executable unavailable")
            file_paths[role] = executable
            for path in executable_runtime_paths(executable):
                file_paths[f"runtime:{path}"] = path
    return (
        canonical_input_paths(
            file_paths, "invalid consumer input file discovery"),
        canonical_input_paths(
            tree_paths, "invalid consumer input tree discovery"),
    )


def consumer_input_state(runtime, content=True, expected=None):
    file_paths, tree_paths = discover_consumer_input_paths(runtime, expected)
    return record_input_paths(
        file_paths, tree_paths, content=content, expected=expected)


def discover_boot_input_paths(runtime, paths):
    file_paths = dict(paths)
    runtime_paths = set()
    for path in paths.values():
        if os.access(path, os.X_OK):
            runtime_paths.update(executable_runtime_paths(path))
    file_paths.update({
        f"runtime:{path}": path for path in sorted(runtime_paths)
    })
    qemu_data = Path(runtime) / "bin/share"
    tree_paths = {"qemu-data": qemu_data}
    return (
        canonical_input_paths(
            file_paths, "invalid boot input file discovery"),
        canonical_input_paths(
            tree_paths, "invalid boot input tree discovery"),
    )


def boot_input_state(runtime, paths, content=True, expected=None):
    file_paths, tree_paths = discover_boot_input_paths(runtime, paths)
    return record_input_paths(
        file_paths, tree_paths, content=content, expected=expected,
        scope="boot")


def consumer_file_records(value):
    require(value.get("schema") == "uk.wamr.consumer-input-custody"
            and value.get("version") == 2,
            "invalid consumer input custody")
    return {
        record["path"]: record for record in value["files"].values()
    }


def bind_command_tools(value):
    selected = {}
    for name in HOST_TOOLS:
        record = value["files"].get("tool:" + name)
        require(isinstance(record, dict), "missing consumer tool input")
        path = Path(record["path"])
        require(path.is_absolute(), "invalid consumer tool input")
        selected[name] = str(path)
    COMMAND_TOOL_PATHS.clear()
    COMMAND_TOOL_PATHS.update(selected)
    supervisor_path = bind_command_supervisor(value)
    environment = {
        "PATH": "/usr/bin:/bin",
        "WAMR_CI_GIT": selected["git"],
        "WAMR_CI_SUPERVISOR": supervisor_path,
    }
    for name, path in selected.items():
        environment[
            "WAMR_CI_TOOL_" + name.upper().replace("-", "_")
        ] = path
    return environment


def bind_command_supervisor(value):
    global COMMAND_SUPERVISOR_PATH
    require(isinstance(value, dict)
            and isinstance(value.get("files"), dict),
            "invalid command supervisor input")
    supervisor = value["files"].get("command-supervisor")
    require(isinstance(supervisor, dict)
            and Path(supervisor["path"]).is_absolute(),
            "missing command supervisor input")
    COMMAND_SUPERVISOR_PATH = supervisor["path"]
    return COMMAND_SUPERVISOR_PATH


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
    require(existing <= limit, limit_reason)
    for entry in bounded_scandir(
            directory, limit - existing, limit_reason, path_reason):
        relative = entry.name if not parent else parent + "/" + entry.name
        path = normalized_repository_relative(relative, path_reason)
        paths.append((entry.name, path))
    return paths


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
                    try:
                        path.resolve(strict=True)
                    except FileNotFoundError:
                        pass
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


def guarded_record_map(domain, records):
    content = hashlib.sha256((domain + "-content\0").encode("ascii"))
    physical = hashlib.sha256((domain + "-physical\0").encode("ascii"))
    total = 0
    for name in sorted(records):
        record = records[name]
        total += record["bytes"]
        bind(content, [name, record["bytes"], record["sha256"]])
        bind(physical, [name, record["metadata"]])
    return {
        "count": len(records),
        "bytes": total,
        "content_closure_sha256": content.hexdigest(),
        "physical_closure_sha256": physical.hexdigest(),
        "records": records,
    }


def supervisor_source_map():
    records = {}
    for relative in SUPERVISOR_SOURCE_FILES:
        record, unused_data = tracked_manifest(relative)
        del unused_data
        records[relative] = {
            "bytes": record["bytes"],
            "sha256": record["sha256"],
            "metadata": record["metadata"],
        }
    return guarded_record_map("uk.wamr.command-supervisor-source-v1", records)


def supervisor_runtime_map(runtime, consumer_inputs):
    path = (Path(runtime)
            / "compute/supervisor/bin/wamr-ci-supervisor").resolve(strict=True)
    files = consumer_inputs["files"]
    executable = files.get("command-supervisor")
    require(isinstance(executable, dict)
            and executable["path"] == str(path),
            "missing command supervisor input")
    records = {
        "executable": {
            "bytes": executable["metadata"][6],
            "sha256": executable["sha256"],
            "metadata": executable["metadata"],
        },
    }
    for runtime_path in sorted(executable_runtime_paths(path)):
        role = "runtime:" + str(runtime_path)
        record = files.get(role)
        require(isinstance(record, dict), "missing command supervisor runtime")
        records[role] = {
            "bytes": record["metadata"][6],
            "sha256": record["sha256"],
            "metadata": record["metadata"],
        }
    return guarded_record_map("uk.wamr.command-supervisor-runtime-v1", records)


def command_supervisor_state(runtime, consumer_inputs):
    return {
        "schema": "uk.wamr.command-supervisor",
        "version": 1,
        "protocol": COMMAND_SUPERVISOR_VERSION,
        "source_map": supervisor_source_map(),
        "runtime_map": supervisor_runtime_map(runtime, consumer_inputs),
    }


def producer_inputs(runtime, expected_consumer=None, content=True):
    current_source = source()
    consumer_inputs = consumer_input_state(
        runtime, content=content, expected=expected_consumer)
    return {
        "source": source_identity(current_source),
        "source_custody": current_source["custody"],
        "tools": {name: digest(Path(tool(name))) for name in HOST_TOOLS},
        "bison_data": bison_inputs(runtime / "bison"),
        "dependencies": dependency_custody(runtime / "compute"),
        "consumer_inputs": consumer_inputs,
        "command_supervisor": command_supervisor_state(
            runtime, consumer_inputs),
    }


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
    encoded = compact_json(files)
    return {"files": len(files), "bytes": total,
            "sha256": hashlib.sha256(encoded).hexdigest()}


def command_error_markers(raw):
    observed = {match.group() for match in COMMAND_ERROR_PATTERN.finditer(raw)}
    return [name for name in COMMAND_ERROR_MARKERS if name.encode("ascii") in observed]


def unittest_failure_markers(raw):
    markers = []
    for match in UNITTEST_FAILURE_PATTERN.finditer(raw):
        marker = (
            match.group(2).decode("ascii") + "." + match.group(1).decode("ascii")
        )
        if marker not in markers:
            markers.append(marker)
        if len(markers) == 8:
            break
    return markers


@contextlib.contextmanager
def retained_executables(paths, records):
    opened = {}
    aliases = {}
    try:
        for path in paths:
            original = str(Path(path))
            canonical_path = str(Path(path).resolve(strict=True))
            aliases[original] = canonical_path
            if canonical_path in opened:
                continue
            require(canonical_path in records, "unbound executable input")
            record = records[canonical_path]
            handle = os.open(canonical_path, open_flags())
            info = os.fstat(handle)
            require(
                list(snapshot(info)) == record["metadata"]
                and stat.S_ISREG(info.st_mode)
                and bool(info.st_mode & 0o111),
                "executable input changed",
            )
            opened[canonical_path] = handle
        yield {
            original: f"/proc/self/fd/{opened[canonical_path]}"
            for original, canonical_path in aliases.items()
        }, tuple(opened.values())
    except OSError as error:
        raise Refusal("executable input changed") from error
    finally:
        for handle in reversed(tuple(opened.values())):
            try:
                os.close(handle)
            except OSError:
                pass


def retained_process_path(path):
    match = re.fullmatch(r"/proc/self/fd/([0-9]+)", path)
    require(match is not None, "invalid retained executable path")
    return f"/proc/{os.getpid()}/fd/{match.group(1)}"


def is_retained_process_path(path):
    return re.fullmatch(r"/proc/(?:self|[0-9]+)/fd/[0-9]+", path) is not None


def canonical_json(value):
    return compact_json(value, newline=True)


def native_integer(value, minimum, maximum, reason):
    require(type(value) is int and minimum <= value <= maximum, reason)
    return value


def native_u8(value, reason):
    return native_integer(value, 0, (1 << 8) - 1, reason)


def native_u16(value, reason):
    return native_integer(value, 0, (1 << 16) - 1, reason)


def native_u32(value, reason):
    return native_integer(value, 0, (1 << 32) - 1, reason)


def native_u64(value, reason):
    return native_integer(value, 0, (1 << 64) - 1, reason)


def native_i64(value, reason):
    return native_integer(value, -(1 << 63), (1 << 63) - 1, reason)


def native_string(value, maximum, reason, allow_empty=True):
    require(isinstance(value, str), reason)
    try:
        raw = value.encode("utf-8")
    except UnicodeEncodeError as error:
        raise Refusal(reason) from error
    require((allow_empty or raw) and len(raw) <= maximum, reason)
    return raw


def native_digest(value, reason):
    require(isinstance(value, str)
            and re.fullmatch(r"[0-9a-f]{64}", value), reason)
    return value


def validate_native_executable_identity(value, reason):
    require(isinstance(value, dict) and set(value) == {
        "content_sha256", "ctime_nanoseconds", "ctime_seconds",
        "device_major", "device_minor", "inode", "mode",
        "mtime_nanoseconds", "mtime_seconds", "size", "uid",
    }, reason)
    native_digest(value["content_sha256"], reason)
    native_u32(value["ctime_nanoseconds"], reason)
    native_i64(value["ctime_seconds"], reason)
    native_u32(value["device_major"], reason)
    native_u32(value["device_minor"], reason)
    native_u64(value["inode"], reason)
    native_u16(value["mode"], reason)
    native_u32(value["mtime_nanoseconds"], reason)
    native_i64(value["mtime_seconds"], reason)
    native_u64(value["size"], reason)
    native_u32(value["uid"], reason)
    require(value["inode"] > 0 and value["size"] > 0
            and value["ctime_nanoseconds"] < 1_000_000_000
            and value["mtime_nanoseconds"] < 1_000_000_000,
            reason)
    return value


def validate_supervisor_limits(value, reason):
    require(isinstance(value, dict) and set(value) == {
        "cleanup_events", "descendants", "primary_events",
        "proc_entries_per_scan", "reap_events", "stderr_bytes",
        "stdout_bytes", "term_grace_ms",
    }, reason)
    native_u64(value["stdout_bytes"], reason)
    native_u64(value["stderr_bytes"], reason)
    native_u16(value["descendants"], reason)
    native_u32(value["primary_events"], reason)
    native_u32(value["cleanup_events"], reason)
    native_u32(value["proc_entries_per_scan"], reason)
    native_u16(value["reap_events"], reason)
    native_u32(value["term_grace_ms"], reason)
    require(1 <= value["stdout_bytes"] <= COMMAND_STREAM_MAX
            and 1 <= value["stderr_bytes"] <= COMMAND_STREAM_MAX
            and 1 <= value["descendants"] <= 256
            and 16 <= value["primary_events"] <= 10_000_000
            and 32 <= value["cleanup_events"] <= 10_000_000
            and 16 <= value["proc_entries_per_scan"] <= 1_000_000
            and value["descendants"] + 3 <= value["reap_events"] <= 1024
            and 1 <= value["term_grace_ms"] <= 10_000,
            reason)
    return value


def validate_supervisor_request(value):
    reason = "invalid native command request"
    require(isinstance(value, dict) and set(value) == {
        "argv", "cleanup_deadline_ns", "cwd", "environment",
        "executable", "limits", "primary_deadline_ns",
        "retained_executables", "schema", "version",
    } and value["schema"] == "uk.wamr.command-supervisor-request"
      and native_u8(value["version"], reason) == 1,
      reason)
    executable = native_string(
        value["executable"], COMMAND_STRING_MAX, reason, allow_empty=False)
    cwd = native_string(
        value["cwd"], COMMAND_STRING_MAX, reason, allow_empty=False)
    require(executable.startswith(b"/") and cwd.startswith(b"/"), reason)
    argv = value["argv"]
    require(isinstance(argv, list) and 1 <= len(argv) <= 4096, reason)
    for argument in argv:
        raw = native_string(argument, COMMAND_STRING_MAX, reason)
        require(b"\0" not in raw, reason)
    require(argv[0] == value["executable"], reason)
    environment = value["environment"]
    require(isinstance(environment, list) and len(environment) <= 512, reason)
    previous = None
    by_name = {}
    for entry in environment:
        require(isinstance(entry, dict)
                and set(entry) == {"name", "value"}, reason)
        name = native_string(
            entry["name"], COMMAND_STRING_MAX, reason, allow_empty=False)
        raw_value = native_string(entry["value"], COMMAND_STRING_MAX, reason)
        require(b"=" not in name and b"\0" not in name
                and b"\0" not in raw_value
                and entry["name"] not in {
                    "WAMR_CI_RETAINED_EXECUTABLE",
                    "WAMR_CI_EXECUTABLE_PATH",
                }
                and (previous is None or previous < name), reason)
        previous = name
        by_name[entry["name"]] = entry["value"]
    retained = value["retained_executables"]
    require(isinstance(retained, list) and len(retained) <= 128, reason)
    previous = None
    for entry in retained:
        require(isinstance(entry, dict)
                and set(entry) == {"name", "path"}, reason)
        name = native_string(
            entry["name"], COMMAND_STRING_MAX, reason, allow_empty=False)
        path = native_string(
            entry["path"], COMMAND_STRING_MAX, reason, allow_empty=False)
        require(b"=" not in name and b"\0" not in name
                and path.startswith(b"/") and b"\0" not in path
                and (previous is None or previous < name)
                and by_name.get(entry["name"]) == entry["path"], reason)
        previous = name
    primary = native_u64(value["primary_deadline_ns"], reason)
    cleanup = native_u64(value["cleanup_deadline_ns"], reason)
    require(primary > 0 and cleanup > primary, reason)
    validate_supervisor_limits(value["limits"], reason)
    raw = canonical_json(value)
    require(len(raw) <= COMMAND_REQUEST_MAX, reason)
    return raw


def command_output_commitment(
        stdout_bytes, stdout_sha256, stderr_bytes, stderr_sha256):
    native_u64(stdout_bytes, "invalid native command output")
    native_u64(stderr_bytes, "invalid native command output")
    native_digest(stdout_sha256, "invalid native command output")
    native_digest(stderr_sha256, "invalid native command output")
    value = hashlib.sha256(COMMAND_OUTPUT_COMMITMENT_DOMAIN)
    value.update(stdout_bytes.to_bytes(8, "big"))
    value.update(bytes.fromhex(stdout_sha256))
    value.update(stderr_bytes.to_bytes(8, "big"))
    value.update(bytes.fromhex(stderr_sha256))
    return value.hexdigest()


def validate_supervisor_outcome(command, limits, reason):
    primary = command["primary"]
    termination = command["termination"]
    require(isinstance(primary, dict)
            and set(primary) == {"code", "kind"}
            and primary["kind"] in {
                "exited", "signal", "unknown", "timeout", "cancelled",
                "output_overflow", "exec_failed", "snapshot_unsupported",
                "event_limit", "local_io", "executable_changed",
            }
            and isinstance(termination, dict)
            and set(termination) == {"code", "kind"}
            and (termination["kind"] is None
                 or termination["kind"] in {
                     "exited", "signal", "stopped", "unknown",
                 }),
            reason)
    if primary["kind"] == "exited":
        native_u8(primary["code"], reason)
    elif primary["kind"] == "signal":
        native_integer(primary["code"], 1, 64, reason)
    elif primary["kind"] == "unknown":
        native_u32(primary["code"], reason)
    else:
        require(primary["code"] is None, reason)
    if termination["kind"] == "exited":
        native_u8(termination["code"], reason)
    elif termination["kind"] in {"signal", "stopped"}:
        native_integer(termination["code"], 1, 64, reason)
    elif termination["kind"] == "unknown":
        native_u32(termination["code"], reason)
    else:
        require(termination["code"] is None, reason)
    if primary["kind"] in {"exited", "signal", "unknown"}:
        require(termination == primary, reason)
    require(command["primary_deadline_reached"]
            is (primary["kind"] == "timeout")
            and command["cancellation_observed"]
            is (primary["kind"] == "cancelled")
            and (primary["kind"] != "event_limit"
                 or command["primary_events"] == limits["primary_events"])
            and (primary["kind"] != "executable_changed"
                 or not command["executable_stable"]
                 and termination == {"code": 0, "kind": "exited"})
            and (command["executable_stable"]
                 or primary != {"code": 0, "kind": "exited"}),
            reason)
    return primary, termination


def validate_supervisor_state(
        command, limits, timing, streams, primary_deadline_ns, reason):
    native_u32(command["primary_events"], reason)
    native_u32(command["cleanup_events"], reason)
    native_u16(command["reap_events"], reason)
    require(command["primary_events"] <= limits["primary_events"]
            and command["cleanup_events"] <= limits["cleanup_events"]
            and command["reap_events"] <= limits["reap_events"], reason)
    descendants = command["descendants"]
    require(isinstance(descendants, dict)
            and set(descendants) == {
                "adopted", "identity_validated", "limit_exceeded",
                "observed", "untracked",
            }
            and type(descendants["limit_exceeded"]) is bool
            and type(descendants["untracked"]) is bool,
            reason)
    for name in ("adopted", "identity_validated", "observed"):
        native_u16(descendants[name], reason)
    require(descendants["adopted"] <= descendants["observed"]
            and descendants["identity_validated"] == descendants["observed"]
            and descendants["observed"] <= limits["descendants"] + 1
            and descendants["limit_exceeded"]
            is (descendants["observed"] > limits["descendants"])
            and (not descendants["untracked"]
                 or descendants["limit_exceeded"]
                 and descendants["observed"] == limits["descendants"] + 1),
            reason)
    primary, termination = validate_supervisor_outcome(
        command, limits, reason)
    for name in ("stdout", "stderr"):
        stream = streams[name]
        size = native_u64(stream["bytes"], reason)
        require(isinstance(stream, dict)
                and set(stream) >= {"bytes", "sha256", "status"}
                and native_digest(stream["sha256"], reason)
                == stream["sha256"]
                and stream["status"] in {
            "complete", "overflow", "io_failed", "incomplete",
        }
                and size <= limits[name + "_bytes"]
                and (stream["status"] != "overflow"
                     or size == limits[name + "_bytes"]),
                reason)
    started = native_u64(timing["started_ns"], reason)
    primary_completed = native_u64(
        timing["primary_completed_ns"], reason)
    completed = native_u64(timing["completed_ns"], reason)
    require(started <= primary_completed <= completed
            and ((primary["kind"] == "timeout"
                  and primary_completed >= primary_deadline_ns)
                 or (primary["kind"] != "timeout"
                     and primary_completed < primary_deadline_ns)),
            reason)
    if command["cleanup"] == "complete":
        if command["primary_events"] == 0:
            require(command["cleanup_events"]
                    >= COMMAND_PRE_RELEASE_CLEANUP_EVENTS_MIN
                    and command["reap_events"] == 2
                    and termination["kind"] is not None
                    and command["executable_stable"] is True
                    and primary["kind"] in {
                        "timeout", "cancelled", "local_io",
                    }
                    and streams["stdout"]["bytes"] == 0
                    and streams["stdout"]["sha256"] == EMPTY_SHA256
                    and streams["stdout"]["status"] == "complete"
                    and streams["stderr"]["bytes"] == 0
                    and streams["stderr"]["sha256"] == EMPTY_SHA256
                    and streams["stderr"]["status"] == "complete"
                    and descendants == {
                        "adopted": 0,
                        "identity_validated": 0,
                        "limit_exceeded": False,
                        "observed": 0,
                        "untracked": False,
                    }, reason)
        else:
            require(command["primary_events"]
                    >= COMMAND_COMPLETE_PRIMARY_EVENTS_MIN
                    and command["cleanup_events"]
                    >= COMMAND_COMPLETE_CLEANUP_EVENTS_MIN
                    and command["reap_events"]
                    == descendants["observed"] + 2
                    and termination["kind"] is not None,
                    reason)
    elif command["cleanup"] == "not_required":
        require(command["primary_events"] == 0
                and command["cleanup_events"] == 0
                and command["reap_events"] == 0
                and command["executable_stable"] is True
                and primary["kind"] in {
                    "timeout", "cancelled", "local_io",
                    "snapshot_unsupported",
                }
                and termination == {"code": None, "kind": None}
                and completed == primary_completed
                and streams["stdout"]["bytes"] == 0
                and streams["stdout"]["sha256"] == EMPTY_SHA256
                and streams["stdout"]["status"] == "complete"
                and streams["stderr"]["bytes"] == 0
                and streams["stderr"]["sha256"] == EMPTY_SHA256
                and streams["stderr"]["status"] == "complete"
                and descendants == {
                    "adopted": 0,
                    "identity_validated": 0,
                    "limit_exceeded": False,
                    "observed": 0,
                    "untracked": False,
                }, reason)
    return primary, termination, started, primary_completed, completed


def command_digest_scope(size):
    return ("reproducible_empty"
            if size == 0 else "transport_authenticated_observation")


def command_literal(value):
    require(isinstance(value, str)
            and len(value.encode("utf-8")) <= 4096,
            "invalid public command literal")
    return {"kind": "literal", "value": value}


def command_path(role, relative=""):
    require(isinstance(role, str)
            and re.fullmatch(r"[a-z0-9][a-z0-9_:-]{0,127}", role)
            and isinstance(relative, str)
            and len(relative.encode("utf-8")) <= 4096,
            "invalid public command path")
    if relative:
        normalized_repository_relative(
            relative, "invalid public command path")
    return {"kind": "path", "role": role, "relative": relative}


def command_path_roots(root, path_roles=None):
    roots = {
        "source": (REPO, True),
        "work": (Path(root), True),
        "runtime": (Path(root).parent, True),
    }
    if COMMAND_SUPERVISOR_PATH is not None:
        roots["command-supervisor"] = (
            Path(COMMAND_SUPERVISOR_PATH), False)
    for name, path in COMMAND_TOOL_PATHS.items():
        roots["tool:" + name] = (Path(path), False)
    if "zig" in COMMAND_TOOL_PATHS:
        roots["tool-tree:zig"] = (
            Path(COMMAND_TOOL_PATHS["zig"]).parent, True)
    if path_roles is not None:
        for role, path in path_roles.items():
            require(isinstance(role, str) and Path(path).is_absolute(),
                    "invalid command path role")
            roots[role] = (Path(path), role in {"compute"})
    result = []
    for role, (path, descendants) in roots.items():
        canonical_path = path.resolve(strict=True)
        result.append((role, canonical_path, descendants))
    result.sort(key=lambda item: (
        not item[2], len(item[1].parts)), reverse=True)
    return result


def normalized_command_value(value, roots, strict=True):
    value = str(value)
    if not strict:
        return {
            "kind": "private",
            "sha256": hashlib.sha256(value.encode("utf-8")).hexdigest(),
        }
    if value == "/usr/bin:/bin" or not Path(value).is_absolute():
        return command_literal(value)
    path = Path(value)
    for role, root, descendants in roots:
        if path == root:
            return command_path(role)
        if descendants:
            try:
                relative = path.relative_to(root).as_posix()
            except ValueError:
                continue
            return command_path(role, relative)
    raise Refusal("unbound public command path")


def command_binding_digest(value):
    return hashlib.sha256(canonical_json(value)).hexdigest()


def command_environment_contract(kind):
    if kind == "validator-only":
        return []
    environment = {
        "HOME": command_path("work", "private"),
        "LANG": command_literal("C"),
        "LC_ALL": command_literal("C"),
        "PATH": command_literal("/usr/bin:/bin"),
        "PYTHONDONTWRITEBYTECODE": command_literal("1"),
        "TMPDIR": command_path(
            "work", "scratch" if kind.startswith("build-") else "private"),
        "WAMR_CI_SUPERVISOR": command_path("command-supervisor"),
    }
    if kind != "supervisor-only":
        environment["WAMR_CI_GIT"] = command_path("tool:git")
        for name in HOST_TOOLS:
            environment[
                "WAMR_CI_TOOL_" + name.upper().replace("-", "_")
            ] = command_path("tool:" + name)
    if kind.startswith("build-"):
        environment.update({
            "BISON_PKGDATADIR": command_path("runtime", "bison"),
            "KCONFIG_CONFIG": command_path(
                "source", "support/apps/wamr-aot/build/.config"),
            "KCONFIG_OVERWRITECONFIG": command_literal("1"),
            "M4": command_path("tool:m4"),
            "MAKEFLAGS": command_literal("-j2"),
            "WAMR_CI_PORTABLE_CONFIG": command_literal("1"),
            "ZIG_GLOBAL_CACHE_DIR": command_path(
                "work", "global-cache"),
            "ZIG_LIB_DIR": command_path("tool-tree:zig", "lib"),
            "ZIG_LOCAL_CACHE_DIR": command_path("work", "cache"),
        })
    if kind == "build-fixtures":
        environment.update({
            "WAMR_CI_PACKAGE": command_path(
                "work", "tools/bin/wamr-ci-package"),
            "WAMR_CI_PYTHON": command_path("tool:python3"),
            "WAMR_CI_SUPERVISOR_FIXTURE": command_path(
                "work", "tools/bin/wamr-ci-supervisor-fixture"),
            "WAMR_CI_LOG_VALIDATE": command_path(
                WAMR_LOG_VALIDATOR_ROLE),
        })
    if kind in {"build-base", "public-validator"}:
        environment["WAMR_CI_LAUNCH_EXECUTABLE"] = command_path("tool:zig")
    return [
        {"name": name, "value": value}
        for name, value in sorted(environment.items())
    ]


def command_retained_names(kind):
    if kind == "validator-only":
        return []
    names = {
        "WAMR_CI_SUPERVISOR",
    }
    if kind != "supervisor-only":
        names.add("WAMR_CI_GIT")
        names.update(
            "WAMR_CI_TOOL_" + name.upper().replace("-", "_")
            for name in HOST_TOOLS
        )
    if kind.startswith("build-"):
        names.add("M4")
    if kind == "build-fixtures":
        names.update(("WAMR_CI_PYTHON", "WAMR_CI_LOG_VALIDATE"))
    if kind in {"build-base", "public-validator"}:
        names.add("WAMR_CI_LAUNCH_EXECUTABLE")
    return sorted(names)


def boot_command_argv(stage, profile=CURRENT_PROFILE):
    modes = SIX_MODES if profile == CURRENT_PROFILE else MODES
    index = modes.index(stage)
    legacy = bool(index % 2)
    if profile == CURRENT_PROFILE:
        source_kind, source_name = (
            ("raw-disk", "unikraft.raw") if index < 2 else
            ("qcow2", "unikraft.qcow2") if index < 4 else
            ("fixed-vhd", "unikraft-derived.vhd")
        )
    else:
        source_kind, source_name = (
            ("raw-disk", "unikraft.raw") if index < 2 else
            ("fixed-vhd", "unikraft.vhd")
        )
    values = [
        command_path("input:local_boot_tool"),
        command_literal("--" + source_kind),
        command_path("work", "package/" + source_name),
        command_literal("--qemu"),
        command_path("input:qemu"),
        command_literal("--ovmf-code"),
        command_path("input:ovmf_code"),
        command_literal("--ovmf-vars"),
        command_path("input:ovmf_vars"),
        command_literal("--work-dir"),
        command_path("work", "boot-" + stage),
        command_literal("--expect"),
        command_literal(MARKER),
        command_literal("--expect-main-return"),
        command_literal("0"),
        command_literal("--cpus"),
        command_literal("1"),
        command_literal("--timeout"),
        command_literal("60"),
    ]
    if legacy:
        values.append(command_literal("--disable-x2apic"))
    if legacy:
        values.extend([
            command_literal("--require-marker"),
            command_literal(LEGACY),
        ])
    for marker in list(FORBIDDEN) + ([] if legacy else [LEGACY]):
        values.extend([
            command_literal("--forbid-marker"),
            command_literal(marker),
        ])
    return values


def production_command_contract(stage, profile=CURRENT_PROFILE):
    handoff_image = (APP / "build" / EFI).relative_to(REPO).as_posix()
    contracts = {
        "adapter": {
            "kind": "build-base", "seconds": 900,
            "output_limit": 8 * MIB,
            "command_executable": command_path("tool:zig"),
            "native_executable": command_path("command-supervisor"),
            "interpreter": None,
            "argv": [
                command_path("command-supervisor"),
                command_literal("--launch-retained"),
                command_path("tool:zig"),
                command_literal("build"),
                command_literal("--build-file"),
                command_path(
                    "source", "support/build/wamr-native-ci/build.zig"),
                command_literal("--system"),
                command_path("work", "dependencies/zig-pkg"),
                command_literal("--prefix"),
                command_path("work", "tools"),
                command_literal("-Doptimize=ReleaseSafe"),
                command_literal("-j2"),
                command_literal("test-unit"),
                command_literal("install"),
            ],
        },
        "local-boot-tool": {
            "kind": "build-base", "seconds": 900,
            "output_limit": 8 * MIB,
            "command_executable": command_path("tool:zig"),
            "native_executable": command_path("command-supervisor"),
            "interpreter": None,
            "argv": [
                command_path("command-supervisor"),
                command_literal("--launch-retained"),
                command_path("tool:zig"),
                command_literal("build"),
                command_literal("--build-file"),
                command_path(
                    "source", "support/tools/hyperv/local_boot/build.zig"),
                command_literal("--system"),
                command_path("work", "dependencies/zig-pkg"),
                command_literal("--prefix"),
                command_path("work", "tools"),
                command_literal("-Doptimize=ReleaseSafe"),
                command_literal("-j2"),
                command_literal("install"),
            ],
        },
        "fixtures": {
            "kind": "build-fixtures", "seconds": 600,
            "output_limit": 8 * MIB,
            "command_executable": command_path("tool:python3"),
            "native_executable": command_path("tool:python3"),
            "interpreter": command_path("tool:python3"),
            "argv": [
                command_path("tool:python3"),
                command_literal("-m"),
                command_literal("unittest"),
                command_literal("discover"),
                command_literal("-s"),
                command_path(
                    "source", "support/build/wamr-native-ci/tests"),
                command_literal("-v"),
            ],
        },
        "prepare": {
            "kind": "build-native", "seconds": 1800,
            "output_limit": 8 * MIB,
            "command_executable": command_path(WAMR_AOT_BUILD_ROLE),
            "native_executable": command_path(WAMR_AOT_BUILD_ROLE),
            "interpreter": None,
            "argv": [
                command_path(WAMR_AOT_BUILD_ROLE),
                command_literal("prepare"),
                command_literal("--repository"),
                command_path("source"),
                command_literal("--source-archive"),
                command_path("runtime", "custody/wamr-source.tar"),
            ],
        },
        "config": {
            "kind": "build-native", "seconds": 600,
            "output_limit": 8 * MIB,
            "command_executable": command_path(WAMR_AOT_BUILD_ROLE),
            "native_executable": command_path(WAMR_AOT_BUILD_ROLE),
            "interpreter": None,
            "argv": [
                command_path(WAMR_AOT_BUILD_ROLE),
                command_literal("olddefconfig"),
                command_literal("--repository"),
                command_path("source"),
            ],
        },
        "native-image": {
            "kind": "build-native", "seconds": 1800,
            "output_limit": 8 * MIB,
            "command_executable": command_path(WAMR_AOT_BUILD_ROLE),
            "native_executable": command_path(WAMR_AOT_BUILD_ROLE),
            "interpreter": None,
            "argv": [
                command_path(WAMR_AOT_BUILD_ROLE),
                command_literal("native-images"),
                command_literal("--repository"),
                command_path("source"),
            ],
        },
        "package": {
            "kind": "bound-tools", "seconds": 150,
            "output_limit": 64 * 1024,
            "command_executable": command_path("input:package_tool"),
            "native_executable": command_path("input:package_tool"),
            "interpreter": None,
            "argv": [
                command_path("input:package_tool"),
                command_literal("package"),
                command_path("input:efi"),
                command_path("work", "package"),
            ],
        },
        "finalize-qcow2": {
            "kind": "bound-tools", "seconds": 150,
            "output_limit": 64 * 1024,
            "command_executable": command_path("input:package_tool"),
            "native_executable": command_path("input:package_tool"),
            "interpreter": None,
            "argv": [
                command_path("input:package_tool"),
                command_literal("finalize-qcow2"),
                command_path(
                    "work", "evidence/qcow2-finalization-intent.json"),
                command_path("work", "package"),
            ],
        },
        "derive-fixed-vhd": {
            "kind": "bound-tools", "seconds": 150,
            "output_limit": 64 * 1024,
            "command_executable": command_path("input:package_tool"),
            "native_executable": command_path("input:package_tool"),
            "interpreter": None,
            "argv": [
                command_path("input:package_tool"),
                command_literal("derive-fixed-vhd"),
                command_path(
                    "work", "evidence/fixed-vhd-derivation-intent.json"),
                command_path("work", "package"),
            ],
        },
        "inspect": {
            "kind": "bound-tools", "seconds": 150,
            "output_limit": 64 * 1024,
            "command_executable": command_path("input:package_tool"),
            "native_executable": command_path("input:package_tool"),
            "interpreter": None,
            "argv": [
                command_path("input:package_tool"),
                command_literal("inspect"),
                command_path("input:efi"),
                command_path("work", "package"),
            ],
        },
        "public-validator-build": {
            "kind": "public-validator", "seconds": 600,
            "output_limit": 8 * MIB,
            "command_executable": command_path("tool:zig"),
            "native_executable": command_path("command-supervisor"),
            "interpreter": None,
            "argv": [
                command_path("command-supervisor"),
                command_literal("--launch-retained"),
                command_path("tool:zig"),
                command_literal("build"),
                command_literal("--build-file"),
                command_path(
                    "source", "support/tools/hyperv/direct/build.zig"),
                command_literal("--cache-dir"),
                command_path("work", "cache"),
                command_literal("--global-cache-dir"),
                command_path("work", "global-cache"),
                command_literal("--prefix"),
                command_path("work", "public-source/tools"),
                *(command_literal(value)
                  for value in RECORDED_EXECUTABLE_TARGET),
                command_literal("-Doptimize=ReleaseSafe"),
                command_literal("-j2"),
                command_literal("install"),
            ],
        },
        "handoff-inspect": {
            "kind": "bound-tools", "seconds": 150,
            "output_limit": 64 * 1024,
            "command_executable": command_path("input:package_tool"),
            "native_executable": command_path("input:package_tool"),
            "interpreter": None,
            "argv": [
                command_path("input:package_tool"),
                command_literal("inspect"),
                command_path("source", handoff_image),
                command_path("compute", "package"),
            ],
        },
        "handoff-inspect-legacy": {
            "kind": "supervisor-only", "seconds": 150,
            "output_limit": 64 * 1024,
            "command_executable": command_path("input:package_tool"),
            "native_executable": command_path("input:package_tool"),
            "interpreter": None,
            "argv": [
                command_path("input:package_tool"),
                command_literal("inspect"),
                command_path("source", handoff_image),
                command_path("compute", "package"),
            ],
        },
        "supervisor-import-identity": {
            "kind": "supervisor-only", "seconds": 30,
            "output_limit": 1024,
            "command_executable": command_path("command-supervisor"),
            "native_executable": command_path("command-supervisor"),
            "interpreter": None,
            "argv": [
                command_path("command-supervisor"),
                command_literal("--identity"),
            ],
        },
        "native-revalidation": {
            "kind": "supervisor-only", "seconds": 600,
            "output_limit": 4096,
            "command_executable": command_path("input:validator"),
            "native_executable": command_path("input:validator"),
            "interpreter": None,
            "argv": [
                command_path("input:validator"),
                command_literal("handoff"),
                command_path("input:bundle"),
            ],
        },
    }
    for mode in (SIX_MODES if profile == CURRENT_PROFILE else MODES):
        contracts[mode] = {
            "kind": "bound-tools", "seconds": 90,
            "output_limit": 64 * 1024,
            "command_executable": command_path("input:local_boot_tool"),
            "native_executable": command_path("input:local_boot_tool"),
            "interpreter": None,
            "argv": boot_command_argv(mode, profile),
        }
    for validator_stage, legacy in LOG_VALIDATOR_STAGES.items():
        contracts[validator_stage] = {
            "kind": "validator-only", "seconds": 30,
            "output_limit": 8192,
            "command_executable": command_path(WAMR_LOG_VALIDATOR_ROLE),
            "native_executable": command_path(WAMR_LOG_VALIDATOR_ROLE),
            "interpreter": None,
            "argv": [
                command_path(WAMR_LOG_VALIDATOR_ROLE),
                command_literal("tiny"),
                command_literal("--log"), command_path("input:serial"),
                command_literal("--identity"), command_path("input:identity"),
                command_literal("--legacy-apic"), command_literal(legacy),
                command_literal("--output"), command_literal("json-v1"),
            ],
        }
    require(stage in contracts, "unknown production command stage")
    contract = contracts[stage]
    return {
        **contract,
        "environment": command_environment_contract(contract["kind"]),
        "retained_names": command_retained_names(contract["kind"]),
        "cwd": command_path("source"),
        "limits": {
            "cleanup_events": 1_000_000,
            "descendants": 64,
            "primary_events": 1_000_000,
            "proc_entries_per_scan": 262_144,
            "reap_events": 512,
            "stderr_bytes": max(
                1, min(contract["output_limit"] + 1, COMMAND_STREAM_MAX)),
            "stdout_bytes": max(
                1, min(contract["output_limit"] + 1, COMMAND_STREAM_MAX)),
            "term_grace_ms": 1000,
        },
    }


def validate_supervised_command_binding(
        value, stage, role_identities=None,
        transport_context="producer_direct", profile=CURRENT_PROFILE):
    require(transport_context in {"producer_direct", "trusted_inner_zip"},
            "invalid supervised command transport context")
    contract = production_command_contract(stage, profile)
    require(isinstance(value, dict) and set(value) == {
        "scope", "stage", "exit_code", "bytes", "sha256", "sha256_scope",
        "over_limit", "known_error_markers", "supervisor",
    } and value["scope"] == "command_diagnostic_not_acceptance"
      and value["stage"] == stage
      and native_u8(value["exit_code"],
                    "invalid supervised command binding") == 0
      and native_u64(value["bytes"],
                     "invalid supervised command binding")
      <= contract["output_limit"]
      and native_digest(value["sha256"],
                        "invalid supervised command binding")
      == value["sha256"]
      and value["sha256_scope"] == command_digest_scope(value["bytes"])
      and value["over_limit"] is False
      and value["known_error_markers"] == [],
      "invalid supervised command binding")
    supervisor = value["supervisor"]
    require(isinstance(supervisor, dict) and set(supervisor) == {
        "schema", "version", "bootstrap", "request", "result",
    } and supervisor["schema"] == "uk.wamr.command-supervisor-result"
      and native_u8(
          supervisor["version"], "invalid supervised command binding") == 1
      and supervisor["bootstrap"] is False,
      "invalid supervised command binding")
    request = supervisor["request"]
    digest_fields = {
        "canonical_sha256", "argv_sha256",
        "environment_sha256", "cwd_sha256",
    }
    require(isinstance(request, dict)
            and set(request) == {
                "schema", "version", "binding_schema", "binding_version",
                "stage", "argv", "environment", "cwd", "supervisor",
                "native_executable", "command_executable", "interpreter",
                "retained_executables", "issued_ns", "primary_deadline_ns",
                "cleanup_deadline_ns", "timeout_ns", "limits",
                *digest_fields,
            }
            and request["schema"] == "uk.wamr.command-supervisor-request"
            and native_u8(
                request["version"], "invalid supervised command binding") == 1
            and request["binding_schema"] == COMMAND_BINDING_SCHEMA
            and native_u8(
                request["binding_version"],
                "invalid supervised command binding")
            == COMMAND_BINDING_VERSION
            and request["stage"] == stage
            and request["argv"] == contract["argv"]
            and request["environment"] == contract["environment"]
            and request["cwd"] == contract["cwd"]
            and request["native_executable"]["path"]
            == contract["native_executable"]
            and request["command_executable"]["path"]
            == contract["command_executable"]
            and (
                request["interpreter"] is None
                if contract["interpreter"] is None
                else request["interpreter"]["path"]
                == contract["interpreter"])
            and request["timeout_ns"]
            == contract["seconds"] * 1_000_000_000
            and request["limits"] == contract["limits"]
            and validate_supervisor_limits(
                request["limits"], "invalid supervised command binding")
            == request["limits"],
            "invalid supervised command binding")
    for key in digest_fields:
        require(isinstance(request[key], str)
                and re.fullmatch(r"[0-9a-f]{64}", request[key]),
                "invalid supervised command binding")
    core = {
        key: item for key, item in request.items()
        if key not in digest_fields
    }
    require(request["canonical_sha256"] == command_binding_digest(core)
            and request["argv_sha256"]
            == command_binding_digest(request["argv"])
            and request["environment_sha256"]
            == command_binding_digest(request["environment"])
            and request["cwd_sha256"]
            == command_binding_digest(request["cwd"]),
            "invalid supervised command binding")
    for binding in (
            request["supervisor"], request["native_executable"],
            request["command_executable"]):
        require(isinstance(binding, dict)
                and set(binding) == {"path", "identity"},
                "invalid supervised command binding")
        validate_native_executable_identity(
            binding["identity"], "invalid supervised command binding")
    if request["interpreter"] is not None:
        require(isinstance(request["interpreter"], dict)
                and set(request["interpreter"]) == {"path", "identity"},
                "invalid supervised command binding")
        validate_native_executable_identity(
            request["interpreter"]["identity"],
            "invalid supervised command binding")
    require(request["supervisor"]["path"]
            == command_path("command-supervisor")
            and native_u64(
                request["issued_ns"],
                "invalid supervised command binding") == request["issued_ns"]
            and native_u64(
                request["timeout_ns"],
                "invalid supervised command binding") == request["timeout_ns"]
            and native_u64(
                request["primary_deadline_ns"],
                "invalid supervised command binding")
            == request["primary_deadline_ns"]
            and native_u64(
                request["cleanup_deadline_ns"],
                "invalid supervised command binding")
            == request["cleanup_deadline_ns"]
            and request["primary_deadline_ns"]
            == request["issued_ns"] + request["timeout_ns"]
            and request["cleanup_deadline_ns"]
            == request["primary_deadline_ns"]
            + COMMAND_CLEANUP_SECONDS * 1_000_000_000,
            "invalid supervised command binding")
    retained = request["retained_executables"]
    require(isinstance(retained, list)
            and [item["name"] for item in retained]
            == contract["retained_names"],
            "invalid supervised command binding")
    environment = {
        item["name"]: item["value"] for item in request["environment"]
    }
    for item in retained:
        require(isinstance(item, dict)
                and set(item) == {"name", "path", "identity"}
                and item["path"] == environment.get(item["name"]),
                "invalid supervised command binding")
        native_string(
            item["name"], COMMAND_STRING_MAX,
            "invalid supervised command binding", allow_empty=False)
        validate_native_executable_identity(
            item["identity"], "invalid supervised command binding")
    if role_identities is not None:
        for binding in (
                request["supervisor"], request["native_executable"],
                request["command_executable"],
                *(()
                  if request["interpreter"] is None
                  else (request["interpreter"],)),
                *retained):
            path = binding["path"]
            require(path["kind"] == "path"
                    and role_identities.get(path["role"])
                    == binding["identity"],
                    "invalid supervised command identity")
    result = supervisor["result"]
    require(isinstance(result, dict) and set(result) == {
        "canonical_sha256", "schema", "version",
        "request_canonical_sha256", "controller_error",
        "native_request", "native_result", "command",
    } and result["schema"] == "uk.wamr.command-supervisor-result"
      and native_u8(
          result["version"], "invalid supervised command binding") == 1
      and result["request_canonical_sha256"]
      == request["canonical_sha256"]
      and result["controller_error"] is None
      and isinstance(result["canonical_sha256"], str)
      and re.fullmatch(r"[0-9a-f]{64}", result["canonical_sha256"]),
      "invalid supervised command binding")
    for name, maximum in (
            ("native_request", COMMAND_REQUEST_MAX),
            ("native_result", COMMAND_RESULT_MAX)):
        transport = result[name]
        require(isinstance(transport, dict) and set(transport) == {
            "bytes", "digest_scope", "sha256",
        } and native_u64(
            transport["bytes"], "invalid supervised command binding")
          <= maximum
          and transport["bytes"] > 0
          and transport["digest_scope"]
          == "direct_producer_or_trusted_inner_zip"
          and native_digest(
              transport["sha256"], "invalid supervised command binding")
          == transport["sha256"],
          "invalid supervised command binding")
    result_core = dict(result)
    del result_core["canonical_sha256"]
    require(result["canonical_sha256"]
            == command_binding_digest(result_core),
            "invalid supervised command binding")
    command = result["command"]
    require(isinstance(command, dict) and set(command) == {
        "cancellation_observed", "cleanup", "cleanup_complete",
        "cleanup_events", "descendants", "executable",
        "executable_stable", "output", "poisoned", "primary",
        "primary_deadline_reached", "primary_events", "reap_events",
        "retained_executables", "stderr", "stdout", "timing", "termination",
    } and command["cleanup"] in {
        "complete", "not_required", "deadline", "event_limit",
        "descendant_untracked", "identity_changed", "signal_failed",
        "reap_failed", "proc_unavailable", "local_io",
    }
      and type(command["cleanup_complete"]) is bool
      and type(command["poisoned"]) is bool
      and command["poisoned"] is (not command["cleanup_complete"])
      and command["cleanup_complete"]
      is (command["cleanup"] in {"complete", "not_required"})
      and type(command["executable_stable"]) is bool
      and type(command["primary_deadline_reached"]) is bool
      and type(command["cancellation_observed"]) is bool
      and command["executable"]
      == request["native_executable"]["identity"]
      and command["retained_executables"] == retained,
      "invalid supervised command binding")
    for name in ("stdout", "stderr"):
        output = command[name]
        require(isinstance(output, dict)
                and set(output) == {
                    "bytes", "digest_scope", "sha256", "status",
                }
                and output["digest_scope"]
                == command_digest_scope(output["bytes"])
                and native_digest(
                    output["sha256"], "invalid supervised command binding")
                == output["sha256"]
                and (output["bytes"] != 0
                     or output["sha256"] == EMPTY_SHA256),
                "invalid supervised command binding")
    output = command["output"]
    require(isinstance(output, dict) and set(output) == {
        "bytes", "combined_sha256", "commitment_sha256", "digest_scope",
    }
            and output["bytes"]
            == command["stdout"]["bytes"] + command["stderr"]["bytes"]
            and output["bytes"] == value["bytes"]
            and output["combined_sha256"] == value["sha256"]
            and output["digest_scope"] == value["sha256_scope"]
            and native_digest(
                output["combined_sha256"],
                "invalid supervised command binding")
            == output["combined_sha256"]
            and output["commitment_sha256"]
            == command_output_commitment(
                command["stdout"]["bytes"], command["stdout"]["sha256"],
                command["stderr"]["bytes"], command["stderr"]["sha256"])
            and (output["bytes"] != 0
                 or output["combined_sha256"] == EMPTY_SHA256),
            "invalid supervised command binding")
    timing = command["timing"]
    require(isinstance(timing, dict) and set(timing) == {
        "cleanup_elapsed_ns", "completed_ns", "primary_completed_ns",
        "primary_elapsed_ns", "started_ns", "total_elapsed_ns",
    }, "invalid supervised command binding")
    for name in timing:
        native_u64(timing[name], "invalid supervised command binding")
    validate_supervisor_state(
        command, request["limits"], timing, {
            "stdout": command["stdout"],
            "stderr": command["stderr"],
        }, request["primary_deadline_ns"],
        "invalid supervised command binding")
    require(request["issued_ns"] <= timing["started_ns"]
            <= timing["primary_completed_ns"] <= timing["completed_ns"]
            and timing["primary_elapsed_ns"]
            == timing["primary_completed_ns"] - timing["started_ns"]
            and timing["cleanup_elapsed_ns"]
            == timing["completed_ns"] - timing["primary_completed_ns"]
            and timing["total_elapsed_ns"]
            == timing["completed_ns"] - timing["started_ns"]
            and timing["primary_completed_ns"]
            < request["primary_deadline_ns"]
            and timing["completed_ns"] <= request["cleanup_deadline_ns"],
            "invalid supervised command binding")
    descendants = command["descendants"]
    require(command["cancellation_observed"] is False
            and command["cleanup"] == "complete"
            and command["cleanup_complete"] is True
            and command["executable_stable"] is True
            and command["poisoned"] is False
            and command["primary"] == {"code": 0, "kind": "exited"}
            and command["primary_deadline_reached"] is False
            and command["termination"] == {"code": 0, "kind": "exited"}
            and command["stdout"]["status"] == "complete"
            and command["stderr"]["status"] == "complete"
            and descendants["limit_exceeded"] is False
            and descendants["untracked"] is False
            and descendants["observed"] <= request["limits"]["descendants"],
            "invalid supervised command binding")
    if value["bytes"] != 0:
        require(transport_context in {
            "producer_direct", "trusted_inner_zip",
        }, "invalid supervised command transport context")
    return value


def native_executable_identity(record):
    metadata = record["metadata"]
    mtime_seconds, mtime_nanoseconds = divmod(metadata[7], 1_000_000_000)
    ctime_seconds, ctime_nanoseconds = divmod(metadata[8], 1_000_000_000)
    return {
        "content_sha256": record["sha256"],
        "ctime_nanoseconds": ctime_nanoseconds,
        "ctime_seconds": ctime_seconds,
        "device_major": os.major(metadata[0]),
        "device_minor": os.minor(metadata[0]),
        "inode": metadata[1],
        "mode": metadata[2],
        "mtime_nanoseconds": mtime_nanoseconds,
        "mtime_seconds": mtime_seconds,
        "size": metadata[6],
        "uid": metadata[3],
    }


def decoded_supervisor_result(
        raw, request, expected_executable, expected_retained=()):
    request_raw = validate_supervisor_request(request)
    require(0 < len(raw) <= COMMAND_RESULT_MAX,
            "native command result exceeded")
    try:
        value = json.loads(raw, object_pairs_hook=unique)
    except (UnicodeDecodeError, json.JSONDecodeError, Refusal) as error:
        raise Refusal("invalid native command result") from error
    try:
        canonical = canonical_json(value)
    except Refusal as error:
        raise Refusal("invalid native command result") from error
    reason = "invalid native command result"
    require(raw == canonical and isinstance(value, dict)
            and set(value) == {
                "command", "controller_error", "request_bytes",
                "request_sha256", "schema", "version",
            }
            and value["schema"] == "uk.wamr.command-supervisor-result"
            and native_u8(value["version"], reason) == 1
            and native_u64(value["request_bytes"], reason) == len(request_raw)
            and native_digest(value["request_sha256"], reason)
            == hashlib.sha256(request_raw).hexdigest()
            and (value["controller_error"] is None
                 or value["controller_error"] in {
                     "cwd_unavailable", "exec_changed", "exec_invalid",
                     "exec_unavailable", "exec_unsupported",
                     "invalid_invocation", "invalid_request", "local_io",
                     "noncanonical_request", "supervisor_unavailable",
                 }),
            reason)
    if value["controller_error"] is not None:
        require(value["command"] is None, reason)
        return value, b"", b""
    command = value["command"]
    require(isinstance(command, dict)
            and set(command) == {
                "cancellation_observed", "cleanup", "cleanup_complete",
                "cleanup_events", "completed_ns", "descendants", "executable",
                "executable_stable", "output_sha256", "poisoned", "primary",
                "primary_completed_ns",
                "primary_deadline_reached", "primary_events", "reap_events",
                "retained_executables", "started_ns",
                "stderr_base64", "stderr_bytes", "stderr_sha256",
                "stderr_status", "stdout_base64", "stdout_bytes",
                "stdout_sha256", "stdout_status", "termination",
            }
            and command["cleanup"] in {
                "complete", "not_required", "deadline", "event_limit",
                "descendant_untracked", "identity_changed", "signal_failed",
                "reap_failed", "proc_unavailable", "local_io",
            }
            and type(command["cleanup_complete"]) is bool
            and type(command["poisoned"]) is bool
            and command["poisoned"] is (not command["cleanup_complete"])
            and command["cleanup_complete"]
            is (command["cleanup"] in {"complete", "not_required"})
            and type(command["executable_stable"]) is bool
            and type(command["primary_deadline_reached"]) is bool
            and type(command["cancellation_observed"]) is bool
            and command["stdout_status"] in {
                "complete", "overflow", "io_failed", "incomplete",
            }
            and command["stderr_status"] in {
                "complete", "overflow", "io_failed", "incomplete",
            }
            and command["executable"] == expected_executable,
            reason)
    validate_native_executable_identity(command["executable"], reason)
    limits = request["limits"]
    require(isinstance(command["retained_executables"], list)
            and command["retained_executables"] == list(expected_retained),
            "invalid retained executable identity")
    for item in command["retained_executables"]:
        require(isinstance(item, dict)
                and set(item) == {"identity", "name", "path"}, reason)
        native_string(
            item["name"], COMMAND_STRING_MAX, reason, allow_empty=False)
        native_string(
            item["path"], COMMAND_STRING_MAX, reason, allow_empty=False)
        validate_native_executable_identity(item["identity"], reason)
    try:
        stdout = base64.b64decode(
            command["stdout_base64"], validate=True)
        stderr = base64.b64decode(
            command["stderr_base64"], validate=True)
    except (TypeError, ValueError) as error:
        raise Refusal(reason) from error
    stdout_sha256 = hashlib.sha256(stdout).hexdigest()
    stderr_sha256 = hashlib.sha256(stderr).hexdigest()
    require(len(stdout) <= limits["stdout_bytes"]
            and len(stderr) <= limits["stderr_bytes"]
            and native_u64(command["stdout_bytes"], reason) == len(stdout)
            and native_u64(command["stderr_bytes"], reason) == len(stderr)
            and native_digest(command["stdout_sha256"], reason)
            == stdout_sha256
            and native_digest(command["stderr_sha256"], reason)
            == stderr_sha256
            and native_digest(command["output_sha256"], reason)
            == command_output_commitment(
                len(stdout), stdout_sha256, len(stderr), stderr_sha256),
            reason)
    primary, unused_termination, started, primary_completed, completed = (
        validate_supervisor_state(
            command, limits, {
                "started_ns": command["started_ns"],
                "primary_completed_ns": command["primary_completed_ns"],
                "completed_ns": command["completed_ns"],
            }, {
                "stdout": {
                    "bytes": len(stdout),
                    "sha256": stdout_sha256,
                    "status": command["stdout_status"],
                },
                "stderr": {
                    "bytes": len(stderr),
                    "sha256": stderr_sha256,
                    "status": command["stderr_status"],
                },
            }, request["primary_deadline_ns"], reason))
    del unused_termination
    require((primary["kind"] != "output_overflow"
             or "overflow" in {
                 command["stdout_status"], command["stderr_status"],
             })
            and (command["primary_deadline_reached"]
                 or started < request["primary_deadline_ns"])
            and (command["cleanup"] != "complete"
                 or completed <= request["cleanup_deadline_ns"])
            and (primary != {"code": 0, "kind": "exited"}
                 or primary_completed < request["primary_deadline_ns"]),
            reason)
    return value, stdout, stderr


def supervised_command_evidence(
        stage, request, request_raw, native, native_raw, stdout, stderr,
        supervisor_identity,
        native_executable, command_executable, interpreter,
        expected_retained, roots, issued_ns, timeout_ns):
    strict = stage in STRICT_SUPERVISED_STAGES

    def identities(values):
        return [
            {
                "identity": value["identity"],
                "name": value["name"],
                "path": normalized_command_value(
                    value["path"], roots, strict),
            }
            for value in values
        ]

    command = native["command"]
    summarized = None
    if command is not None:
        summarized = {
            "cancellation_observed": command["cancellation_observed"],
            "cleanup": command["cleanup"],
            "cleanup_complete": command["cleanup_complete"],
            "cleanup_events": command["cleanup_events"],
            "descendants": command["descendants"],
            "executable": command["executable"],
            "executable_stable": command["executable_stable"],
            "poisoned": command["poisoned"],
            "primary": command["primary"],
            "primary_deadline_reached":
                command["primary_deadline_reached"],
            "primary_events": command["primary_events"],
            "reap_events": command["reap_events"],
            "retained_executables": identities(
                command["retained_executables"]),
            "stderr": {
                "bytes": len(stderr),
                "digest_scope": command_digest_scope(len(stderr)),
                "sha256": command["stderr_sha256"],
                "status": command["stderr_status"],
            },
            "stdout": {
                "bytes": len(stdout),
                "digest_scope": command_digest_scope(len(stdout)),
                "sha256": command["stdout_sha256"],
                "status": command["stdout_status"],
            },
            "output": {
                "bytes": len(stdout) + len(stderr),
                "commitment_sha256": command["output_sha256"],
                "combined_sha256": hashlib.sha256(stdout + stderr).hexdigest(),
                "digest_scope": command_digest_scope(
                    len(stdout) + len(stderr)),
            },
            "timing": {
                "cleanup_elapsed_ns":
                    command["completed_ns"]
                    - command["primary_completed_ns"],
                "completed_ns": command["completed_ns"],
                "primary_completed_ns": command["primary_completed_ns"],
                "primary_elapsed_ns":
                    command["primary_completed_ns"] - command["started_ns"],
                "started_ns": command["started_ns"],
                "total_elapsed_ns":
                    command["completed_ns"] - command["started_ns"],
            },
            "termination": command["termination"],
        }
    request_core = {
        "binding_schema": COMMAND_BINDING_SCHEMA,
        "binding_version": COMMAND_BINDING_VERSION,
        "stage": stage,
        "schema": request["schema"],
        "version": request["version"],
        "argv": [
            normalized_command_value(value, roots, strict)
            for value in request["argv"]
        ],
        "environment": [
            {
                "name": item["name"],
                "value": normalized_command_value(
                    item["value"], roots, strict),
            }
            for item in request["environment"]
        ],
        "cwd": normalized_command_value(request["cwd"], roots, strict),
        "supervisor": {
            "path": command_path("command-supervisor"),
            "identity": supervisor_identity,
        },
        "native_executable": {
            "path": normalized_command_value(
                request["executable"], roots, strict),
            "identity": native_executable,
        },
        "command_executable": {
            "path": normalized_command_value(
                command_executable["path"], roots, strict),
            "identity": command_executable["identity"],
        },
        "interpreter": (
            None if interpreter is None else {
                "path": normalized_command_value(
                    interpreter["path"], roots, strict),
                "identity": interpreter["identity"],
            }
        ),
        "retained_executables": [
            {
                "identity": value["identity"],
                "name": value["name"],
                "path": normalized_command_value(
                    value["path"], roots, strict),
            }
            for value in expected_retained
        ],
        "issued_ns": issued_ns,
        "primary_deadline_ns": request["primary_deadline_ns"],
        "cleanup_deadline_ns": request["cleanup_deadline_ns"],
        "timeout_ns": timeout_ns,
        "limits": request["limits"],
    }
    public_request = {
        **request_core,
        "canonical_sha256": command_binding_digest(request_core),
        "argv_sha256": command_binding_digest(request_core["argv"]),
        "environment_sha256": command_binding_digest(
            request_core["environment"]),
        "cwd_sha256": command_binding_digest(request_core["cwd"]),
    }
    result_core = {
        "schema": native["schema"],
        "version": native["version"],
        "request_canonical_sha256": public_request["canonical_sha256"],
        "controller_error": native["controller_error"],
        "native_request": {
            "bytes": len(request_raw),
            "digest_scope": "direct_producer_or_trusted_inner_zip",
            "sha256": native["request_sha256"],
        },
        "native_result": {
            "bytes": len(native_raw),
            "digest_scope": "direct_producer_or_trusted_inner_zip",
            "sha256": hashlib.sha256(native_raw).hexdigest(),
        },
        "command": summarized,
    }
    return {
        "schema": native["schema"],
        "version": native["version"],
        "bootstrap": False,
        "request": public_request,
        "result": {
            **result_core,
            "canonical_sha256": command_binding_digest(result_core),
        },
    }


def bootstrap_execute(root, stage, args, seconds, limit, cwd, evidence,
                      input_records):
    require(stage in BOOTSTRAP_STAGES, "bootstrap stage is not allowed")
    output = root / "private" / (stage + ".log")
    executable = str(Path(args[0]).resolve(strict=True))
    records = input_records
    if records is None:
        record, unused_directories = physical_file_record(executable)
        del unused_directories
        records = {record["path"]: record}
    with retained_executables((executable,), records) as (retained, pass_fds):
        raw = bounded_subprocess_output(
            [retained[executable], *map(str, args[1:])],
            cwd, limit + 1, seconds,
            "bootstrap command output exceeded",
            "bootstrap command timed out",
            "bootstrap command failed",
            env=command_environment(root, input_records),
            pass_fds=pass_fds,
        )
    with output.open("xb") as stream:
        stream.write(raw)
    record = {
        "scope": "command_diagnostic_not_acceptance", "stage": stage,
        "exit_code": 0, "bytes": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "sha256_scope": command_digest_scope(len(raw)),
        "over_limit": False, "known_error_markers": command_error_markers(raw),
        "supervisor": {
            "schema": "uk.wamr.command-supervisor-result",
            "version": 1, "bootstrap": True,
        },
    }
    if evidence:
        save(root / "evidence" / ("command-" + stage + ".json"), record)
    return output, record


def execute(root, stage, args, seconds=600, limit=8 * MIB, cwd=REPO,
            evidence=True, input_records=None, allow_bootstrap=False,
            path_roles=None):
    """Native fixed-deadline command; raw output stays private."""
    require(type(limit) is int and limit >= 0 and seconds > 0
            and type(allow_bootstrap) is bool,
            "invalid bounded command")
    if allow_bootstrap:
        require(stage in BOOTSTRAP_STAGES, "bootstrap stage is not allowed")
    if COMMAND_SUPERVISOR_PATH is None:
        require(allow_bootstrap, "command supervisor is unavailable")
        return bootstrap_execute(
            root, stage, args, seconds, limit, cwd, evidence, input_records)
    output = root / "private" / (stage + ".log")
    supervisor = str(Path(COMMAND_SUPERVISOR_PATH).resolve(strict=True))
    executable = str(Path(args[0]).resolve(strict=True))
    records = input_records
    if records is None:
        records = {}
        for path in (supervisor, executable):
            file_record, unused_directories = physical_file_record(path)
            del unused_directories
            records[file_record["path"]] = file_record
    require(supervisor in records, "unbound command supervisor input")
    require(executable in records, "unbound executable input")
    roots = command_path_roots(root, path_roles)
    supervisor_identity = native_executable_identity(records[supervisor])
    command_executable = {
        "path": executable,
        "identity": native_executable_identity(records[executable]),
    }
    interpreter = (
        command_executable
        if executable == COMMAND_TOOL_PATHS.get("python3")
        else None
    )
    selected_environment = (
        {} if stage in LOG_VALIDATOR_STAGES else {
            "WAMR_CI_TOOL_" + name.upper().replace("-", "_"): path
            for name, path in COMMAND_TOOL_PATHS.items()
        })
    if stage not in LOG_VALIDATOR_STAGES and "git" in COMMAND_TOOL_PATHS:
        selected_environment["WAMR_CI_GIT"] = COMMAND_TOOL_PATHS["git"]
    launch_retained = executable == COMMAND_TOOL_PATHS.get("zig")
    if launch_retained:
        selected_environment["WAMR_CI_LAUNCH_EXECUTABLE"] = executable
    environment = command_environment(
        root, input_records, selected_environment, stage=stage)
    retained_environment = []
    expected_retained = []
    for name, value in sorted(environment.items()):
        record = records.get(value)
        if record is None or not record["metadata"][2] & 0o111:
            continue
        retained_environment.append({"name": name, "path": value})
        expected_retained.append({
            "identity": native_executable_identity(record),
            "name": name,
            "path": value,
        })
    now = time.monotonic_ns()
    primary_deadline = now + int(seconds * 1_000_000_000)
    cleanup_deadline = primary_deadline + COMMAND_CLEANUP_SECONDS * 1_000_000_000
    stream_limit = max(1, min(limit + 1, COMMAND_STREAM_MAX))
    request = {
        "argv": (
            [supervisor, "--launch-retained", executable, *map(str, args[1:])]
            if launch_retained
            else [executable, *map(str, args[1:])]
        ),
        "cleanup_deadline_ns": cleanup_deadline,
        "cwd": str(Path(cwd).resolve(strict=True)),
        "environment": [
            {"name": name, "value": value}
            for name, value in sorted(environment.items())
        ],
        "executable": supervisor if launch_retained else executable,
        "limits": {
            "cleanup_events": 1_000_000,
            "descendants": 64,
            "primary_events": 1_000_000,
            "proc_entries_per_scan": 262_144,
            "reap_events": 512,
            "stderr_bytes": stream_limit,
            "stdout_bytes": stream_limit,
            "term_grace_ms": 1000,
        },
        "primary_deadline_ns": primary_deadline,
        "retained_executables": retained_environment,
        "schema": "uk.wamr.command-supervisor-request",
        "version": 1,
    }
    request_raw = validate_supervisor_request(request)
    with retained_executables(
            (supervisor,), records) as (retained, pass_fds):
        result = subprocess.run(
            [retained[supervisor]], input=request_raw,
            cwd="/", stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env={}, pass_fds=pass_fds, check=False,
        )
    require(result.returncode == 0 and not result.stderr,
            "native command supervisor failed")
    expected_executable = native_executable_identity(
        records[supervisor if launch_retained else executable])
    native, stdout, stderr = decoded_supervisor_result(
        result.stdout, request, expected_executable, expected_retained)
    command = native["command"]
    combined = (stdout + stderr)[:limit + 1]
    with output.open("xb") as stream:
        stream.write(combined)
    size = len(combined)
    markers = (command_error_markers(read(output, limit + 1))
               if size <= limit + 1 else None)
    exit_code = (
        command["primary"]["code"]
        if command is not None
        and command["primary"]["kind"] == "exited"
        else -1
    )
    record = {
        "scope": "command_diagnostic_not_acceptance", "stage": stage,
        "exit_code": exit_code, "bytes": size,
        "sha256": digest(output) if size else EMPTY_SHA256,
        "sha256_scope": command_digest_scope(size),
        "over_limit": size > limit,
        "known_error_markers": markers,
        "supervisor": supervised_command_evidence(
            stage, request, request_raw, native, result.stdout, stdout, stderr,
            supervisor_identity,
            expected_executable, command_executable, interpreter,
            expected_retained, roots, now,
            int(seconds * 1_000_000_000)),
    }
    if evidence:
        save(root / "evidence" / ("command-" + stage + ".json"), record)
    require(command is not None, "trusted command exec failed")
    require(command["cleanup_complete"]
            and command["cleanup"] == "complete"
            and not command["poisoned"]
            and not command["descendants"]["limit_exceeded"]
            and not command["descendants"]["untracked"],
            "trusted command cleanup failed")
    require(command["executable_stable"], "trusted command executable changed")
    require(command["stdout_status"] == "complete"
            and command["stderr_status"] == "complete"
            and size <= limit,
            "trusted command output exceeded")
    primary = command["primary"]
    require(primary["kind"] != "timeout", "trusted command timed out")
    require(primary["kind"] != "cancelled", "trusted command cancelled")
    require(primary["kind"] not in {
        "exec_failed", "snapshot_unsupported", "executable_changed",
    }, "trusted command exec failed")
    require(primary["kind"] == "exited" and primary["code"] == 0,
            "trusted command failed")
    return output, record


def run(root, stage, args, seconds=600, limit=8 * MIB, input_records=None,
        allow_bootstrap=False, path_roles=None):
    output, _ = execute(
        root, stage, args, seconds, limit, input_records=input_records,
        allow_bootstrap=allow_bootstrap, path_roles=path_roles)
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
                [f"/proc/self/fd/{git_handle}", *git_arguments(*args)],
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
    root = Path(runtime)
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
            compact_json(snapshot(info))).hexdigest(),
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
    entries = [
        entry.name for entry in bounded_scandir(
            restore, 3, "unexpected dependency restore entry",
            "dependency restore enumeration failed")
    ]
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
        used = len(files) + len(directories) - 1
        remaining = PACKAGE_MAX_ENTRIES - used
        if not prefix:
            remaining = min(remaining, PACKAGE_MAX_ROOTS)
        entries = bounded_scandir(
            directory, remaining,
            "invalid dependency package roots" if not prefix
            else "dependency package entry limit exceeded",
            "dependency package enumeration failed",
        )
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
        entries = bounded_scandir(
            directory, PACKAGE_MAX_ENTRIES - files - directories,
            "dependency package entry limit exceeded",
            "dependency package enumeration failed",
        )
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


def package_roots(
        packages, empty_reason="invalid dependency package roots"):
    try:
        before = packages.lstat()
    except FileNotFoundError as error:
        raise Refusal("private pinned dependency restore required") from error
    require(canonical(packages)
            and stat.S_ISDIR(before.st_mode)
            and before.st_uid == os.getuid()
            and stat.S_IMODE(before.st_mode) == 0o700,
            "private pinned dependency restore required")
    entries = bounded_scandir(
        packages, PACKAGE_MAX_ROOTS, "invalid dependency package roots",
        "dependency package enumeration failed")
    require(entries, empty_reason)
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
            "root_metadata_sha256": hashlib.sha256(
                compact_json(root_info)).hexdigest(),
            "manifests": {
                "count": manifest_count,
                "bytes": manifest_bytes,
                "sha256": manifest_digest.hexdigest(),
            },
            "hash_verification": {
                "algorithm": "zig-0.16.0-fetch-path",
                "count": len(hash_records),
                "sha256": hashlib.sha256(
                    compact_json(hash_records)).hexdigest(),
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


def require_recorded_consumer_inputs(expected, content=False):
    record_input_paths(
        {
            name: Path(record["path"])
            for name, record in expected["files"].items()
        },
        {
            name: Path(record["path"])
            for name, record in expected["trees"].items()
        },
        content=content, expected=expected,
    )


def require_boot_inputs(runtime, paths, expected, content=False):
    boot_input_state(
        runtime, paths, content=content, expected=expected)


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
                input_records=consumer_file_records(expected_inputs),
                allow_bootstrap=True)
            require_consumer_inputs(runtime, expected_inputs)
        except Refusal as error:
            raise Refusal("Zig package hash recomputation failed") from error
        require(read(output, 512) == (name + "\n").encode("ascii"),
                "Zig package content hash mismatch")
        require(restored_manifest_state(work, expected) == work_state,
                "dependency hash workspace manifest identity changed")


def restore_dependencies(runtime, root, expected_inputs):
    manifest_sources = dependency_manifest_sources()
    restore = root / "dependencies"
    restore.mkdir(mode=0o700)
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
    try:
        require_consumer_inputs(runtime, expected_inputs)
        _, command = execute(root, "dependency-restore", [
            tool("zig"), "build", "--build-file", restore / "build.zig",
            "--fetch=all", "--cache-dir", root / "cache",
            "--global-cache-dir", root / "global-cache", "-j2",
        ], 900, evidence=False,
            input_records=consumer_file_records(expected_inputs),
            allow_bootstrap=True)
        require_consumer_inputs(runtime, expected_inputs)
    except Refusal as error:
        raise Refusal("pinned dependency restore command failed") from error
    require(command["known_error_markers"] == [], "dependency restore reported an error")
    require(restored_manifest_state(restore, manifest_data) == restored,
            "copied dependency manifest identity changed")
    packages = restore / "zig-pkg"
    package_roots(packages, "private pinned dependency restore required")
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
    return packages


def build_command_supervisor(runtime, root, packages, expected_inputs):
    global COMMAND_SUPERVISOR_PATH
    source_map = supervisor_source_map()
    records = consumer_file_records(expected_inputs)
    require_consumer_inputs(runtime, expected_inputs)
    _, command = execute(root, "supervisor-build", [
        tool("zig"), "build", "--build-file", HERE / "supervisor.build.zig",
        "--system", packages, "--prefix", root / "supervisor",
        "-Dsource-closure-sha256=" + source_map["content_closure_sha256"],
        *RECORDED_EXECUTABLE_TARGET,
        "-Doptimize=ReleaseSafe", "-j2", "install",
    ], 900, evidence=False, input_records=records, allow_bootstrap=True)
    require(command["known_error_markers"] == [],
            "command supervisor build reported an error")
    require_recorded_consumer_inputs(expected_inputs)
    require(supervisor_source_map() == source_map,
            "command supervisor source changed")
    supervisor = (root / "supervisor/bin/wamr-ci-supervisor").resolve(
        strict=True)
    supervisor_record, unused_directories = physical_file_record(supervisor)
    del unused_directories
    COMMAND_SUPERVISOR_PATH = str(supervisor)
    output, unused_record = execute(
        root, "supervisor-version", [supervisor, "--version"],
        30, 127, cwd=REPO, evidence=False,
        input_records={supervisor_record["path"]: supervisor_record})
    del unused_record
    require(read(output, 128)
            == (COMMAND_SUPERVISOR_VERSION + "\n").encode("ascii"),
            "wrong command supervisor version")
    require_recorded_consumer_inputs(expected_inputs)
    require(supervisor_source_map() == source_map,
            "command supervisor source changed")
    return supervisor


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
    require(command_supervisor_state(
        runtime, expected["consumer_inputs"]) == expected["command_supervisor"],
        "command supervisor custody changed")


def require_recorded_build_custody(runtime, expected):
    require(set(expected) == {
        "source", "source_custody", "tools", "bison_data",
        "dependencies", "consumer_inputs", "command_supervisor",
    }, "invalid recorded build custody")
    current_source = source()
    require(source_identity(current_source) == expected["source"]
            and current_source["custody"] == expected["source_custody"],
            "immutable source custody changed")
    require_dependency_custody(runtime / "compute", expected["dependencies"])
    require_recorded_consumer_inputs(
        expected["consumer_inputs"], content=True)
    files = expected["consumer_inputs"]["files"]
    require(set(expected["tools"]) == set(HOST_TOOLS),
            "recorded tool roles changed")
    for name in HOST_TOOLS:
        record = files.get("tool:" + name)
        require(isinstance(record, dict)
                and expected["tools"][name] == record["sha256"],
                "recorded tool custody changed")
    require(bison_inputs(runtime / "bison") == expected["bison_data"],
            "Bison input changed")
    require(command_supervisor_state(
        runtime, expected["consumer_inputs"]) == expected["command_supervisor"],
        "command supervisor custody changed")
    return expected


def require_dependency_custody(root, expected):
    require(dependency_custody(root) == expected, "dependency custody changed")


def run_custodied(runtime, expected, root, stage, args, seconds=600,
                  limit=8 * MIB, extra_inputs=None, extra_input_paths=None):
    require((extra_inputs is None) == (extra_input_paths is None),
            "incomplete extra input custody")
    require_build_custody(runtime, expected)
    if extra_inputs is not None:
        require_boot_inputs(runtime, extra_input_paths, extra_inputs)
    records = consumer_file_records(expected["consumer_inputs"])
    if extra_inputs is not None:
        records.update(consumer_file_records(extra_inputs))
    path_roles = {
        role: Path(record["path"])
        for role, record
        in expected["consumer_inputs"].get("files", {}).items()
        if role.startswith("native:")
    }
    if extra_input_paths is not None:
        path_roles.update({
            "input:" + name: path
            for name, path in extra_input_paths.items()
        })
    output = run(
        root, stage, args, seconds, limit, input_records=records,
        path_roles=path_roles or None)
    record_path = root / "evidence" / ("command-" + stage + ".json")
    if stage in STRICT_SUPERVISED_STAGES and record_path.is_file():
        role_identities = {
            "command-supervisor": native_executable_identity(
                expected["consumer_inputs"]["files"]["command-supervisor"]),
            **{
                "tool:" + name: native_executable_identity(
                    expected["consumer_inputs"]["files"]["tool:" + name])
                for name in HOST_TOOLS
            },
            **{
                role: native_executable_identity(record)
                for role, record
                in expected["consumer_inputs"].get("files", {}).items()
                if role.startswith("native:")
            },
        }
        if extra_inputs is not None:
            role_identities.update({
                "input:" + name: native_executable_identity(
                    extra_inputs["files"][name])
                for name in extra_input_paths
                if extra_inputs["files"][name]["metadata"][2] & 0o111
            })
        validate_supervised_command_binding(
            document(record_path), stage, role_identities)
    if extra_inputs is not None:
        require_boot_inputs(runtime, extra_input_paths, extra_inputs)
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


def native_result(output, record, raw, limit):
    response = read(output, limit + 1)
    require(record["sha256"] == hashlib.sha256(response).hexdigest()
            and record["bytes"] == len(response)
            and response.endswith(b"\n") and response.count(b"\n") == 1,
            "native validator output changed")
    observed = json.loads(response, object_pairs_hook=unique)
    require(isinstance(observed, dict), "invalid native validator result")
    require(set(observed) == {
        "schema", "schema_version", "mode", "raw_serial_bytes",
        "raw_serial_sha256", "compute",
    } and observed["schema"] == "uk.wamr.log-validation"
      and type(observed["schema_version"]) is int
      and observed["schema_version"] == 1
      and observed["mode"] == "tiny"
      and type(observed["raw_serial_bytes"]) is int
      and observed["raw_serial_bytes"] == len(raw)
      and observed["raw_serial_sha256"] == hashlib.sha256(raw).hexdigest()
      and isinstance(observed["compute"], dict),
      "native validator result changed")
    return observed["compute"]


def native_compute(work, identity_path, identity, raw, legacy, consumer_inputs):
    require(consumer_inputs is not None, "native validator custody required")
    root = work.parent
    require_recorded_consumer_inputs(consumer_inputs, content=True)
    files = consumer_inputs["files"]
    executable_record = files.get(WAMR_LOG_VALIDATOR_ROLE)
    require(isinstance(executable_record, dict), "installed native validator required")
    executable = Path(executable_record["path"])
    require(executable == root / "tools/bin/uk-wamr-log-validate",
            "wrong installed native validator")
    require(identity == document(identity_path), "runtime identity changed")
    log = work / "hyperv-efi-boot.log"
    serial_record, unused = physical_file_record(log)
    del unused
    identity_record, unused = physical_file_record(identity_path)
    del unused
    records = consumer_file_records(consumer_inputs)
    records.update({
        serial_record["path"]: serial_record,
        identity_record["path"]: identity_record,
    })
    stage = "log-validator-legacy" if legacy else "log-validator-x2apic"
    contract = production_command_contract(stage)
    private = root / "private" / "log-validation"
    private.mkdir(mode=0o700, exist_ok=True)
    info = private.lstat()
    require(canonical(private) and stat.S_ISDIR(info.st_mode)
            and info.st_uid == os.getuid()
            and stat.S_IMODE(info.st_mode) == 0o700,
            "unsafe native validator output directory")
    for index in range(16):
        invocation = private / f"{work.name}-{index:02d}"
        try:
            invocation.mkdir(mode=0o700)
            break
        except FileExistsError:
            continue
    else:
        raise Refusal("native validator invocation bound")
    for name in ("private", "evidence"):
        (invocation / name).mkdir(mode=0o700)
    output, record = execute(
        invocation, stage,
        [executable, "tiny", "--log", log, "--identity", identity_path,
         "--legacy-apic", LOG_VALIDATOR_STAGES[stage], "--output", "json-v1"],
        seconds=contract["seconds"], limit=contract["output_limit"],
        input_records=records,
        path_roles={
            WAMR_LOG_VALIDATOR_ROLE: executable,
            "input:serial": log,
            "input:identity": identity_path,
        })
    validate_supervised_command_binding(
        record, stage, {
            "command-supervisor": native_executable_identity(
                files["command-supervisor"]),
            WAMR_LOG_VALIDATOR_ROLE: native_executable_identity(
                executable_record),
        })
    compute = native_result(output, record, raw, contract["output_limit"])
    require(consumer_input_state(root.parent, expected=consumer_inputs)
            == consumer_inputs, "native validator tool changed")
    require(serial_record == physical_file_record(log)[0]
            and identity_record == physical_file_record(identity_path)[0]
            and identity == document(identity_path)
            and raw == read(log, 4 * MIB),
            "native validator input changed")
    return compute


def config_for(runtime, root, index, modes=MODES):
    mode = modes[index]
    legacy = bool(index % 2)
    source_kind, source_name = (
        ("raw_disk", "unikraft.raw") if mode.startswith("raw-") else
        ("qcow2", "unikraft.qcow2") if mode.startswith("qcow2-") else
        ("fixed_vhd", (
            "unikraft-derived.vhd"
            if modes == SIX_MODES else "unikraft.vhd"))
    )
    return {
        "source": {
            "kind": source_kind,
            "path": str(root / "package" / source_name),
        },
        "ovmf_code": str(runtime / "firmware/code.fd"),
        "ovmf_vars": str(runtime / "firmware/vars.fd"),
        "qemu": str(runtime / "bin/qemu-system-x86_64"),
        "work_dir": str(root / ("boot-" + mode)),
        "expect": MARKER, "expect_main_return": 0,
        "required": [LEGACY] if legacy else [],
        "forbidden": list(FORBIDDEN) + ([] if legacy else [LEGACY]),
        "cpus": 1, "disable_x2apic": legacy, "timeout_ms": 60_000,
    }


def prepare_boot_output_slots(runtime, root):
    package = root / "package"
    publication = root / "public-source"
    configs = [
        config_for(runtime, root, index, SIX_MODES)
        for index in range(len(SIX_MODES))
    ]
    slots = [
        package, publication,
        *(Path(config["work_dir"]) for config in configs),
    ]
    for path in slots:
        require(canonical(path), "boot output slot unavailable")
        info = path.lstat()
        require(stat.S_ISDIR(info.st_mode)
                and info.st_uid == os.getuid()
                and stat.S_IMODE(info.st_mode) == 0o700
                and not bounded_scandir(
                    path, 1, "boot output already exists",
                    "boot output slot unavailable"),
                "boot output already exists")
    return package, configs


def precreate_boot_output_slots(runtime, root):
    package = root / "package"
    publication = root / "public-source"
    configs = [
        config_for(runtime, root, index, SIX_MODES)
        for index in range(len(SIX_MODES))
    ]
    slots = [
        package, publication,
        *(Path(config["work_dir"]) for config in configs),
    ]
    require(all(not path.exists() and not path.is_symlink() for path in slots),
            "boot output already exists")
    for path in slots:
        path.mkdir(mode=0o700)
    prepare_boot_output_slots(runtime, root)


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


def check_boot(config, identity, boot_inputs=None, *,
               consumer_inputs=None, identity_path=None):
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
    if identity_path is None:
        identity_path = APP / "build/artifacts/identity.json"
    return {"scope": "local_native_compute_only", "report": report,
            "input_pins": request["pins"],
            "request_sha256": digest(work / "request.json"),
            "report_sha256": digest(work / "report.json"),
            "compute": native_compute(
                work, identity_path, identity, raw, config["disable_x2apic"],
                consumer_inputs)}


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
    global COMMAND_SUPERVISOR_PATH
    root = runtime / "compute"
    root.mkdir(mode=0o700)
    for name in ("private", "evidence", "scratch", "cache", "global-cache",
                 "global-cache/tmp", "fixtures", "supervisor", "tools"):
        (root / name).mkdir(mode=0o700)
    precreate_boot_output_slots(runtime, root)
    prepare_source_outputs()
    bison_data = os.environ.get("BISON_PKGDATADIR")
    require(bison_data == str(runtime / "bison"),
            "Bison build environment differs from bound producer input")
    COMMAND_ENVIRONMENT.clear()
    COMMAND_TOOL_PATHS.clear()
    COMMAND_ENVIRONMENT.update({
        "BISON_PKGDATADIR": bison_data,
        "KCONFIG_CONFIG": str(APP / "build/.config"),
        "KCONFIG_OVERWRITECONFIG": "1",
        "M4": tool("m4"),
        "MAKEFLAGS": "-j2",
        "WAMR_CI_PORTABLE_CONFIG": "1",
        "TMPDIR": str(root / "scratch"),
        "ZIG_GLOBAL_CACHE_DIR": str(root / "global-cache"),
        "ZIG_LIB_DIR": str(Path(tool("zig")).parent / "lib"),
        "ZIG_LOCAL_CACHE_DIR": str(root / "cache"),
    })
    os.environ.update(COMMAND_ENVIRONMENT)
    COMMAND_SUPERVISOR_PATH = None
    source_archive = seal_wamr_source(runtime, wamr)
    bootstrap_inputs = consumer_input_state(runtime)
    packages = restore_dependencies(runtime, root, bootstrap_inputs)
    build_command_supervisor(runtime, root, packages, bootstrap_inputs)
    bootstrap_consumer_inputs = consumer_input_state(runtime)
    COMMAND_ENVIRONMENT.update(bind_command_tools(bootstrap_consumer_inputs))
    os.environ.update(COMMAND_ENVIRONMENT)
    initial_source = source()
    save(root / "private/source-metadata.json", {
        "schema": "uk.wamr.git-physical-source-baseline",
        "version": 1,
        "records": source_metadata(),
    })
    bootstrap = producer_inputs(runtime, bootstrap_consumer_inputs)
    require(bootstrap["source"] == source_identity(initial_source)
            and bootstrap["source_custody"] == initial_source["custody"],
            "source changed during dependency restoration")
    zig = tool("zig")
    consumer_records = consumer_file_records(bootstrap_consumer_inputs)
    version_path, unused_record = execute(
        root, "zig-version", [zig, "version"], 30, 64,
        evidence=False, input_records=consumer_records)
    del unused_record
    version = read(version_path, 65)
    require(version.strip() == b"0.16.0", "Zig 0.16.0 required")
    run_custodied(runtime, bootstrap, root, "adapter", [
        tool("zig"), "build", "--build-file", HERE / "build.zig",
        "--system", packages, "--prefix", root / "tools",
        "-Doptimize=ReleaseSafe", "-j2", "test-unit", "install"], 900)
    run_custodied(runtime, bootstrap, root, "local-boot-tool", [
        tool("zig"), "build", "--build-file", LOCAL_BOOT / "build.zig",
        "--system", packages, "--prefix", root / "tools",
        "-Doptimize=ReleaseSafe", "-j2", "install"], 900)
    consumer_inputs = consumer_input_state(runtime)
    COMMAND_ENVIRONMENT.update(bind_command_tools(consumer_inputs))
    os.environ.update(COMMAND_ENVIRONMENT)
    initial = producer_inputs(runtime, consumer_inputs)
    require(initial["source"] == source_identity(initial_source)
            and initial["source_custody"] == initial_source["custody"],
            "source changed during native tool installation")
    save(root / "evidence/build-start.json", initial)
    fixture_environment = {
        "WAMR_CI_PACKAGE": str(root / "tools/bin/wamr-ci-package"),
        "WAMR_CI_PYTHON": tool("python3"),
        "WAMR_CI_LOG_VALIDATE": str(root / "tools/bin/uk-wamr-log-validate"),
        "WAMR_CI_SUPERVISOR_FIXTURE":
            str(root / "tools/bin/wamr-ci-supervisor-fixture"),
    }
    COMMAND_ENVIRONMENT.update(fixture_environment)
    os.environ.update(COMMAND_ENVIRONMENT)
    try:
        run_custodied(runtime, initial, root, "fixtures", [
            sys.executable, "-m", "unittest", "discover",
            "-s", HERE / "tests", "-v"])
    finally:
        for name in fixture_environment:
            COMMAND_ENVIRONMENT.pop(name, None)
            os.environ.pop(name, None)
    wamr_aot_build = root / "tools/bin/uk-wamr-aot-build"
    run_custodied(runtime, initial, root, "prepare", [
        wamr_aot_build, "prepare", "--repository", REPO,
        "--source-archive", source_archive], 1800)
    run_custodied(runtime, initial, root, "config", [
        wamr_aot_build, "olddefconfig", "--repository", REPO])
    require_no_config_backup()
    retain_solved_config()
    solved_config()
    require_build_custody(runtime, initial)
    # This target includes the unchanged final ELF IRQ/constructor/SMP proofs.
    run_custodied(runtime, initial, root, "native-image", [
        wamr_aot_build, "native-images", "--repository", REPO], 1800)
    solved_config()
    require(producer_inputs(runtime, consumer_inputs) == initial,
            "source or producer tool changed during build")
    save(root / "evidence/build.json", check_build())


def image_artifact(path, virtual_bytes):
    record, unused_directories = physical_file_record(path)
    del unused_directories
    info = path.stat()
    allocated = (
        {"state": "available", "bytes": info.st_blocks * 512}
        if hasattr(info, "st_blocks") else
        {"state": "unavailable", "bytes": None}
    )
    return {
        "path": record["path"],
        "sha256": record["sha256"],
        "file_bytes": record["metadata"][6],
        "allocated": allocated,
        "virtual_bytes": virtual_bytes,
        "metadata": record["metadata"],
    }


def require_qcow2_finalization(value, raw, efi, package_tool):
    require(set(value) == {
        "schema", "schema_version", "status", "source_sha256",
        "source_bytes", "output", "identity", "profile", "limits",
        "provenance",
    } and value["schema"] == "uk.wamr.compute-qcow2-finalization"
      and value["schema_version"] == 1 and value["status"] == "succeeded",
      "invalid QCOW2 finalization")
    require(value["source_sha256"] == raw["sha256"]
            and value["source_bytes"] == raw["size"],
            "wrong QCOW2 source")
    output = value["output"]
    require(set(output) == {
        "sha256", "file_bytes", "allocated", "virtual_bytes",
    } and output["virtual_bytes"] == raw["size"]
      and 0 < output["file_bytes"] <= 66 * MIB,
      "invalid QCOW2 output")
    require(value["profile"] == {
        "format": "qcow2", "version": 3, "cluster_bytes": 64 * 1024,
        "compression": "zstd", "incompatible_features": 8,
        "compatible_features": 0, "autoclear_features": 0,
        "header_extensions": False, "extended_l2": False,
        "encryption": False, "snapshots": 0, "backing_file": False,
        "external_data_file": False, "standalone": True,
    }, "wrong QCOW2 profile")
    identity = value["identity"]
    require(identity["workload_sha256"] == efi["sha256"]
            and identity["workload_bytes"] == efi["size"],
            "wrong QCOW2 workload")
    provenance = value["provenance"]
    require(provenance["parent_kind"] == "raw"
            and provenance["parent_sha256"] == raw["sha256"]
            and provenance["producer_sha256"] == package_tool["sha256"],
            "wrong QCOW2 provenance")
    return value


def require_vhd_derivation(
        value, accepted, package_tool, raw, source_identity):
    require(set(value) == {
        "schema", "schema_version", "status", "accepted_qcow2",
        "accepted_qcow2_decoded_sha256", "accepted_qcow2_profile",
        "source_identity", "output", "output_identity", "footer",
        "relocation", "limits", "provenance",
    } and value["schema"] == "uk.wamr.compute-fixed-vhd-derivation"
      and value["schema_version"] == 1 and value["status"] == "succeeded",
      "invalid fixed-VHD derivation")
    source = value["accepted_qcow2"]
    require(source["sha256"] == accepted["sha256"]
            and source["file_bytes"] == accepted["file_bytes"]
            and source["virtual_bytes"] == accepted["virtual_bytes"],
            "wrong accepted QCOW2 input")
    require(value["accepted_qcow2_decoded_sha256"] == raw["sha256"],
            "wrong decoded QCOW2 identity")
    require(value["accepted_qcow2_profile"] == {
        "format": "qcow2", "version": 3, "cluster_bytes": 64 * 1024,
        "compression": "zstd", "incompatible_features": 8,
        "compatible_features": 0, "autoclear_features": 0,
        "header_extensions": False, "extended_l2": False,
        "encryption": False, "snapshots": 0, "backing_file": False,
        "external_data_file": False, "standalone": True,
    }, "wrong accepted QCOW2 profile")
    output = value["output"]
    require(output["file_bytes"] == 66 * MIB + 512
            and output["virtual_bytes"] == 66 * MIB,
            "wrong fixed-VHD geometry")
    require(value["source_identity"] == source_identity
            and value["output_identity"] == source_identity
            and value["footer"]["creator"] == "miz "
            and value["footer"]["timestamp"] == 0,
            "wrong fixed-VHD identity")
    require(value["relocation"] == {
        "was_relocated": False,
        "old_backup_lba": value["relocation"]["new_backup_lba"],
        "new_backup_lba": value["relocation"]["new_backup_lba"],
        "old_last_usable_lba":
            value["relocation"]["new_last_usable_lba"],
        "new_last_usable_lba":
            value["relocation"]["new_last_usable_lba"],
        "allowed_differences":
            "protective-mbr,primary-gpt,relocated-backup-gpt,zero-padding",
    }, "wrong fixed-VHD relocation")
    provenance = value["provenance"]
    require(provenance["parent_kind"] == "qcow2"
            and provenance["parent_sha256"] == accepted["sha256"]
            and provenance["producer_sha256"] == package_tool["sha256"],
            "wrong fixed-VHD provenance")
    return value


def boot(runtime):
    global FAILURE_STAGE
    FAILURE_STAGE = "boot-platform"
    require(platform.machine() == "x86_64" and Path("/dev/kvm").is_char_device()
            and os.access("/dev/kvm", os.R_OK | os.W_OK),
            "x86 KVM runner required; no successful skip")
    root = runtime / "compute"
    FAILURE_STAGE = "boot-build-custody"
    initial = document(root / "evidence/build-start.json")
    consumer_inputs = initial["consumer_inputs"]
    require(producer_inputs(runtime, consumer_inputs) == initial,
            "producer inputs changed")
    COMMAND_ENVIRONMENT.update(bind_command_tools(consumer_inputs))
    os.environ.update(COMMAND_ENVIRONMENT)
    require(check_build() == document(root / "evidence/build.json"), "build identity changed")
    FAILURE_STAGE = "boot-output-slots"
    package_output, configs = prepare_boot_output_slots(runtime, root)
    efi = APP / "build" / EFI
    paths = {"package_tool": root / "tools/bin/wamr-ci-package",
             "local_boot_tool": root / "tools/bin/uk-hyperv-local-boot",
             "qemu": runtime / "bin/qemu-system-x86_64",
             "ovmf_code": runtime / "firmware/code.fd",
             "ovmf_vars": runtime / "firmware/vars.fd",
             "efi": efi}
    FAILURE_STAGE = "boot-input-record"
    inputs = boot_input_state(runtime, paths)
    save(root / "evidence/boot-inputs.json", inputs)

    def verify_inputs(content=False):
        boot_input_state(
            runtime, paths, content=content, expected=inputs)

    FAILURE_STAGE = "boot-package-precheck"
    verify_inputs()
    FAILURE_STAGE = "boot-package-command"
    output = run_custodied(
        runtime, initial, root, "package",
        [paths["package_tool"], "package", efi, package_output],
        150, 64 * 1024, extra_inputs=inputs, extra_input_paths=paths)
    FAILURE_STAGE = "boot-package-result"
    package = document(output)
    require(package["image"]["efi"]["sha256"] == digest(efi)
            and package["producer_sha256"]
            == inputs["files"]["package_tool"]["sha256"],
            "package identity changed")
    save(root / "evidence/package.json", {
        "scope": package["scope"], "acceptance": package["acceptance"],
        "producer_sha256": package["producer_sha256"],
        "image": {key: package["image"][key] for key in (
            "schema_version", "miz_revision", "efi", "raw", "vhd",
            "footer_sha256", "packaging")},
    })
    identity = document(APP / "build/artifacts/identity.json")

    def run_mode(index):
        global FAILURE_STAGE
        mode = SIX_MODES[index]
        config = configs[index]
        FAILURE_STAGE = mode + "-command"
        run_custodied(
            runtime, initial, root, mode,
            boot_args(paths["local_boot_tool"], config), 90, 64 * 1024,
            extra_inputs=inputs, extra_input_paths=paths)
        FAILURE_STAGE = mode + "-result"
        result = check_boot(
            config, identity, inputs, consumer_inputs=initial["consumer_inputs"])
        expected = (
            package["image"]["raw"]["sha256"] if index < 2 else
            finalization["output"]["sha256"] if index < 4 else
            derivation["output"]["sha256"]
        )
        require(digest(Path(config["source"]["path"])) == expected,
                "booted package changed")
        save(root / "evidence" / (mode + "-compute.json"), result)

    finalization = None
    derivation = None
    for index in range(2):
        run_mode(index)

    raw = package["image"]["raw"]
    efi_record = package["image"]["efi"]
    limits = {
        "max_input_bytes": 66 * MIB,
        "max_output_bytes": 66 * MIB + 512,
        "max_virtual_bytes": 66 * MIB,
        "max_partition_array_bytes": MIB,
        "max_metadata_bytes": 128 * 1024,
        "max_metadata_work": 8194,
        "max_work_bytes": 4 * 66 * MIB,
        "max_memory_bytes": 512 * MIB,
        "max_workload_bytes": 64 * MIB,
    }
    finalize_intent = {
        "schema": "uk.wamr.compute-qcow2-finalization-intent",
        "schema_version": 1,
        "source_path": str(root / "package/unikraft.raw"),
        "expected_source_sha256": raw["sha256"],
        "expected_source_bytes": raw["size"],
        "expected_virtual_bytes": raw["size"],
        "expected_workload_sha256": efi_record["sha256"],
        "expected_workload_bytes": efi_record["size"],
        "timeout_ms": 120_000,
        "limits": limits,
    }
    finalize_path = root / "evidence/qcow2-finalization-intent.json"
    save(finalize_path, finalize_intent)
    FAILURE_STAGE = "finalize-qcow2-command"
    finalize_output = run_custodied(
        runtime, initial, root, "finalize-qcow2",
        [paths["package_tool"], "finalize-qcow2",
         finalize_path, root / "package"],
        150, 64 * 1024, extra_inputs=inputs, extra_input_paths=paths)
    FAILURE_STAGE = "finalize-qcow2-result"
    finalization = require_qcow2_finalization(
        document(finalize_output), raw, efi_record,
        inputs["files"]["package_tool"])
    require(finalization == document(
        root / "package/qcow2-finalization.json"),
        "QCOW2 finalization record changed")
    save(root / "evidence/qcow2-finalization.json", finalization)
    qcow2_path = root / "package/unikraft.qcow2"
    require(digest(qcow2_path) == finalization["output"]["sha256"]
            and qcow2_path.stat().st_size
            == finalization["output"]["file_bytes"],
            "finalized QCOW2 bytes changed")

    for index in range(2, 4):
        run_mode(index)

    FAILURE_STAGE = "qcow2-acceptance"
    require(not (root / "package/unikraft-derived.vhd").exists()
            and not (root / "package/fixed-vhd-derivation.json").exists(),
            "VHD derivation preceded QCOW2 acceptance")
    accepted_boots = {}
    for index in range(4):
        mode = SIX_MODES[index]
        checked = check_boot(
            configs[index], identity, inputs,
            consumer_inputs=initial["consumer_inputs"])
        require(checked == document(
            root / "evidence" / (mode + "-compute.json")),
            "pre-derivation boot evidence changed")
        accepted_boots[mode] = {
            "request_sha256": checked["request_sha256"],
            "report_sha256": checked["report_sha256"],
            "serial_sha256": checked["report"]["serial_sha256"],
            "compute_sha256": digest(
                root / "evidence" / (mode + "-compute.json")),
        }
    require_qcow2_finalization(
        document(root / "evidence/qcow2-finalization.json"),
        raw, efi_record, inputs["files"]["package_tool"])
    accepted_qcow2 = image_artifact(
        qcow2_path, finalization["output"]["virtual_bytes"])
    require(accepted_qcow2["sha256"] == finalization["output"]["sha256"]
            and accepted_qcow2["file_bytes"]
            == finalization["output"]["file_bytes"],
            "accepted QCOW2 identity changed")
    acceptance = {
        "schema": "uk.wamr.compute-qcow2-acceptance",
        "schema_version": 1,
        "profile": CURRENT_PROFILE,
        "status": "accepted",
        "source": initial["source"],
        "accepted_qcow2": accepted_qcow2,
        "finalization_sha256": digest(
            root / "evidence/qcow2-finalization.json"),
        "modes": list(SIX_MODES[:4]),
        "boots": accepted_boots,
        "build_sha256": digest(root / "evidence/build.json"),
        "boot_inputs_sha256": digest(root / "evidence/boot-inputs.json"),
    }
    save(root / "evidence/qcow2-acceptance.json", acceptance)

    derive_intent = {
        "schema": "uk.wamr.compute-fixed-vhd-derivation-intent",
        "schema_version": 1,
        "source_path": str(qcow2_path),
        "accepted_qcow2_sha256": accepted_qcow2["sha256"],
        "expected_source_bytes": accepted_qcow2["file_bytes"],
        "expected_capacity_bytes": accepted_qcow2["virtual_bytes"],
        "timeout_ms": 120_000,
        "limits": limits,
    }
    derive_path = root / "evidence/fixed-vhd-derivation-intent.json"
    save(derive_path, derive_intent)
    derivation_gate = {
        "schema": "uk.wamr.compute-fixed-vhd-derivation-gate",
        "schema_version": 1,
        "profile": CURRENT_PROFILE,
        "status": "accepted_qcow2_only",
        "accepted_qcow2_sha256": accepted_qcow2["sha256"],
        "qcow2_acceptance_sha256": digest(
            root / "evidence/qcow2-acceptance.json"),
        "derivation_intent_sha256": digest(derive_path),
        "derived_output_absent": True,
    }
    save(root / "evidence/fixed-vhd-derivation-gate.json",
         derivation_gate)
    FAILURE_STAGE = "derive-fixed-vhd-command"
    derive_output = run_custodied(
        runtime, initial, root, "derive-fixed-vhd",
        [paths["package_tool"], "derive-fixed-vhd",
         derive_path, root / "package"],
        150, 64 * 1024, extra_inputs=inputs, extra_input_paths=paths)
    FAILURE_STAGE = "derive-fixed-vhd-result"
    derivation = require_vhd_derivation(
        document(derive_output), accepted_qcow2,
        inputs["files"]["package_tool"], raw, finalization["identity"])
    require(derivation == document(
        root / "package/fixed-vhd-derivation.json"),
        "fixed-VHD derivation record changed")
    save(root / "evidence/fixed-vhd-derivation.json", derivation)
    vhd_path = root / "package/unikraft-derived.vhd"
    require(digest(vhd_path) == derivation["output"]["sha256"]
            and vhd_path.stat().st_size == derivation["output"]["file_bytes"],
            "derived fixed-VHD bytes changed")
    with vhd_path.open("rb") as stream:
        stream.seek(-512, os.SEEK_END)
        require(hashlib.sha256(stream.read()).hexdigest()
                == derivation["footer"]["sha256"],
                "derived fixed-VHD footer changed")

    for index in range(4, 6):
        run_mode(index)

    FAILURE_STAGE = "boot-inspect-command"
    output = run_custodied(
        runtime, initial, root, "inspect",
        [paths["package_tool"], "inspect", efi, root / "package"],
        150, 64 * 1024, extra_inputs=inputs, extra_input_paths=paths)
    require(document(output) == package, "physical package reload changed")
    verify_inputs(content=True)
    FAILURE_STAGE = "boot-final-inspection"
    all_boots = {}
    for index, mode in enumerate(SIX_MODES):
        checked = check_boot(
            configs[index], identity, inputs,
            consumer_inputs=initial["consumer_inputs"])
        require(checked == document(
            root / "evidence" / (mode + "-compute.json")),
            "final boot evidence changed")
        all_boots[mode] = {
            "request_sha256": checked["request_sha256"],
            "report_sha256": checked["report_sha256"],
            "serial_sha256": checked["report"]["serial_sha256"],
            "compute_sha256": digest(
                root / "evidence" / (mode + "-compute.json")),
        }
    require(document(root / "evidence/qcow2-acceptance.json") == acceptance,
            "QCOW2 acceptance changed")
    require_qcow2_finalization(
        document(root / "evidence/qcow2-finalization.json"),
        raw, efi_record, inputs["files"]["package_tool"])
    require_vhd_derivation(
        document(root / "evidence/fixed-vhd-derivation.json"),
        accepted_qcow2, inputs["files"]["package_tool"],
        raw, finalization["identity"])
    artifacts = {
        "efi": image_artifact(efi, efi_record["size"]),
        "raw": image_artifact(
            root / "package/unikraft.raw", raw["size"]),
        "qcow2": image_artifact(
            qcow2_path, accepted_qcow2["virtual_bytes"]),
        "vhd": image_artifact(
            vhd_path, derivation["output"]["virtual_bytes"]),
    }
    require(artifacts["raw"]["sha256"] == raw["sha256"]
            and artifacts["qcow2"]["sha256"] == accepted_qcow2["sha256"]
            and artifacts["vhd"]["sha256"] == derivation["output"]["sha256"],
            "final image chain changed")
    final_inspection = {
        "schema": "uk.wamr.compute-image-chain-inspection",
        "schema_version": 1,
        "profile": CURRENT_PROFILE,
        "status": "complete",
        "source": initial["source"],
        "artifacts": artifacts,
        "records": {
            name: digest(root / "evidence" / name)
            for name in (
                "build-start.json", "build.json", "boot-inputs.json",
                "package.json", "qcow2-finalization-intent.json",
                "qcow2-finalization.json", "qcow2-acceptance.json",
                "fixed-vhd-derivation-intent.json",
                "fixed-vhd-derivation-gate.json",
                "fixed-vhd-derivation.json")
        },
        "modes": list(SIX_MODES),
        "boots": all_boots,
    }
    save(root / "evidence/final-inspection.json", final_inspection)
    FAILURE_STAGE = "boot-final-custody"
    require(producer_inputs(runtime, consumer_inputs) == initial,
            "producer inputs changed after boot")
    require(check_build() == document(root / "evidence/build.json"), "source or image changed")
    # No self hash: this final record binds earlier immutable observations only.
    save(root / "evidence/result.json", {
        "schema_version": 2, "profile": CURRENT_PROFILE,
        "scope": "local_native_compute_only", "passed": True,
        "hardware_acceptance": "not_established", "cloud_authority": "not_admitted",
        "benchmark": "not_measured", "workload": "tiny",
        "modes": list(SIX_MODES),
        "records": {p.name: digest(p) for p in sorted((root / "evidence").glob("*.json"))},
    })


def diagnostics(runtime):
    """Allowlisted observations only. Raw serial/build/runtime logs stay private."""
    root = runtime / "compute"
    root.mkdir(mode=0o700, exist_ok=True)
    (root / "evidence").mkdir(mode=0o700, exist_ok=True)
    observations = {}
    for mode in SIX_MODES:
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
    build_failures = {}
    try:
        command = document(root / "evidence/command-fixtures.json")
        require(type(command["exit_code"]) is int, "invalid diagnostic")
        if command["exit_code"] != 0:
            build_failures["fixtures"] = {
                "exit_code": command["exit_code"],
                "tests": unittest_failure_markers(
                    read(root / "private/fixtures.log", 64 * 1024)),
            }
    except (OSError, ValueError, KeyError, TypeError, Refusal):
        pass
    try:
        command = document(root / "evidence/command-config.json")
        require(type(command["exit_code"]) is int
                and command["exit_code"] != 0, "invalid diagnostic")
        private = APP / "build"
        for component in ("native-environment",):
            info = private.lstat()
            require(stat.S_ISDIR(info.st_mode)
                    and info.st_uid == os.getuid()
                    and stat.S_IMODE(info.st_mode) == 0o700,
                    "invalid diagnostic directory")
            private /= component
        info = private.lstat()
        require(stat.S_ISDIR(info.st_mode)
                and info.st_uid == os.getuid()
                and stat.S_IMODE(info.st_mode) == 0o700,
                "invalid diagnostic directory")
        error_name = read(private / "failure-error-name.txt", 96)
        require(re.fullmatch(rb"[A-Z][A-Za-z0-9]{0,79}", error_name),
                "invalid native error name")
        build_failures["config"] = {
            "exit_code": command["exit_code"],
            "native_error_name_sha256": hashlib.sha256(error_name).hexdigest(),
        }
        try:
            role = read(private / "failure-tool-role.txt", 96)
            require(re.fullmatch(rb"[a-z][a-z0-9-]{0,79}", role),
                    "invalid native tool role")
            build_failures["config"]["tool_role_sha256"] = (
                hashlib.sha256(role).hexdigest())
        except (OSError, Refusal):
            pass
        private /= "diagnostics"
        info = private.lstat()
        require(stat.S_ISDIR(info.st_mode)
                and info.st_uid == os.getuid()
                and stat.S_IMODE(info.st_mode) == 0o700,
                "invalid diagnostic directory")
        entries = list(private.iterdir())
        require(len(entries) == 1
                and re.fullmatch(r"image-[0-9]+(?:-[0-9]+)?", entries[0].name),
                "invalid diagnostic directory")
        info = entries[0].lstat()
        require(stat.S_ISDIR(info.st_mode)
                and info.st_uid == os.getuid()
                and stat.S_IMODE(info.st_mode) == 0o700,
                "invalid diagnostic directory")
        backend = document(entries[0] / "000-root-olddefconfig.json")
        code = backend["primary"]["exited"]
        require(backend["stage"] == "root-olddefconfig"
                and type(code) is int and 0 <= code <= 255,
                "invalid diagnostic")
        output = read(entries[0] / "000-root-olddefconfig.stderr", 64 * 1024)
        build_failures["config"].update({
            "backend_exit_code": code,
            "known_error_markers": command_error_markers(output),
        })
    except (OSError, ValueError, KeyError, TypeError, Refusal):
        pass
    try:
        command = document(root / "evidence/command-native-image.json")
        require(type(command["exit_code"]) is int
                and command["exit_code"] != 0, "invalid diagnostic")
        private = APP / "build"
        for component in ("native-environment",):
            info = private.lstat()
            require(stat.S_ISDIR(info.st_mode)
                    and info.st_uid == os.getuid()
                    and stat.S_IMODE(info.st_mode) == 0o700,
                    "invalid diagnostic directory")
            private /= component
        info = private.lstat()
        require(stat.S_ISDIR(info.st_mode)
                and info.st_uid == os.getuid()
                and stat.S_IMODE(info.st_mode) == 0o700,
                "invalid diagnostic directory")
        error_name = read(private / "failure-error-name.txt", 96)
        require(re.fullmatch(rb"[A-Z][A-Za-z0-9]{0,79}", error_name),
                "invalid native error name")
        build_failures["native-image"] = {
            "exit_code": command["exit_code"],
            "native_error_name_sha256": hashlib.sha256(error_name).hexdigest(),
        }
        try:
            guard = read(private / "failure-image-guard.txt", 96)
            require(re.fullmatch(rb"[a-z][a-z0-9-]{0,79}", guard),
                    "invalid native image guard")
            build_failures["native-image"]["image_guard_sha256"] = (
                hashlib.sha256(guard).hexdigest())
        except (OSError, Refusal):
            pass
        try:
            role = read(private / "failure-tool-role.txt", 96)
            require(re.fullmatch(rb"[a-z][a-z0-9-]{0,79}", role),
                    "invalid native tool role")
            build_failures["native-image"]["tool_role_sha256"] = (
                hashlib.sha256(role).hexdigest())
        except (OSError, Refusal):
            pass
    except (OSError, ValueError, KeyError, TypeError, Refusal):
        pass
    save(root / "evidence/diagnostics.json", {
        "scope": "diagnostics_not_acceptance",
        "redaction": "no_raw_serial_paths_environment_or_account_state",
        "build_failures": build_failures,
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
        print("WAMR_CI_FAILED_STAGE: " + FAILURE_STAGE
              + "; bounded private logs and redacted diagnostics retained.",
              file=sys.stderr)
        sys.exit(1)
