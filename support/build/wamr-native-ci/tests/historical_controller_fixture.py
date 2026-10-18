# SPDX-License-Identifier: BSD-3-Clause
"""Test-only immutable Python-v2 compatibility evidence, never a current owner."""
import argparse
import ast
import copy
import hashlib
import importlib.abc
import importlib.util
import json
import os
from pathlib import Path
import shutil
import stat
import struct
import subprocess
import sys
import types

REVISION = "e98623f780fa23d05b5797004e4b88160404eb1b"
PACKAGE = "support/build/wamr-native-ci"
COMMAND_CONTRACT = "support/tools/hyperv/process-command-v1.json"
SOURCES = {
    "run.py": (
        "67386d4ab0fc9fb33e675a4232246878f6324c73",
        "988abba2607410b1fb3864e6688b7078b46c1f8c4d167327400925030f55b380",
    ),
    "tests/test_adapter.py": (
        "04c66355c791fd415ff3ad252dcebca0286fdad7",
        "c1369266cd412a712e5fb94729b9cf69bc870213188c806409176aa3597e0cab",
    ),
    COMMAND_CONTRACT: (
        "ad73db8f74d76dfb14a39969b2b0ec8f4bd73419",
        "ee1e038f6538beecac8a09d4d52a6c601a9ca1f503fd70a3753bd8d2e3ac904b",
    ),
}
STAGES = (
    "adapter", "local-boot-tool", "fixtures", "prepare", "config",
    "native-image", "package", "raw-x2apic", "raw-legacy-apic",
    "finalize-qcow2", "qcow2-x2apic", "qcow2-legacy-apic",
    "derive-fixed-vhd", "vpc-x2apic", "vpc-legacy-apic", "inspect",
    "log-validator-x2apic", "log-validator-legacy",
)
ORACLE_REVISION = "c72bd80b024694590912259fb88a4ba06e84f0a2"
ORACLE_SOURCES = {
    "run.py": (
        "bbd27d611f1d52e610e8588138c8a4e6b3903392",
        "5c0335859329a9131defd84bbfe967cfa9009754de1a93807dd7ef9a3fdc0227",
    ),
    "accepted_records.py": (
        "7ff60b1eb83c3ff343885d47d11299d146b1b312",
        "8ded5b670d89620544c02bb9ad0e1f8ac7a9757207d5b05555d7abbebcff9d84",
    ),
    "public_bundle.py": (
        "0915fdad81109e9afdf171ae07c927100aaefda1",
        "68734d9db7ac38eaa41efe6b1c393199033360c5683ab9d26f2fb34ea8ea4536",
    ),
    "handoff.py": (
        "b84b58341248297cd1807dfb21eab4d363b3c060",
        "a8a9eaae6ba41fa7b0643c2af6711f48f7c97e27e13cd9c8bdb5811560edf7d2",
    ),
    COMMAND_CONTRACT: (
        "ad73db8f74d76dfb14a39969b2b0ec8f4bd73419",
        "ee1e038f6538beecac8a09d4d52a6c601a9ca1f503fd70a3753bd8d2e3ac904b",
    ),
}
_SUBPROCESS_RUN = subprocess.run
_ORACLE_BLOB_CACHE = {}
_ORACLE_CODE_CACHE = {}
_STDLIB_SHA256 = hashlib.sha256
_REAL_OS_OPEN = os.open
_REAL_OS_FSTAT = os.fstat
_REAL_OS_CLOSE = os.close
_REAL_OS_PREAD = os.pread
_REAL_OS_WRITE = os.write
_REAL_OS_REPLACE = os.replace
_REAL_OS_UNLINK = os.unlink
_DIGEST_CACHE_MIN_SIZE = 65536
_DIGEST_PROBE_WINDOW = 4096
_SHM_HEADER = struct.Struct("<8sII")
_SHM_ENTRY = struct.Struct("<QIIIIIIQQQqqqqQ32sII")
_SHM_SLOTS = 512
_SHM_SIZE = 16 + _SHM_SLOTS * 136


def _wyhash0_12k(data):
    mask = 0xFFFFFFFFFFFFFFFF
    s0 = 0xa0761d6478bd642f
    s1 = 0xe7037ed1a0b428db
    s2 = 0x8ebc6af09c88c6e3
    s3 = 0x589965cc75374cc3
    x = s0 * s1
    st0 = (x ^ (x >> 64)) & mask
    st1 = st0
    st2 = st0
    words = struct.unpack("<1536Q", data)
    for idx in range(0, 1530, 6):
        x = (words[idx] ^ s1) * (words[idx + 1] ^ st0)
        st0 = (x ^ (x >> 64)) & mask
        x = (words[idx + 2] ^ s2) * (words[idx + 3] ^ st1)
        st1 = (x ^ (x >> 64)) & mask
        x = (words[idx + 4] ^ s3) * (words[idx + 5] ^ st2)
        st2 = (x ^ (x >> 64)) & mask
    st0 ^= st1 ^ st2
    x = (words[1530] ^ s1) * (words[1531] ^ st0)
    st0 = (x ^ (x >> 64)) & mask
    x = (words[1532] ^ s1) * (words[1533] ^ st0)
    st0 = (x ^ (x >> 64)) & mask
    x = (words[1534] ^ s1) * (words[1535] ^ st0)
    a = x & mask
    b = (x >> 64) & mask
    x = (a ^ s0 ^ 12288) * (b ^ s1)
    return (x ^ (x >> 64)) & mask


def _make_cache_key(info, bhash):
    mtime_sec, mtime_nsec = divmod(info.st_mtime_ns, 1_000_000_000)
    ctime_sec, ctime_nsec = divmod(info.st_ctime_ns, 1_000_000_000)
    return (
        1,
        os.major(info.st_dev),
        os.minor(info.st_dev),
        info.st_mode,
        info.st_uid,
        info.st_gid,
        0,
        info.st_ino,
        info.st_nlink,
        info.st_size,
        mtime_sec,
        mtime_nsec,
        ctime_sec,
        ctime_nsec,
        bhash,
    )


def _sync_shm_cache(state):
    if os.open is not _REAL_OS_OPEN:
        return
    shm_path = f"/dev/shm/uk-wamr-digest-cache-{os.geteuid()}-v1.bin"
    flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    try:
        fd = _REAL_OS_OPEN(shm_path, flags)
    except OSError:
        return
    try:
        st = _REAL_OS_FSTAT(fd)
        if (not stat.S_ISREG(st.st_mode) or st.st_uid != os.geteuid()
                or st.st_mode & 0o077 or st.st_size != _SHM_SIZE):
            return
        shm_id = (st.st_ino, st.st_mtime_ns)
        if state["shm_id"] == shm_id:
            return
        raw = _REAL_OS_PREAD(fd, _SHM_SIZE, 0)
        if len(raw) != _SHM_SIZE:
            return
        magic, ver, _ = _SHM_HEADER.unpack_from(raw, 0)
        if magic != b"UKDGST01" or ver != 1:
            return
        state["shm_id"] = shm_id
        state["shm_raw"][:] = raw
        entries = state["entries"]
        for slot in range(_SHM_SLOTS):
            unpacked = _SHM_ENTRY.unpack_from(raw, 16 + slot * 136)
            if unpacked[0] == 1:
                key = unpacked[:15]
                old = entries.get(key)
                merged_flags = unpacked[17] | (old[1] if old else 0)
                entries[key] = (unpacked[15].hex(), merged_flags)
    except OSError:
        return
    finally:
        _REAL_OS_CLOSE(fd)


def _store_shm_entry(state, key, digest_hex, entry_flags):
    entries = state["entries"]
    old = entries.get(key)
    if old is not None and old[0] == digest_hex and (old[1] & entry_flags) == entry_flags:
        return
    merged_flags = entry_flags | (old[1] if old and old[0] == digest_hex else 0)
    entries[key] = (digest_hex, merged_flags)
    if os.open is not _REAL_OS_OPEN:
        return
    _sync_shm_cache(state)
    entries[key] = (digest_hex, merged_flags)
    try:
        raw_digest = bytes.fromhex(digest_hex)
    except ValueError:
        return
    if len(raw_digest) != 32:
        return
    set_idx = (key[7] ^ (key[9] >> 12) ^ key[14] ^ 0x9e3779b97f4a7c15) & 127
    base = set_idx * 4
    shm_raw = state["shm_raw"]
    target_slot = None
    empty_slot = None
    for way in range(4):
        slot = base + way
        unpacked = _SHM_ENTRY.unpack_from(shm_raw, 16 + slot * 136)
        if unpacked[:15] == key:
            target_slot = slot
            merged_flags |= unpacked[17]
            entries[key] = (digest_hex, merged_flags)
            break
        if unpacked[0] == 0 and empty_slot is None:
            empty_slot = slot
    if target_slot is None:
        if empty_slot is not None:
            target_slot = empty_slot
        else:
            target_slot = base + (state["evict_seq"] & 3)
            state["evict_seq"] = (state["evict_seq"] + 1) & 0xFFFFFFFF
    _SHM_ENTRY.pack_into(shm_raw, 16 + target_slot * 136, *key, raw_digest, 0, merged_flags)
    euid = os.geteuid()
    shm_path = f"/dev/shm/uk-wamr-digest-cache-{euid}-v1.bin"
    seq = state["tmp_seq"]
    state["tmp_seq"] = (seq + 1) & 0xFFFFFFFF
    tmp_path = f"/dev/shm/.uk-wamr-digest-cache-{euid}-{os.getpid()}-{seq}.tmp"
    create_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    try:
        fd = _REAL_OS_OPEN(tmp_path, create_flags, 0o600)
        try:
            written = 0
            view = memoryview(shm_raw)
            while written < _SHM_SIZE:
                n = _REAL_OS_WRITE(fd, view[written:])
                if n <= 0:
                    raise OSError("short shm write")
                written += n
            st = _REAL_OS_FSTAT(fd)
        finally:
            _REAL_OS_CLOSE(fd)
        _REAL_OS_REPLACE(tmp_path, shm_path)
        state["shm_id"] = (st.st_ino, st.st_mtime_ns)
    except OSError:
        try:
            _REAL_OS_UNLINK(tmp_path)
        except OSError:
            pass


def _install_oracle_digest_cache(relative, module):
    if relative != "run.py":
        return

    def _fd_boundary_hash(handle, size, reason=None):
        if size < _DIGEST_CACHE_MIN_SIZE:
            return None
        mid = 1048576 if size >= 2097152 else (size // 2) & ~4095
        c0 = module.os.pread(handle, _DIGEST_PROBE_WINDOW, 0)
        c1 = module.os.pread(handle, _DIGEST_PROBE_WINDOW, mid)
        c2 = module.os.pread(handle, _DIGEST_PROBE_WINDOW, size - _DIGEST_PROBE_WINDOW)
        eof = module.os.pread(handle, 1, size)
        ok = (len(c0) == _DIGEST_PROBE_WINDOW and len(c1) == _DIGEST_PROBE_WINDOW
              and len(c2) == _DIGEST_PROBE_WINDOW and not eof)
        if reason is not None:
            module.require(ok, reason)
        elif not ok:
            return None
        return _wyhash0_12k(c0 + c1 + c2)

    def _digest_cache_state():
        state = sys.__dict__.get("_uk_wamr_py_digest_cache")
        if state is None:
            state = {
                "entries": {},
                "verified_archives": set(),
                "shm_id": None,
                "shm_raw": bytearray(_SHM_HEADER.pack(b"UKDGST01", 1, 0) + b"\x00" * (_SHM_SLOTS * 136)),
                "evict_seq": 0,
                "tmp_seq": 0,
            }
            sys.__dict__["_uk_wamr_py_digest_cache"] = state
        state["cached_fd_entry"] = cached_fd_entry
        state["store_fd_digest"] = store_fd_digest
        state["seed_file_digest"] = seed_file_digest
        state["snapshot"] = module.snapshot
        return state

    def cached_fd_entry(handle, expected, reason=None):
        if module.hashlib.sha256 is not _STDLIB_SHA256 or expected.st_size < _DIGEST_CACHE_MIN_SIZE:
            return None, None
        bhash = _fd_boundary_hash(handle, expected.st_size, reason=reason)
        if bhash is None:
            return None, None
        key = _make_cache_key(expected, bhash)
        state = _digest_cache_state()
        entry = state["entries"].get(key)
        if entry is None:
            _sync_shm_cache(state)
            entry = state["entries"].get(key)
        if entry is not None:
            if reason is not None:
                module.require(module.snapshot(module.os.fstat(handle)) == module.snapshot(expected), reason)
            elif module.snapshot(module.os.fstat(handle)) != module.snapshot(expected):
                return None, None
        return key, entry

    def store_fd_digest(handle, expected, digest_hex, reason=None, flags=0, key=None):
        if module.hashlib.sha256 is not _STDLIB_SHA256 or expected.st_size < _DIGEST_CACHE_MIN_SIZE:
            return
        if key is None:
            bhash = _fd_boundary_hash(handle, expected.st_size, reason=reason)
            if bhash is None:
                return
            key = _make_cache_key(expected, bhash)
        _store_shm_entry(_digest_cache_state(), key, digest_hex, flags)

    def seed_file_digest(path, digest_hex, flags=0):
        if module.hashlib.sha256 is not _STDLIB_SHA256:
            return
        path = module.Path(path)
        try:
            info = path.lstat()
            if not module.stat.S_ISREG(info.st_mode) or info.st_size < _DIGEST_CACHE_MIN_SIZE:
                return
            fd = module.os.open(path, module.open_flags())
        except OSError:
            return
        try:
            if module.snapshot(module.os.fstat(fd)) != module.snapshot(info):
                return
            store_fd_digest(fd, info, digest_hex, flags=flags)
        finally:
            module.os.close(fd)

    def digest_descriptor(handle, expected, limit, reason, allow_empty=False):
        module.require(
            module.stat.S_ISREG(expected.st_mode) and not expected.st_mode & 0o022
            and (allow_empty or expected.st_size > 0)
            and expected.st_size <= limit,
            reason,
        )
        module.require(module.snapshot(module.os.fstat(handle)) == module.snapshot(expected), reason)
        key, cached = cached_fd_entry(handle, expected, reason=reason)
        if cached is not None:
            return cached[0]
        value = module.hashlib.sha256()
        position = 0
        while position < expected.st_size:
            chunk = module.os.pread(handle, min(64 * 1024, expected.st_size - position), position)
            module.require(chunk, reason)
            value.update(chunk)
            position += len(chunk)
        module.require(
            not module.os.pread(handle, 1, position)
            and module.snapshot(module.os.fstat(handle)) == module.snapshot(expected),
            reason,
        )
        digest_hex = value.hexdigest()
        if key is not None:
            store_fd_digest(handle, expected, digest_hex, key=key)
        return digest_hex

    module._STDLIB_SHA256 = _STDLIB_SHA256
    module.cached_fd_entry = cached_fd_entry
    module.store_fd_digest = store_fd_digest
    module.seed_file_digest = seed_file_digest
    module.digest_descriptor = digest_descriptor
    _digest_cache_state()


def _normalize_oracle_relative(name):
    if name == COMMAND_CONTRACT or name.endswith(".py"):
        return name
    return name + ".py"


def oracle_blob(repository=None, relative="handoff.py", git="git", *, run=None):
    relative = _normalize_oracle_relative(relative)
    repository = (
        Path(__file__).resolve().parents[4]
        if repository is None
        else Path(repository).resolve()
    )
    key = (str(repository), str(git), relative)
    if run is None and key in _ORACLE_BLOB_CACHE:
        return _ORACLE_BLOB_CACHE[key]
    oid, expected = ORACLE_SOURCES[relative]
    environment = {
        "PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C",
        "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_TERMINAL_PROMPT": "0", "GIT_NO_REPLACE_OBJECTS": "1",
    }
    executable = (
        shutil.which(str(git), path=environment["PATH"])
        or shutil.which(str(git))
    )
    if executable is None:
        raise RuntimeError("explicit historical oracle Git unavailable")
    runner = _SUBPROCESS_RUN if run is None else run
    argv = [executable, "-C", str(repository), "-c", "core.fsmonitor=false"]
    path = relative if relative == COMMAND_CONTRACT else PACKAGE + "/" + relative
    selected = runner(
        argv + ["rev-parse", ORACLE_REVISION + ":" + path],
        env=environment, capture_output=True, timeout=30, check=True,
    ).stdout
    if selected != (oid + "\n").encode("ascii"):
        raise RuntimeError("historical oracle blob identity changed")
    raw = runner(
        argv + ["cat-file", "blob", oid], env=environment,
        capture_output=True, timeout=30, check=True,
    ).stdout
    if len(raw) > 1024 * 1024 or hashlib.sha256(raw).hexdigest() != expected:
        raise RuntimeError("historical oracle source authentication failed")
    if run is None:
        _ORACLE_BLOB_CACHE[key] = raw
    return raw


def oracle_source(name, repository=None, git="git", *, run=None):
    return oracle_blob(repository, name, git, run=run).decode("utf-8")


def _compile_oracle_code(
    relative, module_file, repository=None, git="git", *, source=None, run=None
):
    relative = _normalize_oracle_relative(relative)
    repository = (
        Path(__file__).resolve().parents[4]
        if repository is None
        else Path(repository).resolve()
    )
    key = (str(repository), str(git), relative, str(module_file))
    if source is None and run is None and key in _ORACLE_CODE_CACHE:
        return _ORACLE_CODE_CACHE[key]
    raw_source = (
        oracle_source(relative, repository, git, run=run)
        if source is None
        else source
    )
    tree = ast.parse(raw_source, filename=str(module_file))
    for index, node in enumerate(tree.body):
        if (
            isinstance(node, ast.Import)
            and len(node.names) == 1
            and node.names[0].name == "importlib.util"
            and node.names[0].asname is None
        ):
            tree.body[index] = ast.copy_location(ast.Pass(), node)
    if relative == "run.py":
        contract = oracle_source(COMMAND_CONTRACT, repository, git, run=run)
        assignments = [
            node for node in tree.body
            if isinstance(node, ast.Assign)
            and any(isinstance(name, ast.Name)
                    and name.id == "COMMAND_CONTRACT"
                    for name in node.targets)
        ]
        if len(assignments) != 1:
            raise RuntimeError("historical oracle protocol schema binding changed")
        assignments[0].value = ast.Call(
            func=ast.Attribute(value=ast.Name(id="json", ctx=ast.Load()),
                               attr="loads", ctx=ast.Load()),
            args=[ast.Constant(value=contract)], keywords=[],
        )
    ast.fix_missing_locations(tree)
    code = compile(tree, str(module_file), "exec")
    if source is None and run is None:
        _ORACLE_CODE_CACHE[key] = code
    return code


class _OracleSpecLoader(importlib.abc.Loader):
    def __init__(self, relative, origin, repository, git, run):
        self.relative = relative
        self.origin = str(origin)
        self.repository = repository
        self.git = git
        self.run = run

    def create_module(self, spec):
        return None

    def exec_module(self, module):
        module.__file__ = self.origin
        code = _compile_oracle_code(
            self.relative,
            self.origin,
            self.repository,
            self.git,
            run=self.run,
        )
        module.__dict__["importlib"] = _oracle_importlib(
            self.repository, self.git, self.run
        )
        exec(code, module.__dict__)
        _install_oracle_digest_cache(self.relative, module)


def _oracle_importlib(repository, git="git", run=None):
    def spec_from_file_location(name, location, *args, **kwargs):
        path = Path(location)
        if path.name in ORACLE_SOURCES and path.name.endswith(".py"):
            loader = _OracleSpecLoader(path.name, path, repository, git, run)
            return importlib.util.spec_from_loader(name, loader, origin=str(path))
        return importlib.util.spec_from_file_location(
            name, location, *args, **kwargs
        )

    util = types.SimpleNamespace(
        spec_from_file_location=spec_from_file_location,
        module_from_spec=importlib.util.module_from_spec,
        spec_from_loader=importlib.util.spec_from_loader,
    )
    return types.SimpleNamespace(util=util)


def load_oracle_module(
    name,
    repository=None,
    *,
    producer=None,
    source=None,
    git="git",
    run=None,
    module_name=None,
):
    relative = _normalize_oracle_relative(name)
    repository = (
        Path(__file__).resolve().parents[4]
        if repository is None
        else Path(repository).resolve()
    )
    target = repository if producer is None else Path(producer)
    module_file = str(target / PACKAGE / relative)
    module = types.ModuleType(module_name or relative.removesuffix(".py"))
    module.__file__ = module_file
    module.__dict__["importlib"] = _oracle_importlib(repository, git, run)
    code = _compile_oracle_code(
        relative, module_file, repository, git, source=source, run=run
    )
    exec(code, module.__dict__)
    _install_oracle_digest_cache(relative, module)
    return module


def run_oracle_cli(name="handoff", repository=None, git="git"):
    relative = _normalize_oracle_relative(name)
    repository = (
        Path(__file__).resolve().parents[4]
        if repository is None
        else Path(repository).resolve()
    )
    module_file = str(repository / PACKAGE / relative)
    sys.argv[0] = module_file
    module = types.ModuleType("__main__")
    module.__file__ = module_file
    module.__dict__["importlib"] = _oracle_importlib(repository, git, None)
    sys.modules["__main__"] = module
    code = _compile_oracle_code(relative, module_file, repository, git)
    exec(code, module.__dict__)


def git_blob(repository, git, relative):
    oid, expected = SOURCES[relative]
    environment = {
        "PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C",
        "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_TERMINAL_PROMPT": "0", "GIT_NO_REPLACE_OBJECTS": "1",
    }
    executable = shutil.which(str(git))
    if executable is None:
        raise RuntimeError("explicit historical fixture Git unavailable")
    argv = [executable, "-C", str(repository), "-c", "core.fsmonitor=false"]
    path = relative if relative == COMMAND_CONTRACT else PACKAGE + "/" + relative
    selected = subprocess.run(
        argv + ["rev-parse", REVISION + ":" + path],
        env=environment, capture_output=True, timeout=30, check=True,
    ).stdout
    if selected != (oid + "\n").encode("ascii"):
        raise RuntimeError("historical fixture blob identity changed")
    raw = subprocess.run(
        argv + ["cat-file", "blob", oid], env=environment,
        capture_output=True, timeout=30, check=True,
    ).stdout
    if len(raw) > 1024 * 1024 or hashlib.sha256(raw).hexdigest() != expected:
        raise RuntimeError("historical fixture source authentication failed")
    return raw


def load_controller(repository, git, producer=None):
    raw = git_blob(repository, git, "run.py")
    contract = git_blob(repository, git, COMMAND_CONTRACT).decode("utf-8")
    module = types.ModuleType("immutable_historical_controller")
    module.__file__ = str(Path(producer or repository) / PACKAGE / "run.py")
    tree = ast.parse(raw)
    assignments = [node for node in tree.body
                   if isinstance(node, ast.Assign)
                   and any(isinstance(name, ast.Name)
                           and name.id == "COMMAND_CONTRACT"
                           for name in node.targets)]
    if len(assignments) != 1:
        raise RuntimeError("historical protocol schema binding changed")
    # The older v1 checkouts predate this neutral protocol schema. Supply the
    # exact authenticated historical JSON, never a current filesystem oracle;
    # the controller's original schema checks and every function stay intact.
    assignments[0].value = ast.Call(
        func=ast.Attribute(value=ast.Name(id="json", ctx=ast.Load()),
                           attr="loads", ctx=ast.Load()),
        args=[ast.Constant(value=contract)], keywords=[])
    ast.fix_missing_locations(tree)
    exec(compile(tree, module.__file__, "exec"), module.__dict__)
    return module


def load_bindings(repository, git, controller, uid=None):
    raw = git_blob(repository, git, "tests/test_adapter.py")
    original = ast.parse(raw)
    evidence = next(node for node in original.body
                    if isinstance(node, ast.ClassDef)
                    and node.name == "Evidence")
    names = {"supervised_binding", "rehash_supervised_binding"}
    methods = [node for node in evidence.body
               if isinstance(node, ast.FunctionDef) and node.name in names]
    if {node.name for node in methods} != names:
        raise RuntimeError("historical fixture helpers missing")
    # Extract only authenticated neutral constructors, not the mixed test
    # module's current PUBLIC/handoff imports or its live qualification tests.
    evidence.bases = []
    evidence.decorator_list = []
    evidence.body = methods
    selected = ast.Module(body=[evidence], type_ignores=[])
    namespace = {
        "ci": controller, "copy": copy, "hashlib": hashlib, "stat": stat,
        "os": os if uid is None else types.SimpleNamespace(getuid=lambda: uid),
    }
    exec(compile(selected, REVISION + ":tests/test_adapter.py", "exec"),
         namespace)
    return namespace["Evidence"]()


def differences(original, changed):
    if isinstance(original, dict) and isinstance(changed, dict):
        if original.keys() != changed.keys():
            raise RuntimeError("historical fixture record schema changed")
        return {
            name: differences(value, changed[name])
            for name, value in original.items() if value != changed[name]
        }
    return changed


def frozen_fixture(repository, git):
    ci = load_controller(repository, git)
    evidence = load_bindings(repository, git, ci, uid=0)

    def neutral_binding(stage, profile=ci.CURRENT_PROFILE):
        record = evidence.supervised_binding(stage, profile)[0]

        def normalize(value):
            if isinstance(value, dict):
                if "content_sha256" in value:
                    # These are synthetic schema vectors, not physical pins.
                    # Keep the role digest while sharing neutral metadata.
                    value.update(inode=1, size=4097, ctime_nanoseconds=1,
                                 mtime_nanoseconds=1)
                else:
                    for member in value.values():
                        normalize(member)
            elif isinstance(value, list):
                for member in value:
                    normalize(member)

        normalize(record)
        evidence.rehash_supervised_binding(record)
        return record

    template = neutral_binding("adapter")
    value = {
        "scope": "synthetic_command_diagnostic_not_acceptance",
        "revision": REVISION,
        "sources": {
            name: {"blob": oid, "sha256": sha256}
            for name, (oid, sha256) in SOURCES.items()
        },
        "supervisor_sources": sorted(ci.SUPERVISOR_SOURCE_FILES),
        "handoff_contract": ci.production_command_contract("handoff-inspect"),
        "binding_template": template,
        "bindings": {
            stage: differences(template, neutral_binding(stage))
            for stage in STAGES
        },
        "legacy_binding": differences(
            template, neutral_binding(
                "handoff-inspect-legacy", profile="tiny-aot-two-boot")),
    }
    arrays = {}

    def intern(value):
        if isinstance(value, list) and len(value) > 5:
            key = hashlib.sha256(json.dumps(
                value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
            arrays[key] = value
            return {"fixture_array": key}
        if isinstance(value, dict):
            return {name: intern(member) for name, member in value.items()}
        return value

    value = intern(value)
    value["arrays"] = arrays
    return value


def frozen_bytes(repository, git):
    return (json.dumps(frozen_fixture(repository, git), sort_keys=True,
                       indent=2) + "\n").encode("ascii")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true", required=True)
    parser.add_argument("--git", default="git")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[4]
    target = root / PACKAGE / "controller/fixtures/historical_controller.json"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(frozen_bytes(root, args.git))
