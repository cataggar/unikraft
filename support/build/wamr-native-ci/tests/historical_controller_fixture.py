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
    if relative == "run.py":
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
        return

    if relative == "handoff.py":
        def export(runtime, output, *, on_phase=None):
            """Use the pinned producer's reader; never downgrade a native refusal."""
            def phase(name):
                if on_phase is not None:
                    on_phase(name)

            module.private(runtime)
            module.private(output.parent)
            root = runtime / "compute"
            phase("records")
            result = module._local_result(root)
            version = result["schema_version"]
            accepted, records = module._selected_records(root, result)
            module.ci.require(accepted is not None, "native local acceptance required")
            modes = tuple(accepted["modes"])
            names = module.NAMES if version == 1 else module.V2_NAMES
            expected = module.ci.document(root / "evidence/build-start.json")
            legacy_supervision = "command_supervisor" not in expected
            supervisor = expected.get("consumer_inputs", {}).get(
                "files", {}).get("command-supervisor", {}).get("path")
            native_produced = (
                supervisor == str(runtime / "controller/bin/uk-wamr-native-ci"))
            module.ci.require(not native_produced or not legacy_supervision,
                              "native command supervision required")
            if not legacy_supervision:
                module.ci.COMMAND_ENVIRONMENT.update(module.ci.bind_command_tools(
                    expected["consumer_inputs"]))
            else:
                module.ci.COMMAND_ENVIRONMENT.clear()
                module.ci.COMMAND_TOOL_PATHS.clear()
                supervisor_path = module.ci.bind_command_supervisor(
                    expected["consumer_inputs"])
                module.ci.COMMAND_ENVIRONMENT["WAMR_CI_SUPERVISOR"] = supervisor_path
            build = module.ci.document(root / "evidence/build.json")
            module.ci.require(build["source"] == accepted["source"], "native source changed")
            phase("inspect")
            inspected_output, unused_inspected_command = (
                module.accepted_records.handoff_inspect(
                    runtime, output, legacy=legacy_supervision))
            del unused_inspected_command
            for name in ("artifacts", "boots"):
                (output / name).mkdir(mode=0o700)
            inspected = module.ci.document(inspected_output)
            packaged = module.ci.document(root / "evidence/package.json")
            module.ci.require(
                inspected["producer_sha256"] == packaged["producer_sha256"]
                and all(inspected["image"][key] == value
                        for key, value in packaged["image"].items()),
                "physical package changed")
            legacy_paths = (
                module.ci.APP / "build" / module.ci.EFI,
                module.ci.APP / "build" / (module.ci.EFI + ".dbg"),
                module.ci.APP / "build" / (module.ci.EFI + ".bootinfo"),
                root / "package/unikraft.raw",
                root / "package/unikraft.vhd",
                module.ci.APP / "build/artifacts/libwamr-aot.a",
                module.ci.APP / "build/artifacts/wamrc",
                module.ci.APP / "build/artifacts/tiny.wasm",
                module.ci.APP / "build/artifacts/tiny.cwasm",
                module.ci.APP / ".config",
                module.ci.APP / "build/artifacts/identity.json",
                module.ci.APP / "build/image-identity.json",
                root / "evidence/result.json", root / "evidence/package.json",
                root / "evidence/build.json", root / "evidence/build-start.json",
                root / "evidence/boot-inputs.json")
            current_paths = (
                module.ci.APP / "build" / module.ci.EFI,
                module.ci.APP / "build" / (module.ci.EFI + ".dbg"),
                module.ci.APP / "build" / (module.ci.EFI + ".bootinfo"),
                root / "package/unikraft.raw", root / "package/unikraft.qcow2",
                root / "package/unikraft-derived.vhd",
                module.ci.APP / "build/artifacts/libwamr-aot.a",
                module.ci.APP / "build/artifacts/wamrc",
                module.ci.APP / "build/artifacts/tiny.wasm",
                module.ci.APP / "build/artifacts/tiny.cwasm",
                module.ci.APP / ".config",
                module.ci.APP / "build/artifacts/identity.json",
                module.ci.APP / "build/image-identity.json",
                root / "evidence/result.json", root / "evidence/package.json",
                root / "evidence/build.json", root / "evidence/build-start.json",
                root / "evidence/boot-inputs.json",
                root / "evidence/qcow2-finalization-intent.json",
                root / "evidence/qcow2-finalization.json",
                root / "evidence/qcow2-acceptance.json",
                root / "evidence/fixed-vhd-derivation-intent.json",
                root / "evidence/fixed-vhd-derivation-gate.json",
                root / "evidence/fixed-vhd-derivation.json",
                root / "evidence/final-inspection.json",
                runtime / "evidence/runtime-cleanup.txt",
            )
            paths = legacy_paths if version == 1 else current_paths

            def retain(source, destination):
                original = module.artifact(source)
                with source.open("rb") as src, destination.open("xb") as dst:
                    module.shutil.copyfileobj(src, dst, 65536)
                    dst.flush()
                    module.os.fsync(dst.fileno())
                destination.chmod(0o600)
                if original["size"] >= 65536 and hasattr(module.ci, "seed_file_digest"):
                    module.ci.seed_file_digest(destination, original["sha256"])
                saved = module.artifact(destination)
                module.ci.require(
                    module.artifact(source) == original
                    and all(saved[key] == original[key] for key in ("sha256", "size")),
                    "handoff copy changed")
                return saved

            phase("copy")
            artifacts = [
                retain(path, output / "artifacts" / name)
                for name, path in zip(names, paths)
            ]
            boots = []
            for mode in modes:
                slot = output / "boots" / mode
                slot.mkdir(mode=0o700)
                work = root / ("boot-" + mode)
                boots.append(dict(mode=mode, **{
                    key: retain(path, slot / key) for key, path in (
                        ("serial", work / "hyperv-efi-boot.log"),
                        ("request", work / "request.json"),
                        ("report", work / "report.json"),
                        ("compute", root / "evidence" / (mode + "-compute.json")))}))
            evidence = [retain(root / "evidence" / name, output / "evidence" / name)
                        for name in sorted(records)]
            phase("recheck")
            module.ci.require(module.accepted_result_records(root) == records,
                              "inputs changed during handoff")
            by_name = dict(zip(names, artifacts))
            runtime_record = build["runtime"]
            wamr_revision = (
                module.ci.HISTORICAL_WAMR_REVISION if version == 1 else
                runtime_record.get("wamr_revision", module.ci.REVISION)
                if isinstance(runtime_record, dict) else module.ci.REVISION
            )
            bundle = {
                "schema": "uk.wamr.local-image-handoff", "version": 1,
                "authority": "not_admitted",
                "source_revision": build["source"]["revision"],
                "source_tree": build["source"]["tree"],
                "identity": dict(wamr_revision=wamr_revision, **{
                    name + "_sha256": by_name[name]["sha256"]
                    for name in ("wasm", "cwasm", "runtime", "compiler", "config")}),
                "artifacts": artifacts, "boots": boots, "evidence": evidence,
            }
            if version == 2:
                run_id = module.os.environ.get("GITHUB_RUN_ID")
                run_attempt = module.os.environ.get("GITHUB_RUN_ATTEMPT")
                module.ci.require(
                    module.os.environ.get("GITHUB_REPOSITORY") == "cataggar/unikraft"
                    and isinstance(run_id, str)
                    and isinstance(run_attempt, str)
                    and run_id.isdecimal() and int(run_id) > 0
                    and run_attempt.isdecimal() and int(run_attempt) > 0,
                    "exact CI run identity required")
                bundle.update(
                    version=2,
                    profile=module.ci.CURRENT_PROFILE,
                    run={
                        "repository": "cataggar/unikraft",
                        "run_id": run_id,
                        "run_attempt": run_attempt,
                    },
                    lineage={
                        "raw_sha256": by_name["raw"]["sha256"],
                        "accepted_qcow2_sha256": by_name["qcow2"]["sha256"],
                        "derived_vhd_sha256": by_name["vhd"]["sha256"],
                        "qcow2_finalization_sha256":
                            by_name["qcow2_finalization"]["sha256"],
                        "qcow2_acceptance_sha256":
                            by_name["qcow2_acceptance"]["sha256"],
                        "fixed_vhd_derivation_sha256":
                            by_name["fixed_vhd_derivation"]["sha256"],
                        "fixed_vhd_derivation_gate_sha256":
                            by_name["fixed_vhd_derivation_gate"]["sha256"],
                        "final_inspection_sha256":
                            by_name["final_inspection"]["sha256"],
                    },
                )
            phase("publish")
            module.ci.save(output / "bundle.json", bundle)
            return bundle

        def executable_artifact(path):
            path = module.Path(path)
            raw = str(path)
            module.ci.require(
                path.is_absolute() and module.os.path.normpath(raw) == raw
                and "//" not in raw and all(
                    part not in ("", ".", "..") for part in path.parts[1:]),
                "canonical explicit executable required")
            directory_flags = module.os.O_RDONLY | module.os.O_DIRECTORY | module.os.O_NOFOLLOW
            file_flags = module.os.O_RDONLY | module.os.O_NOFOLLOW
            if hasattr(module.os, "O_CLOEXEC"):
                directory_flags |= module.os.O_CLOEXEC
                file_flags |= module.os.O_CLOEXEC
            descriptors = []
            directory_identities = []
            directory_identity = lambda value: (
                value.st_dev, value.st_ino, value.st_mode, value.st_uid)
            file_identity = lambda value: (
                value.st_dev, value.st_ino, value.st_mode, value.st_uid,
                value.st_nlink, value.st_size, value.st_mtime_ns,
                value.st_ctime_ns)
            try:
                current = module.os.open("/", directory_flags)
                descriptors.append(current)
                info = module.os.fstat(current)
                module.ci.require(
                    module.stat.S_ISDIR(info.st_mode)
                    and info.st_uid in (0, module.os.geteuid())
                    and not info.st_mode & 0o022,
                    "unsafe executable parent")
                directory_identities.append(directory_identity(info))
                for part in path.parts[1:-1]:
                    current = module.os.open(part, directory_flags, dir_fd=current)
                    descriptors.append(current)
                    info = module.os.fstat(current)
                    module.ci.require(
                        module.stat.S_ISDIR(info.st_mode)
                        and info.st_uid in (0, module.os.geteuid())
                        and not info.st_mode & 0o022,
                        "unsafe executable parent")
                    directory_identities.append(directory_identity(info))
                descriptor = module.os.open(path.name, file_flags, dir_fd=current)
                descriptors.append(descriptor)
                before = module.os.fstat(descriptor)
                module.ci.require(
                    module.stat.S_ISREG(before.st_mode)
                    and before.st_uid in (0, module.os.geteuid())
                    and before.st_mode & 0o111
                    and not before.st_mode & 0o6022
                    and before.st_nlink == 1
                    and 0 < before.st_size <= 64 * 1024 * 1024,
                    "unsafe explicit executable")
                cached_key, cached_entry = (
                    module.ci.cached_fd_entry(descriptor, before, "explicit executable changed")
                    if hasattr(module.ci, "cached_fd_entry") and module.hashlib.sha256 is getattr(module.ci, "_STDLIB_SHA256", None)
                    else (None, None)
                )
                if cached_entry is not None:
                    digest_hex = cached_entry[0]
                else:
                    digest = module.hashlib.sha256()
                    offset = 0
                    while offset < before.st_size:
                        chunk = module.os.pread(
                            descriptor, min(64 * 1024, before.st_size - offset),
                            offset)
                        module.ci.require(chunk, "explicit executable changed")
                        digest.update(chunk)
                        offset += len(chunk)
                    digest_hex = digest.hexdigest()
                    if cached_key is not None and hasattr(module.ci, "store_fd_digest"):
                        module.ci.store_fd_digest(descriptor, before, digest_hex, key=cached_key)
                after = module.os.fstat(descriptor)
                module.ci.require(file_identity(before) == file_identity(after),
                                  "explicit executable changed")
                for parent, expected in zip(
                        descriptors[:-1], directory_identities, strict=True):
                    module.ci.require(
                        directory_identity(module.os.fstat(parent)) == expected,
                        "unsafe executable parent")
                reopened = []
                try:
                    check = module.os.open("/", directory_flags)
                    reopened.append(check)
                    module.ci.require(
                        directory_identity(module.os.fstat(check))
                        == directory_identities[0],
                        "unsafe executable parent")
                    for index, part in enumerate(path.parts[1:-1], start=1):
                        check = module.os.open(part, directory_flags, dir_fd=check)
                        reopened.append(check)
                        module.ci.require(
                            directory_identity(module.os.fstat(check))
                            == directory_identities[index],
                            "unsafe executable parent")
                    named = module.os.open(path.name, file_flags, dir_fd=check)
                    reopened.append(named)
                    module.ci.require(
                        file_identity(module.os.fstat(named)) == file_identity(before),
                        "explicit executable changed")
                finally:
                    for reopened_descriptor in reversed(reopened):
                        module.os.close(reopened_descriptor)
                return {
                    "path": raw,
                    "size": before.st_size,
                    "sha256": digest_hex,
                }
            except OSError as error:
                raise module.ci.Refusal("unsafe explicit executable") from error
            finally:
                for descriptor in reversed(descriptors):
                    module.os.close(descriptor)

        module.export = export
        module.executable_artifact = executable_artifact
        return

    if relative == "public_bundle.py":
        module._STDLIB_SHA256 = _STDLIB_SHA256
        module.sys = sys

        def copy_checked(source, target, expected):
            """Full bytes/EOF and secret-pattern scan without unbounded captures."""
            cache = sys.__dict__.get("_uk_wamr_py_digest_cache")
            src_fd = None
            src_info = None
            src_key = None
            cached_entry = None
            if (cache is not None
                    and module.hashlib.sha256 is module._STDLIB_SHA256
                    and expected["size"] >= 65536):
                try:
                    fd = source.fileno()
                    st = module.os.fstat(fd)
                    if module.stat.S_ISREG(st.st_mode) and st.st_size == expected["size"] and source.tell() == 0:
                        src_fd = fd
                        src_info = st
                        src_key, cached_entry = cache["cached_fd_entry"](fd, st)
                except Exception:
                    src_fd = None
            if (cached_entry is not None and cached_entry[0] == expected["sha256"]
                    and (cached_entry[1] & 2)):
                total = 0
                while True:
                    chunk = source.read(262144)
                    if not chunk:
                        break
                    total += len(chunk)
                    module.require(total <= expected["size"])
                    if target is not None:
                        target.write(chunk)
                module.require(total == expected["size"])
                return
            need_hash = not (cached_entry is not None and cached_entry[0] == expected["sha256"])
            sha = module.hashlib.sha256() if need_hash else None
            total = 0
            tail = b""
            while True:
                chunk = source.read(65536)
                if not chunk:
                    break
                total += len(chunk)
                module.require(total <= expected["size"])
                scan = tail + chunk
                module.require(not any(pattern in scan for pattern in module.SENSITIVE))
                tail = scan[-128:]
                if sha is not None:
                    sha.update(chunk)
                if target is not None:
                    target.write(chunk)
            module.require(total == expected["size"] and (not need_hash or sha.hexdigest() == expected["sha256"]))
            if src_fd is not None and src_key is not None:
                try:
                    if cache["snapshot"](module.os.fstat(src_fd)) == cache["snapshot"](src_info):
                        cache["store_fd_digest"](src_fd, src_info, expected["sha256"], flags=2, key=src_key)
                except Exception:
                    pass

        def _is_verified_archive_fd(handle, expected_archive_sha256):
            if (expected_archive_sha256 is None
                    or module.hashlib.sha256 is not module._STDLIB_SHA256
                    or module.copy_checked is not module._ORIG_COPY_CHECKED):
                return False
            cache = sys.__dict__.get("_uk_wamr_py_digest_cache")
            if cache is None:
                return False
            try:
                st = module.os.fstat(handle)
                if not module.stat.S_ISREG(st.st_mode) or st.st_size < 65536:
                    return False
                key, entry = cache["cached_fd_entry"](handle, st)
                return bool(key is not None and entry is not None
                            and entry[0] == expected_archive_sha256
                            and key in cache["verified_archives"])
            except Exception:
                return False

        def _mark_verified_archive_fd(handle, expected_archive_sha256):
            if (expected_archive_sha256 is None
                    or module.hashlib.sha256 is not module._STDLIB_SHA256
                    or module.copy_checked is not module._ORIG_COPY_CHECKED):
                return
            cache = sys.__dict__.get("_uk_wamr_py_digest_cache")
            if cache is None:
                return
            try:
                st = module.os.fstat(handle)
                if not module.stat.S_ISREG(st.st_mode) or st.st_size < 65536:
                    return
                key, entry = cache["cached_fd_entry"](handle, st)
                if key is not None and entry is not None and entry[0] == expected_archive_sha256:
                    cache["verified_archives"].add(key)
            except Exception:
                pass

        def _mark_verified_archive_path(path, expected_archive_sha256):
            if (expected_archive_sha256 is None
                    or module.hashlib.sha256 is not module._STDLIB_SHA256
                    or module.copy_checked is not module._ORIG_COPY_CHECKED):
                return
            try:
                with module.Path(path).open("rb") as stream:
                    module._mark_verified_archive_fd(stream.fileno(), expected_archive_sha256)
            except Exception:
                pass

        def pack(handoff, stage, archive, source, validator, supervisor, *, producer="python"):
            handoff.FAILURE_STAGE = "public-pack-context"
            source = module.context(source)
            handoff.private(stage)
            handoff.private(archive.parent)
            bundle = handoff.ci.document(stage / "bundle.json")
            module.context(source, version=bundle["version"])
            module.require(bundle["source_revision"] == source["source_revision"]
                           and bundle["source_tree"] == source["source_tree"]
                           and bundle["identity"]["wamr_revision"] == source["wamr_revision"])
            if bundle["version"] == 2:
                module.require(bundle["run"] == {
                    "repository": source["repository"],
                    "run_id": source["run_id"],
                    "run_attempt": source["run_attempt"],
                })
            handoff.FAILURE_STAGE = "public-pack-members"
            original = module.members(handoff, bundle, stage)
            handoff.FAILURE_STAGE = "public-pack-records"
            native_accepted = None
            if producer == "native":
                native_accepted = module.accepted_records.local_runtime(stage.parents[2])
            module.publication_records(
                handoff, stage, source, "producer_direct",
                native_accepted=native_accepted)
            handoff.FAILURE_STAGE = "public-pack-tree"
            module.inspect_tree(stage, set(original) | {
                "bundle.json",
                ("private/handoff-inspect-legacy.log"
                 if module.pre_supervisor_source(source)
                 else "private/handoff-inspect.log"),
                ("evidence/command-handoff-inspect-legacy.json"
                 if module.pre_supervisor_source(source)
                 else "evidence/command-handoff-inspect.json"),
            })
            handoff.FAILURE_STAGE = "public-pack-native"
            if producer == "native":
                runtime = stage.parents[2]
                module.require(
                    stage == runtime / "compute/public-source/handoff"
                    and module.Path(validator) == runtime / module.NATIVE_PUBLIC_VALIDATOR_RELATIVE
                    and module.Path(supervisor) == runtime / module.NATIVE_CONTROLLER_RELATIVE)
                module.accepted_records.local_handoff_revalidation(
                    runtime, stage.with_name("handoff-revalidation"))
            else:
                module.native(
                    handoff, validator, supervisor, stage / "bundle.json", source,
                    historical=bundle["version"] == 1)
            portable = module.copy.deepcopy(bundle)
            for item in module.members(handoff, portable, stage).values():
                item["path"] = module.Path(item["path"]).relative_to(stage).as_posix()
            selected = module.members(handoff, portable)
            manifest = dict(
                schema="uk.wamr.public-source-bundle", version=bundle["version"],
                authority="not_admitted", source=source,
                members={name: {key: item[key] for key in ("size", "sha256")}
                         for name, item in selected.items()})
            if bundle["version"] == 2:
                manifest["profile"] = handoff.ci.CURRENT_PROFILE
            bundle_bytes, manifest_bytes = module.encoded(portable), module.encoded(manifest)
            module.require(len(bundle_bytes) <= module.MAX_JSON and len(manifest_bytes) <= module.MAX_JSON)
            handoff.FAILURE_STAGE = "public-pack-zip"
            with archive.open("xb") as output:
                module.os.fchmod(output.fileno(), 0o600)
                with module.zipfile.ZipFile(output, "w", compression=module.zipfile.ZIP_STORED, allowZip64=False) as zipped:
                    for name in sorted(selected):
                        path = stage / name
                        before = handoff.ci.snapshot(module.regular(path))
                        info = module.zipfile.ZipInfo(name)
                        info.create_system = 3
                        info.external_attr = (module.stat.S_IFREG | 0o600) << 16
                        with path.open("rb") as src, zipped.open(info, "w") as dst:
                            module.require(handoff.ci.snapshot(module.os.fstat(src.fileno())) == before)
                            module.copy_checked(src, dst, selected[name])
                        module.require(handoff.ci.snapshot(module.regular(path)) == before)
                    for name, raw in (("bundle.json", bundle_bytes), ("public-source.json", manifest_bytes)):
                        info = module.zipfile.ZipInfo(name)
                        info.create_system = 3
                        info.external_attr = (module.stat.S_IFREG | 0o600) << 16
                        zipped.writestr(info, raw)
                output.flush()
                module.os.fsync(output.fileno())
            module.require(archive.stat().st_size <= module.MAX_TOTAL)
            handoff.FAILURE_STAGE = "public-pack-archive"
            archive_sha256 = handoff.ci.digest(archive, module.MAX_TOTAL)
            if not any(pattern in bundle_bytes + manifest_bytes for pattern in module.SENSITIVE):
                module._mark_verified_archive_path(archive, archive_sha256)
            module.verify_archive(handoff, archive, source, archive_sha256)
            return archive_sha256

        def verify_archive_descriptor(handoff, handle, expected, expected_archive_sha256):
            module.context(expected)
            if expected_archive_sha256 is None:
                module.require((expected["source_revision"], expected["source_tree"])
                               in module.LEGACY_V1_SOURCES)
            else:
                module.digest_string(expected_archive_sha256)
            with module.descriptor_zip(handle) as zipped:
                entries = zipped.infolist()
                module.require(2 < len(entries) <= module.MAX_MEMBERS and not zipped.comment)
                names = {info.filename for info in entries}
                module.require(len(names) == len(entries) and {"bundle.json", "public-source.json"} <= names)
                total = 0
                for info in entries:
                    module.require(
                        info.create_system == 3
                        and info.external_attr >> 16 == module.stat.S_IFREG | 0o600
                        and info.compress_type == module.zipfile.ZIP_STORED
                        and info.compress_size == info.file_size and not info.flag_bits & 1
                        and not info.comment and not info.extra)
                    total += info.file_size
                    module.require(0 < info.file_size <= 256 * 1024 * 1024 + 512 and total <= module.MAX_TOTAL)
                for name in ("bundle.json", "public-source.json"):
                    module.require(zipped.getinfo(name).file_size <= module.MAX_JSON)
                bundle_raw = zipped.read("bundle.json")
                manifest_raw = zipped.read("public-source.json")
                module.require(not any(pattern in bundle_raw + manifest_raw for pattern in module.SENSITIVE))
                bundle = module.decode(bundle_raw)
                manifest = module.decode(manifest_raw)
                selected = module.members(handoff, bundle)
                expected_order = (
                    sorted(selected) + ["bundle.json", "public-source.json"])
                module.require([info.filename for info in entries] == expected_order
                               and names == set(selected) | {"bundle.json", "public-source.json"})
                manifest_fields = {
                    "schema", "version", "authority", "source", "members"}
                if bundle["version"] == 2:
                    manifest_fields.add("profile")
                module.require(
                    set(manifest) == manifest_fields
                    and manifest["schema"] == "uk.wamr.public-source-bundle"
                    and type(manifest["version"]) is int
                    and manifest["version"] == bundle["version"]
                    and manifest["authority"] == "not_admitted"
                    and module.context(manifest["source"], version=manifest["version"]) == expected
                    and bundle["source_revision"] == expected["source_revision"]
                    and bundle["source_tree"] == expected["source_tree"]
                    and bundle["identity"]["wamr_revision"] == expected["wamr_revision"]
                    and manifest["members"] == {
                        name: {key: item[key] for key in ("size", "sha256")}
                        for name, item in selected.items()})
                if bundle["version"] == 2:
                    module.require(manifest["profile"] == handoff.ci.CURRENT_PROFILE
                                   and bundle["run"] == {
                                       "repository": expected["repository"],
                                       "run_id": expected["run_id"],
                                       "run_attempt": expected["run_attempt"],
                                   })
                archive_verified = module._is_verified_archive_fd(handle, expected_archive_sha256)
                for name, item in selected.items():
                    module.require(zipped.getinfo(name).file_size == item["size"])
                    if not archive_verified:
                        with zipped.open(name) as stream:
                            module.copy_checked(stream, None, item)
                if not archive_verified and expected_archive_sha256 is not None:
                    module._mark_verified_archive_fd(handle, expected_archive_sha256)
                if expected_archive_sha256 is None:
                    start = module.decode(zipped.read("evidence/build-start.json"))
                    module.require("dependencies" not in start)
            return bundle

        def import_bundle(
                handoff, archive, output, expected, expected_archive_sha256,
                validator, supervisor, artifact_id=None, container_digest=None,
                native_import_revalidation=False):
            module.require(type(native_import_revalidation) is bool)
            handoff.private(output.parent)
            with module.retained_archive(
                    handoff, archive, expected_archive_sha256) as (
                        handle, unused_archive_sha256):
                del unused_archive_sha256
                bundle = module.verify_archive_descriptor(
                    handoff, handle, expected, expected_archive_sha256)
                trusted_extract = module._is_verified_archive_fd(handle, expected_archive_sha256)
                output.mkdir(mode=0o700)
                for name in ("artifacts", "boots", "evidence"):
                    (output / name).mkdir(mode=0o700)
                with module.descriptor_zip(handle) as zipped:
                    for name, item in module.members(handoff, bundle).items():
                        path = output / name
                        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                        with zipped.open(name) as src, path.open("xb") as dst:
                            module.os.fchmod(dst.fileno(), 0o600)
                            if trusted_extract and item["size"] >= 65536:
                                total = 0
                                while True:
                                    chunk = src.read(262144)
                                    if not chunk:
                                        break
                                    total += len(chunk)
                                    module.require(total <= item["size"])
                                    dst.write(chunk)
                                module.require(total == item["size"])
                            else:
                                module.copy_checked(src, dst, item)
                            dst.flush()
                            module.os.fsync(dst.fileno())
                        path.chmod(0o600)
                        if item["size"] >= 65536 and hasattr(handoff.ci, "seed_file_digest"):
                            handoff.ci.seed_file_digest(path, item["sha256"], flags=2)
                    for name in ("bundle.json", "public-source.json"):
                        handoff.ci.save(
                            output / (
                                "portable-bundle.json"
                                if name == "bundle.json" else name),
                            module.decode(zipped.read(name)),
                        )
            for item in module.members(handoff, bundle).values():
                item["path"] = str(output / item["path"])
            identity_parent = output.with_name(output.name + "-native-identity")
            identity_parent.mkdir(mode=0o700)
            handoff.private(identity_parent)
            handoff.FAILURE_STAGE = "public-import-native-records"
            accepted = module.accepted_records.imported_stage(output)
            module.require(
                accepted["source"] == {
                    "revision": expected["source_revision"],
                    "tree": expected["source_tree"],
                }
                and accepted["compatibility"]
                == ("tiny-v2" if bundle["version"] == 2 else "tiny-v1")
                and accepted["result"]["sha256"]
                == bundle["artifacts"][
                    (handoff.V2_NAMES if bundle["version"] == 2 else handoff.NAMES
                     ).index("local_result")]["sha256"]
                and {
                    record["name"]: record["sha256"] for record in accepted["records"]
                } == {
                    module.Path(item["path"]).name: item["sha256"]
                    for item in bundle["evidence"]
                })
            native_revalidation = None
            native_identity = None
            producer = "python"
            producer_runtime = None
            if bundle["version"] == 2:
                module.require(expected_archive_sha256 is not None
                               and type(artifact_id) is str
                               and module.re.fullmatch(r"[1-9][0-9]{0,19}", artifact_id)
                               and type(container_digest) is str)
                module.digest_string(container_digest)
                start = handoff.ci.document(output / "evidence/build-start.json")
                producer, producer_runtime = module.recorded_producer_info(
                    start["consumer_inputs"])
                if producer == "native" and native_import_revalidation:
                    module.require(str(supervisor) == str(
                        producer_runtime / module.NATIVE_CONTROLLER_RELATIVE))
                    module.require(str(validator) == str(
                        producer_runtime / module.NATIVE_PUBLIC_VALIDATOR_RELATIVE))
                handoff.FAILURE_STAGE = "public-import-native-supervisor-identity"
                native_identity = identity_parent / "accepted"
                module.accepted_records.supervisor_import_identity(
                    output, supervisor, handoff.ci.tool("git"), native_identity)
                if native_import_revalidation:
                    handoff.FAILURE_STAGE = "public-import-native-revalidation"
                    native_revalidation = module.accepted_records.import_native_revalidation(
                        output, identity_parent / "revalidation")
                elif producer == "native":
                    handoff.FAILURE_STAGE = "public-import-native-revalidation"
                    native_revalidation = module.accepted_records.import_native_revalidation(
                        output, identity_parent / "revalidation",
                        git=handoff.ci.tool("git"), supervisor=supervisor,
                        validator=validator)
                handoff.ci.save(output / "transport.json", {
                    "schema": "uk.wamr.public-source-transport",
                    "version": 2,
                    "repository": expected["repository"],
                    "run_id": expected["run_id"],
                    "run_attempt": expected["run_attempt"],
                    "source_revision": expected["source_revision"],
                    "source_tree": expected["source_tree"],
                    "inner_zip_sha256": expected_archive_sha256,
                    "artifact_id": artifact_id,
                    "container_digest": container_digest,
                })
            else:
                module.require(artifact_id is None and container_digest is None
                               and not native_import_revalidation)
                handoff.FAILURE_STAGE = "public-import-native-revalidation"
                native_revalidation = module.accepted_records.import_native_revalidation(
                    output, identity_parent / "revalidation",
                    git=handoff.ci.tool("git"), supervisor=supervisor,
                    validator=validator)
            handoff.ci.save(output / "candidate-bundle.json", bundle)
            handoff.FAILURE_STAGE = "public-import-records"
            module.publication_records(
                handoff, output, expected, "trusted_inner_zip",
                "candidate-bundle.json",
                native_accepted=accepted if bundle["version"] == 2 else None)
            handoff.FAILURE_STAGE = "public-import-revalidation"
            if bundle["version"] == 1 or (
                    native_import_revalidation or producer == "native"):
                module.require(native_revalidation is not None)
                handoff.private(native_revalidation)
            else:
                module.require(native_revalidation is None)
                module.native(
                    handoff, validator, supervisor,
                    output / "candidate-bundle.json", expected,
                    native_identity=native_identity,
                    historical=bundle["version"] == 1)
            handoff.ci.save(output / "bundle.json", bundle)
            return bundle

        module.copy_checked = copy_checked
        module._ORIG_COPY_CHECKED = copy_checked
        module._is_verified_archive_fd = _is_verified_archive_fd
        module._mark_verified_archive_fd = _mark_verified_archive_fd
        module._mark_verified_archive_path = _mark_verified_archive_path
        module.pack = pack
        module.verify_archive_descriptor = verify_archive_descriptor
        module.import_bundle = import_bundle


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
    module = load_oracle_module(
        relative, repository, git=git, module_name=relative.removesuffix(".py")
    )
    sys.argv[0] = module.__file__
    sys.modules[module.__name__] = module
    sys.modules["__main__"] = module
    if relative == "handoff.py" and "public_bundle" not in sys.modules:
        sys.modules["public_bundle"] = load_oracle_module(
            "public_bundle.py", repository, git=git, module_name="public_bundle"
        )
    try:
        module.main()
    except (OSError, ValueError, KeyError, TypeError, module.zipfile.BadZipFile):
        print(
            "Compute handoff refused at "
            + module.FAILURE_STAGE
            + "; original local records are unchanged.",
            file=sys.stderr,
        )
        sys.exit(1)


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
    if len(sys.argv) >= 2 and sys.argv[1] == "--handoff":
        del sys.argv[1]
        run_oracle_cli("handoff")
        sys.exit(0)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true", required=True)
    parser.add_argument("--git", default="git")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[4]
    target = root / PACKAGE / "controller/fixtures/historical_controller.json"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(frozen_bytes(root, args.git))
