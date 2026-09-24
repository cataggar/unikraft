#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""Private synthetic CLI fixtures; no boot, cloud, or benchmark evidence."""
import base64
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
REPO = HERE.parents[3]
MODES = ("snapshot", "aot", "fast", "full")
COREMARK = b"""\
2K performance run parameters for coremark.
CoreMark Size    : 666
Total ticks      : 1
Total time (secs): 0.001000
Iterations/Sec   : 100000.000000
ERROR! Must execute for at least 10 secs for a valid result!
Iterations       : 100
Compiler version : synthetic fixture, not execution evidence
Compiler flags   : synthetic
Memory location  : STACK
seedcrc          : 0xe9f5
[0]crclist       : 0xe714
[0]crcmatrix     : 0x1fd7
[0]crcstate      : 0x8e3a
[0]crcfinal      : 0x988c
Errors detected
"""


def tiny_fixture(wasi=False):
    identity = {
        "wamr_revision": "f" * 40, "minimal_wasi": wasi,
        "files": {"tiny.wasm": "0" * 64, "tiny.cwasm": "1" * 64,
                  "libwamr-aot.a": "2" * 64},
    }
    compute = {
        "version": 1, "workload": "tiny", "wamr_revision": "f" * 40,
        "wasm_sha256": "0" * 64, "cwasm_sha256": "1" * 64,
        "runtime_sha256": "2" * 64, "platform_status": 0, "checks": 2,
        "answer": 42, "terminal": 1, "detail": 2, "reserved_bytes": 0,
        "frame_bytes": 0, "accessible_bytes": 0, "allocation_bytes": 0,
        "error_name": "", "system_page_table_bytes": 4096,
    }
    records = []
    if wasi:
        for name in ("coremark", "coremark-nofp"):
            identity["files"][name + ".wasm"] = "3" * 64
            identity["files"][name + ".cwasm"] = "4" * 64
            records.append(("WAMR_NATIVE_WASI", {
                "version": 1, "correctness_only": True, "workload": name,
                "wasm_sha256": "3" * 64, "cwasm_sha256": "4" * 64,
                "terminal": 2, "detail": 0, "crc_ok": True,
                "output_error": 0, "pending_stdout": 0, "pending_stderr": 0,
                "unsupported_clock": 0, "realtime_supported": True,
                "stdout_base64": base64.b64encode(COREMARK).decode(),
                "stderr_base64": "",
            }))
    records.append(("WAMR_NATIVE_COMPUTE", compute))
    return identity, compute, b"".join(
        name.encode() + b"=" + json.dumps(record).encode() + b"\n"
        for name, record in records)


def invoke(binary, *args):
    return subprocess.run([str(binary), *map(str, args)], capture_output=True,
                          timeout=15, check=False, env={"PATH": "/nonexistent"})


def put(path, raw):
    path.write_bytes(raw)
    path.chmod(0o600)


def accepted(binary, command, raw, identity, mode, compute=None):
    before_identity = identity.read_bytes()
    before_log = Path(command[command.index("--log") + 1]).read_bytes()
    result = invoke(binary, *command, "--output", "json-v1")
    assert result.returncode == 0 and not result.stderr, (mode, result.stderr)
    assert result.stdout.endswith(b"\n") and result.stdout.count(b"\n") == 1
    observed = json.loads(result.stdout)
    expected = {
        "schema": "uk.wamr.log-validation", "schema_version": 1,
        "mode": mode, "raw_serial_bytes": len(raw),
        "raw_serial_sha256": hashlib.sha256(raw).hexdigest(),
    }
    if compute is not None:
        expected["compute"] = compute
    assert observed == expected, (mode, observed, expected)
    assert identity.read_bytes() == before_identity
    assert before_log == raw == Path(command[command.index("--log") + 1]).read_bytes()
    return observed


def refused(binary, command, category=None):
    result = invoke(binary, *command, "--output", "json-v1")
    assert result.returncode == 1 and not result.stdout, (
        result.returncode, result.stdout, result.stderr)
    assert result.stderr.startswith(b"WAMR_LOG_VALIDATION_REFUSED category=")
    assert result.stderr.count(b"\n") == 1 and result.stderr.endswith(b"\n")
    assert len(result.stderr) < 160 and b"/" not in result.stderr
    if category:
        assert b"category=" + category.encode() in result.stderr, result.stderr


def usage(binary, *args):
    result = invoke(binary, *args)
    assert result.returncode == 2 and not result.stdout
    assert result.stderr.startswith(b"usage: uk-wamr-log-validate ")
    assert b"/" not in result.stderr and len(result.stderr) < 400


def main(binary):
    identity_data, expected, records = tiny_fixture()
    boot = ("Hyper-V Hv#1 hypercall page enabled\nHyper-V SynIC:\n"
            "Powered by\nCalling main(0, 0)\n")
    end = "[    1.000001] Info: [libukboot] main returned 0\n"
    raw = boot.encode() + records + b"WAMR_NATIVE_AOT_OK answer=42 teardown=0\n" + end.encode()
    scratch = REPO / ".d" / "validator-cli-fixtures"
    scratch.mkdir(parents=True, exist_ok=True, mode=0o700)
    with tempfile.TemporaryDirectory(dir=scratch, prefix="private-") as location:
        root = Path(location)
        log, identity = root / "serial.bin", root / "identity.json"
        put(log, raw)
        put(identity, json.dumps(identity_data).encode())
        tiny = ("tiny", "--log", str(log), "--identity", str(identity))
        accepted(binary, tiny, raw, identity, "tiny", expected)
        human = invoke(binary, *tiny)
        assert human.returncode == 0 and human.stderr == b""
        assert human.stdout == b"Compute records match; no hardware or benchmark qualification.\n"
        framed = raw.replace(b"\n", b"\x1b[0m\r\n\x00")
        put(log, framed)
        accepted(binary, tiny, framed, identity, "tiny", expected)
        put(log, raw)
        legacy = raw.replace(b"Powered by\n", b"Powered by\nUsing legacy xAPIC MMIO\n")
        put(log, legacy)
        accepted(binary, tiny + ("--legacy-apic", "required"), legacy, identity, "tiny", expected)
        refused(binary, tiny + ("--legacy-apic", "forbidden"), "transcript")
        put(log, raw)
        refused(binary, tiny + ("--legacy-apic", "required"), "transcript")
        for before, after in (
            (b'"answer": 42', b'"answer": 41'),
            (b'"system_page_table_bytes": 4096', b'"system_page_table_bytes": 3'),
            (b"WAMR_NATIVE_AOT_OK answer=42 teardown=0", b"WAMR_NATIVE_AOT_FAIL"),
            (b'"version": 1', b'"version": true'),
            (b'"version": 1', b'"version": 1, "version": 1'),
            (b'WAMR_NATIVE_COMPUTE=', b'echo WAMR_NATIVE_COMPUTE='),
            (b'WAMR_NATIVE_AOT_OK answer=42 teardown=0\n', b''),
        ):
            assert before in raw
            bad = raw.replace(before, after, 1)
            put(log, bad)
            refused(binary, tiny)
        for bad in (
            raw + b"WAMR_NATIVE_AOT_OK answer=42 teardown=0\n",
            raw + records,
            raw.replace(b"Calling main(0, 0)\n", b""),
            raw + b"HYPERV_ACCEPTANCE NETWORK_APP_FINAL PASS\n",
            raw + b"WAMR_NATIVE_WASI={}\n",
            raw + b"\x1b[0\x00m\n",
        ):
            put(log, bad)
            refused(binary, tiny)
        put(log, raw)
        bad_identity = identity.read_bytes().replace(b'"minimal_wasi": false',
                                                     b'"minimal_wasi": true', 1)
        put(identity, bad_identity)
        refused(binary, tiny)
        put(identity, json.dumps(identity_data).encode())

        full_identity, _, full_records = tiny_fixture(wasi=True)
        coremark_raw = (boot.encode() + full_records
                        + b"WAMR_NATIVE_AOT_OK answer=42 teardown=0\n" + end.encode())
        put(log, coremark_raw)
        put(identity, json.dumps(full_identity).encode())
        accepted(binary, tiny, coremark_raw, identity, "tiny", expected)
        for before, after in (
            (b'"crc_ok": true', b'"crc_ok": false'),
            (b'"realtime_supported": true', b'"realtime_supported": false'),
            (b'"stdout_base64": "', b'"stdout_base64": "@@'),
            (b'"output_error": 0', b'"output_error": 1'),
            (b'"terminal": 2', b'"terminal": 1'),
        ):
            changed = coremark_raw.replace(before, after, 1)
            assert changed != coremark_raw
            put(log, changed)
            refused(binary, tiny)

        for mode in MODES:
            original = (HERE / "optional-fixtures" / f"{mode}.log").read_bytes()
            source = (HERE / "optional-fixtures" / f"{mode}.identity.json").read_bytes()
            put(log, original)
            put(identity, source)
            command = ("workload", "--mode", mode, "--log", str(log), "--identity", str(identity))
            accepted(binary, command, original, identity, mode)
            assert b"no boot or measurement qualification" in invoke(binary, *command).stdout
            framed = original.replace(b"\n", b"\x1b[0m\r\n\x00")
            put(log, framed)
            accepted(binary, command, framed, identity, mode)
            put(log, original)
            if mode == "aot":
                assert json.loads(source)["jit_mode"] is None
                missing_mode = json.loads(source)
                del missing_mode["jit_mode"]
                put(identity, json.dumps(missing_mode).encode())
                refused(binary, command, "record")
                put(identity, source)
            corrupt = original.replace(b'"correctness_only": true',
                                       b'"correctness_only": false', 1)
            assert corrupt != original
            put(log, corrupt)
            refused(binary, command)
            for bad in (original + original, original + b"WAMR_BENCH_RESULT={}\n",
                        original + b"\xff\n", original + b"Unikraft Crash\n"):
                put(log, bad)
                refused(binary, command)
            put(log, original[:-1])
            refused(binary, command)

        put(log, raw)
        put(identity, json.dumps(identity_data).encode())
        for arguments in (
            (), ("other",), ("tiny", "--log", str(log)),
            tiny + ("--log", str(log)),
            tiny + ("--mode", "snapshot"),
            tiny + ("--legacy-apic", "ignored"),
            tiny + ("--output", "invalid"),
            tiny + ("--output", "json-v1", "--output", "json-v1"),
            ("workload", "--mode", "wrong", "--log", str(log), "--identity", str(identity)),
            ("workload", "--log", str(log), "--identity", str(identity)),
        ):
            usage(binary, *arguments)
        outside = root / "outside"
        put(outside, raw)
        log.unlink()
        log.symlink_to(outside)
        refused(binary, tiny, "input-snapshot")
        log.unlink()
        put(log, raw)
        log.chmod(0o622)
        refused(binary, tiny, "input-snapshot")
        log.chmod(0o600)
        identity.unlink()
        identity.symlink_to(outside)
        refused(binary, tiny, "input-snapshot")
        identity.unlink()
        put(identity, b'{"minimal_wasi":false,"minimal_wasi":false}')
        refused(binary, tiny)
        put(identity, json.dumps(identity_data).encode())
        put(log, b"x" * (4 * 1024 * 1024))
        refused(binary, tiny, "input-bound")
        assert log.read_bytes() == b"x" * (4 * 1024 * 1024)
    print("installed native validator CLI: tiny, four workload modes, refusal and raw hash fixtures")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: cli_test.py BINARY")
    main(Path(sys.argv[1]).resolve(strict=True))
