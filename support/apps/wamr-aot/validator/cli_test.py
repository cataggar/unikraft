#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""Private synthetic CLI fixtures; no boot, cloud, or benchmark evidence."""
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
APP = HERE.parent
REPO = HERE.parents[3]
MODES = ("snapshot", "aot", "fast", "full")


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def invoke(binary, *args):
    return subprocess.run([str(binary), *map(str, args)], capture_output=True,
                          timeout=15, check=False, env={"PATH": "/nonexistent"})


def put(path, raw):
    path.write_bytes(raw)
    path.chmod(0o600)


def accepted(binary, command, raw, identity, mode, compute=None):
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
    assert identity.read_bytes()
    assert raw == Path(command[command.index("--log") + 1]).read_bytes()
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


def main(binary, differential=False):
    tests = load("cli_compute_cases", APP / "tests/test_compute.py")
    case = tests.ComputeContract()
    case.setUp()
    boot = ("Hyper-V Hv#1 hypercall page enabled\nHyper-V SynIC:\n"
            "Powered by\nCalling main(0, 0)\n")
    end = "\n[    1.000001] Info: [libukboot] main returned 0\n"
    raw = (boot + case.log() + end).encode()
    reference = load("cli_tiny_reference", APP / "check-log.py") if differential else None
    optional_reference = (
        load("cli_optional_reference", APP / "check-workload-log.py")
        if differential else None
    )
    oracle = load("cli_optional_oracle", HERE / "optional_reference_test.py") if differential else None
    scratch = REPO / ".d" / "validator-cli-fixtures"
    scratch.mkdir(parents=True, exist_ok=True, mode=0o700)
    with tempfile.TemporaryDirectory(dir=scratch, prefix="private-") as location:
        root = Path(location)
        log, identity = root / "serial.bin", root / "identity.json"
        put(log, raw)
        put(identity, json.dumps(case.identity).encode())
        tiny = ("tiny", "--log", str(log), "--identity", str(identity))
        expected = case.result
        accepted(binary, tiny, raw, identity, "tiny", expected)
        human = invoke(binary, *tiny)
        assert human.returncode == 0 and human.stderr == b""
        assert human.stdout == b"Compute records match; no hardware or benchmark qualification.\n"
        if differential:
            text = raw.decode()
            reference.validate(text, case.identity)
            assert expected == json.loads(next(
                line.split("=", 1)[1] for line in text.splitlines()
                if line.startswith("WAMR_NATIVE_COMPUTE=")))
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
        ):
            assert before in raw
            bad = raw.replace(before, after, 1)
            put(log, bad)
            refused(binary, tiny)
            if differential:
                try:
                    reference.validate(bad.decode(), case.identity)
                except ValueError:
                    pass
                else:
                    raise AssertionError("Python reference accepted a corrupt tiny fixture")
        put(log, raw)
        bad_identity = identity.read_bytes().replace(b'"minimal_wasi": false',
                                                     b'"minimal_wasi": true', 1)
        put(identity, bad_identity)
        refused(binary, tiny)
        put(identity, json.dumps(case.identity).encode())

        full = tests.ComputeContract()
        full.setUp()
        wasi = full.wasi_fixture()
        coremark_raw = (boot + full.log(wasi) + end).encode()
        put(log, coremark_raw)
        put(identity, json.dumps(full.identity).encode())
        accepted(binary, tiny, coremark_raw, identity, "tiny", full.result)
        if differential:
            reference.validate(coremark_raw.decode(), full.identity)
        for before, after in (
            (b'"crc_ok": true', b'"crc_ok": false'),
            (b'"realtime_supported": true', b'"realtime_supported": false'),
            (b'"stdout_base64": "', b'"stdout_base64": "@@'),
        ):
            changed = coremark_raw.replace(before, after, 1)
            assert changed != coremark_raw
            put(log, changed)
            refused(binary, tiny)
            if differential:
                try:
                    reference.validate(changed.decode(), full.identity)
                except ValueError:
                    pass
                else:
                    raise AssertionError("Python reference accepted a corrupt CoreMark fixture")

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
            if differential:
                sample = oracle.pinned_sdk()
                sampler = sample.validate_sample if sample else (lambda record, *_: record)
                observed = optional_reference.validate(
                    original, json.loads(source), mode, sampler)
                assert observed == {
                    "bytes": len(original),
                    "sha256": hashlib.sha256(original).hexdigest(),
                }
            if mode == "aot":
                assert json.loads(source)["jit_mode"] is None
                missing_mode = json.loads(source)
                del missing_mode["jit_mode"]
                put(identity, json.dumps(missing_mode).encode())
                refused(binary, command, "record")
                if differential:
                    try:
                        optional_reference.validate(original, missing_mode, mode, sampler)
                    except KeyError:
                        pass
                    else:
                        raise AssertionError("Python reference accepted missing AOT jit_mode")
                put(identity, source)
            corrupt = original.replace(b'"correctness_only": true',
                                       b'"correctness_only": false', 1)
            assert corrupt != original
            put(log, corrupt)
            refused(binary, command)
            if differential:
                try:
                    optional_reference.validate(
                        corrupt, json.loads(source), mode, sampler)
                except (ValueError, KeyError, TypeError):
                    pass
                else:
                    raise AssertionError("Python reference accepted a corrupt workload fixture")
            put(log, original[:-1])
            refused(binary, command)

        put(log, raw)
        put(identity, json.dumps(case.identity).encode())
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
        put(identity, json.dumps(case.identity).encode())
        put(log, b"x" * (4 * 1024 * 1024))
        refused(binary, tiny, "input-bound")
        assert log.read_bytes() == b"x" * (4 * 1024 * 1024)
    print("installed native validator CLI: tiny, four workload modes, refusal and raw hash fixtures" +
          ("; Python differential" if differential else ""))


if __name__ == "__main__":
    if len(sys.argv) not in (2, 3) or (len(sys.argv) == 3 and sys.argv[2] != "--differential"):
        raise SystemExit("usage: cli_test.py BINARY [--differential]")
    main(Path(sys.argv[1]).resolve(strict=True), len(sys.argv) == 3)
