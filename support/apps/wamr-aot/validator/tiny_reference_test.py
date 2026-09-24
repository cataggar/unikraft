#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""Test-only differential against the retained Python tiny and CoreMark parsers."""
import base64
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import random
import subprocess
import sys

APP = Path(__file__).resolve().parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


check = load("check_log_reference", APP / "check-log.py")
cases = load("compute_cases_reference", APP / "tests/test_compute.py")
run = load("run_reference", APP.parents[1] / "build/wamr-native-ci/run.py")
BOOT = ("Hyper-V Hv#1 hypercall page enabled\nHyper-V SynIC:\n"
        "Powered by\nCalling main(0, 0)\n")
END = "\n[    1.000001] Info: [libukboot] main returned 0\n"


def serial(contract, wasi=(), legacy=False):
    return (BOOT + ("Using legacy xAPIC MMIO\n" if legacy else "") +
            contract.log(wasi) + END).encode()


def compare(binary, mode, raw, identity, expect=None):
    command = [binary, mode, json.dumps(identity).encode().hex(), raw.hex()]
    actual = subprocess.run(command, capture_output=True, check=False, timeout=15)
    try:
        if mode == "direct" and b"WAMR_NATIVE_WASI=" in raw:
            raise ValueError("direct excludes WASI")
        if any(marker in raw for marker in (b"Unikraft Crash", b"Assertion failure", b"Exception Type")):
            raise ValueError("upstream local-boot crash refusal")
        if mode == "app-required" and not raw.count(run.LEGACY.encode()) == 1:
            raise ValueError("legacy marker required")
        if mode == "app-forbidden" and run.LEGACY.encode() in raw:
            raise ValueError("legacy marker forbidden")
        if mode == "direct" or not identity["minimal_wasi"]:
            expected = run.compute(raw, identity, False if mode == "direct" else mode == "app-required")
        else:
            text = run.normalize_serial(raw)
            check.validate(text, identity)
            expected = json.loads(next(line.split("=", 1)[1] for line in text.splitlines()
                                       if line.startswith("WAMR_NATIVE_COMPUTE=")))
        normalized = run.normalize_serial(raw)
        record_sequence = [line for line in normalized.split("\n")
                           if line.startswith(("WAMR_NATIVE_COMPUTE=", "WAMR_NATIVE_WASI="))
                           or line == run.MARKER]
    except (ValueError, KeyError, IndexError, UnicodeError, TypeError, json.JSONDecodeError):
        expected = None
    if expect is not None:
        assert (expected is not None) == expect, ("bad reference case", mode, expect)
    assert (actual.returncode == 0) == (expected is not None), (
        mode, actual.returncode, raw[:120], actual.stderr)
    assert not actual.stderr, (mode, actual.stderr)
    if expected is None:
        assert not actual.stdout
        return
    response = json.loads(actual.stdout)
    assert response == {
        "result": expected, "raw_serial_bytes": len(raw),
        "raw_serial_sha256": hashlib.sha256(raw).hexdigest(),
        "record_sequence": record_sequence,
    }, (mode, response, expected)


def output(binary, raw, expected):
    actual = subprocess.run([binary, "coremark-output", raw.hex()],
                            capture_output=True, check=False, timeout=15)
    try:
        check.validate_coremark(raw)
        python_ok = True
    except ValueError:
        python_ok = False
    assert python_ok == expected, (raw[:100], python_ok, expected)
    assert (actual.returncode == 0) == expected, (raw[:100], actual.stderr)
    assert not actual.stdout and not actual.stderr


def main(binary):
    contract = cases.ComputeContract()
    contract.setUp()
    no_wasi = copy.deepcopy(contract.identity)
    baseline = serial(contract)
    count = 0
    for mode in ("app", "direct", "app-forbidden"):
        compare(binary, mode, baseline, no_wasi, True)
        count += 1
    for transformed in (
        baseline.replace(b"\n", b"\r\n"),
        baseline.replace(b"Calling main(", b"\0\x1b[1;32mCalling main(\x1b[0m"),
        baseline + b"\0",
    ):
        compare(binary, "app", transformed, no_wasi, True)
        count += 1
    compare(binary, "app-required", baseline, no_wasi, False)
    count += 1
    legacy = serial(contract, legacy=True)
    compare(binary, "app-required", legacy, no_wasi, True)
    count += 1
    compare(binary, "app-forbidden", legacy, no_wasi, False)
    count += 1
    for before, after in (
        (b'"answer": 42', b'"answer": 41'), (b'"checks": 2', b'"checks": true'),
        (b'"version": 1', b'"version": 1.0'), (b'"detail": 2', b'"detail": 0'),
        (b'"reserved_bytes": 0', b'"reserved_bytes": 4096'),
        (b'"frame_bytes": 0', b'"frame_bytes": 1'),
        (b'"allocation_bytes": 0', b'"allocation_bytes": 1'),
        (b'"system_page_table_bytes": 4096', b'"system_page_table_bytes": 3'),
        (b'"runtime_sha256": "2', b'"runtime_sha256": "9'),
        (b'WAMR_NATIVE_COMPUTE=', b'noise WAMR_NATIVE_COMPUTE='),
        (b'WAMR_NATIVE_AOT_OK', b'noise WAMR_NATIVE_AOT_OK'),
    ):
        assert before in baseline
        try:
            compare(binary, "app", baseline.replace(before, after), no_wasi, False)
        except AssertionError:
            print("unexpected differential mutation", before, after, file=sys.stderr)
            raise
        count += 1
    for extra in (b"WAMR_NATIVE_WASI={}\n", b"HYPERV_ACCEPTANCE\n",
                  b"Unikraft Crash\n", b"WAMR_NATIVE_AOT_FAIL\n"):
        compare(binary, "direct", baseline + extra, no_wasi, False)
        count += 1
    for raw in (baseline + baseline, baseline.replace(run.MARKER.encode(), b"NOT_OK")):
        compare(binary, "app", raw, no_wasi, False)
        count += 1

    records = contract.wasi_fixture()
    with_wasi = copy.deepcopy(contract.identity)
    complete = serial(contract, records)
    compare(binary, "app", complete, with_wasi, True)
    count += 1
    lines = complete.splitlines(keepends=True)
    wasi_lines = [line for line in lines if line.startswith(b"WAMR_NATIVE_WASI=")]
    later = b"".join(line for line in lines if line not in wasi_lines)
    later = later.replace(b"WAMR_NATIVE_AOT_OK", b"".join(wasi_lines) + b"WAMR_NATIVE_AOT_OK")
    compare(binary, "app", later, with_wasi, True)
    count += 1
    compare(binary, "direct", complete, with_wasi, False)
    count += 1
    for field, bad in (
        ("stdout_base64", ""), ("stdout_base64", "@@"),
        ("stderr_base64", base64.b64encode(b"ERROR!\n").decode()),
        ("pending_stdout", 29), ("pending_stderr", 1),
        ("output_error", 1), ("unsupported_clock", 1),
        ("realtime_supported", False), ("crc_ok", False),
        ("detail", 0xFFFFFFFF), ("terminal", 1),
        ("wasm_sha256", "9" * 64),
    ):
        mutated = copy.deepcopy(records)
        mutated[0][field] = bad
        compare(binary, "app", serial(contract, mutated), with_wasi, False)
        count += 1
    wrong = cases.COREMARK.replace(b"0xe714", b"0xdead")
    wrong += b"ERROR! list crc 0xdead - should be 0xe714\n"
    mutated = copy.deepcopy(records)
    mutated[0]["stdout_base64"] = base64.b64encode(wrong).decode()
    compare(binary, "app", serial(contract, mutated), with_wasi, False)
    count += 1

    samples = [cases.COREMARK,
               cases.COREMARK.replace(b"\n", b"\r\n"),
               cases.COREMARK.replace(b" : ", b"\t:\t")]
    for data in samples:
        output(binary, data, True)
    for key in (b"[0]crclist", b"[0]crcmatrix", b"[0]crcstate", b"[0]crcfinal"):
        output(binary, cases.COREMARK.replace(key, key[3:]), False)
    for bad in (wrong, b"", cases.COREMARK[:-1], cases.COREMARK + b"\xff\n",
                cases.COREMARK + b"Errors detected\n",
                cases.COREMARK.replace(b"seedcrc", b"not-seedcrc"),
                cases.COREMARK.replace(b"0xe714", b"0xe714\x00")):
        output(binary, bad, False)
    randomizer = random.Random(188)
    for _ in range(128):
        key = randomizer.choice((b'"answer": 42', b'"checks": 2',
                                 b'"detail": 2', b'"reserved_bytes": 0'))
        at = randomizer.randrange(1, key.index(b'"', 1))
        changed = bytearray(key)
        changed[at] = 0
        compare(binary, "app", baseline.replace(key, changed, 1), no_wasi, False)
        count += 1
    # Reject-only hardening: the retained Python identity loader keeps the last
    # spelling while contracts.Document refuses duplicates, including escapes.
    source = json.dumps(no_wasi).encode()
    duplicate = source.replace(b'"minimal_wasi": false',
                               b'"minimal_wasi": false, "minimal_wasi": false')
    assert json.loads(duplicate) == no_wasi
    actual = subprocess.run([binary, "app", duplicate.hex(), baseline.hex()],
                            capture_output=True, check=False, timeout=15)
    assert actual.returncode != 0 and not actual.stdout and not actual.stderr
    print(f"native/Python tiny differential: {count} transcripts; "
          f"CoreMark output: {len(samples) + 4 + 7} native/Python/C golden cases")


if __name__ == "__main__":
    main(sys.argv[1])
