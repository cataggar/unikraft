#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""Temporary differential fixtures; synthetic records are not execution evidence."""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import random
import subprocess
import sys
import types

HERE = Path(__file__).resolve().parent
APP = HERE.parent
CASES = APP / "tests/test_workloads.py"
PIN = "a53205d77be3b880eb8f8b96679512ba58e2331a"


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


cases = load("optional_cases", CASES)
check = cases.check
fixtures = HERE / "optional-fixtures"


def sample_record(mode, identity):
    compiler = mode != "aot"
    memory = {
        "heap_live_bytes": 4096, "heap_peak_bytes": 8192,
        "code_bytes": 1024, "code_reserved_bytes": 4096,
        "linear_reserved_bytes": 8 * 65536, "linear_committed_bytes": 2 * 65536,
    }
    request = hashlib.sha256(f"wamr-native-correctness-only-v1\n{mode}\n".encode()).hexdigest()
    sample = {
        "schema_version": 1, "kind": "wamr-native-jit-sample",
        "qualification": "requires-independent-image-and-deployment-evidence",
        "request_sha256": request, "mode": mode, "compiler_embedded": compiler,
        "wasm_sha256": identity["files"]["matched.wasm"], "wasm_bytes": 4096,
        "cwasm_sha256": identity["files"]["matched.cwasm"], "cwasm_bytes": 4096,
        "workload": "volatile-compute-memory-2000", "expected": 2241491208,
        "lifecycle": "same-instance-workload-initializes-memory-in-timed-call",
        "clock_resolution_ns": 1, "compile_ns": 100 if compiler else None,
        "compiler_phases_ns": dict.fromkeys(
            ("parse", "lower", "optimize", "codegen", "emit"), 10) if compiler else None,
        "compiler_peak_bytes": 65536 if compiler else 0,
        "compiler_retained_bytes": 4096 if compiler else 0,
        "compiler_polls": 100 if compiler else 0,
        "load_ns": 10, "instantiate_ns": 10, "start_ns": 10, "growth_ns": 10,
        "growth_previous_pages": 2, "fuel_per_invocation": 100000 if compiler else None,
        "invocations": [
            {"ns": 10, "outcome": "returned", "value": 2241491208, "diagnostic": None}
            for _ in range(4)
        ],
        "memory_before": memory,
        "memory_after": {**memory, "linear_committed_bytes": 3 * 65536},
        "caller_peak_bytes": 100000, "caller_live_after_teardown": 0,
        "reserved_after_teardown": 0, "failure_stage": None, "failure": None,
    }
    return sample


def baseline(mode):
    if mode == "snapshot":
        instance = cases.SnapshotRecords()
        instance.setUp()
        return instance.raw(), instance.identity
    variant = "sample-aot" if mode == "aot" else "jit"
    identity, build = cases.build_fixture(variant)
    identity["jit_mode"] = None if mode == "aot" else mode
    identity["files"].update({"matched.wasm": "d" * 64, "matched.cwasm": "e" * 64})
    sample = sample_record(mode, identity)
    number, preset = (3, 0) if mode == "aot" else (2, 1 if mode == "fast" else 2)
    raw = ("Powered by Unikraft\nCalling main(1, ['wamr'])\n" +
           "WAMR_JIT_SAMPLE=" + json.dumps(sample) + "\n" +
           "WAMR_NATIVE_WORKLOAD_BUILD=" + json.dumps(build) + "\n" +
           f"WAMR_NATIVE_WORKLOAD_CHECK_OK variant={number} mode={preset} teardown=0\n"
           "main returned 0\n").encode()
    return raw, identity


def pinned_sdk():
    sdk = Path(os.environ.get("WAMR_PINNED_SDK", "/d/wamr"))
    if not (sdk / "scripts/native_jit_benchmark.py").is_file():
        return None
    if subprocess.run(["git", "-C", str(sdk), "cat-file", "-e", PIN + "^{commit}"],
                      capture_output=True, check=False).returncode:
        return None
    scripts = "scripts/native_jit_benchmark.py", "scripts/native_benchmark.py"
    pinned = [subprocess.run(["git", "-C", str(sdk), "show", f"{PIN}:{name}"],
                             capture_output=True, check=True).stdout for name in scripts]
    if (sdk / scripts[1]).read_bytes() != pinned[1]:
        return None
    module = types.ModuleType("native_jit_benchmark")
    module.__file__ = str(sdk / scripts[0])
    exec(compile(pinned[0], module.__file__, "exec"), module.__dict__)
    return module


def compare(binary, mode, raw, identity, sdk, expect=None):
    result = subprocess.run(
        [binary, mode, json.dumps(identity).encode().hex(), raw.hex()],
        capture_output=True, check=False, timeout=15,
    )
    try:
        sampler = (lambda sample, candidate, sha: sdk.validate_sample(sample, candidate, sha)) if sdk else (
            lambda sample, candidate, sha: sample)
        observed = check.validate(raw, identity, mode, sampler)
        valid = True
        normalized = check.native_ci.normalize_serial(raw)
        sequence = [line for line in normalized.split("\n") if line.startswith("WAMR_")]
    except (ValueError, KeyError, IndexError, TypeError, UnicodeError, json.JSONDecodeError):
        valid = False
    if expect is not None:
        assert valid == expect, (mode, "invalid Python fixture", raw[:120], valid, expect)
    assert (result.returncode == 0) == valid, (mode, raw[:140], result.stderr, result.stdout[:250])
    assert not result.stderr, (mode, result.stderr)
    if valid:
        actual = json.loads(result.stdout)
        assert actual == {
            "raw_serial_bytes": observed["bytes"],
            "raw_serial_sha256": observed["sha256"],
            "record_sequence": sequence,
        }, (mode, actual)
    else:
        assert not result.stdout, (mode, result.stdout[:100])


def main(binary):
    sdk = pinned_sdk()
    count = 0
    for mode in ("snapshot", "aot", "fast", "full"):
        raw, identity = baseline(mode)
        assert (fixtures / f"{mode}.log").read_bytes() == raw
        assert json.loads((fixtures / f"{mode}.identity.json").read_text()) == identity
        if sdk and mode != "snapshot":
            request = hashlib.sha256(f"wamr-native-correctness-only-v1\n{mode}\n".encode()).hexdigest()
            sample = json.loads(next(line.split(b"=", 1)[1] for line in raw.splitlines()
                                     if line.startswith(b"WAMR_JIT_SAMPLE=")))
            sdk.validate_sample(sample, mode, request)
        for accepted in (raw, cases.console_frame(raw), b"\n" + raw, raw + b"trailing console\n"):
            compare(binary, mode, accepted, identity, sdk, True)
            count += 1
        if mode == "aot":
            assert "jit_mode" in identity and identity["jit_mode"] is None
            compare(binary, mode, raw, {**identity, "jit_mode": None}, sdk, True)
            count += 1
        if mode != "snapshot":
            missing_jit_mode = dict(identity)
            del missing_jit_mode["jit_mode"]
            compare(binary, mode, raw, missing_jit_mode, sdk, False)
            count += 1
        fields = [
            (b'"correctness_only": true', b'"correctness_only": false'),
            (b'"clock": {"method": "hyperv-reference-monotonic"',
             b'"clock": {"method": "other"'),
            (b'"frame_bytes": 0', b'"frame_bytes": 1'),
            (b'"variant": "' + identity["variant"].encode() + b'"', b'"variant": "other"'),
            (b'WAMR_NATIVE_WORKLOAD_CHECK_OK', b'WAMR_NATIVE_WORKLOAD_FAILED'),
        ]
        if mode == "snapshot":
            fields += [
                (b'"same_instance": true', b'"same_instance": false'),
                (b'"outcome": "returned"', b'"outcome": "trap"'),
                (b'"stdout_base64": ""', b'"stdout_base64": "AA=="'),
                (b'"reset_scope": [', b'"reset_scope": ["extra", '),
            ]
        else:
            fields += [
                (b'"expected": 2241491208', b'"expected": 0'),
                (b'"compiler_embedded": ' + (b"false" if mode == "aot" else b"true"),
                 b'"compiler_embedded": ' + (b"true" if mode == "aot" else b"false")),
                (b'"growth_previous_pages": 2', b'"growth_previous_pages": 3'),
                (b'"caller_live_after_teardown": 0', b'"caller_live_after_teardown": 1'),
                (b'"fuel_per_invocation": ' + (b"null" if mode == "aot" else b"100000"),
                 b'"fuel_per_invocation": 1'),
            ]
        for old, new in fields:
            assert old in raw, (mode, old)
            changed = raw.replace(old, new, 1)
            if sdk is None and old.startswith((
                    b'"expected":', b'"compiler_embedded":', b'"growth_previous_pages":',
                    b'"caller_live_after_teardown":', b'"fuel_per_invocation":')):
                # The retained transport script delegates these fields to the pinned SDK.
                native = subprocess.run([binary, mode, json.dumps(identity).encode().hex(),
                                         changed.hex()], capture_output=True, check=False)
                assert native.returncode != 0 and not native.stdout and not native.stderr
            else:
                compare(binary, mode, changed, identity, sdk, False)
            count += 1
        for bad in (raw[:-1], raw + raw, raw + b"WAMR_BENCH_RESULT={}\n",
                    raw + b"Unikraft Crash\n", b"\xff\n" + raw,
                    raw.replace(b"WAMR_NATIVE_WORKLOAD_BUILD=", b"echo WAMR_NATIVE_WORKLOAD_BUILD=", 1),
                    raw.replace(b"WAMR_NATIVE_WORKLOAD_BUILD=", b"WAMR_NATIVE_WORKLOAD_BUILD={\"x\":1,\"x\":2}\nWAMR_NATIVE_WORKLOAD_BUILD=", 1)):
            compare(binary, mode, bad, identity, sdk, False)
            count += 1
        rng = random.Random(18803)
        for _ in range(24):
            lines = raw.splitlines(keepends=True)
            i = rng.randrange(2, len(lines) - 2)
            lines[i] = b"noise\n" if rng.randrange(2) else lines[i].replace(b"WAMR_", b"ECHO_WAMR_", 1)
            compare(binary, mode, b"".join(lines), identity, sdk, False)
            count += 1
    print(f"optional differential: {count} cases; pinned SDK {'enabled' if sdk else 'unavailable (transport only)'}")


if __name__ == "__main__":
    if sys.argv[1:] == ["--generate"]:
        fixtures.mkdir(exist_ok=True)
        for mode in ("snapshot", "aot", "fast", "full"):
            raw, identity = baseline(mode)
            (fixtures / f"{mode}.log").write_bytes(raw)
            (fixtures / f"{mode}.identity.json").write_text(json.dumps(identity) + "\n")
    else:
        main(sys.argv[1])
