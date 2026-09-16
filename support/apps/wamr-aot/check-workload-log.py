#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""Bounded optional-image correctness checks, never measurement admission."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent
MAX_SERIAL = 2 * 1024 * 1024
PREFIXES = (
    "WAMR_NATIVE_WORKLOAD_BUILD", "WAMR_NATIVE_SNAPSHOT_SETUP",
    "WAMR_NATIVE_SNAPSHOT_RESET", "WAMR_NATIVE_INVOCATION", "WAMR_JIT_SAMPLE",
)
FORBIDDEN = (
    "Unikraft Crash", "Assertion failure", "Exception Type", "HYPERV_ACCEPTANCE",
    "UK_HYPERV_IO_READY", "UK_HYPERV_NETWORK_APP_READY", "UK_HYPERV_PLATFORM_READY",
)
DOMAINS = [
    "globals", "invocation-output", "linear-memory-access-protection",
    "linear-memory-contents", "linear-memory-logical-size",
    "passive-segment-drop-state", "table-entries-signatures", "wasi-context",
]


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


native_ci = load_module(
    "wamr_optional_serial", ROOT.parents[1] / "build/wamr-native-ci/run.py")


def require(condition, message):
    if not condition:
        raise ValueError(message)


def pairs(items):
    result = {}
    for key, value in items:
        require(key not in result, "duplicate JSON key")
        result[key] = value
    return result


def number(value, minimum=0):
    require(type(value) is int and value >= minimum, "missing/non-integer observation")


def records(raw):
    require(0 < len(raw) <= MAX_SERIAL, "empty/oversized raw serial")
    text = native_ci.normalize_serial(raw)
    require(all(char.isprintable() or char in "\n\t" for char in text),
            "invalid optional serial control")
    require(text.endswith("\n"), "truncated serial line")
    require(not any(marker in text for marker in FORBIDDEN),
        "failure/acceptance marker in optional serial")
    found = {prefix: [] for prefix in PREFIXES}
    ok = []
    order = []
    for line in text.split("\n"):
        if "WAMR_" not in line:
            require(not line.strip() or not order or order[-1] == "completed",
                    "unexpected noise within workload transcript")
            continue
        require(line.startswith("WAMR_") and line.count("WAMR_") == 1,
                "unanchored/embedded workload marker")
        require(len(line.encode("utf-8")) + 1 <= 16384, "oversized record")
        if line.startswith("WAMR_NATIVE_WORKLOAD_CHECK_OK "):
            ok.append(line)
            order.append("completed")
            continue
        prefix, separator, payload = line.partition("=")
        require(separator and prefix in found, "unexpected/failure/measurement marker")
        if prefix == "WAMR_JIT_SAMPLE":
            require(len(line.encode("utf-8")) + 1 <= 8192, "oversized sampler record")
        found[prefix].append(json.loads(payload, object_pairs_hook=pairs))
        order.append(prefix)
    require(len(ok) == 1, "exactly one completed correctness marker required")
    return found, ok[0], order


def validate_build(build, identity):
    require(build["version"] == 1 and type(build["version"]) is int and
            build["correctness_only"] is True, "not a correctness build record")
    for key in ("wamr_revision", "source_tree_sha256", "variant"):
        require(build[key] == identity[key], f"changed {key}")
    require(build["runtime_sha256"] == identity["files"]["libwamr-aot.a"] and
            build["compiler_sha256"] == identity["files"]["wamrc"], "changed linked runtime/compiler")
    require(build["clock"] == {"method": "hyperv-reference-monotonic", "resolution_ns": 100},
            "clock capability changed")
    require(build["memory_method"] == "native-vma-owned-4k-data-frames-including-none" and
            build["memory_coverage"] == "code-and-linear-pages-only" and
            build["sampling"] == "callback-boundaries-observed-max-not-peak" and
            build["allocator_quantity"] == "caller-and-adapter-requested-bytes-not-backing" and
            build["excludes"] == ["allocator-backing", "image", "native-stack", "page-tables",
                                  "other-kernel-allocations"], "incorrect memory coverage")
    memory = build["memory"]
    require(set(memory["after_teardown"]) == {
        "reserved_bytes", "frame_bytes", "accessible_bytes", "allocation_bytes"},
        "incomplete teardown coverage")
    for value in memory["after_teardown"].values():
        number(value)
        require(value == 0, "native adapter leak")
    for key in ("observed_max_frame_bytes", "observed_max_reserved_bytes",
                "observed_max_allocation_bytes", "observation_count"):
        number(memory[key], 1)


def invocation(call):
    require(call["schema_version"] == 1 and call["kind"] == "wamr-native-invocation-evidence",
            "bad invocation evidence")
    require(call["outcome"] == "returned" and call["exit_code"] is None and
            call["timing_error"] is None and call["diagnostic"] is None and
            call["output_failure"] is False and call["stdout_complete"] is True and
            call["stderr_complete"] is True and call["measurement_errors"] == [] and
            call["stdout_base64"] == call["stderr_base64"] == "", "failed/nonmatching invocation")


def validate(raw, identity, mode, sampler_validator=None):
    found, marker, order = records(raw)
    require(len(found["WAMR_NATIVE_WORKLOAD_BUILD"]) == 1, "missing/duplicate build record")
    validate_build(found["WAMR_NATIVE_WORKLOAD_BUILD"][0], identity)
    variant = identity["variant"]
    if variant == "snapshot":
        require(mode == "snapshot" and not found["WAMR_JIT_SAMPLE"], "mixed sampler protocol")
        require(marker == "WAMR_NATIVE_WORKLOAD_CHECK_OK variant=1 mode=0 teardown=0", "wrong mode")
        sequence = ["WAMR_NATIVE_INVOCATION", "WAMR_NATIVE_SNAPSHOT_SETUP", "WAMR_NATIVE_INVOCATION"]
        sequence += ["WAMR_NATIVE_SNAPSHOT_RESET", "WAMR_NATIVE_INVOCATION"] * 3
        require(order == sequence * 2 + ["WAMR_NATIVE_WORKLOAD_BUILD", "completed"],
                "reordered snapshot transcript")
        setups = found["WAMR_NATIVE_SNAPSHOT_SETUP"]
        resets = found["WAMR_NATIVE_SNAPSHOT_RESET"]
        calls = found["WAMR_NATIVE_INVOCATION"]
        require(len(setups) == 2 and len(resets) == 6 and len(calls) == 10,
                "incomplete snapshot lifecycle")
        for setup, name in zip(setups, ("compute", "memory"), strict=True):
            require(setup["version"] == 1 and setup["correctness_only"] is True and
                    setup["workload"] == name, "wrong snapshot workload")
            for field, extension in (("wasm", ".wasm"), ("aot", ".cwasm")):
                require(setup[field]["sha256"] == identity["files"][name + extension],
                        "changed embedded workload")
                number(setup[field]["bytes"], 1)
            require(setup["execution_lifecycle"] == {
                "mode": "snapshot-replay", "reset_policy": "restore-post-start-snapshot",
                "reset_before": "each-steady-invocation", "reset_timing": "excluded-from-invocation",
                "reset_scope": DOMAINS}, "not actual snapshot replay")
            require(set(setup["phases_ns"]) ==
                    {"load_ticks", "instantiate_ticks", "lifecycle_setup_ticks"}, "missing separate phases")
            for ticks in setup["phases_ns"].values():
                number(ticks)
            number(setup["pages"]["frame_bytes"], 1)
        for index, call in enumerate(calls):
            invocation(call)
            local = index % 5
            require(call["phase"] == ("module-start" if local == 0 else
                                     "compute" if index < 5 else "memory") and
                    call["index"] == (0 if local == 0 else local - 1), "reordered calls")
            if local:
                number(call["ticks"])
            else:
                require(call["ticks"] is None, "module-start mislabeled as first call")
        for index, reset in enumerate(resets):
            require(reset["workload"] == ("compute" if index < 3 else "memory") and
                    reset["index"] == index % 3 + 1 and reset["same_instance"] is True,
                    "wrong snapshot reset")
            require(reset["reset"]["outcome"] == "completed" and
                    reset["reset"]["diagnostic"] is None and
                    reset["reset"]["timing_error"] is None, "failed snapshot reset")
            number(reset["reset"]["elapsed_ticks"])
    else:
        require(variant in ("jit", "sample-aot") and
                mode in (("fast", "full") if variant == "jit" else ("aot",)), "wrong sampler mode")
        require(identity["jit_mode"] == (mode if variant == "jit" else None),
                "sample mode differs from the built image preset")
        require(all(not found[key] for key in PREFIXES[1:4]), "mixed snapshot protocol")
        require(len(found["WAMR_JIT_SAMPLE"]) == 1, "missing/duplicate sampler record")
        require(order == ["WAMR_JIT_SAMPLE", "WAMR_NATIVE_WORKLOAD_BUILD", "completed"],
                "reordered sampler transcript")
        expected = (2, 1 if mode == "fast" else 2) if variant == "jit" else (3, 0)
        require(marker == f"WAMR_NATIVE_WORKLOAD_CHECK_OK variant={expected[0]} "
                f"mode={expected[1]} teardown=0", "wrong completion marker")
        require(sampler_validator is not None, "matching SDK sampler validator required")
        request = hashlib.sha256(f"wamr-native-correctness-only-v1\n{mode}\n".encode()).hexdigest()
        sample = sampler_validator(found["WAMR_JIT_SAMPLE"][0], mode, request)
        require(sample["wasm_sha256"] == identity["files"]["matched.wasm"],
                "changed matched source")
        if mode == "aot":
            require(sample["cwasm_sha256"] == identity["files"]["matched.cwasm"],
                    "changed comparator artifact")
    return {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--log", type=Path, required=True)
    parser.add_argument("--identity", type=Path, default=ROOT / "build/artifacts/identity.json")
    parser.add_argument("--mode", choices=("snapshot", "aot", "fast", "full"), required=True)
    parser.add_argument("--sdk", type=Path, default=ROOT / "build/wamr-source")
    args = parser.parse_args()
    raw = native_ci.read(args.log, MAX_SERIAL)
    validator = None
    if args.mode != "snapshot":
        sdk = load_module(
            "native_jit_benchmark", args.sdk / "scripts/native_jit_benchmark.py")
        validator = sdk.validate_sample
    observed = validate(raw, json.loads(args.identity.read_text(), object_pairs_hook=pairs),
                        args.mode, validator)
    print("Optional workload correctness records valid; "
          f"raw_serial_bytes={observed['bytes']} raw_serial_sha256={observed['sha256']}; "
          "no boot/measurement qualification.")


if __name__ == "__main__":
    main()
