#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""Check compute records after the existing exact-image local boot validator."""
import argparse
import base64
import json
from pathlib import Path


def require(condition, message):
    if not condition:
        raise ValueError(message)


def records(text, prefix):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, "duplicate record key")
            result[key] = value
        return result
    return [json.loads(line[len(prefix):], object_pairs_hook=unique) for line in text.splitlines()
            if line.startswith(prefix)]


def validate(text, identity):
    compute = records(text, "WAMR_NATIVE_COMPUTE=")
    require(len(compute) == 1, "one compute result required")
    result = compute[0]
    required = {
        "version": 1, "workload": "tiny",
        "wamr_revision": identity["wamr_revision"],
        "wasm_sha256": identity["files"]["tiny.wasm"],
        "cwasm_sha256": identity["files"]["tiny.cwasm"],
        "runtime_sha256": identity["files"]["libwamr-aot.a"],
        "platform_status": 0, "checks": 2, "answer": 42,
        "terminal": 1, "detail": 2, "reserved_bytes": 0,
        "frame_bytes": 0, "accessible_bytes": 0, "allocation_bytes": 0,
        "error_name": "",
    }
    for key, expected in required.items():
        require(result.get(key) == expected and type(result.get(key)) is type(expected),
                f"unexpected compute {key}")
    require(set(result) == set(required) | {"system_page_table_bytes"},
            "unexpected compute fields")
    table_bytes = result.get("system_page_table_bytes")
    require(type(table_bytes) is int and 0 < table_bytes <= 256 * 1024 * 1024
            and table_bytes % 4096 == 0, "invalid system page-table accounting")
    wasi = records(text, "WAMR_NATIVE_WASI=")
    expected_workloads = ["coremark", "coremark-nofp"] if identity["minimal_wasi"] else []
    require([r.get("workload") for r in wasi] == expected_workloads,
            "missing, duplicate or unexpected WASI workloads")
    for r in wasi:
        name = r["workload"]
        require(type(r.get("version")) is int and r["version"] == 1 and
                r.get("correctness_only") is True,
                "not a correctness record")
        require(r.get("wasm_sha256") == identity["files"][name + ".wasm"] and
                r.get("cwasm_sha256") == identity["files"][name + ".cwasm"],
                "wrong CoreMark artifact")
        require(type(r.get("terminal")) is int and type(r.get("detail")) is int and
                0 <= r["detail"] <= 0xFFFFFFFF and r["terminal"] in (0, 2) and
                (r["terminal"] != 2 or r.get("detail") == 0),
                "guest trapped, failed, or exited nonzero")
        require(r.get("crc_ok") is True, "guest CRC/clock/output check failed")
        for field in ("output_error", "pending_stdout", "pending_stderr", "unsupported_clock"):
            require(type(r.get(field)) is int and r[field] == 0,
                    f"unresolved {field}")
        output = []
        for field in ("stdout_base64", "stderr_base64"):
            raw = base64.b64decode(r[field], validate=True)
            require(len(raw) <= 4096 and base64.b64encode(raw).decode() == r[field],
                    "noncanonical or oversized output")
            output.append(raw)
        for marker in (b"0xe9f5", b"0xe714", b"0x1fd7", b"0x8e3a", b"0x988c",
                       b"Must execute for at least 10 secs"):
            require(marker in output[0], "missing raw CRC/short-run diagnostic")
    require(text.count("WAMR_NATIVE_AOT_OK answer=42 teardown=0") == 1,
            "missing or duplicate completion marker")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--log", type=Path, required=True)
    parser.add_argument("--identity", type=Path, required=True)
    args = parser.parse_args()
    require(args.log.stat().st_size <= 4 * 1024 * 1024, "oversized private log")
    validate(args.log.read_text(errors="strict"),
             json.loads(args.identity.read_text()))
    print("Compute records match; no hardware or benchmark qualification.")


if __name__ == "__main__":
    main()
