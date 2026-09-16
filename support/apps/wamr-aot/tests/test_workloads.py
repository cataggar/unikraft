# SPDX-License-Identifier: BSD-3-Clause
"""Synthetic framing/lifecycle regressions, not native execution evidence."""
import copy
import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


check = load("workloads", "check-workload-log.py")
prepare = load("prepare", "prepare.py")


class SnapshotRecords(unittest.TestCase):
    def setUp(self):
        self.identity = {
            "variant": "snapshot", "wamr_revision": "a" * 40,
            "source_tree_sha256": "b" * 64,
            "files": {name: str(i) * 64 for i, name in enumerate((
                "libwamr-aot.a", "wamrc", "compute.wasm", "compute.cwasm",
                "memory.wasm", "memory.cwasm"))},
        }
        pages = dict(reserved_bytes=0, frame_bytes=0, accessible_bytes=0, allocation_bytes=0)
        self.build = {
            "version": 1, "correctness_only": True, "variant": "snapshot",
            "wamr_revision": "a" * 40, "source_tree_sha256": "b" * 64,
            "runtime_sha256": "0" * 64, "compiler_sha256": "1" * 64,
            "clock": {"method": "hyperv-reference-monotonic", "resolution_ns": 100},
            "memory_method": "native-vma-owned-4k-data-frames-including-none",
            "memory_coverage": "code-and-linear-pages-only",
            "sampling": "callback-boundaries-observed-max-not-peak",
            "allocator_quantity": "caller-and-adapter-requested-bytes-not-backing",
            "excludes": ["allocator-backing", "image", "native-stack", "page-tables",
                         "other-kernel-allocations"],
            "memory": {"after_teardown": pages, "observed_max_frame_bytes": 4096,
                       "observed_max_reserved_bytes": 4096,
                       "observed_max_allocation_bytes": 512, "observation_count": 20},
        }
        self.events = []
        for name in ("compute", "memory"):
            for index in range(5):
                self.events.append(("WAMR_NATIVE_INVOCATION", {
                    "schema_version": 1, "kind": "wamr-native-invocation-evidence",
                    "phase": "module-start" if index == 0 else name,
                    "index": max(0, index - 1), "outcome": "returned",
                    "exit_code": None, "ticks": None if index == 0 else 100,
                    "timing_error": None, "diagnostic": None, "output_failure": False,
                    "stdout_complete": True, "stderr_complete": True,
                    "measurement_errors": [], "stdout_base64": "", "stderr_base64": "",
                }))
            self.events.append(("WAMR_NATIVE_SNAPSHOT_SETUP", {
                "version": 1, "correctness_only": True, "workload": name,
                "wasm": {"sha256": self.identity["files"][name + ".wasm"], "bytes": 100},
                "aot": {"sha256": self.identity["files"][name + ".cwasm"], "bytes": 600},
                "execution_lifecycle": {
                    "mode": "snapshot-replay", "reset_policy": "restore-post-start-snapshot",
                    "reset_before": "each-steady-invocation", "reset_timing": "excluded-from-invocation",
                    "reset_scope": check.DOMAINS,
                },
                "phases_ns": {"load_ticks": 100, "instantiate_ticks": 200, "lifecycle_setup_ticks": 100},
                "pages": dict(pages, frame_bytes=4096),
            }))
            for index in range(1, 4):
                self.events.append(("WAMR_NATIVE_SNAPSHOT_RESET", {
                    "workload": name, "index": index, "same_instance": True,
                    "reset": {"outcome": "completed", "elapsed_ticks": 100,
                              "diagnostic": None, "timing_error": None},
                }))
        ordered = []
        for offset in (0, 9):
            events = self.events[offset:offset + 9]
            ordered.extend((events[0], events[5], events[1]))
            for index in range(3):
                ordered.extend((events[6 + index], events[2 + index]))
        self.events = ordered

    def raw(self):
        events = self.events + [("WAMR_NATIVE_WORKLOAD_BUILD", self.build)]
        return (b"\xffopaque boot noise\n" +
                "".join(f"{prefix}={json.dumps(value)}\n" for prefix, value in events).encode() +
                b"WAMR_NATIVE_WORKLOAD_CHECK_OK variant=1 mode=0 teardown=0\n")

    def test_exact_bounded_snapshot(self):
        check.validate(self.raw(), self.identity, "snapshot")

    def test_native_memory_and_identity_fail_closed(self):
        for key, value in (("runtime_sha256", "f" * 64), ("correctness_only", False),
                           ("memory_coverage", "whole-guest"), ("variant", "jit")):
            with self.subTest(key=key):
                original = self.build[key]
                self.build[key] = value
                with self.assertRaises(ValueError):
                    check.validate(self.raw(), self.identity, "snapshot")
                self.build[key] = original
        self.build["memory"]["after_teardown"]["frame_bytes"] = 4096
        with self.assertRaises(ValueError):
            check.validate(self.raw(), self.identity, "snapshot")

    def test_reset_and_actual_invocation_required(self):
        for prefix, key, value in (
                ("WAMR_NATIVE_SNAPSHOT_RESET", "same_instance", False),
                ("WAMR_NATIVE_INVOCATION", "outcome", "trap"),
                ("WAMR_NATIVE_INVOCATION", "stdout_base64", "AA==")):
            saved = copy.deepcopy(self.events)
            next(record for kind, record in self.events if kind == prefix)[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                check.validate(self.raw(), self.identity, "snapshot")
            self.events = saved
        self.events.pop()
        with self.assertRaises(ValueError):
            check.validate(self.raw(), self.identity, "snapshot")

    def test_framing_rejects_duplicate_truncated_and_measurement_records(self):
        raw = self.raw()
        for malformed in (
                raw + raw, raw[:-1], raw + b"WAMR_BENCH_RESULT={}\n",
                raw + b"WAMR_NATIVE_CHECK_RESULT={}\n",
                raw + b"WAMR_JIT_SAMPLE={}\n",
                raw.replace(b'"correctness_only": true', b'"correctness_only": true,"correctness_only": true', 1),
                b"x" * (check.MAX_SERIAL + 1),
                raw + b"WAMR_NATIVE_WORKLOAD_FAILED status=1\n"):
            with self.assertRaises(ValueError):
                check.validate(malformed, self.identity, "snapshot")

    def test_reordered_records_are_not_a_complete_run(self):
        self.events[0], self.events[1] = self.events[1], self.events[0]
        with self.assertRaisesRegex(ValueError, "reordered"):
            check.validate(self.raw(), self.identity, "snapshot")


class BuildBoundary(unittest.TestCase):
    def test_optional_images_require_explicit_unpublished_source_selection(self):
        with patch.object(prepare, "capture", return_value="0.16.0"), \
                patch.object(prepare, "WORKLOAD_REVISION", None):
            for variant in ("snapshot", "jit", "sample-aot"):
                with self.subTest(variant=variant), self.assertRaisesRegex(ValueError, "merged SDK pin"):
                    prepare.prepare(ROOT, False, variant)

    def test_default_and_coremark_cannot_silently_become_jit(self):
        with patch.object(prepare, "capture", return_value="0.16.0"):
            with self.assertRaisesRegex(ValueError, "Coremark|coremark"):
                prepare.prepare(ROOT, True, "jit")
            with self.assertRaisesRegex(ValueError, "only for optional"):
                prepare.prepare(ROOT, False, "tiny", "f" * 40)
        self.assertIn("-fPIC", prepare.NATIVE_FLAGS)
        self.assertIn("-fno-compiler-rt", prepare.NATIVE_FLAGS)


if __name__ == "__main__":
    unittest.main()
