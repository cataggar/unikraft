# SPDX-License-Identifier: BSD-3-Clause
"""Synthetic framing/lifecycle regressions, not native execution evidence."""
import copy
import ctypes
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
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
    def test_all_consumers_and_ci_use_the_same_supported_sdk(self):
        ci = load("workload_ci_pin", "../../build/wamr-native-ci/run.py")
        self.assertEqual(prepare.REVISION, prepare.WORKLOAD_REVISION)
        self.assertEqual(prepare.REVISION, ci.REVISION)
        workflow = ROOT.parents[2] / ".github/workflows/wamr-native-compute.yaml"
        self.assertIn(f"ref: {prepare.REVISION}", workflow.read_text())

    def test_unavailable_optional_pin_requires_explicit_development_selection(self):
        with patch.object(prepare, "capture", return_value="0.16.0"), \
                patch.object(prepare, "WORKLOAD_REVISION", None):
            for variant in ("snapshot", "jit", "sample-aot"):
                with self.subTest(variant=variant), self.assertRaisesRegex(ValueError, "merged SDK pin"):
                    prepare.prepare(ROOT, False, variant,
                                    jit_mode="fast" if variant == "jit" else None)

    def test_default_and_coremark_cannot_silently_become_jit(self):
        with patch.object(prepare, "capture", return_value="0.16.0"):
            with self.assertRaisesRegex(ValueError, "Coremark|coremark"):
                prepare.prepare(ROOT, True, "jit")
            with self.assertRaisesRegex(ValueError, "other variants forbid"):
                prepare.prepare(ROOT, False, "tiny", jit_mode="fast")
            with self.assertRaisesRegex(ValueError, "requires exactly"):
                prepare.prepare(ROOT, False, "jit")
        self.assertIn("-fPIC", prepare.NATIVE_FLAGS)
        self.assertIn("-fno-compiler-rt", prepare.NATIVE_FLAGS)


class BootMode(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        (ROOT / "build").mkdir(mode=0o700, exist_ok=True)
        cls.scratch = tempfile.TemporaryDirectory(dir=ROOT / "build")
        cls.addClassCleanup(cls.scratch.cleanup)
        library = Path(cls.scratch.name) / "workload-mode.so"
        subprocess.run(["zig", "cc", "-shared", "-fPIC", "-std=c11",
                        "-Wall", "-Wextra", "-Werror",
                        str(ROOT / "tests/workload-mode.c"), "-o", str(library)],
                       check=True)
        cls.native = ctypes.CDLL(str(library)).check_mode
        cls.native.argtypes = [ctypes.c_uint, ctypes.c_uint, ctypes.c_int,
                               ctypes.POINTER(ctypes.c_char_p), ctypes.POINTER(ctypes.c_uint)]
        cls.native.restype = ctypes.c_int

    def check_mode(self, variant, configured, args, expected):
        argv = (ctypes.c_char_p * len(args))(*args)
        mode = ctypes.c_uint(99)
        status = self.native(variant, configured, len(args), argv, ctypes.byref(mode))
        self.assertEqual(status == 0, expected is not None)
        self.assertEqual(mode.value, 99 if expected is None else expected)

    def test_fixed_jit_images_boot_without_firmware_arguments(self):
        for mode, name in ((1, b"correctness-fast"), (2, b"correctness-full")):
            self.check_mode(2, mode, [b"wamr"], mode)
            self.check_mode(2, mode, [b"wamr", name], mode)

    def test_absent_contradictory_measurement_and_unknown_modes_refuse(self):
        for mode in (0, 3):
            self.check_mode(2, mode, [b"wamr"], None)
        for mode, argument in ((1, b"correctness-full"), (2, b"correctness-fast"),
                               (1, b"measurement"), (2, b"correctness"), (1, b"fast")):
            self.check_mode(2, mode, [b"wamr", argument], None)
        self.check_mode(2, 1, [b"wamr", b"correctness-fast", b"extra"], None)
        self.check_mode(2, 1, [], None)
        self.check_mode(4, 0, [b"wamr"], None)

    def test_compiler_free_images_do_not_inherit_jit_modes(self):
        for variant in (1, 3):
            self.check_mode(variant, 0, [b"wamr"], 0)
            self.check_mode(variant, 0, [b"wamr", b"correctness"], 0)
            self.check_mode(variant, 1, [b"wamr"], None)
            self.check_mode(variant, 0, [b"wamr", b"correctness-fast"], None)


if __name__ == "__main__":
    unittest.main()
