# SPDX-License-Identifier: BSD-3-Clause
"""Synthetic parser regressions; never native execution evidence."""
import base64
import copy
import ctypes
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "compute", ROOT / "check-log.py")
compute = importlib.util.module_from_spec(spec)
spec.loader.exec_module(compute)

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


class CoreMarkOutput(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        (ROOT / "build").mkdir(mode=0o700, exist_ok=True)
        cls.scratch = tempfile.TemporaryDirectory(dir=ROOT / "build")
        cls.addClassCleanup(cls.scratch.cleanup)
        library = Path(cls.scratch.name) / "coremark.so"
        subprocess.run(
            ["zig", "cc", "-shared", "-fPIC", "-std=c11",
             "-Wall", "-Wextra", "-Werror", str(ROOT / "tests/coremark-output.c"),
             "-o", str(library)], check=True)
        cls.native = ctypes.CDLL(str(library)).check_coremark
        cls.native.argtypes = [ctypes.c_char_p, ctypes.c_size_t]
        cls.native.restype = ctypes.c_int

    def assert_output(self, output, expected):
        self.assertEqual(bool(self.native(output, len(output))), expected)
        if expected:
            compute.validate_coremark(output)
        else:
            with self.assertRaises(ValueError):
                compute.validate_coremark(output)

    def test_exact_fields_and_documented_short_warning(self):
        self.assert_output(COREMARK, True)
        self.assert_output(COREMARK.replace(b"\n", b"\r\n"), True)
        self.assert_output(COREMARK.replace(b" : ", b"\t:\t"), True)

    def test_diagnostic_expected_values_are_not_results(self):
        bad = COREMARK.replace(b"0xe714", b"0xdead")
        bad += b"ERROR! list crc 0xdead - should be 0xe714\n"
        self.assert_output(bad, False)
        self.assert_output(
            b"0xe9f5 0xe714 0x1fd7 0x8e3a 0x988c\n"
            b"Must execute for at least 10 secs\n", False)

    def test_duplicate_missing_wrong_and_ambiguous_fields(self):
        for original, replacement in (
            (b"Iterations       : 100", b"Iterations       : 1000"),
            (b"0xe714", b"0xe7140"), (b"0x988c", b"0x0000"),
            (b"[0]crclist       : 0xe714\n", b""),
            (b"[0]crclist", b"[1]crclist"),
            (b"seedcrc", b"not-seedcrc"),
            (b"Errors detected\n", b""),
            (b"for a valid result!", b"for a valid result! extra"),
            (b"0xe714", b"0xe714\x00"),
        ):
            with self.subTest(replacement=replacement):
                self.assert_output(COREMARK.replace(original, replacement), False)
        for extra in (
            b"[0]crclist : 0xe714\n", b"[1]crclist : 0xe714\n",
            b"seedcrc : 0xe9f5\n", b"Errors detected\n",
            b"ERROR! matrix crc 0x0000 - should be 0x1fd7\n",
            b"ERROR! other failure\n", b"unrecognized output\n",
            b"\x00\n", b"\xff\n",
        ):
            with self.subTest(extra=extra):
                self.assert_output(COREMARK + extra, False)
        self.assert_output(COREMARK[:-1], False)
        self.assert_output(b"", False)


class ComputeContract(unittest.TestCase):
    def setUp(self):
        self.identity = {
            "wamr_revision": "f" * 40, "minimal_wasi": False,
            "files": {name: str(i) * 64 for i, name in enumerate(
                ("tiny.wasm", "tiny.cwasm", "libwamr-aot.a"))},
        }
        self.result = {
            "version": 1, "workload": "tiny", "wamr_revision": "f" * 40,
            "wasm_sha256": "0" * 64, "cwasm_sha256": "1" * 64,
            "runtime_sha256": "2" * 64, "platform_status": 0, "checks": 2,
            "answer": 42, "terminal": 1, "detail": 2,
            "reserved_bytes": 0, "frame_bytes": 0, "accessible_bytes": 0,
            "allocation_bytes": 0, "error_name": "",
            "system_page_table_bytes": 4096,
        }

    def log(self, wasi=()):
        return "\n".join(["WAMR_NATIVE_WASI=" + json.dumps(r) for r in wasi] +
                         ["WAMR_NATIVE_COMPUTE=" + json.dumps(self.result),
                          "WAMR_NATIVE_AOT_OK answer=42 teardown=0"])

    def test_exact_tiny(self):
        compute.validate(self.log(), self.identity)

    def test_bad_results_and_leaks(self):
        for key, value in (("answer", 41), ("checks", 1), ("terminal", 0),
                           ("detail", 0), ("reserved_bytes", 4096),
                           ("frame_bytes", 4096), ("allocation_bytes", 1),
                           ("platform_status", -12), ("version", True),
                           ("runtime_sha256", "9" * 64)):
            original = self.result[key]
            self.result[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                compute.validate(self.log(), self.identity)
            self.result[key] = original

    def test_duplicate_or_missing_records(self):
        for log in ("", self.log() + "\n" + self.log(),
                    self.log().replace("WAMR_NATIVE_AOT_OK", "NOT_OK")):
            with self.assertRaises(ValueError):
                compute.validate(log, self.identity)

    def wasi_fixture(self):
        self.identity["minimal_wasi"] = True
        records = []
        for name in ("coremark", "coremark-nofp"):
            self.identity["files"][name + ".wasm"] = "3" * 64
            self.identity["files"][name + ".cwasm"] = "4" * 64
            records.append({
                "version": 1, "correctness_only": True, "workload": name,
                "wasm_sha256": "3" * 64, "cwasm_sha256": "4" * 64,
                "terminal": 2, "detail": 0, "crc_ok": True,
                "output_error": 0, "pending_stdout": 0, "pending_stderr": 0,
                "unsupported_clock": 0, "realtime_supported": True,
                "stdout_base64": base64.b64encode(COREMARK).decode(),
                "stderr_base64": "",
            })
        return records

    def test_actual_stdout_required_and_unsigned_exit_not_truncated(self):
        records = self.wasi_fixture()
        compute.validate(self.log(records), self.identity)
        for field, value in (("stdout_base64", ""), ("pending_stdout", 29),
                             ("unsupported_clock", 1), ("detail", 0xFFFFFFFF),
                             ("terminal", 1), ("stdout_base64", "@@"),
                             ("realtime_supported", False),
                             ("stderr_base64", base64.b64encode(b"ERROR!\n").decode())):
            mutated = copy.deepcopy(records)
            mutated[0][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                compute.validate(self.log(mutated), self.identity)

    def test_claimed_crc_success_cannot_override_wrong_actual_values(self):
        records = self.wasi_fixture()
        bad = COREMARK.replace(b"0xe714", b"0xdead")
        bad += b"ERROR! list crc 0xdead - should be 0xe714\n"
        records[0]["stdout_base64"] = base64.b64encode(bad).decode()
        with self.assertRaises(ValueError):
            compute.validate(self.log(records), self.identity)


if __name__ == "__main__":
    unittest.main()
