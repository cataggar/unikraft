# SPDX-License-Identifier: BSD-3-Clause
"""Synthetic parser regressions; never native execution evidence."""
import base64
import copy
import importlib.util
import json
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location(
    "compute", Path(__file__).resolve().parents[1] / "check-log.py")
compute = importlib.util.module_from_spec(spec)
spec.loader.exec_module(compute)


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
        output = b"0xe9f5 0xe714 0x1fd7 0x8e3a 0x988c\nMust execute for at least 10 secs\n"
        for name in ("coremark", "coremark-nofp"):
            self.identity["files"][name + ".wasm"] = "3" * 64
            self.identity["files"][name + ".cwasm"] = "4" * 64
            records.append({
                "version": 1, "correctness_only": True, "workload": name,
                "wasm_sha256": "3" * 64, "cwasm_sha256": "4" * 64,
                "terminal": 2, "detail": 0, "crc_ok": True,
                "output_error": 0, "pending_stdout": 0, "pending_stderr": 0,
                "unsupported_clock": 0, "stdout_base64": base64.b64encode(output).decode(),
                "stderr_base64": "",
            })
        return records

    def test_actual_stdout_required_and_unsigned_exit_not_truncated(self):
        records = self.wasi_fixture()
        compute.validate(self.log(records), self.identity)
        for field, value in (("stdout_base64", ""), ("pending_stdout", 29),
                             ("unsupported_clock", 1), ("detail", 0xFFFFFFFF),
                             ("terminal", 1), ("stdout_base64", "@@")):
            mutated = copy.deepcopy(records)
            mutated[0][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                compute.validate(self.log(mutated), self.identity)


if __name__ == "__main__":
    unittest.main()
