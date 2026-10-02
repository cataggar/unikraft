# SPDX-License-Identifier: BSD-3-Clause
"""Offline tests of the native-only fault gate, not guest execution evidence."""
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

from controller_record_fixtures import RecordFixtures
import native_fault_qualification as gate


class NativeFaultGate(unittest.TestCase):
    def setUp(self):
        parent = Path(os.environ["TMPDIR"])
        gate.private(parent)
        self.root = Path(tempfile.mkdtemp(prefix="native-fault-", dir=parent))
        self.addCleanup(shutil.rmtree, self.root)
        self.runtime = self.root / "runtime"
        self.runtime.mkdir(mode=0o700)
        self.evidence = self.runtime / "compute/evidence"
        self.evidence.mkdir(mode=0o700, parents=True)
        (self.runtime / "compute/boot-raw-x2apic").mkdir(mode=0o700)

    def refusal(self, case):
        stage, cause = gate.CASES[case]
        return subprocess.CompletedProcess([], 1, b"", (
            f"WAMR_CI_FAILED_STAGE: {stage}; cause: {cause}; "
            "bounded private logs retained.\n").encode())

    def test_each_fault_requires_its_exact_failure_and_unchanged_state(self):
        for case in gate.CASES:
            with self.subTest(case=case):
                before = gate.snapshot([self.runtime])
                result = self.refusal(case)
                gate.require_refusal(case, result, before, before, self.runtime)
                for altered in (
                    subprocess.CompletedProcess([], 0, b"", b""),
                    subprocess.CompletedProcess([], 2, b"", result.stderr),
                    subprocess.CompletedProcess([], 1, b"unexpected", result.stderr),
                    subprocess.CompletedProcess([], 1, b"", b"WAMR_CI_REFUSED: KVM\n"),
                    self.refusal("missing-build" if case != "missing-build"
                                 else "occupied-boot-slot"),
                ):
                    with self.assertRaises(ValueError):
                        gate.require_refusal(case, altered, before, before, self.runtime)
                (self.evidence / "prior").write_bytes(b"original")
                with self.assertRaises(ValueError):
                    gate.require_refusal(
                        case, result, before, gate.snapshot([self.runtime]), self.runtime)
                (self.evidence / "prior").unlink()
                (self.evidence / "result.json").write_bytes(b'{"passed":true}')
                with self.assertRaises(ValueError):
                    gate.require_refusal(case, result, before, before, self.runtime)
                (self.evidence / "result.json").unlink()

    def test_fault_injection_changes_only_the_requested_fixture(self):
        (self.evidence / "build-start.json").write_bytes(
            b'{"source":{"revision":"1111111111111111111111111111111111111111"}}\n')
        (self.evidence / "build.json").write_bytes(b"accepted build")
        (self.evidence / "unrelated").write_bytes(b"retained")
        gate.inject("build-start-tamper", self.runtime)
        self.assertIn(b"0" * 40, (self.evidence / "build-start.json").read_bytes())
        self.assertEqual((self.evidence / "build.json").read_bytes(), b"accepted build")
        gate.inject("missing-build", self.runtime)
        self.assertFalse((self.evidence / "build.json").exists())
        gate.inject("occupied-boot-slot", self.runtime)
        prior = self.runtime / "compute/boot-raw-x2apic/prior"
        self.assertEqual(prior.read_bytes(), b"prior")
        self.assertEqual(prior.stat().st_mode & 0o777, 0o600)
        self.assertEqual((self.evidence / "unrelated").read_bytes(), b"retained")
        with self.assertRaises(FileExistsError):
            gate.inject("occupied-boot-slot", self.runtime)

    def test_snapshot_detects_same_size_bytes_replacement_and_directory_change(self):
        path = self.evidence / "retained"
        path.write_bytes(b"first")
        before = gate.snapshot([self.runtime])
        path.write_bytes(b"other")
        self.assertNotEqual(before, gate.snapshot([self.runtime]))
        before = gate.snapshot([self.runtime])
        path.rename(self.evidence / "original")
        path.write_bytes(b"other")
        self.assertNotEqual(before, gate.snapshot([self.runtime]))
        before = gate.snapshot([self.runtime])
        (self.evidence / "occupied").mkdir(mode=0o700)
        self.assertNotEqual(before, gate.snapshot([self.runtime]))

    def test_removed_differential_and_unreviewed_wrapper_routes_refuse(self):
        repository = Path(__file__).resolve().parents[4]
        environment = dict(os.environ, GITHUB_ACTIONS="true",
                           GITHUB_JOB="wamr-differential-parity")
        for arguments in (("differential", "missing-build"),
                          ("fault", "success")):
            result = subprocess.run(
                ["bash", ".github/scripts/hyperv-qemu-candidate-runtime.sh",
                 "/d", *arguments], cwd=repository, env=environment,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(b"Invalid native fault driver selection", result.stderr)
        for action in ("local", "full"):
            result = subprocess.run(
                [sys.executable, "-B", str(Path(__file__).with_name(
                    "test_differential_parity.py")), action],
                cwd=repository, env=environment,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
            self.assertEqual(result.returncode, 2)
            self.assertEqual(result.stdout, b"")
            self.assertIn(b"Controller differential CLI retired", result.stderr)


if __name__ == "__main__":
    unittest.main()
