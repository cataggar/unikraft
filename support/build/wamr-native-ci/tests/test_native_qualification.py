# SPDX-License-Identifier: BSD-3-Clause
"""Offline tests of the native-only fault gate, not guest execution evidence."""
import argparse
import contextlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from controller_record_fixtures import RecordFixtures
import native_fault_qualification as gate


class NativeQemuAcquisition(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(
            prefix="qemu-acquisition-", dir=os.environ["TMPDIR"]))
        self.addCleanup(shutil.rmtree, self.root)
        self.bin = self.root / "bin"
        self.bin.mkdir(mode=0o700)
        for name, output in (("uname", "x86_64"), ("id", "1000")):
            path = self.bin / name
            path.write_text(f"#!/bin/sh\nprintf '%s\\n' '{output}'\n")
            path.chmod(0o700)
        downloader = self.bin / "ghr"
        downloader.write_text("""#!/usr/bin/env python3
import json
import os
from pathlib import Path
import sys

args = sys.argv[1:]
with open(os.environ["ACQUISITION_CALLS"], "a") as calls:
    calls.write(json.dumps({
        "anonymous": "--no-auth" in args,
        "token": bool(os.environ.get("GH_TOKEN")),
    }) + "\\n")
output = Path(args[args.index("-o") + 1])
if os.environ["ACQUISITION_FAILURE"] == "archive" and output.name == "release.json":
    output.write_text(json.dumps({
        "tag_name": "v11.0.50-z.7",
        "target_commitish": "559ac9def5a65912ae602cc5682fc7c045fcbbcd",
        "assets": [{
            "id": 477103841,
            "name": "qemu-v11.0.50-z.7-linux-x64.tar.gz",
            "size": 137302371,
            "digest": "sha256:f8b9cc818959f95326010c95dad644177ebb0cbb0feef3db9528c4434855e397",
        }],
    }))
else:
    print("fixture download refusal", file=sys.stderr)
    sys.exit(3 if os.environ["ACQUISITION_FAILURE"] == "archive" else 2)
""")
        downloader.chmod(0o700)

    def acquire(self, name, *, token="", failure="metadata"):
        repository = Path(__file__).resolve().parents[4]
        calls = self.root / f"{name}.jsonl"
        runtime = self.root / name
        environment = dict(
            os.environ, PATH=f"{self.bin}:/usr/bin:/bin",
            GITHUB_ACTIONS="true", GH_TOKEN=token,
            ACQUISITION_CALLS=str(calls), ACQUISITION_FAILURE=failure)
        result = subprocess.run(
            ["bash", ".github/scripts/hyperv-native-qemu-acquire.sh", str(runtime)],
            cwd=repository, env=environment, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, timeout=10)
        return result, runtime, [
            json.loads(line) for line in calls.read_text().splitlines()]

    def test_http_failure_preserves_status_and_diagnostics_with_scoped_auth(self):
        for name, token in (("anonymous", ""), ("authenticated", "fixture-token")):
            with self.subTest(name=name):
                result, runtime, calls = self.acquire(name, token=token)
                self.assertEqual(result.returncode, 2)
                self.assertEqual(result.stdout, b"")
                self.assertIn(b"metadata-download.txt (exit 2)", result.stderr)
                self.assertIn(b"fixture download refusal", result.stderr)
                self.assertEqual(
                    (runtime / "evidence/metadata-download.txt").read_bytes(),
                    b"fixture download refusal\n")
                self.assertEqual(calls, [{
                    "anonymous": not bool(token), "token": bool(token)}])
                self.assertFalse((runtime / "evidence/release.json").exists())
                self.assertFalse(any((runtime / "bin").iterdir()))
                if token:
                    self.assertNotIn(token.encode(), result.stderr)

    def test_archive_verification_failure_keeps_metadata_and_never_extracts(self):
        result, runtime, calls = self.acquire(
            "archive", token="fixture-token", failure="archive")
        self.assertEqual(result.returncode, 3)
        self.assertIn(b"archive-download.txt (exit 3)", result.stderr)
        self.assertIn(b"fixture download refusal", result.stderr)
        self.assertTrue((runtime / "evidence/release.json").is_file())
        self.assertEqual(calls, [
            {"anonymous": False, "token": True},
            {"anonymous": False, "token": True},
        ])
        self.assertFalse(any((runtime / "bin").iterdir()))


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

    def test_all_fault_paths_launch_native_children_with_closed_build_bindings(self):
        wamr = self.root / "wamr-source"
        wamr.mkdir(mode=0o700)
        path = os.environ["PATH"]
        for case in gate.CASES:
            for ambient in ("matching", "hostile"):
                with self.subTest(case=case, ambient=ambient):
                    runtime = self.root / f"{case}-{ambient}"
                    output = self.root / f"{case}-{ambient}-output"
                    runtime.mkdir(mode=0o700)
                    output.mkdir(mode=0o700)
                    bison = runtime / "bison"
                    bison.mkdir(mode=0o700)
                    (bison / "fixture").write_bytes(b"private Bison fixture")
                    (bison / "fixture").chmod(0o600)
                    args = argparse.Namespace(
                        case=case, runtime=runtime, output=output, wamr_source=wamr,
                        controller=runtime / "controller/bin/uk-wamr-native-ci")
                    evidence = runtime / "compute/evidence"
                    actions = []

                    def child(argv, *, env, stdout, stderr):
                        self.assertEqual(env, {
                            "PATH": path, "LANG": "C", "LC_ALL": "C",
                            "BISON_PKGDATADIR": str(bison),
                        })
                        action = argv[1]
                        self.assertEqual(argv, [
                            str(args.controller), action, "--runtime", str(runtime),
                            *([] if action == "boot" else ["--wamr-source", str(wamr)]),
                        ])
                        actions.append(action)
                        if action == "build" and case != "prior-build-output":
                            evidence.mkdir(mode=0o700, parents=True)
                            (runtime / "compute/boot-raw-x2apic").mkdir(mode=0o700)
                            for name in gate.BUILD_RECORDS:
                                record = (b'{"source":{"revision":"' + b"1" * 40
                                          + b'"}}\n' if name == "build-start.json"
                                          else b"{}\n")
                                (evidence / name).write_bytes(record)
                                (evidence / name).chmod(0o600)
                            return mock.Mock(wait=mock.Mock(return_value=0))
                        if case == "prior-build-output":
                            self.assertEqual(action, "build")
                            self.assertTrue((runtime / "compute").is_dir())
                            self.assertFalse(evidence.exists())
                        else:
                            self.assertEqual(action, "boot")
                            if case == "build-start-tamper":
                                self.assertEqual(json.loads(
                                    (evidence / "build-start.json").read_bytes())[
                                        "source"]["revision"], "0" * 40)
                            elif case == "missing-build":
                                self.assertFalse((evidence / "build.json").exists())
                            else:
                                self.assertEqual(
                                    (runtime / "compute/boot-raw-x2apic/prior").read_bytes(),
                                    b"prior")
                        self.assertFalse((evidence / "result.json").exists())
                        stderr.write(self.refusal(case).stderr)
                        return mock.Mock(wait=mock.Mock(return_value=1))

                    inherited = {
                        "PATH": path, "LANG": "ambient", "LC_ALL": "ambient",
                        "BISON_PKGDATADIR": str(bison) if ambient == "matching"
                        else str(self.root / "unrelated-bison"),
                        "LD_PRELOAD": "/untrusted/loader", "MAKEFLAGS": "ambient",
                        "HOME": "/untrusted/home", "PYTHONPATH": "/untrusted/python",
                    }
                    captured = io.StringIO()
                    with mock.patch.dict(os.environ, inherited, clear=True), \
                            mock.patch.object(gate.platform, "machine", return_value="x86_64"), \
                            mock.patch.object(Path, "is_char_device", return_value=True), \
                            mock.patch.object(gate.os, "access", return_value=True), \
                            mock.patch.object(gate.subprocess, "Popen", side_effect=child), \
                            contextlib.redirect_stdout(captured):
                        gate.qualify(args)
                    self.assertEqual(actions, ["build"] if case == "prior-build-output"
                                     else ["build", "boot"])
                    self.assertEqual(captured.getvalue(),
                                     f"NATIVE_FAULT_QUALIFIED: {case}\n")

    def test_invalid_tool_search_path_refuses_before_native_launch(self):
        for index, path in enumerate(("", "/usr/bin:", "relative:/usr/bin")):
            with self.subTest(path=path):
                runtime = self.root / f"invalid-path-{index}"
                output = self.root / f"invalid-path-{index}-output"
                runtime.mkdir(mode=0o700)
                output.mkdir(mode=0o700)
                args = argparse.Namespace(
                    case="prior-build-output", runtime=runtime, output=output,
                    wamr_source=self.root,
                    controller=runtime / "controller/bin/uk-wamr-native-ci")
                with mock.patch.dict(os.environ, {"PATH": path}), \
                        mock.patch.object(gate.platform, "machine", return_value="x86_64"), \
                        mock.patch.object(Path, "is_char_device", return_value=True), \
                        mock.patch.object(gate.os, "access", return_value=True), \
                        mock.patch.object(gate.subprocess, "Popen") as launch:
                    with self.assertRaises(ValueError):
                        gate.qualify(args)
                    launch.assert_not_called()
                self.assertFalse((runtime / "compute").exists())

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
