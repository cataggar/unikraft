# SPDX-License-Identifier: BSD-3-Clause
"""Authenticate neutral historical witnesses without importing current run.py."""
import contextlib
import hashlib
import importlib.util
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

HERE = Path(__file__).resolve()
ROOT = HERE.parents[4]
SPEC = importlib.util.spec_from_file_location(
    "historical_fixture", HERE.with_name("historical_controller_fixture.py"))
fixture = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(fixture)
GIT = os.environ.get("WAMR_CI_GIT", "git")


class HistoricalControllerFixture(unittest.TestCase):
    def test_frozen_native_input_matches_authenticated_historical_helpers(self):
        path = HERE.parents[1] / "controller/fixtures/historical_controller.json"
        self.assertEqual(path.read_bytes(), fixture.frozen_bytes(ROOT, GIT))

    def test_wrong_git_object_and_changed_source_refuse_before_execution(self):
        for output in (b"0" * 40 + b"\n", b"raise AssertionError('executed')\n"):
            with self.subTest(output=output):
                replies = [
                    subprocess.CompletedProcess([], 0, stdout=output),
                ]
                if len(output) != 41:
                    replies.insert(0, subprocess.CompletedProcess(
                        [], 0, stdout=(
                            fixture.SOURCES["run.py"][0] + "\n").encode()))
                with mock.patch.object(subprocess, "run", side_effect=replies):
                    with self.assertRaises(RuntimeError):
                        fixture.load_controller(ROOT, GIT)

    def test_historical_loader_never_imports_current_mixed_adapter(self):
        ci = fixture.load_controller(ROOT, GIT)
        with mock.patch.object(
                importlib.util, "spec_from_file_location",
                side_effect=AssertionError("current oracle import")):
            evidence = fixture.load_bindings(ROOT, GIT, ci)
            record, identities = evidence.supervised_binding("config")
            ci.validate_supervised_command_binding(record, "config", identities)
            changed = record["supervisor"]["request"]
            changed["argv"][1]["value"] = "prepare"
            evidence.rehash_supervised_binding(record)
            with self.assertRaises(ci.Refusal):
                ci.validate_supervised_command_binding(
                    record, "config", identities)

    def test_schema_is_authenticated_without_requiring_a_producer_checkout(self):
        absent = ROOT / ".d/absent-historical-controller-checkout"
        with mock.patch.object(
                Path, "read_text",
                side_effect=AssertionError("unauthenticated physical schema")):
            ci = fixture.load_controller(ROOT, GIT, producer=absent)
            evidence = fixture.load_bindings(ROOT, GIT, ci)
            record, identities = evidence.supervised_binding("config")
            ci.validate_supervised_command_binding(record, "config", identities)
        self.assertEqual(ci.REPO, absent)

    def test_mixed_adapter_collects_native_cases_without_loading_owner_oracles(self):
        original = importlib.util.spec_from_file_location

        def native_only(name, path, *args, **kwargs):
            if Path(path).name in ("run.py", "public_bundle.py"):
                raise AssertionError("native collection imported owner oracle")
            return original(name, path, *args, **kwargs)

        with mock.patch.object(importlib.util, "spec_from_file_location",
                               side_effect=native_only):
            spec = original("native_adapter_collection",
                            HERE.with_name("test_adapter.py"))
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            suite = unittest.defaultTestLoader.loadTestsFromModule(module)
            self.assertEqual(suite.countTestCases(), 155)
            native = unittest.defaultTestLoader.loadTestsFromTestCase(
                module.NativeAcquisitionFixtures)
            self.assertEqual(native.countTestCases(), 10)
            self.assertNotIn("ci", module.__dict__)

    def test_successor_ledger_preserves_inventory_and_real_native_descriptions(self):
        spec = importlib.util.spec_from_file_location(
            "controller_coverage", HERE.with_name("controller_coverage.py"))
        ledger = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(ledger)
        package = HERE.parents[1]
        for source, mapping in (
                (ledger.LIMIT_SOURCE, ledger.PRODUCTION_LIMIT_SUCCESSORS),
                (ledger.NATIVE_SOURCE, ledger.NATIVE_ORACLE_SUCCESSORS)):
            text = (package / source).read_text()
            for successors in mapping.values():
                for description in successors:
                    self.assertIn('test "' + description + '"', text)
        self.assertNotIn(
            "support/build/wamr-native-ci/tests/test_adapter.py",
            (package / ledger.NATIVE_SOURCE).read_text(),
        )
        inventory = json.loads(
            (package / "authority/goldens/python-scenarios.json").read_bytes())
        adapter = [name for name in inventory["scenarios"]
                   if "/tests/test_adapter.py::" in name]
        for name, (classification, count) in ledger.ADAPTER_CLASSES.items():
            self.assertEqual(sum("::" + name + "::" in item
                                 for item in adapter), count, classification)
        self.assertEqual(sum(count for unused, count
                             in ledger.ADAPTER_CLASSES.values()), len(adapter))
        successors = ledger.adapter_successors(inventory["scenarios"])
        self.assertEqual(set(successors), set(adapter))
        for old, entry in successors.items():
            self.assertEqual(old, entry["successor"])
        self.assertEqual(sum(not entry["current_controller_oracle"]
                             for entry in successors.values()), 10)
        matrix = (package / "controller/local_acceptance_tests.zig").read_text()
        for producer in ledger.HISTORICAL_PRODUCERS:
            self.assertIn('"' + producer + '"', matrix)

    def test_oracle_handoff_and_public_bundle_digest_cache_and_cli_dispatch(self):
        handoff = fixture.load_oracle_module("handoff.py", ROOT, git=GIT)
        public_bundle = fixture.load_oracle_module("public_bundle.py", ROOT, git=GIT)
        for attr in ("_STDLIB_SHA256", "cached_fd_entry", "store_fd_digest", "seed_file_digest"):
            self.assertTrue(hasattr(handoff.ci, attr), attr)
        for attr in (
            "_STDLIB_SHA256",
            "_ORIG_COPY_CHECKED",
            "_is_verified_archive_fd",
            "_mark_verified_archive_fd",
            "_mark_verified_archive_path",
        ):
            self.assertTrue(hasattr(public_bundle, attr), attr)
        self.assertIs(public_bundle.copy_checked, public_bundle._ORIG_COPY_CHECKED)

        scratch_base = Path(os.environ.get("TMPDIR") or (ROOT / ".d/tmp"))
        scratch_base.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(scratch_base, 0o700)
        raw_dir = tempfile.mkdtemp(prefix="oracle-fixture-", dir=scratch_base)
        try:
            os.chmod(raw_dir, 0o700)
            work = Path(raw_dir).resolve()
            payload = b"A" * 65536
            digest_hex = hashlib.sha256(payload).hexdigest()
            sample = work / "sample.bin"
            sample.write_bytes(payload)
            sample.chmod(0o600)
            expected = {"size": len(payload), "sha256": digest_hex}
            with sample.open("rb") as src:
                public_bundle.copy_checked(src, None, expected)
            with sample.open("rb") as src:
                st = os.fstat(src.fileno())
                _, cached_entry = handoff.ci.cached_fd_entry(src.fileno(), st)
            self.assertEqual(cached_entry, (digest_hex, 2))
        finally:
            shutil.rmtree(raw_dir, ignore_errors=True)

        completed = subprocess.run(
            [
                sys.executable,
                "-B",
                str(HERE.with_name("historical_controller_fixture.py")),
                "--handoff",
                "--help",
            ],
            cwd=ROOT,
            env={
                "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
                "PYTHONDONTWRITEBYTECODE": "1",
                "LC_ALL": "C",
            },
            capture_output=True,
            text=True,
            check=True,
        )
        for subcommand in (
            "export",
            "prepare-azure-runtime",
            "candidate",
            "plan",
            "record-authorization",
            "admit",
            "public-source-bundle",
            "verify-public-source-bundle",
            "import-public-source-bundle",
        ):
            self.assertIn(subcommand, completed.stdout)

        stderr = io.StringIO()
        saved_argv = sys.argv[:]
        saved_main = sys.modules.get("__main__")
        saved_handoff = sys.modules.get("handoff")
        saved_public = sys.modules.get("public_bundle")
        try:
            sys.modules.pop("public_bundle", None)
            sys.argv = [
                "historical_controller_fixture.py",
                "candidate",
                "--bundle",
                str(ROOT / ".d/nonexistent-bundle/bundle.json"),
                "--output",
                str(ROOT / ".d/nonexistent-bundle/candidate.json"),
            ]
            with contextlib.redirect_stderr(stderr):
                with self.assertRaises(SystemExit) as ctx:
                    fixture.run_oracle_cli("handoff", ROOT, git=GIT)
            self.assertEqual(ctx.exception.code, 1)
            self.assertIn(
                "Compute handoff refused at handoff; original local records are unchanged.",
                stderr.getvalue(),
            )
            self.assertIn("public_bundle", sys.modules)
        finally:
            sys.argv = saved_argv
            if saved_main is not None:
                sys.modules["__main__"] = saved_main
            if saved_handoff is None:
                sys.modules.pop("handoff", None)
            else:
                sys.modules["handoff"] = saved_handoff
            if saved_public is None:
                sys.modules.pop("public_bundle", None)
            else:
                sys.modules["public_bundle"] = saved_public


if __name__ == "__main__":
    unittest.main()
