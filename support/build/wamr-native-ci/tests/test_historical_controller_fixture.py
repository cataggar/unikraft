# SPDX-License-Identifier: BSD-3-Clause
"""Authenticate neutral historical witnesses without importing current run.py."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
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


if __name__ == "__main__":
    unittest.main()
