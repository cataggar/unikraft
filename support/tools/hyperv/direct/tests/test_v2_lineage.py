# SPDX-License-Identifier: BSD-3-Clause
"""Version-2 direct admission and fully rehashed lineage refusals."""
import importlib.util
import os
from pathlib import Path
import shutil
import subprocess
import unittest
import uuid

REPO = Path(__file__).resolve().parents[5]
SPEC = importlib.util.spec_from_file_location(
    "wamr_v2_fixture", Path(__file__).with_name("v2_fixture.py"))
fixture = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(fixture)
HANDOFF_SPEC = importlib.util.spec_from_file_location(
    "wamr_v2_handoff",
    REPO / "support/build/wamr-native-ci/handoff.py")
handoff = importlib.util.module_from_spec(HANDOFF_SPEC)
HANDOFF_SPEC.loader.exec_module(handoff)
PUBLIC_SPEC = importlib.util.spec_from_file_location(
    "wamr_v2_public_bundle",
    REPO / "support/build/wamr-native-ci/public_bundle.py")
public_bundle = importlib.util.module_from_spec(PUBLIC_SPEC)
PUBLIC_SPEC.loader.exec_module(public_bundle)
TOOLS = Path(os.environ["WAMR_DIRECT_TOOLS"]).resolve(strict=True)
VALIDATOR = TOOLS / "uk-wamr-direct-validate"
PACKAGE = Path(os.environ["WAMR_CI_PACKAGE"]).resolve(strict=True)


class LineageV2(unittest.TestCase):
    def setUp(self):
        self.root = REPO / ".d" / ("v2-lineage-" + uuid.uuid4().hex)
        fixture.build(self.root, PACKAGE)
        self.addCleanup(shutil.rmtree, self.root)

    def validate(self, command="handoff", path=None, status=0):
        path = path or self.root / "bundle.json"
        completed = subprocess.run(
            [VALIDATOR, command, path],
            env={}, capture_output=True, timeout=90)
        self.assertEqual(completed.returncode, status, completed.stderr)
        self.assertNotIn(str(self.root).encode(), completed.stderr)
        return completed

    def mutate_json(self, relative, update):
        path = self.root / relative
        value = fixture.read(path)
        update(value)
        fixture.write(path, value)

    def test_real_chain_and_rehashed_tamper_matrix(self):
        self.validate()
        public_bundle.publication_lineage_v2(
            handoff, self.root, fixture.read(self.root / "bundle.json"))
        large = {
            "artifacts/raw", "artifacts/qcow2", "artifacts/vhd",
            "state/unikraft.raw", "state/unikraft.qcow2",
            "state/unikraft.vhd", "state/unikraft-derived.vhd",
        }
        baseline = {
            path.relative_to(self.root).as_posix(): path.read_bytes()
            for path in self.root.rglob("*")
            if path.is_file()
            and path.relative_to(self.root).as_posix() not in large
        }
        with (self.root / "artifacts/vhd").open("rb") as stream:
            stream.seek(4096)
            vhd_byte = stream.read(1)
        cases = {
            "failed-qcow2": lambda: self.mutate_json(
                "boots/qcow2-x2apic/report",
                lambda value: value.update(passed=False)),
            "wrong-qcow2-mode": lambda: self.mutate_json(
                "boots/qcow2-x2apic/request",
                lambda value: value["config"]["source"].update(
                    kind="raw_disk")),
            "cached-qcow2-mode": self.cached_qcow2,
            "request-artifact-mismatch": lambda: self.mutate_json(
                "boots/qcow2-x2apic/request",
                lambda value: value["pins"].__setitem__(
                    0, fixture.pin(self.root / "artifacts/raw"))),
            "conversion-before-acceptance": lambda: self.mutate_json(
                "evidence/fixed-vhd-derivation-gate.json",
                lambda value: value.update(derived_output_absent=False)),
            "wrong-qcow2-input": lambda: self.mutate_json(
                "evidence/fixed-vhd-derivation.json",
                lambda value: (
                    value["accepted_qcow2"].update(sha256="b" * 64),
                    value["provenance"].update(parent_sha256="b" * 64),
                )),
            "substituted-vhd": self.substitute_vhd,
            "incomplete-vhd-modes": lambda: self.mutate_json(
                "evidence/final-inspection.json",
                lambda value: value["boots"].pop("vpc-legacy-apic")),
            "source-mismatch": lambda: self.mutate_json(
                "bundle.json",
                lambda value: value.update(source_revision="c" * 40)),
            "output-record-mismatch": lambda: self.mutate_json(
                "evidence/fixed-vhd-derivation.json",
                lambda value: value["output"].update(sha256="d" * 64)),
            "profile-downgrade": lambda: self.mutate_json(
                "bundle.json",
                lambda value: value.update(profile="tiny-aot-two-boot")),
        }
        for name, mutate in cases.items():
            with self.subTest(name=name):
                for relative, raw in baseline.items():
                    fixture.write(self.root / relative, raw)
                with (self.root / "artifacts/vhd").open("r+b") as stream:
                    stream.seek(4096)
                    stream.write(vhd_byte)
                mutate()
                fixture.seal(self.root)
                self.validate(status=1)
        with self.subTest(name="missing-qcow2-boot"):
            for relative, raw in baseline.items():
                fixture.write(self.root / relative, raw)
            bundle = fixture.read(self.root / "bundle.json")
            bundle["boots"].pop(2)
            fixture.write(self.root / "bundle.json", bundle)
            self.validate(status=1)

    def cached_qcow2(self):
        source = self.root / "boots/qcow2-x2apic"
        target = self.root / "boots/qcow2-legacy-apic"
        for name in ("serial", "request", "report", "compute"):
            shutil.copyfile(source / name, target / name)
            (target / name).chmod(0o600)

    def substitute_vhd(self):
        path = self.root / "artifacts/vhd"
        with path.open("r+b") as stream:
            stream.seek(4096)
            original = stream.read(1)
            stream.seek(4096)
            stream.write(bytes([original[0] ^ 1]))

    def test_candidate_binds_run_attempt_and_transport(self):
        bundle = fixture.read(self.root / "bundle.json")
        transport_path = self.root / "transport.json"
        fixture.write(transport_path, {
            "schema": "uk.wamr.public-source-transport",
            "version": 2,
            "repository": bundle["run"]["repository"],
            "run_id": bundle["run"]["run_id"],
            "run_attempt": bundle["run"]["run_attempt"],
            "source_revision": bundle["source_revision"],
            "source_tree": bundle["source_tree"],
            "inner_zip_sha256": "1" * 64,
            "artifact_id": "12345",
            "container_digest": "2" * 64,
        })
        output = self.root / "candidate.json"
        completed = subprocess.run([
            "python3", REPO / "support/build/wamr-native-ci/handoff.py",
            "plan", "--bundle", self.root / "bundle.json",
            "--output", output,
        ], env={"PYTHONDONTWRITEBYTECODE": "1"},
            capture_output=True, timeout=90)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.validate("candidate", output)

        transport = fixture.read(transport_path)
        transport["run_attempt"] = "2"
        fixture.write(transport_path, transport)
        scope = fixture.read(output)
        admission_path = Path(scope["bundle"]["path"])
        admission = fixture.read(admission_path)
        admission["transport"] = fixture.artifact(transport_path)
        fixture.write(admission_path, admission)
        scope["bundle"] = fixture.artifact(admission_path)
        fixture.write(output, scope)
        self.validate("candidate", output, status=1)


if __name__ == "__main__":
    unittest.main()
