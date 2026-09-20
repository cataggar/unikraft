# SPDX-License-Identifier: BSD-3-Clause
"""Version-2 direct admission and fully rehashed lineage refusals."""
import importlib.util
import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import sysconfig
import time
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
SUPERVISOR = Path(os.environ["WAMR_CI_SUPERVISOR"]).resolve(strict=True)


def remove_sealed_tree(path):
    if not path.exists():
        return
    for current, directories, _ in os.walk(path):
        Path(current).chmod(0o700)
        for name in directories:
            (Path(current) / name).chmod(0o700)
    shutil.rmtree(path)


class LineageV2(unittest.TestCase):
    def setUp(self):
        self.root = REPO / ".d" / ("v2-lineage-" + uuid.uuid4().hex)
        fixture.build(self.root, PACKAGE)
        self.addCleanup(remove_sealed_tree, self.root)
        self.azure_runtime_tools = None

    def runtime_tools(self, stem=""):
        if not stem and self.azure_runtime_tools is not None:
            return self.azure_runtime_tools
        prefix = stem + "-" if stem else ""
        source = self.root / (prefix + "azure-launcher-source")
        source.write_text(
            "#!/usr/bin/python3\n"
            "import os, sys\n"
            "for key in ('AZ_PYTHON', 'PYTHONPATH', 'PYTHONSTARTUP',"
            " 'PYTHONUSERBASE', 'LD_PRELOAD', 'LD_LIBRARY_PATH'):\n"
            " if key in os.environ: raise SystemExit(31)\n"
            "if os.environ.get('PYTHONDONTWRITEBYTECODE') != '1':"
            " raise SystemExit(32)\n"
            "extension_dir = os.environ.get('AZURE_EXTENSION_DIR', '')\n"
            "if (os.environ.get('AZURE_EXTENSION_USE_DYNAMIC_INSTALL') != 'no'"
            " or not os.path.isdir(extension_dir)"
            " or os.listdir(extension_dir)):\n"
            " raise SystemExit(34)\n"
            "if os.path.exists(os.path.join(os.environ['HOME'],"
            " 'expect-descriptor')) and not __file__.startswith("
            "'/proc/self/fd/'):\n"
            " raise SystemExit(33)\n"
            "if os.path.exists(os.path.join(os.environ['HOME'],"
            " 'expect-descriptor')):\n"
            " if not os.environ.get('PYTHONHOME', '').startswith("
            "'/proc/self/fd/'):\n"
            "  raise SystemExit(35)\n"
            " try:\n"
            "  open(__file__, 'ab').close()\n"
            " except OSError:\n"
            "  pass\n"
            " else:\n"
            "  raise SystemExit(36)\n"
            "if len(sys.argv) > 1 and sys.argv[1] == 'version':\n"
            " print('{\"azure-cli\":\"2.75.0\","
            "\"azure-cli-core\":\"2.75.0\","
            "\"azure-cli-telemetry\":\"1.1.0\",\"extensions\":{}}')\n"
            " raise SystemExit(0)\n"
            "if '--help' in sys.argv[1:]:\n"
            " raise SystemExit(0)\n"
            "path = os.path.join(os.environ['HOME'], 'backend-calls')\n"
            "fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)\n"
            "try:\n"
            " os.write(fd, (' '.join(sys.argv[1:]) + '\\n').encode())\n"
            "finally:\n"
            " os.close(fd)\n"
            "if sys.argv[1:3] == ['group', 'exists']:\n"
            " print('false')\n"
            " raise SystemExit(0)\n"
            "raise SystemExit(29)\n")
        source.chmod(0o700)
        version = f"python{sys.version_info.major}.{sys.version_info.minor}"
        stdlib = self.root / (prefix + "stdlib-source") / version
        stdlib.mkdir(parents=True, mode=0o700)
        shutil.copytree(
            Path(sysconfig.get_path("stdlib")) / "encodings",
            stdlib / "encodings")
        native = stdlib / "native-fixture.so"
        native_source = next(iter(sorted(
            Path(sysconfig.get_config_var("DESTSHARED")).glob("*.so"))))
        shutil.copyfile(native_source, native)
        native.chmod(0o600)
        loader_fixture = self.root / (prefix + "loader-fixture.so")
        shutil.copyfile(native_source, loader_fixture)
        loader_fixture.chmod(0o500)
        output = self.root / (prefix + "azure-runtime")
        handoff.prepare_azure_runtime(
            output, source, Path(sys.executable).resolve(strict=True), stdlib,
            native_dependencies=(loader_fixture,),
            validator=VALIDATOR)
        (self.root / "expect-descriptor").write_text("required\n")
        closure = fixture.read(output / "azure-runtime.json")
        result = dict(
            azure=Path(closure["launcher"]["path"]),
            uploader=VALIDATOR,
            validator=VALIDATOR,
            supervisor=SUPERVISOR,
            az_python=Path(closure["interpreter"]["path"]),
            azure_runtime=output / "azure-runtime.json",
        )
        if not stem:
            self.azure_runtime_tools = result
        return result

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

    def write_transport(self):
        bundle = fixture.read(self.root / "bundle.json")
        path = self.root / "transport.json"
        fixture.write(path, {
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
        return path

    def prepare_contract(self, maximum=100_000_000, decision="approved",
                         tools=None, stem="", ledger=None):
        self.write_transport()
        ledger = ledger or self.root / (stem + "ledger")
        ledger.mkdir(mode=0o700)
        paths = {
            "plan": self.root / (stem + "execution-plan.json"),
            "template": self.root / (stem + "approval-template.json"),
            "candidate": self.root / (stem + "candidate.json"),
            "authorization": self.root / (stem + "authorization.json"),
            "admission": self.root / (stem + "admission.json"),
        }
        tools = tools or self.runtime_tools()
        handoff.plan(
            self.root / "bundle.json", paths["plan"], paths["template"],
            paths["candidate"],
            campaign_id="cccccccc-cccc-4ccc-accc-cccccccccccc",
            ledger=ledger,
            subscription="bbbbbbbb-bbbb-4bbb-bbbb-bbbbbbbbbbbb",
            prefix="authorized-fixture",
            maximum_authorized_cost_microusd=maximum,
            attempt_id="aaaaaaaa-aaaa-4aaa-aaaa-aaaaaaaaaaaa",
            created_unix=int(time.time()), **tools)
        now = int(time.time())
        handoff.record_authorization(
            paths["plan"], paths["template"], paths["authorization"],
            decision=decision, approver="fixture-operator",
            reference="cataggar/unikraft#170-test",
            recorded_unix=now - 1, expires_unix=now + 600, **tools)
        if decision == "approved":
            handoff.admission(
                paths["plan"], paths["authorization"],
                paths["admission"], **tools)
        return paths, tools

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
        transport_path = self.write_transport()
        output = self.root / "candidate.json"
        completed = subprocess.run([
            "python3", REPO / "support/build/wamr-native-ci/handoff.py",
            "candidate", "--bundle", self.root / "bundle.json",
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

    def test_strict_plan_authorization_admission_and_canonical_cost(self):
        paths, _ = self.prepare_contract(maximum=10_000_000)
        self.validate("admission", paths["admission"])
        plan = fixture.read(paths["plan"])
        template = fixture.read(paths["template"])
        authorization = fixture.read(paths["authorization"])
        admission = fixture.read(paths["admission"])
        self.assertEqual(
            paths["plan"].read_bytes(),
            (json.dumps(plan, sort_keys=True, separators=(",", ":"))
             + "\n").encode())
        self.assertEqual(plan["version"], 2)
        self.assertEqual(plan["authority"], "not_admitted")
        self.assertEqual(plan["cost"], {
            "unit": "micro_usd",
            "policy":
                "northeurope-standard-d2s-v5-conservative-2026-09-v1",
            "estimated_upper_bound": 9_500_000,
            "maximum_authorized": 10_000_000,
            "repository_policy_maximum": 100_000_000,
        })
        self.assertEqual(
            template["plan_sha256"],
            hashlib.sha256(paths["plan"].read_bytes()).hexdigest())
        self.assertEqual(authorization["decision"], "approved")
        self.assertEqual(admission["authority"], "approved")
        self.assertEqual(admission["plan"]["sha256"],
                         template["plan_sha256"])
        self.assertEqual(plan["resources"]["boot_count"], 2)
        self.assertEqual(plan["resources"]["maximum_parallelism"], 1)
        self.assertEqual(plan["retry_count"], 0)
        self.assertFalse(any(plan["substitution"].values()))
        self.assertEqual(plan["ledger"]["campaign_id"], plan["campaign_id"])
        self.assertTrue(plan["ledger"]["initialization_required"])
        public = public_bundle.members(
            handoff, fixture.read(self.root / "bundle.json"), self.root)
        self.assertEqual(len(public) + 2, 85)
        for private_name in (
                "execution-plan.json", "approval-template.json",
                "authorization.json", "admission.json", "candidate.json"):
            self.assertNotIn(private_name, public)

    def test_fully_rehashed_plan_policy_tamper_matrix(self):
        paths, _ = self.prepare_contract()
        original_plan = paths["plan"].read_bytes()
        original_template = paths["template"].read_bytes()
        changes = {
            "region": lambda value: value.update(location="westus"),
            "sku": lambda value: value["resources"].update(
                os_disk_sku="Premium_LRS"),
            "vm-count": lambda value: value["resources"].update(
                vm_count=2),
            "disk": lambda value: value["resources"].update(
                os_disk_count=2),
            "data-disk": lambda value: value["resources"].update(
                data_disk_count=1),
            "generation": lambda value: value["resources"].update(
                generation=1),
            "disk-capacity": lambda value: value["resources"].update(
                os_disk_capacity_bytes=1),
            "network": lambda value: value["resources"].update(
                public_ip_count=1),
            "network-mode": lambda value: value["resources"].update(
                network="public"),
            "boots": lambda value: value["resources"].update(boot_count=1),
            "parallel": lambda value: value["resources"].update(
                maximum_parallelism=2),
            "retry": lambda value: value.update(retry_count=1),
            "substitution": lambda value: value["substitution"].update(
                image=True),
            "cleanup": lambda value: value["cleanup"].update(
                independent_absence_observation=False),
            "cleanup-ownership": lambda value: value["cleanup"].update(
                exact_owned_resources_only=False),
            "cleanup-delete": lambda value: value["cleanup"].update(
                delete_owned_resource_group=False),
            "cleanup-replacement": lambda value: value["cleanup"].update(
                replacement_resources=True),
            "estimate": lambda value: value["cost"].update(
                estimated_upper_bound=9_499_999),
            "cost-float": lambda value: value["cost"].update(
                estimated_upper_bound=9_500_000.0),
            "cost-negative": lambda value: value["cost"].update(
                estimated_upper_bound=-1),
            "cost-u64-overflow": lambda value: value["cost"].update(
                estimated_upper_bound=1 << 64),
            "cost-zero": lambda value: value["cost"].update(
                maximum_authorized=0),
            "maximum-below-estimate": lambda value: value["cost"].update(
                maximum_authorized=9_499_999),
            "maximum-over-policy": lambda value: value["cost"].update(
                maximum_authorized=100_000_001),
            "maximum-u64-overflow": lambda value: value["cost"].update(
                maximum_authorized=1 << 64),
            "runtime": lambda value: value.update(runtime_seconds=3599),
            "cleanup-time": lambda value: value.update(
                cleanup_seconds=1799),
            "operation-time": lambda value: value.update(
                operation_seconds=599),
            "poll-time": lambda value: value.update(poll_seconds=9),
            "attempt": lambda value: value.update(
                attempt_id="dddddddd-dddd-4ddd-addd-dddddddddddd"),
            "ledger-campaign": lambda value: value["ledger"].update(
                campaign_id="dddddddd-dddd-4ddd-addd-dddddddddddd"),
            "ledger-id": lambda value: value["ledger"].update(
                ledger_id="dddddddd-dddd-4ddd-addd-dddddddddddd"),
            "ledger-directory": lambda value: value["ledger"][
                "directory"].update(
                    inode=value["ledger"]["directory"]["inode"] + 1),
            "ledger-initialization": lambda value: value["ledger"].update(
                initialization_required=False),
            "ledger-pre-state": lambda value: value["ledger"].update(
                initial_state_sha256="e" * 64),
            "ledger-marker": lambda value: value["ledger"].update(
                marker_sha256="e" * 64),
            "source": lambda value: value.update(source_tree="e" * 40),
            "run-attempt": lambda value: value["run"].update(
                run_attempt="2"),
            "candidate-hash": lambda value: value["candidate"].update(
                sha256="e" * 64),
            "qcow2-hash": lambda value: value["qcow2"].update(
                sha256="e" * 64),
            "vhd-hash": lambda value: value["os_vhd"].update(
                sha256="e" * 64),
            "vhd-bytes": lambda value: value.update(
                vhd_bytes=value["vhd_bytes"] - 1),
            "vhd-capacity": lambda value: value.update(
                vhd_capacity_bytes=value["vhd_capacity_bytes"] - 1),
            "artifact-id": lambda value: value.update(artifact_id="54321"),
            "tool-hash": lambda value: value["tools"]["azure"].update(
                sha256="e" * 64),
            "runtime-content": lambda value: value[
                "azure_runtime"].update(content_sha256="e" * 64),
            "runtime-root": lambda value: value[
                "azure_runtime"].update(root="/unapproved/runtime"),
            "runtime-document": lambda value: value[
                "azure_runtime_document"].update(sha256="e" * 64),
            "unknown": lambda value: value.update(unexpected=True),
        }
        for name, change in changes.items():
            with self.subTest(name=name):
                paths["plan"].write_bytes(original_plan)
                paths["template"].write_bytes(original_template)
                plan = fixture.read(paths["plan"])
                change(plan)
                fixture.write(paths["plan"], plan)
                template = fixture.read(paths["template"])
                template["plan_sha256"] = hashlib.sha256(
                    paths["plan"].read_bytes()).hexdigest()
                if name in (
                        "estimate", "cost-negative", "cost-u64-overflow"):
                    template["estimated_cost_upper_bound_microusd"] = (
                        plan["cost"]["estimated_upper_bound"])
                if name.startswith("maximum-") or name == "cost-zero":
                    template["maximum_authorized_cost_microusd"] = (
                        plan["cost"]["maximum_authorized"])
                if name == "runtime":
                    template["limits"]["runtime_seconds"] = 3599
                if name == "cleanup-time":
                    template["limits"]["cleanup_seconds"] = 1799
                if name == "operation-time":
                    template["limits"]["operation_seconds"] = 599
                if name == "attempt":
                    template["attempt_id"] = plan["attempt_id"]
                if name == "candidate-hash":
                    template["candidate_sha256"] = (
                        plan["candidate"]["sha256"])
                fixture.write(paths["template"], template)
                completed = subprocess.run(
                    [VALIDATOR, "plan", paths["plan"], paths["template"]],
                    env={}, capture_output=True, timeout=90)
                self.assertNotEqual(completed.returncode, 0)

    def test_approval_replay_denial_expiry_and_unknown_fields_refuse(self):
        paths, tools = self.prepare_contract()
        original = paths["authorization"].read_bytes()
        cases = {
            "wrong-plan": lambda value: value.update(plan_sha256="f" * 64),
            "wrong-attempt": lambda value: value.update(
                attempt_id="dddddddd-dddd-4ddd-addd-dddddddddddd"),
            "wrong-candidate": lambda value: value.update(
                candidate_sha256="e" * 64),
            "wrong-cost": lambda value: value.update(
                maximum_authorized_cost_microusd=99_999_999),
            "wrong-limits": lambda value: value["limits"].update(
                boot_count=1),
            "wrong-runtime": lambda value: value[
                "azure_runtime"].update(content_sha256="e" * 64),
            "wrong-approver": lambda value: value.update(approver=""),
            "wrong-reference": lambda value: value.update(reference="x" * 257),
            "missing-reference": lambda value: value.pop("reference"),
            "future": lambda value: value.update(
                recorded_unix=int(time.time()) + 60,
                expires_unix=int(time.time()) + 600),
            "expired": lambda value: value.update(
                recorded_unix=int(time.time()) - 600,
                expires_unix=int(time.time()) - 1),
            "reversed-window": lambda value: value.update(
                recorded_unix=int(time.time()),
                expires_unix=int(time.time()) - 1),
            "oversized-window": lambda value: value.update(
                recorded_unix=int(time.time()) - 1,
                expires_unix=int(time.time()) + 3601),
            "time-u64-overflow": lambda value: value.update(
                recorded_unix=1 << 64, expires_unix=(1 << 64) + 1),
            "unknown": lambda value: value.update(unexpected=True),
        }
        for name, change in cases.items():
            with self.subTest(name=name):
                value = json.loads(original)
                change(value)
                fixture.write(paths["authorization"], value)
                completed = subprocess.run(
                    [VALIDATOR, "authorization", paths["plan"],
                     paths["authorization"]],
                    env={}, capture_output=True, timeout=90)
                self.assertNotEqual(completed.returncode, 0)
        paths["authorization"].write_bytes(
            original.replace(
                b'"decision":"approved"',
                b'"decision":"approved","decision":"approved"', 1))
        duplicate = subprocess.run(
            [VALIDATOR, "authorization", paths["plan"],
             paths["authorization"]],
            env={}, capture_output=True, timeout=90)
        self.assertNotEqual(duplicate.returncode, 0)
        paths["authorization"].write_text(
            json.dumps(json.loads(original), indent=2) + "\n")
        noncanonical = subprocess.run(
            [VALIDATOR, "authorization", paths["plan"],
             paths["authorization"]],
            env={}, capture_output=True, timeout=90)
        self.assertNotEqual(noncanonical.returncode, 0)
        paths["authorization"].write_bytes(original)
        original_template = paths["template"].read_bytes()
        for name, change in {
                "unknown": lambda value: value.update(unexpected=True),
                "wrong-runtime": lambda value: value[
                    "azure_runtime"].update(content_sha256="e" * 64),
        }.items():
            with self.subTest(template=name):
                template = json.loads(original_template)
                change(template)
                fixture.write(paths["template"], template)
                output = self.root / (
                    name + "-template-authorization.json")
                with self.assertRaises(ValueError):
                    handoff.record_authorization(
                        paths["plan"], paths["template"], output,
                        decision="approved", approver="fixture-operator",
                        reference="cataggar/unikraft#170-template",
                        recorded_unix=int(time.time()) - 1,
                        expires_unix=int(time.time()) + 600, **tools)
                self.assertFalse(output.exists())
        paths["template"].write_bytes(original_template)
        original_plan = paths["plan"].read_bytes()
        for name, change in {
                "campaign-replay": lambda value: value.update(
                    campaign_id="dddddddd-dddd-4ddd-addd-dddddddddddd"),
                "source-replay": lambda value: value.update(
                    source_tree="e" * 40),
                "image-replay": lambda value: value["os_vhd"].update(
                    sha256="e" * 64),
                "cost-replay": lambda value: value["cost"].update(
                    maximum_authorized=99_999_999),
        }.items():
            with self.subTest(name=name):
                plan = json.loads(original_plan)
                change(plan)
                fixture.write(paths["plan"], plan)
                replay = subprocess.run(
                    [VALIDATOR, "authorization", paths["plan"],
                     paths["authorization"]],
                    env={}, capture_output=True, timeout=90)
                self.assertNotEqual(replay.returncode, 0)
        paths["plan"].write_bytes(original_plan)
        denied = self.root / "denied.json"
        now = int(time.time())
        handoff.record_authorization(
            paths["plan"], paths["template"], denied,
            decision="denied", approver="fixture-operator",
            reference="cataggar/unikraft#170-denied",
            recorded_unix=now - 1, expires_unix=now + 600, **tools)
        with self.assertRaises(ValueError):
            handoff.admission(
                paths["plan"], denied, self.root / "denied-admission.json",
                **tools)
        self.assertFalse((self.root / "denied-admission.json").exists())
        self.assertEqual(list((self.root / "ledger").iterdir()), [])

    def test_legacy_candidate_cannot_act_as_authorization(self):
        self.write_transport()
        candidate = self.root / "legacy-candidate.json"
        handoff.candidate_plan(self.root / "bundle.json", candidate)
        completed = subprocess.run(
            [VALIDATOR, "admission", candidate],
            env={}, capture_output=True, timeout=90)
        self.assertNotEqual(completed.returncode, 0)

    def test_wrong_runtime_closure_in_admission_refuses(self):
        paths, _ = self.prepare_contract()
        original = paths["admission"].read_bytes()
        changes = {
            "content": lambda value: value["azure_runtime"].update(
                content_sha256="e" * 64),
            "metadata": lambda value: value["azure_runtime"].update(
                metadata_sha256="e" * 64),
            "document": lambda value: value[
                "azure_runtime_document"].update(sha256="e" * 64),
            "launcher": lambda value: value["azure_runtime"][
                "launcher"].update(sha256="e" * 64),
            "interpreter": lambda value: value["azure_runtime"][
                "interpreter"].update(sha256="e" * 64),
        }
        for name, mutate in changes.items():
            with self.subTest(name=name):
                admission = json.loads(original)
                mutate(admission)
                fixture.write(paths["admission"], admission)
                self.validate("admission", paths["admission"], status=1)

    def test_fresh_subprocess_cli_requires_explicit_bound_tools(self):
        self.write_transport()
        ledger = self.root / "cli-ledger"
        ledger.mkdir(mode=0o700)
        paths = {
            name: self.root / ("cli-" + name + ".json")
            for name in (
                "plan", "template", "candidate", "authorization",
                "admission")
        }
        tools = self.runtime_tools()
        tool_args = [
            "--azure", tools["azure"],
            "--uploader", tools["uploader"],
            "--validator", tools["validator"],
            "--supervisor", tools["supervisor"],
            "--az-python", tools["az_python"],
            "--azure-runtime", tools["azure_runtime"],
        ]
        commands = [[
            "plan",
            "--bundle", self.root / "bundle.json",
            "--output", paths["plan"],
            "--approval-template", paths["template"],
            "--candidate-output", paths["candidate"],
            "--campaign-id", "cccccccc-cccc-4ccc-accc-cccccccccccc",
            "--ledger", ledger,
            "--subscription", "bbbbbbbb-bbbb-4bbb-bbbb-bbbbbbbbbbbb",
            "--prefix", "authorized-cli-fixture",
            "--maximum-authorized-cost-microusd", "10000000",
            *tool_args,
        ]]
        now = int(time.time())
        commands.append([
            "record-authorization",
            "--plan", paths["plan"],
            "--template", paths["template"],
            "--output", paths["authorization"],
            "--decision", "approved",
            "--approver", "fixture-operator",
            "--reference", "cataggar/unikraft#170-cli",
            "--recorded-unix", str(now - 1),
            "--expires-unix", str(now + 600),
            *tool_args,
        ])
        commands.append([
            "admit",
            "--plan", paths["plan"],
            "--authorization", paths["authorization"],
            "--output", paths["admission"],
            *tool_args,
        ])
        script = REPO / "support/build/wamr-native-ci/handoff.py"
        for command in commands:
            completed = subprocess.run(
                [sys.executable, script, *map(str, command)],
                env={"PYTHONDONTWRITEBYTECODE": "1"},
                capture_output=True, timeout=90)
            self.assertEqual(completed.returncode, 0, completed.stderr)
        self.validate("admission", paths["admission"])

    def backend_tools(self):
        calls = self.root / "backend-calls"
        return calls, self.runtime_tools()

    def blocking_backend_tools(self):
        calls = self.root / "backend-calls"
        ready = self.root / "blocking-backend-ready"
        release = self.root / "blocking-backend-release"
        return calls, ready, release, self.runtime_tools()

    def controller_command(self, paths, tools, attempt, ledger=None):
        return [
            TOOLS / "uk-wamr-direct-compute", paths["admission"], attempt,
            ledger or self.root / "ledger", tools["azure"],
            tools["uploader"], tools["validator"], tools["supervisor"],
            "--az-python", tools["az_python"],
            "--azure-runtime", tools["azure_runtime"],
        ]

    def wait_for(self, path, process, timeout=30):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if path.exists():
                return
            if process.poll() is not None:
                stdout, stderr = process.communicate()
                self.fail(
                    f"controller exited before phase gate: "
                    f"{process.returncode} {stdout!r} {stderr!r}")
            time.sleep(0.01)
        process.kill()
        process.wait()
        self.fail("controller phase gate timed out")

    def release_gate(self, path):
        descriptor = os.open(
            path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            os.write(descriptor, b"release\n")
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def run_blocked_controller(self, paths, tools, attempt, ready, release,
                               mutate, ledger=None):
        ready.unlink(missing_ok=True)
        release.unlink(missing_ok=True)
        command = self.controller_command(
            paths, tools, attempt, ledger)
        command[0] = (
            TOOLS / "wamr-direct-authorization-controller-fixture")
        process = subprocess.Popen(
            command,
            env={
                "HOME": str(self.root),
                "UK_WAMR_AUTHORIZATION_GATE_READY": str(ready),
                "UK_WAMR_AUTHORIZATION_GATE_RELEASE": str(release),
            },
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.wait_for(ready, process)
        mutate()
        self.release_gate(release)
        stdout, stderr = process.communicate(timeout=60)
        return process.returncode, stdout, stderr

    def ledger_claims(self, ledger=None):
        ledger = ledger or self.root / "ledger"
        return {
            path.name for path in ledger.iterdir()
            if path.name.startswith(("attempt-", "compute-", "sha256-"))
        }

    def marker_value(self, plan):
        ledger = plan["ledger"]
        return {
            "schema": "uk.wamr.azure-campaign-ledger-identity",
            "version": 1,
            "purpose": "qcow2-derived-vhd-two-boot",
            "campaign_id": ledger["campaign_id"],
            "ledger_id": ledger["ledger_id"],
            "state": "initialized",
            "migration": "authorized_legacy_state",
            "initial_state_sha256": ledger["initial_state_sha256"],
        }

    def test_controller_consumes_exactly_once_only_after_complete_admission(self):
        calls, tools = self.backend_tools()
        paths, _ = self.prepare_contract(tools=tools)
        attempt = self.root / "approved-attempt"
        completed = subprocess.run([
            TOOLS / "uk-wamr-direct-compute", paths["admission"],
            attempt, self.root / "ledger", tools["azure"],
            tools["uploader"], tools["validator"], tools["supervisor"],
            "--az-python", tools["az_python"],
            "--azure-runtime", tools["azure_runtime"],
        ], env={"HOME": str(self.root)}, capture_output=True, timeout=90)
        self.assertNotEqual(completed.returncode, 0)
        self.assertTrue(attempt.is_dir())
        ledger_names = {
            path.name for path in (self.root / "ledger").iterdir()
            if not path.name.startswith(".")
        }
        plan = fixture.read(paths["plan"])
        self.assertEqual(ledger_names, {
            "ledger-identity.json",
            "ledger-identity.initialized",
            "attempt-" + plan["attempt_id"],
            "compute-" + plan["source_tree"],
            "sha256-" + plan["os_vhd"]["sha256"],
        })
        self.assertIn("group exists", calls.read_text())
        before = calls.read_bytes()
        retried = subprocess.run([
            TOOLS / "uk-wamr-direct-compute", paths["admission"],
            self.root / "retry-attempt", self.root / "ledger",
            tools["azure"], tools["uploader"], tools["validator"],
            tools["supervisor"], "--az-python", tools["az_python"],
            "--azure-runtime", tools["azure_runtime"],
        ], env={"HOME": str(self.root)}, capture_output=True, timeout=30)
        self.assertNotEqual(retried.returncode, 0)
        self.assertFalse((self.root / "retry-attempt").exists())
        self.assertEqual(calls.read_bytes(), before)

    def test_pinned_admission_scope_marker_and_tool_swaps_refuse_before_claim(self):
        calls, ready, release, tools = self.blocking_backend_tools()
        paths, _ = self.prepare_contract(tools=tools)
        marker = self.root / "ledger/ledger-identity.json"

        def execute(name, mutate, restore):
            with self.subTest(name=name):
                attempt = self.root / (name + "-attempt")
                try:
                    status, _, _ = self.run_blocked_controller(
                        paths, tools, attempt, ready, release, mutate)
                finally:
                    restore()
                self.assertNotEqual(status, 0)
                self.assertEqual(self.ledger_claims(), set())
                self.assertEqual(list((self.root / "ledger").iterdir()), [])
                self.assertFalse(calls.exists())

        execute(
            "admission-inode-swap",
            lambda: (
                paths["admission"].rename(
                    paths["admission"].with_suffix(".retained")),
                paths["admission"].write_bytes(
                    paths["admission"].with_suffix(".retained").read_bytes()),
                paths["admission"].chmod(0o600),
            ),
            lambda: (
                paths["admission"].unlink(missing_ok=True),
                paths["admission"].with_suffix(".retained").rename(
                    paths["admission"]),
            ),
        )
        execute(
            "admission-path-removed",
            lambda: paths["admission"].rename(
                paths["admission"].with_suffix(".retained")),
            lambda: paths["admission"].with_suffix(".retained").rename(
                paths["admission"]),
        )
        execute(
            "stored-scope-tamper",
            lambda: (self.root / "stored-scope-tamper-attempt/scope.json")
            .write_bytes(b"{}\n"),
            lambda: None,
        )
        execute(
            "marker-concurrent-replacement",
            lambda: (
                marker.write_bytes(b"{}\n"),
                marker.chmod(0o600),
            ),
            lambda: marker.unlink(missing_ok=True),
        )

    def test_azure_runtime_tamper_after_admission_refuses_before_claim(self):
        def make_writable(path):
            path.parent.chmod(0o700)
            path.chmod(0o700 if path.is_dir() else 0o600)

        def replace_same_content(path):
            original = path.read_bytes()
            mode = stat.S_IMODE(path.stat().st_mode)
            path.parent.chmod(0o700)
            path.rename(path.with_name(path.name + ".retained"))
            path.write_bytes(original)
            path.chmod(mode)

        cases = {
            "launcher-same-content-inode": lambda value: replace_same_content(
                value["launcher"]),
            "interpreter-same-content-inode": lambda value: replace_same_content(
                value["interpreter"]),
            "launcher-path-removed": lambda value: (
                value["launcher"].parent.chmod(0o700),
                value["launcher"].rename(
                    value["launcher"].with_name("azure-cli.removed")),
            ),
            "launcher-mode": lambda value: value["launcher"].chmod(0o700),
            "runtime-parent-mode": lambda value: value["root"].parent.chmod(
                0o770),
            "module-content": lambda value: (
                make_writable(value["module"]),
                value["module"].write_bytes(
                    value["module"].read_bytes() + b"\n# changed\n"),
            ),
            "module-directory-mode": lambda value: value[
                "module"].parent.chmod(0o700),
            "module-added": lambda value: (
                value["module"].parent.chmod(0o700),
                value["module"].with_name("injected.py").write_text(
                    "raise RuntimeError('unapproved')\n"),
            ),
            "extension-added": lambda value: (
                value["extensions"].chmod(0o700),
                (value["extensions"] / "unapproved.py").write_text(
                    "raise RuntimeError('unapproved extension')\n"),
            ),
            "module-removed": lambda value: (
                value["module"].parent.chmod(0o700),
                value["module"].rename(
                    value["module"].with_name("__init__.py.removed")),
            ),
            "module-symlink": lambda value: (
                value["module"].parent.chmod(0o700),
                value["module"].rename(
                    value["module"].with_name("__init__.py.retained")),
                value["module"].symlink_to("__init__.py.retained"),
            ),
            "module-hardlink": lambda value: (
                value["module"].parent.chmod(0o700),
                os.link(
                    value["module"],
                    value["module"].with_name("__init__.py.link")),
            ),
            "native-extension": lambda value: (
                make_writable(value["native"]),
                value["native"].write_bytes(b"changed native extension\n"),
            ),
            "loader-dependency": lambda value: (
                value["loader"].chmod(0o700),
                value["loader"].write_bytes(b"changed loader dependency\n"),
            ),
            "manifest-same-content-inode": lambda value: replace_same_content(
                value["manifest"]),
        }
        for index, (name, mutate) in enumerate(cases.items()):
            with self.subTest(name=name):
                stem = f"runtime-{index}"
                tools = self.runtime_tools(stem)
                paths, _ = self.prepare_contract(
                    tools=tools, stem=stem + "-")
                closure = fixture.read(tools["azure_runtime"])
                python_root = (
                    Path(closure["root"]) / "lib"
                    / ("python" + closure["python_version"]))
                values = {
                    "root": Path(closure["root"]),
                    "launcher": Path(closure["launcher"]["path"]),
                    "interpreter": Path(closure["interpreter"]["path"]),
                    "manifest": Path(closure["manifest"]["path"]),
                    "extensions": Path(closure["extensions"]),
                    "module": python_root / "encodings/__init__.py",
                    "native": python_root / "native-fixture.so",
                    "loader": next(
                        Path(item["path"])
                        for item in closure["loader_dependencies"]
                        if Path(item["path"]).name.endswith(
                            "loader-fixture.so")),
                }
                calls = self.root / "backend-calls"
                ready = self.root / "blocking-backend-ready"
                release = self.root / "blocking-backend-release"
                status, _, _ = self.run_blocked_controller(
                    paths,
                    tools,
                    self.root / (stem + "-attempt"),
                    ready,
                    release,
                    lambda: mutate(values),
                    ledger=self.root / (stem + "-ledger"),
                )
                self.assertNotEqual(status, 0)
                self.assertEqual(
                    self.ledger_claims(self.root / (stem + "-ledger")),
                    set())
                self.assertEqual(
                    list((self.root / (stem + "-ledger")).iterdir()), [])
                self.assertFalse(calls.exists())

    def test_azure_runtime_tamper_precedes_attempt_ledger_and_backend(self):
        tools = self.runtime_tools("preadmission-runtime")
        ledger = self.root / "preadmission-ledger"
        paths, _ = self.prepare_contract(
            tools=tools, stem="preadmission-", ledger=ledger)
        closure = fixture.read(tools["azure_runtime"])
        module = (
            Path(closure["root"]) / "lib"
            / ("python" + closure["python_version"])
            / "encodings/__init__.py")
        module.parent.chmod(0o700)
        module.chmod(0o600)
        module.write_bytes(module.read_bytes() + b"\n# pre-admission tamper\n")
        attempt = self.root / "preadmission-attempt"
        completed = subprocess.run(
            self.controller_command(paths, tools, attempt, ledger=ledger),
            env={"HOME": str(self.root)},
            capture_output=True,
            timeout=30)
        self.assertNotEqual(completed.returncode, 0)
        self.assertFalse(attempt.exists())
        self.assertEqual(list(ledger.iterdir()), [])
        self.assertFalse((self.root / "backend-calls").exists())

    def test_ledger_identity_migration_replacements_and_retained_directory(self):
        calls, ready, release, tools = self.blocking_backend_tools()
        paths, _ = self.prepare_contract(tools=tools)
        plan = fixture.read(paths["plan"])
        ledger = self.root / "ledger"

        stale_paths, _ = self.prepare_contract(
            tools=tools, stem="stale-")
        stale_ledger = self.root / "stale-ledger"
        stale = stale_ledger / "stale"
        stale.write_text("changed\n")
        stale.chmod(0o600)
        stale_attempt = self.root / "stale-ledger-attempt"
        stale_run = subprocess.run(
            self.controller_command(
                stale_paths, tools, stale_attempt, ledger=stale_ledger),
            env={"HOME": str(self.root)}, capture_output=True, timeout=30)
        self.assertNotEqual(stale_run.returncode, 0)
        self.assertFalse(stale_attempt.exists())
        self.assertFalse(
            (stale_ledger / "ledger-identity.json").exists())
        self.assertFalse(calls.exists())

        replacement_paths, _ = self.prepare_contract(
            tools=tools, stem="replacement-")
        replacement_ledger = self.root / "replacement-ledger"
        retained_empty = self.root / "planned-ledger"
        replacement_ledger.rename(retained_empty)
        replacement_ledger.mkdir(mode=0o700)
        replacement_attempt = self.root / "replacement-ledger-attempt"
        replacement = subprocess.run(
            self.controller_command(
                replacement_paths, tools, replacement_attempt,
                ledger=replacement_ledger),
            env={"HOME": str(self.root)}, capture_output=True, timeout=30)
        self.assertNotEqual(replacement.returncode, 0)
        self.assertFalse(replacement_attempt.exists())
        self.assertEqual(list(replacement_ledger.iterdir()), [])

        wrong_paths, _ = self.prepare_contract(
            tools=tools, stem="wrong-")
        wrong_ledger = self.root / "wrong-ledger"
        wrong_plan = fixture.read(wrong_paths["plan"])
        wrong_marker = self.marker_value(wrong_plan)
        wrong_marker["campaign_id"] = (
            "dddddddd-dddd-4ddd-addd-dddddddddddd")
        fixture.write(
            wrong_ledger / "ledger-identity.json", wrong_marker)
        wrong = subprocess.run(
            self.controller_command(
                wrong_paths, tools, self.root / "wrong-marker-attempt",
                ledger=wrong_ledger),
            env={"HOME": str(self.root)}, capture_output=True, timeout=30)
        self.assertNotEqual(wrong.returncode, 0)
        self.assertFalse((self.root / "wrong-marker-attempt").exists())

        wrong_id_paths, _ = self.prepare_contract(
            tools=tools, stem="wrong-id-")
        wrong_id_ledger = self.root / "wrong-id-ledger"
        wrong_id_marker = self.marker_value(
            fixture.read(wrong_id_paths["plan"]))
        wrong_id_marker["ledger_id"] = (
            "dddddddd-dddd-4ddd-addd-dddddddddddd")
        fixture.write(
            wrong_id_ledger / "ledger-identity.json", wrong_id_marker)
        wrong_id = subprocess.run(
            self.controller_command(
                wrong_id_paths, tools,
                self.root / "wrong-ledger-id-attempt",
                ledger=wrong_id_ledger),
            env={"HOME": str(self.root)}, capture_output=True, timeout=30)
        self.assertNotEqual(wrong_id.returncode, 0)
        self.assertFalse(
            (self.root / "wrong-ledger-id-attempt").exists())

        marker_attempt = self.root / "concurrent-marker-attempt"

        def concurrent_marker():
            fixture.write(
                ledger / "ledger-identity.json",
                self.marker_value(plan))
            (ledger / "ledger-identity.initialized").mkdir(mode=0o700)
            paths["admission"].chmod(0o400)

        status, _, _ = self.run_blocked_controller(
            paths, tools, marker_attempt, ready, release,
            concurrent_marker)
        paths["admission"].chmod(0o600)
        self.assertNotEqual(status, 0)
        self.assertTrue(marker_attempt.is_dir())
        self.assertEqual(self.ledger_claims(), set())
        self.assertEqual(
            hashlib.sha256(
                (ledger / "ledger-identity.json").read_bytes()).hexdigest(),
            plan["ledger"]["marker_sha256"])

        ready.unlink(missing_ok=True)
        release.unlink(missing_ok=True)
        retained = self.root / "retained-ledger"
        retained_attempt = self.root / "retained-directory-attempt"
        retained_command = self.controller_command(
            paths, tools, retained_attempt)
        retained_command[0] = (
            TOOLS / "wamr-direct-authorization-controller-fixture")
        process = subprocess.Popen(
            retained_command,
            env={
                "HOME": str(self.root),
                "UK_WAMR_AUTHORIZATION_GATE_READY": str(ready),
                "UK_WAMR_AUTHORIZATION_GATE_RELEASE": str(release),
            },
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.wait_for(ready, process)
        ledger.rename(retained)
        ledger.mkdir(mode=0o700)
        self.release_gate(release)
        retained_stdout, retained_stderr = process.communicate(timeout=60)
        self.assertNotEqual(process.returncode, 0)
        self.assertEqual(list(ledger.iterdir()), [])
        self.assertEqual(
            len(self.ledger_claims(retained)), 3,
            (retained_stdout, retained_stderr,
             (retained_attempt / "driver.stderr").read_text(),
             {
                 path.name: path.read_text()
                 for path in retained_attempt.glob("*.stderr")
             }))
        self.assertTrue(
            calls.exists(),
            (retained_stdout, retained_stderr,
             (retained_attempt / "driver.stderr").read_text(),
             sorted(path.name for path in retained_attempt.iterdir())))

        future = {
            name: self.root / ("future-" + name + ".json")
            for name in (
                "plan", "template", "candidate", "authorization",
                "admission")
        }
        handoff.plan(
            self.root / "bundle.json", future["plan"], future["template"],
            future["candidate"], campaign_id=plan["campaign_id"],
            ledger=retained,
            subscription="bbbbbbbb-bbbb-4bbb-bbbb-bbbbbbbbbbbb",
            prefix="future-authorized-fixture",
            maximum_authorized_cost_microusd=10_000_000,
            azure=tools["azure"], uploader=tools["uploader"],
            validator=tools["validator"], supervisor=tools["supervisor"],
            az_python=tools["az_python"],
            azure_runtime=tools["azure_runtime"],
            attempt_id="dddddddd-dddd-4ddd-addd-dddddddddddd",
            created_unix=int(time.time()))
        future_plan = fixture.read(future["plan"])
        self.assertFalse(
            future_plan["ledger"]["initialization_required"])
        self.assertEqual(
            future_plan["ledger"]["ledger_id"],
            plan["ledger"]["ledger_id"])
        now = int(time.time())
        handoff.record_authorization(
            future["plan"], future["template"], future["authorization"],
            decision="approved", approver="fixture-operator",
            reference="cataggar/unikraft#170-future",
            recorded_unix=now - 1, expires_unix=now + 600, **tools)
        handoff.admission(
            future["plan"], future["authorization"],
            future["admission"], **tools)
        (retained / "ledger-identity.json").unlink()
        calls_before = calls.read_bytes()
        missing_attempt = self.root / "missing-initialized-marker-attempt"
        missing = subprocess.run(
            self.controller_command(
                future, tools, missing_attempt, ledger=retained),
            env={"HOME": str(self.root)}, capture_output=True, timeout=30)
        self.assertNotEqual(missing.returncode, 0)
        self.assertFalse(missing_attempt.exists())
        self.assertFalse((retained / "ledger-identity.json").exists())
        self.assertTrue(
            (retained / "ledger-identity.initialized").is_dir())
        self.assertEqual(calls.read_bytes(), calls_before)

    def test_malformed_authorization_has_zero_ledger_backend_and_attempt_calls(self):
        calls, tools = self.backend_tools()
        paths, _ = self.prepare_contract(tools=tools)
        original_authorization = paths["authorization"].read_bytes()
        original_admission = paths["admission"].read_bytes()
        now = int(time.time())
        changes = {
            "malformed": b"{",
            "stale": dict(recorded_unix=now - 600, expires_unix=now - 1),
            "wrong-plan": dict(plan_sha256="f" * 64),
            "wrong-attempt": dict(
                attempt_id="dddddddd-dddd-4ddd-addd-dddddddddddd"),
            "wrong-cost": dict(
                maximum_authorized_cost_microusd=99_999_999),
        }
        for name, change in changes.items():
            with self.subTest(name=name):
                paths["authorization"].write_bytes(original_authorization)
                paths["admission"].write_bytes(original_admission)
                if isinstance(change, bytes):
                    paths["authorization"].write_bytes(change)
                else:
                    authorization = json.loads(original_authorization)
                    authorization.update(change)
                    fixture.write(paths["authorization"], authorization)
                admission = json.loads(original_admission)
                admission["authorization"] = fixture.pin(
                    paths["authorization"])
                fixture.write(paths["admission"], admission)
                attempt = self.root / (name + "-attempt")
                completed = subprocess.run([
                    TOOLS / "uk-wamr-direct-compute", paths["admission"],
                    attempt, self.root / "ledger", tools["azure"],
                    tools["uploader"], tools["validator"],
                    tools["supervisor"], "--az-python",
                    tools["az_python"],
                    "--azure-runtime", tools["azure_runtime"],
                ], env={
                    "HOME": str(self.root),
                    "AZ_PYTHON": "/ambient/refused",
                    "PATH": "/ambient/refused",
                }, capture_output=True, timeout=30)
                self.assertNotEqual(completed.returncode, 0)
                self.assertFalse(attempt.exists())
                self.assertEqual(
                    list((self.root / "ledger").iterdir()), [])
                self.assertFalse(calls.exists())
        paths["authorization"].write_bytes(original_authorization)
        paths["admission"].write_bytes(original_admission)
        missing = paths["authorization"].with_name("missing-authorization.json")
        admission = json.loads(original_admission)
        admission["authorization"]["path"] = str(missing)
        fixture.write(paths["admission"], admission)
        missing_attempt = self.root / "missing-attempt"
        completed = subprocess.run([
            TOOLS / "uk-wamr-direct-compute", paths["admission"],
            missing_attempt, self.root / "ledger", tools["azure"],
            tools["uploader"], tools["validator"], tools["supervisor"],
            "--az-python", tools["az_python"],
            "--azure-runtime", tools["azure_runtime"],
        ], env={"HOME": str(self.root)}, capture_output=True, timeout=30)
        self.assertNotEqual(completed.returncode, 0)
        self.assertFalse(missing_attempt.exists())
        self.assertEqual(list((self.root / "ledger").iterdir()), [])
        self.assertFalse(calls.exists())
        paths["admission"].write_bytes(original_admission)
        omitted = subprocess.run([
            TOOLS / "uk-wamr-direct-compute", paths["admission"],
            self.root / "omitted-attempt", self.root / "ledger",
            tools["azure"], tools["uploader"], tools["validator"],
        ], env={
            "HOME": str(self.root),
            "WAMR_CI_SUPERVISOR": str(tools["supervisor"]),
            "AZ_PYTHON": str(tools["az_python"]),
        }, capture_output=True, timeout=30)
        self.assertNotEqual(omitted.returncode, 0)
        self.assertFalse((self.root / "omitted-attempt").exists())
        ambient_admission = self.root / "ambient-admission.json"
        ambient = subprocess.run([
            "python3", REPO / "support/build/wamr-native-ci/handoff.py",
            "admit", "--plan", paths["plan"],
            "--authorization", paths["authorization"],
            "--output", ambient_admission,
            "--azure", tools["azure"], "--uploader", tools["uploader"],
            "--validator", tools["validator"],
            "--az-python", tools["az_python"],
        ], env={
            "PYTHONDONTWRITEBYTECODE": "1",
            "WAMR_CI_SUPERVISOR": str(tools["supervisor"]),
        }, capture_output=True, timeout=30)
        self.assertNotEqual(ambient.returncode, 0)
        self.assertFalse(ambient_admission.exists())


if __name__ == "__main__":
    unittest.main()
