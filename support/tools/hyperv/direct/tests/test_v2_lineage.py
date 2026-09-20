# SPDX-License-Identifier: BSD-3-Clause
"""Version-2 direct admission and fully rehashed lineage refusals."""
import importlib.util
import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
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
                         tools=None):
        self.write_transport()
        ledger = self.root / "ledger"
        ledger.mkdir(mode=0o700)
        paths = {
            "plan": self.root / "execution-plan.json",
            "template": self.root / "approval-template.json",
            "candidate": self.root / "candidate.json",
            "authorization": self.root / "authorization.json",
            "admission": self.root / "admission.json",
        }
        tools = tools or dict(
            azure=VALIDATOR, uploader=VALIDATOR, validator=VALIDATOR,
            supervisor=SUPERVISOR, az_python=VALIDATOR)
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
        self.assertEqual(plan["version"], 1)
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
        template = json.loads(original_template)
        template["unexpected"] = True
        fixture.write(paths["template"], template)
        with self.assertRaises(ValueError):
            handoff.record_authorization(
                paths["plan"], paths["template"],
                self.root / "unknown-template-authorization.json",
                decision="approved", approver="fixture-operator",
                reference="cataggar/unikraft#170-template",
                recorded_unix=int(time.time()) - 1,
                expires_unix=int(time.time()) + 600, **tools)
        self.assertFalse(
            (self.root / "unknown-template-authorization.json").exists())
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

    def test_legacy_candidate_cannot_act_as_authorization(self):
        self.write_transport()
        candidate = self.root / "legacy-candidate.json"
        handoff.candidate_plan(self.root / "bundle.json", candidate)
        completed = subprocess.run(
            [VALIDATOR, "admission", candidate],
            env={}, capture_output=True, timeout=90)
        self.assertNotEqual(completed.returncode, 0)

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
        tool_args = [
            "--azure", VALIDATOR,
            "--uploader", VALIDATOR,
            "--validator", VALIDATOR,
            "--supervisor", SUPERVISOR,
            "--az-python", VALIDATOR,
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
        backend = self.root / "explicit-azure-fixture"
        backend.write_text(
            "#!/usr/bin/python3\n"
            "import json, pathlib, sys\n"
            f"calls = pathlib.Path({str(calls)!r})\n"
            "if len(sys.argv) > 1 and sys.argv[1] == 'version':\n"
            "    print(json.dumps({'azure-cli':'2.75.0',"
            "'azure-cli-core':'2.75.0','azure-cli-telemetry':'1.1.0',"
            "'extensions':{}}))\n"
            "    raise SystemExit(0)\n"
            "with calls.open('ab') as stream:\n"
            "    stream.write((' '.join(sys.argv[1:]) + '\\n').encode())\n"
            "raise SystemExit(29)\n")
        backend.chmod(0o700)
        return calls, dict(
            azure=backend, uploader=backend, validator=VALIDATOR,
            supervisor=SUPERVISOR, az_python=backend)

    def test_controller_consumes_exactly_once_only_after_complete_admission(self):
        calls, tools = self.backend_tools()
        paths, _ = self.prepare_contract(tools=tools)
        attempt = self.root / "approved-attempt"
        completed = subprocess.run([
            TOOLS / "uk-wamr-direct-compute", paths["admission"],
            attempt, self.root / "ledger", tools["azure"],
            tools["uploader"], tools["validator"], tools["supervisor"],
            "--az-python", tools["az_python"],
        ], env={"HOME": str(self.root)}, capture_output=True, timeout=90)
        self.assertNotEqual(completed.returncode, 0)
        self.assertTrue(attempt.is_dir())
        ledger_names = {
            path.name for path in (self.root / "ledger").iterdir()
            if not path.name.startswith(".")
        }
        plan = fixture.read(paths["plan"])
        self.assertEqual(ledger_names, {
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
        ], env={"HOME": str(self.root)}, capture_output=True, timeout=30)
        self.assertNotEqual(retried.returncode, 0)
        self.assertFalse((self.root / "retry-attempt").exists())
        self.assertEqual(calls.read_bytes(), before)

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
