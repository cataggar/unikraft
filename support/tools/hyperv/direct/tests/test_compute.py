# SPDX-License-Identifier: BSD-3-Clause
"""Existing native fake backend only. These are synthetic, non-cloud observations."""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import time
import unittest
from unittest import mock
import uuid

REPO = Path(__file__).resolve().parents[5]
TOOLS = Path(os.environ["WAMR_DIRECT_TOOLS"]).resolve(strict=True)
VALIDATOR = TOOLS / "uk-wamr-direct-validate"
FAKE = TOOLS / "wamr-direct-fixture-cli"
CONTROLLER = TOOLS / "wamr-direct-controller-fixture"
SDK = "a53205d77be3b880eb8f8b96679512ba58e2331a"
OWNER = "aaaaaaaa-aaaa-4aaa-aaaa-aaaaaaaaaaaa"
SUBSCRIPTION = "bbbbbbbb-bbbb-4bbb-bbbb-bbbbbbbbbbbb"
spec = importlib.util.spec_from_file_location(
    "wamr_handoff", REPO / "support/build/wamr-native-ci/handoff.py")
handoff = importlib.util.module_from_spec(spec)
spec.loader.exec_module(handoff)


def write(path, value):
    path.write_bytes(value if isinstance(value, bytes) else json.dumps(value).encode())
    path.chmod(0o600)


def read(path):
    return json.loads(path.read_bytes())


def digest(data):
    return hashlib.sha256(data).hexdigest()


def identity():
    return dict(wamr_revision=SDK, **{
        name + "_sha256": "a" * 64
        for name in ("wasm", "cwasm", "runtime", "compiler", "config")})


def result():
    return dict(
        version=1, workload="tiny", wamr_revision=SDK, wasm_sha256="a" * 64,
        cwasm_sha256="a" * 64, runtime_sha256="a" * 64, platform_status=0,
        checks=2, answer=42, terminal=1, detail=2, reserved_bytes=0, frame_bytes=0,
        accessible_bytes=0, allocation_bytes=0, system_page_table_bytes=4096,
        error_name="")


def serial(boot=1, value=None):
    return ("\n".join([
        f"synthetic boot {boot}", "Hyper-V Hv#1 hypercall page enabled",
        "Hyper-V SynIC:", "Powered by", "Calling main(0, 0)",
        "WAMR_NATIVE_COMPUTE=" + json.dumps(result() if value is None else value),
        "WAMR_NATIVE_AOT_OK answer=42 teardown=0",
        "[    1.000001] Info: [libukboot] main returned 0", "",
    ])).encode()


class Compute(unittest.TestCase):
    def setUp(self):
        for path in (VALIDATOR, FAKE, CONTROLLER):
            self.assertTrue(path.is_file())
            with path.open("rb") as stream:
                self.assertEqual(stream.read(4), b"\x7fELF")
        self.root = REPO / ".d" / ("compute-fixture-" + uuid.uuid4().hex)
        self.root.mkdir(mode=0o700)
        self.addCleanup(shutil.rmtree, self.root)
        now = int(time.time())
        self.scope = dict(
            schema="uk.wamr.direct-compute", version=1, purpose="tiny-aot-two-boot",
            authority="final_image_approved", approval=dict(
                direct_specialized_gen2=True, os_only_private=True, two_boots_only=True,
                cleanup_owned_group=True, exact_image_and_local_bundle_reviewed=True,
                fresh_final_approval=True, approved_unix=now - 1, expires_unix=now + 600),
            attempt_id=OWNER, subscription=SUBSCRIPTION, location="northeurope",
            prefix="fixture-direct", vm_size="Standard_D2s_v5",
            serial_mode="per_boot", runtime_seconds=60, cleanup_seconds=60,
            operation_seconds=30, poll_seconds=1,
            source_revision="a" * 40, source_tree="b" * 40, identity=identity(),
            os_vhd=dict(path=str(self.root / "os.vhd"), size=69206528, sha256="a" * 64),
            bundle=dict(path=str(self.root / "bundle.json"), size=1, sha256="a" * 64))
        self.scope_path = self.root / "scope.json"
        write(self.scope_path, self.scope)

    def validate(self, command, *args, status=0):
        completed = subprocess.run(
            [VALIDATOR, command, self.scope_path, *args], env={},
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
        self.assertEqual(completed.returncode, status, completed.stderr)
        self.assertNotIn(str(self.root).encode(), completed.stderr)
        return completed

    def test_exact_native_result_and_cumulative_padding(self):
        first, second = self.root / "first", self.root / "second"
        write(first, serial() + b"\0" * 20)
        self.assertEqual(json.loads(self.validate("serial", first).stdout), result())
        for mode in ("per_boot", "cumulative", "azure_cumulative"):
            self.scope["serial_mode"] = mode
            write(self.scope_path, self.scope)
            prefix = b"" if mode == "per_boot" else (
                first.read_bytes() if mode == "cumulative" else serial())
            write(second, prefix + serial(2))
            self.validate("serial", first, second)
        write(second, serial(2))
        self.validate("serial", first, second, status=1)

    def test_fail_closed_actual_record_schema(self):
        path = self.root / "serial"
        for key, value in (
                ("answer", 43), ("checks", 1), ("checks", -1), ("terminal", 0),
                ("detail", 0), ("frame_bytes", 4096), ("reserved_bytes", 1),
                ("accessible_bytes", 4096), ("allocation_bytes", 1),
                ("system_page_table_bytes", 0), ("system_page_table_bytes", 3),
                ("version", True), ("wasm_sha256", "b" * 64),
                ("cwasm_sha256", "b" * 64), ("runtime_sha256", "b" * 64),
                ("wamr_revision", "b" * 40), ("error_name", "failure"),
                ("unexpected", 0)):
            with self.subTest(key=key, value=value):
                write(path, serial(value=dict(result(), **{key: value})))
                self.validate("serial", path, status=1)
        original = serial()
        for bad in (
                original.replace(b'"version": 1', b'"version": 1, "version": 1'),
                original.replace(b"WAMR_NATIVE_COMPUTE=", b"noise WAMR_NATIVE_COMPUTE="),
                original + original,
                original.replace(b"main returned 0", b"main returned -1"),
                original.replace(b"WAMR_NATIVE_AOT_OK", b"noise WAMR_NATIVE_AOT_OK"),
                original + b"WAMR_NATIVE_WASI={}\n",
                original + b"Unikraft Crash\n",
                original + b"\x1b[", b"x" * 8193 + b"\n" + original,
                original + b"\x07", b"x" * (4 * 1024 * 1024)):
            write(path, bad)
            self.validate("serial", path, status=1)
        for incomplete in (b"", original.split(b"WAMR_NATIVE_COMPUTE=")[0],
                           original.split(b"[    1.000001]")[0]):
            write(path, incomplete)
            self.validate("serial", path, status=2)

    def test_purpose_approval_source_sdk_and_deadline_refusals(self):
        for key, value in (
                ("schema", "uk.hyperv.direct-two-boot"), ("purpose", "platform-only-v1"),
                ("authority", "not_admitted"), ("location", "westus"),
                ("vm_size", "Standard_B2s"), ("source_tree", "b" * 39),
                ("attempt_id", "not-a-uuid"), ("runtime_seconds", 3601),
                ("cleanup_seconds", 1801)):
            with self.subTest(key=key):
                write(self.scope_path, dict(self.scope, **{key: value}))
                self.validate("scope", status=1)
        for key, value in (
                ("fresh_final_approval", False), ("approved_unix", int(time.time()) + 100),
                ("expires_unix", int(time.time()) - 1),
                ("expires_unix", int(time.time()) + 4000)):
            changed = copy.deepcopy(self.scope)
            changed["approval"][key] = value
            write(self.scope_path, changed)
            self.validate("scope", status=1)
        changed = copy.deepcopy(self.scope)
        changed["identity"]["wamr_revision"] = "b" * 40
        write(self.scope_path, changed)
        self.validate("scope", status=1)
        write(self.scope_path, self.scope)
        self.validate("scope")
        other = subprocess.run([TOOLS / "uk-hyperv-direct-validate", "scope", self.scope_path],
                               env={"HOME": str(self.root)}, capture_output=True, timeout=30)
        self.assertNotEqual(other.returncode, 0)

    def lifecycle(self, scenario="success", log1=None):
        root = self.root
        write(root / "ISOLATED_OFFLINE_FIXTURE", b"direct-two-boot-offline-only\n")
        write(root / "fixture-backend.json", {"backend": "native"})
        write(root / "scenario", scenario.encode())
        write(root / "fake-cloud.json", {})
        write(root / "calls", b"")
        write(root / "boot1.log", serial() if log1 is None else log1)
        write(root / "boot2.log", serial(2))
        (root / "ledger").mkdir(mode=0o700)
        args = [CONTROLLER, self.scope_path, root / "attempt", root / "ledger",
                FAKE, FAKE, FAKE]
        # No inherited HOME, Azure config, PATH, credentials or real CLI. The
        # existing native fixture checks its marker, ELF names and confinement.
        env = {"UK_DIRECT_FIXTURE_ROOT": str(root),
               "UK_DIRECT_FIXTURE_VALIDATOR": str(VALIDATOR)}
        completed = subprocess.run(args, env=env, capture_output=True, timeout=160)
        outcome = read(root / "attempt/outcome.json")
        self.assertNotIn(b"PRIVATE_FIXTURE_SAS", completed.stdout + completed.stderr)
        for name in ("grant-os.json", "grant-os.stderr", "upload-os/sas.txt"):
            self.assertFalse((root / "attempt" / name).exists())
        self.assertFalse((root / "attempt/upload-data").exists())
        calls = (root / "calls").read_text()
        return completed, outcome, calls, args, env

    def test_offline_two_boots_exact_topology_results_cleanup_and_consumption(self):
        completed, outcome, calls, args, env = self.lifecycle()
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertTrue(outcome["accepted"])
        self.assertTrue(outcome["compute_evidence_complete"])
        self.assertTrue(outcome["owned_group_absent"])
        self.assertNotIn("persistence_evidence_complete", outcome)
        self.assertEqual(outcome["reserved_boots"], 2)
        for boot in (1, 2):
            record = read(self.root / f"attempt/boot{boot}-compute.json")
            capture = read(self.root / f"attempt/boot{boot}-capture.json")
            self.assertEqual(record["compute"], result())
            self.assertEqual(record["attempt_id"], OWNER)
            self.assertEqual(record["serial_sha256"],
                             digest((self.root / f"attempt/boot{boot}.log").read_bytes()))
            self.assertEqual(capture["compute_result_sha256"],
                             digest((self.root / f"attempt/boot{boot}-compute.json").read_bytes()))
            self.assertIsNone(capture["data_id"])
        cloud = read(self.root / "fake-cloud.json")
        self.assertEqual(cloud["boots"], 2)
        self.assertFalse(cloud["exists"])
        self.assertFalse(cloud["data"]["created"])
        before = (self.root / "calls").read_bytes()
        args[2] = self.root / "retry"
        retried = subprocess.run(args, env=env, capture_output=True, timeout=30)
        self.assertNotEqual(retried.returncode, 0)
        self.assertEqual((self.root / "calls").read_bytes(), before)

    def test_cleanup_failure_is_independent(self):
        completed, outcome, *_ = self.lifecycle("delete-failure")
        self.assertNotEqual(completed.returncode, 0)
        self.assertEqual(outcome["primary_exit"], 0)
        self.assertNotEqual(outcome["cleanup_exit"], 0)
        self.assertFalse(outcome["accepted"])
        self.assertFalse(outcome["owned_group_absent"])

    def test_foreign_inventory_never_deleted(self):
        completed, outcome, calls, *_ = self.lifecycle("foreign-resource")
        self.assertNotEqual(completed.returncode, 0)
        self.assertTrue(outcome["compute_evidence_complete"])
        self.assertNotIn("group delete", calls)
        self.assertFalse(outcome["owned_group_absent"])

    def test_replaced_disk_never_deleted(self):
        completed, outcome, calls, *_ = self.lifecycle("identity-drift")
        self.assertNotEqual(completed.returncode, 0)
        self.assertNotEqual(outcome["primary_exit"], 0)
        self.assertEqual(outcome["reserved_boots"], 2)
        self.assertNotIn("group delete", calls)
        self.assertFalse(outcome["accepted"])

    def test_wrong_group_owner_ambiguous_absence(self):
        completed, outcome, calls, *_ = self.lifecycle("cleanup-unowned")
        self.assertNotEqual(completed.returncode, 0)
        self.assertTrue(outcome["compute_evidence_complete"])
        self.assertNotIn("group delete", calls)
        self.assertFalse(outcome["owned_group_absent"])

    def test_replaced_vm_never_deleted(self):
        completed, outcome, calls, *_ = self.lifecycle("diagnostics-vm-identity-drift")
        self.assertNotEqual(completed.returncode, 0)
        self.assertEqual(outcome["reserved_boots"], 1)
        self.assertNotEqual(outcome["cleanup_exit"], 0)
        self.assertNotIn("group delete", calls)

    def test_wrong_attempt_is_refused_before_fake_cloud(self):
        self.scope["attempt_id"] = "cccccccc-cccc-4ccc-accc-cccccccccccc"
        write(self.scope_path, self.scope)
        completed, outcome, calls, *_ = self.lifecycle()
        self.assertNotEqual(completed.returncode, 0)
        self.assertFalse(outcome["group_creation_attempted"])
        self.assertEqual(calls, "")

    def test_expired_and_unapproved_production_scope_never_calls_backend(self):
        (self.root / "ledger").mkdir(mode=0o700)
        for i, change in enumerate(("unapproved", "expired")):
            changed = copy.deepcopy(self.scope)
            if change == "unapproved":
                changed["authority"] = "not_admitted"
            else:
                changed["approval"]["approved_unix"] = int(time.time()) - 100
                changed["approval"]["expires_unix"] = int(time.time()) - 1
            write(self.scope_path, changed)
            outcome = subprocess.run(
                [TOOLS / "uk-wamr-direct-compute", self.scope_path,
                 self.root / f"refused-{i}", self.root / "ledger", FAKE, FAKE, VALIDATOR],
                env={}, capture_output=True, timeout=30)
            self.assertNotEqual(outcome.returncode, 0)
            self.assertFalse((self.root / "calls").exists())

    def test_failed_compute_still_cleans_up_without_boot2(self):
        completed, outcome, _, *_ = self.lifecycle(
            log1=serial(value=dict(result(), answer=43)))
        self.assertNotEqual(completed.returncode, 0)
        self.assertNotEqual(outcome["primary_exit"], 0)
        self.assertEqual(outcome["cleanup_exit"], 0)
        self.assertEqual(outcome["reserved_boots"], 1)
        self.assertTrue(outcome["owned_group_absent"])
        self.assertFalse((self.root / "attempt/boot2-compute.json").exists())

    def test_plan_is_never_approval_and_revalidates_bytes(self):
        path = self.root / "artifact"
        write(path, b"synthetic non-executable bytes")
        item = handoff.artifact(path)
        bundle = dict(
            schema="uk.wamr.local-image-handoff", version=1, authority="not_admitted",
            source_revision="a" * 40, source_tree="b" * 40, identity=identity(),
            artifacts=[item] * len(handoff.NAMES), evidence=[], boots=[])
        bundle_path = self.root / "bundle.json"
        write(bundle_path, bundle)
        output = self.root / "plan.json"
        value = handoff.plan(bundle_path, output)
        self.assertEqual(value["authority"], "not_admitted")
        self.assertFalse(value["approval"]["fresh_final_approval"])
        self.assertEqual(value["approval"]["expires_unix"], 0)
        self.scope_path = output
        self.validate("scope", status=1)
        write(path, b"changed")
        with self.assertRaises(ValueError):
            handoff.plan(bundle_path, self.root / "changed-plan.json")

    def test_sealed_topology(self):
        template = read(REPO / "support/azure/wamr-direct-compute.json")
        self.assertEqual(len(template["resources"]), 4)
        self.assertNotIn("dataDiskId", template["parameters"])
        text = json.dumps(template)
        for forbidden in ("publicIPAddresses", "osProfile", "customData", "extensions",
                          "cloud-init", "ssh", "dataDiskId"):
            self.assertNotIn(forbidden, text)
        vm = template["resources"][-1]["properties"]
        self.assertEqual(vm["storageProfile"]["dataDisks"], [])
        self.assertEqual(vm["storageProfile"]["osDisk"]["createOption"], "Attach")
        self.assertEqual(vm["storageProfile"]["osDisk"]["deleteOption"], "Detach")
        self.assertEqual(vm["diagnosticsProfile"], {"bootDiagnostics": {"enabled": True}})
        rules = template["resources"][0]["properties"]["securityRules"]
        self.assertEqual({r["properties"]["direction"] for r in rules}, {"Inbound", "Outbound"})
        self.assertTrue(all(r["properties"]["access"] == "Deny" for r in rules))

    def test_physical_handoff_reopens_full_image_and_all_four_local_records(self):
        package_tool = Path(os.environ["WAMR_CI_PACKAGE"]).resolve(strict=True)
        runtime = self.root / "runtime"
        root = runtime / "compute"
        app = self.root / "app"
        for path in (runtime, root, app, app / "build", app / "build/artifacts",
                     root / "evidence", root / "tools", root / "tools/bin",
                     runtime / "bin", runtime / "firmware"):
            path.mkdir(mode=0o700)
        shutil.copyfile(REPO / "support/apps/wamr-aot/check-log.py", app / "check-log.py")
        shutil.copyfile(package_tool, root / "tools/bin/wamr-ci-package")
        (root / "tools/bin/wamr-ci-package").chmod(0o700)
        ci = handoff.ci
        data = bytearray(512)
        data[:2] = b"MZ"
        struct.pack_into("<I", data, 0x3c, 0x80)
        data[0x80:0x84] = b"PE\0\0"
        for offset, value in ((0x84, 0x8664), (0x86, 1), (0x94, 0xf0),
                              (0x98, 0x20b), (0xdc, 10)):
            struct.pack_into("<H", data, offset, value)
        efi = app / "build" / ci.EFI
        write(efi, bytes(data))
        for path in (app / "build" / (ci.EFI + ".dbg"), app / "build" / (ci.EFI + ".bootinfo"),
                     app / ".config", runtime / "bin/qemu-system-x86_64",
                     runtime / "firmware/code.fd", runtime / "firmware/vars.fd",
                     root / "tools/bin/uk-hyperv-local-boot"):
            write(path, b"synthetic fixture, not execution evidence\n")
        files = {}
        for name in ("embedded.c", "identity.h", "libwamr-aot.a", "tiny.cwasm",
                     "tiny.wasm", "wamr_aot.h", "wamrc"):
            path = app / "build/artifacts" / name
            write(path, ("synthetic " + name).encode())
            files[name] = ci.digest(path)
        runtime_identity = dict(wamr_revision=SDK, minimal_wasi=False,
                                compiler_profile="unikraft-x86_64", zig_version="0.16.0",
                                files=files)
        write(app / "build/artifacts/identity.json", runtime_identity)
        source = dict(revision="a" * 40, tree="b" * 40)
        image_identity = dict(
            unikraft_revision=source["revision"],
            runtime_inputs_sha256=ci.digest(app / "build/artifacts/identity.json"),
            solved_config_sha256=ci.digest(app / ".config"),
            files={name: ci.digest(app / "build" / name)
                   for name in (ci.EFI, ci.EFI + ".dbg", ci.EFI + ".bootinfo")})
        write(app / "build/image-identity.json", image_identity)
        build = dict(source=source, runtime=runtime_identity, image=image_identity)
        producer = dict(source=source, fixture_only=True)
        write(root / "evidence/build.json", build)
        write(root / "evidence/build-start.json", producer)
        tools = dict(
            package_tool=root / "tools/bin/wamr-ci-package",
            local_boot_tool=root / "tools/bin/uk-hyperv-local-boot",
            qemu=runtime / "bin/qemu-system-x86_64",
            ovmf_code=runtime / "firmware/code.fd", ovmf_vars=runtime / "firmware/vars.fd")
        write(root / "evidence/boot-inputs.json",
              {key: ci.digest(path) for key, path in tools.items()})
        packaged = subprocess.run([tools["package_tool"], "package", efi, root / "package"],
                                  capture_output=True, timeout=150)
        self.assertEqual(packaged.returncode, 0, packaged.stderr)
        package = json.loads(packaged.stdout)
        write(root / "evidence/package.json", dict(
            scope=package["scope"], acceptance=package["acceptance"],
            producer_sha256=package["producer_sha256"],
            image={key: package["image"][key] for key in (
                "schema_version", "miz_revision", "efi", "raw", "vhd",
                "footer_sha256", "packaging")}))
        observation = dict(result(), **{
            key + "_sha256": files[name] for key, name in (
                ("wasm", "tiny.wasm"), ("cwasm", "tiny.cwasm"), ("runtime", "libwamr-aot.a"))})
        with mock.patch.object(ci, "APP", app):
            for i, mode in enumerate(ci.MODES):
                config = ci.config_for(runtime, root, i)
                work = Path(config["work_dir"])
                work.mkdir(mode=0o700)
                raw = (b"Using legacy xAPIC MMIO\n" if i % 2 else b"") + serial(i, observation)
                write(work / "hyperv-efi-boot.log", raw)
                write(work / "launched", b"")
                paths = [config["raw_disk"] or config["fixed_vhd"],
                         config["ovmf_code"], config["ovmf_vars"], config["qemu"]]
                write(work / "request.json", dict(
                    schema_version=1, config=config,
                    pins=[dict(size=Path(path).stat().st_size,
                               sha256=list(bytes.fromhex(ci.digest(Path(path))))) for path in paths]))
                write(work / "report.json", dict(
                    schema_version=1, scope="public_local_qemu_only", acceptance="not_established",
                    passed=True, consumed=True, cleanup_complete=True, input_unchanged=True,
                    serial_valid=True, serial_limit_reached=False, serial_bytes=len(raw),
                    serial_sha256=digest(raw), termination={"exited": 0},
                    failures=dict(primary=None, cleanup=None, recording=None)))
                write(root / "evidence" / (mode + "-compute.json"), ci.check_boot(config, runtime_identity))
            write(root / "evidence/result.json", dict(
                schema_version=1, scope="local_native_compute_only", passed=True,
                hardware_acceptance="not_established", cloud_authority="not_admitted",
                benchmark="not_measured", workload="tiny", modes=list(ci.MODES),
                records={p.name: ci.digest(p) for p in sorted((root / "evidence").glob("*.json"))}))
            original = (root / "evidence/result.json").read_bytes()
            with mock.patch.object(ci, "check_build", return_value=build), \
                    mock.patch.object(ci, "producer_inputs", return_value=producer):
                handoff.export(runtime, self.root / "handoff")
        self.assertEqual((root / "evidence/result.json").read_bytes(), original)
        bundle_path = self.root / "handoff/bundle.json"
        bundle = read(bundle_path)
        self.assertEqual(bundle["authority"], "not_admitted")
        self.assertEqual(len(bundle["boots"]), 4)
        revalidated = subprocess.run([VALIDATOR, "handoff", bundle_path],
                                    env={}, capture_output=True, timeout=60)
        self.assertEqual(revalidated.returncode, 0, revalidated.stderr)
        self.assertIn(b"authority=not_admitted", revalidated.stdout)
        self.scope.update(
            bundle=handoff.artifact(bundle_path),
            os_vhd=bundle["artifacts"][handoff.NAMES.index("vhd")],
            identity=bundle["identity"])
        write(self.scope_path, self.scope)
        self.validate("inputs")
        for key in ("source_tree", "source_revision"):
            changed = dict(self.scope, **{key: "c" * 40})
            write(self.scope_path, changed)
            self.validate("inputs", status=1)
        write(self.scope_path, self.scope)
        changed = copy.deepcopy(self.scope)
        changed["os_vhd"]["sha256"] = "b" * 64
        write(self.scope_path, changed)
        self.validate("inputs", status=1)
        write(self.scope_path, self.scope)
        retained_raw = Path(bundle["artifacts"][handoff.NAMES.index("raw")]["path"])
        with retained_raw.open("r+b") as stream:
            stream.seek(66 * 1024 * 1024 - 1)
            stream.write(b"\x07")
        self.validate("inputs", status=1)
        with self.assertRaises(ValueError):
            handoff.plan(bundle_path, self.root / "mutated-plan.json")


if __name__ == "__main__":
    unittest.main()
