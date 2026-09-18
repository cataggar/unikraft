# SPDX-License-Identifier: BSD-3-Clause
"""Existing native fake backend only. These are synthetic, non-cloud observations."""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import stat
import struct
import subprocess
import time
import types
import unittest
from unittest import mock
import uuid
import zipfile

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
public_spec = importlib.util.spec_from_file_location(
    "wamr_public_bundle", REPO / "support/build/wamr-native-ci/public_bundle.py")
public_bundle = importlib.util.module_from_spec(public_spec)
public_spec.loader.exec_module(public_bundle)


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


def source_custody():
    ci = handoff.ci
    return {
        "schema": "uk.wamr.git-physical-source",
        "version": 1,
        "object_format": "sha1",
        "files": 1,
        "directories": 1,
        "bytes": 1,
        "content_sha256": digest(b"source-content"),
        "physical_sha256": digest(b"source-physical"),
        "role_excluded_outputs": list(ci.SOURCE_OUTPUT_ROLES),
    }


def dependency_custody(source):
    ci = handoff.ci
    source_manifests = {}
    trusted = public_bundle.trusted_source_manifests(ci, {
        "source_revision": source["revision"],
        "source_tree": source["tree"],
    })
    for index, name in enumerate(("build.zig", "build.zig.zon"), 1):
        source_record = trusted[name]
        size = source_record["bytes"]
        sha256 = source_record["sha256"]
        source_metadata = [
            1, 10 + index, stat.S_IFREG | 0o644,
            1000, 1000, 1, size, 1, 1,
        ]
        source_manifests[name] = {
            "source": dict(
                source_record,
                metadata=source_metadata,
                metadata_sha256=public_bundle.metadata_sha256(
                    source_metadata),
            ),
            "copy": {
                "bytes": size,
                "sha256": sha256,
                "metadata": [
                    1, 10 + index, stat.S_IFREG | 0o600,
                    1000, 1000, 1, size, 1, 1,
                ],
            },
        }
    manifest = {
        "bytes": 24,
        "sha256": "5" * 64,
        "dependencies": [],
    }
    record = {
        "package_hash": ci.MIZ_PACKAGE_HASH,
        "content": {
            "files": 2,
            "directories": 1,
            "bytes": 64,
            "tree_sha256": "6" * 64,
            "physical_sha256": "7" * 64,
        },
        "manifest": manifest,
    }
    manifest_digest = hashlib.sha256(b"uk.wamr.package-manifests-v1\0")
    public_bundle.bind(manifest_digest, [ci.MIZ_PACKAGE_HASH, manifest])
    closure = hashlib.sha256(b"uk.wamr.package-closure-v1\0")
    public_bundle.bind(closure, record)
    physical = hashlib.sha256(b"uk.wamr.package-physical-closure-v1\0")
    public_bundle.bind(physical, [ci.MIZ_PACKAGE_HASH, "7" * 64])
    root_metadata = [
        1, 10, stat.S_IFDIR | 0o700,
        1000, 1000, 3, 4096, 1, 1,
    ]
    hash_records = [{
        "package_hash": ci.MIZ_PACKAGE_HASH,
        "sha256": digest((ci.MIZ_PACKAGE_HASH + "\n").encode("ascii")),
    }]
    return {
        "schema": "uk.wamr.zig-dependency-custody",
        "version": 1,
        "request": {
            "url": ci.MIZ_URL,
            "revision": ci.MIZ_REVISION,
            "package_hash": ci.MIZ_PACKAGE_HASH,
        },
        "source_manifests": source_manifests,
        "restore_directory": {
            "metadata": [
                1, 10, stat.S_IFDIR | 0o700,
                1000, 1000, 3, 4096, 1, 1,
            ],
        },
        "restore": {
            "scope": "command_diagnostic_not_acceptance",
            "stage": "dependency-restore",
            "exit_code": 0,
            "bytes": 0,
            "sha256": digest(b""),
            "over_limit": False,
            "known_error_markers": [],
        },
        "packages": {
            "roots": 1,
            "files": 2,
            "directories": 1,
            "bytes": 64,
            "closure_sha256": closure.hexdigest(),
            "physical_sha256": physical.hexdigest(),
            "root_metadata": root_metadata,
            "root_metadata_sha256": public_bundle.metadata_sha256(
                root_metadata),
            "manifests": {
                "count": 1,
                "bytes": 24,
                "sha256": manifest_digest.hexdigest(),
            },
            "hash_verification": {
                "algorithm": "zig-0.16.0-fetch-path",
                "count": 1,
                "sha256": digest(json.dumps(
                    hash_records, sort_keys=True,
                    separators=(",", ":")).encode("ascii")),
            },
            "records": [record],
        },
    }


def delivered_public_bundle():
    raw = subprocess.check_output([
        "git", "show",
        "993e4d0d394c08202c0d0c57ea97450a19a4f394:"
        "support/build/wamr-native-ci/public_bundle.py",
    ], cwd=REPO, timeout=60)
    module = types.ModuleType("delivered_wamr_public_bundle")
    exec(compile(raw, "delivered-public-bundle.py", "exec"), module.__dict__)
    return module


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

    def lifecycle(self, scenario="success", log1=None, log2=None, python=False):
        root = self.root
        write(root / "ISOLATED_OFFLINE_FIXTURE", b"direct-two-boot-offline-only\n")
        write(root / "fixture-backend.json", {"backend": "native"})
        write(root / "scenario", scenario.encode())
        write(root / "fake-cloud.json", {})
        write(root / "calls", b"")
        write(root / "boot1.log", serial() if log1 is None else log1)
        write(root / "boot2.log", serial(2) if log2 is None else log2)
        (root / "ledger").mkdir(mode=0o700)
        args = [CONTROLLER, self.scope_path, root / "attempt", root / "ledger",
                FAKE, FAKE, FAKE]
        if python:
            args += ["--az-python", FAKE]
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

    def test_explicit_interpreter_preflight_precedes_consumption(self):
        completed, outcome, *_ = self.lifecycle(python=True)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertTrue(outcome["accepted"])
        self.assertEqual((self.root / "cli-version-called").read_bytes(), b"before-consumption\n")
        record = read(self.root / "attempt/cli-version.process.json")
        self.assertEqual(record["interpreter"]["path"], str(FAKE))
        self.assertEqual(record["authority"], "not_admitted")

    def test_cli_startup_failure_leaves_ledger_unconsumed(self):
        write(self.root / "cli-version-control", b"fail")
        completed, outcome, calls, *_ = self.lifecycle()
        self.assertNotEqual(completed.returncode, 0)
        self.assertEqual(outcome["primary_exit"], 29)
        self.assertEqual(outcome["cleanup_exit"], 0)
        self.assertFalse(outcome["group_creation_attempted"])
        self.assertFalse(outcome["owned_group_absent"])
        self.assertEqual(outcome["reserved_boots"], 0)
        self.assertEqual(calls, "")
        self.assertEqual(list((self.root / "ledger").iterdir()), [])
        self.assertFalse((self.root / "attempt/consumed.json").exists())
        self.assertEqual(read(self.root / "attempt/cli-version.process.json")["termination"], {"exited": 29})

    def test_malformed_cli_version_cannot_consume(self):
        write(self.root / "cli-version-control", b"malformed")
        completed, outcome, calls, *_ = self.lifecycle()
        self.assertNotEqual(completed.returncode, 0)
        self.assertEqual(list((self.root / "ledger").iterdir()), [])
        self.assertEqual(calls, "")
        self.assertFalse(outcome["accepted"])
        self.assertIn("CliVersionInvalid", (self.root / "attempt/driver.stderr").read_text())

    def test_cli_startup_timeout_preserves_original_operation_budget(self):
        self.scope["operation_seconds"] = 10
        write(self.scope_path, self.scope)
        write(self.root / "cli-version-control", b"timeout")
        start = time.monotonic()
        completed, outcome, calls, *_ = self.lifecycle()
        self.assertEqual(completed.returncode, 124)
        self.assertEqual(outcome["primary_exit"], 124)
        self.assertLess(time.monotonic() - start, 15)
        self.assertEqual(list((self.root / "ledger").iterdir()), [])
        self.assertEqual(calls, "")
        record = read(self.root / "attempt/cli-version.process.json")
        self.assertEqual(record["failures"]["primary"]["category"], "timeout")
        self.assertTrue(record["cleanup_complete"])

    def test_approval_expiring_during_successful_startup_cannot_consume(self):
        self.scope["approval"]["expires_unix"] = int(time.time()) + 5
        write(self.scope_path, self.scope)
        write(self.root / "cli-version-control", b"expire")
        completed, outcome, calls, *_ = self.lifecycle()
        self.assertEqual(completed.returncode, 125)
        self.assertEqual(outcome["primary_exit"], 125)
        self.assertEqual(list((self.root / "ledger").iterdir()), [])
        self.assertEqual(calls, "")
        self.assertEqual(read(self.root / "attempt/cli-version.process.json")["termination"], {"exited": 0})

    def test_bounded_cli_version_cannot_consume(self):
        write(self.root / "cli-version-control", b"overflow")
        completed, outcome, calls, *_ = self.lifecycle()
        self.assertNotEqual(completed.returncode, 0)
        self.assertEqual(list((self.root / "ledger").iterdir()), [])
        self.assertEqual(calls, "")
        self.assertFalse(outcome["accepted"])
        self.assertLessEqual((self.root / "attempt/cli-version.stdout").stat().st_size, 4096)

    def test_cli_stderr_cannot_consume(self):
        write(self.root / "cli-version-control", b"stderr")
        completed, outcome, calls, *_ = self.lifecycle()
        self.assertNotEqual(completed.returncode, 0)
        self.assertEqual(list((self.root / "ledger").iterdir()), [])
        self.assertEqual(calls, "")
        self.assertFalse(outcome["accepted"])
        self.assertNotIn(b"private synthetic", completed.stderr + completed.stdout)

    def test_missing_campaign_ledger_has_preadmission_diagnostic(self):
        for name in ("uk-wamr-direct-compute", "uk-hyperv-direct-two-boot"):
            completed = subprocess.run(
                [TOOLS / name, self.scope_path, self.root / "attempt", self.root / "missing-ledger",
                 FAKE, FAKE, FAKE], env={"HOME": str(self.root)},
                capture_output=True, timeout=10)
            self.assertNotEqual(completed.returncode, 0)
            self.assertIn(b"phase=pre-admission reason=CampaignLedgerMissing", completed.stderr)
            self.assertNotIn(str(self.root).encode(), completed.stderr)
            self.assertFalse((self.root / "attempt").exists())
            self.assertFalse((self.root / "missing-ledger").exists())

    def test_interpreter_path_refused_before_attempt_creation(self):
        binary = self.root / "python"
        shutil.copyfile(FAKE, binary)
        binary.chmod(0o700)
        link = self.root / "python-link"
        link.symlink_to(binary)
        directory = self.root / "directory"
        directory.mkdir(mode=0o700)
        nonexec = self.root / "nonexec"
        write(nonexec, b"not executable")
        unsafe = self.root / "unsafe"
        write(unsafe, b"not a trusted interpreter")
        unsafe.chmod(0o777)
        fifo = self.root / "fifo"
        os.mkfifo(fifo, 0o600)
        for path in ("relative-python", self.root / "missing", link, directory, nonexec, unsafe, fifo):
            with self.subTest(kind=str(path.name) if isinstance(path, Path) else path):
                completed = subprocess.run(
                    [TOOLS / "uk-wamr-direct-compute", self.scope_path, self.root / "attempt",
                     self.root / "ledger", FAKE, FAKE, FAKE, "--az-python", path],
                    env={"HOME": str(self.root)}, capture_output=True, timeout=10)
                self.assertNotEqual(completed.returncode, 0)
                self.assertIn(b"phase=pre-admission", completed.stderr)
                self.assertNotIn(str(self.root).encode(), completed.stderr)
                self.assertFalse((self.root / "attempt").exists())
                self.assertFalse((self.root / "ledger").exists())

    def test_production_standalone_preflight_never_needs_attempt_or_ledger(self):
        fixture = TOOLS / "hyperv-direct-runtime-fixture"
        with fixture.open("rb") as stream:
            self.assertEqual(stream.read(4), b"\x7fELF")
        for name in ("uk-wamr-direct-compute", "uk-hyperv-direct-two-boot"):
            for python in (False, True):
                capture = self.root / (name + str(python))
                capture.mkdir(mode=0o700)
                args = [TOOLS / name, "preflight", capture, fixture]
                if python:
                    args += ["--az-python", fixture]
                env = dict.fromkeys(("AZ_PYTHON", "PYTHONPATH", "PYTHONHOME", "PYTHONSTARTUP",
                                     "LD_PRELOAD", "LD_LIBRARY_PATH", "PATH"), "/never/inherit")
                # Loader hooks cannot be supplied to the controller executable
                # itself; native Environment tests cover their removal directly.
                del env["LD_PRELOAD"]
                del env["LD_LIBRARY_PATH"]
                env["HOME"] = str(self.root)
                completed = subprocess.run(args, env=env, capture_output=True, timeout=10)
                self.assertEqual(completed.returncode, 0, completed.stderr)
                self.assertIn(b"authority=not_admitted", completed.stdout)
                self.assertEqual(completed.stderr, b"")
                self.assertEqual(set(p.name for p in capture.iterdir()), {
                    ".writer.lock", "cli-version.stdout", "cli-version.stderr", "cli-version.process.json"})
        self.assertFalse((self.root / "attempt").exists())
        self.assertFalse((self.root / "ledger").exists())

    def test_standalone_preserves_child_and_recording_failures(self):
        fixture = self.root / "cli-version-exit29"
        shutil.copyfile(TOOLS / "hyperv-direct-runtime-fixture", fixture)
        fixture.chmod(0o700)
        capture = self.root / "preflight-capture"
        capture.mkdir(mode=0o700)
        write(capture / "cli-version.process.json", b"existing immutable record")
        completed = subprocess.run(
            [TOOLS / "uk-wamr-direct-compute", "preflight", capture, fixture],
            env={"HOME": str(self.root)}, capture_output=True, timeout=10)
        self.assertEqual(completed.returncode, 29)
        status = json.loads(completed.stderr)
        self.assertEqual(status["phase"], "local-cli-startup")
        self.assertEqual(status["termination"], {"exited": 29})
        self.assertIsNotNone(status["recording_error"])
        self.assertTrue(status["cleanup_complete"])
        self.assertNotIn(str(self.root).encode(), completed.stderr)
        self.assertEqual((capture / "cli-version.process.json").read_bytes(), b"existing immutable record")

    def test_required_interpreter_is_not_recovered_from_ambient_variable(self):
        fixture = self.root / "requires-python"
        shutil.copyfile(TOOLS / "hyperv-direct-runtime-fixture", fixture)
        fixture.chmod(0o700)
        for explicit in (False, True):
            capture = self.root / ("required-python" + str(explicit))
            capture.mkdir(mode=0o700)
            args = [TOOLS / "uk-wamr-direct-compute", "preflight", capture, fixture]
            if explicit:
                args += ["--az-python", TOOLS / "hyperv-direct-runtime-fixture"]
            completed = subprocess.run(args, env={"HOME": str(self.root), "AZ_PYTHON": str(fixture)},
                                       capture_output=True, timeout=10)
            self.assertEqual(completed.returncode == 0, explicit, completed.stderr)
            if not explicit:
                self.assertEqual(json.loads(completed.stderr)["reason"], "CliStartupFailed")
        self.assertFalse((self.root / "attempt").exists())
        self.assertFalse((self.root / "ledger").exists())

    def test_cumulative_identical_boot_output_requires_two_real_frames(self):
        self.scope["serial_mode"] = "azure_cumulative"
        write(self.scope_path, self.scope)
        deterministic = serial()
        completed, outcome, *_ = self.lifecycle(
            "cached-then-fresh", deterministic + b"\0" * 16,
            deterministic + deterministic + b"\0" * 16)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertTrue(outcome["accepted"])
        self.assertEqual(outcome["boot2_freshness"]["cached_reads"], 1)
        self.assertEqual(read(self.root / "attempt/boot1-compute.json")["compute"],
                         read(self.root / "attempt/boot2-compute.json")["compute"])

    def test_cumulative_cached_first_only_expires_without_boot2_evidence(self):
        self.scope["serial_mode"] = "azure_cumulative"
        self.scope["approval"]["expires_unix"] = int(time.time()) + 5
        write(self.scope_path, self.scope)
        deterministic = serial()
        completed, outcome, *_ = self.lifecycle(
            "stale-boot1-log", deterministic, deterministic)
        self.assertNotEqual(completed.returncode, 0)
        self.assertEqual(outcome["reserved_boots"], 2)
        self.assertGreater(outcome["boot2_freshness"]["cached_reads"], 0)
        self.assertFalse(outcome["accepted"])
        self.assertTrue(outcome["owned_group_absent"])
        self.assertFalse((self.root / "attempt/boot2-compute.json").exists())

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
        workspace = self.root / "unikraft"
        workspace.mkdir(mode=0o700)
        (workspace / ".d").mkdir(mode=0o700)
        runtime = workspace / ".d/wamr-native-runtime"
        root = runtime / "compute"
        app = self.root / "app"
        for path in (runtime, root, app, app / "build", app / "build/artifacts",
                     root / "evidence", root / "tools", root / "tools/bin",
                     root / "tools/consumer-tree", runtime / "bin",
                     runtime / "bin/share", runtime / "firmware"):
            path.mkdir(mode=0o700)
        shutil.copyfile(REPO / "support/apps/wamr-aot/check-log.py", app / "check-log.py")
        shutil.copyfile(package_tool, root / "tools/bin/wamr-ci-package")
        (root / "tools/bin/wamr-ci-package").chmod(0o700)
        ci = handoff.ci
        handoff_parent = self.root / "outputs"
        handoff_parent.mkdir(mode=0o700)
        for mode in ci.MODES:
            (root / ("boot-" + mode)).mkdir(mode=0o700)
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
        source = dict(
            revision=ci.git("rev-parse", "HEAD"),
            tree=ci.git("rev-parse", "HEAD^{tree}"),
        )
        image_identity = dict(
            unikraft_revision=source["revision"],
            runtime_inputs_sha256=ci.digest(app / "build/artifacts/identity.json"),
            solved_config_sha256=ci.digest(app / ".config"),
            files={name: ci.digest(app / "build" / name)
                   for name in (ci.EFI, ci.EFI + ".dbg", ci.EFI + ".bootinfo")})
        write(app / "build/image-identity.json", image_identity)
        build = dict(source=source, runtime=runtime_identity, image=image_identity)
        source_archive = root / "tools/wamr-source.tar"
        write(source_archive, b"synthetic source archive\n")
        consumer_files = {
            f"tool:{name}": source_archive for name in ci.HOST_TOOLS
        }
        for name in ("bash", "head", "timeout"):
            consumer_files[f"tool:{name}"] = Path(ci.tool(name))
        consumer_files["wamr-source-archive"] = source_archive
        consumer_inputs = ci.record_input_paths(
            consumer_files,
            {name: root / "tools/consumer-tree"
             for name in (
                 "bison", "python-stdlib", "system-bin", "zig", "llvm")})
        producer = dict(
            source=source,
            source_custody=source_custody(),
            dependencies=dependency_custody(source),
            consumer_inputs=consumer_inputs,
            fixture_only=True,
        )
        write(root / "evidence/build.json", build)
        write(root / "evidence/build-start.json", producer)
        tools = dict(
            package_tool=root / "tools/bin/wamr-ci-package",
            local_boot_tool=root / "tools/bin/uk-hyperv-local-boot",
            qemu=runtime / "bin/qemu-system-x86_64",
            ovmf_code=runtime / "firmware/code.fd",
            ovmf_vars=runtime / "firmware/vars.fd",
            efi=efi)
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
        boot_inputs = ci.record_input_paths(
            tools, {"qemu-data": runtime / "bin/share"})
        write(root / "evidence/boot-inputs.json", boot_inputs)
        observation = dict(result(), **{
            key + "_sha256": files[name] for key, name in (
                ("wasm", "tiny.wasm"), ("cwasm", "tiny.cwasm"), ("runtime", "libwamr-aot.a"))})
        with mock.patch.object(ci, "APP", app):
            for i, mode in enumerate(ci.MODES):
                config = ci.config_for(runtime, root, i)
                work = Path(config["work_dir"])
                raw = (b"Using legacy xAPIC MMIO\n" if i % 2 else b"") + serial(i, observation)
                write(work / "hyperv-efi-boot.log", raw)
                write(work / "launched", b"")
                source_record, unused = ci.physical_file_record(
                    Path(config["source"]["path"]))
                del unused
                pins = [ci.pin_from_record(source_record)] + [
                    ci.pin_from_record(boot_inputs["files"][name])
                    for name in ("ovmf_code", "ovmf_vars", "qemu")
                ]
                write(work / "request.json", dict(
                    schema_version=2, supervisor_pid=12345, config=config,
                    pins=pins))
                write(work / "report.json", dict(
                    schema_version=1, scope="public_local_qemu_only", acceptance="not_established",
                    passed=True, consumed=True, cleanup_complete=True, input_unchanged=True,
                    serial_valid=True, serial_limit_reached=False, serial_bytes=len(raw),
                    serial_sha256=digest(raw), termination={"exited": 0},
                    failures=dict(primary=None, cleanup=None, recording=None)))
                write(root / "evidence" / (mode + "-compute.json"),
                      ci.check_boot(config, runtime_identity, boot_inputs))
            for stage in public_bundle.STAGES:
                write(root / "evidence" / ("command-" + stage + ".json"), dict(
                    scope="command_diagnostic_not_acceptance", stage=stage,
                    exit_code=0, bytes=1, sha256=digest(b"\n"), over_limit=False,
                    known_error_markers=[]))
            write(root / "evidence/result.json", dict(
                schema_version=1, scope="local_native_compute_only", passed=True,
                hardware_acceptance="not_established", cloud_authority="not_admitted",
                benchmark="not_measured", workload="tiny", modes=list(ci.MODES),
                records={p.name: ci.digest(p) for p in sorted((root / "evidence").glob("*.json"))}))
            original = (root / "evidence/result.json").read_bytes()

            def mocked_producer_inputs(actual_runtime, expected_consumer=None,
                                       content=True):
                self.assertEqual(actual_runtime, runtime)
                self.assertEqual(expected_consumer, consumer_inputs)
                self.assertTrue(content)
                return producer

            with mock.patch.object(ci, "check_build", return_value=build), \
                    mock.patch.object(
                        ci, "producer_inputs", autospec=True,
                        side_effect=mocked_producer_inputs):
                with mock.patch.object(ci, "require_build_custody"):
                    handoff.export(runtime, handoff_parent / "handoff")
        self.assertEqual((root / "evidence/result.json").read_bytes(), original)
        bundle_path = handoff_parent / "handoff/bundle.json"
        bundle = read(bundle_path)
        self.assertEqual(bundle["authority"], "not_admitted")
        self.assertEqual(len(bundle["boots"]), 4)
        revalidated = subprocess.run([VALIDATOR, "handoff", bundle_path],
                                    env={}, capture_output=True, timeout=60)
        self.assertEqual(revalidated.returncode, 0, revalidated.stderr)
        self.assertIn(b"authority=not_admitted", revalidated.stdout)
        self.public_archive_checks(bundle_path)
        self.scope.update(
            bundle=handoff.artifact(bundle_path),
            os_vhd=bundle["artifacts"][handoff.NAMES.index("vhd")],
            identity=bundle["identity"],
            source_revision=bundle["source_revision"],
            source_tree=bundle["source_tree"])
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

    def public_archive_checks(self, bundle_path):
        stage = bundle_path.parent
        bundle = read(bundle_path)
        source = dict(repository="cataggar/unikraft", run_id="1234567", run_attempt="1",
                      source_revision=bundle["source_revision"], source_tree=bundle["source_tree"],
                      wamr_revision=SDK)
        archive = self.root / "public.zip"
        for name in ("subscription.json", "sas.txt", "credentials", "extra"):
            write(stage / name, b"must never be published")
            with self.subTest(member=name), self.assertRaises(ValueError):
                public_bundle.pack(handoff, stage, archive, source, VALIDATOR)
            (stage / name).unlink()
            self.assertFalse(archive.exists())
        (stage / "unexpected-link").symlink_to(stage / "artifacts/raw")
        with self.assertRaises(ValueError):
            public_bundle.pack(handoff, stage, archive, source, VALIDATOR)
        (stage / "unexpected-link").unlink()
        archive_sha256 = public_bundle.pack(
            handoff, stage, archive, source, VALIDATOR)
        portable = public_bundle.verify_archive(
            handoff, archive, source, archive_sha256)
        with self.assertRaises(ValueError):
            public_bundle.verify_archive(handoff, archive, source, None)
        selected = public_bundle.members(handoff, portable)
        self.assertEqual(len(public_bundle.EVIDENCE), 20)
        self.assertNotIn("command-dependency-restore.json", public_bundle.EVIDENCE)
        with zipfile.ZipFile(archive) as zipped:
            self.assertEqual(set(zipped.namelist()), set(selected) | {"bundle.json", "public-source.json"})
            self.assertEqual(len(zipped.namelist()), 55)
            self.assertFalse(any("private/" in name or "diagnostic" in name for name in zipped.namelist()))
            self.assertEqual(zipped.read("boots/raw-x2apic/serial"),
                             (stage / "boots/raw-x2apic/serial").read_bytes())
            self.assertNotIn(str(self.root).encode(), zipped.read("bundle.json"))
            self.assertNotIn(str(self.root).encode(), zipped.read("public-source.json"))
        self.assertEqual(
            read(stage / "artifacts/build")["source"],
            {
                "revision": source["source_revision"],
                "tree": source["source_tree"],
            },
        )
        delivered = delivered_public_bundle()
        delivered.verify_archive(handoff, archive, source)
        delivered.publication_records(handoff, stage, source)
        output = self.root / "imported"
        imported = public_bundle.import_bundle(
            handoff, archive, output, source, archive_sha256, VALIDATOR)
        self.assertEqual(imported["authority"], "not_admitted")
        self.assertEqual((output / "artifacts/vhd").read_bytes(), (stage / "artifacts/vhd").read_bytes())
        self.assertEqual(handoff.plan(output / "bundle.json", self.root / "public-plan.json")["authority"],
                         "not_admitted")
        for key in ("source_revision", "source_tree", "wamr_revision", "run_id", "run_attempt"):
            wrong = dict(source, **{key: "2" if key.startswith("run_") else "c" * 40})
            with self.subTest(binding=key), self.assertRaises(ValueError):
                public_bundle.verify_archive(
                    handoff, archive, wrong, archive_sha256)
        for name in ("extra", "sas.txt", "../escape", "/absolute", "artifacts/raw/link"):
            bad = self.root / "bad-member.zip"
            shutil.copyfile(archive, bad)
            with zipfile.ZipFile(bad, "a") as zipped:
                info = zipfile.ZipInfo(name)
                info.create_system = 3
                info.external_attr = (stat.S_IFREG | 0o600) << 16
                zipped.writestr(info, b"x")
            with self.subTest(member=name), self.assertRaises(ValueError):
                public_bundle.verify_archive(
                    handoff, bad, source,
                    handoff.ci.digest(bad, public_bundle.MAX_TOTAL))
            bad.unlink()
        for name in ("artifacts/efi", "boots/raw-x2apic/report",
                     "boots/raw-x2apic/serial", "evidence/raw-x2apic-compute.json"):
            bad = self.root / "changed.zip"
            with zipfile.ZipFile(archive) as original, zipfile.ZipFile(bad, "w") as zipped:
                for info in original.infolist():
                    raw = original.read(info)
                    if info.filename == name:
                        raw = b"x" + raw[1:]
                    zipped.writestr(info, raw)
            with self.subTest(changed=name), self.assertRaises(ValueError):
                public_bundle.verify_archive(
                    handoff, bad, source,
                    handoff.ci.digest(bad, public_bundle.MAX_TOTAL))
            bad.unlink()
        bad = self.root / "symlink.zip"
        with zipfile.ZipFile(archive) as original, zipfile.ZipFile(bad, "w") as zipped:
            for info in original.infolist():
                raw = original.read(info)
                if info.filename == "artifacts/raw":
                    info.external_attr = (stat.S_IFLNK | 0o600) << 16
                zipped.writestr(info, raw)
        with self.assertRaises(ValueError):
            public_bundle.verify_archive(
                handoff, bad, source,
                handoff.ci.digest(bad, public_bundle.MAX_TOTAL))
        # Recomputed member digests still cannot promote a failed boot receipt.
        bad = self.root / "failed-receipt.zip"
        portable = copy.deepcopy(portable)
        with zipfile.ZipFile(archive) as original:
            report = json.loads(original.read("boots/raw-x2apic/report"))
            report["passed"] = False
            changed = public_bundle.encoded(report)
            item = portable["boots"][0]["report"]
            item.update(size=len(changed), sha256=digest(changed))
            manifest = json.loads(original.read("public-source.json"))
            manifest["members"]["boots/raw-x2apic/report"] = {
                "size": len(changed), "sha256": digest(changed)}
            with zipfile.ZipFile(bad, "w") as zipped:
                for info in original.infolist():
                    raw = original.read(info)
                    if info.filename == "boots/raw-x2apic/report":
                        raw = changed
                    elif info.filename == "bundle.json":
                        raw = public_bundle.encoded(portable)
                    elif info.filename == "public-source.json":
                        raw = public_bundle.encoded(manifest)
                    zipped.writestr(info, raw)
        failed = self.root / "failed-import"
        with self.assertRaises(ValueError):
            public_bundle.import_bundle(
                handoff, bad, failed, source,
                handoff.ci.digest(bad, public_bundle.MAX_TOTAL), VALIDATOR)
        self.assertFalse((failed / "bundle.json").exists())

        def rewritten_archive(label, mutate):
            changed_archive = self.root / ("current-" + label + ".zip")
            with zipfile.ZipFile(archive) as original:
                content = {
                    info.filename: original.read(info)
                    for info in original.infolist()
                }
                start = json.loads(content["evidence/build-start.json"])
                mutate(start)
                start_raw = public_bundle.encoded(start)
                content["evidence/build-start.json"] = start_raw
                content["artifacts/build_start"] = start_raw
                local_result = json.loads(content["artifacts/local_result"])
                local_result["records"]["build-start.json"] = digest(start_raw)
                local_result_raw = public_bundle.encoded(local_result)
                content["artifacts/local_result"] = local_result_raw
                changed_bundle = json.loads(content["bundle.json"])
                by_name = dict(zip(handoff.NAMES, changed_bundle["artifacts"]))
                by_name["build_start"].update(
                    size=len(start_raw), sha256=digest(start_raw))
                by_name["local_result"].update(
                    size=len(local_result_raw), sha256=digest(local_result_raw))
                evidence = dict(zip(
                    sorted(public_bundle.EVIDENCE), changed_bundle["evidence"]))
                evidence["build-start.json"].update(
                    size=len(start_raw), sha256=digest(start_raw))
                content["bundle.json"] = public_bundle.encoded(changed_bundle)
                manifest = json.loads(content["public-source.json"])
                for name in (
                        "artifacts/build_start", "artifacts/local_result",
                        "evidence/build-start.json"):
                    manifest["members"][name] = {
                        "size": len(content[name]),
                        "sha256": digest(content[name]),
                    }
                content["public-source.json"] = public_bundle.encoded(manifest)
                with zipfile.ZipFile(changed_archive, "w") as changed:
                    for info in original.infolist():
                        changed.writestr(info, content[info.filename])
            return changed_archive

        def remove_dependencies(start):
            start.pop("dependencies")

        def skeletal_dependencies(start):
            request = start["dependencies"]["request"]
            start["dependencies"] = {
                "schema": "uk.wamr.zig-dependency-custody",
                "version": 1,
                "request": request,
            }

        def tamper_package_tree(start):
            start["dependencies"]["packages"]["records"][0][
                "content"]["tree_sha256"] = "f" * 64

        for label, mutate in (
                ("removed", remove_dependencies),
                ("skeletal", skeletal_dependencies),
                ("tampered", tamper_package_tree)):
            changed_archive = rewritten_archive(label, mutate)
            changed_output = self.root / ("current-" + label + "-import")
            with self.subTest(dependency=label), self.assertRaises(ValueError):
                public_bundle.import_bundle(
                    handoff, changed_archive, changed_output, source,
                    handoff.ci.digest(
                        changed_archive, public_bundle.MAX_TOTAL),
                    VALIDATOR)
            self.assertFalse((changed_output / "bundle.json").exists())

        def mutate_git_oid(start):
            start["dependencies"]["source_manifests"]["build.zig"][
                "source"]["git_oid"] = "f" * 40

        def mutate_source_metadata_sha256(start):
            start["dependencies"]["source_manifests"]["build.zig"][
                "source"]["metadata_sha256"] = "f" * 64

        def mutate_hash_verification_sha256(start):
            start["dependencies"]["packages"]["hash_verification"][
                "sha256"] = "f" * 64

        def mutate_root_metadata_sha256(start):
            start["dependencies"]["packages"][
                "root_metadata_sha256"] = "f" * 64

        for label, mutate in (
                ("source-git-oid", mutate_git_oid),
                ("source-metadata-sha256", mutate_source_metadata_sha256),
                ("hash-verification-sha256",
                 mutate_hash_verification_sha256),
                ("root-metadata-sha256", mutate_root_metadata_sha256)):
            changed_archive = rewritten_archive(label, mutate)
            changed_sha256 = handoff.ci.digest(
                changed_archive, public_bundle.MAX_TOTAL)
            changed_output = self.root / (label + "-source-refusal")
            with self.subTest(custody=label), self.assertRaises(ValueError):
                public_bundle.import_bundle(
                    handoff, changed_archive, changed_output, source,
                    changed_sha256, VALIDATOR)
            self.assertFalse((changed_output / "bundle.json").exists())
            with self.subTest(external=label), self.assertRaises(ValueError):
                public_bundle.verify_archive(
                    handoff, changed_archive, source, archive_sha256)

        def forge_source_metadata(start):
            source_record = start["dependencies"]["source_manifests"][
                "build.zig"]["source"]
            source_record["metadata"][8] += 1
            source_record["metadata_sha256"] = public_bundle.metadata_sha256(
                source_record["metadata"])

        def forge_package_physical_custody(start):
            packages = start["dependencies"]["packages"]
            packages["records"][0]["content"]["physical_sha256"] = "f" * 64
            closure = hashlib.sha256(b"uk.wamr.package-closure-v1\0")
            physical = hashlib.sha256(
                b"uk.wamr.package-physical-closure-v1\0")
            for record in packages["records"]:
                public_bundle.bind(closure, record)
                public_bundle.bind(physical, [
                    record["package_hash"],
                    record["content"]["physical_sha256"],
                ])
            packages["closure_sha256"] = closure.hexdigest()
            packages["physical_sha256"] = physical.hexdigest()

        for label, mutate in (
                ("self-consistent-source-metadata", forge_source_metadata),
                ("self-consistent-package-physical",
                 forge_package_physical_custody)):
            changed_archive = rewritten_archive(label, mutate)
            with self.subTest(external=label), self.assertRaises(ValueError):
                public_bundle.verify_archive(
                    handoff, changed_archive, source, archive_sha256)

        def copied_stage(name):
            target = self.root / name
            shutil.copytree(stage, target)
            (target / "private/native-revalidation.log").unlink()
            (target / "evidence/command-native-revalidation.json").unlink()
            copied = read(target / "bundle.json")
            for item in copied["artifacts"] + copied["evidence"] + [
                    boot[key] for boot in copied["boots"]
                    for key in public_bundle.BOOT_KEYS]:
                item["path"] = str(target / Path(item["path"]).relative_to(stage))
            return target, copied

        def rewrite_stage(
                target, copied, start, build=None, image_identity=None,
                identity=None, legacy_v1=False):
            start_raw = public_bundle.encoded(start)
            for path in (target / "artifacts/build_start",
                         target / "evidence/build-start.json"):
                write(path, start_raw)
            changed_records = {"build-start.json": digest(start_raw)}
            if legacy_v1:
                current_inputs = read(target / "artifacts/boot_inputs")
                legacy_inputs = {
                    name: current_inputs["files"][name]["sha256"]
                    for name in (
                        "package_tool", "local_boot_tool", "qemu",
                        "ovmf_code", "ovmf_vars")
                }
                inputs_raw = public_bundle.encoded(legacy_inputs)
                for path in (target / "artifacts/boot_inputs",
                             target / "evidence/boot-inputs.json"):
                    write(path, inputs_raw)
                changed_records["boot-inputs.json"] = digest(inputs_raw)
                for mode in handoff.ci.MODES:
                    slot = target / "boots" / mode
                    request_path = slot / "request"
                    request = read(request_path)
                    request["schema_version"] = 1
                    request["pins"] = [
                        {"size": pin["size"], "sha256": pin["sha256"]}
                        for pin in request["pins"]
                    ]
                    write(request_path, public_bundle.encoded(request))
                    compute = read(slot / "compute")
                    compute.pop("input_pins")
                    compute["request_sha256"] = handoff.ci.digest(request_path)
                    compute_raw = public_bundle.encoded(compute)
                    write(slot / "compute", compute_raw)
                    write(target / "evidence" / (mode + "-compute.json"),
                          compute_raw)
                    changed_records[mode + "-compute.json"] = digest(
                        compute_raw)
            if build is not None:
                build_raw = public_bundle.encoded(build)
                for path in (target / "artifacts/build",
                             target / "evidence/build.json"):
                    write(path, build_raw)
                changed_records["build.json"] = digest(build_raw)
            local_result_path = target / "artifacts/local_result"
            local_result = read(local_result_path)
            local_result["records"].update(changed_records)
            write(local_result_path, public_bundle.encoded(local_result))
            if identity is not None:
                copied["source_revision"] = identity["source_revision"]
                copied["source_tree"] = identity["source_tree"]
            by_name = dict(zip(handoff.NAMES, copied["artifacts"]))
            for name, path in (
                    ("build_start", target / "artifacts/build_start"),
                    ("local_result", local_result_path)):
                by_name[name].update(
                    size=path.stat().st_size, sha256=handoff.ci.digest(path))
            if legacy_v1:
                path = target / "artifacts/boot_inputs"
                by_name["boot_inputs"].update(
                    size=path.stat().st_size, sha256=handoff.ci.digest(path))
            if build is not None:
                path = target / "artifacts/build"
                by_name["build"].update(
                    size=path.stat().st_size, sha256=handoff.ci.digest(path))
            if image_identity is not None:
                path = target / "artifacts/image_identity"
                write(path, public_bundle.encoded(image_identity))
                by_name["image_identity"].update(
                    size=path.stat().st_size, sha256=handoff.ci.digest(path))
            evidence = dict(zip(sorted(public_bundle.EVIDENCE), copied["evidence"]))
            for name in changed_records:
                path = target / "evidence" / name
                evidence[name].update(
                    size=path.stat().st_size, sha256=handoff.ci.digest(path))
            if legacy_v1:
                boots = {boot["mode"]: boot for boot in copied["boots"]}
                for mode in handoff.ci.MODES:
                    for name in ("request", "compute"):
                        path = target / "boots" / mode / name
                        boots[mode][name].update(
                            size=path.stat().st_size,
                            sha256=handoff.ci.digest(path))
            write(target / "bundle.json", public_bundle.encoded(copied))

        legacy_sources = (
            (
                "993e4d0d394c08202c0d0c57ea97450a19a4f394",
                "54f8e118146c78c24e7c802657c6ec62b268a5de",
            ),
            (
                "34e5c88a165c4da878b3122b8b91716116d65d4b",
                "54f8e118146c78c24e7c802657c6ec62b268a5de",
            ),
            (
                "b5a8fdbee033349f7145fbc76aebfee29b2fa04f",
                "54f8e118146c78c24e7c802657c6ec62b268a5de",
            ),
        )
        self.assertEqual(
            public_bundle.LEGACY_V1_SOURCES, frozenset(legacy_sources))
        for index, (legacy_revision, legacy_tree) in enumerate(
                legacy_sources):
            old_stage, old_bundle = copied_stage(
                f"old-v1-stage-{index}")
            old_source = dict(
                source, source_revision=legacy_revision,
                source_tree=legacy_tree)
            old_start = dict(
                source={
                    "revision": legacy_revision,
                    "tree": legacy_tree,
                },
                fixture_only=True,
            )
            old_build = read(old_stage / "artifacts/build")
            old_build["source"] = {
                "revision": legacy_revision,
                "tree": legacy_tree,
            }
            old_image_identity = read(
                old_stage / "artifacts/image_identity")
            old_image_identity["unikraft_revision"] = legacy_revision
            old_build["image"] = old_image_identity
            rewrite_stage(
                old_stage, old_bundle, old_start, build=old_build,
                image_identity=old_image_identity, identity=old_source,
                legacy_v1=True)
            old_archive = self.root / f"old-v1-{index}.zip"
            delivered.pack(
                handoff, old_stage, old_archive, old_source, VALIDATOR)
            public_bundle.verify_archive(
                handoff, old_archive, old_source, None)
            public_bundle.publication_records(
                handoff, old_stage, old_source)
            old_output = self.root / f"old-v1-imported-{index}"
            delivered.import_bundle(
                handoff, old_archive, old_output, old_source, VALIDATOR)
            self.assertNotIn(
                "dependencies",
                read(old_output / "evidence/build-start.json"),
            )

        unrelated_stage, unrelated_bundle = copied_stage(
            "unrelated-v1-stage")
        unrelated_revision = "f" * 40
        unrelated_tree = legacy_sources[0][1]
        unrelated_source = dict(
            source, source_revision=unrelated_revision,
            source_tree=unrelated_tree)
        unrelated_start = {
            "source": {
                "revision": unrelated_revision,
                "tree": unrelated_tree,
            },
            "fixture_only": True,
        }
        unrelated_build = read(unrelated_stage / "artifacts/build")
        unrelated_build["source"] = unrelated_start["source"]
        unrelated_image_identity = read(
            unrelated_stage / "artifacts/image_identity")
        unrelated_image_identity["unikraft_revision"] = unrelated_revision
        unrelated_build["image"] = unrelated_image_identity
        rewrite_stage(
            unrelated_stage, unrelated_bundle, unrelated_start,
            build=unrelated_build,
            image_identity=unrelated_image_identity,
            identity=unrelated_source, legacy_v1=True)
        with self.assertRaises(ValueError):
            public_bundle.pack(
                handoff, unrelated_stage, self.root / "unrelated-v1.zip",
                unrelated_source, VALIDATOR)

    def test_public_export_has_no_arbitrary_private_tree_mode(self):
        with mock.patch.dict(os.environ, {}, clear=True), self.assertRaises(ValueError):
            public_bundle.publish_ci(handoff)
        with mock.patch.dict(os.environ, {
                "GITHUB_ACTIONS": "true", "GITHUB_REPOSITORY": "private/repo",
                "GITHUB_JOB": "wamr-native-compute"}, clear=True), self.assertRaises(ValueError):
            public_bundle.publish_ci(handoff)
        import io
        for secret in public_bundle.SENSITIVE:
            with self.subTest(secret=secret), self.assertRaises(ValueError):
                public_bundle.copy_checked(io.BytesIO(secret), None,
                                           {"size": len(secret), "sha256": digest(secret)})

if __name__ == "__main__":
    unittest.main()
