# SPDX-License-Identifier: BSD-3-Clause
"""Synthetic unit/physical packaging fixtures; never real guest boot evidence."""
import ast
import base64
import copy
import contextlib
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
import threading
import time
import types
import unittest
from unittest import mock
import zipfile

HERE = Path(__file__).resolve().parents[1]
PYTHON = os.environ.get("WAMR_CI_PYTHON", sys.executable)
GIT = os.environ.get("WAMR_CI_GIT", "git")
SUPERVISOR = os.environ.get("WAMR_CI_SUPERVISOR")
SUPERVISOR_FIXTURE = os.environ.get("WAMR_CI_SUPERVISOR_FIXTURE")
LOG_VALIDATE = os.environ.get("WAMR_CI_LOG_VALIDATE")
spec = importlib.util.spec_from_file_location("wamr_ci", HERE / "run.py")
ci = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ci)
if SUPERVISOR is not None:
    ci.COMMAND_SUPERVISOR_PATH = str(
        Path(SUPERVISOR).resolve(strict=True))
bundle_spec = importlib.util.spec_from_file_location(
    "wamr_public_bundle", HERE / "public_bundle.py")
public_bundle = importlib.util.module_from_spec(bundle_spec)
bundle_spec.loader.exec_module(public_bundle)
ci.COMMAND_TOOL_PATHS.update({
    name: os.environ["WAMR_CI_TOOL_" + name.upper().replace("-", "_")]
    for name in ci.HOST_TOOLS
    if "WAMR_CI_TOOL_" + name.upper().replace("-", "_") in os.environ
})


class Contract(unittest.TestCase):
    def setUp(self):
        self.identity = {
            "wamr_revision": "f" * 40, "minimal_wasi": False,
            "files": {"tiny.wasm": "0" * 64, "tiny.cwasm": "1" * 64,
                      "libwamr-aot.a": "2" * 64},
        }
        self.result = {
            "version": 1, "workload": "tiny", "wamr_revision": "f" * 40,
            "wasm_sha256": "0" * 64, "cwasm_sha256": "1" * 64,
            "runtime_sha256": "2" * 64, "platform_status": 0, "checks": 2,
            "answer": 42, "terminal": 1, "detail": 2, "reserved_bytes": 0,
            "frame_bytes": 0, "accessible_bytes": 0, "allocation_bytes": 0,
            "error_name": "", "system_page_table_bytes": 4096,
        }

    def log(self, legacy=False):
        return ("\n".join([
            ci.LEGACY if legacy else "",
            "Hyper-V Hv#1 hypercall page enabled", "Hyper-V SynIC:",
            "Powered by", "Calling main(0, 0)",
            "WAMR_NATIVE_COMPUTE=" + json.dumps(self.result), ci.MARKER,
            "main returned 0", "",
        ])).encode()

    def test_legacy_four_exact_disk_modes_never_hardware_return(self):
        for index in range(4):
            config = ci.config_for(Path("/runtime"), Path("/runtime/compute"), index)
            args = ci.boot_args(Path("/native-local-boot"), config)
            self.assertEqual(config["expect_main_return"], 0)
            self.assertEqual(config["cpus"], 1)
            self.assertEqual(config["source"]["kind"],
                             "raw_disk" if index < 2 else "fixed_vhd")
            self.assertEqual("--disable-x2apic" in args, bool(index % 2))
            self.assertEqual("--raw-disk" in args, index < 2)
            self.assertEqual("--fixed-vhd" in args, index >= 2)
            self.assertNotIn("--image", args)
            self.assertIn("60", args)
            self.assertIn(ci.MARKER, args)

    def test_current_six_modes_bind_raw_qcow2_and_derived_vhd(self):
        self.assertEqual(ci.SIX_MODES, (
            "raw-x2apic", "raw-legacy-apic",
            "qcow2-x2apic", "qcow2-legacy-apic",
            "vpc-x2apic", "vpc-legacy-apic",
        ))
        expected = (
            ("raw_disk", "--raw-disk"),
            ("raw_disk", "--raw-disk"),
            ("qcow2", "--qcow2"),
            ("qcow2", "--qcow2"),
            ("fixed_vhd", "--fixed-vhd"),
            ("fixed_vhd", "--fixed-vhd"),
        )
        for index, (kind, flag) in enumerate(expected):
            with self.subTest(mode=ci.SIX_MODES[index]):
                config = ci.config_for(
                    Path("/runtime"), Path("/runtime/compute"), index,
                    ci.SIX_MODES)
                args = ci.boot_args(Path("/native-local-boot"), config)
                self.assertEqual(config["source"]["kind"], kind)
                self.assertIn(flag, args)
                self.assertEqual(
                    "--disable-x2apic" in args, bool(index % 2))
                self.assertEqual(config["expect_main_return"], 0)
                self.assertEqual(config["cpus"], 1)

    def test_build_refuses_development_and_optional_images(self):
        identity = {
            "wamr_revision": ci.REVISION, "minimal_wasi": False,
            "compiler_profile": "unikraft-x86_64", "zig_version": "0.16.0",
            "variant": "tiny", "development_only": False, "jit_mode": None,
        }
        for key, value in (("development_only", True), ("variant", "snapshot"),
                           ("variant", "jit"), ("variant", "sample-aot"),
                           ("jit_mode", "fast"), ("jit_mode", "full")):
            with self.subTest(key=key, value=value), \
                    mock.patch.object(ci, "document", return_value=dict(identity, **{key: value})), \
                    mock.patch.object(ci, "digest", side_effect=AssertionError("artifact read")), \
                    self.assertRaisesRegex(ci.Refusal, "not the pinned tiny producer"):
                ci.check_build()

    def test_production_build_stages_bind_only_the_native_wamr_controller(self):
        executable = ci.command_path(ci.WAMR_AOT_BUILD_ROLE)
        expected = {
            "prepare": [
                executable,
                ci.command_literal("prepare"),
                ci.command_literal("--repository"),
                ci.command_path("source"),
                ci.command_literal("--source-archive"),
                ci.command_path("runtime", "custody/wamr-source.tar"),
            ],
            "config": [
                executable,
                ci.command_literal("olddefconfig"),
                ci.command_literal("--repository"),
                ci.command_path("source"),
            ],
            "native-image": [
                executable,
                ci.command_literal("native-images"),
                ci.command_literal("--repository"),
                ci.command_path("source"),
            ],
        }
        for stage, argv in expected.items():
            with self.subTest(stage=stage):
                contract = ci.production_command_contract(stage)
                self.assertEqual(contract["kind"], "build-native")
                self.assertEqual(contract["command_executable"], executable)
                self.assertEqual(contract["native_executable"], executable)
                self.assertIsNone(contract["interpreter"])
                self.assertEqual(contract["argv"], argv)
                environment = {
                    item["name"] for item in contract["environment"]
                }
                self.assertNotIn("WAMR_CI_PYTHON", environment)
                self.assertNotIn("WAMR_CI_PYTHON",
                                 contract["retained_names"])

    def test_native_producer_has_no_python_controller_fallback(self):
        production = (
            ci.APP / "Makefile",
            ci.APP / "Makefile.uk",
            ci.APP / "README.md",
            ci.APP / "WORKLOADS.md",
            ci.APP / "Config.uk",
            ci.HERE / "run.py",
            ci.HERE / "README.md",
            ci.REPO / ".github/workflows/wamr-native-compute.yaml",
        )
        for path in production:
            with self.subTest(path=path):
                text = path.read_text()
                self.assertNotIn("prepare.py", text)
                self.assertNotIn("build-image.py", text)
        self.assertFalse((ci.APP / "prepare.py").exists())
        self.assertFalse((ci.APP / "build-image.py").exists())
        self.assertFalse((ci.APP / "tests/test_prepare_differential.py").exists())
        self.assertFalse((ci.APP / "tests/test_image_differential.py").exists())
        self.assertIn(
            f'pub const revision = "{ci.REVISION}";',
            (ci.APP / "build-tool-contract.zig").read_text(),
        )
        self.assertIn(
            f"ref: {ci.REVISION}",
            (ci.REPO / ".github/workflows/wamr-native-compute.yaml").read_text(),
        )
        makefile = (ci.APP / "Makefile").read_text()
        makefile_uk = (ci.APP / "Makefile.uk").read_text()
        self.assertIn(
            "APPWAMRAOT_TOOL ?= "
            "$(CURDIR)/build/tool/bin/uk-wamr-aot-build",
            makefile,
        )
        self.assertIn(
            '"$(APPWAMRAOT_TOOL)" verify --repository "$(CONFIG_UK_BASE)"',
            makefile_uk,
        )
        self.assertNotIn("command -v", makefile + makefile_uk)

    def test_adapter_installs_the_app_owned_native_wamr_artifact(self):
        manifest = (ci.HERE / "build.zig.zon").read_text()
        build = (ci.HERE / "build.zig").read_text()
        self.assertIn(
            '.wamr_aot_build = .{ .path = "../../apps/wamr-aot" }',
            manifest,
        )
        self.assertEqual(
            build.count('b.dependency("wamr_aot_build"'), 1)
        self.assertEqual(
            build.count(
                'wamr_aot_build.artifact("uk-wamr-aot-build")'),
            1,
        )
        self.assertIn(
            '.root_source_file = b.path("../../apps/wamr-aot/validator/main.zig")',
            build,
        )
        self.assertIn('b.installArtifact(log_cli)', build)
        self.assertNotIn('uk-wamr-log-validate', ci.PRODUCTION_COMMAND_STAGES)


class PhysicalPackage(unittest.TestCase):
    """Run the actual native adapter + pinned miz on a nonbootable synthetic PE."""

    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="wamr-native-ci-"))
        self.root.chmod(0o700)
        self.addCleanup(shutil.rmtree, self.root)
        self.cli = Path(os.environ["WAMR_CI_PACKAGE"]).resolve(strict=True)
        self.efi = self.root / "synthetic.efi"
        data = bytearray(512)
        data[:2] = b"MZ"
        struct.pack_into("<I", data, 0x3c, 0x80)
        data[0x80:0x84] = b"PE\0\0"
        for offset, value in ((0x84, 0x8664), (0x86, 1), (0x94, 0xf0),
                              (0x98, 0x20b), (0xdc, 10)):
            struct.pack_into("<H", data, offset, value)
        self.efi.write_bytes(data)
        self.efi.chmod(0o600)
        self.state = self.root / "package"

    def call(self, command, success=True, precreate=True):
        if command == "package" and precreate and not self.state.exists():
            self.state.mkdir(mode=0o700)
        result = subprocess.run([self.cli, command, self.efi, self.state],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                timeout=150, check=False)
        if success:
            self.assertEqual(result.returncode, 0, result.stderr)
            return json.loads(result.stdout)
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn(str(self.root).encode(), result.stderr)

    def test_real_packaging_full_vhd_reload_and_no_reuse(self):
        report = self.call("package")
        self.assertEqual(report["scope"], "public_local_compute_packaging_only")
        self.assertEqual(report["acceptance"], "not_established")
        self.assertEqual(report["image"]["efi"]["sha256"], ci.digest(self.efi))
        self.assertEqual(report["image"]["raw"]["size"], 66 * ci.MIB)
        self.assertEqual(report["image"]["vhd"]["size"], 66 * ci.MIB + 512)
        for name in ("raw", "vhd"):
            self.assertEqual(report["image"][name]["sha256"],
                             ci.digest(self.state / ("unikraft." + name)))
        with (self.state / "unikraft.vhd").open("rb") as stream:
            stream.seek(-512, 2)
            self.assertEqual(report["image"]["footer_sha256"],
                             hashlib.sha256(stream.read()).hexdigest())
        self.assertEqual(self.call("inspect"), report)
        self.call("package", success=False)
        with (self.state / "unikraft.vhd").open("r+b") as stream:
            stream.seek(-1, 2)
            stream.write(b"\x01")
        self.call("inspect", success=False)

    def test_changed_efi_and_unfinished_package_refuse(self):
        self.state.mkdir(mode=0o700)
        self.call("inspect", success=False)
        (self.state / ".writer.lock").unlink()
        self.state.rmdir()
        self.call("package")
        with self.efi.open("r+b") as stream:
            stream.seek(511)
            stream.write(b"\x01")
        self.call("inspect", success=False)

    def test_package_requires_precreated_empty_state(self):
        self.call("package", success=False, precreate=False)
        self.state.mkdir(mode=0o700)
        (self.state / "unexpected").write_bytes(b"x")
        self.call("package", success=False)

    @unittest.skipIf(not SUPERVISOR, "native command supervisor unavailable")
    def test_supervised_python_does_not_rebind_nested_package_identity(self):
        controller = self.root / "controller"
        (controller / "private").mkdir(parents=True, mode=0o700)
        (controller / "evidence").mkdir(mode=0o700)
        self.state.mkdir(mode=0o700)
        script = (
            "import subprocess,sys\n"
            "result=subprocess.run(sys.argv[1:],stdout=subprocess.PIPE,"
            "stderr=subprocess.PIPE)\n"
            "sys.stdout.buffer.write(result.stdout)\n"
            "sys.stderr.buffer.write(result.stderr)\n"
            "raise SystemExit(result.returncode)\n"
        )
        output, unused_record = ci.execute(
            controller, "nested-package",
            [PYTHON, "-c", script, self.cli, "package",
             self.efi, self.state],
            seconds=150, limit=ci.MIB, evidence=False)
        del unused_record
        report = json.loads(output.read_bytes())
        self.assertEqual(report["image"]["efi"]["sha256"], ci.digest(self.efi))
        self.assertEqual(self.call("inspect"), report)


class Evidence(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="wamr-native-ci-"))
        self.root.chmod(0o700)
        self.addCleanup(shutil.rmtree, self.root)
        for name in ("private", "evidence", "package", "firmware", "bin"):
            (self.root / name).mkdir(mode=0o700)
        self.contract = Contract()
        self.contract.setUp()
        validator = mock.patch.object(
            ci, "native_compute", side_effect=self.fixture_native_compute)
        validator.start()
        self.fixture_validator = validator
        self.addCleanup(validator.stop)

    def put(self, path, value):
        path.write_bytes(value)
        path.chmod(0o600)

    def fixture_native_compute(self, work, identity_path, identity, raw,
                               legacy, consumer_inputs):
        self.assertIsNotNone(LOG_VALIDATE)
        self.assertEqual(ci.document(identity_path), identity)
        self.assertEqual((work / "hyperv-efi-boot.log").read_bytes(), raw)
        self.assertIsNotNone(consumer_inputs)
        result = subprocess.run(
            [LOG_VALIDATE, "tiny", "--log", str(work / "hyperv-efi-boot.log"),
             "--identity", str(identity_path), "--legacy-apic",
             "required" if legacy else "forbidden", "--output", "json-v1"],
            capture_output=True, env={}, timeout=15)
        if result.returncode:
            raise ci.Refusal("native validator refused synthetic boot")
        observed = json.loads(result.stdout, object_pairs_hook=ci.unique)
        self.assertEqual(observed["raw_serial_bytes"], len(raw))
        self.assertEqual(observed["raw_serial_sha256"],
                         hashlib.sha256(raw).hexdigest())
        return observed["compute"]

    def check_fixture_boot(self, config, identity):
        return ci.check_boot(
            config, identity, consumer_inputs={"files": {}},
            identity_path=self.root / "private/identity.json")

    def supervised_binding(self, stage):
        contract = ci.production_command_contract(stage)
        roles = {
            "command-supervisor",
            contract["native_executable"]["role"],
            contract["command_executable"]["role"],
        }
        if contract["interpreter"] is not None:
            roles.add(contract["interpreter"]["role"])
        environment = {
            item["name"]: item["value"]
            for item in contract["environment"]
        }
        roles.update(
            environment[name]["role"]
            for name in contract["retained_names"])
        identities = {}
        for index, role in enumerate(sorted(roles), 1):
            identities[role] = {
                "content_sha256": hashlib.sha256(
                    role.encode("ascii")).hexdigest(),
                "ctime_nanoseconds": index,
                "ctime_seconds": 1,
                "device_major": 1,
                "device_minor": 2,
                "inode": index,
                "mode": stat.S_IFREG | 0o500,
                "mtime_nanoseconds": index,
                "mtime_seconds": 1,
                "size": 4096 + index,
                "uid": os.getuid(),
            }

        def binding(path):
            return {
                "path": copy.deepcopy(path),
                "identity": identities[path["role"]],
            }

        primary = 10_000_000_000_000
        issued = primary - contract["seconds"] * 1_000_000_000
        request_core = {
            "binding_schema": ci.COMMAND_BINDING_SCHEMA,
            "binding_version": ci.COMMAND_BINDING_VERSION,
            "stage": stage,
            "schema": "uk.wamr.command-supervisor-request",
            "version": 1,
            "argv": copy.deepcopy(contract["argv"]),
            "environment": copy.deepcopy(contract["environment"]),
            "cwd": copy.deepcopy(contract["cwd"]),
            "supervisor": binding(ci.command_path("command-supervisor")),
            "native_executable": binding(contract["native_executable"]),
            "command_executable": binding(contract["command_executable"]),
            "interpreter": (
                None if contract["interpreter"] is None
                else binding(contract["interpreter"])
            ),
            "retained_executables": [
                {
                    "name": name,
                    **binding(environment[name]),
                }
                for name in contract["retained_names"]
            ],
            "issued_ns": issued,
            "primary_deadline_ns": primary,
            "cleanup_deadline_ns":
                primary + ci.COMMAND_CLEANUP_SECONDS * 1_000_000_000,
            "timeout_ns": contract["seconds"] * 1_000_000_000,
            "limits": copy.deepcopy(contract["limits"]),
        }
        request = {
            **request_core,
            "canonical_sha256": ci.command_binding_digest(request_core),
            "argv_sha256": ci.command_binding_digest(request_core["argv"]),
            "environment_sha256": ci.command_binding_digest(
                request_core["environment"]),
            "cwd_sha256": ci.command_binding_digest(request_core["cwd"]),
        }
        empty = hashlib.sha256(b"").hexdigest()
        output_commitment = ci.command_output_commitment(
            0, empty, 0, empty)
        started = issued + 1
        primary_completed = started + 2
        completed = primary_completed + 3
        command = {
            "cancellation_observed": False,
            "cleanup": "complete",
            "cleanup_complete": True,
            "cleanup_events": ci.COMMAND_COMPLETE_CLEANUP_EVENTS_MIN,
            "descendants": {
                "adopted": 0,
                "identity_validated": 0,
                "limit_exceeded": False,
                "observed": 0,
                "untracked": False,
            },
            "executable": request["native_executable"]["identity"],
            "executable_stable": True,
            "output": {
                "bytes": 0,
                "combined_sha256": empty,
                "commitment_sha256": output_commitment,
                "digest_scope": "reproducible_empty",
            },
            "poisoned": False,
            "primary": {"code": 0, "kind": "exited"},
            "primary_deadline_reached": False,
            "primary_events": ci.COMMAND_COMPLETE_PRIMARY_EVENTS_MIN,
            "reap_events": 2,
            "retained_executables": copy.deepcopy(
                request["retained_executables"]),
            "stderr": {
                "bytes": 0, "digest_scope": "reproducible_empty",
                "sha256": empty, "status": "complete",
            },
            "stdout": {
                "bytes": 0, "digest_scope": "reproducible_empty",
                "sha256": empty, "status": "complete",
            },
            "timing": {
                "cleanup_elapsed_ns": completed - primary_completed,
                "completed_ns": completed,
                "primary_completed_ns": primary_completed,
                "primary_elapsed_ns": primary_completed - started,
                "started_ns": started,
                "total_elapsed_ns": completed - started,
            },
            "termination": {"code": 0, "kind": "exited"},
        }
        result_core = {
            "schema": "uk.wamr.command-supervisor-result",
            "version": 1,
            "request_canonical_sha256": request["canonical_sha256"],
            "controller_error": None,
            "native_request": {
                "bytes": 128,
                "digest_scope": "direct_producer_or_trusted_inner_zip",
                "sha256": hashlib.sha256(b"native-request").hexdigest(),
            },
            "native_result": {
                "bytes": 256,
                "digest_scope": "direct_producer_or_trusted_inner_zip",
                "sha256": hashlib.sha256(b"native-result").hexdigest(),
            },
            "command": command,
        }
        record = {
            "scope": "command_diagnostic_not_acceptance",
            "stage": stage,
            "exit_code": 0,
            "bytes": 0,
            "sha256": empty,
            "sha256_scope": "reproducible_empty",
            "over_limit": False,
            "known_error_markers": [],
            "supervisor": {
                "schema": "uk.wamr.command-supervisor-result",
                "version": 1,
                "bootstrap": False,
                "request": request,
                "result": {
                    **result_core,
                    "canonical_sha256":
                        ci.command_binding_digest(result_core),
                },
            },
        }
        return record, identities

    def rehash_supervised_binding(self, record):
        request = record["supervisor"]["request"]
        for name, value in (
                ("argv_sha256", request["argv"]),
                ("environment_sha256", request["environment"]),
                ("cwd_sha256", request["cwd"])):
            request[name] = ci.command_binding_digest(value)
        request_core = {
            key: value for key, value in request.items()
            if key not in {
                "canonical_sha256", "argv_sha256",
                "environment_sha256", "cwd_sha256",
            }
        }
        request["canonical_sha256"] = ci.command_binding_digest(
            request_core)
        result = record["supervisor"]["result"]
        result["request_canonical_sha256"] = request["canonical_sha256"]
        result_core = dict(result)
        result_core.pop("canonical_sha256", None)
        result["canonical_sha256"] = ci.command_binding_digest(result_core)
        return record

    def source_repository(self, name="source-repository", extra=None):
        repository = self.root / name
        app = repository / "support/apps/wamr-aot"
        app.mkdir(parents=True, mode=0o700)
        source = repository / "source"
        source.mkdir(mode=0o700)
        self.put(source / "input", b"tracked\n")
        self.put(app / "defconfig", b"CONFIG_FIXTURE=y\n")
        self.put(repository / ".gitignore", b"""\
/.d/
/.zig-cache/
/support/apps/wamr-aot/.config
/support/apps/wamr-aot/build/
*.o
*.a
*.pyc
""")
        for relative, data in (extra or {}).items():
            path = repository / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            self.put(path, data)
        subprocess.run([GIT, "init", "-q"], cwd=repository, check=True)
        subprocess.run([GIT, "config", "user.email", "fixture@example.invalid"],
                       cwd=repository, check=True)
        subprocess.run([GIT, "config", "user.name", "Fixture"],
                       cwd=repository, check=True)
        subprocess.run([GIT, "add", "."], cwd=repository, check=True)
        subprocess.run([GIT, "commit", "-qm", "fixture"],
                       cwd=repository, check=True)
        (repository / ".d").mkdir(mode=0o700)
        (repository / ".zig-cache").mkdir(mode=0o700)
        (app / "build").mkdir(mode=0o700)
        self.put(app / ".config", b"CONFIG_FIXTURE=y\n")
        return repository

    def test_reading_can_update_atime_without_changing_identity(self):
        path = self.root / "first-read"
        self.put(path, b"fresh build artifact")
        os.utime(path, ns=(1, path.stat().st_mtime_ns))
        self.assertEqual(ci.digest(path), hashlib.sha256(b"fresh build artifact").hexdigest())

    def test_private_bison_content_binding_and_refusals(self):
        root = self.root / "bison"
        root.mkdir(mode=0o700)
        file = root / "skeleton"
        self.put(file, b"first")
        self.put(root / "empty", b"")
        before = ci.bison_inputs(root)
        self.assertEqual((before["files"], before["bytes"]), (2, 5))
        self.put(file, b"other")
        self.assertNotEqual(before["sha256"], ci.bison_inputs(root)["sha256"])
        file.chmod(0o666)
        with self.assertRaises(ci.Refusal):
            ci.bison_inputs(root)
        file.chmod(0o600)
        (root / "link").symlink_to(file)
        with self.assertRaises(ci.Refusal):
            ci.bison_inputs(root)
        (root / "link").unlink()
        root.chmod(0o755)
        with self.assertRaises(ci.Refusal):
            ci.bison_inputs(root)

    def test_bison_entry_and_byte_bounds(self):
        root = self.root / "bison"
        root.mkdir(mode=0o700)
        with self.assertRaises(ci.Refusal):
            ci.bison_inputs(root)
        self.put(root / "oversized", b"x" * (8 * ci.MIB + 1))
        with self.assertRaises(ci.Refusal):
            ci.bison_inputs(root)
        (root / "oversized").unlink()
        for index in range(513):
            self.put(root / str(index), b"")
        with self.assertRaises(ci.Refusal):
            ci.bison_inputs(root)

    def test_consumer_input_records_bind_inode_metadata_directories_and_content(self):
        inputs = self.root / "consumer-inputs"
        tree = inputs / "tree"
        tree.mkdir(parents=True, mode=0o700)
        executable = inputs / "tool"
        self.put(executable, b"#!/bin/sh\nexit 0\n")
        executable.chmod(0o700)
        self.put(tree / "data", b"same bytes")
        file_paths = {"tool:fixture": executable}
        tree_paths = {"fixture": tree}
        expected = ci.record_input_paths(
            file_paths, tree_paths)
        ci.record_input_paths(
            file_paths, tree_paths, content=False, expected=expected)

        retained = inputs / "retained"
        executable.rename(retained)
        self.put(executable, retained.read_bytes())
        executable.chmod(0o700)
        changed = ci.record_input_paths(
            {"tool:fixture": executable}, {"fixture": tree})
        self.assertEqual(
            expected["files"]["tool:fixture"]["sha256"],
            changed["files"]["tool:fixture"]["sha256"],
        )
        self.assertNotEqual(
            expected["files"]["tool:fixture"]["metadata"],
            changed["files"]["tool:fixture"]["metadata"],
        )
        executable.unlink()
        retained.rename(executable)
        with self.assertRaisesRegex(ci.Refusal, "custody changed"):
            ci.record_input_paths(
                file_paths, tree_paths, content=False, expected=expected)

        refreshed = ci.record_input_paths(
            {"tool:fixture": executable}, {"fixture": tree})
        executable.chmod(0o500)
        executable.chmod(0o700)
        with self.assertRaisesRegex(ci.Refusal, "custody changed"):
            ci.record_input_paths(
                file_paths, tree_paths, content=False, expected=refreshed)

        hardlink = inputs / "hardlink"
        os.link(executable, hardlink)
        with self.assertRaisesRegex(ci.Refusal, "unsafe physical input"):
            ci.physical_file_record(executable)
        hardlink.unlink()
        symlink = inputs / "symlink"
        symlink.symlink_to(executable)
        with self.assertRaisesRegex(ci.Refusal, "unsafe physical input"):
            ci.physical_file_record(symlink)

    def test_current_input_records_reject_rehashed_omissions_and_substitutions(self):
        inputs = self.root / "independent-input-discovery"
        consumer_tree = inputs / "consumer-tree"
        qemu_data = inputs / "qemu-data"
        consumer_tree.mkdir(parents=True, mode=0o700)
        qemu_data.mkdir(mode=0o700)
        self.put(consumer_tree / "data", b"consumer")
        self.put(qemu_data / "firmware", b"qemu")
        direct = inputs / "direct"
        runtime = inputs / "runtime"
        boot = inputs / "boot"
        replacement = inputs / "replacement"
        for path, data in (
                (direct, b"direct"), (runtime, b"runtime"),
                (boot, b"boot"), (replacement, b"replacement")):
            self.put(path, data)
        consumer_files = {
            "tool:direct": direct,
            f"runtime:{runtime}": runtime,
        }
        consumer_trees = {"zig": consumer_tree}
        consumer = ci.record_input_paths(consumer_files, consumer_trees)
        boot_files = {
            "qemu": boot,
            f"runtime:{runtime}": runtime,
        }
        boot_trees = {"qemu-data": qemu_data}
        boot_record = ci.record_input_paths(boot_files, boot_trees)

        def rehash(value):
            value = copy.deepcopy(value)
            value.pop("aggregate_sha256")
            value["aggregate_sha256"] = ci.record_digest(value)
            return value

        with mock.patch.object(
                ci, "discover_consumer_input_paths",
                return_value=(consumer_files, consumer_trees)):
            for role in consumer_files:
                forged = copy.deepcopy(consumer)
                del forged["files"][role]
                forged = rehash(forged)
                with self.subTest(consumer_omission=role), \
                        self.assertRaisesRegex(ci.Refusal, "roles changed"):
                    ci.consumer_input_state(
                        inputs, content=False, expected=forged)
            forged = copy.deepcopy(consumer)
            del forged["trees"]["zig"]
            forged = rehash(forged)
            with self.assertRaisesRegex(ci.Refusal, "roles changed"):
                ci.consumer_input_state(inputs, content=False, expected=forged)
            forged = copy.deepcopy(consumer)
            forged["files"]["tool:direct"]["path"] = str(replacement)
            forged = rehash(forged)
            with self.assertRaisesRegex(ci.Refusal, "paths changed"):
                ci.consumer_input_state(inputs, content=False, expected=forged)
            forged = copy.deepcopy(consumer)
            forged["version"] = 1
            forged = rehash(forged)
            with self.assertRaisesRegex(
                    ci.Refusal, "invalid consumer input custody"):
                ci.consumer_input_state(inputs, content=False, expected=forged)

        with mock.patch.object(
                ci, "discover_boot_input_paths",
                return_value=(boot_files, boot_trees)):
            for kind, role in (
                    ("boot", "qemu"),
                    ("runtime", f"runtime:{runtime}")):
                forged = copy.deepcopy(boot_record)
                del forged["files"][role]
                forged = rehash(forged)
                with self.subTest(boot_omission=kind), \
                        self.assertRaisesRegex(
                            ci.Refusal,
                            "boot input file roles changed.*"
                            + (r"direct -0/\+1"
                               if kind == "boot" else r"runtime -0/\+1")):
                    ci.boot_input_state(
                        inputs, {"qemu": boot}, content=False,
                        expected=forged)
            forged = copy.deepcopy(boot_record)
            del forged["trees"]["qemu-data"]
            forged = rehash(forged)
            with self.assertRaisesRegex(ci.Refusal, "roles changed"):
                ci.boot_input_state(
                    inputs, {"qemu": boot}, content=False, expected=forged)

    def test_v2_public_archive_is_closed_ordered_and_not_downgradable(self):
        handoff = types.SimpleNamespace(
            ci=ci,
            V2_NAMES=(
                "efi", "debug_elf", "bootinfo", "raw", "qcow2", "vhd",
                "runtime", "compiler", "wasm", "cwasm", "config",
                "runtime_identity", "image_identity", "local_result",
                "package", "build", "build_start", "boot_inputs",
                "qcow2_finalization_intent", "qcow2_finalization",
                "qcow2_acceptance", "fixed_vhd_derivation_intent",
                "fixed_vhd_derivation_gate", "fixed_vhd_derivation",
                "final_inspection", "cleanup",
            ),
        )
        sha256 = hashlib.sha256(b"x").hexdigest()
        item = lambda path: {
            "path": path, "size": 1, "sha256": sha256}
        artifacts = [
            item("artifacts/" + name) for name in handoff.V2_NAMES]
        by_name = dict(zip(handoff.V2_NAMES, artifacts))
        boots = [
            {
                "mode": mode,
                **{
                    key: item(f"boots/{mode}/{key}")
                    for key in public_bundle.BOOT_KEYS
                },
            }
            for mode in ci.SIX_MODES
        ]
        evidence = [
            item("evidence/" + name)
            for name in sorted(public_bundle.V2_EVIDENCE)
        ]
        bundle = {
            "schema": "uk.wamr.local-image-handoff",
            "version": 2,
            "profile": ci.CURRENT_PROFILE,
            "authority": "not_admitted",
            "source_revision": "1" * 40,
            "source_tree": "2" * 40,
            "run": {
                "repository": "cataggar/unikraft",
                "run_id": "123",
                "run_attempt": "1",
            },
            "identity": {
                "wamr_revision": ci.REVISION,
                **{
                    name + "_sha256": sha256
                    for name in (
                        "wasm", "cwasm", "runtime", "compiler", "config")
                },
            },
            "lineage": {
                "raw_sha256": by_name["raw"]["sha256"],
                "accepted_qcow2_sha256": by_name["qcow2"]["sha256"],
                "derived_vhd_sha256": by_name["vhd"]["sha256"],
                "qcow2_finalization_sha256":
                    by_name["qcow2_finalization"]["sha256"],
                "qcow2_acceptance_sha256":
                    by_name["qcow2_acceptance"]["sha256"],
                "fixed_vhd_derivation_gate_sha256":
                    by_name["fixed_vhd_derivation_gate"]["sha256"],
                "fixed_vhd_derivation_sha256":
                    by_name["fixed_vhd_derivation"]["sha256"],
                "final_inspection_sha256":
                    by_name["final_inspection"]["sha256"],
            },
            "artifacts": artifacts,
            "boots": boots,
            "evidence": evidence,
        }
        selected = public_bundle.members(handoff, bundle)
        self.assertEqual(len(public_bundle.EVIDENCE), 20)
        self.assertEqual(len(public_bundle.V2_EVIDENCE), 33)
        self.assertEqual(public_bundle.V1_ZIP_MEMBERS, 55)
        self.assertEqual(public_bundle.V2_ZIP_MEMBERS, 85)
        self.assertEqual(public_bundle.MAX_MEMBERS, 96)
        self.assertEqual(len(selected) + 2, 85)

        source = {
            "repository": "cataggar/unikraft",
            "run_id": "123", "run_attempt": "1",
            "source_revision": bundle["source_revision"],
            "source_tree": bundle["source_tree"],
            "wamr_revision": ci.REVISION,
        }
        manifest = {
            "schema": "uk.wamr.public-source-bundle",
            "version": 2,
            "profile": ci.CURRENT_PROFILE,
            "authority": "not_admitted",
            "source": source,
            "members": {
                name: {"size": value["size"], "sha256": value["sha256"]}
                for name, value in selected.items()
            },
        }

        def archive(path, names):
            with zipfile.ZipFile(
                    path, "w", compression=zipfile.ZIP_STORED,
                    allowZip64=False) as output:
                for name in names:
                    info = zipfile.ZipInfo(name)
                    info.create_system = 3
                    info.external_attr = (stat.S_IFREG | 0o600) << 16
                    raw = (
                        public_bundle.encoded(bundle)
                        if name == "bundle.json" else
                        public_bundle.encoded(manifest)
                        if name == "public-source.json" else b"x"
                    )
                    output.writestr(info, raw)
            path.chmod(0o600)

        correct = (
            sorted(selected) + ["bundle.json", "public-source.json"])
        good = self.root / "v2-good.zip"
        archive(good, correct)
        public_bundle.verify_archive(
            handoff, good, source, ci.digest(good))
        for name, names in (
                ("duplicate", correct[:1] + correct),
                ("unlisted", sorted(selected) + ["extra"]
                 + ["bundle.json", "public-source.json"]),
                ("reordered", list(reversed(sorted(selected)))
                 + ["bundle.json", "public-source.json"])):
            with self.subTest(name=name):
                bad = self.root / f"v2-{name}.zip"
                archive(bad, names)
                with self.assertRaises(ValueError):
                    public_bundle.verify_archive(
                        handoff, bad, source, ci.digest(bad))
        for key, value in (
                ("version", 1),
                ("profile", "tiny-aot-two-boot")):
            downgraded = copy.deepcopy(bundle)
            downgraded[key] = value
            with self.subTest(downgrade=key), self.assertRaises(ValueError):
                public_bundle.members(handoff, downgraded)

    def test_public_bundle_accepts_only_fixed_ci_runtime_roots(self):
        runtime_owner = type("RuntimeOwner", (), {"REPO": ci.REPO})
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("WAMR_CI_RUNTIME", None)
            self.assertEqual(
                public_bundle.ci_runtime(runtime_owner),
                ci.REPO / ".d/wamr-native-runtime",
            )
        with mock.patch.dict(
                os.environ,
                {"WAMR_CI_RUNTIME": "/d/wamr-ci/wamr-native-runtime"}):
            self.assertEqual(
                public_bundle.ci_runtime(runtime_owner),
                Path("/d/wamr-ci/wamr-native-runtime"),
            )
        with mock.patch.dict(
                os.environ, {"WAMR_CI_RUNTIME": "/d/other-runtime"}), \
                self.assertRaisesRegex(ValueError, "bundle refused"):
            public_bundle.ci_runtime(runtime_owner)

    def test_public_start_revalidates_recorded_custody_before_binding(self):
        runtime = self.root / "public-runtime"
        consumer = {
            "schema": "uk.wamr.consumer-input-custody",
            "version": 2,
            "files": {
                **{
                    "tool:" + name: {"path": "/trusted/" + name}
                    for name in ci.HOST_TOOLS
                },
                "wamr-source-archive": {"path": "/trusted/wamr.tar"},
                "command-supervisor": {"path": "/trusted/supervisor"},
            },
            "trees": {
                name: {} for name in (
                    "bison", "python-stdlib", "zig", "llvm")
            },
            "directories": {},
            "aggregate_sha256": "f" * 64,
        }
        start = {
            "source": {"revision": "1" * 40, "tree": "2" * 40},
            "source_custody": {},
            "tools": {name: "3" * 64 for name in ci.HOST_TOOLS},
            "bison_data": {},
            "dependencies": {},
            "consumer_inputs": consumer,
            "command_supervisor": {},
        }
        owner = type("Handoff", (), {"ci": ci})
        events = []

        def recorded(expected, content=False):
            self.assertIs(expected, consumer)
            self.assertTrue(content)
            self.assertIsNone(ci.COMMAND_SUPERVISOR_PATH)
            events.append("consumer")

        def custody(actual_runtime, expected):
            self.assertEqual(actual_runtime, runtime)
            self.assertIs(expected, start)
            if ci.COMMAND_SUPERVISOR_PATH is None:
                self.assertEqual(
                    ci.COMMAND_TOOL_PATHS,
                    {"git": "/trusted/git"})
                events.append("custody-before-bind")
            else:
                self.assertEqual(
                    ci.COMMAND_SUPERVISOR_PATH,
                    "/trusted/supervisor")
                self.assertEqual(
                    set(ci.COMMAND_TOOL_PATHS), set(ci.HOST_TOOLS))
                events.append("custody-after-bind")
            return expected

        original_supervisor = ci.COMMAND_SUPERVISOR_PATH
        original_tools = dict(ci.COMMAND_TOOL_PATHS)
        original_environment = dict(ci.COMMAND_ENVIRONMENT)
        try:
            ci.COMMAND_SUPERVISOR_PATH = None
            ci.COMMAND_TOOL_PATHS.clear()
            ci.COMMAND_ENVIRONMENT.clear()
            with mock.patch.object(
                    ci, "document", return_value=start), \
                    mock.patch.object(
                        public_bundle, "source_custody_record"), \
                    mock.patch.object(
                        public_bundle, "consumer_input_record"), \
                    mock.patch.object(
                        public_bundle, "command_supervisor_record"), \
                    mock.patch.object(
                        public_bundle, "dependency_record",
                        side_effect=lambda *unused: events.append(
                            "dependency")), \
                    mock.patch.object(
                        public_bundle, "require_consumer_tree_roles"), \
                    mock.patch.object(
                        public_bundle, "require_public_consumer_paths"), \
                    mock.patch.object(
                        ci, "require_recorded_consumer_inputs",
                        side_effect=recorded), \
                    mock.patch.object(
                        ci, "require_recorded_build_custody",
                        side_effect=custody):
                self.assertIs(
                    public_bundle.accepted_public_build_start(
                        owner, runtime),
                    start)
            self.assertEqual(events, [
                "consumer", "dependency", "custody-before-bind",
                "custody-after-bind",
            ])
        finally:
            ci.COMMAND_SUPERVISOR_PATH = original_supervisor
            ci.COMMAND_TOOL_PATHS.clear()
            ci.COMMAND_TOOL_PATHS.update(original_tools)
            ci.COMMAND_ENVIRONMENT.clear()
            ci.COMMAND_ENVIRONMENT.update(original_environment)

    def test_public_start_missing_or_tampered_consumer_inputs_never_bind(self):
        runtime = self.root / "public-runtime-refusal"
        base_files = {
            **{
                "tool:" + name: {"path": "/trusted/" + name}
                for name in ci.HOST_TOOLS
            },
            "wamr-source-archive": {"path": "/trusted/wamr.tar"},
            "command-supervisor": {"path": "/trusted/supervisor"},
        }
        consumer = {
            "files": base_files,
            "trees": {
                name: {} for name in (
                    "bison", "python-stdlib", "zig", "llvm")
            },
        }
        start = {
            "source": {"revision": "1" * 40, "tree": "2" * 40},
            "source_custody": {}, "tools": {}, "bison_data": {},
            "dependencies": {}, "consumer_inputs": consumer,
            "command_supervisor": {},
        }
        owner = type("Handoff", (), {"ci": ci})
        for case in ("missing", "tampered"):
            candidate = copy.deepcopy(start)
            if case == "missing":
                del candidate["consumer_inputs"]["files"][
                    "command-supervisor"]
            with self.subTest(case=case), \
                    mock.patch.object(
                        ci, "document", return_value=candidate), \
                    mock.patch.object(
                        public_bundle, "source_custody_record"), \
                    mock.patch.object(
                        public_bundle, "consumer_input_record"), \
                    mock.patch.object(
                        public_bundle, "command_supervisor_record"), \
                    mock.patch.object(
                        public_bundle, "require_consumer_tree_roles"), \
                    mock.patch.object(
                        public_bundle, "require_public_consumer_paths"), \
                    mock.patch.object(
                        ci, "require_recorded_consumer_inputs",
                        side_effect=(
                            ci.Refusal("consumer input custody changed")
                            if case == "tampered" else None)), \
                    mock.patch.object(
                        ci, "bind_command_tools") as bind, \
                    self.assertRaises((ValueError, ci.Refusal)):
                public_bundle.accepted_public_build_start(owner, runtime)
            bind.assert_not_called()

    def test_public_context_binds_installed_log_validator_or_refuses(self):
        runtime = self.root / "public-validator-runtime"
        (runtime / "compute/evidence").mkdir(parents=True, mode=0o700)
        for directory in ("bison", "llvm"):
            (runtime / directory).mkdir(mode=0o700)
        files = {
            "tool:" + name: {"path": "/trusted/" + name}
            for name in ci.HOST_TOOLS
        }
        for role, relative in (
                ("command-supervisor",
                 "compute/supervisor/bin/wamr-ci-supervisor"),
                (ci.WAMR_AOT_BUILD_ROLE, ci.WAMR_AOT_BUILD_RELATIVE),
                (ci.WAMR_LOG_VALIDATOR_ROLE, ci.WAMR_LOG_VALIDATOR_RELATIVE),
                ("wamr-source-archive", "custody/wamr-source.tar")):
            path = runtime / relative
            path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            self.put(path, b"fixture executable or archive")
            files[role] = {"path": str(path)}
        consumer = {
            "files": files,
            "trees": {
                "bison": {"path": str(runtime / "bison")},
                "llvm": {"path": str(runtime / "llvm")},
                "zig": {"path": "/trusted"},
                "python-stdlib": {
                    "path": str(Path(ci.sysconfig.get_paths()["stdlib"])
                                .resolve(strict=True)),
                },
            },
        }
        start = {
            "source": {"revision": "1" * 40, "tree": "2" * 40},
            "source_custody": {}, "tools": {}, "bison_data": {},
            "dependencies": {}, "consumer_inputs": consumer,
            "command_supervisor": {},
        }
        owner = types.SimpleNamespace(
            ci=ci, result_records=mock.Mock(), FAILURE_STAGE="handoff")
        original_supervisor = ci.COMMAND_SUPERVISOR_PATH
        original_tools = dict(ci.COMMAND_TOOL_PATHS)
        original_environment = dict(ci.COMMAND_ENVIRONMENT)
        try:
            for case in ("present", "missing", "wrong-path", "extra-role"):
                candidate = copy.deepcopy(start)
                if case == "missing":
                    del candidate["consumer_inputs"]["files"][
                        ci.WAMR_LOG_VALIDATOR_ROLE]
                elif case == "wrong-path":
                    candidate["consumer_inputs"]["files"][
                        ci.WAMR_LOG_VALIDATOR_ROLE]["path"] = "/trusted/other"
                elif case == "extra-role":
                    candidate["consumer_inputs"]["files"][
                        "native:unapproved"] = {"path": "/trusted/other"}
                ci.COMMAND_SUPERVISOR_PATH = None
                ci.COMMAND_TOOL_PATHS.clear()
                ci.COMMAND_ENVIRONMENT.clear()
                with self.subTest(case=case), \
                        mock.patch.object(
                            public_bundle, "ci_runtime",
                            return_value=runtime), \
                        mock.patch.object(
                            ci, "document", return_value=candidate), \
                        mock.patch.object(
                            public_bundle, "source_custody_record"), \
                        mock.patch.object(
                            public_bundle, "consumer_input_record"), \
                        mock.patch.object(
                            public_bundle, "command_supervisor_record"), \
                        mock.patch.object(
                            ci, "require_recorded_consumer_inputs"), \
                        mock.patch.object(
                            ci, "executable_runtime_paths",
                            return_value=set()), \
                        mock.patch.object(
                            public_bundle, "dependency_record"), \
                        mock.patch.object(
                            ci, "require_recorded_build_custody"), \
                        mock.patch.object(
                            ci, "bind_command_tools", return_value={}) as bind, \
                        mock.patch.object(
                            public_bundle, "ci_context",
                            side_effect=RuntimeError("past public context")
                        ) as context:
                    if case == "present":
                        with self.assertRaisesRegex(
                                RuntimeError, "past public context"):
                            public_bundle.publish_ci(owner)
                        owner.result_records.assert_called_with(
                            runtime / "compute")
                        context.assert_called_once_with(owner, candidate)
                        bind.assert_called_once_with(consumer)
                        self.assertEqual(owner.FAILURE_STAGE, "public-context")
                    else:
                        failure = (
                            ci.Refusal if case == "missing" else ValueError)
                        with self.assertRaises(failure):
                            public_bundle.publish_ci(owner)
                        bind.assert_not_called()
                        context.assert_not_called()
        finally:
            ci.COMMAND_SUPERVISOR_PATH = original_supervisor
            ci.COMMAND_TOOL_PATHS.clear()
            ci.COMMAND_TOOL_PATHS.update(original_tools)
            ci.COMMAND_ENVIRONMENT.clear()
            ci.COMMAND_ENVIRONMENT.update(original_environment)

    def test_fresh_publication_binds_before_validator_and_rechecks_record(self):
        repository = self.root / "fresh-publication"
        (repository / ".d").mkdir(parents=True, mode=0o700)
        runtime = self.root / "fresh-runtime"
        (runtime / "compute/evidence").mkdir(parents=True, mode=0o700)
        consumer = {
            "files": {
                **{
                    "tool:" + name: {
                        "path": "/trusted/" + name,
                        "metadata": [1, 1, stat.S_IFREG | 0o500,
                                     1, 1, 1, 1, 1, 1],
                    }
                    for name in ci.HOST_TOOLS
                },
                "command-supervisor": {
                    "path": "/trusted/supervisor",
                    "metadata": [1, 2, stat.S_IFREG | 0o500,
                                 1, 1, 1, 1, 1, 1],
                },
            },
        }
        start = {"consumer_inputs": consumer}
        source = {
            "repository": "cataggar/unikraft",
            "run_id": "123", "run_attempt": "1",
            "source_revision": "1" * 40, "source_tree": "2" * 40,
            "wamr_revision": ci.REVISION,
        }
        validator_record = {"fixture": "fully supervised"}
        handoff = mock.Mock()
        handoff.ci = ci
        handoff.export.return_value = {"version": 2}
        events = []

        def accept(unused_handoff, actual_runtime):
            self.assertEqual(actual_runtime, runtime)
            self.assertIsNone(ci.COMMAND_SUPERVISOR_PATH)
            ci.bind_command_tools(consumer)
            events.append("bound")
            return start

        def execute(*unused, **kwargs):
            self.assertEqual(
                ci.COMMAND_SUPERVISOR_PATH, "/trusted/supervisor")
            self.assertNotIn("allow_bootstrap", kwargs)
            events.append("validator")
            return self.root / "unused-validator.log", validator_record

        def validate(*args):
            self.assertIs(args[1], validator_record)
            events.append("validated")
            return validator_record

        original_supervisor = ci.COMMAND_SUPERVISOR_PATH
        original_tools = dict(ci.COMMAND_TOOL_PATHS)
        original_environment = dict(ci.COMMAND_ENVIRONMENT)
        try:
            ci.COMMAND_SUPERVISOR_PATH = None
            ci.COMMAND_TOOL_PATHS.clear()
            ci.COMMAND_ENVIRONMENT.clear()
            with mock.patch.object(ci, "REPO", repository), \
                    mock.patch.object(
                        public_bundle, "ci_runtime",
                        return_value=runtime), \
                    mock.patch.object(
                        public_bundle, "accepted_public_build_start",
                        side_effect=accept), \
                    mock.patch.object(
                        public_bundle, "ci_context",
                        return_value=source), \
                    mock.patch.object(
                        ci, "read", return_value=b"primary=0 cleanup=0\n"), \
                    mock.patch.object(
                        ci, "execute", side_effect=execute), \
                    mock.patch.object(
                        ci, "consumer_file_records", return_value={}), \
                    mock.patch.object(
                        ci, "native_executable_identity",
                        side_effect=lambda record: {
                            "path": record["path"]}), \
                    mock.patch.object(
                        ci, "document", return_value=validator_record), \
                    mock.patch.object(
                        ci, "require_recorded_build_custody"), \
                    mock.patch.object(
                        public_bundle, "supervised_command_record",
                        side_effect=validate), \
                    mock.patch.object(
                        public_bundle, "pack",
                        return_value="f" * 64), \
                    mock.patch.object(public_bundle, "import_bundle"):
                public_bundle.publish_ci(handoff)
            self.assertEqual(events[:3], [
                "bound", "validator", "validated"])
            self.assertEqual(events.count("validated"), 3)
            handoff.export.assert_called_once()
        finally:
            ci.COMMAND_SUPERVISOR_PATH = original_supervisor
            ci.COMMAND_TOOL_PATHS.clear()
            ci.COMMAND_TOOL_PATHS.update(original_tools)
            ci.COMMAND_ENVIRONMENT.clear()
            ci.COMMAND_ENVIRONMENT.update(original_environment)

    def test_publication_refuses_bootstrap_validator_record_before_export(self):
        repository = self.root / "bootstrap-publication"
        (repository / ".d").mkdir(parents=True, mode=0o700)
        runtime = self.root / "bootstrap-runtime"
        (runtime / "compute/evidence").mkdir(parents=True, mode=0o700)
        consumer = {
            "files": {
                **{
                    "tool:" + name: {
                        "path": "/trusted/" + name,
                        "metadata": [1, 1, stat.S_IFREG | 0o500,
                                     1, 1, 1, 1, 1, 1],
                    }
                    for name in ci.HOST_TOOLS
                },
                "command-supervisor": {
                    "path": "/trusted/supervisor",
                    "metadata": [1, 2, stat.S_IFREG | 0o500,
                                 1, 1, 1, 1, 1, 1],
                },
            },
        }
        start = {"consumer_inputs": consumer}
        bootstrap = {
            "scope": "command_diagnostic_not_acceptance",
            "stage": "public-validator-build",
            "exit_code": 0, "bytes": 0,
            "sha256": hashlib.sha256(b"").hexdigest(),
            "over_limit": False, "known_error_markers": [],
            "supervisor": {
                "schema": "uk.wamr.command-supervisor-result",
                "version": 1, "bootstrap": True,
            },
        }
        handoff = mock.Mock()
        handoff.ci = ci
        original_supervisor = ci.COMMAND_SUPERVISOR_PATH
        try:
            ci.COMMAND_SUPERVISOR_PATH = None
            with mock.patch.object(ci, "REPO", repository), \
                    mock.patch.object(
                        public_bundle, "ci_runtime",
                        return_value=runtime), \
                    mock.patch.object(
                        public_bundle, "accepted_public_build_start",
                        return_value=start), \
                    mock.patch.object(
                        public_bundle, "ci_context",
                        return_value={
                            "repository": "cataggar/unikraft",
                            "run_id": "123", "run_attempt": "1",
                            "source_revision": "1" * 40,
                            "source_tree": "2" * 40,
                            "wamr_revision": ci.REVISION,
                        }), \
                    mock.patch.object(
                        ci, "read", return_value=b"primary=0 cleanup=0\n"), \
                    mock.patch.object(
                        ci, "execute",
                        return_value=(self.root / "unused", bootstrap)), \
                    mock.patch.object(
                        ci, "consumer_file_records", return_value={}), \
                    mock.patch.object(
                        ci, "native_executable_identity",
                        side_effect=lambda record: {
                            "path": record["path"]}), \
                    mock.patch.object(
                        ci, "document", return_value=bootstrap), \
                    self.assertRaises(ValueError):
                public_bundle.publish_ci(handoff)
            handoff.export.assert_not_called()
        finally:
            ci.COMMAND_SUPERVISOR_PATH = original_supervisor

    def test_public_bundle_rejects_current_system_bin_tree(self):
        current = {"trees": {
            "bison": {}, "python-stdlib": {}, "zig": {}, "llvm": {},
        }}
        public_bundle.require_consumer_tree_roles(current, False)
        current["trees"]["system-bin"] = {}
        with self.assertRaisesRegex(ValueError, "bundle refused"):
            public_bundle.require_consumer_tree_roles(current, False)
        public_bundle.require_consumer_tree_roles(current, True)

    def test_current_public_import_requires_independent_inner_zip_digest(self):
        expected = {
            "repository": "cataggar/unikraft",
            "run_id": "35422844896",
            "run_attempt": "1",
            "source_revision": "1" * 40,
            "source_tree": "2" * 40,
            "wamr_revision": ci.REVISION,
        }
        handoff = mock.Mock()
        handoff.ci = ci
        with self.assertRaisesRegex(ValueError, "bundle refused"):
            public_bundle.verify_archive_descriptor(
                handoff, -1, expected, None)

    def test_public_supervisor_maps_recompute_closures_and_legacy_is_compatible(self):
        artifact = self.root / "supervisor-map-artifact"
        self.put(artifact, b"guarded map")
        record, unused_directories = ci.physical_file_record(artifact)
        del unused_directories
        entry = {
            "bytes": record["metadata"][6],
            "sha256": record["sha256"],
            "metadata": record["metadata"],
        }
        for suffix in ("source", "runtime"):
            domain = f"uk.wamr.command-supervisor-{suffix}-v1"
            guarded = ci.guarded_record_map(domain, {"fixture": entry})
            self.assertEqual(
                public_bundle.guarded_map_record(guarded, domain), guarded)
            tampered = copy.deepcopy(guarded)
            tampered["content_closure_sha256"] = "0" * 64
            with self.assertRaises(ValueError):
                public_bundle.guarded_map_record(tampered, domain)
        for revision, tree in (
                public_bundle.LEGACY_V1_SOURCES
                | public_bundle.PRE_SUPERVISOR_SOURCES):
            self.assertTrue(public_bundle.pre_supervisor_source({
                "source_revision": revision, "source_tree": tree,
            }))

    def test_boot_output_slots_preserve_their_shared_parent(self):
        runtime = self.root / "runtime"
        compute = runtime / "compute"
        compute.mkdir(parents=True, mode=0o700)
        ci.precreate_boot_output_slots(runtime, compute)
        package, configs = ci.prepare_boot_output_slots(runtime, compute)
        parent = ci.snapshot(compute.lstat())
        (package / "artifact").write_bytes(b"package")
        publication = compute / "public-source"
        (publication / "handoff").mkdir(mode=0o700)
        (publication / "tools").mkdir(mode=0o700)
        for config in configs:
            (Path(config["work_dir"]) / "serial").write_bytes(b"boot")
        self.assertEqual(ci.snapshot(compute.lstat()), parent)
        with self.assertRaisesRegex(ci.Refusal, "boot output already exists"):
            ci.prepare_boot_output_slots(runtime, compute)

    def test_package_producer_uses_v2_boot_file_record(self):
        state = ci.record_input_paths(
            {"package_tool": Path(os.environ["WAMR_CI_PACKAGE"])}, {})
        self.assertEqual(
            state["files"]["package_tool"]["sha256"],
            ci.digest(Path(os.environ["WAMR_CI_PACKAGE"])),
        )
        self.assertNotIn("package_tool", state)

    def test_physical_tree_bounds_enumeration_and_symlink_hash_work(self):
        entries = self.root / "bounded-tree"
        entries.mkdir(mode=0o700)
        for index in range(3):
            self.put(entries / f"entry-{index}", b"")
        with mock.patch.object(ci, "INPUT_TREE_MAX_ENTRIES", 3), \
                self.assertRaisesRegex(
                    ci.Refusal, "physical input tree entry limit exceeded"):
            ci.physical_tree_record(entries)

        target = self.root / "t"
        self.put(target, b"12345678")
        links = self.root / "symlink-tree"
        links.mkdir(mode=0o700)
        (links / "first").symlink_to("../t")
        (links / "second").symlink_to("../t")
        with mock.patch.object(ci, "INPUT_TREE_MAX_BYTES", 8):
            record, unused_directories = ci.physical_tree_record(links)
            del unused_directories
        self.assertEqual(record["symlinks"], 2)
        self.put(target, b"123456789")
        with mock.patch.object(ci, "INPUT_TREE_MAX_BYTES", 8), \
                self.assertRaisesRegex(
                    ci.Refusal, "physical input tree hash limit exceeded"):
            ci.physical_tree_record(links)

    def test_physical_tree_directory_symlink_custody(self):
        directory_links = self.root / "directory-symlink-tree"
        data = directory_links / "data"
        data.mkdir(parents=True, mode=0o700)
        self.put(data / "input", b"bounded")
        (directory_links / "alias").symlink_to("data")
        record, unused_directories = ci.physical_tree_record(directory_links)
        del unused_directories
        self.assertEqual(record["symlinks"], 1)
        outside = self.root / "outside-directory"
        outside.mkdir(mode=0o700)
        (directory_links / "escape").symlink_to(outside)
        with self.assertRaisesRegex(
                ci.Refusal, "unsafe physical input tree symlink"):
            ci.physical_tree_record(directory_links)

    def test_physical_tree_stable_dangling_symlink_custody(self):
        dangling = self.root / "dangling-symlink-tree"
        dangling.mkdir(mode=0o700)
        missing = (
            Path("/usr/bin")
            / f"wamr-ci-missing-tree-target-{os.getpid()}")
        self.assertFalse(missing.exists())
        (dangling / "stable-missing").symlink_to(missing)
        record, unused_directories = ci.physical_tree_record(dangling)
        del unused_directories
        self.assertEqual(record["symlinks"], 1)
        depth_64 = (
            Path("/usr") / f"wamr-ci-missing-depth-{os.getpid()}"
            / Path(*(["x"] * 62))
        )
        self.assertEqual(len(depth_64.parts) - 1, 64)
        (dangling / "deep").symlink_to(depth_64)
        self.assertEqual(ci.physical_tree_record(dangling)[0]["symlinks"], 2)
        (dangling / "deep").unlink()
        (dangling / "deep").symlink_to(depth_64 / "x")
        with self.assertRaisesRegex(
                ci.Refusal, "unsafe physical input tree symlink"):
            ci.physical_tree_record(dangling)

    def test_physical_tree_mutable_dangling_symlink_custody(self):
        dangling = self.root / "dangling-symlink-tree"
        dangling.mkdir(mode=0o700)
        (dangling / "mutable-missing").symlink_to(self.root / "missing")
        with self.assertRaisesRegex(
                ci.Refusal, "unsafe physical input tree symlink"):
            ci.physical_tree_record(dangling)

    def test_retained_executable_descriptor_survives_path_swap(self):
        directory = self.root / "retained-executable"
        directory.mkdir(mode=0o700)
        executable = directory / "tool"
        original = b"#!/bin/sh\nprintf original\n"
        replacement = b"#!/bin/sh\nprintf replacement\n"
        self.put(executable, original)
        executable.chmod(0o700)
        state = ci.record_input_paths({"tool": executable}, {})
        records = ci.consumer_file_records(state)
        alias = directory / "tool-alias"
        alias.symlink_to("tool")
        with ci.retained_executables((alias,), records) as (
                retained, unused_fds):
            del unused_fds
            saved = directory / "saved"
            executable.rename(saved)
            self.put(executable, replacement)
            executable.chmod(0o700)
            self.assertEqual(
                Path(retained[str(alias)]).read_bytes(), original)
            executable.unlink()
            saved.rename(executable)
        with self.assertRaisesRegex(ci.Refusal, "custody changed"):
            ci.record_input_paths(
                {"tool": executable}, {}, content=False, expected=state)

    def test_indirect_tool_environment_uses_retained_descriptor(self):
        root = self.root / "retained-indirect"
        (root / "private").mkdir(parents=True, mode=0o700)
        executable = root / "tool"
        original = Path(SUPERVISOR_FIXTURE).read_bytes()
        replacement = Path("/usr/bin/false").resolve(strict=True).read_bytes()
        self.put(executable, original)
        executable.chmod(0o700)
        ready = root / "ready"
        consumed = root / "consumed"
        script = (
            "import os,pathlib,subprocess,time\n"
            f"pathlib.Path({str(ready)!r}).touch()\n"
            "time.sleep(0.2)\n"
            "try:\n"
            " value=subprocess.check_output([os.environ['WAMR_CI_TOOL_GIT'],"
            "'bytes','8','0','0'])\n"
            "finally:\n"
            f" pathlib.Path({str(consumed)!r}).touch()\n"
            "time.sleep(0.2)\n"
            "print(value.decode(),end='')\n"
        )
        records = {}
        for path in {
                Path(ci.COMMAND_SUPERVISOR_PATH).resolve(strict=True),
                Path(PYTHON).resolve(strict=True),
                executable}:
            record, unused_directories = ci.physical_file_record(path)
            del unused_directories
            records[record["path"]] = record

        def swap_and_restore():
            while not ready.exists():
                time.sleep(0.005)
            saved = root / "saved"
            executable.rename(saved)
            self.put(executable, replacement)
            executable.chmod(0o700)
            while not consumed.exists():
                time.sleep(0.005)
            executable.unlink()
            saved.rename(executable)

        attacker = threading.Thread(target=swap_and_restore)
        attacker.start()
        try:
            with mock.patch.dict(
                    ci.COMMAND_TOOL_PATHS,
                    {"git": str(executable)}, clear=True):
                output, unused_record = ci.execute(
                    root, "retained-indirect-command",
                    [PYTHON, "-c", script], evidence=False,
                    input_records=records)
            del unused_record
        finally:
            attacker.join(timeout=2)
        self.assertFalse(attacker.is_alive())
        self.assertEqual(output.read_bytes(), b"oooooooo")
        self.assertEqual(executable.read_bytes(), original)

    def test_boot_revalidation_does_not_need_inherited_build_environment(self):
        root = self.root / "bison"
        root.mkdir(mode=0o700)
        self.put(root / "skeleton", b"fixture")
        expected = ci.bison_inputs(root)
        source = {
            "revision": "1" * 40,
            "tree": "2" * 40,
            "custody": {"fixture": True},
        }
        with mock.patch.dict(os.environ, {}, clear=True), \
                mock.patch.object(ci, "source", return_value=source), \
                mock.patch.object(ci, "tool", return_value="/synthetic-tool"), \
                mock.patch.object(ci, "digest", return_value="f" * 64), \
                mock.patch.object(
                    ci, "consumer_input_state",
                    return_value={"schema": "fixture"}), \
                mock.patch.object(
                    ci, "command_supervisor_state",
                    return_value={"schema": "fixture"}), \
                mock.patch.object(ci, "dependency_custody",
                                  return_value={"fixture": True}):
            self.assertEqual(ci.producer_inputs(self.root)["bison_data"], expected)
            self.assertNotIn("BISON_PKGDATADIR", os.environ)

    def test_boot_binds_only_independently_revalidated_consumer_tools(self):
        consumer = {
            "files": {
                "tool:" + name: {"path": "/trusted/" + name}
                for name in ci.HOST_TOOLS
            } | {
                "command-supervisor": {"path": "/trusted/supervisor"},
            },
        }
        initial = {"consumer_inputs": consumer}

        def independently_validate(runtime, expected):
            self.assertEqual(runtime, self.root)
            self.assertEqual(expected, consumer)
            self.assertFalse(ci.COMMAND_TOOL_PATHS)
            return initial

        def check_after_binding():
            self.assertEqual(
                ci.COMMAND_TOOL_PATHS,
                {name: "/trusted/" + name for name in ci.HOST_TOOLS},
            )
            raise RuntimeError("stop after validated binding")

        with mock.patch.dict(ci.COMMAND_TOOL_PATHS, {}, clear=True), \
                mock.patch.dict(ci.COMMAND_ENVIRONMENT, {}, clear=True), \
                mock.patch.object(ci, "COMMAND_SUPERVISOR_PATH", None), \
                mock.patch.dict(os.environ, {}, clear=False), \
                mock.patch.object(ci.platform, "machine", return_value="x86_64"), \
                mock.patch.object(Path, "is_char_device", return_value=True), \
                mock.patch.object(ci.os, "access", return_value=True), \
                mock.patch.object(ci, "document", return_value=initial), \
                mock.patch.object(
                    ci, "producer_inputs", side_effect=independently_validate), \
                mock.patch.object(ci, "check_build", side_effect=check_after_binding), \
                self.assertRaisesRegex(
                    RuntimeError, "stop after validated binding"):
            ci.boot(self.root)

    def test_consumer_inventory_uses_exact_indirect_tools_not_system_bin(self):
        runtime = self.root / "inventory"
        runtime.mkdir(mode=0o700)
        captured = {}

        def record(file_paths, tree_paths, content=True, expected=None):
            captured["files"] = file_paths
            captured["trees"] = tree_paths
            self.assertTrue(content)
            self.assertIsNone(expected)
            return {"schema": "fixture"}

        with mock.patch.object(
                ci, "tool", side_effect=lambda name: f"/tools/{name}"), \
                mock.patch.object(
                    ci, "executable_runtime_paths", return_value=set()), \
                mock.patch.object(
                    ci, "canonical_input_paths",
                    side_effect=lambda paths, unused_reason: dict(paths)), \
                mock.patch.object(
                    ci, "record_input_paths", side_effect=record):
            self.assertEqual(
                ci.consumer_input_state(runtime), {"schema": "fixture"})

        self.assertNotIn("system-bin", captured["trees"])
        for name in ci.INDIRECT_HOST_TOOLS:
            self.assertEqual(
                captured["files"][f"tool:{name}"], Path(f"/tools/{name}"))
        tools = {
            "files": {
                f"tool:{name}": {
                    "path": (
                        f"/system/{name}" if name in ci.INDIRECT_HOST_TOOLS
                        else f"/selected/{name}"
                    )
                }
                for name in ci.HOST_TOOLS
            } | {
                "command-supervisor": {"path": "/selected/supervisor"},
            }
        }
        original_supervisor = ci.COMMAND_SUPERVISOR_PATH
        original_tools = dict(ci.COMMAND_TOOL_PATHS)
        try:
            environment = ci.bind_command_tools(tools)
            self.assertEqual(environment["PATH"], "/usr/bin:/bin")
            self.assertEqual(environment["WAMR_CI_GIT"], "/selected/git")
            self.assertEqual(
                environment["WAMR_CI_SUPERVISOR"],
                "/selected/supervisor")
            self.assertEqual(
                environment["WAMR_CI_TOOL_DASH"], "/system/dash")
        finally:
            ci.COMMAND_SUPERVISOR_PATH = original_supervisor
            ci.COMMAND_TOOL_PATHS.clear()
            ci.COMMAND_TOOL_PATHS.update(original_tools)

    def test_native_wamr_role_enters_only_the_final_consumer_baseline(self):
        runtime = self.root / "native-role"
        executable = runtime / ci.WAMR_AOT_BUILD_RELATIVE
        executable.parent.mkdir(parents=True, mode=0o700)

        def canonical(paths, unused_reason):
            return dict(paths)

        patches = (
            mock.patch.object(
                ci, "tool", side_effect=lambda name: f"/tools/{name}"),
            mock.patch.object(
                ci, "executable_runtime_paths", return_value=set()),
            mock.patch.object(
                ci, "canonical_input_paths", side_effect=canonical),
        )
        with contextlib.ExitStack() as stack:
            for patch in patches:
                stack.enter_context(patch)
            files, unused_trees = ci.discover_consumer_input_paths(runtime)
            self.assertNotIn(ci.WAMR_AOT_BUILD_ROLE, files)

            self.put(executable, b"native executable")
            executable.chmod(0o700)
            files, unused_trees = ci.discover_consumer_input_paths(runtime)
            self.assertEqual(
                files[ci.WAMR_AOT_BUILD_ROLE], executable)

            files, unused_trees = ci.discover_consumer_input_paths(
                runtime, {"files": {}})
            self.assertNotIn(ci.WAMR_AOT_BUILD_ROLE, files)

            files, unused_trees = ci.discover_consumer_input_paths(
                runtime, {"files": {ci.WAMR_AOT_BUILD_ROLE: {}}})
            self.assertEqual(
                files[ci.WAMR_AOT_BUILD_ROLE], executable)

            sealed = ci.record_input_paths(
                {ci.WAMR_AOT_BUILD_ROLE: executable}, {})
            executable.write_bytes(b"changed executable")
            with self.assertRaises(ci.Refusal):
                ci.record_input_paths(
                    {ci.WAMR_AOT_BUILD_ROLE: executable}, {},
                    expected=sealed)

            executable.unlink()
            executable.symlink_to("/does/not/exist")
            with self.assertRaisesRegex(
                    ci.Refusal,
                    "installed native WAMR build executable unavailable"):
                ci.discover_consumer_input_paths(
                    runtime,
                    {"files": {ci.WAMR_AOT_BUILD_ROLE: {}}},
                )

    def test_installed_log_validator_role_is_custodied_without_caller_cutover(self):
        runtime = self.root / "log-validator-role"
        executable = runtime / ci.WAMR_LOG_VALIDATOR_RELATIVE
        executable.parent.mkdir(parents=True, mode=0o700)
        with mock.patch.object(
                ci, "tool", side_effect=lambda name: f"/tools/{name}"), \
                mock.patch.object(
                    ci, "executable_runtime_paths", return_value=set()), \
                mock.patch.object(
                    ci, "canonical_input_paths",
                    side_effect=lambda paths, unused_reason: dict(paths)):
            files, unused = ci.discover_consumer_input_paths(runtime)
            self.assertNotIn(ci.WAMR_LOG_VALIDATOR_ROLE, files)
            self.put(executable, b"installed native log validator")
            executable.chmod(0o700)
            files, unused = ci.discover_consumer_input_paths(runtime)
            self.assertEqual(files[ci.WAMR_LOG_VALIDATOR_ROLE], executable)
            files, unused = ci.discover_consumer_input_paths(
                runtime, {"files": {}})
            self.assertNotIn(ci.WAMR_LOG_VALIDATOR_ROLE, files)
            files, unused = ci.discover_consumer_input_paths(
                runtime, {"files": {ci.WAMR_LOG_VALIDATOR_ROLE: {}}})
            self.assertEqual(files[ci.WAMR_LOG_VALIDATOR_ROLE], executable)
            baseline = ci.record_input_paths(
                {ci.WAMR_LOG_VALIDATOR_ROLE: executable}, {})
            executable.write_bytes(b"tampered native log validator")
            with self.assertRaises(ci.Refusal):
                ci.record_input_paths(
                    {ci.WAMR_LOG_VALIDATOR_ROLE: executable}, {},
                    expected=baseline)
            executable.unlink()
            executable.symlink_to("/does/not/exist")
            with self.assertRaises(ci.Refusal):
                ci.discover_consumer_input_paths(
                    runtime, {"files": {ci.WAMR_LOG_VALIDATOR_ROLE: {}}})

    def test_recorded_consumer_revalidation_allows_only_new_roles(self):
        inputs = self.root / "recorded-consumer-inputs"
        inputs.mkdir(mode=0o700)
        tool = inputs / "tool"
        self.put(tool, b"stable")
        added_root = inputs / "new-role-root"
        added_root.mkdir(mode=0o700)
        expected = ci.record_input_paths({"tool": tool}, {})
        added = added_root / "new-role"
        self.put(added, b"new")
        ci.require_recorded_consumer_inputs(expected)
        self.put(tool, b"changed")
        with self.assertRaises(ci.Refusal):
            ci.require_recorded_consumer_inputs(expected)

    def test_build_refuses_an_unbound_bison_environment(self):
        for index, override in enumerate((None, str(self.root / "different"))):
            runtime = self.root / ("build-" + str(index))
            runtime.mkdir(mode=0o700)
            values = {} if override is None else {"BISON_PKGDATADIR": override}
            with mock.patch.dict(os.environ, values, clear=True), \
                    mock.patch.object(ci, "producer_inputs") as inputs:
                with self.assertRaises(ci.Refusal):
                    ci.build(runtime, self.root)
                inputs.assert_not_called()

    def test_restore_precedes_custody_and_both_builds_use_one_package_tree(self):
        runtime = self.root / "runtime"
        runtime.mkdir(mode=0o700)
        packages = runtime / "packages"
        packages.mkdir(mode=0o700)
        events = []
        commands = []

        source = {"revision": "1" * 40, "tree": "2" * 40, "custody": {}}
        bootstrap_consumer = {
            "schema": "fixture",
            "files": {
                f"tool:{name}": {"path": f"/tools/{name}"}
                for name in ci.HOST_TOOLS
            } | {
                "command-supervisor": {"path": "/tools/supervisor"},
            },
        }
        consumer = copy.deepcopy(bootstrap_consumer)
        consumer["files"][ci.WAMR_AOT_BUILD_ROLE] = {
            "path": str(
                runtime / "compute/tools/bin/uk-wamr-aot-build"),
        }

        def restore(runtime_value, root, expected_inputs):
            events.append("restore")
            self.assertEqual(runtime_value, runtime)
            self.assertEqual(expected_inputs, bootstrap_consumer)
            return packages

        def supervisor(runtime_value, root, package_tree, expected_inputs):
            events.append("supervisor")
            self.assertEqual(runtime_value, runtime)
            self.assertEqual(package_tree, packages)
            self.assertEqual(expected_inputs, bootstrap_consumer)
            return Path("/tools/supervisor")

        def inputs(root, expected_consumer=None, content=True):
            events.append("custody")
            self.assertIn(
                expected_consumer, (bootstrap_consumer, consumer))
            self.assertTrue(content)
            return {
                "source": ci.source_identity(source),
                "source_custody": source["custody"],
                "dependencies": {},
                "consumer_inputs": expected_consumer,
                "command_supervisor": {"schema": "fixture"},
            }

        def command(runtime, expected, root, stage, args, *unused):
            self.assertEqual(ci.COMMAND_ENVIRONMENT["WAMR_CI_PORTABLE_CONFIG"], "1")
            self.assertEqual(os.environ["WAMR_CI_PORTABLE_CONFIG"], "1")
            planned = {
                item["name"]: item["value"]
                for item in ci.production_command_contract(stage)["environment"]
            }
            self.assertEqual(
                planned["WAMR_CI_PORTABLE_CONFIG"], ci.command_literal("1"))
            fixture_only = (
                "WAMR_CI_PACKAGE",
                "WAMR_CI_PYTHON",
                "WAMR_CI_SUPERVISOR_FIXTURE",
            )
            if stage == "fixtures":
                for name in fixture_only:
                    self.assertIn(name, ci.COMMAND_ENVIRONMENT)
                    self.assertIn(name, os.environ)
            if stage in ("prepare", "config", "native-image"):
                for name in fixture_only:
                    self.assertNotIn(name, ci.COMMAND_ENVIRONMENT)
                    self.assertNotIn(name, os.environ)
            if stage == "config":
                self.assertEqual(os.environ["KCONFIG_OVERWRITECONFIG"], "1")
                self.assertEqual(os.environ["M4"], "/tools/m4")
                self.assertEqual(os.environ["ZIG_LIB_DIR"], "/tools/lib")
            commands.append((stage, list(map(str, args))))
            return root / "private" / (stage + ".log")

        def execute_direct(root, stage, args, *unused, **unused_keywords):
            self.assertEqual(stage, "zig-version")
            path = root / "private/zig-version.log"
            path.write_bytes(b"0.16.0\n")
            return path, {}

        original_supervisor = ci.COMMAND_SUPERVISOR_PATH
        original_tools = dict(ci.COMMAND_TOOL_PATHS)
        with contextlib.ExitStack() as stack:
            stack.enter_context(mock.patch.dict(
                os.environ,
                {"BISON_PKGDATADIR": str(runtime / "bison")},
                clear=True,
            ))
            for name, kwargs in (
                ("prepare_source_outputs", {}),
                ("seal_wamr_source", {
                    "return_value": runtime / "custody/wamr-source.tar"}),
                ("consumer_input_state", {
                    "side_effect": [
                        bootstrap_consumer,
                        bootstrap_consumer,
                        consumer,
                    ],
                }),
                ("source", {"return_value": source}),
                ("source_metadata", {"return_value": []}),
                ("restore_dependencies", {"side_effect": restore}),
                ("build_command_supervisor", {"side_effect": supervisor}),
                ("producer_inputs", {"side_effect": inputs}),
                ("run_custodied", {"side_effect": command}),
                ("execute", {"side_effect": execute_direct}),
                ("require_no_config_backup", {}),
                ("retain_solved_config", {}),
                ("solved_config", {"return_value": "f" * 64}),
                ("require_build_custody", {}),
                ("save", {}),
                ("check_build", {"return_value": {}}),
                ("digest", {"return_value": "f" * 64}),
                ("consumer_file_records", {"return_value": {}}),
                ("retained_executables", {
                    "return_value": contextlib.nullcontext(
                        ({"/tools/zig": "/tools/zig"}, ())),
                }),
                ("bounded_subprocess_output", {
                    "return_value": b"0.16.0\n"}),
                ("tool", {
                    "side_effect": lambda name: "/tools/" + name}),
            ):
                stack.enter_context(mock.patch.object(ci, name, **kwargs))
            stack.enter_context(mock.patch.object(
                ci.subprocess, "check_output", return_value=b"0.16.0\n"))
            ci.build(runtime, self.root)
        ci.COMMAND_TOOL_PATHS.clear()
        ci.COMMAND_TOOL_PATHS.update(original_tools)
        ci.COMMAND_SUPERVISOR_PATH = original_supervisor

        self.assertEqual(events[:3], ["restore", "supervisor", "custody"])
        selected = dict(commands)
        for stage in ("adapter", "local-boot-tool"):
            self.assertIn("--system", selected[stage])
            self.assertEqual(
                selected[stage][selected[stage].index("--system") + 1],
                str(packages),
            )
        self.assertIn("test-unit", selected["adapter"])
        self.assertNotIn("test", selected["adapter"])
        wamr_aot_build = str(
            runtime / "compute/tools/bin/uk-wamr-aot-build")
        self.assertEqual(selected["prepare"], [
            wamr_aot_build,
            "prepare",
            "--repository",
            str(ci.REPO),
            "--source-archive",
            str(runtime / "custody/wamr-source.tar"),
        ])
        self.assertEqual(selected["config"], [
            wamr_aot_build,
            "olddefconfig",
            "--repository",
            str(ci.REPO),
        ])
        self.assertEqual(selected["native-image"], [
            wamr_aot_build,
            "native-images",
            "--repository",
            str(ci.REPO),
        ])
        for stage in ("prepare", "config", "native-image"):
            self.assertNotIn(sys.executable, selected[stage])
        self.assertFalse((ci.LOCAL_BOOT / "zig-pkg").exists())
        self.assertFalse((ci.HERE / "zig-pkg").exists())

    def test_restore_requires_the_private_fetched_package_tree(self):
        missing = ci.REPO / ".d/missing-dependency-source"
        missing_root = self.root / "missing-restore"
        missing_root.mkdir(mode=0o700)
        with mock.patch.object(ci, "LOCAL_BOOT", missing), \
                mock.patch.object(
                    ci, "tracked_manifest",
                    side_effect=ci.Refusal("pinned dependency manifest unavailable")):
            with self.assertRaisesRegex(
                    ci.Refusal, "pinned dependency manifest unavailable"):
                ci.restore_dependencies(
                    missing_root.parent, missing_root, {"schema": "fixture"})
        root = self.root / "restore"
        root.mkdir(mode=0o700)
        for name in ("private", "evidence", "cache", "global-cache"):
            (root / name).mkdir(mode=0o700)
        with mock.patch.object(ci, "require_consumer_inputs"), \
                mock.patch.object(ci, "consumer_file_records",
                                  return_value={}), \
                mock.patch.object(ci, "execute", return_value=(
                    root / "private/dependency-restore.log",
                    {"known_error_markers": []})):
            with self.assertRaisesRegex(
                    ci.Refusal, "private pinned dependency restore required"):
                ci.restore_dependencies(
                    root.parent, root, {"schema": "fixture"})

    def test_dependency_paths_refuse_outside_or_missing_repository_without_leak(self):
        manifests = {
            "build.zig": b"const std = @import(\"std\");\n",
            "build.zig.zon": (
                '.{ .dependencies = .{ .miz_source = .{ '
                f'.url = "{ci.MIZ_URL}", .hash = "{ci.MIZ_PACKAGE_HASH}" '
                '} } }\n'
            ).encode(),
        }
        repository = self.source_repository(
            "dependency-source",
            {
                "support/tools/hyperv/local_boot/" + name: data
                for name, data in manifests.items()
            },
        )
        outside = self.root / "outside-local-boot"
        outside.mkdir(mode=0o700)
        for name, data in manifests.items():
            self.put(outside / name, data)

        for index, local_boot in enumerate((
                outside,
                repository / "support/tools/hyperv/missing-local-boot",
        )):
            restore_root = self.root / f"path-restore-{index}"
            restore_root.mkdir(mode=0o700)
            fixture_root, _, _ = self.dependency_fixture()
            custody_root = self.root / f"path-custody-{index}"
            fixture_root.rename(custody_root)
            with self.subTest(local_boot=local_boot), \
                    mock.patch.object(ci, "REPO", repository), \
                    mock.patch.object(ci, "LOCAL_BOOT", local_boot):
                for operation in (
                        lambda: ci.restore_dependencies(
                            restore_root.parent, restore_root,
                            {"schema": "fixture"}),
                        lambda: ci.dependency_custody(custody_root),
                ):
                    with self.assertRaises(ci.Refusal) as refusal:
                        operation()
                    self.assertEqual(
                        str(refusal.exception),
                        "pinned dependency manifest unavailable",
                    )
                    self.assertIsNone(refusal.exception.__cause__)
                    self.assertNotIn(str(local_boot), str(refusal.exception))

    def test_tracked_manifest_descriptor_walk_rejects_component_and_file_races(self):
        manifests = {
            "build.zig": b"const std = @import(\"std\");\n",
            "build.zig.zon": (
                '.{ .dependencies = .{ .miz_source = .{ '
                f'.url = "{ci.MIZ_URL}", .hash = "{ci.MIZ_PACKAGE_HASH}" '
                '} } }\n'
            ).encode(),
        }
        repository = self.source_repository(
            "manifest-races",
            {
                "support/tools/hyperv/local_boot/" + name: data
                for name, data in manifests.items()
            },
        )
        external = self.root / "external-manifests"
        external.mkdir(mode=0o700)
        for name in manifests:
            self.put(external / name, b"external bytes must not be read\n")
        real_open = ci.os.open

        def race_component(path, flags, mode=0o777, *, dir_fd=None):
            if path == "local_boot" and dir_fd is not None:
                target = repository / "support/tools/hyperv/local_boot"
                saved = target.with_name("local_boot-retained")
                target.rename(saved)
                target.symlink_to(external, target_is_directory=True)
                try:
                    return real_open(path, flags, mode, dir_fd=dir_fd)
                finally:
                    target.unlink()
                    saved.rename(target)
            return real_open(path, flags, mode, dir_fd=dir_fd)

        with mock.patch.object(ci.os, "open", side_effect=race_component), \
                self.assertRaisesRegex(
                    ci.Refusal, "pinned dependency manifest unavailable"):
            ci.tracked_manifest(
                "support/tools/hyperv/local_boot/build.zig", repository)

        def race_file(path, flags, mode=0o777, *, dir_fd=None):
            if path == "build.zig" and dir_fd is not None:
                target = repository / "support/tools/hyperv/local_boot/build.zig"
                saved = target.with_name("build.zig-retained")
                target.rename(saved)
                target.symlink_to(external / "build.zig")
                try:
                    return real_open(path, flags, mode, dir_fd=dir_fd)
                finally:
                    target.unlink()
                    saved.rename(target)
            return real_open(path, flags, mode, dir_fd=dir_fd)

        with mock.patch.object(ci.os, "open", side_effect=race_file), \
                self.assertRaisesRegex(
                    ci.Refusal, "pinned dependency manifest unavailable"):
            ci.tracked_manifest(
                "support/tools/hyperv/local_boot/build.zig", repository)

        original_read = ci.read_descriptor
        raced = False

        def rename_restore(handle, info, limit, reason):
            nonlocal raced
            if not raced:
                raced = True
                target = repository / "support/tools/hyperv/local_boot"
                saved = target.with_name("local_boot-retained")
                target.rename(saved)
                target.symlink_to(external, target_is_directory=True)
                target.unlink()
                saved.rename(target)
            return original_read(handle, info, limit, reason)

        with mock.patch.object(ci, "read_descriptor",
                               side_effect=rename_restore), \
                self.assertRaisesRegex(
                    ci.Refusal, "pinned dependency manifest unavailable"):
            ci.tracked_manifest(
                "support/tools/hyperv/local_boot/build.zig", repository)
        self.assertTrue(raced)

    def dependency_fixture(self):
        root = self.root / "dependency-fixture"
        root.mkdir(mode=0o700)
        private = root / "private"
        private.mkdir(mode=0o700)
        restore = root / "dependencies"
        restore.mkdir(mode=0o700)
        self.put(restore / "build.zig", b"const std = @import(\"std\");\n")
        manifest = (
            '.{ .dependencies = .{ .miz_source = .{ '
            f'.url = "{ci.MIZ_URL}", .hash = "{ci.MIZ_PACKAGE_HASH}" '
            '} } }\n'
        ).encode()
        self.put(restore / "build.zig.zon", manifest)
        self.put(private / "dependency-restore.log", b"")
        packages = restore / "zig-pkg"
        packages.mkdir(mode=0o700)
        miz = packages / ci.MIZ_PACKAGE_HASH
        miz.mkdir(mode=0o700)
        self.put(miz / "build.zig.zon", b".{ .dependencies = .{} }\n")
        self.put(miz / "source.zig", b"pub const answer = 42;\n")
        self.put(private / "dependency-hash-000.log",
                 (ci.MIZ_PACKAGE_HASH + "\n").encode())

        def manifest_record(relative, repository=ci.REPO):
            data = (restore / Path(relative).name).read_bytes()
            metadata = [
                1, 2, stat.S_IFREG | 0o644,
                os.getuid(), os.getgid(), 1, len(data), 1, 1,
            ]
            return ({
                "path": relative, "mode": "100644", "bytes": len(data),
                "sha256": hashlib.sha256(data).hexdigest(), "git_oid": "1" * 40,
                "metadata": metadata,
                "metadata_sha256": hashlib.sha256(json.dumps(
                    metadata, separators=(",", ":")).encode()).hexdigest(),
            }, data)

        return root, packages, mock.patch.object(
            ci, "tracked_manifest", side_effect=manifest_record)

    def test_restore_manifest_requires_exact_miz_revision_hash_and_one_pin(self):
        valid = (
            '.{ .dependencies = .{ .miz_source = .{ '
            f'.url = "{ci.MIZ_URL}", .hash = "{ci.MIZ_PACKAGE_HASH}" '
            '} } }\n'
        ).encode()
        self.assertEqual(ci.validate_restore_manifest(valid)["revision"],
                         ci.MIZ_REVISION)
        for malformed in (
                valid.replace(ci.MIZ_REVISION.encode(), b"1" * 40),
                valid.replace(ci.MIZ_PACKAGE_HASH.encode(), b"miz-0.2.0-wrong"),
                valid.replace(b"} } }\n", (
                    f'}}, .alias = .{{ .hash = "{ci.MIZ_PACKAGE_HASH}" }} }} }}\n'
                ).encode()),
        ):
            with self.subTest(manifest=malformed), self.assertRaises(ci.Refusal):
                ci.validate_restore_manifest(malformed)

    def test_tracked_restore_manifests_keep_exact_miz_module_wiring(self):
        build_record, build = ci.tracked_manifest(
            "support/tools/hyperv/local_boot/build.zig")
        zon_record, zon = ci.tracked_manifest(
            "support/tools/hyperv/local_boot/build.zig.zon")
        self.assertEqual(build.count(
            b'b.dependency("miz_source", .{ .target = target, .optimize = optimize })'
            b'.module("miz")'), 1)
        self.assertEqual(build.count(b'.{ .name = "miz", .module = miz }'), 2)
        self.assertEqual(ci.validate_restore_manifest(zon), {
            "url": ci.MIZ_URL,
            "revision": ci.MIZ_REVISION,
            "package_hash": ci.MIZ_PACKAGE_HASH,
        })
        self.assertEqual(build_record["bytes"], len(build))
        self.assertEqual(zon_record["bytes"], len(zon))

    def test_dependency_custody_detects_same_hash_name_mutation_and_replacement(self):
        root, packages, patch = self.dependency_fixture()
        with patch:
            expected = ci.dependency_custody(root)
            source = packages / ci.MIZ_PACKAGE_HASH / "source.zig"
            self.put(source, b"pub const answer = 41;\n")
            with self.assertRaisesRegex(ci.Refusal, "dependency custody changed"):
                ci.require_dependency_custody(root, expected)
            self.put(source, b"pub const answer = 42;\n")
            original = packages / ci.MIZ_PACKAGE_HASH
            retained = root / "retained-package"
            original.rename(retained)
            shutil.copytree(retained, original)
            with self.assertRaisesRegex(ci.Refusal, "dependency custody changed"):
                ci.require_dependency_custody(root, expected)

    def test_dependency_custody_rejects_symlink_type_missing_and_extra_roots(self):
        root, packages, patch = self.dependency_fixture()
        miz = packages / ci.MIZ_PACKAGE_HASH
        with patch:
            link = miz / "link"
            link.symlink_to("source.zig")
            with self.assertRaises(ci.Refusal):
                ci.dependency_custody(root)
            link.unlink()
            fifo = miz / "fifo"
            os.mkfifo(fifo, 0o600)
            with self.assertRaises(ci.Refusal):
                ci.dependency_custody(root)
            fifo.unlink()
            extra = packages / "extra-0.1.0-aaaaaaaa"
            extra.mkdir(mode=0o700)
            self.put(extra / "source.zig", b"extra\n")
            with self.assertRaisesRegex(ci.Refusal, "unexpected transitive"):
                ci.dependency_custody(root)
            shutil.rmtree(extra)
            self.put(miz / "build.zig.zon", (
                '.{ .dependencies = .{ .missing = .{ '
                '.hash = "missing-0.1.0-aaaaaaaa" } } }\n'
            ).encode())
            with self.assertRaisesRegex(ci.Refusal, "missing transitive"):
                ci.dependency_custody(root)

    def test_zig_hash_recomputation_rejects_wrong_named_content(self):
        root, packages, _ = self.dependency_fixture()
        (root / "dependency-hash-work").mkdir(mode=0o700)
        (root / "dependency-hash-cache").mkdir(mode=0o700)
        shutil.rmtree(root / "dependency-hash-work")
        shutil.rmtree(root / "dependency-hash-cache")
        (root / "private/dependency-hash-000.log").unlink()

        def wrong(*args, **kwargs):
            work = root / "dependency-hash-work"
            self.assertEqual(kwargs["cwd"], work)
            self.assertEqual((work / "build.zig").read_bytes(),
                             (root / "dependencies/build.zig").read_bytes())
            self.assertEqual((work / "build.zig.zon").read_bytes(),
                             (root / "dependencies/build.zig.zon").read_bytes())
            self.assertTrue((work / "zig-pkg").is_dir())
            output = root / "private/dependency-hash-000.log"
            self.put(output, b"miz-0.2.0-wrong\n")
            return output, {}

        with mock.patch.object(ci, "require_consumer_inputs"), \
                mock.patch.object(ci, "consumer_file_records",
                                  return_value={}), \
                mock.patch.object(ci, "execute", side_effect=wrong), \
                self.assertRaisesRegex(ci.Refusal, "content hash mismatch"):
            ci.verify_package_hashes(
                root.parent, root, packages, {"schema": "fixture"})

    def test_zig_hash_recomputation_never_creates_a_repository_package_root(self):
        root, packages, _ = self.dependency_fixture()
        shutil.copyfile(ci.LOCAL_BOOT / "build.zig",
                        root / "dependencies/build.zig")
        shutil.copyfile(ci.LOCAL_BOOT / "build.zig.zon",
                        root / "dependencies/build.zig.zon")
        self.put(packages / ci.MIZ_PACKAGE_HASH / "build.zig.zon", b""".{
    .name = .fixture,
    .version = "0.0.0",
    .fingerprint = 0x5e540eeabebe342,
    .minimum_zig_version = "0.16.0",
    .dependencies = .{},
    .paths = .{""},
}
""")
        (root / "private/dependency-hash-000.log").unlink()
        repository_packages = ci.REPO / "zig-pkg"
        self.assertFalse(repository_packages.exists())
        with mock.patch.object(ci, "require_consumer_inputs"), \
                mock.patch.object(ci, "consumer_file_records",
                                  return_value=None), \
                self.assertRaisesRegex(ci.Refusal, "content hash mismatch"):
            ci.verify_package_hashes(
                root.parent, root, packages, {"schema": "fixture"})
        self.assertFalse(repository_packages.exists())
        self.assertTrue((root / "dependency-hash-work/zig-pkg").is_dir())

    def test_create_exact_copy_never_follows_or_overwrites(self):
        directory = self.root / "copies"
        directory.mkdir(mode=0o700)
        existing = directory / "existing"
        self.put(existing, b"original")
        with self.assertRaisesRegex(ci.Refusal, "already exists"):
            ci.create_exact_copy(existing, b"replacement")
        link = directory / "link"
        link.symlink_to(existing)
        with self.assertRaisesRegex(ci.Refusal, "already exists"):
            ci.create_exact_copy(link, b"replacement")
        self.assertEqual(existing.read_bytes(), b"original")
        large = directory / "large"
        payload = b"x" * (ci.MIB + 1)
        record = ci.create_exact_copy(large, payload)
        self.assertEqual(record["bytes"], len(payload))
        self.assertEqual(large.read_bytes(), payload)

    def test_restore_rejects_manifest_swap_restore_before_zig_returns(self):
        root = self.root / "restore-swap"
        root.mkdir(mode=0o700)
        for name in ("private", "evidence", "cache", "global-cache"):
            (root / name).mkdir(mode=0o700)
        manifests = {
            "build.zig": b"const std = @import(\"std\");\n",
            "build.zig.zon": (
                '.{ .dependencies = .{ .miz_source = .{ '
                f'.url = "{ci.MIZ_URL}", .hash = "{ci.MIZ_PACKAGE_HASH}" '
                '} } }\n'
            ).encode(),
        }

        def manifest_record(relative, repository=ci.REPO):
            data = manifests[Path(relative).name]
            metadata = [
                1, 2, stat.S_IFREG | 0o644,
                os.getuid(), os.getgid(), 1, len(data), 1, 1,
            ]
            return ({
                "path": relative, "mode": "100644", "bytes": len(data),
                "sha256": hashlib.sha256(data).hexdigest(), "git_oid": "1" * 40,
                "metadata": metadata,
                "metadata_sha256": hashlib.sha256(json.dumps(
                    metadata, separators=(",", ":")).encode()).hexdigest(),
            }, data)

        def swap_restore(*unused, **kwargs):
            target = root / "dependencies/build.zig"
            retained = root / "retained-build.zig"
            target.rename(retained)
            shutil.copyfile(retained, target)
            target.chmod(0o600)
            target.unlink()
            retained.rename(target)
            return root / "private/dependency-restore.log", {
                "known_error_markers": [],
            }

        with mock.patch.object(ci, "require_consumer_inputs"), \
                mock.patch.object(ci, "consumer_file_records",
                                  return_value={}), \
                mock.patch.object(ci, "tracked_manifest", side_effect=manifest_record), \
                mock.patch.object(ci, "execute", side_effect=swap_restore), \
                self.assertRaisesRegex(
                    ci.Refusal, "copied dependency manifest identity changed"):
            ci.restore_dependencies(
                root.parent, root, {"schema": "fixture"})
        self.assertEqual(
            (root / "dependencies/build.zig").read_bytes(),
            manifests["build.zig"],
        )

    def test_dependency_inventory_rejects_later_directory_transient(self):
        root, packages, patch = self.dependency_fixture()
        miz = packages / ci.MIZ_PACKAGE_HASH
        self.put(miz / "a-first", b"read first\n")
        later = miz / "z-later"
        later.mkdir(mode=0o700)
        self.put(later / "retained", b"retained\n")
        original = ci.package_file
        mutated = False

        def transient(path, expected):
            nonlocal mutated
            if not mutated and path.name == "a-first":
                changed = later / "transient"
                self.put(changed, b"created and removed\n")
                changed.unlink()
                mutated = True
            return original(path, expected)

        with patch, mock.patch.object(ci, "package_file", side_effect=transient), \
                self.assertRaisesRegex(
                    ci.Refusal, "dependency package directory changed"):
            ci.dependency_custody(root)
        self.assertTrue(mutated)

    def test_dependency_toctou_refuses_before_build_and_after_stage(self):
        root, packages, _ = self.dependency_fixture()
        source_record = {"revision": "1" * 40, "tree": "2" * 40, "custody": {}}
        runtime = root.parent
        compute = runtime / "compute"
        root.rename(compute)
        packages = compute / "dependencies/zig-pkg"
        restore = compute / "dependencies"

        def manifest_record(relative, repository=ci.REPO):
            data = (restore / Path(relative).name).read_bytes()
            metadata = [
                1, 2, stat.S_IFREG | 0o644,
                os.getuid(), os.getgid(), 1, len(data), 1, 1,
            ]
            return ({
                "path": relative, "mode": "100644", "bytes": len(data),
                "sha256": hashlib.sha256(data).hexdigest(), "git_oid": "1" * 40,
                "metadata": metadata,
                "metadata_sha256": hashlib.sha256(json.dumps(
                    metadata, separators=(",", ":")).encode()).hexdigest(),
            }, data)

        patch = mock.patch.object(ci, "tracked_manifest", side_effect=manifest_record)
        with patch:
            dependency = ci.dependency_custody(compute)
            expected = {
                "source": ci.source_identity(source_record),
                "source_custody": source_record["custody"],
                "dependencies": dependency,
                "consumer_inputs": {"schema": "fixture"},
                "command_supervisor": {"schema": "fixture"},
            }
            target = packages / ci.MIZ_PACKAGE_HASH / "source.zig"
            self.put(target, b"changed before build\n")
            with mock.patch.object(ci, "source", return_value=source_record), \
                    mock.patch.object(ci, "require_consumer_inputs"), \
                    mock.patch.object(
                        ci, "command_supervisor_state",
                        return_value={"schema": "fixture"}), \
                    mock.patch.object(ci, "consumer_file_records",
                                      return_value={}), \
                    mock.patch.object(ci, "run") as command, \
                    self.assertRaisesRegex(ci.Refusal, "dependency custody changed"):
                ci.run_custodied(runtime, expected, compute, "adapter", ["false"])
            command.assert_not_called()
            self.put(target, b"pub const answer = 42;\n")
            dependency = ci.dependency_custody(compute)
            expected["dependencies"] = dependency

            def mutate(*unused, **unused_keywords):
                self.put(target, b"changed during build\n")
                return compute / "private/adapter.log"

            with mock.patch.object(ci, "source", return_value=source_record), \
                    mock.patch.object(ci, "require_consumer_inputs"), \
                    mock.patch.object(
                        ci, "command_supervisor_state",
                        return_value={"schema": "fixture"}), \
                    mock.patch.object(ci, "consumer_file_records",
                                      return_value={}), \
                    mock.patch.object(ci, "run", side_effect=mutate), \
                    self.assertRaisesRegex(ci.Refusal, "dependency custody changed"):
                ci.run_custodied(runtime, expected, compute, "adapter", ["fixture"])

    def test_run_custodied_revalidates_extra_inputs_as_boot_roles(self):
        expected = {"consumer_inputs": {"schema": "consumer"}}
        boot_inputs = {"schema": "boot"}
        boot_paths = {"qemu": self.root / "qemu"}
        with mock.patch.object(ci, "require_build_custody"), \
                mock.patch.object(ci, "require_boot_inputs") as verify_boot, \
                mock.patch.object(
                    ci, "consumer_file_records", return_value={}), \
                mock.patch.object(ci, "run", return_value=self.root / "log"):
            self.assertEqual(
                ci.run_custodied(
                    self.root, expected, self.root, "boot", ["fixture"],
                    extra_inputs=boot_inputs, extra_input_paths=boot_paths),
                self.root / "log",
            )
        self.assertEqual(
            verify_boot.call_args_list,
            [
                mock.call(self.root, boot_paths, boot_inputs),
                mock.call(self.root, boot_paths, boot_inputs),
            ],
        )
        with self.assertRaisesRegex(
                ci.Refusal, "incomplete extra input custody"):
            ci.run_custodied(
                self.root, expected, self.root, "boot", ["fixture"],
                extra_inputs=boot_inputs)

    def test_source_custody_detects_ignored_create_delete_metadata(self):
        repository = self.root / "repository"
        repository.mkdir(mode=0o700)
        (repository / "source").mkdir(mode=0o700)
        self.put(repository / "source/input", b"tracked\n")
        (repository / "source/link").symlink_to("input")
        self.put(repository / ".gitignore", b"""\
/.d/
/.zig-cache/
/support/apps/wamr-aot/.config
/support/apps/wamr-aot/build/
source/generated/
""")
        app = repository / "support/apps/wamr-aot"
        app.mkdir(parents=True, mode=0o700)
        self.put(app / "defconfig", b"CONFIG_FIXTURE=y\n")
        subprocess.run([GIT, "init", "-q"], cwd=repository, check=True)
        subprocess.run([GIT, "config", "user.email", "fixture@example.invalid"],
                       cwd=repository, check=True)
        subprocess.run([GIT, "config", "user.name", "Fixture"],
                       cwd=repository, check=True)
        subprocess.run([GIT, "add", ".gitignore", "source/input", "source/link",
                        "support/apps/wamr-aot/defconfig"],
                       cwd=repository, check=True)
        subprocess.run([GIT, "commit", "-qm", "fixture"], cwd=repository, check=True)
        (repository / ".d").mkdir(mode=0o700)
        (repository / ".zig-cache").mkdir(mode=0o700)
        (app / "build").mkdir(mode=0o700)
        self.put(app / ".config", b"CONFIG_FIXTURE=y\n")
        expected = ci.source(repository)
        self.assertEqual(ci.source(repository), expected)
        generated = repository / "source/generated"
        generated.mkdir(mode=0o700)
        generated.rmdir()
        self.assertEqual(
            subprocess.check_output(
                [GIT, "status", "--porcelain=v2", "--untracked-files=all"],
                cwd=repository),
            b"",
        )
        with self.assertRaisesRegex(ci.Refusal, "immutable source custody changed"):
            ci.require_source(expected, repository)
        baseline = ci.source_metadata(repository)
        baseline_path = self.root / "source-metadata.json"
        ci.save(baseline_path, {
            "schema": "uk.wamr.git-physical-source-baseline",
            "version": 1,
            "records": baseline,
        })
        self.assertEqual(
            ci.source_metadata_document(baseline_path)["records"],
            json.loads(json.dumps(baseline)),
        )
        generated.mkdir(mode=0o700)
        generated.rmdir()
        changes = ci.source_metadata_changes(
            baseline, ci.source_metadata(repository))
        self.assertEqual(changes["changed_records"], 1)
        self.assertEqual(
            [(item["kind"], item["path"]) for item in changes["changed"]],
            [("directory", "source")],
        )
        self.assertFalse(changes["truncated"])
        self.put(self.root / "outside", b"not source\n")
        (repository / "source/link").unlink()
        (repository / "source/link").symlink_to("../../outside")
        subprocess.run([GIT, "add", "source/link"], cwd=repository, check=True)
        subprocess.run([GIT, "commit", "-qm", "escaping link"],
                       cwd=repository, check=True)
        with self.assertRaisesRegex(ci.Refusal, "symlink escapes repository"):
            ci.source(repository)

    def test_ignored_source_policy_rejects_existing_and_late_global_ignores(self):
        for index, suffix in enumerate(("o", "a", "pyc")):
            repository = self.source_repository(f"ignored-{index}")
            ignored = repository / "source" / ("hidden." + suffix)
            self.put(ignored, b"unreviewed ignored input\n")
            with self.subTest(suffix=suffix), self.assertRaisesRegex(
                    ci.Refusal, "outside output roles"):
                ci.source(repository)

        repository = self.source_repository("ignored-late")
        expected = ci.source(repository)
        self.put(repository / "source/late.o", b"created after baseline\n")
        with self.assertRaisesRegex(ci.Refusal, "outside output roles"):
            ci.require_source(expected, repository)

    def test_ignored_source_policy_uses_exact_roles_and_safe_types(self):
        repository = self.source_repository("ignored-roles")
        expected = ci.source(repository)
        for relative in (
                ".d/runtime.o",
                ".zig-cache/cache.a",
                "support/apps/wamr-aot/build/generated.pyc",
        ):
            self.put(repository / relative, b"approved output\n")
        (repository / "support/apps/wamr-aot/build/Makefile").symlink_to(
            repository / "source/input")
        self.put(
            repository / "support/apps/wamr-aot/.config",
            b"CONFIG_SOLVED=y\n",
        )
        self.assertEqual(ci.source(repository), expected)
        (repository / ".d-sibling").mkdir(mode=0o700)
        self.put(repository / ".d-sibling/escape.o", b"sibling escape\n")
        with self.assertRaisesRegex(ci.Refusal, "outside output roles"):
            ci.source(repository)

    def test_ignored_source_policy_rejects_symlink_type_and_path_escape(self):
        repository = self.source_repository("ignored-unsafe")
        self.put(repository / ".d/tool", b"tool\n")
        (repository / ".d/tool-link").symlink_to("tool")
        ci.source(repository)
        (repository / ".d/tool-link").unlink()
        (repository / ".d/tool-link").symlink_to("future-tool")
        ci.source(repository)
        (repository / ".d/tool-link").unlink()
        (repository / ".d/a").symlink_to("b")
        (repository / ".d/b").symlink_to("a")
        with self.assertRaisesRegex(ci.Refusal, "symlink escapes repository"):
            ci.source(repository)
        (repository / ".d/a").unlink()
        (repository / ".d/b").unlink()
        outside = self.root / "ignored-unsafe-outside"
        self.put(outside, b"outside\n")
        (repository / ".d/tool-link").symlink_to(
            os.path.relpath(outside, repository / ".d"))
        with self.assertRaisesRegex(ci.Refusal, "symlink escapes repository"):
            ci.source(repository)
        (repository / ".d/tool-link").unlink()
        fifo = repository / ".d/fifo"
        os.mkfifo(fifo, 0o600)
        with self.assertRaisesRegex(ci.Refusal, "unsupported ignored source entry type"):
            ci.source(repository)
        fifo.unlink()
        cache = repository / ".zig-cache"
        cache.rmdir()
        cache.symlink_to(".d")
        with self.assertRaisesRegex(ci.Refusal, "unsafe source output role"):
            ci.source(repository)

    def test_ignored_source_policy_enforces_entry_byte_path_and_depth_limits(self):
        repository = self.source_repository("ignored-bounds")
        for name in ("a", "b", "c"):
            self.put(repository / ".d" / name, b"x")
        with mock.patch.object(ci, "SOURCE_IGNORED_MAX_ENTRIES", 6), \
                self.assertRaisesRegex(ci.Refusal, "entry limit exceeded"):
            ci.source(repository)
        with mock.patch.object(ci, "SOURCE_IGNORED_MAX_BYTES", 2), \
                self.assertRaisesRegex(ci.Refusal, "byte limit exceeded"):
            ci.source(repository)
        with mock.patch.object(ci, "SOURCE_IGNORED_MAX_PATH", 3), \
                self.assertRaisesRegex(ci.Refusal, "source output role policy"):
            ci.source(repository)
        with mock.patch.object(ci, "SOURCE_IGNORED_MAX_DEPTH", 1), \
                self.assertRaisesRegex(ci.Refusal, "source output role policy"):
            ci.source(repository)

    def test_custody_git_commands_disable_repository_fsmonitor(self):
        repository = self.source_repository("fsmonitor-disabled")
        marker = repository / ".git/fsmonitor-executed"
        hook = repository / ".git/malicious-fsmonitor"
        hook.write_text(
            "#!/bin/sh\n"
            f"printf executed > {str(marker)!r}\n"
            "exit 1\n",
            encoding="ascii",
        )
        hook.chmod(0o700)
        wrapper = self.root / "fsmonitor-git-wrapper"
        real_git = Path(shutil.which(GIT)).resolve(strict=True)
        wrapper.write_text(
            "#!/bin/sh\n"
            "case \" $* \" in\n"
            "  *' -c core.fsmonitor=false '*) ;;\n"
            f"  *) printf missing-fsmonitor > {str(marker)!r}; exit 97 ;;\n"
            "esac\n"
            "case \" $* \" in\n"
            "  *' -c core.fsmonitorHookVersion= '*) ;;\n"
            f"  *) printf missing-version > {str(marker)!r}; exit 98 ;;\n"
            "esac\n"
            f"exec {str(real_git)!r} \"$@\"\n",
            encoding="ascii",
        )
        wrapper.chmod(0o700)
        subprocess.run(
            [GIT, "config", "core.fsmonitor", str(hook)],
            cwd=repository, check=True)
        subprocess.run(
            [GIT, "config", "core.fsmonitorHookVersion", "2"],
            cwd=repository, check=True)
        with mock.patch.dict(
                ci.COMMAND_TOOL_PATHS, {"git": str(wrapper)}, clear=False):
            ci.source(repository)
            self.assertRegex(
                ci.git_directory_output(
                    repository, 65, "rev-parse", "HEAD").decode().strip(),
                r"^[0-9a-f]{40}$",
            )
        self.assertFalse(marker.exists())
        self.assertIn("core.fsmonitor=false", ci.git_command("status"))
        self.assertIn("core.fsmonitorHookVersion=", ci.git_command("status"))

    def test_bounded_directory_collection_stops_on_first_excess(self):
        class Entry:
            def __init__(self, name):
                self.name = name

        class Scan:
            def __init__(self):
                self.count = 0

            def __iter__(self):
                return self

            def __next__(self):
                self.count += 1
                if self.count > 129:
                    raise AssertionError("enumerated beyond first excess")
                return Entry(f"entry-{self.count:03d}")

            def close(self):
                pass

        scan = Scan()
        with mock.patch.object(ci.os, "scandir", return_value=scan), \
                self.assertRaisesRegex(ci.Refusal, "root inventory too large"):
            ci.bounded_directory_paths(
                self.root, "", 0, 128,
                "source root inventory too large",
                "invalid source root inventory",
            )
        self.assertEqual(scan.count, 129)

    def test_package_scans_bound_before_sorting_or_materializing(self):
        restore = self.root / "bounded-restore"
        restore.mkdir(mode=0o700)
        for name in ("build.zig", "build.zig.zon", "zig-pkg", "excess"):
            path = restore / name
            if name == "zig-pkg":
                path.mkdir(mode=0o700)
            else:
                self.put(path, b"x")
        with self.assertRaisesRegex(
                ci.Refusal, "unexpected dependency restore entry"):
            ci.restored_manifest_state(restore, {})

        packages = self.root / "bounded-package-roots"
        packages.mkdir(mode=0o700)
        for name in ("package-a", "package-b", "package-c"):
            (packages / name).mkdir(mode=0o700)
        with mock.patch.object(ci, "PACKAGE_MAX_ROOTS", 2):
            with self.assertRaisesRegex(
                    ci.Refusal, "invalid dependency package roots"):
                ci.package_tree_state(packages)
            with self.assertRaisesRegex(
                    ci.Refusal, "invalid dependency package roots"):
                ci.package_roots(packages)

        inventory_packages = self.root / "bounded-inventory"
        package = inventory_packages / "package"
        package.mkdir(parents=True, mode=0o700)
        inventory_packages.chmod(0o700)
        self.put(package / "first", b"first")
        self.put(package / "second", b"second")
        state = ci.package_tree_state(inventory_packages)
        with mock.patch.object(ci, "PACKAGE_MAX_ENTRIES", 2), \
                self.assertRaisesRegex(
                    ci.Refusal, "dependency package entry limit exceeded"):
            ci.directory_inventory(inventory_packages, "package", state)

    def test_bounded_subprocess_collection_terminates_on_first_excess(self):
        marker = self.root / "unbounded-reader-finished"
        script = (
            "import os,time\n"
            "from pathlib import Path\n"
            f"os.write(1, b'x' * {ci.MIB + 1})\n"
            "time.sleep(10)\n"
            f"Path({str(marker)!r}).write_text('late')\n"
        )
        started = time.monotonic()
        with self.assertRaisesRegex(ci.Refusal, "fixture overflow"):
            ci.bounded_subprocess_output(
                [PYTHON, "-c", script], self.root, ci.MIB, 20,
                "fixture overflow", "fixture timeout", "fixture failed",
            )
        self.assertLess(time.monotonic() - started, 5)
        self.assertFalse(marker.exists())

    def test_bootstrap_is_explicit_and_has_an_exact_closed_stage_allowlist(self):
        original = ci.COMMAND_SUPERVISOR_PATH
        ci.COMMAND_SUPERVISOR_PATH = None
        try:
            with mock.patch.dict(
                    os.environ,
                    {"WAMR_CI_SUPERVISOR": "/attacker/supervisor"},
                    clear=False):
                with self.assertRaisesRegex(
                        ci.Refusal, "command supervisor is unavailable"):
                    ci.execute(
                        self.root, "public-validator-build",
                        [PYTHON, "-c", "print('must not run')"])
            output, record = ci.execute(
                self.root, "dependency-restore",
                [PYTHON, "-c", "print('bootstrap')"],
                allow_bootstrap=True)
            self.assertEqual(output.read_bytes(), b"bootstrap\n")
            self.assertTrue(record["supervisor"]["bootstrap"])
            for stage in (
                    "dependency-restore-extra", "dependency-hash",
                    "dependency-hash-128", "adapter", "package",
                    "public-validator-build"):
                with self.subTest(stage=stage), self.assertRaisesRegex(
                        ci.Refusal, "bootstrap stage is not allowed"):
                    ci.execute(
                        self.root, stage, [PYTHON, "-c", "pass"],
                        allow_bootstrap=True)
            self.assertEqual(
                ci.BOOTSTRAP_STAGES,
                frozenset({
                    "dependency-restore", "supervisor-build",
                    *(f"dependency-hash-{index:03d}"
                      for index in range(ci.PACKAGE_MAX_ROOTS)),
                }),
            )
        finally:
            ci.COMMAND_SUPERVISOR_PATH = original

    def test_only_dependency_and_supervisor_construction_request_bootstrap(self):
        tree = ast.parse((HERE / "run.py").read_text())
        observed = []

        class Calls(ast.NodeVisitor):
            def __init__(self):
                self.functions = []

            def visit_FunctionDef(self, node):
                self.functions.append(node.name)
                self.generic_visit(node)
                self.functions.pop()

            def visit_Call(self, node):
                if (isinstance(node.func, ast.Name)
                        and node.func.id in {"execute", "run"}):
                    enabled = [
                        keyword for keyword in node.keywords
                        if keyword.arg == "allow_bootstrap"
                    ]
                    if enabled:
                        if (self.functions[-1] == "run"
                                and len(enabled) == 1
                                and isinstance(enabled[0].value, ast.Name)
                                and enabled[0].value.id
                                == "allow_bootstrap"):
                            self.generic_visit(node)
                            return
                        self.assert_true(
                            len(enabled) == 1
                            and isinstance(enabled[0].value, ast.Constant)
                            and enabled[0].value.value is True)
                        observed.append((self.functions[-1], node.lineno))
                self.generic_visit(node)

            def assert_true(self, value):
                if not value:
                    raise AssertionError("nonliteral bootstrap capability")

        Calls().visit(tree)
        self.assertEqual(
            [name for name, unused_line in observed],
            [
                "verify_package_hashes",
                "restore_dependencies",
                "build_command_supervisor",
            ],
        )
        for relative in ("handoff.py", "public_bundle.py"):
            self.assertNotIn(
                "allow_bootstrap",
                (HERE / relative).read_text(),
            )

    def test_supervisor_build_pins_portable_target(self):
        target = ("-Dtarget=x86_64-linux-gnu", "-Dcpu=x86_64_v2")
        self.assertEqual(ci.RECORDED_EXECUTABLE_TARGET, target)
        with mock.patch.object(
                ci, "supervisor_source_map",
                return_value={"content_closure_sha256": "1" * 64}), \
                mock.patch.object(ci, "consumer_file_records"), \
                mock.patch.object(ci, "require_consumer_inputs"), \
                mock.patch.object(ci, "tool", return_value="/tools/zig"), \
                mock.patch.object(
                    ci, "execute", side_effect=RuntimeError("build captured")) as execute:
            with self.assertRaisesRegex(RuntimeError, "build captured"):
                ci.build_command_supervisor(
                    self.root, self.root, self.root / "packages", {})
        args = execute.call_args.args[2]
        self.assertEqual(
            [arg for arg in args if str(arg).startswith(("-Dtarget=", "-Dcpu="))],
            list(target),
        )
        self.assertIn("-Doptimize=ReleaseSafe", args)

    def test_public_validator_build_and_contract_pin_portable_target(self):
        target = ("-Dtarget=x86_64-linux-gnu", "-Dcpu=x86_64_v2")
        runtime = self.root / "runtime"
        (self.root / ".d").mkdir(mode=0o700)
        handoff = types.SimpleNamespace(
            ci=ci, result_records=mock.Mock(), private=mock.Mock())
        with mock.patch.object(ci, "REPO", self.root), \
                mock.patch.object(ci, "tool", return_value="/tools/zig"), \
                mock.patch.object(ci, "consumer_file_records"), \
                mock.patch.object(
                    ci, "read", return_value=b"primary=0 cleanup=0\n"), \
                mock.patch.object(public_bundle, "ci_runtime", return_value=runtime), \
                mock.patch.object(
                    public_bundle, "accepted_public_build_start",
                    return_value={"consumer_inputs": {}}), \
                mock.patch.object(public_bundle, "ci_context"), \
                mock.patch.object(
                    ci, "execute", side_effect=RuntimeError("build captured")) as execute:
            with self.assertRaisesRegex(RuntimeError, "build captured"):
                public_bundle.publish_ci(handoff)
        args = execute.call_args.args[2]
        self.assertEqual(
            [arg for arg in args if str(arg).startswith(("-Dtarget=", "-Dcpu="))],
            list(target),
        )
        self.assertIn("-Doptimize=ReleaseSafe", args)
        record, identities = self.supervised_binding("public-validator-build")
        argv = record["supervisor"]["request"]["argv"]
        for flag in target:
            self.assertIn(ci.command_literal(flag), argv)
            for replacement in ("-Dcpu=native", "-Dcpu=x86_64_v3",
                                "-Dtarget=aarch64-linux-gnu", None):
                with self.subTest(flag=flag, replacement=replacement):
                    changed = copy.deepcopy(record)
                    changed_argv = changed["supervisor"]["request"]["argv"]
                    index = changed_argv.index(ci.command_literal(flag))
                    if replacement is None:
                        changed_argv.pop(index)
                    else:
                        changed_argv[index] = ci.command_literal(replacement)
                    self.rehash_supervised_binding(changed)
                    with self.assertRaises(ValueError):
                        public_bundle.supervised_command_record(
                            ci, changed, "public-validator-build", identities,
                            "trusted_inner_zip")

    def test_native_wamr_command_binding_refuses_rehashed_tamper(self):
        for stage in ("prepare", "config", "native-image"):
            with self.subTest(stage=stage):
                record, identities = self.supervised_binding(stage)
                ci.validate_supervised_command_binding(
                    record, stage, identities)

                tampered = copy.deepcopy(record)
                tampered["supervisor"]["request"]["argv"][0] = (
                    ci.command_path("tool:python3"))
                with self.assertRaises(ci.Refusal):
                    ci.validate_supervised_command_binding(
                        self.rehash_supervised_binding(tampered),
                        stage, identities)

                tampered = copy.deepcopy(record)
                tampered["supervisor"]["request"]["interpreter"] = (
                    copy.deepcopy(
                        tampered["supervisor"]["request"][
                            "native_executable"]))
                with self.assertRaises(ci.Refusal):
                    ci.validate_supervised_command_binding(
                        self.rehash_supervised_binding(tampered),
                        stage, identities)

                changed_identities = copy.deepcopy(identities)
                changed_identities[ci.WAMR_AOT_BUILD_ROLE][
                    "content_sha256"] = "0" * 64
                with self.assertRaises(ci.Refusal):
                    ci.validate_supervised_command_binding(
                        record, stage, changed_identities)

    def test_prepared_validator_supervision_is_closed_and_identity_bound(self):
        for stage, legacy in (("log-validator-x2apic", "forbidden"),
                              ("log-validator-legacy", "required")):
            with self.subTest(stage=stage):
                self.assertNotIn(stage, ci.PRODUCTION_COMMAND_STAGES)
                contract = ci.production_command_contract(stage)
                self.assertEqual(contract["environment"], [])
                self.assertEqual(contract["retained_names"], [])
                self.assertIsNone(contract["interpreter"])
                self.assertEqual(contract["argv"][-4:], [
                    ci.command_literal("--legacy-apic"),
                    ci.command_literal(legacy),
                    ci.command_literal("--output"),
                    ci.command_literal("json-v1"),
                ])
                record, identities = self.supervised_binding(stage)
                ci.validate_supervised_command_binding(
                    record, stage, identities)
                changed = copy.deepcopy(record)
                changed["supervisor"]["request"]["argv"][-3] = (
                    ci.command_literal("forbidden" if legacy == "required"
                                       else "required"))
                with self.assertRaises(ci.Refusal):
                    ci.validate_supervised_command_binding(
                        self.rehash_supervised_binding(changed),
                        stage, identities)
                changed = copy.deepcopy(record)
                changed["supervisor"]["request"]["argv"][0] = (
                    ci.command_path("tool:python3"))
                with self.assertRaises(ci.Refusal):
                    ci.validate_supervised_command_binding(
                        self.rehash_supervised_binding(changed),
                        stage, identities)
                changed_identities = copy.deepcopy(identities)
                changed_identities[ci.WAMR_LOG_VALIDATOR_ROLE][
                    "content_sha256"] = "0" * 64
                with self.assertRaises(ci.Refusal):
                    ci.validate_supervised_command_binding(
                        record, stage, changed_identities)

    def test_fixture_environment_uses_the_installed_validator_role(self):
        validator = self.root / "tools/bin/uk-wamr-log-validate"
        validator.parent.mkdir(parents=True, mode=0o700)
        self.put(validator, b"installed native log validator")
        validator.chmod(0o700)
        contract = ci.production_command_contract("fixtures")
        expected = next(
            entry["value"] for entry in contract["environment"]
            if entry["name"] == "WAMR_CI_LOG_VALIDATE"
        )
        roots = ci.command_path_roots(
            self.root, {ci.WAMR_LOG_VALIDATOR_ROLE: validator})
        observed = ci.normalized_command_value(
            str(validator), roots, strict=True)
        self.assertEqual(expected, observed)
        self.assertEqual(expected, ci.command_path(ci.WAMR_LOG_VALIDATOR_ROLE))
        self.assertIn("WAMR_CI_LOG_VALIDATE", contract["retained_names"])

    def test_real_supervised_validator_matches_both_closed_apic_contracts(self):
        self.assertIsNotNone(SUPERVISOR)
        self.assertIsNotNone(LOG_VALIDATE)
        supervisor = Path(SUPERVISOR).resolve(strict=True)
        validator = Path(LOG_VALIDATE).resolve(strict=True)
        records = {}
        for path in (supervisor, validator):
            record, unused_directories = ci.physical_file_record(path)
            del unused_directories
            records[record["path"]] = record
        identities = {
            "command-supervisor": ci.native_executable_identity(
                records[str(supervisor)]),
            ci.WAMR_LOG_VALIDATOR_ROLE: ci.native_executable_identity(
                records[str(validator)]),
        }
        original_supervisor = ci.COMMAND_SUPERVISOR_PATH
        ci.COMMAND_SUPERVISOR_PATH = str(supervisor)
        try:
            for stage, legacy in ci.LOG_VALIDATOR_STAGES.items():
                with self.subTest(stage=stage):
                    raw = (
                        "Hyper-V Hv#1 hypercall page enabled\n"
                        "Hyper-V SynIC:\nPowered by\n"
                        + ("Using legacy xAPIC MMIO\n"
                           if legacy == "required" else "")
                        + "Calling main(0, 0)\nWAMR_NATIVE_COMPUTE="
                        + json.dumps(self.contract.result)
                        + "\nWAMR_NATIVE_AOT_OK answer=42 teardown=0\n"
                        "[    1.000001] Info: [libukboot] main returned 0\n"
                    ).encode()
                    log = self.root / "private" / (stage + ".serial")
                    identity = self.root / "private" / (stage + ".identity")
                    self.put(log, raw)
                    self.put(identity, json.dumps(self.contract.identity).encode())
                    args = [
                        validator, "tiny", "--log", log,
                        "--identity", identity, "--legacy-apic", legacy,
                        "--output", "json-v1",
                    ]
                    contract = ci.production_command_contract(stage)
                    self.assertEqual(contract["environment"], [])
                    self.assertEqual(
                        ci.command_environment(self.root, stage=stage), {})
                    with mock.patch.dict(
                            ci.COMMAND_ENVIRONMENT,
                            {"PATH": "/untrusted/bin", "LD_PRELOAD": "/untrusted/lib.so"}):
                        output, record = ci.execute(
                            self.root, stage, args,
                            seconds=contract["seconds"],
                            limit=contract["output_limit"], cwd=ci.REPO,
                            input_records=records,
                            path_roles={
                                ci.WAMR_LOG_VALIDATOR_ROLE: validator,
                                "input:serial": log,
                                "input:identity": identity,
                            })
                    payload = output.read_bytes()
                    self.assertTrue(payload.endswith(b"\n"))
                    self.assertEqual(payload.count(b"\n"), 1)
                    self.assertEqual(json.loads(payload), {
                        "schema": "uk.wamr.log-validation",
                        "schema_version": 1,
                        "mode": "tiny",
                        "raw_serial_bytes": len(raw),
                        "raw_serial_sha256": hashlib.sha256(raw).hexdigest(),
                        "compute": self.contract.result,
                    })
                    self.assertEqual(
                        record["supervisor"]["result"]["command"]["stdout"]["bytes"],
                        len(payload))
                    self.assertEqual(
                        record["supervisor"]["result"]["command"]["stderr"]["bytes"],
                        0)
                    request = record["supervisor"]["request"]
                    self.assertEqual(request["environment"], [])
                    self.assertEqual(request["retained_executables"], [])
                    self.assertEqual(request["argv"], contract["argv"])
                    ci.validate_supervised_command_binding(
                        record, stage, identities)

                    injected = copy.deepcopy(record)
                    injected["supervisor"]["request"]["environment"] = [{
                        "name": "PATH", "value": ci.command_literal("/untrusted/bin"),
                    }]
                    with self.assertRaises(ci.Refusal):
                        ci.validate_supervised_command_binding(
                            self.rehash_supervised_binding(injected),
                            stage, identities)

                    failure = self.root / (stage + "-wrong-apic")
                    (failure / "private").mkdir(parents=True, mode=0o700)
                    (failure / "evidence").mkdir(mode=0o700)
                    self.put(log, raw.replace(
                        b"Using legacy xAPIC MMIO\n", b""))
                    if legacy == "forbidden":
                        self.put(log, raw.replace(
                            b"Powered by\n",
                            b"Powered by\nUsing legacy xAPIC MMIO\n"))
                    with self.assertRaises(ci.Refusal):
                        ci.execute(
                            failure, stage, args,
                            seconds=contract["seconds"],
                            limit=contract["output_limit"], cwd=ci.REPO,
                            input_records=records,
                            path_roles={
                                ci.WAMR_LOG_VALIDATOR_ROLE: validator,
                                "input:serial": log,
                                "input:identity": identity,
                            })
                    failed = ci.document(
                        failure / "evidence" / ("command-" + stage + ".json"))
                    self.assertEqual(
                        failed["supervisor"]["result"]["command"]["stdout"]["bytes"],
                        0)
                    self.assertEqual(failed["exit_code"], 1)
                    self.assertEqual(
                        (failure / "private" / (stage + ".log")).read_bytes(),
                        b"WAMR_LOG_VALIDATION_REFUSED category=transcript reason=invalid\n")
        finally:
            ci.COMMAND_SUPERVISOR_PATH = original_supervisor

    def test_native_result_requires_exact_raw_and_output_commitment(self):
        raw = self.contract.log()
        output = self.root / "private/validator.json"
        payload = {
            "schema": "uk.wamr.log-validation", "schema_version": 1,
            "mode": "tiny", "raw_serial_bytes": len(raw),
            "raw_serial_sha256": hashlib.sha256(raw).hexdigest(),
            "compute": self.contract.result,
        }
        self.put(output, json.dumps(payload).encode() + b"\n")
        record = {"bytes": output.stat().st_size, "sha256": ci.digest(output)}
        self.assertEqual(ci.native_result(output, record, raw, 8192),
                         self.contract.result)
        for change in (
            {"raw_serial_bytes": len(raw) - 1},
            {"raw_serial_sha256": "0" * 64},
            {"schema_version": True},
            {"compute": None},
            {"mode": "snapshot"},
        ):
            self.put(output, json.dumps(dict(payload, **change)).encode() + b"\n")
            changed = {"bytes": output.stat().st_size,
                       "sha256": ci.digest(output)}
            with self.subTest(change=change), self.assertRaises(ci.Refusal):
                ci.native_result(output, changed, raw, 8192)
        self.put(output, json.dumps(payload).encode() + b"\n")
        self.put(output, output.read_bytes().replace(b'"answer": 42',
                                                      b'"answer": 41'))
        with self.assertRaisesRegex(ci.Refusal, "output changed"):
            ci.native_result(output, record, raw, 8192)

    def test_check_boot_requires_native_validator_custody(self):
        config = self.synthetic_boot()
        self.fixture_validator.stop()
        with self.assertRaisesRegex(ci.Refusal, "validator custody"):
            ci.check_boot(config, self.contract.identity,
                          identity_path=self.root / "private/identity.json")

    def test_publication_binds_installed_log_validator_role(self):
        record, identities = self.supervised_binding("log-validator-x2apic")

        def input_record(identity):
            return {
                "metadata": [
                    os.makedev(
                        identity["device_major"], identity["device_minor"]),
                    identity["inode"], identity["mode"], identity["uid"],
                    os.getgid(), 1, identity["size"],
                    identity["mtime_seconds"] * 1_000_000_000
                    + identity["mtime_nanoseconds"],
                    identity["ctime_seconds"] * 1_000_000_000
                    + identity["ctime_nanoseconds"],
                ],
                "sha256": identity["content_sha256"],
            }

        consumer = {
            role: input_record(identity)
            for role, identity in identities.items()
            if role in {"command-supervisor", ci.WAMR_LOG_VALIDATOR_ROLE}
        }
        for name in ci.HOST_TOOLS:
            consumer["tool:" + name] = input_record(
                identities["command-supervisor"])
        boot = {
            name: input_record(identities["command-supervisor"])
            for name in ("package_tool", "local_boot_tool")
        }
        roles = public_bundle.publication_role_identities(
            ci, consumer, boot)
        ci.validate_supervised_command_binding(
            record, "log-validator-x2apic", roles)
        consumer[ci.WAMR_LOG_VALIDATOR_ROLE]["sha256"] = "0" * 64
        roles = public_bundle.publication_role_identities(
            ci, consumer, boot)
        with self.assertRaises(ci.Refusal):
            ci.validate_supervised_command_binding(
                record, "log-validator-x2apic", roles)

    def test_publication_binds_native_producer_to_consumer_custody(self):
        def input_record(identity):
            return {
                "metadata": [
                    os.makedev(
                        identity["device_major"], identity["device_minor"]),
                    identity["inode"], identity["mode"], identity["uid"],
                    os.getgid(), 1, identity["size"],
                    identity["mtime_seconds"] * 1_000_000_000
                    + identity["mtime_nanoseconds"],
                    identity["ctime_seconds"] * 1_000_000_000
                    + identity["ctime_nanoseconds"],
                ],
                "sha256": identity["content_sha256"],
            }

        for stage in ("adapter", "prepare", "config", "native-image"):
            with self.subTest(stage=stage):
                record, identities = self.supervised_binding(stage)
                consumer_files = {
                    role: input_record(identity)
                    for role, identity in identities.items()
                }
                boot_files = {
                    role: input_record(identities["command-supervisor"])
                    for role in ("package_tool", "local_boot_tool")
                }
                roles = public_bundle.publication_role_identities(
                    ci, consumer_files, boot_files)
                public_bundle.supervised_command_record(
                    ci, record, stage, roles, "producer_direct")

                without_native = dict(consumer_files)
                without_native.pop(ci.WAMR_AOT_BUILD_ROLE, None)
                legacy_roles = public_bundle.publication_role_identities(
                    ci, without_native, boot_files)
                if stage == "adapter":
                    public_bundle.supervised_command_record(
                        ci, record, stage, legacy_roles, "producer_direct")
                else:
                    with self.assertRaises(ci.Refusal):
                        public_bundle.supervised_command_record(
                            ci, record, stage, legacy_roles, "producer_direct")
                    altered = copy.deepcopy(consumer_files)
                    altered[ci.WAMR_AOT_BUILD_ROLE]["sha256"] = "0" * 64
                    altered_roles = public_bundle.publication_role_identities(
                        ci, altered, boot_files)
                    with self.assertRaises(ci.Refusal):
                        public_bundle.supervised_command_record(
                            ci, record, stage, altered_roles, "producer_direct")

    def test_public_command_binding_rehash_and_stage_substitution_are_closed(self):
        record, identities = self.supervised_binding(
            "public-validator-build")
        public_bundle.supervised_command_record(
            ci, record, "public-validator-build", identities,
            "trusted_inner_zip")
        boundary = copy.deepcopy(record)
        boundary_command = boundary["supervisor"]["result"]["command"]
        boundary_request = boundary["supervisor"]["request"]
        boundary_timing = boundary_command["timing"]
        boundary_timing["primary_completed_ns"] = (
            boundary_request["primary_deadline_ns"] - 1)
        boundary_timing["completed_ns"] = (
            boundary_request["primary_deadline_ns"])
        boundary_timing["primary_elapsed_ns"] = (
            boundary_timing["primary_completed_ns"]
            - boundary_timing["started_ns"])
        boundary_timing["cleanup_elapsed_ns"] = 1
        boundary_timing["total_elapsed_ns"] = (
            boundary_timing["completed_ns"]
            - boundary_timing["started_ns"])
        public_bundle.supervised_command_record(
            ci, self.rehash_supervised_binding(boundary),
            "public-validator-build", identities, "trusted_inner_zip")
        mutations = []

        changed = copy.deepcopy(record)
        changed["supervisor"]["request"]["argv_sha256"] = "0" * 64
        mutations.append(("digest", changed))

        changed = copy.deepcopy(record)
        argv = changed["supervisor"]["request"]["argv"]
        argv[3], argv[4] = argv[4], argv[3]
        mutations.append(("argv-reorder", self.rehash_supervised_binding(
            changed)))

        changed = copy.deepcopy(record)
        changed["supervisor"]["request"]["argv"][3] = ci.command_literal(
            "test")
        mutations.append(("argument-change", self.rehash_supervised_binding(
            changed)))

        changed = copy.deepcopy(record)
        changed["supervisor"]["request"]["environment"].append({
            "name": "LD_PRELOAD",
            "value": ci.command_path("source", "attacker.so"),
        })
        changed["supervisor"]["request"]["environment"].sort(
            key=lambda item: item["name"])
        mutations.append(("environment-injection",
                          self.rehash_supervised_binding(changed)))

        changed = copy.deepcopy(record)
        del changed["supervisor"]["request"]["environment"][0]
        mutations.append(("environment-removal",
                          self.rehash_supervised_binding(changed)))

        changed = copy.deepcopy(record)
        changed["supervisor"]["request"]["cwd"] = ci.command_path("work")
        mutations.append(("cwd", self.rehash_supervised_binding(changed)))

        changed = copy.deepcopy(record)
        changed["supervisor"]["request"]["limits"]["descendants"] = 63
        mutations.append(("limit", self.rehash_supervised_binding(changed)))

        changed = copy.deepcopy(record)
        changed["supervisor"]["request"]["timeout_ns"] -= 1
        mutations.append(("timeout", self.rehash_supervised_binding(changed)))

        changed = copy.deepcopy(record)
        changed["supervisor"]["request"]["cleanup_deadline_ns"] -= 1
        mutations.append(("cleanup-deadline",
                          self.rehash_supervised_binding(changed)))

        changed = copy.deepcopy(record)
        request = changed["supervisor"]["request"]
        request["command_executable"] = copy.deepcopy(
            request["supervisor"])
        mutations.append(("executable", self.rehash_supervised_binding(
            changed)))

        changed = copy.deepcopy(record)
        changed["stage"] = "adapter"
        changed["supervisor"]["request"]["stage"] = "adapter"
        mutations.append(("stage", self.rehash_supervised_binding(changed)))

        changed = copy.deepcopy(record)
        changed["supervisor"]["result"]["command"]["cleanup"] = "deadline"
        mutations.append(("result", self.rehash_supervised_binding(changed)))

        changed = copy.deepcopy(record)
        changed["supervisor"]["result"]["command"]["descendants"][
            "identity_validated"] = 1
        mutations.append(("descendant-summary",
                          self.rehash_supervised_binding(changed)))

        changed = copy.deepcopy(record)
        changed["supervisor"]["result"]["command"]["reap_events"] = 1
        mutations.append(("reap-count",
                          self.rehash_supervised_binding(changed)))

        changed = copy.deepcopy(record)
        changed["supervisor"]["result"]["command"]["primary_events"] = (
            changed["supervisor"]["request"]["limits"]["primary_events"] + 1)
        mutations.append(("primary-count",
                          self.rehash_supervised_binding(changed)))

        changed = copy.deepcopy(record)
        changed["supervisor"]["result"]["command"]["primary_events"] = 0
        mutations.append(("zero-primary-events",
                          self.rehash_supervised_binding(changed)))

        changed = copy.deepcopy(record)
        changed["supervisor"]["result"]["command"]["cleanup_events"] = (
            ci.COMMAND_COMPLETE_CLEANUP_EVENTS_MIN - 1)
        mutations.append(("short-cleanup-events",
                          self.rehash_supervised_binding(changed)))

        changed = copy.deepcopy(record)
        changed["supervisor"]["result"]["command"]["stdout"]["sha256"] = (
            "0" * 64)
        mutations.append(("empty-stream-digest",
                          self.rehash_supervised_binding(changed)))

        changed = copy.deepcopy(record)
        changed["supervisor"]["result"]["command"]["output"][
            "commitment_sha256"] = "0" * 64
        mutations.append(("aggregate-output",
                          self.rehash_supervised_binding(changed)))

        changed = copy.deepcopy(record)
        changed["supervisor"]["result"]["command"]["timing"][
            "primary_completed_ns"] = (
                changed["supervisor"]["result"]["command"]["timing"][
                    "started_ns"] - 1)
        mutations.append(("timing-reset",
                          self.rehash_supervised_binding(changed)))

        changed = copy.deepcopy(record)
        request = changed["supervisor"]["request"]
        command = changed["supervisor"]["result"]["command"]
        timing = command["timing"]
        timing["primary_completed_ns"] = request["primary_deadline_ns"]
        timing["completed_ns"] = request["primary_deadline_ns"] + 1
        timing["primary_elapsed_ns"] = (
            timing["primary_completed_ns"] - timing["started_ns"])
        timing["cleanup_elapsed_ns"] = 1
        timing["total_elapsed_ns"] = (
            timing["completed_ns"] - timing["started_ns"])
        mutations.append(("success-at-deadline",
                          self.rehash_supervised_binding(changed)))

        changed = copy.deepcopy(record)
        request = changed["supervisor"]["request"]
        command = changed["supervisor"]["result"]["command"]
        command["primary"] = {"code": None, "kind": "timeout"}
        command["primary_deadline_reached"] = True
        command["termination"] = {"code": 15, "kind": "signal"}
        timing = command["timing"]
        timing["primary_completed_ns"] = request["primary_deadline_ns"] - 1
        timing["completed_ns"] = timing["primary_completed_ns"]
        timing["primary_elapsed_ns"] = (
            timing["primary_completed_ns"] - timing["started_ns"])
        timing["cleanup_elapsed_ns"] = 0
        timing["total_elapsed_ns"] = (
            timing["completed_ns"] - timing["started_ns"])
        mutations.append(("timeout-before-deadline",
                          self.rehash_supervised_binding(changed)))

        for stream_name, marker in (("stdout", b"o"), ("stderr", b"e")):
            changed = copy.deepcopy(record)
            request = changed["supervisor"]["request"]
            command = changed["supervisor"]["result"]["command"]
            command["primary"] = {
                "code": None, "kind": "output_overflow",
            }
            size = request["limits"][stream_name + "_bytes"] - 1
            data = marker * size
            command[stream_name] = {
                "bytes": size,
                "digest_scope": ci.command_digest_scope(size),
                "sha256": hashlib.sha256(data).hexdigest(),
                "status": "overflow",
            }
            stdout = data if stream_name == "stdout" else b""
            stderr = data if stream_name == "stderr" else b""
            command["output"] = {
                "bytes": len(stdout) + len(stderr),
                "combined_sha256":
                    hashlib.sha256(stdout + stderr).hexdigest(),
                "commitment_sha256": ci.command_output_commitment(
                    len(stdout), hashlib.sha256(stdout).hexdigest(),
                    len(stderr), hashlib.sha256(stderr).hexdigest()),
                "digest_scope":
                    ci.command_digest_scope(len(stdout) + len(stderr)),
            }
            changed["bytes"] = command["output"]["bytes"]
            changed["sha256"] = command["output"]["combined_sha256"]
            changed["sha256_scope"] = command["output"]["digest_scope"]
            mutations.append((
                stream_name + "-overflow-before-fill",
                self.rehash_supervised_binding(changed),
            ))

        changed = copy.deepcopy(record)
        changed["supervisor"]["result"]["command"][
            "cancellation_observed"] = True
        mutations.append(("incoherent-outcome",
                          self.rehash_supervised_binding(changed)))

        changed = copy.deepcopy(record)
        changed["supervisor"]["result"]["canonical_sha256"] = "0" * 64
        mutations.append(("result-canonical", changed))

        for name, changed in mutations:
            with self.subTest(name=name), self.assertRaises(ValueError):
                public_bundle.supervised_command_record(
                    ci, changed, "public-validator-build", identities,
                    "trusted_inner_zip")

        changed = copy.deepcopy(record)
        changed["supervisor"]["request"]["issued_ns"] = 10 ** 100
        with self.assertRaisesRegex(
                (ci.Refusal, ValueError), "native range"):
            self.rehash_supervised_binding(changed)

        python_record, python_identities = self.supervised_binding("fixtures")
        changed = copy.deepcopy(python_record)
        changed["supervisor"]["request"]["interpreter"] = copy.deepcopy(
            changed["supervisor"]["request"]["supervisor"])
        self.rehash_supervised_binding(changed)
        with self.assertRaises(ValueError):
            public_bundle.supervised_command_record(
                ci, changed, "fixtures", python_identities,
                "trusted_inner_zip")

    def test_public_pre_spawn_state_vectors_are_exact_and_rehashed(self):
        record, identities = self.supervised_binding(
            "public-validator-build")

        def fixture(kind):
            value = copy.deepcopy(record)
            request = value["supervisor"]["request"]
            command = value["supervisor"]["result"]["command"]
            timing = command["timing"]
            observed = (request["primary_deadline_ns"]
                        if kind == "timeout"
                        else timing["started_ns"] + 1)
            command.update({
                "cancellation_observed": kind == "cancelled",
                "cleanup": "not_required",
                "cleanup_complete": True,
                "cleanup_events": 0,
                "descendants": {
                    "adopted": 0,
                    "identity_validated": 0,
                    "limit_exceeded": False,
                    "observed": 0,
                    "untracked": False,
                },
                "executable_stable": True,
                "poisoned": False,
                "primary": {"code": None, "kind": kind},
                "primary_deadline_reached": kind == "timeout",
                "primary_events": 0,
                "reap_events": 0,
                "termination": {"code": None, "kind": None},
            })
            timing.update({
                "cleanup_elapsed_ns": 0,
                "completed_ns": observed,
                "primary_completed_ns": observed,
                "primary_elapsed_ns": observed - timing["started_ns"],
                "total_elapsed_ns": observed - timing["started_ns"],
            })
            return self.rehash_supervised_binding(value)

        def validate(value):
            request = value["supervisor"]["request"]
            command = value["supervisor"]["result"]["command"]
            return ci.validate_supervisor_state(
                command, request["limits"], command["timing"], {
                    "stdout": command["stdout"],
                    "stderr": command["stderr"],
                }, request["primary_deadline_ns"],
                "invalid supervised command binding")

        for kind in (
                "timeout", "cancelled", "local_io",
                "snapshot_unsupported"):
            with self.subTest(valid=kind):
                validate(fixture(kind))

        valid = fixture("local_io")
        mutations = []

        changed = copy.deepcopy(valid)
        command = changed["supervisor"]["result"]["command"]
        data = b"x"
        command["stdout"] = {
            "bytes": len(data),
            "digest_scope": ci.command_digest_scope(len(data)),
            "sha256": hashlib.sha256(data).hexdigest(),
            "status": "complete",
        }
        command["output"] = {
            "bytes": len(data),
            "combined_sha256": hashlib.sha256(data).hexdigest(),
            "commitment_sha256": ci.command_output_commitment(
                len(data), command["stdout"]["sha256"],
                0, ci.EMPTY_SHA256),
            "digest_scope": ci.command_digest_scope(len(data)),
        }
        changed["bytes"] = len(data)
        changed["sha256"] = command["output"]["combined_sha256"]
        changed["sha256_scope"] = command["output"]["digest_scope"]
        mutations.append(("output", self.rehash_supervised_binding(changed)))

        changed = copy.deepcopy(valid)
        changed["supervisor"]["result"]["command"]["stdout"][
            "status"] = "overflow"
        mutations.append(("overflow", self.rehash_supervised_binding(changed)))

        changed = copy.deepcopy(valid)
        changed["supervisor"]["result"]["command"]["termination"] = {
            "code": 0, "kind": "exited",
        }
        mutations.append((
            "termination", self.rehash_supervised_binding(changed)))

        changed = copy.deepcopy(valid)
        command = changed["supervisor"]["result"]["command"]
        command["primary"] = {"code": 0, "kind": "exited"}
        command["termination"] = {"code": 0, "kind": "exited"}
        mutations.append((
            "primary", self.rehash_supervised_binding(changed)))

        changed = copy.deepcopy(valid)
        changed["supervisor"]["result"]["command"][
            "executable_stable"] = False
        mutations.append((
            "executable", self.rehash_supervised_binding(changed)))

        changed = copy.deepcopy(valid)
        changed["supervisor"]["result"]["command"]["stdout"][
            "sha256"] = "0" * 64
        mutations.append((
            "empty-hash", self.rehash_supervised_binding(changed)))

        changed = copy.deepcopy(valid)
        command = changed["supervisor"]["result"]["command"]
        command["timing"]["completed_ns"] += 1
        command["timing"]["cleanup_elapsed_ns"] = 1
        command["timing"]["total_elapsed_ns"] += 1
        mutations.append((
            "cleanup-time", self.rehash_supervised_binding(changed)))

        for name, changed in mutations:
            with self.subTest(name=name), self.assertRaises(ci.Refusal):
                validate(changed)
            with self.subTest(public=name), self.assertRaises(ValueError):
                public_bundle.supervised_command_record(
                    ci, changed, "public-validator-build", identities,
                    "trusted_inner_zip")

    def test_valid_hosted_command_invariant_vectors(self):
        vectors = (
            {
                "stage": "public-validator-build",
                "primary_events": 5929, "cleanup_events": 873,
                "descendants": 0, "bytes": 0,
                "stdout_bytes": 0, "stdout_sha256": ci.EMPTY_SHA256,
                "stderr_bytes": 0, "stderr_sha256": ci.EMPTY_SHA256,
                "combined_sha256": ci.EMPTY_SHA256,
            },
            {
                "stage": "fixtures",
                "primary_events": 1043, "cleanup_events": 1280,
                "descendants": 12, "bytes": 11444,
                "stdout_bytes": 0, "stdout_sha256": ci.EMPTY_SHA256,
                "stderr_bytes": 11444,
                "stderr_sha256":
                    "78ba6ee6302bfc3ded0d6842a07e90323d38f471b5da084077aa76c7240436c0",
                "combined_sha256":
                    "78ba6ee6302bfc3ded0d6842a07e90323d38f471b5da084077aa76c7240436c0",
            },
            {
                "stage": "raw-x2apic",
                "primary_events": 236, "cleanup_events": 889,
                "descendants": 0, "bytes": 401,
                "stdout_bytes": 401,
                "stdout_sha256":
                    "56fbb15c01cbe0566c52146dafc7974bcde5993ce33ad2b76f49d98d685b7d8e",
                "stderr_bytes": 0, "stderr_sha256": ci.EMPTY_SHA256,
                "combined_sha256":
                    "56fbb15c01cbe0566c52146dafc7974bcde5993ce33ad2b76f49d98d685b7d8e",
            },
        )
        for vector in vectors:
            with self.subTest(stage=vector["stage"]):
                record, identities = self.supervised_binding(vector["stage"])
                command = record["supervisor"]["result"]["command"]
                command["primary_events"] = vector["primary_events"]
                command["cleanup_events"] = vector["cleanup_events"]
                command["descendants"].update({
                    "adopted": vector["descendants"],
                    "identity_validated": vector["descendants"],
                    "observed": vector["descendants"],
                })
                command["reap_events"] = vector["descendants"] + 2
                for name in ("stdout", "stderr"):
                    size = vector[name + "_bytes"]
                    command[name] = {
                        "bytes": size,
                        "digest_scope": ci.command_digest_scope(size),
                        "sha256": vector[name + "_sha256"],
                        "status": "complete",
                    }
                command["output"] = {
                    "bytes": vector["bytes"],
                    "combined_sha256": vector["combined_sha256"],
                    "commitment_sha256": ci.command_output_commitment(
                        vector["stdout_bytes"], vector["stdout_sha256"],
                        vector["stderr_bytes"], vector["stderr_sha256"]),
                    "digest_scope":
                        ci.command_digest_scope(vector["bytes"]),
                }
                record["bytes"] = vector["bytes"]
                record["sha256"] = vector["combined_sha256"]
                record["sha256_scope"] = ci.command_digest_scope(
                    vector["bytes"])
                self.rehash_supervised_binding(record)
                public_bundle.supervised_command_record(
                    ci, record, vector["stage"], identities,
                    "trusted_inner_zip")

    @unittest.skipIf(
        not SUPERVISOR or not SUPERVISOR_FIXTURE,
        "native command supervisor fixtures unavailable")
    def test_native_supervised_record_is_complete_and_cleanup_closed(self):
        original = ci.COMMAND_SUPERVISOR_PATH
        supervisor = Path(SUPERVISOR).resolve(strict=True)
        fixture = Path(SUPERVISOR_FIXTURE).resolve(strict=True)
        ci.COMMAND_SUPERVISOR_PATH = str(supervisor)
        try:
            output, record = ci.execute(
                self.root, "supervisor-record-fixture",
                [fixture, "ordinary-child"], 10, 1024,
                cwd=self.root)
            pid = int(output.read_text().strip())
            with self.assertRaises(ProcessLookupError):
                os.kill(pid, 0)
            command = record["supervisor"]["result"]["command"]
            self.assertGreaterEqual(command["descendants"]["observed"], 1)
            self.assertGreaterEqual(
                command["descendants"]["identity_validated"], 1)
            self.assertEqual(command["cleanup"], "complete")
            self.assertTrue(command["cleanup_complete"])
            self.assertFalse(command["poisoned"])
            self.assertFalse(record["supervisor"]["bootstrap"])
            substituted = copy.deepcopy(record)
            substituted["supervisor"] = {
                "schema": "uk.wamr.command-supervisor-result",
                "version": 1,
                "bootstrap": True,
            }
            self.assertTrue(substituted["supervisor"]["bootstrap"])
        finally:
            ci.COMMAND_SUPERVISOR_PATH = original

    def test_native_supervisor_cleans_all_ordinary_descendant_shapes(self):
        self.assertIsNotNone(SUPERVISOR)
        self.assertIsNotNone(SUPERVISOR_FIXTURE)
        original = ci.COMMAND_SUPERVISOR_PATH
        ci.COMMAND_SUPERVISOR_PATH = str(
            Path(SUPERVISOR).resolve(strict=True))
        try:
            for mode in (
                    "ordinary-child", "setsid-child", "double-fork",
                    "closed-child"):
                output, record = ci.execute(
                    self.root, "descendant-" + mode,
                    [SUPERVISOR_FIXTURE, mode], 10, 1024,
                    cwd=self.root, evidence=False)
                pid = int(output.read_text().strip())
                with self.subTest(mode=mode):
                    with self.assertRaises(ProcessLookupError):
                        os.kill(pid, 0)
                    command = record["supervisor"]["result"]["command"]
                    descendants = command["descendants"]
                    self.assertGreaterEqual(descendants["observed"], 1)
                    self.assertGreaterEqual(
                        descendants["identity_validated"], 1)
                    self.assertTrue(
                        command["cleanup_complete"])
                    self.assertEqual(
                        command["cleanup"], "complete")
        finally:
            ci.COMMAND_SUPERVISOR_PATH = original

    def test_native_supervisor_maps_primary_and_controller_failures(self):
        self.assertIsNotNone(SUPERVISOR)
        self.assertIsNotNone(SUPERVISOR_FIXTURE)
        original = ci.COMMAND_SUPERVISOR_PATH
        ci.COMMAND_SUPERVISOR_PATH = str(
            Path(SUPERVISOR).resolve(strict=True))
        cases = (
            ("native-timeout", [SUPERVISOR_FIXTURE, "partial"], 0.05, 1024,
             "timeout"),
            ("native-overflow",
             [SUPERVISOR_FIXTURE, "bytes", "4096", "0", "0"],
             10, 32, "output_overflow"),
            ("native-nonzero",
             [SUPERVISOR_FIXTURE, "bytes", "0", "0", "7"],
             10, 1024, "exited"),
        )
        try:
            for stage, args, seconds, limit, primary in cases:
                with self.subTest(stage=stage), self.assertRaises(ci.Refusal):
                    ci.execute(
                        self.root, stage, args, seconds, limit,
                        cwd=self.root)
                record = ci.document(
                    self.root / "evidence" / ("command-" + stage + ".json"))
                self.assertEqual(
                    record["supervisor"]["result"]["command"]["primary"]["kind"],
                    primary)
                self.assertTrue(
                    record["supervisor"]["result"]["command"][
                        "cleanup_complete"])
            invalid = self.root / "not-elf"
            self.put(invalid, b"#!/bin/sh\nexit 0\n")
            invalid.chmod(0o700)
            with self.assertRaisesRegex(ci.Refusal, "exec failed"):
                ci.execute(
                    self.root, "native-exec-failure", [invalid],
                    10, 1024, cwd=self.root)
            record = ci.document(
                self.root / "evidence/command-native-exec-failure.json")
            self.assertEqual(
                record["supervisor"]["result"]["controller_error"],
                "exec_unsupported")
        finally:
            ci.COMMAND_SUPERVISOR_PATH = original

    def test_native_supervisor_poison_result_tamper_identity_and_environment(self):
        self.assertIsNotNone(SUPERVISOR)
        self.assertIsNotNone(SUPERVISOR_FIXTURE)
        supervisor = Path(SUPERVISOR).resolve(strict=True)
        fixture = Path(SUPERVISOR_FIXTURE).resolve(strict=True)
        fixture_record, unused_directories = ci.physical_file_record(fixture)
        del unused_directories
        expected = ci.native_executable_identity(fixture_record)

        def invoke(argv, environment=(), limits=None):
            now = time.monotonic_ns()
            request = {
                "argv": [str(fixture), *argv],
                "cleanup_deadline_ns": now + 5_000_000_000,
                "cwd": str(self.root),
                "environment": [
                    {"name": name, "value": value}
                    for name, value in sorted(environment)
                ],
                "executable": str(fixture),
                "limits": limits or {
                    "cleanup_events": 1_000_000,
                    "descendants": 64,
                    "primary_events": 1_000_000,
                    "proc_entries_per_scan": 262_144,
                    "reap_events": 512,
                    "stderr_bytes": 4096,
                    "stdout_bytes": 4096,
                    "term_grace_ms": 1000,
                },
                "primary_deadline_ns": now + 3_000_000_000,
                "retained_executables": [],
                "schema": "uk.wamr.command-supervisor-request",
                "version": 1,
            }
            result = subprocess.run(
                [supervisor], input=ci.canonical_json(request),
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                env={}, check=False)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stderr, b"")
            return result.stdout, request

        raw, request = invoke(["environment"], (("LC_ALL", "C"),))
        decoded, stdout, stderr = ci.decoded_supervisor_result(
            raw, request, expected)
        self.assertEqual(stdout, b"environment-ok\n")
        self.assertEqual(stderr, b"")
        self.assertEqual(decoded["command"]["retained_executables"], [])
        with self.assertRaisesRegex(ci.Refusal, "invalid native command result"):
            ci.decoded_supervisor_result(raw + b" ", request, expected)
        changed = json.loads(raw)
        changed["command"]["executable"]["content_sha256"] = "0" * 64
        with self.assertRaisesRegex(ci.Refusal, "invalid native command result"):
            ci.decoded_supervisor_result(
                ci.canonical_json(changed), request, expected)
        mutations = []

        changed = json.loads(raw)
        changed["command"]["descendants"]["identity_validated"] = 1
        mutations.append(("descendants", changed))

        changed = json.loads(raw)
        changed["command"]["stderr_sha256"] = "0" * 64
        mutations.append(("zero-byte-hash", changed))

        changed = json.loads(raw)
        changed["command"]["output_sha256"] = "0" * 64
        mutations.append(("aggregate", changed))

        changed = json.loads(raw)
        changed["command"]["primary_events"] = (
            request["limits"]["primary_events"] + 1)
        mutations.append(("count", changed))

        changed = json.loads(raw)
        changed["command"]["primary_completed_ns"] = (
            changed["command"]["started_ns"] - 1)
        mutations.append(("deadline-order", changed))

        changed = json.loads(raw)
        changed["command"]["termination"] = {
            "code": 15, "kind": "signal",
        }
        mutations.append(("outcome", changed))

        changed = json.loads(raw)
        changed["command"]["primary"] = {"code": 256, "kind": "exited"}
        changed["command"]["termination"] = {"code": 256, "kind": "exited"}
        mutations.append(("exit-domain", changed))

        changed = json.loads(raw)
        changed["command"]["primary"] = {"code": 0, "kind": "signal"}
        changed["command"]["termination"] = {"code": 0, "kind": "signal"}
        mutations.append(("signal-domain", changed))

        for name, changed in mutations:
            with self.subTest(name=name), self.assertRaisesRegex(
                    ci.Refusal, "invalid native command result"):
                ci.decoded_supervisor_result(
                    ci.canonical_json(changed), request, expected)

        limits = {
            "cleanup_events": 32,
            "descendants": 64,
            "primary_events": 1_000_000,
            "proc_entries_per_scan": 16,
            "reap_events": 512,
            "stderr_bytes": 4096,
            "stdout_bytes": 4096,
            "term_grace_ms": 1000,
        }
        poisoned_raw, poisoned_request = invoke(
            ["many-immediate", "32"], limits=limits)
        poisoned, unused_stdout, unused_stderr = (
            ci.decoded_supervisor_result(
                poisoned_raw, poisoned_request, expected))
        del unused_stdout, unused_stderr
        command = poisoned["command"]
        self.assertFalse(command["cleanup_complete"])
        self.assertTrue(command["poisoned"])
        self.assertNotEqual(command["cleanup"], "complete")

    @unittest.skipIf(
        not SUPERVISOR or not SUPERVISOR_FIXTURE,
        "native command supervisor fixtures unavailable")
    def test_native_supervisor_state_machine_boundaries_and_rehashed_mutations(self):
        supervisor = Path(SUPERVISOR).resolve(strict=True)
        fixture = Path(SUPERVISOR_FIXTURE).resolve(strict=True)
        fixture_record, unused_directories = ci.physical_file_record(fixture)
        del unused_directories
        expected = ci.native_executable_identity(fixture_record)

        def invoke(argv, primary_ms=3000, stream_limit=32):
            now = time.monotonic_ns()
            request = {
                "argv": [str(fixture), *argv],
                "cleanup_deadline_ns": now + 5_000_000_000,
                "cwd": str(self.root),
                "environment": [],
                "executable": str(fixture),
                "limits": {
                    "cleanup_events": 1_000_000,
                    "descendants": 64,
                    "primary_events": 1_000_000,
                    "proc_entries_per_scan": 262_144,
                    "reap_events": 512,
                    "stderr_bytes": stream_limit,
                    "stdout_bytes": stream_limit,
                    "term_grace_ms": 1000,
                },
                "primary_deadline_ns": now + primary_ms * 1_000_000,
                "retained_executables": [],
                "schema": "uk.wamr.command-supervisor-request",
                "version": 1,
            }
            result = subprocess.run(
                [supervisor], input=ci.canonical_json(request),
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                env={}, check=False)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stderr, b"")
            return result.stdout, request

        fast_raw, fast_request = invoke(["bytes", "0", "0", "0"])
        fast, unused_stdout, unused_stderr = ci.decoded_supervisor_result(
            fast_raw, fast_request, expected)
        del unused_stdout, unused_stderr
        self.assertGreaterEqual(
            fast["command"]["primary_events"],
            ci.COMMAND_COMPLETE_PRIMARY_EVENTS_MIN)
        self.assertGreaterEqual(
            fast["command"]["cleanup_events"],
            ci.COMMAND_COMPLETE_CLEANUP_EVENTS_MIN)
        boundary = copy.deepcopy(fast)
        boundary["command"]["primary_events"] = (
            ci.COMMAND_COMPLETE_PRIMARY_EVENTS_MIN)
        boundary["command"]["cleanup_events"] = (
            ci.COMMAND_COMPLETE_CLEANUP_EVENTS_MIN)
        ci.decoded_supervisor_result(
            ci.canonical_json(boundary), fast_request, expected)
        early_raw, early_request = invoke(
            ["bytes", "0", "0", "0"], primary_ms=-1)
        early, unused_stdout, unused_stderr = ci.decoded_supervisor_result(
            early_raw, early_request, expected)
        del unused_stdout, unused_stderr
        early_command = early["command"]
        self.assertEqual(early_command["cleanup"], "not_required")
        self.assertEqual(early_command["primary_events"], 0)
        self.assertEqual(early_command["cleanup_events"], 0)
        self.assertEqual(early_command["reap_events"], 0)
        self.assertEqual(early_command["stdout_bytes"], 0)
        self.assertEqual(early_command["stderr_bytes"], 0)
        self.assertEqual(early_command["stdout_status"], "complete")
        self.assertEqual(early_command["stderr_status"], "complete")
        self.assertEqual(early_command["stdout_sha256"], ci.EMPTY_SHA256)
        self.assertEqual(early_command["stderr_sha256"], ci.EMPTY_SHA256)
        self.assertEqual(
            early_command["output_sha256"],
            ci.command_output_commitment(
                0, ci.EMPTY_SHA256, 0, ci.EMPTY_SHA256))
        self.assertEqual(
            early_command["termination"], {"code": None, "kind": None})
        self.assertTrue(early_command["executable_stable"])
        self.assertEqual(
            early_command["primary_completed_ns"],
            early_command["completed_ns"])

        def pre_spawn_fixture(kind):
            value = copy.deepcopy(early)
            request = copy.deepcopy(early_request)
            command = value["command"]
            started = command["started_ns"]
            request["primary_deadline_ns"] = started + 1000
            request["cleanup_deadline_ns"] = started + 2000
            if kind == "timeout":
                observed = request["primary_deadline_ns"]
            else:
                observed = started + 1
            command.update({
                "cancellation_observed": kind == "cancelled",
                "completed_ns": observed,
                "primary": {"code": None, "kind": kind},
                "primary_completed_ns": observed,
                "primary_deadline_reached": kind == "timeout",
            })
            request_raw = ci.validate_supervisor_request(request)
            value["request_bytes"] = len(request_raw)
            value["request_sha256"] = hashlib.sha256(
                request_raw).hexdigest()
            return value, request

        for kind in (
                "timeout", "cancelled", "local_io",
                "snapshot_unsupported"):
            value, request = pre_spawn_fixture(kind)
            with self.subTest(valid_pre_spawn=kind):
                ci.decoded_supervisor_result(
                    ci.canonical_json(value), request, expected)

        def leader_tracking_fixture(offset):
            value = copy.deepcopy(early)
            request = copy.deepcopy(early_request)
            command = value["command"]
            started = command["started_ns"]
            request["primary_deadline_ns"] = started + 1000
            request["cleanup_deadline_ns"] = started + 2000
            observed = request["primary_deadline_ns"] + offset
            command.update({
                "cancellation_observed": False,
                "cleanup": "complete",
                "cleanup_complete": True,
                "cleanup_events":
                    ci.COMMAND_PRE_RELEASE_CLEANUP_EVENTS_MIN,
                "completed_ns": observed + 1,
                "poisoned": False,
                "primary": {
                    "code": None,
                    "kind": "local_io" if offset < 0 else "timeout",
                },
                "primary_completed_ns": observed,
                "primary_deadline_reached": offset >= 0,
                "primary_events": 0,
                "reap_events": 2,
                "stderr_status": "complete",
                "stdout_status": "complete",
                "termination": {"code": 9, "kind": "signal"},
            })
            request_raw = ci.validate_supervisor_request(request)
            value["request_bytes"] = len(request_raw)
            value["request_sha256"] = hashlib.sha256(
                request_raw).hexdigest()
            return value, request

        self.assertEqual(ci.COMMAND_PRE_RELEASE_CLEANUP_EVENTS_MIN, 4)
        for offset in (-1, 0, 1):
            value, request = leader_tracking_fixture(offset)
            with self.subTest(leader_tracking_offset=offset):
                decoded, stdout, stderr = ci.decoded_supervisor_result(
                    ci.canonical_json(value), request, expected)
                command = decoded["command"]
                self.assertEqual(stdout, b"")
                self.assertEqual(stderr, b"")
                self.assertEqual(command["cleanup"], "complete")
                self.assertTrue(command["cleanup_complete"])
                self.assertFalse(command["poisoned"])
                self.assertEqual(command["reap_events"], 2)
                self.assertEqual(
                    command["termination"],
                    {"code": 9, "kind": "signal"})
                self.assertEqual(
                    command["primary"]["kind"],
                    "local_io" if offset < 0 else "timeout")
                self.assertEqual(
                    command["primary_completed_ns"],
                    request["primary_deadline_ns"] + offset)

        equality, equality_request = leader_tracking_fixture(0)
        equality["command"]["primary"] = {
            "code": None, "kind": "local_io",
        }
        equality["command"]["primary_deadline_reached"] = False
        with self.assertRaisesRegex(
                ci.Refusal, "invalid native command result"):
            ci.decoded_supervisor_result(
                ci.canonical_json(equality), equality_request, expected)

        before, before_request = leader_tracking_fixture(-1)
        before["command"]["primary"] = {
            "code": None, "kind": "timeout",
        }
        before["command"]["primary_deadline_reached"] = True
        with self.assertRaisesRegex(
                ci.Refusal, "invalid native command result"):
            ci.decoded_supervisor_result(
                ci.canonical_json(before), before_request, expected)

        incomplete_gate, incomplete_gate_request = (
            leader_tracking_fixture(-1))
        incomplete_gate["command"]["cleanup_events"] = (
            ci.COMMAND_PRE_RELEASE_CLEANUP_EVENTS_MIN - 1)
        with self.assertRaisesRegex(
                ci.Refusal, "invalid native command result"):
            ci.decoded_supervisor_result(
                ci.canonical_json(incomplete_gate),
                incomplete_gate_request, expected)

        exact_negatives = []
        valid, valid_request = pre_spawn_fixture("local_io")

        changed = copy.deepcopy(valid)
        command = changed["command"]
        raw_stdout = b"x"
        command["stdout_base64"] = base64.b64encode(
            raw_stdout).decode("ascii")
        command["stdout_bytes"] = len(raw_stdout)
        command["stdout_sha256"] = hashlib.sha256(raw_stdout).hexdigest()
        command["output_sha256"] = ci.command_output_commitment(
            len(raw_stdout), command["stdout_sha256"],
            0, ci.EMPTY_SHA256)
        exact_negatives.append(("not-required-output", changed))

        changed = copy.deepcopy(valid)
        changed["command"]["stdout_status"] = "overflow"
        exact_negatives.append(("not-required-overflow", changed))

        for kind, code in (
                ("exited", 0), ("signal", 15), ("unknown", 0)):
            changed = copy.deepcopy(valid)
            changed["command"]["primary"] = {
                "code": code, "kind": kind,
            }
            changed["command"]["termination"] = {
                "code": code, "kind": kind,
            }
            exact_negatives.append(("not-required-" + kind, changed))

        for kind in (
                "output_overflow", "exec_failed", "event_limit",
                "executable_changed"):
            changed = copy.deepcopy(valid)
            changed["command"]["primary"] = {
                "code": None, "kind": kind,
            }
            if kind == "event_limit":
                changed["command"]["primary_events"] = (
                    valid_request["limits"]["primary_events"])
            if kind == "executable_changed":
                changed["command"]["executable_stable"] = False
                changed["command"]["termination"] = {
                    "code": 0, "kind": "exited",
                }
            exact_negatives.append(("not-required-" + kind, changed))

        changed = copy.deepcopy(valid)
        changed["command"]["termination"] = {
            "code": 0, "kind": "exited",
        }
        exact_negatives.append(("not-required-termination", changed))

        changed = copy.deepcopy(valid)
        changed["command"]["executable_stable"] = False
        exact_negatives.append(("not-required-mutated-executable", changed))

        changed = copy.deepcopy(valid)
        changed["command"]["stdout_sha256"] = "0" * 64
        changed["command"]["output_sha256"] = ci.command_output_commitment(
            0, "0" * 64, 0, ci.EMPTY_SHA256)
        exact_negatives.append(("not-required-empty-hash", changed))

        changed = copy.deepcopy(valid)
        changed["command"]["completed_ns"] += 1
        exact_negatives.append(("not-required-cleanup-time", changed))

        for name, changed in exact_negatives:
            with self.subTest(name=name), self.assertRaisesRegex(
                    ci.Refusal, "invalid native command result"):
                ci.decoded_supervisor_result(
                    ci.canonical_json(changed),
                    valid_request, expected)

        for name, fields in (
                ("zero-events", {
                    "primary_events": 0,
                    "cleanup_events": 0,
                }),
                ("short-cleanup", {
                    "cleanup_events":
                        ci.COMMAND_COMPLETE_CLEANUP_EVENTS_MIN - 1,
                })):
            changed = copy.deepcopy(fast)
            changed["command"].update(fields)
            with self.subTest(name=name), self.assertRaisesRegex(
                    ci.Refusal, "invalid native command result"):
                ci.decoded_supervisor_result(
                    ci.canonical_json(changed), fast_request, expected)

        # This case needs a released child, not a deadline exhausted while
        # hashing its executable on a CPU without hardware SHA acceleration.
        timeout_raw, timeout_request = invoke(["partial"], stream_limit=128)
        timeout, timeout_stdout, timeout_stderr = (
            ci.decoded_supervisor_result(
                timeout_raw, timeout_request, expected))
        self.assertEqual(
            timeout_stdout, b"private-stdout?sig=synthetic-secret\n")
        self.assertEqual(
            timeout_stderr, b"private-stderr?sig=synthetic-secret\n")
        self.assertEqual(timeout["command"]["cleanup"], "complete")
        self.assertTrue(timeout["command"]["cleanup_complete"])
        self.assertEqual(timeout["command"]["termination"]["kind"], "signal")
        self.assertEqual(
            timeout["command"]["primary"],
            {"code": None, "kind": "timeout"})
        self.assertGreaterEqual(
            timeout["command"]["primary_completed_ns"],
            timeout_request["primary_deadline_ns"])
        equality = copy.deepcopy(timeout)
        equality["command"]["primary_completed_ns"] = (
            timeout_request["primary_deadline_ns"])
        ci.decoded_supervisor_result(
            ci.canonical_json(equality), timeout_request, expected)
        before = copy.deepcopy(equality)
        before["command"]["primary_completed_ns"] -= 1
        with self.assertRaisesRegex(
                ci.Refusal, "invalid native command result"):
            ci.decoded_supervisor_result(
                ci.canonical_json(before), timeout_request, expected)

        def truncate_stream(value, stream_name):
            command = value["command"]
            raw = base64.b64decode(
                command[stream_name + "_base64"], validate=True)[:-1]
            command[stream_name + "_base64"] = (
                base64.b64encode(raw).decode("ascii"))
            command[stream_name + "_bytes"] = len(raw)
            command[stream_name + "_sha256"] = (
                hashlib.sha256(raw).hexdigest())
            stdout = base64.b64decode(
                command["stdout_base64"], validate=True)
            stderr = base64.b64decode(
                command["stderr_base64"], validate=True)
            command["output_sha256"] = ci.command_output_commitment(
                len(stdout), hashlib.sha256(stdout).hexdigest(),
                len(stderr), hashlib.sha256(stderr).hexdigest())

        overflow_cases = (
            ("stdout", ["bytes", "33", "5", "0"], "stdout"),
            ("stderr", ["bytes", "5", "33", "0"], "stderr"),
            ("combined", ["bytes", "33", "33", "0"], "stderr"),
        )
        for name, argv, mutated_stream in overflow_cases:
            raw, request = invoke(argv)
            decoded, stdout, stderr = ci.decoded_supervisor_result(
                raw, request, expected)
            command = decoded["command"]
            with self.subTest(name=name):
                self.assertEqual(
                    command["primary"],
                    {"code": None, "kind": "output_overflow"})
                for stream_name, captured in (
                        ("stdout", stdout), ("stderr", stderr)):
                    if command[stream_name + "_status"] == "overflow":
                        self.assertEqual(
                            len(captured),
                            request["limits"][stream_name + "_bytes"])
                if name == "stdout":
                    self.assertLess(
                        len(stderr), request["limits"]["stderr_bytes"])
                elif name == "stderr":
                    self.assertLess(
                        len(stdout), request["limits"]["stdout_bytes"])
                else:
                    self.assertEqual(command["stdout_status"], "overflow")
                    self.assertEqual(command["stderr_status"], "overflow")
                changed = copy.deepcopy(decoded)
                truncate_stream(changed, mutated_stream)
                with self.assertRaisesRegex(
                        ci.Refusal, "invalid native command result"):
                    ci.decoded_supervisor_result(
                        ci.canonical_json(changed), request, expected)

    @unittest.skipIf(
        not SUPERVISOR or not SUPERVISOR_FIXTURE,
        "native command supervisor fixtures unavailable")
    def test_python_native_canonical_unicode_vectors_and_byte_limits(self):
        supervisor = Path(SUPERVISOR).resolve(strict=True)
        fixture = Path(SUPERVISOR_FIXTURE).resolve(strict=True)
        fixture_record, unused_directories = ci.physical_file_record(fixture)
        del unused_directories
        expected = ci.native_executable_identity(fixture_record)
        nfc = self.root / "unicode-\u00e9-\U0001f600"
        nfd = self.root / "unicode-e\u0301-\U0001f600"
        nfc.mkdir(mode=0o700)
        nfd.mkdir(mode=0o700)

        def request(cwd, marker):
            now = time.monotonic_ns()
            return {
                "argv": [
                    str(fixture), "environment",
                    "\u03bb-" + marker, "\U0001f600",
                ],
                "cleanup_deadline_ns": now + 5_000_000_000,
                "cwd": str(cwd),
                "environment": [
                    {"name": "LC_ALL", "value": "C"},
                    {"name": "UNICODE_\u00c4",
                     "value": "BMP-\u03bb-NONBMP-\U0001f600-" + marker},
                ],
                "executable": str(fixture),
                "limits": {
                    "cleanup_events": 1_000_000,
                    "descendants": 64,
                    "primary_events": 1_000_000,
                    "proc_entries_per_scan": 262_144,
                    "reap_events": 512,
                    "stderr_bytes": 4096,
                    "stdout_bytes": 4096,
                    "term_grace_ms": 1000,
                },
                "primary_deadline_ns": now + 3_000_000_000,
                "retained_executables": [],
                "schema": "uk.wamr.command-supervisor-request",
                "version": 1,
            }

        def invoke(value, raw=None):
            encoded = ci.validate_supervisor_request(value) if raw is None else raw
            result = subprocess.run(
                [supervisor], input=encoded, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, env={}, check=False)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stderr, b"")
            return result.stdout, encoded

        nfc_request = request(nfc, "\u00e9")
        nfd_request = request(nfd, "e\u0301")
        nfc_raw = ci.validate_supervisor_request(nfc_request)
        nfd_raw = ci.validate_supervisor_request(nfd_request)
        self.assertIn("\u00e9".encode(), nfc_raw)
        self.assertIn("e\u0301".encode(), nfd_raw)
        self.assertNotEqual(nfc_raw, nfd_raw)
        self.assertNotEqual(
            hashlib.sha256(nfc_raw).hexdigest(),
            hashlib.sha256(nfd_raw).hexdigest())

        for name, value in (("nfc", nfc_request), ("nfd", nfd_request)):
            with self.subTest(vector=name):
                raw, request_raw = invoke(value)
                decoded, stdout, stderr = ci.decoded_supervisor_result(
                    raw, value, expected)
                self.assertEqual(stdout, b"environment-ok\n")
                self.assertEqual(stderr, b"")
                self.assertEqual(
                    decoded["request_sha256"],
                    hashlib.sha256(request_raw).hexdigest())

        escaped = (
            json.dumps(
                nfc_request, ensure_ascii=True, sort_keys=True,
                separators=(",", ":")) + "\n"
        ).encode("ascii")
        self.assertNotEqual(escaped, nfc_raw)
        escaped_result, unused = invoke(nfc_request, escaped)
        del unused
        escaped_value = json.loads(escaped_result)
        self.assertEqual(escaped_value["controller_error"],
                         "noncanonical_request")
        self.assertIsNone(escaped_value["request_sha256"])

        invalid_surrogate = copy.deepcopy(nfc_request)
        invalid_surrogate["argv"].append("\ud800")
        with self.assertRaisesRegex(ci.Refusal, "valid Unicode"):
            ci.canonical_json(invalid_surrogate)
        surrogate_raw = (
            json.dumps(
                invalid_surrogate, ensure_ascii=True, sort_keys=True,
                separators=(",", ":")) + "\n"
        ).encode("ascii")
        surrogate_result, unused = invoke(nfc_request, surrogate_raw)
        del unused
        self.assertEqual(
            json.loads(surrogate_result)["controller_error"],
            "invalid_request")
        non_utf8_result, unused = invoke(nfc_request, b"\xff\n")
        del unused
        self.assertEqual(
            json.loads(non_utf8_result)["controller_error"],
            "invalid_request")

        boundary = copy.deepcopy(nfc_request)
        boundary["cwd"] = "/" + "\u00e9" * 2047 + "a"
        self.assertEqual(
            len(boundary["cwd"].encode("utf-8")), ci.COMMAND_STRING_MAX)
        boundary_result, unused = invoke(boundary)
        del unused
        self.assertEqual(
            json.loads(boundary_result)["controller_error"],
            "cwd_unavailable")
        excess = copy.deepcopy(boundary)
        excess["cwd"] += "a"
        self.assertEqual(
            len(excess["cwd"].encode("utf-8")),
            ci.COMMAND_STRING_MAX + 1)
        with self.assertRaisesRegex(
                ci.Refusal, "invalid native command request"):
            ci.validate_supervisor_request(excess)
        excess_result, unused = invoke(
            nfc_request, ci.canonical_json(excess))
        del unused
        self.assertEqual(
            json.loads(excess_result)["controller_error"],
            "invalid_request")

    def test_native_schema_integer_boundaries_refuse_first_excess(self):
        identity = {
            "content_sha256": "0" * 64,
            "ctime_nanoseconds": 999_999_999,
            "ctime_seconds": -(1 << 63),
            "device_major": (1 << 32) - 1,
            "device_minor": (1 << 32) - 1,
            "inode": (1 << 64) - 1,
            "mode": (1 << 16) - 1,
            "mtime_nanoseconds": 999_999_999,
            "mtime_seconds": (1 << 63) - 1,
            "size": (1 << 64) - 1,
            "uid": (1 << 32) - 1,
        }
        self.assertEqual(
            ci.validate_native_executable_identity(
                identity, "invalid identity"),
            identity)
        for field, value in (
                ("ctime_nanoseconds", 1 << 32),
                ("ctime_seconds", 1 << 63),
                ("device_major", 1 << 32),
                ("inode", 1 << 64),
                ("mode", 1 << 16),
                ("uid", 1 << 32)):
            changed = copy.deepcopy(identity)
            changed[field] = value
            with self.subTest(field=field), self.assertRaises(ci.Refusal):
                ci.validate_native_executable_identity(
                    changed, "invalid identity")
        with self.assertRaisesRegex(ci.Refusal, "native range"):
            ci.canonical_json({"huge": 10 ** 100})
        maximum_limits = {
            "cleanup_events": 10_000_000,
            "descendants": 256,
            "primary_events": 10_000_000,
            "proc_entries_per_scan": 1_000_000,
            "reap_events": 1024,
            "stderr_bytes": ci.COMMAND_STREAM_MAX,
            "stdout_bytes": ci.COMMAND_STREAM_MAX,
            "term_grace_ms": 10_000,
        }
        self.assertEqual(
            ci.validate_supervisor_limits(maximum_limits, "invalid limits"),
            maximum_limits)
        for field, value in (
                ("cleanup_events", 10_000_001),
                ("descendants", 257),
                ("primary_events", 10_000_001),
                ("proc_entries_per_scan", 1_000_001),
                ("reap_events", 1025),
                ("stderr_bytes", ci.COMMAND_STREAM_MAX + 1),
                ("stdout_bytes", ci.COMMAND_STREAM_MAX + 1),
                ("term_grace_ms", 10_001)):
            changed = copy.deepcopy(maximum_limits)
            changed[field] = value
            with self.subTest(limit=field), self.assertRaises(ci.Refusal):
                ci.validate_supervisor_limits(changed, "invalid limits")
        minimum_limits = {
            "cleanup_events": 32,
            "descendants": 1,
            "primary_events": 16,
            "proc_entries_per_scan": 16,
            "reap_events": 4,
            "stderr_bytes": 1,
            "stdout_bytes": 1,
            "term_grace_ms": 1,
        }
        self.assertEqual(
            ci.validate_supervisor_limits(minimum_limits, "invalid limits"),
            minimum_limits)
        for field, value in (
                ("cleanup_events", 31),
                ("descendants", 0),
                ("primary_events", 15),
                ("proc_entries_per_scan", 15),
                ("reap_events", 3),
                ("stderr_bytes", 0),
                ("stdout_bytes", 0),
                ("term_grace_ms", 0)):
            changed = copy.deepcopy(minimum_limits)
            changed[field] = value
            with self.subTest(minimum=field), self.assertRaises(ci.Refusal):
                ci.validate_supervisor_limits(changed, "invalid limits")

    def test_execute_drops_ambient_loader_shell_python_and_make_injection(self):
        root = self.root / "closed-command-environment"
        (root / "private").mkdir(parents=True, mode=0o700)
        injected = root / "injected"
        self.put(injected, b"printf injected\n")
        names = (
            "BASH_ENV", "ENV", "LD_AUDIT", "LD_LIBRARY_PATH", "LD_PRELOAD",
            "MAKEFILES", "PYTHONHOME", "PYTHONPATH", "ZIG_LIB_DIR",
        )
        script = (
            "import json,os\n"
            f"print(json.dumps(sorted(set(os.environ) & set({names!r}))))\n"
        )
        ambient = {name: str(injected) for name in names}
        with mock.patch.dict(os.environ, ambient, clear=False):
            output, unused_record = ci.execute(
                root, "closed-environment",
                [PYTHON, "-c", script],
                evidence=False,
                input_records=None,
            )
        del unused_record
        self.assertEqual(output.read_bytes(), b"[]\n")

    def test_source_root_inventory_refuses_the_129th_entry(self):
        repository = self.root / "root-inventory"
        repository.mkdir(mode=0o700)
        for index in range(129):
            self.put(repository / f"entry-{index:03d}", b"")
        with self.assertRaisesRegex(ci.Refusal, "root inventory too large"):
            ci.source_root_inventory(repository)

    def test_precreated_output_roots_keep_source_parent_metadata_exact(self):
        for stage, subcommand in (
                ("config", "olddefconfig"),
                ("native-image", "native-images")):
            contract = ci.production_command_contract(stage)
            self.assertEqual(
                contract["argv"],
                [
                    ci.command_path(ci.WAMR_AOT_BUILD_ROLE),
                    ci.command_literal(subcommand),
                    ci.command_literal("--repository"),
                    ci.command_path("source"),
                ],
            )
            self.assertIsNone(contract["interpreter"])
        repository = self.root / "repository"
        app = repository / "support/apps/wamr-aot"
        app.mkdir(parents=True, mode=0o700)
        self.put(app / "defconfig", b"CONFIG_FIXTURE=y\n")
        (repository / ".d").mkdir(mode=0o700)
        cache = repository / ".zig-cache"
        with mock.patch.object(ci, "APP", app), \
                mock.patch.object(ci, "REPO", repository):
            self.put(app / ".config.old", b"stale\n")
            with self.assertRaisesRegex(ci.Refusal, "fresh precreated"):
                ci.prepare_source_outputs()
            (app / ".config.old").unlink()
            cache.mkdir(mode=0o700)
            with self.assertRaisesRegex(ci.Refusal, "fresh precreated"):
                ci.prepare_source_outputs()
            cache.rmdir()
            ci.prepare_source_outputs()
            self.assertTrue(cache.is_dir())
            self.assertEqual(stat.S_IMODE(cache.stat().st_mode), 0o700)
            root_before = ci.snapshot(repository.lstat())
            before = ci.snapshot(app.lstat())
            ci.require_no_config_backup()
            self.put(app / "build/.config",
                     b"CONFIG_FIXTURE=y\nCONFIG_SOLVED=y\n")
            self.assertEqual(ci.snapshot(app.lstat()), before)
            self.put(cache / "child-cache-entry", b"cache\n")
            self.assertEqual(ci.snapshot(repository.lstat()), root_before)
            ci.retain_solved_config()
            self.assertEqual(ci.snapshot(app.lstat()), before)
            self.assertEqual(
                (app / ".config").read_bytes(),
                b"CONFIG_FIXTURE=y\nCONFIG_SOLVED=y\n",
            )
            self.assertEqual(
                ci.solved_config(),
                hashlib.sha256(
                    b"CONFIG_FIXTURE=y\nCONFIG_SOLVED=y\n").hexdigest(),
            )
            self.put(app / ".config.old", b"unexpected\n")
            with self.assertRaisesRegex(ci.Refusal, "configuration backup"):
                ci.require_no_config_backup()
            (app / ".config.old").unlink()
            self.put(app / "build/.config", b"CONFIG_CHANGED=y\n")
            with self.assertRaisesRegex(ci.Refusal, "build configuration changed"):
                ci.solved_config()

    def synthetic_boot(self, raw=None):
        config = ci.config_for(self.root, self.root, 0)
        self.put(self.root / "private/identity.json",
                 json.dumps(self.contract.identity).encode())
        for name in ("package/unikraft.raw", "firmware/code.fd",
                     "firmware/vars.fd", "bin/qemu-system-x86_64"):
            self.put(self.root / name, b"explicitly synthetic, never native boot evidence")
        work = Path(config["work_dir"])
        work.mkdir(mode=0o700)
        paths = [config["source"]["path"], config["ovmf_code"],
                 config["ovmf_vars"], config["qemu"]]
        ci.save(work / "request.json", {
            "schema_version": 2, "supervisor_pid": 123, "config": config,
            "pins": [
                ci.pin_from_record(ci.physical_file_record(Path(p))[0])
                for p in paths
            ],
        })
        if raw is None:
            raw = self.contract.log()
        self.put(work / "hyperv-efi-boot.log", raw)
        self.put(work / "launched", b"")
        ci.save(work / "report.json", {
            "schema_version": 1, "scope": "public_local_qemu_only",
            "acceptance": "not_established", "passed": True, "consumed": True,
            "cleanup_complete": True, "input_unchanged": True, "serial_valid": True,
            "serial_limit_reached": False, "serial_bytes": len(raw),
            "serial_sha256": hashlib.sha256(raw).hexdigest(),
            "termination": {"exited": 0},
            "failures": {"primary": None, "cleanup": None, "recording": None},
        })
        return config

    def test_console_normalization_preserves_raw_hash_binding(self):
        original = self.contract.log()
        raw = original.replace(b"\n", b"\x1b[0m\0\r\n\0")
        config = self.synthetic_boot(raw)
        observed = self.check_fixture_boot(config, self.contract.identity)
        raw_hash = hashlib.sha256(raw).hexdigest()
        normalized_hash = hashlib.sha256(original).hexdigest()
        self.assertNotEqual(raw_hash, normalized_hash)
        self.assertEqual(observed["report"]["serial_sha256"], raw_hash)
        self.assertEqual(observed["compute"], self.contract.result)
        report_path = Path(config["work_dir"]) / "report.json"
        report = ci.document(report_path)
        report["serial_sha256"] = normalized_hash
        self.put(report_path, json.dumps(report).encode())
        with self.assertRaises(ValueError):
            self.check_fixture_boot(config, self.contract.identity)

    def test_physical_request_log_and_report_bindings(self):
        config = self.synthetic_boot()
        identity = self.contract.identity
        observed = self.check_fixture_boot(config, identity)
        self.assertEqual(observed["compute"], self.contract.result)
        changed = dict(config, disable_x2apic=True)
        with self.assertRaises(ValueError):
            self.check_fixture_boot(changed, identity)
        work = Path(config["work_dir"])
        original = (work / "hyperv-efi-boot.log").read_bytes()
        self.put(work / "hyperv-efi-boot.log", original + b"changed")
        with self.assertRaises(ValueError):
            self.check_fixture_boot(config, identity)
        self.put(work / "hyperv-efi-boot.log", original)
        self.put(Path(config["source"]["path"]), b"different package")
        with self.assertRaises(ValueError):
            self.check_fixture_boot(config, identity)

    def test_failed_native_report_never_becomes_compute_result(self):
        config = self.synthetic_boot()
        report_path = Path(config["work_dir"]) / "report.json"
        saved = ci.document(report_path)
        for key, value in (("cleanup_complete", False), ("passed", False),
                           ("serial_limit_reached", True), ("termination", {"exited": 1})):
            report = dict(saved, **{key: value})
            self.put(report_path, json.dumps(report).encode())
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.check_fixture_boot(config, self.contract.identity)

    def test_bounded_failure_capture_and_timeout(self):
        for stage, source, seconds, limit in (
                ("failed", "raise SystemExit(3)", 10, 1024),
                ("overflow", "print('x' * 4096)", 10, 32),
                ("timeout", "import time; time.sleep(20)", 1, 1024)):
            with self.subTest(stage=stage), self.assertRaises(ValueError):
                ci.run(self.root, stage, [PYTHON, "-c", source], seconds, limit)
            record = ci.document(self.root / "evidence" / ("command-" + stage + ".json"))
            self.assertLessEqual(record["bytes"], limit + 1)
            self.assertEqual(record["scope"], "command_diagnostic_not_acceptance")
        self.assertFalse((self.root / "evidence/result.json").exists())

    def test_redaction_never_copies_arbitrary_serial_or_error_state(self):
        runtime = self.root
        root = runtime / "compute"
        root.mkdir(mode=0o700)
        (root / "evidence").mkdir(mode=0o700)
        (root / "private").mkdir(mode=0o700)
        work = root / "boot-raw-x2apic"
        work.mkdir(mode=0o700)
        self.put(work / "hyperv-efi-boot.log", b"PRIVATE_SYNTHETIC_STATE")
        self.put(root / "private/fixtures.log", (
            b"test_safe_name (test_adapter.Evidence.test_safe_name) ... ERROR\n"
            b"PRIVATE_SYNTHETIC_STATE\n"
        ))
        ci.save(root / "evidence/command-fixtures.json", {
            "exit_code": 1,
        })
        ci.save(root / "evidence/command-config.json", {
            "exit_code": 2,
        })
        app = self.root / "synthetic-app"
        backend = app / "build/native-environment/diagnostics/image-42"
        backend.mkdir(parents=True, mode=0o700)
        for directory in (app / "build", app / "build/native-environment",
                          backend.parent):
            directory.chmod(0o700)
        self.put(backend.parent.parent / "failure-error-name.txt",
                 b"InvalidToolOverride")
        self.put(backend.parent.parent / "failure-tool-role.txt", b"make")
        ci.save(backend / "000-root-olddefconfig.json", {
            "stage": "root-olddefconfig",
            "primary": {"exited": 1},
        })
        self.put(backend / "000-root-olddefconfig.stderr",
                 b"error: InvalidNativeMakePath\nPRIVATE_SYNTHETIC_STATE\n")
        ci.save(work / "report.json", {
            "passed": False, "cleanup_complete": True, "input_unchanged": True,
            "serial_valid": False, "serial_limit_reached": False,
            "failures": {"primary": {"arbitrary": "PRIVATE_SYNTHETIC_STATE"},
                         "cleanup": None, "recording": None},
        })
        with mock.patch.object(ci, "APP", app):
            ci.diagnostics(runtime)
        raw = (root / "evidence/diagnostics.json").read_bytes()
        self.assertNotIn(b"PRIVATE_SYNTHETIC_STATE", raw)
        self.assertNotIn(b"InvalidToolOverride", raw)
        self.assertNotIn(b'"make"', raw)
        self.assertNotIn(str(self.root).encode(), raw)
        self.assertIn(
            b"test_adapter.Evidence.test_safe_name", raw)
        self.assertEqual(json.loads(raw)["build_failures"]["config"], {
            "exit_code": 2, "backend_exit_code": 1,
            "native_error_name_sha256":
                hashlib.sha256(b"InvalidToolOverride").hexdigest(),
            "tool_role_sha256": hashlib.sha256(b"make").hexdigest(),
            "known_error_markers": ["InvalidNativeMakePath"],
        })
        self.assertFalse((root / "evidence/result.json").exists())

    def test_native_config_failure_digest_without_child_launch(self):
        runtime = self.root
        root = runtime / "compute"
        root.mkdir(mode=0o700)
        (root / "evidence").mkdir(mode=0o700)
        ci.save(root / "evidence/command-config.json", {"exit_code": 2})
        app = self.root / "synthetic-app"
        state = app / "build/native-environment"
        state.mkdir(parents=True, mode=0o700)
        (app / "build").chmod(0o700)
        (state / "diagnostics").mkdir(mode=0o700)
        self.put(state / "failure-error-name.txt", b"InvalidBisonData")
        with mock.patch.object(ci, "APP", app):
            ci.diagnostics(runtime)
        raw = (root / "evidence/diagnostics.json").read_bytes()
        self.assertNotIn(b"InvalidBisonData", raw)
        self.assertEqual(json.loads(raw)["build_failures"]["config"], {
            "exit_code": 2,
            "native_error_name_sha256":
                hashlib.sha256(b"InvalidBisonData").hexdigest(),
        })

    def test_native_image_failure_digest_without_private_text(self):
        runtime = self.root
        root = runtime / "compute"
        root.mkdir(mode=0o700)
        (root / "evidence").mkdir(mode=0o700)
        ci.save(root / "evidence/command-native-image.json", {"exit_code": 2})
        app = self.root / "synthetic-app"
        state = app / "build/native-environment"
        state.mkdir(parents=True, mode=0o700)
        (app / "build").chmod(0o700)
        self.put(state / "failure-error-name.txt", b"ImageInputChanged")
        self.put(state / "failure-image-guard.txt", b"config-after-root")
        with mock.patch.object(ci, "APP", app):
            ci.diagnostics(runtime)
        raw = (root / "evidence/diagnostics.json").read_bytes()
        self.assertNotIn(b"ImageInputChanged", raw)
        self.assertNotIn(b"config-after-root", raw)
        self.assertNotIn(str(self.root).encode(), raw)
        self.assertEqual(json.loads(raw)["build_failures"]["native-image"], {
            "exit_code": 2,
            "native_error_name_sha256":
                hashlib.sha256(b"ImageInputChanged").hexdigest(),
            "image_guard_sha256":
                hashlib.sha256(b"config-after-root").hexdigest(),
        })

    def test_command_markers_are_closed_diagnostics_not_external_text(self):
        raw = (b"\xff\0error: UnsafeFile\nerror: InvalidNativeMakePath\n"
               b"error: PRIVATE_SYNTHETIC_STATE\nUnsafeFileSuffix\n"
               b"/private/fixture/secret\nerror: UnsafeFile\n")
        self.assertEqual(ci.command_error_markers(raw),
                         ["InvalidNativeMakePath", "UnsafeFile"])
        self.assertEqual(ci.command_error_markers(
            b"UnsafeFileSuffix PrefixUnsafeFile PRIVATE_SYNTHETIC_STATE"), [])
        source = "import sys; sys.stdout.buffer.write(" + repr(raw) + "); sys.exit(3)"
        with self.assertRaises(ci.Refusal):
            ci.run(self.root, "closed-markers", [PYTHON, "-c", source])
        record_path = self.root / "evidence/command-closed-markers.json"
        record = ci.document(record_path)
        self.assertEqual(record["known_error_markers"],
                         ["InvalidNativeMakePath", "UnsafeFile"])
        self.assertEqual(record["exit_code"], 3)
        self.assertEqual(record["sha256"], hashlib.sha256(raw).hexdigest())
        self.assertEqual(record["bytes"], len(raw))
        self.assertNotIn(b"PRIVATE_SYNTHETIC_STATE", record_path.read_bytes())
        self.assertNotIn(b"/private/fixture", record_path.read_bytes())
        self.assertFalse((self.root / "evidence/result.json").exists())


if __name__ == "__main__":
    unittest.main()
