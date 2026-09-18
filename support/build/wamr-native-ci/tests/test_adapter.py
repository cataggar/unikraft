# SPDX-License-Identifier: BSD-3-Clause
"""Synthetic unit/physical packaging fixtures; never real guest boot evidence."""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("wamr_ci", HERE / "run.py")
ci = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ci)


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

    def test_exact_result_both_apics(self):
        for legacy in (False, True):
            self.assertEqual(ci.compute(self.log(legacy), self.identity, legacy), self.result)

    def test_console_nul_and_ansi_framing(self):
        for legacy in (False, True):
            raw = self.log(legacy).replace(
                b"Calling main(0, 0)\n",
                b"\x1b[1mCalling main(0, 0)\x1b[0m\r\n\0")
            raw = raw.replace(ci.MARKER.encode(),
                              b"\x1b[32m" + ci.MARKER.encode() + b"\x1b[0m\0")
            self.assertEqual(ci.compute(raw, self.identity, legacy), self.result)

    def test_normalization_keeps_native_serial_refusals(self):
        raw = self.log()
        malformed = [raw + suffix for suffix in
                     (b"\x1b", b"\x1b[", b"\x1b[0\0m", b"\x07", b"\xc2\0\xa3")]
        malformed.append(b"x" * 8193 + b"\n" + raw)
        for value in malformed:
            with self.subTest(raw=value), self.assertRaises(ValueError):
                ci.compute(value, self.identity, False)

    def test_wrong_result_trap_growth_selftest_accounting_and_identity(self):
        for key, value in (("answer", 43), ("checks", 1), ("terminal", 0),
                           ("detail", 0), ("frame_bytes", 4096),
                           ("platform_status", -1), ("version", True),
                           ("runtime_sha256", "9" * 64)):
            original = copy.deepcopy(self.result)
            self.result[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                ci.compute(self.log(), self.identity, False)
            self.result = original

    def test_exact_completion_not_substring_or_request_echo(self):
        raw = self.log()
        marker = ci.MARKER.encode()
        cases = [
            raw.replace(marker, b"echo " + marker),
            raw.replace(marker, marker + b" suffix"),
            raw + marker + b"\n",
            marker + b"\n" + raw.replace(marker + b"\n", b""),
            raw.replace(marker + b"\n", b"") + marker + b"\n",
            raw.replace(b"WAMR_NATIVE_COMPUTE=", b"request WAMR_NATIVE_COMPUTE="),
            raw + b"HYPERV_ACCEPTANCE NETWORK_APP_FINAL PASS\n",
            raw + ci.LEGACY.encode(),
            raw.replace(b'"version": 1', b'"version": 1, "version": 1'),
        ]
        for malformed in cases:
            with self.subTest(raw=malformed), self.assertRaises(ValueError):
                ci.compute(malformed, self.identity, False)
        with self.assertRaises(ValueError):
            ci.compute(raw, self.identity, True)

    def test_four_exact_disk_modes_never_hardware_return(self):
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

    def call(self, command, success=True):
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


class Evidence(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="wamr-native-ci-"))
        self.root.chmod(0o700)
        self.addCleanup(shutil.rmtree, self.root)
        for name in ("private", "evidence", "package", "firmware", "bin"):
            (self.root / name).mkdir(mode=0o700)
        self.contract = Contract()
        self.contract.setUp()

    def put(self, path, value):
        path.write_bytes(value)
        path.chmod(0o600)

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

    def test_boot_revalidation_does_not_need_inherited_build_environment(self):
        root = self.root / "bison"
        root.mkdir(mode=0o700)
        self.put(root / "skeleton", b"fixture")
        expected = ci.bison_inputs(root)
        with mock.patch.dict(os.environ, {}, clear=True), \
                mock.patch.object(ci, "source", return_value={"fixture": True}), \
                mock.patch.object(ci, "tool", return_value="/synthetic-tool"), \
                mock.patch.object(ci, "digest", return_value="f" * 64), \
                mock.patch.object(ci, "dependency_custody",
                                  return_value={"fixture": True}):
            self.assertEqual(ci.producer_inputs(self.root)["bison_data"], expected)
            self.assertNotIn("BISON_PKGDATADIR", os.environ)

    def test_compute_dynamic_validator_never_writes_bytecode(self):
        app = self.root / "validator-app"
        app.mkdir(mode=0o700)
        checker = app / "check-log.py"
        self.put(checker, b"def validate(text, identity):\n    return None\n")
        log = self.root / "serial.log"
        self.put(log, self.contract.log())
        before = {
            path: ci.snapshot(path.lstat())
            for path in (app, checker)
        }
        script = """
import os
from pathlib import Path
import sys
assert "PYTHONDONTWRITEBYTECODE" not in os.environ
assert sys.dont_write_bytecode is False
path = Path(sys.argv[1])
scope = {"__file__": str(path), "__name__": "wamr_ci_fixture"}
exec(compile(path.read_bytes(), str(path), "exec"), scope)
assert sys.dont_write_bytecode is True
scope["APP"] = Path(sys.argv[2])
scope["compute"](Path(sys.argv[3]).read_bytes(), {}, False)
"""
        completed = subprocess.run(
            [sys.executable, "-c", script, str(HERE / "run.py"), str(app), str(log)],
            env={}, capture_output=True, timeout=30)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(list(app.iterdir()), [checker])
        self.assertEqual(
            {path: ci.snapshot(path.lstat()) for path in (app, checker)},
            before,
        )

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

    def test_restore_precedes_custody_and_both_builds_use_one_system_tree(self):
        runtime = self.root / "runtime"
        runtime.mkdir(mode=0o700)
        packages = runtime / "packages"
        packages.mkdir(mode=0o700)
        events = []
        commands = []

        source = {"revision": "1" * 40, "tree": "2" * 40, "custody": {}}

        def restore(root, expected):
            events.append("restore")
            self.assertEqual(expected, source)
            return packages

        def inputs(root):
            events.append("custody")
            return {"source": source, "dependencies": {}}

        def command(runtime, expected, root, stage, args, *unused):
            commands.append((stage, list(map(str, args))))
            return root / "private" / (stage + ".log")

        with mock.patch.dict(os.environ, {
                "BISON_PKGDATADIR": str(runtime / "bison")}, clear=True), \
                mock.patch.object(ci, "prepare_source_outputs"), \
                mock.patch.object(ci, "source", return_value=source), \
                mock.patch.object(ci, "restore_dependencies", side_effect=restore), \
                mock.patch.object(ci, "producer_inputs", side_effect=inputs), \
                mock.patch.object(ci, "run_custodied", side_effect=command), \
                mock.patch.object(ci, "retain_solved_config"), \
                mock.patch.object(ci, "solved_config", return_value="f" * 64), \
                mock.patch.object(ci, "require_build_custody"), \
                mock.patch.object(ci, "save"), \
                mock.patch.object(ci, "check_build", return_value={}), \
                mock.patch.object(ci, "digest", return_value="f" * 64), \
                mock.patch.object(ci, "tool", side_effect=lambda name: "/tools/" + name), \
                mock.patch.object(ci.subprocess, "check_output", return_value=b"0.16.0\n"):
            ci.build(runtime, self.root)

        self.assertEqual(events[:2], ["restore", "custody"])
        selected = dict(commands)
        for stage in ("adapter", "local-boot-tool"):
            self.assertIn("--system", selected[stage])
            self.assertEqual(
                selected[stage][selected[stage].index("--system") + 1],
                str(packages),
            )
        self.assertFalse((ci.LOCAL_BOOT / "zig-pkg").exists())
        self.assertFalse((ci.HERE / "zig-pkg").exists())

    def test_restore_requires_the_private_fetched_package_tree(self):
        missing = self.root / "missing-source"
        missing_root = self.root / "missing-restore"
        missing_root.mkdir(mode=0o700)
        with mock.patch.object(ci, "LOCAL_BOOT", missing), \
                mock.patch.object(
                    ci, "tracked_manifest",
                    side_effect=ci.Refusal("pinned dependency manifest unavailable")), \
                mock.patch.object(ci, "require_source"):
            with self.assertRaisesRegex(
                    ci.Refusal, "pinned dependency manifest unavailable"):
                ci.restore_dependencies(missing_root, {"source": "fixture"})
        root = self.root / "restore"
        root.mkdir(mode=0o700)
        for name in ("private", "evidence", "cache", "global-cache"):
            (root / name).mkdir(mode=0o700)
        with mock.patch.object(ci, "require_source"), \
                mock.patch.object(ci, "execute", return_value=(
                    root / "private/dependency-restore.log",
                    {"known_error_markers": []})):
            with self.assertRaisesRegex(
                    ci.Refusal, "private pinned dependency restore required"):
                ci.restore_dependencies(root, {"source": "fixture"})

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
            return ({
                "path": relative, "mode": "100644", "bytes": len(data),
                "sha256": hashlib.sha256(data).hexdigest(), "git_oid": "1" * 40,
                "metadata_sha256": "2" * 64,
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
            output = root / "private/dependency-hash-000.log"
            self.put(output, b"miz-0.2.0-wrong\n")
            return output, {}

        with mock.patch.object(ci, "execute", side_effect=wrong), \
                self.assertRaisesRegex(ci.Refusal, "content hash mismatch"):
            ci.verify_package_hashes(root, packages)

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
            return ({
                "path": relative, "mode": "100644", "bytes": len(data),
                "sha256": hashlib.sha256(data).hexdigest(), "git_oid": "1" * 40,
                "metadata_sha256": "2" * 64,
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

        with mock.patch.object(ci, "require_source"), \
                mock.patch.object(ci, "tracked_manifest", side_effect=manifest_record), \
                mock.patch.object(ci, "execute", side_effect=swap_restore), \
                self.assertRaisesRegex(
                    ci.Refusal, "copied dependency manifest identity changed"):
            ci.restore_dependencies(root, {"source": "fixture"})
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
            return ({
                "path": relative, "mode": "100644", "bytes": len(data),
                "sha256": hashlib.sha256(data).hexdigest(), "git_oid": "1" * 40,
                "metadata_sha256": "2" * 64,
            }, data)

        patch = mock.patch.object(ci, "tracked_manifest", side_effect=manifest_record)
        with patch:
            dependency = ci.dependency_custody(compute)
            expected = {"source": source_record, "dependencies": dependency}
            target = packages / ci.MIZ_PACKAGE_HASH / "source.zig"
            self.put(target, b"changed before build\n")
            with mock.patch.object(ci, "source", return_value=source_record), \
                    mock.patch.object(ci, "run") as command, \
                    self.assertRaisesRegex(ci.Refusal, "dependency custody changed"):
                ci.run_custodied(runtime, expected, compute, "adapter", ["false"])
            command.assert_not_called()
            self.put(target, b"pub const answer = 42;\n")
            dependency = ci.dependency_custody(compute)
            expected["dependencies"] = dependency

            def mutate(*unused):
                self.put(target, b"changed during build\n")
                return compute / "private/adapter.log"

            with mock.patch.object(ci, "source", return_value=source_record), \
                    mock.patch.object(ci, "run", side_effect=mutate), \
                    self.assertRaisesRegex(ci.Refusal, "dependency custody changed"):
                ci.run_custodied(runtime, expected, compute, "adapter", ["fixture"])

    def test_source_custody_detects_ignored_create_delete_metadata(self):
        repository = self.root / "repository"
        repository.mkdir(mode=0o700)
        (repository / "source").mkdir(mode=0o700)
        self.put(repository / "source/input", b"tracked\n")
        (repository / "source/link").symlink_to("input")
        self.put(repository / ".gitignore", b"source/generated/\n")
        subprocess.run(["git", "init", "-q"], cwd=repository, check=True)
        subprocess.run(["git", "config", "user.email", "fixture@example.invalid"],
                       cwd=repository, check=True)
        subprocess.run(["git", "config", "user.name", "Fixture"],
                       cwd=repository, check=True)
        subprocess.run(["git", "add", ".gitignore", "source/input", "source/link"],
                       cwd=repository, check=True)
        subprocess.run(["git", "commit", "-qm", "fixture"], cwd=repository, check=True)
        expected = ci.source(repository)
        self.assertEqual(ci.source(repository), expected)
        generated = repository / "source/generated"
        generated.mkdir(mode=0o700)
        generated.rmdir()
        self.assertEqual(
            subprocess.check_output(
                ["git", "status", "--porcelain=v2", "--untracked-files=all"],
                cwd=repository),
            b"",
        )
        with self.assertRaisesRegex(ci.Refusal, "immutable source custody changed"):
            ci.require_source(expected, repository)
        self.put(self.root / "outside", b"not source\n")
        (repository / "source/link").unlink()
        (repository / "source/link").symlink_to("../../outside")
        subprocess.run(["git", "add", "source/link"], cwd=repository, check=True)
        subprocess.run(["git", "commit", "-qm", "escaping link"],
                       cwd=repository, check=True)
        with self.assertRaisesRegex(ci.Refusal, "symlink escapes repository"):
            ci.source(repository)

    def test_precreated_output_roots_keep_source_parent_metadata_exact(self):
        app = self.root / "app"
        app.mkdir(mode=0o700)
        self.put(app / "defconfig", b"CONFIG_FIXTURE=y\n")
        with mock.patch.object(ci, "APP", app):
            ci.prepare_source_outputs()
            before = ci.snapshot(app.lstat())
            self.put(app / "build/.config",
                     b"CONFIG_FIXTURE=y\nCONFIG_SOLVED=y\n")
            self.assertEqual(ci.snapshot(app.lstat()), before)
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
            self.put(app / "build/.config", b"CONFIG_CHANGED=y\n")
            with self.assertRaisesRegex(ci.Refusal, "build configuration changed"):
                ci.solved_config()

    def synthetic_boot(self, raw=None):
        config = ci.config_for(self.root, self.root, 0)
        for name in ("package/unikraft.raw", "firmware/code.fd",
                     "firmware/vars.fd", "bin/qemu-system-x86_64"):
            self.put(self.root / name, b"explicitly synthetic, never native boot evidence")
        work = Path(config["work_dir"])
        work.mkdir(mode=0o700)
        paths = [config["source"]["path"], config["ovmf_code"],
                 config["ovmf_vars"], config["qemu"]]
        ci.save(work / "request.json", {
            "schema_version": 1, "supervisor_pid": 123, "config": config,
            "pins": [{"size": Path(p).stat().st_size,
                      "sha256": list(bytes.fromhex(ci.digest(Path(p))))} for p in paths],
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
        raw = self.contract.log().replace(b"\n", b"\x1b[0m\0\r\n\0")
        config = self.synthetic_boot(raw)
        observed = ci.check_boot(config, self.contract.identity)
        raw_hash = hashlib.sha256(raw).hexdigest()
        normalized_hash = hashlib.sha256(ci.normalize_serial(raw).encode()).hexdigest()
        self.assertNotEqual(raw_hash, normalized_hash)
        self.assertEqual(observed["report"]["serial_sha256"], raw_hash)
        self.assertEqual(observed["compute"], self.contract.result)
        report_path = Path(config["work_dir"]) / "report.json"
        report = ci.document(report_path)
        report["serial_sha256"] = normalized_hash
        self.put(report_path, json.dumps(report).encode())
        with self.assertRaises(ValueError):
            ci.check_boot(config, self.contract.identity)

    def test_physical_request_log_and_report_bindings(self):
        config = self.synthetic_boot()
        identity = self.contract.identity
        observed = ci.check_boot(config, identity)
        self.assertEqual(observed["compute"], self.contract.result)
        changed = dict(config, disable_x2apic=True)
        with self.assertRaises(ValueError):
            ci.check_boot(changed, identity)
        work = Path(config["work_dir"])
        original = (work / "hyperv-efi-boot.log").read_bytes()
        self.put(work / "hyperv-efi-boot.log", original + b"changed")
        with self.assertRaises(ValueError):
            ci.check_boot(config, identity)
        self.put(work / "hyperv-efi-boot.log", original)
        self.put(Path(config["source"]["path"]), b"different package")
        with self.assertRaises(ValueError):
            ci.check_boot(config, identity)

    def test_failed_native_report_never_becomes_compute_result(self):
        config = self.synthetic_boot()
        report_path = Path(config["work_dir"]) / "report.json"
        saved = ci.document(report_path)
        for key, value in (("cleanup_complete", False), ("passed", False),
                           ("serial_limit_reached", True), ("termination", {"exited": 1})):
            report = dict(saved, **{key: value})
            self.put(report_path, json.dumps(report).encode())
            with self.subTest(key=key), self.assertRaises(ValueError):
                ci.check_boot(config, self.contract.identity)

    def test_bounded_failure_capture_and_timeout(self):
        for stage, source, seconds, limit in (
                ("failed", "raise SystemExit(3)", 10, 1024),
                ("overflow", "print('x' * 4096)", 10, 32),
                ("timeout", "import time; time.sleep(20)", 1, 1024)):
            with self.subTest(stage=stage), self.assertRaises(ValueError):
                ci.run(self.root, stage, [sys.executable, "-c", source], seconds, limit)
            record = ci.document(self.root / "evidence" / ("command-" + stage + ".json"))
            self.assertLessEqual(record["bytes"], limit + 1)
            self.assertEqual(record["scope"], "command_diagnostic_not_acceptance")
        self.assertFalse((self.root / "evidence/result.json").exists())

    def test_redaction_never_copies_arbitrary_serial_or_error_state(self):
        runtime = self.root
        root = runtime / "compute"
        root.mkdir(mode=0o700)
        (root / "evidence").mkdir(mode=0o700)
        work = root / "boot-raw-x2apic"
        work.mkdir(mode=0o700)
        self.put(work / "hyperv-efi-boot.log", b"PRIVATE_SYNTHETIC_STATE")
        ci.save(work / "report.json", {
            "passed": False, "cleanup_complete": True, "input_unchanged": True,
            "serial_valid": False, "serial_limit_reached": False,
            "failures": {"primary": {"arbitrary": "PRIVATE_SYNTHETIC_STATE"},
                         "cleanup": None, "recording": None},
        })
        ci.diagnostics(runtime)
        raw = (root / "evidence/diagnostics.json").read_bytes()
        self.assertNotIn(b"PRIVATE_SYNTHETIC_STATE", raw)
        self.assertNotIn(str(self.root).encode(), raw)
        self.assertFalse((root / "evidence/result.json").exists())

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
            ci.run(self.root, "closed-markers", [sys.executable, "-c", source])
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
