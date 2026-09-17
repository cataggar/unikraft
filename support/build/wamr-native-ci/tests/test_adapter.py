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
import unittest
from unittest import mock
import uuid

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
            self.assertEqual("--disable-x2apic" in args, bool(index % 2))
            self.assertEqual("--raw-disk" in args, index < 2)
            self.assertEqual("--fixed-vhd" in args, index >= 2)
            self.assertNotIn("--image", args)
            self.assertIn("60", args)
            self.assertIn(ci.MARKER, args)


class PhysicalPackage(unittest.TestCase):
    """Run the actual native adapter + pinned miz on a nonbootable synthetic PE."""

    def setUp(self):
        self.root = HERE / (".fixture-" + uuid.uuid4().hex)
        self.root.mkdir(mode=0o700)
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
        self.root = HERE / (".fixture-" + uuid.uuid4().hex)
        self.root.mkdir(mode=0o700)
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
                mock.patch.object(ci, "digest", return_value="f" * 64):
            self.assertEqual(ci.producer_inputs(self.root)["bison_data"], expected)
            self.assertNotIn("BISON_PKGDATADIR", os.environ)

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

    def synthetic_boot(self, raw=None):
        config = ci.config_for(self.root, self.root, 0)
        for name in ("package/unikraft.raw", "firmware/code.fd",
                     "firmware/vars.fd", "bin/qemu-system-x86_64"):
            self.put(self.root / name, b"explicitly synthetic, never native boot evidence")
        work = Path(config["work_dir"])
        work.mkdir(mode=0o700)
        paths = [config["raw_disk"], config["ovmf_code"],
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
        self.put(Path(config["raw_disk"]), b"different package")
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
