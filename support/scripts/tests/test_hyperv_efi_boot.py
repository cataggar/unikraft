# SPDX-License-Identifier: BSD-3-Clause

import importlib
import io
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

TESTS = Path(__file__).resolve().parents[2] / "build/tests"
sys.path.insert(0, str(TESTS))
boot = importlib.import_module("hyperv-efi-boot-test")

MILESTONES = (
    "Hyper-V Hv#1 hypercall page enabled",
    "Hyper-V SynIC:",
    "Powered by",
    "Calling main(",
    "Hello world!",
    "main returned 0",
)


class HypervEfiBootTest(unittest.TestCase):
    @staticmethod
    def arguments(root):
        return [
            "hyperv-efi-boot-test", "--image", str(root / "image"),
            "--ovmf-code", str(root / "code"),
            "--ovmf-vars", str(root / "vars"),
            "--work-dir", str(root / "work"), "--expect", "Hello world!",
        ]

    def test_application_boot(self):
        boot.validate_boot_log("\n".join(MILESTONES), "Hello world!")

    def test_every_milestone_is_required(self):
        for marker in MILESTONES:
            with self.subTest(marker=marker):
                with self.assertRaisesRegex(ValueError, "missing boot milestone"):
                    boot.validate_boot_log(
                        "\n".join(m for m in MILESTONES if m != marker),
                        "Hello world!",
                    )

    def test_crash_after_application_marker_is_not_success(self):
        for failure in ("Unikraft Crash", "Assertion failure", "Exception Type"):
            with self.subTest(failure=failure):
                with self.assertRaisesRegex(ValueError, "guest reported"):
                    boot.validate_boot_log(
                        "\n".join((*MILESTONES, failure)), "Hello world!"
                    )

    def test_cpu_count_preserves_default_and_enables_explicit_smp(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name in ("image", "code", "vars"):
                (root / name).write_bytes(b"fixture")

            def run(command, **kwargs):
                kwargs["stdout"].write("\n".join(MILESTONES).encode())
                return mock.Mock(returncode=0)

            for options, expected in (([], "1"), (["--cpus", "2"], "2")):
                with self.subTest(options=options):
                    with mock.patch.object(sys, "argv", self.arguments(root) + options):
                        with mock.patch.object(boot.subprocess, "run", side_effect=run) as qemu:
                            with redirect_stdout(io.StringIO()):
                                boot.main()
                    command = qemu.call_args.args[0]
                    self.assertEqual(command[command.index("-smp") + 1], expected)

    def test_invalid_cpu_counts_fail_before_qemu(self):
        for options in (
            ["--cpus", "0"],
            ["--cpus", "9"],
            ["--cpus", "2", "--disable-x2apic"],
        ):
            with self.subTest(options=options):
                with mock.patch.object(sys, "argv", self.arguments(Path("unused")) + options):
                    with mock.patch.object(boot.subprocess, "run") as qemu:
                        with redirect_stderr(io.StringIO()):
                            with self.assertRaises(SystemExit) as error:
                                boot.main()
                self.assertEqual(error.exception.code, 2)
                qemu.assert_not_called()


if __name__ == "__main__":
    unittest.main()
