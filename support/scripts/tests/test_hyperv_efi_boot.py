# SPDX-License-Identifier: BSD-3-Clause

import importlib
from pathlib import Path
import sys
import unittest

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


if __name__ == "__main__":
    unittest.main()
