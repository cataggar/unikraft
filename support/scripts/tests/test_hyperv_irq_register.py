# SPDX-License-Identifier: BSD-3-Clause

import importlib
from pathlib import Path
import sys
import unittest

TESTS = Path(__file__).resolve().parents[2] / "build/tests"
sys.path.insert(0, str(TESTS))
irq = importlib.import_module("hyperv-irq-register-test")

CALLBACK = "schedcoop_thread_woken_isr"


class HypervIrqConstructorTest(unittest.TestCase):
    def test_direct_constructor_binding(self):
        functions = {
            1: ("uk_schedcoop_create", [(1, "mov", f"<{CALLBACK}>")]),
        }
        irq.verify_schedcoop_callbacks(functions, {"uk_schedcoop_create": 1})

    def test_both_constructor_wrappers_reach_shared_binding(self):
        functions = {
            1: ("uk_schedcoop_create", [(1, "jmp", "3 <schedcoop_create>")]),
            2: ("uk_schedcoop_create_on", [(2, "call", "3 <schedcoop_create>")]),
            3: ("schedcoop_create", [(3, "mov", f"<{CALLBACK}>")]),
        }
        irq.verify_schedcoop_callbacks(functions, {
            "uk_schedcoop_create": 1, "uk_schedcoop_create_on": 2,
        })

    def test_missing_constructors_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "constructor binding not found"):
            irq.verify_schedcoop_callbacks({}, {CALLBACK: 4})

    def test_every_present_constructor_must_bind(self):
        functions = {
            1: ("uk_schedcoop_create", [(1, "mov", f"<{CALLBACK}>")]),
            2: ("uk_schedcoop_create_on", [(2, "ret", "")]),
        }
        with self.assertRaisesRegex(ValueError, "uk_schedcoop_create_on"):
            irq.verify_schedcoop_callbacks(functions, {
                "uk_schedcoop_create": 1, "uk_schedcoop_create_on": 2,
            })

    def test_unresolved_and_cyclic_wrappers_are_rejected(self):
        for functions in (
            {},
            {
                1: ("uk_schedcoop_create", [(1, "jmp", "2 <schedcoop_create>")]),
                2: ("schedcoop_create", [(2, "jmp", "1 <uk_schedcoop_create>")]),
            },
        ):
            with self.subTest(functions=functions):
                with self.assertRaisesRegex(ValueError, "callback binding not found"):
                    irq.verify_schedcoop_callbacks(
                        functions, {"uk_schedcoop_create": 1}
                    )


class HypervFixedSmpCpuCountTest(unittest.TestCase):
    def test_boot_uses_strong_acpi_platform_count(self):
        functions = {
            1: ("uk_boot_entry", [(1, "call", "2 <ukplat_lcpu_count>")]),
            2: ("ukplat_lcpu_count", [(2, "jmp", "3 <uk_acpi_cpu_count>")]),
            3: ("uk_acpi_cpu_count", [(3, "ret", "")]),
        }
        irq.verify_fixed_smp_cpu_count_binding(
            functions,
            {
                "uk_boot_fixed_smp_prepare": 4,
                "uk_boot_entry": 1,
                "ukplat_lcpu_count": 2,
                "uk_acpi_cpu_count": 3,
            },
            {"ukplat_lcpu_count": ["T"]},
        )

    def test_localized_weak_count_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "one strong platform symbol"):
            irq.verify_fixed_smp_cpu_count_binding(
                {},
                {
                    "uk_boot_fixed_smp_prepare": 4,
                    "ukplat_lcpu_count": 2,
                },
                {"ukplat_lcpu_count": ["T", "t"]},
            )

    def test_boot_or_platform_misbinding_is_rejected(self):
        symbols = {
            "uk_boot_fixed_smp_prepare": 4,
            "uk_boot_entry": 1,
            "ukplat_lcpu_count": 2,
            "uk_acpi_cpu_count": 3,
        }
        kinds = {"ukplat_lcpu_count": ["T"]}
        for functions, message in (
            (
                {
                    1: ("uk_boot_entry", [(1, "call", "5 <weak_count>")]),
                    2: (
                        "ukplat_lcpu_count",
                        [(2, "jmp", "3 <uk_acpi_cpu_count>")],
                    ),
                },
                "boot does not call",
            ),
            (
                {
                    1: (
                        "uk_boot_entry",
                        [(1, "call", "2 <ukplat_lcpu_count>")],
                    ),
                    2: ("ukplat_lcpu_count", [(2, "ret", "")]),
                },
                "does not use ACPI",
            ),
        ):
            with self.subTest(message=message):
                with self.assertRaisesRegex(ValueError, message):
                    irq.verify_fixed_smp_cpu_count_binding(
                        functions, symbols, kinds
                    )


if __name__ == "__main__":
    unittest.main()
