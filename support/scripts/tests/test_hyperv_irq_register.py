# SPDX-License-Identifier: BSD-3-Clause

import importlib
from pathlib import Path
import sys
import unittest
from unittest import mock

TESTS = Path(__file__).resolve().parents[2] / "build/tests"
sys.path.insert(0, str(TESTS))
irq = importlib.import_module("hyperv-irq-register-test")
smp = importlib.import_module("hyperv-smp-link-test")

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


class HypervFixedSmpBindingTest(unittest.TestCase):
    @staticmethod
    def startup_controls(
        efer=0x900, cr4=0x20, cr0=0x80010001,
        clear_edx=True, efer_msr=0xC0000080,
    ):
        operations = [
            ("movl", f"${cr4:#x}, %eax"),
            ("movq", "%rax, %cr4"),
        ]
        if clear_edx:
            operations.append(("xorl", "%edx, %edx"))
        operations.extend((
            ("movl", f"${efer:#x}, %eax"),
            ("movl", f"${efer_msr:#x}, %ecx"),
            ("wrmsr", ""),
            ("movl", f"${cr0:#x}, %eax"),
            ("movq", "%rax, %cr0"),
        ))
        return [
            (10 + index, op, operands)
            for index, (op, operands) in enumerate(operations)
        ]

    def setUp(self):
        self.functions = {
            1: ("uk_boot_entry", [(1, "call", "2 <ukplat_lcpu_count>")]),
            2: ("ukplat_lcpu_count", [(2, "jmp", "3 <uk_acpi_cpu_count>")]),
            3: ("uk_acpi_cpu_count", [(3, "ret", "")]),
            5: (
                "uk_boot_fixed_smp_lcpu_entry",
                [
                    (5, "call", "6 <uk_lcpu_init>"),
                    (6, "call", "8 <uk_paging_pt_get_active>"),
                    (7, "call", "9 <uk_paging_pt_activate_lcpu>"),
                ],
            ),
            10: (
                "x86_start16_end",
                self.startup_controls(),
            ),
        }
        self.symbols = {
            "uk_boot_fixed_smp_prepare": 4,
            "uk_boot_entry": 1,
            "ukplat_lcpu_count": 2,
            "uk_acpi_cpu_count": 3,
            "uk_boot_fixed_smp_lcpu_entry": 5,
            "uk_lcpu_init": 6,
            "uk_paging_pt_get_active": 8,
            "uk_paging_pt_activate_lcpu": 9,
            "lcpu_start32": 10,
            "lcpu_start64": 18,
        }
        self.kinds = {"ukplat_lcpu_count": ["T"]}

    def test_boot_uses_strong_acpi_count_and_initializes_ap(self):
        irq.verify_fixed_smp_bindings(
            self.functions, self.symbols, self.kinds,
        )

    def test_localized_weak_count_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "one strong platform symbol"):
            irq.verify_fixed_smp_bindings(
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
                    irq.verify_fixed_smp_bindings(
                        functions, symbols, kinds
                    )

    def test_missing_or_misbound_ap_initialization_is_rejected(self):
        for instructions in (
            [],
            [(5, "call", "7 <wrong_init>")],
            [(5, "call", "*%rax")],
        ):
            with self.subTest(instructions=instructions):
                self.functions[5] = ("uk_boot_fixed_smp_lcpu_entry", instructions)
                with self.assertRaisesRegex(ValueError, "does not initialize"):
                    irq.verify_fixed_smp_bindings(
                        self.functions, self.symbols, self.kinds,
                    )

    def test_missing_or_misordered_ap_address_space_activation_is_rejected(self):
        variants = (
            (
                [(5, "call", "6 <uk_lcpu_init>")],
                "does not activate",
            ),
            (
                [
                    (5, "call", "8 <uk_paging_pt_get_active>"),
                    (6, "call", "6 <uk_lcpu_init>"),
                    (7, "call", "9 <uk_paging_pt_activate_lcpu>"),
                ],
                "initialization order",
            ),
            (
                [
                    (5, "call", "6 <uk_lcpu_init>"),
                    (6, "call", "9 <uk_paging_pt_activate_lcpu>"),
                    (7, "call", "8 <uk_paging_pt_get_active>"),
                ],
                "initialization order",
            ),
        )
        for instructions, message in variants:
            with self.subTest(message=message):
                self.functions[5] = (
                    "uk_boot_fixed_smp_lcpu_entry", instructions
                )
                with self.assertRaisesRegex(ValueError, message):
                    irq.verify_fixed_smp_bindings(
                        self.functions, self.symbols, self.kinds,
                    )

    def test_ap_runtime_paging_requires_nxe(self):
        invalid = (
            self.startup_controls(efer=0x100),
            self.startup_controls(efer=0x800),
            self.startup_controls(clear_edx=False),
            self.startup_controls(efer_msr=0xC0000081),
        )
        for instructions in invalid:
            with self.subTest(instructions=instructions):
                self.functions[10] = ("x86_start16_end", instructions)
                with self.assertRaisesRegex(ValueError, "EFER.NXE"):
                    irq.verify_fixed_smp_bindings(
                        self.functions, self.symbols, self.kinds,
                    )

    def test_ap_runtime_paging_requires_cr0_and_cr4_controls(self):
        variants = (
            (self.startup_controls(cr4=0), "CR4.PAE"),
            (self.startup_controls(cr0=0x80000001), "CR0.PE/WP/PG"),
        )
        for instructions, message in variants:
            with self.subTest(message=message):
                self.functions[10] = ("x86_start16_end", instructions)
                with self.assertRaisesRegex(ValueError, message):
                    irq.verify_fixed_smp_bindings(
                        self.functions, self.symbols, self.kinds,
                    )

    def test_ap_paging_rejects_clobbered_or_overwritten_controls(self):
        variants = (
            (0, [("jmp", "17 <skip_controls>")]),
            (1, [("xorl", "%eax, %eax")]),
            (3, [("movl", "$0x1, %edx")]),
            (4, [("andl", "$0xfffff7ff, %eax")]),
            (6, [
                ("xorl", "%edx, %edx"),
                ("movl", "$0x100, %eax"),
                ("movl", "$0xc0000080, %ecx"),
                ("wrmsr", ""),
            ]),
            (7, [("xorl", "%eax, %eax")]),
        )
        for position, inserted in variants:
            with self.subTest(position=position):
                operations = [
                    (op, operands) for _, op, operands in self.startup_controls()
                ]
                operations[position:position] = inserted
                instructions = [
                    (10 + index, op, operands)
                    for index, (op, operands) in enumerate(operations)
                ]
                self.functions[10] = ("x86_start16_end", instructions)
                self.symbols["lcpu_start64"] = 10 + len(instructions)
                with self.assertRaises(ValueError):
                    irq.verify_fixed_smp_bindings(
                        self.functions, self.symbols, self.kinds,
                    )

    def test_non_fixed_image_does_not_require_fixed_bindings(self):
        irq.verify_fixed_smp_bindings({}, {}, {})

    def test_multicpu_link_without_fixed_scheduler_is_supported(self):
        hooks = (
            "ukplat_lcpu_startup_hook", "ukplat_lcpu_init_hook",
            "ukplat_lcpu_fini_hook", "hyperv_vmbus_shutdown",
            "hyperv_vmbus_fini", "hyperv_vmbus_message",
            "hyperv_vmbus_event", "hyperv_vmbus_event_word",
        )
        symbols = "\n".join(f"{i:x} T {hook}" for i, hook in enumerate(hooks))
        calls = {
            "uk_boot_entry": ("ukplat_lcpu_startup_hook",),
            "uk_lcpu_init": ("ukplat_lcpu_init_hook",),
            "lcpu_halt": ("ukplat_lcpu_fini_hook",),
            "ukplat_lcpu_startup_hook": (
                "uk_lcpu_start", "hyperv_vmbus_message",
                "hyperv_vmbus_event_word", "hyperv_vmbus_shutdown",
            ),
        }
        disassembly = "".join(
            f"{i:x} <{caller}>:\n" + "".join(
                f"  {i:x}: call 0 <{callee}>\n" for callee in callees
            )
            for i, (caller, callees) in enumerate(calls.items())
        )
        with mock.patch.object(smp, "output", side_effect=[symbols, disassembly]):
            with mock.patch.object(sys, "argv", [
                "hyperv-smp-link-test.py", "--image", "unused", "--max-cpus", "2",
            ]):
                smp.main()


if __name__ == "__main__":
    unittest.main()
