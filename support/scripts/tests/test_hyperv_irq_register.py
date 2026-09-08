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


if __name__ == "__main__":
    unittest.main()
