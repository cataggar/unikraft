#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026, The Unikraft Authors.

import importlib.util
import os
from pathlib import Path
import shlex
import sys
import unittest
from unittest import mock

SCRIPTS_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(SCRIPTS_DIR))

elf_tools = importlib.import_module("elf_tools")
configured_tool = elf_tools.configured_tool
tool_output = elf_tools.tool_output


def load_script(name):
    spec = importlib.util.spec_from_file_location(
        f"test_{name}", SCRIPTS_DIR / f"{name}.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ElfToolsTest(unittest.TestCase):
    def test_default_tool_name_is_preserved(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertEqual(configured_tool("NM", "nm"), ["nm"])

    def test_multiword_tool_runs_without_a_shell(self):
        stand_in = (
            f"{shlex.quote(sys.executable)} -c "
            f"{shlex.quote('import sys; print(sys.argv[1])')}"
        )
        with mock.patch.dict(os.environ, {"NM": stand_in}):
            command = configured_tool("NM", "nm")

        output = tool_output(command, "argument with spaces", text=True)
        self.assertEqual(output.strip(), "argument with spaces")

    def test_empty_tool_is_rejected(self):
        with mock.patch.dict(os.environ, {"NM": ""}):
            with self.assertRaisesRegex(ValueError, "NM"):
                configured_tool("NM", "nm")

    def test_image_scripts_select_configured_tools(self):
        environment = {
            "NM": "python3 -m nm_stand_in",
            "OBJDUMP": "python3 -m objdump_stand_in",
            "READELF": "python3 -m readelf_stand_in",
        }
        expected = {
            name: shlex.split(value) for name, value in environment.items()
        }
        with mock.patch.dict(os.environ, environment):
            mkukpcpuvar = load_script("mkukpcpuvar")
            mkbootinfo = load_script("mkbootinfo")
            mkukreloc = load_script("mkukreloc")
            mklinux = load_script("mklinux")
            mkefi = load_script("mkefi")

        self.assertEqual(mkukpcpuvar.NM, expected["NM"])
        self.assertEqual(mkbootinfo.OBJDUMP, expected["OBJDUMP"])
        self.assertEqual(mkukreloc.NM, expected["NM"])
        self.assertEqual(mkukreloc.READELF, expected["READELF"])
        self.assertEqual(mklinux.NM, expected["NM"])
        self.assertEqual(mkefi.NM, expected["NM"])
        self.assertEqual(mkefi.READELF, expected["READELF"])


if __name__ == "__main__":
    unittest.main()
