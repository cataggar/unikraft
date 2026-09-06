#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026, The Unikraft Authors.
"""
Tests for support/scripts/lto-proof.py.

Covers: _build_commands flag invariants (only -flto differs), symbol-name
parsing, proof-result assertion logic, tool-failure propagation, and a CLI
integration test with fake zig/nm executables including paths with spaces.
No real Zig compiler or ELF binary required.
"""

import importlib.util
import os
import shlex
import shutil
import subprocess
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
SCRIPTS_DIR = REPO / "support" / "scripts"
sys.path.insert(0, str(SCRIPTS_DIR))

_PROOF_SCRIPT = SCRIPTS_DIR / "lto-proof.py"


def _load_proof():
    spec = importlib.util.spec_from_file_location("lto_proof", _PROOF_SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _write_exe(path, body):
    path.write_text(body, encoding="utf-8")
    path.chmod(0o755)


class _Base(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        root = os.environ.get("LTO_PROOF_TEST_ROOT")
        cls.work = (
            Path(root) if root
            else REPO / ".cache" / f"lto-proof-tests-{os.getpid()}"
        ).resolve()
        cls.work.mkdir(parents=True, exist_ok=True)

    @classmethod
    def tearDownClass(cls):
        if not os.environ.get("LTO_PROOF_TEST_ROOT"):
            shutil.rmtree(cls.work, ignore_errors=True)

    def setUp(self):
        self._mod = _load_proof()
        self._td = self.work / self.id().replace(".", "_")
        self._td.mkdir(parents=True, exist_ok=True)

    def _tool(self, name, body):
        p = self._td / name
        _write_exe(p, body)
        return p


# ---------------------------------------------------------------------------
# Pure command-construction tests
# ---------------------------------------------------------------------------

class BuildCommandsTest(_Base):
    """_build_commands() is pure; tests run without any subprocess calls."""

    def test_baseline_commands_have_no_flto(self):
        cmds, _ = self._mod._build_commands(self._td, ["zig"], use_lto=False)
        for cmd in cmds:
            self.assertNotIn("-flto", cmd)

    def test_lto_commands_have_flto(self):
        cmds, _ = self._mod._build_commands(self._td, ["zig"], use_lto=True)
        for cmd in cmds:
            self.assertIn("-flto", cmd)

    def test_flto_is_the_only_flag_difference(self):
        """Catches any future addition of -fvisibility=hidden or similar."""
        base_cmds, _ = self._mod._build_commands(self._td, ["zig"], use_lto=False)
        lto_cmds, _ = self._mod._build_commands(self._td, ["zig"], use_lto=True)
        for base_cmd, lto_cmd in zip(base_cmds, lto_cmds):
            base_flags = {a for a in base_cmd if a.startswith("-")}
            lto_flags = {a for a in lto_cmd if a.startswith("-")}
            extra = lto_flags - base_flags
            missing = base_flags - lto_flags
            self.assertEqual(extra, {"-flto"},
                             f"LTO adds unexpected flags: {extra - {'-flto'}!r}")
            self.assertEqual(missing, set(),
                             f"LTO drops baseline flags: {missing!r}")

    def test_output_elf_suffix_differs_between_variants(self):
        _, base_elf = self._mod._build_commands(self._td, ["zig"], use_lto=False)
        _, lto_elf = self._mod._build_commands(self._td, ["zig"], use_lto=True)
        self.assertNotEqual(base_elf, lto_elf)
        self.assertIn("baseline", base_elf.name)
        self.assertIn("lto", lto_elf.name)

    def test_work_dir_with_spaces_appears_in_commands(self):
        spaced = self._td / "work dir with spaces"
        spaced.mkdir(exist_ok=True)
        cmds, _ = self._mod._build_commands(spaced, ["zig"], use_lto=False)
        all_args = [a for cmd in cmds for a in cmd]
        self.assertTrue(any("work dir with spaces" in a for a in all_args))

    def test_zig_cmd_prefix_preserved_verbatim(self):
        zig_cmd = ["/path/to zig", "--extra-arg"]
        cmds, _ = self._mod._build_commands(self._td, zig_cmd, use_lto=False)
        for cmd in cmds:
            self.assertEqual(cmd[0], "/path/to zig")
            self.assertEqual(cmd[1], "--extra-arg")
            self.assertEqual(cmd[2], "cc")


# ---------------------------------------------------------------------------
# Symbol-name parsing tests
# ---------------------------------------------------------------------------

class DefinedSymbolNamesTest(_Base):
    """Tests for _defined_symbol_names() using fake nm executables."""

    def test_parses_address_type_name_columns(self):
        nm = self._tool("nm_std.py",
            "#!/usr/bin/env python3\n"
            "print('0000000001001000 T main')\n"
            "print('0000000001001020 T lto_proof_callee')\n"
        )
        dummy = self._td / "dummy.elf"
        dummy.write_bytes(b"\x00")
        syms = self._mod._defined_symbol_names([sys.executable, str(nm)], dummy)
        self.assertIn("main", syms)
        self.assertIn("lto_proof_callee", syms)

    def test_empty_output_returns_empty_set(self):
        nm = self._tool("nm_empty.py", "#!/usr/bin/env python3\n")
        dummy = self._td / "dummy2.elf"
        dummy.write_bytes(b"\x00")
        syms = self._mod._defined_symbol_names([sys.executable, str(nm)], dummy)
        self.assertEqual(syms, set())

    def test_nm_failure_raises_called_process_error(self):
        nm = self._tool("nm_fail.py",
            "#!/usr/bin/env python3\nimport sys\nsys.exit(1)\n"
        )
        dummy = self._td / "dummy3.elf"
        dummy.write_bytes(b"\x00")
        with self.assertRaises(subprocess.CalledProcessError):
            self._mod._defined_symbol_names([sys.executable, str(nm)], dummy)

    def test_elf_path_with_spaces_forwarded_as_single_argument(self):
        """The nm subprocess must receive the spaced path as one argument."""
        arg_log = self._td / "nm_args.txt"
        nm = self._tool("nm_echo.py",
            "#!/usr/bin/env python3\n"
            "import sys\n"
            "from pathlib import Path\n"
            f"Path({str(arg_log)!r}).write_text('\\n'.join(sys.argv[1:]), encoding='utf-8')\n"
            "print('0000000000000000 T main')\n"
        )
        spaced = self._td / "my elf with spaces.elf"
        spaced.write_bytes(b"\x00")
        self._mod._defined_symbol_names([sys.executable, str(nm)], spaced)
        received = arg_log.read_text(encoding="utf-8").splitlines()
        self.assertIn(str(spaced), received,
                      f"spaced path not received as a single argument; got: {received}")


# ---------------------------------------------------------------------------
# Proof-result assertion tests
# ---------------------------------------------------------------------------

class CheckProofResultTest(_Base):
    """Tests for _check_proof_result() — purely functional, no I/O."""

    def test_pass_returns_empty_list(self):
        result = self._mod._check_proof_result(
            {"main", "lto_proof_callee"}, {"main"}, "lto_proof_callee"
        )
        self.assertEqual(result, [])

    def test_missing_baseline_symbol_reported(self):
        result = self._mod._check_proof_result(
            {"main"}, {"main"}, "lto_proof_callee"
        )
        self.assertEqual(len(result), 1)
        self.assertIn("baseline", result[0])

    def test_retained_lto_symbol_reported(self):
        result = self._mod._check_proof_result(
            {"main", "lto_proof_callee"},
            {"main", "lto_proof_callee"},
            "lto_proof_callee",
        )
        self.assertEqual(len(result), 1)
        self.assertIn("LTO", result[0])

    def test_both_failures_reported_independently(self):
        result = self._mod._check_proof_result(
            {"main"}, {"main", "lto_proof_callee"}, "lto_proof_callee"
        )
        self.assertEqual(len(result), 2)


# ---------------------------------------------------------------------------
# CLI integration tests with fake zig and nm
# ---------------------------------------------------------------------------

def _fake_zig_script():
    """Return body for a fake 'zig' that creates output files and exits 0."""
    return (
        "#!/usr/bin/env python3\n"
        "import sys, stat\n"
        "from pathlib import Path\n"
        "args = sys.argv[1:]\n"
        "if 'cc' in args and '-o' in args:\n"
        "    out = Path(args[args.index('-o') + 1])\n"
        "    if '-c' in args:\n"
        "        out.write_bytes(b'\\x00' * 8)\n"
        "    else:\n"
        "        out.write_text('#!/bin/sh\\nexit 0\\n')\n"
        "        out.chmod(out.stat().st_mode | 0o111)\n"
    )


def _fake_nm_pass_script():
    """nm that returns lto_proof_callee for baseline but not for lto."""
    return (
        "#!/usr/bin/env python3\n"
        "import sys\n"
        "path = sys.argv[-1]\n"
        "if 'baseline' in path:\n"
        "    print('0000000000000000 T main')\n"
        "    print('0000000000000020 T lto_proof_callee')\n"
        "else:\n"
        "    print('0000000000000000 T main')\n"
    )


def _fake_nm_missing_baseline_script():
    """nm that never returns lto_proof_callee (simulates failed baseline retention)."""
    return (
        "#!/usr/bin/env python3\n"
        "print('0000000000000000 T main')\n"
    )


def _fake_nm_retained_lto_script():
    """nm that always returns lto_proof_callee (simulates failed LTO elimination)."""
    return (
        "#!/usr/bin/env python3\n"
        "print('0000000000000000 T main')\n"
        "print('0000000000000020 T lto_proof_callee')\n"
    )


class CLIIntegrationTest(_Base):
    """CLI tests using fake zig and nm; no real compiler required."""

    def _run_proof(self, work_dir, zig_path, nm_cmd=None, extra_args=()):
        cmd = [
            sys.executable, str(_PROOF_SCRIPT),
            "--work-dir", str(work_dir),
            "--zig", str(zig_path),
        ]
        if nm_cmd:
            cmd += ["--nm", nm_cmd]
        cmd += list(extra_args)
        return subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

    def test_passes_when_symbols_are_correct(self):
        fake_zig = self._tool("zig_pass.py", _fake_zig_script())
        fake_nm = self._tool("nm_pass.py", _fake_nm_pass_script())
        nm_cmd = shlex.quote(sys.executable) + " " + shlex.quote(str(fake_nm))
        result = self._run_proof(self._td, fake_zig, nm_cmd=nm_cmd)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("PASS", result.stdout)

    def test_fails_when_baseline_symbol_absent(self):
        fake_zig = self._tool("zig_nb.py", _fake_zig_script())
        fake_nm = self._tool("nm_nb.py", _fake_nm_missing_baseline_script())
        nm_cmd = shlex.quote(sys.executable) + " " + shlex.quote(str(fake_nm))
        result = self._run_proof(self._td, fake_zig, nm_cmd=nm_cmd)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("baseline", result.stderr)

    def test_fails_when_lto_symbol_retained(self):
        fake_zig = self._tool("zig_lr.py", _fake_zig_script())
        fake_nm = self._tool("nm_lr.py", _fake_nm_retained_lto_script())
        nm_cmd = shlex.quote(sys.executable) + " " + shlex.quote(str(fake_nm))
        result = self._run_proof(self._td, fake_zig, nm_cmd=nm_cmd)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("LTO", result.stderr)

    def test_zig_failure_propagates(self):
        bad_zig = self._tool("zig_bad.py",
            "#!/usr/bin/env python3\nimport sys\nsys.exit(1)\n"
        )
        result = self._run_proof(self._td, bad_zig)
        self.assertNotEqual(result.returncode, 0)

    def test_nm_failure_propagates(self):
        fake_zig = self._tool("zig_nmf.py", _fake_zig_script())
        bad_nm = self._tool("nm_bad.py",
            "#!/usr/bin/env python3\nimport sys\nsys.exit(1)\n"
        )
        nm_cmd = shlex.quote(sys.executable) + " " + shlex.quote(str(bad_nm))
        result = self._run_proof(self._td, fake_zig, nm_cmd=nm_cmd)
        self.assertNotEqual(result.returncode, 0)

    def test_work_dir_with_spaces(self):
        # Use a parent in self._td so the test directory can have a spaced name.
        spaced = self._td / "work dir with spaces"
        spaced.mkdir(parents=True, exist_ok=True)
        fake_zig = self._tool("zig_sp.py", _fake_zig_script())
        fake_nm = self._tool("nm_sp.py", _fake_nm_pass_script())
        nm_cmd = shlex.quote(sys.executable) + " " + shlex.quote(str(fake_nm))
        result = self._run_proof(spaced, fake_zig, nm_cmd=nm_cmd)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_zig_path_with_spaces(self):
        spaced_dir = self._td / "tool dir with spaces"
        spaced_dir.mkdir(parents=True, exist_ok=True)
        fake_zig = spaced_dir / "zig tool.py"
        _write_exe(fake_zig, _fake_zig_script())
        fake_nm = self._tool("nm_zsp.py", _fake_nm_pass_script())
        nm_cmd = shlex.quote(sys.executable) + " " + shlex.quote(str(fake_nm))
        result = self._run_proof(self._td, fake_zig, nm_cmd=nm_cmd)
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
