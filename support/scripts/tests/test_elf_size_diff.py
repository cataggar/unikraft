#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026, The Unikraft Authors.
"""
Tests for support/scripts/elf-size-diff.py.

Covers: section parsing, delta arithmetic, zero baselines, missing sections,
spaces in ELF and tool paths, malformed tool output, tool failures, JSON and
table output formats.

No full Unikraft build is required; all ELF interactions go through fake
tool executables written to a per-run work directory.
"""

import importlib.util
import json
import os
import shlex
import shutil
import subprocess
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
SCRIPTS_DIR = REPO / "support" / "scripts"

# Insert scripts dir so we can import elf_tools (used by elf-size-diff).
sys.path.insert(0, str(SCRIPTS_DIR))

_DIFF_SCRIPT = SCRIPTS_DIR / "elf-size-diff.py"


def _load_diff():
    spec = importlib.util.spec_from_file_location("elf_size_diff", _DIFF_SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _write_exe(path, body):
    path.write_text(body, encoding="utf-8")
    path.chmod(0o755)


# Canonical readelf -SW output used by most tests.  Sizes are in hex.
_READELF_BODY_A = """\
Section Headers:
  [Nr] Name              Type            Address          Off    Size   ES Flg Lk Inf Al
  [ 0]                   NULL            0000000000000000 000000 000000 00      0   0  0
  [ 1] .text             PROGBITS        0000000000401000 001000 001000 00  AX  0   0 16
  [ 2] .rodata           PROGBITS        0000000000402000 002000 000200 00   A  0   0  8
  [ 3] .data             PROGBITS        0000000000403000 003000 000100 00  WA  0   0  8
  [ 4] .bss              NOBITS          0000000000403100 003100 000080 00  WA  0   0  8
"""

# Same sections, smaller .text and no .bss (simulates LTO result).
_READELF_BODY_B = """\
Section Headers:
  [Nr] Name              Type            Address          Off    Size   ES Flg Lk Inf Al
  [ 0]                   NULL            0000000000000000 000000 000000 00      0   0  0
  [ 1] .text             PROGBITS        0000000000401000 001000 000c00 00  AX  0   0 16
  [ 2] .rodata           PROGBITS        0000000000402000 002000 000200 00   A  0   0  8
  [ 3] .data             PROGBITS        0000000000403000 003000 000100 00  WA  0   0  8
"""

# Readelf output with a non-hex size field.
_READELF_BODY_BAD = """\
Section Headers:
  [Nr] Name              Type            Address          Off    Size   ES Flg Lk Inf Al
  [ 1] .text             PROGBITS        0000000000401000 001000 ZZZZZZ 00  AX  0   0 16
"""

# 10 defined symbols.
_NM_BODY_10 = "\n".join(
    f"0000000000401{i:03x} T sym{i}" for i in range(10)
)

# 8 defined symbols (LTO eliminated 2).
_NM_BODY_8 = "\n".join(
    f"0000000000401{i:03x} T sym{i}" for i in range(8)
)


def _fake_readelf_script(body):
    return (
        "#!/usr/bin/env python3\n"
        "import sys\n"
        f"sys.stdout.write({body!r})\n"
    )


def _fake_nm_script(body):
    return (
        "#!/usr/bin/env python3\n"
        "import sys\n"
        f"sys.stdout.write({body!r})\n"
    )


def _failing_script():
    return (
        "#!/usr/bin/env python3\n"
        "import sys\n"
        "sys.stderr.write('simulated tool failure\\n')\n"
        "sys.exit(1)\n"
    )


class _Base(unittest.TestCase):
    """Base class that creates and tears down a per-test work directory."""

    @classmethod
    def setUpClass(cls):
        root = os.environ.get("ELF_SIZE_DIFF_TEST_ROOT")
        cls.work = (
            Path(root)
            if root
            else REPO / ".cache" / f"elf-size-diff-tests-{os.getpid()}"
        ).resolve()
        cls.work.mkdir(parents=True, exist_ok=True)

    @classmethod
    def tearDownClass(cls):
        if not os.environ.get("ELF_SIZE_DIFF_TEST_ROOT"):
            shutil.rmtree(cls.work, ignore_errors=True)

    def setUp(self):
        self._mod = _load_diff()
        # Per-test subdirectory to avoid collisions.
        self._td = self.work / self.id().replace(".", "_")
        self._td.mkdir(parents=True, exist_ok=True)

    def _fake_elf(self, name, size=1024):
        """Create a dummy file of *size* bytes and return its Path."""
        path = self._td / name
        path.write_bytes(b"\x00" * size)
        return path

    def _tool(self, name, body):
        """Write a fake executable and return its path."""
        p = self._td / name
        _write_exe(p, body)
        return p

    def _readelf_cmd(self, body):
        p = self._tool("readelf.py", _fake_readelf_script(body))
        return shlex.quote(sys.executable) + " " + shlex.quote(str(p))

    def _nm_cmd(self, body):
        p = self._tool("nm.py", _fake_nm_script(body))
        return shlex.quote(sys.executable) + " " + shlex.quote(str(p))


class ParseSectionsTest(_Base):
    """Unit tests for read_sections()."""

    def _readelf(self, body):
        p = self._tool("re.py", _fake_readelf_script(body))
        return [sys.executable, str(p)]

    def test_parses_all_four_tracked_sections(self):
        secs = self._mod.read_sections(self._readelf(_READELF_BODY_A), self._fake_elf("a.elf"))
        self.assertEqual(secs[".text"], 0x1000)
        self.assertEqual(secs[".rodata"], 0x200)
        self.assertEqual(secs[".data"], 0x100)
        self.assertEqual(secs[".bss"], 0x80)

    def test_missing_section_absent_from_dict(self):
        # _READELF_BODY_B has no .bss.
        secs = self._mod.read_sections(self._readelf(_READELF_BODY_B), self._fake_elf("b.elf"))
        self.assertNotIn(".bss", secs)

    def test_malformed_size_field_raises_value_error(self):
        with self.assertRaises(ValueError) as ctx:
            self._mod.read_sections(self._readelf(_READELF_BODY_BAD), self._fake_elf("bad.elf"))
        self.assertIn("ZZZZZZ", str(ctx.exception))

    def test_elf_path_with_spaces_is_forwarded_correctly(self):
        spaced = self._td / "my elf with spaces.elf"
        spaced.write_bytes(b"\x00" * 256)
        # The fake readelf ignores arguments; we just verify no exception.
        secs = self._mod.read_sections(self._readelf(_READELF_BODY_A), spaced)
        self.assertIn(".text", secs)

    def test_tool_failure_raises_called_process_error(self):
        bad_re = self._tool("bad_re.py", _failing_script())
        import subprocess
        with self.assertRaises(subprocess.CalledProcessError):
            self._mod.read_sections([sys.executable, str(bad_re)], self._fake_elf("x.elf"))


class ComputeDeltaTest(_Base):
    """Unit tests for compute_delta()."""

    def test_negative_delta(self):
        delta, pct = self._mod.compute_delta(1000, 800)
        self.assertEqual(delta, -200)
        self.assertAlmostEqual(pct, -20.0)

    def test_positive_delta(self):
        delta, pct = self._mod.compute_delta(800, 1000)
        self.assertEqual(delta, 200)
        self.assertAlmostEqual(pct, 25.0)

    def test_zero_delta(self):
        delta, pct = self._mod.compute_delta(500, 500)
        self.assertEqual(delta, 0)
        self.assertAlmostEqual(pct, 0.0)

    def test_zero_baseline_yields_none_pct(self):
        delta, pct = self._mod.compute_delta(0, 0)
        self.assertEqual(delta, 0)
        self.assertIsNone(pct)

    def test_zero_baseline_nonzero_lto_yields_none_pct(self):
        delta, pct = self._mod.compute_delta(0, 100)
        self.assertEqual(delta, 100)
        self.assertIsNone(pct)

    def test_percentage_rounds_to_two_decimal_places(self):
        # 1/3 ≈ 33.33%
        _, pct = self._mod.compute_delta(300, 400)
        self.assertEqual(pct, round(100 / 3, 2))


class MetricsOrderTest(_Base):
    """Verify that compare() preserves the declared METRICS_ORDER."""

    def _fake_readelf(self, body):
        p = self._tool("re_ord.py", _fake_readelf_script(body))
        return [sys.executable, str(p)]

    def _fake_nm(self, body):
        p = self._tool("nm_ord.py", _fake_nm_script(body))
        return [sys.executable, str(p)]

    def test_metrics_order_matches_constant(self):
        belf = self._fake_elf("b.elf", 2000)
        lelf = self._fake_elf("l.elf", 1600)
        re_cmd = self._fake_readelf(_READELF_BODY_A)
        nm_cmd = self._fake_nm(_NM_BODY_10)
        b_metrics = self._mod.gather_metrics(re_cmd, nm_cmd, belf)
        l_metrics = self._mod.gather_metrics(re_cmd, nm_cmd, lelf)
        comparison = self._mod.compare(b_metrics, l_metrics)
        self.assertEqual(list(comparison.keys()), list(self._mod.METRICS_ORDER))


class GatherMetricsTest(_Base):
    """Tests for gather_metrics() combining readelf + nm + file size."""

    def _re(self, body):
        p = self._tool("re_gm.py", _fake_readelf_script(body))
        return [sys.executable, str(p)]

    def _nm(self, body):
        p = self._tool("nm_gm.py", _fake_nm_script(body))
        return [sys.executable, str(p)]

    def test_file_size_matches_actual_file(self):
        elf = self._fake_elf("sized.elf", 3000)
        metrics = self._mod.gather_metrics(self._re(_READELF_BODY_A), self._nm(_NM_BODY_10), elf)
        self.assertEqual(metrics["file_size"], 3000)

    def test_missing_section_defaults_to_zero(self):
        elf = self._fake_elf("nobss.elf")
        metrics = self._mod.gather_metrics(self._re(_READELF_BODY_B), self._nm(_NM_BODY_8), elf)
        self.assertEqual(metrics[".bss"], 0)

    def test_symbol_count_is_line_count(self):
        elf = self._fake_elf("sym.elf")
        metrics = self._mod.gather_metrics(self._re(_READELF_BODY_A), self._nm(_NM_BODY_10), elf)
        self.assertEqual(metrics["symbol_count"], 10)

    def test_nm_failure_raises(self):
        elf = self._fake_elf("fail.elf")
        bad_nm = self._tool("bad_nm.py", _failing_script())
        with self.assertRaises(subprocess.CalledProcessError):
            self._mod.gather_metrics(
                self._re(_READELF_BODY_A),
                [sys.executable, str(bad_nm)],
                elf,
            )


class CLIJsonTest(_Base):
    """Integration tests for the JSON output format."""

    def _run(self, *args):
        return subprocess.run(
            [sys.executable, str(_DIFF_SCRIPT), *args],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

    def _setup(self, baseline_size, lto_size, re_body_b, re_body_l, nm_b, nm_l):
        """Create two fake ELFs and their dedicated fake tools."""
        belf = self._td / "baseline.elf"
        lelf = self._td / "lto.elf"
        belf.write_bytes(b"\x00" * baseline_size)
        lelf.write_bytes(b"\x00" * lto_size)

        re_b = self._tool("re_b.py", _fake_readelf_script(re_body_b))
        re_l = self._tool("re_l.py", _fake_readelf_script(re_body_l))
        nm_b_p = self._tool("nm_b.py", _fake_nm_script(nm_b))
        nm_l_p = self._tool("nm_l.py", _fake_nm_script(nm_l))

        # Use a wrapper readelf that dispatches on the ELF argument.
        dispatch_re = self._td / "dispatch_re.py"
        _write_exe(
            dispatch_re,
            f"#!/usr/bin/env python3\n"
            f"import subprocess, sys\n"
            f"arg = sys.argv[-1]\n"
            f"if arg == {str(belf)!r}:\n"
            f"    subprocess.run([sys.executable, {str(re_b)!r}] + sys.argv[1:])\n"
            f"else:\n"
            f"    subprocess.run([sys.executable, {str(re_l)!r}] + sys.argv[1:])\n",
        )
        dispatch_nm = self._td / "dispatch_nm.py"
        _write_exe(
            dispatch_nm,
            f"#!/usr/bin/env python3\n"
            f"import subprocess, sys\n"
            f"arg = sys.argv[-1]\n"
            f"if arg == {str(belf)!r}:\n"
            f"    subprocess.run([sys.executable, {str(nm_b_p)!r}] + sys.argv[1:])\n"
            f"else:\n"
            f"    subprocess.run([sys.executable, {str(nm_l_p)!r}] + sys.argv[1:])\n",
        )
        re_cmd = shlex.quote(sys.executable) + " " + shlex.quote(str(dispatch_re))
        nm_cmd = shlex.quote(sys.executable) + " " + shlex.quote(str(dispatch_nm))
        return belf, lelf, re_cmd, nm_cmd

    def test_json_contains_all_metrics(self):
        belf, lelf, re_cmd, nm_cmd = self._setup(
            2048, 1600, _READELF_BODY_A, _READELF_BODY_B, _NM_BODY_10, _NM_BODY_8
        )
        result = self._run(
            "--json",
            "--readelf", re_cmd,
            "--nm", nm_cmd,
            str(belf),
            str(lelf),
        )
        data = json.loads(result.stdout)
        self.assertIn("baseline", data)
        self.assertIn("lto", data)
        metrics = data["metrics"]
        for key in ("file_size", ".text", ".rodata", ".data", ".bss", "symbol_count"):
            self.assertIn(key, metrics, f"metric {key!r} missing from JSON")

    def test_json_file_size_delta(self):
        belf, lelf, re_cmd, nm_cmd = self._setup(
            2048, 1600, _READELF_BODY_A, _READELF_BODY_B, _NM_BODY_10, _NM_BODY_8
        )
        result = self._run(
            "--json",
            "--readelf", re_cmd,
            "--nm", nm_cmd,
            str(belf),
            str(lelf),
        )
        data = json.loads(result.stdout)
        fs = data["metrics"]["file_size"]
        self.assertEqual(fs["baseline"], 2048)
        self.assertEqual(fs["lto"], 1600)
        self.assertEqual(fs["delta"], -448)
        self.assertAlmostEqual(fs["pct"], round(-448 / 2048 * 100, 2))

    def test_json_zero_baseline_section_pct_is_null(self):
        # Build a readelf that reports .bss = 0 for baseline and 0 for LTO.
        belf, lelf, re_cmd, nm_cmd = self._setup(
            1000, 1000, _READELF_BODY_B, _READELF_BODY_B, _NM_BODY_8, _NM_BODY_8
        )
        result = self._run(
            "--json",
            "--readelf", re_cmd,
            "--nm", nm_cmd,
            str(belf),
            str(lelf),
        )
        data = json.loads(result.stdout)
        # .bss is absent from _READELF_BODY_B so gather_metrics returns 0.
        self.assertIsNone(data["metrics"][".bss"]["pct"])

    def test_json_text_section_delta(self):
        # baseline .text = 0x1000 = 4096, lto .text = 0x0c00 = 3072
        belf, lelf, re_cmd, nm_cmd = self._setup(
            4096, 3072, _READELF_BODY_A, _READELF_BODY_B, _NM_BODY_10, _NM_BODY_8
        )
        result = self._run(
            "--json",
            "--readelf", re_cmd,
            "--nm", nm_cmd,
            str(belf),
            str(lelf),
        )
        data = json.loads(result.stdout)
        text = data["metrics"][".text"]
        self.assertEqual(text["baseline"], 0x1000)
        self.assertEqual(text["lto"], 0x0C00)
        self.assertEqual(text["delta"], -1024)

    def test_symbol_count_delta(self):
        belf, lelf, re_cmd, nm_cmd = self._setup(
            1000, 1000, _READELF_BODY_A, _READELF_BODY_B, _NM_BODY_10, _NM_BODY_8
        )
        result = self._run(
            "--json",
            "--readelf", re_cmd,
            "--nm", nm_cmd,
            str(belf),
            str(lelf),
        )
        data = json.loads(result.stdout)
        sc = data["metrics"]["symbol_count"]
        self.assertEqual(sc["baseline"], 10)
        self.assertEqual(sc["lto"], 8)
        self.assertEqual(sc["delta"], -2)


class CLITableTest(_Base):
    """Integration tests for the human-readable table output."""

    def _run_table(self, belf, lelf, re_cmd, nm_cmd):
        return subprocess.run(
            [
                sys.executable, str(_DIFF_SCRIPT),
                "--readelf", re_cmd,
                "--nm", nm_cmd,
                str(belf),
                str(lelf),
            ],
            check=True,
            stdout=subprocess.PIPE,
            text=True,
        )

    def test_table_has_header_and_separator(self):
        belf = self._td / "b.elf"
        lelf = self._td / "l.elf"
        belf.write_bytes(b"\x00" * 512)
        lelf.write_bytes(b"\x00" * 512)
        re_p = self._tool("re_tbl.py", _fake_readelf_script(_READELF_BODY_A))
        nm_p = self._tool("nm_tbl.py", _fake_nm_script(_NM_BODY_8))
        re_cmd = shlex.quote(sys.executable) + " " + shlex.quote(str(re_p))
        nm_cmd = shlex.quote(sys.executable) + " " + shlex.quote(str(nm_p))
        out = self._run_table(belf, lelf, re_cmd, nm_cmd).stdout
        self.assertIn("Metric", out)
        self.assertIn("Baseline", out)
        self.assertIn("Delta", out)
        self.assertIn("%Delta", out)
        self.assertIn("file_size", out)
        self.assertIn(".text", out)

    def test_table_na_for_zero_baseline(self):
        belf = self._td / "bz.elf"
        lelf = self._td / "lz.elf"
        belf.write_bytes(b"\x00" * 512)
        lelf.write_bytes(b"\x00" * 512)
        re_p = self._tool("re_na.py", _fake_readelf_script(_READELF_BODY_B))
        nm_p = self._tool("nm_na.py", _fake_nm_script(_NM_BODY_8))
        re_cmd = shlex.quote(sys.executable) + " " + shlex.quote(str(re_p))
        nm_cmd = shlex.quote(sys.executable) + " " + shlex.quote(str(nm_p))
        out = self._run_table(belf, lelf, re_cmd, nm_cmd).stdout
        self.assertIn("N/A", out)


class CLISpacesTest(_Base):
    """Verify that spaces in ELF paths and tool paths are handled correctly."""

    def test_spaces_in_elf_paths(self):
        spaced_b = self._td / "baseline file with spaces.elf"
        spaced_l = self._td / "lto file with spaces.elf"
        spaced_b.write_bytes(b"\x00" * 512)
        spaced_l.write_bytes(b"\x00" * 512)
        re_p = self._tool("re_sp.py", _fake_readelf_script(_READELF_BODY_A))
        nm_p = self._tool("nm_sp.py", _fake_nm_script(_NM_BODY_8))
        re_cmd = shlex.quote(sys.executable) + " " + shlex.quote(str(re_p))
        nm_cmd = shlex.quote(sys.executable) + " " + shlex.quote(str(nm_p))
        result = subprocess.run(
            [
                sys.executable, str(_DIFF_SCRIPT),
                "--json",
                "--readelf", re_cmd,
                "--nm", nm_cmd,
                str(spaced_b),
                str(spaced_l),
            ],
            check=True,
            stdout=subprocess.PIPE,
            text=True,
        )
        data = json.loads(result.stdout)
        self.assertIn("spaces", data["baseline"])
        self.assertIn("spaces", data["lto"])

    def test_spaces_in_tool_path(self):
        """A tool command with spaces in the script path must work."""
        # Place the fake scripts inside a subdirectory whose name has a space.
        spaced_dir = self._td / "tool dir with spaces"
        spaced_dir.mkdir(parents=True, exist_ok=True)
        re_p = spaced_dir / "readelf tool.py"
        nm_p = spaced_dir / "nm tool.py"
        _write_exe(re_p, _fake_readelf_script(_READELF_BODY_A))
        _write_exe(nm_p, _fake_nm_script(_NM_BODY_8))
        re_cmd = shlex.quote(sys.executable) + " " + shlex.quote(str(re_p))
        nm_cmd = shlex.quote(sys.executable) + " " + shlex.quote(str(nm_p))
        belf = self._td / "b_sp.elf"
        lelf = self._td / "l_sp.elf"
        belf.write_bytes(b"\x00" * 512)
        lelf.write_bytes(b"\x00" * 512)
        result = subprocess.run(
            [
                sys.executable, str(_DIFF_SCRIPT),
                "--json",
                "--readelf", re_cmd,
                "--nm", nm_cmd,
                str(belf),
                str(lelf),
            ],
            check=True,
            stdout=subprocess.PIPE,
            text=True,
        )
        self.assertIn("metrics", json.loads(result.stdout))


class CLIFailureTest(_Base):
    """Verify that tool failures propagate as non-zero exit codes."""

    def test_readelf_failure_exits_nonzero(self):
        belf = self._td / "be.elf"
        lelf = self._td / "le.elf"
        belf.write_bytes(b"\x00" * 64)
        lelf.write_bytes(b"\x00" * 64)
        bad = self._tool("bad_re_cli.py", _failing_script())
        nm_p = self._tool("nm_fe.py", _fake_nm_script(_NM_BODY_8))
        re_cmd = shlex.quote(sys.executable) + " " + shlex.quote(str(bad))
        nm_cmd = shlex.quote(sys.executable) + " " + shlex.quote(str(nm_p))
        proc = subprocess.run(
            [
                sys.executable, str(_DIFF_SCRIPT),
                "--readelf", re_cmd,
                "--nm", nm_cmd,
                str(belf),
                str(lelf),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.assertNotEqual(proc.returncode, 0)

    def test_nm_failure_exits_nonzero(self):
        belf = self._td / "bn.elf"
        lelf = self._td / "ln.elf"
        belf.write_bytes(b"\x00" * 64)
        lelf.write_bytes(b"\x00" * 64)
        re_p = self._tool("re_nf.py", _fake_readelf_script(_READELF_BODY_A))
        bad = self._tool("bad_nm_cli.py", _failing_script())
        re_cmd = shlex.quote(sys.executable) + " " + shlex.quote(str(re_p))
        nm_cmd = shlex.quote(sys.executable) + " " + shlex.quote(str(bad))
        proc = subprocess.run(
            [
                sys.executable, str(_DIFF_SCRIPT),
                "--readelf", re_cmd,
                "--nm", nm_cmd,
                str(belf),
                str(lelf),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.assertNotEqual(proc.returncode, 0)

    def test_malformed_readelf_output_exits_nonzero(self):
        belf = self._td / "bm.elf"
        lelf = self._td / "lm.elf"
        belf.write_bytes(b"\x00" * 64)
        lelf.write_bytes(b"\x00" * 64)
        re_p = self._tool("re_bad.py", _fake_readelf_script(_READELF_BODY_BAD))
        nm_p = self._tool("nm_bad.py", _fake_nm_script(_NM_BODY_8))
        re_cmd = shlex.quote(sys.executable) + " " + shlex.quote(str(re_p))
        nm_cmd = shlex.quote(sys.executable) + " " + shlex.quote(str(nm_p))
        proc = subprocess.run(
            [
                sys.executable, str(_DIFF_SCRIPT),
                "--readelf", re_cmd,
                "--nm", nm_cmd,
                str(belf),
                str(lelf),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.assertNotEqual(proc.returncode, 0)


class CLIErrorFormatTest(_Base):
    """Errors at the CLI boundary emit 'error:' prefix without tracebacks."""

    def _run(self, *args):
        return subprocess.run(
            [sys.executable, str(_DIFF_SCRIPT), *args],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

    def _assert_clean_error(self, proc):
        self.assertNotEqual(proc.returncode, 0)
        combined = proc.stdout + proc.stderr
        self.assertIn("error:", combined.lower(), "expected 'error:' prefix in output")
        self.assertNotIn("Traceback", combined, "unexpected traceback in output")

    def test_missing_elf_emits_clean_error(self):
        proc = self._run(
            "--readelf", "readelf",
            "--nm", "nm",
            "/nonexistent/baseline.elf",
            "/nonexistent/lto.elf",
        )
        self._assert_clean_error(proc)

    def test_readelf_failure_emits_clean_error(self):
        belf = self._td / "b_ef.elf"
        lelf = self._td / "l_ef.elf"
        belf.write_bytes(b"\x00" * 64)
        lelf.write_bytes(b"\x00" * 64)
        bad = self._tool("re_ef.py", _failing_script())
        nm_p = self._tool("nm_ef.py", _fake_nm_script(_NM_BODY_8))
        proc = self._run(
            "--readelf", shlex.quote(sys.executable) + " " + shlex.quote(str(bad)),
            "--nm", shlex.quote(sys.executable) + " " + shlex.quote(str(nm_p)),
            str(belf), str(lelf),
        )
        self._assert_clean_error(proc)

    def test_nm_failure_emits_clean_error(self):
        belf = self._td / "b_nf.elf"
        lelf = self._td / "l_nf.elf"
        belf.write_bytes(b"\x00" * 64)
        lelf.write_bytes(b"\x00" * 64)
        re_p = self._tool("re_nf.py", _fake_readelf_script(_READELF_BODY_A))
        bad = self._tool("nm_nf.py", _failing_script())
        proc = self._run(
            "--readelf", shlex.quote(sys.executable) + " " + shlex.quote(str(re_p)),
            "--nm", shlex.quote(sys.executable) + " " + shlex.quote(str(bad)),
            str(belf), str(lelf),
        )
        self._assert_clean_error(proc)

    def test_malformed_readelf_output_emits_clean_error(self):
        belf = self._td / "b_mf.elf"
        lelf = self._td / "l_mf.elf"
        belf.write_bytes(b"\x00" * 64)
        lelf.write_bytes(b"\x00" * 64)
        re_p = self._tool("re_mf.py", _fake_readelf_script(_READELF_BODY_BAD))
        nm_p = self._tool("nm_mf.py", _fake_nm_script(_NM_BODY_8))
        proc = self._run(
            "--readelf", shlex.quote(sys.executable) + " " + shlex.quote(str(re_p)),
            "--nm", shlex.quote(sys.executable) + " " + shlex.quote(str(nm_p)),
            str(belf), str(lelf),
        )
        self._assert_clean_error(proc)


if __name__ == "__main__":
    unittest.main()
