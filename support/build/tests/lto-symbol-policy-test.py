#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause

"""Tests for lto-symbol-policy.py."""

import os
import stat
import sys
import tempfile
import textwrap
import unittest

sys.path.insert(
    0, os.path.join(os.path.dirname(__file__), os.pardir, os.pardir)
)

# Import the module under test.
import importlib.util

_SCRIPT = os.path.join(os.path.dirname(__file__), os.pardir, "lto-symbol-policy.py")
_spec = importlib.util.spec_from_file_location("lto_symbol_policy", _SCRIPT)
policy = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(policy)


class TestParseLibrarySpecs(unittest.TestCase):
    def test_single_library(self):
        specs = policy.parse_library_specs(
            ["--library", "libfoo", "--input", "a.o", "--input", "b.o"]
        )
        self.assertEqual(len(specs), 1)
        self.assertEqual(specs[0]["name"], "libfoo")
        self.assertEqual(specs[0]["inputs"], ["a.o", "b.o"])
        self.assertEqual(specs[0]["export_files"], [])

    def test_library_with_exports(self):
        specs = policy.parse_library_specs(
            [
                "--library",
                "libfoo",
                "--export-file",
                "exports.uk",
                "--input",
                "a.o",
            ]
        )
        self.assertEqual(specs[0]["export_files"], ["exports.uk"])

    def test_multiple_libraries(self):
        specs = policy.parse_library_specs(
            [
                "--library",
                "libA",
                "--input",
                "a.o",
                "--library",
                "libB",
                "--export-file",
                "b.uk",
                "--input",
                "b.o",
            ]
        )
        self.assertEqual(len(specs), 2)
        self.assertEqual(specs[0]["name"], "libA")
        self.assertEqual(specs[1]["name"], "libB")
        self.assertEqual(specs[1]["export_files"], ["b.uk"])


class TestReadExportSymbols(unittest.TestCase):
    def _write(self, content):
        fd, path = tempfile.mkstemp(suffix=".uk")
        os.write(fd, content.encode())
        os.close(fd)
        self.addCleanup(os.unlink, path)
        return path

    def test_basic(self):
        path = self._write("foo\nbar\nbaz\n")
        syms = policy.read_export_symbols(path)
        self.assertEqual(syms, {"foo", "bar", "baz"})

    def test_comments_and_blanks(self):
        path = self._write("# comment\nfoo\n\n# another\nbar\n")
        syms = policy.read_export_symbols(path)
        self.assertEqual(syms, {"foo", "bar"})

    def test_trailing_whitespace(self):
        path = self._write("foo  \nbar\t\n")
        syms = policy.read_export_symbols(path)
        self.assertEqual(syms, {"foo", "bar"})

    def test_shared_export_file(self):
        """Two libraries sharing the same export file path is valid."""
        path = self._write("shared_sym\n")
        syms1 = policy.read_export_symbols(path)
        syms2 = policy.read_export_symbols(path)
        self.assertEqual(syms1, syms2)


class TestParseNmOutput(unittest.TestCase):
    def test_posix_format(self):
        output = textwrap.dedent("""\
            foo T
            bar D
            baz U
        """)
        result = policy.parse_nm_output(output)
        self.assertEqual(result, {"foo": "T", "bar": "D", "baz": "U"})

    def test_empty_output(self):
        self.assertEqual(policy.parse_nm_output(""), {})
        self.assertEqual(policy.parse_nm_output("\n\n"), {})

    def test_malformed_lines_skipped(self):
        output = "foo T\n!!garbage!!\nbar D\n"
        result = policy.parse_nm_output(output)
        self.assertEqual(result, {"foo": "T", "bar": "D"})


class TestQuoteVersionScriptSymbol(unittest.TestCase):
    def test_plain_identifier(self):
        self.assertEqual(policy.quote_version_script_symbol("foo"), "foo")
        self.assertEqual(
            policy.quote_version_script_symbol("_start"), "_start"
        )
        self.assertEqual(
            policy.quote_version_script_symbol("foo.bar"), "foo.bar"
        )
        self.assertEqual(
            policy.quote_version_script_symbol("foo$bar"), "foo$bar"
        )

    def test_needs_quoting(self):
        self.assertEqual(
            policy.quote_version_script_symbol("foo bar"), '"foo bar"'
        )
        self.assertEqual(
            policy.quote_version_script_symbol('foo"bar'), '"foo\\"bar"'
        )

    def test_leading_digit(self):
        self.assertEqual(
            policy.quote_version_script_symbol("0foo"), '"0foo"'
        )


class TestGenerateVersionScript(unittest.TestCase):
    def test_deterministic_order(self):
        script1 = policy.generate_version_script(["b_sym", "a_sym", "c_sym"])
        script2 = policy.generate_version_script(["b_sym", "a_sym", "c_sym"])
        self.assertEqual(script1, script2)
        # Symbols are listed in the order provided (pre-sorted by caller).
        self.assertIn("b_sym", script1)
        self.assertIn("local:", script1)
        self.assertIn("*;", script1)

    def test_empty_globals(self):
        script = policy.generate_version_script([])
        self.assertIn("global:", script)
        self.assertIn("local:", script)
        self.assertIn("*;", script)

    def test_quoting_in_script(self):
        script = policy.generate_version_script(["normal", "has space"])
        self.assertIn("normal;", script)
        self.assertIn('"has space";', script)


class TestValidateAndGenerate(unittest.TestCase):
    """Test the core validation logic using a mock NM tool."""

    def setUp(self):
        self._tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        import shutil

        shutil.rmtree(self._tmpdir)

    def _write(self, name, content):
        path = os.path.join(self._tmpdir, name)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            f.write(content)
        return path

    def _make_mock_nm(self, mapping):
        """Create a mock NM script that returns canned output per input file.

        mapping: {absolute_path: "nm_output_string"}
        """
        cases = []
        for path, output in mapping.items():
            escaped_path = path.replace("\\", "\\\\").replace("'", "'\\''")
            escaped_output = output.replace("\\", "\\\\").replace("'", "'\\''")
            cases.append(
                f"    '{escaped_path}') echo '{escaped_output}' ;;"
            )
        script_content = "#!/bin/sh\n"
        script_content += "# Mock NM — returns canned output for last arg.\n"
        script_content += 'INPUT="${@: -1}"\n'
        script_content += 'case "$INPUT" in\n'
        script_content += "\n".join(cases) + "\n"
        script_content += "    *) echo 'error: unknown input' >&2; exit 1 ;;\n"
        script_content += "esac\n"
        path = os.path.join(self._tmpdir, "mock-nm")
        with open(path, "w") as f:
            f.write(script_content)
        os.chmod(path, os.stat(path).st_mode | stat.S_IEXEC)
        return path

    def test_distinct_export_files_no_collision(self):
        """Two libraries with distinct exports — no collision."""
        exports_a = self._write("a_exports.uk", "api_a\n")
        exports_b = self._write("b_exports.uk", "api_b\n")
        obj_a = self._write("a.o", "")
        obj_b = self._write("b.o", "")
        nm = self._make_mock_nm(
            {
                obj_a: "api_a T\nhelper_a T",
                obj_b: "api_b T\nhelper_b T",
            }
        )
        libs = [
            {
                "name": "libA",
                "export_files": [exports_a],
                "inputs": [obj_a],
            },
            {
                "name": "libB",
                "export_files": [exports_b],
                "inputs": [obj_b],
            },
        ]
        globals_, errors = policy.validate_and_generate(nm, libs)
        self.assertEqual(errors, [])
        self.assertIn("api_a", globals_)
        self.assertIn("api_b", globals_)
        self.assertNotIn("helper_a", globals_)
        self.assertNotIn("helper_b", globals_)

    def test_shared_export_file_path(self):
        """Two libraries sharing the same export file — valid."""
        shared = self._write("shared.uk", "shared_api\n")
        obj_a = self._write("a.o", "")
        obj_b = self._write("b.o", "")
        nm = self._make_mock_nm(
            {
                obj_a: "shared_api T\npriv_a T",
                obj_b: "shared_api T\npriv_b T",
            }
        )
        libs = [
            {
                "name": "libA",
                "export_files": [shared],
                "inputs": [obj_a],
            },
            {
                "name": "libB",
                "export_files": [shared],
                "inputs": [obj_b],
            },
        ]
        globals_, errors = policy.validate_and_generate(nm, libs)
        self.assertEqual(errors, [])
        self.assertIn("shared_api", globals_)

    def test_distinct_files_sharing_symbol_names(self):
        """Two distinct export files both exporting same symbol — valid
        (both make it global; linker resolves multiple definitions)."""
        exports_a = self._write("a.uk", "common_sym\n")
        exports_b = self._write("b.uk", "common_sym\n")
        obj_a = self._write("a.o", "")
        obj_b = self._write("b.o", "")
        nm = self._make_mock_nm(
            {
                obj_a: "common_sym T",
                obj_b: "common_sym T",
            }
        )
        libs = [
            {
                "name": "libA",
                "export_files": [exports_a],
                "inputs": [obj_a],
            },
            {
                "name": "libB",
                "export_files": [exports_b],
                "inputs": [obj_b],
            },
        ]
        globals_, errors = policy.validate_and_generate(nm, libs)
        self.assertEqual(errors, [])
        self.assertIn("common_sym", globals_)

    def test_private_collision_detected(self):
        """Two libraries with private definitions of the same symbol."""
        exports_a = self._write("a.uk", "api_a\n")
        exports_b = self._write("b.uk", "api_b\n")
        obj_a = self._write("a.o", "")
        obj_b = self._write("b.o", "")
        nm = self._make_mock_nm(
            {
                obj_a: "api_a T\nclash T",
                obj_b: "api_b T\nclash T",
            }
        )
        libs = [
            {
                "name": "libA",
                "export_files": [exports_a],
                "inputs": [obj_a],
            },
            {
                "name": "libB",
                "export_files": [exports_b],
                "inputs": [obj_b],
            },
        ]
        globals_, errors = policy.validate_and_generate(nm, libs)
        self.assertTrue(len(errors) > 0)
        self.assertTrue(any("clash" in e for e in errors))

    def test_cross_library_private_reference_detected(self):
        """Library A references a private symbol from library B."""
        exports_b = self._write("b.uk", "api_b\n")
        obj_a = self._write("a.o", "")
        obj_b = self._write("b.o", "")
        nm = self._make_mock_nm(
            {
                obj_a: "helper_b U",
                obj_b: "api_b T\nhelper_b T",
            }
        )
        libs = [
            {
                "name": "libA",
                "export_files": [],
                "inputs": [obj_a],
            },
            {
                "name": "libB",
                "export_files": [exports_b],
                "inputs": [obj_b],
            },
        ]
        globals_, errors = policy.validate_and_generate(nm, libs)
        self.assertTrue(len(errors) > 0)
        self.assertTrue(any("helper_b" in e for e in errors))
        self.assertTrue(any("libA" in e and "libB" in e for e in errors))

    def test_library_without_exports_all_global(self):
        """Library without export list — all symbols are global."""
        exports_b = self._write("b.uk", "api_b\n")
        obj_a = self._write("a.o", "")
        obj_b = self._write("b.o", "")
        nm = self._make_mock_nm(
            {
                obj_a: "everything T\nglobal_too T",
                obj_b: "api_b T\npriv_b T",
            }
        )
        libs = [
            {
                "name": "libA",
                "export_files": [],
                "inputs": [obj_a],
            },
            {
                "name": "libB",
                "export_files": [exports_b],
                "inputs": [obj_b],
            },
        ]
        globals_, errors = policy.validate_and_generate(nm, libs)
        self.assertEqual(errors, [])
        self.assertIn("everything", globals_)
        self.assertIn("global_too", globals_)
        self.assertIn("api_b", globals_)
        self.assertNotIn("priv_b", globals_)

    def test_nm_tool_failure(self):
        """NM tool failure produces exit code 2."""
        obj = self._write("bad.o", "")
        bad_nm = self._write("bad-nm", "#!/bin/sh\nexit 1\n")
        os.chmod(bad_nm, os.stat(bad_nm).st_mode | stat.S_IEXEC)
        libs = [
            {
                "name": "libBad",
                "export_files": [],
                "inputs": [obj],
            },
        ]
        with self.assertRaises(SystemExit) as cm:
            policy.validate_and_generate(bad_nm, libs)
        self.assertEqual(cm.exception.code, 2)

    def test_paths_with_spaces(self):
        """Paths containing spaces work correctly."""
        exports = self._write("my lib/exports.uk", "my_sym\n")
        obj = self._write("my lib/code.o", "")
        nm = self._make_mock_nm({obj: "my_sym T\npriv T"})
        libs = [
            {
                "name": "my lib",
                "export_files": [exports],
                "inputs": [obj],
            },
        ]
        globals_, errors = policy.validate_and_generate(nm, libs)
        self.assertEqual(errors, [])
        self.assertIn("my_sym", globals_)

    def test_deterministic_output_order(self):
        """Generated globals are sorted deterministically."""
        exports = self._write("e.uk", "z_sym\na_sym\nm_sym\n")
        obj = self._write("x.o", "")
        nm = self._make_mock_nm({obj: "z_sym T\na_sym T\nm_sym T"})
        libs = [
            {
                "name": "libX",
                "export_files": [exports],
                "inputs": [obj],
            },
        ]
        globals_, errors = policy.validate_and_generate(nm, libs)
        self.assertEqual(errors, [])
        self.assertEqual(globals_, ["a_sym", "m_sym", "z_sym"])


class TestMainIntegration(unittest.TestCase):
    def setUp(self):
        self._tmpdir = tempfile.mkdtemp()

    def tearDown(self):
        import shutil

        shutil.rmtree(self._tmpdir)

    def _write(self, name, content, executable=False):
        path = os.path.join(self._tmpdir, name)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            f.write(content)
        if executable:
            os.chmod(path, os.stat(path).st_mode | stat.S_IEXEC)
        return path

    def test_end_to_end(self):
        exports = self._write("exports.uk", "api_sym\n")
        obj = self._write("lib.o", "")
        output = os.path.join(self._tmpdir, "out", "policy.lds")
        nm = self._write(
            "nm",
            f"#!/bin/sh\necho 'api_sym T\npriv_sym T'\n",
            executable=True,
        )
        policy.main(
            [
                "--nm",
                nm,
                "--output",
                output,
                "--library",
                "libFoo",
                "--export-file",
                exports,
                "--input",
                obj,
            ]
        )
        self.assertTrue(os.path.exists(output))
        content = open(output).read()
        self.assertIn("api_sym", content)
        self.assertNotIn("priv_sym", content)
        self.assertIn("local:", content)
        self.assertIn("*;", content)

    def test_no_libraries(self):
        output = os.path.join(self._tmpdir, "empty.lds")
        policy.main(["--nm", "unused", "--output", output])
        self.assertTrue(os.path.exists(output))
        content = open(output).read()
        self.assertIn("local:", content)


if __name__ == "__main__":
    unittest.main()
