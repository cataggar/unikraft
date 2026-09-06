#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause

"""Tests for lto-symbol-policy.py."""

import os
import stat
import sys
import tempfile
import textwrap
import unittest

# Import the module under test.
import importlib.util

_SCRIPT = os.path.join(
    os.path.dirname(__file__), os.pardir, "lto-symbol-policy.py"
)
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

    def test_missing_file(self):
        """Missing export file exits with code 2."""
        with self.assertRaises(SystemExit) as cm:
            policy.read_export_symbols("/nonexistent/export.uk")
        self.assertEqual(cm.exception.code, 2)


class TestParseNmOutput(unittest.TestCase):
    def test_posix_format(self):
        output = "foo T\nbar D\nbaz U\n"
        result = policy.parse_nm_output(output)
        self.assertEqual(result, {"foo": "T", "bar": "D", "baz": "U"})

    def test_posix_with_value_and_size(self):
        output = "main T 0000000000001000 0000000000000040\n"
        result = policy.parse_nm_output(output)
        self.assertEqual(result, {"main": "T"})

    def test_empty_output(self):
        self.assertEqual(policy.parse_nm_output(""), {})
        self.assertEqual(policy.parse_nm_output("\n\n"), {})

    def test_archive_member_headings(self):
        output = (
            "/path/to/libfoo.a(bar.o):\n"
            "api_func T\n"
            "\n"
            "/path/to/libfoo.a(baz.o):\n"
            "other_func T\n"
        )
        result = policy.parse_nm_output(output)
        self.assertEqual(
            result, {"api_func": "T", "other_func": "T"}
        )

    def test_malformed_line_raises(self):
        output = "foo T\n!!garbage!!\nbar D\n"
        with self.assertRaises(policy.NmParseError) as cm:
            policy.parse_nm_output(output, path="test.o")
        self.assertIn("test.o", str(cm.exception))
        self.assertIn("line 2", str(cm.exception))

    def test_malformed_with_path_diagnostic(self):
        output = "bad line here\n"
        with self.assertRaises(policy.NmParseError) as cm:
            policy.parse_nm_output(output, path="/build/lib.o")
        self.assertIn("/build/lib.o", str(cm.exception))

    def test_archive_defined_then_undefined_preserves_definition(self):
        """Archive member 1 defines bar, member 2 references bar as U.
        The definition must dominate."""
        output = (
            "lib.a(def.o):\n"
            "bar T\n"
            "\n"
            "lib.a(ref.o):\n"
            "bar U\n"
        )
        result = policy.parse_nm_output(output)
        self.assertEqual(result["bar"], "T")

    def test_archive_undefined_then_defined_preserves_definition(self):
        """Archive member 1 references bar as U, member 2 defines bar.
        The definition must dominate regardless of order."""
        output = (
            "lib.a(ref.o):\n"
            "bar U\n"
            "\n"
            "lib.a(def.o):\n"
            "bar T\n"
        )
        result = policy.parse_nm_output(output)
        self.assertEqual(result["bar"], "T")

    def test_strong_defined_dominates_weak_defined(self):
        output = "sym W\nsym T\n"
        result = policy.parse_nm_output(output)
        self.assertEqual(result["sym"], "T")

    def test_weak_defined_dominates_undefined(self):
        output = "sym U\nsym W\n"
        result = policy.parse_nm_output(output)
        self.assertEqual(result["sym"], "W")

    def test_weak_undefined_stays_undefined(self):
        output = "sym w\n"
        result = policy.parse_nm_output(output)
        self.assertEqual(result["sym"], "w")


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
        script1 = policy.generate_version_script(["a_sym", "b_sym", "c_sym"])
        script2 = policy.generate_version_script(["a_sym", "b_sym", "c_sym"])
        self.assertEqual(script1, script2)
        self.assertIn("a_sym", script1)
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

    def test_no_non_ascii(self):
        script = policy.generate_version_script(["sym"])
        # Verify no non-ASCII bytes (e.g. em dashes).
        script.encode("ascii")  # Raises if non-ASCII present.


class TestGenerateForceKeepResponse(unittest.TestCase):
    def test_deterministic_arguments(self):
        response = policy.generate_force_keep_response(["z_sym", "a_sym"])
        self.assertEqual(
            response,
            '"-Wl,-u,a_sym"\n"-Wl,-u,z_sym"\n',
        )

    def test_response_argument_escaping(self):
        response = policy.generate_force_keep_response(
            ['has"quote', r"has\slash"]
        )
        self.assertIn(r'"-Wl,-u,has\"quote"', response)
        self.assertIn(r'"-Wl,-u,has\\slash"', response)


def _make_python_mock_nm(tmpdir, mapping):
    """Create a Python-based mock NM script.

    Portable: no shell required. Uses sys.executable.
    mapping: {absolute_path: "nm_output_string"}
    """
    lines = [
        "#!%s" % sys.executable,
        "import sys",
        "path = sys.argv[-1]",
        "mapping = {",
    ]
    for path, output in mapping.items():
        lines.append("    %r: %r," % (path, output))
    lines.append("}")
    lines.append("if path in mapping:")
    lines.append("    sys.stdout.write(mapping[path])")
    lines.append("else:")
    lines.append(
        "    sys.stderr.write('error: unknown input: %s\\n' % path)"
    )
    lines.append("    sys.exit(1)")

    nm_path = os.path.join(tmpdir, "mock-nm.py")
    with open(nm_path, "w") as f:
        f.write("\n".join(lines) + "\n")
    os.chmod(nm_path, os.stat(nm_path).st_mode | stat.S_IEXEC)
    return nm_path


class TestValidateAndGenerate(unittest.TestCase):
    """Test the core validation logic using a Python-based mock NM."""

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

    def _nm(self, mapping):
        return _make_python_mock_nm(self._tmpdir, mapping)

    def test_distinct_export_files_no_collision(self):
        exports_a = self._write("a_exports.uk", "api_a\n")
        exports_b = self._write("b_exports.uk", "api_b\n")
        obj_a = self._write("a.o", "")
        obj_b = self._write("b.o", "")
        nm = self._nm({
            obj_a: "api_a T\nhelper_a T\n",
            obj_b: "api_b T\nhelper_b T\n",
        })
        libs = [
            {"name": "libA", "export_files": [exports_a], "inputs": [obj_a]},
            {"name": "libB", "export_files": [exports_b], "inputs": [obj_b]},
        ]
        globals_, errors = policy.validate_and_generate(nm, libs)
        self.assertEqual(errors, [])
        self.assertIn("api_a", globals_)
        self.assertIn("api_b", globals_)
        self.assertNotIn("helper_a", globals_)
        self.assertNotIn("helper_b", globals_)

    def test_shared_export_file_path(self):
        shared = self._write("shared.uk", "shared_api\n")
        obj_a = self._write("a.o", "")
        obj_b = self._write("b.o", "")
        nm = self._nm({
            obj_a: "shared_api T\npriv_a T\n",
            obj_b: "shared_api T\npriv_b T\n",
        })
        libs = [
            {"name": "libA", "export_files": [shared], "inputs": [obj_a]},
            {"name": "libB", "export_files": [shared], "inputs": [obj_b]},
        ]
        globals_, errors = policy.validate_and_generate(nm, libs)
        # shared_api is global in both, but priv_a and priv_b are each
        # private in only one library -> no collision.
        self.assertEqual(errors, [])
        self.assertIn("shared_api", globals_)

    def test_distinct_files_sharing_symbol_names(self):
        exports_a = self._write("a.uk", "common_sym\n")
        exports_b = self._write("b.uk", "common_sym\n")
        obj_a = self._write("a.o", "")
        obj_b = self._write("b.o", "")
        nm = self._nm({
            obj_a: "common_sym T\n",
            obj_b: "common_sym T\n",
        })
        libs = [
            {"name": "libA", "export_files": [exports_a], "inputs": [obj_a]},
            {"name": "libB", "export_files": [exports_b], "inputs": [obj_b]},
        ]
        globals_, errors = policy.validate_and_generate(nm, libs)
        # Both global -- global+global is accepted.
        self.assertEqual(errors, [])
        self.assertIn("common_sym", globals_)

    def test_private_collision_detected(self):
        exports_a = self._write("a.uk", "api_a\n")
        exports_b = self._write("b.uk", "api_b\n")
        obj_a = self._write("a.o", "")
        obj_b = self._write("b.o", "")
        nm = self._nm({
            obj_a: "api_a T\nclash T\n",
            obj_b: "api_b T\nclash T\n",
        })
        libs = [
            {"name": "libA", "export_files": [exports_a], "inputs": [obj_a]},
            {"name": "libB", "export_files": [exports_b], "inputs": [obj_b]},
        ]
        globals_, errors = policy.validate_and_generate(nm, libs)
        self.assertTrue(len(errors) > 0)
        self.assertTrue(any("clash" in e for e in errors))

    def test_private_plus_global_collision_detected(self):
        """A symbol that is global in one library and private in another
        must be rejected: the standard pipeline permits local+global via
        per-library objcopy, but flat linking cannot represent this."""
        exports_a = self._write("a.uk", "shared\n")
        exports_b = self._write("b.uk", "other\n")
        obj_a = self._write("a.o", "")
        obj_b = self._write("b.o", "")
        nm = self._nm({
            obj_a: "shared T\n",
            obj_b: "shared T\nother T\n",
        })
        libs = [
            {"name": "libA", "export_files": [exports_a], "inputs": [obj_a]},
            {"name": "libB", "export_files": [exports_b], "inputs": [obj_b]},
        ]
        globals_, errors = policy.validate_and_generate(nm, libs)
        self.assertTrue(len(errors) > 0)
        self.assertTrue(any("shared" in e for e in errors))
        # Error should mention both libraries.
        err_text = " ".join(errors)
        self.assertIn("libA", err_text)
        self.assertIn("libB", err_text)

    def test_cross_library_private_reference_detected(self):
        exports_b = self._write("b.uk", "api_b\n")
        obj_a = self._write("a.o", "")
        obj_b = self._write("b.o", "")
        nm = self._nm({
            obj_a: "helper_b U\n",
            obj_b: "api_b T\nhelper_b T\n",
        })
        libs = [
            {"name": "libA", "export_files": [], "inputs": [obj_a]},
            {"name": "libB", "export_files": [exports_b], "inputs": [obj_b]},
        ]
        globals_, errors = policy.validate_and_generate(nm, libs)
        self.assertTrue(len(errors) > 0)
        self.assertTrue(any("helper_b" in e for e in errors))
        err_text = " ".join(errors)
        self.assertIn("libA", err_text)
        self.assertIn("libB", err_text)

    def test_library_without_exports_all_global(self):
        exports_b = self._write("b.uk", "api_b\n")
        obj_a = self._write("a.o", "")
        obj_b = self._write("b.o", "")
        nm = self._nm({
            obj_a: "everything T\nglobal_too T\n",
            obj_b: "api_b T\npriv_b T\n",
        })
        libs = [
            {"name": "libA", "export_files": [], "inputs": [obj_a]},
            {"name": "libB", "export_files": [exports_b], "inputs": [obj_b]},
        ]
        globals_, errors = policy.validate_and_generate(nm, libs)
        self.assertEqual(errors, [])
        self.assertIn("everything", globals_)
        self.assertIn("global_too", globals_)
        self.assertIn("api_b", globals_)
        self.assertNotIn("priv_b", globals_)

    def test_nm_tool_failure(self):
        obj = self._write("bad.o", "")
        bad_nm = self._write("bad-nm.py", (
            "#!%s\nimport sys\nsys.exit(1)\n" % sys.executable
        ))
        os.chmod(bad_nm, os.stat(bad_nm).st_mode | stat.S_IEXEC)
        libs = [
            {"name": "libBad", "export_files": [], "inputs": [obj]},
        ]
        with self.assertRaises(SystemExit) as cm:
            policy.validate_and_generate(bad_nm, libs)
        self.assertEqual(cm.exception.code, 2)

    def test_malformed_nm_output_fails(self):
        obj = self._write("m.o", "")
        nm = self._nm({obj: "foo T\n!!garbage!!\nbar D\n"})
        libs = [
            {"name": "libM", "export_files": [], "inputs": [obj]},
        ]
        with self.assertRaises(SystemExit) as cm:
            policy.validate_and_generate(nm, libs)
        self.assertEqual(cm.exception.code, 2)

    def test_archive_nm_output(self):
        obj = self._write("lib.a", "")
        nm = self._nm({
            obj: (
                "/path/lib.a(foo.o):\n"
                "foo_func T\n"
                "\n"
                "/path/lib.a(bar.o):\n"
                "bar_func T\n"
            ),
        })
        libs = [
            {"name": "libAr", "export_files": [], "inputs": [obj]},
        ]
        globals_, errors = policy.validate_and_generate(nm, libs)
        self.assertEqual(errors, [])
        self.assertIn("foo_func", globals_)
        self.assertIn("bar_func", globals_)

    def test_paths_with_spaces(self):
        exports = self._write("my lib/exports.uk", "my_sym\n")
        obj = self._write("my lib/code.o", "")
        nm = self._nm({obj: "my_sym T\npriv T\n"})
        libs = [
            {"name": "my lib", "export_files": [exports], "inputs": [obj]},
        ]
        globals_, errors = policy.validate_and_generate(nm, libs)
        self.assertEqual(errors, [])
        self.assertIn("my_sym", globals_)

    def test_deterministic_output_order(self):
        exports = self._write("e.uk", "z_sym\na_sym\nm_sym\n")
        obj = self._write("x.o", "")
        nm = self._nm({obj: "z_sym T\na_sym T\nm_sym T\n"})
        libs = [
            {"name": "libX", "export_files": [exports], "inputs": [obj]},
        ]
        globals_, errors = policy.validate_and_generate(nm, libs)
        self.assertEqual(errors, [])
        self.assertEqual(globals_, ["a_sym", "m_sym", "z_sym"])

    def test_archive_T_then_U_exported_global_preserved(self):
        """An archive where member 1 defines 'api' (T) and member 2
        references 'api' (U).  'api' is exported and must appear in
        the global set, not be misclassified as undefined."""
        exports = self._write("e.uk", "api\n")
        archive = self._write("lib.a", "")
        nm = self._nm({
            archive: (
                "lib.a(impl.o):\n"
                "api T\nhelper T\n"
                "\n"
                "lib.a(user.o):\n"
                "api U\nfoo T\n"
            ),
        })
        libs = [
            {"name": "libA", "export_files": [exports], "inputs": [archive]},
        ]
        globals_, errors = policy.validate_and_generate(nm, libs)
        self.assertEqual(errors, [])
        self.assertIn("api", globals_)

    def test_archive_U_then_T_no_false_cross_library_error(self):
        """Archive in libB: member 1 references 'helper' (U), member 2
        defines 'helper' (T).  'helper' is private in libB.  libA must
        NOT get a false cross-library private-reference error for
        'helper' since libB defines it internally."""
        exports_a = self._write("a.uk", "api_a\n")
        exports_b = self._write("b.uk", "api_b\n")
        obj_a = self._write("a.o", "")
        archive_b = self._write("b.a", "")
        nm = self._nm({
            obj_a: "api_a T\n",
            archive_b: (
                "b.a(ref.o):\n"
                "helper U\napi_b T\n"
                "\n"
                "b.a(def.o):\n"
                "helper T\n"
            ),
        })
        libs = [
            {"name": "libA", "export_files": [exports_a], "inputs": [obj_a]},
            {"name": "libB", "export_files": [exports_b], "inputs": [archive_b]},
        ]
        globals_, errors = policy.validate_and_generate(nm, libs)
        self.assertEqual(errors, [])
        self.assertIn("api_a", globals_)
        self.assertIn("api_b", globals_)
        self.assertNotIn("helper", globals_)


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
        force_keep = os.path.join(self._tmpdir, "out", "force-keep.rsp")
        nm = _make_python_mock_nm(
            self._tmpdir, {obj: "api_sym T\npriv_sym T\n"}
        )
        policy.main([
            "--nm", nm, "--output", output,
            "--force-keep-output", force_keep,
            "--library", "libFoo",
            "--export-file", exports,
            "--input", obj,
        ])
        self.assertTrue(os.path.exists(output))
        with open(output) as f:
            content = f.read()
        self.assertIn("api_sym", content)
        self.assertNotIn("priv_sym", content)
        self.assertIn("local:", content)
        self.assertIn("*;", content)
        with open(force_keep) as f:
            force_keep_content = f.read()
        self.assertEqual(force_keep_content, '"-Wl,-u,api_sym"\n')

    def test_no_libraries(self):
        output = os.path.join(self._tmpdir, "empty.lds")
        force_keep = os.path.join(self._tmpdir, "empty.rsp")
        policy.main([
            "--nm", "unused", "--output", output,
            "--force-keep-output", force_keep,
        ])
        self.assertTrue(os.path.exists(output))
        with open(output) as f:
            content = f.read()
        self.assertIn("local:", content)
        with open(force_keep) as f:
            self.assertEqual(f.read(), "")

    def test_violation_exits_1(self):
        exports_a = self._write("a.uk", "api_a\n")
        exports_b = self._write("b.uk", "api_b\n")
        obj_a = self._write("a.o", "")
        obj_b = self._write("b.o", "")
        output = os.path.join(self._tmpdir, "bad.lds")
        nm = _make_python_mock_nm(self._tmpdir, {
            obj_a: "api_a T\nclash T\n",
            obj_b: "api_b T\nclash T\n",
        })
        with self.assertRaises(SystemExit) as cm:
            policy.main([
                "--nm", nm, "--output", output,
                "--library", "libA",
                "--export-file", exports_a, "--input", obj_a,
                "--library", "libB",
                "--export-file", exports_b, "--input", obj_b,
            ])
        self.assertEqual(cm.exception.code, 1)


if __name__ == "__main__":
    unittest.main()
