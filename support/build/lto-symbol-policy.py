#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause

"""LTO symbol-policy generator for Unikraft native Zig builds.

Reads per-library object/archive inputs and export-symbol files, invokes an
NM tool to extract defined/undefined symbols, validates cross-library symbol
policy, and emits a deterministic LLD version script that preserves the
per-library localization semantics the standard objcopy pipeline provides.

Usage:
    lto-symbol-policy.py --nm TOOL --output VERSION_SCRIPT \\
        [--library NAME [--export-file PATH] [--input PATH ...]] ...

The NM tool must accept ``-g --format=posix`` for both individual objects
(ELF or LLVM bitcode) and archives.  ``llvm-nm`` satisfies this.  Archive
member headings (lines ending with ``:``) are recognized and skipped.

Exit codes:
    0  version script written successfully
    1  symbol-policy violation detected (message on stderr)
    2  NM tool failure or I/O error (message on stderr)
    3  argument/usage error
"""

import argparse
import os
import re
import subprocess
import sys
from collections import defaultdict


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="Generate an LLD version script enforcing per-library "
        "symbol-export semantics for LTO flat linking.",
    )
    parser.add_argument(
        "--nm", required=True, help="Path to nm tool (e.g. llvm-nm)"
    )
    parser.add_argument(
        "--output", required=True, help="Output version-script path"
    )
    parser.add_argument(
        "--force-keep-output",
        help="Optional output response file containing linker force-keep flags",
    )
    args, remaining = parser.parse_known_args(argv)
    args.spec = remaining
    return args


def parse_library_specs(spec_args):
    """Parse the interleaved --library/--export-file/--input arguments.

    Returns a list of dicts:
        {"name": str, "export_files": [str], "inputs": [str]}
    """
    libraries = []
    current = None
    i = 0
    while i < len(spec_args):
        arg = spec_args[i]
        if arg == "--library":
            i += 1
            if i >= len(spec_args):
                print("error: --library requires a NAME", file=sys.stderr)
                sys.exit(3)
            current = {
                "name": spec_args[i],
                "export_files": [],
                "inputs": [],
            }
            libraries.append(current)
        elif arg == "--export-file":
            if current is None:
                print(
                    "error: --export-file before any --library",
                    file=sys.stderr,
                )
                sys.exit(3)
            i += 1
            if i >= len(spec_args):
                print(
                    "error: --export-file requires a PATH", file=sys.stderr
                )
                sys.exit(3)
            current["export_files"].append(spec_args[i])
        elif arg == "--input":
            if current is None:
                print(
                    "error: --input before any --library", file=sys.stderr
                )
                sys.exit(3)
            i += 1
            if i >= len(spec_args):
                print("error: --input requires a PATH", file=sys.stderr)
                sys.exit(3)
            current["inputs"].append(spec_args[i])
        else:
            print("error: unexpected argument: %s" % arg, file=sys.stderr)
            sys.exit(3)
        i += 1
    return libraries


def read_export_symbols(path):
    """Read an exportsyms.uk file and return a set of symbol names."""
    try:
        with open(path) as f:
            symbols = set()
            for raw_line in f:
                line = raw_line.strip()
                if not line or line.startswith("#"):
                    continue
                symbols.add(line)
            return symbols
    except OSError as e:
        print(
            "error: cannot read export file '%s': %s" % (path, e),
            file=sys.stderr,
        )
        sys.exit(2)


def run_nm(nm_tool, path):
    """Run nm -g --format=posix on path and return stdout."""
    cmd = [nm_tool, "-g", "--format=posix", path]
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=True,
        )
        return result.stdout
    except FileNotFoundError:
        print(
            "error: nm tool not found: %s" % nm_tool,
            file=sys.stderr,
        )
        sys.exit(2)
    except subprocess.CalledProcessError as e:
        print(
            "error: nm failed for '%s':\n"
            "  command: %s\n"
            "  stderr: %s" % (path, " ".join(cmd), e.stderr.strip()),
            file=sys.stderr,
        )
        sys.exit(2)


# llvm-nm POSIX format: "name type [value size]" per line.
# Archive member headings are lines like "/path/to/archive.a(member.o):".
# Blank lines separate archive members.
_NM_SYMBOL = re.compile(r"^(\S+)\s+([A-Za-z?])(?:\s|$)")
_NM_ARCHIVE_HEADING = re.compile(r"^.+:$")


class NmParseError(Exception):
    """Raised when an NM output line cannot be classified."""

    def __init__(self, path, line_number, line):
        self.path = path
        self.line_number = line_number
        self.line = line
        super().__init__(
            "error: unrecognized nm output for '%s' line %d: %s"
            % (path, line_number, repr(line))
        )


def parse_nm_output(output, path="<nm>"):
    """Parse POSIX-format nm output into {name: type_char} dict.

    Recognizes:
      - Symbol lines: "name type [value [size]]"
      - Archive member headings: lines ending with ":"
      - Blank/whitespace-only lines

    When the same symbol appears multiple times (common in archives where
    one member defines a symbol and another references it), a defined
    occurrence always takes precedence over an undefined one.  Among
    defined occurrences, strong definitions (uppercase T/D/B/etc.)
    dominate weak definitions (W/V).

    Raises NmParseError on any other non-empty line.
    """
    symbols = {}
    for lineno, raw in enumerate(output.splitlines(), 1):
        line = raw.strip()
        if not line:
            continue
        m = _NM_SYMBOL.match(line)
        if m:
            name, sym_type = m.group(1), m.group(2)
            existing = symbols.get(name)
            if existing is None:
                symbols[name] = sym_type
            else:
                symbols[name] = _dominant_type(existing, sym_type)
            continue
        if _NM_ARCHIVE_HEADING.match(line):
            continue
        raise NmParseError(path, lineno, line)
    return symbols


def _is_undefined(sym_type):
    """True for undefined (U) and weak-undefined (w, v) type chars."""
    return sym_type in ("U", "w", "v")


def _is_weak_defined(sym_type):
    """True for weak-defined (W, V) type chars."""
    return sym_type in ("W", "V")


def _dominant_type(a, b):
    """Return the dominant type when a symbol appears with two type chars.

    Precedence: strong-defined > weak-defined > undefined.
    """
    for t in (a, b):
        if not _is_undefined(t) and not _is_weak_defined(t):
            return t  # strong defined wins
    for t in (a, b):
        if not _is_undefined(t):
            return t  # weak defined wins over undefined
    return a  # both undefined, keep first


def collect_library_symbols(nm_tool, library):
    """Collect defined and undefined symbols for a library.

    Returns (defined: set, undefined: set).
    Raises NmParseError on malformed output. Calls sys.exit(2) on nm failure.
    """
    defined = set()
    undefined = set()
    for input_path in library["inputs"]:
        output = run_nm(nm_tool, input_path)
        try:
            all_syms = parse_nm_output(output, path=input_path)
        except NmParseError as e:
            print(str(e), file=sys.stderr)
            sys.exit(2)
        for name, sym_type in all_syms.items():
            if _is_undefined(sym_type):
                undefined.add(name)
            else:
                defined.add(name)
    # Symbols that are both defined and undefined within the same library
    # are internal references, not truly undefined.
    undefined -= defined
    return defined, undefined


def validate_and_generate(nm_tool, libraries):
    """Validate symbol policy and return (global_symbols, errors).

    For each library with export lists:
      - Only exported symbols are global; everything else is private.

    For libraries without export lists:
      - All definitions are global (no localization was ever applied).

    Rejects:
      - Any multi-definition set containing at least one private provider,
        because the standard pipeline permits local+global coexistence via
        per-library objcopy while flat linking cannot represent this.
      - Cross-library references to private symbols.

    Returns:
      global_symbols: sorted list of symbol names for the version script
      errors: list of error message strings (empty on success)
    """
    # Phase 1: collect per-library symbols.
    lib_data = []
    for lib in libraries:
        exports = set()
        for ef in lib["export_files"]:
            exports |= read_export_symbols(ef)
        defined, undefined = collect_library_symbols(nm_tool, lib)
        has_export_policy = len(lib["export_files"]) > 0
        lib_data.append(
            {
                "name": lib["name"],
                "exports": exports,
                "defined": defined,
                "undefined": undefined,
                "has_policy": has_export_policy,
            }
        )

    # Phase 2: compute global/private sets.
    global_symbols = set()
    # Map: symbol -> list of (library_name, is_private) for defined symbols.
    definition_map = defaultdict(list)

    for ld in lib_data:
        if ld["has_policy"]:
            lib_globals = ld["defined"] & ld["exports"]
            lib_privates = ld["defined"] - ld["exports"]
        else:
            lib_globals = ld["defined"]
            lib_privates = set()

        global_symbols |= lib_globals
        for sym in lib_globals:
            definition_map[sym].append((ld["name"], False))
        for sym in lib_privates:
            definition_map[sym].append((ld["name"], True))

    # Phase 3: validate.
    errors = []

    # Reject any multi-definition set containing at least one private
    # provider.  The standard pipeline uses per-library objcopy to permit
    # local+global coexistence for the same name; flat linking cannot.
    for sym, providers in sorted(definition_map.items()):
        if len(providers) < 2:
            continue
        has_private = any(is_priv for _, is_priv in providers)
        if has_private:
            libs = ", ".join(
                "%s(%s)" % (name, "private" if priv else "global")
                for name, priv in sorted(providers)
            )
            errors.append(
                "symbol '%s' has conflicting definitions that flat "
                "linking cannot represent: %s" % (sym, libs)
            )

    # Cross-library private references: if library A references symbol S,
    # and S is only provided as private (no global provider), that
    # reference would break without localization.
    private_only_defs = {}
    for sym, providers in definition_map.items():
        if all(is_priv for _, is_priv in providers):
            private_only_defs[sym] = providers[0][0]

    for ld in lib_data:
        for sym in sorted(ld["undefined"]):
            if sym in private_only_defs and private_only_defs[sym] != ld["name"]:
                errors.append(
                    "library '%s' references private symbol "
                    "'%s' defined only in '%s'"
                    % (ld["name"], sym, private_only_defs[sym])
                )

    return sorted(global_symbols), errors



def quote_version_script_symbol(name):
    """Quote a symbol name for an LLD version script if needed.

    Symbol names containing non-identifier characters need quoting.
    LLD version scripts use shell-like double quoting.
    """
    if re.fullmatch(r"[A-Za-z_.$][A-Za-z0-9_.$]*", name):
        return name
    escaped = name.replace("\\", "\\\\").replace('"', '\\"')
    return '"%s"' % escaped


def generate_version_script(global_symbols):
    """Generate a deterministic LLD version script body.

    The script uses an anonymous version node with the global symbols
    listed explicitly and ``local: *;`` to internalize everything else.
    """
    lines = ["/* Generated by lto-symbol-policy.py -- do not edit. */"]
    lines.append("{")
    lines.append("  global:")
    for sym in global_symbols:
        lines.append("    %s;" % quote_version_script_symbol(sym))
    lines.append("  local:")
    lines.append("    *;")
    lines.append("};")
    return "\n".join(lines) + "\n"


def quote_response_argument(value):
    """Quote one compiler response-file argument."""
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return '"%s"' % escaped


def generate_force_keep_response(global_symbols):
    """Generate deterministic linker arguments that preserve LTO exports."""
    return "".join(
        "%s\n" % quote_response_argument("-Wl,-u,%s" % symbol)
        for symbol in sorted(global_symbols)
    )


def write_output(path, content):
    """Write a generated output, creating its parent directory if needed."""
    try:
        out_dir = os.path.dirname(path)
        if out_dir:
            os.makedirs(out_dir, exist_ok=True)
        with open(path, "w") as f:
            f.write(content)
    except OSError as e:
        print(
            "error: cannot write output '%s': %s" % (path, e),
            file=sys.stderr,
        )
        sys.exit(2)


def main(argv=None):
    args = parse_args(argv)
    libraries = parse_library_specs(args.spec)

    global_symbols = []
    if not libraries:
        script = generate_version_script([])
    else:
        global_symbols, errors = validate_and_generate(args.nm, libraries)
        if errors:
            print(
                "error: LTO symbol-policy violations detected:",
                file=sys.stderr,
            )
            for err in sorted(errors):
                print("  %s" % err, file=sys.stderr)
            sys.exit(1)
        script = generate_version_script(global_symbols)

    write_output(args.output, script)
    if args.force_keep_output:
        write_output(
            args.force_keep_output,
            generate_force_keep_response(global_symbols),
        )


if __name__ == "__main__":
    main()
