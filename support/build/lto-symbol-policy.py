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

The NM tool must accept ``-g --defined-only --format=posix`` and
``-g --undefined-only --format=posix`` for objects, and ``-g --format=posix``
for archives.  ``llvm-nm`` satisfies this for both ELF and LLVM bitcode.

Exit codes:
    0  version script written successfully
    1  symbol-policy violation detected (message on stderr)
    2  NM tool failure (message on stderr)
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
            print(f"error: unexpected argument: {arg}", file=sys.stderr)
            sys.exit(3)
        i += 1
    return libraries


def read_export_symbols(path):
    """Read an exportsyms.uk file and return a set of symbol names."""
    symbols = set()
    with open(path) as f:
        for raw_line in f:
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            symbols.add(line)
    return symbols


def run_nm(nm_tool, path, flags):
    """Run nm with the given flags and return stdout, or raise on failure."""
    cmd = [nm_tool] + flags + [path]
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
            f"error: nm tool not found: {nm_tool}",
            file=sys.stderr,
        )
        sys.exit(2)
    except subprocess.CalledProcessError as e:
        print(
            f"error: nm failed for '{path}':\n"
            f"  command: {' '.join(cmd)}\n"
            f"  stderr: {e.stderr.strip()}",
            file=sys.stderr,
        )
        sys.exit(2)


# POSIX nm format: "name type [value size]" or "name type" per line.
# We only care about name and type.
_NM_LINE = re.compile(r"^(\S+)\s+([A-Za-z?])")


def parse_nm_output(output):
    """Parse posix-format nm output into {name: type_char} dict."""
    symbols = {}
    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        m = _NM_LINE.match(line)
        if m:
            symbols[m.group(1)] = m.group(2)
    return symbols


def nm_defined_symbols(nm_tool, path):
    """Return the set of globally-defined symbol names in path."""
    output = run_nm(nm_tool, path, ["-g", "--defined-only", "--format=posix"])
    return set(parse_nm_output(output).keys())


def nm_undefined_symbols(nm_tool, path):
    """Return the set of undefined symbol names referenced by path."""
    output = run_nm(nm_tool, path, ["-u", "--format=posix"])
    return set(parse_nm_output(output).keys())


def nm_all_global_symbols(nm_tool, path):
    """Return {name: type_char} for all global symbols (defined+undefined)."""
    output = run_nm(nm_tool, path, ["-g", "--format=posix"])
    return parse_nm_output(output)


def collect_library_symbols(nm_tool, library):
    """Collect defined and undefined symbols for a library.

    Returns (defined: set, undefined: set).
    """
    defined = set()
    undefined = set()
    for input_path in library["inputs"]:
        all_syms = nm_all_global_symbols(nm_tool, input_path)
        for name, sym_type in all_syms.items():
            if sym_type in ("U", "w", "v"):
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
      - Private definitions must not collide across libraries.
      - No other library may reference a private symbol.

    For libraries without export lists:
      - All definitions are global (no localization was ever applied).

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
            # Only exported symbols become global.
            lib_globals = ld["defined"] & ld["exports"]
            lib_privates = ld["defined"] - ld["exports"]
        else:
            # All definitions are global.
            lib_globals = ld["defined"]
            lib_privates = set()

        global_symbols |= lib_globals
        for sym in lib_globals:
            definition_map[sym].append((ld["name"], False))
        for sym in lib_privates:
            definition_map[sym].append((ld["name"], True))

    # Phase 3: validate.
    errors = []

    # Check for private definition collisions.
    for sym, providers in definition_map.items():
        private_providers = [name for name, is_priv in providers if is_priv]
        if len(private_providers) > 1:
            errors.append(
                f"private symbol '{sym}' is defined in multiple "
                f"libraries: {', '.join(sorted(private_providers))}"
            )

    # Check for cross-library private references: if library A references
    # symbol S, and S is only provided as private by library B, that
    # reference would break without localization.
    private_defs = {}  # symbol -> library_name (only private defs)
    for sym, providers in definition_map.items():
        private_only = [
            name
            for name, is_priv in providers
            if is_priv
            and not any(not p for _, p in providers)
        ]
        if private_only:
            private_defs[sym] = private_only[0]

    for ld in lib_data:
        for sym in ld["undefined"]:
            if sym in private_defs and private_defs[sym] != ld["name"]:
                errors.append(
                    f"library '{ld['name']}' references private symbol "
                    f"'{sym}' defined only in '{private_defs[sym]}'"
                )

    return sorted(global_symbols), errors


def quote_version_script_symbol(name):
    """Quote a symbol name for an LLD version script if needed.

    Symbol names containing non-identifier characters need quoting.
    LLD version scripts use shell-like double quoting.
    """
    if re.fullmatch(r"[A-Za-z_.$][A-Za-z0-9_.$]*", name):
        return name
    # Quote: escape backslashes and double-quotes, then wrap.
    escaped = name.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def generate_version_script(global_symbols):
    """Generate a deterministic LLD version script body.

    The script uses an anonymous version node with the global symbols
    listed explicitly and ``local: *;`` to internalize everything else.
    """
    lines = ["/* Generated by lto-symbol-policy.py — do not edit. */"]
    lines.append("{")
    lines.append("  global:")
    for sym in global_symbols:
        lines.append(f"    {quote_version_script_symbol(sym)};")
    lines.append("  local:")
    lines.append("    *;")
    lines.append("};")
    return "\n".join(lines) + "\n"


def main(argv=None):
    args = parse_args(argv)
    libraries = parse_library_specs(args.spec)

    if not libraries:
        # No libraries — emit a permissive version script.
        script = generate_version_script([])
        os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
        with open(args.output, "w") as f:
            f.write(script)
        return

    global_symbols, errors = validate_and_generate(args.nm, libraries)

    if errors:
        print(
            "error: LTO symbol-policy violations detected:",
            file=sys.stderr,
        )
        for err in sorted(errors):
            print(f"  {err}", file=sys.stderr)
        sys.exit(1)

    script = generate_version_script(global_symbols)
    os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
    with open(args.output, "w") as f:
        f.write(script)


if __name__ == "__main__":
    main()
