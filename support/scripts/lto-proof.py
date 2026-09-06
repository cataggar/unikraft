#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026, The Unikraft Authors.
# Licensed under the BSD-3-Clause License (the "License").
# You may not use this file except in compliance with the License.
"""
lto-proof — prove Zig 0.16 performs cross-translation-unit LTO.

Compiles two C translation units with and without -flto, links them, then
asserts:
  - baseline: lto_proof_callee appears as a defined symbol in the binary
  - lto:      lto_proof_callee is absent (inlined and eliminated by LTO)

Usage:
    python lto-proof.py --work-dir <dir> --zig <path> [--nm <cmd>]

ZIG_GLOBAL_CACHE_DIR and ZIG_LOCAL_CACHE_DIR are pinned under <work-dir>.
All generated files stay under <work-dir>.
Tool paths are explicit; no PATH-based discovery for zig or nm.
"""

import argparse
import os
import shlex
import subprocess
import sys
from pathlib import Path

# A callee in its own translation unit.  Returns a compile-time constant so
# that LTO can constant-fold the call site and then dead-code-eliminate the
# callee body entirely.
_CALLEE_SRC = """\
/* lto-proof callee: lives in a separate translation unit */
int lto_proof_callee(void) {
    return 42;
}
"""

# A caller in its own translation unit.  Subtracts the known return value so
# the executable exits with status 0 when run.
_CALLER_SRC = """\
/* lto-proof caller: lives in a separate translation unit */
extern int lto_proof_callee(void);

int main(void) {
    return lto_proof_callee() - 42;
}
"""

# The symbol whose presence/absence we assert.
_PROOF_SYMBOL = "lto_proof_callee"


def _run(argv, env=None):
    subprocess.run(argv, check=True, env=env)  # nosec


def _defined_symbol_names(nm_cmd, elf_path):
    """Return the set of defined symbol names in *elf_path*."""
    result = subprocess.run(  # nosec
        [*nm_cmd, "--defined-only", str(elf_path)],
        check=True,
        stdout=subprocess.PIPE,
        text=True,
    )
    names = set()
    for line in result.stdout.splitlines():
        parts = line.strip().split()
        # nm output: [value] [type] name   (or just [type] name for locals)
        if len(parts) >= 2:
            names.add(parts[-1])
    return names


def _compile_and_link(work_dir, zig_cmd, env, use_lto):
    """Compile callee.c + caller.c and link them.  Return path to the binary."""
    suffix = "lto" if use_lto else "baseline"
    callee_src = work_dir / "callee.c"
    caller_src = work_dir / "caller.c"
    callee_obj = work_dir / f"callee-{suffix}.o"
    caller_obj = work_dir / f"caller-{suffix}.o"
    output_elf = work_dir / f"{suffix}.elf"

    extra = ["-flto", "-fvisibility=hidden"] if use_lto else []
    opt = ["-O2"]

    _run([*zig_cmd, "cc", *opt, *extra, "-c", str(callee_src), "-o", str(callee_obj)], env=env)
    _run([*zig_cmd, "cc", *opt, *extra, "-c", str(caller_src), "-o", str(caller_obj)], env=env)
    _run([*zig_cmd, "cc", *opt, *extra, str(callee_obj), str(caller_obj), "-o", str(output_elf)], env=env)
    return output_elf


def main():
    parser = argparse.ArgumentParser(
        description="Prove Zig 0.16 cross-TU LTO eliminates the designated callee."
    )
    parser.add_argument(
        "--work-dir", required=True, help="directory for all generated files"
    )
    parser.add_argument(
        "--zig", required=True, help="path to the zig executable"
    )
    parser.add_argument(
        "--nm", default="nm", help="nm command (default: nm)"
    )
    args = parser.parse_args()

    work_dir = Path(args.work_dir).resolve()
    work_dir.mkdir(parents=True, exist_ok=True)

    zig_cmd = [args.zig]
    nm_cmd = shlex.split(args.nm)
    if not nm_cmd:
        parser.error("--nm command must not be empty")

    env = os.environ.copy()
    env["ZIG_GLOBAL_CACHE_DIR"] = str(work_dir / "zig-global-cache")
    env["ZIG_LOCAL_CACHE_DIR"] = str(work_dir / "zig-local-cache")

    (work_dir / "callee.c").write_text(_CALLEE_SRC, encoding="utf-8")
    (work_dir / "caller.c").write_text(_CALLER_SRC, encoding="utf-8")

    baseline_elf = _compile_and_link(work_dir, zig_cmd, env, use_lto=False)
    lto_elf = _compile_and_link(work_dir, zig_cmd, env, use_lto=True)

    baseline_syms = _defined_symbol_names(nm_cmd, baseline_elf)
    lto_syms = _defined_symbol_names(nm_cmd, lto_elf)

    failures = []
    if _PROOF_SYMBOL not in baseline_syms:
        failures.append(
            f"FAIL: '{_PROOF_SYMBOL}' absent from baseline binary"
            " (expected it to be retained without LTO)"
        )
    if _PROOF_SYMBOL in lto_syms:
        failures.append(
            f"FAIL: '{_PROOF_SYMBOL}' still present in LTO binary"
            " (expected LTO to eliminate it)"
        )

    if failures:
        for msg in failures:
            print(msg, file=sys.stderr)
        sys.exit(1)

    print(f"PASS: cross-TU LTO proof for '{_PROOF_SYMBOL}'")
    print(f"  baseline ({baseline_elf.name}): symbol retained")
    print(f"  lto      ({lto_elf.name}): symbol eliminated")


if __name__ == "__main__":
    main()
