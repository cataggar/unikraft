#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026, The Unikraft Authors.
"""
lto-proof — prove Zig 0.16 performs cross-translation-unit LTO.

Compiles two tiny C translation units with and without -flto (all other
compiler/linker flags are identical), links them, runs both binaries to
confirm they exit 0, then asserts:
  - baseline: lto_proof_callee is a defined symbol
  - lto:      lto_proof_callee is absent (inlined and eliminated by LTO)

Usage:
    python lto-proof.py --work-dir <dir> --zig <path> [--nm <cmd>]

ZIG_GLOBAL_CACHE_DIR and ZIG_LOCAL_CACHE_DIR are pinned under <work-dir>.
All generated files stay under <work-dir>.  Tool paths are explicit.
"""

import argparse
import os
import shlex
import subprocess
import sys
from pathlib import Path

_CALLEE_SRC = """\
/* lto-proof: callee in its own translation unit */
int lto_proof_callee(void) {
    return 42;
}
"""

_CALLER_SRC = """\
/* lto-proof: caller in its own translation unit */
extern int lto_proof_callee(void);

int main(void) {
    return lto_proof_callee() - 42;
}
"""

_PROOF_SYMBOL = "lto_proof_callee"


def _build_commands(work_dir, zig_cmd, use_lto):
    """Return (commands, output_elf) for one compilation variant.

    commands is a list of argv lists.  Purely constructs paths and arguments;
    executes nothing.  -flto is the only flag that differs between variants.
    """
    suffix = "lto" if use_lto else "baseline"
    callee_src = work_dir / "callee.c"
    caller_src = work_dir / "caller.c"
    callee_obj = work_dir / f"callee-{suffix}.o"
    caller_obj = work_dir / f"caller-{suffix}.o"
    output_elf = work_dir / f"{suffix}.elf"
    flags = ["-O2"] + (["-flto"] if use_lto else [])
    return [
        [*zig_cmd, "cc", *flags, "-c", str(callee_src), "-o", str(callee_obj)],
        [*zig_cmd, "cc", *flags, "-c", str(caller_src), "-o", str(caller_obj)],
        [*zig_cmd, "cc", *flags, str(callee_obj), str(caller_obj), "-o", str(output_elf)],
    ], output_elf


def _defined_symbol_names(nm_cmd, elf_path):
    """Return the set of defined symbol names in *elf_path*.

    Raises subprocess.CalledProcessError if nm exits non-zero.
    """
    result = subprocess.run(  # nosec
        [*nm_cmd, "--defined-only", str(elf_path)],
        check=True,
        stdout=subprocess.PIPE,
        text=True,
    )
    names = set()
    for line in result.stdout.splitlines():
        parts = line.strip().split()
        if len(parts) >= 2:
            names.add(parts[-1])
    return names


def _verify_runs_ok(elf_path):
    """Run the binary and assert it exits 0.

    Raises AssertionError if the binary exits non-zero.
    """
    result = subprocess.run([str(elf_path)], check=False)  # nosec
    if result.returncode != 0:
        raise AssertionError(
            f"{elf_path.name!r} exited with status {result.returncode}"
        )


def _check_proof_result(baseline_syms, lto_syms, symbol):
    """Return a list of failure messages; an empty list means the proof passed."""
    failures = []
    if symbol not in baseline_syms:
        failures.append(
            f"'{symbol}' absent from baseline binary (expected retained without LTO)"
        )
    if symbol in lto_syms:
        failures.append(
            f"'{symbol}' still present in LTO binary (expected LTO to eliminate it)"
        )
    return failures


def main():
    parser = argparse.ArgumentParser(
        description="Prove Zig 0.16 cross-TU LTO eliminates the designated callee."
    )
    parser.add_argument("--work-dir", required=True)
    parser.add_argument("--zig", required=True, help="path to the zig executable")
    parser.add_argument("--nm", default="nm", help="nm command (default: nm)")
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

    for use_lto in (False, True):
        cmds, _ = _build_commands(work_dir, zig_cmd, use_lto=use_lto)
        for argv in cmds:
            subprocess.run(argv, check=True, env=env)  # nosec

    _, baseline_elf = _build_commands(work_dir, zig_cmd, use_lto=False)
    _, lto_elf = _build_commands(work_dir, zig_cmd, use_lto=True)

    _verify_runs_ok(baseline_elf)
    _verify_runs_ok(lto_elf)

    baseline_syms = _defined_symbol_names(nm_cmd, baseline_elf)
    lto_syms = _defined_symbol_names(nm_cmd, lto_elf)

    failures = _check_proof_result(baseline_syms, lto_syms, _PROOF_SYMBOL)
    if failures:
        for msg in failures:
            print(f"FAIL: {msg}", file=sys.stderr)
        sys.exit(1)

    print(f"PASS: cross-TU LTO proof for '{_PROOF_SYMBOL}'")
    print(f"  baseline ({baseline_elf.name}): symbol retained")
    print(f"  lto      ({lto_elf.name}): symbol eliminated")


if __name__ == "__main__":
    main()
