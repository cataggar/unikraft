#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026, The Unikraft Authors.
# Licensed under the BSD-3-Clause License (the "License").
# You may not use this file except in compliance with the License.
"""
elf-size-diff — compare section sizes and symbol counts between two ELF files.

Reports the benefit (or cost) of link-time optimisation by diffing a baseline
(non-LTO) ELF against an LTO ELF.

Usage:
    python elf-size-diff.py [options] <baseline.elf> <lto.elf>

Options:
    --readelf CMD   readelf command (env: READELF; default: readelf)
    --nm CMD        nm command (env: NM; default: nm)
    --json          emit machine-readable JSON (default: human-readable table)

Metrics: file_size, .text, .rodata, .data, .bss, symbol_count.

Exit codes: 0 success, 1 tool or argument error.
"""

import argparse
import json
import os
import re
import shlex
import sys

from elf_tools import configured_tool, tool_output

# Matches a single wide-format readelf section-header line:
#   [Nr] Name Type Address Off Size ES ...
# Requires Address and Off to be hex (to distinguish section-header lines from
# other output), but captures the Size slot as any token so that non-hex values
# trigger an explicit ValueError instead of being silently skipped.
# Captures: group 1 = Name, group 2 = Size token (must be hex).
_SECTION_RE = re.compile(
    r"^\s*\[\s*\d+\]\s+(\S+)\s+\S+\s+[0-9a-fA-F]+\s+[0-9a-fA-F]+\s+(\S+)"
)

TRACKED_SECTIONS = (".text", ".rodata", ".data", ".bss")
METRICS_ORDER = ("file_size",) + TRACKED_SECTIONS + ("symbol_count",)


def read_sections(readelf, elf_path):
    """Return {section_name: byte_size} for every section in the ELF.

    Raises subprocess.CalledProcessError if readelf exits non-zero.
    Raises ValueError if a size field cannot be parsed as hexadecimal.
    """
    raw = tool_output(readelf, "-SW", str(elf_path), text=True)
    sections = {}
    for line in raw.splitlines():
        m = _SECTION_RE.match(line)
        if not m:
            continue
        name, size_hex = m.group(1), m.group(2)
        try:
            sections[name] = int(size_hex, 16)
        except ValueError as exc:
            raise ValueError(
                f"malformed size field {size_hex!r} in readelf output line: {line!r}"
            ) from exc
    return sections


def count_defined_symbols(nm, elf_path):
    """Return the count of defined symbols in the ELF.

    Raises subprocess.CalledProcessError if nm exits non-zero.
    """
    raw = tool_output(nm, "--defined-only", str(elf_path), text=True)
    return sum(1 for line in raw.splitlines() if line.strip())


def gather_metrics(readelf, nm, elf_path):
    """Collect all tracked metrics for a single ELF file."""
    sections = read_sections(readelf, elf_path)
    sym_count = count_defined_symbols(nm, elf_path)
    file_size = os.path.getsize(elf_path)
    metrics = {"file_size": file_size}
    for sec in TRACKED_SECTIONS:
        metrics[sec] = sections.get(sec, 0)
    metrics["symbol_count"] = sym_count
    return metrics


def compute_delta(baseline_val, lto_val):
    """Return (absolute_delta, percentage_delta_or_None).

    Percentage is None when baseline_val is zero (division undefined).
    """
    delta = lto_val - baseline_val
    pct = None if baseline_val == 0 else round(delta / baseline_val * 100.0, 2)
    return delta, pct


def compare(baseline_metrics, lto_metrics):
    """Return an OrderedDict of metric comparisons preserving METRICS_ORDER."""
    result = {}
    for key in METRICS_ORDER:
        b = baseline_metrics[key]
        l = lto_metrics[key]
        delta, pct = compute_delta(b, l)
        result[key] = {"baseline": b, "lto": l, "delta": delta, "pct": pct}
    return result


def emit_json(baseline_path, lto_path, comparison):
    out = {
        "baseline": str(baseline_path),
        "lto": str(lto_path),
        "metrics": comparison,
    }
    print(json.dumps(out, indent=2))


def emit_table(comparison):
    col_w = (16, 14, 14, 12, 10)
    header = (
        f"{'Metric':<{col_w[0]}}"
        f"{'Baseline':>{col_w[1]}}"
        f"{'LTO':>{col_w[2]}}"
        f"{'Delta':>{col_w[3]}}"
        f"{'%Delta':>{col_w[4]}}"
    )
    sep = "-" * len(header)
    print(header)
    print(sep)
    for key, vals in comparison.items():
        b = vals["baseline"]
        l = vals["lto"]
        d = vals["delta"]
        p = vals["pct"]
        pct_str = f"{p:+.2f}%" if p is not None else "N/A"
        print(
            f"{key:<{col_w[0]}}"
            f"{b:>{col_w[1]}}"
            f"{l:>{col_w[2]}}"
            f"{d:>+{col_w[3]}}"
            f"{pct_str:>{col_w[4]}}"
        )


def _parse_tool(arg_value, env_var, default):
    """Parse a shell-quoted tool command string into a list."""
    parts = shlex.split(arg_value) if arg_value else None
    if parts is not None:
        if not parts:
            raise argparse.ArgumentTypeError(
                f"tool command must not be empty"
            )
        return parts
    return configured_tool(env_var, default)


def main():
    parser = argparse.ArgumentParser(
        description="Compare ELF section sizes and defined-symbol counts."
    )
    parser.add_argument("--readelf", metavar="CMD", help="readelf command (env: READELF)")
    parser.add_argument("--nm", metavar="CMD", help="nm command (env: NM)")
    parser.add_argument(
        "--json",
        action="store_true",
        dest="emit_json",
        help="emit machine-readable JSON",
    )
    parser.add_argument("baseline", help="baseline ELF (built without LTO)")
    parser.add_argument("lto", help="LTO ELF (built with LTO)")
    args = parser.parse_args()

    try:
        readelf = _parse_tool(args.readelf, "READELF", "readelf")
        nm = _parse_tool(args.nm, "NM", "nm")
    except (argparse.ArgumentTypeError, ValueError) as exc:
        parser.error(str(exc))

    baseline_metrics = gather_metrics(readelf, nm, args.baseline)
    lto_metrics = gather_metrics(readelf, nm, args.lto)
    comparison = compare(baseline_metrics, lto_metrics)

    if args.emit_json:
        emit_json(args.baseline, args.lto, comparison)
    else:
        emit_table(comparison)


if __name__ == "__main__":
    main()
