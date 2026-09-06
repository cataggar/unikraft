#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause

import argparse
import subprocess


def output(*args: str) -> str:
    return subprocess.check_output(args, text=True)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--object", required=True)
    parser.add_argument("--nm", default="llvm-nm")
    parser.add_argument("--readelf", default="llvm-readelf")
    args = parser.parse_args()

    undefined = output(args.nm, "-u", args.object).strip()
    if undefined:
        raise SystemExit(f"Hyper-V runtime has external dependencies:\n{undefined}")

    symbols = output(args.nm, "-n", args.object)
    required = (
        "hyperv_hypercall_page_storage",
        "hyperv_runtime_detect",
        "hyperv_runtime_enable",
        "hyperv_runtime_disable",
        "hyperv_hypercall",
        "hyperv_time_ref_count",
        "hyperv_reference_time",
        "hyperv_synic_enable",
        "hyperv_synic_disable",
        "hyperv_synic_message_take",
        "hyperv_synic_event_take_word",
        "hyperv_x86_irq_to_vector",
        "hyperv_stimer0_arm",
        "hyperv_stimer0_cancel",
    )
    for symbol in required:
        if symbol not in symbols:
            raise SystemExit(f"missing Hyper-V runtime symbol: {symbol}")

    sections = output(args.readelf, "-SW", args.object)
    for name in (
        ".text.hyperv_hypercall_page",
        ".bss.hyperv_simp_page",
        ".bss.hyperv_siefp_page",
        ".bss.hyperv_reference_tsc_page",
    ):
        page_section = next(
            (line for line in sections.splitlines() if name in line),
            None,
        )
        if page_section is None or "001000" not in page_section:
            raise SystemExit(f"{name} is not a 4 KiB section")
        if not page_section.rstrip().endswith("4096"):
            raise SystemExit(f"{name} is not 4 KiB aligned")


if __name__ == "__main__":
    main()
