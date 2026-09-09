#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause

import argparse
import re
import subprocess


def output(*args: str) -> str:
    return subprocess.check_output(args, text=True)


def function(disassembly: str, name: str) -> str:
    match = re.search(
        rf"^[0-9a-f]+ <{re.escape(name)}>:\n(.*?)(?=^[0-9a-f]+ <|\Z)",
        disassembly,
        re.MULTILINE | re.DOTALL,
    )
    if not match:
        raise SystemExit(f"missing linked function: {name}")
    return match.group(1)


def require_call(body: str, target: str) -> None:
    if not re.search(rf"\bcall\w*\b.*<{re.escape(target)}>", body):
        raise SystemExit(f"linked call does not target strong {target}")

def require_any_call(disassembly: str, target: str) -> None:
    if not re.search(rf"\bcall\w*\b.*<{re.escape(target)}>", disassembly):
        raise SystemExit(f"linked image has no reachable call to {target}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--image", required=True)
    parser.add_argument("--nm", default="llvm-nm")
    parser.add_argument("--objdump", default="llvm-objdump")
    parser.add_argument("--max-cpus", type=int, required=True)
    args = parser.parse_args()

    symbols = output(args.nm, "-a", args.image)
    for hook in (
        "ukplat_lcpu_startup_hook",
        "ukplat_lcpu_init_hook",
        "ukplat_lcpu_fini_hook",
        "hyperv_vmbus_shutdown",
        "hyperv_vmbus_fini",
        "hyperv_vmbus_message",
        "hyperv_vmbus_event",
        "hyperv_vmbus_event_word",
    ):
        definitions = re.findall(
            rf"^[0-9a-f]+\s+([TWtw])\s+{re.escape(hook)}$",
            symbols,
            re.MULTILINE,
        )
        if definitions != ["T"]:
            raise SystemExit(
                f"{hook} did not resolve uniquely to the Hyper-V strong symbol: "
                f"{definitions}"
            )

    disassembly = output(args.objdump, "-d", args.image)
    require_call(function(disassembly, "uk_boot_entry"),
                 "ukplat_lcpu_startup_hook")
    require_call(function(disassembly, "uk_lcpu_init"),
                 "ukplat_lcpu_init_hook")
    require_call(function(disassembly, "lcpu_halt"),
                 "ukplat_lcpu_fini_hook")
    require_any_call(disassembly, "hyperv_vmbus_message")
    require_any_call(disassembly, "hyperv_vmbus_event_word")
    require_any_call(disassembly, "hyperv_vmbus_shutdown")
    if args.max_cpus > 1:
        require_call(function(disassembly, "ukplat_lcpu_startup_hook"),
                     "uk_lcpu_start")
        require_call(function(disassembly, "uk_boot_fixed_smp_lcpu_entry"),
                     "uk_lcpu_init")


if __name__ == "__main__":
    main()
