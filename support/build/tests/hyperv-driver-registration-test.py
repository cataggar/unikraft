#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause

"""Verify VMBus data-path constructors in a final, unstripped Hyper-V ELF."""

import argparse
import re
import subprocess


DRIVERS = {
    "storvsc": "libstorvsc",
    "netvsc": "libnetvsc",
}


def output(*args: str) -> str:
    return subprocess.check_output(args, text=True)


def function(disassembly: str, name: str) -> str:
    match = re.search(
        rf"^[0-9a-f]+ <{re.escape(name)}>:\n(.*?)(?=^[0-9a-f]+ <|\Z)",
        disassembly,
        re.MULTILINE | re.DOTALL,
    )
    if not match:
        raise ValueError(f"missing linked constructor: {name}")
    return match.group(1)


def verify(image: str, nm: str, objdump: str, required: list[str]) -> None:
    symbol_text = output(nm, "-a", image)
    symbols: dict[str, list[tuple[int, str]]] = {}
    for line in symbol_text.splitlines():
        match = re.fullmatch(r"([0-9a-f]+)\s+([A-Za-z])\s+(.+)", line)
        if match:
            address, kind, name = match.groups()
            symbols.setdefault(name, []).append((int(address, 16), kind))

    register = symbols.get("_vmbus_register_driver")
    if register is None or len(register) != 1 or register[0][1] != "T":
        raise ValueError(
            "_vmbus_register_driver is not the unique strong exported target: "
            f"{register}"
        )
    start = symbols.get("uk_ctortab_start")
    end = symbols.get("uk_ctortab_end")
    if start is None or end is None or len(start) != 1 or len(end) != 1:
        raise ValueError("missing unique final constructor table boundaries")
    table_start = start[0][0]
    table_end = end[0][0]
    if table_start >= table_end:
        raise ValueError("empty final constructor table")

    section_text = output(objdump, "-h", image)
    orphaned = re.findall(r"\.uk_ctortab(?!\s)(\S+)", section_text)
    if orphaned:
        raise ValueError(f"orphaned constructor sections: {orphaned}")

    disassembly = output(objdump, "-d", "--no-show-raw-insn", image)
    for driver in required:
        library = DRIVERS[driver]
        constructor = f"{library}_vmbus_register_driver"
        entry = f"__uk_ctortab1_{constructor}"
        constructor_symbols = symbols.get(constructor)
        if (
            constructor_symbols is None
            or len(constructor_symbols) != 1
            or constructor_symbols[0][1] not in ("T", "t")
        ):
            raise ValueError(
                f"{driver}: missing unique strong constructor: "
                f"{constructor_symbols}"
            )
        entries = symbols.get(entry)
        if entries is None or len(entries) != 1:
            raise ValueError(f"{driver}: missing priority-1 table entry {entry}")
        entry_address, entry_kind = entries[0]
        if entry_kind not in ("D", "d") or not (
            table_start <= entry_address < table_end
        ):
            raise ValueError(
                f"{driver}: constructor entry {entry_address:#x}/{entry_kind} "
                f"is outside [{table_start:#x}, {table_end:#x})"
            )
        body = function(disassembly, constructor)
        if not re.search(
            r"\b(?:call|jmp)\w*\b.*<_vmbus_register_driver>", body
        ):
            raise ValueError(
                f"{driver}: constructor does not call the strong VMBus "
                "registration target"
            )

    print(
        "PASS: final VMBus driver constructors are in uk_ctortab and call "
        f"the strong registration target: {', '.join(required)}"
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True)
    parser.add_argument("--nm", default="llvm-nm")
    parser.add_argument("--objdump", default="llvm-objdump")
    parser.add_argument(
        "--require-driver",
        action="append",
        choices=sorted(DRIVERS),
        default=[],
    )
    args = parser.parse_args()
    if not args.require_driver:
        parser.error("at least one --require-driver is required")
    try:
        verify(
            args.image,
            args.nm,
            args.objdump,
            list(dict.fromkeys(args.require_driver)),
        )
    except ValueError as error:
        raise SystemExit(f"FAIL: {error}") from error


if __name__ == "__main__":
    main()
