#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause

"""Check the returning SynIC IRQ graph in a final, unstripped x86-64 ELF.

Follow linked addresses (including tail branches and Zig symbol aliases), not
object-file relocations: export localization can otherwise hide a weak fallback.
Indirect edges are the native IRQ event, the registered SynIC/timer callbacks,
and schedcoop's thread_woken_isr callback. Protocol offers, channel callbacks
and drivers are consumed by the worker, not the interrupt.
"""

import argparse
import re
import subprocess


ROOTS = (
    "hyperv_message_irq",
    "hyperv_timer_irq",
    "hyperv_time_mark_pending",
    "hyperv_vmbus_message",
    "hyperv_vmbus_event",
    "hyperv_vmbus_event_word",
)
STRONG = ROOTS[3:]
INDIRECT = {
    "uk_plat_native_except_irq_handler": ("uk_intctlr_xpic_handle_irq",),
    "uk_intctlr_irq_handle": ROOTS[:3],
    "uk_thread_wake_isr": ("schedcoop_thread_woken_isr",),
}
REGISTERS = re.compile(r"%(?:[xyz]mm\d+|mm\d+|st(?:\(\d+\))?|k[0-7]|tmm\d+)\b")
STATE = re.compile(
    r"^(?:f\w+|v\w+|emms|ldmxcsr|stmxcsr|[fl]x(?:save|rstor)\w*|"
    r"x(?:save|rstor)\w*|k(?:mov|and|or|xor|not|shift|test|unpck)\w*)$"
)


def output(*args):
    return subprocess.check_output(args, text=True)


def terminal_assertion(instructions, index):
    """Only exempt logging followed straight-line by a fatal UD2, never return."""
    for _, op, _ in instructions[index + 1:]:
        if op == "ud2":
            return True
        if op.startswith(("j", "call", "ret", "loop")):
            return False
    return False


def schedcoop_callback_bound(functions, symbols, constructor, callback):
    """Follow scheduler constructor wrappers to the callback assignment."""
    pending = [symbols[constructor]]
    visited = set()
    while pending:
        address = pending.pop()
        if address in visited or address not in functions:
            continue
        visited.add(address)
        _, instructions = functions[address]
        for _, op, operands in instructions:
            if f"<{callback}>" in operands:
                return True
            if not op.startswith(("call", "j")) or operands.startswith("*"):
                continue
            target = re.match(r"(?:0x)?([0-9a-f]+)\s+<", operands)
            if not target:
                continue
            destination = int(target[1], 16)
            if destination in functions and "schedcoop_create" in functions[destination][0]:
                pending.append(destination)
    return False


def verify_schedcoop_callbacks(functions, symbols):
    constructors = tuple(
        name for name in ("uk_schedcoop_create", "uk_schedcoop_create_on")
        if name in symbols
    )
    if not constructors:
        raise ValueError("schedcoop constructor binding not found")
    for constructor in constructors:
        if not schedcoop_callback_bound(
            functions, symbols, constructor, "schedcoop_thread_woken_isr"
        ):
            raise ValueError(
                f"{constructor}: schedcoop wake callback binding not found"
            )


def verify(image, nm, objdump):
    symbols = {}
    kinds = {}
    symbol_table = output(nm, "-a", image)
    for line in symbol_table.splitlines():
        match = re.fullmatch(r"([0-9a-f]+)\s+([TtWw])\s+(.+)", line)
        if match:
            address, kind, name = match.groups()
            symbols[name] = int(address, 16)
            kinds.setdefault(name, []).append(kind)
    for name in STRONG:
        if kinds.get(name) != ["T"]:
            raise ValueError(f"{name}: expected unique strong export, got {kinds.get(name)}")
    irq_events = re.findall(
        r"\b_uk_event_native_except_event_irq_\d+_(\w+)$", symbol_table, re.MULTILINE
    )
    if irq_events != ["uk_intctlr_xpic_handle_irq"]:
        raise ValueError(f"unreviewed native IRQ event handlers: {irq_events}")

    functions = {}
    current = None
    disassembly = output(objdump, "-d", "--no-show-raw-insn", image)
    for line in disassembly.splitlines():
        label = re.fullmatch(r"([0-9a-f]+) <(.+)>:", line)
        if label:
            current = int(label[1], 16)
            functions[current] = (label[2], [])
            continue
        instruction = re.match(r"\s*([0-9a-f]+):\s+(\S+)\s*(.*)", line)
        if instruction and current is not None:
            functions[current][1].append(
                (int(instruction[1], 16), instruction[2], instruction[3])
            )

    pending = [symbols["uk_plat_native_except_irq_handler"]]
    visited = set()
    fatal_logs = 0
    indirect_counts = dict.fromkeys(INDIRECT, 0)
    while pending:
        address = pending.pop()
        if address in visited:
            continue
        visited.add(address)
        if address not in functions:
            raise ValueError(f"no disassembly for IRQ target {address:#x}")
        name, instructions = functions[address]
        local = {addr for addr, _, _ in instructions}
        for index, (addr, op, operands) in enumerate(instructions):
            if REGISTERS.search(operands) or STATE.fullmatch(op):
                raise ValueError(f"{name}+{addr-address:#x}: unsaved FP/SIMD: {op} {operands}")
            if not op.startswith(("call", "j", "loop")):
                continue
            if operands.startswith("*"):
                caller = next((key for key in INDIRECT if symbols.get(key) == address), None)
                if caller is None or not op.startswith("call"):
                    raise ValueError(f"{name}: unreviewed indirect IRQ edge: {op} {operands}")
                if caller == "uk_thread_wake_isr":
                    verify_schedcoop_callbacks(functions, symbols)
                elif caller == "uk_intctlr_irq_handle":
                    # For SynIC vectors, time.c registers these three callbacks.
                    constructor = functions[symbols["ukplat_time_init"]][1]
                    for callback in ROOTS[:3]:
                        if not any(f"<{callback}>" in args for _, _, args in constructor):
                            raise ValueError(f"SynIC callback binding not found: {callback}")
                pending.extend(symbols[callback] for callback in INDIRECT[caller])
                indirect_counts[caller] += 1
                continue
            target = re.match(r"(?:0x)?([0-9a-f]+)\s+<", operands)
            if not target:
                raise ValueError(f"{name}: unresolved IRQ edge: {op} {operands}")
            destination = int(target[1], 16)
            if destination in local:
                continue
            if destination == symbols.get("_uk_printk") and terminal_assertion(instructions, index):
                fatal_logs += 1
                continue
            pending.append(destination)

    required = ROOTS + (
        "hyperv_synic_message_take_page",
        "hyperv_synic_event_take_word_page",
        "vmbus_protocol_state",
        "vmbus_protocol_generation",
        "vmbus_protocol_version",
        "uk_thread_wake_isr",
        "schedcoop_thread_woken_isr",
    )
    for name in required:
        if symbols[name] not in visited:
            raise ValueError(f"IRQ graph did not reach {name}")
    expected_indirect = dict(zip(INDIRECT, (1, 2, 1)))
    if indirect_counts != expected_indirect:
        raise ValueError(f"unreviewed indirect callback counts: {indirect_counts}")
    print(f"PASS: {len(visited)} returning IRQ functions, no FP/SIMD; "
          f"{sum(indirect_counts.values())} reviewed indirect call sites; "
          f"{fatal_logs} terminal assertion log calls excluded")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True)
    parser.add_argument("--nm", default="llvm-nm")
    parser.add_argument("--objdump", default="llvm-objdump")
    args = parser.parse_args()
    try:
        verify(args.image, args.nm, args.objdump)
    except (KeyError, ValueError) as error:
        raise SystemExit(f"FAIL: {error}") from error


if __name__ == "__main__":
    main()
