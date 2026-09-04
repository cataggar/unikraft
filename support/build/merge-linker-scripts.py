#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026, The Unikraft Authors.

import re
import sys
from collections import defaultdict
from pathlib import Path


def masked(text):
    return re.sub(
        r"/\*.*?\*/|//[^\n]*|'(?:\\.|[^'\\])*'|\"(?:\\.|[^\"\\])*\"",
        lambda match: "\n" * match.group(0).count("\n")
        + " " * (len(match.group(0)) - match.group(0).count("\n")),
        text,
        flags=re.DOTALL,
    )


def matching_brace(text, opening):
    depth = 0
    for index in range(opening, len(text)):
        if text[index] == "{":
            depth += 1
        elif text[index] == "}":
            depth -= 1
            if depth == 0:
                return index
    raise ValueError("unmatched linker script brace")


def named_blocks(script, name):
    clean = masked(script)
    position = 0
    bodies = []
    while match := re.search(rf"\b{name}\s*\{{", clean[position:]):
        opening = clean.find("{", position + match.start())
        closing = matching_brace(clean, opening)
        bodies.append(script[opening + 1 : closing].strip())
        position = closing + 1
    return bodies


def sections_bodies(script):
    clean = masked(script)
    position = 0
    bodies = []
    while match := re.search(r"\bSECTIONS\s*\{", clean[position:]):
        start = position + match.start()
        opening = clean.find("{", start)
        closing = matching_brace(clean, opening)
        next_sections = re.search(r"\bSECTIONS\s*\{", clean[closing + 1 :])
        limit = (
            closing + 1 + next_sections.start()
            if next_sections
            else len(clean)
        )
        insert = re.search(
            r"\bINSERT\s+(AFTER|BEFORE)\s+([A-Za-z0-9_.$/]+)\s*;?",
            clean[closing + 1 : limit],
        )
        if not insert:
            raise ValueError(
                "supplemental linker script SECTIONS block has no "
                "INSERT directive"
            )
        bodies.append(
            (
                insert.group(1),
                insert.group(2),
                script[opening + 1 : closing].strip(),
            )
        )
        position = closing + 1 + insert.end()
    if not bodies:
        raise ValueError("linker script has no SECTIONS block")
    return bodies


def section_bounds(script, section):
    clean = masked(script)
    match = re.search(r"\bSECTIONS\s*\{", clean)
    if not match:
        raise ValueError("primary linker script has no SECTIONS block")
    opening = clean.find("{", match.start())
    closing = matching_brace(clean, opening)
    depth = 0
    pattern = re.compile(
        re.escape(section) + r"(?:\s+[^:{}\n]+)?\s*:"
    )
    for candidate in pattern.finditer(clean, opening + 1, closing):
        for char in clean[opening + 1 : candidate.start()]:
            if char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
        if depth:
            depth = 0
            continue
        block_open = clean.find("{", candidate.end(), closing)
        if block_open < 0:
            break
        block_close = matching_brace(clean, block_open)
        end = block_close + 1
        while True:
            trailer = re.match(
                r"\s*(?::[A-Za-z_][A-Za-z0-9_]*|>[A-Za-z_][A-Za-z0-9_]*"
                r"|AT\s*\([^)]*\)|=\s*[^\s;]+)",
                clean[end:],
            )
            if not trailer:
                break
            end += trailer.end()
        return candidate.start(), end
    raise ValueError(f"primary linker script has no {section} output section")


def main():
    if len(sys.argv) < 4:
        raise SystemExit(
            "usage: merge-linker-scripts.py OUTPUT PRIMARY SUPPLEMENT..."
        )

    output = Path(sys.argv[1])
    primary = Path(sys.argv[2])
    groups = defaultdict(list)
    order = []
    phdrs = []

    for name in sys.argv[3:]:
        supplement = Path(name).read_text()
        phdrs.extend(named_blocks(supplement, "PHDRS"))
        for mode, section, body in sections_bodies(supplement):
            key = (mode, section)
            if key not in groups:
                order.append(key)
            groups[key].append(body)

    result = primary.read_text()
    if phdrs:
        clean = masked(result)
        match = re.search(r"\bPHDRS\s*\{", clean)
        if match:
            opening = clean.find("{", match.start())
            closing = matching_brace(clean, opening)
            result = (
                result[:closing]
                + "\n"
                + "\n".join(phdrs)
                + "\n"
                + result[closing:]
            )
        else:
            result = "PHDRS\n{\n" + "\n".join(phdrs) + "\n}\n" + result

    for mode, section in order:
        start, end = section_bounds(result, section)
        insertion = "\n" + "\n".join(groups[(mode, section)]) + "\n"
        offset = start if mode == "BEFORE" else end
        result = result[:offset] + insertion + result[offset:]

    output.write_text(result)


if __name__ == "__main__":
    main()
