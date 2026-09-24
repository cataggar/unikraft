#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""Compare test-only Zig normalization with the retained Python reference."""
import base64
import binascii
import importlib.util
from pathlib import Path
import random
import subprocess
import sys
import unicodedata

APP = Path(__file__).resolve().parents[1]
RUN = APP.parents[1] / "build/wamr-native-ci/run.py"
spec = importlib.util.spec_from_file_location("wamr_native_reference", RUN)
reference = importlib.util.module_from_spec(spec)
spec.loader.exec_module(reference)

# UnicodeData.txt 15.0.0, SHA-256
# 806e9aed65037197f1ec85e12be6e8cd870fc5608b4de0fffd990f689f376a73:
# all Unicode 16-printable scalars that Python 3.12 (Unicode 15) rejects.
UNICODE16_ONLY_PRINTABLE = (
    (0x897, 0x897), (0x1B4E, 0x1B4F), (0x1B7F, 0x1B7F),
    (0x1C89, 0x1C8A), (0x2427, 0x2429), (0x2FFC, 0x2FFF),
    (0x31E4, 0x31E5), (0x31EF, 0x31EF), (0xA7CB, 0xA7CD),
    (0xA7DA, 0xA7DC), (0x105C0, 0x105F3), (0x10D40, 0x10D65),
    (0x10D69, 0x10D85), (0x10D8E, 0x10D8F),
    (0x10EC2, 0x10EC4), (0x10EFC, 0x10EFC),
    (0x11380, 0x11389), (0x1138B, 0x1138B), (0x1138E, 0x1138E),
    (0x11390, 0x113B5), (0x113B7, 0x113C0),
    (0x113C2, 0x113C2), (0x113C5, 0x113C5),
    (0x113C7, 0x113CA), (0x113CC, 0x113D5),
    (0x113D7, 0x113D8), (0x113E1, 0x113E2),
    (0x116D0, 0x116E3), (0x11BC0, 0x11BE1),
    (0x11BF0, 0x11BF9), (0x11F5A, 0x11F5A),
    (0x13460, 0x143FA), (0x16100, 0x16139),
    (0x16D40, 0x16D79), (0x18CFF, 0x18CFF),
    (0x1CC00, 0x1CCF9), (0x1CD00, 0x1CEB3),
    (0x1E5D0, 0x1E5FA), (0x1E5FF, 0x1E5FF),
    (0x1F8B2, 0x1F8BB), (0x1F8C0, 0x1F8C1),
    (0x1FA89, 0x1FA89), (0x1FA8F, 0x1FA8F),
    (0x1FABE, 0x1FABE), (0x1FAC6, 0x1FAC6),
    (0x1FADC, 0x1FADC), (0x1FADF, 0x1FADF),
    (0x1FAE9, 0x1FAE9), (0x1FBCB, 0x1FBEF),
    (0x2EBF0, 0x2EE5D),
)

if unicodedata.unidata_version not in ("15.0.0", "16.0.0"):
    raise RuntimeError("Unicode 15 production parity requires Python Unicode 15 or 16")


def printable_15(char):
    if char in "\n\t":
        return True
    if not char.isprintable():
        return False
    return (unicodedata.unidata_version == "15.0.0" or
            not any(first <= ord(char) <= last
                    for first, last in UNICODE16_ONLY_PRINTABLE))


def compare(binary, mode, raw):
    actual = subprocess.run(
        [binary, mode, raw.hex()], capture_output=True, check=False, timeout=10)
    try:
        if mode == "optional" and len(raw) > 2 * 1024 * 1024:
            raise ValueError("optional serial bound")
        text = reference.normalize_serial(raw)
        if mode == "optional" and not all(map(printable_15, text)):
            raise ValueError("nonprintable optional serial")
        expected = text.encode()
    except (UnicodeDecodeError, ValueError):
        expected = None
    assert (actual.returncode == 0) == (expected is not None), (
        mode, raw.hex(), actual.returncode, expected)
    assert actual.stdout == (expected or b""), (mode, raw.hex())
    assert not actual.stderr, (mode, raw.hex(), actual.stderr)


def compare_base64(binary, value):
    actual = subprocess.run(
        [binary, "base64", value], capture_output=True, check=False, timeout=10)
    try:
        encoded = value.encode("ascii")
        decoded = base64.b64decode(encoded, validate=True)
        if len(decoded) > 4096 or base64.b64encode(decoded) != encoded:
            raise ValueError("noncanonical output")
    except (UnicodeError, ValueError, binascii.Error):
        decoded = None
    assert (actual.returncode == 0) == (decoded is not None), value
    assert actual.stdout == (decoded or b""), value
    assert not actual.stderr, (value, actual.stderr)


def main(binary):
    assert len(UNICODE16_ONLY_PRINTABLE) == 50
    assert sum(last - first + 1 for first, last in UNICODE16_ONLY_PRINTABLE) == 5812
    for index, (first, last) in enumerate(UNICODE16_ONLY_PRINTABLE):
        assert first <= last and (index == 0 or UNICODE16_ONLY_PRINTABLE[index - 1][1] < first)
        assert all(chr(cp).isprintable() == (unicodedata.unidata_version == "16.0.0")
                   for cp in range(first, last + 1))
    samples = [
        b"", b"plain\n", b"plain\r\n", b"plain\r",
        b"\0\x1b[1;32mWAMR_NATIVE_COMPUTE={}\x1b[0m\r\n\0",
        b"before\r\x1b[0m\n", b"\t", b"\x7f", b"\xc2\x85",
        b"\xe2\x80\xa8", b"\xe2\x80\x8b", b"\xcd\xb8", b"\xee\x80\x80",
        b"\xc3\xa9", b"\xc2\0\xa3", b"\xff", b"\xc0\xaf",
        b"\x1b", b"\x1b[", b"\x1b[0\0m", b"\x1b]title\x07",
        b"\x07", b"\v", b"\f", b"\x1b[?25l\n",
        b"x" * 8192 + b"\r\n", b"x" * 8193 + b"\n",
    ]
    random_source = random.Random(188)
    seed = b"WAMR_NATIVE_COMPUTE={}\r\n"
    for _ in range(192):
        value = bytearray(seed)
        for _ in range(random_source.randint(1, 4)):
            index = random_source.randrange(len(value))
            value[index] = random_source.randrange(256)
        samples.append(bytes(value))
    for _ in range(96):
        scalar = random_source.randrange(0x80, 0x110000)
        if not 0xd800 <= scalar <= 0xdfff:
            samples.append(chr(scalar).encode() + b"\n")
    for first, last in UNICODE16_ONLY_PRINTABLE:
        for scalar in {first - 1, first, (first + last) // 2, last, last + 1}:
            samples.append(chr(scalar).encode() + b"\n")
    samples.extend(scalar.encode() + b"\n" for scalar in (
        "\u00e9", "\u1b7e", "\U0001f600", "\U0001f8b1",
        "\U0001fabd", "\U0001fabf", "\U0001cc00",
        "\U0001ccf9", "\U0002ebf0",
    ))
    for mode in ("tiny", "optional"):
        for raw in samples:
            compare(binary, mode, raw)
    encoded = [
        "", "Zg==", "Zm8=", "Zm9v", "AP8=", "AAECAwQ=",
        "Zg", "Zg=", "Zg==\n", "Zh==", "_/8=", "Zg== ", "Zm9v=", "====",
    ]
    for _ in range(100):
        original = base64.b64encode(random_source.randbytes(
            random_source.randrange(0, 64))).decode()
        if original:
            at = random_source.randrange(len(original))
            original = original[:at] + random_source.choice("=+/_Az") + original[at+1:]
        encoded.append(original)
    for text in encoded:
        compare_base64(binary, text)
    print(f"native/Python differential: {2 * len(samples)} serial, {len(encoded)} base64 cases")


if __name__ == "__main__":
    main(sys.argv[1])
