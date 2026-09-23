#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""Compare test-only Zig normalization with the retained Python reference."""
import importlib.util
import base64
import binascii
from pathlib import Path
import random
import subprocess
import sys

APP = Path(__file__).resolve().parents[1]
RUN = APP.parents[1] / "build/wamr-native-ci/run.py"
spec = importlib.util.spec_from_file_location("wamr_native_reference", RUN)
reference = importlib.util.module_from_spec(spec)
spec.loader.exec_module(reference)


def compare(binary, mode, raw):
    actual = subprocess.run(
        [binary, mode, raw.hex()], capture_output=True, check=False, timeout=10)
    try:
        if mode == "optional" and len(raw) > 2 * 1024 * 1024:
            raise ValueError("optional serial bound")
        text = reference.normalize_serial(raw)
        if mode == "optional" and not all(
                char.isprintable() or char in "\n\t" for char in text):
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
