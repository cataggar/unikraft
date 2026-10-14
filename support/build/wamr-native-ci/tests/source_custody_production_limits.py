#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""Compatibility launcher for the native production-limit gate, not an oracle.

The five former ProductionSourceCustodyLimits scenarios map to the real native
exact/excess tests in controller/source_custody_limits_tests.zig; see
controller_coverage.py. No constants or file enumeration are checked by Python.
Pass the existing Zig build's private cache/system/optimization arguments after
this script. This entry point remains excluded from unittest discovery.
"""
from pathlib import Path
import subprocess
import sys


def main(arguments):
    root = Path(__file__).resolve().parents[4]
    return subprocess.run([
        "zig", "build", "--build-file",
        str(root / "support/build/wamr-native-ci/build.zig"),
        "test-controller-limits", "-j1", *arguments,
    ], cwd=root, check=False).returncode


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
