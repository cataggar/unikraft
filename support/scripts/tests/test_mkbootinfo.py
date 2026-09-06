# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026, The Unikraft Authors.

import importlib
import sys
import unittest
from pathlib import Path

SCRIPTS_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(SCRIPTS_DIR))

mkbootinfo = importlib.import_module("mkbootinfo")
normalize_load_regions = mkbootinfo.normalize_load_regions


class NormalizeLoadRegionsTest(unittest.TestCase):
    def test_disjoint_segments_are_sorted_and_preserved(self):
        phdrs = [
            ("0x3000", "0x1000", "rw-"),
            ("0x2000", "0x0", "r--"),
            ("0x1000", "0x800", "r-x"),
        ]

        self.assertEqual(
            normalize_load_regions(phdrs),
            [
                (0x1000, 0x1000, "r-x"),
                (0x3000, 0x1000, "rw-"),
            ],
        )

    def test_nested_segment_with_matching_flags_is_folded(self):
        phdrs = [
            ("0x40131000", "0x4", "rw-"),
            ("0x40131000", "0x5d000", "rw-"),
        ]

        self.assertEqual(
            normalize_load_regions(phdrs),
            [(0x40131000, 0x5D000, "rw-")],
        )

    def test_partially_overlapping_segments_are_merged(self):
        phdrs = [
            ("0x2000", "0x1800", "rw-"),
            ("0x3000", "0x2000", "rw-"),
        ]

        self.assertEqual(
            normalize_load_regions(phdrs),
            [(0x2000, 0x3000, "rw-")],
        )

    def test_overlapping_permissions_are_rejected(self):
        phdrs = [
            ("0x1000", "0x2000", "r-x"),
            ("0x2000", "0x1000", "rw-"),
        ]

        with self.assertRaisesRegex(ValueError, "incompatible flags"):
            normalize_load_regions(phdrs)


if __name__ == "__main__":
    unittest.main()
