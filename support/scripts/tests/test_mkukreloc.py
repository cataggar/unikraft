# SPDX-License-Identifier: BSD-3-Clause

import importlib
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
reloc = importlib.import_module("mkukreloc")


class RelocationSectionTest(unittest.TestCase):
    def section(self, size=76, flags="A"):
        return {"Address": 0x1000, "Size": size, "Flags": flags}

    def test_exact_fit_includes_signature_and_sentinel(self):
        reloc.validate_reloc_section(self.section(), 0x1000, 0x104C, 2)

    def test_nonallocated_lld_section_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "must be allocated"):
            reloc.validate_reloc_section(self.section(flags=""), 0x1000, 0x104C, 2)

    def test_header_and_sentinel_space_is_required(self):
        with self.assertRaisesRegex(ValueError, "including signature and sentinel"):
            reloc.validate_reloc_section(self.section(48), 0x1000, 0x1030, 2)

    def test_adjacent_dynamic_sections_are_not_relocation_storage(self):
        with self.assertRaisesRegex(ValueError, "only 28 bytes"):
            reloc.validate_reloc_section(self.section(28), 0x1000, 0x2000, 2)

    def test_linker_bounds_must_cover_payload(self):
        with self.assertRaisesRegex(ValueError, "only 28 bytes"):
            reloc.validate_reloc_section(self.section(), 0x1000, 0x101C, 2)

    def test_linker_start_must_match_section(self):
        with self.assertRaisesRegex(ValueError, "do not match"):
            reloc.validate_reloc_section(self.section(), 0, 0x104C, 2)

    def test_previously_populated_section_can_be_processed_again(self):
        reloc.validate_reloc_section(self.section(), 0x1000, 0x2000, 2)


if __name__ == "__main__":
    unittest.main()
