# SPDX-License-Identifier: BSD-3-Clause
"""Neutral synthetic bytes for #187/#189 oracles; never acceptance evidence."""
import hashlib
import json
from pathlib import Path
import unittest


FIXTURES = Path(__file__).resolve().parent / "fixtures/differential"
MODES = (
    "raw-x2apic", "raw-legacy-apic", "qcow2-x2apic", "qcow2-legacy-apic",
    "vpc-x2apic", "vpc-legacy-apic",
)


def accepted_result(version):
    if type(version) is not int or version not in (1, 2):
        raise ValueError("unknown fixture version")
    return json.loads((FIXTURES / f"accepted-v{version}.json").read_bytes())


def write_result_fixture(evidence, version):
    value = accepted_result(version)
    for name in value["records"]:
        with (evidence / name).open("xb") as stream:
            stream.write(b"{}\n")
        (evidence / name).chmod(0o600)
    path = evidence / "result.json"
    with path.open("xb") as stream:
        stream.write((FIXTURES / f"accepted-v{version}.json").read_bytes())
    path.chmod(0o600)
    return value


class RecordFixtures(unittest.TestCase):
    def test_v1_v2_neutral_bytes_and_record_commitments(self):
        for version in (1, 2):
            with self.subTest(version=version):
                value = accepted_result(version)
                self.assertEqual(value["schema_version"], version)
                self.assertEqual(len(value["records"]), 8 if version == 1 else 33)
                self.assertNotIn("result.json", value["records"])
                self.assertEqual(set(value["records"].values()),
                                 {hashlib.sha256(b"{}\n").hexdigest()})
                raw = (FIXTURES / f"accepted-v{version}.json").read_bytes()
                self.assertEqual(raw, (json.dumps(
                    value, ensure_ascii=False, sort_keys=True,
                    separators=(",", ":")) + "\n").encode())
