# SPDX-License-Identifier: BSD-3-Clause

import json
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import unittest
import uuid
import zlib


ROOT = Path(__file__).resolve().parents[3]
GENERATOR = ROOT / "support" / "scripts" / "hyperv-storage-manifest.py"
RUN_ID = "00112233445566778899aabbccddeeff"
DISK_ID = "102132435465768798a9bacbdcedfe0f"


class StorageManifestTests(unittest.TestCase):
    def setUp(self):
        base = ROOT / ".d" / "storage-manifest-tests"
        base.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.directory = base / uuid.uuid4().hex
        self.directory.mkdir(mode=0o700)

    def tearDown(self):
        shutil.rmtree(self.directory)

    def run_generator(self, *arguments, success=True):
        result = subprocess.run(
            [
                sys.executable,
                str(GENERATOR),
                "--output-prefix",
                str(self.directory / "seed"),
                "--sectors",
                "4096",
                "--lun",
                "7",
                "--run-id",
                RUN_ID,
                "--disk-id",
                DISK_ID,
                *arguments,
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode == 0, success, result.stderr)
        return result

    def read_outputs(self):
        raw = self.directory / "seed.raw"
        config = self.directory / "seed.config"
        receipt = self.directory / "seed.json"
        for path in (raw, config, receipt):
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        with raw.open("rb") as source:
            source.seek(8 * 512)
            seed0 = source.read(512)
            seed1 = source.read(512)
        self.assertEqual(seed0, seed1)
        self.assertEqual(len(seed0), 512)
        stored_crc = struct.unpack_from("<I", seed0, 508)[0]
        copy = bytearray(seed0)
        copy[508:512] = b"\0" * 4
        self.assertEqual(stored_crc, zlib.crc32(copy))
        return seed0, config.read_text(), json.loads(receipt.read_text())

    def test_address_v1_remains_default_and_address_bound(self):
        self.run_generator("--path", "4", "--target", "5")
        seed, config, receipt = self.read_outputs()
        self.assertEqual(seed[:8], b"UKPSEED1")
        self.assertEqual(struct.unpack_from("<H", seed, 8)[0], 1)
        self.assertEqual(struct.unpack_from("<I", seed, 60)[0], 1)
        self.assertEqual(seed[108:112], bytes((4, 5, 7, 0)))
        self.assertIn(
            "CONFIG_APPHYPERVACCEPTANCE_PERSISTENCE_IDENTITY_POLICY=1\n",
            config,
        )
        self.assertIn(
            "CONFIG_APPHYPERVACCEPTANCE_PERSISTENCE_PATH=4\n", config
        )
        self.assertIn(
            "CONFIG_APPHYPERVACCEPTANCE_PERSISTENCE_TARGET=5\n", config
        )
        self.assertEqual(receipt["identity_policy"], "address-v1")
        self.assertEqual(receipt["version"], 1)
        self.assertEqual(receipt["identity_policy_version"], 1)
        self.assertEqual(receipt["path"], 4)
        self.assertEqual(receipt["target"], 5)

    def test_seed_enrollment_v2_binds_policy_lun_and_geometry(self):
        self.run_generator("--identity-policy", "seed-enrollment-v2")
        seed, config, receipt = self.read_outputs()
        self.assertEqual(seed[:8], b"UKPSEED2")
        self.assertEqual(struct.unpack_from("<H", seed, 8)[0], 2)
        self.assertEqual(struct.unpack_from("<I", seed, 60)[0], 2)
        self.assertEqual(seed[108:112], bytes((2, 0, 7, 0)))
        self.assertIn(
            "CONFIG_APPHYPERVACCEPTANCE_PERSISTENCE_IDENTITY_POLICY=2\n",
            config,
        )
        self.assertNotIn(
            "CONFIG_APPHYPERVACCEPTANCE_PERSISTENCE_PATH=", config
        )
        self.assertNotIn(
            "CONFIG_APPHYPERVACCEPTANCE_PERSISTENCE_TARGET=", config
        )
        self.assertEqual(receipt["identity_policy"], "seed-enrollment-v2")
        self.assertEqual(receipt["version"], 2)
        self.assertEqual(receipt["identity_policy_version"], 2)
        self.assertIsNone(receipt["path"])
        self.assertIsNone(receipt["target"])
        self.assertEqual(receipt["lun"], 7)
        self.assertEqual(receipt["sectors"], 4096)

    def test_policy_specific_arguments_fail_closed(self):
        result = self.run_generator(success=False)
        self.assertIn("address-v1 requires --path and --target", result.stderr)
        shutil.rmtree(self.directory)
        self.directory.mkdir(mode=0o700)
        result = self.run_generator(
            "--identity-policy",
            "seed-enrollment-v2",
            "--path",
            "0",
            "--target",
            "0",
            success=False,
        )
        self.assertIn(
            "seed-enrollment-v2 does not accept --path or --target",
            result.stderr,
        )


if __name__ == "__main__":
    unittest.main()
