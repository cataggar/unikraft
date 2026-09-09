#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""Generate a private StorVSC persistence seed and Kconfig fragment."""

import argparse
import json
import os
import secrets
import struct
import zlib
from pathlib import Path

SECTOR_SIZE = 512
SEED0_LBA = 8
SEED1_LBA = 9
INTENT_LBA = 16
RECEIPT_LBA = 17
EXTENT_LBA = 32
EXTENT_SECTORS = 16
IDENTITY_POLICIES = {
    "address-v1": 1,
    "seed-enrollment-v2": 2,
}


def parse_id(value: str) -> bytes:
    if len(value) != 32 or any(c not in "0123456789abcdef" for c in value):
        raise argparse.ArgumentTypeError(
            "IDs must be exactly 32 lowercase hexadecimal digits"
        )
    return bytes.fromhex(value)


def manifest(run_id: bytes, disk_id: bytes, sectors: int,
             identity_policy: int, path: int, target: int, lun: int) -> bytes:
    if identity_policy not in IDENTITY_POLICIES.values():
        raise ValueError("unsupported identity policy")
    if identity_policy == 2 and (path or target):
        raise ValueError("seed-enrollment-v2 cannot bind path or target")
    record = bytearray(SECTOR_SIZE)
    record[0:8] = b"UKPSEED1" if identity_policy == 1 else b"UKPSEED2"
    struct.pack_into(
        "<HHI", record, 8, identity_policy, 128, SECTOR_SIZE
    )
    record[16:32] = run_id
    record[32:48] = disk_id
    struct.pack_into(
        "<QIIQQQQQI",
        record,
        48,
        sectors,
        SECTOR_SIZE,
        identity_policy,
        SEED0_LBA,
        SEED1_LBA,
        INTENT_LBA,
        RECEIPT_LBA,
        EXTENT_LBA,
        EXTENT_SECTORS,
    )
    if identity_policy == 1:
        struct.pack_into("<BBBB", record, 108, path, target, lun, 0)
    else:
        struct.pack_into("<BBBB", record, 108, identity_policy, 0, lun, 0)
    struct.pack_into("<I", record, 508, zlib.crc32(record))
    return bytes(record)


def create_private(path: Path, mode: str):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    return os.fdopen(descriptor, mode)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-prefix", required=True, type=Path)
    parser.add_argument("--sectors", required=True, type=int)
    parser.add_argument(
        "--identity-policy",
        choices=IDENTITY_POLICIES,
        default="address-v1",
    )
    parser.add_argument("--path", type=int)
    parser.add_argument("--target", type=int)
    parser.add_argument("--lun", required=True, type=int)
    parser.add_argument("--run-id", type=parse_id)
    parser.add_argument("--disk-id", type=parse_id)
    args = parser.parse_args()

    if args.sectors <= EXTENT_LBA + EXTENT_SECTORS:
        parser.error("disk is too small for the fixed persistence layout")
    if args.sectors > ((1 << 63) - 1) // SECTOR_SIZE:
        parser.error("disk size is not representable")
    identity_policy = IDENTITY_POLICIES[args.identity_policy]
    if identity_policy == 1 and (args.path is None or args.target is None):
        parser.error("address-v1 requires --path and --target")
    if identity_policy == 2 and (
        args.path is not None or args.target is not None
    ):
        parser.error("seed-enrollment-v2 does not accept --path or --target")
    path = args.path if args.path is not None else 0
    target = args.target if args.target is not None else 0
    if any(value < 0 or value > 255
           for value in (path, target, args.lun)):
        parser.error("path, target, and LUN must fit in one byte")
    args.output_prefix.parent.mkdir(parents=True, exist_ok=True)
    run_id = args.run_id or secrets.token_bytes(16)
    disk_id = args.disk_id or secrets.token_bytes(16)
    sector = manifest(
        run_id, disk_id, args.sectors, identity_policy,
        path, target, args.lun
    )

    raw_path = args.output_prefix.with_suffix(".raw")
    config_path = args.output_prefix.with_suffix(".config")
    json_path = args.output_prefix.with_suffix(".json")
    if any(path.exists() for path in (raw_path, config_path, json_path)):
        parser.error("output files already exist")
    with create_private(raw_path, "wb") as output:
        output.truncate(args.sectors * SECTOR_SIZE)
        output.seek(SEED0_LBA * SECTOR_SIZE)
        output.write(sector)
        output.write(sector)
    with create_private(config_path, "w") as output:
        output.write("CONFIG_APPHYPERVACCEPTANCE_PERSISTENCE=y\n")
        output.write("CONFIG_LIBSTORVSC_LUN_DISCOVERY=y\n")
        output.write("CONFIG_LIBSTORVSC_GUARDED_IO=y\n")
        output.write("CONFIG_LIBSTORVSC_MAX_DEVICES=2\n")
        output.write("CONFIG_LIBSTORVSC_MAX_LUNS=8\n")
        output.write(
            f'CONFIG_APPHYPERVACCEPTANCE_PERSISTENCE_RUN_ID="'
            f'{run_id.hex()}"\n'
        )
        output.write(
            f'CONFIG_APPHYPERVACCEPTANCE_PERSISTENCE_DISK_ID="'
            f'{disk_id.hex()}"\n'
        )
        output.write(
            f"CONFIG_APPHYPERVACCEPTANCE_PERSISTENCE_SECTORS="
            f"{args.sectors}\n"
        )
        output.write(
            "CONFIG_APPHYPERVACCEPTANCE_PERSISTENCE_SECTOR_SIZE=512\n"
        )
        output.write(
            "CONFIG_APPHYPERVACCEPTANCE_PERSISTENCE_IDENTITY_POLICY="
            f"{identity_policy}\n"
        )
        if identity_policy == 1:
            output.write(
                f"CONFIG_APPHYPERVACCEPTANCE_PERSISTENCE_PATH={path}\n"
            )
            output.write(
                f"CONFIG_APPHYPERVACCEPTANCE_PERSISTENCE_TARGET={target}\n"
            )
        output.write(
            f"CONFIG_APPHYPERVACCEPTANCE_PERSISTENCE_LUN={args.lun}\n"
        )
    with create_private(json_path, "w") as output:
        json.dump(
            {
                "version": identity_policy,
                "run_id": run_id.hex(),
                "disk_id": disk_id.hex(),
                "sectors": args.sectors,
                "sector_size": SECTOR_SIZE,
                "identity_policy": args.identity_policy,
                "identity_policy_version": identity_policy,
                "path": path if identity_policy == 1 else None,
                "target": target if identity_policy == 1 else None,
                "lun": args.lun,
                "seed_lbas": [SEED0_LBA, SEED1_LBA],
                "intent_lba": INTENT_LBA,
                "receipt_lba": RECEIPT_LBA,
                "extent_lba": EXTENT_LBA,
                "extent_sectors": EXTENT_SECTORS,
                "manifest_crc32": struct.unpack_from("<I", sector, 508)[0],
            },
            output,
            sort_keys=True,
        )
        output.write("\n")
    print(json_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
