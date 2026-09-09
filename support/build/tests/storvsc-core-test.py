#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause

import argparse
import subprocess


def output(*args: str) -> str:
    return subprocess.check_output(args, text=True)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--object", required=True)
    parser.add_argument("--nm", default="llvm-nm")
    parser.add_argument("--mapping-api-object", action="append", default=[])
    args = parser.parse_args()

    undefined = output(args.nm, "-u", args.object).strip()
    if undefined:
        raise SystemExit(
            "StorVSC core has external/runtime dependencies:\n" + undefined
        )
    symbols = output(args.nm, "-n", args.object)
    for symbol in (
        "storvsc_core_initialize",
        "storvsc_core_start",
        "storvsc_core_receive",
        "storvsc_core_tick",
        "storvsc_core_prepare_scsi",
        "storvsc_core_prepare_block",
        "storvsc_core_prepare_block_at",
        "storvsc_core_prepare_block_media",
        "storvsc_core_prepare_block_media_cdb",
        "storvsc_core_begin_reset",
        "storvsc_core_cancel_all",
        "storvsc_core_take_completed",
        "storvsc_build_report_luns",
        "storvsc_parse_report_luns",
        "storvsc_parse_vpd83",
        "storvsc_parse_inquiry",
        "storvsc_parse_capacity10",
        "storvsc_parse_capacity16",
        "storvsc_parse_mode_sense6",
        "storvsc_parse_mode_sense10",
    ):
        if symbol not in symbols:
            raise SystemExit(f"missing StorVSC core symbol: {symbol}")
    for path in args.mapping_api_object:
        references = {
            line.split()[0]
            for line in output(args.nm, "-u", "--format=posix", path).splitlines()
            if line.split()
        }
        for symbol in (
            "uk_storvsc_mapping_count",
            "uk_storvsc_mapping_get",
            "uk_storvsc_mapping_find",
            "uk_storvsc_inventory_get",
            "uk_storvsc_inventory_pristine_empty",
        ):
            if symbol not in references:
                raise SystemExit(f"missing unmangled mapping API in {path}: {symbol}")


if __name__ == "__main__":
    main()
