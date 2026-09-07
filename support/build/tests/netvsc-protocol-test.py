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
    args = parser.parse_args()

    undefined = output(args.nm, "-u", args.object).strip()
    if undefined:
        raise SystemExit(
            "NetVSC protocol core has external/runtime dependencies:\n" + undefined
        )
    symbols = output(args.nm, "-n", args.object)
    for symbol in (
        "netvsc_nvs_build_init",
        "netvsc_nvs_build_receive_buffer",
        "netvsc_nvs_parse_receive_buffer_complete",
        "netvsc_nvs_parse_transfer_range",
        "netvsc_rndis_build_initialize",
        "netvsc_rndis_build_query",
        "netvsc_rndis_build_set",
        "netvsc_rndis_build_keepalive",
        "netvsc_rndis_build_halt",
        "netvsc_rndis_build_packet_header",
        "netvsc_rndis_parse_completion",
        "netvsc_rndis_parse_packet",
        "netvsc_rndis_parse_status",
    ):
        if symbol not in symbols:
            raise SystemExit(f"missing NetVSC protocol symbol: {symbol}")


if __name__ == "__main__":
    main()
