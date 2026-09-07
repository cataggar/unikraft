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
            "VMBus protocol object has external/runtime dependencies:\n"
            + undefined
        )

    symbols = output(args.nm, "-n", args.object)
    for symbol in (
        "vmbus_post_input",
        "vmbus_post_message",
        "vmbus_protocol_start",
        "vmbus_protocol_receive",
        "vmbus_protocol_tick",
        "vmbus_protocol_unload",
        "vmbus_protocol_state",
        "vmbus_protocol_generation",
        "vmbus_protocol_version",
    ):
        if symbol not in symbols:
            raise SystemExit(f"missing VMBus protocol symbol: {symbol}")


if __name__ == "__main__":
    main()
