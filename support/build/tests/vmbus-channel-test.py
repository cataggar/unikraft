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
            "VMBus channel core has external/runtime dependencies:\n" + undefined
        )
    symbols = output(args.nm, "-n", args.object)
    for symbol in (
        "vmbus_ring_initialize",
        "vmbus_ring_write",
        "vmbus_ring_read",
        "vmbus_gpadl_header",
        "vmbus_gpadl_body",
        "vmbus_open_message",
        "vmbus_close_message",
        "vmbus_gpadl_teardown_message",
        "vmbus_signal_event",
    ):
        if symbol not in symbols:
            raise SystemExit(f"missing VMBus channel symbol: {symbol}")


if __name__ == "__main__":
    main()
