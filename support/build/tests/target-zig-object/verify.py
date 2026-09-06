#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause

import argparse
import subprocess


def output(*args):
    return subprocess.run(args, check=True, text=True, stdout=subprocess.PIPE).stdout


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--readelf", required=True)
    parser.add_argument("--nm", required=True)
    parser.add_argument("object")
    args = parser.parse_args()

    header = output(args.readelf, "--file-header", args.object)
    if "ELF64" not in header or "X86-64" not in header or "REL (Relocatable file)" not in header:
        raise SystemExit(f"unexpected target object header:\n{header}")

    symbols = output(args.nm, "--format=posix", args.object)
    if "issue34_zig_target_value" not in symbols:
        raise SystemExit("target object does not export issue34_zig_target_value")

    undefined = output(args.nm, "--undefined-only", "--format=posix", args.object)
    if undefined.strip():
        raise SystemExit(f"target object has unresolved runtime or libc symbols:\n{undefined}")


if __name__ == "__main__":
    main()
