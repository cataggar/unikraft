#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause

import argparse
import os
import shlex
import shutil
import subprocess


def command(value):
    result = shlex.split(value)
    if not result:
        raise ValueError("tool command must not be empty")
    return result


def run(argv, **kwargs):
    subprocess.run(argv, check=True, **kwargs)  # nosec


def main():
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="action", required=True)

    strip = subparsers.add_parser("strip")
    strip.add_argument("--tool", required=True)
    strip.add_argument("--remove-section", action="append", default=[])
    strip.add_argument("input")
    strip.add_argument("output")

    bootinfo = subparsers.add_parser("bootinfo")
    bootinfo.add_argument("--script", required=True)
    bootinfo.add_argument("--objdump", required=True)
    bootinfo.add_argument("--objcopy", required=True)
    bootinfo.add_argument("--arch", required=True, choices=("x86_64", "arm64"))
    bootinfo.add_argument("--names", action="store_true")
    bootinfo.add_argument("input")
    bootinfo.add_argument("side_output")
    bootinfo.add_argument("output")

    multiboot = subparsers.add_parser("multiboot")
    multiboot.add_argument("--script", required=True)
    multiboot.add_argument("input")
    multiboot.add_argument("output")

    efi = subparsers.add_parser("efi")
    efi.add_argument("--script", required=True)
    efi.add_argument("--nm", required=True)
    efi.add_argument("--readelf", required=True)
    efi.add_argument("input")
    efi.add_argument("debug")
    efi.add_argument("output")

    binary = subparsers.add_parser("objcopy-binary")
    binary.add_argument("--tool", required=True)
    binary.add_argument("input")
    binary.add_argument("output")

    linux = subparsers.add_parser("linux-header")
    linux.add_argument("--script", required=True)
    linux.add_argument("--nm", required=True)
    linux.add_argument("input")
    linux.add_argument("elf")
    linux.add_argument("output")

    compile_database = subparsers.add_parser("compile-database")
    compile_database.add_argument("--script", required=True)
    compile_database.add_argument("--search-root", required=True)
    compile_database.add_argument("input_dependency")
    compile_database.add_argument("output")

    args = parser.parse_args()

    if args.action == "strip":
        remove = [item for section in args.remove_section for item in ("-R", section)]
        run([*command(args.tool), "-s", *remove, args.input, "-o", args.output])
    elif args.action == "bootinfo":
        env = os.environ.copy()
        env["OBJDUMP"] = args.objdump
        mkbootinfo = [
            args.script,
            args.input,
            args.side_output,
            "-a",
            args.arch,
        ]
        if args.names:
            mkbootinfo.append("-n")
        run([*command(os.environ.get("PYTHON", "python3")), *mkbootinfo], env=env)
        run(
            [
                *command(args.objcopy),
                args.input,
                f"--update-section=.uk_bootinfo={args.side_output}",
                args.output,
            ]
        )
    elif args.action == "multiboot":
        shutil.copyfile(args.input, args.output)
        run(
            [
                *command(os.environ.get("PYTHON", "python3")),
                args.script,
                args.output,
            ]
        )
    elif args.action == "efi":
        shutil.copyfile(args.input, args.output)
        env = os.environ.copy()
        env["NM"] = args.nm
        env["READELF"] = args.readelf
        run(
            [
                *command(os.environ.get("PYTHON", "python3")),
                args.script,
                "--debug",
                args.debug,
                args.output,
            ],
            env=env,
        )
    elif args.action == "objcopy-binary":
        run([*command(args.tool), "-O", "binary", args.input, args.output])
    elif args.action == "linux-header":
        shutil.copyfile(args.input, args.output)
        env = os.environ.copy()
        env["NM"] = args.nm
        run(
            [
                *command(os.environ.get("PYTHON", "python3")),
                args.script,
                args.output,
                args.elf,
            ],
            env=env,
        )
    elif args.action == "compile-database":
        with open(args.output, "wb") as output:
            run(
                [
                    *command(os.environ.get("PYTHON", "python3")),
                    args.script,
                    args.search_root,
                ],
                stdout=output,
            )


if __name__ == "__main__":
    main()
