#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause

import argparse
import pathlib
import shlex
import struct
import subprocess
import sys
import tempfile


def write_executable(path, body):
    path.write_text(body, encoding="utf-8")
    path.chmod(0o755)


def elf64(machine):
    ident = b"\x7fELF\x02\x01\x01" + b"\0" * 9
    return ident + struct.pack("<HHIQQQIHHHHHH", 2, machine, 1, 0, 64, 64, 0, 64, 56, 0, 64, 0, 0)


def invoke(runner, *args):
    subprocess.run([sys.executable, runner, *map(str, args)], check=True)  # nosec


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--work-dir", required=True)
    parser.add_argument("--base", required=True)
    args = parser.parse_args()
    work_root = pathlib.Path(args.work_dir)
    work_root.mkdir(parents=True, exist_ok=True)
    base = pathlib.Path(args.base)
    runner = base / "support/build/native-postprocess-runner.py"
    bootinfo = base / "support/scripts/mkbootinfo.py"
    multiboot = base / "support/scripts/multiboot.py"
    efi = base / "support/scripts/mkefi.py"
    linux = base / "support/scripts/mklinux.py"
    compile_database = base / "support/scripts/mkcompiledb.py"

    with tempfile.TemporaryDirectory(prefix="post process ", dir=work_root) as temp:
        root = pathlib.Path(temp)
        fake_strip = root / "strip tool.py"
        fake_objdump = root / "objdump tool.py"
        fake_objcopy = root / "objcopy tool.py"
        fake_nm = root / "nm tool.py"
        fake_reloc = root / "mkukreloc.py"
        write_executable(
            fake_strip,
            """#!/usr/bin/env python3
import pathlib, shutil, sys
shutil.copyfile(sys.argv[sys.argv.index("-o") - 1], sys.argv[sys.argv.index("-o") + 1])
""",
        )
        write_executable(
            fake_objdump,
            """#!/usr/bin/env python3
import sys
if "-h" in sys.argv:
    print("  1 .uk_bootinfo 00000100  00000000")
else:
    print(" LOAD off 0x0 vaddr 0x400000 paddr 0x400000")
    print("      filesz 0x100 memsz 0x1000 flags rw-")
""",
        )
        write_executable(
            fake_objcopy,
            """#!/usr/bin/env python3
import pathlib, shutil, sys
if "-O" in sys.argv:
    shutil.copyfile(sys.argv[-2], sys.argv[-1])
elif sys.argv[1].startswith("--update-section=.uk_reloc="):
    target = pathlib.Path(sys.argv[-1])
    reloc = pathlib.Path(sys.argv[1].removeprefix("--update-section=.uk_reloc=")).read_bytes()
    target.write_bytes(target.read_bytes() + reloc)
else:
    shutil.copyfile(sys.argv[1], sys.argv[-1])
""",
        )
        write_executable(
            fake_reloc,
            """#!/usr/bin/env python3
import argparse, pathlib
parser = argparse.ArgumentParser()
parser.add_argument("--output", required=True)
parser.add_argument("elf")
args = parser.parse_args()
pathlib.Path(args.output).write_bytes((0x0BADB0B0).to_bytes(4, "little") + bytes(24))
""",
        )
        write_executable(
            fake_nm,
            """#!/usr/bin/env python3
print("0000000040000000 A _start_ram_addr")
print("0000000040200040 A _base_addr")
print("0000000040202f00 A __bss_start")
print("0000000040200040 T uk_efi_entry64")
print("0000000040200080 T _libkvmplat_entry")
""",
        )
        fake_readelf = root / "readelf tool.py"
        write_executable(
            fake_readelf,
            """#!/usr/bin/env python3
print(" LOAD 0x000000 0x0000000040200000 0x0000000040200000 0x1000 0x1000 R E 0x1000")
print(" LOAD 0x001000 0x0000000040201000 0x0000000040201000 0x1000 0x2000 RW  0x1000")
""",
        )
        strip_cmd = f"{shlex.quote(sys.executable)} {shlex.quote(str(fake_strip))}"
        objdump_cmd = f"{shlex.quote(sys.executable)} {shlex.quote(str(fake_objdump))}"
        objcopy_cmd = f"{shlex.quote(sys.executable)} {shlex.quote(str(fake_objcopy))}"
        nm_cmd = f"{shlex.quote(sys.executable)} {shlex.quote(str(fake_nm))}"
        readelf_cmd = f"{shlex.quote(sys.executable)} {shlex.quote(str(fake_readelf))}"

        x86_debug = root / "x86 debug.elf"
        x86_image = root / "x86 stripped.elf"
        x86_side = root / "x86 boot info.bin"
        x86_bootinfo = root / "x86 with boot info.elf"
        x86_final = root / "x86 multiboot image.elf"
        x86_debug.write_bytes(elf64(62))
        x86_relocations = root / "x86 relocations.bin"
        x86_relocated = root / "x86 relocated.elf"
        invoke(
            runner,
            "uk-reloc",
            "--script",
            fake_reloc,
            "--nm",
            nm_cmd,
            "--readelf",
            readelf_cmd,
            "--objcopy",
            objcopy_cmd,
            x86_debug,
            x86_relocations,
            x86_relocated,
        )
        assert x86_relocations.read_bytes()[:4] == (0x0BADB0B0).to_bytes(
            4, "little"
        )
        assert x86_relocated.read_bytes().endswith(x86_relocations.read_bytes())
        invoke(runner, "strip", "--tool", strip_cmd, x86_debug, x86_image)
        invoke(
            runner,
            "bootinfo",
            "--script",
            bootinfo,
            "--objdump",
            objdump_cmd,
            "--objcopy",
            objcopy_cmd,
            "--arch",
            "x86_64",
            x86_image,
            x86_side,
            x86_bootinfo,
        )
        invoke(runner, "multiboot", "--script", multiboot, x86_bootinfo, x86_final)
        x86_data = x86_final.read_bytes()
        assert x86_side.read_bytes()[:4] == (0xB007B0B0).to_bytes(4, "little")
        assert x86_data[:5] == b"\x7fELF\x01"
        assert x86_data[18:20] == (3).to_bytes(2, "little")
        assert x86_data[52:56] == (0x1BADB002).to_bytes(4, "little")

        efi_image = root / "x86 EFI image.elf"
        invoke(
            runner,
            "efi",
            "--script",
            efi,
            "--nm",
            nm_cmd,
            "--readelf",
            readelf_cmd,
            x86_image,
            x86_debug,
            efi_image,
        )
        efi_data = efi_image.read_bytes()
        assert efi_data[:2] == b"MZ"
        assert efi_data[64:68] == b"PE\0\0"
        assert efi_data[68:70] == (0x8664).to_bytes(2, "little")

        arm_debug = root / "arm debug.elf"
        arm_image = root / "arm stripped.elf"
        arm_side = root / "arm boot info.bin"
        arm_bootinfo = root / "arm with boot info.elf"
        arm_binary = root / "arm raw image.bin"
        arm_final = root / "arm Linux Image"
        arm_debug.write_bytes(elf64(183))
        invoke(runner, "strip", "--tool", strip_cmd, arm_debug, arm_image)
        invoke(
            runner,
            "bootinfo",
            "--script",
            bootinfo,
            "--objdump",
            objdump_cmd,
            "--objcopy",
            objcopy_cmd,
            "--arch",
            "arm64",
            arm_image,
            arm_side,
            arm_bootinfo,
        )
        invoke(
            runner,
            "objcopy-binary",
            "--tool",
            objcopy_cmd,
            arm_bootinfo,
            arm_binary,
        )
        raw = arm_binary.read_bytes()
        invoke(
            runner,
            "linux-header",
            "--script",
            linux,
            "--nm",
            nm_cmd,
            arm_binary,
            arm_debug,
            arm_final,
        )
        arm_data = arm_final.read_bytes()
        assert arm_data[56:60] == b"ARM\x64"
        assert int.from_bytes(arm_data[8:16], "little") == 0x200000
        assert int.from_bytes(arm_data[24:32], "little") == 0xA
        assert arm_data[64:] == raw

        compile_root = root / "compile database inputs"
        nested = compile_root / "nested dir"
        nested.mkdir(parents=True)
        (compile_root / "first.ukcmpdb.json").write_text(
            '{"directory":"/one","file":"one.c","command":"cc one.c"},\n',
            encoding="utf-8",
        )
        (nested / "second.ukcmpdb.json").write_text(
            '{"directory":"/two","file":"two.c","command":"cc two.c"},\n',
            encoding="utf-8",
        )
        compile_output = root / "compile commands.json"
        invoke(
            runner,
            "compile-database",
            "--script",
            compile_database,
            "--search-root",
            compile_root,
            arm_final,
            compile_output,
        )
        database = compile_output.read_text(encoding="utf-8")
        assert database.startswith("[\n")
        assert '"file":"one.c"' in database
        assert '"file":"two.c"' in database
        assert database.endswith("\n]\n")


if __name__ == "__main__":
    main()
