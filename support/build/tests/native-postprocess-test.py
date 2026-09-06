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
    linux = base / "support/scripts/mklinux.py"
    compile_database = base / "support/scripts/mkcompiledb.py"

    with tempfile.TemporaryDirectory(prefix="post process ", dir=work_root) as temp:
        root = pathlib.Path(temp)
        fake_strip = root / "strip tool.py"
        fake_objdump = root / "objdump tool.py"
        fake_objcopy = root / "objcopy tool.py"
        fake_nm = root / "nm tool.py"
        write_executable(
            fake_strip,
            """#!/usr/bin/env python3
import pathlib, shutil, sys
shutil.copyfile(sys.argv[sys.argv.index("-s") + 1], sys.argv[sys.argv.index("-o") + 1])
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
else:
    shutil.copyfile(sys.argv[1], sys.argv[-1])
""",
        )
        write_executable(
            fake_nm,
            """#!/usr/bin/env python3
print("0000000040000000 A _start_ram_addr")
print("0000000040200040 A _base_addr")
print("0000000040200080 T _libkvmplat_entry")
""",
        )
        strip_cmd = f"{shlex.quote(sys.executable)} {shlex.quote(str(fake_strip))}"
        objdump_cmd = f"{shlex.quote(sys.executable)} {shlex.quote(str(fake_objdump))}"
        objcopy_cmd = f"{shlex.quote(sys.executable)} {shlex.quote(str(fake_objcopy))}"
        nm_cmd = f"{shlex.quote(sys.executable)} {shlex.quote(str(fake_nm))}"

        x86_debug = root / "x86 debug.elf"
        x86_image = root / "x86 stripped.elf"
        x86_side = root / "x86 boot info.bin"
        x86_bootinfo = root / "x86 with boot info.elf"
        x86_final = root / "x86 multiboot image.elf"
        x86_debug.write_bytes(elf64(62))
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
