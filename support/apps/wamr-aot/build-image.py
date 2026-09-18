#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""Use the existing native Zig graph and its safety gates, not a deployer."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess

ROOT = Path(__file__).resolve().parent
REPO = ROOT.parents[2]


def tool(name):
    path = shutil.which(name)
    if not path:
        raise RuntimeError(f"required build tool unavailable: {name}")
    return str(Path(path).resolve(strict=True))


def sha(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def bison_data():
    configured = os.environ.get("BISON_PKGDATADIR")
    if configured is None:
        configured = subprocess.check_output(
            [tool("bison"), "--print-datadir"], text=True).strip()
    path = Path(configured)
    if not path.is_absolute():
        raise ValueError("Bison data must be an explicit absolute directory")
    path = path.resolve(strict=True)
    if not path.is_dir():
        raise ValueError("Bison data must be a directory")
    return str(path)


def record(command):
    output = ROOT / "build"
    names = ("wamr_hyperv-x86_64-efi", "wamr_hyperv-x86_64-efi.dbg",
             "wamr_hyperv-x86_64-efi.bootinfo")
    manifest = {
        "schema_version": 1,
        "command": command,
        "scope": "native-build-only-not-boot-or-hardware-qualification",
        "unikraft_revision": subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=REPO, text=True).strip(),
        "unikraft_diff_sha256": hashlib.sha256(subprocess.check_output(
            ["git", "diff", "HEAD", "--binary"], cwd=REPO)).hexdigest(),
        "application_sources": {
            p.name: sha(p) for p in sorted(ROOT.iterdir()) if p.is_file()
            and not p.name.startswith(".")
        },
        "tools": {name: sha(tool(name)) for name in (
            "zig", "make", "llvm-nm", "llvm-objcopy", "llvm-objdump",
            "llvm-readelf", "llvm-strip", "bison", "flex")},
        "files": {name: sha(output / name) for name in names},
        "solved_config_sha256": sha(ROOT / ".config"),
        "runtime_inputs_sha256": sha(output / "artifacts/identity.json"),
    }
    path = output / "image-identity.json"
    path.write_text(json.dumps(manifest, sort_keys=True, indent=2) + "\n")
    path.chmod(0o600)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("step", choices=("olddefconfig", "native-images"))
    args = parser.parse_args()
    state = ROOT / "build" / "native-environment"
    state.mkdir(mode=0o700, parents=True, exist_ok=True)
    state.chmod(0o700)
    contract = {
        "bison_data": bison_data(),
        "m4": tool("m4"),
        "schema": "unikraft_native_make_environment_v1",
        "shell": tool("bash"),
    }
    for name in ("tmp", "xdg_cache", "xdg_config", "zig_global_cache",
                 "zig_local_cache"):
        path = state / name
        path.mkdir(mode=0o700, exist_ok=True)
        path.chmod(0o700)
        contract[name] = str(path)
    environment = state / "environment.json"
    environment.write_text(json.dumps(contract, sort_keys=True,
                                      separators=(",", ":")) + "\n")
    environment.chmod(0o600)
    if not (ROOT / ".config").exists():
        shutil.copyfile(ROOT / "defconfig", ROOT / ".config")
        manifest = json.loads((ROOT / "build/artifacts/identity.json").read_text())
        if manifest.get("variant", "tiny") != "tiny":
            with (ROOT / ".config").open("a") as config:
                config.write("\nCONFIG_STACK_SIZE_PAGE_ORDER=8\n")
                mode = {None: 0, "fast": 1, "full": 2}[manifest["jit_mode"]]
                config.write(f"CONFIG_APPWAMRAOT_JIT_BOOT_MODE={mode}\n")
    zig = tool("zig")
    command = [
        zig, "build", args.step, "-j2",
        f"-Dapp={ROOT}", f"-Dnative-make-environment={environment}",
        f"-Dmake-command={tool('make')}",
        f"-Dcompiler={zig} cc -target x86_64-freestanding-none",
        "-Dcompiler-targeted=true", f"-Dhost-cc={zig} cc",
        f"-Dhost-cxx={zig} c++", "-Dhost-cflags=-fno-sanitize=null",
        f"-Dmake-arg=AR={zig} ar",
        "-Dmake-arg=KCONFIG_OVERWRITECONFIG=1",
        "-Dmake-arg=UK_CFLAGS=-std=gnu17",
        "-Dmake-arg=UK_LDFLAGS=-rtlib=compiler-rt",
    ]
    for variable, name in (("NM", "llvm-nm"), ("OBJCOPY", "llvm-objcopy"),
                           ("OBJDUMP", "llvm-objdump"),
                           ("READELF", "llvm-readelf"), ("STRIP", "llvm-strip")):
        command.append(f"-Dmake-arg={variable}={tool(name)}")
    if args.step == "native-images":
        command.append("-Dnative-profile=hyperv-x86_64-efi-wamr")
    subprocess.run(command, cwd=REPO, check=True,
                   env=dict(os.environ, TMPDIR=contract["tmp"]))
    if args.step == "native-images":
        record(command)


if __name__ == "__main__":
    main()
