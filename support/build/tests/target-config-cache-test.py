#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause

import argparse
import os
import pathlib
import shutil
import subprocess


def write_config(path, name):
    path.write_text(
        'CONFIG_ARCH_X86_64=y\n'
        'CONFIG_PLAT_KVM=y\n'
        'CONFIG_KVM_BOOT_PROTO_MULTIBOOT=y\n'
        f'CONFIG_UK_NAME="{name}"\n',
        encoding="utf-8",
    )


def run_build(zig, base, work, config):
    env = os.environ.copy()
    env["ZIG_GLOBAL_CACHE_DIR"] = str(work / "global-cache")
    env["ZIG_LOCAL_CACHE_DIR"] = str(work / "local-cache")
    env["TMPDIR"] = str(work / "tmp")
    env["XDG_CACHE_HOME"] = str(work / "tool-cache")
    subprocess.run(
        [
            zig,
            "build",
            "target-config-header",
            f"-Dapp={work}",
            f"-Doutput={work / 'output'}",
            f"-Dconfig={config}",
            "--prefix",
            str(work / "install"),
            "--summary",
            "failures",
        ],
        cwd=base,
        env=env,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--base", required=True)
    parser.add_argument("--work-dir", required=True)
    parser.add_argument("--zig", required=True)
    args = parser.parse_args()

    os.umask(0o077)
    base = pathlib.Path(args.base)
    work = pathlib.Path(args.work_dir)
    if work.exists():
        shutil.rmtree(work)
    work.mkdir(parents=True, mode=0o700)
    for child in ("global-cache", "local-cache", "tmp", "tool-cache", "install"):
        (work / child).mkdir(mode=0o700)

    config = work / "same-path.config"
    installed = work / "install/target-config-header.h"

    write_config(config, "cache-first")
    run_build(args.zig, base, work, config)
    first = installed.read_text(encoding="utf-8")
    if '#define CONFIG_UK_NAME "cache-first"' not in first:
        raise SystemExit("first content-tracked target header was not generated")
    marker = work / "output/.unikraft-zig-build"
    marker.write_text("unikraft-zig-build-v1\n", encoding="utf-8")
    marker.chmod(0o600)

    write_config(config, "cache-second")
    run_build(args.zig, base, work, config)
    second = installed.read_text(encoding="utf-8")
    if '#define CONFIG_UK_NAME "cache-second"' not in second:
        raise SystemExit("target header was stale after same-path config update")
    if first == second:
        raise SystemExit("same-path config update did not invalidate the target header")


if __name__ == "__main__":
    main()
