#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause

import argparse
import hashlib
import json
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


def build_environment(work, packages):
    env = os.environ.copy()
    env["ZIG_GLOBAL_CACHE_DIR"] = str(work / "global-cache")
    env["ZIG_LOCAL_CACHE_DIR"] = str(work / "local-cache")
    env["ZIG_LOCAL_PKG_DIR"] = str(packages)
    env["TMPDIR"] = str(work / "tmp")
    env["XDG_CACHE_HOME"] = str(work / "tool-cache")
    return env


def build(zig, base, work, packages, arguments):
    return subprocess.run(
        [zig, "build", "--system", str(packages), *arguments, "--summary", "failures"],
        cwd=base,
        env=build_environment(work, packages),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )


def expect_build(zig, base, work, packages, arguments, diagnostic=None):
    result = build(zig, base, work, packages, arguments)
    if diagnostic is None:
        if result.returncode:
            raise SystemExit(result.stdout)
    elif result.returncode == 0 or diagnostic not in result.stdout:
        raise SystemExit(f"expected refusal {diagnostic!r}:\n{result.stdout}")
    return result.stdout


def run_build(zig, base, work, packages, config):
    expect_build(
        zig, base, work, packages,
        [
            "target-config-header",
            f"-Dapp={work}",
            f"-Doutput={work / 'output'}",
            f"-Dconfig={config}",
            "--prefix",
            str(work / "install"),
        ],
    )


def tracked_config(zig, base, work, packages):
    fixture = work / "configure-fixture"
    fixture.mkdir()
    for source, destination in (
        ("tests/configure-cache/build.zig", "build.zig"),
        ("native-config-input.zig", "native-config-input.zig"),
    ):
        shutil.copyfile(base / "support/build" / source, fixture / destination)
    config = fixture / "same-path.config"
    installed = work / "install/config-source"
    arguments = [f"-Dconfig={config}", "--prefix", str(work / "install")]
    config.write_text("first\n", encoding="utf-8")
    expect_build(zig, fixture, work, packages, arguments)
    expect_build(zig, fixture, work, packages, arguments)
    original = config.stat()
    replacement = fixture / "replacement.config"
    replacement.write_text("other\n", encoding="utf-8")
    os.utime(replacement, ns=(original.st_atime_ns, original.st_mtime_ns))
    replacement.replace(config)
    expect_build(zig, fixture, work, packages, arguments)
    if installed.read_text(encoding="utf-8") != "other\n":
        raise SystemExit("warm configuration cache reused replaced .config contents")
    config.unlink()
    expect_build(zig, fixture, work, packages, arguments, "FileNotFound")


def live_trust(zig, base, work, packages):
    identity = hashlib.sha256(os.fsencode(work)).hexdigest()[:16]
    backend_dir = base / f".target-config-backend-{identity}"
    backend_dir.mkdir(mode=0o700)
    try:
        live_trust_fixture(zig, base, work, packages, backend_dir)
    finally:
        shutil.rmtree(backend_dir)


def live_trust_fixture(zig, base, work, packages, backend_dir):
    app = work / "application"
    app.mkdir()
    recorded = work / "make-argv"
    # Cache directories may be writable by other users; the backend policy
    # correctly rejects executables beneath such ancestors.
    source = backend_dir / "record-make.c"
    make = backend_dir / "record-make"
    source.write_text(
        "#include <stdio.h>\n"
        "int main(int argc, char **argv) {\n"
        f"FILE *output = fopen({json.dumps(str(recorded))}, \"w\");\n"
        "if (!output) return 1;\n"
        "for (int i = 1; i < argc; ++i) fprintf(output, \"%s\\n\", argv[i]);\n"
        "return fclose(output) != 0;\n}\n",
        encoding="utf-8",
    )
    subprocess.run(
        [zig, "cc", "-O2", str(source), "-o", str(make)],
        cwd=base, env=build_environment(work, packages), check=True,
    )
    make.chmod(0o700)
    tool = work / "wamr-tool"
    tool.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    tool.chmod(0o700)
    arguments = [
        "objs", f"-Dapp={app}", f"-Doutput={work / 'output'}",
        f"-Dmake-command={make}", f"-Dwamr-aot-tool={tool}",
        "-Dmake-arg=AR=zig ar",
    ]
    expect_build(zig, base, work, packages, arguments)
    expect_build(zig, base, work, packages, arguments)
    argv = recorded.read_text(encoding="utf-8").splitlines()
    if "AR=zig ar" not in argv or "objs" not in argv:
        raise SystemExit("warm-cache Make passthrough lost argument boundaries")
    recorded.unlink()
    empty_packages = work / "empty-packages"
    empty_packages.mkdir()
    expect_build(zig, base, work, empty_packages, arguments, "package not found at")
    if recorded.exists():
        raise SystemExit("Make executed without the restored root package closure")
    original = tool.stat()
    tool.chmod(0o600)
    os.utime(tool, ns=(original.st_atime_ns, original.st_mtime_ns))
    expect_build(zig, base, work, packages, arguments, "executable regular file")
    if recorded.exists():
        raise SystemExit("Make executed after a live executable-trust refusal")
    tool.chmod(0o700)
    expect_build(zig, base, work, packages, arguments)
    recorded.unlink()
    original_tool = work / "original-wamr-tool"
    tool.rename(original_tool)
    tool.symlink_to(original_tool)
    expect_build(zig, base, work, packages, arguments, "existing canonical executable")
    if recorded.exists():
        raise SystemExit("Make executed after executable path replacement")
    tool.unlink()
    original_tool.rename(tool)
    app.rename(work / "original-application")
    app.write_text("not a directory\n", encoding="utf-8")
    expect_build(zig, base, work, packages, arguments, "NotDirectory")
    if recorded.exists():
        raise SystemExit("Make executed after application directory replacement")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--base", required=True)
    parser.add_argument("--work-dir", required=True)
    parser.add_argument("--zig", required=True)
    parser.add_argument("--packages", required=True)
    args = parser.parse_args()

    os.umask(0o077)
    base = pathlib.Path(args.base).resolve()
    work = pathlib.Path(args.work_dir).resolve()
    packages = pathlib.Path(args.packages).resolve(strict=True)
    if not packages.is_dir():
        raise SystemExit("root package depot must be a restored directory")
    if work.exists():
        shutil.rmtree(work)
    work.mkdir(parents=True, mode=0o700)
    for child in ("global-cache", "local-cache", "tmp", "tool-cache", "install"):
        (work / child).mkdir(mode=0o700)

    config = work / "same-path.config"
    installed = work / "install/target-config-header.h"

    write_config(config, "cache-first")
    run_build(args.zig, base, work, packages, config)
    first = installed.read_text(encoding="utf-8")
    if '#define CONFIG_UK_NAME "cache-first"' not in first:
        raise SystemExit("first content-tracked target header was not generated")
    marker = work / "output/.unikraft-zig-build"
    marker.write_text("unikraft-zig-build-v1\n", encoding="utf-8")
    marker.chmod(0o600)

    write_config(config, "cache-second")
    run_build(args.zig, base, work, packages, config)
    second = installed.read_text(encoding="utf-8")
    if '#define CONFIG_UK_NAME "cache-second"' not in second:
        raise SystemExit("target header was stale after same-path config update")
    if first == second:
        raise SystemExit("same-path config update did not invalidate the target header")
    tracked_config(args.zig, base, work, packages)
    live_trust(args.zig, base, work, packages)


if __name__ == "__main__":
    main()
