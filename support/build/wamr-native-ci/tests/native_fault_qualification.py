# SPDX-License-Identifier: BSD-3-Clause
"""Native-only fault execution and physical before/after observation.

This is a test driver, not a controller or record validator. Only the installed
native controller builds/admit inputs; fixtures never substitute for that build.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import stat
import subprocess
import sys


CASES = {
    "build-start-tamper": ("boot-platform", "BuildStartChanged"),
    "missing-build": ("boot-platform", "FileNotFound"),
    "occupied-boot-slot": ("boot-platform", "PriorOutput"),
    "prior-build-output": ("startup", "PathAlreadyExists"),
}
BUILD_RECORDS = {
    "build-start.json", "build.json", "command-adapter.json",
    "command-local-boot-tool.json", "command-fixtures.json",
    "command-prepare.json", "command-config.json", "command-native-image.json",
}
MAX_ENTRIES = 131072


def require(condition):
    if not condition:
        raise ValueError("native fault qualification refused")


def private(path):
    require(path.is_absolute() and path.resolve(strict=True) == path)
    info = path.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid()
            and stat.S_IMODE(info.st_mode) == 0o700)


def snapshot(roots):
    result = {}

    def visit(path):
        require(len(result) < MAX_ENTRIES)
        info = path.lstat()
        metadata = tuple(getattr(info, name) for name in (
            "st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_nlink",
            "st_size", "st_mtime_ns", "st_ctime_ns"))
        if stat.S_ISREG(info.st_mode):
            digest = hashlib.sha256()
            with path.open("rb") as stream:
                for block in iter(lambda: stream.read(1024 * 1024), b""):
                    digest.update(block)
            contents = digest.hexdigest()
        elif stat.S_ISLNK(info.st_mode):
            contents = os.readlink(path)
        else:
            require(stat.S_ISDIR(info.st_mode))
            contents = None
        require(metadata == tuple(getattr(path.lstat(), name) for name in (
            "st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_nlink",
            "st_size", "st_mtime_ns", "st_ctime_ns")))
        result[str(path)] = (metadata, contents)
        if stat.S_ISDIR(info.st_mode):
            for child in sorted(path.iterdir()):
                visit(child)

    for root in roots:
        if root.exists() or root.is_symlink():
            visit(root)
        else:
            result[str(root)] = None
    return result


def inject(case, runtime):
    evidence = runtime / "compute/evidence"
    if case == "build-start-tamper":
        path = evidence / "build-start.json"
        value = json.loads(path.read_bytes())
        require(value["source"]["revision"] != "0" * 40)
        value["source"]["revision"] = "0" * 40
        path.write_bytes((json.dumps(
            value, ensure_ascii=False, sort_keys=True,
            separators=(",", ":")) + "\n").encode())
    elif case == "missing-build":
        (evidence / "build.json").unlink()
    elif case == "occupied-boot-slot":
        path = runtime / "compute/boot-raw-x2apic/prior"
        with path.open("xb") as stream:
            stream.write(b"prior")
        path.chmod(0o600)
    else:
        require(case == "prior-build-output")
        (runtime / "compute").mkdir(mode=0o700)


def require_refusal(case, result, before, after, runtime):
    stage, cause = CASES[case]
    require(result.returncode == 1 and result.stdout == b""
            and result.stderr == (
                f"WAMR_CI_FAILED_STAGE: {stage}; cause: {cause}; "
                "bounded private logs retained.\n").encode())
    require(before == after)
    require(not (runtime / "compute/evidence/result.json").exists()
            and not (runtime / "compute/evidence/result.json").is_symlink())
    if case == "prior-build-output":
        require(not (runtime / "compute/evidence/build.json").exists())


def execute(controller, action, args, environment):
    paths = [args.output / f"{action}.{name}" for name in ("stdout", "stderr")]
    argv = [str(controller), action, "--runtime", str(args.runtime),
            *([] if action == "boot" else
              ["--wamr-source", str(args.wamr_source)])]
    with paths[0].open("xb") as stdout, paths[1].open("xb") as stderr:
        for path in paths:
            path.chmod(0o600)
        process = subprocess.Popen(argv, env=environment, stdout=stdout, stderr=stderr)
        try:
            code = process.wait(timeout=7200 if action == "build" else 3600)
        except subprocess.TimeoutExpired:
            # Let the native signal latch supervise its own bounded cleanup.
            process.terminate()
            try:
                process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
            raise ValueError("native fault qualification exceeded deadline") from None
    require(all(path.stat().st_size <= 1024 * 1024 for path in paths))
    return subprocess.CompletedProcess(argv, code, *(path.read_bytes() for path in paths))


def qualify(args):
    require(os.getuid() != 0 and platform.machine() == "x86_64"
            and Path("/dev/kvm").is_char_device()
            and os.access("/dev/kvm", os.R_OK | os.W_OK))
    for path in (args.runtime, args.output):
        private(path)
    require(not any(args.output.iterdir()))
    require(args.controller == args.runtime / "controller/bin/uk-wamr-native-ci")
    require(args.wamr_source.is_absolute()
            and args.wamr_source.resolve(strict=True) == args.wamr_source)
    repository = Path.cwd().resolve(strict=True)
    require(not args.output.is_relative_to(repository)
            and not args.runtime.is_relative_to(repository)
            and not args.output.is_relative_to(args.runtime))
    require(not (args.runtime / "compute").exists()
            and not (args.runtime / "compute").is_symlink())
    environment = {
        "PATH": os.environ["PATH"], "LANG": "C", "LC_ALL": "C",
        "BISON_PKGDATADIR": str(args.runtime / "bison"),
    }
    require(all(part.startswith("/") for part in environment["PATH"].split(":")))
    # Native startup requires this exact private Bison binding, not ambient data.
    roots = [args.runtime / name for name in (
        "compute", "controller", "custody", "bin", "runtime", "firmware",
        "bison", "llvm")]
    roots += [repository / "support/apps/wamr-aot" / name
              for name in (".config", ".config.old", "build")]
    if args.case == "prior-build-output":
        inject(args.case, args.runtime)
        before = snapshot(roots)
        result = execute(args.controller, "build", args, environment)
    else:
        built = execute(args.controller, "build", args, environment)
        require(built.returncode == 0 and not built.stdout and not built.stderr)
        evidence = args.runtime / "compute/evidence"
        require({path.name for path in evidence.iterdir()} == BUILD_RECORDS)
        inject(args.case, args.runtime)
        before = snapshot(roots)
        result = execute(args.controller, "boot", args, environment)
    require_refusal(args.case, result, before, snapshot(roots), args.runtime)
    print(f"NATIVE_FAULT_QUALIFIED: {args.case}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--case", choices=CASES, required=True)
    for name in ("runtime", "output", "wamr-source", "controller"):
        parser.add_argument("--" + name, type=Path, required=True)
    qualify(parser.parse_args())


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, subprocess.SubprocessError):
        print("NATIVE_FAULT_REFUSED: qualification failed; private logs retained.",
              file=sys.stderr)
        sys.exit(1)
