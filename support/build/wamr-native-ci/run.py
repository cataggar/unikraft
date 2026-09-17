#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""One tiny native compute image; no cloud, hardware, or benchmark admission."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import shutil
import stat
import subprocess
import sys

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
APP = REPO / "support/apps/wamr-aot"
REVISION = "a53205d77be3b880eb8f8b96679512ba58e2331a"
MARKER = "WAMR_NATIVE_AOT_OK answer=42 teardown=0"
LEGACY = "Using legacy xAPIC MMIO"
MODES = ("raw-x2apic", "raw-legacy-apic", "vpc-x2apic", "vpc-legacy-apic")
FORBIDDEN = ("HYPERV_ACCEPTANCE", "UK_HYPERV_IO_READY",
             "UK_HYPERV_NETWORK_APP_READY", "UK_HYPERV_PLATFORM_READY",
             "WAMR_NATIVE_WASI=", "WAMR_NATIVE_AOT_FAIL")
EFI = "wamr_hyperv-x86_64-efi"
MIB = 1024 * 1024
HOST_TOOLS = ("zig", "make", "llvm-nm", "llvm-objcopy", "llvm-objdump",
              "llvm-readelf", "llvm-strip", "bison", "flex",
              "python3", "git", "bash", "m4", "timeout", "head")
ANSI_ESCAPE = re.compile(rb"\x1b\[[0-?]*[ -/]*[@-~]")
COMMAND_ERROR_MARKERS = (
    "AccessDenied", "BrokenPipe", "FileNotFound", "FileTooBig", "InputOutput",
    "InvalidEnumTag", "InvalidNativeMakeEnvironment", "InvalidNativeMakePath",
    "InvalidPath", "MissingField", "ModuleNotFound", "NameTooLong", "NoSpaceLeft",
    "NoncanonicalNativeMakeEnvironment", "NotDir", "OutOfMemory",
    "PathAlreadyExists", "PermissionDenied", "ReadOnlyFileSystem",
    "SystemResources", "TooManySymbolicLinkLevels", "UnexpectedToken",
    "UnsafeFile", "UnsafeNativeMakeTool", "UnsupportedNativeMakeHost",
    "UnsupportedTarget",
)
COMMAND_ERROR_PATTERN = re.compile(
    rb"\b(?:" + b"|".join(name.encode("ascii") for name in COMMAND_ERROR_MARKERS) + rb")\b")


class Refusal(ValueError):
    """Only fixed adapter-owned diagnostic text, never external exception text."""


def require(condition, reason):
    if not condition:
        raise Refusal(reason)


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate JSON key")
        result[key] = value
    return result


def snapshot(info):
    return tuple(getattr(info, name) for name in (
        "st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_nlink",
        "st_size", "st_mtime_ns", "st_ctime_ns"))


def read(path, limit):
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and not info.st_mode & 0o022
            and info.st_size <= limit, "unsafe or oversized file")
    with path.open("rb") as stream:
        require(snapshot(os.fstat(stream.fileno())) == snapshot(info), "file replaced")
        data = stream.read(limit + 1)
    require(len(data) == info.st_size and snapshot(path.lstat()) == snapshot(info),
            "file changed")
    return data


def document(path):
    return json.loads(read(path, 64 * 1024), object_pairs_hook=unique)


def digest(path, limit=256 * MIB + 512):
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and not info.st_mode & 0o022
            and 0 < info.st_size <= limit, "unsafe hash input")
    value = hashlib.sha256()
    with path.open("rb") as stream:
        require(snapshot(os.fstat(stream.fileno())) == snapshot(info), "hash input replaced")
        remaining = info.st_size
        while remaining:
            chunk = stream.read(min(remaining, 65536))
            require(chunk, "hash input truncated")
            value.update(chunk)
            remaining -= len(chunk)
        require(not stream.read(1), "hash input grew")
    # Reading may update atime; it is not a content/identity mutation.
    require(snapshot(path.lstat()) == snapshot(info), "hash input changed")
    return value.hexdigest()


def save(path, value):
    with path.open("x", encoding="ascii") as stream:
        json.dump(value, stream, sort_keys=True, separators=(",", ":"))
        stream.write("\n")
    path.chmod(0o600)


def tool(name):
    path = shutil.which(name)
    require(path is not None, "required tool unavailable")
    return str(Path(path).resolve(strict=True))


def git(*args):
    return subprocess.check_output(["git", *args], cwd=REPO, timeout=60).decode().strip()


def source():
    require(not git("status", "--porcelain", "--untracked-files=normal"),
            "clean committed source required")
    head = git("rev-parse", "HEAD")
    require(head == os.environ.get("GITHUB_SHA", head), "unexpected source revision")
    return {"revision": head, "tree": git("rev-parse", "HEAD^{tree}")}


def producer_inputs(runtime):
    return {"source": source(),
            "tools": {name: digest(Path(tool(name))) for name in HOST_TOOLS},
            "bison_data": bison_inputs(runtime / "bison")}


def bison_inputs(root):
    require(root.is_absolute(), "absolute private Bison data required")
    require(root.resolve(strict=True) == root
            and stat.S_ISDIR(root.lstat().st_mode)
            and root.stat().st_uid == os.getuid()
            and stat.S_IMODE(root.stat().st_mode) == 0o700,
            "private Bison directory required")
    files = {}
    total = 0
    for index, path in enumerate(root.rglob("*")):
        info = path.lstat()
        require(index < 512 and info.st_uid == os.getuid()
                and not info.st_mode & 0o7022, "unsafe Bison data input")
        if stat.S_ISDIR(info.st_mode):
            continue
        require(stat.S_ISREG(info.st_mode), "nonregular Bison data input")
        raw = read(path, 8 * MIB - total)
        total += len(raw)
        files[path.relative_to(root).as_posix()] = {
            "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
    require(files, "empty Bison data")
    encoded = json.dumps(files, sort_keys=True, separators=(",", ":")).encode("ascii")
    return {"files": len(files), "bytes": total,
            "sha256": hashlib.sha256(encoded).hexdigest()}


def command_error_markers(raw):
    observed = {match.group() for match in COMMAND_ERROR_PATTERN.finditer(raw)}
    return [name for name in COMMAND_ERROR_MARKERS if name.encode("ascii") in observed]


def run(root, stage, args, seconds=600, limit=8 * MIB):
    """Fixed timeout/head ceiling; raw output stays private, never in Actions stdout."""
    output = root / "private" / (stage + ".log")
    with output.open("xb") as stream:
        result = subprocess.run([
            tool("timeout"), "--signal=TERM", "--kill-after=5s", str(seconds),
            tool("bash"), "--noprofile", "--norc", "-o", "pipefail", "-c",
            '"$@" 2>&1 | head -c "$WAMR_CI_CAPTURE_LIMIT"', "_",
            *map(str, args),
        ], cwd=REPO, stdout=stream, stderr=subprocess.STDOUT,
            env=dict(os.environ, WAMR_CI_CAPTURE_LIMIT=str(limit + 1)), check=False)
    size = output.stat().st_size
    markers = (command_error_markers(read(output, limit + 1))
               if size <= limit + 1 else None)
    save(root / "evidence" / ("command-" + stage + ".json"), {
        "scope": "command_diagnostic_not_acceptance", "stage": stage,
        "exit_code": result.returncode, "bytes": size,
        "sha256": digest(output) if size else hashlib.sha256(b"").hexdigest(),
        "over_limit": size > limit,
        "known_error_markers": markers,
    })
    require(result.returncode == 0 and size <= limit, "bounded command failed")
    return output


def check_build():
    identity = document(APP / "build/artifacts/identity.json")
    require(identity["wamr_revision"] == REVISION
            and identity.get("development_only", False) is False
            and identity.get("variant", "tiny") == "tiny"
            and identity.get("jit_mode") is None
            and identity["compiler_profile"] == "unikraft-x86_64"
            and identity["zig_version"] == "0.16.0"
            and identity["minimal_wasi"] is False, "not the pinned tiny producer")
    names = {"embedded.c", "identity.h", "libwamr-aot.a", "tiny.cwasm",
             "tiny.wasm", "wamr_aot.h", "wamrc"}
    require(set(identity["files"]) == names, "unexpected runtime artifacts")
    for name, expected in identity["files"].items():
        require(digest(APP / "build/artifacts" / name) == expected,
                "runtime artifact changed")
    image = document(APP / "build/image-identity.json")
    require(image["schema_version"] == 1
            and image["unikraft_revision"] == source()["revision"]
            and image["unikraft_diff_sha256"] == hashlib.sha256(b"").hexdigest(),
            "dirty or different image source")
    require(image["runtime_inputs_sha256"] == digest(APP / "build/artifacts/identity.json"),
            "runtime manifest changed")
    require(image["solved_config_sha256"] == digest(APP / ".config"), "config changed")
    require(set(image["files"]) == {EFI, EFI + ".dbg", EFI + ".bootinfo"},
            "unexpected final images")
    for name, expected in image["files"].items():
        require(digest(APP / "build" / name) == expected, "final image changed")
    actual_sources = {p.name: digest(p) for p in APP.iterdir()
                      if p.is_file() and not p.name.startswith(".")}
    require(image["application_sources"] == actual_sources, "application changed")
    require(set(image["tools"]) == {"zig", "make", "llvm-nm", "llvm-objcopy",
                                   "llvm-objdump", "llvm-readelf", "llvm-strip",
                                   "bison", "flex"}, "missing build tools")
    for name, expected in image["tools"].items():
        require(name in ("zig", "make", "llvm-nm", "llvm-objcopy", "llvm-objdump",
                         "llvm-readelf", "llvm-strip", "bison", "flex")
                and digest(Path(tool(name))) == expected, "build tool changed")
    config = read(APP / ".config", MIB).decode()
    for setting in ("CONFIG_APPWAMRAOT=y", "CONFIG_ARCH_X86_64=y",
                    "CONFIG_PLAT_HYPERV=y", "CONFIG_LIBUKVMEM=y",
                    "CONFIG_LIBUKPAGING=y", "CONFIG_UKPLAT_CPU_MAXCOUNT=1"):
        require(config.splitlines().count(setting) == 1, "wrong compute config")
    for symbol in ("APPHYPERVACCEPTANCE", "APPHYPERVSMPWORKLOAD", "LIBSTORVSC",
                   "LIBNETVSC", "LIBLWIP"):
        require("CONFIG_" + symbol + "=y" not in config.splitlines(),
                "hardware application configuration")
    return {"source": source(), "runtime": identity, "image": image}


def normalize_serial(raw):
    # Match local_boot/serial.zig; evidence identities remain over the raw bytes.
    require(0 < len(raw) < 4 * MIB, "serial bound")
    raw.decode("utf-8")
    normalized = ANSI_ESCAPE.sub(b"", raw).replace(b"\0", b"")
    require(all(byte >= 0x20 or byte in b"\n\r\t" for byte in normalized),
            "invalid serial control")
    require(all(len(line) <= 8192 for line in normalized.split(b"\n")),
            "serial line bound")
    return normalized.decode("utf-8").replace("\r\n", "\n")


def compute(raw, identity, legacy):
    text = normalize_serial(raw)
    lines = text.split("\n")
    require(lines.count(MARKER) == 1 and text.count(MARKER) == 1,
            "completion must be one exact line")
    require(text.count(LEGACY) == int(legacy), "wrong APIC observation")
    require(not any(marker in text for marker in FORBIDDEN), "unexpected acceptance")
    compute_lines = [line for line in lines if "WAMR_NATIVE_COMPUTE=" in line]
    require(len(compute_lines) == 1 and compute_lines[0].startswith("WAMR_NATIVE_COMPUTE="),
            "one anchored compute record required")
    start = text.index("Calling main(")
    record = text.index(compute_lines[0])
    done = text.index(MARKER)
    terminal = text.index("main returned")
    require(start < record < done < terminal, "compute envelope order")
    spec = importlib.util.spec_from_file_location("wamr_app_log", APP / "check-log.py")
    checker = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(checker)
    # The app-owned validator supplies independent exact answer/growth/trap and
    # native selftest/accounting expectations; the CLI already checked terminal/crash.
    checker.validate(text, identity)
    return json.loads(compute_lines[0].split("=", 1)[1], object_pairs_hook=unique)


def config_for(runtime, root, index):
    legacy = bool(index % 2)
    return {
        "image": None,
        "raw_disk": str(root / "package/unikraft.raw") if index < 2 else None,
        "fixed_vhd": str(root / "package/unikraft.vhd") if index >= 2 else None,
        "ovmf_code": str(runtime / "firmware/code.fd"),
        "ovmf_vars": str(runtime / "firmware/vars.fd"),
        "qemu": str(runtime / "bin/qemu-system-x86_64"),
        "work_dir": str(root / ("boot-" + MODES[index])),
        "expect": MARKER, "expect_main_return": 0,
        "required": [LEGACY] if legacy else [],
        "forbidden": list(FORBIDDEN) + ([] if legacy else [LEGACY]),
        "cpus": 1, "disable_x2apic": legacy, "timeout_ms": 60_000,
    }


def boot_args(cli, config):
    args = [str(cli)]
    for key in ("raw_disk", "fixed_vhd", "qemu", "ovmf_code", "ovmf_vars",
                "work_dir", "expect", "expect_main_return", "cpus"):
        if config[key] is not None:
            args += ["--" + key.replace("_", "-"), str(config[key])]
    args += ["--timeout", "60"]
    if config["disable_x2apic"]:
        args += ["--disable-x2apic"]
    for key, flag in (("required", "--require-marker"), ("forbidden", "--forbid-marker")):
        for marker in config[key]:
            args += [flag, marker]
    return args


def check_boot(config, identity):
    work = Path(config["work_dir"])
    request = document(work / "request.json")
    require(request["schema_version"] == 1 and request["config"] == config,
            "wrong boot request")
    paths = [config["raw_disk"] or config["fixed_vhd"],
             config["ovmf_code"], config["ovmf_vars"], config["qemu"]]
    require(len(request["pins"]) == 4, "missing physical pins")
    for path, pin in zip(paths, request["pins"]):
        file = Path(path)
        require(pin == {"size": file.stat().st_size,
                        "sha256": list(bytes.fromhex(digest(file)))}, "boot input changed")
    require(read(work / "launched", 1) == b"", "invalid launch")
    report = document(work / "report.json")
    require(report["schema_version"] == 1
            and report["scope"] == "public_local_qemu_only"
            and report["acceptance"] == "not_established", "wrong local report")
    for name in ("passed", "consumed", "cleanup_complete", "input_unchanged", "serial_valid"):
        require(report[name] is True, "incomplete local boot")
    require(report["serial_limit_reached"] is False
            and report["termination"] == {"exited": 0}
            and report["failures"] == {"primary": None, "cleanup": None, "recording": None},
            "local boot failed")
    raw = read(work / "hyperv-efi-boot.log", 4 * MIB)
    require(report["serial_bytes"] == len(raw)
            and report["serial_sha256"] == hashlib.sha256(raw).hexdigest(),
            "serial binding changed")
    return {"scope": "local_native_compute_only", "report": report,
            "request_sha256": digest(work / "request.json"),
            "report_sha256": digest(work / "report.json"),
            "compute": compute(raw, identity, config["disable_x2apic"])}


def build(runtime, wamr):
    root = runtime / "compute"
    root.mkdir(mode=0o700)
    for name in ("private", "evidence", "scratch", "cache", "global-cache",
                 "global-cache/tmp", "fixtures"):
        (root / name).mkdir(mode=0o700)
    os.environ.update(TMPDIR=str(root / "scratch"), MAKEFLAGS="-j2",
                      ZIG_LOCAL_CACHE_DIR=str(root / "cache"),
                      ZIG_GLOBAL_CACHE_DIR=str(root / "global-cache"))
    require(os.environ.get("BISON_PKGDATADIR") == str(runtime / "bison"),
            "Bison build environment differs from bound producer input")
    initial = producer_inputs(runtime)
    save(root / "evidence/build-start.json", initial)
    require(subprocess.check_output([tool("zig"), "version"]).strip() == b"0.16.0",
            "Zig 0.16.0 required")
    run(root, "adapter", [tool("zig"), "build", "--build-file", HERE / "build.zig",
                          "--prefix", root / "tools", "-Doptimize=ReleaseSafe",
                          "-j2", "test", "install"], 900)
    run(root, "local-boot-tool", [tool("zig"), "build", "--build-file",
                                REPO / "support/tools/hyperv/local_boot/build.zig",
                                "--prefix", root / "tools", "-Doptimize=ReleaseSafe",
                                "-j2", "install"], 900)
    os.environ["WAMR_CI_PACKAGE"] = str(root / "tools/bin/wamr-ci-package")
    run(root, "fixtures", [sys.executable, "-m", "unittest", "discover", "-s",
                          HERE / "tests", "-v"])
    run(root, "prepare", [sys.executable, APP / "prepare.py", "prepare", "--source", wamr], 1800)
    run(root, "config", [sys.executable, APP / "build-image.py", "olddefconfig"])
    # This target includes the unchanged final ELF IRQ/constructor/SMP proofs.
    run(root, "native-image", [sys.executable, APP / "build-image.py", "native-images"], 1800)
    require(producer_inputs(runtime) == initial, "source or producer tool changed during build")
    save(root / "evidence/build.json", check_build())
    save(root / "evidence/boot-inputs.json", {
        "package_tool": digest(root / "tools/bin/wamr-ci-package"),
        "local_boot_tool": digest(root / "tools/bin/uk-hyperv-local-boot"),
        "qemu": digest(runtime / "bin/qemu-system-x86_64"),
        "ovmf_code": digest(runtime / "firmware/code.fd"),
        "ovmf_vars": digest(runtime / "firmware/vars.fd"),
    })


def boot(runtime):
    require(platform.machine() == "x86_64" and Path("/dev/kvm").is_char_device()
            and os.access("/dev/kvm", os.R_OK | os.W_OK),
            "x86 KVM runner required; no successful skip")
    root = runtime / "compute"
    require(producer_inputs(runtime) == document(root / "evidence/build-start.json"),
            "producer inputs changed")
    require(check_build() == document(root / "evidence/build.json"), "build identity changed")
    inputs = document(root / "evidence/boot-inputs.json")
    paths = {"package_tool": root / "tools/bin/wamr-ci-package",
             "local_boot_tool": root / "tools/bin/uk-hyperv-local-boot",
             "qemu": runtime / "bin/qemu-system-x86_64",
             "ovmf_code": runtime / "firmware/code.fd",
             "ovmf_vars": runtime / "firmware/vars.fd"}

    def verify_inputs():
        require(inputs == {name: digest(path) for name, path in paths.items()},
                "boot tool or firmware changed")

    verify_inputs()
    efi = APP / "build" / EFI
    output = run(root, "package", [paths["package_tool"], "package", efi, root / "package"],
                 150, 64 * 1024)
    package = document(output)
    require(package["image"]["efi"]["sha256"] == digest(efi)
            and package["producer_sha256"] == inputs["package_tool"],
            "package identity changed")
    save(root / "evidence/package.json", {
        "scope": package["scope"], "acceptance": package["acceptance"],
        "producer_sha256": package["producer_sha256"],
        "image": {key: package["image"][key] for key in (
            "schema_version", "miz_revision", "efi", "raw", "vhd",
            "footer_sha256", "packaging")},
    })
    identity = document(APP / "build/artifacts/identity.json")
    for index, mode in enumerate(MODES):
        config = config_for(runtime, root, index)
        Path(config["work_dir"]).mkdir(mode=0o700)
        run(root, mode, boot_args(paths["local_boot_tool"], config), 90, 64 * 1024)
        result = check_boot(config, identity)
        expected = package["image"]["raw" if index < 2 else "vhd"]["sha256"]
        require(digest(Path(config["raw_disk"] or config["fixed_vhd"])) == expected,
                "booted package changed")
        save(root / "evidence" / (mode + "-compute.json"), result)
    output = run(root, "inspect", [paths["package_tool"], "inspect", efi, root / "package"],
                 150, 64 * 1024)
    require(document(output) == package, "physical package reload changed")
    verify_inputs()
    require(producer_inputs(runtime) == document(root / "evidence/build-start.json"),
            "producer inputs changed after boot")
    require(check_build() == document(root / "evidence/build.json"), "source or image changed")
    # No self hash: this final record binds earlier immutable observations only.
    save(root / "evidence/result.json", {
        "schema_version": 1, "scope": "local_native_compute_only", "passed": True,
        "hardware_acceptance": "not_established", "cloud_authority": "not_admitted",
        "benchmark": "not_measured", "workload": "tiny", "modes": list(MODES),
        "records": {p.name: digest(p) for p in sorted((root / "evidence").glob("*.json"))},
    })


def diagnostics(runtime):
    """Allowlisted observations only. Raw serial/build/runtime logs stay private."""
    root = runtime / "compute"
    root.mkdir(mode=0o700, exist_ok=True)
    (root / "evidence").mkdir(mode=0o700, exist_ok=True)
    observations = {}
    for mode in MODES:
        entry = {"report": "unavailable", "serial": "unavailable"}
        work = root / ("boot-" + mode)
        try:
            report = document(work / "report.json")
            for key in ("passed", "cleanup_complete", "input_unchanged",
                        "serial_valid", "serial_limit_reached"):
                require(type(report[key]) is bool, "invalid diagnostic")
            entry["report"] = {key: report[key] for key in (
                "passed", "cleanup_complete", "input_unchanged",
                "serial_valid", "serial_limit_reached")}
            entry["failure_lanes"] = [key for key in ("primary", "cleanup", "recording")
                                     if report["failures"][key] is not None]
            if report["cleanup_complete"]:
                raw = read(work / "hyperv-efi-boot.log", 4 * MIB)
                entry["serial"] = {"bytes": len(raw),
                                   "sha256": hashlib.sha256(raw).hexdigest()}
        except (OSError, ValueError, KeyError, TypeError):
            pass
        observations[mode] = entry
    save(root / "evidence/diagnostics.json", {
        "scope": "diagnostics_not_acceptance",
        "redaction": "no_raw_serial_paths_environment_or_account_state",
        "boots": observations,
    })


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("build", "boot", "diagnostics"))
    parser.add_argument("--runtime", type=Path, required=True)
    parser.add_argument("--wamr-source", type=Path)
    args = parser.parse_args()
    runtime = args.runtime
    require(runtime.is_absolute() and runtime.resolve(strict=True) == runtime
            and runtime.stat().st_uid == os.getuid()
            and stat.S_IMODE(runtime.stat().st_mode) == 0o700, "private runtime root required")
    os.umask(0o077)
    if args.command == "build":
        require(args.wamr_source is not None, "pinned WAMR checkout required")
        build(runtime, args.wamr_source.resolve(strict=True))
    elif args.command == "boot":
        boot(runtime)
    else:
        diagnostics(runtime)


if __name__ == "__main__":
    try:
        main()
    except Refusal as error:
        print("WAMR_CI_REFUSED: " + str(error), file=sys.stderr)
        sys.exit(1)
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        print("WAMR native compute CI failed; bounded private logs and redacted diagnostics retained.",
              file=sys.stderr)
        sys.exit(1)
