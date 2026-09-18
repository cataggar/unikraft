#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""One tiny native compute image; no cloud, hardware, or benchmark admission."""
import sys

sys.dont_write_bytecode = True

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import shutil
import stat
import subprocess

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
APP = REPO / "support/apps/wamr-aot"
LOCAL_BOOT = REPO / "support/tools/hyperv/local_boot"
REVISION = "a53205d77be3b880eb8f8b96679512ba58e2331a"
MARKER = "WAMR_NATIVE_AOT_OK answer=42 teardown=0"
LEGACY = "Using legacy xAPIC MMIO"
MODES = ("raw-x2apic", "raw-legacy-apic", "vpc-x2apic", "vpc-legacy-apic")
FORBIDDEN = ("HYPERV_ACCEPTANCE", "UK_HYPERV_IO_READY",
             "UK_HYPERV_NETWORK_APP_READY", "UK_HYPERV_PLATFORM_READY",
             "WAMR_NATIVE_WASI=", "WAMR_NATIVE_AOT_FAIL")
EFI = "wamr_hyperv-x86_64-efi"
MIB = 1024 * 1024
MIZ_REVISION = "669a27982b376311f558e820b69e9a692735b0cd"
MIZ_PACKAGE_HASH = "miz-0.2.0-Z3lHlD--2gAdGiguNwbjjdjBmv2f8QlAcwHYRw1De0Sx"
MIZ_URL = "git+https://github.com/cataggar/miz.git#" + MIZ_REVISION
SOURCE_MAX_ENTRIES = 40_000
SOURCE_MAX_BYTES = 2 * 1024 * MIB
SOURCE_MAX_FILE = 256 * MIB
PACKAGE_MAX_ROOTS = 128
PACKAGE_MAX_ENTRIES = 16_384
PACKAGE_MAX_BYTES = 256 * MIB
PACKAGE_MAX_FILE = 64 * MIB
PACKAGE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,159}")
SOURCE_OUTPUT_ROLES = (
    ".d",
    "support/apps/wamr-aot/.config",
    "support/apps/wamr-aot/build",
)
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


def canonical(path):
    try:
        return path.resolve(strict=True) == path
    except (OSError, RuntimeError):
        return False


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


def bind(hasher, value):
    raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii")
    hasher.update(len(raw).to_bytes(8, "big"))
    hasher.update(raw)


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


def git(*args, repository=REPO):
    return subprocess.check_output(
        ["git", *args], cwd=repository, timeout=60).decode().strip()


def git_raw(repository, *args):
    return subprocess.check_output(["git", *args], cwd=repository, timeout=60)


def source_file(repository, relative, mode, oid, object_format):
    path = repository / relative
    try:
        before = path.lstat()
    except FileNotFoundError as error:
        raise Refusal("tracked source unavailable") from error
    if mode == "120000":
        require(stat.S_ISLNK(before.st_mode) and before.st_uid in (0, os.getuid())
                and 0 < before.st_size < 4096,
                "tracked source type changed")
        raw = os.readlink(os.fsencode(path))
        require(len(raw) == before.st_size and snapshot(path.lstat()) == snapshot(before),
                "tracked source changed")
        try:
            target = path.resolve(strict=True)
        except (OSError, RuntimeError) as error:
            raise Refusal("tracked source symlink target unavailable") from error
        require(target == repository or repository in target.parents,
                "tracked source symlink escapes repository")
    else:
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                and before.st_uid in (0, os.getuid()) and not before.st_mode & 0o022
                and bool(before.st_mode & 0o111) == (mode == "100755"),
                "tracked source type changed")
        raw = read(path, SOURCE_MAX_FILE)
        require(snapshot(path.lstat()) == snapshot(before), "tracked source changed")
    object_hash = hashlib.new(object_format)
    object_hash.update(f"blob {len(raw)}\0".encode("ascii"))
    object_hash.update(raw)
    require(object_hash.hexdigest() == oid, "tracked source content differs from Git")
    return raw, before


def source(repository=REPO):
    repository = Path(repository)
    require(repository.is_absolute() and canonical(repository)
            and stat.S_ISDIR(repository.lstat().st_mode), "canonical source required")
    status = git_raw(repository, "status", "--porcelain=v2", "--untracked-files=all")
    require(not status, "clean committed source required")
    head = git("rev-parse", "HEAD", repository=repository)
    tree = git("rev-parse", "HEAD^{tree}", repository=repository)
    if repository == REPO:
        require(head == os.environ.get("GITHUB_SHA", head), "unexpected source revision")
    object_format = git("rev-parse", "--show-object-format", repository=repository)
    require(object_format in ("sha1", "sha256"), "unsupported Git object format")
    listing = git_raw(repository, "ls-tree", "-r", "-z", "--full-tree", head)
    require(0 < len(listing) <= 4 * MIB and listing.endswith(b"\0"),
            "invalid tracked source map")
    entries = []
    names = set()
    directories = {""}
    for raw in listing[:-1].split(b"\0"):
        try:
            header, encoded = raw.split(b"\t", 1)
            mode, kind, oid = header.decode("ascii").split(" ")
            relative = encoded.decode("utf-8")
        except (UnicodeDecodeError, ValueError) as error:
            raise Refusal("invalid tracked source map") from error
        path = PurePosixPath(relative)
        require(kind == "blob" and mode in ("100644", "100755", "120000")
                and len(oid) == hashlib.new(object_format).digest_size * 2
                and relative not in names and not path.is_absolute()
                and relative not in ("", ".", "..") and ".." not in path.parts
                and len(relative.encode()) <= 1024
                and len(entries) < SOURCE_MAX_ENTRIES,
                "invalid tracked source map")
        names.add(relative)
        entries.append((relative, mode, oid))
        for parent in path.parents:
            if str(parent) != ".":
                directories.add(parent.as_posix())
    directory_state = {}
    for relative in sorted(directories, key=lambda item: (item.count("/"), item)):
        path = repository if not relative else repository / relative
        try:
            info = path.lstat()
        except FileNotFoundError as error:
            raise Refusal("tracked source directory unavailable") from error
        require(stat.S_ISDIR(info.st_mode) and info.st_uid in (0, os.getuid())
                and not info.st_mode & 0o022, "unsafe tracked source directory")
        directory_state[relative] = snapshot(info)
    content = hashlib.sha256(b"uk.wamr.git-source-content-v1\0")
    physical = hashlib.sha256(b"uk.wamr.git-source-physical-v1\0")
    for relative in sorted(directory_state):
        bind(physical, ["directory", relative, directory_state[relative]])
    total = 0
    for relative, mode, oid in entries:
        raw, info = source_file(repository, relative, mode, oid, object_format)
        total += len(raw)
        require(total <= SOURCE_MAX_BYTES, "tracked source byte limit exceeded")
        sha256 = hashlib.sha256(raw).hexdigest()
        bind(content, ["file", relative, mode, oid, len(raw), sha256])
        bind(physical, ["file", relative, mode, oid, len(raw), sha256, snapshot(info)])
    for relative, expected in directory_state.items():
        path = repository if not relative else repository / relative
        require(snapshot(path.lstat()) == expected, "tracked source directory changed")
    require(not git_raw(repository, "status", "--porcelain=v2", "--untracked-files=all")
            and git("rev-parse", "HEAD", repository=repository) == head
            and git("rev-parse", "HEAD^{tree}", repository=repository) == tree,
            "tracked source changed during inspection")
    return {
        "revision": head,
        "tree": tree,
        "custody": {
            "schema": "uk.wamr.git-physical-source",
            "version": 1,
            "object_format": object_format,
            "files": len(entries),
            "directories": len(directory_state),
            "bytes": total,
            "content_sha256": content.hexdigest(),
            "physical_sha256": physical.hexdigest(),
            "role_excluded_outputs": list(SOURCE_OUTPUT_ROLES),
        },
    }


def require_source(expected, repository=REPO):
    require(source(repository) == expected, "immutable source custody changed")


def source_identity(value):
    return {"revision": value["revision"], "tree": value["tree"]}


def producer_inputs(runtime):
    current_source = source()
    return {"source": source_identity(current_source),
            "source_custody": current_source["custody"],
            "tools": {name: digest(Path(tool(name))) for name in HOST_TOOLS},
            "bison_data": bison_inputs(runtime / "bison"),
            "dependencies": dependency_custody(runtime / "compute")}


def bison_inputs(root):
    require(root.is_absolute(), "absolute private Bison data required")
    require(canonical(root)
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


def execute(root, stage, args, seconds=600, limit=8 * MIB, cwd=REPO, evidence=True):
    """Fixed timeout/head ceiling; raw output stays private, never in Actions stdout."""
    output = root / "private" / (stage + ".log")
    with output.open("xb") as stream:
        result = subprocess.run([
            tool("timeout"), "--signal=TERM", "--kill-after=5s", str(seconds),
            tool("bash"), "--noprofile", "--norc", "-o", "pipefail", "-c",
            '"$@" 2>&1 | head -c "$WAMR_CI_CAPTURE_LIMIT"', "_",
            *map(str, args),
        ], cwd=cwd, stdout=stream, stderr=subprocess.STDOUT,
            env=dict(os.environ, WAMR_CI_CAPTURE_LIMIT=str(limit + 1)), check=False)
    size = output.stat().st_size
    markers = (command_error_markers(read(output, limit + 1))
               if size <= limit + 1 else None)
    record = {
        "scope": "command_diagnostic_not_acceptance", "stage": stage,
        "exit_code": result.returncode, "bytes": size,
        "sha256": digest(output) if size else hashlib.sha256(b"").hexdigest(),
        "over_limit": size > limit,
        "known_error_markers": markers,
    }
    if evidence:
        save(root / "evidence" / ("command-" + stage + ".json"), record)
    require(result.returncode == 0 and size <= limit, "bounded command failed")
    return output, record


def run(root, stage, args, seconds=600, limit=8 * MIB):
    output, _ = execute(root, stage, args, seconds, limit)
    return output


def zon_without_comments(raw):
    require(len(raw) <= 4 * MIB, "oversized package manifest")
    result = bytearray(raw)
    index = 0
    quote = False
    while index < len(raw):
        if quote:
            if raw[index] == 0x5c:
                index += 2
                continue
            if raw[index] == 0x22:
                quote = False
            index += 1
            continue
        if raw[index] == 0x22:
            quote = True
            index += 1
            continue
        if raw[index:index + 2] == b"//":
            end = raw.find(b"\n", index + 2)
            end = len(raw) if end < 0 else end
            result[index:end] = b" " * (end - index)
            index = end
            continue
        if raw[index:index + 2] == b"/*":
            depth = 1
            end = index + 2
            while end < len(raw) and depth:
                if raw[end:end + 2] == b"/*":
                    depth += 1
                    end += 2
                elif raw[end:end + 2] == b"*/":
                    depth -= 1
                    end += 2
                else:
                    end += 1
            require(depth == 0, "invalid package manifest")
            result[index:end] = b" " * (end - index)
            index = end
            continue
        index += 1
    require(not quote, "invalid package manifest")
    return bytes(result)


def zon_block(raw, field, required=True):
    clean = zon_without_comments(raw)
    marker = re.compile(
        rb"(?<![A-Za-z0-9_])\." + re.escape(field.encode("ascii"))
        + rb"\s*=\s*\.\s*\{")
    matches = list(marker.finditer(clean))
    if not matches and not required:
        return None
    require(len(matches) == 1, "ambiguous package manifest field")
    start = clean.find(b"{", matches[0].start())
    depth = 0
    quote = False
    index = start
    while index < len(clean):
        byte = clean[index]
        if quote:
            if byte == 0x5c:
                index += 2
                continue
            if byte == 0x22:
                quote = False
        elif byte == 0x22:
            quote = True
        elif byte == 0x7b:
            depth += 1
        elif byte == 0x7d:
            depth -= 1
            if depth == 0:
                return clean[start:index + 1]
        index += 1
    raise Refusal("invalid package manifest")


def zon_strings(raw, field):
    marker = re.compile(
        rb"(?<![A-Za-z0-9_])\." + re.escape(field.encode("ascii")) + rb"\b")
    values = re.findall(
        rb"(?<![A-Za-z0-9_])\." + re.escape(field.encode("ascii"))
        + rb'\s*=\s*"([A-Za-z0-9._+:/#-]+)"', raw)
    require(len(values) == len(marker.findall(raw)), "invalid package manifest string")
    return [value.decode("ascii") for value in values]


def validate_restore_manifest(raw):
    dependencies = zon_block(raw, "dependencies")
    miz = zon_block(dependencies, "miz_source")
    urls = zon_strings(miz, "url")
    hashes = zon_strings(miz, "hash")
    require(urls == [MIZ_URL] and hashes == [MIZ_PACKAGE_HASH]
            and zon_strings(dependencies, "hash") == [MIZ_PACKAGE_HASH],
            "wrong pinned Miz dependency")
    return {"url": MIZ_URL, "revision": MIZ_REVISION,
            "package_hash": MIZ_PACKAGE_HASH}


def tracked_manifest(relative, repository=REPO):
    encoded = relative.encode("utf-8")
    raw = git_raw(repository, "ls-tree", "-z", "HEAD", "--", relative)
    if not raw:
        raise Refusal("pinned dependency manifest unavailable")
    require(raw.endswith(b"\0") and raw.count(b"\0") == 1,
            "pinned dependency manifest is not uniquely tracked")
    try:
        header, found = raw[:-1].split(b"\t", 1)
        mode, kind, oid = header.decode("ascii").split(" ")
    except (UnicodeDecodeError, ValueError) as error:
        raise Refusal("invalid pinned dependency manifest identity") from error
    object_format = git("rev-parse", "--show-object-format", repository=repository)
    require(found == encoded and kind == "blob" and mode in ("100644", "100755"),
            "invalid pinned dependency manifest identity")
    data, info = source_file(repository, relative, mode, oid, object_format)
    return {
        "path": relative,
        "mode": mode,
        "bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "git_oid": oid,
        "metadata": list(snapshot(info)),
        "metadata_sha256": hashlib.sha256(
            json.dumps(snapshot(info), separators=(",", ":")).encode("ascii")).hexdigest(),
    }, data


def create_exact_copy(path, data):
    require(canonical(path.parent)
            and stat.S_ISDIR(path.parent.lstat().st_mode), "unsafe copy directory")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        handle = os.open(path, flags, 0o600)
    except FileExistsError as error:
        raise Refusal("dependency manifest target already exists") from error
    try:
        os.fchmod(handle, 0o600)
        offset = 0
        while offset < len(data):
            count = os.write(handle, data[offset:])
            require(count > 0, "dependency manifest copy failed")
            offset += count
        os.fsync(handle)
        copied = snapshot(os.fstat(handle))
    finally:
        os.close(handle)
    require(read(path, MIB) == data and snapshot(path.lstat()) == copied,
            "dependency manifest copy changed")
    return {
        "bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "metadata": list(copied),
    }


def restored_manifest_state(restore, expected):
    try:
        before = restore.lstat()
    except FileNotFoundError as error:
        raise Refusal("dependency restore directory unavailable") from error
    require(canonical(restore)
            and stat.S_ISDIR(before.st_mode)
            and before.st_uid == os.getuid()
            and stat.S_IMODE(before.st_mode) == 0o700,
            "unsafe dependency restore directory")
    entries = sorted(entry.name for entry in os.scandir(restore))
    require(entries == ["build.zig", "build.zig.zon", "zig-pkg"],
            "unexpected dependency restore entry")
    packages = restore / "zig-pkg"
    package_info = packages.lstat()
    require(stat.S_ISDIR(package_info.st_mode) and package_info.st_uid == os.getuid()
            and stat.S_IMODE(package_info.st_mode) == 0o700,
            "unsafe dependency package directory")
    manifests = {}
    for name in ("build.zig", "build.zig.zon"):
        path = restore / name
        info = path.lstat()
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
                and info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o600,
                "unsafe copied dependency manifest")
        data = read(path, MIB)
        require(data == expected[name] and snapshot(path.lstat()) == snapshot(info),
                "copied dependency manifest differs from source")
        manifests[name] = {
            "bytes": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
            "metadata": list(snapshot(info)),
        }
    require(snapshot(restore.lstat()) == snapshot(before),
            "dependency restore directory changed")
    return {
        "directory": {"metadata": list(snapshot(before))},
        "manifests": manifests,
    }


def safe_package_name(name):
    require(PACKAGE_NAME.fullmatch(name) is not None
            and name not in (".", ".."), "unsafe package root name")
    return name


def safe_package_component(name):
    require(name not in ("", ".", "..") and "/" not in name and "\0" not in name
            and len(name.encode("utf-8")) <= 255,
            "unsafe dependency package path")
    return name


def package_tree_state(packages):
    try:
        root_before = packages.lstat()
    except FileNotFoundError as error:
        raise Refusal("private pinned dependency restore required") from error
    require(canonical(packages)
            and stat.S_ISDIR(root_before.st_mode)
            and root_before.st_uid == os.getuid()
            and stat.S_IMODE(root_before.st_mode) == 0o700,
            "private pinned dependency restore required")
    directories = {}
    files = {}
    roots = []

    def collect(directory, prefix, depth):
        require(depth <= 64, "dependency package depth exceeded")
        before = directory.lstat()
        require(stat.S_ISDIR(before.st_mode) and before.st_uid == os.getuid(),
                "unsafe dependency package directory")
        directories[prefix] = snapshot(before)
        require(len(files) + len(directories) - 1 <= PACKAGE_MAX_ENTRIES,
                "dependency package entry limit exceeded")
        try:
            entries = sorted(os.scandir(directory), key=lambda entry: entry.name)
        except OSError as error:
            raise Refusal("dependency package enumeration failed") from error
        if not prefix:
            require(0 < len(entries) <= PACKAGE_MAX_ROOTS,
                    "invalid dependency package roots")
        for entry in entries:
            if not prefix:
                safe_package_name(entry.name)
            else:
                safe_package_component(entry.name)
            relative = entry.name if not prefix else prefix + "/" + entry.name
            require(len(relative.encode()) <= 1024,
                    "dependency package path too long")
            path = directory / entry.name
            info = path.lstat()
            if stat.S_ISDIR(info.st_mode):
                if not prefix:
                    roots.append(entry.name)
                collect(path, relative, depth + 1)
                continue
            require(prefix and stat.S_ISREG(info.st_mode) and info.st_nlink == 1
                    and info.st_uid == os.getuid() and info.st_size <= PACKAGE_MAX_FILE,
                    "nonregular or unsafe dependency package entry")
            files[relative] = snapshot(info)
            require(len(files) + len(directories) - 1 <= PACKAGE_MAX_ENTRIES,
                    "dependency package entry limit exceeded")
        require(snapshot(directory.lstat()) == snapshot(before),
                "dependency package directory changed")

    collect(packages, "", -1)
    require(roots == sorted(set(roots)), "ambiguous dependency package roots")
    return {"roots": roots, "directories": directories, "files": files}


def package_file(path, expected):
    info = path.lstat()
    require(snapshot(info) == expected
            and stat.S_ISREG(info.st_mode) and info.st_nlink == 1
            and info.st_uid == os.getuid() and info.st_size <= PACKAGE_MAX_FILE,
            "dependency package file replaced")
    with path.open("rb") as stream:
        require(snapshot(os.fstat(stream.fileno())) == expected,
                "dependency package file replaced")
        data = stream.read(PACKAGE_MAX_FILE + 1)
    require(len(data) == info.st_size and snapshot(path.lstat()) == expected,
            "dependency package file changed")
    return data


def directory_inventory(packages, name, state):
    root = packages / name
    tree = hashlib.sha256(b"hyperv-native-tree-v1\0")
    physical = hashlib.sha256(b"hyperv-native-physical-v1\0")
    files = 0
    directories = 0
    total = 0
    seen_directories = set()
    seen_files = set()

    def collect(directory, prefix, depth):
        nonlocal files, directories, total
        require(depth <= 64, "dependency package depth exceeded")
        relative = name if not prefix else name + "/" + prefix
        require(relative in state["directories"], "unexpected dependency package directory")
        before = state["directories"][relative]
        require(snapshot(directory.lstat()) == before,
                "dependency package directory changed")
        seen_directories.add(relative)
        directories += 1
        require(files + directories <= PACKAGE_MAX_ENTRIES,
                "dependency package entry limit exceeded")
        bind(tree, ["directory", prefix, stat.S_IMODE(before[2])])
        bind(physical, ["directory", prefix, before])
        try:
            entries = sorted(os.scandir(directory), key=lambda entry: entry.name)
        except OSError as error:
            raise Refusal("dependency package enumeration failed") from error
        for entry in entries:
            safe_package_component(entry.name)
            relative = entry.name if not prefix else prefix + "/" + entry.name
            require(len(relative.encode()) <= 1024, "dependency package path too long")
            path = directory / entry.name
            global_relative = name + "/" + relative
            if global_relative in state["directories"]:
                collect(path, relative, depth + 1)
                continue
            require(global_relative in state["files"],
                    "unexpected dependency package entry")
            info = state["files"][global_relative]
            data = package_file(path, info)
            seen_files.add(global_relative)
            files += 1
            total += len(data)
            require(files + directories <= PACKAGE_MAX_ENTRIES
                    and total <= PACKAGE_MAX_BYTES,
                    "dependency package limit exceeded")
            sha256 = hashlib.sha256(data).hexdigest()
            bind(tree, ["file", relative, len(data), stat.S_IMODE(info[2]), sha256])
            bind(physical, ["file", relative, len(data), sha256, info])
        require(snapshot(directory.lstat()) == before,
                "dependency package directory changed")

    collect(root, "", 0)
    expected_directories = {
        relative for relative in state["directories"]
        if relative == name or relative.startswith(name + "/")
    }
    expected_files = {
        relative for relative in state["files"]
        if relative.startswith(name + "/")
    }
    require(files > 0 and seen_directories == expected_directories
            and seen_files == expected_files,
            "empty or changed dependency package")
    return {
        "files": files,
        "directories": directories,
        "bytes": total,
        "tree_sha256": tree.hexdigest(),
        "physical_sha256": physical.hexdigest(),
    }


def package_roots(packages):
    try:
        before = packages.lstat()
    except FileNotFoundError as error:
        raise Refusal("private pinned dependency restore required") from error
    require(canonical(packages)
            and stat.S_ISDIR(before.st_mode)
            and before.st_uid == os.getuid()
            and stat.S_IMODE(before.st_mode) == 0o700,
            "private pinned dependency restore required")
    entries = sorted(os.scandir(packages), key=lambda entry: entry.name)
    require(0 < len(entries) <= PACKAGE_MAX_ROOTS, "invalid dependency package roots")
    names = []
    for entry in entries:
        safe_package_name(entry.name)
        info = (packages / entry.name).lstat()
        require(stat.S_ISDIR(info.st_mode), "dependency package root must be a directory")
        names.append(entry.name)
    require(len(names) == len(set(names)) and snapshot(packages.lstat()) == snapshot(before),
            "ambiguous or changed dependency package roots")
    return names


def package_dependencies(raw):
    dependencies = zon_block(raw, "dependencies", required=False)
    if dependencies is None:
        return []
    hashes = zon_strings(dependencies, "hash")
    for value in hashes:
        safe_package_name(value)
    require(len(hashes) == len(set(hashes)), "ambiguous transitive package dependency")
    return sorted(hashes)


def command_record(path, stage, limit):
    raw = read(path, limit + 1)
    require(len(raw) <= limit, "dependency command capture exceeded")
    return {
        "scope": "command_diagnostic_not_acceptance",
        "stage": stage,
        "exit_code": 0,
        "bytes": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "over_limit": False,
        "known_error_markers": command_error_markers(raw),
    }


def dependency_custody(root):
    restore = root / "dependencies"
    require(canonical(restore)
            and stat.S_ISDIR(restore.lstat().st_mode)
            and restore.lstat().st_uid == os.getuid()
            and stat.S_IMODE(restore.lstat().st_mode) == 0o700,
            "private dependency restore directory required")
    manifests = {}
    manifest_data = {}
    for name in ("build.zig", "build.zig.zon"):
        relative = (LOCAL_BOOT / name).relative_to(REPO).as_posix()
        source_record, expected = tracked_manifest(relative)
        manifest_data[name] = expected
        manifests[name] = {"source": source_record}
    restored = restored_manifest_state(restore, manifest_data)
    for name in manifests:
        manifests[name]["copy"] = restored["manifests"][name]
    request = validate_restore_manifest(read(restore / "build.zig.zon", MIB))
    packages = restore / "zig-pkg"
    package_state = package_tree_state(packages)
    names = package_state["roots"]
    records = []
    manifest_digest = hashlib.sha256(b"uk.wamr.package-manifests-v1\0")
    manifest_count = 0
    manifest_bytes = 0
    dependencies = {}
    for name in names:
        package = packages / name
        inventory = directory_inventory(packages, name, package_state)
        manifest = package / "build.zig.zon"
        if manifest.exists():
            require(not manifest.is_symlink(), "unsafe transitive package manifest")
            raw = read(manifest, 4 * MIB)
            deps = package_dependencies(raw)
            manifest_record = {
                "bytes": len(raw),
                "sha256": hashlib.sha256(raw).hexdigest(),
                "dependencies": deps,
            }
            manifest_count += 1
            manifest_bytes += len(raw)
            bind(manifest_digest, [name, manifest_record])
        else:
            manifest_record = None
            deps = []
        dependencies[name] = deps
        records.append({"package_hash": name, "content": inventory,
                        "manifest": manifest_record})
    require(package_tree_state(packages) == package_state,
            "dependency package directory set changed")
    reachable = set()
    pending = [MIZ_PACKAGE_HASH]
    while pending:
        name = pending.pop()
        require(name in dependencies, "missing transitive dependency package")
        if name in reachable:
            continue
        reachable.add(name)
        pending.extend(dependencies[name])
        require(len(reachable) + len(pending) <= PACKAGE_MAX_ROOTS * 2,
                "transitive dependency closure limit exceeded")
    require(reachable == set(names), "unexpected transitive dependency package")
    hash_records = []
    for index, name in enumerate(names):
        path = root / "private" / f"dependency-hash-{index:03d}.log"
        raw = read(path, 512)
        require(raw == (name + "\n").encode("ascii"),
                "Zig package content hash mismatch")
        hash_records.append({"package_hash": name,
                             "sha256": hashlib.sha256(raw).hexdigest()})
    closure = hashlib.sha256(b"uk.wamr.package-closure-v1\0")
    for record in records:
        bind(closure, record)
    physical = hashlib.sha256(b"uk.wamr.package-physical-closure-v1\0")
    for record in records:
        bind(physical, [record["package_hash"], record["content"]["physical_sha256"]])
    root_info = package_state["directories"][""]
    record = {
        "schema": "uk.wamr.zig-dependency-custody",
        "version": 1,
        "request": request,
        "source_manifests": manifests,
        "restore_directory": restored["directory"],
        "restore": command_record(root / "private/dependency-restore.log",
                                  "dependency-restore", 8 * MIB),
        "packages": {
            "roots": len(records),
            "files": sum(item["content"]["files"] for item in records),
            "directories": sum(item["content"]["directories"] for item in records),
            "bytes": sum(item["content"]["bytes"] for item in records),
            "closure_sha256": closure.hexdigest(),
            "physical_sha256": physical.hexdigest(),
            "root_metadata": list(root_info),
            "root_metadata_sha256": hashlib.sha256(json.dumps(
                root_info, separators=(",", ":")).encode("ascii")).hexdigest(),
            "manifests": {
                "count": manifest_count,
                "bytes": manifest_bytes,
                "sha256": manifest_digest.hexdigest(),
            },
            "hash_verification": {
                "algorithm": "zig-0.16.0-fetch-path",
                "count": len(hash_records),
                "sha256": hashlib.sha256(json.dumps(
                    hash_records, sort_keys=True,
                    separators=(",", ":")).encode("ascii")).hexdigest(),
            },
            "records": records,
        },
    }
    require(record["packages"]["files"] <= PACKAGE_MAX_ENTRIES
            and record["packages"]["files"] + record["packages"]["directories"]
            <= PACKAGE_MAX_ENTRIES
            and record["packages"]["bytes"] <= PACKAGE_MAX_BYTES,
            "dependency closure limit exceeded")
    return record


def verify_package_hashes(root, packages):
    work = root / "dependency-hash-work"
    cache = root / "dependency-hash-cache"
    work.mkdir(mode=0o700)
    cache.mkdir(mode=0o700)
    expected = {}
    copies = {}
    for name in ("build.zig", "build.zig.zon"):
        data = read(root / "dependencies" / name, MIB)
        expected[name] = data
        copies[name] = create_exact_copy(work / name, data)
    (work / "zig-pkg").mkdir(mode=0o700)
    work_state = restored_manifest_state(work, expected)
    require(work_state["manifests"] == copies,
            "dependency hash workspace manifest identity changed")
    names = package_roots(packages)
    for index, name in enumerate(names):
        try:
            output, _ = execute(
                root, f"dependency-hash-{index:03d}",
                [tool("zig"), "fetch", "--global-cache-dir", cache, packages / name],
                300, 511, cwd=work, evidence=False)
        except Refusal as error:
            raise Refusal("Zig package hash recomputation failed") from error
        require(read(output, 512) == (name + "\n").encode("ascii"),
                "Zig package content hash mismatch")
        require(restored_manifest_state(work, expected) == work_state,
                "dependency hash workspace manifest identity changed")


def restore_dependencies(root, expected_source):
    restore = root / "dependencies"
    restore.mkdir(mode=0o700)
    require_source(expected_source)
    source_manifests = {}
    manifest_data = {}
    copied_manifests = {}
    for name in ("build.zig", "build.zig.zon"):
        try:
            record, data = tracked_manifest(
                (LOCAL_BOOT / name).relative_to(REPO).as_posix())
        except FileNotFoundError as error:
            raise Refusal("pinned dependency manifest unavailable") from error
        source_manifests[name] = record
        manifest_data[name] = data
        copied_manifests[name] = create_exact_copy(restore / name, data)
    (restore / "zig-pkg").mkdir(mode=0o700)
    validate_restore_manifest(read(restore / "build.zig.zon", MIB))
    restored = restored_manifest_state(restore, manifest_data)
    require(restored["manifests"] == copied_manifests,
            "copied dependency manifest identity changed")
    require_source(expected_source)
    try:
        _, command = execute(root, "dependency-restore", [
            tool("zig"), "build", "--build-file", restore / "build.zig",
            "--fetch=all", "--cache-dir", root / "cache",
            "--global-cache-dir", root / "global-cache", "-j2",
        ], 900, evidence=False)
    except Refusal as error:
        raise Refusal("pinned dependency restore command failed") from error
    require(command["known_error_markers"] == [], "dependency restore reported an error")
    require(restored_manifest_state(restore, manifest_data) == restored,
            "copied dependency manifest identity changed")
    packages = restore / "zig-pkg"
    require(any(os.scandir(packages)), "private pinned dependency restore required")
    package_roots(packages)
    verify_package_hashes(root, packages)
    custody = dependency_custody(root)
    require(custody["source_manifests"] == {
        name: {
            "source": record,
            "copy": copied_manifests[name],
        }
        for name, record in source_manifests.items()
    } and custody["restore_directory"] == restored["directory"],
            "copied dependency manifest identity changed")
    require_source(expected_source)
    return packages


def require_build_custody(runtime, expected):
    current_source = source()
    require(source_identity(current_source) == expected["source"]
            and current_source["custody"] == expected["source_custody"],
            "immutable source custody changed")
    require_dependency_custody(runtime / "compute", expected["dependencies"])


def require_dependency_custody(root, expected):
    require(dependency_custody(root) == expected, "dependency custody changed")


def run_custodied(runtime, expected, root, stage, args, seconds=600, limit=8 * MIB):
    require_build_custody(runtime, expected)
    output = run(root, stage, args, seconds, limit)
    require_build_custody(runtime, expected)
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
    current_source = source()
    image = document(APP / "build/image-identity.json")
    require(image["schema_version"] == 1
            and image["unikraft_revision"] == current_source["revision"]
            and image["unikraft_diff_sha256"] == hashlib.sha256(b"").hexdigest(),
            "dirty or different image source")
    require(image["runtime_inputs_sha256"] == digest(APP / "build/artifacts/identity.json"),
            "runtime manifest changed")
    require(image["solved_config_sha256"] == solved_config(), "config changed")
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
    return {"source": source_identity(current_source),
            "runtime": identity, "image": image}


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
    source_kind = "raw_disk" if index < 2 else "fixed_vhd"
    return {
        "source": {
            "kind": source_kind,
            "path": str(root / "package" / ("unikraft.raw" if index < 2 else "unikraft.vhd")),
        },
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
    source = config["source"]
    args = [str(cli), "--" + source["kind"].replace("_", "-"), source["path"]]
    for key in ("qemu", "ovmf_code", "ovmf_vars", "work_dir", "expect",
                "expect_main_return", "cpus"):
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
    paths = [config["source"]["path"],
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


def prepare_source_outputs():
    output = APP / "build"
    config = APP / ".config"
    backup = APP / ".config.old"
    require(not output.exists() and not output.is_symlink()
            and not config.exists() and not config.is_symlink()
            and not backup.exists() and not backup.is_symlink(),
            "fresh precreated source output roots required")
    output.mkdir(mode=0o700)
    definition = read(APP / "defconfig", MIB)
    create_exact_copy(output / ".config", definition)
    create_exact_copy(config, definition)


def require_no_config_backup():
    backup = APP / ".config.old"
    require(not backup.exists() and not backup.is_symlink(),
            "unexpected configuration backup")


def retain_solved_config():
    source_path = APP / "build/.config"
    target = APP / ".config"
    data = read(source_path, MIB)
    parent = snapshot(APP.lstat())
    before = target.lstat()
    require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
            and before.st_uid == os.getuid() and stat.S_IMODE(before.st_mode) == 0o600,
            "unsafe solved configuration target")
    flags = os.O_WRONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    handle = os.open(target, flags)
    try:
        require(snapshot(os.fstat(handle)) == snapshot(before),
                "solved configuration target replaced")
        os.ftruncate(handle, 0)
        offset = 0
        while offset < len(data):
            count = os.write(handle, data[offset:])
            require(count > 0, "solved configuration copy failed")
            offset += count
        os.fsync(handle)
    finally:
        os.close(handle)
    require(read(target, MIB) == data and snapshot(APP.lstat()) == parent,
            "solved configuration publication changed source directory")


def solved_config():
    retained = read(APP / ".config", MIB)
    require(retained == read(APP / "build/.config", MIB),
            "solved build configuration changed")
    return hashlib.sha256(retained).hexdigest()


def build(runtime, wamr):
    root = runtime / "compute"
    root.mkdir(mode=0o700)
    for name in ("private", "evidence", "scratch", "cache", "global-cache",
                 "global-cache/tmp", "fixtures"):
        (root / name).mkdir(mode=0o700)
    prepare_source_outputs()
    os.environ.update(TMPDIR=str(root / "scratch"), MAKEFLAGS="-j2",
                      ZIG_LOCAL_CACHE_DIR=str(root / "cache"),
                      ZIG_GLOBAL_CACHE_DIR=str(root / "global-cache"),
                      KCONFIG_CONFIG=str(APP / "build/.config"),
                      KCONFIG_OVERWRITECONFIG="1",
                      M4=tool("m4"),
                      PYTHONDONTWRITEBYTECODE="1")
    require(os.environ.get("BISON_PKGDATADIR") == str(runtime / "bison"),
            "Bison build environment differs from bound producer input")
    initial_source = source()
    packages = restore_dependencies(root, initial_source)
    initial = producer_inputs(runtime)
    require(initial["source"] == source_identity(initial_source)
            and initial["source_custody"] == initial_source["custody"],
            "source changed during dependency restoration")
    save(root / "evidence/build-start.json", initial)
    require(subprocess.check_output([tool("zig"), "version"]).strip() == b"0.16.0",
            "Zig 0.16.0 required")
    run_custodied(runtime, initial, root, "adapter", [
        tool("zig"), "build", "--build-file", HERE / "build.zig",
        "--system", packages, "--prefix", root / "tools",
        "-Doptimize=ReleaseSafe", "-j2", "test", "install"], 900)
    run_custodied(runtime, initial, root, "local-boot-tool", [
        tool("zig"), "build", "--build-file", LOCAL_BOOT / "build.zig",
        "--system", packages, "--prefix", root / "tools",
        "-Doptimize=ReleaseSafe", "-j2", "install"], 900)
    os.environ["WAMR_CI_PACKAGE"] = str(root / "tools/bin/wamr-ci-package")
    run_custodied(runtime, initial, root, "fixtures", [
        sys.executable, "-m", "unittest", "discover", "-s", HERE / "tests", "-v"])
    run_custodied(runtime, initial, root, "prepare", [
        sys.executable, APP / "prepare.py", "prepare", "--source", wamr], 1800)
    run_custodied(runtime, initial, root, "config", [
        sys.executable, APP / "build-image.py", "olddefconfig"])
    require_no_config_backup()
    retain_solved_config()
    solved_config()
    require_build_custody(runtime, initial)
    # This target includes the unchanged final ELF IRQ/constructor/SMP proofs.
    run_custodied(runtime, initial, root, "native-image", [
        sys.executable, APP / "build-image.py", "native-images"], 1800)
    solved_config()
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
    initial = document(root / "evidence/build-start.json")
    require(producer_inputs(runtime) == initial, "producer inputs changed")
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
    output = run_custodied(
        runtime, initial, root, "package",
        [paths["package_tool"], "package", efi, root / "package"], 150, 64 * 1024)
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
        run_custodied(
            runtime, initial, root, mode,
            boot_args(paths["local_boot_tool"], config), 90, 64 * 1024)
        result = check_boot(config, identity)
        expected = package["image"]["raw" if index < 2 else "vhd"]["sha256"]
        require(digest(Path(config["source"]["path"])) == expected,
                "booted package changed")
        save(root / "evidence" / (mode + "-compute.json"), result)
    output = run_custodied(
        runtime, initial, root, "inspect",
        [paths["package_tool"], "inspect", efi, root / "package"], 150, 64 * 1024)
    require(document(output) == package, "physical package reload changed")
    verify_inputs()
    require(producer_inputs(runtime) == initial, "producer inputs changed after boot")
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
    require(runtime.is_absolute() and canonical(runtime)
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
    except (OSError, RuntimeError, ValueError, KeyError, TypeError,
            subprocess.SubprocessError):
        print("WAMR native compute CI failed; bounded private logs and redacted diagnostics retained.",
              file=sys.stderr)
        sys.exit(1)
