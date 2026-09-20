#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""Private exact-image handoff, finite-cost authorization records; no Azure."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import stat
import struct
import subprocess
import sys
import time
import uuid
import zipfile

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("wamr_native_ci", HERE / "run.py")
ci = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ci)
NAMES = ("efi", "debug_elf", "bootinfo", "raw", "vhd", "runtime", "compiler",
         "wasm", "cwasm", "config", "runtime_identity", "image_identity",
         "local_result", "package", "build", "build_start", "boot_inputs")
V2_NAMES = (
    "efi", "debug_elf", "bootinfo", "raw", "qcow2", "vhd",
    "runtime", "compiler", "wasm", "cwasm", "config",
    "runtime_identity", "image_identity", "local_result", "package",
    "build", "build_start", "boot_inputs",
    "qcow2_finalization_intent", "qcow2_finalization",
    "qcow2_acceptance", "fixed_vhd_derivation_intent",
    "fixed_vhd_derivation_gate", "fixed_vhd_derivation",
    "final_inspection", "cleanup",
)
FAILURE_STAGE = "handoff"
CANONICALIZATION = "utf8-byte-sorted-keys-compact-lf-v1"
COST_POLICY = "northeurope-standard-d2s-v5-conservative-2026-09-v1"
REPOSITORY_MAXIMUM_COST_MICROUSD = 100_000_000
ESTIMATED_COST_UPPER_BOUND_MICROUSD = 9_500_000
FIXED_VHD_BYTES = 66 * 1024 * 1024 + 512
FIXED_VHD_CAPACITY_BYTES = FIXED_VHD_BYTES - 512
AZURE_RUNTIME_MAX_FILES = 16_384
AZURE_RUNTIME_MAX_DIRECTORIES = 4_096
AZURE_RUNTIME_MAX_BYTES = 2 * 1024 * 1024 * 1024
AZURE_RUNTIME_MAX_DEPTH = 32
AZURE_RUNTIME_MAX_FILE_BYTES = 256 * 1024 * 1024
AZURE_RUNTIME_MAX_LOADER_FILES = 256
AZURE_RUNTIME_MAX_MANIFEST_BYTES = 32 * 1024 * 1024
AZURE_RUNTIME_COMMANDS = (
    ("version",),
    ("group", "exists"),
    ("group", "create"),
    ("group", "show"),
    ("group", "delete"),
    ("disk", "create"),
    ("disk", "show"),
    ("disk", "grant-access"),
    ("disk", "revoke-access"),
    ("deployment", "group", "create"),
    ("vm", "deallocate"),
    ("vm", "start"),
    ("vm", "show"),
    ("vm", "get-instance-view"),
    ("vm", "boot-diagnostics", "get-boot-log"),
    ("resource", "list"),
)


def private(path):
    ci.require(path.is_absolute() and path.resolve(strict=True) == path,
               "absolute nonsymlink private path required")
    info = path.lstat()
    ci.require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid()
               and stat.S_IMODE(info.st_mode) == 0o700, "private directory required")


def artifact(path):
    return {"path": str(path), "size": path.stat().st_size, "sha256": ci.digest(path)}


def _canonical_absolute(path, reason):
    path = Path(path)
    raw = str(path)
    ci.require(path.is_absolute() and os.path.normpath(raw) == raw
               and "//" not in raw and all(
                   part not in ("", ".", "..") for part in path.parts[1:]),
               reason)
    return path


def _physical(info):
    mtime = divmod(info.st_mtime_ns, 1_000_000_000)
    ctime = divmod(info.st_ctime_ns, 1_000_000_000)
    return (
        os.major(info.st_dev), os.minor(info.st_dev), info.st_ino,
        info.st_mode, info.st_uid, info.st_gid, info.st_nlink, info.st_size,
        mtime[0], mtime[1], ctime[0], ctime[1],
    )


def _metadata_line(tag, path, info):
    return (
        f"{tag}\t{path}\t"
        + "\t".join(map(str, _physical(info))) + "\n"
    ).encode()


def _parent_line(path, info):
    return (
        f"P\t{path}\t{os.major(info.st_dev)}\t{os.minor(info.st_dev)}\t"
        f"{info.st_ino}\t{info.st_mode}\t{info.st_uid}\t{info.st_gid}\n"
    ).encode()


def _safe_source_tree(path):
    path = _canonical_absolute(path, "canonical Azure runtime source required")
    ci.require(path.resolve(strict=True) == path, "Azure runtime source symlink forbidden")
    info = path.lstat()
    ci.require(stat.S_ISDIR(info.st_mode)
               and info.st_uid in (0, os.geteuid())
               and not info.st_mode & 0o022,
               "unsafe Azure runtime source directory")
    return path


class _RuntimeCopyBudget:
    def __init__(self, root):
        self.root = Path(root)
        self.files = 0
        self.directories = 0
        self.bytes = 0

    def directory(self, destination):
        self.directories += 1
        depth = len(Path(destination).relative_to(self.root).parts)
        ci.require(
            self.directories <= AZURE_RUNTIME_MAX_DIRECTORIES
            and depth <= AZURE_RUNTIME_MAX_DEPTH,
            "Azure runtime closure limit exceeded")

    def file(self, destination, size):
        self.files += 1
        self.bytes += size
        depth = len(Path(destination).relative_to(self.root).parts) - 1
        ci.require(
            self.files <= AZURE_RUNTIME_MAX_FILES
            and self.bytes <= AZURE_RUNTIME_MAX_BYTES
            and depth <= AZURE_RUNTIME_MAX_DEPTH,
            "Azure runtime closure limit exceeded")


def _copy_runtime_file(source, destination, executable=None, budget=None,
                       parent_fd=None, source_name=None):
    source = Path(source)
    if parent_fd is None:
        source = _canonical_absolute(
            source, "canonical Azure runtime file required")
        info = source.lstat()
        ci.require(source.resolve(strict=True) == source,
                   "unsafe Azure runtime file")
    else:
        ci.require(source_name is not None, "unsafe Azure runtime file")
        info = os.stat(source_name, dir_fd=parent_fd, follow_symlinks=False)
    ci.require(stat.S_ISREG(info.st_mode)
               and info.st_uid in (0, os.geteuid())
               and not info.st_mode & 0o7022
               and info.st_nlink == 1
               and 0 < info.st_size <= AZURE_RUNTIME_MAX_FILE_BYTES,
               "unsafe Azure runtime file")
    if budget is not None:
        budget.file(destination, info.st_size)
    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    flags = os.O_RDONLY | os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    descriptor = os.open(
        source if parent_fd is None else source_name,
        flags, dir_fd=parent_fd)
    try:
        before = os.fstat(descriptor)
        ci.require(
            _physical(before) == _physical(info),
            "Azure runtime source changed")
        with os.fdopen(os.dup(descriptor), "rb") as incoming, \
                destination.open("xb") as outgoing:
            os.fchmod(outgoing.fileno(), 0o600)
            shutil.copyfileobj(incoming, outgoing, 64 * 1024)
            outgoing.flush()
            os.fsync(outgoing.fileno())
        ci.require(
            _physical(os.fstat(descriptor)) == _physical(before),
            "Azure runtime source changed")
        reopened = os.open(
            source if parent_fd is None else source_name,
            flags, dir_fd=parent_fd)
        try:
            ci.require(
                _physical(os.fstat(reopened)) == _physical(before),
                "Azure runtime source changed")
        finally:
            os.close(reopened)
    except OSError as error:
        raise ci.Refusal("Azure runtime source changed") from error
    finally:
        os.close(descriptor)
    mode = bool(before.st_mode & 0o111) if executable is None else executable
    destination.chmod(0o500 if mode else 0o400)


def _copy_runtime_tree(source, destination, budget, merge=False):
    source = _safe_source_tree(source)
    destination.mkdir(mode=0o700, parents=True, exist_ok=merge)
    budget.directory(destination)
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        directory_flags |= os.O_CLOEXEC

    def copy_directory(current, target, descriptor):
        info = os.fstat(descriptor)
        ci.require(stat.S_ISDIR(info.st_mode)
                   and info.st_uid in (0, os.geteuid())
                   and not info.st_mode & 0o022,
                   "unsafe Azure runtime source directory")
        try:
            with os.scandir(descriptor) as scan:
                for entry in scan:
                    source_child = current / entry.name
                    target_child = target / entry.name
                    child_info = os.stat(
                        entry.name, dir_fd=descriptor,
                        follow_symlinks=False)
                    ci.require(not stat.S_ISLNK(child_info.st_mode),
                               "Azure runtime source symlink forbidden")
                    ci.require(not target_child.exists(),
                               "Azure runtime tree collision")
                    if stat.S_ISDIR(child_info.st_mode):
                        ci.require(
                            child_info.st_uid in (0, os.geteuid())
                            and not child_info.st_mode & 0o022,
                            "unsafe Azure runtime source directory")
                        budget.directory(target_child)
                        target_child.mkdir(mode=0o700)
                        child_descriptor = os.open(
                            entry.name, directory_flags,
                            dir_fd=descriptor)
                        try:
                            ci.require(
                                _physical(os.fstat(child_descriptor))
                                == _physical(child_info),
                                "Azure runtime source changed")
                            copy_directory(
                                source_child, target_child,
                                child_descriptor)
                            reopened = os.open(
                                entry.name, directory_flags,
                                dir_fd=descriptor)
                            try:
                                ci.require(
                                    _physical(os.fstat(reopened))
                                    == _physical(child_info),
                                    "Azure runtime source changed")
                            finally:
                                os.close(reopened)
                        finally:
                            os.close(child_descriptor)
                    else:
                        ci.require(
                            stat.S_ISREG(child_info.st_mode)
                            and source_child.suffix != ".pth"
                            and source_child.name not in (
                                "sitecustomize.py", "usercustomize.py"),
                            "Python startup hook forbidden")
                        _copy_runtime_file(
                            source_child, target_child, budget=budget,
                            parent_fd=descriptor,
                            source_name=entry.name)
            ci.require(
                _physical(os.fstat(descriptor)) == _physical(info),
                "Azure runtime source changed")
        except OSError as error:
            raise ci.Refusal("Azure runtime source changed") from error

    root_descriptor = os.open(source, directory_flags)
    try:
        root_info = source.lstat()
        ci.require(
            _physical(os.fstat(root_descriptor)) == _physical(root_info),
            "Azure runtime source changed")
        copy_directory(source, destination, root_descriptor)
        reopened = os.open(source, directory_flags)
        try:
            ci.require(
                _physical(os.fstat(reopened)) == _physical(root_info),
                "Azure runtime source changed")
        finally:
            os.close(reopened)
    except OSError as error:
        raise ci.Refusal("Azure runtime source changed") from error
    finally:
        os.close(root_descriptor)


def _elf_dependencies(paths):
    ldd = Path("/usr/bin/ldd")
    ci.require(ldd.is_file(), "explicit dynamic loader inspection required")
    dependencies = set()
    for path in sorted(map(Path, paths)):
        with path.open("rb") as stream:
            if stream.read(4) != b"\x7fELF":
                continue
        completed = subprocess.run(
            [str(ldd), str(path)], env={"LC_ALL": "C"},
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, timeout=60, check=False)
        ci.require(completed.returncode == 0
                   and len(completed.stdout) <= 1024 * 1024,
                   "dynamic loader dependency inspection failed")
        for raw in completed.stdout.decode("utf-8", "strict").splitlines():
            line = raw.strip()
            if not line or line.startswith("linux-vdso."):
                continue
            candidate = None
            if " => " in line:
                value = line.split(" => ", 1)[1].split(" (", 1)[0]
                ci.require(value != "not found",
                           "unresolved native Azure runtime dependency")
                if value.startswith("/"):
                    candidate = value
            elif line.startswith("/"):
                candidate = line.split(" (", 1)[0]
            if candidate is not None:
                resolved = Path(candidate).resolve(strict=True)
                info = resolved.lstat()
                ci.require(stat.S_ISREG(info.st_mode)
                           and info.st_uid in (0, os.geteuid())
                           and not info.st_mode & 0o7022
                           and info.st_nlink == 1
                           and 0 < info.st_size
                           <= AZURE_RUNTIME_MAX_FILE_BYTES,
                           "unsafe native Azure runtime dependency")
                dependencies.add(resolved)
    ci.require(len(dependencies) <= AZURE_RUNTIME_MAX_LOADER_FILES,
               "Azure runtime loader dependency limit exceeded")
    return sorted(dependencies, key=str)


def _elf_interpreter(path):
    with Path(path).open("rb") as stream:
        header = stream.read(64)
        ci.require(
            len(header) == 64 and header[:6] == b"\x7fELF\x02\x01",
            "explicit ELF interpreter required")
        program_offset = struct.unpack_from("<Q", header, 32)[0]
        program_size, program_count = struct.unpack_from("<HH", header, 54)
        ci.require(
            program_size == 56 and 0 < program_count <= 1024,
            "explicit ELF interpreter required")
        found = None
        for index in range(program_count):
            stream.seek(program_offset + index * program_size)
            program = stream.read(program_size)
            ci.require(
                len(program) == program_size,
                "explicit ELF interpreter required")
            if struct.unpack_from("<I", program)[0] != 3:
                continue
            offset = struct.unpack_from("<Q", program, 8)[0]
            size = struct.unpack_from("<Q", program, 32)[0]
            ci.require(
                found is None and 1 < size <= 4096,
                "explicit ELF interpreter required")
            stream.seek(offset)
            value = stream.read(size)
            ci.require(
                len(value) == size and value[-1:] == b"\0"
                and b"\0" not in value[:-1],
                "explicit ELF interpreter required")
            found = Path(value[:-1].decode("utf-8", "strict"))
        ci.require(found is not None, "explicit ELF interpreter required")
        return _canonical_absolute(
            found.resolve(strict=True), "canonical ELF interpreter required")


def _parent_records(paths):
    parents = {Path("/")}
    for path in paths:
        parent = Path(path).parent
        while True:
            parents.add(parent)
            if parent == Path("/"):
                break
            parent = parent.parent
    result = []
    for parent in sorted(parents, key=str):
        ci.require(parent.resolve(strict=True) == parent,
                   "Azure runtime parent symlink forbidden")
        info = parent.lstat()
        ci.require(stat.S_ISDIR(info.st_mode)
                   and info.st_uid in (0, os.geteuid())
                   and not info.st_mode & 0o022,
                   "unsafe Azure runtime parent")
        result.append((str(parent), info))
    return result


def _runtime_role(relative, launcher, interpreter):
    path = relative.as_posix()
    if path == launcher:
        return "launcher"
    if path == interpreter:
        return "interpreter"
    if ".so" in relative.name:
        return "native-extension"
    if path.startswith("lib/"):
        return "python-module"
    if path.startswith("share/"):
        return "fixed-data"
    return "runtime"


def _scan_azure_runtime(root, launcher, interpreter, dependencies):
    root = Path(root)
    records = []
    file_count = 0
    directory_count = 0
    total_bytes = 0
    observed_depth = 0
    pending = [root]
    while pending:
        current = pending.pop()
        relative_dir = current.relative_to(root)
        depth = 0 if relative_dir == Path(".") else len(relative_dir.parts)
        observed_depth = max(observed_depth, depth)
        directory_count += 1
        ci.require(
            directory_count <= AZURE_RUNTIME_MAX_DIRECTORIES
            and observed_depth <= AZURE_RUNTIME_MAX_DEPTH,
            "Azure runtime closure limit exceeded")
        info = current.lstat()
        ci.require(stat.S_ISDIR(info.st_mode)
                   and info.st_uid == os.geteuid()
                   and not info.st_mode & 0o022,
                   "unsafe prepared Azure runtime directory")
        relative = Path(".") if relative_dir == Path(".") else relative_dir
        records.append(("D", relative.as_posix(), info, None))
        directories = []
        try:
            with os.scandir(current) as scan:
                for entry in scan:
                    child = current / entry.name
                    child_info = child.lstat()
                    ci.require(not stat.S_ISLNK(child_info.st_mode),
                               "prepared Azure runtime symlink forbidden")
                    if stat.S_ISDIR(child_info.st_mode):
                        directories.append(child)
                    elif stat.S_ISREG(child_info.st_mode):
                        ci.require(
                            child_info.st_uid == os.geteuid()
                            and not child_info.st_mode & 0o7022
                            and child_info.st_nlink == 1
                            and 0 < child_info.st_size
                            <= AZURE_RUNTIME_MAX_FILE_BYTES,
                            "unsafe prepared Azure runtime file")
                        file_count += 1
                        total_bytes += child_info.st_size
                        ci.require(
                            file_count <= AZURE_RUNTIME_MAX_FILES
                            and total_bytes <= AZURE_RUNTIME_MAX_BYTES,
                            "Azure runtime closure limit exceeded")
                        relative = child.relative_to(root).as_posix()
                        records.append(
                            ("F", relative, child_info, ci.digest(child)))
                    else:
                        raise ci.Refusal(
                            "unsafe prepared Azure runtime entry")
        except OSError as error:
            raise ci.Refusal("prepared Azure runtime changed") from error
        pending.extend(sorted(directories, key=str, reverse=True))
    records.sort(key=lambda item: item[1].encode())
    content = hashlib.sha256()
    metadata = hashlib.sha256()
    manifest = [b"UK-WAMR-AZURE-RUNTIME-CLOSURE\t1\n"]
    for kind, relative, info, digest in records:
        content_size = info.st_size if kind == "F" else 0
        content.update(
            f"C\t{kind}\t{relative}\t{content_size}\t"
            f"{digest or '-'}\n".encode())
        metadata.update(_metadata_line("M", relative, info))
        role = _runtime_role(
            Path(relative),
            Path(launcher).relative_to(root).as_posix(),
            Path(interpreter).relative_to(root).as_posix())
        manifest.append((
            f"{kind}\t{role}\t{relative}\t"
            + "\t".join(map(str, _physical(info)))
            + f"\t{digest or '-'}\n"
        ).encode())
    loader_artifacts = []
    for dependency in dependencies:
        info = dependency.lstat()
        digest = ci.digest(dependency)
        content.update(
            f"C\tL\t{dependency}\t{info.st_size}\t{digest}\n".encode())
        metadata.update(_metadata_line("L", str(dependency), info))
        manifest.append((
            f"L\tloader-dependency\t{dependency}\t"
            + "\t".join(map(str, _physical(info)))
            + f"\t{digest}\n"
        ).encode())
        loader_artifacts.append(artifact(dependency))

    parent_hash = hashlib.sha256()
    for path, info in _parent_records([root, *dependencies]):
        line = _parent_line(path, info)
        parent_hash.update(line)
        manifest.append(line)
    return {
        "records": manifest,
        "loader_dependencies": loader_artifacts,
        "observed": {
            "files": file_count,
            "directories": directory_count,
            "bytes": total_bytes,
            "depth": observed_depth,
            "loader_files": len(loader_artifacts),
        },
        "content": content,
        "metadata": metadata,
        "parents_sha256": parent_hash.hexdigest(),
    }


def prepare_azure_runtime(output, azure, az_python, stdlib, *,
                          package_roots=(), data_roots=(),
                          native_dependencies=(), validator):
    output = Path(output)
    private(output.parent)
    ci.require(not output.exists(), "fresh Azure runtime output required")
    azure = _canonical_absolute(azure, "canonical Azure launcher required")
    az_python = _canonical_absolute(
        az_python, "canonical Azure interpreter required")
    executable_artifact(azure)
    executable_artifact(az_python)
    stdlib = _safe_source_tree(stdlib)
    python_version = stdlib.name.removeprefix("python")
    ci.require(stdlib.name.startswith("python")
               and 3 <= len(stdlib.name) <= 16
               and len(python_version.split(".")) == 2
               and all(part.isdigit() and 1 <= len(part) <= 3
                       for part in python_version.split(".")),
               "canonical Python stdlib root required")

    output.mkdir(mode=0o700)
    runtime = output / "runtime"
    runtime.mkdir(mode=0o700)
    budget = _RuntimeCopyBudget(runtime)
    extensions = runtime / "extensions"
    extensions.mkdir(mode=0o700)
    launcher = runtime / "bootstrap/azure-cli"
    interpreter = runtime / "bin/python"
    _copy_runtime_file(
        azure, launcher, executable=True, budget=budget)
    _copy_runtime_file(
        az_python, interpreter, executable=True, budget=budget)
    library = runtime / "lib" / stdlib.name
    _copy_runtime_tree(stdlib, library, budget)
    for package_root in package_roots:
        _copy_runtime_tree(package_root, library, budget, merge=True)
    for index, data_root in enumerate(data_roots):
        source = _safe_source_tree(data_root)
        _copy_runtime_tree(
            source, runtime / "share" / f"{index:03d}-{source.name}",
            budget)

    manifest = output / "azure-runtime.manifest"
    record = output / "azure-runtime.json"
    config = output / "startup-config"
    config.mkdir(mode=0o700)
    for path in (manifest, record):
        with path.open("xb") as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.flush()
            os.fsync(stream.fileno())

    native_files = [
        path for path in runtime.rglob("*")
        if path.is_file() and (
            path == interpreter or ".so" in path.name)
    ]
    explicit_native = []
    for dependency in native_dependencies:
        dependency = _canonical_absolute(
            dependency, "canonical native dependency required")
        ci.require(
            dependency.resolve(strict=True) == dependency,
            "native dependency symlink forbidden")
        info = dependency.lstat()
        ci.require(
            stat.S_ISREG(info.st_mode)
            and info.st_uid in (0, os.geteuid())
            and not info.st_mode & 0o7022
            and info.st_nlink == 1
            and 0 < info.st_size <= AZURE_RUNTIME_MAX_FILE_BYTES,
            "unsafe native Azure runtime dependency")
        explicit_native.append(dependency)
    dynamic_loader_source = _elf_interpreter(az_python)
    dependency_sources = set(_elf_dependencies(
        [*native_files, *explicit_native]))
    dependency_sources.update(explicit_native)
    dependency_sources.add(dynamic_loader_source)
    dependency_sources = sorted(dependency_sources, key=str)
    ci.require(len(dependency_sources) <= AZURE_RUNTIME_MAX_LOADER_FILES,
               "Azure runtime loader dependency limit exceeded")
    loader_directory = runtime / "loader"
    loader_directory.mkdir(mode=0o700)
    dependencies = []
    loader_names = {}
    for dependency in dependency_sources:
        destination = loader_directory / dependency.name
        prior = loader_names.get(dependency.name)
        ci.require(
            prior is None or ci.digest(prior) == ci.digest(dependency),
            "Azure runtime loader basename collision")
        if prior is None:
            _copy_runtime_file(
                dependency, destination,
                executable=dependency == dynamic_loader_source,
                budget=budget)
            loader_names[dependency.name] = dependency
            dependencies.append(destination)
    dependencies.sort(key=str)
    dynamic_loader = loader_directory / dynamic_loader_source.name

    for current, names, file_names in os.walk(
            runtime, topdown=False, followlinks=False):
        for name in file_names:
            path = Path(current) / name
            mode = 0o500 if path.stat().st_mode & 0o111 else 0o400
            path.chmod(mode)
        for name in names:
            (Path(current) / name).chmod(0o500)
        Path(current).chmod(0o500)

    scan = _scan_azure_runtime(
        runtime, launcher, interpreter, dependencies)

    with manifest.open("r+b") as stream:
        stream.truncate(0)
        for manifest_record in scan["records"]:
            stream.write(manifest_record)
        stream.flush()
        os.fsync(stream.fileno())
    ci.require(manifest.stat().st_size <= AZURE_RUNTIME_MAX_MANIFEST_BYTES,
               "Azure runtime manifest limit exceeded")
    manifest_info = manifest.lstat()
    manifest_digest = ci.digest(manifest)
    scan["content"].update(
        f"C\tA\t{manifest}\t{manifest_info.st_size}\t"
        f"{manifest_digest}\n".encode())
    scan["metadata"].update(_metadata_line("A", str(manifest), manifest_info))
    value = {
        "schema": "uk.wamr.azure-cli-runtime-closure",
        "version": 1,
        "canonicalization": CANONICALIZATION,
        "root": str(runtime),
        "python_version": python_version,
        "extensions": str(extensions),
        "launcher": executable_artifact(launcher),
        "interpreter": executable_artifact(interpreter),
        "dynamic_loader": executable_artifact(dynamic_loader),
        "manifest": artifact(manifest),
        "limits": {
            "files": AZURE_RUNTIME_MAX_FILES,
            "directories": AZURE_RUNTIME_MAX_DIRECTORIES,
            "bytes": AZURE_RUNTIME_MAX_BYTES,
            "depth": AZURE_RUNTIME_MAX_DEPTH,
            "file_bytes": AZURE_RUNTIME_MAX_FILE_BYTES,
            "loader_files": AZURE_RUNTIME_MAX_LOADER_FILES,
        },
        "observed": scan["observed"],
        "content_sha256": scan["content"].hexdigest(),
        "metadata_sha256": scan["metadata"].hexdigest(),
        "parents_sha256": scan["parents_sha256"],
        "loader_dependencies": scan["loader_dependencies"],
        "commands": [list(command) for command in AZURE_RUNTIME_COMMANDS],
        "isolation": {
            "python_home": "closure_root",
            "module_layout": "flat_python_home_v1",
            "extensions": "closure_empty",
            "dynamic_extension_install": "disabled",
            "user_site": "disabled",
            "site_import": "disabled",
            "bytecode_writes": "disabled",
            "path_environment": "forbidden",
            "startup_hooks": "forbidden",
            "loader_environment": "retained_readonly_root",
            "package_restore": "forbidden_after_custody",
        },
    }
    raw_record = ci.compact_json(value, newline=True)
    with record.open("r+b") as stream:
        stream.truncate(0)
        stream.write(raw_record)
        stream.flush()
        os.fsync(stream.fileno())
    native_validate(validator, "azure-runtime", record)
    probe_environment = {
        "HOME": str(output),
        "AZURE_CONFIG_DIR": str(config),
        "LC_ALL": "C",
        "AZURE_CORE_COLLECT_TELEMETRY": "0",
        "AZURE_EXTENSION_DIR": str(extensions),
        "AZURE_EXTENSION_USE_DYNAMIC_INSTALL": "no",
        "PYTHONHOME": str(runtime),
        "PYTHONNOUSERSITE": "1",
        "PYTHONSAFEPATH": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
    }
    for command in AZURE_RUNTIME_COMMANDS:
        arguments = [
            str(dynamic_loader), "--inhibit-cache", "--library-path",
            str(loader_directory), str(interpreter),
            "-s", "-S", "-B", "-P", str(launcher), *command,
        ]
        if command == ("version",):
            arguments.extend(("--output", "json", "--only-show-errors"))
        else:
            arguments.append("--help")
        ci.bounded_subprocess_output(
            arguments, output, 1024 * 1024, 30,
            "prepared Azure runtime probe overflow",
            "prepared Azure runtime probe timeout",
            "prepared Azure runtime command unavailable",
            env=probe_environment)
    native_validate(validator, "azure-runtime", record)
    return value


def result_records(root):
    result = ci.document(root / "evidence/result.json")
    version = result["schema_version"]
    modes = ci.MODES if version == 1 else ci.SIX_MODES
    ci.require(version in (1, 2) and result["passed"] is True
               and (version == 1 or result.get("profile") == ci.CURRENT_PROFILE)
               and result["scope"] == "local_native_compute_only"
               and result["hardware_acceptance"] == "not_established"
               and result["cloud_authority"] == "not_admitted"
               and result["benchmark"] == "not_measured"
               and result["workload"] == "tiny"
               and result["modes"] == list(modes), "wrong local result")
    records = result["records"]
    ci.require(8 <= len(records) <= 64 and "result.json" not in records,
               "invalid earlier record set")
    for name, expected in records.items():
        ci.require(Path(name).name == name and name.endswith(".json")
                   and name not in (".json", "..json"), "invalid record name")
        ci.require(ci.digest(root / "evidence" / name) == expected, "local record changed")
    required = {"build.json", "build-start.json", "boot-inputs.json", "package.json"}
    required.update(mode + "-compute.json" for mode in modes)
    if version == 2:
        required.update({
            "qcow2-finalization-intent.json", "qcow2-finalization.json",
            "qcow2-acceptance.json", "fixed-vhd-derivation-intent.json",
            "fixed-vhd-derivation-gate.json",
            "fixed-vhd-derivation.json", "final-inspection.json",
        })
    ci.require(required <= records.keys(), "incomplete local records")
    return records


def export(runtime, output):
    private(runtime)
    private(output.parent)
    root = runtime / "compute"
    records = result_records(root)
    result = ci.document(root / "evidence/result.json")
    version = result["schema_version"]
    modes = ci.MODES if version == 1 else ci.SIX_MODES
    names = NAMES if version == 1 else V2_NAMES
    expected = ci.document(root / "evidence/build-start.json")
    legacy_supervision = "command_supervisor" not in expected
    if (not legacy_supervision
            and "command-supervisor" in expected["consumer_inputs"]["files"]):
        ci.COMMAND_ENVIRONMENT.update(ci.bind_command_tools(
            expected["consumer_inputs"]))
    elif legacy_supervision:
        ci.COMMAND_ENVIRONMENT.clear()
        ci.COMMAND_TOOL_PATHS.clear()
        if "command-supervisor" in expected["consumer_inputs"]["files"]:
            supervisor_path = ci.bind_command_supervisor(
                expected["consumer_inputs"])
            ci.COMMAND_ENVIRONMENT[
                "WAMR_CI_SUPERVISOR"] = supervisor_path
    before = ci.producer_inputs(runtime, expected["consumer_inputs"])
    ci.require(before == expected,
               "producer inputs changed")
    build = ci.check_build()
    ci.require(build == ci.document(root / "evidence/build.json"), "build changed")
    inputs = ci.document(root / "evidence/boot-inputs.json")
    tools = {"package_tool": root / "tools/bin/wamr-ci-package",
             "local_boot_tool": root / "tools/bin/uk-hyperv-local-boot",
             "qemu": runtime / "bin/qemu-system-x86_64",
             "ovmf_code": runtime / "firmware/code.fd",
             "ovmf_vars": runtime / "firmware/vars.fd",
             "efi": ci.APP / "build" / ci.EFI}
    ci.boot_input_state(runtime, tools, expected=inputs)
    for i, mode in enumerate(modes):
        checked = ci.check_boot(
            ci.config_for(runtime, root, i, modes), build["runtime"], inputs)
        ci.require(checked == ci.document(root / "evidence" / (mode + "-compute.json")),
                   "physical local result changed")
    ci.require_build_custody(runtime, before)
    output.mkdir(mode=0o700)
    for name in ("private", "evidence", "artifacts", "boots"):
        (output / name).mkdir(mode=0o700)
    input_records = ci.consumer_file_records(expected["consumer_inputs"])
    input_records.update(ci.consumer_file_records(inputs))
    compatibility_supervisor = None
    if ci.COMMAND_SUPERVISOR_PATH is not None:
        supervisor_path = str(Path(
            ci.COMMAND_SUPERVISOR_PATH).resolve(strict=True))
        if supervisor_path not in input_records:
            compatibility_supervisor = ci.record_input_paths(
                {"command-supervisor": Path(supervisor_path)}, {})
            input_records.update(ci.consumer_file_records(
                compatibility_supervisor))
    if legacy_supervision and ci.COMMAND_SUPERVISOR_PATH is not None:
        ci.COMMAND_ENVIRONMENT[
            "WAMR_CI_SUPERVISOR"] = ci.COMMAND_SUPERVISOR_PATH
    inspect_stage = (
        "handoff-inspect-legacy"
        if legacy_supervision else "handoff-inspect")
    inspected_output, inspected_command = ci.execute(
        output, inspect_stage,
        [tools["package_tool"], "inspect", ci.APP / "build" / ci.EFI, root / "package"],
        150, 64 * 1024, input_records=input_records,
        path_roles={
            "input:package_tool": tools["package_tool"],
            "compute": root,
        })
    ci.validate_supervised_command_binding(
        inspected_command, inspect_stage, {
            "command-supervisor": ci.native_executable_identity(
                input_records[str(Path(
                    ci.COMMAND_SUPERVISOR_PATH).resolve(strict=True))]),
            **({} if legacy_supervision else {
                "tool:" + name: ci.native_executable_identity(
                    expected["consumer_inputs"]["files"]["tool:" + name])
                for name in ci.HOST_TOOLS
            }),
            "input:package_tool": ci.native_executable_identity(
                inputs["files"]["package_tool"]),
        }, profile=(
            ci.CURRENT_PROFILE
            if version == 2 else "tiny-aot-two-boot"))
    inspected = ci.document(inspected_output)
    packaged = ci.document(root / "evidence/package.json")
    ci.require(inspected["producer_sha256"] == packaged["producer_sha256"]
               and all(inspected["image"][key] == value
                       for key, value in packaged["image"].items()),
               "physical package changed")
    if compatibility_supervisor is not None:
        ci.record_input_paths(
            {"command-supervisor": Path(ci.COMMAND_SUPERVISOR_PATH)}, {},
            expected=compatibility_supervisor)
    legacy_paths = (
        ci.APP / "build" / ci.EFI, ci.APP / "build" / (ci.EFI + ".dbg"),
        ci.APP / "build" / (ci.EFI + ".bootinfo"), root / "package/unikraft.raw",
        root / "package/unikraft.vhd", ci.APP / "build/artifacts/libwamr-aot.a",
        ci.APP / "build/artifacts/wamrc", ci.APP / "build/artifacts/tiny.wasm",
        ci.APP / "build/artifacts/tiny.cwasm", ci.APP / ".config",
        ci.APP / "build/artifacts/identity.json", ci.APP / "build/image-identity.json",
        root / "evidence/result.json", root / "evidence/package.json",
        root / "evidence/build.json", root / "evidence/build-start.json",
        root / "evidence/boot-inputs.json")
    current_paths = (
        ci.APP / "build" / ci.EFI, ci.APP / "build" / (ci.EFI + ".dbg"),
        ci.APP / "build" / (ci.EFI + ".bootinfo"),
        root / "package/unikraft.raw", root / "package/unikraft.qcow2",
        root / "package/unikraft-derived.vhd",
        ci.APP / "build/artifacts/libwamr-aot.a",
        ci.APP / "build/artifacts/wamrc", ci.APP / "build/artifacts/tiny.wasm",
        ci.APP / "build/artifacts/tiny.cwasm", ci.APP / ".config",
        ci.APP / "build/artifacts/identity.json",
        ci.APP / "build/image-identity.json",
        root / "evidence/result.json", root / "evidence/package.json",
        root / "evidence/build.json", root / "evidence/build-start.json",
        root / "evidence/boot-inputs.json",
        root / "evidence/qcow2-finalization-intent.json",
        root / "evidence/qcow2-finalization.json",
        root / "evidence/qcow2-acceptance.json",
        root / "evidence/fixed-vhd-derivation-intent.json",
        root / "evidence/fixed-vhd-derivation-gate.json",
        root / "evidence/fixed-vhd-derivation.json",
        root / "evidence/final-inspection.json",
        runtime / "evidence/runtime-cleanup.txt",
    )
    paths = legacy_paths if version == 1 else current_paths

    def retain(source, destination):
        original = artifact(source)
        with source.open("rb") as src, destination.open("xb") as dst:
            shutil.copyfileobj(src, dst, 65536)
            dst.flush()
            os.fsync(dst.fileno())
        destination.chmod(0o600)
        saved = artifact(destination)
        ci.require(artifact(source) == original
                   and all(saved[key] == original[key] for key in ("sha256", "size")),
                   "handoff copy changed")
        return saved

    artifacts = [
        retain(path, output / "artifacts" / name)
        for name, path in zip(names, paths)
    ]
    boots = []
    for mode in modes:
        slot = output / "boots" / mode
        slot.mkdir(mode=0o700)
        work = root / ("boot-" + mode)
        boots.append(dict(mode=mode, **{
            key: retain(path, slot / key) for key, path in (
                ("serial", work / "hyperv-efi-boot.log"), ("request", work / "request.json"),
                ("report", work / "report.json"),
                ("compute", root / "evidence" / (mode + "-compute.json")))}))
    evidence = [retain(root / "evidence" / name, output / "evidence" / name)
                for name in sorted(records)]
    ci.require(result_records(root) == records and ci.check_build() == build
               and ci.producer_inputs(
                   runtime, expected["consumer_inputs"]) == before,
               "inputs changed during handoff")
    ci.boot_input_state(runtime, tools, content=True, expected=inputs)
    by_name = dict(zip(names, artifacts))
    bundle = {
        "schema": "uk.wamr.local-image-handoff", "version": 1,
        "authority": "not_admitted",
        "source_revision": build["source"]["revision"], "source_tree": build["source"]["tree"],
        "identity": dict(wamr_revision=ci.REVISION, **{
            name + "_sha256": by_name[name]["sha256"]
            for name in ("wasm", "cwasm", "runtime", "compiler", "config")}),
        "artifacts": artifacts, "boots": boots, "evidence": evidence,
    }
    if version == 2:
        run_id = os.environ.get("GITHUB_RUN_ID")
        run_attempt = os.environ.get("GITHUB_RUN_ATTEMPT")
        ci.require(
            os.environ.get("GITHUB_REPOSITORY") == "cataggar/unikraft"
            and isinstance(run_id, str)
            and isinstance(run_attempt, str)
            and run_id.isdecimal() and int(run_id) > 0
            and run_attempt.isdecimal() and int(run_attempt) > 0,
            "exact CI run identity required")
        bundle.update(
            version=2,
            profile=ci.CURRENT_PROFILE,
            run={
                "repository": "cataggar/unikraft",
                "run_id": run_id,
                "run_attempt": run_attempt,
            },
            lineage={
                "raw_sha256": by_name["raw"]["sha256"],
                "accepted_qcow2_sha256": by_name["qcow2"]["sha256"],
                "derived_vhd_sha256": by_name["vhd"]["sha256"],
                "qcow2_finalization_sha256":
                    by_name["qcow2_finalization"]["sha256"],
                "qcow2_acceptance_sha256":
                    by_name["qcow2_acceptance"]["sha256"],
                "fixed_vhd_derivation_sha256":
                    by_name["fixed_vhd_derivation"]["sha256"],
                "fixed_vhd_derivation_gate_sha256":
                    by_name["fixed_vhd_derivation_gate"]["sha256"],
                "final_inspection_sha256":
                    by_name["final_inspection"]["sha256"],
            },
        )
    ci.save(output / "bundle.json", bundle)
    return bundle


def candidate_plan(bundle_path, output, *, attempt_id=None,
                   subscription=None, prefix=None):
    private(bundle_path.parent)
    private(output.parent)
    bundle = ci.document(bundle_path)
    ci.require(bundle["schema"] == "uk.wamr.local-image-handoff"
               and bundle["version"] in (1, 2)
               and bundle["authority"] == "not_admitted"
               and bundle["identity"]["wamr_revision"] == ci.REVISION,
               "not a compute handoff")
    version = bundle["version"]
    names = NAMES if version == 1 else V2_NAMES
    modes = ci.MODES if version == 1 else ci.SIX_MODES
    if version == 2:
        ci.require(bundle["profile"] == ci.CURRENT_PROFILE
                   and bundle["run"]["repository"] == "cataggar/unikraft"
                   and bundle["run"]["run_id"].isdecimal()
                   and bundle["run"]["run_attempt"].isdecimal(),
                   "not a version-2 compute handoff")
    for item in bundle["artifacts"] + bundle["evidence"] + [
            boot[key] for boot in bundle["boots"] for key in ("serial", "request", "report", "compute")]:
        ci.require(artifact(Path(item["path"])) == item, "handoff bytes changed")
    scope_bundle = artifact(bundle_path)
    purpose = "tiny-aot-two-boot"
    if version == 2:
        transport_path = bundle_path.parent / "transport.json"
        transport = ci.document(transport_path)
        ci.require(
            set(transport) == {
                "schema", "version", "repository", "run_id", "run_attempt",
                "source_revision", "source_tree", "inner_zip_sha256",
                "artifact_id", "container_digest",
            }
            and transport["schema"] == "uk.wamr.public-source-transport"
            and transport["version"] == 2
            and transport["repository"] == bundle["run"]["repository"]
            and transport["run_id"] == bundle["run"]["run_id"]
            and transport["run_attempt"] == bundle["run"]["run_attempt"]
            and transport["source_revision"] == bundle["source_revision"]
            and transport["source_tree"] == bundle["source_tree"],
            "untrusted version-2 transport")
        admission_path = output.parent / (output.name + ".admission.json")
        admission = {
            "schema": "uk.wamr.direct-compute-admission",
            "version": 2,
            "profile": ci.CURRENT_PROFILE,
            "authority": "not_admitted",
            "source_revision": bundle["source_revision"],
            "source_tree": bundle["source_tree"],
            "run": bundle["run"],
            "lineage": bundle["lineage"],
            "public_bundle": artifact(bundle_path),
            "transport": artifact(transport_path),
        }
        ci.save(admission_path, admission)
        scope_bundle = artifact(admission_path)
        purpose = ci.CURRENT_PROFILE
    value = {
        "schema": "uk.wamr.direct-compute", "version": version,
        "purpose": purpose,
        "authority": "not_admitted",
        "approval": dict.fromkeys((
            "direct_specialized_gen2", "os_only_private", "two_boots_only",
            "cleanup_owned_group", "exact_image_and_local_bundle_reviewed",
            "fresh_final_approval"), False),
        "attempt_id": str(uuid.uuid4()) if attempt_id is None else attempt_id,
        "subscription": "FINAL-APPROVED-SUBSCRIPTION-UUID",
        "location": "northeurope", "prefix": "FINAL-APPROVED-FRESH-NAME",
        "vm_size": "Standard_D2s_v5", "serial_mode": "azure_cumulative",
        "runtime_seconds": 3600, "cleanup_seconds": 1800,
        "operation_seconds": 600, "poll_seconds": 10,
        "source_revision": bundle["source_revision"], "source_tree": bundle["source_tree"],
        "identity": bundle["identity"],
        "os_vhd": bundle["artifacts"][names.index("vhd")],
        "bundle": scope_bundle,
    }
    if version == 2:
        value.update(
            subscription=(
                "00000000-0000-0000-0000-000000000001"
                if subscription is None else subscription),
            prefix="not-admitted-candidate" if prefix is None else prefix,
        )
    ci.require([boot["mode"] for boot in bundle["boots"]] == list(modes),
               "wrong compute handoff modes")
    value["approval"].update(approved_unix=0, expires_unix=0)
    ci.save(output, value)
    return value


def canonical_document(path):
    value = ci.document(path)
    ci.require(ci.read(path, 64 * 1024) == ci.compact_json(value, newline=True),
               "canonical private JSON required")
    return value


def executable_artifact(path):
    path = Path(path)
    raw = str(path)
    ci.require(path.is_absolute() and os.path.normpath(raw) == raw
               and "//" not in raw and all(
                   part not in ("", ".", "..") for part in path.parts[1:]),
               "canonical explicit executable required")
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    file_flags = os.O_RDONLY | os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        directory_flags |= os.O_CLOEXEC
        file_flags |= os.O_CLOEXEC
    descriptors = []
    directory_identities = []
    directory_identity = lambda value: (
        value.st_dev, value.st_ino, value.st_mode, value.st_uid)
    file_identity = lambda value: (
        value.st_dev, value.st_ino, value.st_mode, value.st_uid,
        value.st_nlink, value.st_size, value.st_mtime_ns,
        value.st_ctime_ns)
    try:
        current = os.open("/", directory_flags)
        descriptors.append(current)
        info = os.fstat(current)
        ci.require(
            stat.S_ISDIR(info.st_mode)
            and info.st_uid in (0, os.geteuid())
            and not info.st_mode & 0o022,
            "unsafe executable parent")
        directory_identities.append(directory_identity(info))
        for part in path.parts[1:-1]:
            current = os.open(part, directory_flags, dir_fd=current)
            descriptors.append(current)
            info = os.fstat(current)
            ci.require(
                stat.S_ISDIR(info.st_mode)
                and info.st_uid in (0, os.geteuid())
                and not info.st_mode & 0o022,
                "unsafe executable parent")
            directory_identities.append(directory_identity(info))
        descriptor = os.open(path.name, file_flags, dir_fd=current)
        descriptors.append(descriptor)
        before = os.fstat(descriptor)
        ci.require(
            stat.S_ISREG(before.st_mode)
            and before.st_uid in (0, os.geteuid())
            and before.st_mode & 0o111
            and not before.st_mode & 0o6022
            and before.st_nlink == 1
            and 0 < before.st_size <= 64 * 1024 * 1024,
            "unsafe explicit executable")
        digest = hashlib.sha256()
        offset = 0
        while offset < before.st_size:
            chunk = os.pread(
                descriptor, min(64 * 1024, before.st_size - offset),
                offset)
            ci.require(chunk, "explicit executable changed")
            digest.update(chunk)
            offset += len(chunk)
        after = os.fstat(descriptor)
        ci.require(file_identity(before) == file_identity(after),
                   "explicit executable changed")
        for parent, expected in zip(
                descriptors[:-1], directory_identities, strict=True):
            ci.require(
                directory_identity(os.fstat(parent)) == expected,
                "unsafe executable parent")
        reopened = []
        try:
            check = os.open("/", directory_flags)
            reopened.append(check)
            ci.require(
                directory_identity(os.fstat(check))
                == directory_identities[0],
                "unsafe executable parent")
            for index, part in enumerate(path.parts[1:-1], start=1):
                check = os.open(part, directory_flags, dir_fd=check)
                reopened.append(check)
                ci.require(
                    directory_identity(os.fstat(check))
                    == directory_identities[index],
                    "unsafe executable parent")
            named = os.open(path.name, file_flags, dir_fd=check)
            reopened.append(named)
            ci.require(
                file_identity(os.fstat(named)) == file_identity(before),
                "explicit executable changed")
        finally:
            for reopened_descriptor in reversed(reopened):
                os.close(reopened_descriptor)
        return {
            "path": raw,
            "size": before.st_size,
            "sha256": digest.hexdigest(),
        }
    except OSError as error:
        raise ci.Refusal("unsafe explicit executable") from error
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def native_validate(validator, *arguments):
    validator = Path(validator)
    executable_artifact(validator)
    completed = subprocess.run(
        [str(validator), *map(str, arguments)],
        env={"LC_ALL": "C"}, stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=300,
        check=False,
    )
    ci.require(completed.returncode == 0, "native authorization validation failed")


def native_json(validator, *arguments):
    validator = Path(validator)
    executable_artifact(validator)
    completed = subprocess.run(
        [str(validator), *map(str, arguments)],
        env={"LC_ALL": "C"}, stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=300,
        check=False,
    )
    ci.require(completed.returncode == 0
               and 0 < len(completed.stdout) <= 64 * 1024,
               "native authorization inspection failed")
    try:
        value = json.loads(completed.stdout)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ci.Refusal("native authorization inspection failed") from error
    ci.require(
        completed.stdout
        == (json.dumps(value, sort_keys=True, separators=(",", ":"))
            + "\n").encode(),
        "canonical native authorization inspection required")
    return value


def exact_tool_bindings(azure, uploader, validator, supervisor, az_python,
                        azure_runtime):
    runtime_path = Path(azure_runtime)
    private(runtime_path.parent)
    runtime = canonical_document(runtime_path)
    ci.require(
        runtime["schema"] == "uk.wamr.azure-cli-runtime-closure"
        and runtime["version"] == 1
        and runtime["launcher"]["path"] == str(azure)
        and runtime["interpreter"]["path"] == str(az_python),
        "explicit Azure runtime closure mismatch")
    native_validate(validator, "azure-runtime", runtime_path)
    return ({
        name: executable_artifact(Path(path))
        for name, path in (
            ("azure", azure),
            ("uploader", uploader),
            ("validator", validator),
            ("supervisor", supervisor),
            ("az_python", az_python),
        )
    }, artifact(runtime_path), runtime)


def require_tool_bindings(plan_value, azure, uploader, validator, supervisor,
                          az_python, azure_runtime):
    actual, document, runtime = exact_tool_bindings(
        azure, uploader, validator, supervisor, az_python, azure_runtime)
    ci.require(
        actual == plan_value["tools"]
        and document == plan_value["azure_runtime_document"]
        and runtime == plan_value["azure_runtime"],
        "approved tool/runtime binding changed")
    return actual, document, runtime


def runtime_approval_binding(plan_value):
    runtime = plan_value["azure_runtime"]
    return {
        "schema": runtime["schema"],
        "version": runtime["version"],
        "canonicalization": runtime["canonicalization"],
        "document_sha256":
            plan_value["azure_runtime_document"]["sha256"],
        "python_version": runtime["python_version"],
        "manifest": runtime["manifest"],
        "launcher": runtime["launcher"],
        "interpreter": runtime["interpreter"],
        "dynamic_loader": runtime["dynamic_loader"],
        "content_sha256": runtime["content_sha256"],
        "metadata_sha256": runtime["metadata_sha256"],
        "parents_sha256": runtime["parents_sha256"],
        "root": runtime["root"],
        "extensions": runtime["extensions"],
        "limits": runtime["limits"],
        "observed": runtime["observed"],
        "loader_dependencies": runtime["loader_dependencies"],
        "commands": runtime["commands"],
        "isolation": runtime["isolation"],
    }


def approval_limits(plan_value):
    return {
        "runtime_seconds": plan_value["runtime_seconds"],
        "cleanup_seconds": plan_value["cleanup_seconds"],
        "operation_seconds": plan_value["operation_seconds"],
        "maximum_parallelism":
            plan_value["resources"]["maximum_parallelism"],
        "boot_count": plan_value["resources"]["boot_count"],
        "retry_count": plan_value["retry_count"],
    }


def plan(bundle_path, output, approval_template, candidate_output, *,
         campaign_id, ledger, subscription, prefix,
         maximum_authorized_cost_microusd, azure, uploader, validator,
         supervisor, az_python, azure_runtime, attempt_id=None, ledger_id=None,
         created_unix=None):
    private(bundle_path.parent)
    private(output.parent)
    private(approval_template.parent)
    private(candidate_output.parent)
    private(ledger)
    ci.require(all(not path.exists() for path in (
        output, approval_template, candidate_output,
        candidate_output.parent / (candidate_output.name + ".admission.json"),
    )), "fresh plan outputs required")
    try:
        campaign_id = str(uuid.UUID(campaign_id))
        attempt_id = str(uuid.uuid4() if attempt_id is None
                         else uuid.UUID(attempt_id))
        ledger_id = str(uuid.uuid4() if ledger_id is None
                        else uuid.UUID(ledger_id))
        subscription = str(uuid.UUID(subscription))
    except (ValueError, AttributeError) as error:
        raise ci.Refusal("canonical plan UUID required") from error
    ci.require(type(maximum_authorized_cost_microusd) is int
               and ESTIMATED_COST_UPPER_BOUND_MICROUSD
               <= maximum_authorized_cost_microusd
               <= REPOSITORY_MAXIMUM_COST_MICROUSD,
               "finite micro-USD authorization maximum required")
    ci.require(type(prefix) is str and 6 <= len(prefix) <= 32
               and all(char.islower() or char.isdigit() or char == "-"
                       for char in prefix), "invalid exact resource prefix")
    created_unix = int(time.time()) if created_unix is None else created_unix
    ci.require(type(created_unix) is int and created_unix > 0,
               "invalid plan creation time")
    tools, runtime_document, runtime_closure = exact_tool_bindings(
        azure, uploader, validator, supervisor, az_python, azure_runtime)
    candidate = candidate_plan(
        bundle_path, candidate_output, attempt_id=attempt_id,
        subscription=subscription, prefix=prefix)
    native_validate(validator, "candidate", candidate_output)
    ci.require(candidate["version"] == 2
               and candidate["purpose"] == ci.CURRENT_PROFILE
               and candidate["authority"] == "not_admitted",
               "strict Azure plan requires imported version-2 candidate")
    imported = canonical_document(Path(candidate["bundle"]["path"]))
    public_bundle = canonical_document(Path(imported["public_bundle"]["path"]))
    transport = canonical_document(Path(imported["transport"]["path"]))
    names = [item["path"] for item in public_bundle["artifacts"]]
    by_name = dict(zip(V2_NAMES, public_bundle["artifacts"]))
    ci.require(len(names) == len(V2_NAMES)
               and by_name["vhd"] == candidate["os_vhd"],
               "candidate image binding changed")
    ledger_binding = native_json(
        validator, "ledger-proposal", ledger, campaign_id, ledger_id)
    ci.require(
        ledger_binding["campaign_id"] == campaign_id
        and ledger_binding["ledger_id"],
        "wrong campaign ledger proposal")
    resources = {
        "vm_count": 1,
        "os_disk_count": 1,
        "data_disk_count": 0,
        "public_ip_count": 0,
        "boot_count": 2,
        "maximum_parallelism": 1,
        "generation": 2,
        "os_disk_sku": "StandardSSD_LRS",
        "os_disk_capacity_bytes": FIXED_VHD_CAPACITY_BYTES,
        "network": "private_no_default_outbound",
    }
    value = {
        "schema": "uk.wamr.azure-execution-plan",
        "version": 2,
        "purpose": "qcow2-derived-vhd-two-boot",
        "profile": ci.CURRENT_PROFILE,
        "authority": "not_admitted",
        "canonicalization": CANONICALIZATION,
        "created_unix": created_unix,
        "attempt_id": attempt_id,
        "campaign_id": campaign_id,
        "campaign_profile": ci.CURRENT_PROFILE,
        "ledger_path": str(ledger),
        "ledger": ledger_binding,
        "subscription": subscription,
        "location": candidate["location"],
        "prefix": prefix,
        "vm_size": candidate["vm_size"],
        "serial_mode": "azure_cumulative",
        "runtime_seconds": 3600,
        "cleanup_seconds": 1800,
        "operation_seconds": 600,
        "poll_seconds": 10,
        "source_revision": candidate["source_revision"],
        "source_tree": candidate["source_tree"],
        "run": public_bundle["run"],
        "identity": candidate["identity"],
        "lineage": public_bundle["lineage"],
        "candidate": artifact(candidate_output),
        "bundle": candidate["bundle"],
        "public_bundle": imported["public_bundle"],
        "transport": imported["transport"],
        "qcow2": by_name["qcow2"],
        "os_vhd": by_name["vhd"],
        "vhd_bytes": by_name["vhd"]["size"],
        "vhd_capacity_bytes": FIXED_VHD_CAPACITY_BYTES,
        "artifact_id": transport["artifact_id"],
        "inner_zip_sha256": transport["inner_zip_sha256"],
        "container_digest": transport["container_digest"],
        "resources": resources,
        "retry_count": 0,
        "substitution": {
            "source": False, "image": False,
            "topology": False, "workload": False,
        },
        "cleanup": {
            "exact_owned_resources_only": True,
            "delete_owned_resource_group": True,
            "independent_absence_observation": True,
            "replacement_resources": False,
        },
        "cost": {
            "unit": "micro_usd",
            "policy": COST_POLICY,
            "estimated_upper_bound": ESTIMATED_COST_UPPER_BOUND_MICROUSD,
            "maximum_authorized": maximum_authorized_cost_microusd,
            "repository_policy_maximum":
                REPOSITORY_MAXIMUM_COST_MICROUSD,
        },
        "tools": tools,
        "azure_runtime_document": runtime_document,
        "azure_runtime": runtime_closure,
    }
    ci.require(value["vhd_bytes"] == FIXED_VHD_BYTES,
               "wrong fixed VHD byte length")
    ci.save(output, value)
    plan_sha256 = ci.digest(output, 64 * 1024)
    template = {
        "schema": "uk.wamr.azure-execution-approval-template",
        "version": 2,
        "decision": "pending",
        "plan_sha256": plan_sha256,
        "attempt_id": attempt_id,
        "campaign_id": campaign_id,
        "ledger_id": ledger_binding["ledger_id"],
        "ledger_initialization_required":
            ledger_binding["initialization_required"],
        "candidate_sha256": value["candidate"]["sha256"],
        "estimated_cost_upper_bound_microusd":
            ESTIMATED_COST_UPPER_BOUND_MICROUSD,
        "maximum_authorized_cost_microusd":
            maximum_authorized_cost_microusd,
        "limits": approval_limits(value),
        "azure_runtime": runtime_approval_binding(value),
    }
    ci.save(approval_template, template)
    native_validate(validator, "plan", output, approval_template)
    return value, template


def publish_validated(output, value, validator, command):
    ci.require(not output.exists(), "fresh private output required")
    partial = output.parent / (
        output.name + ".partial-" + uuid.uuid4().hex)
    try:
        ci.save(partial, value)
        native_validate(validator, *command, partial)
        os.link(partial, output, follow_symlinks=False)
        partial.unlink()
        directory = os.open(output.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if partial.exists():
            partial.unlink()


def record_authorization(plan_path, template_path, output, *, decision,
                         approver, reference, recorded_unix, expires_unix,
                         azure, uploader, validator, supervisor, az_python,
                         azure_runtime):
    private(plan_path.parent)
    private(template_path.parent)
    private(output.parent)
    plan_value = canonical_document(plan_path)
    template = canonical_document(template_path)
    require_tool_bindings(
        plan_value, azure, uploader, validator, supervisor, az_python,
        azure_runtime)
    native_validate(validator, "plan", plan_path, template_path)
    ci.require(template["plan_sha256"] == ci.digest(plan_path, 64 * 1024)
               and template["attempt_id"] == plan_value["attempt_id"]
               and template["campaign_id"] == plan_value["campaign_id"]
               and template["ledger_id"]
               == plan_value["ledger"]["ledger_id"]
               and template["ledger_initialization_required"]
               == plan_value["ledger"]["initialization_required"]
               and template["candidate_sha256"]
               == plan_value["candidate"]["sha256"]
               and template["azure_runtime"]
               == runtime_approval_binding(plan_value)
               and template["decision"] == "pending",
               "approval template does not bind exact plan")
    ci.require(decision in ("approved", "denied"),
               "explicit approved or denied decision required")
    ci.require(type(approver) is str and 1 <= len(approver.encode()) <= 128
               and type(reference) is str
               and 1 <= len(reference.encode()) <= 256
               and all(0x20 <= ord(char) != 0x7f
                       for char in approver + reference),
               "bounded authority fields required")
    ci.require(type(recorded_unix) is int and type(expires_unix) is int
               and recorded_unix > 0
               and recorded_unix < expires_unix
               and expires_unix - recorded_unix <= 3600,
               "bounded approval window required")
    authorization = {
        "schema": "uk.wamr.azure-execution-authorization",
        "version": 2,
        "decision": decision,
        "plan_sha256": template["plan_sha256"],
        "attempt_id": template["attempt_id"],
        "campaign_id": template["campaign_id"],
        "ledger_id": template["ledger_id"],
        "ledger_initialization_required":
            template["ledger_initialization_required"],
        "candidate_sha256": template["candidate_sha256"],
        "estimated_cost_upper_bound_microusd":
            template["estimated_cost_upper_bound_microusd"],
        "maximum_authorized_cost_microusd":
            template["maximum_authorized_cost_microusd"],
        "limits": template["limits"],
        "azure_runtime": template["azure_runtime"],
        "approver": approver,
        "reference": reference,
        "recorded_unix": recorded_unix,
        "expires_unix": expires_unix,
    }
    publish_validated(
        output, authorization, validator,
        ("authorization", plan_path))
    return authorization


def admission(plan_path, authorization_path, output, *, azure, uploader,
              validator, supervisor, az_python, azure_runtime):
    private(plan_path.parent)
    private(authorization_path.parent)
    private(output.parent)
    plan_value = canonical_document(plan_path)
    authorization = canonical_document(authorization_path)
    require_tool_bindings(
        plan_value, azure, uploader, validator, supervisor, az_python,
        azure_runtime)
    native_validate(
        validator, "authorization", plan_path, authorization_path)
    ci.require(authorization["decision"] == "approved",
               "denied decision cannot produce admission")
    value = {
        key: item for key, item in plan_value.items()
        if key not in ("schema", "version", "authority")
    }
    value.update({
        "schema": "uk.wamr.azure-execution-admission",
        "version": 2,
        "authority": "approved",
        "plan": artifact(plan_path),
        "authorization": artifact(authorization_path),
        "approval": {
            "approver": authorization["approver"],
            "reference": authorization["reference"],
            "approved_unix": authorization["recorded_unix"],
            "expires_unix": authorization["expires_unix"],
        },
    })
    publish_validated(output, value, validator, ("admission",))
    return value


def main():
    global FAILURE_STAGE
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    exp = sub.add_parser("export")
    exp.add_argument("--runtime", type=Path, required=True)
    exp.add_argument("--output", type=Path, required=True)
    prepare_runtime = sub.add_parser(
        "prepare-azure-runtime",
        help="Build a private create-only Azure CLI Python/module closure")
    prepare_runtime.add_argument("--output", type=Path, required=True)
    prepare_runtime.add_argument("--azure", type=Path, required=True)
    prepare_runtime.add_argument("--az-python", type=Path, required=True)
    prepare_runtime.add_argument("--stdlib", type=Path, required=True)
    prepare_runtime.add_argument(
        "--package-root", type=Path, action="append", required=True,
        help=("Reviewed Python import root; repeat for every Azure CLI "
              "package root"))
    prepare_runtime.add_argument(
        "--data-root", type=Path, action="append", default=[])
    prepare_runtime.add_argument(
        "--native-dependency", type=Path, action="append", default=[])
    prepare_runtime.add_argument(
        "--validator", type=Path, required=True)
    candidate = sub.add_parser(
        "candidate", help="Legacy non-authorizing candidate generation")
    candidate.add_argument("--bundle", type=Path, required=True)
    candidate.add_argument("--output", type=Path, required=True)
    pln = sub.add_parser("plan")
    pln.add_argument("--bundle", type=Path, required=True)
    pln.add_argument("--output", type=Path, required=True)
    pln.add_argument("--approval-template", type=Path, required=True)
    pln.add_argument("--candidate-output", type=Path, required=True)
    pln.add_argument("--campaign-id", required=True)
    pln.add_argument(
        "--ledger", type=Path, required=True,
        help="Existing private 0700 campaign ledger; planning never mutates it")
    pln.add_argument("--subscription", required=True)
    pln.add_argument("--prefix", required=True)
    pln.add_argument("--maximum-authorized-cost-microusd",
                     type=int, required=True)
    pln.add_argument("--attempt-id")
    pln.add_argument(
        "--ledger-id",
        help=("Proposed UUID for an uninitialized legacy ledger; defaults to "
              "a fresh UUID and is ignored for an initialized ledger"))
    pln.add_argument("--created-unix", type=int)
    for tool_name in ("azure", "uploader", "validator",
                      "supervisor", "az-python", "azure-runtime"):
        pln.add_argument("--" + tool_name, type=Path, required=True)
    authorize = sub.add_parser("record-authorization")
    authorize.add_argument("--plan", type=Path, required=True)
    authorize.add_argument("--template", type=Path, required=True)
    authorize.add_argument("--output", type=Path, required=True)
    authorize.add_argument("--decision", choices=("approved", "denied"),
                           required=True)
    authorize.add_argument("--approver", required=True)
    authorize.add_argument("--reference", required=True)
    authorize.add_argument("--recorded-unix", type=int, required=True)
    authorize.add_argument("--expires-unix", type=int, required=True)
    for tool_name in ("azure", "uploader", "validator",
                      "supervisor", "az-python", "azure-runtime"):
        authorize.add_argument("--" + tool_name, type=Path, required=True)
    admit = sub.add_parser("admit")
    admit.add_argument("--plan", type=Path, required=True)
    admit.add_argument("--authorization", type=Path, required=True)
    admit.add_argument("--output", type=Path, required=True)
    for tool_name in ("azure", "uploader", "validator",
                      "supervisor", "az-python", "azure-runtime"):
        admit.add_argument("--" + tool_name, type=Path, required=True)
    sub.add_parser("public-source-bundle", help="Explicit fixed public-repository tiny CI publication only")
    verify = sub.add_parser("verify-public-source-bundle")
    verify.add_argument("--archive", type=Path, required=True)
    verify.add_argument("--expected-source", required=True)
    verify.add_argument("--expected-tree", required=True)
    verify.add_argument("--expected-archive-sha256", required=True)
    verify.add_argument("--run-id", required=True)
    verify.add_argument("--run-attempt", required=True)
    imp = sub.add_parser("import-public-source-bundle")
    imp.add_argument("--archive", type=Path, required=True)
    imp.add_argument("--output", type=Path, required=True)
    imp.add_argument("--expected-source", required=True)
    imp.add_argument("--expected-tree", required=True)
    imp.add_argument("--expected-archive-sha256")
    imp.add_argument("--run-id", required=True)
    imp.add_argument("--run-attempt", required=True)
    imp.add_argument("--validator", type=Path, required=True)
    imp.add_argument("--supervisor", type=Path, required=True)
    imp.add_argument("--artifact-id")
    imp.add_argument("--container-digest")
    args = parser.parse_args()
    os.umask(0o077)
    if args.command == "export":
        export(args.runtime, args.output)
    elif args.command == "prepare-azure-runtime":
        prepare_azure_runtime(
            args.output, args.azure, args.az_python, args.stdlib,
            package_roots=args.package_root,
            data_roots=args.data_root,
            native_dependencies=args.native_dependency,
            validator=args.validator)
    elif args.command == "candidate":
        candidate_plan(args.bundle, args.output)
    elif args.command == "plan":
        plan(
            args.bundle, args.output, args.approval_template,
            args.candidate_output, campaign_id=args.campaign_id,
            ledger=args.ledger, subscription=args.subscription,
            prefix=args.prefix,
            maximum_authorized_cost_microusd=
                args.maximum_authorized_cost_microusd,
            azure=args.azure, uploader=args.uploader,
            validator=args.validator, supervisor=args.supervisor,
            az_python=args.az_python, azure_runtime=args.azure_runtime,
            attempt_id=args.attempt_id,
            ledger_id=args.ledger_id,
            created_unix=args.created_unix)
    elif args.command == "record-authorization":
        record_authorization(
            args.plan, args.template, args.output,
            decision=args.decision, approver=args.approver,
            reference=args.reference, recorded_unix=args.recorded_unix,
            expires_unix=args.expires_unix, azure=args.azure,
            uploader=args.uploader, validator=args.validator,
            supervisor=args.supervisor, az_python=args.az_python,
            azure_runtime=args.azure_runtime)
    elif args.command == "admit":
        admission(
            args.plan, args.authorization, args.output,
            azure=args.azure, uploader=args.uploader,
            validator=args.validator, supervisor=args.supervisor,
            az_python=args.az_python,
            azure_runtime=args.azure_runtime)
    else:
        import public_bundle

        if args.command == "public-source-bundle":
            FAILURE_STAGE = "public-entry"
            unused_archive, archive_sha256, source_tree = (
                public_bundle.publish_ci(sys.modules[__name__]))
            del unused_archive
            print("Public source archive SHA-256: " + archive_sha256)
            print("Public source tree: " + source_tree)
        else:
            FAILURE_STAGE = (
                "public-verify"
                if args.command == "verify-public-source-bundle"
                else "public-import")
            expected = dict(repository="cataggar/unikraft", run_id=args.run_id,
                            run_attempt=args.run_attempt, source_revision=args.expected_source,
                            source_tree=args.expected_tree, wamr_revision=ci.REVISION)
            if args.command == "verify-public-source-bundle":
                unused_bundle, archive_sha256 = (
                    public_bundle.verify_archive_with_digest(
                        sys.modules[__name__], args.archive, expected,
                        args.expected_archive_sha256))
                del unused_bundle
                print("Public source archive SHA-256: " + archive_sha256)
            else:
                public_bundle.import_bundle(
                    sys.modules[__name__], args.archive, args.output, expected,
                    args.expected_archive_sha256, args.validator,
                    args.supervisor, args.artifact_id,
                    args.container_digest)
    print("Compute private contract prepared; no Azure operations.")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError, zipfile.BadZipFile):
        print("Compute handoff refused at " + FAILURE_STAGE
              + "; original local records are unchanged.", file=sys.stderr)
        sys.exit(1)
