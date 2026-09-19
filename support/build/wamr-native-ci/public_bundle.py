#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""Explicit public-source tiny CI bundle; no arbitrary private export or authority."""
import copy
import contextlib
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import zipfile

MAX_TOTAL = 512 * 1024 * 1024
MAX_MEMBERS = 96
MAX_JSON = 65536
V1_ZIP_MEMBERS = 55
V2_ZIP_MEMBERS = 85
LEGACY_V1_SOURCES = frozenset({
    ("993e4d0d394c08202c0d0c57ea97450a19a4f394",
     "54f8e118146c78c24e7c802657c6ec62b268a5de"),
    ("34e5c88a165c4da878b3122b8b91716116d65d4b",
     "54f8e118146c78c24e7c802657c6ec62b268a5de"),
    # Retained run 35277215611 archive source, independently inspected.
    ("b5a8fdbee033349f7145fbc76aebfee29b2fa04f",
     "54f8e118146c78c24e7c802657c6ec62b268a5de"),
})
PRE_SUPERVISOR_SOURCES = frozenset({
    ("0711a0b6bf2285a4ba6ab6dd3bd4088478d665e1",
     "3d9def2872f41248b518a850a48a5c462e158890"),
    ("c9c00535399354063486957611bf6e09c8ae4592",
     "02827e49c25d06eba21bb2157833fc135811eedb"),
    ("3c6d5d98dc5736d86e97884184b26be39c3f11d5",
     "feb57a66615a6083378c7261e1e53c37730e0650"),
})
BOOT_KEYS = ("serial", "request", "report", "compute")
STAGES = ("adapter", "local-boot-tool", "fixtures", "prepare", "config",
          "native-image", "package", "raw-x2apic", "raw-legacy-apic",
          "vpc-x2apic", "vpc-legacy-apic", "inspect")
EVIDENCE = frozenset(
    ["build-start.json", "build.json", "boot-inputs.json", "package.json"]
    + [f"command-{stage}.json" for stage in STAGES]
    + [f"{mode}-compute.json" for mode in STAGES[7:11]])
V2_STAGES = (
    "adapter", "local-boot-tool", "fixtures", "prepare", "config",
    "native-image", "package",
    "raw-x2apic", "raw-legacy-apic", "finalize-qcow2",
    "qcow2-x2apic", "qcow2-legacy-apic", "derive-fixed-vhd",
    "vpc-x2apic", "vpc-legacy-apic", "inspect",
)
V2_CHAIN_RECORDS = frozenset({
    "qcow2-finalization-intent.json", "qcow2-finalization.json",
    "qcow2-acceptance.json", "fixed-vhd-derivation-intent.json",
    "fixed-vhd-derivation-gate.json", "fixed-vhd-derivation.json",
    "final-inspection.json",
})
V2_EVIDENCE = frozenset(
    ["build-start.json", "build.json", "boot-inputs.json", "package.json"]
    + [f"command-{stage}.json" for stage in V2_STAGES]
    + [f"{mode}-compute.json" for mode in (
        "raw-x2apic", "raw-legacy-apic",
        "qcow2-x2apic", "qcow2-legacy-apic",
        "vpc-x2apic", "vpc-legacy-apic")]
) | V2_CHAIN_RECORDS
SENSITIVE = (
    b"-----BEGIN PRIVATE KEY", b"-----BEGIN RSA PRIVATE KEY",
    b"Authorization: Bearer ", b"AccountKey=", b"SharedAccessSignature=",
    b"accessSAS", b"accessSas", b"AZURE_CLIENT_SECRET",
    b"PRIVATE_FIXTURE_SAS", b'"subscription"', b'"vm_uuid"', b'"os_uuid"',
    b'"fresh_final_approval"', b'"client_secret"', b'"access_token"',
    b"?sv=", b"&sig=",
)


def require(ok):
    if not ok:
        raise ValueError("public-source bundle refused")


def pre_supervisor_source(source):
    identity = (source["source_revision"], source["source_tree"])
    return identity in LEGACY_V1_SOURCES or identity in PRE_SUPERVISOR_SOURCES


def bind(hasher, value):
    raw = encoded(value, newline=False)
    hasher.update(len(raw).to_bytes(8, "big"))
    hasher.update(raw)


def bounded_integer(value, lower, upper):
    require(type(value) is int and lower <= value <= upper)
    return value


def digest_string(value, lengths=(64,)):
    require(type(value) is str and len(value) in lengths
            and re.fullmatch(r"[0-9a-f]+", value))
    return value


def physical_metadata(value, kind, permissions, size=None):
    require(type(value) is list and len(value) == 9)
    for item in value:
        bounded_integer(item, 0, (1 << 64) - 1)
    require(value[0] > 0 and value[1] > 0 and value[5] > 0
            and stat.S_IMODE(value[2]) == permissions)
    require(stat.S_ISREG(value[2]) if kind == "file" else stat.S_ISDIR(value[2]))
    if size is not None:
        require(value[6] == size)
    return value


def metadata_sha256(value):
    return hashlib.sha256(encoded(value, newline=False)).hexdigest()


def git_output(ci, limit, *args):
    try:
        return ci.bounded_subprocess_output(
            ci.git_command(*args), ci.REPO, limit, 60,
            "public-source bundle refused",
            "public-source bundle refused",
            "public-source bundle refused",
            env=ci.git_environment(),
        )
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        raise ValueError("public-source bundle refused") from error


def trusted_source_manifests(ci, expected):
    revision = expected["source_revision"]
    tree = expected["source_tree"]
    commit = git_output(
        ci, 65, "rev-parse", "--verify", revision + "^{commit}").decode().strip()
    actual_tree = git_output(
        ci, 65, "rev-parse", revision + "^{tree}").decode().strip()
    object_format = git_output(
        ci, 16, "rev-parse", "--show-object-format").decode().strip()
    require(commit == revision and actual_tree == tree and object_format == "sha1")
    result = {}
    for name in ("build.zig", "build.zig.zon"):
        relative = "support/tools/hyperv/local_boot/" + name
        raw = git_output(ci, 2048, "ls-tree", "-z", tree, "--", relative)
        require(raw.endswith(b"\0") and raw.count(b"\0") == 1)
        try:
            header, found = raw[:-1].split(b"\t", 1)
            mode, kind, oid = header.decode("ascii").split(" ")
        except (UnicodeDecodeError, ValueError) as error:
            raise ValueError("public-source bundle refused") from error
        require(found == relative.encode("ascii") and mode == "100644"
                and kind == "blob" and re.fullmatch(r"[0-9a-f]{40}", oid))
        size_raw = git_output(ci, 32, "cat-file", "-s", oid)
        require(re.fullmatch(rb"[1-9][0-9]{0,6}\n", size_raw) is not None)
        size = int(size_raw)
        require(size <= 1024 * 1024)
        data = git_output(ci, size, "cat-file", "blob", oid)
        require(len(data) == size)
        result[name] = {
            "path": relative,
            "mode": mode,
            "bytes": size,
            "sha256": hashlib.sha256(data).hexdigest(),
            "git_oid": oid,
        }
    return result


def trusted_supervisor_source_map(ci, expected, value):
    revision = expected["source_revision"]
    tree = expected["source_tree"]
    commit = git_output(
        ci, 65, "rev-parse", "--verify", revision + "^{commit}").decode().strip()
    actual_tree = git_output(
        ci, 65, "rev-parse", revision + "^{tree}").decode().strip()
    require(commit == revision and actual_tree == tree)
    records = value["records"]
    require(set(records) == set(ci.SUPERVISOR_SOURCE_FILES))
    for relative in ci.SUPERVISOR_SOURCE_FILES:
        raw = git_output(ci, 2048, "ls-tree", "-z", tree, "--", relative)
        require(raw.endswith(b"\0") and raw.count(b"\0") == 1)
        try:
            header, found = raw[:-1].split(b"\t", 1)
            mode, kind, oid = header.decode("ascii").split(" ")
        except (UnicodeDecodeError, ValueError) as error:
            raise ValueError("public-source bundle refused") from error
        require(found == relative.encode("ascii")
                and mode == "100644"
                and kind == "blob"
                and re.fullmatch(r"[0-9a-f]{40}", oid))
        size_raw = git_output(ci, 32, "cat-file", "-s", oid)
        require(re.fullmatch(rb"[1-9][0-9]{0,7}\n", size_raw) is not None)
        size = int(size_raw)
        require(size <= 16 * 1024 * 1024)
        data = git_output(ci, size, "cat-file", "blob", oid)
        require(len(data) == size
                and records[relative]["bytes"] == size
                and records[relative]["sha256"]
                == hashlib.sha256(data).hexdigest())
    return value["content_closure_sha256"]


def command_record(value, stage, limit):
    require(set(value) == {"scope", "stage", "exit_code", "bytes", "sha256",
                           "over_limit", "known_error_markers"}
            and value["scope"] == "command_diagnostic_not_acceptance"
            and value["stage"] == stage
            and type(value["exit_code"]) is int and value["exit_code"] == 0
            and value["over_limit"] is False
            and value["known_error_markers"] == [])
    bounded_integer(value["bytes"], 0, limit)
    digest_string(value["sha256"])
    return value


def executable_identity(value):
    require(isinstance(value, dict) and set(value) == {
        "content_sha256", "ctime_nanoseconds", "ctime_seconds",
        "device_major", "device_minor", "inode", "mode",
        "mtime_nanoseconds", "mtime_seconds", "size", "uid",
    })
    digest_string(value["content_sha256"])
    for key in ("ctime_nanoseconds", "device_major", "device_minor",
                "mtime_nanoseconds", "uid"):
        bounded_integer(value[key], 0, (1 << 32) - 1)
    bounded_integer(value["mode"], 0, (1 << 16) - 1)
    for key in ("inode", "size"):
        bounded_integer(value[key], 0, (1 << 64) - 1)
    for key in ("ctime_seconds", "mtime_seconds"):
        bounded_integer(value[key], -(1 << 63), (1 << 63) - 1)
    require(value["inode"] > 0 and value["size"] > 0
            and value["ctime_nanoseconds"] < 1_000_000_000
            and value["mtime_nanoseconds"] < 1_000_000_000)
    return value


def supervised_command_record(
        ci, value, stage, role_identities, transport_context,
        profile="qcow2-derived-vhd"):
    ci.validate_supervised_command_binding(
        value, stage, role_identities, transport_context, profile)
    request = value["supervisor"]["request"]
    bindings = [
        request["supervisor"],
        request["native_executable"],
        request["command_executable"],
        *request["retained_executables"],
    ]
    if request["interpreter"] is not None:
        bindings.append(request["interpreter"])
    for binding in bindings:
        executable_identity(binding["identity"])
    return value


def source_custody_record(ci, value):
    require(set(value) == {
        "schema", "version", "object_format", "files", "directories", "bytes",
        "content_sha256", "physical_sha256", "role_excluded_outputs",
    } and value["schema"] == "uk.wamr.git-physical-source"
      and type(value["version"]) is int and value["version"] == 1
      and value["object_format"] == "sha1"
      and value["role_excluded_outputs"] == list(ci.SOURCE_OUTPUT_ROLES))
    bounded_integer(value["files"], 1, ci.SOURCE_MAX_ENTRIES)
    bounded_integer(value["directories"], 1, ci.SOURCE_MAX_ENTRIES)
    bounded_integer(value["bytes"], 1, ci.SOURCE_MAX_BYTES)
    digest_string(value["content_sha256"])
    digest_string(value["physical_sha256"])
    return value


def consumer_input_record(ci, value):
    require(set(value) == {
        "schema", "version", "files", "trees", "directories",
        "aggregate_sha256",
    } and value["schema"] == "uk.wamr.consumer-input-custody"
      and type(value["version"]) is int and value["version"] == 2)
    files = value["files"]
    require(type(files) is dict and 1 <= len(files) <= 256)
    for name, record in files.items():
        require(type(name) is str and 0 < len(name.encode("utf-8")) <= 4096
                and set(record) == {"path", "metadata", "sha256"}
                and type(record["path"]) is str
                and record["path"].startswith("/")
                and len(record["path"].encode("utf-8")) <= 4096)
        metadata = physical_metadata(
            record["metadata"], "file",
            stat.S_IMODE(record["metadata"][2]))
        require(metadata[5] > 0 and metadata[6] > 0
                and not metadata[2] & 0o022)
        digest_string(record["sha256"])
    trees = value["trees"]
    require(type(trees) is dict and 1 <= len(trees) <= 16)
    for name, record in trees.items():
        require(type(name) is str and re.fullmatch(r"[a-z0-9-]{1,64}", name)
                and set(record) == {
                    "path", "files", "directories", "symlinks", "bytes",
                    "content_sha256", "physical_sha256",
                }
                and type(record["path"]) is str
                and record["path"].startswith("/")
                and len(record["path"].encode("utf-8")) <= 4096)
        file_count = bounded_integer(
            record["files"], 0, ci.INPUT_TREE_MAX_ENTRIES)
        directory_count = bounded_integer(
            record["directories"], 1, ci.INPUT_TREE_MAX_ENTRIES)
        symlink_count = bounded_integer(
            record["symlinks"], 0, ci.INPUT_TREE_MAX_ENTRIES)
        require(file_count + directory_count + symlink_count
                <= ci.INPUT_TREE_MAX_ENTRIES)
        bounded_integer(record["bytes"], 0, ci.INPUT_TREE_MAX_BYTES)
        digest_string(record["content_sha256"])
        digest_string(record["physical_sha256"])
    directories = value["directories"]
    require(type(directories) is dict and 1 <= len(directories) <= 512)
    for path, metadata in directories.items():
        require(type(path) is str and path.startswith("/")
                and len(path.encode("utf-8")) <= 4096)
        physical_metadata(
            metadata, "directory", stat.S_IMODE(metadata[2]))
        require(not metadata[2] & 0o022)
    digest_string(value["aggregate_sha256"])
    unsigned = dict(value)
    del unsigned["aggregate_sha256"]
    require(value["aggregate_sha256"]
            == hashlib.sha256(encoded(unsigned, newline=False)).hexdigest())
    return value


def guarded_map_record(value, domain):
    require(set(value) == {
        "count", "bytes", "content_closure_sha256",
        "physical_closure_sha256", "records",
    } and type(value["records"]) is dict
      and value["count"] == len(value["records"]))
    bounded_integer(value["count"], 1, 256)
    bounded_integer(value["bytes"], 1, 512 * 1024 * 1024)
    digest_string(value["content_closure_sha256"])
    digest_string(value["physical_closure_sha256"])
    content = hashlib.sha256((domain + "-content\0").encode("ascii"))
    physical = hashlib.sha256((domain + "-physical\0").encode("ascii"))
    total = 0
    for name in sorted(value["records"]):
        record = value["records"][name]
        require(type(name) is str and name
                and set(record) == {"bytes", "sha256", "metadata"})
        size = bounded_integer(record["bytes"], 1, 256 * 1024 * 1024)
        physical_metadata(
            record["metadata"], "file",
            stat.S_IMODE(record["metadata"][2]), size)
        digest_string(record["sha256"])
        total += size
        bind(content, [name, size, record["sha256"]])
        bind(physical, [name, record["metadata"]])
    require(total == value["bytes"]
            and content.hexdigest() == value["content_closure_sha256"]
            and physical.hexdigest() == value["physical_closure_sha256"])
    return value


def command_supervisor_record(value):
    require(set(value) == {
        "schema", "version", "protocol", "source_map", "runtime_map",
    } and value["schema"] == "uk.wamr.command-supervisor"
      and type(value["version"]) is int and value["version"] == 1
      and value["protocol"]
      == "uk.wamr.command-supervisor/1 process-command/1")
    guarded_map_record(
        value["source_map"], "uk.wamr.command-supervisor-source-v1")
    guarded_map_record(
        value["runtime_map"], "uk.wamr.command-supervisor-runtime-v1")
    require("executable" in value["runtime_map"]["records"])
    return value


def dependency_record(ci, value, expected):
    require(set(value) == {
        "schema", "version", "request", "source_manifests",
        "restore_directory", "restore", "packages",
    } and value["schema"] == "uk.wamr.zig-dependency-custody"
      and type(value["version"]) is int and value["version"] == 1
      and value["request"] == {
          "url": ci.MIZ_URL,
          "revision": ci.MIZ_REVISION,
          "package_hash": ci.MIZ_PACKAGE_HASH,
      })
    expected_paths = {
        "build.zig": "support/tools/hyperv/local_boot/build.zig",
        "build.zig.zon": "support/tools/hyperv/local_boot/build.zig.zon",
    }
    trusted = trusted_source_manifests(ci, expected)
    manifests = value["source_manifests"]
    require(set(manifests) == set(expected_paths))
    for name, expected_path in expected_paths.items():
        item = manifests[name]
        require(set(item) == {"source", "copy"})
        source = item["source"]
        require(set(source) == {
            "path", "mode", "bytes", "sha256", "git_oid", "metadata",
            "metadata_sha256"}
                and source["path"] == expected_path
                and {key: source[key] for key in trusted[name]} == trusted[name])
        physical_metadata(
            source["metadata"], "file", 0o644, source["bytes"])
        require(source["metadata_sha256"] == metadata_sha256(source["metadata"]))
        copied = item["copy"]
        require(set(copied) == {"bytes", "sha256", "metadata"})
        bounded_integer(copied["bytes"], 1, 1024 * 1024)
        require(copied["bytes"] == source["bytes"]
                and copied["sha256"] == source["sha256"])
        physical_metadata(copied["metadata"], "file", 0o600, copied["bytes"])
        require(copied["metadata"][5] == 1)
    restore_directory = value["restore_directory"]
    require(set(restore_directory) == {"metadata"})
    physical_metadata(restore_directory["metadata"], "directory", 0o700)
    command_record(value["restore"], "dependency-restore", 8 * 1024 * 1024)

    packages = value["packages"]
    require(set(packages) == {
        "roots", "files", "directories", "bytes", "closure_sha256",
        "physical_sha256", "root_metadata", "root_metadata_sha256", "manifests",
        "hash_verification", "records",
    })
    roots = bounded_integer(packages["roots"], 1, ci.PACKAGE_MAX_ROOTS)
    files = bounded_integer(packages["files"], 1, ci.PACKAGE_MAX_ENTRIES)
    directories = bounded_integer(
        packages["directories"], roots, ci.PACKAGE_MAX_ENTRIES)
    package_bytes = bounded_integer(packages["bytes"], 1, ci.PACKAGE_MAX_BYTES)
    require(files + directories <= ci.PACKAGE_MAX_ENTRIES)
    for key in ("closure_sha256", "physical_sha256", "root_metadata_sha256"):
        digest_string(packages[key])
    root_metadata = physical_metadata(
        packages["root_metadata"], "directory", 0o700)
    require(packages["root_metadata_sha256"] == metadata_sha256(root_metadata))
    records = packages["records"]
    require(type(records) is list and len(records) == roots)
    names = []
    manifest_count = 0
    manifest_bytes = 0
    dependency_graph = {}
    total_files = 0
    total_directories = 0
    total_bytes = 0
    manifest_digest = hashlib.sha256(b"uk.wamr.package-manifests-v1\0")
    for record in records:
        require(set(record) == {"package_hash", "content", "manifest"})
        name = record["package_hash"]
        require(type(name) is str
                and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,159}", name)
                and name not in (".", ".."))
        names.append(name)
        content = record["content"]
        require(set(content) == {
            "files", "directories", "bytes", "tree_sha256", "physical_sha256"})
        count_files = bounded_integer(
            content["files"], 1, ci.PACKAGE_MAX_ENTRIES)
        count_directories = bounded_integer(
            content["directories"], 1, ci.PACKAGE_MAX_ENTRIES)
        count_bytes = bounded_integer(content["bytes"], 1, ci.PACKAGE_MAX_BYTES)
        require(count_files + count_directories <= ci.PACKAGE_MAX_ENTRIES)
        digest_string(content["tree_sha256"])
        digest_string(content["physical_sha256"])
        total_files += count_files
        total_directories += count_directories
        total_bytes += count_bytes
        manifest = record["manifest"]
        if manifest is None:
            dependencies = []
        else:
            require(set(manifest) == {"bytes", "sha256", "dependencies"})
            size = bounded_integer(manifest["bytes"], 1, 4 * 1024 * 1024)
            digest_string(manifest["sha256"])
            dependencies = manifest["dependencies"]
            require(type(dependencies) is list
                    and len(dependencies) <= ci.PACKAGE_MAX_ROOTS)
            for dependency in dependencies:
                require(type(dependency) is str
                        and re.fullmatch(
                            r"[A-Za-z0-9][A-Za-z0-9._+-]{0,159}", dependency)
                        and dependency not in (".", ".."))
            require(dependencies == sorted(set(dependencies)))
            manifest_count += 1
            manifest_bytes += size
            bind(manifest_digest, [name, manifest])
        dependency_graph[name] = dependencies
    require(names == sorted(set(names))
            and total_files == files
            and total_directories == directories
            and total_bytes == package_bytes
            and ci.MIZ_PACKAGE_HASH in dependency_graph)
    reachable = set()
    pending = [ci.MIZ_PACKAGE_HASH]
    while pending:
        name = pending.pop()
        require(name in dependency_graph)
        if name in reachable:
            continue
        reachable.add(name)
        pending.extend(dependency_graph[name])
        require(len(reachable) + len(pending) <= ci.PACKAGE_MAX_ROOTS * 2)
    require(reachable == set(names))

    manifest_summary = packages["manifests"]
    require(set(manifest_summary) == {"count", "bytes", "sha256"})
    bounded_integer(manifest_summary["count"], 0, roots)
    bounded_integer(manifest_summary["bytes"], 0, package_bytes)
    require(manifest_summary["count"] == manifest_count
            and manifest_summary["bytes"] == manifest_bytes
            and manifest_summary["sha256"] == manifest_digest.hexdigest())
    hash_verification = packages["hash_verification"]
    require(set(hash_verification) == {"algorithm", "count", "sha256"}
            and hash_verification["algorithm"] == "zig-0.16.0-fetch-path")
    bounded_integer(hash_verification["count"], 1, ci.PACKAGE_MAX_ROOTS)
    require(hash_verification["count"] == roots)
    hash_records = [{
        "package_hash": name,
        "sha256": hashlib.sha256((name + "\n").encode("ascii")).hexdigest(),
    } for name in names]
    require(hash_verification["sha256"]
            == hashlib.sha256(
                encoded(hash_records, newline=False)).hexdigest())
    closure = hashlib.sha256(b"uk.wamr.package-closure-v1\0")
    physical = hashlib.sha256(b"uk.wamr.package-physical-closure-v1\0")
    for record in records:
        bind(closure, record)
        bind(physical, [
            record["package_hash"], record["content"]["physical_sha256"]])
    require(packages["closure_sha256"] == closure.hexdigest()
            and packages["physical_sha256"] == physical.hexdigest())
    return value


def json_domain(value):
    if value is None or type(value) is bool:
        return
    if type(value) is int:
        require(-(1 << 63) <= value <= (1 << 64) - 1)
        return
    if isinstance(value, str):
        try:
            value.encode("utf-8")
        except UnicodeEncodeError as error:
            raise ValueError("public-source bundle refused") from error
        return
    if isinstance(value, (list, tuple)):
        for item in value:
            json_domain(item)
        return
    require(isinstance(value, dict))
    for key, item in value.items():
        require(isinstance(key, str))
        json_domain(key)
        json_domain(item)


def encoded(value, newline=True):
    json_domain(value)
    try:
        text = json.dumps(
            value, ensure_ascii=False, allow_nan=False,
            sort_keys=True, separators=(",", ":"))
        return (text + ("\n" if newline else "")).encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError) as error:
        raise ValueError("public-source bundle refused") from error


def decode(raw):
    require(len(raw) <= MAX_JSON)
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result)
            result[key] = value
        return result
    try:
        value = json.loads(raw, object_pairs_hook=unique)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("public-source bundle refused") from error
    require(raw == encoded(value))
    return value


def context(value):
    require(set(value) == {"repository", "run_id", "run_attempt", "source_revision",
                           "source_tree", "wamr_revision"})
    require(value["repository"] == "cataggar/unikraft"
            and value["wamr_revision"] == "a53205d77be3b880eb8f8b96679512ba58e2331a")
    for key in ("run_id", "run_attempt"):
        require(type(value[key]) is str and re.fullmatch(r"[1-9][0-9]{0,19}", value[key]))
    for key in ("source_revision", "source_tree"):
        require(type(value[key]) is str and re.fullmatch(r"[0-9a-f]{40}", value[key]))
    return value


def ci_runtime(ci):
    default = ci.REPO / ".d/wamr-native-runtime"
    selected = Path(os.environ.get("WAMR_CI_RUNTIME", str(default)))
    require(selected in (default, Path("/d/wamr-ci/wamr-native-runtime")))
    return selected


def ci_context(handoff, start):
    ci = handoff.ci
    require(os.environ.get("GITHUB_ACTIONS") == "true"
            and os.environ.get("GITHUB_REPOSITORY") == "cataggar/unikraft"
            and os.environ.get("GITHUB_JOB") == "wamr-native-compute"
            and os.environ.get("GITHUB_EVENT_NAME") == "pull_request"
            and os.environ.get("GITHUB_REPOSITORY_VISIBILITY") == "public"
            and os.environ.get("GITHUB_WORKSPACE") == str(ci.REPO)
            and os.environ.get("GITHUB_WORKFLOW_REF", "").startswith(
                "cataggar/unikraft/.github/workflows/wamr-native-compute.yaml@"))
    source = ci.source()
    require(ci.source_identity(source) == start["source"]
            and os.environ.get("GITHUB_SHA") == source["revision"])
    return context(dict(repository="cataggar/unikraft", run_id=os.environ["GITHUB_RUN_ID"],
                        run_attempt=os.environ["GITHUB_RUN_ATTEMPT"],
                        source_revision=source["revision"], source_tree=source["tree"],
                        wamr_revision=ci.REVISION))


def require_public_consumer_paths(ci, runtime, consumer_inputs):
    files = consumer_inputs["files"]
    required_files = (
        {f"tool:{name}" for name in ci.HOST_TOOLS}
        | {"wamr-source-archive", "command-supervisor"})
    require(required_files <= set(files))
    supervisor = (
        runtime / "compute/supervisor/bin/wamr-ci-supervisor").resolve(
            strict=True)
    require(files["command-supervisor"]["path"] == str(supervisor)
            and files["wamr-source-archive"]["path"]
            == str((runtime / "custody/wamr-source.tar").resolve(
                strict=True)))
    runtime_paths = set()
    for name in ci.HOST_TOOLS:
        runtime_paths.update(ci.executable_runtime_paths(
            Path(files["tool:" + name]["path"])))
    runtime_paths.update(ci.executable_runtime_paths(supervisor))
    expected_files = required_files | {
        "runtime:" + str(path) for path in runtime_paths
    }
    require(set(files) == expected_files)
    trees = consumer_inputs["trees"]
    require(set(trees) == {"bison", "python-stdlib", "zig", "llvm"}
            and trees["bison"]["path"]
            == str((runtime / "bison").resolve(strict=True))
            and trees["zig"]["path"]
            == str(Path(files["tool:zig"]["path"]).parent)
            and trees["llvm"]["path"]
            == str((runtime / "llvm").resolve(strict=True))
            and trees["python-stdlib"]["path"]
            == str(Path(ci.sysconfig.get_paths()["stdlib"]).resolve(
                strict=True)))
    return consumer_inputs


def accepted_public_build_start(handoff, runtime):
    ci = handoff.ci
    start = ci.document(runtime / "compute/evidence/build-start.json")
    require(set(start) == {
        "source", "source_custody", "tools", "bison_data",
        "dependencies", "consumer_inputs", "command_supervisor",
    } and set(start["source"]) == {"revision", "tree"})
    digest_string(start["source"]["revision"], (40,))
    digest_string(start["source"]["tree"], (40,))
    source = {
        "source_revision": start["source"]["revision"],
        "source_tree": start["source"]["tree"],
    }
    source_custody_record(ci, start["source_custody"])
    consumer_input_record(ci, start["consumer_inputs"])
    command_supervisor_record(start["command_supervisor"])
    files = start["consumer_inputs"]["files"]
    required_files = (
        {f"tool:{name}" for name in ci.HOST_TOOLS}
        | {"wamr-source-archive", "command-supervisor"})
    require(required_files <= set(files))
    require_consumer_tree_roles(start["consumer_inputs"], False)
    ci.require_recorded_consumer_inputs(
        start["consumer_inputs"], content=True)
    require_public_consumer_paths(ci, runtime, start["consumer_inputs"])

    original_tools = dict(ci.COMMAND_TOOL_PATHS)
    ci.COMMAND_TOOL_PATHS.clear()
    ci.COMMAND_TOOL_PATHS["git"] = files["tool:git"]["path"]
    try:
        dependency_record(ci, start["dependencies"], source)
        ci.require_recorded_build_custody(runtime, start)
    finally:
        ci.COMMAND_TOOL_PATHS.clear()
        ci.COMMAND_TOOL_PATHS.update(original_tools)

    ci.COMMAND_ENVIRONMENT.clear()
    ci.COMMAND_TOOL_PATHS.clear()
    ci.COMMAND_SUPERVISOR_PATH = None
    ci.COMMAND_ENVIRONMENT.update(
        ci.bind_command_tools(start["consumer_inputs"]))
    ci.require_recorded_build_custody(runtime, start)
    return start


def members(handoff, bundle, root=None):
    """Closed positional schema; paths never select additional publication members."""
    if bundle.get("version") == 2:
        return members_v2(handoff, bundle, root)
    require(set(bundle) == {"schema", "version", "authority", "source_revision",
                           "source_tree", "identity", "artifacts", "boots", "evidence"})
    require(bundle["schema"] == "uk.wamr.local-image-handoff"
            and type(bundle["version"]) is int and bundle["version"] == 1
            and bundle["authority"] == "not_admitted")
    require(set(bundle["identity"]) == {
        "wamr_revision", "wasm_sha256", "cwasm_sha256",
        "runtime_sha256", "compiler_sha256", "config_sha256"})
    for name, value in bundle["identity"].items():
        require(type(value) is str and re.fullmatch(
            r"[0-9a-f]{40}" if name == "wamr_revision" else r"[0-9a-f]{64}", value))
    require(len(bundle["artifacts"]) == len(handoff.NAMES)
            and len(bundle["boots"]) == 4 and len(bundle["evidence"]) == len(EVIDENCE))
    result = {}
    def add(name, item, maximum):
        require(set(item) == {"path", "sha256", "size"}
                and item["path"] == (str(root / name) if root else name)
                and type(item["size"]) is int and 0 < item["size"] <= maximum
                and type(item["sha256"]) is str and re.fullmatch(r"[0-9a-f]{64}", item["sha256"]))
        require(name not in result)
        result[name] = item
    for name, item in zip(handoff.NAMES, bundle["artifacts"]):
        maximum = 256 * 1024 * 1024 + 512 if name in (
            "efi", "debug_elf", "bootinfo", "raw", "vhd", "runtime", "compiler", "wasm", "cwasm") else (
                1024 * 1024 if name == "config" else MAX_JSON)
        add("artifacts/" + name, item, maximum)
    for mode, boot in zip(handoff.ci.MODES, bundle["boots"]):
        require(set(boot) == {"mode", *BOOT_KEYS} and boot["mode"] == mode)
        for key in BOOT_KEYS:
            add(f"boots/{mode}/{key}", boot[key], 4 * 1024 * 1024 if key == "serial" else MAX_JSON)
    for name, item in zip(sorted(EVIDENCE), bundle["evidence"]):
        add("evidence/" + name, item, MAX_JSON)
    require(len(result) + 2 == V1_ZIP_MEMBERS
            and len(result) + 2 <= MAX_MEMBERS
            and sum(item["size"] for item in result.values()) <= MAX_TOTAL - 2 * MAX_JSON)
    return result


def members_v2(handoff, bundle, root=None):
    require(set(bundle) == {
        "schema", "version", "profile", "authority", "source_revision",
        "source_tree", "run", "identity", "lineage", "artifacts", "boots",
        "evidence",
    })
    require(bundle["schema"] == "uk.wamr.local-image-handoff"
            and type(bundle["version"]) is int and bundle["version"] == 2
            and bundle["profile"] == handoff.ci.CURRENT_PROFILE
            and bundle["authority"] == "not_admitted")
    require(set(bundle["run"]) == {
        "repository", "run_id", "run_attempt",
    } and bundle["run"]["repository"] == "cataggar/unikraft")
    for key in ("run_id", "run_attempt"):
        require(type(bundle["run"][key]) is str
                and re.fullmatch(r"[1-9][0-9]{0,19}", bundle["run"][key]))
    require(set(bundle["identity"]) == {
        "wamr_revision", "wasm_sha256", "cwasm_sha256",
        "runtime_sha256", "compiler_sha256", "config_sha256"})
    for name, value in bundle["identity"].items():
        require(type(value) is str and re.fullmatch(
            r"[0-9a-f]{40}" if name == "wamr_revision" else r"[0-9a-f]{64}",
            value))
    require(set(bundle["lineage"]) == {
        "raw_sha256", "accepted_qcow2_sha256", "derived_vhd_sha256",
        "qcow2_finalization_sha256", "qcow2_acceptance_sha256",
        "fixed_vhd_derivation_gate_sha256",
        "fixed_vhd_derivation_sha256", "final_inspection_sha256",
    })
    for value in bundle["lineage"].values():
        digest_string(value)
    require(len(bundle["artifacts"]) == len(handoff.V2_NAMES)
            and len(bundle["boots"]) == 6
            and len(bundle["evidence"]) == len(V2_EVIDENCE))
    result = {}

    def add(name, item, maximum):
        require(set(item) == {"path", "sha256", "size"}
                and item["path"] == (str(root / name) if root else name)
                and type(item["size"]) is int and 0 < item["size"] <= maximum
                and type(item["sha256"]) is str
                and re.fullmatch(r"[0-9a-f]{64}", item["sha256"]))
        require(name not in result)
        result[name] = item

    large = {
        "efi", "debug_elf", "bootinfo", "raw", "qcow2", "vhd",
        "runtime", "compiler", "wasm", "cwasm",
    }
    for name, item in zip(handoff.V2_NAMES, bundle["artifacts"]):
        maximum = (
            256 * 1024 * 1024 + 512 if name in large else
            1024 * 1024 if name == "config" else MAX_JSON
        )
        add("artifacts/" + name, item, maximum)
    for mode, boot in zip(handoff.ci.SIX_MODES, bundle["boots"]):
        require(set(boot) == {"mode", *BOOT_KEYS} and boot["mode"] == mode)
        for key in BOOT_KEYS:
            add(
                f"boots/{mode}/{key}", boot[key],
                4 * 1024 * 1024 if key == "serial" else MAX_JSON)
    for name, item in zip(sorted(V2_EVIDENCE), bundle["evidence"]):
        add("evidence/" + name, item, MAX_JSON)
    by_name = dict(zip(handoff.V2_NAMES, bundle["artifacts"]))
    require(bundle["lineage"] == {
        "raw_sha256": by_name["raw"]["sha256"],
        "accepted_qcow2_sha256": by_name["qcow2"]["sha256"],
        "derived_vhd_sha256": by_name["vhd"]["sha256"],
        "qcow2_finalization_sha256":
            by_name["qcow2_finalization"]["sha256"],
        "qcow2_acceptance_sha256": by_name["qcow2_acceptance"]["sha256"],
        "fixed_vhd_derivation_sha256":
            by_name["fixed_vhd_derivation"]["sha256"],
        "fixed_vhd_derivation_gate_sha256":
            by_name["fixed_vhd_derivation_gate"]["sha256"],
        "final_inspection_sha256": by_name["final_inspection"]["sha256"],
    })
    require(len(result) + 2 == V2_ZIP_MEMBERS
            and len(result) + 2 <= MAX_MEMBERS
            and sum(item["size"] for item in result.values())
            <= MAX_TOTAL - 2 * MAX_JSON)
    return result


def regular(path):
    require(path.resolve(strict=True) == path)
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
            and info.st_uid == os.getuid() and not info.st_mode & 0o022)
    return info


@contextlib.contextmanager
def retained_archive(handoff, archive, expected_archive_sha256):
    archive = Path(archive)
    require(archive.is_absolute() and handoff.ci.canonical(archive))
    with handoff.ci.retained_absolute(
            archive, reason="public-source bundle refused") as (
                handle, directories, parent):
        del directories, parent
        info = os.fstat(handle)
        require(
            stat.S_ISREG(info.st_mode) and info.st_nlink == 1
            and info.st_uid in (0, os.getuid()) and not info.st_mode & 0o022
            and 0 < info.st_size <= MAX_TOTAL
        )
        before = handoff.ci.snapshot(info)
        archive_sha256 = handoff.ci.digest_descriptor(
            handle, info, MAX_TOTAL, "public-source bundle refused")
        if expected_archive_sha256 is not None:
            require(archive_sha256 == expected_archive_sha256)
        try:
            yield handle, archive_sha256
        finally:
            require(handoff.ci.snapshot(os.fstat(handle)) == before)


@contextlib.contextmanager
def descriptor_zip(handle):
    duplicate = os.dup(handle)
    try:
        with os.fdopen(duplicate, "rb") as source:
            duplicate = -1
            with zipfile.ZipFile(source) as zipped:
                yield zipped
    finally:
        if duplicate >= 0:
            os.close(duplicate)


def inspect_tree(root, expected):
    found = set()
    directories = {str(Path(name).parent) for name in expected}
    directories |= {str(parent) for name in expected for parent in Path(name).parents}
    for path in root.rglob("*"):
        name = path.relative_to(root).as_posix()
        require(not path.is_symlink())
        if path.is_dir():
            require(name in directories)
        else:
            regular(path)
            found.add(name)
    require(found == set(expected))


def copy_checked(source, target, expected):
    """Full bytes/EOF and secret-pattern scan without unbounded captures."""
    sha = hashlib.sha256()
    total = 0
    tail = b""
    while True:
        chunk = source.read(65536)
        if not chunk:
            break
        total += len(chunk)
        require(total <= expected["size"])
        scan = tail + chunk
        require(not any(pattern in scan for pattern in SENSITIVE))
        tail = scan[-128:]
        sha.update(chunk)
        if target is not None:
            target.write(chunk)
    require(total == expected["size"] and sha.hexdigest() == expected["sha256"])


def validate_local_supervisor(handoff, supervisor, start, expected):
    ci = handoff.ci
    supervisor = Path(supervisor)
    require(supervisor.is_absolute()
            and supervisor.resolve(strict=True) == supervisor)
    current = start.get("command_supervisor")
    if current is None:
        require(pre_supervisor_source(expected))
        source_closure = ci.supervisor_source_map()[
            "content_closure_sha256"]
    else:
        command_supervisor_record(current)
        source_closure = trusted_supervisor_source_map(
            ci, expected, current["source_map"])
    runtime_paths = sorted(ci.executable_runtime_paths(supervisor))
    local_paths = {
        "command-supervisor": supervisor,
        **{"runtime:" + str(path): path for path in runtime_paths},
    }
    custody = ci.record_input_paths(local_paths, {}, content=True)
    record = custody["files"]["command-supervisor"]
    require(record["metadata"][2] & 0o111)
    if current is not None:
        expected_runtime = current["runtime_map"]["records"]
        expected_record = expected_runtime["executable"]
        accepted_record = start["consumer_inputs"]["files"][
            "command-supervisor"]
        require(expected_record == {
            "bytes": accepted_record["metadata"][6],
            "sha256": accepted_record["sha256"],
            "metadata": accepted_record["metadata"],
        })
        require(record["sha256"] == expected_record["sha256"]
                and record["metadata"][6] == expected_record["bytes"])
        require(sorted(
            (item["bytes"], item["sha256"])
            for name, item in expected_runtime.items()
            if name != "executable"
        ) == sorted(
            (item["metadata"][6], item["sha256"])
            for name, item in custody["files"].items()
            if name != "command-supervisor"
        ))
    data = ci.read(supervisor, 16 * 1024 * 1024)
    require(len(data) == record["metadata"][6]
            and data[:4] == b"\x7fELF"
            and data[4:6] == b"\x02\x01"
            and len(data) >= 20
            and int.from_bytes(data[16:18], "little") in (2, 3)
            and int.from_bytes(data[18:20], "little") in (62, 183))
    identity = {
        "protocol": ci.COMMAND_SUPERVISOR_VERSION,
        "schema": "uk.wamr.command-supervisor-identity",
        "source_content_closure_sha256": source_closure,
        "version": 1,
    }
    ci.record_input_paths(
        local_paths, {}, content=True, expected=custody)
    return custody, identity


def native(handoff, validator, supervisor, bundle, expected):
    validator = Path(validator)
    supervisor = Path(supervisor)
    require(validator.is_absolute() and supervisor.is_absolute()
            and validator.resolve(strict=True) == validator
            and supervisor.resolve(strict=True) == supervisor
            and bundle.is_absolute()
            and bundle.resolve(strict=True) == bundle)
    # Reuse the existing command deadline and bounded capture machinery. These
    # private captures and allowlisted failure flags are never archive members.
    for name in ("private", "evidence"):
        (bundle.parent / name).mkdir(mode=0o700, exist_ok=True)
    start = handoff.ci.document(bundle.parent / "evidence/build-start.json")
    supervisor_input, supervisor_identity_document = validate_local_supervisor(
        handoff, supervisor, start, expected)
    validator_input = handoff.ci.record_input_paths(
        {"validator": validator}, {}, content=True)
    input_records = handoff.ci.consumer_file_records(supervisor_input)
    input_records.update(handoff.ci.consumer_file_records(validator_input))
    original_supervisor = handoff.ci.COMMAND_SUPERVISOR_PATH
    original_tools = dict(handoff.ci.COMMAND_TOOL_PATHS)
    original_environment = dict(handoff.ci.COMMAND_ENVIRONMENT)
    try:
        handoff.ci.COMMAND_SUPERVISOR_PATH = None
        handoff.ci.COMMAND_TOOL_PATHS.clear()
        handoff.ci.COMMAND_ENVIRONMENT.clear()
        supervisor_path = handoff.ci.bind_command_supervisor(
            supervisor_input)
        handoff.ci.COMMAND_ENVIRONMENT[
            "WAMR_CI_SUPERVISOR"] = supervisor_path
        identity_output, identity_command = handoff.ci.execute(
            bundle.parent, "supervisor-import-identity",
            [supervisor, "--identity"], 30, 1024, evidence=False,
            input_records=input_records)
        supervisor_role_identity = handoff.ci.native_executable_identity(
            supervisor_input["files"]["command-supervisor"])
        supervised_command_record(
            handoff.ci, identity_command, "supervisor-import-identity",
            {"command-supervisor": supervisor_role_identity},
            "producer_direct")
        require(handoff.ci.read(identity_output, 1024)
                == handoff.ci.canonical_json(
                    supervisor_identity_document))
        output, command = handoff.ci.execute(
            bundle.parent, "native-revalidation",
            [validator, "handoff", bundle], 600, 4096,
            input_records=input_records,
            path_roles={
                "input:validator": validator,
                "input:bundle": bundle,
            })
        role_identities = {
            "command-supervisor": supervisor_role_identity,
            "input:validator": handoff.ci.native_executable_identity(
                validator_input["files"]["validator"]),
        }
        supervised_command_record(
            handoff.ci, command, "native-revalidation",
            role_identities, "producer_direct")
        require(handoff.ci.read(output, 4096)
                == b"Compute handoff revalidated; authority=not_admitted.\n")
        handoff.ci.record_input_paths(
            {"validator": validator}, {}, content=True,
            expected=validator_input)
        handoff.ci.record_input_paths(
            {
                name: Path(record["path"])
                for name, record in supervisor_input["files"].items()
            }, {}, content=True,
            expected=supervisor_input)
    finally:
        handoff.ci.COMMAND_SUPERVISOR_PATH = original_supervisor
        handoff.ci.COMMAND_TOOL_PATHS.clear()
        handoff.ci.COMMAND_TOOL_PATHS.update(original_tools)
        handoff.ci.COMMAND_ENVIRONMENT.clear()
        handoff.ci.COMMAND_ENVIRONMENT.update(original_environment)


def require_consumer_tree_roles(value, legacy):
    roles = set(value["trees"])
    require({"bison", "python-stdlib", "zig", "llvm"} <= roles)
    require("system-bin" not in roles or legacy)


def publication_lineage_v2(handoff, stage, bundle):
    ci = handoff.ci
    by_name = dict(zip(handoff.V2_NAMES, bundle["artifacts"]))
    package = ci.document(stage / "evidence/package.json")
    boot_inputs = ci.document(stage / "evidence/boot-inputs.json")
    package_tool = boot_inputs["files"]["package_tool"]
    finalization = ci.document(stage / "evidence/qcow2-finalization.json")
    ci.require_qcow2_finalization(
        finalization, package["image"]["raw"], package["image"]["efi"],
        package_tool)
    require(finalization == ci.document(
        stage / "artifacts/qcow2_finalization"))
    require(finalization["output"]["sha256"] == by_name["qcow2"]["sha256"]
            and finalization["output"]["file_bytes"]
            == by_name["qcow2"]["size"])
    finalize_intent = ci.document(
        stage / "evidence/qcow2-finalization-intent.json")
    require(finalize_intent == ci.document(
        stage / "artifacts/qcow2_finalization_intent")
            and finalize_intent["expected_source_sha256"]
            == by_name["raw"]["sha256"]
            and finalize_intent["expected_source_bytes"]
            == by_name["raw"]["size"])

    acceptance = ci.document(stage / "evidence/qcow2-acceptance.json")
    require(set(acceptance) == {
        "schema", "schema_version", "profile", "status", "source",
        "accepted_qcow2", "finalization_sha256", "modes", "boots",
        "build_sha256", "boot_inputs_sha256",
    } and acceptance["schema"] == "uk.wamr.compute-qcow2-acceptance"
      and acceptance["schema_version"] == 1
      and acceptance["profile"] == ci.CURRENT_PROFILE
      and acceptance["status"] == "accepted"
      and acceptance["source"] == {
          "revision": bundle["source_revision"],
          "tree": bundle["source_tree"],
      }
      and acceptance["modes"] == list(ci.SIX_MODES[:4])
      and set(acceptance["boots"]) == set(ci.SIX_MODES[:4])
      and acceptance["finalization_sha256"]
      == by_name["qcow2_finalization"]["sha256"]
      and acceptance["accepted_qcow2"]["sha256"]
      == by_name["qcow2"]["sha256"]
      and acceptance["accepted_qcow2"]["file_bytes"]
      == by_name["qcow2"]["size"]
      and acceptance["build_sha256"] == by_name["build"]["sha256"]
      and acceptance["boot_inputs_sha256"]
      == by_name["boot_inputs"]["sha256"])
    require(acceptance == ci.document(stage / "artifacts/qcow2_acceptance"))
    boots = {boot["mode"]: boot for boot in bundle["boots"]}
    for mode in ci.SIX_MODES[:4]:
        observed = acceptance["boots"][mode]
        require(set(observed) == {
            "request_sha256", "report_sha256", "serial_sha256",
            "compute_sha256",
        } and observed["request_sha256"] == boots[mode]["request"]["sha256"]
          and observed["report_sha256"] == boots[mode]["report"]["sha256"]
          and observed["serial_sha256"] == boots[mode]["serial"]["sha256"]
          and observed["compute_sha256"] == boots[mode]["compute"]["sha256"])

    derive_intent = ci.document(
        stage / "evidence/fixed-vhd-derivation-intent.json")
    require(derive_intent == ci.document(
        stage / "artifacts/fixed_vhd_derivation_intent")
            and derive_intent["accepted_qcow2_sha256"]
            == by_name["qcow2"]["sha256"]
            and derive_intent["expected_source_bytes"]
            == by_name["qcow2"]["size"])
    gate = ci.document(
        stage / "evidence/fixed-vhd-derivation-gate.json")
    require(set(gate) == {
        "schema", "schema_version", "profile", "status",
        "accepted_qcow2_sha256", "qcow2_acceptance_sha256",
        "derivation_intent_sha256", "derived_output_absent",
    } and gate["schema"] == "uk.wamr.compute-fixed-vhd-derivation-gate"
      and gate["schema_version"] == 1
      and gate["profile"] == ci.CURRENT_PROFILE
      and gate["status"] == "accepted_qcow2_only"
      and gate["accepted_qcow2_sha256"] == by_name["qcow2"]["sha256"]
      and gate["qcow2_acceptance_sha256"]
      == by_name["qcow2_acceptance"]["sha256"]
      and gate["derivation_intent_sha256"]
      == by_name["fixed_vhd_derivation_intent"]["sha256"]
      and gate["derived_output_absent"] is True)
    require(gate == ci.document(
        stage / "artifacts/fixed_vhd_derivation_gate"))

    derivation = ci.document(
        stage / "evidence/fixed-vhd-derivation.json")
    ci.require_vhd_derivation(
        derivation, acceptance["accepted_qcow2"], package_tool,
        package["image"]["raw"], finalization["identity"])
    require(derivation == ci.document(
        stage / "artifacts/fixed_vhd_derivation")
            and derivation["output"]["sha256"] == by_name["vhd"]["sha256"]
            and derivation["output"]["file_bytes"] == by_name["vhd"]["size"])

    inspection = ci.document(stage / "evidence/final-inspection.json")
    require(set(inspection) == {
        "schema", "schema_version", "profile", "status", "source",
        "artifacts", "records", "modes", "boots",
    } and inspection["schema"] == "uk.wamr.compute-image-chain-inspection"
      and inspection["schema_version"] == 1
      and inspection["profile"] == ci.CURRENT_PROFILE
      and inspection["status"] == "complete"
      and inspection["source"] == acceptance["source"]
      and inspection["modes"] == list(ci.SIX_MODES)
      and set(inspection["boots"]) == set(ci.SIX_MODES)
      and set(inspection["artifacts"]) == {"efi", "raw", "qcow2", "vhd"})
    for name in ("efi", "raw", "qcow2", "vhd"):
        require(inspection["artifacts"][name]["sha256"]
                == by_name[name]["sha256"]
                and inspection["artifacts"][name]["file_bytes"]
                == by_name[name]["size"])
    for mode in ci.SIX_MODES:
        observed = inspection["boots"][mode]
        require(observed["request_sha256"] == boots[mode]["request"]["sha256"]
                and observed["report_sha256"]
                == boots[mode]["report"]["sha256"]
                and observed["serial_sha256"]
                == boots[mode]["serial"]["sha256"]
                and observed["compute_sha256"]
                == boots[mode]["compute"]["sha256"])
    record_roles = {
        "build-start.json": "build_start",
        "build.json": "build",
        "boot-inputs.json": "boot_inputs",
        "package.json": "package",
        "qcow2-finalization-intent.json": "qcow2_finalization_intent",
        "qcow2-finalization.json": "qcow2_finalization",
        "qcow2-acceptance.json": "qcow2_acceptance",
        "fixed-vhd-derivation-intent.json":
            "fixed_vhd_derivation_intent",
        "fixed-vhd-derivation-gate.json": "fixed_vhd_derivation_gate",
        "fixed-vhd-derivation.json": "fixed_vhd_derivation",
    }
    require(set(inspection["records"]) == set(record_roles))
    for filename, role in record_roles.items():
        require(inspection["records"][filename] == by_name[role]["sha256"])
    require(inspection == ci.document(stage / "artifacts/final_inspection")
            and ci.read(stage / "artifacts/cleanup", 128)
            == b"primary=0 cleanup=0\n")


def publication_records(
        handoff, stage, source, transport_context,
        bundle_name="bundle.json"):
    """The uploaded originals must be the successful fixed public lane records."""
    ci = handoff.ci
    bundle = ci.document(stage / bundle_name)
    version = bundle["version"]
    evidence_names = EVIDENCE if version == 1 else V2_EVIDENCE
    modes = ci.MODES if version == 1 else ci.SIX_MODES
    profile = (
        "tiny-aot-two-boot"
        if version == 1 else ci.CURRENT_PROFILE)
    value = ci.document(stage / "artifacts/local_result")
    require(set(value["records"]) == evidence_names
            and value["schema_version"] == version
            and value["passed"] is True
            and value["cloud_authority"] == "not_admitted"
            and value["modes"] == list(modes)
            and (version == 1 or value["profile"] == ci.CURRENT_PROFILE))
    build = ci.document(stage / "artifacts/build")
    expected_source = {
        "revision": source["source_revision"],
        "tree": source["source_tree"],
    }
    require(build["source"] == expected_source)
    start = ci.document(stage / "evidence/build-start.json")
    require(start["source"] == expected_source)
    legacy = version == 1 and (
        source["source_revision"], source["source_tree"]
    ) in LEGACY_V1_SOURCES
    pre_supervisor = version == 1 and pre_supervisor_source(source)
    if "dependencies" not in start:
        require(legacy and "source_custody" not in start
                and "consumer_inputs" not in start)
    else:
        source_custody_record(ci, start["source_custody"])
        dependency_record(ci, start["dependencies"], source)
        if "consumer_inputs" not in start:
            require(legacy)
        else:
            consumer_input_record(ci, start["consumer_inputs"])
            required_files = (
                {f"tool:{name}" for name in ci.HOST_TOOLS}
                | {"wamr-source-archive"})
            if not pre_supervisor:
                required_files.add("command-supervisor")
            require(required_files <= set(start["consumer_inputs"]["files"]))
            require_consumer_tree_roles(start["consumer_inputs"], legacy)
            if "command_supervisor" in start:
                command_supervisor_record(start["command_supervisor"])
            else:
                require(pre_supervisor)
    boot_inputs = ci.document(stage / "evidence/boot-inputs.json")
    if boot_inputs.get("schema") == "uk.wamr.consumer-input-custody":
        consumer_input_record(ci, boot_inputs)
        require(
            {"package_tool", "local_boot_tool", "qemu",
             "ovmf_code", "ovmf_vars", "efi"} <= set(boot_inputs["files"])
            and "qemu-data" in boot_inputs["trees"])
    else:
        require(legacy and set(boot_inputs) == {
            "package_tool", "local_boot_tool", "qemu",
            "ovmf_code", "ovmf_vars",
        })
        for value in boot_inputs.values():
            digest_string(value)
    if not pre_supervisor:
        consumer_files = start["consumer_inputs"]["files"]
        role_identities = {
            "command-supervisor": ci.native_executable_identity(
                consumer_files["command-supervisor"]),
            **{
                "tool:" + name: ci.native_executable_identity(
                    consumer_files["tool:" + name])
                for name in ci.HOST_TOOLS
            },
            "input:package_tool": ci.native_executable_identity(
                boot_inputs["files"]["package_tool"]),
            "input:local_boot_tool": ci.native_executable_identity(
                boot_inputs["files"]["local_boot_tool"]),
        }
    for name in sorted(evidence_names):
        item = ci.document(stage / "evidence" / name)
        if name.startswith("command-"):
            expected_fields = {
                "scope", "stage", "exit_code", "bytes", "sha256",
                "over_limit", "known_error_markers",
            }
            if not pre_supervisor:
                expected_fields.update({"sha256_scope", "supervisor"})
            require(set(item) == expected_fields
                    and item["scope"] == "command_diagnostic_not_acceptance"
                    and item["stage"] + ".json" == name[len("command-"):]
                    and type(item["exit_code"]) is int and item["exit_code"] == 0
                    and item["over_limit"] is False
                    and item["known_error_markers"] == []
                    and type(item["bytes"]) is int and 0 <= item["bytes"] <= 8 * 1024 * 1024
                    and re.fullmatch(r"[0-9a-f]{64}", item["sha256"]))
            if not pre_supervisor:
                command_stage = name[len("command-"):-len(".json")]
                supervised_command_record(
                    ci, item, command_stage, role_identities,
                    transport_context, profile=profile)
    by_name = dict(zip(
        handoff.NAMES if version == 1 else handoff.V2_NAMES,
        bundle["artifacts"]))
    for mode in modes:
        request = ci.document(stage / "boots" / mode / "request")
        require(set(request) == {
            "schema_version", "supervisor_pid", "config", "pins",
        } and type(request["supervisor_pid"]) is int
          and 0 < request["supervisor_pid"] <= 0x7fffffff)
        if request["schema_version"] == 1:
            require(legacy)
            for pin in request["pins"]:
                require(set(pin) == {"size", "sha256"})
                bounded_integer(pin["size"], 1, 256 * 1024 * 1024 + 512)
                require(type(pin["sha256"]) is list and len(pin["sha256"]) == 32
                        and all(type(item) is int and 0 <= item <= 255
                                for item in pin["sha256"]))
        else:
            require(request["schema_version"] == 2
                    and len(request["pins"]) == 4)
            for pin in request["pins"]:
                require(set(pin) == {
                    "device_major", "device_minor", "inode", "mode",
                    "uid", "gid", "nlink", "size",
                    "mtime_seconds", "mtime_nanoseconds",
                    "ctime_seconds", "ctime_nanoseconds", "sha256",
                })
                for key in (
                        "device_major", "device_minor", "inode", "mode",
                        "uid", "gid", "nlink", "size",
                        "mtime_nanoseconds", "ctime_nanoseconds"):
                    bounded_integer(pin[key], 0, (1 << 64) - 1)
                require(pin["inode"] > 0 and pin["nlink"] > 0
                        and stat.S_ISREG(pin["mode"])
                        and not pin["mode"] & 0o022
                        and pin["mtime_nanoseconds"] < 1_000_000_000
                        and pin["ctime_nanoseconds"] < 1_000_000_000
                        and type(pin["mtime_seconds"]) is int
                        and type(pin["ctime_seconds"]) is int
                        and type(pin["sha256"]) is list
                        and len(pin["sha256"]) == 32
                        and all(type(item) is int and 0 <= item <= 255
                                for item in pin["sha256"]))
        cfg = request["config"]
        require(set(cfg) == set(ci.config_for(Path("/unused"), Path("/unused/compute"), 0)))
        # Exact original request bytes are retained. Their paths must only name
        # this known public runner checkout, never operator/campaign inputs.
        path = Path(cfg["work_dir"])
        require(path.name == "boot-" + mode and path.parent.name == "compute")
        runtime = path.parent.parent
        require(runtime in (
            ci.REPO / ".d/wamr-native-runtime",
            Path("/d/wamr-ci/wamr-native-runtime"),
        ))
        require(cfg == ci.config_for(
            runtime, runtime / "compute", modes.index(mode), modes))
        if request["schema_version"] == 2:
            for index, name in enumerate(("ovmf_code", "ovmf_vars", "qemu"), 1):
                require(name in boot_inputs["files"])
                record = boot_inputs["files"][name]
                metadata = record["metadata"]
                seconds_m, nanoseconds_m = divmod(
                    metadata[7], 1_000_000_000)
                seconds_c, nanoseconds_c = divmod(
                    metadata[8], 1_000_000_000)
                require(request["pins"][index] == {
                    "device_major": os.major(metadata[0]),
                    "device_minor": os.minor(metadata[0]),
                    "inode": metadata[1],
                    "mode": metadata[2],
                    "uid": metadata[3],
                    "gid": metadata[4],
                    "nlink": metadata[5],
                    "size": metadata[6],
                    "mtime_seconds": seconds_m,
                    "mtime_nanoseconds": nanoseconds_m,
                    "ctime_seconds": seconds_c,
                    "ctime_nanoseconds": nanoseconds_c,
                    "sha256": list(bytes.fromhex(record["sha256"])),
                })
            compute = ci.document(stage / "boots" / mode / "compute")
            require(compute["input_pins"] == request["pins"])
        require(request["pins"][0]["size"]
                == by_name[
                    "raw" if mode.startswith("raw-") else
                    "qcow2" if mode.startswith("qcow2-") else
                    "vhd"]["size"])
        require(bytes(request["pins"][0]["sha256"]).hex()
                == by_name[
                    "raw" if mode.startswith("raw-") else
                    "qcow2" if mode.startswith("qcow2-") else
                    "vhd"]["sha256"])
    if version == 2:
        publication_lineage_v2(handoff, stage, bundle)


def pack(handoff, stage, archive, source, validator, supervisor):
    handoff.FAILURE_STAGE = "public-pack-context"
    source = context(source)
    handoff.private(stage)
    handoff.private(archive.parent)
    bundle = handoff.ci.document(stage / "bundle.json")
    require(bundle["source_revision"] == source["source_revision"]
            and bundle["source_tree"] == source["source_tree"]
            and bundle["identity"]["wamr_revision"] == source["wamr_revision"])
    if bundle["version"] == 2:
        require(bundle["run"] == {
            "repository": source["repository"],
            "run_id": source["run_id"],
            "run_attempt": source["run_attempt"],
        })
    handoff.FAILURE_STAGE = "public-pack-members"
    original = members(handoff, bundle, stage)
    handoff.FAILURE_STAGE = "public-pack-records"
    publication_records(handoff, stage, source, "producer_direct")
    # The private handoff's known inspection captures exist but are never copied.
    handoff.FAILURE_STAGE = "public-pack-tree"
    inspect_tree(stage, set(original) | {
        "bundle.json",
        ("private/handoff-inspect-legacy.log"
         if pre_supervisor_source(source)
         else "private/handoff-inspect.log"),
        ("evidence/command-handoff-inspect-legacy.json"
         if pre_supervisor_source(source)
         else "evidence/command-handoff-inspect.json"),
    })
    handoff.FAILURE_STAGE = "public-pack-native"
    native(
        handoff, validator, supervisor, stage / "bundle.json", source)
    portable = copy.deepcopy(bundle)
    for item in members(handoff, portable, stage).values():
        item["path"] = Path(item["path"]).relative_to(stage).as_posix()
    selected = members(handoff, portable)
    manifest = dict(
        schema="uk.wamr.public-source-bundle", version=bundle["version"],
        authority="not_admitted", source=source,
        members={name: {key: item[key] for key in ("size", "sha256")}
                 for name, item in selected.items()})
    if bundle["version"] == 2:
        manifest["profile"] = handoff.ci.CURRENT_PROFILE
    bundle_bytes, manifest_bytes = encoded(portable), encoded(manifest)
    require(len(bundle_bytes) <= MAX_JSON and len(manifest_bytes) <= MAX_JSON)
    handoff.FAILURE_STAGE = "public-pack-zip"
    with archive.open("xb") as output:
        os.fchmod(output.fileno(), 0o600)
        with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_STORED, allowZip64=False) as zipped:
            for name in sorted(selected):
                path = stage / name
                before = handoff.ci.snapshot(regular(path))
                info = zipfile.ZipInfo(name)
                info.create_system = 3
                info.external_attr = (stat.S_IFREG | 0o600) << 16
                with path.open("rb") as src, zipped.open(info, "w") as dst:
                    require(handoff.ci.snapshot(os.fstat(src.fileno())) == before)
                    copy_checked(src, dst, selected[name])
                require(handoff.ci.snapshot(regular(path)) == before)
            for name, raw in (("bundle.json", bundle_bytes), ("public-source.json", manifest_bytes)):
                info = zipfile.ZipInfo(name)
                info.create_system = 3
                info.external_attr = (stat.S_IFREG | 0o600) << 16
                zipped.writestr(info, raw)
        output.flush()
        os.fsync(output.fileno())
    require(archive.stat().st_size <= MAX_TOTAL)
    # Reopen the complete exported bytes, not just the pre-copy manifest.
    handoff.FAILURE_STAGE = "public-pack-archive"
    archive_sha256 = handoff.ci.digest(archive, MAX_TOTAL)
    verify_archive(handoff, archive, source, archive_sha256)
    return archive_sha256


def verify_archive_descriptor(handoff, handle, expected,
                              expected_archive_sha256):
    context(expected)
    if expected_archive_sha256 is None:
        require((expected["source_revision"], expected["source_tree"])
                in LEGACY_V1_SOURCES)
    else:
        digest_string(expected_archive_sha256)
    with descriptor_zip(handle) as zipped:
        entries = zipped.infolist()
        require(2 < len(entries) <= MAX_MEMBERS and not zipped.comment)
        names = {info.filename for info in entries}
        require(len(names) == len(entries) and {"bundle.json", "public-source.json"} <= names)
        total = 0
        for info in entries:
            require(info.create_system == 3
                    and info.external_attr >> 16 == stat.S_IFREG | 0o600
                    and info.compress_type == zipfile.ZIP_STORED
                    and info.compress_size == info.file_size and not info.flag_bits & 1
                    and not info.comment and not info.extra)
            total += info.file_size
            require(0 < info.file_size <= 256 * 1024 * 1024 + 512 and total <= MAX_TOTAL)
        for name in ("bundle.json", "public-source.json"):
            require(zipped.getinfo(name).file_size <= MAX_JSON)
        bundle_raw = zipped.read("bundle.json")
        manifest_raw = zipped.read("public-source.json")
        require(not any(pattern in bundle_raw + manifest_raw for pattern in SENSITIVE))
        bundle = decode(bundle_raw)
        manifest = decode(manifest_raw)
        selected = members(handoff, bundle)
        expected_order = (
            sorted(selected) + ["bundle.json", "public-source.json"])
        require([info.filename for info in entries] == expected_order
                and names == set(selected) | {"bundle.json", "public-source.json"})
        manifest_fields = {
            "schema", "version", "authority", "source", "members"}
        if bundle["version"] == 2:
            manifest_fields.add("profile")
        require(set(manifest) == manifest_fields
                and manifest["schema"] == "uk.wamr.public-source-bundle"
                and type(manifest["version"]) is int
                and manifest["version"] == bundle["version"]
                and manifest["authority"] == "not_admitted"
                and context(manifest["source"]) == expected
                and bundle["source_revision"] == expected["source_revision"]
                and bundle["source_tree"] == expected["source_tree"]
                and bundle["identity"]["wamr_revision"] == expected["wamr_revision"]
                and manifest["members"] == {
                    name: {key: item[key] for key in ("size", "sha256")}
                    for name, item in selected.items()})
        if bundle["version"] == 2:
            require(manifest["profile"] == handoff.ci.CURRENT_PROFILE
                    and bundle["run"] == {
                        "repository": expected["repository"],
                        "run_id": expected["run_id"],
                        "run_attempt": expected["run_attempt"],
                    })
        for name, item in selected.items():
            require(zipped.getinfo(name).file_size == item["size"])
            with zipped.open(name) as stream:
                copy_checked(stream, None, item)
        if expected_archive_sha256 is None:
            start = decode(zipped.read("evidence/build-start.json"))
            require("dependencies" not in start)
    return bundle


def verify_archive_with_digest(
        handoff, archive, expected, expected_archive_sha256):
    context(expected)
    if expected_archive_sha256 is not None:
        digest_string(expected_archive_sha256)
    with retained_archive(
            handoff, archive, expected_archive_sha256) as (
                handle, archive_sha256):
        bundle = verify_archive_descriptor(
            handoff, handle, expected, expected_archive_sha256)
    return bundle, archive_sha256


def verify_archive(handoff, archive, expected, expected_archive_sha256):
    bundle, unused_archive_sha256 = verify_archive_with_digest(
        handoff, archive, expected, expected_archive_sha256)
    del unused_archive_sha256
    return bundle


def import_bundle(
        handoff, archive, output, expected, expected_archive_sha256,
        validator, supervisor, artifact_id=None, container_digest=None):
    handoff.private(output.parent)
    with retained_archive(
            handoff, archive, expected_archive_sha256) as (
                handle, unused_archive_sha256):
        del unused_archive_sha256
        bundle = verify_archive_descriptor(
            handoff, handle, expected, expected_archive_sha256)
        output.mkdir(mode=0o700)
        with descriptor_zip(handle) as zipped:
            for name, item in members(handoff, bundle).items():
                path = output / name
                path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                with zipped.open(name) as src, path.open("xb") as dst:
                    os.fchmod(dst.fileno(), 0o600)
                    copy_checked(src, dst, item)
                    dst.flush()
                    os.fsync(dst.fileno())
                path.chmod(0o600)
            for name in ("bundle.json", "public-source.json"):
                handoff.ci.save(
                    output / (
                        "portable-bundle.json"
                        if name == "bundle.json" else name),
                    decode(zipped.read(name)),
                )
    for item in members(handoff, bundle).values():
        item["path"] = str(output / item["path"])
    if bundle["version"] == 2:
        require(expected_archive_sha256 is not None
                and type(artifact_id) is str
                and re.fullmatch(r"[1-9][0-9]{0,19}", artifact_id)
                and type(container_digest) is str)
        digest_string(container_digest)
        handoff.ci.save(output / "transport.json", {
            "schema": "uk.wamr.public-source-transport",
            "version": 2,
            "repository": expected["repository"],
            "run_id": expected["run_id"],
            "run_attempt": expected["run_attempt"],
            "source_revision": expected["source_revision"],
            "source_tree": expected["source_tree"],
            "inner_zip_sha256": expected_archive_sha256,
            "artifact_id": artifact_id,
            "container_digest": container_digest,
        })
    else:
        require(artifact_id is None and container_digest is None)
    handoff.ci.save(output / "candidate-bundle.json", bundle)
    publication_records(
        handoff, output, expected, "trusted_inner_zip",
        "candidate-bundle.json")
    native(
        handoff, validator, supervisor,
        output / "candidate-bundle.json", expected)
    # Only a fully revalidated import publishes the operator-facing bundle.
    handoff.ci.save(output / "bundle.json", bundle)
    return bundle


def publish_ci(handoff):
    """Only the named public repository lane may select this fixed publication."""
    handoff.FAILURE_STAGE = "public-context"
    runtime = ci_runtime(handoff.ci)
    handoff.result_records(runtime / "compute")
    start = accepted_public_build_start(handoff, runtime)
    source = ci_context(handoff, start)
    publication = runtime / "compute/public-source"
    stage = publication / "handoff"
    output = handoff.ci.REPO / ".d/wamr-public-source-bundle"
    handoff.private(runtime)
    handoff.private(publication)
    handoff.FAILURE_STAGE = "public-cleanup-record"
    require(handoff.ci.read(runtime / "evidence/runtime-cleanup.txt", 128)
            == b"primary=0 cleanup=0\n")
    output.mkdir(mode=0o700)
    handoff.FAILURE_STAGE = "public-validator-build"
    unused_output, validator_record = handoff.ci.execute(
        runtime / "compute", "public-validator-build", [
        handoff.ci.tool("zig"), "build", "--build-file",
        handoff.ci.REPO / "support/tools/hyperv/direct/build.zig",
        "--cache-dir", runtime / "compute/cache",
        "--global-cache-dir", runtime / "compute/global-cache",
        "--prefix", publication / "tools",
        "-Doptimize=ReleaseSafe", "-j2", "install"], 600,
        input_records=handoff.ci.consumer_file_records(
            start["consumer_inputs"]))
    del unused_output
    consumer_files = start["consumer_inputs"]["files"]
    role_identities = {
        "command-supervisor": handoff.ci.native_executable_identity(
            consumer_files["command-supervisor"]),
        **{
            "tool:" + name: handoff.ci.native_executable_identity(
                consumer_files["tool:" + name])
            for name in handoff.ci.HOST_TOOLS
        },
    }
    validator_record_path = (
        runtime / "compute/evidence/command-public-validator-build.json")

    def require_validator_record():
        recorded = handoff.ci.document(validator_record_path)
        require(recorded == validator_record)
        supervised_command_record(
            handoff.ci, recorded, "public-validator-build",
            role_identities, "producer_direct")
        handoff.ci.require_recorded_build_custody(runtime, start)
        require(ci_context(handoff, start) == source)

    require_validator_record()
    handoff.FAILURE_STAGE = "public-export"
    exported = handoff.export(runtime, stage)
    require_validator_record()
    validator = publication / "tools/bin/uk-wamr-direct-validate"
    supervisor = Path(handoff.ci.COMMAND_SUPERVISOR_PATH)
    archive = output / "tiny-aot-public-source.zip"
    handoff.FAILURE_STAGE = "public-pack"
    archive_sha256 = pack(
        handoff, stage, archive, source, validator, supervisor)
    # V2 production import is intentionally deferred until the exact uploaded
    # artifact ID has been redownloaded and its container digest is available.
    if exported["version"] == 1:
        handoff.FAILURE_STAGE = "public-reopen"
        import_bundle(
            handoff, archive, publication / "reopened",
            source, archive_sha256, validator, supervisor)
    handoff.FAILURE_STAGE = "public-final-context"
    require_validator_record()
    return archive, archive_sha256, source["source_tree"]
