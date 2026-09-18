#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""Explicit public-source tiny CI bundle; no arbitrary private export or authority."""
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import zipfile

MAX_TOTAL = 512 * 1024 * 1024
MAX_MEMBERS = 64
MAX_JSON = 65536
LEGACY_V1_SOURCES = frozenset({
    ("993e4d0d394c08202c0d0c57ea97450a19a4f394",
     "54f8e118146c78c24e7c802657c6ec62b268a5de"),
    ("34e5c88a165c4da878b3122b8b91716116d65d4b",
     "54f8e118146c78c24e7c802657c6ec62b268a5de"),
    # Retained run 35277215611 archive source, independently inspected.
    ("b5a8fdbee033349f7145fbc76aebfee29b2fa04f",
     "54f8e118146c78c24e7c802657c6ec62b268a5de"),
})
BOOT_KEYS = ("serial", "request", "report", "compute")
STAGES = ("adapter", "local-boot-tool", "fixtures", "prepare", "config",
          "native-image", "package", "raw-x2apic", "raw-legacy-apic",
          "vpc-x2apic", "vpc-legacy-apic", "inspect")
EVIDENCE = frozenset(
    ["build-start.json", "build.json", "boot-inputs.json", "package.json"]
    + [f"command-{stage}.json" for stage in STAGES]
    + [f"{mode}-compute.json" for mode in STAGES[7:11]])
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


def bind(hasher, value):
    raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii")
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
    return hashlib.sha256(json.dumps(
        value, separators=(",", ":")).encode("ascii")).hexdigest()


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
    require(value["aggregate_sha256"] == hashlib.sha256(json.dumps(
        unsigned, sort_keys=True,
        separators=(",", ":")).encode("ascii")).hexdigest())
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
    require(hash_verification["sha256"] == hashlib.sha256(json.dumps(
        hash_records, sort_keys=True,
        separators=(",", ":")).encode("ascii")).hexdigest())
    closure = hashlib.sha256(b"uk.wamr.package-closure-v1\0")
    physical = hashlib.sha256(b"uk.wamr.package-physical-closure-v1\0")
    for record in records:
        bind(closure, record)
        bind(physical, [
            record["package_hash"], record["content"]["physical_sha256"]])
    require(packages["closure_sha256"] == closure.hexdigest()
            and packages["physical_sha256"] == physical.hexdigest())
    return value


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")


def decode(raw):
    require(len(raw) <= MAX_JSON)
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result)
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=unique)


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


def ci_context(handoff):
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
    runtime = ci.REPO / ".d/wamr-native-runtime"
    start = ci.document(runtime / "compute/evidence/build-start.json")
    consumer_input_record(ci, start["consumer_inputs"])
    ci.consumer_input_state(
        runtime, content=True, expected=start["consumer_inputs"])
    require("wamr-source-archive" in start["consumer_inputs"]["files"])
    return context(dict(repository="cataggar/unikraft", run_id=os.environ["GITHUB_RUN_ID"],
                        run_attempt=os.environ["GITHUB_RUN_ATTEMPT"],
                        source_revision=source["revision"], source_tree=source["tree"],
                        wamr_revision=ci.REVISION))


def members(handoff, bundle, root=None):
    """Closed positional schema; paths never select additional publication members."""
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
    require(len(result) + 2 <= MAX_MEMBERS
            and sum(item["size"] for item in result.values()) <= MAX_TOTAL - 2 * MAX_JSON)
    return result


def regular(path):
    require(path.resolve(strict=True) == path)
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
            and info.st_uid == os.getuid() and not info.st_mode & 0o022)
    return info


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


def native(handoff, validator, bundle):
    regular(validator)
    # Reuse the existing command deadline and bounded capture machinery. These
    # private captures and allowlisted failure flags are never archive members.
    for name in ("private", "evidence"):
        (bundle.parent / name).mkdir(mode=0o700, exist_ok=True)
    start = handoff.ci.document(bundle.parent / "evidence/build-start.json")
    validator_input = handoff.ci.record_input_paths(
        {"validator": validator}, {}, content=True)
    input_records = handoff.ci.consumer_file_records(start["consumer_inputs"])
    input_records.update(handoff.ci.consumer_file_records(validator_input))
    output = handoff.ci.run(bundle.parent, "native-revalidation",
                            [validator, "handoff", bundle], 600, 4096,
                            input_records=input_records)
    require(handoff.ci.read(output, 4096)
            == b"Compute handoff revalidated; authority=not_admitted.\n")
    handoff.ci.record_input_paths(
        {}, {}, content=True, expected=validator_input)


def publication_records(handoff, stage, source):
    """The uploaded originals must be the successful fixed public lane records."""
    ci = handoff.ci
    value = ci.document(stage / "artifacts/local_result")
    require(set(value["records"]) == EVIDENCE
            and value["passed"] is True and value["cloud_authority"] == "not_admitted")
    build = ci.document(stage / "artifacts/build")
    expected_source = {
        "revision": source["source_revision"],
        "tree": source["source_tree"],
    }
    require(build["source"] == expected_source)
    start = ci.document(stage / "evidence/build-start.json")
    require(start["source"] == expected_source)
    legacy = (
        source["source_revision"], source["source_tree"]
    ) in LEGACY_V1_SOURCES
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
            require(
                {f"tool:{name}" for name in ci.HOST_TOOLS}
                | {"wamr-source-archive"}
                <= set(start["consumer_inputs"]["files"])
                and {"bison", "python-stdlib", "system-bin", "zig", "llvm"}
                <= set(start["consumer_inputs"]["trees"]))
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
    for name in sorted(EVIDENCE):
        item = ci.document(stage / "evidence" / name)
        if name.startswith("command-"):
            require(set(item) == {"scope", "stage", "exit_code", "bytes", "sha256",
                                  "over_limit", "known_error_markers"}
                    and item["scope"] == "command_diagnostic_not_acceptance"
                    and item["stage"] + ".json" == name[len("command-"):]
                    and type(item["exit_code"]) is int and item["exit_code"] == 0
                    and item["over_limit"] is False
                    and item["known_error_markers"] == []
                    and type(item["bytes"]) is int and 0 <= item["bytes"] <= 8 * 1024 * 1024
                    and re.fullmatch(r"[0-9a-f]{64}", item["sha256"]))
    for mode in ci.MODES:
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
        require(runtime.name == "wamr-native-runtime" and runtime.parent.name == ".d")
        workspace = runtime.parent.parent
        require(workspace.is_absolute() and ".." not in workspace.parts
                and workspace.name == "unikraft")
        require(cfg == ci.config_for(runtime, runtime / "compute", ci.MODES.index(mode)))
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


def pack(handoff, stage, archive, source, validator):
    source = context(source)
    handoff.private(stage)
    handoff.private(archive.parent)
    bundle = handoff.ci.document(stage / "bundle.json")
    require(bundle["source_revision"] == source["source_revision"]
            and bundle["source_tree"] == source["source_tree"]
            and bundle["identity"]["wamr_revision"] == source["wamr_revision"])
    original = members(handoff, bundle, stage)
    publication_records(handoff, stage, source)
    # The private handoff's known inspection captures exist but are never copied.
    inspect_tree(stage, set(original) | {
        "bundle.json", "private/handoff-inspect.log", "evidence/command-handoff-inspect.json"})
    native(handoff, validator, stage / "bundle.json")
    portable = copy.deepcopy(bundle)
    for item in members(handoff, portable, stage).values():
        item["path"] = Path(item["path"]).relative_to(stage).as_posix()
    selected = members(handoff, portable)
    manifest = dict(schema="uk.wamr.public-source-bundle", version=1,
                    authority="not_admitted", source=source,
                    members={name: {key: item[key] for key in ("size", "sha256")}
                             for name, item in selected.items()})
    bundle_bytes, manifest_bytes = encoded(portable), encoded(manifest)
    require(len(bundle_bytes) <= MAX_JSON and len(manifest_bytes) <= MAX_JSON)
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
    archive_sha256 = handoff.ci.digest(archive, MAX_TOTAL)
    verify_archive(handoff, archive, source, archive_sha256)
    return archive_sha256


def verify_archive(handoff, archive, expected, expected_archive_sha256):
    context(expected)
    if expected_archive_sha256 is None:
        require((expected["source_revision"], expected["source_tree"])
                in LEGACY_V1_SOURCES)
    else:
        digest_string(expected_archive_sha256)
    info = regular(archive)
    require(0 < info.st_size <= MAX_TOTAL)
    before = handoff.ci.snapshot(info)
    if expected_archive_sha256 is not None:
        require(handoff.ci.digest(archive, MAX_TOTAL) == expected_archive_sha256
                and handoff.ci.snapshot(regular(archive)) == before)
    with zipfile.ZipFile(archive) as zipped:
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
        require(names == set(selected) | {"bundle.json", "public-source.json"})
        require(set(manifest) == {"schema", "version", "authority", "source", "members"}
                and manifest["schema"] == "uk.wamr.public-source-bundle"
                and type(manifest["version"]) is int and manifest["version"] == 1
                and manifest["authority"] == "not_admitted"
                and context(manifest["source"]) == expected
                and bundle["source_revision"] == expected["source_revision"]
                and bundle["source_tree"] == expected["source_tree"]
                and bundle["identity"]["wamr_revision"] == expected["wamr_revision"]
                and manifest["members"] == {
                    name: {key: item[key] for key in ("size", "sha256")}
                    for name, item in selected.items()})
        for name, item in selected.items():
            require(zipped.getinfo(name).file_size == item["size"])
            with zipped.open(name) as stream:
                copy_checked(stream, None, item)
        if expected_archive_sha256 is None:
            start = decode(zipped.read("evidence/build-start.json"))
            require("dependencies" not in start)
    require(handoff.ci.snapshot(regular(archive)) == before)
    return bundle


def import_bundle(
        handoff, archive, output, expected, expected_archive_sha256, validator):
    handoff.private(output.parent)
    bundle = verify_archive(
        handoff, archive, expected, expected_archive_sha256)
    before = handoff.ci.snapshot(regular(archive))
    output.mkdir(mode=0o700)
    with zipfile.ZipFile(archive) as zipped:
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
            handoff.ci.save(output / ("portable-bundle.json" if name == "bundle.json" else name),
                            decode(zipped.read(name)))
    require(handoff.ci.snapshot(regular(archive)) == before)
    for item in members(handoff, bundle).values():
        item["path"] = str(output / item["path"])
    publication_records(handoff, output, expected)
    handoff.ci.save(output / "candidate-bundle.json", bundle)
    native(handoff, validator, output / "candidate-bundle.json")
    # Only a fully revalidated import publishes the operator-facing bundle.
    handoff.ci.save(output / "bundle.json", bundle)
    return bundle


def publish_ci(handoff):
    """Only the named public repository lane may select this fixed publication."""
    source = ci_context(handoff)
    runtime = handoff.ci.REPO / ".d/wamr-native-runtime"
    stage = runtime / "public-source-handoff"
    output = handoff.ci.REPO / ".d/wamr-public-source-bundle"
    handoff.private(runtime)
    require(handoff.ci.read(runtime / "evidence/runtime-cleanup.txt", 128)
            == b"primary=0 cleanup=0\n")
    output.mkdir(mode=0o700)
    start = handoff.ci.document(
        runtime / "compute/evidence/build-start.json")
    handoff.ci.run(runtime / "compute", "public-validator-build", [
        handoff.ci.tool("zig"), "build", "--build-file",
        handoff.ci.REPO / "support/tools/hyperv/direct/build.zig",
        "--cache-dir", runtime / "compute/cache",
        "--global-cache-dir", runtime / "compute/global-cache",
        "--prefix", runtime / "compute/public-tools",
        "-Doptimize=ReleaseSafe", "-j2", "install"], 600,
        input_records=handoff.ci.consumer_file_records(
            start["consumer_inputs"]))
    handoff.export(runtime, stage)
    validator = runtime / "compute/public-tools/bin/uk-wamr-direct-validate"
    archive = output / "tiny-aot-public-source.zip"
    archive_sha256 = pack(handoff, stage, archive, source, validator)
    # Re-extract and run the actual production checker on the exported archive.
    import_bundle(
        handoff, archive, runtime / "public-source-reopened",
        source, archive_sha256, validator)
    require(ci_context(handoff) == source)
    return archive
