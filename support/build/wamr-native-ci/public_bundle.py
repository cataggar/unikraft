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
    ("71eba1fdfe863d2b0d56a02165e44bbb888b83a7",
     "40450504eda1cb8ca5b5f9209f07feaea1ab18f0"),
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


def dependency_record(ci, value):
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
    manifests = value["source_manifests"]
    require(set(manifests) == set(expected_paths))
    for name, expected_path in expected_paths.items():
        item = manifests[name]
        require(set(item) == {"source", "copy"})
        source = item["source"]
        require(set(source) == {
            "path", "mode", "bytes", "sha256", "git_oid", "metadata_sha256"}
                and source["path"] == expected_path
                and source["mode"] == "100644")
        bounded_integer(source["bytes"], 1, 1024 * 1024)
        digest_string(source["sha256"])
        digest_string(source["git_oid"], (40,))
        digest_string(source["metadata_sha256"])
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
        "physical_sha256", "root_metadata_sha256", "manifests",
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
    digest_string(hash_verification["sha256"])
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
    sdk = ci.REPO / ".d/wamr-source"
    def git(*args):
        return subprocess.check_output(["git", "-C", str(sdk), *args], timeout=60).decode().strip()
    require(git("rev-parse", "HEAD") == ci.REVISION
            and not git("status", "--porcelain", "--untracked-files=normal")
            and git("remote", "get-url", "origin") in (
                "https://github.com/cataggar/wamr", "https://github.com/cataggar/wamr.git"))
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
    output = handoff.ci.run(bundle.parent, "native-revalidation",
                            [validator, "handoff", bundle], 600, 4096)
    require(handoff.ci.read(output, 4096)
            == b"Compute handoff revalidated; authority=not_admitted.\n")


def publication_records(handoff, stage, source):
    """The uploaded originals must be the successful fixed public lane records."""
    ci = handoff.ci
    value = ci.document(stage / "artifacts/local_result")
    require(set(value["records"]) == EVIDENCE
            and value["passed"] is True and value["cloud_authority"] == "not_admitted")
    build = ci.document(stage / "artifacts/build")
    require(build["source"]["revision"] == source["source_revision"]
            and build["source"]["tree"] == source["source_tree"])
    start = ci.document(stage / "evidence/build-start.json")
    require(start["source"]["revision"] == source["source_revision"]
            and start["source"]["tree"] == source["source_tree"])
    if "dependencies" not in start:
        require((source["source_revision"], source["source_tree"])
                in LEGACY_V1_SOURCES)
    else:
        dependency_record(ci, start["dependencies"])
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
        require(set(request) == {"schema_version", "supervisor_pid", "config", "pins"}
                and type(request["supervisor_pid"]) is int
                and 0 < request["supervisor_pid"] <= 0x7fffffff)
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
    verify_archive(handoff, archive, source)


def verify_archive(handoff, archive, expected):
    context(expected)
    require(0 < regular(archive).st_size <= MAX_TOTAL)
    before = handoff.ci.snapshot(archive.stat())
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
    require(handoff.ci.snapshot(regular(archive)) == before)
    return bundle


def import_bundle(handoff, archive, output, expected, validator):
    handoff.private(output.parent)
    bundle = verify_archive(handoff, archive, expected)
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
    handoff.ci.run(runtime / "compute", "public-validator-build", [
        handoff.ci.tool("zig"), "build", "--build-file",
        handoff.ci.REPO / "support/tools/hyperv/direct/build.zig",
        "--cache-dir", runtime / "compute/cache",
        "--global-cache-dir", runtime / "compute/global-cache",
        "--prefix", runtime / "compute/public-tools",
        "-Doptimize=ReleaseSafe", "-j2", "install"], 600)
    handoff.export(runtime, stage)
    validator = runtime / "compute/public-tools/bin/uk-wamr-direct-validate"
    archive = output / "tiny-aot-public-source.zip"
    pack(handoff, stage, archive, source, validator)
    # Re-extract and run the actual production checker on the exported archive.
    import_bundle(handoff, archive, runtime / "public-source-reopened", source, validator)
    require(ci_context(handoff) == source)
    return archive
