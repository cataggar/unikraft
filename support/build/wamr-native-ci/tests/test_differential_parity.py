# SPDX-License-Identifier: BSD-3-Clause
"""Unpublished Python/native differential oracle; synthetic fixtures are not KVM evidence.

Local: python3 tests/test_differential_parity.py local
Protected x86: python3 tests/test_differential_parity.py full --help
The full runner needs TWO unused, clean Git worktrees, real pinned WAMR, a
pre-acquired runtime template, and an independently built portable controller.
It never substitutes a fixture for a missing production dependency.
"""
import argparse
import copy
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
import unittest
from unittest import mock


HERE = Path(__file__).resolve().parent
PROJECT = HERE.parents[3]
CONTROLLER = HERE.parent
FIXTURES = HERE / "fixtures" / "differential"
MODES = (
    "raw-x2apic", "raw-legacy-apic", "qcow2-x2apic", "qcow2-legacy-apic",
    "vpc-x2apic", "vpc-legacy-apic",
)
BUILD = (
    "command-adapter.json", "command-local-boot-tool.json",
    "build-start.json", "command-fixtures.json", "command-prepare.json",
    "command-config.json", "command-native-image.json", "build.json",
)
BOOT = (
    "boot-inputs.json", "command-package.json", "package.json",
    "command-raw-x2apic.json", "raw-x2apic-compute.json",
    "command-raw-legacy-apic.json", "raw-legacy-apic-compute.json",
    "qcow2-finalization-intent.json", "command-finalize-qcow2.json",
    "qcow2-finalization.json", "command-qcow2-x2apic.json",
    "qcow2-x2apic-compute.json", "command-qcow2-legacy-apic.json",
    "qcow2-legacy-apic-compute.json", "qcow2-acceptance.json",
    "fixed-vhd-derivation-intent.json", "fixed-vhd-derivation-gate.json",
    "command-derive-fixed-vhd.json", "fixed-vhd-derivation.json",
    "command-vpc-x2apic.json", "vpc-x2apic-compute.json",
    "command-vpc-legacy-apic.json", "vpc-legacy-apic-compute.json",
    "command-inspect.json", "final-inspection.json", "result.json",
)
ORDER = BUILD + BOOT
HEX = re.compile(r"[0-9a-f]{64}\Z")
MAX_RECORD = 4 * 1024 * 1024
FROZEN_HOST_TOOLS = (
    "git", "python3", "bash", "dash", "cp", "env", "mkdir", "readlink",
    "uname", "zig", "make", "llvm-nm", "llvm-objcopy", "llvm-objdump",
    "llvm-readelf", "llvm-strip", "bison", "flex", "m4",
)
NATIVE_SOURCE_FILES = (
    "support/build/wamr-native-ci/build.zig",
    "support/build/wamr-native-ci/build.zig.zon",
    "support/build/wamr-native-ci/controller/boot_pipeline.zig",
    "support/build/wamr-native-ci/controller/build_pipeline.zig",
    "support/build/wamr-native-ci/controller/cli.zig",
    "support/build/wamr-native-ci/controller/command_adapter.zig",
    "support/build/wamr-native-ci/controller/command_plan.zig",
    "support/build/wamr-native-ci/controller/custody_files.zig",
    "support/build/wamr-native-ci/controller/custody_limits.zig",
    "support/build/wamr-native-ci/controller/dependency_custody.zig",
    "support/build/wamr-native-ci/controller/fixture_contract.zig",
    "support/build/wamr-native-ci/controller/fixture_runner.zig",
    "support/build/wamr-native-ci/controller/input_custody.zig",
    "support/build/wamr-native-ci/controller/install.zig",
    "support/build/wamr-native-ci/controller/install_target_tests.zig",
    "support/build/wamr-native-ci/controller/layout.zig",
    "support/build/wamr-native-ci/controller/main.zig",
    "support/build/wamr-native-ci/controller/portable_main.zig",
    "support/build/wamr-native-ci/controller/profile.zig",
    "support/build/wamr-native-ci/controller/records.zig",
    "support/build/wamr-native-ci/controller/root.zig",
    "support/build/wamr-native-ci/controller/source_custody.zig",
    "support/build/wamr-native-ci/controller/target.zig",
    "support/build/wamr-native-ci/controller/test_command.zig",
    "support/build/wamr-native-ci/controller/tests.zig",
    "support/build/wamr-native-ci/tests/native_command_oracle.py",
    "support/controller_source_closure.zig",
    "support/tools/hyperv/contracts.zig",
    "support/tools/hyperv/core.zig",
    "support/tools/hyperv/diagnostics.zig",
    "support/tools/hyperv/private_files.zig",
    "support/tools/hyperv/process-command-v1.json",
    "support/tools/hyperv/process.zig",
    "support/tools/hyperv/sensitive.zig",
    "support/tools/hyperv/sha256.zig",
    "support/tools/hyperv/sha256_clear_upper.S",
)
NATIVE_CONSUMER_ROLES = {
    "command-supervisor": "controller/bin/uk-wamr-native-ci",
    "wamr-source-archive": "custody/wamr-source.tar",
    "native:wamr-aot-build": "compute/tools/bin/uk-wamr-aot-build",
    "native:wamr-log-validate": "compute/tools/bin/uk-wamr-log-validate",
    "native:wamr-native-ci-fixtures": "compute/tools/bin/wamr-native-ci-fixtures",
    "native:wamr-ci-package": "compute/tools/bin/wamr-ci-package",
    "native:wamr-ci-supervisor-fixture":
        "compute/tools/bin/wamr-ci-supervisor-fixture",
}


class ParityError(AssertionError):
    pass


def check(condition, reason):
    if not condition:
        raise ParityError(reason)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def oracle(repository=PROJECT):
    source = repository / "support/build/wamr-native-ci/run.py"
    spec = importlib.util.spec_from_file_location("wamr_ci_differential", source)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def private(path, *, empty=False):
    check(path.is_absolute() and path.resolve(strict=True) == path,
          "absolute canonical private path required")
    info = path.lstat()
    check(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid()
          and stat.S_IMODE(info.st_mode) == 0o700, "owner-only 0700 root required")
    if empty:
        check(not any(path.iterdir()), "fresh empty root required")
    return path


def fresh(parent, name):
    private(parent)
    child = parent / name
    check(not child.exists() and not child.is_symlink(), "prior output refused")
    child.mkdir(mode=0o700)
    return private(child, empty=True)


def fixture_parent():
    selected = os.environ.get("TMPDIR")
    if selected:
        candidate = Path(selected)
        if (candidate.is_absolute() and candidate.name in ("scratch", "private")
                and "compute" in candidate.parts and candidate.exists()
                and candidate.parts[:2] != ("/", "tmp")
                and candidate.parts[:3] != ("/", "var", "tmp")):
            return private(candidate)
    scratch = PROJECT / ".d"
    if not scratch.exists():
        scratch.mkdir(mode=0o700)
    return private(scratch)


def checked_file(path, limit=MAX_RECORD):
    before = path.lstat()
    check(stat.S_ISREG(before.st_mode) and before.st_uid == os.getuid()
          and stat.S_IMODE(before.st_mode) == 0o600 and before.st_nlink == 1
          and before.st_size <= limit, "unsafe evidence file")
    with path.open("rb") as stream:
        raw = stream.read(limit + 1)
    after = path.lstat()
    stable = lambda info: (
        info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
        info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
    check(len(raw) == before.st_size and stable(after) == stable(before),
          "evidence file changed")
    return raw


def parsed(raw, reference):
    check(len(raw) <= MAX_RECORD, "oversized record")
    value = json.loads(raw, object_pairs_hook=reference.unique,
                       parse_constant=lambda token: (_ for _ in ()).throw(
                           ParityError("nonfinite JSON constant")))
    check(raw == reference.compact_json(value, newline=True),
          "noncanonical record bytes")
    return value


def category(result):
    stderr = result.stderr.decode("utf-8", "replace")
    if result.returncode == 0:
        return "success"
    if result.returncode == 2 and ("usage:" in stderr or "error:" in stderr):
        return "usage"
    if "WAMR_CI_REFUSED:" in stderr:
        return "refused"
    match = re.search(r"WAMR_CI_FAILED_STAGE: ([a-z0-9-]+);", stderr)
    if match:
        return "failed_stage:" + match.group(1)
    return "unclassified_failure"


def run(argv, repository, environment=None, seconds=1900):
    try:
        return subprocess.run(argv, cwd=repository, env=environment,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              timeout=seconds, check=False)
    except subprocess.TimeoutExpired as exc:
        raise ParityError("controller exceeded outer timeout") from exc


def command(argv, repository, environment=None, seconds=1900):
    result = run(argv, repository, environment, seconds)
    check(len(result.stdout) <= 1024 * 1024 and len(result.stderr) <= 1024 * 1024,
          "unbounded diagnostic stream")
    return result


def identity(path):
    hasher = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            hasher.update(block)
    return hasher.hexdigest()


def phase_snapshot(runtime, reference):
    compute = runtime / "compute"
    if not compute.exists():
        return {"order": (), "records": {}, "retained": {}, "artifacts": {}}
    evidence = compute / "evidence"
    records = {}
    publications = []
    if evidence.exists():
        private(evidence)
        for path in evidence.iterdir():
            check(path.name in ORDER or path.name == "diagnostics.json",
                  "unlisted evidence: " + path.name)
            raw = checked_file(path)
            records[path.name] = (raw, parsed(raw, reference))
            publications.append((path.stat().st_mtime_ns, path.name))
    publications.sort()
    check(all(left[0] != right[0] for left, right in
              zip(publications, publications[1:])),
          "ambiguous evidence publication order")
    ordered = tuple(name for _, name in publications)
    check(tuple(sorted(ordered, key=lambda name: ORDER.index(name)
                      if name in ORDER else len(ORDER))) == ordered,
          "evidence phase order changed")
    if "result.json" in records:
        result = records["result.json"][1]
        check(ordered[-1] == "result.json"
              and result.get("records", {}).keys()
              == records.keys() - {"result.json"},
              "result not last or unexpected evidence membership")
        for name, digest in result["records"].items():
            check(digest == sha(records[name][0]), "result evidence hash changed")
    for name, (_, record) in records.items():
        if not name.startswith("command-"):
            continue
        stage = name[len("command-"):-len(".json")]
        log = checked_file(compute / "private" / (stage + ".log"), 8 * 1024 * 1024)
        check(record["scope"] == "command_diagnostic_not_acceptance"
              and record["stage"] == stage and record["bytes"] == len(log)
              and record["sha256"] == sha(log)
              and record["known_error_markers"] == reference.command_error_markers(log)
              and record["sha256_scope"] == reference.command_digest_scope(len(log)),
              "command log binding changed: " + name)
        supervisor = record["supervisor"]
        request, result = supervisor["request"], supervisor["result"]
        digest_fields = ("canonical_sha256", "argv_sha256",
                         "environment_sha256", "cwd_sha256")
        request_core = {key: value for key, value in request.items()
                        if key not in digest_fields}
        for field, payload in (
                ("canonical_sha256", request_core),
                ("argv_sha256", request["argv"]),
                ("environment_sha256", request["environment"]),
                ("cwd_sha256", request["cwd"])):
            check(request[field] == reference.command_binding_digest(payload),
                  "command request hash changed: " + name)
        result_core = {key: value for key, value in result.items()
                       if key != "canonical_sha256"}
        check(result["canonical_sha256"] == reference.command_binding_digest(result_core)
              and result["request_canonical_sha256"] == request["canonical_sha256"],
              "command result hash changed: " + name)
        output = result["command"]["output"]
        stdout, stderr = result["command"]["stdout"], result["command"]["stderr"]
        check(output["bytes"] == stdout["bytes"] + stderr["bytes"]
              and output["commitment_sha256"] == reference.command_output_commitment(
                  stdout["bytes"], stdout["sha256"],
                  stderr["bytes"], stderr["sha256"]),
              "command output commitment changed: " + name)
        if not record["over_limit"]:
            check(output["combined_sha256"] == sha(log),
                  "command output bytes changed: " + name)
        check(result["command"]["cleanup_complete"]
              and not result["command"]["poisoned"],
              "incomplete command cleanup: " + name)
        event = result["command"]
        minima = reference.COMMAND_CONTRACT
        if event["cleanup"] == "not_required":
            check(event["primary_events"] == event["cleanup_events"] ==
                  event["reap_events"] == event["descendants"]["observed"] == 0,
                  "unexpected no-child cleanup events: " + name)
        else:
            check(event["cleanup"] == "complete",
                  "incomplete command cleanup: " + name)
            if event["primary_events"] == 0:
                minimum_cleanup = minima["pre_release_cleanup_events_min"]
            else:
                check(event["primary_events"] >= minima["complete_primary_events_min"],
                      "too few primary events: " + name)
                minimum_cleanup = minima["complete_cleanup_events_min"]
            check(event["cleanup_events"] >= minimum_cleanup
                  and event["reap_events"] == event["descendants"]["observed"] + 2,
                  "incomplete command events: " + name)
        timing = result["command"]["timing"]
        started, primary, completed = (
            timing["started_ns"], timing["primary_completed_ns"],
            timing["completed_ns"])
        deadline = request["primary_deadline_ns"]
        check(request["primary_deadline_ns"] == request["issued_ns"] +
              request["timeout_ns"]
              and request["cleanup_deadline_ns"] == deadline +
              reference.COMMAND_CLEANUP_SECONDS * 1_000_000_000
              and started <= primary <= completed
              and (primary >= deadline) == (
                  result["command"]["primary"]["kind"] == "timeout")
              and timing["primary_elapsed_ns"] == primary - started
              and timing["cleanup_elapsed_ns"] == completed - primary
              and timing["total_elapsed_ns"] == completed - started,
              "command deadline relationship changed: " + name)
    retained = {}
    for slot in ("private", "fixtures", "package", "public-source",
                 *(f"boot-{mode}" for mode in MODES)):
        directory = compute / slot
        if not directory.exists():
            continue
        private(directory)
        for path in directory.rglob("*"):
            check(len(retained) < 10000, "retained output entry limit exceeded")
            info = path.lstat()
            check(stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode),
                  "retained output is not an ordinary file or directory")
            relative = path.relative_to(compute).as_posix()
            retained[relative] = (
                "directory" if stat.S_ISDIR(info.st_mode) else "file",
                stat.S_IMODE(info.st_mode),
                None if stat.S_ISDIR(info.st_mode) else info.st_size,
            )
    artifacts = {}
    for label, path in {
        "config": reference.APP / ".config",
        "efi": reference.APP / "build" / reference.EFI,
        "raw": compute / "package/unikraft.raw",
        "qcow2": compute / "package/unikraft.qcow2",
        "vhd": compute / "package/unikraft-derived.vhd",
    }.items():
        if path.exists():
            check(path.is_file() and not path.is_symlink(), "unsafe artifact")
            artifacts[label] = (path.stat().st_size, identity(path),
                                stat.S_IMODE(path.stat().st_mode))
    return {"order": ordered, "records": records, "retained": retained,
            "artifacts": artifacts}


class Normalizer:
    """Normalize only documented physical metadata and path roots, not content."""

    def __init__(self, roots):
        self.roots = tuple(str(p) for p in roots)
        self.seen = {}

    def token(self, kind, value):
        check(type(value) is int, "nondeterministic field not an integer")
        names = self.seen.setdefault(kind, {})
        if value not in names:
            names[value] = f"<{kind}:{len(names)}>"
        return names[value]

    def normalize(self, value, key="", path=()):
        if isinstance(value, dict):
            normalized = {name: self.normalize(item, name, (*path, name)) for name, item
                    in sorted(value.items())}
            if "device_major" in value and "device_minor" in value:
                check(type(value["device_major"]) is int and
                      type(value["device_minor"]) is int, "invalid device identity")
                normalized["device_major"] = self.token(
                    "device", os.makedev(value["device_major"], value["device_minor"]))
                normalized["device_minor"] = "<device-minor-component>"
            for prefix in ("mtime", "ctime"):
                seconds, nanos = prefix + "_seconds", prefix + "_nanoseconds"
                if seconds in value and nanos in value:
                    check(type(value[seconds]) is int and type(value[nanos]) is int
                          and 0 <= value[nanos] < 1_000_000_000,
                          "invalid physical timestamp")
                    normalized[seconds] = self.token(
                        prefix, value[seconds] * 1_000_000_000 + value[nanos])
                    normalized[nanos] = "<nanoseconds-component>"
            if "physical_closure_sha256" in value and key in (
                    "source_map", "runtime_map"):
                domain = "uk.wamr.command-supervisor-" + (
                    "source" if key == "source_map" else "runtime") + "-v1"
                expected = oracle().guarded_record_map(domain, value["records"])
                check(expected == value, "invalid physical closure recipe")
                normalized["physical_closure_sha256"] = "<verified-physical-closure>"
            return normalized
        if isinstance(value, list):
            if key == "metadata" and len(value) == 9 and all(
                    type(item) is int for item in value):
                return [
                    self.token("device", value[0]),
                    self.token("inode", value[1]),
                    *value[2:7],
                    self.token("mtime", value[7]),
                    self.token("ctime", value[8]),
                ]
            return [self.normalize(item, key, path) for item in value]
        if key in ("issued_ns", "started_ns", "primary_completed_ns",
                   "completed_ns", "primary_deadline_ns", "cleanup_deadline_ns"
                   ) and ("timing" in path or "request" in path):
            return self.token("monotonic-ns", value)
        if key in ("primary_elapsed_ns", "cleanup_elapsed_ns", "total_elapsed_ns"
                   ) and "timing" in path:
            check(type(value) is int and value >= 0, "invalid elapsed time")
            return "<elapsed-positive>" if value else "<elapsed-zero>"
        if key in ("primary_events", "cleanup_events") and "command" in path:
            check(type(value) is int and value >= 0, "invalid event count")
            return "<event-positive>" if value else "<event-zero>"
        if key in ("pid", "parent_pid") and "command" in path:
            return self.token("pid", value)
        for field in ("inode", "device_major", "device_minor",
                      "mtime_seconds", "mtime_nanoseconds",
                      "ctime_seconds", "ctime_nanoseconds"):
            if key == field:
                return self.token(field, value)
        if isinstance(value, str) and key not in (
                "argv", "environment", "value", "relative", "stage",
                "mode", "profile", "schema", "sha256", "content_sha256"):
            for index, prefix in sorted(enumerate(self.roots),
                                        key=lambda entry: len(entry[1]),
                                        reverse=True):
                if value == prefix or value.startswith(prefix + "/"):
                    return f"<root:{index}>" + value[len(prefix):]
        return value


def native_fixture_contract(reference):
    check(tuple(reference.HOST_TOOLS) == FROZEN_HOST_TOOLS,
          "fixtures native reviewed host-tool set changed")
    path = reference.command_path
    literal = reference.command_literal
    environment = {
        "HOME": path("work", "private"),
        "LANG": literal("C"),
        "LC_ALL": literal("C"),
        "PATH": literal("/usr/bin:/bin"),
        "PYTHONDONTWRITEBYTECODE": literal("1"),
        "TMPDIR": path("work", "scratch"),
        "WAMR_CI_GIT": path("tool:git"),
        "WAMR_CI_SUPERVISOR": path("command-supervisor"),
        "BISON_PKGDATADIR": path("runtime", "bison"),
        "KCONFIG_CONFIG": path("source", "support/apps/wamr-aot/build/.config"),
        "KCONFIG_OVERWRITECONFIG": literal("1"),
        "M4": path("tool:m4"),
        "MAKEFLAGS": literal("-j2"),
        "ZIG_GLOBAL_CACHE_DIR": path("work", "global-cache"),
        "ZIG_LIB_DIR": path("tool-tree:zig", "lib"),
        "ZIG_LOCAL_CACHE_DIR": path("work", "cache"),
        "WAMR_CI_PACKAGE": path("work", "tools/bin/wamr-ci-package"),
        "WAMR_CI_PYTHON": path("tool:python3"),
        "WAMR_CI_LOG_VALIDATE": path("native:wamr-log-validate"),
        "WAMR_CI_SUPERVISOR_FIXTURE":
            path("work", "tools/bin/wamr-ci-supervisor-fixture"),
    }
    for name in FROZEN_HOST_TOOLS:
        environment["WAMR_CI_TOOL_" + name.upper().replace("-", "_")] = (
            path("tool:" + name))
    retained = {
        "M4", "WAMR_CI_GIT", "WAMR_CI_SUPERVISOR", "WAMR_CI_PYTHON",
        "WAMR_CI_LOG_VALIDATE",
        *("WAMR_CI_TOOL_" + name.upper().replace("-", "_")
          for name in FROZEN_HOST_TOOLS),
    }
    executable = path("native:wamr-native-ci-fixtures")
    return {
        "kind": "build-fixtures",
        "seconds": 600,
        "output_limit": 8 * 1024 * 1024,
        "command_executable": executable,
        "native_executable": executable,
        "interpreter": None,
        "argv": [
            executable, literal("--fixture-root"), path("work", "fixtures"),
        ],
        "environment": [
            {"name": name, "value": environment[name]}
            for name in sorted(environment)
        ],
        "retained_names": sorted(retained),
        "cwd": path("source"),
        "limits": {
            "cleanup_events": 1_000_000,
            "descendants": 64,
            "primary_events": 1_000_000,
            "proc_entries_per_scan": 262_144,
            "reap_events": 512,
            "stderr_bytes": 4 * 1024 * 1024,
            "stdout_bytes": 4 * 1024 * 1024,
            "term_grace_ms": 1000,
        },
    }


SHARED_BUILD_STAGES = ("prepare", "config", "native-image")


def native_build_command_contract(reference, stage):
    check(stage in ("adapter", "local-boot-tool"),
          "unknown native build command stage")
    fixture = native_fixture_contract(reference)
    path, literal = reference.command_path, reference.command_literal
    build_file = ("support/build/wamr-native-ci/build.zig"
                  if stage == "adapter" else
                  "support/tools/hyperv/local_boot/build.zig")
    prefix = "tools" if stage == "adapter" else "local-boot-tools"
    environment = {
        item["name"]: item["value"] for item in fixture["environment"]
        if item["name"] not in (
            "WAMR_CI_PACKAGE", "WAMR_CI_PYTHON", "WAMR_CI_LOG_VALIDATE",
            "WAMR_CI_SUPERVISOR_FIXTURE")
    }
    environment["WAMR_CI_LAUNCH_EXECUTABLE"] = path("tool:zig")
    retained = {
        "M4", "WAMR_CI_GIT", "WAMR_CI_SUPERVISOR",
        "WAMR_CI_LAUNCH_EXECUTABLE",
        *("WAMR_CI_TOOL_" + name.upper().replace("-", "_")
          for name in FROZEN_HOST_TOOLS),
    }
    argv = [
        path("tool:zig"), literal("build"), literal("--build-file"),
        path("source", build_file), literal("--system"),
        path("work", "dependencies/zig-pkg"), literal("--prefix"),
        path("work", prefix), literal("-Doptimize=ReleaseSafe"),
        literal("-j2"),
    ]
    if stage == "adapter":
        argv.append(literal("test-unit"))
    argv.append(literal("install"))
    return {
        "kind": "build-base", "seconds": 900,
        "output_limit": 8 * 1024 * 1024,
        "command_executable": path("tool:zig"),
        "native_executable": path("tool:zig"),
        "interpreter": None, "argv": argv,
        "environment": [
            {"name": name, "value": environment[name]}
            for name in sorted(environment)
        ],
        "retained_names": sorted(retained), "cwd": path("source"),
        "limits": fixture["limits"],
    }


def reviewed_build_command_contract(reference, side, stage):
    if side == "python" or stage in SHARED_BUILD_STAGES:
        return reference.production_command_contract(stage)
    if stage == "fixtures":
        return native_fixture_contract(reference)
    return native_build_command_contract(reference, stage)


def checked_stage(record, log, side, reference, stage, seen=None):
    check(side in ("python", "native")
          and stage in REVIEWED_BUILD_COMMANDS,
          "unknown supervised build-stage side")
    contract = reviewed_build_command_contract(reference, side, stage)
    label = f"{stage} {side}"
    check(record["scope"] == "command_diagnostic_not_acceptance"
          and record["stage"] == stage, f"{label} stage/scope changed")
    check(record["exit_code"] == 0 and record["over_limit"] is False
          and record["known_error_markers"] == [],
          f"{label} stage outcome changed")
    check(record["bytes"] == len(log) and record["sha256"] == sha(log)
          and record["sha256_scope"] == reference.command_digest_scope(len(log)),
          f"{label} private log hash/size changed")
    request = record["supervisor"]["request"]
    for field in ("argv", "environment", "cwd"):
        check(request[field] == contract[field],
              f"{label} {field} changed")
    for field in ("command_executable", "native_executable"):
        check(request[field]["path"] == contract[field],
              f"{label} {field} role changed")
    check((request["interpreter"] is None if contract["interpreter"] is None
           else request["interpreter"]["path"] == contract["interpreter"]),
          f"{label} interpreter changed")
    check(request["stage"] == stage
          and request["supervisor"]["path"] == reference.command_path(
              "command-supervisor")
          and request["timeout_ns"] == contract["seconds"] * 1_000_000_000
          and request["limits"] == contract["limits"],
          f"{label} stage/deadline/limits changed")
    check([item["name"] for item in request["retained_executables"]]
          == contract["retained_names"],
          f"{label} retained executable roles changed")
    command_result = record["supervisor"]["result"]["command"]
    stdout, stderr = command_result["stdout"], command_result["stderr"]
    check(command_result["output"]["commitment_sha256"] ==
          reference.command_output_commitment(
              stdout["bytes"], stdout["sha256"],
              stderr["bytes"], stderr["sha256"]),
          f"{label} output commitment changed")
    check(command_result["output"]["bytes"] == len(log)
          and command_result["output"]["combined_sha256"] == sha(log)
          and command_result["cleanup"] == "complete"
          and command_result["cleanup_complete"] is True
          and command_result["poisoned"] is False,
          f"{label} output/cleanup changed")
    role_identities = None
    if seen is not None:
        runtime = seen["roots"][0]
        baseline = seen["files"]["records"]["build-start.json"][1]
        pinned = baseline["consumer_inputs"]["files"]
        roles = (
            request["supervisor"], request["native_executable"],
            request["command_executable"],
            *(() if request["interpreter"] is None else (request["interpreter"],)),
            *request["retained_executables"],
        )
        role_identities = {}
        for binding in roles:
            role = binding["path"]["role"]
            check(role in pinned, f"{label} missing pinned role: {role}")
            captured = pinned[role]
            physical, _ = reference.physical_file_record(Path(captured["path"]))
            check(physical == captured
                  and binding["identity"] ==
                  reference.native_executable_identity(captured),
                  f"{label} executable identity changed: {role}")
            role_identities[role] = binding["identity"]
        supervisor_path = (runtime / "compute/supervisor/bin/wamr-ci-supervisor"
                           if side == "python" else
                           runtime / "controller/bin/uk-wamr-native-ci")
        check(pinned["command-supervisor"]["path"] == str(supervisor_path),
              f"{label} supervisor location changed")
        if side == "native" and stage == "fixtures":
            check(pinned["native:wamr-native-ci-fixtures"]["path"] ==
                  str(runtime / "compute/tools/bin/wamr-native-ci-fixtures"),
                  "fixtures native executable location changed")
    try:
        if side == "python":
            reference.validate_supervised_command_binding(
                record, stage, role_identities)
        else:
            original = reference.production_command_contract
            reference.production_command_contract = (
                lambda stage, profile=reference.CURRENT_PROFILE:
                contract if stage == record["stage"] else original(stage, profile))
            try:
                reference.validate_supervised_command_binding(
                    record, stage, role_identities)
            finally:
                reference.production_command_contract = original
    except reference.Refusal as error:
        raise ParityError(
            f"{label} supervised binding refused: {error}") from error
    return {
        "scope": record["scope"],
        "stage": record["stage"],
        "exit_code": record["exit_code"],
        "over_limit": record["over_limit"],
        "known_error_markers": record["known_error_markers"],
        "primary": command_result["primary"],
        "termination": command_result["termination"],
        "cleanup": command_result["cleanup"],
        "cleanup_complete": command_result["cleanup_complete"],
        "poisoned": command_result["poisoned"],
        "stdout_status": stdout["status"],
        "stderr_status": stderr["status"],
        "primary_deadline_reached": command_result["primary_deadline_reached"],
        "cancellation_observed": command_result["cancellation_observed"],
    }


def fixture_stage(record, log, side, reference, seen=None):
    return checked_stage(record, log, side, reference, "fixtures", seen)


def verified_supervisor_source_map(reference, value, side):
    names = (reference.SUPERVISOR_SOURCE_FILES if side == "python"
             else NATIVE_SOURCE_FILES)
    if side == "native":
        embedded = (reference.REPO / "support/controller_source_closure.zig"
                    ).read_text()
        declared = re.findall(r'\.name = "([^"]+)", \.content = @embedFile\(',
                              embedded)
        check(tuple(declared) == NATIVE_SOURCE_FILES,
              "build-start native controller source closure membership changed")
    records = {}
    for name in names:
        pinned, _ = reference.tracked_manifest(name)
        records[name] = {
            "bytes": pinned["bytes"], "sha256": pinned["sha256"],
            "metadata": pinned["metadata"],
        }
    expected = reference.guarded_record_map(
        "uk.wamr.command-supervisor-source-v1", records)
    check(value == expected,
          f"build-start {side} supervisor source closure/record changed")
    return records


def verified_supervisor_runtime_map(reference, value, side, runtime, files):
    executable = (runtime / "compute/supervisor/bin/wamr-ci-supervisor"
                  if side == "python" else
                  runtime / NATIVE_CONSUMER_ROLES["command-supervisor"])
    check(files["command-supervisor"]["path"] == str(executable),
          f"build-start {side} supervisor executable path changed")
    paths = {"executable": files["command-supervisor"]}
    for physical_path in reference.executable_runtime_paths(executable):
        role = "runtime:" + str(physical_path)
        check(role in files,
              f"build-start {side} supervisor loader role missing: {role}")
        paths[role] = files[role]
    records = {
        name: {
            "bytes": item["metadata"][6], "sha256": item["sha256"],
            "metadata": item["metadata"],
        }
        for name, item in paths.items()
    }
    expected = reference.guarded_record_map(
        "uk.wamr.command-supervisor-runtime-v1", records)
    check(value == expected,
          f"build-start {side} supervisor runtime closure/record changed")
    return records


def verified_consumer_inputs(reference, value, side, runtime):
    file_paths, tree_paths = reference.discover_consumer_input_paths(runtime)
    if side == "python":
        check(file_paths.get("command-supervisor") ==
              runtime / "compute/supervisor/bin/wamr-ci-supervisor",
              "build-start python supervisor role missing")
    else:
        check("command-supervisor" not in file_paths,
              "build-start native substituted Python supervisor")
        for role, relative in NATIVE_CONSUMER_ROLES.items():
            path = runtime / relative
            check(role not in file_paths or file_paths[role] == path,
                  f"build-start native role substituted: {role}")
            file_paths[role] = path
            if role != "wamr-source-archive":
                for dependency in reference.executable_runtime_paths(path):
                    file_paths["runtime:" + str(dependency)] = dependency
    check(set(value) == {
        "schema", "version", "files", "trees", "directories", "aggregate_sha256",
    }, f"build-start {side} consumer input shape changed")
    check(value == reference.record_input_paths(
        file_paths, tree_paths, expected=value),
        f"build-start {side} consumer physical custody changed")
    return value["files"], value["trees"]


def verified_build_start_side(seen, side):
    reference = seen["reference"]
    runtime, repository = seen["roots"]
    check(reference.REPO == repository and side in ("python", "native"),
          "build-start reference/source mismatch")
    value = seen["files"]["records"]["build-start.json"][1]
    check(set(value) == {
        "source", "source_custody", "tools", "bison_data",
        "dependencies", "consumer_inputs", "command_supervisor",
    }, f"build-start {side} top-level fields changed")
    source = reference.source(repository)
    check(value["source"] == {
        "revision": source["revision"], "tree": source["tree"]}
          and value["source_custody"] == source["custody"],
          f"build-start {side} source custody changed")
    check(tuple(reference.HOST_TOOLS) == FROZEN_HOST_TOOLS
          and set(value["tools"]) == set(FROZEN_HOST_TOOLS),
          f"build-start {side} tool roles changed")
    for name in FROZEN_HOST_TOOLS:
        check(value["tools"][name] == reference.digest(
            Path(reference.tool(name))),
            f"build-start {side} tool content changed: {name}")
    check(value["bison_data"] == reference.bison_inputs(runtime / "bison"),
          f"build-start {side} Bison content changed")
    check(value["dependencies"] == reference.dependency_custody(
        runtime / "compute"), f"build-start {side} dependency custody changed")
    files, trees = verified_consumer_inputs(
        reference, value["consumer_inputs"], side, runtime)
    supervisor = value["command_supervisor"]
    check(set(supervisor) == {
        "schema", "version", "protocol", "source_map", "runtime_map",
    } and supervisor["schema"] == "uk.wamr.command-supervisor"
          and supervisor["version"] == 1
          and supervisor["protocol"] ==
          "uk.wamr.command-supervisor/1 process-command/1",
          f"build-start {side} supervisor contract changed")
    sources = verified_supervisor_source_map(
        reference, supervisor["source_map"], side)
    runtimes = verified_supervisor_runtime_map(
        reference, supervisor["runtime_map"], side, runtime, files)
    return {
        "record": value, "files": files, "trees": trees,
        "source_files": sources, "runtime_files": runtimes,
    }


def compare_build_start(left, right):
    python = verified_build_start_side(left, "python")
    native = verified_build_start_side(right, "native")
    a, b = python["record"], native["record"]
    failures = []

    def equal(field, first, second):
        if first != second:
            failures.append("record_content:build-start.json." + field)

    equal("source", a["source"], b["source"])
    for field in ("schema", "version", "object_format", "files", "directories",
                  "bytes", "content_sha256", "role_excluded_outputs"):
        equal("source_custody." + field,
              a["source_custody"][field], b["source_custody"][field])
    equal("tools", a["tools"], b["tools"])
    equal("bison_data", a["bison_data"], b["bison_data"])
    a_dep, b_dep = a["dependencies"], b["dependencies"]
    check(set(a_dep) == set(b_dep) == {
        "schema", "version", "request", "source_manifests",
        "restore_directory", "restore", "packages",
    }, "build-start dependency field membership changed")
    for field in ("schema", "version", "request", "restore"):
        equal("dependencies." + field, a_dep[field], b_dep[field])
    equal("dependencies.source_manifests.membership",
          sorted(a_dep["source_manifests"]),
          sorted(b_dep["source_manifests"]))
    for name in a_dep["source_manifests"].keys() & b_dep["source_manifests"].keys():
        one, two = (item["source_manifests"][name] for item in (a_dep, b_dep))
        for field in ("path", "mode", "bytes", "sha256", "git_oid"):
            equal(f"dependencies.source_manifests.{name}.source.{field}",
                  one["source"][field], two["source"][field])
        for field in ("bytes", "sha256"):
            equal(f"dependencies.source_manifests.{name}.copy.{field}",
                  one["copy"][field], two["copy"][field])
    equal("dependencies.packages.roots",
          a_dep["packages"]["roots"], b_dep["packages"]["roots"])
    for key in ("files", "directories", "bytes", "manifests",
                "hash_verification"):
        equal("dependencies.packages." + key,
              a_dep["packages"][key], b_dep["packages"][key])
    a_packages = a_dep["packages"]["records"]
    b_packages = b_dep["packages"]["records"]
    equal("dependencies.packages.package_hashes",
          [item["package_hash"] for item in a_packages],
          [item["package_hash"] for item in b_packages])
    for index, (one, two) in enumerate(zip(a_packages, b_packages)):
        for field in ("tree_sha256", "files", "directories", "bytes"):
            equal(f"dependencies.packages.records[{index}].content.{field}",
                  one["content"][field], two["content"][field])
        equal(f"dependencies.packages.records[{index}].manifest",
              one["manifest"], two["manifest"])
    for role in sorted(python["files"].keys() & native["files"].keys()):
        if role == "command-supervisor":
            continue
        one, two = python["files"][role], native["files"][role]
        equal("consumer_inputs.files." + role + ".sha256",
              one["sha256"], two["sha256"])
        equal("consumer_inputs.files." + role + ".stable_metadata",
              one["metadata"][2:7], two["metadata"][2:7])
        if one["path"] != two["path"]:
            equal("consumer_inputs.files." + role + ".path",
                  Normalizer(left["roots"]).normalize({"path": one["path"]}),
                  Normalizer(right["roots"]).normalize({"path": two["path"]}))
    for role in sorted(python["trees"].keys() & native["trees"].keys()):
        one, two = python["trees"][role], native["trees"][role]
        for field in ("content_sha256", "files", "directories",
                      "symlinks", "bytes"):
            equal("consumer_inputs.trees." + role + "." + field,
                  one[field], two[field])
        equal("consumer_inputs.trees." + role + ".path",
              Normalizer(left["roots"]).normalize({"path": one["path"]}),
              Normalizer(right["roots"]).normalize({"path": two["path"]}))
    for name in sorted(python["source_files"].keys() &
                       native["source_files"].keys()):
        equal("command_supervisor.source_map.records." + name + ".sha256",
              python["source_files"][name]["sha256"],
              native["source_files"][name]["sha256"])
    for name in sorted(python["runtime_files"].keys() &
                       native["runtime_files"].keys()):
        if name != "executable":
            equal("command_supervisor.runtime_map.records." + name + ".sha256",
                  python["runtime_files"][name]["sha256"],
                  native["runtime_files"][name]["sha256"])
    return failures


LOCAL_BOOT_TOOL = "uk-hyperv-local-boot"


def local_boot_install_path(runtime, side):
    check(side in ("python", "native"), "unknown local-boot install side")
    prefix = "tools" if side == "python" else "local-boot-tools"
    return runtime / "compute" / prefix / "bin" / LOCAL_BOOT_TOOL


def verified_local_boot_install(seen, side):
    reference = seen["reference"]
    runtime, repository = seen["roots"]
    check(reference.REPO == repository, "local-boot source binding changed")
    path = local_boot_install_path(runtime, side)
    other = local_boot_install_path(
        runtime, "native" if side == "python" else "python")
    check(not other.exists() and not other.is_symlink(),
          f"{side} local-boot executable substituted")
    record, _ = reference.physical_file_record(path)
    metadata = record["metadata"]
    check(record["path"] == str(path)
          and metadata[3] == os.getuid()
          and stat.S_ISREG(metadata[2]) and metadata[2] & 0o111,
          f"{side} local-boot executable location/mode changed")
    return record


def compare_local_boot_installs(left, right):
    installs = (
        verified_local_boot_install(left, "python"),
        verified_local_boot_install(right, "native"),
    )
    failures = []
    if installs[0]["sha256"] != installs[1]["sha256"]:
        failures.append("local_boot_install:sha256")
    if installs[0]["metadata"][2:7] != installs[1]["metadata"][2:7]:
        failures.append("local_boot_install:stable_metadata")
    return installs, failures


def verified_log_validator(seen):
    reference = seen["reference"]
    runtime, repository = seen["roots"]
    path = runtime / "compute/tools/bin/uk-wamr-log-validate"
    pinned = seen["files"]["records"]["build-start.json"][1][
        "consumer_inputs"]["files"].get("native:wamr-log-validate")
    physical, _ = reference.physical_file_record(path)
    check(reference.REPO == repository and isinstance(pinned, dict)
          and pinned == physical
          and pinned["path"] == str(path)
          and stat.S_ISREG(pinned["metadata"][2])
          and pinned["metadata"][2] & 0o111
          and pinned["metadata"][3] == os.getuid(),
          "boot log validator physical role/path/identity changed")
    return physical


def verified_boot_inputs(seen, side, local_boot):
    reference = seen["reference"]
    runtime, repository = seen["roots"]
    value = seen["files"]["records"]["boot-inputs.json"][1]
    paths = {
        "package_tool": runtime / "compute/tools/bin/wamr-ci-package",
        "local_boot_tool": local_boot_install_path(runtime, side),
        "qemu": runtime / "bin/qemu-system-x86_64",
        "ovmf_code": runtime / "firmware/code.fd",
        "ovmf_vars": runtime / "firmware/vars.fd",
        "efi": reference.APP / "build" / reference.EFI,
    }
    if side == "native":
        paths["log_validator"] = (
            runtime / "compute/tools/bin/uk-wamr-log-validate")
    check(reference.REPO == repository
          and value["files"]["local_boot_tool"] == local_boot,
          f"{side} boot local-boot executable custody changed")
    if side == "native":
        check(value["files"].get("log_validator") == verified_log_validator(seen),
              "native boot log validator role/identity changed")
    else:
        check("log_validator" not in value["files"],
              "Python boot gained native log validator role")
    check(reference.boot_input_state(runtime, paths, expected=value) == value,
          f"{side} boot input physical custody changed")
    return value


def compare_boot_inputs(left, right, local_boots):
    first = verified_boot_inputs(left, "python", local_boots[0])
    second = verified_boot_inputs(right, "native", local_boots[1])
    failures = []

    def equal(field, a, b):
        if a != b:
            failures.append("record_content:boot-inputs.json." + field)

    for field in ("schema", "version"):
        equal(field, first[field], second[field])
    first_files, second_files = first["files"], second["files"]
    equal("files.membership", sorted(first_files),
          sorted(second_files.keys() - {"log_validator"}))
    python_validator = verified_log_validator(left)
    native_validator = verified_log_validator(right)
    equal("files.log_validator.sha256",
          python_validator["sha256"], native_validator["sha256"])
    equal("files.log_validator.stable_metadata",
          python_validator["metadata"][2:7],
          native_validator["metadata"][2:7])
    for role in sorted(first_files.keys() & second_files.keys()):
        a, b = first_files[role], second_files[role]
        equal("files." + role + ".sha256", a["sha256"], b["sha256"])
        equal("files." + role + ".stable_metadata",
              a["metadata"][2:7], b["metadata"][2:7])
        if role != "local_boot_tool":
            equal("files." + role + ".path",
                  Normalizer(left["roots"]).normalize({"path": a["path"]}),
                  Normalizer(right["roots"]).normalize({"path": b["path"]}))
    first_trees, second_trees = first["trees"], second["trees"]
    equal("trees.membership", sorted(first_trees), sorted(second_trees))
    for role in sorted(first_trees.keys() & second_trees.keys()):
        a, b = first_trees[role], second_trees[role]
        for field in ("files", "directories", "symlinks", "bytes",
                      "content_sha256"):
            equal("trees." + role + "." + field, a[field], b[field])
        equal("trees." + role + ".path",
              Normalizer(left["roots"]).normalize({"path": a["path"]}),
              Normalizer(right["roots"]).normalize({"path": b["path"]}))
    return failures


ACCEPTANCE_FIELDS = frozenset({
    "schema", "schema_version", "profile", "status", "source",
    "accepted_qcow2", "finalization_sha256", "modes", "boots",
    "build_sha256", "boot_inputs_sha256",
})


def verified_qcow2_acceptance(seen):
    reference = seen["reference"]
    records = seen["files"]["records"]
    raw, value = records["qcow2-acceptance.json"]
    boot_raw, boot = records["boot-inputs.json"]
    check(parsed(raw, reference) == value
          and set(value) == ACCEPTANCE_FIELDS
          and value["schema"] == "uk.wamr.compute-qcow2-acceptance"
          and value["schema_version"] == 1
          and value["profile"] == reference.CURRENT_PROFILE
          and value["status"] == "accepted"
          and value["modes"] == list(reference.SIX_MODES[:4]),
          "qcow2 acceptance field/shape changed")
    check(parsed(boot_raw, reference) == boot
          and value["boot_inputs_sha256"] == sha(boot_raw),
          "qcow2 acceptance boot-input byte commitment changed")
    return value


def compare_qcow2_acceptance(left, right):
    first = verified_qcow2_acceptance(left)
    second = verified_qcow2_acceptance(right)
    first = dict(first, boot_inputs_sha256="<verified-own-boot-input-bytes>")
    second = dict(second, boot_inputs_sha256="<verified-own-boot-input-bytes>")
    a = Normalizer(left["roots"]).normalize(first)
    b = Normalizer(right["roots"]).normalize(second)
    return [
        "record_content:qcow2-acceptance.json." + field
        for field in sorted(ACCEPTANCE_FIELDS - {"boot_inputs_sha256"})
        if a[field] != b[field]
    ]


REVIEWED_BUILD_COMMANDS = (
    "adapter", "local-boot-tool", "fixtures", *SHARED_BUILD_STAGES,
)


def compare_observations(left, right, reviewed_build_compat=False):
    failures = []
    for key in ("returncode",):
        if getattr(left["exit"], key) != getattr(right["exit"], key):
            failures.append(key)
    if category(left["exit"]) != category(right["exit"]):
        failures.append("refusal_category")
    l_records, r_records = left["files"]["records"], right["files"]["records"]
    proven = (reviewed_build_compat
              and "build-start.json" in l_records
              and "build-start.json" in r_records)
    if proven:
        failures.extend(compare_build_start(left, right))
    checked_commands = {}
    for stage in REVIEWED_BUILD_COMMANDS:
        name = f"command-{stage}.json"
        if proven and name in l_records and name in r_records:
            checked_commands[stage] = (
                checked_stage(l_records[name][1], left["files"]["command_logs"][stage],
                              "python", left["reference"], stage, left),
                checked_stage(r_records[name][1], right["files"]["command_logs"][stage],
                              "native", right["reference"], stage, right),
            )
    local_boots = None
    checked_acceptance = False
    if "local-boot-tool" in checked_commands:
        local_boots, install_failures = compare_local_boot_installs(left, right)
        failures.extend(install_failures)
        if "boot-inputs.json" in l_records and "boot-inputs.json" in r_records:
            failures.extend(compare_boot_inputs(left, right, local_boots))
            if ("qcow2-acceptance.json" in l_records
                    and "qcow2-acceptance.json" in r_records):
                failures.extend(compare_qcow2_acceptance(left, right))
                checked_acceptance = True
    for key in ("order", "retained"):
        left_value, right_value = left["files"][key], right["files"][key]
        if key == "retained" and checked_commands:
            def verified_log_slots(side):
                entries = dict(side["files"]["retained"])
                for stage in checked_commands:
                    name = f"private/{stage}.log"
                    check(name in entries and entries[name][:2] == ("file", 0o600)
                          and entries[name][2] ==
                          len(side["files"]["command_logs"][stage]),
                          f"{stage} private log slot changed")
                    entries[name] = ("file", 0o600, "<verified-stage-log-size>")
                return entries
            left_value, right_value = verified_log_slots(left), verified_log_slots(right)
        if left_value != right_value:
            failures.append(key)
    left_artifacts = left["files"]["artifacts"]
    right_artifacts = right["files"]["artifacts"]
    roles = {"config", "efi", "raw", "qcow2", "vhd"}
    check(left_artifacts.keys() <= roles and right_artifacts.keys() <= roles,
          "invalid artifact comparison roles")
    if left_artifacts.keys() != right_artifacts.keys():
        failures.append("artifacts:membership")
    for role in ("config", "efi", "raw", "qcow2", "vhd"):
        if role not in left_artifacts or role not in right_artifacts:
            continue
        one, two = left_artifacts[role], right_artifacts[role]
        check(len(one) == len(two) == 3, "invalid artifact comparison shape")
        for index, field in enumerate(("bytes", "sha256", "mode")):
            if one[index] != two[index]:
                failures.append(f"artifacts:{role}.{field}")
    if l_records.keys() != r_records.keys():
        failures.append("evidence_membership")
    left_normalizer, right_normalizer = Normalizer(left["roots"]), Normalizer(right["roots"])
    for name in (record for record in ORDER if record in l_records and record in r_records):
        if ((name == "build-start.json" and proven)
                or (name == "boot-inputs.json" and local_boots is not None)
                or (name == "qcow2-acceptance.json" and checked_acceptance)):
            continue
        stage = name.removeprefix("command-").removesuffix(".json")
        if name == f"command-{stage}.json" and stage in checked_commands:
            python, native = checked_commands[stage]
            for field in python:
                if python[field] != native[field]:
                    failures.append(f"{stage}_outcome:" + field)
            continue
        a, b = l_records[name], r_records[name]
        a_value, b_value = a[1], b[1]
        if name == "result.json":
            a_value = dict(a_value, records={record: "<verified-file-sha256>"
                                             for record in a_value["records"]})
            b_value = dict(b_value, records={record: "<verified-file-sha256>"
                                             for record in b_value["records"]})
        if left_normalizer.normalize(a_value) != right_normalizer.normalize(b_value):
            failures.append("record_content:" + name)
        if a[0] != b[0] and a[1] == b[1]:
            failures.append("record_bytes:" + name)
    return failures


def observed(result, runtime, repository):
    reference = oracle(repository)
    files = phase_snapshot(runtime, reference)
    files["command_logs"] = {}
    for stage in REVIEWED_BUILD_COMMANDS:
        if f"command-{stage}.json" in files["records"]:
            files["command_logs"][stage] = checked_file(
                runtime / "compute/private" / f"{stage}.log", 8 * 1024 * 1024)
    return {"exit": result, "files": files, "roots": (runtime, repository),
            "reference": reference}


def compare_pair(python, native, py_runtime, native_runtime, py_repo, native_repo,
                 reviewed_build_compat=False):
    failures = compare_observations(
        observed(python, py_runtime, py_repo),
        observed(native, native_runtime, native_repo), reviewed_build_compat)
    return failures


DECLARED_INVALID_CLI = frozenset({
    "relative-runtime", "duplicate-runtime", "boot-with-build-source",
})
STRICT_CLI = {
    "no-kvm": ((1, "refused"), (1, "refused")),
    "unknown-profile": ((2, "usage"), (2, "usage")),
    "unknown-command": ((2, "usage"), (2, "usage")),
}


def cli_vector_failures(label, python, native):
    check(label in DECLARED_INVALID_CLI or label in STRICT_CLI,
          "unknown CLI compatibility vector")
    observed_pair = (
        (python["exit"].returncode, category(python["exit"])),
        (native["exit"].returncode, category(native["exit"])),
    )
    expected = (
        ((1, "refused"), (2, "usage"))
        if label in DECLARED_INVALID_CLI else STRICT_CLI[label]
    )
    failures = compare_observations(python, native)
    if observed_pair != expected:
        failures.append("wrong_cli_exit_or_category")
    if any(side["files"]["order"] or side["files"]["records"]
           for side in (python, native)):
        failures.append("cli_published_evidence")
    if label in DECLARED_INVALID_CLI and observed_pair == expected:
        check("returncode" in failures and "refusal_category" in failures,
              "declared CLI incompatibility was not observed")
        failures = [failure for failure in failures
                    if failure not in ("returncode", "refusal_category")]
    return failures


def no_kvm(host_command, root=PROJECT):
    check(platform.machine() != "x86_64" or not (
          Path("/dev/kvm").is_char_device()
          and os.access("/dev/kvm", os.R_OK | os.W_OK)),
          "local no-KVM vector requires a host without accessible x86 KVM")
    scratch = fixture_parent()
    parent = fresh(scratch, f"differential-no-kvm-{os.getpid()}")
    try:
        python_root, native_root = (fresh(parent, name)
                                    for name in ("python", "native"))
        prefix = fresh(parent, "host-cli")
        built = command([*host_command, "--prefix", str(prefix),
                         "-Doptimize=ReleaseSafe", "install"], root, seconds=180)
        check(built.returncode == 0, "native host-fixture build failed: " +
              built.stderr.decode("utf-8", "replace")[:1000])
        native_cli = prefix / "bin/uk-wamr-native-ci-host-differential"
        check(native_cli.is_file() and os.access(native_cli, os.X_OK),
              "missing native host-fixture CLI")
        vectors = (
            ("no-kvm", ("boot", "--runtime", "{runtime}")),
            ("unknown-profile", ("boot", "--runtime", "{runtime}",
                                 "--profile", "coremark")),
            ("unknown-command", ("azure", "--runtime", "{runtime}")),
            ("relative-runtime", ("boot", "--runtime", "relative")),
            ("duplicate-runtime", ("boot", "--runtime", "{runtime}",
                                   "--runtime", "{runtime}")),
            ("boot-with-build-source", ("boot", "--runtime", "{runtime}",
                                        "--wamr-source", "{runtime}")),
        )
        failures, categories = {}, {}
        for label, argv in vectors:
            py_args = [argument.replace("{runtime}", str(python_root))
                       for argument in argv]
            native_args = [argument.replace("{runtime}", str(native_root))
                           for argument in argv]
            py = command([sys.executable, "-B", str(CONTROLLER / "run.py"),
                          *py_args], root, seconds=90)
            native = command([str(native_cli), *native_args], root, seconds=120)
            categories[label] = (category(py), category(native))
            py_seen = observed(py, python_root, root)
            native_seen = observed(native, native_root, root)
            mismatches = cli_vector_failures(label, py_seen, native_seen)
            if (python_root / "compute").exists() or (native_root / "compute").exists():
                mismatches.append("cli_created_compute_output")
            if mismatches:
                failures[label] = mismatches
        return failures, categories
    finally:
        shutil.rmtree(parent)


def checked_repository(path):
    check(path.is_absolute() and path.resolve(strict=True) == path,
          "canonical worktree required")
    git = lambda *args: command(["git", "-C", str(path), *args],
                                 path, seconds=30)
    head = git("rev-parse", "HEAD")
    tree = git("rev-parse", "HEAD^{tree}")
    dirty = git("status", "--porcelain=v1", "--untracked-files=all")
    check(head.returncode == tree.returncode == dirty.returncode == 0
          and not dirty.stdout, "fresh clean Git worktree required")
    for relative in (".zig-cache", "support/apps/wamr-aot/.config",
                     "support/apps/wamr-aot/build"):
        check(not (path / relative).exists(), "prior source output refused")
    output_root = path / ".d"
    check(output_root.is_dir() and not output_root.is_symlink(),
          "precreated empty .d source output role required")
    private(output_root, empty=True)
    return head.stdout.strip(), tree.stdout.strip()


def copy_input_tree(template, destination):
    private(template)
    for name in ("bin", "firmware", "bison", "llvm"):
        source = template / name
        check(source.is_dir() and not source.is_symlink(),
              "missing real runtime input: " + name)
        shutil.copytree(source, destination / name, symlinks=True)
    required = (
        "bin/qemu-system-x86_64", "firmware/code.fd", "firmware/vars.fd",
    )
    for name in required:
        check((destination / name).is_file(), "missing pinned runtime input: " + name)


def manifest(root):
    entries = {}
    for base in ("bin", "firmware", "bison", "llvm"):
        for path in sorted((root / base).rglob("*")):
            name = path.relative_to(root).as_posix()
            info = path.lstat()
            mode = stat.S_IMODE(info.st_mode)
            if stat.S_ISLNK(info.st_mode):
                target = os.readlink(path)
                check(not Path(target).is_absolute()
                      and path.resolve(strict=True).is_relative_to(root),
                      "runtime template symlink escapes its private root")
                entries[name] = ("symlink", target)
            elif stat.S_ISREG(info.st_mode):
                entries[name] = ("file", mode, info.st_size, identity(path))
            elif stat.S_ISDIR(info.st_mode):
                entries[name] = ("directory", mode)
            else:
                raise ParityError("unsafe runtime template input")
            check(len(entries) <= 100000, "runtime input entry limit exceeded")
    return entries


def require_prior_build_output_refusal(python, native, py_runtime, native_runtime):
    for label, result, runtime in (
            ("python", python, py_runtime), ("native", native, native_runtime)):
        actual = category(result)
        check(result.returncode == 1 and actual == "failed_stage:startup",
              f"{label} occupied build root: expected failed_stage:startup/1, "
              f"got {actual}/{result.returncode}")
        for name in ("build.json", "result.json"):
            path = runtime / "compute/evidence" / name
            check(not path.exists() and not path.is_symlink(),
                  f"{label} occupied build root published {name}")


def outcome_details(results, snapshots):
    details = []
    for label in ("python", "native"):
        result = results[label]
        files = snapshots[label]["files"]
        classification = category(result)
        reason = ""
        if classification == "refused":
            marker = re.search(
                r"(?m)^WAMR_CI_REFUSED: ([A-Za-z0-9 .:_-]{1,120})$",
                result.stderr.decode("utf-8", "replace"))
            if marker:
                reason = " reason:" + marker.group(1)
        elif classification.startswith("failed_stage:"):
            marker = re.search(
                r"(?m)^WAMR_CI_FAILED_STAGE: [a-z0-9-]+; "
                r"(?:operation: ([a-z][a-z0-9-]{0,39}); )?"
                r"cause: ([A-Za-z][A-Za-z0-9_]{0,79}); "
                r"bounded private logs retained\.$",
                result.stderr.decode("utf-8", "replace"))
            if marker:
                if marker.group(1):
                    reason = " operation:" + marker.group(1)
                reason += " cause:" + marker.group(2)
        details.append(
            f"{label}=exit:{result.returncode} category:{classification}{reason} "
            f"evidence:{','.join(files['order'])} "
            f"artifacts:{','.join(sorted(files['artifacts']))}")
    return "; ".join(details)


def report_progress(side, phase):
    check(side in ("python", "native")
          and phase in ("build-start", "build-done", "boot-start", "boot-done"),
          "invalid differential progress label")
    print(f"DIFFERENTIAL_PROGRESS: {side}:{phase}", file=sys.stderr, flush=True)


def full(args):
    check(platform.machine() == "x86_64"
          and Path("/dev/kvm").is_char_device()
          and os.access("/dev/kvm", os.R_OK | os.W_OK),
          "full chain requires real accessible x86 KVM; no successful skip")
    parent = private(args.root, empty=True)
    py_repo, native_repo = args.python_repository, args.native_repository
    check(py_repo != native_repo and py_repo != PROJECT and native_repo != PROJECT,
          "two separate protected fresh worktrees required")
    check(not any(parent == path or parent.is_relative_to(path)
                  for path in (py_repo, native_repo, args.runtime_template,
                               args.wamr_source)),
          "differential root must be outside all input trees")
    check(checked_repository(py_repo) == checked_repository(native_repo),
          "source revision/tree mismatch")
    check(args.wamr_source.is_absolute()
          and args.wamr_source.resolve(strict=True) == args.wamr_source,
          "canonical pinned WAMR checkout required")
    rev = command(["git", "-C", str(args.wamr_source), "rev-parse", "HEAD"],
                  args.wamr_source, seconds=30)
    check(rev.returncode == 0 and
          rev.stdout.strip().decode("ascii") == oracle(py_repo).REVISION,
          "real pinned WAMR checkout required")
    check(args.controller.is_file() and not args.controller.is_symlink(),
          "missing prebuilt portable controller")
    check(args.case in {"success", "build-start-tamper", "missing-build",
                        "occupied-boot-slot", "prior-build-output"},
          "unknown differential case")
    py_runtime = fresh(parent, "python")
    native_runtime = fresh(parent, "native")
    for runtime in (py_runtime, native_runtime):
        copy_input_tree(args.runtime_template, runtime)
    check(manifest(py_runtime) == manifest(native_runtime),
          "different pinned runtime input bytes or modes")
    controller_parent = native_runtime / "controller"
    controller_parent.mkdir(mode=0o700)
    installed = controller_parent / "bin"
    installed.mkdir(mode=0o700)
    controller = installed / "uk-wamr-native-ci"
    shutil.copyfile(args.controller, controller)
    controller.chmod(0o700)
    check(identity(controller) == identity(args.controller),
          "installed native controller bytes changed")
    described = command([str(controller), "describe", "--output", "json-v1"],
                        native_repo, seconds=60)
    check(described.returncode == 0, "portable controller describe unavailable")
    description = json.loads(described.stdout)
    check(described.stdout == oracle(py_repo).compact_json(description, newline=True)
          and description["schema"] == "uk.wamr.native-ci-describe"
          and description["schema_version"] == 1
          and description["recorded_executable_target"] ==
          list(oracle(py_repo).RECORDED_EXECUTABLE_TARGET)
          and HEX.fullmatch(description["source_closure_sha256"]),
          "wrong portable controller target/closure")
    check(command(["zig", "version"], py_repo, seconds=15).stdout.strip()
          == b"0.16.0", "pinned Zig 0.16.0 required")
    for name in oracle(py_repo).HOST_TOOLS:
        check(shutil.which(name) is not None, "missing production tool: " + name)
    check(not os.environ.get("BISON_PKGDATADIR"),
          "ambiguous inherited Bison binding")
    path = os.environ.get("PATH", "")
    check(path and all(component.startswith("/") for component in path.split(":")),
          "absolute closed tool search path required")
    env = {"PATH": path, "LANG": "C", "LC_ALL": "C",
           "PYTHONDONTWRITEBYTECODE": "1"}
    executions = {}
    for label, repo, runtime, executable in (
            ("python", py_repo, py_runtime, [sys.executable, "-B",
                                              str(py_repo / "support/build/wamr-native-ci/run.py")]),
            ("native", native_repo, native_runtime, [str(controller)])):
        environment = dict(env, BISON_PKGDATADIR=str(runtime / "bison"))
        executions[label] = (repo, runtime, executable, environment)
    if args.case == "prior-build-output":
        for _, runtime, _, _ in executions.values():
            (runtime / "compute").mkdir(mode=0o700)
    results = {}
    for label, (repo, runtime, executable, environment) in executions.items():
        report_progress(label, "build-start")
        results[label] = command([*executable, "build", "--runtime", str(runtime),
                                  "--wamr-source", str(args.wamr_source)],
                                 repo, environment, seconds=7200)
        report_progress(label, "build-done")
    py, native = (results[name] for name in ("python", "native"))
    snapshots = {
        label: observed(results[label], runtime, repo)
        for label, (repo, runtime, _, _) in executions.items()
    }
    failures = ["build:" + name for name in compare_observations(
        snapshots["python"], snapshots["native"], reviewed_build_compat=True)]
    if args.case == "prior-build-output":
        require_prior_build_output_refusal(
            py, native, py_runtime, native_runtime)
    else:
        check(py.returncode == native.returncode == 0,
              "build did not reach accepted state; " +
              outcome_details(results, snapshots) + "; " +
              ", ".join(failures))
        for repo, runtime, _, _ in executions.values():
            compute = runtime / "compute"
            if args.case == "build-start-tamper":
                record = compute / "evidence/build-start.json"
                reference = oracle(repo)
                data = parsed(checked_file(record), reference)
                check(data["source"]["revision"] != "0" * 40,
                      "tamper was a no-op")
                data["source"]["revision"] = "0" * 40
                record.write_bytes(reference.compact_json(data, newline=True))
            elif args.case == "missing-build":
                (compute / "evidence/build.json").unlink()
            elif args.case == "occupied-boot-slot":
                path = compute / "boot-raw-x2apic/prior"
                path.write_bytes(b"prior")
                path.chmod(0o600)
        results = {}
        for label, (repo, runtime, executable, environment) in executions.items():
            report_progress(label, "boot-start")
            results[label] = command([*executable, "boot", "--runtime", str(runtime)],
                                     repo, environment, seconds=3600)
            report_progress(label, "boot-done")
        py, native = (results[name] for name in ("python", "native"))
        boot_snapshots = {
            label: observed(results[label], runtime, repo)
            for label, (repo, runtime, _, _) in executions.items()
        }
        failures.extend("boot:" + name for name in compare_observations(
            boot_snapshots["python"], boot_snapshots["native"],
            reviewed_build_compat=True))
        check((py.returncode == native.returncode == 0) == (args.case == "success"),
              "unexpected full-chain outcome; " +
              outcome_details(results, boot_snapshots) + "; " +
              ", ".join(failures))
        if args.case == "success":
            for runtime in (py_runtime, native_runtime):
                check((runtime / "compute/evidence/result.json").is_file(),
                      "missing real KVM acceptance record")
        else:
            for runtime in (py_runtime, native_runtime):
                check(not (runtime / "compute/evidence/result.json").exists(),
                      "refusal published acceptance")
    check(not failures, "differential mismatches: " + ", ".join(failures))


class DeterministicContracts(unittest.TestCase):
    def test_full_requires_fresh_precreated_source_output_roots(self):
        parent = fresh(fixture_parent(), f"differential-source-role-{os.getpid()}")
        try:
            repository = fresh(parent, "repository")
            (repository / ".gitignore").write_text(".d/\n")
            for args in (
                    ("init", "-q"),
                    ("add", ".gitignore"),
                    ("-c", "user.name=Fixture", "-c",
                     "user.email=fixture@example.invalid", "commit", "-qm",
                     "tracked source")):
                result = command(["git", "-C", str(repository), *args],
                                 repository, seconds=30)
                self.assertEqual(result.returncode, 0, result.stderr[:300])
            with self.assertRaisesRegex(ParityError, "precreated empty .d"):
                checked_repository(repository)
            output = repository / ".d"
            output.mkdir(mode=0o700)
            output.chmod(0o755)
            with self.assertRaisesRegex(ParityError, "owner-only 0700"):
                checked_repository(repository)
            output.chmod(0o700)
            (output / "prior").write_bytes(b"prior")
            with self.assertRaisesRegex(ParityError, "fresh empty root"):
                checked_repository(repository)
            (output / "prior").unlink()
            self.assertEqual(len(checked_repository(repository)), 2)
        finally:
            shutil.rmtree(parent)

    def test_build_start_compares_shared_identities_after_side_specific_proof(self):
        reference = oracle()
        custody = {
            "schema": "synthetic", "version": 1, "object_format": "sha1",
            "files": {"common": {"sha256": "a" * 64}},
            "directories": {}, "bytes": 42,
            "content_sha256": "b" * 64, "role_excluded_outputs": [],
        }
        dependencies = {
            "schema": "synthetic", "version": 1, "request": {},
            "source_manifests": {}, "restore_directory": {},
            "restore": {}, "packages": {
                "roots": [], "files": 0, "directories": 0, "bytes": 0,
                "manifests": [], "hash_verification": True, "records": [],
            },
        }
        record = {
            "source": {"revision": "r", "tree": "t"},
            "source_custody": custody,
            "tools": {"zig": {"sha256": "c" * 64}},
            "bison_data": {}, "dependencies": dependencies,
            "consumer_inputs": {}, "command_supervisor": {},
        }
        common_file = {
            "path": "/usr/bin/zig", "sha256": "d" * 64,
            "metadata": [1, 2, 3, 4, 5, 1, 42, 7, 8],
        }
        controller = copy.deepcopy(common_file)
        controller["path"] = "/python/supervisor"
        native_controller = copy.deepcopy(controller)
        native_controller.update(path="/native/controller", sha256="e" * 64)
        shared_source = {
            "bytes": 42, "sha256": "f" * 64,
            "metadata": [1, 2, 3, 4, 5, 1, 42, 7, 8],
        }
        first = {
            "record": copy.deepcopy(record),
            "files": {
                "tool:zig": common_file, "command-supervisor": controller,
            },
            "trees": {}, "source_files": {"shared": copy.deepcopy(shared_source)},
            "runtime_files": {
                "executable": copy.deepcopy(shared_source),
                "runtime:/lib": copy.deepcopy(shared_source),
            },
        }
        second = copy.deepcopy(first)
        second["files"]["command-supervisor"] = native_controller
        second["source_files"]["native-only"] = copy.deepcopy(shared_source)
        second["runtime_files"]["executable"]["sha256"] = "e" * 64
        observations = ({"roots": (Path("/python"), PROJECT)},
                        {"roots": (Path("/native"), PROJECT)})

        def compared():
            with mock.patch.dict(compare_build_start.__globals__, {
                    "verified_build_start_side": lambda seen, side: (
                        first if side == "python" else second)}):
                return compare_build_start(*observations)

        self.assertEqual(compared(), [])
        for kind, field in (
                ("source", "source_custody.files"),
                ("tool", "tools"),
                ("consumer", "consumer_inputs.files.tool:zig.sha256"),
                ("closure", "command_supervisor.source_map.records.shared.sha256"),
                ("loader", "command_supervisor.runtime_map.records.runtime:/lib.sha256"),
        ):
            with self.subTest(kind=kind):
                altered = copy.deepcopy(second)
                if kind == "source":
                    altered["record"]["source_custody"]["files"]["common"][
                        "sha256"] = "0" * 64
                    altered["record"]["source_custody"]["content_sha256"] = (
                        reference.record_digest(
                            altered["record"]["source_custody"]["files"]))
                elif kind == "tool":
                    altered["record"]["tools"]["zig"]["sha256"] = "0" * 64
                elif kind == "consumer":
                    altered["files"]["tool:zig"]["sha256"] = "0" * 64
                elif kind == "closure":
                    altered["source_files"]["shared"]["sha256"] = "0" * 64
                else:
                    altered["runtime_files"]["runtime:/lib"]["sha256"] = (
                        "0" * 64)
                with mock.patch.dict(compare_build_start.__globals__, {
                        "verified_build_start_side": lambda seen, side: (
                            first if side == "python" else altered)}):
                    failures = compare_build_start(*observations)
                self.assertIn("record_content:build-start.json." + field,
                              failures)

    def test_pinned_supervisor_closure_rejects_rehashed_source_mutations(self):
        reference = oracle()
        domain = "uk.wamr.command-supervisor-source-v1"
        for side in ("python", "native"):
            with self.subTest(side=side):
                names = (reference.SUPERVISOR_SOURCE_FILES if side == "python"
                         else NATIVE_SOURCE_FILES)
                records = {}
                for name in names:
                    pinned, _ = reference.tracked_manifest(name)
                    records[name] = {
                        "bytes": pinned["bytes"], "sha256": pinned["sha256"],
                        "metadata": pinned["metadata"],
                    }
                baseline = reference.guarded_record_map(domain, records)
                self.assertEqual(
                    verified_supervisor_source_map(reference, baseline, side),
                    records)
                for kind in ("content", "physical", "omitted"):
                    with self.subTest(side=side, kind=kind):
                        changed = copy.deepcopy(records)
                        first = names[0]
                        if kind == "content":
                            changed[first]["sha256"] = "0" * 64
                        elif kind == "physical":
                            changed[first]["metadata"][7] += 1
                        else:
                            del changed[first]
                        rehashed = reference.guarded_record_map(domain, changed)
                        with self.assertRaisesRegex(
                                ParityError, "source closure/record changed"):
                            verified_supervisor_source_map(
                                reference, rehashed, side)

    def test_physical_consumer_roles_and_runtime_closure_reject_rehashed_mutations(self):
        reference = oracle()
        runtime = fresh(fixture_parent(), f"differential-roles-{os.getpid()}")
        reference.executable_runtime_paths = lambda path: ()
        try:
            paths = {}
            for role, relative in NATIVE_CONSUMER_ROLES.items():
                path = runtime / relative
                path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                path.write_bytes(("synthetic role: " + role).encode())
                path.chmod(0o600)
                paths[role] = path
            reference.discover_consumer_input_paths = lambda root: ({}, {})
            baseline = reference.record_input_paths(paths, {})
            files, _ = verified_consumer_inputs(
                reference, baseline, "native", runtime)
            self.assertEqual(set(files), set(NATIVE_CONSUMER_ROLES))
            for kind in ("content", "role", "runtime-content"):
                with self.subTest(kind=kind):
                    changed = copy.deepcopy(baseline)
                    if kind == "role":
                        changed["files"]["native:counterfeit"] = (
                            changed["files"].pop("native:wamr-ci-package"))
                    else:
                        key = ("command-supervisor" if kind == "runtime-content"
                               else "native:wamr-ci-package")
                        changed["files"][key]["sha256"] = "0" * 64
                    changed["aggregate_sha256"] = reference.record_digest({
                        key: value for key, value in changed.items()
                        if key != "aggregate_sha256"
                    })
                    with self.assertRaises((ParityError, reference.Refusal)):
                        verified_consumer_inputs(
                            reference, changed, "native", runtime)
            for side in ("native", "python"):
                with self.subTest(side=side):
                    if side == "python":
                        path = runtime / "compute/supervisor/bin/wamr-ci-supervisor"
                        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                        path.write_bytes(b"synthetic Python supervisor")
                        path.chmod(0o600)
                        reference.discover_consumer_input_paths = (
                            lambda root: ({"command-supervisor": path}, {}))
                        consumer = reference.record_input_paths(
                            {"command-supervisor": path}, {})
                        files, _ = verified_consumer_inputs(
                            reference, consumer, "python", runtime)
                    role = files["command-supervisor"]
                    record = {
                        "executable": {
                            "bytes": role["metadata"][6], "sha256": role["sha256"],
                            "metadata": role["metadata"],
                        },
                    }
                    domain = "uk.wamr.command-supervisor-runtime-v1"
                    closure = reference.guarded_record_map(domain, record)
                    self.assertEqual(
                        verified_supervisor_runtime_map(
                            reference, closure, side, runtime, files), record)
                    for field in ("sha256", "metadata"):
                        with self.subTest(side=side, field=field):
                            changed = copy.deepcopy(record)
                            if field == "sha256":
                                changed["executable"]["sha256"] = "0" * 64
                            else:
                                changed["executable"]["metadata"][7] += 1
                            with self.assertRaisesRegex(
                                    ParityError, "runtime closure/record changed"):
                                verified_supervisor_runtime_map(
                                    reference, reference.guarded_record_map(
                                        domain, changed), side, runtime, files)
        finally:
            shutil.rmtree(runtime)

    def test_fixtures_stage_side_specific_exact_contract_and_tamper(self):
        reference = oracle()
        empty = sha(b"")

        def synthetic(side, log, stage="fixtures"):
            contract = reviewed_build_command_contract(reference, side, stage)
            executable = {
                "content_sha256": sha(b"synthetic-fixture-only"),
                "ctime_nanoseconds": 0, "ctime_seconds": 1,
                "device_major": 0, "device_minor": 1, "inode": 12,
                "mode": stat.S_IFREG | 0o500, "mtime_nanoseconds": 0,
                "mtime_seconds": 1, "size": 22, "uid": os.getuid(),
            }
            def identified(binding):
                return {"path": binding, "identity": executable}
            env = {entry["name"]: entry["value"]
                   for entry in contract["environment"]}
            retained = [
                {"name": name, "path": env[name], "identity": executable}
                for name in contract["retained_names"]
            ]
            issued = 1_000_000_000
            request = {
                "schema": "uk.wamr.command-supervisor-request",
                "version": 1,
                "binding_schema": "uk.wamr.supervised-command-binding",
                "binding_version": 1,
                "stage": stage,
                "argv": contract["argv"],
                "environment": contract["environment"],
                "cwd": contract["cwd"],
                "supervisor": identified(reference.command_path(
                    "command-supervisor")),
                "native_executable": identified(contract["native_executable"]),
                "command_executable": identified(contract["command_executable"]),
                "interpreter": (None if contract["interpreter"] is None
                                else identified(contract["interpreter"])),
                "retained_executables": retained,
                "issued_ns": issued,
                "primary_deadline_ns": issued + contract["seconds"] * 1_000_000_000,
                "cleanup_deadline_ns": issued + (
                    contract["seconds"] + 10) * 1_000_000_000,
                "timeout_ns": contract["seconds"] * 1_000_000_000,
                "limits": contract["limits"],
            }
            for key, payload in (
                    ("canonical_sha256", request),
                    ("argv_sha256", request["argv"]),
                    ("environment_sha256", request["environment"]),
                    ("cwd_sha256", request["cwd"])):
                request[key] = reference.command_binding_digest(payload)
            started = issued + 1000
            primary = started + 2_000_000
            completed = primary + 1_000_000
            stdout = {
                "bytes": len(log), "sha256": sha(log), "status": "complete",
                "digest_scope": reference.command_digest_scope(len(log)),
            }
            stderr = {
                "bytes": 0, "sha256": empty, "status": "complete",
                "digest_scope": reference.command_digest_scope(0),
            }
            summary = {
                "cancellation_observed": False,
                "cleanup": "complete", "cleanup_complete": True,
                "cleanup_events": 5,
                "descendants": {
                    "adopted": 0, "identity_validated": 0, "limit_exceeded": False,
                    "observed": 0, "untracked": False,
                },
                "executable": executable, "executable_stable": True,
                "output": {
                    "bytes": len(log), "combined_sha256": sha(log),
                    "commitment_sha256": reference.command_output_commitment(
                        len(log), sha(log), 0, empty),
                    "digest_scope": reference.command_digest_scope(len(log)),
                },
                "poisoned": False, "primary": {"code": 0, "kind": "exited"},
                "primary_deadline_reached": False, "primary_events": 1,
                "reap_events": 2, "retained_executables": retained,
                "stderr": stderr, "stdout": stdout,
                "timing": {
                    "started_ns": started, "primary_completed_ns": primary,
                    "completed_ns": completed,
                    "primary_elapsed_ns": primary - started,
                    "cleanup_elapsed_ns": completed - primary,
                    "total_elapsed_ns": completed - started,
                },
                "termination": {"code": 0, "kind": "exited"},
            }
            result = {
                "schema": "uk.wamr.command-supervisor-result",
                "version": 1, "request_canonical_sha256":
                    request["canonical_sha256"], "controller_error": None,
                "native_request": {
                    "bytes": 128, "sha256": sha(b"request"),
                    "digest_scope": "direct_producer_or_trusted_inner_zip",
                },
                "native_result": {
                    "bytes": 128, "sha256": sha(b"result"),
                    "digest_scope": "direct_producer_or_trusted_inner_zip",
                },
                "command": summary,
            }
            result["canonical_sha256"] = reference.command_binding_digest(result)
            return {
                "scope": "command_diagnostic_not_acceptance", "stage": stage,
                "exit_code": 0, "bytes": len(log), "sha256": sha(log),
                "sha256_scope": reference.command_digest_scope(len(log)),
                "over_limit": False, "known_error_markers": [],
                "supervisor": {
                    "schema": "uk.wamr.command-supervisor-result",
                    "version": 1, "bootstrap": False,
                    "request": request, "result": result,
                },
            }

        python_log = b"synthetic-python-fixture-ok\n"
        native_log = b"synthetic-native-fixture-ok\n"
        python = synthetic("python", python_log)
        native = synthetic("native", native_log)
        self.assertNotEqual(python["supervisor"]["request"]["argv"],
                            native["supervisor"]["request"]["argv"])
        self.assertNotEqual(python["sha256"], native["sha256"])
        self.assertEqual(fixture_stage(
            python, python_log, "python", reference), fixture_stage(
                native, native_log, "native", reference))
        for side, record, log in (
                ("python", python, python_log), ("native", native, native_log)):
            for change, key in (
                    ("argv", "argv"),
                    ("environment", "environment"),
                    ("commitment", "output commitment"),
                    ("log", "private log")):
                with self.subTest(side=side, change=change):
                    altered = copy.deepcopy(record)
                    if change == "argv":
                        altered["supervisor"]["request"]["argv"][1] = (
                            reference.command_literal("--altered"))
                    elif change == "environment":
                        altered["supervisor"]["request"]["environment"][0]["value"] = (
                            reference.command_literal("altered"))
                    elif change == "commitment":
                        altered["supervisor"]["result"]["command"]["output"][
                            "commitment_sha256"] = "0" * 64
                    if change in ("argv", "environment", "commitment"):
                        request = altered["supervisor"]["request"]
                        if change in ("argv", "environment"):
                            request[change + "_sha256"] = (
                                reference.command_binding_digest(request[change]))
                            request["canonical_sha256"] = (
                                reference.command_binding_digest({
                                    name: value for name, value in request.items()
                                    if name not in (
                                        "canonical_sha256", "argv_sha256",
                                        "environment_sha256", "cwd_sha256")
                                }))
                        result = altered["supervisor"]["result"]
                        result["request_canonical_sha256"] = (
                            request["canonical_sha256"])
                        result["canonical_sha256"] = (
                            reference.command_binding_digest({
                                name: value for name, value in result.items()
                                if name != "canonical_sha256"
                            }))
                    with self.assertRaisesRegex(ParityError, key):
                        fixture_stage(
                            altered, log + b"tampered" if change == "log" else log,
                            side, reference)
        for stage in ("adapter", "local-boot-tool", *SHARED_BUILD_STAGES):
            python = synthetic("python", b"synthetic-python-build-ok\n", stage)
            native = synthetic("native", b"synthetic-native-build-ok\n", stage)
            with self.subTest(stage=stage):
                if stage in ("adapter", "local-boot-tool"):
                    self.assertNotEqual(
                        python["supervisor"]["request"]["argv"],
                        native["supervisor"]["request"]["argv"])
                else:
                    self.assertEqual(
                        python["supervisor"]["request"]["argv"],
                        native["supervisor"]["request"]["argv"])
                self.assertEqual(checked_stage(
                    python, b"synthetic-python-build-ok\n", "python",
                    reference, stage), checked_stage(
                        native, b"synthetic-native-build-ok\n", "native",
                        reference, stage))
            for side, record, log in (
                    ("python", python, b"synthetic-python-build-ok\n"),
                    ("native", native, b"synthetic-native-build-ok\n")):
                for field in ("argv", "environment", "limits",
                              "commitment_sha256"):
                    with self.subTest(stage=stage, side=side, field=field):
                        altered = copy.deepcopy(record)
                        request = altered["supervisor"]["request"]
                        result = altered["supervisor"]["result"]
                        if field in ("argv", "environment"):
                            payload = request[field]
                            if field == "argv":
                                payload[1] = reference.command_literal("altered")
                            else:
                                payload[0]["value"] = reference.command_literal(
                                    "altered")
                            request[field + "_sha256"] = (
                                reference.command_binding_digest(payload))
                        elif field == "limits":
                            request["limits"]["stdout_bytes"] -= 1
                        else:
                            result["command"]["output"][field] = "0" * 64
                        request["canonical_sha256"] = (
                            reference.command_binding_digest({
                                name: value for name, value in request.items()
                                if name not in (
                                    "canonical_sha256", "argv_sha256",
                                    "environment_sha256", "cwd_sha256")
                            }))
                        result["request_canonical_sha256"] = request["canonical_sha256"]
                        result["canonical_sha256"] = (
                            reference.command_binding_digest({
                                name: value for name, value in result.items()
                                if name != "canonical_sha256"
                            }))
                        expected = "output commitment" if field == "commitment_sha256" else (
                            "stage/deadline/limits" if field == "limits" else field)
                        with self.assertRaisesRegex(ParityError, expected):
                            checked_stage(altered, log, side, reference, stage)

    def test_v1_read_only_and_v2_acceptance_parser_fixtures(self):
        reference = oracle()
        for version in (1, 2):
            with self.subTest(version=version):
                raw = (FIXTURES / f"accepted-v{version}.json").read_bytes()
                result = parsed(raw, reference)
                self.assertEqual(result["schema_version"], version)
                self.assertEqual(result["modes"], list(
                    reference.MODES if version == 1 else reference.SIX_MODES))
                self.assertEqual(len(result["records"]), 8 if version == 1 else 33)
                self.assertNotIn("result.json", result["records"])
                self.assertEqual(set(result["records"]), set(
                    ("build-start.json", "build.json", "boot-inputs.json",
                     "package.json", *(mode + "-compute.json"
                                       for mode in result["modes"]))
                    if version == 1 else set(ORDER) - {"result.json"}))
                self.assertEqual(set(result["records"].values()), {sha(b"{}\n")})

    def test_python_v1_v2_reader_rehashes_synthetic_parser_fixtures(self):
        spec = importlib.util.spec_from_file_location(
            "wamr_handoff_fixture_reader", CONTROLLER / "handoff.py")
        handoff = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(handoff)
        scratch = fixture_parent()
        parent = fresh(scratch, f"synthetic-result-parser-{os.getpid()}")
        try:
            for version in (1, 2):
                root = fresh(parent, f"v{version}")
                evidence = fresh(root, "evidence")
                raw = (FIXTURES / f"accepted-v{version}.json").read_bytes()
                value = parsed(raw, handoff.ci)
                for name in value["records"]:
                    file = evidence / name
                    file.write_bytes(b"{}\n")
                    file.chmod(0o600)
                (evidence / "result.json").write_bytes(raw)
                (evidence / "result.json").chmod(0o600)
                self.assertEqual(handoff.result_records(root), value["records"])
                changed = evidence / "build.json"
                changed.write_bytes(b'{"tampered":true}\n')
                with self.assertRaises(handoff.ci.Refusal):
                    handoff.result_records(root)
        finally:
            shutil.rmtree(parent)

    def test_normalization_preserves_metadata_equivalence_not_content(self):
        roots = (Path("/private/python"), Path("/checkout/python"))
        a = Normalizer(roots)
        first = a.normalize({"path": "/private/python/compute/evidence/x",
                             "metadata": [4, 11, 33188, 1000, 1000, 1, 2, 20, 30],
                             "hash": "a" * 64})
        second = a.normalize({"path": "/private/python/compute/evidence/y",
                              "metadata": [4, 11, 33188, 1000, 1000, 1, 2, 20, 30],
                              "hash": "a" * 64})
        self.assertEqual(first["metadata"], second["metadata"])
        b = Normalizer((Path("/private/native"), Path("/checkout/native")))
        native = b.normalize({"path": "/private/native/compute/evidence/x",
                              "metadata": [7, 92, 33188, 1000, 1000, 1, 2, 52, 66],
                              "hash": "b" * 64})
        self.assertEqual(first["metadata"], native["metadata"])
        self.assertNotEqual(first["hash"], native["hash"])
        self.assertNotEqual(first["path"], second["path"])
        self.assertEqual(first["path"], native["path"])
        bridged = b.normalize({
            "device_major": os.major(7), "device_minor": os.minor(7),
            "inode": 92, "mtime_seconds": 0, "mtime_nanoseconds": 52,
            "ctime_seconds": 0, "ctime_nanoseconds": 66,
        })
        self.assertEqual(bridged["device_major"], native["metadata"][0])
        self.assertEqual(bridged["inode"], native["metadata"][1])
        self.assertEqual(bridged["mtime_seconds"], native["metadata"][7])
        self.assertEqual(bridged["ctime_seconds"], native["metadata"][8])

    def test_no_kvm_exit_category_mismatch_is_not_a_success(self):
        class Exit:
            def __init__(self, returncode, stderr):
                self.returncode, self.stderr = returncode, stderr
        python = {"exit": Exit(1, b"WAMR_CI_REFUSED: x86 KVM required\n"),
                  "files": {"order": (), "records": {}, "retained": {}, "artifacts": {}},
                  "roots": (Path("/python"),)}
        native = {"exit": Exit(1, b"WAMR_CI_FAILED_STAGE: boot-platform; logs retained.\n"),
                  "files": python["files"], "roots": (Path("/native"),)}
        self.assertEqual(compare_observations(python, native), ["refusal_category"])

    def test_artifact_differences_name_only_fixed_roles_and_fields(self):
        exit_ok = subprocess.CompletedProcess([], 0, b"", b"")
        original = {"exit": exit_ok, "files": {
            "order": (), "records": {}, "retained": {},
            "artifacts": {"efi": (123, "a" * 64, 0o600)},
        }, "roots": (Path("/python"),)}
        changed = copy.deepcopy(original)
        changed["roots"] = (Path("/native"),)
        changed["files"]["artifacts"]["efi"] = (124, "b" * 64, 0o700)
        self.assertEqual(compare_observations(original, changed), [
            "artifacts:efi.bytes", "artifacts:efi.sha256", "artifacts:efi.mode",
        ])
        changed["files"]["artifacts"] = {}
        self.assertEqual(compare_observations(original, changed),
                         ["artifacts:membership"])
        changed["files"]["artifacts"] = {"unexpected": (123, "a" * 64, 0o600)}
        with self.assertRaisesRegex(ParityError, "invalid artifact comparison roles"):
            compare_observations(original, changed)

    def test_only_three_invalid_cli_vectors_have_exact_declared_exits(self):
        class Exit:
            def __init__(self, code, stderr):
                self.returncode, self.stderr = code, stderr

        def seen(code, stderr, name):
            return {
                "exit": Exit(code, stderr),
                "files": {"order": (), "records": {}, "retained": {},
                          "artifacts": {}},
                "roots": (Path("/private/" + name),),
            }

        refused = seen(1, b"WAMR_CI_REFUSED: private runtime root required\n",
                       "python")
        usage = seen(2, b"usage: uk-wamr-native-ci boot --runtime ABS\n",
                     "native")
        for label in DECLARED_INVALID_CLI:
            with self.subTest(label=label):
                self.assertEqual(cli_vector_failures(label, refused, usage), [])
                self.assertIn("wrong_cli_exit_or_category", cli_vector_failures(
                    label, refused, seen(
                        1, b"WAMR_CI_FAILED_STAGE: startup; logs retained.\n",
                        "native")))
                with_record = dict(usage, files={
                    **usage["files"], "records": {"result.json": (b"{}\n", {})},
                    "order": ("result.json",),
                })
                self.assertIn("cli_published_evidence",
                              cli_vector_failures(label, refused, with_record))
        self.assertIn("wrong_cli_exit_or_category",
                      cli_vector_failures("no-kvm", refused, usage))
        self.assertEqual(cli_vector_failures(
            "no-kvm", refused, seen(
                1, b"WAMR_CI_REFUSED: x86 KVM required\n", "native")), [])
        self.assertEqual(cli_vector_failures(
            "unknown-command", usage, usage), [])
        self.assertEqual(cli_vector_failures(
            "unknown-profile", usage, usage), [])
        with self.assertRaisesRegex(ParityError, "unknown CLI compatibility"):
            cli_vector_failures("different-vector", refused, usage)

    def test_failed_outcome_summary_is_bounded_and_redacts_paths(self):
        results = {
            "python": subprocess.CompletedProcess(
                [], 1, b"", b"WAMR_CI_REFUSED: source custody changed\n"),
            "native": subprocess.CompletedProcess(
                [], 1, b"", b"WAMR_CI_REFUSED: /private/secret\n"),
        }
        snapshots = {
            "python": {"files": {
                "order": ("command-adapter.json",),
                "artifacts": {"config": ("private",)},
            }},
            "native": {"files": {"order": (), "artifacts": {}}},
        }
        details = outcome_details(results, snapshots)
        self.assertIn("python=exit:1 category:refused reason:source custody changed "
                      "evidence:command-adapter.json artifacts:config", details)
        self.assertIn("native=exit:1 category:refused evidence: artifacts:",
                      details)
        self.assertNotIn("/private/secret", details)

    def test_failed_boot_summary_reports_only_path_free_refusal(self):
        results = {
            "python": subprocess.CompletedProcess(
                [], 1, b"", b"WAMR_CI_REFUSED: producer inputs changed\n"
                             b"private: /private/secret\n"),
            "native": subprocess.CompletedProcess([], 0, b"", b""),
        }
        snapshots = {
            label: {"files": {"order": ("build-start.json",), "artifacts": {}}}
            for label in results
        }
        details = outcome_details(results, snapshots)
        self.assertIn("python=exit:1 category:refused "
                      "reason:producer inputs changed", details)
        self.assertIn("native=exit:0 category:success", details)
        self.assertNotIn("/private/secret", details)

    def test_protected_progress_labels_are_closed_and_path_free(self):
        with mock.patch("builtins.print") as emit:
            report_progress("native", "boot-start")
            emit.assert_called_once_with(
                "DIFFERENTIAL_PROGRESS: native:boot-start",
                file=sys.stderr, flush=True)
            with self.assertRaisesRegex(ParityError, "invalid differential progress"):
                report_progress("/private/secret", "boot-start")
            with self.assertRaisesRegex(ParityError, "invalid differential progress"):
                report_progress("native", "/private/secret")
            emit.assert_called_once()

    def test_failed_build_summary_reports_only_static_native_error_names(self):
        results = {
            "python": subprocess.CompletedProcess(
                [], 0, b"", b""),
            "native": subprocess.CompletedProcess(
                [], 1, b"",
                b"WAMR_CI_FAILED_STAGE: dependency-restore; "
                b"operation: bind-bootstrap-inputs; cause: UnsafeFile; "
                b"bounded private logs retained.\n"
                b"error: /private/secret\n"),
        }
        snapshots = {
            label: {"files": {"order": (), "artifacts": {}}}
            for label in results
        }
        details = outcome_details(results, snapshots)
        self.assertIn("native=exit:1 category:failed_stage:dependency-restore "
                      "operation:bind-bootstrap-inputs cause:UnsafeFile", details)
        self.assertNotIn("/private/secret", details)
        results["native"] = subprocess.CompletedProcess(
            [], 1, b"",
            b"WAMR_CI_FAILED_STAGE: dependency-restore; "
            b"operation: /private/secret; cause: UnsafeFile; "
            b"bounded private logs retained.\n")
        self.assertNotIn("operation:", outcome_details(results, snapshots))
        self.assertNotIn("cause:", outcome_details(results, snapshots))

    def test_matrix_driver_refuses_unreviewed_cases_and_jobs(self):
        scripts = PROJECT / ".github/scripts"
        environment = {
            "PATH": "/usr/bin:/bin",
            "GITHUB_ACTIONS": "true",
            "GITHUB_JOB": "wamr-differential-parity",
        }
        for name, arguments, job, marker in (
                ("wamr-native-differential-ci.sh", ("/d", "success"),
                 "wamr-differential-parity", b"refused: case"),
                ("hyperv-qemu-candidate-runtime.sh",
                 ("/d", "differential", "success"),
                 "wamr-differential-parity",
                 b"Invalid differential driver selection"),
                ("hyperv-qemu-candidate-runtime.sh",
                 ("/d", "differential", "missing-build"),
                 "wamr-native-compute",
                 b"Invalid differential driver selection")):
            with self.subTest(script=name, arguments=arguments, job=job):
                result = subprocess.run(
                    ["/usr/bin/bash", str(scripts / name), *arguments],
                    cwd=PROJECT, env=dict(environment, GITHUB_JOB=job),
                    capture_output=True, timeout=10, check=False)
                self.assertEqual(result.returncode, 2, result.stderr[:300])
                self.assertIn(marker, result.stderr)

    def test_prior_build_output_requires_startup_failure_and_no_acceptance(self):
        class Exit:
            def __init__(self, code, stderr):
                self.returncode, self.stderr = code, stderr

        startup = Exit(1, b"WAMR_CI_FAILED_STAGE: startup; logs retained.\n")
        root = fresh(fixture_parent(), f"differential-prior-{os.getpid()}")
        try:
            py_runtime, native_runtime = (
                fresh(root, label) for label in ("python", "native"))
            for runtime in (py_runtime, native_runtime):
                (runtime / "compute").mkdir(mode=0o700)

            def require(python, native):
                require_prior_build_output_refusal(
                    python, native, py_runtime, native_runtime)

            require(startup, startup)
            for side in ("python", "native"):
                for code, stderr in (
                        (0, b""),
                        (1, b"WAMR_CI_REFUSED: prior output\n"),
                        (1, b"WAMR_CI_FAILED_STAGE: build; logs retained.\n"),
                        (2, b"usage: build --runtime ABS\n")):
                    with self.subTest(side=side, code=code, stderr=stderr):
                        one = Exit(code, stderr)
                        pair = (one, startup) if side == "python" else (startup, one)
                        with self.assertRaisesRegex(
                                ParityError, "expected failed_stage:startup/1"):
                            require(*pair)
                runtime = py_runtime if side == "python" else native_runtime
                evidence = runtime / "compute/evidence"
                evidence.mkdir(mode=0o700)
                for name in ("build.json", "result.json"):
                    with self.subTest(side=side, published=name):
                        publication = evidence / name
                        publication.write_bytes(b"synthetic fixture, not evidence\n")
                        publication.chmod(0o600)
                        with self.assertRaisesRegex(
                                ParityError, side + " occupied build root published "
                                + re.escape(name)):
                            require(startup, startup)
                        publication.unlink()
                dangling = evidence / "result.json"
                dangling.symlink_to("missing-synthetic-fixture")
                with self.assertRaisesRegex(
                        ParityError, side + " occupied build root published result.json"):
                    require(startup, startup)
                dangling.unlink()
        finally:
            shutil.rmtree(root)

    def test_differential_record_hash_mutation_is_not_a_success(self):
        class Exit:
            returncode = 0
            stderr = b""
        files = {"order": ("build-start.json",), "retained": {},
                 "artifacts": {}, "records": {
                     "build-start.json": (b'{"a":1}\n', {"a": 1})}}
        left = {"exit": Exit(), "files": files, "roots": (Path("/left"),)}
        changed = dict(files, records={"build-start.json":
                       (b'{"a":2}\n', {"a": 2})})
        right = {"exit": Exit(), "files": changed, "roots": (Path("/right"),)}
        self.assertEqual(compare_observations(left, right),
                         ["record_content:build-start.json"])

    def test_record_mutation_and_publication_order_are_not_normalized(self):
        source = Normalizer((Path("/private/a"),))
        self.assertNotEqual(source.normalize({"stage": "prepare", "sha256": "a" * 64}),
                            source.normalize({"stage": "config", "sha256": "a" * 64}))
        self.assertNotEqual(source.normalize({"stage": "prepare", "sha256": "a" * 64}),
                            source.normalize({"stage": "prepare", "sha256": "b" * 64}))
        self.assertEqual(len(ORDER), len(set(ORDER)))

    def test_local_boot_install_and_boot_custody_prove_distinct_paths(self):
        reference = oracle()
        self.assertEqual(
            reference.production_command_contract("local-boot-tool")["argv"][9],
            reference.command_path("work", "tools"))
        self.assertEqual(
            native_build_command_contract(reference, "local-boot-tool")["argv"][7],
            reference.command_path("work", "local-boot-tools"))
        root = fresh(fixture_parent(), f"differential-local-boot-{os.getpid()}")
        original_app = reference.APP
        original_runtime_paths = reference.executable_runtime_paths
        reference.APP = root / "synthetic-app"
        reference.executable_runtime_paths = lambda path: ()

        def write(path, data, mode=0o600):
            path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            path.write_bytes(data)
            path.chmod(mode)

        try:
            efi = reference.APP / "build" / reference.EFI
            write(efi, b"synthetic EFI identity")
            prepared = {}
            observations = {}
            for side in ("python", "native"):
                runtime = fresh(root, side)
                local = local_boot_install_path(runtime, side)
                write(local, b"synthetic shared local boot executable", 0o700)
                common = {
                    "package_tool": runtime / "compute/tools/bin/wamr-ci-package",
                    "qemu": runtime / "bin/qemu-system-x86_64",
                    "ovmf_code": runtime / "firmware/code.fd",
                    "ovmf_vars": runtime / "firmware/vars.fd",
                }
                for role, path in common.items():
                    write(path, ("synthetic " + role).encode(),
                          0o700 if role in ("package_tool", "qemu") else 0o600)
                validator = runtime / "compute/tools/bin/uk-wamr-log-validate"
                write(validator, b"synthetic log validator", 0o700)
                if side == "native":
                    common["log_validator"] = validator
                write(runtime / "bin/share/fixture-data", b"synthetic QEMU data")
                paths = {**common, "local_boot_tool": local, "efi": efi}
                prepared[side] = (runtime, paths, validator)
            for side, (runtime, paths, validator) in prepared.items():
                record = reference.boot_input_state(runtime, paths)
                validator_record, _ = reference.physical_file_record(validator)
                observations[side] = {
                    "reference": reference, "roots": (runtime, reference.REPO),
                    "files": {
                        "records": {
                            "boot-inputs.json": (
                                reference.compact_json(record, newline=True),
                                record),
                            "build-start.json": (
                                b"synthetic build-start fixture\n",
                                {"consumer_inputs": {"files": {
                                    "native:wamr-log-validate":
                                        validator_record,
                                }}}),
                        },
                    },
                }
            python, native = observations["python"], observations["native"]
            installed, failures = compare_local_boot_installs(python, native)
            self.assertEqual(failures, [])
            self.assertEqual(installed[0]["sha256"], installed[1]["sha256"])
            self.assertNotEqual(installed[0]["path"], installed[1]["path"])
            self.assertEqual(compare_boot_inputs(python, native, installed), [])
            native_record = native["files"]["records"]["boot-inputs.json"][1]

            def mutated_boot(value):
                changed = {
                    **native, "files": {
                        "records": {
                            **native["files"]["records"],
                            "boot-inputs.json": (
                                reference.compact_json(value, newline=True), value),
                        },
                    },
                }
                return changed

            for kind in ("missing-validator", "altered-role",
                         "bad-validator-hash", "substituted-validator-path",
                         "extra-field"):
                with self.subTest(kind=kind):
                    changed_record = copy.deepcopy(native_record)
                    bindings = changed_record["files"]
                    if kind == "missing-validator":
                        del bindings["log_validator"]
                    elif kind == "altered-role":
                        bindings["validator-unreviewed"] = bindings.pop(
                            "log_validator")
                    elif kind == "bad-validator-hash":
                        bindings["log_validator"]["sha256"] = "0" * 64
                    elif kind == "substituted-validator-path":
                        bindings["log_validator"] = copy.deepcopy(
                            bindings["package_tool"])
                    else:
                        changed_record["unreviewed"] = True
                    changed_record["aggregate_sha256"] = reference.record_digest({
                        key: value for key, value in changed_record.items()
                        if key != "aggregate_sha256"
                    })
                    with self.assertRaises((ParityError, reference.Refusal)):
                        compare_boot_inputs(
                            python, mutated_boot(changed_record), installed)

            for seen in observations.values():
                boot_raw = seen["files"]["records"]["boot-inputs.json"][0]
                value = {
                    "schema": "uk.wamr.compute-qcow2-acceptance",
                    "schema_version": 1,
                    "profile": reference.CURRENT_PROFILE,
                    "status": "accepted",
                    "source": {"revision": "synthetic"},
                    "accepted_qcow2": {"sha256": "a" * 64},
                    "finalization_sha256": "b" * 64,
                    "modes": list(reference.SIX_MODES[:4]),
                    "boots": {}, "build_sha256": "c" * 64,
                    "boot_inputs_sha256": sha(boot_raw),
                }
                seen["files"]["records"]["qcow2-acceptance.json"] = (
                    reference.compact_json(value, newline=True), value)
            self.assertNotEqual(
                python["files"]["records"]["qcow2-acceptance.json"][1][
                    "boot_inputs_sha256"],
                native["files"]["records"]["qcow2-acceptance.json"][1][
                    "boot_inputs_sha256"])
            self.assertEqual(compare_qcow2_acceptance(python, native), [])

            def mutated_acceptance(side, value):
                seen = observations[side]
                return {
                    **seen, "files": {
                        "records": {
                            **seen["files"]["records"],
                            "qcow2-acceptance.json": (
                                reference.compact_json(value, newline=True),
                                value),
                        },
                    },
                }

            for side in ("python", "native"):
                for kind in ("wrong-boot-hash", "extra-field", "other-field"):
                    with self.subTest(side=side, kind=kind):
                        changed = copy.deepcopy(
                            observations[side]["files"]["records"][
                                "qcow2-acceptance.json"][1])
                        if kind == "wrong-boot-hash":
                            changed["boot_inputs_sha256"] = "0" * 64
                        elif kind == "extra-field":
                            changed["unreviewed"] = True
                        else:
                            changed["source"]["revision"] = "altered"
                        tampered = mutated_acceptance(side, changed)
                        pair = ((tampered, native) if side == "python"
                                else (python, tampered))
                        if kind == "other-field":
                            self.assertEqual(
                                compare_qcow2_acceptance(*pair),
                                ["record_content:qcow2-acceptance.json.source"])
                        else:
                            with self.assertRaisesRegex(
                                    ParityError,
                                    "acceptance.*(commitment|field/shape)"):
                                compare_qcow2_acceptance(*pair)
            accepted = copy.deepcopy(
                native["files"]["records"]["qcow2-acceptance.json"][1])
            forged_boot = dict(native_record, unreviewed=True)
            forged_raw = reference.compact_json(forged_boot, newline=True)
            accepted["boot_inputs_sha256"] = sha(forged_raw)
            stale = {
                **native, "files": {
                    "records": {
                        **native["files"]["records"],
                        "boot-inputs.json": (forged_raw, native_record),
                        "qcow2-acceptance.json": (
                            reference.compact_json(accepted, newline=True),
                            accepted),
                    },
                },
            }
            with self.assertRaisesRegex(
                    ParityError, "acceptance boot-input byte commitment changed"):
                verified_qcow2_acceptance(stale)

            for kind in ("path", "sha256", "metadata"):
                with self.subTest(kind=kind):
                    altered = copy.deepcopy(native_record)
                    role = altered["files"]["local_boot_tool"]
                    if kind == "path":
                        role.update(altered["files"]["package_tool"])
                    elif kind == "sha256":
                        role["sha256"] = "0" * 64
                    else:
                        role["metadata"][7] += 1
                    altered["aggregate_sha256"] = reference.record_digest({
                        key: value for key, value in altered.items()
                        if key != "aggregate_sha256"
                    })
                    changed = {
                        **native, "files": {
                            "records": {
                                **native["files"]["records"],
                                "boot-inputs.json": (
                                    b"synthetic rehashed fixture\n", altered),
                            },
                        },
                    }
                    with self.assertRaisesRegex(
                            ParityError, "boot local-boot executable custody changed"):
                        compare_boot_inputs(python, changed, installed)
            altered = copy.deepcopy(native_record)
            altered["files"]["package_tool"] = copy.deepcopy(
                altered["files"]["local_boot_tool"])
            altered["aggregate_sha256"] = reference.record_digest({
                key: value for key, value in altered.items()
                if key != "aggregate_sha256"
            })
            changed = {
                **native, "files": {
                    "records": {
                        **native["files"]["records"],
                        "boot-inputs.json": (
                            b"synthetic rehashed unrelated role\n", altered),
                    },
                },
            }
            with self.assertRaises(reference.Refusal):
                compare_boot_inputs(python, changed, installed)
            wrong_path = local_boot_install_path(
                native["roots"][0], "python")
            write(wrong_path, b"synthetic shared local boot executable", 0o700)
            substituted, _ = reference.physical_file_record(wrong_path)
            changed_record = copy.deepcopy(native_record)
            changed_record["files"]["local_boot_tool"] = substituted
            changed_record["aggregate_sha256"] = reference.record_digest({
                key: value for key, value in changed_record.items()
                if key != "aggregate_sha256"
            })
            changed = {
                **native, "files": {
                    "records": {
                        **native["files"]["records"],
                        "boot-inputs.json": (
                            b"synthetic rehashed substitution\n", changed_record),
                    },
                },
            }
            with self.assertRaisesRegex(
                    ParityError, "boot local-boot executable custody changed"):
                verified_boot_inputs(changed, "native", installed[1])
            with self.assertRaisesRegex(
                    ParityError, "native local-boot executable substituted"):
                verified_local_boot_install(native, "native")
            wrong_path.unlink()
            local_boot_install_path(native["roots"][0], "native").write_bytes(
                b"synthetic substituted executable")
            self.assertIn("local_boot_install:sha256",
                          compare_local_boot_installs(python, native)[1])
        finally:
            reference.APP = original_app
            reference.executable_runtime_paths = original_runtime_paths
            shutil.rmtree(root)

    def test_unreviewed_retained_paths_remain_strict(self):

        class Exit:
            returncode = 0
            stderr = b""

        def seen(prefix):
            return {
                "exit": Exit(), "roots": (Path("/private/" + prefix),),
                "files": {
                    "order": (), "records": {}, "artifacts": {},
                    "retained": {
                        "private/" + prefix + ".log": ("file", 0o600, 123),
                    },
                },
            }

        self.assertEqual(
            compare_observations(seen("unreviewed-a"), seen("unreviewed-b")),
            ["retained"])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="action", required=True)
    sub.add_parser("local", help="run real Python and host-fixture Zig no-KVM CLIs")
    full_parser = sub.add_parser("full", help="real x86/KVM differential, no skips")
    full_parser.add_argument("--case", choices=(
        "success", "build-start-tamper", "missing-build",
        "occupied-boot-slot", "prior-build-output"), default="success")
    for name in ("root", "python-repository", "native-repository",
                 "runtime-template", "wamr-source", "controller"):
        full_parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    if args.action == "full":
        full(args)
    else:
        zig = shutil.which("zig")
        check(zig is not None, "Zig 0.16.0 required")
        failures, categories = no_kvm([
            zig, "build", "--build-file",
            str(HERE / "differential.build.zig"),
        ])
        print(json.dumps({"categories": categories, "mismatches": failures},
                         sort_keys=True))
        check(not failures, "local differential mismatches: " +
              ", ".join(failures))


if __name__ == "__main__":
    try:
        main()
    except ParityError as exc:
        print("DIFFERENTIAL_REFUSED: " + str(exc), file=sys.stderr)
        raise SystemExit(1) from None
