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
import struct
import subprocess
import sys
import tempfile
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
    "support/apps/wamr-aot/validator/base64.zig",
    "support/apps/wamr-aot/validator/coremark.zig",
    "support/apps/wamr-aot/validator/input.zig",
    "support/apps/wamr-aot/validator/optional.zig",
    "support/apps/wamr-aot/validator/records.zig",
    "support/apps/wamr-aot/validator/root.zig",
    "support/apps/wamr-aot/validator/sampler.zig",
    "support/apps/wamr-aot/validator/tiny.zig",
    "support/build/wamr-native-ci/build.zig",
    "support/build/wamr-native-ci/build.zig.zon",
    "support/build/wamr-native-ci/controller/accepted_run.zig",
    "support/build/wamr-native-ci/controller/boot_pipeline.zig",
    "support/build/wamr-native-ci/controller/build_pipeline.zig",
    "support/build/wamr-native-ci/controller/cli.zig",
    "support/build/wamr-native-ci/controller/command_adapter.zig",
    "support/build/wamr-native-ci/controller/command_plan.zig",
    "support/build/wamr-native-ci/controller/command_validation.zig",
    "support/build/wamr-native-ci/controller/custody_files.zig",
    "support/build/wamr-native-ci/controller/custody_limits.zig",
    "support/build/wamr-native-ci/controller/dependency_custody.zig",
    "support/build/wamr-native-ci/controller/fixture_contract.zig",
    "support/build/wamr-native-ci/controller/fixture_runner.zig",
    "support/build/wamr-native-ci/controller/handoff_inspect.zig",
    "support/build/wamr-native-ci/controller/import_supervisor_identity.zig",
    "support/build/wamr-native-ci/controller/input_custody.zig",
    "support/build/wamr-native-ci/controller/install.zig",
    "support/build/wamr-native-ci/controller/install_target_tests.zig",
    "support/build/wamr-native-ci/controller/layout.zig",
    "support/build/wamr-native-ci/controller/main.zig",
    "support/build/wamr-native-ci/controller/portable_main.zig",
    "support/build/wamr-native-ci/controller/profile.zig",
    "support/build/wamr-native-ci/controller/public_image_serial.zig",
    "support/build/wamr-native-ci/controller/public_validator_build.zig",
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
    "support/tools/hyperv/local_boot/serial.zig",
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


def phase_snapshot(runtime, reference, rewritten_build_start=False):
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
    if rewritten_build_start:
        check("build-start.json" in records,
              "rewritten build-start evidence missing")
        publications = [
            item for item in publications if item[1] != "build-start.json"]
    ordered = tuple(name for _, name in publications)
    check(tuple(sorted(ordered, key=lambda name: ORDER.index(name)
                      if name in ORDER else len(ORDER))) == ordered,
          "evidence phase order changed")
    if rewritten_build_start:
        ordered = tuple(sorted(
            (*ordered, "build-start.json"),
            key=lambda name: ORDER.index(name)
            if name in ORDER else len(ORDER)))
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
        "WAMR_CI_PORTABLE_CONFIG": literal("1"),
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
REVIEWED_BOOT_COMMANDS = (
    "package", *MODES[:2], "finalize-qcow2", *MODES[2:4],
    "derive-fixed-vhd", *MODES[4:], "inspect",
)
REVIEWED_VALIDATOR_COMMANDS = (
    "log-validator-x2apic", "log-validator-legacy",
)


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
    if stage in REVIEWED_VALIDATOR_COMMANDS:
        contract = reference.production_command_contract(stage)
        if side == "native":
            contract = copy.deepcopy(contract)
            contract["output_limit"] = 64 * 1024
            contract["limits"]["stdout_bytes"] = 64 * 1024
            contract["limits"]["stderr_bytes"] = 4 * 1024
        return contract
    if (side == "python" or stage in SHARED_BUILD_STAGES
            or stage in REVIEWED_BOOT_COMMANDS):
        return reference.production_command_contract(stage)
    if stage == "fixtures":
        return native_fixture_contract(reference)
    return native_build_command_contract(reference, stage)


def checked_stage(record, log, side, reference, stage, seen=None):
    check(side in ("python", "native")
          and stage in (*REVIEWED_BUILD_COMMANDS, *REVIEWED_BOOT_COMMANDS,
                        *REVIEWED_VALIDATOR_COMMANDS),
          "unknown supervised stage/side")
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
    if stage in REVIEWED_VALIDATOR_COMMANDS:
        check(stderr["bytes"] == 0, f"{label} validator stderr changed")
    role_identities = None
    if seen is not None:
        runtime = seen["roots"][0]
        baseline = seen["files"]["records"]["build-start.json"][1]
        pinned = dict(baseline["consumer_inputs"]["files"])
        if stage in REVIEWED_BOOT_COMMANDS:
            boot_inputs = seen["files"]["records"]["boot-inputs.json"][1]["files"]
            pinned.update({
                "input:package_tool": boot_inputs["package_tool"],
                "input:local_boot_tool": boot_inputs["local_boot_tool"],
            })
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
    check(value["build_sha256"] == sha(records["build.json"][0])
          and value["finalization_sha256"] ==
          sha(records["qcow2-finalization.json"][0])
          and isinstance(value["boots"], dict)
          and value["boots"].keys() == set(reference.SIX_MODES[:4]),
          "qcow2 acceptance source commitment changed")
    for mode in reference.SIX_MODES[:4]:
        summary = value["boots"][mode]
        mode_raw, mode_record = records[mode + "-compute.json"]
        runtime = seen["roots"][0]
        work = runtime / "compute" / ("boot-" + mode)
        try:
            request = checked_file(work / "request.json", 64 * 1024)
            report = checked_file(work / "report.json", 64 * 1024)
            serial = checked_file(work / "hyperv-efi-boot.log", MAX_RECORD)
        except OSError:
            raise ParityError("qcow2 acceptance boot slot inaccessible") from None
        request_value = parsed(request, reference)
        report_value = parsed(report, reference)
        check(isinstance(summary, dict)
              and summary.keys() == {
                  "request_sha256", "report_sha256",
                  "serial_sha256", "compute_sha256",
              }
              and request_value["schema_version"] == 2
              and type(request_value["supervisor_pid"]) is int
              and request_value["supervisor_pid"] > 0
              and request_value["config"] == reference.config_for(
                  runtime, runtime / "compute",
                  reference.SIX_MODES.index(mode), reference.SIX_MODES)
              and mode_record["input_pins"] == request_value["pins"]
              and mode_record["report"] == report_value
              and report_value["serial_sha256"] == sha(serial)
              and report_value["serial_bytes"] == len(serial)
              and mode_record["request_sha256"] == sha(request)
              and mode_record["report_sha256"] == sha(report)
              and summary["request_sha256"] == sha(request)
              and summary["report_sha256"] == sha(report)
              and summary["serial_sha256"] == sha(serial)
              and summary["compute_sha256"] == sha(mode_raw),
              "qcow2 acceptance boot commitment changed")
    return value


def compare_qcow2_acceptance(left, right, reviewed_modes=None):
    first = verified_qcow2_acceptance(left)
    second = verified_qcow2_acceptance(right)
    first = copy.deepcopy(first)
    second = copy.deepcopy(second)
    for side in (first, second):
        side["boot_inputs_sha256"] = "<verified-own-boot-input-bytes>"
    if reviewed_modes is not None:
        check(set(reviewed_modes) == set(MODES[:4]),
              "unreviewed QCOW2 acceptance boot roles")
        for side in (first, second):
            side["build_sha256"] = "<verified-own-build>"
            side["finalization_sha256"] = "<verified-own-finalization>"
            for mode in MODES[:4]:
                side["boots"][mode] = {
                    field: "<verified-own-" + field + ">"
                    for field in ("request_sha256", "report_sha256",
                                  "serial_sha256", "compute_sha256")
                }
    a = Normalizer(left["roots"]).normalize(first)
    b = Normalizer(right["roots"]).normalize(second)
    failures = [
        "record_content:qcow2-acceptance.json." + field
        for field in sorted(ACCEPTANCE_FIELDS - {"boot_inputs_sha256"})
        if a[field] != b[field]
    ]
    if a["boots"] != b["boots"]:
        for mode in first["modes"]:
            for field in ("request_sha256", "report_sha256",
                          "serial_sha256", "compute_sha256"):
                if a["boots"][mode][field] != b["boots"][mode][field]:
                    failures.append(
                        "record_content:qcow2-acceptance.json.boots." +
                        mode + "." + field)
    return failures


IMAGE_CONFIG_DOMAIN = b"uk.wamr.compute-image-config-v1\x00"
IMAGE_PROVENANCE_FIELDS = (
    "producer_sha256", "producer_bytes", "miz_revision",
    "config_sha256", "parent_kind", "parent_sha256",
)


def verified_image_provenance(seen, name):
    records = seen["files"]["records"]
    runtime = seen["roots"][0]
    if name == "qcow2-finalization.json":
        intent_name = "qcow2-finalization-intent.json"
        source = "unikraft.raw"
        parent = records["package.json"][1]["image"]["raw"]["sha256"]
        kind = "raw"
        source_field = "expected_source_sha256"
    else:
        check(name == "fixed-vhd-derivation.json",
              "unknown image provenance role")
        intent_name = "fixed-vhd-derivation-intent.json"
        source = "unikraft.qcow2"
        parent = records["qcow2-finalization.json"][1]["output"]["sha256"]
        kind = "qcow2"
        source_field = "accepted_qcow2_sha256"
    intent_raw, intent = records[intent_name]
    provenance = records[name][1]["provenance"]
    package_tool = records["boot-inputs.json"][1]["files"]["package_tool"]
    check(parsed(intent_raw, seen["reference"]) == intent
          and set(provenance) == set(IMAGE_PROVENANCE_FIELDS)
          and intent["source_path"] == str(runtime / "compute/package" / source)
          and intent[source_field] == parent
          and provenance == {
              "producer_sha256": package_tool["sha256"],
              "producer_bytes": package_tool["metadata"][6],
              "miz_revision": records["package.json"][1]["image"]["miz_revision"],
              "config_sha256": sha(IMAGE_CONFIG_DOMAIN + intent_raw),
              "parent_kind": kind, "parent_sha256": parent,
          }, "image provenance source/config commitment changed")
    return intent


def reviewed_image_provenance(left, right, name):
    a_intent = verified_image_provenance(left, name)
    b_intent = verified_image_provenance(right, name)
    check(Normalizer(left["roots"]).normalize(a_intent) ==
          Normalizer(right["roots"]).normalize(b_intent),
          "image intent semantic difference")
    normalized = []
    for side in (left, right):
        record = copy.deepcopy(side["files"]["records"][name][1])
        record["provenance"]["config_sha256"] = "<verified-root-bound-intent>"
        normalized.append(Normalizer(side["roots"]).normalize(record))
    check(normalized[0] == normalized[1],
          "image finalization semantic difference")


SERIAL_TIMESTAMP = re.compile(rb"(?m)^\[\s*[0-9]+\.[0-9]{6}\]")
SERIAL_ANSI = re.compile(rb"\x1b\[[0-?]*[ -/]*[@-~]")
SERIAL_NUMBER = re.compile(
    rb"(?<![A-Za-z_])(?:0x[0-9a-fA-F]+|[0-9]+)(?![A-Za-z_])")


def diagnostic_serial_text(raw):
    return SERIAL_ANSI.sub(b"", raw).replace(b"\x00", b"").replace(
        b"\r\n", b"\n")


def serial_first_phase(text, line_index):
    lines = text.splitlines(keepends=True)
    position = len(b"".join(lines[:line_index]))
    for marker, phase in (
            (b"Hyper-V Hv#1 hypercall page enabled", "before-hyperv"),
            (b"Powered by", "hyperv-init"),
            (b"Calling main(", "before-main"),
            (b"WAMR_NATIVE_AOT_OK answer=42 teardown=0", "guest-main"),
            (b"main returned 0", "guest-return")):
        found = text.find(marker)
        if found < 0:
            return "unlocated"
        if position <= found:
            return phase
    return "after-return"


def verified_serial(seen, mode):
    reference = seen["reference"]
    record = seen["files"]["records"][mode + "-compute.json"][1]
    work = seen["roots"][0] / "compute" / ("boot-" + mode)
    try:
        serial = checked_file(work / "hyperv-efi-boot.log", MAX_RECORD)
        report = checked_file(work / "report.json", 64 * 1024)
    except OSError:
        raise ParityError("boot serial/report inaccessible") from None
    check(parsed(report, reference) == record["report"]
          and sha(report) == record["report_sha256"]
          and record["report"]["serial_bytes"] == len(serial)
          and record["report"]["serial_sha256"] == sha(serial),
          "boot serial/report commitment changed")
    return serial


def verified_mode(seen, mode):
    reference = seen["reference"]
    records = seen["files"]["records"]
    record_raw, record = records[mode + "-compute.json"]
    runtime = seen["roots"][0]
    work = runtime / "compute" / ("boot-" + mode)
    serial = verified_serial(seen, mode)
    try:
        request_raw = checked_file(work / "request.json", 64 * 1024)
    except OSError:
        raise ParityError("boot request inaccessible") from None
    request = parsed(request_raw, reference)
    index = MODES.index(mode)
    config = reference.config_for(runtime, runtime / "compute", index,
                                  reference.SIX_MODES)
    check(set(request) == {"schema_version", "supervisor_pid", "config", "pins"}
          and request["schema_version"] == 2
          and type(request["supervisor_pid"]) is int
          and request["supervisor_pid"] > 0
          and request["config"] == config
          and set(record) == {"scope", "report", "input_pins",
                              "request_sha256", "report_sha256", "compute"}
          and record["scope"] == "local_native_compute_only"
          and request["pins"] == record["input_pins"]
          and record["request_sha256"] == sha(request_raw)
          and parsed(record_raw, reference) == record,
          "boot request/compute commitment changed")
    paths = (config["source"]["path"], config["ovmf_code"],
             config["ovmf_vars"], config["qemu"])
    check(len(request["pins"]) == len(paths), "boot physical pin count changed")
    for pin, path in zip(request["pins"], paths):
        physical, _ = reference.physical_file_record(Path(path))
        check(pin == reference.pin_from_record(physical),
              "boot physical input pin changed")
    report = record["report"]
    check(report["passed"] is True and report["consumed"] is True
          and report["cleanup_complete"] is True
          and report["input_unchanged"] is True
          and report["serial_valid"] is True
          and report["serial_limit_reached"] is False
          and report["termination"] == {"exited": 0}
          and report["failures"] == {
              "primary": None, "cleanup": None, "recording": None,
          }, "boot report is not a successful local run")
    return request, record, serial


def reviewed_mode(left, right, mode):
    first, second = verified_mode(left, mode), verified_mode(right, mode)
    a_request, a_record, a_serial = first
    b_request, b_record, b_serial = second
    a_text = SERIAL_TIMESTAMP.sub(b"<time>", diagnostic_serial_text(a_serial))
    b_text = SERIAL_TIMESTAMP.sub(b"<time>", diagnostic_serial_text(b_serial))
    check(a_text == b_text, "unreviewed boot serial difference")
    a_request = dict(a_request, supervisor_pid="<verified-positive-pid>")
    b_request = dict(b_request, supervisor_pid="<verified-positive-pid>")
    normalized = lambda side, value: Normalizer(side["roots"]).normalize(value)
    check(normalized(left, a_request) == normalized(right, b_request),
          "boot request semantic difference")
    a_report = dict(a_record["report"], serial_sha256="<verified-serial>")
    b_report = dict(b_record["report"], serial_sha256="<verified-serial>")
    a_record = dict(a_record, report=a_report,
                    request_sha256="<verified-request>",
                    report_sha256="<verified-report>")
    b_record = dict(b_record, report=b_report,
                    request_sha256="<verified-request>",
                    report_sha256="<verified-report>")
    check(normalized(left, a_record) == normalized(right, b_record),
          "boot compute semantic difference")
    return first, second


def serial_differences(left, right):
    failures = []
    for mode in MODES:
        name = mode + "-compute.json"
        if name not in left["files"]["records"] or name not in right["files"]["records"]:
            continue
        a, b = verified_serial(left, mode), verified_serial(right, mode)
        if a == b:
            continue
        label = "serial:" + mode
        timestamp_only = (SERIAL_TIMESTAMP.sub(b"<time>", a) ==
                          SERIAL_TIMESTAMP.sub(b"<time>", b))
        if timestamp_only:
            failures.append(label + ".kernel-timestamp-only")
        else:
            failures.append(label + ".non-timestamp-difference")
        clean_a, clean_b = diagnostic_serial_text(a), diagnostic_serial_text(b)
        if not timestamp_only and clean_a == clean_b:
            failures.append(label + ".uart-framing-only")
        elif not timestamp_only and SERIAL_TIMESTAMP.sub(b"<time>", clean_a) == (
                SERIAL_TIMESTAMP.sub(b"<time>", clean_b)):
            failures.append(label + ".uart-framing-and-timestamp-only")
        elif not timestamp_only and SERIAL_NUMBER.sub(b"<number>", clean_a) == (
                SERIAL_NUMBER.sub(b"<number>", clean_b)):
            failures.append(label + ".number-fields-only")
        clean_lines_a = clean_a.splitlines(keepends=True)
        clean_lines_b = clean_b.splitlines(keepends=True)
        clean_first = next(
            (i for i, pair in enumerate(zip(clean_lines_a, clean_lines_b))
             if pair[0] != pair[1]),
            min(len(clean_lines_a), len(clean_lines_b)))
        phases = (serial_first_phase(clean_a, clean_first),
                  serial_first_phase(clean_b, clean_first))
        failures.append(label + ".first-phase." +
                        (phases[0] if phases[0] == phases[1] else "shifted"))
        lines_a, lines_b = a.splitlines(keepends=True), b.splitlines(keepends=True)
        first = next((i for i, pair in enumerate(zip(lines_a, lines_b))
                      if pair[0] != pair[1]), min(len(lines_a), len(lines_b)))
        different = (lines_a[first] if first < len(lines_a) else b"",
                     lines_b[first] if first < len(lines_b) else b"")
        if all(SERIAL_TIMESTAMP.match(line) for line in different):
            failures.append(label + ".first-line.kernel-timestamp")
        elif first == min(len(lines_a), len(lines_b)):
            failures.append(label + ".first-line.appended-or-missing")
        else:
            failures.append(label + ".first-line.other")
        if len(a) != len(b):
            failures.append(label + ".bytes")
    return failures


BOOT_SUMMARY_FIELDS = {
    "request_sha256", "report_sha256", "serial_sha256", "compute_sha256",
}


def verified_boot_summaries(seen, boots, modes):
    records = seen["files"]["records"]
    check(isinstance(boots, dict) and boots.keys() == set(modes),
          "boot summary roles changed")
    for mode in modes:
        summary = boots[mode]
        record_raw, record = records[mode + "-compute.json"]
        _, _, serial = verified_mode(seen, mode)
        check(set(summary) == BOOT_SUMMARY_FIELDS
              and summary == {
                  "request_sha256": record["request_sha256"],
                  "report_sha256": record["report_sha256"],
                  "serial_sha256": sha(serial),
                  "compute_sha256": sha(record_raw),
              }, "boot summary commitment changed")


def reviewed_vhd_gate(left, right):
    normalized = []
    for side in (left, right):
        records = side["files"]["records"]
        value = copy.deepcopy(records["fixed-vhd-derivation-gate.json"][1])
        check(set(value) == {
            "schema", "schema_version", "profile", "status",
            "accepted_qcow2_sha256", "qcow2_acceptance_sha256",
            "derivation_intent_sha256", "derived_output_absent",
        } and value["qcow2_acceptance_sha256"] ==
            sha(records["qcow2-acceptance.json"][0])
          and value["derivation_intent_sha256"] ==
            sha(records["fixed-vhd-derivation-intent.json"][0]),
            "VHD gate source commitment changed")
        for field in ("qcow2_acceptance_sha256",
                      "derivation_intent_sha256"):
            value[field] = "<verified-own-" + field + ">"
        normalized.append(Normalizer(side["roots"]).normalize(value))
    check(normalized[0] == normalized[1], "VHD gate semantic difference")


def reviewed_final_inspection(left, right):
    names = {
        "build-start.json", "build.json", "boot-inputs.json", "package.json",
        "qcow2-finalization-intent.json", "qcow2-finalization.json",
        "qcow2-acceptance.json", "fixed-vhd-derivation-intent.json",
        "fixed-vhd-derivation-gate.json", "fixed-vhd-derivation.json",
    }
    normalized = []
    for side in (left, right):
        records = side["files"]["records"]
        value = copy.deepcopy(records["final-inspection.json"][1])
        check(set(value) == {
            "schema", "schema_version", "profile", "status", "source",
            "artifacts", "records", "modes", "boots",
        } and value["records"].keys() == names
          and value["modes"] == list(MODES),
          "final inspection roles changed")
        for name in names:
            check(value["records"][name] == sha(records[name][0]),
                  "final inspection record commitment changed")
            value["records"][name] = "<verified-own-record>"
        verified_boot_summaries(side, value["boots"], MODES)
        for summary in value["boots"].values():
            for field in BOOT_SUMMARY_FIELDS:
                summary[field] = "<verified-own-" + field + ">"
        normalized.append(Normalizer(side["roots"]).normalize(value))
    check(normalized[0] == normalized[1],
          "final inspection semantic difference")


REVIEWED_BUILD_COMMANDS = (
    "adapter", "local-boot-tool", "fixtures", *SHARED_BUILD_STAGES,
)


def source_root_only_config(left, right):
    normalized = []
    for side in (left, right):
        repository = side["roots"][1]
        raw = checked_file(repository / "support/apps/wamr-aot/.config", 1024 * 1024)
        recorded = side["files"]["artifacts"]["config"]
        check(len(raw) == recorded[0] and sha(raw) == recorded[1],
              "config changed during comparison")
        source_root = os.fsencode(repository)
        if source_root not in raw:
            return False
        normalized.append(raw.replace(source_root, b"<source-root>"))
    return normalized[0] == normalized[1]


RUNTIME_FILE_ROLES = {
    "embedded.c": "embedded",
    "identity.h": "identity",
    "libwamr-aot.a": "library",
    "tiny.cwasm": "aot",
    "tiny.wasm": "wasm",
    "wamr_aot.h": "header",
    "wamrc": "compiler",
}

IMAGE_SECTION_NAMES = {
    name.encode(): name[1:] for name in (
        ".text", ".rodata", ".data", ".bss", ".dynamic", ".dynsym",
        ".dynstr", ".gnu.hash", ".hash", ".rela.dyn", ".rela.plt",
        ".eh_frame", ".eh_frame_hdr", ".got", ".plt", ".init_array",
        ".fini_array", ".debug_info", ".debug_abbrev", ".debug_line",
        ".debug_str", ".debug_ranges", ".debug_rnglists", ".debug_line_str",
        ".symtab", ".strtab", ".shstrtab",
        ".uk_libinfo",
    )
}


def runtime_input_differences(left, right):
    identities = []
    for side in (left, right):
        repository = side["roots"][1]
        raw = checked_file(
            repository / "support/apps/wamr-aot/build/artifacts/identity.json",
            4 * 1024 * 1024)
        committed = side["files"]["records"]["build.json"][1]["image"][
            "runtime_inputs_sha256"]
        check(sha(raw) == committed, "runtime identity changed during comparison")
        identity = json.loads(raw)
        check(isinstance(identity, dict) and identity.get("schema_version") == 1
              and identity.get("variant") == "tiny"
              and isinstance(identity.get("files"), dict)
              and identity["files"].keys() == RUNTIME_FILE_ROLES.keys()
              and isinstance(identity.get("commands"), list),
              "runtime identity diagnostic shape changed")
        identities.append(identity)
    first, second = identities
    failures = [
        "record_content:build.json.image.runtime_inputs.files." + role
        for name, role in RUNTIME_FILE_ROLES.items()
        if first["files"][name] != second["files"][name]
    ]
    if first["commands"] != second["commands"]:
        failures.append("record_content:build.json.image.runtime_inputs.commands")
    first_metadata = {key: value for key, value in first.items()
                      if key not in ("files", "commands")}
    second_metadata = {key: value for key, value in second.items()
                       if key not in ("files", "commands")}
    if first_metadata != second_metadata:
        failures.append("record_content:build.json.image.runtime_inputs.metadata")
    return failures or ["record_content:build.json.image.runtime_inputs.bytes"]


def image_regions(side, name, committed, kind):
    path = side["reference"].APP / "build" / name
    try:
        before = path.lstat()
    except OSError:
        raise ParityError("image diagnostic input unavailable") from None
    check(stat.S_ISREG(before.st_mode) and before.st_uid == os.getuid()
          and before.st_nlink == 1 and before.st_size <= 512 * 1024 * 1024,
          "unsafe image diagnostic input")
    regions = {}
    debug_strings = None
    try:
        handle = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError:
        raise ParityError("image diagnostic input unavailable") from None
    with os.fdopen(handle, "rb") as stream:
        handle = stream.fileno()
        opened = os.fstat(handle)
        check((before.st_dev, before.st_ino) == (opened.st_dev, opened.st_ino),
              "image changed during comparison")

        def read(offset, size):
            check(offset >= 0 and size >= 0 and offset <= before.st_size
                  and size <= before.st_size - offset,
                  "invalid image diagnostic region")
            try:
                raw = os.pread(handle, size, offset)
            except OSError:
                raise ParityError("image diagnostic read failed") from None
            check(len(raw) == size, "image changed during comparison")
            return raw

        def region(label, offset, size):
            digest = hashlib.sha256()
            for position in range(offset, offset + size, 1024 * 1024):
                digest.update(read(position, min(1024 * 1024, offset + size - position)))
            regions[label] = (size, digest.hexdigest())

        if kind == "efi":
            header = read(0, 200)
            check(header[:2] == b"MZ" and header[64:68] == b"PE\0\0",
                  "invalid EFI diagnostic header")
            count = struct.unpack_from("<H", header, 70)[0]
            header_size = struct.unpack_from("<I", header, 148)[0]
            check(0 < count <= 32 and 200 + 40 * count <= header_size <=
                  min(before.st_size, 1024 * 1024), "invalid EFI diagnostic sections")
            region("headers", 0, header_size)
            for index in range(count):
                section = read(200 + index * 40, 40)
                size, offset = struct.unpack_from("<II", section, 16)
                region(f"section-{index}", offset, size)
        else:
            header = read(0, 64)
            check(header[:6] == b"\x7fELF\x02\x01",
                  "invalid debug ELF diagnostic header")
            table = struct.unpack_from("<Q", header, 40)[0]
            entry_size, count = struct.unpack_from("<HH", header, 58)
            check(entry_size == 64 and 0 < count <= 512,
                  "invalid debug ELF diagnostic sections")
            read(table, entry_size * count)
            region("headers", 0, 64)
            region("section-table", table, entry_size * count)
            names_index = struct.unpack_from("<H", header, 62)[0]
            names = b""
            if names_index:
                check(names_index < count, "invalid debug ELF section names")
                names_section = read(table + names_index * entry_size, entry_size)
                names_offset, names_size = struct.unpack_from(
                    "<QQ", names_section, 24)
                check(struct.unpack_from("<I", names_section, 4)[0] == 3
                      and names_size <= 64 * 1024,
                      "invalid debug ELF section names")
                names = read(names_offset, names_size)
            for index in range(count):
                section = read(table + index * entry_size, entry_size)
                section_type = struct.unpack_from("<I", section, 4)[0]
                flags = struct.unpack_from("<Q", section, 8)[0]
                offset, size = struct.unpack_from("<QQ", section, 24)
                label = ("alloc" if flags & 2 else "nonalloc") + f"-{index}"
                name_offset = struct.unpack_from("<I", section)[0]
                if name_offset < len(names):
                    end = names.find(b"\0", name_offset)
                    if end != -1:
                        known = IMAGE_SECTION_NAMES.get(names[name_offset:end])
                        if known:
                            label += "." + known
                if section_type == 8:
                    regions[label] = (size, None)
                else:
                    region(label, offset, size)
                    if kind == "debug" and label.endswith(".debug_str"):
                        if size <= 64 * 1024 * 1024:
                            debug_strings = read(offset, size)
        digest = hashlib.sha256()
        for position in range(0, before.st_size, 1024 * 1024):
            digest.update(read(position, min(1024 * 1024, before.st_size - position)))
        after = os.fstat(handle)
        check((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns,
               before.st_ctime_ns) ==
              (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns,
               after.st_ctime_ns) and digest.hexdigest() == committed,
              "image changed during comparison")
    return regions, debug_strings


def debug_string_differences(first, second, left, right):
    prefix = "record_content:build.json.image.files.debug.debug_str."
    if first is None or second is None:
        return [prefix + "unavailable"]
    first_root = os.fsencode(str(left["reference"].REPO))
    second_root = os.fsencode(str(right["reference"].REPO))
    check(first_root and second_root, "invalid debug diagnostic root")
    first_entries = set(first.split(b"\0"))
    second_entries = set(second.split(b"\0"))
    unique = first_entries ^ second_entries
    categories = set()
    for entry in unique:
        root = first_root if entry in first_entries else second_root
        if root in entry:
            categories.add("source-root")
            categories.add("source-root.leading" if entry.startswith(root)
                           else "source-root.embedded")
            app_build = root + b"/support/apps/wamr-aot/build"
            if entry == app_build:
                categories.add("source-root.app-build-directory")
            elif app_build + b"/" in entry and not any(
                    app_build + suffix in entry for suffix in (
                        b"/artifacts/embedded.c", b"/libuklibid/",
                        b"/appwamraot/")):
                categories.add("source-root.app-build-other")
                tail = entry.split(app_build + b"/", 1)[1]
                categories.add("source-root.app-build.immediate-child"
                               if b"/" not in tail else
                               "source-root.app-build.nested-child")
                for name, label in (
                        (b"artifacts", "artifacts-dir"),
                        (b"include", "include-dir"),
                        (b"native-environment", "native-environment"),
                        (b"tool", "tool-output"),
                        (b".zig-cache", "zig-cache"),
                        (b".d", "dependency-output")):
                    if tail == name or tail.startswith(name + b"/"):
                        categories.add("source-root.app-build." + label)
                if tail.startswith(b"native-environment/"):
                    nested = tail[len(b"native-environment/"):]
                    matched = False
                    for name in (b"zig_local_cache", b"zig_global_cache",
                                 b"tmp", b"xdg_cache", b"xdg_config"):
                        if nested == name or nested.startswith(name + b"/"):
                            matched = True
                            categories.add(
                                "source-root.app-build.native-environment." +
                                name.decode("ascii"))
                            if nested.startswith(name + b"/o/"):
                                categories.add(
                                    "source-root.app-build.native-environment." +
                                    name.decode("ascii") + ".object-cache")
                    if not matched:
                        categories.add(
                            "source-root.app-build.native-environment.other")
                for suffix, label in (
                        (b"/include/", "generated-include"),
                        (b"/artifacts/", "generated-artifacts"),
                        (b"/lib", "library-output"),
                        (b"/plat", "platform-output"),
                        (b"/kconfig/", "kconfig-output")):
                    if app_build + suffix in entry:
                        categories.add("source-root.app-build." + label)
                if entry.endswith(b".o"):
                    categories.add("source-root.app-build.object")
                elif entry.endswith(b".c"):
                    categories.add("source-root.app-build.generated-c")
                elif entry.endswith(b".h"):
                    categories.add("source-root.app-build.generated-header")
                elif entry.endswith((b".a", b".dbg", b".json", b".cmd",
                                     b".wasm", b".cwasm", b".ld", b".S")):
                    categories.add("source-root.app-build.other-file")
            if b"-fdebug-prefix-map=" in entry or b"-ffile-prefix-map=" in entry:
                categories.add("source-root.recorded-switch")
            for suffix, label in (
                    (b"/support/apps/wamr-aot/build", "app-build"),
                    (b"/support/apps/wamr-aot/build/artifacts/embedded.c",
                     "embedded-source"),
                    (b"/support/apps/wamr-aot/build/libuklibid/",
                     "libuklibid-output"),
                    (b"/support/apps/wamr-aot/build/appwamraot/",
                     "appwamraot-output"),
                    (b"/support/apps/wamr-aot/", "app-source"),
                    (b"/lib/", "lib-source"),
                    (b"/arch/", "arch-source"),
                    (b"/plat/", "plat-source"),
                    (b"/.zig-cache/", "zig-cache")):
                if root + suffix in entry:
                    categories.add("source-root." + label)
        elif entry.startswith(b"/"):
            categories.add("other-absolute")
        elif b"/" in entry:
            categories.add("relative-path")
        else:
            categories.add("other")
    if not unique:
        categories.add("order-or-duplicates")
    if len(first.split(b"\0")) != len(second.split(b"\0")):
        categories.add("string-count")
    if first.replace(first_root, b"/wamr-ci/source") == second.replace(
            second_root, b"/wamr-ci/source"):
        categories.add("source-root-remap-equal")
    if {entry.replace(first_root, b"/wamr-ci/source")
            for entry in first_entries} == {
            entry.replace(second_root, b"/wamr-ci/source")
            for entry in second_entries}:
        categories.add("source-root-string-set-equal")
    return [prefix + category for category in sorted(categories)]


def image_region_differences(left, right, name, kind, first_digest, second_digest):
    first, first_strings = image_regions(left, name, first_digest, kind)
    second, second_strings = image_regions(right, name, second_digest, kind)
    prefix = "record_content:build.json.image.files." + kind + "."
    differences = [prefix + key for key in sorted(first.keys() | second.keys())
                   if first.get(key) != second.get(key)]
    if kind == "debug" and any(key.endswith(".debug_str")
                               and first.get(key) != second.get(key)
                               for key in first.keys() | second.keys()):
        differences.extend(debug_string_differences(
            first_strings, second_strings, left, right))
    return differences or [prefix + "outside-sections"]


def build_image_differences(left, right, verified_tool_roles=False):
    first = left["files"]["records"]["build.json"][1]["image"]
    second = right["files"]["records"]["build.json"][1]["image"]
    check(isinstance(first, dict) and isinstance(second, dict)
          and first.keys() == second.keys(), "build image field membership changed")
    failures = []
    for field in ("schema_version", "scope", "unikraft_revision",
                  "unikraft_diff_sha256"):
        if first.get(field) != second.get(field):
            failures.append("record_content:build.json.image." + field)
    if "command" in first and first["command"] != second["command"]:
        first_command = Normalizer(left["roots"]).normalize(
            reviewed_image_command(left, verified_tool_roles))
        second_command = Normalizer(right["roots"]).normalize(
            reviewed_image_command(right, verified_tool_roles))
        if len(first_command) != len(second_command):
            failures.append("record_content:build.json.image.command.count")
        for index, (one, two) in enumerate(zip(first_command, second_command)):
            if one == two:
                continue
            failures.append("record_content:build.json.image.command.arg-" +
                            str(index))
            first_tool = image_command_tool_path_class(left, index)
            second_tool = image_command_tool_path_class(right, index)
            if first_tool is not None and second_tool is not None:
                check(first_tool[0] == second_tool[0],
                      "image command tool role changed")
                failures.append(
                    "record_content:build.json.image.command.tool." +
                    first_tool[0] + "." + first_tool[1] + "-to-" +
                    second_tool[1])
    for field in ("runtime_inputs_sha256", "solved_config_sha256",
                  "application_sources", "tools"):
        check(field in first, "missing build image field")
        if first[field] != second[field]:
            failures.append("record_content:build.json.image." + field)
            if field == "runtime_inputs_sha256":
                failures.extend(runtime_input_differences(left, right))
    files = (left["reference"].EFI, left["reference"].EFI + ".dbg",
             left["reference"].EFI + ".bootinfo")
    check(right["reference"].EFI == files[0]
          and isinstance(first.get("files"), dict)
          and isinstance(second.get("files"), dict)
          and first["files"].keys() == second["files"].keys() == set(files),
          "build image file membership changed")
    for role, name in zip(("efi", "debug", "bootinfo"), files):
        if first["files"][name] != second["files"][name]:
            failures.append("record_content:build.json.image.files." + role)
            if role in ("efi", "debug"):
                failures.extend(image_region_differences(
                    left, right, name, role, first["files"][name],
                    second["files"][name]))
    return failures


IMAGE_TOOL_OPTIONS = {
    "-Dmake-command=": ("make", ""),
    "-Dbison-command=": ("bison", ""),
    "-Dflex-command=": ("flex", ""),
    "-Dcompiler=": ("zig", " cc -target x86_64-freestanding-none"),
    "-Dhost-cc=": ("zig", " cc"),
    "-Dhost-cxx=": ("zig", " c++"),
    "-Dmake-arg=AR=": ("zig", " ar"),
    "-Dmake-arg=CP=": ("cp", " -f"),
    "-Dmake-arg=MKDIR=": ("mkdir", ""),
    "-Dmake-arg=PYTHON=": ("python3", ""),
    "-Dmake-arg=READLINK=": ("readlink", ""),
    "-Dmake-arg=ZIG=": ("zig", ""),
    "-Dmake-arg=YACC=": ("bison", ""),
    "-Dmake-arg=LEX=": ("flex", ""),
    "-Dmake-arg=NM=": ("llvm-nm", ""),
    "-Dmake-arg=OBJCOPY=": ("llvm-objcopy", ""),
    "-Dmake-arg=OBJDUMP=": ("llvm-objdump", ""),
    "-Dmake-arg=READELF=": ("llvm-readelf", ""),
    "-Dmake-arg=STRIP=": ("llvm-strip", ""),
}


def image_command_tool_path_class(side, index):
    command = side["files"]["records"]["build.json"][1]["image"]["command"]
    if index == 0:
        role, path = "zig", command[0]
    else:
        for prefix, (role, suffix) in IMAGE_TOOL_OPTIONS.items():
            arg = command[index]
            if arg.startswith(prefix) and arg.endswith(suffix):
                path = arg[len(prefix):len(arg) - len(suffix) if suffix else len(arg)]
                break
        else:
            return None
    if re.fullmatch(r"/proc/(?:self|[1-9][0-9]*)/fd/[0-9]+", path):
        kind = "retained"
    else:
        records = side["files"]["records"]
        pinned = records.get("build-start.json", (None, {}))[1].get(
            "consumer_inputs", {}).get("files", {}).get("tool:" + role, {})
        if path == pinned.get("path"):
            kind = "bound"
        elif any(path == str(root) or path.startswith(str(root) + "/")
                 for root in side["roots"]):
            kind = "root"
        elif path.startswith("/"):
            kind = "absolute"
        else:
            kind = "other"
    return role, kind


def reviewed_image_command(side, verified_tool_roles=False):
    command = side["files"]["records"]["build.json"][1]["image"]["command"]
    check(isinstance(command, list) and 4 <= len(command) <= 128
          and all(isinstance(arg, str) and len(arg) <= 4096 for arg in command)
          and command[1:4] == ["build", "native-images", "-j2"],
          "image command shape changed")
    repository = side["reference"].REPO
    app = side["reference"].APP
    expected = {
        "-Dapp=": str(app),
        "-Dnative-make-environment=":
            str(app / "build/native-environment/environment.json"),
        "-Dconfig=": str(app / "build/.config"),
        "-Dwamr-aot-tool=":
            str(side["roots"][0] / "compute/tools/bin/uk-wamr-aot-build"),
    }
    check(command[4:8] == [
        "--cache-dir", str(app / "build/native-environment/zig_local_cache"),
        "--global-cache-dir",
        str(app / "build/native-environment/zig_global_cache"),
    ], "image command cache paths changed")
    seen = set()
    seen_tools = set()
    tool_paths = {}
    roots = tuple(str(root) for root in side["roots"])
    pinned_tools = (side["files"]["records"]["build-start.json"][1]
                    ["consumer_inputs"]["files"] if verified_tool_roles else {})
    normalized = []
    def tool_path(role, path):
        check(path.startswith("/"), "image command tool path is not absolute")
        if role in tool_paths:
            check(tool_paths[role] == path, "image command tool role changed")
        else:
            tool_paths[role] = path
        if path.startswith("/proc/"):
            check(re.fullmatch(r"/proc/(?:self|[1-9][0-9]*)/fd/[0-9]+", path),
                  "image command retained tool path changed")
            if not verified_tool_roles:
                return path
        if verified_tool_roles:
            pinned = pinned_tools.get("tool:" + role)
            check(isinstance(pinned, dict) and isinstance(pinned.get("path"), str),
                  "image command pinned tool role missing")
            if path.startswith("/proc/") or path == pinned["path"]:
                return "<verified-tool:" + role + ">"
        for index, root in sorted(enumerate(roots),
                                  key=lambda item: len(item[1]), reverse=True):
            if path == root or path.startswith(root + "/"):
                return f"<root:{index}>" + path[len(root):]
        return path

    for index, arg in enumerate(command):
        if index == 0:
            normalized.append(tool_path("zig", arg))
            continue
        for prefix in expected:
            if not arg.startswith(prefix):
                continue
            check(prefix not in seen, "image command repeats a reviewed path")
            seen.add(prefix)
            path = arg[len(prefix):]
            check(path == expected[prefix], "image command path changed")
            for index, root in sorted(enumerate(roots),
                                      key=lambda item: len(item[1]), reverse=True):
                if path == root or path.startswith(root + "/"):
                    path = f"<root:{index}>" + path[len(root):]
                    break
            normalized.append(prefix + path)
            break
        else:
            for prefix, (role, suffix) in IMAGE_TOOL_OPTIONS.items():
                if not arg.startswith(prefix):
                    continue
                check(prefix not in seen_tools and arg.endswith(suffix),
                      "image command repeats a reviewed tool")
                seen_tools.add(prefix)
                path = arg[len(prefix):len(arg) - len(suffix) if suffix else len(arg)]
                normalized.append(prefix + tool_path(role, path) + suffix)
                break
            else:
                normalized.append(arg)
    check(seen == set(expected) and seen_tools == set(IMAGE_TOOL_OPTIONS)
          and app == repository / "support/apps/wamr-aot",
          "image command reviewed paths missing")
    return normalized


def retained_differences(first, second):
    slots = {"private", "fixtures", "package", "public-source",
             *(f"boot-{mode}" for mode in MODES)}
    fields = ("kind", "mode", "bytes")
    package_roles = {
        "package-job.json": "package-job",
        "package-report.json": "package-report",
        "qcow2-job.json": "qcow2-job",
        "qcow2-finalization.json": "qcow2-finalization",
        "vhd-job.json": "vhd-job",
        "fixed-vhd-derivation.json": "vhd-derivation",
        "unikraft.raw": "raw-image",
        "unikraft.qcow2": "qcow2-image",
        "unikraft.vhd": "vhd-image",
        "unikraft-derived.vhd": "derived-vhd-image",
    }
    boot_roles = {
        "request.json": "request",
        "report.json": "report",
        "hyperv-efi-boot.log": "serial",
        "log-validator-x2apic.log": "validator-log",
        "log-validator-legacy.log": "validator-log",
        "command-log-validator-x2apic.json": "validator-command",
        "command-log-validator-legacy.json": "validator-command",
    }
    labels = set()
    for path in first.keys() | second.keys():
        slot = path.split("/", 1)[0]
        check(slot in slots, "unexpected retained output role")
        role = slot + (".log" if slot == "private" and path.endswith(".log")
                       else "")
        if slot == "package":
            role += "." + package_roles.get(path.removeprefix("package/"), "other")
        elif slot.startswith("boot-"):
            role += "." + boot_roles.get(path.removeprefix(slot + "/"), "other")
        elif path == "private/log-validation" or re.fullmatch(
                r"private/log-validation/(?:boot-)?(?:raw|qcow2|vpc)-(?:x2apic|legacy-apic)-[0-9]{2}(?:/(?:private|evidence)(?:/(?:command-log-validator-(?:x2apic|legacy)\.json|log-validator-(?:x2apic|legacy)\.log))?)?",
                path):
            role = "private.validator-output"
        if path not in first or path not in second:
            labels.add(role + ".membership")
            continue
        check(len(first[path]) == len(second[path]) == len(fields),
              "invalid retained output shape")
        for field, one, two in zip(fields, first[path], second[path]):
            if one != two:
                labels.add(role + "." + field)
    return ["retained:" + label for label in sorted(labels)]


def boot_record_differences(name, first, second):
    if name in (mode + "-compute.json" for mode in MODES):
        fields = ("scope", "report", "input_pins", "request_sha256",
                  "report_sha256", "compute")
        nested = {
            "report": ("serial_bytes", "serial_sha256", "passed", "consumed",
                       "cleanup_complete", "input_unchanged", "serial_valid",
                       "serial_limit_reached", "termination", "failures"),
        }
    elif name == "qcow2-finalization.json":
        fields = ("schema", "schema_version", "status", "source_sha256",
                  "source_bytes", "output", "identity", "profile", "limits",
                  "provenance")
        nested = {
            "output": ("sha256", "file_bytes", "allocated", "virtual_bytes"),
            "identity": ("workload_sha256", "workload_bytes"),
            "provenance": IMAGE_PROVENANCE_FIELDS,
        }
    elif name == "fixed-vhd-derivation.json":
        fields = ("schema", "schema_version", "status",
                  "accepted_qcow2", "accepted_qcow2_decoded_sha256",
                  "accepted_qcow2_profile", "source_identity", "output",
                  "output_identity", "footer", "relocation", "limits",
                  "provenance")
        nested = {
            "output": ("sha256", "file_bytes", "allocated", "virtual_bytes"),
            "accepted_qcow2": ("sha256", "file_bytes", "virtual_bytes",
                               "metadata"),
            "provenance": IMAGE_PROVENANCE_FIELDS,
        }
    else:
        return []
    check(isinstance(first, dict) and isinstance(second, dict)
          and first.keys() == second.keys() == set(fields),
          "boot record diagnostic field membership changed")
    prefix = "record_content:" + name + "."
    failures = []
    for field in fields:
        if first[field] == second[field]:
            continue
        failures.append(prefix + field)
        if field in nested:
            check(isinstance(first[field], dict)
                  and isinstance(second[field], dict),
                  "boot record diagnostic field shape changed")
            failures.extend(prefix + field + "." + key
                            for key in nested[field]
                            if first[field].get(key) != second[field].get(key))
    return failures


def expected_native_fixture_report(reference):
    scenarios = []
    for name, primary, exit_code, stdout, stderr in (
            ("ok", "exited", 0, b"native fixture ok\n", b""),
            ("nonzero", "exited", 7, b"", b"PermissionDenied /private/secret\n"),
            ("partial", "exited", 9, b"partial private output\n", b""),
            ("signal", "signal", -1, b"", b""),
            ("overflow", "output_overflow", -1, b"X" * 33, b""),
            ("timeout", "timeout", -1, b"", b""),
            ("cancelled", "cancelled", -1, b"", b"")):
        scenarios.append({
            "name": name, "primary": primary, "exit_code": exit_code,
            "stdout_bytes": len(stdout), "stdout_sha256": sha(stdout),
            "stderr_bytes": len(stderr), "stderr_sha256": sha(stderr),
            "cleanup_complete": True, "executable_stable": True,
        })
    return reference.compact_json({
        "schema": "uk.wamr.native-ci-fixtures", "schema_version": 1,
        "production_modes": 6, "build_stages": 6, "status": "passed",
        "scenarios": scenarios,
    }, newline=True)


def reviewed_side_specific_outputs(python, native, left, right):
    left, right = dict(left), dict(right)

    def require_only(side, entries, other, path, limit, expected=None):
        check(path in entries and path not in other,
              "side-specific retained output changed")
        try:
            raw = checked_file(side["roots"][0] / "compute" / path, limit)
        except OSError:
            raise ParityError("side-specific retained output inaccessible") from None
        check(entries.pop(path) == ("file", 0o600, len(raw)),
              "side-specific retained output changed")
        if expected is not None:
            check(raw == expected, "side-specific retained content changed")
        return raw

    reference = python["reference"]
    require_only(python, left, right, "private/zig-version.log", 64,
                 b"0.16.0\n")
    require_only(python, left, right, "private/supervisor-version.log", 127,
                 (reference.COMMAND_SUPERVISOR_VERSION + "\n").encode("ascii"))
    supervisor_log = require_only(
        python, left, right, "private/supervisor-build.log", 8 * 1024 * 1024)
    check(reference.command_error_markers(supervisor_log) == [],
          "supervisor build diagnostic changed")
    metadata_path = "private/source-metadata.json"
    metadata = require_only(python, left, right, metadata_path, MAX_RECORD)
    try:
        baseline = reference.source_metadata_document(
            python["roots"][0] / "compute" / metadata_path)
    except (OSError, reference.Refusal):
        raise ParityError("source metadata diagnostic changed") from None
    check(parsed(metadata, reference) == baseline and baseline["records"],
          "source metadata diagnostic changed")
    require_only(native, right, left, "fixtures/native-scenarios.json", 8192,
                 expected_native_fixture_report(native["reference"]))
    return left, right


def verified_image_job(seen, name):
    reference = seen["reference"]
    runtime = seen["roots"][0]
    records = seen["files"]["records"]
    kind, intent_name, source_name, fields = {
        "qcow2-job.json": (
            "qcow2", "qcow2-finalization-intent.json", "unikraft.raw",
            ("expected_virtual_bytes", "expected_workload_sha256",
             "expected_workload_bytes"),
        ),
        "vhd-job.json": (
            "vhd", "fixed-vhd-derivation-intent.json", "unikraft.qcow2",
            ("expected_capacity_bytes",),
        ),
    }[name]
    path = runtime / "compute/package" / name
    try:
        job = parsed(checked_file(path, 64 * 1024), reference)
    except OSError:
        raise ParityError("image job inaccessible") from None
    intent_raw, intent = records[intent_name]
    source_path = runtime / "compute/package" / source_name
    source, _ = reference.physical_file_record(source_path)
    package_tool = records["boot-inputs.json"][1]["files"]["package_tool"]
    parent = ("expected_source_sha256" if kind == "qcow2"
              else "accepted_qcow2_sha256")
    check(set(job) == {
        "schema_version", "supervisor_pid", "state_dir", "attempt",
        "source", "producer", "limits", "config_sha256", *fields,
    } and job["schema_version"] == 2
      and type(job["supervisor_pid"]) is int and job["supervisor_pid"] > 0
      and job["state_dir"] == str(runtime / "compute/package")
      and job["source"] == {
          "artifact": {
              "path": str(source_path), "size": intent["expected_source_bytes"],
              "sha256": intent[parent],
          },
          "pin": reference.pin_from_record(source),
      } and source["sha256"] == intent[parent]
      and job["producer"] == {
          "path": package_tool["path"], "size": package_tool["metadata"][6],
          "sha256": package_tool["sha256"],
      } and job["limits"] == intent["limits"]
      and job["config_sha256"] == sha(IMAGE_CONFIG_DOMAIN + intent_raw)
      and all(job[field] == intent[field] for field in fields),
          "image job source/config commitment changed")
    attempt = job["attempt"]
    check(set(attempt) == {"schema", "schema_version", "kind",
                           "stage", "output", "record"}
          and attempt["schema"] == "uk.wamr.compute-attempt-ownership"
          and attempt["schema_version"] == 1
          and attempt["kind"] == kind,
          "image job attempt role changed")
    for role in ("stage", "output", "record"):
        item = attempt[role]
        check(set(item) == {"device_major", "device_minor", "inode",
                            "mode", "uid", "nlink"}
              and type(item["inode"]) is int and item["inode"] > 0
              and item["uid"] == os.getuid()
              and stat.S_IFMT(item["mode"]) == (
                  stat.S_IFDIR if role == "stage" else stat.S_IFREG)
              and stat.S_IMODE(item["mode"]) == (
                  0o700 if role == "stage" else 0o600)
              and (item["nlink"] >= 2 if role == "stage" else
                   item["nlink"] == 1),
              "image job attempt ownership changed")
    return job


def reviewed_validator_outputs(seen, side, entries):
    reference = seen["reference"]
    runtime = seen["roots"][0]
    records = seen["files"]["records"]

    def remove(path, kind, size=None):
        check(path in entries and entries.pop(path) == (
            kind, 0o700 if kind == "directory" else 0o600, size),
            "validator retained slot changed")

    if side == "python":
        remove("private/log-validation", "directory")
    for index, mode in enumerate(MODES):
        stage = ("log-validator-legacy" if index % 2 else
                 "log-validator-x2apic")
        serial = verified_serial(seen, mode)
        count = (3 if index < 4 else 2) if side == "python" else 1
        for invocation in range(count):
            if side == "python":
                base = f"private/log-validation/boot-{mode}-{invocation:02d}"
                remove(base, "directory")
                remove(base + "/private", "directory")
                remove(base + "/evidence", "directory")
                log = base + "/private/" + stage + ".log"
                command_name = base + "/evidence/command-" + stage + ".json"
            else:
                base = "boot-" + mode
                log = base + "/" + stage + ".log"
                command_name = base + "/command-" + stage + ".json"
            try:
                log_bytes = checked_file(runtime / "compute" / log, 64 * 1024)
                command_raw = checked_file(runtime / "compute" /
                                           command_name)
            except OSError:
                raise ParityError("validator retained output inaccessible") from None
            command_record = parsed(command_raw, reference)
            checked_stage(command_record, log_bytes, side, reference,
                          stage, seen)
            result = parsed(log_bytes, reference)
            check(set(result) == {
                "schema", "schema_version", "mode", "raw_serial_bytes",
                "raw_serial_sha256", "compute",
            } and result["schema"] == "uk.wamr.log-validation"
              and result["schema_version"] == 1
              and result["mode"] == "tiny"
              and result["raw_serial_bytes"] == len(serial)
              and result["raw_serial_sha256"] == sha(serial)
              and result["compute"] == records[mode + "-compute.json"][1]["compute"],
                  "validator result commitment changed")
            remove(log, "file", len(log_bytes))
            remove(command_name, "file", len(command_raw))


def reviewed_boot_retained(left, right, first, second):
    results = []
    for seen, side, entries in ((left, "python", first),
                                (right, "native", second)):
        entries = dict(entries)
        reviewed_validator_outputs(seen, side, entries)
        for mode in MODES:
            path = "boot-" + mode + "/request.json"
            request = checked_file(seen["roots"][0] / "compute" / path, 64 * 1024)
            check(entries[path] == ("file", 0o600, len(request)),
                  "boot request retained size changed")
            entries[path] = ("file", 0o600, "<verified-request-size>")
        for job_name in ("qcow2-job.json", "vhd-job.json"):
            job = verified_image_job(seen, job_name)
            path = "package/" + job_name
            raw = checked_file(seen["roots"][0] / "compute" / path, 64 * 1024)
            check(entries[path] == ("file", 0o600, len(raw))
                  and job["state_dir"] == str(seen["roots"][0] / "compute/package"),
                  "image job retained size changed")
            entries[path] = ("file", 0o600, "<verified-image-job-size>")
        results.append(entries)
    return results


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
    verified_tool_roles = "native-image" in checked_commands
    local_boots = None
    checked_acceptance = False
    reviewed_boots = False
    if "local-boot-tool" in checked_commands:
        local_boots, install_failures = compare_local_boot_installs(left, right)
        failures.extend(install_failures)
        if "boot-inputs.json" in l_records and "boot-inputs.json" in r_records:
            failures.extend(compare_boot_inputs(left, right, local_boots))
            for stage in REVIEWED_BOOT_COMMANDS:
                name = f"command-{stage}.json"
                if name in l_records and name in r_records:
                    checked_commands[stage] = (
                        checked_stage(l_records[name][1], left["files"]["command_logs"][stage],
                                      "python", left["reference"], stage, left),
                        checked_stage(r_records[name][1], right["files"]["command_logs"][stage],
                                      "native", right["reference"], stage, right),
                    )
            if (set(REVIEWED_BOOT_COMMANDS) <= checked_commands.keys()
                    and all(mode + "-compute.json" in records
                            for records in (l_records, r_records)
                            for mode in MODES)
                    and all(name in records for records in (l_records, r_records)
                            for name in ("qcow2-finalization.json",
                                         "fixed-vhd-derivation.json"))):
                for mode in MODES:
                    reviewed_mode(left, right, mode)
                for name in ("qcow2-finalization.json",
                             "fixed-vhd-derivation.json"):
                    reviewed_image_provenance(left, right, name)
                reviewed_boots = True
            if ("qcow2-acceptance.json" in l_records
                    and "qcow2-acceptance.json" in r_records):
                failures.extend(compare_qcow2_acceptance(
                    left, right, MODES[:4] if reviewed_boots else None))
                checked_acceptance = True
            if reviewed_boots:
                reviewed_vhd_gate(left, right)
                reviewed_final_inspection(left, right)
    if (proven and not reviewed_boots
            and "boot-inputs.json" in l_records and "boot-inputs.json" in r_records):
        for name in ("qcow2-finalization.json", "fixed-vhd-derivation.json"):
            if name in l_records and name in r_records:
                a_intent = verified_image_provenance(left, name)
                b_intent = verified_image_provenance(right, name)
                if (Normalizer(left["roots"]).normalize(a_intent) !=
                        Normalizer(right["roots"]).normalize(b_intent)):
                    failures.append("record_content:" + name + ".provenance.intent")
                elif l_records[name][1]["provenance"]["config_sha256"] != (
                        r_records[name][1]["provenance"]["config_sha256"]):
                    failures.append(
                        "record_content:" + name +
                        ".provenance.config_sha256.root-bound-intent")
        failures.extend(serial_differences(left, right))
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
            if "build.json" in l_records and "build.json" in r_records:
                left_value, right_value = reviewed_side_specific_outputs(
                    left, right, left_value, right_value)
            if reviewed_boots:
                left_value, right_value = reviewed_boot_retained(
                    left, right, left_value, right_value)
        if left_value != right_value:
            failures.append(key)
            if key == "retained":
                failures.extend(retained_differences(left_value, right_value))
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
        if (role == "config" and one[1] != two[1]
                and len(left["roots"]) == len(right["roots"]) == 2
                and source_root_only_config(left, right)):
            failures.append("artifacts:config.source-root-dependent")
    if l_records.keys() != r_records.keys():
        failures.append("evidence_membership")
    left_normalizer, right_normalizer = Normalizer(left["roots"]), Normalizer(right["roots"])
    for name in (record for record in ORDER if record in l_records and record in r_records):
        if ((name == "build-start.json" and proven)
                or (name == "boot-inputs.json" and local_boots is not None)
                or (name == "qcow2-acceptance.json" and checked_acceptance)
                or (reviewed_boots and name in {
                    *(mode + "-compute.json" for mode in MODES),
                    "qcow2-finalization.json", "fixed-vhd-derivation.json",
                    "fixed-vhd-derivation-gate.json", "final-inspection.json",
                })):
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
        if name == "build.json":
            check(set(a_value) == set(b_value) == {"source", "runtime", "image"},
                  "build record membership changed")
            a_value = dict(a_value, image=dict(
                a_value["image"], command=reviewed_image_command(
                    left, verified_tool_roles)))
            b_value = dict(b_value, image=dict(
                b_value["image"], command=reviewed_image_command(
                    right, verified_tool_roles)))
        if name == "result.json":
            a_value = dict(a_value, records={record: "<verified-file-sha256>"
                                             for record in a_value["records"]})
            b_value = dict(b_value, records={record: "<verified-file-sha256>"
                                             for record in b_value["records"]})
        normalized_a = left_normalizer.normalize(a_value)
        normalized_b = right_normalizer.normalize(b_value)
        if normalized_a != normalized_b:
            failures.append("record_content:" + name)
            if name == "build.json":
                for field in ("source", "runtime", "image"):
                    if normalized_a[field] != normalized_b[field]:
                        failures.append("record_content:build.json." + field)
                failures.extend(build_image_differences(
                    left, right, verified_tool_roles))
            else:
                failures.extend(boot_record_differences(
                    name, normalized_a, normalized_b))
        if a[0] != b[0] and a[1] == b[1]:
            failures.append("record_bytes:" + name)
    return failures


def observed(result, runtime, repository, rewritten_build_start=False):
    reference = oracle(repository)
    files = phase_snapshot(
        runtime, reference, rewritten_build_start=rewritten_build_start)
    files["command_logs"] = {}
    for stage in (*REVIEWED_BUILD_COMMANDS, *REVIEWED_BOOT_COMMANDS):
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


FAULT_REFUSALS = {
    "build-start-tamper": ("producer inputs changed", "BuildStartChanged"),
    "missing-build": ("unsafe or oversized file", "FileNotFound"),
    "occupied-boot-slot": ("boot output already exists", "PriorOutput"),
}


def require_fault_refusal(case, results):
    python_reason, native_cause = FAULT_REFUSALS[case]
    expected = {
        "python": f"WAMR_CI_REFUSED: {python_reason}\n".encode(),
        "native": (
            "WAMR_CI_FAILED_STAGE: boot-platform; cause: "
            f"{native_cause}; bounded private logs retained.\n").encode(),
    }
    for side in ("python", "native"):
        result = results[side]
        check(result.returncode == 1 and result.stderr == expected[side]
              and not result.stdout,
              f"{case} {side} refused with a different fault outcome")


def require_fault_transition(case, side, before, after):
    prior, current = before["files"], after["files"]
    records = dict(prior["records"])
    retained = dict(prior["retained"])
    order = prior["order"]
    if case == "build-start-tamper":
        original = records["build-start.json"][1]
        check(original["source"]["revision"] != "0" * 40,
              "build-start tamper was not a mutation")
        changed = copy.deepcopy(original)
        changed["source"]["revision"] = "0" * 40
        records["build-start.json"] = (
            before["reference"].compact_json(changed, newline=True), changed)
    elif case == "missing-build":
        del records["build.json"]
        order = tuple(name for name in order if name != "build.json")
    elif case == "occupied-boot-slot":
        check("boot-raw-x2apic/prior" not in retained,
              "boot slot was occupied before fault injection")
        retained["boot-raw-x2apic/prior"] = ("file", 0o600, len(b"prior"))
    else:
        raise ParityError("unknown reviewed fault")
    check(current["order"] == order and current["records"] == records,
          f"{case} {side} changed other evidence")
    check(current["retained"] == retained
          and current["artifacts"] == prior["artifacts"],
          f"{case} {side} changed other retained outputs")
    checked = after
    if case == "build-start-tamper":
        original_records = dict(current["records"])
        original_records["build-start.json"] = prior["records"][
            "build-start.json"]
        checked = dict(after, files=dict(current, records=original_records))
    verified_build_start_side(checked, side)


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
          and phase in (
              "build-start", "build-done", "boot-start", "boot-done",
              "records-start", "records-checked", "inspect-start",
              "inspect-done", "validator-start", "validator-done",
              "records-done"),
          "invalid differential progress label")
    print(f"DIFFERENTIAL_PROGRESS: {side}:{phase}", file=sys.stderr, flush=True)


def require_matching_builds_before_boot(failures):
    check(not failures, "differential mismatches: " + ", ".join(failures))


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
    inspection_parent = (
        fresh(parent, "native-inspection") if args.case == "success" else None)
    validator_parent = (
        fresh(parent, "native-validation") if args.case == "success" else None)
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
        require_matching_builds_before_boot(failures)
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
            label: observed(
                results[label], runtime, repo,
                rewritten_build_start=args.case == "build-start-tamper")
            for label, (repo, runtime, _, _) in executions.items()
        }
        if args.case == "success":
            failures.extend("boot:" + name for name in compare_observations(
                boot_snapshots["python"], boot_snapshots["native"],
                reviewed_build_compat=True))
            check(py.returncode == native.returncode == 0,
                  "unexpected full-chain outcome; " +
                  outcome_details(results, boot_snapshots) + "; " +
                  ", ".join(failures))
            for runtime in (py_runtime, native_runtime):
                check((runtime / "compute/evidence/result.json").is_file(),
                      "missing real KVM acceptance record")
        else:
            require_fault_refusal(args.case, results)
            for label in ("python", "native"):
                require_fault_transition(
                    args.case, label, snapshots[label], boot_snapshots[label])
            for runtime in (py_runtime, native_runtime):
                check(not (runtime / "compute/evidence/result.json").exists(),
                      "refusal published acceptance")
    check(not failures, "differential mismatches: " + ", ".join(failures))
    if args.case == "success":
        report_progress("native", "records-start")
        result = command([
            str(controller), "records", "--runtime", str(native_runtime),
            "--output", "handoff-v1",
        ], native_repo, executions["native"][3], seconds=600)
        refusal = re.search(
            r"(?m)^WAMR_CI_FAILED_STAGE: records; cause: "
            r"([A-Za-z][A-Za-z0-9_]{0,79}); bounded private logs retained\.$",
            result.stderr.decode("utf-8", "replace"))
        check(result.returncode == 0 and not result.stderr,
              "native completed-run records replay refused: " +
              (refusal.group(1) if refusal else "unexpected result"))
        reference = oracle(native_repo)
        view = parsed(result.stdout, reference)
        recorded = parsed(checked_file(
            native_runtime / "compute/evidence/result.json"), reference)
        check(
            result.stdout == reference.compact_json(view, newline=True)
            and view["schema"] == "uk.wamr.native-ci-controller-records"
            and view["schema_version"] == 1
            and view["context"] == "local-runtime"
            and view["compatibility"] == "tiny-v2"
            and view["profile"] == reference.CURRENT_PROFILE
            and view["modes"] == list(reference.SIX_MODES)
            and len(view["records"]) == len(recorded["records"]) == 33
            and len(view["artifacts"]) == 49
            and {item["name"]: item["sha256"] for item in view["records"]}
            == recorded["records"]
            and sum(
                item["role"] == "command-supervisor"
                and item["path"] == str(controller)
                for item in view["runtime_inputs"]) == 1,
            "native completed-run records differ from accepted evidence")
        report_progress("native", "records-checked")
        script = (
            "import importlib.util,json,sys\n"
            "from pathlib import Path\n"
            "spec=importlib.util.spec_from_file_location("
            "'native_handoff',Path(sys.argv[1])/'support/build/wamr-native-ci/handoff.py')\n"
            "handoff=importlib.util.module_from_spec(spec)\n"
            "spec.loader.exec_module(handoff)\n"
            "records=handoff.result_records(Path(sys.argv[2])/'compute')\n"
            "sys.stdout.write(json.dumps(records,sort_keys=True,separators=(',',':'))+'\\n')\n"
        )
        bridged = command([
            sys.executable, "-B", "-c", script,
            str(native_repo), str(native_runtime),
        ], native_repo, dict(
            executions["native"][3], WAMR_CI_CONTROLLER=str(controller)),
            seconds=650)
        try:
            refusal = re.search(
                r"(?m)^(?:ValueError|wamr_native_ci\.Refusal): "
                r"([A-Za-z][A-Za-z0-9 _-]{0,119})$",
                bridged.stderr.decode("utf-8", "replace"))
            check(bridged.returncode == 0,
                  "Python local handoff refused native-produced records: " +
                  (refusal.group(1) if refusal else "unexpected result"))
            check(json.loads(bridged.stdout) == recorded["records"],
                  "Python local handoff returned different record hashes")
            report_progress("native", "inspect-start")
            inspection = inspection_parent / "handoff"
            inspected = command([
                str(controller), "handoff-inspect",
                "--runtime", str(native_runtime),
                "--output", str(inspection),
            ], native_repo, executions["native"][3], seconds=1200)
            refusal = re.search(
                r"(?m)^WAMR_CI_FAILED_STAGE: handoff-inspect; cause: "
                r"([A-Za-z][A-Za-z0-9_]{0,79}); bounded private logs retained\.$",
                inspected.stderr.decode("utf-8", "replace"))
            check(inspected.returncode == 0
                  and not inspected.stdout and not inspected.stderr,
                  "native completed-run handoff inspection refused: " +
                  (refusal.group(1) if refusal else "unexpected result"))
            inspection_record = parsed(checked_file(
                inspection / "evidence/command-handoff-inspect.json"), reference)
            inspection_log = checked_file(
                inspection / "private/handoff-inspect.log")
            check(
                inspection_record["scope"] == "command_diagnostic_not_acceptance"
                and inspection_record["stage"] == "handoff-inspect"
                and inspection_record["exit_code"] == 0
                and inspection_record["bytes"] == len(inspection_log)
                and inspection_record["sha256"] == sha(inspection_log),
                "native handoff inspection command output changed")
            report_progress("native", "inspect-done")
            report_progress("native", "validator-start")
            validation = validator_parent / "build"
            built = command([
                str(controller), "public-validator-build",
                "--runtime", str(native_runtime),
                "--output", str(validation),
            ], native_repo, executions["native"][3], seconds=1200)
            refusal = re.search(
                r"(?m)^WAMR_CI_FAILED_STAGE: public-validator-build; cause: "
                r"([A-Za-z][A-Za-z0-9_]{0,79}); bounded private logs retained\.$",
                built.stderr.decode("utf-8", "replace"))
            check(built.returncode == 0 and not built.stdout and not built.stderr,
                  "native public validator build refused: " +
                  (refusal.group(1) if refusal else "unexpected result"))
            validator_record = parsed(checked_file(
                validation / "evidence/command-public-validator-build.json"),
                reference)
            validator_log = checked_file(
                validation / "private/public-validator-build.log",
                8 * 1024 * 1024 + 1)
            check(
                validator_record["scope"] == "command_diagnostic_not_acceptance"
                and validator_record["stage"] == "public-validator-build"
                and validator_record["exit_code"] == 0
                and validator_record["bytes"] == len(validator_log)
                and validator_record["sha256"] == sha(validator_log),
                "native public validator command output changed")
            validator = (
                validation / "public-source/tools/bin/uk-wamr-direct-validate")
            before = validator.lstat()
            check(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                  and before.st_uid == os.getuid()
                  and stat.S_IMODE(before.st_mode) & 0o022 == 0
                  and before.st_mode & 0o111 != 0
                  and 20 <= before.st_size <= 64 * 1024 * 1024,
                  "unsafe native-built public validator")
            with validator.open("rb") as stream:
                header = stream.read(20)
            after = validator.lstat()
            check(header[:6] == b"\x7fELF\x02\x01"
                  and header[18:20] == b"\x3e\x00"
                  and (before.st_dev, before.st_ino, before.st_size,
                       before.st_mtime_ns, before.st_ctime_ns)
                  == (after.st_dev, after.st_ino, after.st_size,
                      after.st_mtime_ns, after.st_ctime_ns),
                  "native-built public validator identity changed")
            report_progress("native", "validator-done")
        finally:
            # The comparison root is a pinned runtime ancestor until replay ends.
            with (parent / "native-records.json").open("xb") as output:
                os.fchmod(output.fileno(), 0o600)
                output.write(result.stdout)
                output.flush()
                os.fsync(output.fileno())
        report_progress("native", "records-done")


class DeterministicContracts(unittest.TestCase):
    def test_rewritten_build_start_preserves_other_evidence_order(self):
        parent = fresh(fixture_parent(), f"fault-order-{os.getpid()}")
        try:
            runtime = fresh(parent, "runtime")
            compute = fresh(runtime, "compute")
            evidence = fresh(compute, "evidence")
            reference = oracle()
            reference.APP = parent / "absent-app"
            start = evidence / "build-start.json"
            build = evidence / "build.json"
            boot_inputs = evidence / "boot-inputs.json"
            for path in (start, build, boot_inputs):
                path.write_bytes(b"{}\n")
                path.chmod(0o600)
            os.utime(start, ns=(1_000_000_000, 1_000_000_000))
            os.utime(build, ns=(2_000_000_000, 2_000_000_000))
            os.utime(boot_inputs, ns=(4_000_000_000, 4_000_000_000))
            self.assertEqual(
                phase_snapshot(runtime, reference)["order"],
                ("build-start.json", "build.json", "boot-inputs.json"))
            os.utime(start, ns=(5_000_000_000, 5_000_000_000))
            with self.assertRaisesRegex(
                    ParityError, "evidence phase order changed"):
                phase_snapshot(runtime, reference)
            self.assertEqual(
                phase_snapshot(runtime, reference, rewritten_build_start=True)[
                    "order"],
                ("build-start.json", "build.json", "boot-inputs.json"))
            prelude = evidence / "prelude.json"
            prelude.write_bytes(b"{}\n")
            prelude.chmod(0o600)
            os.utime(prelude, ns=(500_000_000, 500_000_000))
            with mock.patch.dict(
                    phase_snapshot.__globals__,
                    {"ORDER": ("prelude.json", *ORDER)}):
                self.assertEqual(
                    phase_snapshot(
                        runtime, reference, rewritten_build_start=True)["order"],
                    ("prelude.json", "build-start.json",
                     "build.json", "boot-inputs.json"))
            os.utime(build, ns=(6_000_000_000, 6_000_000_000))
            with mock.patch.dict(
                    phase_snapshot.__globals__,
                    {"ORDER": ("prelude.json", *ORDER)}):
                with self.assertRaisesRegex(
                        ParityError, "evidence phase order changed"):
                    phase_snapshot(
                        runtime, reference, rewritten_build_start=True)
        finally:
            shutil.rmtree(parent)

    def test_fault_outcomes_and_post_states_are_case_exact(self):
        reference = oracle()
        original = {
            "source": {"revision": "1" * 40, "tree": "2" * 40},
        }
        records = {
            "build-start.json": (
                reference.compact_json(original, newline=True), original),
            "build.json": (b"{}\n", {}),
        }
        before = {
            "reference": reference,
            "files": {
                "records": records,
                "order": ("build-start.json", "build.json"),
                "retained": {"boot-raw-x2apic": ("directory", 0o700, None)},
                "artifacts": {"efi": (7, "a" * 64, 0o600)},
            },
        }
        for case, (python_reason, native_cause) in FAULT_REFUSALS.items():
            with self.subTest(case=case):
                results = {
                    "python": subprocess.CompletedProcess(
                        [], 1, b"",
                        f"WAMR_CI_REFUSED: {python_reason}\n".encode()),
                    "native": subprocess.CompletedProcess(
                        [], 1, b"",
                        ("WAMR_CI_FAILED_STAGE: boot-platform; cause: "
                         f"{native_cause}; bounded private logs retained.\n"
                         ).encode()),
                }
                require_fault_refusal(case, results)
                results["native"] = subprocess.CompletedProcess(
                    [], 1, b"",
                    b"WAMR_CI_FAILED_STAGE: boot-platform; cause: Other;\n")
                with self.assertRaisesRegex(
                        ParityError, "different fault outcome"):
                    require_fault_refusal(case, results)
                after = dict(before, files=copy.deepcopy(before["files"]))
                current = after["files"]
                if case == "build-start-tamper":
                    changed = copy.deepcopy(original)
                    changed["source"]["revision"] = "0" * 40
                    current["records"]["build-start.json"] = (
                        reference.compact_json(changed, newline=True), changed)
                elif case == "missing-build":
                    del current["records"]["build.json"]
                    current["order"] = ("build-start.json",)
                else:
                    current["retained"]["boot-raw-x2apic/prior"] = (
                        "file", 0o600, len(b"prior"))
                with mock.patch(
                        __name__ + ".verified_build_start_side") as verify:
                    require_fault_transition(case, "python", before, after)
                    checked = verify.call_args.args[0]
                    self.assertEqual(
                        checked["files"]["records"]["build-start.json"],
                        before["files"]["records"]["build-start.json"])
                current["artifacts"]["efi"] = (7, "b" * 64, 0o600)
                with self.assertRaisesRegex(
                        ParityError, "changed other retained outputs"):
                    require_fault_transition(case, "python", before, after)
                current["artifacts"]["efi"] = before["files"][
                    "artifacts"]["efi"]
                current["records"]["result.json"] = (b"{}\n", {})
                with self.assertRaisesRegex(
                        ParityError, "changed other evidence"):
                    require_fault_transition(case, "python", before, after)
                del current["records"]["result.json"]
                current["retained"]["private/unreviewed"] = (
                    "file", 0o600, 1)
                with self.assertRaisesRegex(
                        ParityError, "changed other retained outputs"):
                    require_fault_transition(case, "python", before, after)

    def test_build_mismatch_refuses_before_boot(self):
        self.assertIsNone(require_matching_builds_before_boot([]))
        with self.assertRaisesRegex(
                ParityError,
                r"^differential mismatches: build:record_content:build.json.image.files.debug$"):
            require_matching_builds_before_boot([
                "build:record_content:build.json.image.files.debug"])

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
        for stage in ("adapter", "local-boot-tool", *SHARED_BUILD_STAGES,
                      *REVIEWED_BOOT_COMMANDS, *REVIEWED_VALIDATOR_COMMANDS):
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
                            elif not payload:
                                payload.append({
                                    "name": "UNREVIEWED",
                                    "value": reference.command_literal("altered"),
                                })
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

    def test_v1_v2_reference_parser_and_record_hashes_without_controller(self):
        reference = oracle()
        parent = fresh(fixture_parent(), f"reference-result-parser-{os.getpid()}")
        try:
            for version in (1, 2):
                with self.subTest(version=version):
                    evidence = fresh(fresh(parent, f"v{version}"), "evidence")
                    raw = (FIXTURES / f"accepted-v{version}.json").read_bytes()
                    result_path = evidence / "result.json"
                    result_path.write_bytes(raw)
                    result_path.chmod(0o600)
                    result = parsed(checked_file(result_path), reference)
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
                    for name in result["records"]:
                        path = evidence / name
                        path.write_bytes(b"{}\n")
                        path.chmod(0o600)
                    self.assertEqual(reference.digest(result_path), sha(raw))
                    self.assertEqual(
                        {name: reference.digest(evidence / name)
                         for name in result["records"]},
                        result["records"])
                    (evidence / "build.json").write_bytes(b'{"tampered":true}\n')
                    self.assertNotEqual(
                        reference.digest(evidence / "build.json"),
                        result["records"]["build.json"])
        finally:
            shutil.rmtree(parent)

    def test_native_local_handoff_refuses_synthetic_parser_fixtures(self):
        if not os.environ.get("WAMR_CI_CONTROLLER"):
            self.skipTest("native controller not configured")
        spec = importlib.util.spec_from_file_location(
            "wamr_handoff_fixture_reader", CONTROLLER / "handoff.py")
        handoff = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(handoff)
        scratch = fixture_parent()
        parent = fresh(scratch, f"synthetic-result-parser-{os.getpid()}")
        try:
            for version in (1, 2):
                runtime = fresh(parent, f"v{version}")
                root = fresh(runtime, "compute")
                evidence = fresh(root, "evidence")
                raw = (FIXTURES / f"accepted-v{version}.json").read_bytes()
                value = parsed(raw, handoff.ci)
                for name in value["records"]:
                    file = evidence / name
                    file.write_bytes(b"{}\n")
                    file.chmod(0o600)
                (evidence / "result.json").write_bytes(raw)
                (evidence / "result.json").chmod(0o600)
                with self.assertRaises(ValueError):
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

    def test_build_image_diagnostics_name_fixed_fields_without_hashes(self):
        reference = oracle()
        image = {"runtime_inputs_sha256": "a" * 64,
                 "solved_config_sha256": "b" * 64,
                 "application_sources": {}, "tools": {},
                 "files": {reference.EFI: "c" * 64,
                           reference.EFI + ".dbg": "d" * 64,
                           reference.EFI + ".bootinfo": "e" * 64}}
        original = {"files": {"records": {"build.json": (b"{}\n", {"image": image})}},
                    "reference": reference}
        changed = {"files": {"records": {"build.json": (
            b"{}\n", {"image": copy.deepcopy(image)})}}, "reference": reference}
        changed_image = changed["files"]["records"]["build.json"][1]["image"]
        changed_image["solved_config_sha256"] = "f" * 64
        changed_image["files"][reference.EFI + ".dbg"] = "0" * 64
        with mock.patch.object(sys.modules[__name__], "image_region_differences",
                               return_value=[]):
            self.assertEqual(build_image_differences(original, changed), [
                "record_content:build.json.image.solved_config_sha256",
                "record_content:build.json.image.files.debug",
            ])
        self.assertEqual(build_image_differences(original, original), [])
        del changed_image["files"][reference.EFI]
        with self.assertRaisesRegex(ParityError, "file membership"):
            build_image_differences(original, changed)

    def test_image_command_normalizes_only_reviewed_nested_checkout_paths(self):
        def side(name):
            repo = Path("/checkout") / name
            runtime = Path("/private") / name
            app = repo / "support/apps/wamr-aot"
            descriptor_pid = 101 if name == "python" else 202
            roles = sorted({"zig", *(role for role, _ in IMAGE_TOOL_OPTIONS.values())})
            tools = {role: f"/proc/{descriptor_pid}/fd/{index + 3}"
                     for index, role in enumerate(roles)}
            pinned = {role: "/opt/reviewed/" + role for role in roles}
            command = [
                tools["zig"], "build", "native-images", "-j2",
                "--cache-dir", str(app / "build/native-environment/zig_local_cache"),
                "--global-cache-dir",
                str(app / "build/native-environment/zig_global_cache"),
                "-Dapp=" + str(app),
                "-Dnative-make-environment=" +
                str(app / "build/native-environment/environment.json"),
                "-Dconfig=" + str(app / "build/.config"),
                "-Dwamr-aot-tool=" + str(runtime / "compute/tools/bin/uk-wamr-aot-build"),
            ]
            command.extend(prefix + tools[role] + suffix
                           for prefix, (role, suffix) in IMAGE_TOOL_OPTIONS.items())
            image = {
                "command": command, "schema_version": 1,
                "scope": "native-build-only-not-boot-or-hardware-qualification",
                "unikraft_revision": "0" * 40,
                "unikraft_diff_sha256": sha(b""),
                "runtime_inputs_sha256": sha(b"runtime"),
                "solved_config_sha256": sha(b"config"),
                "application_sources": {}, "tools": {},
                "files": {"fixture-image": sha(b"efi"),
                          "fixture-image.dbg": sha(b"debug"),
                          "fixture-image.bootinfo": sha(b"bootinfo")},
            }
            return {"reference": mock.Mock(REPO=repo, APP=app),
                    "roots": (runtime, repo),
                    "exit": subprocess.CompletedProcess([], 0, b"", b""),
                    "files": {"order": ("build.json",),
                              "retained": {}, "artifacts": {},
                              "records": {
                                  "build-start.json": (b"", {
                                      "consumer_inputs": {"files": {
                                          "tool:" + role: {"path": path}
                                          for role, path in pinned.items()}}}),
                                  "build.json": (b"", {
                                      "source": {}, "runtime": {},
                                      "image": image})}}}

        first, second = side("python"), side("native")
        first["reference"].EFI = second["reference"].EFI = "fixture-image"
        one = Normalizer(first["roots"]).normalize(
            reviewed_image_command(first, verified_tool_roles=True))
        two = Normalizer(second["roots"]).normalize(
            reviewed_image_command(second, verified_tool_roles=True))
        self.assertEqual(one, two)
        self.assertIn("record_content:build.json",
                      compare_observations(first, second))
        second_command = second["files"]["records"]["build.json"][1]["image"]["command"]
        pinned = second["files"]["records"]["build-start.json"][1][
            "consumer_inputs"]["files"]
        second_command[0] = pinned["tool:zig"]["path"]
        for index, arg in enumerate(second_command):
            for prefix, (role, suffix) in IMAGE_TOOL_OPTIONS.items():
                if arg.startswith(prefix):
                    second_command[index] = prefix + pinned["tool:" + role]["path"] + suffix
                    break
        self.assertEqual(one, Normalizer(second["roots"]).normalize(
            reviewed_image_command(second, verified_tool_roles=True)))
        self.assertIn("record_content:build.json",
                      compare_observations(first, second))
        for side in (first, second):
            side["files"]["records"]["command-native-image.json"] = (b"", {})
            side["files"]["command_logs"] = {"native-image": b"checked\n"}
            side["files"]["retained"]["private/native-image.log"] = (
                "file", 0o600, len(b"checked\n"))
        with (mock.patch.object(sys.modules[__name__], "compare_build_start",
                                return_value=[]),
              mock.patch.object(sys.modules[__name__], "checked_stage",
                                return_value={}) as checked,
              mock.patch.object(sys.modules[__name__],
                                "reviewed_side_specific_outputs",
                                side_effect=lambda py, native, left, right:
                                (left, right))):
            self.assertEqual(compare_observations(
                first, second, reviewed_build_compat=True), [])
            self.assertEqual(checked.call_count, 2)
            self.assertIn("record_content:build.json",
                          compare_observations(first, second))
            second["files"]["records"].pop("command-native-image.json")
            self.assertIn("record_content:build.json",
                          compare_observations(
                              first, second, reviewed_build_compat=True))
            second["files"]["records"]["command-native-image.json"] = (b"", {})
        original_make = second_command[12]
        second_command[12] = "-Dmake-command=/opt/make"
        self.assertEqual(build_image_differences(
            first, second, verified_tool_roles=True), [
            "record_content:build.json.image.command.arg-12",
            "record_content:build.json.image.command.tool.make.retained-to-absolute",
        ])
        self.assertNotEqual(one, Normalizer(second["roots"]).normalize(
            reviewed_image_command(second, verified_tool_roles=True)))
        second_command[12] = original_make
        second_command[0] = "/proc/202/fd/999"
        with self.assertRaisesRegex(ParityError, "image command tool role changed"):
            reviewed_image_command(second, verified_tool_roles=True)
        second_command[0] = pinned["tool:zig"]["path"]
        second_command.append("-Dmake-arg=UNREVIEWED=" +
                              str(second["reference"].REPO / "unreviewed"))
        self.assertNotEqual(one, Normalizer(second["roots"]).normalize(
            reviewed_image_command(second, verified_tool_roles=True)))
        self.assertEqual(build_image_differences(
            first, second, verified_tool_roles=True), [
            "record_content:build.json.image.command.count",
        ])
        second_command[8] = "-Dapp=/unreviewed"
        with self.assertRaisesRegex(ParityError, "image command path changed"):
            reviewed_image_command(second, verified_tool_roles=True)

    def test_retained_diagnostics_name_fixed_roles_not_private_files(self):
        first = {"private/secret.log": ("file", 0o600, 42),
                 "fixtures/local": ("file", 0o600, 1)}
        second = {"private/secret.log": ("file", 0o600, 43),
                  "fixtures/other": ("file", 0o600, 1)}
        self.assertEqual(retained_differences(first, second), [
            "retained:fixtures.membership", "retained:private.log.bytes",
        ])
        first = {
            "package/qcow2-job.json": ("file", 0o600, 120),
            "boot-raw-x2apic/request.json": ("file", 0o600, 345),
            "private/log-validation/boot-raw-x2apic-00/private/"
            "log-validator-x2apic.log": ("file", 0o600, 20),
        }
        second = {
            "package/qcow2-job.json": ("file", 0o600, 121),
            "boot-raw-x2apic/request.json": ("file", 0o600, 346),
        }
        self.assertEqual(retained_differences(first, second), [
            "retained:boot-raw-x2apic.request.bytes",
            "retained:package.qcow2-job.bytes",
            "retained:private.validator-output.membership",
        ])

    def test_boot_diagnostics_name_only_reviewed_fields(self):
        report = {
            "serial_bytes": 12, "serial_sha256": "a" * 64,
            "passed": True, "consumed": True,
            "cleanup_complete": True, "input_unchanged": True,
            "serial_valid": True, "serial_limit_reached": False,
            "termination": {"exited": 0}, "failures": {},
        }
        first = {
            "scope": "local_native_compute_only", "report": report,
            "input_pins": [], "request_sha256": "a" * 64,
            "report_sha256": "b" * 64, "compute": {},
        }
        second = copy.deepcopy(first)
        second["request_sha256"] = "c" * 64
        second["report"]["serial_sha256"] = "d" * 64
        self.assertEqual(boot_record_differences(
            "raw-x2apic-compute.json", first, second), [
            "record_content:raw-x2apic-compute.json.report",
            "record_content:raw-x2apic-compute.json.report.serial_sha256",
            "record_content:raw-x2apic-compute.json.request_sha256",
        ])
        second["unreviewed"] = True
        with self.assertRaisesRegex(ParityError, "field membership"):
            boot_record_differences("raw-x2apic-compute.json", first, second)

    def test_image_provenance_rehashes_own_root_bound_intent(self):
        reference = oracle()
        sides = []
        for root in (Path("/private/python"), Path("/private/native")):
            records = {
                "package.json": (b"", {"image": {
                    "raw": {"sha256": "a" * 64}, "miz_revision": "revision",
                }}),
                "boot-inputs.json": (b"", {"files": {
                    "package_tool": {"sha256": "b" * 64,
                                     "metadata": [0, 0, 0, 0, 0, 1, 123]},
                }}),
                "qcow2-finalization.json": (b"", {
                    "output": {"sha256": "c" * 64},
                }),
            }
            for name, intent_name, source, parent, kind, field in (
                    ("qcow2-finalization.json",
                     "qcow2-finalization-intent.json", "unikraft.raw",
                     "a" * 64, "raw", "expected_source_sha256"),
                    ("fixed-vhd-derivation.json",
                     "fixed-vhd-derivation-intent.json", "unikraft.qcow2",
                     "c" * 64, "qcow2", "accepted_qcow2_sha256")):
                intent = {"source_path": str(root / "compute/package" / source),
                          field: parent}
                raw = reference.compact_json(intent, newline=True)
                records[intent_name] = (raw, intent)
                records[name] = (b"", {
                    **(records[name][1] if name in records else {}),
                    "provenance": {
                        "producer_sha256": "b" * 64, "producer_bytes": 123,
                        "miz_revision": "revision",
                        "config_sha256": sha(IMAGE_CONFIG_DOMAIN + raw),
                        "parent_kind": kind, "parent_sha256": parent,
                    },
                })
            sides.append({"reference": reference, "roots": (root, PROJECT),
                          "files": {"records": records}})
        for name in ("qcow2-finalization.json", "fixed-vhd-derivation.json"):
            left, right = (verified_image_provenance(side, name) for side in sides)
            self.assertNotEqual(left["source_path"], right["source_path"])
            self.assertEqual(Normalizer(sides[0]["roots"]).normalize(left),
                             Normalizer(sides[1]["roots"]).normalize(right))
            changed = sides[1]["files"]["records"][name][1]["provenance"]
            expected = changed["config_sha256"]
            changed["config_sha256"] = "0" * 64
            with self.assertRaisesRegex(ParityError, "provenance"):
                verified_image_provenance(sides[1], name)
            changed["config_sha256"] = expected

    def test_serial_diagnostics_rehash_without_exposing_raw_lines(self):
        reference = oracle()
        with tempfile.TemporaryDirectory() as temp:
            sides = []
            for name, stamp in (("python", b"1.000001"),
                                ("native", b"9.123456")):
                runtime = Path(temp) / name
                work = runtime / "compute/boot-raw-x2apic"
                work.mkdir(parents=True)
                serial = b"[    " + stamp + b"] Info: booted\n"
                report = reference.compact_json({
                    "serial_bytes": len(serial), "serial_sha256": sha(serial),
                }, newline=True)
                for filename, raw in (("hyperv-efi-boot.log", serial),
                                      ("report.json", report)):
                    (work / filename).write_bytes(raw)
                    (work / filename).chmod(0o600)
                sides.append({"reference": reference, "roots": (runtime, PROJECT),
                              "files": {"records": {"raw-x2apic-compute.json": (
                                  b"", {"report": parsed(report, reference),
                                        "report_sha256": sha(report)})}}})
            self.assertEqual(serial_differences(*sides), [
                "serial:raw-x2apic.kernel-timestamp-only",
                "serial:raw-x2apic.first-phase.unlocated",
                "serial:raw-x2apic.first-line.kernel-timestamp",
            ])
            self.assertEqual(
                diagnostic_serial_text(b"\x1b[0m[    1.000001]\r\n"),
                b"[    1.000001]\n")
            self.assertEqual(serial_first_phase(
                b"UEFI boot\nHyper-V Hv#1 hypercall page enabled\n"
                b"Powered by\nCalling main(0, 0)\n"
                b"WAMR_NATIVE_AOT_OK answer=42 teardown=0\n"
                b"main returned 0\n", 0), "before-hyperv")
            report = sides[1]["files"]["records"]["raw-x2apic-compute.json"][1]
            report["report"]["serial_sha256"] = "0" * 64
            with self.assertRaisesRegex(ParityError, "serial/report commitment"):
                serial_differences(*sides)

    def test_reviewed_mode_requires_physical_pins_and_semantic_serial(self):
        reference = oracle()
        with tempfile.TemporaryDirectory() as temp:
            observations = []
            for name, pid, stamp in (("python", 123, b"1.000001"),
                                     ("native", 456, b"9.123456")):
                runtime = Path(temp) / name
                work = runtime / "compute/boot-raw-x2apic"
                for directory in (work, runtime / "compute/package",
                                  runtime / "firmware", runtime / "bin"):
                    directory.mkdir(parents=True, exist_ok=True)
                config = reference.config_for(
                    runtime, runtime / "compute", 0, reference.SIX_MODES)
                paths = (config["source"]["path"], config["ovmf_code"],
                         config["ovmf_vars"], config["qemu"])
                pins = []
                for path in paths:
                    file = Path(path)
                    file.write_bytes(b"paired physical boot input")
                    file.chmod(0o600)
                    record, _ = reference.physical_file_record(file)
                    pins.append(reference.pin_from_record(record))
                request = reference.compact_json({
                    "schema_version": 2, "supervisor_pid": pid,
                    "config": config, "pins": pins,
                }, newline=True)
                serial = (b"Hyper-V Hv#1 hypercall page enabled\n"
                          b"Hyper-V SynIC:\nPowered by\nCalling main(0, 0)\n"
                          b"WAMR_NATIVE_AOT_OK answer=42 teardown=0\n[    " +
                          stamp + b"] Info: [libukboot] main returned 0\n")
                report = reference.compact_json({
                    "schema_version": 1, "scope": "public_local_qemu_only",
                    "acceptance": "not_established",
                    "passed": True, "consumed": True, "cleanup_complete": True,
                    "input_unchanged": True, "serial_valid": True,
                    "serial_limit_reached": False, "serial_bytes": len(serial),
                    "serial_sha256": sha(serial), "termination": {"exited": 0},
                    "failures": {
                        "primary": None, "cleanup": None, "recording": None,
                    },
                }, newline=True)
                for filename, raw in (("request.json", request),
                                      ("report.json", report),
                                      ("hyperv-efi-boot.log", serial)):
                    file = work / filename
                    file.write_bytes(raw)
                    file.chmod(0o600)
                record = {
                    "scope": "local_native_compute_only",
                    "report": parsed(report, reference), "input_pins": pins,
                    "request_sha256": sha(request),
                    "report_sha256": sha(report),
                    "compute": {"answer": 42},
                }
                observations.append({
                    "reference": reference, "roots": (runtime, PROJECT),
                    "files": {"records": {
                        "raw-x2apic-compute.json": (
                            reference.compact_json(record, newline=True),
                            record),
                    }},
                })
            left, right = observations
            self.assertNotEqual(
                left["files"]["records"]["raw-x2apic-compute.json"][1][
                    "request_sha256"],
                right["files"]["records"]["raw-x2apic-compute.json"][1][
                    "request_sha256"])
            self.assertEqual(len(reviewed_mode(left, right, "raw-x2apic")), 2)
            request = right["roots"][0] / "compute/boot-raw-x2apic/request.json"
            request.write_bytes(request.read_bytes().replace(
                b'"supervisor_pid":456', b'"supervisor_pid":457'))
            with self.assertRaisesRegex(ParityError, "request/compute"):
                reviewed_mode(left, right, "raw-x2apic")

    def test_image_job_retained_size_requires_own_pins_and_config(self):
        reference = oracle()
        with tempfile.TemporaryDirectory() as temp:
            runtime = Path(temp)
            package = runtime / "compute/package"
            package.mkdir(parents=True)
            raw = package / "unikraft.raw"
            raw.write_bytes(b"small physical image")
            raw.chmod(0o600)
            physical, _ = reference.physical_file_record(raw)
            tool = {
                "path": str(runtime / "compute/tools/bin/wamr-ci-package"),
                "metadata": [0, 0, 0, 0, 0, 1, 42],
                "sha256": "b" * 64,
            }
            intent = {
                "source_path": str(raw),
                "expected_source_sha256": physical["sha256"],
                "expected_source_bytes": raw.stat().st_size,
                "expected_virtual_bytes": raw.stat().st_size,
                "expected_workload_sha256": "c" * 64,
                "expected_workload_bytes": 19,
                "limits": {"max_input_bytes": 42},
            }
            intent_raw = reference.compact_json(intent, newline=True)
            ownership = {
                "device_major": 1, "device_minor": 2, "inode": 3,
                "mode": stat.S_IFREG | 0o600, "uid": os.getuid(), "nlink": 1,
            }
            job = {
                "schema_version": 2, "supervisor_pid": 123,
                "state_dir": str(package),
                "attempt": {
                    "schema": "uk.wamr.compute-attempt-ownership",
                    "schema_version": 1, "kind": "qcow2",
                    "stage": {
                        **ownership, "mode": stat.S_IFDIR | 0o700, "nlink": 2,
                    },
                    "output": ownership, "record": ownership,
                },
                "source": {
                    "artifact": {
                        "path": str(raw), "size": raw.stat().st_size,
                        "sha256": physical["sha256"],
                    },
                    "pin": reference.pin_from_record(physical),
                },
                "producer": {
                    "path": tool["path"], "size": tool["metadata"][6],
                    "sha256": tool["sha256"],
                },
                "expected_virtual_bytes": intent["expected_virtual_bytes"],
                "expected_workload_sha256": intent["expected_workload_sha256"],
                "expected_workload_bytes": intent["expected_workload_bytes"],
                "limits": intent["limits"],
                "config_sha256": sha(IMAGE_CONFIG_DOMAIN + intent_raw),
            }
            job_path = package / "qcow2-job.json"
            job_path.write_bytes(reference.compact_json(job, newline=True))
            job_path.chmod(0o600)
            seen = {
                "roots": (runtime, PROJECT), "reference": reference,
                "files": {"records": {
                    "qcow2-finalization-intent.json": (intent_raw, intent),
                    "boot-inputs.json": (b"", {"files": {
                        "package_tool": tool,
                    }}),
                }},
            }
            self.assertEqual(verified_image_job(seen, job_path.name), job)
            changed = copy.deepcopy(job)
            changed["source"]["pin"]["sha256"] = [0] * 32
            job_path.write_bytes(reference.compact_json(changed, newline=True))
            with self.assertRaisesRegex(ParityError, "source/config"):
                verified_image_job(seen, job_path.name)

    def test_validator_retained_slots_bind_each_raw_serial_and_compute(self):
        reference = oracle()
        with tempfile.TemporaryDirectory() as temp:
            for side in ("python", "native"):
                with self.subTest(side=side):
                    runtime = Path(temp) / side
                    entries = {}
                    records = {}

                    def write(relative, raw):
                        path = runtime / "compute" / relative
                        path.parent.mkdir(parents=True, exist_ok=True)
                        path.write_bytes(raw)
                        path.chmod(0o600)
                        entries[relative] = ("file", 0o600, len(raw))
                        return path

                    if side == "python":
                        entries["private/log-validation"] = (
                            "directory", 0o700, None)
                    for index, mode in enumerate(MODES):
                        serial = (mode + "\n").encode()
                        report = reference.compact_json({
                            "serial_bytes": len(serial),
                            "serial_sha256": sha(serial),
                        }, newline=True)
                        write("boot-" + mode + "/hyperv-efi-boot.log", serial)
                        write("boot-" + mode + "/report.json", report)
                        records[mode + "-compute.json"] = (b"", {
                            "report": parsed(report, reference),
                            "report_sha256": sha(report),
                            "compute": {"answer": 42},
                        })
                        stage = ("log-validator-legacy" if index % 2 else
                                 "log-validator-x2apic")
                        result = reference.compact_json({
                            "schema": "uk.wamr.log-validation",
                            "schema_version": 1, "mode": "tiny",
                            "raw_serial_bytes": len(serial),
                            "raw_serial_sha256": sha(serial),
                            "compute": {"answer": 42},
                        }, newline=True)
                        count = (3 if index < 4 else 2) if side == "python" else 1
                        for invocation in range(count):
                            if side == "python":
                                base = (f"private/log-validation/"
                                        f"boot-{mode}-{invocation:02d}")
                                for relative in (base, base + "/private",
                                                 base + "/evidence"):
                                    entries[relative] = ("directory", 0o700, None)
                                log = base + "/private/" + stage + ".log"
                                command_name = (
                                    base + "/evidence/command-" + stage + ".json")
                            else:
                                base = "boot-" + mode
                                log = base + "/" + stage + ".log"
                                command_name = base + "/command-" + stage + ".json"
                            write(log, result)
                            write(command_name, b"{}\n")
                    seen = {
                        "reference": reference, "roots": (runtime, PROJECT),
                        "files": {"records": records},
                    }
                    with mock.patch.dict(
                            reviewed_validator_outputs.__globals__,
                            {"checked_stage": lambda *args: None}):
                        cleaned = dict(entries)
                        reviewed_validator_outputs(seen, side, cleaned)
                        self.assertEqual(
                            set(entries) - set(cleaned),
                            {name for name in entries if (
                                name.startswith("private/log-validation") or
                                name.endswith((".log", ".json")) and
                                "log-validator" in name)})
                        if side == "native":
                            changed = runtime / (
                                "compute/boot-raw-x2apic/log-validator-x2apic.log")
                            changed.write_bytes(changed.read_bytes().replace(
                                b'"answer":42', b'"answer":43'))
                            with self.assertRaisesRegex(
                                    ParityError, "validator retained slot changed|"
                                    "validator result commitment changed"):
                                reviewed_validator_outputs(seen, side, dict(entries))

    def test_side_specific_retained_outputs_require_physical_contracts(self):
        reference = oracle()
        with tempfile.TemporaryDirectory() as scratch:
            sides = []
            for role in ("python", "native"):
                runtime = Path(scratch) / role
                for slot in ("private", "fixtures"):
                    (runtime / "compute" / slot).mkdir(parents=True)
                sides.append({"roots": (runtime,), "reference": reference})
            python, native = sides
            left = {"private/shared.log": ("file", 0o600, 12)}
            right = dict(left)

            def retain(side, entries, name, raw):
                path = side["roots"][0] / "compute" / name
                path.write_bytes(raw)
                path.chmod(0o600)
                entries[name] = ("file", 0o600, len(raw))

            retain(python, left, "private/zig-version.log", b"0.16.0\n")
            retain(python, left, "private/supervisor-version.log",
                   (reference.COMMAND_SUPERVISOR_VERSION + "\n").encode("ascii"))
            retain(python, left, "private/supervisor-build.log", b"build ok\n")
            retain(python, left, "private/source-metadata.json",
                   reference.compact_json({
                       "schema": "uk.wamr.git-physical-source-baseline",
                       "version": 1,
                       "records": [["file", "run.py", [0] * 9]],
                   }, newline=True))
            retain(native, right, "fixtures/native-scenarios.json",
                   expected_native_fixture_report(reference))
            self.assertEqual(
                reviewed_side_specific_outputs(python, native, left, right),
                ({"private/shared.log": ("file", 0o600, 12)},
                 {"private/shared.log": ("file", 0o600, 12)}))
            path = native["roots"][0] / "compute/fixtures/native-scenarios.json"
            report = path.read_bytes()
            path.write_bytes(report.replace(b'"status":"passed"',
                                            b'"status":"faileD"'))
            with self.assertRaisesRegex(ParityError, "side-specific retained content"):
                reviewed_side_specific_outputs(python, native, left, right)
            path.write_bytes(report)
            path.unlink()
            with self.assertRaisesRegex(ParityError, "side-specific retained output"):
                reviewed_side_specific_outputs(python, native, left, right)
            retain(native, right, "fixtures/native-scenarios.json", report)
            left["private/unreviewed.log"] = ("file", 0o600, 2)
            first, second = reviewed_side_specific_outputs(
                python, native, left, right)
            self.assertEqual(retained_differences(first, second),
                             ["retained:private.log.membership"])

    def test_image_region_diagnostics_bind_images_and_name_fixed_sections(self):
        reference = oracle()
        with tempfile.TemporaryDirectory() as scratch:
            sides = []
            for role in ("python", "native"):
                app = Path(scratch) / role / "support/apps/wamr-aot"
                images = app / "build"
                images.mkdir(parents=True)
                efi = bytearray(4104)
                efi[:2], efi[64:68] = b"MZ", b"PE\0\0"
                struct.pack_into("<H", efi, 70, 2)
                struct.pack_into("<I", efi, 148, 4096)
                struct.pack_into("<II", efi, 216, 4, 4096)
                struct.pack_into("<II", efi, 256, 4, 4100)
                efi[4096:4104] = b"ABCDWXYZ" if role == "python" else b"AXCDWXYZ"
                names = b"\0.text\0.debug_str\0.shstrtab\0"
                debug = bytearray(329 + len(names))
                debug[:6] = b"\x7fELF\x02\x01"
                struct.pack_into("<Q", debug, 40, 64)
                struct.pack_into("<HHH", debug, 58, 64, 4, 3)
                for index, (flags, offset, size) in enumerate((
                        (2, 320, 4), (0, 324, 5), (0, 329, len(names))), 1):
                    section = 64 + 64 * index
                    section_name = (b".text", b".debug_str", b".shstrtab")[index - 1]
                    struct.pack_into("<II", debug, section,
                                     names.index(section_name), 3 if index == 3 else 1)
                    struct.pack_into("<Q", debug, section + 8, flags)
                    struct.pack_into("<QQ", debug, section + 24, offset, size)
                debug[320:329] = (b"TEXTpaths" if role == "python"
                                  else b"ZEXTpAths")
                debug[329:] = names
                (images / reference.EFI).write_bytes(efi)
                (images / (reference.EFI + ".dbg")).write_bytes(debug)
                files = {
                    reference.EFI: sha(efi),
                    reference.EFI + ".dbg": sha(debug),
                    reference.EFI + ".bootinfo": "a" * 64,
                }
                image = {"runtime_inputs_sha256": "b" * 64,
                         "solved_config_sha256": "c" * 64,
                         "application_sources": {}, "tools": {}, "files": files}
                sides.append({
                    "reference": mock.Mock(EFI=reference.EFI, APP=app,
                                           REPO=Path(scratch) / role),
                    "files": {"records": {"build.json": (b"", {"image": image})}},
                })
            self.assertEqual(build_image_differences(*sides), [
                "record_content:build.json.image.files.efi",
                "record_content:build.json.image.files.efi.section-0",
                "record_content:build.json.image.files.debug",
                "record_content:build.json.image.files.debug.alloc-1.text",
                "record_content:build.json.image.files.debug.nonalloc-2.debug_str",
                "record_content:build.json.image.files.debug.debug_str.other",
            ])
            (images / (reference.EFI + ".dbg")).write_bytes(debug[:-1] + b"?")
            with self.assertRaisesRegex(
                    ParityError, "image changed during comparison"):
                build_image_differences(*sides)

    def test_debug_string_diagnostics_classify_paths_without_contents(self):
        left = {"reference": mock.Mock(REPO=Path("/private/first"))}
        right = {"reference": mock.Mock(REPO=Path("/private/second"))}
        first = b"/private/first/source.c\0/elsewhere/first.c\0relative/a.c\0"
        second = b"/private/second/source.c\0/elsewhere/second.c\0relative/b.c\0"
        self.assertEqual(debug_string_differences(first, second, left, right), [
            "record_content:build.json.image.files.debug.debug_str.other-absolute",
            "record_content:build.json.image.files.debug.debug_str.relative-path",
            "record_content:build.json.image.files.debug.debug_str.source-root",
            "record_content:build.json.image.files.debug.debug_str.source-root.leading",
        ])
        self.assertEqual(debug_string_differences(
            b"/private/first/source.c\0", b"/private/second/source.c\0",
            left, right), sorted([
                "record_content:build.json.image.files.debug.debug_str.source-root",
                "record_content:build.json.image.files.debug.debug_str.source-root.leading",
                "record_content:build.json.image.files.debug.debug_str.source-root-remap-equal",
                "record_content:build.json.image.files.debug.debug_str.source-root-string-set-equal",
            ]))
        self.assertEqual(debug_string_differences(
            b"-fdebug-prefix-map=/private/first=/wamr-ci/source\0",
            b"-fdebug-prefix-map=/private/second=/wamr-ci/source\0",
            left, right), sorted([
                "record_content:build.json.image.files.debug.debug_str.source-root",
                "record_content:build.json.image.files.debug.debug_str.source-root.embedded",
                "record_content:build.json.image.files.debug.debug_str.source-root.recorded-switch",
                "record_content:build.json.image.files.debug.debug_str.source-root-remap-equal",
                "record_content:build.json.image.files.debug.debug_str.source-root-string-set-equal",
            ]))
        self.assertIn(
            "record_content:build.json.image.files.debug.debug_str.source-root.embedded-source",
            debug_string_differences(
                b"/private/first/support/apps/wamr-aot/build/artifacts/embedded.c\0",
                b"/private/second/support/apps/wamr-aot/build/artifacts/embedded.c\0",
                left, right))
        self.assertIn(
            "record_content:build.json.image.files.debug.debug_str.source-root.app-build-directory",
            debug_string_differences(
                b"/private/first/support/apps/wamr-aot/build\0",
                b"/private/second/support/apps/wamr-aot/build\0",
                left, right))
        self.assertIn(
            "record_content:build.json.image.files.debug.debug_str.source-root.app-build.generated-include",
            debug_string_differences(
                b"/private/first/support/apps/wamr-aot/build/include/uk/bits/config.h\0",
                b"/private/second/support/apps/wamr-aot/build/include/uk/bits/config.h\0",
                left, right))
        self.assertIn(
            "record_content:build.json.image.files.debug.debug_str.source-root.app-build.artifacts-dir",
            debug_string_differences(
                b"/private/first/support/apps/wamr-aot/build/artifacts\0",
                b"/private/second/support/apps/wamr-aot/build/artifacts\0",
                left, right))
        cache = (
            "record_content:build.json.image.files.debug.debug_str."
            "source-root.app-build.native-environment.zig_local_cache"
        )
        self.assertTrue({cache, cache + ".object-cache"} <= set(
            debug_string_differences(
                b"/private/first/support/apps/wamr-aot/build/"
                b"native-environment/zig_local_cache/o/test\0",
                b"/private/second/support/apps/wamr-aot/build/"
                b"native-environment/zig_local_cache/o/test\0",
                left, right)))

    def test_runtime_input_diagnostics_name_only_fixed_roles(self):
        with tempfile.TemporaryDirectory() as scratch:
            observations = []
            for side in ("python", "native"):
                repository = Path(scratch) / side
                identity_path = (repository /
                    "support/apps/wamr-aot/build/artifacts/identity.json")
                identity_path.parent.mkdir(parents=True)
                files = {name: "a" * 64 for name in RUNTIME_FILE_ROLES}
                if side == "native":
                    files["libwamr-aot.a"] = "b" * 64
                    files["identity.h"] = "c" * 64
                identity_path.write_text(json.dumps({
                    "variant": "tiny", "files": files,
                    "commands": [{"argv": [side], "cwd": side}],
                    "schema_version": 1,
                }) + "\n")
                identity_path.chmod(0o600)
                observations.append({
                    "roots": (Path(scratch), repository),
                    "files": {"records": {"build.json": (b"", {
                        "image": {"runtime_inputs_sha256":
                                  sha(identity_path.read_bytes())}})}},
                })
            expected = [
                "record_content:build.json.image.runtime_inputs.files.identity",
                "record_content:build.json.image.runtime_inputs.files.library",
                "record_content:build.json.image.runtime_inputs.commands",
            ]
            self.assertEqual(runtime_input_differences(*observations), expected)
            identity_path.write_text("{}\n")
            with self.assertRaisesRegex(
                    ParityError, "runtime identity changed during comparison"):
                runtime_input_differences(*observations)

    def test_config_source_root_diagnostic_does_not_normalize_artifact_parity(self):
        with tempfile.TemporaryDirectory() as scratch:
            observations = []
            for side in ("python", "native"):
                repository = Path(scratch) / ("source-" + side)
                config = repository / "support/apps/wamr-aot/.config"
                config.parent.mkdir(parents=True)
                raw = b"CONFIG_SOURCE=" + os.fsencode(repository) + b"\n"
                config.write_bytes(raw)
                config.chmod(0o600)
                observations.append({
                    "exit": subprocess.CompletedProcess([], 0, b"", b""),
                    "files": {"order": (), "records": {}, "retained": {},
                              "artifacts": {"config": (len(raw), sha(raw), 0o600)}},
                    "roots": (Path(scratch) / ("runtime-" + side), repository),
                })
            self.assertEqual(compare_observations(*observations), [
                "artifacts:config.sha256",
                "artifacts:config.source-root-dependent",
            ])
            config.write_bytes(raw + b"other=1\n")
            changed = config.read_bytes()
            observations[1]["files"]["artifacts"]["config"] = (
                len(changed), sha(changed), 0o600)
            self.assertEqual(compare_observations(*observations), [
                "artifacts:config.bytes", "artifacts:config.sha256",
            ])

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
                for mode in reference.SIX_MODES[:4]:
                    (runtime / "compute" / ("boot-" + mode)).mkdir(
                        mode=0o700)
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
                runtime = seen["roots"][0]
                records = seen["files"]["records"]
                records["build.json"] = (b"{}\n", {})
                records["qcow2-finalization.json"] = (b"{}\n", {})
                summaries = {}
                for index, mode in enumerate(reference.SIX_MODES[:4]):
                    work = runtime / "compute" / ("boot-" + mode)
                    request = reference.compact_json({
                        "schema_version": 2, "supervisor_pid": index + 1,
                        "config": reference.config_for(
                            runtime, runtime / "compute", index,
                            reference.SIX_MODES),
                        "pins": [],
                    }, newline=True)
                    serial = b"synthetic boot serial\n"
                    report = reference.compact_json({
                        "serial_sha256": sha(serial),
                        "serial_bytes": len(serial),
                    }, newline=True)
                    for name, raw in (("request.json", request),
                                      ("report.json", report),
                                      ("hyperv-efi-boot.log", serial)):
                        write(work / name, raw)
                    mode_record = {
                        "input_pins": [], "report": parsed(report, reference),
                        "request_sha256": sha(request),
                        "report_sha256": sha(report),
                    }
                    mode_raw = reference.compact_json(
                        mode_record, newline=True)
                    records[mode + "-compute.json"] = (
                        mode_raw, mode_record)
                    summaries[mode] = {
                        "request_sha256": sha(request),
                        "report_sha256": sha(report),
                        "serial_sha256": sha(serial),
                        "compute_sha256": sha(mode_raw),
                    }
                boot_raw = seen["files"]["records"]["boot-inputs.json"][0]
                value = {
                    "schema": "uk.wamr.compute-qcow2-acceptance",
                    "schema_version": 1,
                    "profile": reference.CURRENT_PROFILE,
                    "status": "accepted",
                    "source": {"revision": "synthetic"},
                    "accepted_qcow2": {"sha256": "a" * 64},
                    "finalization_sha256": sha(b"{}\n"),
                    "modes": list(reference.SIX_MODES[:4]),
                    "boots": summaries, "build_sha256": sha(b"{}\n"),
                    "boot_inputs_sha256": sha(boot_raw),
                }
                seen["files"]["records"]["qcow2-acceptance.json"] = (
                    reference.compact_json(value, newline=True), value)
            self.assertNotEqual(
                python["files"]["records"]["qcow2-acceptance.json"][1][
                    "boot_inputs_sha256"],
                native["files"]["records"]["qcow2-acceptance.json"][1][
                    "boot_inputs_sha256"])
            baseline_failures = compare_qcow2_acceptance(python, native)
            self.assertEqual(baseline_failures, [
                "record_content:qcow2-acceptance.json.boots",
                *(f"record_content:qcow2-acceptance.json.boots.{mode}.{field}"
                  for mode in reference.SIX_MODES[:4]
                  for field in ("request_sha256", "compute_sha256")),
            ])
            self.assertEqual(
                compare_qcow2_acceptance(python, native, MODES[:4]), [])

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
                for kind in ("wrong-boot-hash", "wrong-boot-receipt",
                             "extra-field", "other-field"):
                    with self.subTest(side=side, kind=kind):
                        changed = copy.deepcopy(
                            observations[side]["files"]["records"][
                                "qcow2-acceptance.json"][1])
                        if kind == "wrong-boot-hash":
                            changed["boot_inputs_sha256"] = "0" * 64
                        elif kind == "wrong-boot-receipt":
                            changed["boots"]["raw-x2apic"]["compute_sha256"] = "0" * 64
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
                                [baseline_failures[0],
                                 "record_content:qcow2-acceptance.json.source",
                                 *baseline_failures[1:]])
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
            ["retained", "retained:private.log.membership"])


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
