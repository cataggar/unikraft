#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""Freeze #189 authority contracts from the current Python oracle.

Regenerate intentionally with:
  python3 -B support/build/wamr-native-ci/tests/test_authority_contract_goldens.py --write
"""
import argparse
import ast
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[4]
WAMR_CI = ROOT / "support/build/wamr-native-ci"
GOLDEN = WAMR_CI / "authority/goldens/contracts.json"
SCENARIOS = WAMR_CI / "authority/goldens/python-scenarios.json"

def scratch_root():
    explicit = os.environ.get("WAMR_AUTHORITY_CONTRACT_SCRATCH")
    if explicit:
        return Path(explicit)
    zig_cache = os.environ.get("ZIG_LOCAL_CACHE_DIR")
    if zig_cache:
        return Path(zig_cache) / "authority-contract-work"
    return Path.home() / ".cache/wamr-authority-contract-work"


SCRATCH = scratch_root()
AUTHORITY_COMMANDS = (
    "prepare-azure-runtime",
    "plan",
    "record-authorization",
    "admit",
)
SCENARIO_SOURCES = (
    "support/tools/hyperv/direct/tests/test_v2_lineage.py",
    "support/tools/hyperv/direct/tests/test_compute.py",
    "support/build/wamr-native-ci/tests/test_adapter.py",
)
REV = "0123456789012345678901234567890123456789"
ATTEMPT = "00000000-0000-4000-8000-000000000001"
CAMPAIGN = "00000000-0000-4000-8000-000000000002"
LEDGER = "00000000-0000-4000-8000-000000000003"
SUBSCRIPTION = "00000000-0000-4000-8000-000000000004"
GENERATED_ATTEMPT = "00000000-0000-4000-8000-000000000101"
GENERATED_LEDGER = "00000000-0000-4000-8000-000000000102"
CREATED = 1_800_000_000
RECORDED = 1_800_000_100
PROBE_SENTINEL = b"AUTHORITY-PROBE-SENTINEL"
_ORIGINAL_SHA256 = hashlib.sha256


def remove_tree(path):
    path = Path(path)
    if not path.exists():
        return
    for current, directories, files in os.walk(path, topdown=False):
        current = Path(current)
        for name in files:
            try:
                (current / name).chmod(0o600)
            except FileNotFoundError:
                pass
        for name in directories:
            try:
                (current / name).chmod(0o700)
            except FileNotFoundError:
                pass
        try:
            current.chmod(0o700)
        except FileNotFoundError:
            pass
    shutil.rmtree(path)


def load(name):
    spec = importlib.util.spec_from_file_location(name, WAMR_CI / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def canonical_file(value):
    return json.dumps(
        value, ensure_ascii=False, allow_nan=False,
        sort_keys=True, separators=(",", ":")) + "\n"


def canonical_json(handoff, value):
    return handoff.ci.compact_json(value, newline=True).decode("utf-8")


def digest_bytes(data):
    if isinstance(data, str):
        data = data.encode("utf-8")
    return _ORIGINAL_SHA256(data).hexdigest()


def digest_label(label):
    return digest_bytes(("authority-contract:" + label).encode("utf-8"))




def native_cost_coefficients():
    source = (ROOT / "support/tools/hyperv/direct/compute.zig").read_text(encoding="utf-8")
    result = {}
    for name in ("fixed_overhead_microusd", "vm_hour_microusd", "os_disk_hour_microusd"):
        prefix = f"const {name}: u64 = "
        line = next(line for line in source.splitlines() if line.startswith(prefix))
        result[name] = int(line.removeprefix(prefix).rstrip(";").replace("_", ""))
    return result


def synthetic_artifact(path, *, size=1, sha=None):
    return {"path": path, "size": size, "sha256": sha or digest_label(path)}


class FakeStat:
    def __init__(self, *, mode, size, path_key, uid=1000, gid=1000):
        digest = _ORIGINAL_SHA256(path_key.encode("utf-8")).digest()
        inode = 10_000 + int.from_bytes(digest[:4], "big")
        tick = int.from_bytes(digest[4:8], "big")
        self.st_dev = os.makedev(8, 1)
        self.st_ino = inode
        self.st_mode = mode
        self.st_uid = uid
        self.st_gid = gid
        self.st_nlink = 2 if stat.S_ISDIR(mode) else 1
        self.st_size = size
        self.st_mtime_ns = 1_700_000_000_000_000_000 + tick
        self.st_ctime_ns = 1_700_000_100_000_000_000 + tick


class StableSha256:
    def __init__(self, normalize):
        self._normalize = normalize
        self._hash = _ORIGINAL_SHA256()

    def update(self, data):
        self._hash.update(self._normalize(bytes(data)))

    def hexdigest(self):
        return self._hash.hexdigest()

    def digest(self):
        return self._hash.digest()

    def copy(self):
        clone = StableSha256(self._normalize)
        clone._hash = self._hash.copy()
        return clone


class AuthorityOracle:
    def __init__(self, handoff):
        self.handoff = handoff
        self.root = SCRATCH
        self.anchor = self.root / "authority"
        self.uid = 1000
        self.gid = 1000
        self.uuid_queue = []
        self.uuid_counter = 0
        self.probe_outputs = []
        self.runtime_record = None
        self.runtime_record_path = None
        self.runtime_schema_record = None
        self.runtime_manifest_text = None
        self.tool_paths = {}

    def reset(self):
        remove_tree(self.root)
        self.anchor.mkdir(mode=0o700, parents=True)

    def logical(self, path):
        raw = os.fspath(path)
        if raw.startswith("/authority"):
            return raw
        physical = Path(raw)
        try:
            relative = physical.resolve(strict=False).relative_to(self.anchor.resolve(strict=False))
        except ValueError:
            return raw
        return "/authority" if not relative.parts else "/authority/" + relative.as_posix()

    def physical(self, path):
        raw = os.fspath(path)
        if raw == "/authority":
            return self.anchor
        if raw.startswith("/authority/"):
            return self.anchor / raw.removeprefix("/authority/")
        return Path(raw)

    def normalize_bytes(self, data):
        anchor = str(self.anchor).encode("utf-8")
        return bytes(data).replace(anchor, b"/authority")

    def stable_file_bytes(self, path):
        return self.normalize_bytes(self.physical(path).read_bytes())

    def digest(self, path, limit=256 * 1024 * 1024 + 512):
        del limit
        return digest_bytes(self.stable_file_bytes(path))

    def fake_lstat(self, original_lstat, path):
        physical = self.physical(path)
        if not physical.exists():
            return original_lstat(path)
        try:
            logical = self.logical(physical)
        except OSError:
            return original_lstat(path)
        if not logical.startswith("/authority"):
            return original_lstat(path)
        real = original_lstat(physical)
        if stat.S_ISDIR(real.st_mode):
            mode = stat.S_IFDIR | (stat.S_IMODE(real.st_mode) or 0o500)
            size = 4096
        elif stat.S_ISREG(real.st_mode):
            mode = stat.S_IFREG | (stat.S_IMODE(real.st_mode) or 0o400)
            size = len(self.stable_file_bytes(physical))
        else:
            mode = real.st_mode
            size = real.st_size
        return FakeStat(mode=mode, size=size, path_key=logical, uid=self.uid, gid=self.gid)

    def normalize_value(self, value):
        if isinstance(value, str):
            return value.replace(str(self.anchor), "/authority")
        if isinstance(value, list):
            return [self.normalize_value(item) for item in value]
        if isinstance(value, dict):
            return {key: self.normalize_value(item) for key, item in value.items()}
        return value

    def artifact(self, path):
        return {
            "path": self.logical(path),
            "size": len(self.stable_file_bytes(path)),
            "sha256": self.digest(path),
        }

    def executable_artifact(self, path):
        return self.artifact(path)

    def canonical_document(self, path):
        data = self.stable_file_bytes(path)
        value = json.loads(data, object_pairs_hook=self.handoff.ci.unique)
        self.handoff.ci.require(
            data == self.handoff.ci.compact_json(value, newline=True),
            "canonical private JSON required")
        return value

    def private(self, path):
        del path

    def native_validate(self, validator, *arguments):
        del validator, arguments

    def native_json(self, validator, *arguments):
        del validator
        self.handoff.ci.require(
            len(arguments) == 4 and arguments[0] == "ledger-proposal",
            "native authorization inspection failed")
        unused_ledger, campaign_id, ledger_id = arguments[1:]
        del unused_ledger
        return {
            "schema": "uk.wamr.azure-campaign-ledger-binding",
            "version": 1,
            "purpose": "qcow2-derived-vhd-two-boot",
            "campaign_id": str(campaign_id),
            "ledger_id": str(ledger_id),
            "directory": {
                "device_major": 8,
                "device_minor": 1,
                "inode": 3001,
                "uid": self.uid,
                "mode": 0o700,
            },
            "initialization_required": True,
            "initial_state_sha256": digest_label("ledger-initial"),
            "marker_sha256": digest_label("ledger-marker"),
        }

    def safe_source_tree(self, path):
        return self.physical(path)

    def copy_runtime_file(self, source, destination, executable=None, budget=None,
                          parent_fd=None, source_name=None):
        del parent_fd, source_name
        source = self.physical(source)
        destination = self.physical(destination)
        data = source.read_bytes()
        if budget is not None:
            budget.file(destination, len(data))
        destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        destination.write_bytes(data)
        destination.chmod(0o500 if executable else 0o400)

    def copy_runtime_tree(self, source, destination, budget, merge=False):
        source = self.physical(source)
        destination = self.physical(destination)
        destination.mkdir(mode=0o700, parents=True, exist_ok=merge)
        budget.directory(destination)
        for current, directories, files in os.walk(source):
            current = Path(current)
            relative = current.relative_to(source)
            target = destination if relative == Path(".") else destination / relative
            for directory in sorted(directories):
                child = target / directory
                child.mkdir(mode=0o700, exist_ok=merge)
                budget.directory(child)
            for name in sorted(files):
                child_source = current / name
                child_target = target / name
                self.copy_runtime_file(child_source, child_target, budget=budget)

    def elf_interpreter(self, path):
        del path
        return self.tool_paths["loader_source"]

    def elf_dependencies(self, paths):
        del paths
        return {"libpython3.12.so.1.0": self.tool_paths["libpython"]}

    def parent_records(self, paths):
        parents = set()
        for item in paths:
            current = Path(self.logical(item)).parent
            while True:
                parents.add(current.as_posix())
                if current == Path("/"):
                    break
                current = current.parent
        result = []
        for parent in sorted(parents):
            result.append((parent, FakeStat(
                mode=stat.S_IFDIR | 0o500, size=4096,
                path_key="parent:" + parent, uid=self.uid, gid=self.gid)))
        return result

    def bounded_subprocess_output(self, arguments, cwd, limit, timeout,
                                  overflow, timeout_reason, failure,
                                  env=None):
        del cwd, limit, timeout, overflow, timeout_reason, failure, env
        logical_args = [self.logical(arg) for arg in arguments]
        self.probe_outputs.append(logical_args)
        if "--list" in [str(arg) for arg in arguments]:
            return b""
        return PROBE_SENTINEL + b"\n"

    def next_uuid(self):
        if self.uuid_queue:
            value = self.uuid_queue.pop(0)
        else:
            self.uuid_counter += 1
            value = f"00000000-0000-4000-8000-{0x900 + self.uuid_counter:012x}"
        return self.handoff.uuid.UUID(value)

    @contextlib.contextmanager
    def patched(self):
        handoff = self.handoff
        original_path_lstat = Path.lstat
        original_sha256 = hashlib.sha256
        originals = {
            "private": handoff.private,
            "native_validate": handoff.native_validate,
            "native_json": handoff.native_json,
            "candidate_plan": handoff.candidate_plan,
            "artifact": handoff.artifact,
            "executable_artifact": handoff.executable_artifact,
            "canonical_document": handoff.canonical_document,
            "exact_tool_bindings": handoff.exact_tool_bindings,
            "require_tool_bindings": handoff.require_tool_bindings,
            "copy_runtime_file": handoff._copy_runtime_file,
            "copy_runtime_tree": handoff._copy_runtime_tree,
            "safe_source_tree": handoff._safe_source_tree,
            "elf_interpreter": handoff._elf_interpreter,
            "elf_dependencies": handoff._elf_dependencies,
            "parent_records": handoff._parent_records,
            "ci_digest": handoff.ci.digest,
            "bounded_subprocess_output": handoff.ci.bounded_subprocess_output,
            "uuid4": handoff.uuid.uuid4,
            "time": handoff.time.time,
            "geteuid": handoff.os.geteuid,
        }

        def stable_sha256(data=b""):
            value = StableSha256(self.normalize_bytes)
            if data:
                value.update(data)
            return value

        def exact_tool_bindings(*args, **kwargs):
            return originals["exact_tool_bindings"](*args, **kwargs)

        def require_tool_bindings(*args, **kwargs):
            return originals["require_tool_bindings"](*args, **kwargs)

        handoff.private = self.private
        handoff.native_validate = self.native_validate
        handoff.native_json = self.native_json
        handoff.candidate_plan = self.candidate_plan
        handoff.artifact = self.artifact
        handoff.executable_artifact = self.executable_artifact
        handoff.canonical_document = self.canonical_document
        handoff.exact_tool_bindings = exact_tool_bindings
        handoff.require_tool_bindings = require_tool_bindings
        handoff._copy_runtime_file = self.copy_runtime_file
        handoff._copy_runtime_tree = self.copy_runtime_tree
        handoff._safe_source_tree = self.safe_source_tree
        handoff._elf_interpreter = self.elf_interpreter
        handoff._elf_dependencies = self.elf_dependencies
        handoff._parent_records = self.parent_records
        handoff.ci.digest = self.digest
        handoff.ci.bounded_subprocess_output = self.bounded_subprocess_output
        handoff.uuid.uuid4 = self.next_uuid
        handoff.time.time = lambda: CREATED
        handoff.os.geteuid = lambda: self.uid
        hashlib.sha256 = stable_sha256
        Path.lstat = lambda path_self: self.fake_lstat(original_path_lstat, path_self)
        try:
            yield
        finally:
            handoff.private = originals["private"]
            handoff.native_validate = originals["native_validate"]
            handoff.native_json = originals["native_json"]
            handoff.candidate_plan = originals["candidate_plan"]
            handoff.artifact = originals["artifact"]
            handoff.executable_artifact = originals["executable_artifact"]
            handoff.canonical_document = originals["canonical_document"]
            handoff.exact_tool_bindings = originals["exact_tool_bindings"]
            handoff.require_tool_bindings = originals["require_tool_bindings"]
            handoff._copy_runtime_file = originals["copy_runtime_file"]
            handoff._copy_runtime_tree = originals["copy_runtime_tree"]
            handoff._safe_source_tree = originals["safe_source_tree"]
            handoff._elf_interpreter = originals["elf_interpreter"]
            handoff._elf_dependencies = originals["elf_dependencies"]
            handoff._parent_records = originals["parent_records"]
            handoff.ci.digest = originals["ci_digest"]
            handoff.ci.bounded_subprocess_output = originals["bounded_subprocess_output"]
            handoff.uuid.uuid4 = originals["uuid4"]
            handoff.time.time = originals["time"]
            handoff.os.geteuid = originals["geteuid"]
            hashlib.sha256 = original_sha256
            Path.lstat = original_path_lstat

    def write_input(self, relative, data, mode=0o600):
        path = self.anchor / relative
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        path.write_bytes(data)
        path.chmod(mode)
        return path

    def make_inputs(self):
        for directory in (
            self.anchor / "bin",
            self.anchor / "private",
            self.anchor / "sources/python3.12",
            self.anchor / "sources/package/azure",
            self.anchor / "sources/data",
        ):
            directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.tool_paths = {
            "azure": self.write_input("bin/azure", b"azure-cli-launcher\n", 0o500),
            "az_python": self.write_input("bin/python3.12", b"python-interpreter\n", 0o500),
            "validator": self.write_input("bin/uk-wamr-direct-validate", b"validator\n", 0o500),
            "uploader": self.write_input("bin/uk-hyperv-transfer", b"uploader\n", 0o500),
            "supervisor": self.write_input("bin/wamr-ci-supervisor", b"supervisor\n", 0o500),
            "loader_source": self.write_input("native/ld-linux-x86-64.so.2", b"loader\n", 0o500),
            "libpython": self.write_input("native/libpython3.12.so.1.0", b"libpython\n", 0o500),
        }
        self.write_input("sources/python3.12/os.py", b"# stdlib os\n")
        self.write_input("sources/python3.12/encodings/__init__.py", b"# encodings\n")
        self.write_input("sources/package/azure/__init__.py", b"# azure\n")
        self.write_input("sources/package/azure/core.so", b"native extension\n", 0o500)
        self.write_input("sources/data/clouds.config", b"AzureCloud\n")
        ledger = self.anchor / "private/campaign-ledger"
        ledger.mkdir(mode=0o700, parents=True, exist_ok=True)
        bundle = self.anchor / "private/bundle.json"
        self.handoff.ci.save(bundle, {"schema": "authority-contract-placeholder", "version": 1})
        return {
            "ledger": ledger,
            "bundle": bundle,
            "stdlib": self.anchor / "sources/python3.12",
            "package_root": self.anchor / "sources/package",
            "data_root": self.anchor / "sources/data",
        }

    def prepare_runtime(self, inputs):
        output = self.anchor / "private/azure-runtime-closure"
        raw_value = self.handoff.prepare_azure_runtime(
            output, self.tool_paths["azure"], self.tool_paths["az_python"],
            inputs["stdlib"], package_roots=(inputs["package_root"],),
            data_roots=(inputs["data_root"],), native_dependencies=(),
            validator=self.tool_paths["validator"])
        self.runtime_schema_record = self.normalize_value(raw_value)
        self.runtime_record_path = output / "azure-runtime.json"
        self.runtime_record = self.canonical_document(self.runtime_record_path)
        self.runtime_manifest_text = self.stable_file_bytes(output / "azure-runtime.manifest").decode("utf-8")
        return self.runtime_record

    def candidate_plan(self, bundle_path, output, *, attempt_id=None,
                       subscription=None, prefix=None):
        del bundle_path
        output = self.physical(output)
        imported_path = output.parent / (output.name + ".admission.json")
        public_bundle_path = output.parent / "bundle.json"
        transport_path = output.parent / "transport.json"
        names = list(self.handoff.V2_NAMES)
        artifacts = []
        for name in names:
            size = self.handoff.FIXED_VHD_BYTES if name == "vhd" else 1024 + len(artifacts)
            artifacts.append(synthetic_artifact(
                f"/authority/private/imported-image/artifacts/{name}",
                size=size, sha=digest_label("artifact-" + name)))
        by_name = dict(zip(names, artifacts))
        public_bundle = {
            "schema": "uk.wamr.local-image-handoff",
            "version": 2,
            "authority": "not_admitted",
            "source_revision": REV,
            "source_tree": REV,
            "profile": self.handoff.ci.CURRENT_PROFILE,
            "run": {"repository": "cataggar/unikraft", "run_id": "1", "run_attempt": "1"},
            "identity": {
                "wamr_revision": self.handoff.ci.REVISION,
                "wasm_sha256": digest_label("wasm"),
                "cwasm_sha256": digest_label("cwasm"),
                "runtime_sha256": digest_label("wamr-runtime"),
                "compiler_sha256": digest_label("compiler"),
                "config_sha256": digest_label("config"),
            },
            "lineage": {
                "raw_sha256": by_name["raw"]["sha256"],
                "accepted_qcow2_sha256": by_name["qcow2"]["sha256"],
                "derived_vhd_sha256": by_name["vhd"]["sha256"],
                "qcow2_finalization_sha256": by_name["qcow2_finalization"]["sha256"],
                "qcow2_acceptance_sha256": by_name["qcow2_acceptance"]["sha256"],
                "fixed_vhd_derivation_sha256": by_name["fixed_vhd_derivation"]["sha256"],
                "fixed_vhd_derivation_gate_sha256": by_name["fixed_vhd_derivation_gate"]["sha256"],
                "final_inspection_sha256": by_name["final_inspection"]["sha256"],
            },
            "artifacts": artifacts,
            "boots": [],
            "evidence": [],
        }
        transport = {
            "schema": "uk.wamr.public-source-transport",
            "version": 2,
            "repository": "cataggar/unikraft",
            "run_id": "1",
            "run_attempt": "1",
            "source_revision": REV,
            "source_tree": REV,
            "inner_zip_sha256": digest_label("inner-zip"),
            "artifact_id": "1",
            "container_digest": digest_label("container"),
        }
        self.handoff.ci.save(public_bundle_path, public_bundle)
        self.handoff.ci.save(transport_path, transport)
        imported = {
            "schema": "uk.wamr.direct-compute-admission",
            "version": 2,
            "profile": self.handoff.ci.CURRENT_PROFILE,
            "authority": "not_admitted",
            "source_revision": REV,
            "source_tree": REV,
            "run": public_bundle["run"],
            "lineage": public_bundle["lineage"],
            "public_bundle": self.artifact(public_bundle_path),
            "transport": self.artifact(transport_path),
        }
        self.handoff.ci.save(imported_path, imported)
        value = {
            "schema": "uk.wamr.direct-compute",
            "version": 2,
            "purpose": self.handoff.ci.CURRENT_PROFILE,
            "authority": "not_admitted",
            "approval": {
                "direct_specialized_gen2": False,
                "os_only_private": False,
                "two_boots_only": False,
                "cleanup_owned_group": False,
                "exact_image_and_local_bundle_reviewed": False,
                "fresh_final_approval": False,
                "approved_unix": 0,
                "expires_unix": 0,
            },
            "attempt_id": attempt_id,
            "subscription": subscription,
            "location": "northeurope",
            "prefix": prefix,
            "vm_size": "Standard_D2s_v5",
            "serial_mode": "azure_cumulative",
            "runtime_seconds": 3600,
            "cleanup_seconds": 1800,
            "operation_seconds": 600,
            "poll_seconds": 10,
            "source_revision": REV,
            "source_tree": REV,
            "identity": public_bundle["identity"],
            "lineage": public_bundle["lineage"],
            "os_vhd": by_name["vhd"],
            "bundle": self.artifact(imported_path),
        }
        self.handoff.ci.save(output, value)
        return value

    def authority_args(self):
        runtime = self.runtime_record
        return {
            "azure": Path(runtime["launcher"]["path"]),
            "uploader": Path("/authority/bin/uk-hyperv-transfer"),
            "validator": Path("/authority/bin/uk-wamr-direct-validate"),
            "supervisor": Path("/authority/bin/wamr-ci-supervisor"),
            "az_python": Path(runtime["interpreter"]["path"]),
            "azure_runtime": Path("/authority/private/azure-runtime-closure/azure-runtime.json"),
        }

    def case_dir(self, name):
        path = self.anchor / "private/cases" / name
        path.mkdir(mode=0o700, parents=True, exist_ok=False)
        (path / "ledger").mkdir(mode=0o700)
        return path

    def plan_case(self, name, *, attempt_id=ATTEMPT, ledger_id=LEDGER,
                  campaign_id=CAMPAIGN, subscription=SUBSCRIPTION,
                  prefix="auth-freeze", maximum=None, created_unix=CREATED):
        case = self.case_dir(name)
        maximum = self.handoff.ESTIMATED_COST_UPPER_BOUND_MICROUSD if maximum is None else maximum
        plan_path = case / "plan.json"
        template_path = case / "template.json"
        candidate_path = case / "candidate.json"
        value, template = self.handoff.plan(
            self.anchor / "private/bundle.json", plan_path, template_path,
            candidate_path, campaign_id=campaign_id, ledger=case / "ledger",
            subscription=subscription, prefix=prefix,
            maximum_authorized_cost_microusd=maximum,
            attempt_id=attempt_id, ledger_id=ledger_id,
            created_unix=created_unix, **self.authority_args())
        return {
            "plan": value,
            "template": template,
            "plan_path": plan_path,
            "template_path": template_path,
            "candidate_path": candidate_path,
        }

    def authorization_case(self, name, plan_path, template_path, *,
                           decision="approved", approver="authority-freeze-operator",
                           reference="issue-189-contract-freeze",
                           recorded_unix=RECORDED, expires_unix=RECORDED + 3600):
        case = self.case_dir(name)
        output = case / "authorization.json"
        value = self.handoff.record_authorization(
            plan_path, template_path, output, decision=decision,
            approver=approver, reference=reference,
            recorded_unix=recorded_unix, expires_unix=expires_unix,
            **self.authority_args())
        return {"authorization": value, "authorization_path": output}

    def admission_case(self, name, plan_path, authorization_path):
        case = self.case_dir(name)
        output = case / "admission.json"
        value = self.handoff.admission(
            plan_path, authorization_path, output, **self.authority_args())
        return {"admission": value, "admission_path": output}

    def outcome(self, name, operation, outputs):
        try:
            operation()
            refused = False
            exception = None
            reason = None
        except Exception as error:  # noqa: BLE001 - contract freezes refusal class.
            if not isinstance(error, self.handoff.ci.Refusal):
                raise
            refused = True
            exception = type(error).__module__ + "." + type(error).__name__
            reason = str(error)
        output_map = {label: self.physical(path).exists() for label, path in outputs.items()}
        return {
            "name": name,
            "refused": refused,
            "exception": exception,
            "reason": reason,
            "output_file_appeared": any(output_map.values()),
            "outputs": output_map,
        }


def manifest_summary(text):
    lines = [line + "\n" for line in text.splitlines()]
    header = lines[0]
    body = lines[1:]

    def first(tag, role=None):
        for line in body:
            fields = line.rstrip("\n").split("\t")
            if fields[0] == tag and (role is None or fields[1] == role):
                return line
        raise AssertionError(f"missing manifest {tag} {role}")

    return {
        "header": header,
        "directory": first("D"),
        "file": first("F", "launcher"),
        "loader": first("L", "loader-dependency"),
        "parent": first("P"),
        "sample": text,
    }


def capture_parser(handoff):
    captured = {}

    class Captured(Exception):
        pass

    original = handoff.argparse.ArgumentParser.parse_args

    def replacement(self, *args, **kwargs):
        captured["parser"] = self
        raise Captured

    handoff.argparse.ArgumentParser.parse_args = replacement
    try:
        try:
            handoff.main()
        except Captured:
            pass
    finally:
        handoff.argparse.ArgumentParser.parse_args = original
    return captured["parser"]


def subcommands(parser):
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            return action.choices
    raise AssertionError("no subcommands")


def option_type(action):
    if action.type is None:
        return None
    return getattr(action.type, "__name__", str(action.type))


def cli_surface(handoff):
    choices = subcommands(capture_parser(handoff))
    result = {}
    for command in AUTHORITY_COMMANDS:
        parser = choices[command]
        options = []
        for action in parser._actions:
            if isinstance(action, argparse._HelpAction):
                continue
            flags = list(action.option_strings)
            if not flags:
                continue
            options.append({
                "flags": flags,
                "dest": action.dest,
                "required": bool(getattr(action, "required", False)),
                "repeated": isinstance(action, argparse._AppendAction),
                "choices": list(action.choices) if action.choices is not None else [],
                "type": option_type(action),
            })
        result[command] = {
            "options": options,
            "required": [item["flags"][0] for item in options if item["required"] and not item["repeated"]],
            "optional": [item["flags"][0] for item in options if not item["required"] and not item["repeated"]],
            "repeated_required": [item["flags"][0] for item in options if item["required"] and item["repeated"]],
            "repeated_optional": [item["flags"][0] for item in options if not item["required"] and item["repeated"]],
        }
    return result


def run_handoff(*args):
    env = {"PYTHONDONTWRITEBYTECODE": "1", "LC_ALL": "C"}
    completed = subprocess.run(
        [sys.executable, "-B", str(WAMR_CI / "handoff.py"), *args],
        cwd=ROOT,
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    return completed.returncode, completed.stdout.decode("utf-8", "strict"), completed.stderr.decode("utf-8", "strict")


def direct_main_success(handoff, oracle, plan_path, template_path):
    output = oracle.anchor / "private/main-success-authorization.json"
    argv = [
        "handoff.py", "record-authorization",
        "--plan", str(plan_path),
        "--template", str(template_path),
        "--output", str(output),
        "--decision", "approved",
        "--approver", "main-success-operator",
        "--reference", "main-success-reference",
        "--recorded-unix", str(RECORDED),
        "--expires-unix", str(RECORDED + 3600),
    ]
    for key, value in oracle.authority_args().items():
        argv.extend(("--" + key.replace("_", "-"), str(value)))
    original_argv = sys.argv
    stdout = io.StringIO()
    try:
        sys.argv = argv
        with contextlib.redirect_stdout(stdout):
            handoff.main()
        code = 0
    except SystemExit as error:
        code = int(error.code or 0)
    finally:
        sys.argv = original_argv
    return code, stdout.getvalue()


def exit_contract(handoff, oracle, plan_path, template_path):
    help_exit = {}
    malformed_exit = {}
    for command in AUTHORITY_COMMANDS:
        code, unused_stdout, unused_stderr = run_handoff(command, "--help")
        del unused_stdout, unused_stderr
        help_exit[command] = code
        code, unused_stdout, unused_stderr = run_handoff(command)
        del unused_stdout, unused_stderr
        malformed_exit[command] = code
    refusal_args = (
        "plan",
        "--bundle", "bundle.json",
        "--output", "plan.json",
        "--approval-template", "template.json",
        "--candidate-output", "candidate.json",
        "--campaign-id", CAMPAIGN,
        "--ledger", "ledger",
        "--subscription", SUBSCRIPTION,
        "--prefix", "auth-freeze",
        "--maximum-authorized-cost-microusd", str(handoff.ESTIMATED_COST_UPPER_BOUND_MICROUSD),
        "--azure", "azure",
        "--uploader", "uploader",
        "--validator", "validator",
        "--supervisor", "supervisor",
        "--az-python", "python",
        "--azure-runtime", "runtime.json",
    )
    refusal_exit, refusal_stdout, refusal_stderr = run_handoff(*refusal_args)
    success_exit, success_stdout = direct_main_success(handoff, oracle, plan_path, template_path)
    runtime_bytes = canonical_json(handoff, oracle.runtime_record).encode("utf-8")
    manifest_bytes = oracle.runtime_manifest_text.encode("utf-8")
    return {
        "help_exit": help_exit,
        "malformed_exit": malformed_exit,
        "refusal_exit": refusal_exit,
        "refusal_stdout": refusal_stdout,
        "refusal_stderr": refusal_stderr,
        "success_exit": success_exit,
        "success_stdout": success_stdout,
        "validator_probe_streams_public": any(
            PROBE_SENTINEL in payload for payload in (runtime_bytes, manifest_bytes)),
    }


def schemas(values):
    runtime = values["azure_runtime"]
    plan = values["plan"]
    template = values["approval_template"]
    authorization = values["authorization_approved"]
    admission = values["admission"]
    return {
        "artifact": list(plan["candidate"].keys()),
        "azure_runtime": list(runtime.keys()),
        "azure_runtime_limits": list(runtime["limits"].keys()),
        "azure_runtime_observed": list(runtime["observed"].keys()),
        "azure_runtime_isolation": list(runtime["isolation"].keys()),
        "ledger": list(plan["ledger"].keys()),
        "ledger_directory": list(plan["ledger"]["directory"].keys()),
        "run": list(plan["run"].keys()),
        "identity": list(plan["identity"].keys()),
        "lineage": list(plan["lineage"].keys()),
        "resources": list(plan["resources"].keys()),
        "substitution": list(plan["substitution"].keys()),
        "cleanup": list(plan["cleanup"].keys()),
        "cost": list(plan["cost"].keys()),
        "tools": list(plan["tools"].keys()),
        "azure_runtime_approval": list(template["azure_runtime"].keys()),
        "approval_limits": list(template["limits"].keys()),
        "plan": list(plan.keys()),
        "approval_template": list(template.keys()),
        "authorization": list(authorization.keys()),
        "admission": list(admission.keys()),
        "admission_approval": list(admission["approval"].keys()),
    }


def binary_max(success, high):
    lo = 0
    hi = high
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if success(mid):
            lo = mid
        else:
            hi = mid - 1
    return lo


def derive_live_probes(handoff, oracle, base):
    refusals = []
    successes = []

    def auth_success(name, **kwargs):
        try:
            oracle.authorization_case(name, base["plan_path"], base["template_path"], **kwargs)
            return True
        except handoff.ci.Refusal:
            return False

    def plan_success(name, **kwargs):
        try:
            oracle.plan_case(name, **kwargs)
            return True
        except handoff.ci.Refusal:
            return False

    def add_refusal(name, operation, outputs):
        outcome = oracle.outcome(name, operation, outputs)
        refusals.append(outcome)
        return outcome

    approver_max = binary_max(
        lambda n: auth_success(f"probe-approver-{n}", approver="a" * n), 4097)
    reference_max = binary_max(
        lambda n: auth_success(f"probe-reference-{n}", reference="r" * n), 4097)
    window_max = binary_max(
        lambda n: auth_success(
            f"probe-window-{n}", recorded_unix=RECORDED,
            expires_unix=RECORDED + n), 86401)
    for name, kwargs, output_name in (
        ("approver-min-accepted", {"approver": "a"}, "authorization.json"),
        ("approver-max-accepted", {"approver": "a" * approver_max}, "authorization.json"),
        ("reference-min-accepted", {"reference": "r"}, "authorization.json"),
        ("reference-max-accepted", {"reference": "r" * reference_max}, "authorization.json"),
        ("approval-window-max-accepted", {"expires_unix": RECORDED + window_max}, "authorization.json"),
    ):
        case = oracle.authorization_case(name, base["plan_path"], base["template_path"], **kwargs)
        successes.append({"name": name, "output": oracle.logical(case["authorization_path"]), "file": output_name})
    for name, kwargs in (
        ("approver-empty", {"approver": ""}),
        ("approver-control-lf", {"approver": "bad\n"}),
        ("approver-del", {"approver": "bad" + chr(0x7f)}),
        ("approver-over", {"approver": "a" * (approver_max + 1)}),
        ("reference-empty", {"reference": ""}),
        ("reference-control-lf", {"reference": "bad\n"}),
        ("reference-del", {"reference": "bad" + chr(0x7f)}),
        ("reference-over", {"reference": "r" * (reference_max + 1)}),
        ("approval-window-zero-recorded", {"recorded_unix": 0, "expires_unix": window_max}),
        ("approval-window-over", {"expires_unix": RECORDED + window_max + 1}),
    ):
        case = oracle.anchor / "private/cases" / name / "authorization.json"
        add_refusal(
            name,
            lambda kwargs=kwargs, name=name: oracle.authorization_case(
                name, base["plan_path"], base["template_path"], **kwargs),
            {"authorization": case})
    denied = oracle.authorization_case(
        "denied-for-admission", base["plan_path"], base["template_path"],
        decision="denied")
    add_refusal(
        "denied-authorization-admission",
        lambda: oracle.admission_case(
            "denied-authorization-admission", base["plan_path"],
            denied["authorization_path"]),
        {"admission": oracle.anchor / "private/cases/denied-authorization-admission/admission.json"})

    for name, kwargs in (
        ("uuid-attempt-invalid", {"attempt_id": "not-a-uuid"}),
        ("uuid-campaign-invalid", {"campaign_id": "not-a-uuid"}),
        ("uuid-subscription-invalid", {"subscription": "not-a-uuid"}),
        ("cost-under-estimate", {"maximum": handoff.ESTIMATED_COST_UPPER_BOUND_MICROUSD - 1}),
        ("cost-over-repository", {"maximum": handoff.REPOSITORY_MAXIMUM_COST_MICROUSD + 1}),
    ):
        base_path = oracle.anchor / "private/cases" / name
        add_refusal(
            name,
            lambda kwargs=kwargs, name=name: oracle.plan_case(name, **kwargs),
            {
                "plan": base_path / "plan.json",
                "template": base_path / "template.json",
                "candidate": base_path / "candidate.json",
            })
    cost_min = oracle.plan_case(
        "cost-min-accepted",
        maximum=handoff.ESTIMATED_COST_UPPER_BOUND_MICROUSD)["plan"]["cost"]["maximum_authorized"]
    cost_max = oracle.plan_case(
        "cost-max-accepted",
        maximum=handoff.REPOSITORY_MAXIMUM_COST_MICROUSD)["plan"]["cost"]["maximum_authorized"]
    uuid_cases = []
    for index, raw in enumerate((
        "00000000000040008000000000000001",
        "{00000000-0000-4000-8000-000000000001}",
        "00000000-0000-4000-8000-000000000001",
        "00000000-0000-4000-8000-00000000000A",
    )):
        plan = oracle.plan_case(
            f"uuid-normalize-{index}", attempt_id=raw)["plan"]
        uuid_cases.append({"input": raw, "normalized": plan["attempt_id"]})
    oracle.uuid_queue = [GENERATED_ATTEMPT, GENERATED_LEDGER]
    generated = oracle.plan_case(
        "uuid-generated", attempt_id=None, ledger_id=None)["plan"]
    return {
        "limits": {
            "approver_min_bytes": 1,
            "approver_max_bytes": approver_max,
            "reference_min_bytes": 1,
            "reference_max_bytes": reference_max,
            "authorization_window_seconds": window_max,
        },
        "cost": {
            "maximum_authorized_minimum": cost_min,
            "maximum_authorized_maximum": cost_max,
        },
        "success_scenarios": successes,
        "refusal_scenarios": refusals,
        "uuid_normalization": uuid_cases,
        "generated_ids": {
            "attempt_id": generated["attempt_id"],
            "ledger_id": generated["ledger"]["ledger_id"],
        },
    }


def authority_contract_golden():
    handoff = load("handoff")
    oracle = AuthorityOracle(handoff)
    oracle.reset()
    try:
        with oracle.patched():
            inputs = oracle.make_inputs()
            runtime = oracle.prepare_runtime(inputs)
            base = oracle.plan_case("base")
            approved = oracle.authorization_case(
                "authorization-approved", base["plan_path"], base["template_path"])
            denied = oracle.authorization_case(
                "authorization-denied", base["plan_path"], base["template_path"],
                decision="denied")
            admission = oracle.admission_case(
                "admission", base["plan_path"], approved["authorization_path"])
            values = {
                "azure_runtime": runtime,
                "plan": oracle.canonical_document(base["plan_path"]),
                "approval_template": oracle.canonical_document(base["template_path"]),
                "authorization_approved": oracle.canonical_document(approved["authorization_path"]),
                "authorization_denied": oracle.canonical_document(denied["authorization_path"]),
                "admission": oracle.canonical_document(admission["admission_path"]),
            }
            schema_values = {
                "azure_runtime": oracle.runtime_schema_record,
                "plan": base["plan"],
                "approval_template": base["template"],
                "authorization_approved": approved["authorization"],
                "authorization_denied": denied["authorization"],
                "admission": admission["admission"],
            }
            probes = derive_live_probes(handoff, oracle, base)
            cost_coefficients = native_cost_coefficients()
            value = {
                "schema": "uk.wamr.authority-contract-golden",
                "schema_version": 1,
                "authority_domain": "azure-execution",
                "canonicalization": handoff.CANONICALIZATION,
                "cli": {
                    "commands": cli_surface(handoff),
                    "exit_contract": exit_contract(
                        handoff, oracle, base["plan_path"], base["template_path"]),
                },
                "limits": {
                    "runtime_files": runtime["limits"]["files"],
                    "runtime_directories": runtime["limits"]["directories"],
                    "runtime_bytes": runtime["limits"]["bytes"],
                    "runtime_depth": runtime["limits"]["depth"],
                    "runtime_file_bytes": runtime["limits"]["file_bytes"],
                    "runtime_loader_files": runtime["limits"]["loader_files"],
                    "runtime_manifest_bytes": handoff.AZURE_RUNTIME_MAX_MANIFEST_BYTES,
                    **probes["limits"],
                },
                "policy": {
                    "purpose": values["plan"]["purpose"],
                    "profile": values["plan"]["profile"],
                    "authority_before_admission": values["plan"]["authority"],
                    "authority_after_admission": values["admission"]["authority"],
                    "location": values["plan"]["location"],
                    "vm_size": values["plan"]["vm_size"],
                    "serial_mode": values["plan"]["serial_mode"],
                    "runtime_seconds": values["plan"]["runtime_seconds"],
                    "cleanup_seconds": values["plan"]["cleanup_seconds"],
                    "operation_seconds": values["plan"]["operation_seconds"],
                    "poll_seconds": values["plan"]["poll_seconds"],
                    "fixed_vhd_bytes": values["plan"]["vhd_bytes"],
                    "fixed_vhd_capacity_bytes": values["plan"]["vhd_capacity_bytes"],
                    "resources": values["plan"]["resources"],
                    "retry_count": values["plan"]["retry_count"],
                    "substitution": values["plan"]["substitution"],
                    "cleanup": values["plan"]["cleanup"],
                    "cost": {
                        "unit": values["plan"]["cost"]["unit"],
                        "policy": values["plan"]["cost"]["policy"],
                        "fixed_overhead_microusd": cost_coefficients["fixed_overhead_microusd"],
                        "vm_hour_microusd": cost_coefficients["vm_hour_microusd"],
                        "os_disk_hour_microusd": cost_coefficients["os_disk_hour_microusd"],
                        "estimated_upper_bound": values["plan"]["cost"]["estimated_upper_bound"],
                        "repository_policy_maximum": values["plan"]["cost"]["repository_policy_maximum"],
                        **probes["cost"],
                    },
                },
                "azure_runtime": {
                    "manifest": manifest_summary(oracle.runtime_manifest_text),
                    "commands": runtime["commands"],
                    "isolation": runtime["isolation"],
                },
                "schemas": schemas(schema_values),
                "canonical_records": {
                    key: canonical_json(handoff, item) for key, item in values.items()
                },
                "uuid_normalization": probes["uuid_normalization"],
                "generated_ids": probes["generated_ids"],
                "live_success_scenarios": probes["success_scenarios"],
                "live_refusal_scenarios": probes["refusal_scenarios"],
            }
            return canonical_file(value)
    finally:
        remove_tree(oracle.root)


def discover_scenarios():
    scenarios = []
    source_counts = {}
    for source in SCENARIO_SOURCES:
        path = ROOT / source
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        count = 0
        for node in tree.body:
            if isinstance(node, ast.ClassDef):
                for child in node.body:
                    if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)) and child.name.startswith("test"):
                        scenarios.append(f"{source}::{node.name}::{child.name}")
                        count += 1
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name.startswith("test"):
                scenarios.append(f"{source}::{node.name}")
                count += 1
        source_counts[source] = count
    scenarios.sort()
    return {
        "schema": "uk.wamr.authority-python-scenario-inventory",
        "schema_version": 1,
        "sources": list(SCENARIO_SOURCES),
        "source_counts": source_counts,
        "count": len(scenarios),
        "scenarios": scenarios,
    }


def scenario_inventory_golden():
    return canonical_file(discover_scenarios())


class AuthorityContractGoldens(unittest.TestCase):
    def test_python_oracle_matches_checked_in_contract_golden(self):
        self.assertEqual(GOLDEN.read_text(encoding="utf-8"), authority_contract_golden())

    def test_python_scenario_inventory_matches_current_tests(self):
        self.assertEqual(SCENARIOS.read_text(encoding="utf-8"), scenario_inventory_golden())

    def test_exit_contract_uses_no_azure_and_no_public_probe_streams(self):
        contract = json.loads(authority_contract_golden())
        exits = contract["cli"]["exit_contract"]
        self.assertEqual(0, exits["success_exit"])
        self.assertTrue(all(value == 0 for value in exits["help_exit"].values()))
        self.assertTrue(all(value == 2 for value in exits["malformed_exit"].values()))
        self.assertEqual(1, exits["refusal_exit"])
        self.assertEqual("", exits["refusal_stdout"])
        self.assertEqual("Compute handoff refused at handoff; original local records are unchanged.\n", exits["refusal_stderr"])
        self.assertFalse(exits["validator_probe_streams_public"])

    def test_live_refusal_scenarios_refuse_without_outputs(self):
        contract = json.loads(authority_contract_golden())
        self.assertTrue(contract["live_refusal_scenarios"])
        for scenario in contract["live_refusal_scenarios"]:
            self.assertTrue(scenario["refused"], scenario["name"])
            self.assertEqual("wamr_native_ci.Refusal", scenario["exception"], scenario["name"])
            self.assertFalse(scenario["output_file_appeared"], scenario["name"])


if __name__ == "__main__":
    if sys.argv[1:] == ["--write"]:
        GOLDEN.write_text(authority_contract_golden(), encoding="utf-8")
        SCENARIOS.write_text(scenario_inventory_golden(), encoding="utf-8")
    else:
        unittest.main()
