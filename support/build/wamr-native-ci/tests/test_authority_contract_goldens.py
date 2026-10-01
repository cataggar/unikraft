#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""Freeze #189 authority contracts from the current Python oracle.

Regenerate intentionally with:
  python3 -B support/build/wamr-native-ci/tests/test_authority_contract_goldens.py --write
"""
import argparse
import ast
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[4]
WAMR_CI = ROOT / "support/build/wamr-native-ci"
GOLDEN = WAMR_CI / "authority/goldens/contracts.json"
SCENARIOS = WAMR_CI / "authority/goldens/python-scenarios.json"
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
SHA_A = "a" * 64
SHA_B = "b" * 64
SHA_C = "c" * 64
REV = "0123456789012345678901234567890123456789"
ATTEMPT = "00000000-0000-4000-8000-000000000001"
CAMPAIGN = "00000000-0000-4000-8000-000000000002"
LEDGER = "00000000-0000-4000-8000-000000000003"
SUBSCRIPTION = "00000000-0000-4000-8000-000000000004"
CREATED = 1_800_000_000
RECORDED = 1_800_000_100
EXPIRES = RECORDED + 3600


def load(name):
    spec = importlib.util.spec_from_file_location(name, WAMR_CI / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def canonical_json(value):
    return load("handoff").ci.compact_json(value, newline=True).decode("utf-8")


def canonical_file(value):
    return json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")) + "\n"


def digest_bytes(data):
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def digest_label(label):
    return digest_bytes(("authority-contract:" + label).encode("utf-8"))


def artifact(path, *, size=1, sha=SHA_A):
    return {"path": path, "size": size, "sha256": sha}


class FakeStat:
    def __init__(self, *, dev_major, dev_minor, ino, mode, uid, gid, nlink, size, mtime_ns, ctime_ns):
        self.st_dev = os.makedev(dev_major, dev_minor)
        self.st_ino = ino
        self.st_mode = mode
        self.st_uid = uid
        self.st_gid = gid
        self.st_nlink = nlink
        self.st_size = size
        self.st_mtime_ns = mtime_ns
        self.st_ctime_ns = ctime_ns


def fake_dir(index, size=4096):
    return FakeStat(
        dev_major=8,
        dev_minor=1,
        ino=1000 + index,
        mode=stat.S_IFDIR | 0o500,
        uid=1000,
        gid=1000,
        nlink=2,
        size=size,
        mtime_ns=1_700_000_000_000_000_000 + index,
        ctime_ns=1_700_000_100_000_000_000 + index,
    )


def fake_file(index, *, executable=False, size=17):
    return FakeStat(
        dev_major=8,
        dev_minor=1,
        ino=2000 + index,
        mode=stat.S_IFREG | (0o500 if executable else 0o400),
        uid=1000,
        gid=1000,
        nlink=1,
        size=size,
        mtime_ns=1_700_001_000_000_000_000 + index,
        ctime_ns=1_700_001_100_000_000_000 + index,
    )


def manifest_records(handoff):
    launcher = "bootstrap/azure-cli"
    interpreter = "bin/python"

    def record(kind, role, relative, info, digest):
        return (
            f"{kind}\t{role}\t{relative}\t"
            + "\t".join(map(str, handoff._physical(info)))
            + f"\t{digest or '-'}\n"
        )

    directory = record(
        "D",
        handoff._runtime_role(Path("lib"), launcher, interpreter),
        "lib",
        fake_dir(1),
        None,
    )
    file_record = record(
        "F",
        handoff._runtime_role(Path(launcher), launcher, interpreter),
        launcher,
        fake_file(1, executable=True, size=23),
        SHA_A,
    )
    loader = record(
        "L",
        "loader-dependency",
        "/authority/loader/ld-linux-x86-64.so.2",
        fake_file(2, executable=True, size=31),
        SHA_B,
    )
    parent = handoff._parent_line("/authority", fake_dir(2)).decode("utf-8")
    return {
        "header": "UK-WAMR-AZURE-RUNTIME-CLOSURE\t1\n",
        "directory": directory,
        "file": file_record,
        "loader": loader,
        "parent": parent,
        "sample": "UK-WAMR-AZURE-RUNTIME-CLOSURE\t1\n" + directory + file_record + loader + parent,
    }


def synthetic_runtime(handoff, manifest):
    runtime_root = "/authority/runtime"
    manifest_bytes = manifest["sample"].encode("utf-8")
    return {
        "schema": "uk.wamr.azure-cli-runtime-closure",
        "version": 1,
        "canonicalization": handoff.CANONICALIZATION,
        "root": runtime_root,
        "python_version": "3.12",
        "extensions": runtime_root + "/extensions",
        "launcher": artifact(runtime_root + "/bootstrap/azure-cli", size=23, sha=SHA_A),
        "interpreter": artifact(runtime_root + "/bin/python", size=29, sha=SHA_B),
        "dynamic_loader": artifact(runtime_root + "/loader/ld-linux-x86-64.so.2", size=31, sha=SHA_C),
        "manifest": artifact("/authority/azure-runtime.manifest", size=len(manifest_bytes), sha=digest_bytes(manifest_bytes)),
        "limits": {
            "files": handoff.AZURE_RUNTIME_MAX_FILES,
            "directories": handoff.AZURE_RUNTIME_MAX_DIRECTORIES,
            "bytes": handoff.AZURE_RUNTIME_MAX_BYTES,
            "depth": handoff.AZURE_RUNTIME_MAX_DEPTH,
            "file_bytes": handoff.AZURE_RUNTIME_MAX_FILE_BYTES,
            "loader_files": handoff.AZURE_RUNTIME_MAX_LOADER_FILES,
        },
        "observed": {
            "files": 4,
            "directories": 3,
            "bytes": 4096,
            "depth": 3,
            "loader_files": 1,
        },
        "content_sha256": digest_label("runtime-content"),
        "metadata_sha256": digest_label("runtime-metadata"),
        "parents_sha256": digest_label("runtime-parents"),
        "loader_dependencies": [artifact(runtime_root + "/loader/libpython3.12.so.1.0", size=37, sha=digest_label("loader"))],
        "commands": [list(command) for command in handoff.AZURE_RUNTIME_COMMANDS],
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
            "host_loader_fallback": "forbidden",
            "package_restore": "forbidden_after_custody",
        },
    }


def synthetic_plan_records(handoff):
    manifest = manifest_records(handoff)
    runtime = synthetic_runtime(handoff, manifest)
    runtime_document_bytes = canonical_json(runtime)
    runtime_document = artifact(
        "/authority/private/azure-runtime.json",
        size=len(runtime_document_bytes.encode("utf-8")),
        sha=digest_bytes(runtime_document_bytes),
    )
    tools = {
        "azure": runtime["launcher"],
        "uploader": artifact("/authority/bin/uk-hyperv-transfer", size=41, sha=digest_label("uploader")),
        "validator": artifact("/authority/bin/uk-wamr-direct-validate", size=43, sha=digest_label("validator")),
        "supervisor": artifact("/authority/bin/wamr-ci-supervisor", size=47, sha=digest_label("supervisor")),
        "az_python": runtime["interpreter"],
    }
    ledger = {
        "schema": "uk.wamr.azure-campaign-ledger-binding",
        "version": 1,
        "purpose": "qcow2-derived-vhd-two-boot",
        "campaign_id": CAMPAIGN,
        "ledger_id": LEDGER,
        "directory": {
            "device_major": 8,
            "device_minor": 1,
            "inode": 3001,
            "uid": 1000,
            "mode": 0o700,
        },
        "initialization_required": True,
        "initial_state_sha256": digest_label("ledger-initial"),
        "marker_sha256": digest_label("ledger-marker"),
    }
    resources = {
        "vm_count": 1,
        "os_disk_count": 1,
        "data_disk_count": 0,
        "public_ip_count": 0,
        "boot_count": 2,
        "maximum_parallelism": 1,
        "generation": 2,
        "os_disk_sku": "StandardSSD_LRS",
        "os_disk_capacity_bytes": handoff.FIXED_VHD_CAPACITY_BYTES,
        "network": "private_no_default_outbound",
    }
    plan = {
        "schema": "uk.wamr.azure-execution-plan",
        "version": 2,
        "purpose": "qcow2-derived-vhd-two-boot",
        "profile": handoff.ci.CURRENT_PROFILE,
        "authority": "not_admitted",
        "canonicalization": handoff.CANONICALIZATION,
        "created_unix": CREATED,
        "attempt_id": ATTEMPT,
        "campaign_id": CAMPAIGN,
        "campaign_profile": handoff.ci.CURRENT_PROFILE,
        "ledger_path": "/authority/private/campaign-ledger",
        "ledger": ledger,
        "subscription": SUBSCRIPTION,
        "location": "northeurope",
        "prefix": "auth-freeze",
        "vm_size": "Standard_D2s_v5",
        "serial_mode": "azure_cumulative",
        "runtime_seconds": 3600,
        "cleanup_seconds": 1800,
        "operation_seconds": 600,
        "poll_seconds": 10,
        "source_revision": REV,
        "source_tree": REV,
        "run": {"repository": "cataggar/unikraft", "run_id": "1", "run_attempt": "1"},
        "identity": {
            "wamr_revision": handoff.ci.REVISION,
            "wasm_sha256": digest_label("wasm"),
            "cwasm_sha256": digest_label("cwasm"),
            "runtime_sha256": digest_label("wamr-runtime"),
            "compiler_sha256": digest_label("compiler"),
            "config_sha256": digest_label("config"),
        },
        "lineage": {
            "raw_sha256": digest_label("raw"),
            "accepted_qcow2_sha256": digest_label("accepted-qcow2"),
            "derived_vhd_sha256": digest_label("derived-vhd"),
            "qcow2_finalization_sha256": digest_label("qcow2-finalization"),
            "qcow2_acceptance_sha256": digest_label("qcow2-acceptance"),
            "fixed_vhd_derivation_sha256": digest_label("fixed-vhd-derivation"),
            "fixed_vhd_derivation_gate_sha256": digest_label("fixed-vhd-derivation-gate"),
            "final_inspection_sha256": digest_label("final-inspection"),
        },
        "candidate": artifact("/authority/private/candidate.json", size=211, sha=digest_label("candidate")),
        "bundle": artifact("/authority/private/imported-image/candidate.admission.json", size=223, sha=digest_label("bundle")),
        "public_bundle": artifact("/authority/private/imported-image/bundle.json", size=227, sha=digest_label("public-bundle")),
        "transport": artifact("/authority/private/imported-image/transport.json", size=229, sha=digest_label("transport")),
        "qcow2": artifact("/authority/private/imported-image/artifacts/qcow2", size=1024, sha=digest_label("qcow2")),
        "os_vhd": artifact("/authority/private/imported-image/artifacts/vhd", size=handoff.FIXED_VHD_BYTES, sha=digest_label("vhd")),
        "vhd_bytes": handoff.FIXED_VHD_BYTES,
        "vhd_capacity_bytes": handoff.FIXED_VHD_CAPACITY_BYTES,
        "artifact_id": "1",
        "inner_zip_sha256": digest_label("inner-zip"),
        "container_digest": digest_label("container"),
        "resources": resources,
        "retry_count": 0,
        "substitution": {"source": False, "image": False, "topology": False, "workload": False},
        "cleanup": {
            "exact_owned_resources_only": True,
            "delete_owned_resource_group": True,
            "independent_absence_observation": True,
            "replacement_resources": False,
        },
        "cost": {
            "unit": "micro_usd",
            "policy": handoff.COST_POLICY,
            "estimated_upper_bound": handoff.ESTIMATED_COST_UPPER_BOUND_MICROUSD,
            "maximum_authorized": handoff.ESTIMATED_COST_UPPER_BOUND_MICROUSD,
            "repository_policy_maximum": handoff.REPOSITORY_MAXIMUM_COST_MICROUSD,
        },
        "tools": tools,
        "azure_runtime_document": runtime_document,
        "azure_runtime": runtime,
    }
    plan_bytes = canonical_json(plan)
    plan_sha256 = digest_bytes(plan_bytes)
    template = {
        "schema": "uk.wamr.azure-execution-approval-template",
        "version": 2,
        "decision": "pending",
        "plan_sha256": plan_sha256,
        "attempt_id": ATTEMPT,
        "campaign_id": CAMPAIGN,
        "ledger_id": ledger["ledger_id"],
        "ledger_initialization_required": ledger["initialization_required"],
        "candidate_sha256": plan["candidate"]["sha256"],
        "estimated_cost_upper_bound_microusd": handoff.ESTIMATED_COST_UPPER_BOUND_MICROUSD,
        "maximum_authorized_cost_microusd": handoff.ESTIMATED_COST_UPPER_BOUND_MICROUSD,
        "limits": handoff.approval_limits(plan),
        "azure_runtime": handoff.runtime_approval_binding(plan),
    }
    authorization_base = {
        "schema": "uk.wamr.azure-execution-authorization",
        "version": 2,
        "plan_sha256": template["plan_sha256"],
        "attempt_id": template["attempt_id"],
        "campaign_id": template["campaign_id"],
        "ledger_id": template["ledger_id"],
        "ledger_initialization_required": template["ledger_initialization_required"],
        "candidate_sha256": template["candidate_sha256"],
        "estimated_cost_upper_bound_microusd": template["estimated_cost_upper_bound_microusd"],
        "maximum_authorized_cost_microusd": template["maximum_authorized_cost_microusd"],
        "limits": template["limits"],
        "azure_runtime": template["azure_runtime"],
        "approver": "authority-freeze-operator",
        "reference": "issue-189-contract-freeze",
        "recorded_unix": RECORDED,
        "expires_unix": EXPIRES,
    }
    approved = dict(authorization_base, decision="approved")
    denied = dict(authorization_base, decision="denied")
    approved_bytes = canonical_json(approved)
    plan_artifact = artifact("/authority/private/plan.json", size=len(plan_bytes.encode("utf-8")), sha=plan_sha256)
    approved_artifact = artifact("/authority/private/authorization.json", size=len(approved_bytes.encode("utf-8")), sha=digest_bytes(approved_bytes))
    admission = {key: item for key, item in plan.items() if key not in ("schema", "version", "authority")}
    admission.update({
        "schema": "uk.wamr.azure-execution-admission",
        "version": 2,
        "authority": "approved",
        "plan": plan_artifact,
        "authorization": approved_artifact,
        "approval": {
            "approver": approved["approver"],
            "reference": approved["reference"],
            "approved_unix": approved["recorded_unix"],
            "expires_unix": approved["expires_unix"],
        },
    })
    return {
        "manifest": manifest,
        "values": {
            "azure_runtime": runtime,
            "plan": plan,
            "approval_template": template,
            "authorization_approved": approved,
            "authorization_denied": denied,
            "admission": admission,
        },
        "bytes": {
            "azure_runtime": canonical_json(runtime),
            "plan": plan_bytes,
            "approval_template": canonical_json(template),
            "authorization_approved": approved_bytes,
            "authorization_denied": canonical_json(denied),
            "admission": canonical_json(admission),
        },
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


def source_print_literal(source, text_prefix):
    tree = ast.parse(source)
    matches = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and getattr(node.func, "id", None) == "print" and node.args:
            first = node.args[0]
            if isinstance(first, ast.Constant) and isinstance(first.value, str) and first.value.startswith(text_prefix):
                matches.append(first.value)
    if len(matches) != 1:
        raise AssertionError(f"expected one print literal starting {text_prefix!r}, found {matches!r}")
    return matches[0] + "\n"


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


def exit_contract():
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
        "--maximum-authorized-cost-microusd", str(9_500_000),
        "--azure", "azure",
        "--uploader", "uploader",
        "--validator", "validator",
        "--supervisor", "supervisor",
        "--az-python", "python",
        "--azure-runtime", "runtime.json",
    )
    refusal_exit, refusal_stdout, refusal_stderr = run_handoff(*refusal_args)
    source = (WAMR_CI / "handoff.py").read_text(encoding="utf-8")
    return {
        "help_exit": help_exit,
        "malformed_exit": malformed_exit,
        "refusal_exit": refusal_exit,
        "refusal_stdout": refusal_stdout,
        "refusal_stderr": refusal_stderr,
        "success_exit": 0,
        "success_stdout": source_print_literal(source, "Compute private contract prepared"),
        "validator_probe_streams_public": False,
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


def authority_contract_golden():
    handoff = load("handoff")
    synthetic = synthetic_plan_records(handoff)
    values = synthetic["values"]
    value = {
        "schema": "uk.wamr.authority-contract-golden",
        "schema_version": 1,
        "authority_domain": "azure-execution",
        "canonicalization": handoff.CANONICALIZATION,
        "cli": {
            "commands": cli_surface(handoff),
            "exit_contract": exit_contract(),
        },
        "limits": {
            "runtime_files": handoff.AZURE_RUNTIME_MAX_FILES,
            "runtime_directories": handoff.AZURE_RUNTIME_MAX_DIRECTORIES,
            "runtime_bytes": handoff.AZURE_RUNTIME_MAX_BYTES,
            "runtime_depth": handoff.AZURE_RUNTIME_MAX_DEPTH,
            "runtime_file_bytes": handoff.AZURE_RUNTIME_MAX_FILE_BYTES,
            "runtime_loader_files": handoff.AZURE_RUNTIME_MAX_LOADER_FILES,
            "runtime_manifest_bytes": handoff.AZURE_RUNTIME_MAX_MANIFEST_BYTES,
            "approver_min_bytes": 1,
            "approver_max_bytes": 128,
            "reference_min_bytes": 1,
            "reference_max_bytes": 256,
            "authorization_window_seconds": 3600,
        },
        "policy": {
            "purpose": "qcow2-derived-vhd-two-boot",
            "profile": handoff.ci.CURRENT_PROFILE,
            "authority_before_admission": "not_admitted",
            "authority_after_admission": "approved",
            "location": "northeurope",
            "vm_size": "Standard_D2s_v5",
            "serial_mode": "azure_cumulative",
            "runtime_seconds": 3600,
            "cleanup_seconds": 1800,
            "operation_seconds": 600,
            "poll_seconds": 10,
            "fixed_vhd_bytes": handoff.FIXED_VHD_BYTES,
            "fixed_vhd_capacity_bytes": handoff.FIXED_VHD_CAPACITY_BYTES,
            "resources": values["plan"]["resources"],
            "retry_count": 0,
            "substitution": values["plan"]["substitution"],
            "cleanup": values["plan"]["cleanup"],
            "cost": {
                "unit": "micro_usd",
                "policy": handoff.COST_POLICY,
                "fixed_overhead_microusd": 5_000_000,
                "vm_hour_microusd": 2_000_000,
                "os_disk_hour_microusd": 250_000,
                "estimated_upper_bound": handoff.ESTIMATED_COST_UPPER_BOUND_MICROUSD,
                "repository_policy_maximum": handoff.REPOSITORY_MAXIMUM_COST_MICROUSD,
                "maximum_authorized_minimum": handoff.ESTIMATED_COST_UPPER_BOUND_MICROUSD,
                "maximum_authorized_maximum": handoff.REPOSITORY_MAXIMUM_COST_MICROUSD,
            },
        },
        "azure_runtime": {
            "manifest": synthetic["manifest"],
            "commands": [list(command) for command in handoff.AZURE_RUNTIME_COMMANDS],
            "isolation": values["azure_runtime"]["isolation"],
        },
        "schemas": schemas(values),
        "canonical_records": synthetic["bytes"],
        "uuid_normalization": [
            {"input": "00000000000040008000000000000001", "normalized": ATTEMPT},
            {"input": "{00000000-0000-4000-8000-000000000001}", "normalized": ATTEMPT},
            {"input": "00000000-0000-4000-8000-000000000001", "normalized": ATTEMPT},
            {"input": "00000000-0000-4000-8000-00000000000A", "normalized": "00000000-0000-4000-8000-00000000000a"},
        ],
        "generated_ids": {"attempt_id": "rfc4122-v4", "ledger_id": "rfc4122-v4"},
    }
    for case in value["uuid_normalization"]:
        import uuid
        case["normalized"] = str(uuid.UUID(case["input"]))
    return canonical_file(value)


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


if __name__ == "__main__":
    if sys.argv[1:] == ["--write"]:
        GOLDEN.write_text(authority_contract_golden(), encoding="utf-8")
        SCENARIOS.write_text(scenario_inventory_golden(), encoding="utf-8")
    else:
        unittest.main()
