#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""Private exact-image handoff, finite-cost authorization records; no Azure."""
import argparse
import importlib.util
import os
from pathlib import Path
import shutil
import stat
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


def private(path):
    ci.require(path.is_absolute() and path.resolve(strict=True) == path,
               "absolute nonsymlink private path required")
    info = path.lstat()
    ci.require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid()
               and stat.S_IMODE(info.st_mode) == 0o700, "private directory required")


def artifact(path):
    return {"path": str(path), "size": path.stat().st_size, "sha256": ci.digest(path)}


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
    ci.require(path.is_absolute() and path.resolve(strict=True) == path,
               "explicit nonsymlink executable required")
    info = path.stat()
    ci.require(stat.S_ISREG(info.st_mode)
               and info.st_mode & 0o111 and not info.st_mode & 0o022
               and 0 < info.st_size <= 64 * 1024 * 1024,
               "unsafe explicit executable")
    return artifact(path)


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


def exact_tool_bindings(azure, uploader, validator, supervisor, az_python):
    return {
        name: executable_artifact(Path(path))
        for name, path in (
            ("azure", azure),
            ("uploader", uploader),
            ("validator", validator),
            ("supervisor", supervisor),
            ("az_python", az_python),
        )
    }


def require_tool_bindings(plan_value, azure, uploader, validator, supervisor,
                          az_python):
    actual = exact_tool_bindings(
        azure, uploader, validator, supervisor, az_python)
    ci.require(actual == plan_value["tools"], "approved tool binding changed")
    return actual


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
         supervisor, az_python, attempt_id=None, created_unix=None):
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
    tools = exact_tool_bindings(
        azure, uploader, validator, supervisor, az_python)
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
        "version": 1,
        "purpose": "qcow2-derived-vhd-two-boot",
        "profile": ci.CURRENT_PROFILE,
        "authority": "not_admitted",
        "canonicalization": CANONICALIZATION,
        "created_unix": created_unix,
        "attempt_id": attempt_id,
        "campaign_id": campaign_id,
        "campaign_profile": ci.CURRENT_PROFILE,
        "ledger_path": str(ledger),
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
    }
    ci.require(value["vhd_bytes"] == FIXED_VHD_BYTES,
               "wrong fixed VHD byte length")
    ci.save(output, value)
    plan_sha256 = ci.digest(output, 64 * 1024)
    template = {
        "schema": "uk.wamr.azure-execution-approval-template",
        "version": 1,
        "decision": "pending",
        "plan_sha256": plan_sha256,
        "attempt_id": attempt_id,
        "candidate_sha256": value["candidate"]["sha256"],
        "estimated_cost_upper_bound_microusd":
            ESTIMATED_COST_UPPER_BOUND_MICROUSD,
        "maximum_authorized_cost_microusd":
            maximum_authorized_cost_microusd,
        "limits": approval_limits(value),
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
                         azure, uploader, validator, supervisor, az_python):
    private(plan_path.parent)
    private(template_path.parent)
    private(output.parent)
    plan_value = canonical_document(plan_path)
    template = canonical_document(template_path)
    require_tool_bindings(
        plan_value, azure, uploader, validator, supervisor, az_python)
    native_validate(validator, "plan", plan_path, template_path)
    ci.require(template["plan_sha256"] == ci.digest(plan_path, 64 * 1024)
               and template["attempt_id"] == plan_value["attempt_id"]
               and template["candidate_sha256"]
               == plan_value["candidate"]["sha256"]
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
        "version": 1,
        "decision": decision,
        "plan_sha256": template["plan_sha256"],
        "attempt_id": template["attempt_id"],
        "candidate_sha256": template["candidate_sha256"],
        "estimated_cost_upper_bound_microusd":
            template["estimated_cost_upper_bound_microusd"],
        "maximum_authorized_cost_microusd":
            template["maximum_authorized_cost_microusd"],
        "limits": template["limits"],
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
              validator, supervisor, az_python):
    private(plan_path.parent)
    private(authorization_path.parent)
    private(output.parent)
    plan_value = canonical_document(plan_path)
    authorization = canonical_document(authorization_path)
    require_tool_bindings(
        plan_value, azure, uploader, validator, supervisor, az_python)
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
        "version": 1,
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
    pln.add_argument("--ledger", type=Path, required=True)
    pln.add_argument("--subscription", required=True)
    pln.add_argument("--prefix", required=True)
    pln.add_argument("--maximum-authorized-cost-microusd",
                     type=int, required=True)
    pln.add_argument("--attempt-id")
    pln.add_argument("--created-unix", type=int)
    for tool_name in ("azure", "uploader", "validator",
                      "supervisor", "az-python"):
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
                      "supervisor", "az-python"):
        authorize.add_argument("--" + tool_name, type=Path, required=True)
    admit = sub.add_parser("admit")
    admit.add_argument("--plan", type=Path, required=True)
    admit.add_argument("--authorization", type=Path, required=True)
    admit.add_argument("--output", type=Path, required=True)
    for tool_name in ("azure", "uploader", "validator",
                      "supervisor", "az-python"):
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
            az_python=args.az_python, attempt_id=args.attempt_id,
            created_unix=args.created_unix)
    elif args.command == "record-authorization":
        record_authorization(
            args.plan, args.template, args.output,
            decision=args.decision, approver=args.approver,
            reference=args.reference, recorded_unix=args.recorded_unix,
            expires_unix=args.expires_unix, azure=args.azure,
            uploader=args.uploader, validator=args.validator,
            supervisor=args.supervisor, az_python=args.az_python)
    elif args.command == "admit":
        admission(
            args.plan, args.authorization, args.output,
            azure=args.azure, uploader=args.uploader,
            validator=args.validator, supervisor=args.supervisor,
            az_python=args.az_python)
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
