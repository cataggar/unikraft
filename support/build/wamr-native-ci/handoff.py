#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""Private exact-image handoff and non-authorizing plan; never invokes Azure."""
import argparse
import importlib.util
import os
from pathlib import Path
import shutil
import stat
import sys
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


def plan(bundle_path, output):
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
        "attempt_id": str(uuid.uuid4()), "subscription": "FINAL-APPROVED-SUBSCRIPTION-UUID",
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
            subscription="00000000-0000-0000-0000-000000000001",
            prefix="not-admitted-candidate",
        )
    ci.require([boot["mode"] for boot in bundle["boots"]] == list(modes),
               "wrong compute handoff modes")
    value["approval"].update(approved_unix=0, expires_unix=0)
    ci.save(output, value)
    return value


def main():
    global FAILURE_STAGE
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    exp = sub.add_parser("export")
    exp.add_argument("--runtime", type=Path, required=True)
    exp.add_argument("--output", type=Path, required=True)
    pln = sub.add_parser("plan")
    pln.add_argument("--bundle", type=Path, required=True)
    pln.add_argument("--output", type=Path, required=True)
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
    elif args.command == "plan":
        plan(args.bundle, args.output)
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
    print("Compute handoff/plan prepared; authority=not_admitted. No Azure operations.")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError, zipfile.BadZipFile):
        print("Compute handoff refused at " + FAILURE_STAGE
              + "; original local records are unchanged.", file=sys.stderr)
        sys.exit(1)
