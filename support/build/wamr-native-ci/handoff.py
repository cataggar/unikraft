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
    ci.require(result["schema_version"] == 1 and result["passed"] is True
               and result["scope"] == "local_native_compute_only"
               and result["hardware_acceptance"] == "not_established"
               and result["cloud_authority"] == "not_admitted"
               and result["benchmark"] == "not_measured"
               and result["workload"] == "tiny"
               and result["modes"] == list(ci.MODES), "wrong local result")
    records = result["records"]
    ci.require(8 <= len(records) <= 64 and "result.json" not in records,
               "invalid earlier record set")
    for name, expected in records.items():
        ci.require(Path(name).name == name and name.endswith(".json")
                   and name not in (".json", "..json"), "invalid record name")
        ci.require(ci.digest(root / "evidence" / name) == expected, "local record changed")
    required = {"build.json", "build-start.json", "boot-inputs.json", "package.json"}
    required.update(mode + "-compute.json" for mode in ci.MODES)
    ci.require(required <= records.keys(), "incomplete local records")
    return records


def export(runtime, output):
    private(runtime)
    private(output.parent)
    root = runtime / "compute"
    records = result_records(root)
    before = ci.producer_inputs(runtime)
    ci.require(before == ci.document(root / "evidence/build-start.json"),
               "producer inputs changed")
    build = ci.check_build()
    ci.require(build == ci.document(root / "evidence/build.json"), "build changed")
    inputs = ci.document(root / "evidence/boot-inputs.json")
    tools = {"package_tool": root / "tools/bin/wamr-ci-package",
             "local_boot_tool": root / "tools/bin/uk-hyperv-local-boot",
             "qemu": runtime / "bin/qemu-system-x86_64",
             "ovmf_code": runtime / "firmware/code.fd",
             "ovmf_vars": runtime / "firmware/vars.fd"}
    ci.require(inputs == {key: ci.digest(path) for key, path in tools.items()},
               "boot tools changed")
    for i, mode in enumerate(ci.MODES):
        checked = ci.check_boot(ci.config_for(runtime, root, i), build["runtime"])
        ci.require(checked == ci.document(root / "evidence" / (mode + "-compute.json")),
                   "physical local result changed")
    ci.require_build_custody(runtime, before)
    output.mkdir(mode=0o700)
    for name in ("private", "evidence", "artifacts", "boots"):
        (output / name).mkdir(mode=0o700)
    inspected = ci.document(ci.run(
        output, "handoff-inspect",
        [tools["package_tool"], "inspect", ci.APP / "build" / ci.EFI, root / "package"],
        150, 64 * 1024))
    packaged = ci.document(root / "evidence/package.json")
    ci.require(inspected["producer_sha256"] == packaged["producer_sha256"]
               and all(inspected["image"][key] == value
                       for key, value in packaged["image"].items()),
               "physical package changed")
    paths = (
        ci.APP / "build" / ci.EFI, ci.APP / "build" / (ci.EFI + ".dbg"),
        ci.APP / "build" / (ci.EFI + ".bootinfo"), root / "package/unikraft.raw",
        root / "package/unikraft.vhd", ci.APP / "build/artifacts/libwamr-aot.a",
        ci.APP / "build/artifacts/wamrc", ci.APP / "build/artifacts/tiny.wasm",
        ci.APP / "build/artifacts/tiny.cwasm", ci.APP / ".config",
        ci.APP / "build/artifacts/identity.json", ci.APP / "build/image-identity.json",
        root / "evidence/result.json", root / "evidence/package.json",
        root / "evidence/build.json", root / "evidence/build-start.json",
        root / "evidence/boot-inputs.json")

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

    artifacts = [retain(path, output / "artifacts" / name) for name, path in zip(NAMES, paths)]
    boots = []
    for mode in ci.MODES:
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
               and ci.producer_inputs(runtime) == before
               and inputs == {key: ci.digest(path) for key, path in tools.items()},
               "inputs changed during handoff")
    by_name = dict(zip(NAMES, artifacts))
    bundle = {
        "schema": "uk.wamr.local-image-handoff", "version": 1,
        "authority": "not_admitted",
        "source_revision": build["source"]["revision"], "source_tree": build["source"]["tree"],
        "identity": dict(wamr_revision=ci.REVISION, **{
            name + "_sha256": by_name[name]["sha256"]
            for name in ("wasm", "cwasm", "runtime", "compiler", "config")}),
        "artifacts": artifacts, "boots": boots, "evidence": evidence,
    }
    ci.save(output / "bundle.json", bundle)
    return bundle


def plan(bundle_path, output):
    private(bundle_path.parent)
    private(output.parent)
    bundle = ci.document(bundle_path)
    ci.require(bundle["schema"] == "uk.wamr.local-image-handoff"
               and bundle["version"] == 1 and bundle["authority"] == "not_admitted"
               and bundle["identity"]["wamr_revision"] == ci.REVISION,
               "not a compute handoff")
    for item in bundle["artifacts"] + bundle["evidence"] + [
            boot[key] for boot in bundle["boots"] for key in ("serial", "request", "report", "compute")]:
        ci.require(artifact(Path(item["path"])) == item, "handoff bytes changed")
    value = {
        "schema": "uk.wamr.direct-compute", "version": 1, "purpose": "tiny-aot-two-boot",
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
        "identity": bundle["identity"], "os_vhd": bundle["artifacts"][NAMES.index("vhd")],
        "bundle": artifact(bundle_path),
    }
    value["approval"].update(approved_unix=0, expires_unix=0)
    ci.save(output, value)
    return value


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    exp = sub.add_parser("export")
    exp.add_argument("--runtime", type=Path, required=True)
    exp.add_argument("--output", type=Path, required=True)
    pln = sub.add_parser("plan")
    pln.add_argument("--bundle", type=Path, required=True)
    pln.add_argument("--output", type=Path, required=True)
    sub.add_parser("public-source-bundle", help="Explicit fixed public-repository tiny CI publication only")
    imp = sub.add_parser("import-public-source-bundle")
    imp.add_argument("--archive", type=Path, required=True)
    imp.add_argument("--output", type=Path, required=True)
    imp.add_argument("--expected-source", required=True)
    imp.add_argument("--expected-tree", required=True)
    imp.add_argument("--expected-archive-sha256")
    imp.add_argument("--run-id", required=True)
    imp.add_argument("--run-attempt", required=True)
    imp.add_argument("--validator", type=Path, required=True)
    args = parser.parse_args()
    os.umask(0o077)
    if args.command == "export":
        export(args.runtime, args.output)
    elif args.command == "plan":
        plan(args.bundle, args.output)
    else:
        import public_bundle
        if args.command == "public-source-bundle":
            public_bundle.publish_ci(sys.modules[__name__])
        else:
            expected = dict(repository="cataggar/unikraft", run_id=args.run_id,
                            run_attempt=args.run_attempt, source_revision=args.expected_source,
                            source_tree=args.expected_tree, wamr_revision=ci.REVISION)
            public_bundle.import_bundle(
                sys.modules[__name__], args.archive, args.output, expected,
                args.expected_archive_sha256, args.validator)
    print("Compute handoff/plan prepared; authority=not_admitted. No Azure operations.")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError, zipfile.BadZipFile):
        print("Compute handoff refused; original local records are unchanged.", file=sys.stderr)
        sys.exit(1)
