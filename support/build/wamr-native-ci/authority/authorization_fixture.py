# SPDX-License-Identifier: BSD-3-Clause
"""Synthetic source-test inputs; no real decisions, owners, boots or cloud."""
import importlib.util
import json
import os
from pathlib import Path
import shutil
import sys


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def build(root, package, native_tool):
    repo = Path(__file__).resolve().parents[4]
    fixture = load(
        "authorization_v2_fixture",
        repo / "support/tools/hyperv/direct/tests/v2_fixture.py")
    handoff = load(
        "authorization_handoff",
        repo / "support/build/wamr-native-ci/handoff.py")
    fixture.build(root, package)
    golden = json.loads(Path(__file__).with_name(
        "goldens").joinpath("contracts.json").read_bytes())
    plan = json.loads(golden["canonical_records"]["plan"])
    runtime = json.loads(golden["canonical_records"]["azure_runtime"])
    output = root / "azure-runtime"
    closure = output / "runtime"
    for path in (output, closure, closure / "bootstrap", closure / "bin",
                 closure / "loader", closure / "extensions"):
        path.mkdir(mode=0o700)
    launcher = closure / "bootstrap/azure-cli"
    interpreter = closure / "bin/python"
    loader = closure / "loader/synthetic-loader"
    # These are explicitly synthetic tool bindings, not claims that a fixture
    # is a real Python interpreter, Azure launcher, validator or supervisor.
    for path in (launcher, interpreter, loader):
        shutil.copyfile(native_tool, path)
        path.chmod(0o500)
    for path in (closure / "bootstrap", closure / "bin", closure / "loader",
                 closure / "extensions", closure):
        path.chmod(0o500)
    scan = handoff._scan_azure_runtime(
        closure, launcher, interpreter, (loader,))
    manifest = output / "azure-runtime.manifest"
    fixture.write(manifest, b"".join(scan["records"]))
    info = manifest.stat()
    digest = fixture.digest(manifest)
    scan["content"].update(
        f"C\tA\t{manifest}\t{info.st_size}\t{digest}\n".encode())
    scan["metadata"].update(
        handoff._metadata_line("A", str(manifest), info))
    runtime.update(
        root=str(closure), extensions=str(closure / "extensions"),
        launcher=fixture.artifact(launcher),
        interpreter=fixture.artifact(interpreter),
        dynamic_loader=fixture.artifact(loader),
        manifest=fixture.artifact(manifest),
        observed=scan["observed"],
        loader_dependencies=scan["loader_dependencies"],
        content_sha256=scan["content"].hexdigest(),
        metadata_sha256=scan["metadata"].hexdigest(),
        parents_sha256=scan["parents_sha256"],
    )
    runtime_path = output / "azure-runtime.json"
    fixture.write(runtime_path, runtime)
    bundle = fixture.read(root / "bundle.json")
    imported_path = root / "imported.json"
    transport_path = root / "transport.json"
    fixture.write(transport_path, dict(
        schema="uk.wamr.public-source-transport", version=2,
        repository=bundle["run"]["repository"],
        run_id=bundle["run"]["run_id"],
        run_attempt=bundle["run"]["run_attempt"],
        source_revision=bundle["source_revision"],
        source_tree=bundle["source_tree"],
        artifact_id="12345", inner_zip_sha256="1" * 64,
        container_digest="2" * 64,
    ))
    fixture.write(imported_path, dict(
        schema="uk.wamr.direct-compute-admission", version=2,
        profile="qcow2-derived-vhd", authority="not_admitted",
        source_revision=bundle["source_revision"],
        source_tree=bundle["source_tree"], run=bundle["run"],
        lineage=bundle["lineage"],
        public_bundle=fixture.artifact(root / "bundle.json"),
        transport=fixture.artifact(transport_path),
    ))
    by_name = dict(zip(fixture.ROLES, bundle["artifacts"]))
    (root / "ledger").mkdir(mode=0o700)
    plan.update(
        source_revision=bundle["source_revision"],
        source_tree=bundle["source_tree"],
        run=bundle["run"], identity=bundle["identity"],
        lineage=bundle["lineage"],
        bundle=fixture.artifact(imported_path),
        public_bundle=fixture.artifact(root / "bundle.json"),
        transport=fixture.artifact(transport_path),
        qcow2=by_name["qcow2"], os_vhd=by_name["vhd"],
        ledger_path=str(root / "ledger"),
        artifact_id="12345", inner_zip_sha256="1" * 64,
        container_digest="2" * 64,
        azure_runtime=runtime,
        azure_runtime_document=fixture.artifact(runtime_path),
        tools=dict(
            azure=fixture.artifact(launcher),
            az_python=fixture.artifact(interpreter),
            uploader=fixture.artifact(native_tool),
            validator=fixture.artifact(native_tool),
            supervisor=fixture.artifact(native_tool),
        ),
    )
    candidate = {name: plan[name] for name in (
        "attempt_id", "subscription", "location", "prefix", "vm_size",
        "serial_mode", "runtime_seconds", "cleanup_seconds",
        "operation_seconds", "poll_seconds", "source_revision",
        "source_tree", "identity", "os_vhd", "bundle")}
    candidate.update(
        schema="uk.wamr.direct-compute", version=2,
        purpose="qcow2-derived-vhd", authority="not_admitted",
        approval=dict(
            direct_specialized_gen2=False, os_only_private=False,
            two_boots_only=False, cleanup_owned_group=False,
            exact_image_and_local_bundle_reviewed=False,
            fresh_final_approval=False, approved_unix=0, expires_unix=0),
    )
    candidate_path = root / "candidate.json"
    fixture.write(candidate_path, candidate)
    plan["candidate"] = fixture.artifact(candidate_path)
    fixture.write(root / "plan-seed.json", plan)


if __name__ == "__main__":
    if sys.argv[1] == "--cleanup":
        root = Path(sys.argv[2])
        for current, directories, _ in os.walk(root):
            Path(current).chmod(0o700)
            for name in directories:
                (Path(current) / name).chmod(0o700)
        shutil.rmtree(root)
    else:
        build(Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3]))
