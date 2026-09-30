#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""Freeze #187 handoff/public-bundle contracts from the Python oracle.

Regenerate intentionally with:
  python3 -B support/build/wamr-native-ci/tests/test_handoff_contract_goldens.py --write
"""
import importlib.util, json, os, sys, tempfile, unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
WAMR_CI = ROOT / "support/build/wamr-native-ci"
FIXTURES = WAMR_CI / "tests/fixtures/differential"
GOLDEN = WAMR_CI / "handoff/goldens/contracts-profile-layout.json"
SHA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
REV = "0123456789012345678901234567890123456789"
UUID = "00000000-0000-4000-8000-000000000001"


def load(name):
    spec = importlib.util.spec_from_file_location(name, WAMR_CI / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def artifact(path, size=1):
    return {"path": path, "size": size, "sha256": SHA}


def portable_bundle(handoff, public_bundle, version, *, sizes=None, paths=None, validate=True):
    sizes, paths = sizes or {}, paths or {}
    names = list(handoff.NAMES if version == 1 else handoff.V2_NAMES)
    modes = list(handoff.ci.MODES if version == 1 else handoff.ci.SIX_MODES)
    evidence = sorted(public_bundle.EVIDENCE if version == 1 else public_bundle.V2_EVIDENCE)

    def member(path):
        return artifact(paths.get(path, path), sizes.get(path, 1))

    artifacts = [member(f"artifacts/{name}") for name in names]
    boots = [
        {"mode": mode, **{key: member(f"boots/{mode}/{key}") for key in public_bundle.BOOT_KEYS}}
        for mode in modes
    ]
    bundle = {
        "schema": "uk.wamr.local-image-handoff",
        "version": 1,
        "authority": "not_admitted",
        "source_revision": REV,
        "source_tree": REV,
        "identity": {
            "wamr_revision": handoff.ci.REVISION,
            "wasm_sha256": SHA,
            "cwasm_sha256": SHA,
            "runtime_sha256": SHA,
            "compiler_sha256": SHA,
            "config_sha256": SHA,
        },
        "artifacts": artifacts,
        "boots": boots,
        "evidence": [member(f"evidence/{name}") for name in evidence],
    }
    if version == 2:
        by_name = dict(zip(names, artifacts))
        bundle.update(
            version=2,
            profile=handoff.ci.CURRENT_PROFILE,
            run={"repository": "cataggar/unikraft", "run_id": "1", "run_attempt": "1"},
            lineage={
                "raw_sha256": by_name["raw"]["sha256"],
                "accepted_qcow2_sha256": by_name["qcow2"]["sha256"],
                "derived_vhd_sha256": by_name["vhd"]["sha256"],
                "qcow2_finalization_sha256": by_name["qcow2_finalization"]["sha256"],
                "qcow2_acceptance_sha256": by_name["qcow2_acceptance"]["sha256"],
                "fixed_vhd_derivation_sha256": by_name["fixed_vhd_derivation"]["sha256"],
                "fixed_vhd_derivation_gate_sha256": by_name["fixed_vhd_derivation_gate"]["sha256"],
                "final_inspection_sha256": by_name["final_inspection"]["sha256"],
            },
        )
    if validate:
        public_bundle.members(handoff, bundle)
    return bundle


def manifest_for(handoff, public_bundle, bundle):
    selected = public_bundle.members(handoff, bundle)
    source = {
        "repository": "cataggar/unikraft",
        "run_id": "1",
        "run_attempt": "1",
        "source_revision": REV,
        "source_tree": REV,
        "wamr_revision": handoff.ci.REVISION,
    }
    manifest = {
        "schema": "uk.wamr.public-source-bundle",
        "version": bundle["version"],
        "authority": "not_admitted",
        "source": source,
        "members": {name: {key: item[key] for key in ("size", "sha256")}
                    for name, item in selected.items()},
    }
    if bundle["version"] == 2:
        manifest["profile"] = handoff.ci.CURRENT_PROFILE
    public_bundle.decode(public_bundle.encoded(manifest))
    return manifest


def max_accepted_member_size(handoff, public_bundle, member, upper):
    lo, hi = 1, upper
    while lo < hi:
        mid = (lo + hi + 1) // 2
        try:
            portable_bundle(handoff, public_bundle, 2, sizes={member: mid})
            lo = mid
        except ValueError:
            hi = mid - 1
    return lo


def candidate_records(handoff, public_bundle):
    with tempfile.TemporaryDirectory(prefix="handoff-contract-") as raw:
        root = Path(raw).resolve()
        os.chmod(root, 0o700)
        stage = root / "stage"
        stage.mkdir(mode=0o700)
        bundle = portable_bundle(handoff, public_bundle, 2)

        def materialize(item):
            path = stage / item["path"]
            path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            path.write_bytes(b"x")
            path.chmod(0o600)
            return handoff.artifact(path)

        bundle["artifacts"] = [materialize(item) for item in bundle["artifacts"]]
        bundle["evidence"] = [materialize(item) for item in bundle["evidence"]]
        bundle["boots"] = [
            {"mode": boot["mode"], **{key: materialize(boot[key]) for key in public_bundle.BOOT_KEYS}}
            for boot in bundle["boots"]
        ]
        by_name = dict(zip(handoff.V2_NAMES, bundle["artifacts"]))
        bundle["lineage"] = {
            "raw_sha256": by_name["raw"]["sha256"],
            "accepted_qcow2_sha256": by_name["qcow2"]["sha256"],
            "derived_vhd_sha256": by_name["vhd"]["sha256"],
            "qcow2_finalization_sha256": by_name["qcow2_finalization"]["sha256"],
            "qcow2_acceptance_sha256": by_name["qcow2_acceptance"]["sha256"],
            "fixed_vhd_derivation_sha256": by_name["fixed_vhd_derivation"]["sha256"],
            "fixed_vhd_derivation_gate_sha256": by_name["fixed_vhd_derivation_gate"]["sha256"],
            "final_inspection_sha256": by_name["final_inspection"]["sha256"],
        }
        transport = {
            "schema": "uk.wamr.public-source-transport",
            "version": 2,
            "repository": "cataggar/unikraft",
            "run_id": "1",
            "run_attempt": "1",
            "source_revision": REV,
            "source_tree": REV,
            "inner_zip_sha256": SHA,
            "artifact_id": "1",
            "container_digest": SHA,
        }
        handoff.ci.save(stage / "transport.json", transport)
        handoff.ci.save(stage / "bundle.json", bundle)
        candidate = handoff.candidate_plan(
            stage / "bundle.json", stage / "candidate.json",
            attempt_id=UUID, subscription=UUID, prefix="not-admitted-candidate")
        admission = handoff.ci.document(stage / "candidate.json.admission.json")
        return candidate, admission, transport


def contract_golden():
    handoff, public_bundle = load("handoff"), load("public_bundle")
    bundles = {version: portable_bundle(handoff, public_bundle, version) for version in (1, 2)}
    manifests = {version: manifest_for(handoff, public_bundle, bundles[version]) for version in (1, 2)}
    candidate, admission, transport = candidate_records(handoff, public_bundle)
    serial_max = max_accepted_member_size(handoff, public_bundle, "boots/raw-x2apic/serial", 5 * 1024 * 1024)
    large_max = max_accepted_member_size(handoff, public_bundle, "artifacts/raw", 300 * 1024 * 1024)

    profiles = []
    for version in (1, 2):
        result = public_bundle.decode((FIXTURES / f"accepted-v{version}.json").read_bytes())
        selected = public_bundle.members(handoff, bundles[version])
        profiles.append({
            "version": result["schema_version"],
            "compatibility": "tiny-v2" if version == 2 else "tiny-v1",
            "profile": result.get("profile"),
            "production": result.get("profile") == handoff.ci.CURRENT_PROFILE,
            "workload": result["workload"],
            "modes": result["modes"],
            "artifact_count": len(bundles[version]["artifacts"]),
            "evidence_count": len(bundles[version]["evidence"]),
            "boot_member_count": sum(len(public_bundle.BOOT_KEYS) for _ in bundles[version]["boots"]),
            "zip_member_count": len(selected) + 2,
        })

    schemas = {
        "artifact": list(candidate["os_vhd"].keys()),
        "manifest_member": list(next(iter(manifests[1]["members"].values())).keys()),
        "boot": list(bundles[1]["boots"][0].keys()),
        "identity": list(bundles[1]["identity"].keys()),
        "local_image_handoff_v1": list(bundles[1].keys()),
        "local_image_handoff_v2": list(bundles[2].keys()),
        "public_source_manifest_v1": list(manifests[1].keys()),
        "public_source_manifest_v2": list(manifests[2].keys()),
        "public_source_transport_v2": list(transport.keys()),
        "direct_compute_candidate": list(candidate.keys()),
        "direct_compute_admission_v2": list(admission.keys()),
        "run": list(bundles[2]["run"].keys()),
        "lineage": list(bundles[2]["lineage"].keys()),
        "public_context": list(manifests[2]["source"].keys()),
        "approval": list(candidate["approval"].keys()),
    }
    value = {
        "schema": "uk.wamr.handoff-contract-golden",
        "schema_version": 1,
        "authority": "not_admitted",
        "canonicalization": "utf8-byte-sorted-keys-compact-lf-v1",
        "limits": {
            "max_members": public_bundle.MAX_MEMBERS,
            "max_total_bytes": public_bundle.MAX_TOTAL,
            "json_bytes": public_bundle.MAX_JSON,
            "serial_bytes": serial_max,
            "large_artifact_bytes": large_max,
            "v1_zip_members": public_bundle.V1_ZIP_MEMBERS,
            "v2_zip_members": public_bundle.V2_ZIP_MEMBERS,
        },
        "profiles": profiles,
        "historical_sources": {
            "legacy_v1_without_external_archive_digest": [{"revision": r, "tree": t} for r, t in sorted(public_bundle.LEGACY_V1_SOURCES)],
            "pre_supervisor_with_external_archive_digest": [{"revision": r, "tree": t} for r, t in sorted(public_bundle.PRE_SUPERVISOR_SOURCES)],
        },
        "tables": {
            "artifact_names_v1": list(handoff.NAMES),
            "artifact_names_v2": list(handoff.V2_NAMES),
            "boot_keys": list(public_bundle.BOOT_KEYS),
            "evidence_v1": sorted(public_bundle.EVIDENCE),
            "evidence_v2": sorted(public_bundle.V2_EVIDENCE),
            "zip_members_v1": sorted(public_bundle.members(handoff, bundles[1])) + ["bundle.json", "public-source.json"],
            "zip_members_v2": sorted(public_bundle.members(handoff, bundles[2])) + ["bundle.json", "public-source.json"],
        },
        "schemas": schemas,
    }
    return json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")) + "\n"


class HandoffContractGoldens(unittest.TestCase):
    def test_python_oracle_matches_checked_in_golden(self):
        self.assertEqual(GOLDEN.read_text(encoding="utf-8"), contract_golden())

    def test_python_members_match_zig_sample_verdicts(self):
        handoff, public_bundle = load("handoff"), load("public_bundle")
        large = max_accepted_member_size(handoff, public_bundle, "artifacts/raw", 300 * 1024 * 1024)
        cases = {
            "accepted-v1": (portable_bundle(handoff, public_bundle, 1), True),
            "accepted-v2": (portable_bundle(handoff, public_bundle, 2), True),
            "bare-path": (portable_bundle(handoff, public_bundle, 1, paths={"artifacts/efi": "efi"}, validate=False), False),
            "swapped-evidence": (portable_bundle(handoff, public_bundle, 2, paths={"evidence/boot-inputs.json": "evidence/build-start.json"}, validate=False), False),
            "oversized-total": (portable_bundle(handoff, public_bundle, 2, sizes={"artifacts/raw": large, "artifacts/qcow2": large}, validate=False), False),
        }
        for name, (bundle, expected) in cases.items():
            with self.subTest(name=name):
                try:
                    public_bundle.members(handoff, bundle)
                    accepted = True
                except ValueError:
                    accepted = False
                self.assertEqual(expected, accepted)


if __name__ == "__main__":
    if sys.argv[1:] == ["--write"]:
        GOLDEN.write_text(contract_golden(), encoding="utf-8")
    else:
        unittest.main()
