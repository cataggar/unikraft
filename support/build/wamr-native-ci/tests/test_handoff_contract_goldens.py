#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""Freeze #187 handoff/public-bundle contracts from the Python oracle.

Regenerate intentionally with:
  python3 -B support/build/wamr-native-ci/tests/test_handoff_contract_goldens.py --write
"""
import contextlib, copy, hashlib, importlib.util, io, json, os, shutil, stat, sys, tempfile, unittest, zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
WAMR_CI = ROOT / "support/build/wamr-native-ci"
FIXTURES = WAMR_CI / "tests/fixtures/differential"
GOLDEN = WAMR_CI / "handoff/goldens/contracts-profile-layout.json"
ZIP_MULTI = WAMR_CI / "handoff/goldens/zip-stored-multi.zip"
ZIP_EMPTY = WAMR_CI / "handoff/goldens/zip-stored-empty.zip"
PACK_V1 = WAMR_CI / "handoff/goldens/zip-pack-v1.zip"
PACK_V2 = WAMR_CI / "handoff/goldens/zip-pack-v2.zip"
PACK_V1_BUNDLE = WAMR_CI / "handoff/goldens/zip-pack-v1-bundle.json"
PACK_V1_PUBLIC_SOURCE = WAMR_CI / "handoff/goldens/zip-pack-v1-public-source.json"
PACK_V2_BUNDLE = WAMR_CI / "handoff/goldens/zip-pack-v2-bundle.json"
PACK_V2_PUBLIC_SOURCE = WAMR_CI / "handoff/goldens/zip-pack-v2-public-source.json"
PACK_HASHES = WAMR_CI / "handoff/goldens/zip-pack-hashes.json"
ROOT_BOUND_V1 = WAMR_CI / "handoff/goldens/root-bound-v1.json"
ROOT_BOUND_V2 = WAMR_CI / "handoff/goldens/root-bound-v2.json"
EXPORT_BUNDLE_V2 = WAMR_CI / "handoff/goldens/export-bundle-v2.json"
ROOT_BOUND_STAGE = "/opt/wamr-handoff-golden-stage"
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


def scratch_parent():
    path = ROOT / ".zig-cache/handoff-python-goldens"
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(path, 0o700)
    return path


@contextlib.contextmanager
def private_tempdir(prefix):
    raw = tempfile.mkdtemp(prefix=prefix, dir=scratch_parent())
    try:
        root = Path(raw).resolve()
        os.chmod(root, 0o700)
        yield root
    finally:
        shutil.rmtree(raw, ignore_errors=True)


def zip_fixture(entries):
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", compression=zipfile.ZIP_STORED, allowZip64=False) as zipped:
        for name, raw in entries:
            info = zipfile.ZipInfo(name)
            info.create_system = 3
            info.external_attr = (stat.S_IFREG | 0o600) << 16
            zipped.writestr(info, raw)
    return out.getvalue()


def zip_multi_golden():
    return zip_fixture((
        ("alpha.txt", b"alpha\n"),
        ("dir/nested.bin", b"\x00stored bytes\n"),
        ("omega.dat", b"last member"),
    ))


def zip_empty_golden():
    return zip_fixture((
        ("empty.bin", b""),
        ("nonempty.txt", b"non-empty\n"),
    ))


def source_context(public_bundle, handoff):
    return public_bundle.context({
        "repository": "cataggar/unikraft",
        "run_id": "1",
        "run_attempt": "1",
        "source_revision": REV,
        "source_tree": REV,
        "wamr_revision": handoff.ci.REVISION,
    })


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


def materialize_bundle(handoff, public_bundle, stage, version):
    bundle = copy.deepcopy(portable_bundle(handoff, public_bundle, version, validate=False))

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
    if version == 2:
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
    return bundle


def packed_records(handoff, public_bundle, version):
    with private_tempdir("handoff-contract-pack-") as root:
        stage = root / "stage"
        stage.mkdir(mode=0o700)
        out = root / "out"
        out.mkdir(mode=0o700)
        source = source_context(public_bundle, handoff)
        handoff.ci.save(stage / "bundle.json", materialize_bundle(handoff, public_bundle, stage, version))

        original_publication_records = public_bundle.publication_records
        original_inspect_tree = public_bundle.inspect_tree
        original_native = public_bundle.native
        try:
            public_bundle.publication_records = lambda *args, **kwargs: None
            public_bundle.inspect_tree = lambda *args, **kwargs: None
            public_bundle.native = lambda *args, **kwargs: None
            archive = out / "bundle.zip"
            archive_sha256 = public_bundle.pack(handoff, stage, archive, source, None, None)
            with archive.open("rb") as handle:
                public_bundle.verify_archive_descriptor(handoff, handle.fileno(), source, archive_sha256)
            with zipfile.ZipFile(archive) as zipped:
                bundle_raw = zipped.read("bundle.json")
                manifest_raw = zipped.read("public-source.json")
                bundle = public_bundle.decode(bundle_raw)
                manifest = public_bundle.decode(manifest_raw)
            archive_bytes = archive.read_bytes()
            return {
                "bundle": bundle,
                "manifest": manifest,
                "source": source,
                "archive": archive_bytes,
                "archive_sha256": archive_sha256,
                "bundle_raw": bundle_raw,
                "manifest_raw": manifest_raw,
            }
        finally:
            public_bundle.publication_records = original_publication_records
            public_bundle.inspect_tree = original_inspect_tree
            public_bundle.native = original_native


def pack_hashes(packed):
    value = {
        "zip-pack-v1.zip": hashlib.sha256(packed[1]["archive"]).hexdigest(),
        "zip-pack-v2.zip": hashlib.sha256(packed[2]["archive"]).hexdigest(),
    }
    return json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n"


def max_accepted_member_size(handoff, public_bundle, version, member, upper):
    lo, hi = 1, upper
    while lo < hi:
        mid = (lo + hi + 1) // 2
        try:
            portable_bundle(handoff, public_bundle, version, sizes={member: mid})
            lo = mid
        except ValueError:
            hi = mid - 1
    return lo


def artifact_limits(handoff, public_bundle, version):
    names = list(handoff.NAMES if version == 1 else handoff.V2_NAMES)
    return [
        {
            "name": name,
            "max_bytes": max_accepted_member_size(
                handoff, public_bundle, version,
                f"artifacts/{name}", 300 * 1024 * 1024),
        }
        for name in names
    ]


def candidate_records(handoff, public_bundle, version):
    with private_tempdir("handoff-contract-") as root:
        stage = root / "stage"
        stage.mkdir(mode=0o700)
        bundle = materialize_bundle(handoff, public_bundle, stage, version)
        transport = None
        if version == 2:
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
        admission = (
            handoff.ci.document(stage / "candidate.json.admission.json")
            if version == 2 else None
        )
        return candidate, admission, transport


def root_bound_bundle(handoff, public_bundle, version):
    with private_tempdir("handoff-contract-root-bound-") as root:
        stage = root / "stage"
        stage.mkdir(mode=0o700)
        bundle = materialize_bundle(handoff, public_bundle, stage, version)
        selected = public_bundle.members(handoff, bundle, stage)
        assert len(selected) + 2 == (
            public_bundle.V1_ZIP_MEMBERS if version == 1 else public_bundle.V2_ZIP_MEMBERS)
        actual = stage.as_posix()

    def normalize(value):
        if isinstance(value, dict):
            return {
                key: (ROOT_BOUND_STAGE + raw[len(actual):]
                      if key == "path" and isinstance(raw := item, str)
                      and raw.startswith(actual + "/") else normalize(item))
                for key, item in value.items()
            }
        if isinstance(value, list):
            return [normalize(item) for item in value]
        return value

    normalized = normalize(bundle)
    public_bundle.members(handoff, normalized, Path(ROOT_BOUND_STAGE))
    return public_bundle.encoded(normalized)


def export_bundle_v2(handoff, public_bundle):
    with private_tempdir("handoff-export-bundle-") as root:
        stage = root / "stage"
        stage.mkdir(mode=0o700)
        bundle = materialize_bundle(handoff, public_bundle, stage, 2)
        by_name = dict(zip(handoff.V2_NAMES, bundle["artifacts"]))
        bundle["identity"] = {
            "wamr_revision": handoff.ci.REVISION,
            **{name + "_sha256": by_name[name]["sha256"]
               for name in ("wasm", "cwasm", "runtime", "compiler", "config")},
        }
        actual = stage.as_posix()

    def normalize(value):
        if isinstance(value, dict):
            return {
                key: (ROOT_BOUND_STAGE + raw[len(actual):]
                      if key == "path" and isinstance(raw := item, str)
                      and raw.startswith(actual + "/") else normalize(item))
                for key, item in value.items()
            }
        if isinstance(value, list):
            return [normalize(item) for item in value]
        return value

    normalized = normalize(bundle)
    public_bundle.members(handoff, normalized, Path(ROOT_BOUND_STAGE))
    return public_bundle.encoded(normalized)


def contract_golden():
    handoff, public_bundle = load("handoff"), load("public_bundle")
    packed = {version: packed_records(handoff, public_bundle, version) for version in (1, 2)}
    bundles = {version: packed[version]["bundle"] for version in (1, 2)}
    manifests = {version: packed[version]["manifest"] for version in (1, 2)}
    candidate_v1, unused_admission_v1, unused_transport_v1 = candidate_records(handoff, public_bundle, 1)
    candidate_v2, admission, transport = candidate_records(handoff, public_bundle, 2)
    del unused_admission_v1, unused_transport_v1
    artifact_limits_v1 = artifact_limits(handoff, public_bundle, 1)
    artifact_limits_v2 = artifact_limits(handoff, public_bundle, 2)
    serial_max = max_accepted_member_size(handoff, public_bundle, 2, "boots/raw-x2apic/serial", 5 * 1024 * 1024)
    config_max = next(item["max_bytes"] for item in artifact_limits_v2 if item["name"] == "config")
    large_max = next(item["max_bytes"] for item in artifact_limits_v2 if item["name"] == "raw")

    profiles = []
    for version in (1, 2):
        result = public_bundle.decode((FIXTURES / f"accepted-v{version}.json").read_bytes())
        selected = public_bundle.members(handoff, bundles[version])
        modes = list(handoff.ci.MODES if version == 1 else handoff.ci.SIX_MODES)
        profiles.append({
            "version": version,
            "compatibility": "tiny-v2" if version == 2 else "tiny-v1",
            "profile": result.get("profile"),
            "production": result.get("profile") == handoff.ci.CURRENT_PROFILE,
            "workload": result["workload"],
            "modes": modes,
            "artifact_count": len(bundles[version]["artifacts"]),
            "evidence_count": len(bundles[version]["evidence"]),
            "boot_member_count": len(modes) * len(public_bundle.BOOT_KEYS),
            "zip_member_count": len(selected) + 2,
        })

    assert list(candidate_v1.keys()) == list(candidate_v2.keys())
    schemas = {
        "artifact": list(candidate_v2["os_vhd"].keys()),
        "manifest_member": list(next(iter(manifests[1]["members"].values())).keys()),
        "boot": list(bundles[1]["boots"][0].keys()),
        "identity": list(bundles[1]["identity"].keys()),
        "local_image_handoff_v1": list(bundles[1].keys()),
        "local_image_handoff_v2": list(bundles[2].keys()),
        "public_source_manifest_v1": list(manifests[1].keys()),
        "public_source_manifest_v2": list(manifests[2].keys()),
        "public_source_transport_v2": list(transport.keys()),
        "direct_compute_candidate": list(candidate_v2.keys()),
        "direct_compute_candidate_v1": list(candidate_v1.keys()),
        "direct_compute_candidate_v2": list(candidate_v2.keys()),
        "direct_compute_admission_v2": list(admission.keys()),
        "run": list(bundles[2]["run"].keys()),
        "lineage": list(bundles[2]["lineage"].keys()),
        "public_context": list(public_bundle.context(packed[2]["source"]).keys()),
        "approval": list(candidate_v2["approval"].keys()),
    }
    value = {
        "schema": "uk.wamr.handoff-contract-golden",
        "schema_version": 1,
        "authority": "not_admitted",
        "canonicalization": handoff.CANONICALIZATION,
        "limits": {
            "max_members": public_bundle.MAX_MEMBERS,
            "max_total_bytes": public_bundle.MAX_TOTAL,
            "json_bytes": public_bundle.MAX_JSON,
            "serial_bytes": serial_max,
            "config_bytes": config_max,
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
            "artifact_limits_v1": artifact_limits_v1,
            "artifact_limits_v2": artifact_limits_v2,
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
        self.assertEqual(ZIP_MULTI.read_bytes(), zip_multi_golden())
        self.assertEqual(ZIP_EMPTY.read_bytes(), zip_empty_golden())
        handoff, public_bundle = load("handoff"), load("public_bundle")
        packed = {version: packed_records(handoff, public_bundle, version) for version in (1, 2)}
        self.assertEqual(PACK_V1.read_bytes(), packed[1]["archive"])
        self.assertEqual(PACK_V2.read_bytes(), packed[2]["archive"])
        self.assertEqual(PACK_V1_BUNDLE.read_bytes(), packed[1]["bundle_raw"])
        self.assertEqual(PACK_V1_PUBLIC_SOURCE.read_bytes(), packed[1]["manifest_raw"])
        self.assertEqual(PACK_V2_BUNDLE.read_bytes(), packed[2]["bundle_raw"])
        self.assertEqual(PACK_V2_PUBLIC_SOURCE.read_bytes(), packed[2]["manifest_raw"])
        self.assertEqual(PACK_HASHES.read_text(encoding="utf-8"), pack_hashes(packed))
        self.assertEqual(ROOT_BOUND_V1.read_bytes(), root_bound_bundle(handoff, public_bundle, 1))
        self.assertEqual(ROOT_BOUND_V2.read_bytes(), root_bound_bundle(handoff, public_bundle, 2))
        self.assertEqual(EXPORT_BUNDLE_V2.read_bytes(), export_bundle_v2(handoff, public_bundle))

    def test_python_members_match_zig_sample_verdicts(self):
        handoff, public_bundle = load("handoff"), load("public_bundle")
        large = max_accepted_member_size(handoff, public_bundle, 2, "artifacts/raw", 300 * 1024 * 1024)
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

    def test_python_accepts_real_root_bound_handoff_and_v1_candidate(self):
        handoff, public_bundle = load("handoff"), load("public_bundle")
        with private_tempdir("handoff-contract-root-") as root:
            stage = root / "stage"
            stage.mkdir(mode=0o700)
            bundle = materialize_bundle(handoff, public_bundle, stage, 2)
            selected = public_bundle.members(handoff, bundle, stage)
            self.assertEqual(public_bundle.V2_ZIP_MEMBERS, len(selected) + 2)
            with self.assertRaises(ValueError):
                public_bundle.members(handoff, bundle)

        candidate, admission, transport = candidate_records(handoff, public_bundle, 1)
        self.assertIsNone(admission)
        self.assertIsNone(transport)
        self.assertEqual(1, candidate["version"])
        self.assertEqual("FINAL-APPROVED-FRESH-NAME", candidate["prefix"])
        self.assertEqual("FINAL-APPROVED-SUBSCRIPTION-UUID", candidate["subscription"])


if __name__ == "__main__":
    if sys.argv[1:] == ["--write"]:
        GOLDEN.write_text(contract_golden(), encoding="utf-8")
        ZIP_MULTI.write_bytes(zip_multi_golden())
        ZIP_EMPTY.write_bytes(zip_empty_golden())
        handoff, public_bundle = load("handoff"), load("public_bundle")
        packed = {version: packed_records(handoff, public_bundle, version) for version in (1, 2)}
        PACK_V1.write_bytes(packed[1]["archive"])
        PACK_V2.write_bytes(packed[2]["archive"])
        PACK_V1_BUNDLE.write_bytes(packed[1]["bundle_raw"])
        PACK_V1_PUBLIC_SOURCE.write_bytes(packed[1]["manifest_raw"])
        PACK_V2_BUNDLE.write_bytes(packed[2]["bundle_raw"])
        PACK_V2_PUBLIC_SOURCE.write_bytes(packed[2]["manifest_raw"])
        PACK_HASHES.write_text(pack_hashes(packed), encoding="utf-8")
        ROOT_BOUND_V1.write_bytes(root_bound_bundle(handoff, public_bundle, 1))
        ROOT_BOUND_V2.write_bytes(root_bound_bundle(handoff, public_bundle, 2))
        EXPORT_BUNDLE_V2.write_bytes(export_bundle_v2(handoff, public_bundle))
    else:
        unittest.main()
