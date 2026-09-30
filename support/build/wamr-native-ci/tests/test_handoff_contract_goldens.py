#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""Freeze #187 handoff/public-bundle contract tables from Python.

Regenerate intentionally with:
  python3 -B support/build/wamr-native-ci/tests/test_handoff_contract_goldens.py --write
"""
import importlib.util, json, sys, unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
WAMR_CI = ROOT / "support/build/wamr-native-ci"
GOLDEN = WAMR_CI / "handoff/goldens/contracts-profile-layout.json"


def load(name):
    spec = importlib.util.spec_from_file_location(name, WAMR_CI / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def contract_golden():
    handoff, public_bundle = load("handoff"), load("public_bundle")
    boot_keys = list(public_bundle.BOOT_KEYS)
    modes_v1, modes_v2 = list(handoff.ci.MODES), list(handoff.ci.SIX_MODES)
    evidence_v1, evidence_v2 = sorted(public_bundle.EVIDENCE), sorted(public_bundle.V2_EVIDENCE)

    def members(names, modes, evidence):
        selected = ([f"artifacts/{name}" for name in names]
                    + [f"boots/{mode}/{key}" for mode in modes for key in boot_keys]
                    + [f"evidence/{name}" for name in evidence])
        return sorted(selected) + ["bundle.json", "public-source.json"]

    schemas = {
        "artifact": ["path", "sha256", "size"],
        "boot": ["mode", "serial", "request", "report", "compute"],
        "identity": ["wamr_revision", "wasm_sha256", "cwasm_sha256", "runtime_sha256", "compiler_sha256", "config_sha256"],
        "local_image_handoff_v1": ["schema", "version", "authority", "source_revision", "source_tree", "identity", "artifacts", "boots", "evidence"],
        "local_image_handoff_v2": ["schema", "version", "profile", "authority", "source_revision", "source_tree", "run", "identity", "lineage", "artifacts", "boots", "evidence"],
        "public_source_manifest_v1": ["schema", "version", "authority", "source", "members"],
        "public_source_manifest_v2": ["schema", "version", "profile", "authority", "source", "members"],
        "public_source_transport_v2": ["schema", "version", "repository", "run_id", "run_attempt", "source_revision", "source_tree", "inner_zip_sha256", "artifact_id", "container_digest"],
        "direct_compute_candidate": ["schema", "version", "purpose", "authority", "approval", "attempt_id", "subscription", "location", "prefix", "vm_size", "serial_mode", "runtime_seconds", "cleanup_seconds", "operation_seconds", "poll_seconds", "source_revision", "source_tree", "identity", "os_vhd", "bundle"],
        "direct_compute_admission_v2": ["schema", "version", "profile", "authority", "source_revision", "source_tree", "run", "lineage", "public_bundle", "transport"],
    }
    profiles = [
        (1, "tiny-v1", None, False, modes_v1, len(handoff.NAMES), len(evidence_v1), public_bundle.V1_ZIP_MEMBERS),
        (2, "tiny-v2", handoff.ci.CURRENT_PROFILE, True, modes_v2, len(handoff.V2_NAMES), len(evidence_v2), public_bundle.V2_ZIP_MEMBERS),
    ]
    value = {
        "schema": "uk.wamr.handoff-contract-golden", "schema_version": 1,
        "authority": "not_admitted", "canonicalization": "utf8-byte-sorted-keys-compact-lf-v1",
        "limits": {"max_members": public_bundle.MAX_MEMBERS, "max_total_bytes": public_bundle.MAX_TOTAL,
                   "json_bytes": public_bundle.MAX_JSON, "serial_bytes": 4 * 1024 * 1024,
                   "large_artifact_bytes": 256 * 1024 * 1024 + 512,
                   "v1_zip_members": public_bundle.V1_ZIP_MEMBERS, "v2_zip_members": public_bundle.V2_ZIP_MEMBERS},
        "profiles": [{"version": v, "compatibility": c, "profile": p, "production": prod,
                      "workload": "tiny", "modes": modes, "artifact_count": ac,
                      "evidence_count": ec, "boot_member_count": len(modes) * len(boot_keys),
                      "zip_member_count": zc} for v, c, p, prod, modes, ac, ec, zc in profiles],
        "historical_sources": {
            "legacy_v1_without_external_archive_digest": [{"revision": r, "tree": t} for r, t in sorted(public_bundle.LEGACY_V1_SOURCES)],
            "pre_supervisor_with_external_archive_digest": [{"revision": r, "tree": t} for r, t in sorted(public_bundle.PRE_SUPERVISOR_SOURCES)],
        },
        "tables": {"artifact_names_v1": list(handoff.NAMES), "artifact_names_v2": list(handoff.V2_NAMES),
                   "boot_keys": boot_keys, "evidence_v1": evidence_v1, "evidence_v2": evidence_v2,
                   "zip_members_v1": members(list(handoff.NAMES), modes_v1, evidence_v1),
                   "zip_members_v2": members(list(handoff.V2_NAMES), modes_v2, evidence_v2)},
        "schemas": schemas,
    }
    return json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")) + "\n"


class HandoffContractGoldens(unittest.TestCase):
    def test_python_oracle_matches_checked_in_golden(self):
        self.assertEqual(GOLDEN.read_text(encoding="utf-8"), contract_golden())


if __name__ == "__main__":
    if sys.argv[1:] == ["--write"]:
        GOLDEN.write_text(contract_golden(), encoding="utf-8")
    else:
        unittest.main()
