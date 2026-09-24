#!/usr/bin/env python3
"""Differential check of native command records against the frozen Python oracle."""
import hashlib
import importlib.util
import json
from pathlib import Path
import sys


def main():
    source, record_path, log_path = map(Path, sys.argv[1:])
    spec = importlib.util.spec_from_file_location("wamr_native_reference", source)
    reference = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(reference)
    raw = record_path.read_bytes()
    record = json.loads(raw)
    log = log_path.read_bytes()
    assert raw == reference.compact_json(record, newline=True)
    assert record["scope"] == "command_diagnostic_not_acceptance"
    assert record["stage"] == "fixtures"
    assert record["bytes"] == len(log)
    assert record["sha256"] == hashlib.sha256(log).hexdigest()
    assert record["known_error_markers"] == reference.command_error_markers(log)
    assert record["sha256_scope"] == reference.command_digest_scope(len(log))
    binding = record["supervisor"]
    assert binding["schema"] == "uk.wamr.command-supervisor-result"
    assert binding["bootstrap"] is False
    request = binding["request"]
    legacy_fixture = reference.production_command_contract("fixtures")
    assert request["environment"] == legacy_fixture["environment"]
    expected_limits = dict(legacy_fixture["limits"])
    for stream in ("stdout_bytes", "stderr_bytes"):
        assert 0 < request["limits"][stream] <= expected_limits[stream]
        expected_limits[stream] = request["limits"][stream]
    assert request["limits"] == expected_limits
    assert request["cwd"] == legacy_fixture["cwd"]
    assert (
        0 < request["timeout_ns"]
        <= legacy_fixture["seconds"] * 1_000_000_000
        and request["timeout_ns"] % 1_000_000_000 == 0
    )
    assert [item["name"] for item in request["retained_executables"]] == (
        legacy_fixture["retained_names"]
    )
    assert request["argv"] == [
        {"kind": "path", "role": "native:wamr-native-ci-fixtures", "relative": ""},
        {"kind": "literal", "value": "--fixture-root"},
        {"kind": "path", "role": "work", "relative": "fixtures"},
    ]
    assert request["interpreter"] is None
    assert request["command_executable"] == request["native_executable"]
    core = {
        key: item for key, item in request.items()
        if key not in {
            "canonical_sha256", "argv_sha256", "environment_sha256", "cwd_sha256"
        }
    }
    for field, payload in (
        ("canonical_sha256", core),
        ("argv_sha256", request["argv"]),
        ("environment_sha256", request["environment"]),
        ("cwd_sha256", request["cwd"]),
    ):
        assert request[field] == reference.command_binding_digest(payload), field
    result = binding["result"]
    without_digest = dict(result)
    del without_digest["canonical_sha256"]
    assert result["canonical_sha256"] == reference.command_binding_digest(
        without_digest
    )
    command = result["command"]
    stdout = command["stdout"]
    stderr = command["stderr"]
    assert command["output"]["commitment_sha256"] == (
        reference.command_output_commitment(
            stdout["bytes"], stdout["sha256"],
            stderr["bytes"], stderr["sha256"],
        )
    )
    assert command["output"]["bytes"] == stdout["bytes"] + stderr["bytes"]
    assert command["output"]["combined_sha256"] == record["sha256"] or (
        record["over_limit"]
    )
    assert command["cleanup_complete"] and not command["poisoned"]
    if record["exit_code"] == 0 and not record["over_limit"]:
        native_fixture = dict(
            legacy_fixture,
            argv=request["argv"],
            command_executable=request["command_executable"]["path"],
            native_executable=request["native_executable"]["path"],
            interpreter=None,
            seconds=request["timeout_ns"] // 1_000_000_000,
            limits=request["limits"],
        )
        original = reference.production_command_contract
        reference.production_command_contract = (
            lambda stage, profile=reference.CURRENT_PROFILE:
            native_fixture if stage == "fixtures" else original(stage, profile)
        )
        identities = {
            "command-supervisor": request["supervisor"]["identity"],
            "native:wamr-native-ci-fixtures":
                request["native_executable"]["identity"],
        }
        for retained in request["retained_executables"]:
            identities[retained["path"]["role"]] = retained["identity"]
        if record["known_error_markers"]:
            try:
                reference.validate_supervised_command_binding(
                    record, "fixtures", identities
                )
            except reference.Refusal:
                pass
            else:
                raise AssertionError("Python admitted an error marker")
        else:
            reference.validate_supervised_command_binding(
                record, "fixtures", identities
            )
    for stage, verb in (
        ("prepare", "prepare"),
        ("config", "olddefconfig"),
        ("native-image", "native-images"),
    ):
        legacy = reference.production_command_contract(stage)
        assert legacy["interpreter"] is None
        assert legacy["command_executable"] == legacy["native_executable"]
        assert legacy["argv"][1] == {"kind": "literal", "value": verb}
        assert legacy["seconds"] == (600 if stage == "config" else 1800)


if __name__ == "__main__":
    main()
