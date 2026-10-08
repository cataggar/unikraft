# SPDX-License-Identifier: BSD-3-Clause
"""Controller witness ledger; successors do not authorize Python owner removal."""

LIMIT_SOURCE = "controller/source_custody_limits_tests.zig"
NATIVE_SOURCE = "controller/tests.zig"

PRODUCTION_LIMIT_SUCCESSORS = {
    "test_00_production_constants_are_unmodified": (
        "production source limits are frozen and tracked counters accept only "
        "the exact maximum",
    ),
    "test_10_real_enumeration_entry_and_sparse_byte_boundaries": (
        "real ignored source enumeration accepts 131072 entries and 8 GiB, "
        "refuses first excess",
    ),
    "test_20_real_git_output_byte_boundary": (
        "real ignored Git inventory accepts eight MiB and refuses the next byte",
    ),
    "test_30_real_git_path_and_depth_boundaries": (
        "real ignored inventory path 1024 and depth 64 succeed, first excess "
        "refuses",
    ),
    "test_40_real_root_enumeration_128_and_129": (
        "real root inventory accepts 128 entries and refuses 129",
    ),
}

NATIVE_ORACLE_SUCCESSORS = {
    "handoff inspect command matches Python's closed post-run contract": (
        "handoff inspect command matches the authenticated historical post-run "
        "contract",
    ),
    "import identity source allowlist matches the historical supervisor "
    "source set": (
        "import identity source allowlist matches authenticated historical "
        "evidence",
    ),
    "native import identity matches Python guarded source map under supervision": (
        "native import identity binds the compiled source map under real "
        "supervision",
    ),
    "historical v2 supervised bindings use the closed imported producer contract": (
        "historical v2 supervised bindings use the closed imported producer "
        "contract",
    ),
    "legacy handoff inspect command fixture matches Python strictness": (
        "legacy handoff inspect preserves five rehashed historical refusal "
        "witnesses",
    ),
}

# Exact discovery identity/counts remain in authority/goldens/python-scenarios.
# Collection loads neither current run.py nor PUBLIC; only these retained
# owner classes opt into those implementations when actually executed.
ADAPTER_CLASSES = {
    "NativeAcquisitionFixtures": ("native-tool-fixtures-no-controller-oracle", 10),
    "NativeRecordBridge": ("retained-live-handoff-public-owner", 37),
    "Contract": ("retained-controller-compatibility-witness", 6),
    "PhysicalPackage": ("retained-physical-package-owner", 4),
    "Evidence": ("retained-mixed-custody-supervision-public-owner", 93),
}

HISTORICAL_GENERATION = {
    "prepare/current-run.py": "authenticated e986 controller physical scans",
    "prepare/current-test_adapter.py": "authenticated neutral helper AST only",
    "input-runtime/current-run.py": "historical scan plus native recheck and pin",
    "runtime-path-build/current-run.py": "rehashed path substitution/native refusal",
    "runtime-path-boot/current-run.py": "rehashed path substitution/native refusal",
    "supervisor-source/current-run.py": "rehashed historical map/native refusal",
    "supervisor-runtime/current-run.py": "rehashed historical map/native refusal",
    "command-identity/current-test_adapter.py": "historical seal/native refusal",
    "private-cli/current-handoff.py": "retained live 83-member export parity",
}

HISTORICAL_PRODUCERS = (
    "e98623f780fa23d05b5797004e4b88160404eb1b",
    "0711a0b6bf2285a4ba6ab6dd3bd4088478d665e1",
    "c9c00535399354063486957611bf6e09c8ae4592",
    "3c6d5d98dc5736d86e97884184b26be39c3f11d5",
)

# These are live native qualification drivers, not run.py execution oracles.
# Missing genuine x86 KVM/build custody blocks them; synthetic fixtures cannot
# replace their before/after physical observations or publication refusals.
RETAINED_NATIVE_FAULTS = {
    "build-start-tamper": ("boot-platform", "BuildStartChanged"),
    "missing-build": ("boot-platform", "FileNotFound"),
    "occupied-boot-slot": ("boot-platform", "PriorOutput"),
    "prior-build-output": ("startup", "PathAlreadyExists"),
}
