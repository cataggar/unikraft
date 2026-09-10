#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""Bounded private nested-KVM Hyper-V platform preflight controller."""

import argparse
import base64
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import hashlib
import importlib
from importlib.metadata import distribution as package_distribution
from importlib.metadata import PackageNotFoundError
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import shlex
import shutil
import signal
import stat
import subprocess
import sys
import threading
import time
import uuid

import hyperv_private_preflight_runner as host_runner


azure = importlib.import_module("hyperv-azure")

SUPPORT = Path(__file__).resolve().parents[1]
RUNNER_PATH = Path(__file__).with_name("hyperv_private_preflight_runner.py")
BLOB_WORKER_PATH = Path(__file__).with_name(
    "hyperv_private_preflight_blob.py"
)
TEMPLATE_PATH = SUPPORT / "azure" / "hyperv-private-preflight.json"
REQUIREMENTS_PATH = SUPPORT / "azure" / "requirements.txt"
SHARED_CONTROLLER_PATH = Path(__file__).with_name("hyperv-azure.py")
NETWORK_CONTROLLER_PATH = Path(__file__).with_name(
    "hyperv_network_controller.py"
)
NATIVE_POSTPROCESS_RUNNER_PATH = (
    SUPPORT / "build" / "native-postprocess-runner.py"
)
UK_RELOC_SCRIPT_PATH = SUPPORT / "scripts" / "mkukreloc.py"
INPUT_SCHEMA = "unikraft.hyperv.private-preflight-input"
STATE_SCHEMA = "unikraft.hyperv.private-preflight-state"
RECEIPT_SCHEMA = "unikraft.hyperv.private-preflight-receipt"
INPUT_SCHEMA_VERSION = 9
STATE_SCHEMA_VERSION = 2
RECEIPT_SCHEMA_VERSION = 4
NESTED_CAPABILITY_ADMISSION_SCHEMA = (
    "unikraft.hyperv.nested-capability-admission"
)
NESTED_CAPABILITY_ADMISSION_VERSION = 1
HOST_PHASE_SCHEMA = host_runner.SCHEMA
HOST_EVIDENCE_SCHEMA = host_runner.EVIDENCE_SCHEMA
INPUT_MANIFEST = "private-preflight-input.json"
SOLVED_CONFIG = "solved.config"
CAPABILITY_REFERENCE = "capability.source.json"
PRIVATE_BUILD_RECEIPT = "private-build-receipt.json"
GIT_RUNTIME = "git-runtime"
GIT_RUNTIME_SCHEMA = "unikraft.git-runtime-v2"
GIT_EXECUTABLE = Path("bin/git")
GIT_LOADER = Path("lib/loader")
NATIVE_EFI_NAME = "helloworld_hyperv-x86_64-efi-netvsc"
CAPABILITY_REFERENCE_SCHEMA = "unikraft.hyperv.capability-reference"
PRIVATE_BUILD_SCHEMA = "unikraft.hyperv.private-local-build"
PRIVATE_BUILD_SCHEMA_VERSION = 6
STATE_FILE = "state.json"
LOCATION = "northeurope"
VM_SIZE = "Standard_D2s_v5"
VM_MEMORY_GB = 8
HOST_COMPUTE_API_VERSION = "2025-11-01"
FIXED_SKU_CAPABILITY_NAMES = (
    "CpuArchitectureType",
    "vCPUs",
    "MemoryGB",
    "HyperVGenerations",
    "NestedVirtualization",
)
CONTAINER = "preflight"
WORKLOAD = "platform-only-v1"
NESTED_VIRTUALIZATION_REFERENCE = {
    "url": (
        "https://learn.microsoft.com/en-us/azure/virtual-machines/"
        "sizes/general-purpose/dsv5-series"
    ),
    "source_commit": "2072bfd7009384b9fde1357342d91953104e293d",
    "updated": "2026-07-27",
}
SDK_VERSION = "12.28.0"
SDK_DISTRIBUTIONS = (
    ("azure-core", "1.41.0"),
    ("azure-storage-blob", SDK_VERSION),
    ("certifi", "2026.7.22"),
    ("cffi", "2.1.1"),
    ("charset-normalizer", "3.5.1"),
    ("cryptography", "50.0.1"),
    ("idna", "3.19"),
    ("isodate", "0.7.2"),
    ("pycparser", "3.0"),
    ("requests", "2.34.2"),
    ("typing-extensions", "4.16.0"),
    ("urllib3", "2.7.0"),
)
MAX_ATTEMPT_SECONDS = 60 * 60
MAX_TOTAL_BYTES = 256 * 1024 * 1024
MAX_EVIDENCE_BYTES = 8 * 1024 * 1024
MAX_CONTROL_BYTES = 512 * 1024
MAX_MANIFEST_BYTES = 64 * 1024
MAX_STATE_BYTES = 192 * 1024
MAX_BLOB_SAS_BYTES = 4096
MAX_TRACKED_ENTRIES = 100_000
MAX_TRACKED_BYTES = 2 * 1024 * 1024 * 1024
MAX_TRACKED_FILE_BYTES = 256 * 1024 * 1024
TRANSFER_TIMEOUT_SECONDS = 300
RECONCILE_TIMEOUT_SECONDS = 120
CLEANUP_TIMEOUT_SECONDS = 20 * 60
SHA256 = re.compile(r"[0-9a-f]{64}")
IDENTITY = re.compile(r"[0-9a-f]{32}")
STORAGE_NAME = re.compile(r"[a-z0-9]{3,24}")
GIT_COMMIT = re.compile(r"[0-9a-f]{40,64}")
SAFE_RELATIVE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,255}")
INPUT_NAMES = {
    "qemu": "qemu/bin/qemu-system-x86_64",
    "ovmf_code": "OVMF_CODE.fd",
    "ovmf_vars": "OVMF_VARS.fd",
    "capability_raw": "capability.raw",
    "efi": "private.efi",
    "raw": "private.raw",
    "vhd": "private.vhd",
}
PUBLIC_ROLES = ("qemu", "ovmf_code", "ovmf_vars", "capability_raw")
PRIVATE_ROLES = ("raw", "vhd")
REMOTE_ROLES = PUBLIC_ROLES + PRIVATE_ROLES
LOCAL_ROLES = ("efi",)
ALL_ROLES = REMOTE_ROLES + LOCAL_ROLES
BOOT_POLICIES = (
    "platform-unavailable-v1",
    "platform-main-zero-v1",
    "guarded-v2-pristine-unavailable",
)
GUARDED_BOOT_POLICY = "guarded-v2-pristine-unavailable"
GUARDED_CONTRACT_SCHEMA = (
    "unikraft.hyperv.guarded-v2-pristine-unavailable"
)
GUARDED_PRODUCER_SCHEMA = "unikraft.hyperv.guarded-producer-pin"
GUARDED_PRODUCER_SCHEMA_VERSION = 4
GUARDED_PRODUCER_CLOSURES = {
    "support/build": {
        "name": "support/build",
        "sha256": (
            "31d6c4329313af242dd336f172c1be9c92f156a4da4f24f629ebf30266622cc2"
        ),
        "size": 1255979,
        "files": 182,
    },
    "support/kconfig": {
        "name": "support/kconfig",
        "sha256": (
            "1922363c552b45adbe8edf0df83b5a05eed16140d8525c9cd1908b80da5662b3"
        ),
        "size": 692952,
        "files": 111,
    },
}
GUARDED_BUILD_CONTROL_FILES = (
    "Config.uk",
    "Makefile",
    "Makefile.uk",
    "build.zig",
    "build.zig.zon",
    "version.mk",
    "support/build/Makefile.build",
    "support/build/Makefile.clean",
    "support/build/Makefile.graph",
    "support/build/Makefile.rules",
    "support/build/build-context.zig",
    "support/build/cc-version.sh",
    "support/build/component-api.zig",
    "support/build/config-submenu.sh",
    "support/build/elf-common-validator.zig",
    "support/build/final-link.zig",
    "support/build/kconfig.zig",
    "support/build/linker-script.zig",
    "support/build/lto-symbol-policy.py",
    "support/build/lto-symbol-policy.zig",
    "support/build/merge-linker-scripts.py",
    "support/build/native-build-tools.zig",
    "support/build/native-config-metadata.py",
    "support/build/native-config-metadata.zig",
    "support/build/native-config-tool.zig",
    "support/build/native-image-data.zig",
    "support/build/native-image-graph.zig",
    "support/build/native-kconfig-bridge.c",
    "support/build/native-library-link.zig",
    "support/build/native-lto.zig",
    "support/build/native-postprocess-runner.py",
    "support/build/native-postprocess.zig",
    "support/build/native-target-object.zig",
    "support/build/symbols/libukrandom-lcpu.localize",
    "support/build/target/native-profile.zig",
    "support/build/zig-facade-paths.zig",
    "support/build/zig-facade-runner.zig",
)
GUARDED_EXECUTED_HELPER_FILES = (
    "support/build/tests/hyperv-smp-link-test.py",
    "support/build/tests/hyperv-irq-register-test.py",
    "support/build/tests/hyperv-driver-registration-test.py",
    "support/scripts/build-graph.py",
    "support/scripts/configupdate",
    "support/scripts/elf_tools.py",
    "support/scripts/gitsha1",
    "support/scripts/mkbootinfo.py",
    "support/scripts/mkcompiledb.py",
    "support/scripts/mkefi.py",
    "support/scripts/mklinux.py",
    "support/scripts/mkukreloc.py",
    "support/scripts/multiboot.py",
    "support/scripts/uk-gdb.py",
)
GUARDED_PRODUCER_FILES = {
    "Config.uk": (
        "31ad9392835d740c86f36c8801dc1d0973ee33c2a40ef6f758ecb8f65cc58d5f"
    ),
    "Makefile": (
        "c790738ac50a85be2e7def288a32890a1c2703b9a148ffb2dd633d200305d562"
    ),
    "Makefile.uk": (
        "288bb7b13ca5484812e1fa5c6bdc34724607b61d8542cef08357c4e4988bcf09"
    ),
    "build.zig": (
        "28f7a432f0b5c9d04dedd6686ba6e42ca516e5c770634bd9596edd6dd4b9cdfb"
    ),
    "build.zig.zon": (
        "511efb394c90490f52120af26e87c5e0a3ea27a444ab1c197ce04f1b3b709e4e"
    ),
    "version.mk": (
        "cafea59f9f8b9ca7b2d8c15e907cc984f2b8992e52766ed2e826337de0c9503c"
    ),
    "support/build/Makefile.build": (
        "61ae89caa8ca9c5b41d8daf4fd2a855b3c80fec347ae473dd51c0bfa1656b8c8"
    ),
    "support/build/Makefile.clean": (
        "067162c663472b42c09401aba78ed0d1bbb39dd9cb809718a9b12eb8d7aec55f"
    ),
    "support/build/Makefile.graph": (
        "32a17fdb76ae0c52be5b501d6c5270503b4f235f491a2ac508ff22df95edd538"
    ),
    "support/build/Makefile.rules": (
        "a8ad0532d523b7acb632f73ea5c4dc81050740452c747e1fdd3af36884233ee5"
    ),
    "support/build/build-context.zig": (
        "87e9e9c1b396275ed472d746a1d05b610e1fde97a1a9617087ea850e1b0af495"
    ),
    "support/build/cc-version.sh": (
        "fcf53f6cd69d082189c1e1a57c10fb0c34a5c0ac6b5e23f6035562287cfd9ae9"
    ),
    "support/build/component-api.zig": (
        "f34516c624f42b1151d45fe4674e41a3bd8cb76dd03ad279b74afe9feb6860c2"
    ),
    "support/build/config-submenu.sh": (
        "8036c9d1665fcf577b3ac96d28e0fc6196fada7683077884ba85b8ba4ca5f9cd"
    ),
    "support/build/elf-common-validator.zig": (
        "9aa2cd402443fa41ce65040332698859853a89c4916be65a8b032907a4bf108f"
    ),
    "support/build/final-link.zig": (
        "2b2934844c13e511351ae5a6f63fd7f4168a98ee007a1cc37e2411016fb71067"
    ),
    "support/build/kconfig.zig": (
        "e3f8ea0dbb9b136038f4c462e67a88394407e299b0ff87cae803a698d630c624"
    ),
    "support/build/linker-script.zig": (
        "e3c29e543d56b538807524a915fecba1241365010f3165fe715d0f2812c702ff"
    ),
    "support/build/lto-symbol-policy.py": (
        "139c967944d7460b92dcad82c8a2149a56d5698a27f7bc1029b1b789da4b19ce"
    ),
    "support/build/lto-symbol-policy.zig": (
        "c9866d7d1e93b7fa63f338e0b5dab79dc09469ed0346e4d900df43d8c4e4b2e5"
    ),
    "support/build/merge-linker-scripts.py": (
        "dd39b9cec861bdf4771fba05c0b477aea37e2b2f1d40d843f31d3c1df011ee3a"
    ),
    "support/build/native-build-tools.zig": (
        "7d04586443a85ae6712673b7b47f7ac67622bfc656fe930c9c16082f1362132d"
    ),
    "support/build/native-config-metadata.py": (
        "a8a98d3eaab01e454fc863d07214aea947baafdf512debf55259807ed96998b7"
    ),
    "support/build/native-config-metadata.zig": (
        "aa4d88591d27633eff90c424451782aad753e160d005ecaefc00e99c1f4281e2"
    ),
    "support/build/native-config-tool.zig": (
        "30291f034f98c970bbf7879189e9bc4c8bc5aa5a6a19fe1ed247d508641d46a9"
    ),
    "support/build/native-image-data.zig": (
        "8800b7373be0a4e995d259fdf3369476d028b322a589ff03e49762a705ba4d9a"
    ),
    "support/build/native-kconfig-bridge.c": (
        "457137bfa280d69f8c3c819ca059c20b76a6c5dcb190575d10a7e5b1ea05f93a"
    ),
    "support/build/native-library-link.zig": (
        "562a0b713e67e6e3de6897077f6bd18cc0ee135b8522bfaecd6d8c11a61423fe"
    ),
    "support/build/native-lto.zig": (
        "cb5a2c661288b243ce97246c27e5c3a6b8b33aa9c037fdb263a42a1774aaba4a"
    ),
    "support/build/native-target-object.zig": (
        "c738d4dcd2acf2085c29716725461822752c8c96bab20ab8ec6e9338f51daa20"
    ),
    "support/build/symbols/libukrandom-lcpu.localize": (
        "b00d5cfee43ae40b56bda292365bf7339d2c8f4239131d632edbebe623e940c6"
    ),
    "support/build/target/native-profile.zig": (
        "ab321fb4434415ddd6ed4e34e173956a9555af91b91f26557b47673b6fe310de"
    ),
    "support/build/zig-facade-paths.zig": (
        "38325cf826d855004e9808924e2687dc70bc42264b952da98f2dce0ad801b8f0"
    ),
    "support/build/zig-facade-runner.zig": (
        "5ba4f753fd4a0537564009a47298f242d10a1b831fe6fda00b5172023de8db77"
    ),
    "support/build/tests/hyperv-smp-link-test.py": (
        "dc40554f6da6ddca3e9f65b5b6c12243c734d24992a342d3564750ecc5e71488"
    ),
    "support/build/tests/hyperv-irq-register-test.py": (
        "a8041f4954d1b0d3ab7082350cdb912bde5ea9a83102e329845ac09cfbfeed8b"
    ),
    "support/build/tests/hyperv-driver-registration-test.py": (
        "b5696ca8cc32ae189a1a388675df85bc7021a6c3d7311ab7d01f53e990f3b8ef"
    ),
    "support/scripts/build-graph.py": (
        "d4618b21455fda35240f29779b289191ddebeabdecbfcafcf27d32bcd8ebd1ab"
    ),
    "support/scripts/configupdate": (
        "2530183ffd12a43fae6003024e41524dade65b2b073de9dc3d59d23b72c41d62"
    ),
    "support/scripts/gitsha1": (
        "10f93856e88dc7afea74e2aff8cbe0048ee907c5f819834325542efa40794564"
    ),
    "support/scripts/mkcompiledb.py": (
        "8c9a11a03940e6c2cbc82f334303908cd52ca9d31c3de42003d21b1306b59339"
    ),
    "support/scripts/mklinux.py": (
        "25aecf13f71468d27537c8b84f7fa1deb271ba3867a0d0655d1b04cd321c1c67"
    ),
    "support/scripts/multiboot.py": (
        "91d3d660ebbc11f03d6b86bc04a70ca7b7e28539c4a293abbbdba7e1ee3ba6a9"
    ),
    "support/scripts/uk-gdb.py": (
        "cc0d9b9c1c2e8721aa267c2fc1885bb72a6662e2d2573cdc04227e6998a79434"
    ),
    "drivers/hyperv/netvsc/Makefile.uk": (
        "4d3f452f93db4bf3f7f48618a6b5e4eb60e42808e258616d4170d7a1a9c6f636"
    ),
    "drivers/hyperv/netvsc/exportsyms.uk": (
        "664a748b4fabfa6a175994cfa828054b2d8626fd2efbe1227ba43a962b9a8571"
    ),
    "drivers/hyperv/netvsc/include/uk/netvsc.h": (
        "9a501414e2749b031bf1fca8015d3049b9af42c74f1a0da9f514e5165e6d33cb"
    ),
    "drivers/hyperv/netvsc/netvsc.c": (
        "08bdeca07921446c2993ac0a1c61963c9eb3b398948736e96f378e33ff3582c3"
    ),
    "drivers/hyperv/storvsc/Config.uk": (
        "4ee6997ebb98a63bf8cc39ac219e447c5bcec0b783140d2802ba19238711b12c"
    ),
    "drivers/hyperv/storvsc/Makefile.uk": (
        "9ea0883afdb3e08df3110347df9a3917dbd602a151a302b6d3bceea02ec6b905"
    ),
    "drivers/hyperv/storvsc/exportsyms.uk": (
        "0d15682c08580e5dd5f9546b66990e2b053ed1b2b8b0746a05670aaeadc61a6d"
    ),
    "drivers/hyperv/storvsc/include/uk/storvsc.h": (
        "e0e666ff4faefc2ba1186403a4320170fb3163375cc31a04312bbce011aa9f10"
    ),
    "drivers/hyperv/storvsc/storvsc.c": (
        "42e59853180fa7aa039e0895fe6d217d4fcbf0874d6cdb927dad4237ab92a6f0"
    ),
    "drivers/hyperv/storvsc/storvsc_core.h": (
        "8422dd6de969b13a533fe0291a7019442712ae9b7f6177420e6fd4df22860ab7"
    ),
    "drivers/hyperv/storvsc/storvsc_core.zig": (
        "0c09b2e8399302294e9c037619189798b5ef82dce18ca05a04f532ec3b34bb94"
    ),
    "drivers/hyperv/vmbus/Config.uk": (
        "05a880a38a10e130510fafbfa786f080d3da1413feb84ca7fc2a068c04a4d069"
    ),
    "drivers/hyperv/vmbus/Makefile.uk": (
        "7622b3998629db41f2e1c8f8538872cf3efc64fff16e5832d0fb053ba2437a57"
    ),
    "drivers/hyperv/vmbus/exportsyms.uk": (
        "340c49783a88696b2027f815ac0db70bc2b0ae34a331aac8bac0f6a0314a1918"
    ),
    "drivers/hyperv/vmbus/include/uk/vmbus.h": (
        "13bc5450a7a8eb9c360e240c35907e1b5d82f683e36c2ee4e9a19f90f4d76bcb"
    ),
    "drivers/hyperv/vmbus/vmbus_bus.c": (
        "6428a549e5b41155103e6d66ea31b4baf4a90d2657114edc9e7b60dd4746f28e"
    ),
    "drivers/hyperv/vmbus/vmbus_channel.c": (
        "088cc06d1db460cb52525aeee56d980a2074be5c0c0d8cdfa15eef72b656cc1c"
    ),
    "drivers/hyperv/vmbus/vmbus_protocol.h": (
        "c00e58790f9d8ece3518fdda9b82b02b843eccb3c2cc90002344192b554e44a9"
    ),
    "drivers/hyperv/vmbus/vmbus_protocol.zig": (
        "4815d095de1aefcbc8f9bd40c87f7b17b1ff5e51bc816b8ba0b73980b5eab2a3"
    ),
    "plat/hyperv/Config.uk": (
        "c5fe6226a426333e2119845366cac6c712b4258d8c7ead82980d7ac57c7c0505"
    ),
    "plat/hyperv/Makefile.uk": (
        "672e146edc8058fce245a05e475564a89e634b2e41394625236a17167d7a08a4"
    ),
    "plat/hyperv/hyperv_runtime.zig": (
        "901a9caf76b33fa9990acdc061139553862caf394d1c78039cb71008262ec076"
    ),
    "plat/hyperv/include/hyperv/hyperv.h": (
        "af844d90dea4b706ad00ef50beaa0df54697a6b324888d4d41dc918ae2b57b3c"
    ),
    "plat/hyperv/platform.c": (
        "0129808beafd31996448bc8a636a1329feda5d538f19704875a908125e37da5a"
    ),
    "plat/hyperv/time.c": (
        "3b97fcf27fa0a76b93e565b770bb2b1d8b0d7496267387039b6c88d0e1a1cce1"
    ),
    "support/build/native-image-graph.zig": (
        "503321662757432253b462a3bcb0e85403d3cf871b5fbb1f846921a6f966e463"
    ),
    "support/build/native-postprocess-runner.py": (
        "6f68d5dbe410fb7391b7a68e9e98ba3455210a83754c47989f5d31149c7fa094"
    ),
    "support/build/native-postprocess.zig": (
        "fe6adc24f97bf72dcb111853f2b8d5c30a4a86596402e33d9d30945892a8f49f"
    ),
    "support/scripts/elf_tools.py": (
        "0aad63e7830a814a5c29a7330925f64e8c844cf28700aa959002a629d5019820"
    ),
    "support/scripts/mkbootinfo.py": (
        "61436b01857de643ea4cc8ccc1563b8d8321e1ddc1c425d459b08aa1b0aaa409"
    ),
    "support/scripts/mkefi.py": (
        "f2587a5108d5ad57e7418cc6c6a6c2351ccd1e763c68e63a9fc0c8da52426225"
    ),
    "support/scripts/mkukreloc.py": (
        "325817c2c76a389c21358df535ac2ae0f1beb36b7e4cb73b62648d1f5faac8cc"
    ),
    "support/apps/hyperv-acceptance/Config.uk": (
        "548e97aadb9b55101e2ec1dbb7a4b22f82b210a22d5f14eb441b17fdd2009aa7"
    ),
    "support/apps/hyperv-acceptance/Makefile.uk": (
        "2e5c23e4ca47bd306a4d4ab6d75b996ccf5b6ddc885698d25f478ead40df4ac3"
    ),
    "support/apps/hyperv-acceptance/acceptance_protocol.c": (
        "5ba77f19e204c9bc3b9b579cf6ccd9e0184952fd9e0d14c123f5a19af05dd64e"
    ),
    "support/apps/hyperv-acceptance/acceptance_protocol.h": (
        "1b7d718ca10b760b61df07570b640586cce34d1d3c498c68fbd336a61669db4e"
    ),
    "support/apps/hyperv-acceptance/application_network.c": (
        "829b522860c21278eec3c1e849a1b9259c200ee7270f38dbc5872cb5f3c6f82f"
    ),
    "support/apps/hyperv-acceptance/application_network.h": (
        "dba07b1331d6a6f02c3f017c2fabe5a0c1c03f61ffd1df7e07e49c84427d2231"
    ),
    "support/apps/hyperv-acceptance/main.c": (
        "deaf231ec5edf0746e99e7a657a73fcb813da8bc18116b8ef5b6543213064ddb"
    ),
    "support/apps/hyperv-acceptance/persistence.c": (
        "2cad1014dbc49fe9c8d5a3d6c31a282f2ec045b9990ce6b013041681a8df3741"
    ),
    "support/apps/hyperv-acceptance/persistence.h": (
        "8ef53f9ed76286b945212ea487bed1e6d51ec161078d4a2283f9054b962bd70f"
    ),
    "support/apps/hyperv-acceptance/persistence_host.h": (
        "29f1f4f0f272225ae1d2578612a4f8320f1bc8d245e9447ce6696300b80ad23c"
    ),
    "support/apps/hyperv-acceptance/storage_target.c": (
        "f1ea10aca41b49e0a82c9cb8bc855cb7ddf86354abb8331c198127345b018a03"
    ),
    "support/apps/hyperv-acceptance/storage_target.h": (
        "8e357584c2544f25f511b61e486719dea66b526a2e01539e282a67d95530d915"
    ),
}
APPROVED_CAPABILITY_REFERENCE = {
    "name": CAPABILITY_REFERENCE,
    "sha256": (
        "eeff27fe4cd755cd46905860b0cd1663e6234cc67b9b8a55ce7c357cc5c03ec9"
    ),
    "size": 1325,
    "receipt": {
        "schema": CAPABILITY_REFERENCE_SCHEMA,
        "schema_version": 1,
        "scope": (
            "historical nonsecret capability only; "
            "not current private deployment provenance"
        ),
        "source": {
            "provider": "github-actions",
            "repository": "cataggar/unikraft",
            "repository_id": 1356638974,
            "workflow_ref": (
                "cataggar/unikraft/.github/workflows/integration.yaml@"
                "refs/heads/zig16"
            ),
            "head_sha": "67ca3cdbc30774b600b18f515c158620caf902c4",
            "run_id": 34296179269,
            "run_attempt": 1,
            "job": "zig-hyperv",
        },
        "manifest_sha256": (
            "6d9224e4f2693815cf7056c389ee57615c38b6dccede73cce85b7b7ab8020735"
        ),
        "efi_sha256": (
            "22195c323579350040adf822f30d7f0d8cb72f80773b52121f5bedbe2391897d"
        ),
        "raw": {
            "sha256": (
                "e69a9b70b0ed8959b47ec00ac037c065567d44a0aaf02f5077af107e00f67ad1"
            ),
            "size": 69206016,
        },
        "source_vhd": {
            "sha256": (
                "54960c639e80471d3b111a608f913cfea4f5b91bf0e4fc09df84061a2064d460"
            ),
            "size": 69206528,
        },
        "source_boot_evidence": {
            "boots": {
                "raw": {
                    "legacy-apic": {
                        "apic_path": "legacy-xapic",
                        "io_ready": False,
                        "platform_ready": True,
                    },
                    "x2apic": {
                        "apic_path": "x2apic",
                        "io_ready": False,
                        "platform_ready": True,
                    },
                },
                "vhd": {
                    "legacy-apic": {
                        "apic_path": "legacy-xapic",
                        "io_ready": False,
                        "platform_ready": True,
                    },
                    "x2apic": {
                        "apic_path": "x2apic",
                        "io_ready": False,
                        "platform_ready": True,
                    },
                },
            },
            "platform_marker": host_runner.PLATFORM_MARKER,
            "scope": "platform-only",
        },
    },
}
BUILD_TOOL_NAMES = (
    "git", "zig", "make", "python", "bison", "flex", "m4",
    "llvm-nm", "llvm-objcopy", "llvm-objdump", "llvm-readelf",
    "llvm-strip", "bison-data",
)
PURPOSE = "private-hyperv-platform-preflight"
IMPLEMENTATION_PATHS = {
    "controller": Path(__file__),
    "runner": RUNNER_PATH,
    "blob_worker": BLOB_WORKER_PATH,
    "shared_controller": SHARED_CONTROLLER_PATH,
    "network_controller": NETWORK_CONTROLLER_PATH,
    "template": TEMPLATE_PATH,
    "requirements": REQUIREMENTS_PATH,
    **{
        f"guarded_producer:{relative}": SUPPORT.parent / relative
        for relative in GUARDED_PRODUCER_FILES
    },
}


def require_sha256(value, description):
    if not isinstance(value, str) or not SHA256.fullmatch(value):
        raise ValueError(f"{description} must be a lowercase SHA-256 digest")
    return value


def require_uuid(value, description):
    if not isinstance(value, str):
        raise ValueError(f"{description} is invalid")
    try:
        parsed = uuid.UUID(value)
    except ValueError:
        raise ValueError(f"{description} is invalid") from None
    if str(parsed) != value:
        raise ValueError(f"{description} is invalid")
    return value


def exact_fields(value, fields, description):
    return azure.require_exact_fields(value, fields, description)


def validate_private_failure_record(value):
    required = {"category", "code", "phase"}
    optional = {"reconciliation", "cleanup", "recording"}
    if (
        not isinstance(value, dict)
        or not required.issubset(value)
        or not set(value).issubset(required | optional)
        or not isinstance(value["category"], str)
        or not re.fullmatch(
            r"[A-Za-z][A-Za-z0-9_]{0,79}", value["category"]
        )
        or value["code"] is not None
        and (
            not isinstance(value["code"], str)
            or not re.fullmatch(
                r"[A-Za-z][A-Za-z0-9_-]{0,79}", value["code"]
            )
        )
        or not isinstance(value["phase"], str)
        or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]{0,79}", value["phase"])
    ):
        raise ValueError("Private-preflight failure record is invalid")
    reconciliation = value.get("reconciliation")
    if reconciliation is not None and (
        not isinstance(reconciliation, dict)
        or set(reconciliation) != {"category", "code"}
        or not isinstance(reconciliation["category"], str)
        or not re.fullmatch(
            r"[A-Za-z][A-Za-z0-9_]{0,79}",
            reconciliation["category"],
        )
        or reconciliation["code"] is not None
        and (
            not isinstance(reconciliation["code"], str)
            or not re.fullmatch(
                r"[A-Za-z][A-Za-z0-9_-]{0,79}",
                reconciliation["code"],
            )
        )
    ):
        raise ValueError("Private-preflight reconciliation failure is invalid")
    bounded_lists = {}
    for field, stages in (
        (
            "cleanup",
            {
                "private-files", "firewall", "sas",
                "deallocate", "resource-group", "cleanup",
            },
        ),
        ("recording", {"initial", "final"}),
    ):
        entries = value.get(field)
        if entries is None:
            continue
        if (
            not isinstance(entries, list)
            or not 1 <= len(entries) <= 8
        ):
            raise ValueError(
                f"Private-preflight {field} failures are invalid"
            )
        bounded = []
        for entry in entries:
            if (
                not isinstance(entry, dict)
                or set(entry) != {"stage", "category", "code"}
                or entry["stage"] not in stages
                or not isinstance(entry["category"], str)
                or not re.fullmatch(
                    r"[A-Za-z][A-Za-z0-9_]{0,79}",
                    entry["category"],
                )
                or entry["code"] is not None
                and (
                    not isinstance(entry["code"], str)
                    or not re.fullmatch(
                        r"[A-Za-z][A-Za-z0-9_-]{0,79}",
                        entry["code"],
                    )
                )
            ):
                raise ValueError(
                    f"Private-preflight {field} failure is invalid"
                )
            bounded.append(dict(entry))
        bounded_lists[field] = bounded
    return {
        **value,
        **(
            {"reconciliation": dict(reconciliation)}
            if reconciliation is not None else {}
        ),
        **bounded_lists,
    }


def require_relative(value, description):
    if (
        not isinstance(value, str)
        or not SAFE_RELATIVE.fullmatch(value)
        or value.startswith("/")
        or ".." in Path(value).parts
    ):
        raise ValueError(f"{description} is invalid")
    return value


def guarded_producer_contract():
    return {
        "schema": GUARDED_PRODUCER_SCHEMA,
        "schema_version": GUARDED_PRODUCER_SCHEMA_VERSION,
        "files": dict(GUARDED_PRODUCER_FILES),
        "closures": {
            name: dict(record)
            for name, record in GUARDED_PRODUCER_CLOSURES.items()
        },
    }


def verify_guarded_producer_sources(repository):
    repository = Path(repository).resolve(strict=True)
    if repository != SUPPORT.parent.resolve(strict=True):
        raise ValueError("Guarded producer must use this repository worktree")
    if not (
        set(GUARDED_BUILD_CONTROL_FILES)
        | set(GUARDED_EXECUTED_HELPER_FILES)
    ).issubset(GUARDED_PRODUCER_FILES):
        raise RuntimeError("Guarded build proof closure is incomplete")
    for relative, expected in GUARDED_PRODUCER_FILES.items():
        path = repository / relative
        if (
            path.is_symlink()
            or not path.is_file()
            or azure.image_sha256(path) != expected
        ):
            raise ValueError(
                "Guarded producer differs from the reviewed V2 contract"
            )
    for relative, expected in GUARDED_PRODUCER_CLOSURES.items():
        if directory_record(
            repository / relative, relative,
            "Guarded producer execution closure",
        ) != expected:
            raise ValueError(
                "Guarded producer differs from the reviewed V2 contract"
            )


def guarded_contract_from_solved_config(config_path):
    raw = azure.read_regular_file(
        config_path, 1024 * 1024, "Solved guarded V2 configuration"
    )
    try:
        lines = raw.decode("utf-8").splitlines()
    except UnicodeDecodeError:
        raise ValueError("Solved guarded V2 configuration is not UTF-8") from None
    names = (
        "CONFIG_APPHYPERVACCEPTANCE_PERSISTENCE",
        "CONFIG_LIBSTORVSC",
        "CONFIG_LIBSTORVSC_LUN_DISCOVERY",
        "CONFIG_LIBSTORVSC_GUARDED_IO",
        "CONFIG_LIBSTORVSC_MAX_DEVICES",
        "CONFIG_LIBSTORVSC_MAX_LUNS",
        "CONFIG_APPHYPERVACCEPTANCE_PERSISTENCE_RUN_ID",
        "CONFIG_APPHYPERVACCEPTANCE_PERSISTENCE_DISK_ID",
        "CONFIG_APPHYPERVACCEPTANCE_PERSISTENCE_SECTORS",
        "CONFIG_APPHYPERVACCEPTANCE_PERSISTENCE_SECTOR_SIZE",
        "CONFIG_APPHYPERVACCEPTANCE_PERSISTENCE_IDENTITY_POLICY",
        "CONFIG_APPHYPERVACCEPTANCE_PERSISTENCE_PATH",
        "CONFIG_APPHYPERVACCEPTANCE_PERSISTENCE_TARGET",
        "CONFIG_APPHYPERVACCEPTANCE_PERSISTENCE_LUN",
        "CONFIG_APPHYPERVACCEPTANCE_NETWORK_APPLICATION",
    )
    values = {}
    for line in lines:
        for name in names:
            prefix = name + "="
            if line.startswith(prefix):
                if name in values:
                    raise ValueError(
                        "Solved guarded V2 configuration repeats a field"
                    )
                values[name] = line[len(prefix):]
                break
    if values.get("CONFIG_APPHYPERVACCEPTANCE_PERSISTENCE") != "y":
        return None
    required_enabled = (
        "CONFIG_LIBSTORVSC",
        "CONFIG_LIBSTORVSC_LUN_DISCOVERY",
        "CONFIG_LIBSTORVSC_GUARDED_IO",
    )
    if any(values.get(name) != "y" for name in required_enabled):
        raise ValueError(
            "Guarded V2 configuration must enable solved StorVSC discovery"
        )
    if values.get("CONFIG_APPHYPERVACCEPTANCE_NETWORK_APPLICATION") == "y":
        raise ValueError(
            "Guarded persistence cannot enable the network application"
        )
    if any(
        name in values
        for name in (
            "CONFIG_APPHYPERVACCEPTANCE_PERSISTENCE_PATH",
            "CONFIG_APPHYPERVACCEPTANCE_PERSISTENCE_TARGET",
        )
    ):
        raise ValueError(
            "Guarded V2 seed enrollment cannot bind path or target"
        )

    def quoted(name):
        value = values.get(name)
        if (
            not isinstance(value, str)
            or len(value) != 34
            or value[0] != '"'
            or value[-1] != '"'
            or not IDENTITY.fullmatch(value[1:-1])
        ):
            raise ValueError(
                "Guarded V2 run and disk IDs must be 32 lowercase hex digits"
            )
        return value[1:-1]

    def integer(name):
        value = values.get(name)
        if (
            not isinstance(value, str)
            or not re.fullmatch(r"0|[1-9][0-9]*", value)
        ):
            raise ValueError("Guarded V2 configuration has an invalid integer")
        return int(value)

    run_id = quoted("CONFIG_APPHYPERVACCEPTANCE_PERSISTENCE_RUN_ID")
    disk_id = quoted("CONFIG_APPHYPERVACCEPTANCE_PERSISTENCE_DISK_ID")
    sectors = integer("CONFIG_APPHYPERVACCEPTANCE_PERSISTENCE_SECTORS")
    sector_size = integer(
        "CONFIG_APPHYPERVACCEPTANCE_PERSISTENCE_SECTOR_SIZE"
    )
    identity_policy = integer(
        "CONFIG_APPHYPERVACCEPTANCE_PERSISTENCE_IDENTITY_POLICY"
    )
    lun = integer("CONFIG_APPHYPERVACCEPTANCE_PERSISTENCE_LUN")
    max_devices = integer("CONFIG_LIBSTORVSC_MAX_DEVICES")
    max_luns = integer("CONFIG_LIBSTORVSC_MAX_LUNS")
    if (
        identity_policy != 2
        or sector_size != 512
        or sectors <= 48
        or sectors > ((1 << 63) - 1) // sector_size
        or not 0 <= lun <= 255
        or max_devices != 2
        or max_luns != 8
    ):
        raise ValueError(
            "Guarded V2 solved geometry or identity policy is incompatible"
        )
    return {
        "schema": GUARDED_CONTRACT_SCHEMA,
        "schema_version": 1,
        "scope": "platform-only",
        "result": "UNAVAILABLE",
        "protocol": 1,
        "identity_policy": 2,
        "reason": "no-devices",
        "main_return": 2,
        "run_id": run_id,
        "disk_id": disk_id,
        "path": 0,
        "target": 0,
        "lun": lun,
        "sectors": sectors,
        "sector_size": sector_size,
        "solved_config_sha256": hashlib.sha256(raw).hexdigest(),
        "producer": guarded_producer_contract(),
    }


def validate_guarded_contract(value, boot_policy, solved_config_sha256):
    if boot_policy != GUARDED_BOOT_POLICY:
        if value is not None:
            raise ValueError(
                "Ordinary platform boot policies cannot carry guarded state"
            )
        return None
    value = exact_fields(
        value,
        (
            "schema", "schema_version", "scope", "result", "protocol",
            "identity_policy", "reason", "main_return", "run_id",
            "disk_id", "path", "target", "lun", "sectors",
            "sector_size", "solved_config_sha256", "producer",
        ),
        "Guarded V2 pristine-unavailable contract",
    )
    producer = exact_fields(
        value["producer"],
        ("schema", "schema_version", "files", "closures"),
        "Guarded V2 producer pin",
    )
    files = exact_fields(
        producer["files"], GUARDED_PRODUCER_FILES,
        "Guarded V2 producer files",
    )
    closures = exact_fields(
        producer["closures"], GUARDED_PRODUCER_CLOSURES,
        "Guarded V2 producer closures",
    )
    if (
        value["schema"] != GUARDED_CONTRACT_SCHEMA
        or type(value["schema_version"]) is not int
        or value["schema_version"] != 1
        or value["scope"] != "platform-only"
        or value["result"] != "UNAVAILABLE"
        or type(value["protocol"]) is not int
        or value["protocol"] != 1
        or type(value["identity_policy"]) is not int
        or value["identity_policy"] != 2
        or value["reason"] != "no-devices"
        or type(value["main_return"]) is not int
        or value["main_return"] != 2
        or not isinstance(value["run_id"], str)
        or not IDENTITY.fullmatch(value["run_id"])
        or not isinstance(value["disk_id"], str)
        or not IDENTITY.fullmatch(value["disk_id"])
        or type(value["path"]) is not int
        or value["path"] != 0
        or type(value["target"]) is not int
        or value["target"] != 0
        or type(value["lun"]) is not int
        or not 0 <= value["lun"] <= 255
        or type(value["sectors"]) is not int
        or value["sectors"] <= 48
        or value["sectors"] > ((1 << 63) - 1) // 512
        or type(value["sector_size"]) is not int
        or value["sector_size"] != 512
        or require_sha256(
            value["solved_config_sha256"],
            "Guarded V2 solved configuration",
        ) != solved_config_sha256
        or producer["schema"] != GUARDED_PRODUCER_SCHEMA
        or type(producer["schema_version"]) is not int
        or producer["schema_version"] != GUARDED_PRODUCER_SCHEMA_VERSION
        or dict(files) != GUARDED_PRODUCER_FILES
        or dict(closures) != GUARDED_PRODUCER_CLOSURES
    ):
        raise ValueError("Guarded V2 pristine-unavailable contract is invalid")
    return {
        **value,
        "producer": {
            **producer,
            "files": dict(files),
            "closures": {
                name: dict(record)
                for name, record in closures.items()
            },
        },
    }


def file_record(value, role):
    value = exact_fields(
        value, ("name", "sha256", "size"), f"{role} input fingerprint"
    )
    if (
        value["name"] != INPUT_NAMES[role]
        or type(value["size"]) is not int
        or value["size"] <= 0
        or value["size"] > host_runner.MAX_FILE_BYTES
    ):
        raise ValueError(f"{role} input name or size is invalid")
    require_sha256(value["sha256"], f"{role} input fingerprint")
    return dict(value)


def support_record(value):
    value = exact_fields(
        value, ("path", "sha256", "size"), "QEMU support file"
    )
    path = require_relative(value["path"], "QEMU support path")
    if (
        not path.startswith("qemu/")
        or path == INPUT_NAMES["qemu"]
        or len(Path(path).parts) < 3
        or Path(path).parts[1] not in ("lib", "share")
        or type(value["size"]) is not int
        or not 0 < value["size"] <= host_runner.MAX_FILE_BYTES
    ):
        raise ValueError("QEMU support file is invalid")
    require_sha256(value["sha256"], "QEMU support fingerprint")
    return dict(value)


def implementation_contract():
    return {
        "sdk": sdk_dependency_contract(),
        "files": {
            name: {
                "path": str(path.relative_to(SUPPORT.parent)),
                "sha256": azure.image_sha256(path),
                "size": path.stat().st_size,
            }
            for name, path in IMPLEMENTATION_PATHS.items()
        },
    }


def sdk_dependency_contract():
    expected_requirements = "".join(
        f"{name}=={version}\n" for name, version in SDK_DISTRIBUTIONS
    ).encode()
    requirements = azure.read_regular_file(
        REQUIREMENTS_PATH, 16 * 1024,
        "Private-preflight dependency lock",
    )
    if requirements != expected_requirements:
        raise RuntimeError(
            "Private-preflight dependency lock is incompatible"
        )
    records = []
    for name, expected_version in SDK_DISTRIBUTIONS:
        try:
            package = package_distribution(name)
        except PackageNotFoundError:
            raise RuntimeError(
                "Pinned private-preflight dependency is unavailable"
            ) from None
        if package.version != expected_version or package.files is None:
            raise RuntimeError(
                "Pinned private-preflight dependency is incompatible"
            )
        digest = hashlib.sha256()
        count = 0
        total = 0
        for relative in sorted(package.files, key=str):
            path = Path(package.locate_file(relative))
            try:
                metadata = path.lstat()
            except OSError:
                raise RuntimeError(
                    "Pinned private-preflight dependency is incomplete"
                ) from None
            if (
                stat.S_ISLNK(metadata.st_mode)
                or not stat.S_ISREG(metadata.st_mode)
            ):
                raise RuntimeError(
                    "Pinned private-preflight dependency is unsafe"
                )
            fingerprint = azure.image_sha256(path)
            encoded = str(relative).encode()
            digest.update(len(encoded).to_bytes(4, "big"))
            digest.update(encoded)
            digest.update(metadata.st_size.to_bytes(8, "big"))
            digest.update(bytes.fromhex(fingerprint))
            count += 1
            total += metadata.st_size
        if count == 0:
            raise RuntimeError(
                "Pinned private-preflight dependency is empty"
            )
        records.append({
            "name": name,
            "version": expected_version,
            "files": count,
            "bytes": total,
            "sha256": digest.hexdigest(),
        })
    return {
        "requirements_sha256": hashlib.sha256(requirements).hexdigest(),
        "distributions": records,
    }


def validate_implementation(value):
    value = exact_fields(
        value, ("sdk", "files"), "Private-preflight implementation"
    )
    sdk = exact_fields(
        value["sdk"], ("requirements_sha256", "distributions"),
        "Blob SDK contract",
    )
    require_sha256(
        sdk["requirements_sha256"], "Dependency lock fingerprint"
    )
    if (
        sdk["requirements_sha256"] != azure.image_sha256(REQUIREMENTS_PATH)
        or not isinstance(sdk["distributions"], list)
        or len(sdk["distributions"]) != len(SDK_DISTRIBUTIONS)
    ):
        raise ValueError("Blob SDK contract is incompatible")
    distributions = []
    for record, (name, version) in zip(
        sdk["distributions"], SDK_DISTRIBUTIONS
    ):
        record = exact_fields(
            record, ("name", "version", "files", "bytes", "sha256"),
            "Blob SDK distribution",
        )
        if (
            record["name"] != name
            or record["version"] != version
            or type(record["files"]) is not int
            or record["files"] <= 0
            or type(record["bytes"]) is not int
            or record["bytes"] <= 0
        ):
            raise ValueError("Blob SDK distribution is incompatible")
        require_sha256(
            record["sha256"], "Blob SDK distribution fingerprint"
        )
        distributions.append(dict(record))
    files = exact_fields(
        value["files"], tuple(IMPLEMENTATION_PATHS),
        "Private-preflight implementation files",
    )
    normalized = {}
    for name, path in IMPLEMENTATION_PATHS.items():
        record = exact_fields(
            files[name], ("path", "sha256", "size"),
            f"{name} implementation file",
        )
        if (
            record["path"] != str(path.relative_to(SUPPORT.parent))
            or type(record["size"]) is not int
            or record["size"] <= 0
        ):
            raise ValueError("Private-preflight implementation is invalid")
        require_sha256(
            record["sha256"], f"{name} implementation fingerprint"
        )
        normalized[name] = dict(record)
    return {
        "sdk": {
            "requirements_sha256": sdk["requirements_sha256"],
            "distributions": distributions,
        },
        "files": normalized,
    }


def validate_git_runtime_record(value):
    value = exact_fields(
        value,
        (
            "schema", "name", "sha256", "size", "files",
            "executable", "loader", "libraries",
        ),
        "Private Git runtime fingerprint",
    )
    executable = exact_fields(
        value["executable"], ("name", "sha256", "size"),
        "Private Git executable fingerprint",
    )
    loader = exact_fields(
        value["loader"], ("name", "sha256", "size"),
        "Private Git loader fingerprint",
    )
    libraries = value["libraries"]
    if not isinstance(libraries, list) or not libraries:
        raise ValueError("Private Git runtime libraries are invalid")
    libraries = [
        exact_fields(
            library, ("name", "sha256", "size"),
            "Private Git runtime library fingerprint",
        )
        for library in libraries
    ]
    if any(
        not isinstance(library["name"], str)
        for library in libraries
    ):
        raise ValueError("Private Git runtime libraries are invalid")
    member_names = [
        executable["name"], loader["name"],
        *(library["name"] for library in libraries),
    ]
    if (
        value["schema"] != GIT_RUNTIME_SCHEMA
        or value["name"] != GIT_RUNTIME
        or type(value["size"]) is not int
        or value["size"] <= 0
        or type(value["files"]) is not int
        or value["files"] != len(member_names)
        or executable["name"] != GIT_EXECUTABLE.as_posix()
        or loader["name"] != GIT_LOADER.as_posix()
        or type(executable["size"]) is not int
        or executable["size"] <= 0
        or type(loader["size"]) is not int
        or loader["size"] <= 0
        or len(member_names) != len(set(member_names))
        or [library["name"] for library in libraries]
        != sorted(library["name"] for library in libraries)
        or any(
            not re.fullmatch(
                r"lib/[A-Za-z0-9][A-Za-z0-9._+-]{0,127}",
                library["name"],
            )
            or library["name"] == GIT_LOADER.as_posix()
            or type(library["size"]) is not int
            or library["size"] <= 0
            for library in libraries
        )
        or value["size"] != sum(
            member["size"]
            for member in (executable, loader, *libraries)
        )
    ):
        raise ValueError("Private Git runtime fingerprint is invalid")
    require_sha256(value["sha256"], "Private Git runtime fingerprint")
    for member in (executable, loader, *libraries):
        require_sha256(
            member["sha256"], "Private Git runtime member fingerprint"
        )
    digest = hashlib.sha256()
    for member in sorted(
        (executable, loader, *libraries), key=lambda item: item["name"]
    ):
        encoded = member["name"].encode()
        digest.update(len(encoded).to_bytes(4, "big"))
        digest.update(encoded)
        digest.update(member["size"].to_bytes(8, "big"))
        digest.update(bytes.fromhex(member["sha256"]))
    if digest.hexdigest() != value["sha256"]:
        raise ValueError("Private Git runtime aggregate is inconsistent")
    return {
        **value,
        "executable": dict(executable),
        "loader": dict(loader),
        "libraries": [dict(library) for library in libraries],
    }


def validate_provenance(value):
    value = exact_fields(
        value,
        (
            "scheme", "head_commit", "tree_sha256", "physical_sha256",
            "tracked_entries", "tracked_bytes", "config", "git",
        ),
        "Private-preflight build provenance",
    )
    config = exact_fields(
        value["config"], ("name", "sha256", "size"),
        "Solved configuration provenance",
    )
    if (
        value["scheme"] != "unikraft.git-physical-tree-v2"
        or not isinstance(value["head_commit"], str)
        or not GIT_COMMIT.fullmatch(value["head_commit"])
        or type(value["tracked_entries"]) is not int
        or not 0 < value["tracked_entries"] <= MAX_TRACKED_ENTRIES
        or type(value["tracked_bytes"]) is not int
        or not 0 < value["tracked_bytes"] <= MAX_TRACKED_BYTES
        or config["name"] != SOLVED_CONFIG
        or type(config["size"]) is not int
        or not 0 < config["size"] <= 1024 * 1024
    ):
        raise ValueError("Private-preflight build provenance is invalid")
    require_sha256(value["tree_sha256"], "Tracked source-tree fingerprint")
    require_sha256(
        value["physical_sha256"], "Physical source-tree fingerprint"
    )
    require_sha256(config["sha256"], "Solved configuration fingerprint")
    git = validate_git_runtime_record(value["git"])
    return {**value, "config": dict(config), "git": git}


def expected_budget(files, qemu_support):
    remote = sum(files[role]["size"] for role in REMOTE_ROLES)
    remote += sum(record["size"] for record in qemu_support)
    firmware_working = (
        files["ovmf_vars"]["size"] * host_runner.TOTAL_BOOT_COUNT
    )
    total = (
        remote + firmware_working
        + MAX_CONTROL_BYTES + MAX_EVIDENCE_BYTES
    )
    return {
        "remote_input_bytes": remote,
        "firmware_variable_copy_count": host_runner.TOTAL_BOOT_COUNT,
        "firmware_working_copy_bytes": firmware_working,
        "control_payload_max_bytes": MAX_CONTROL_BYTES,
        "evidence_max_bytes": MAX_EVIDENCE_BYTES,
        "total_max_bytes": total,
        "remaining_bytes": MAX_TOTAL_BYTES - total,
    }


def validate_packaging_report(report, efi_sha256, efi_size, file_size):
    expected = azure.packaging_contract(efi_sha256, file_size)
    report = exact_fields(
        report,
        tuple(expected) + (
            "boot-file-size", "disk-guid", "esp-partition-guid",
            "esp-volume-id",
        ),
        "Fixed-VHD packaging contract",
    )
    azure.check_packaging_report(report, efi_sha256, file_size)
    if type(report["boot-file-size"]) is not int or (
        report["boot-file-size"] != efi_size
    ):
        raise ValueError("Fixed-VHD boot file size is invalid")
    if (
        type(report["esp-volume-id"]) is not int
        or not 0 < report["esp-volume-id"] <= 0xffffffff
    ):
        raise ValueError("Fixed-VHD ESP volume ID is invalid")
    for field in ("disk-guid", "esp-partition-guid"):
        value = report[field]
        try:
            parsed = uuid.UUID(value) if isinstance(value, str) else None
        except ValueError:
            parsed = None
        if parsed is None or parsed.int == 0 or str(parsed) != value:
            raise ValueError(f"Fixed-VHD {field} is invalid")
    return dict(report)


def validate_input_manifest(value):
    value = exact_fields(
        value,
        (
            "schema", "schema_version", "workload", "boot_policy",
            "raw_size", "provenance", "files", "qemu_support", "miz",
            "packaging", "implementation", "budget",
            "capability_reference", "private_build", "guarded",
        ),
        "Private-preflight input manifest",
    )
    if (
        value["schema"] != INPUT_SCHEMA
        or type(value["schema_version"]) is not int
        or value["schema_version"] != INPUT_SCHEMA_VERSION
        or value["workload"] != WORKLOAD
        or value["boot_policy"] not in BOOT_POLICIES
        or type(value["raw_size"]) is not int
        or value["raw_size"] != azure.VIRTUAL_SIZE
    ):
        raise ValueError("Private-preflight input manifest is incompatible")
    files = exact_fields(
        value["files"], ALL_ROLES, "Private-preflight input files"
    )
    files = {role: file_record(files[role], role) for role in ALL_ROLES}
    if (
        not isinstance(value["qemu_support"], list)
        or len(value["qemu_support"]) > 124
    ):
        raise ValueError("QEMU support closure must be a list")
    qemu_support = [support_record(record) for record in value["qemu_support"]]
    support_paths = [record["path"] for record in qemu_support]
    if support_paths != sorted(set(support_paths)):
        raise ValueError("QEMU support closure must be sorted and unique")
    if (
        files["raw"]["size"] != value["raw_size"]
        or files["capability_raw"]["size"] != value["raw_size"]
        or files["vhd"]["size"] != value["raw_size"] + 512
    ):
        raise ValueError("Private-preflight raw/fixed-VHD sizes are invalid")
    miz = exact_fields(
        value["miz"], ("name", "revision", "sha256", "size"),
        "Private-preflight miz fingerprint",
    )
    if (
        miz["name"] != "miz"
        or miz["revision"] != azure.MIZ_REVISION
        or type(miz["size"]) is not int
        or miz["size"] <= 0
    ):
        raise ValueError("Private-preflight miz contract is invalid")
    require_sha256(miz["sha256"], "Private-preflight miz fingerprint")
    provenance = validate_provenance(value["provenance"])
    guarded = validate_guarded_contract(
        value["guarded"], value["boot_policy"],
        provenance["config"]["sha256"],
    )
    capability_reference = validate_capability_reference(
        value["capability_reference"], files["capability_raw"]
    )
    private_build = validate_private_build(
        value["private_build"], provenance, files["efi"], guarded
    )
    implementation = validate_implementation(value["implementation"])
    budget = exact_fields(
        value["budget"],
        (
            "remote_input_bytes", "firmware_variable_copy_count",
            "firmware_working_copy_bytes",
            "control_payload_max_bytes",
            "evidence_max_bytes", "total_max_bytes", "remaining_bytes",
        ),
        "Private-preflight byte budget",
    )
    expected = expected_budget(files, qemu_support)
    if (
        any(type(budget[field]) is not int for field in budget)
        or dict(budget) != expected
        or expected["remaining_bytes"] < 0
    ):
        raise ValueError("Private-preflight staged files exceed 256 MiB")
    packaging = validate_packaging_report(
        value["packaging"], files["efi"]["sha256"], files["efi"]["size"],
        files["vhd"]["size"],
    )
    return {
        **value,
        "provenance": provenance,
        "guarded": guarded,
        "capability_reference": capability_reference,
        "private_build": private_build,
        "files": files,
        "qemu_support": qemu_support,
        "miz": dict(miz),
        "packaging": dict(packaging),
        "implementation": implementation,
        "budget": dict(budget),
    }


def private_directory(path, description, *, must_exist=True):
    path = path.absolute()
    if must_exist:
        resolved = path.resolve(strict=True)
        if resolved != path:
            raise ValueError(f"{description} must not contain symlinks")
        metadata = path.stat()
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or metadata.st_mode & 0o077
        ):
            raise ValueError(f"{description} must be owner-only")
    else:
        parent = path.parent.resolve(strict=True)
        if parent != path.parent:
            raise ValueError(f"{description} parent must not contain symlinks")
    return path


def sha256_prefix(path, length):
    digest = hashlib.sha256()
    remaining = length
    with path.open("rb") as source:
        while remaining:
            chunk = source.read(min(1024 * 1024, remaining))
            if not chunk:
                raise ValueError("Fixed VHD data region is truncated")
            digest.update(chunk)
            remaining -= len(chunk)
    return digest.hexdigest()


def regular_record(path, name, description):
    original = Path(path)
    metadata = original.lstat()
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
    ):
        raise ValueError(f"{description} must be a regular non-symlink file")
    path = original.resolve(strict=True)
    size = path.stat().st_size
    if not 0 < size <= host_runner.MAX_FILE_BYTES:
        raise ValueError(f"{description} has an invalid size")
    return {
        "name": name,
        "sha256": azure.image_sha256(path),
        "size": size,
    }


def directory_record(path, name, description):
    original = Path(path)
    metadata = original.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise ValueError(f"{description} must be a non-symlink directory")
    root = original.resolve(strict=True)
    digest = hashlib.sha256()
    count = 0
    total = 0
    for entry in sorted(root.rglob("*")):
        relative = entry.relative_to(root).as_posix()
        metadata = entry.lstat()
        if stat.S_ISLNK(metadata.st_mode):
            raise ValueError(f"{description} contains a symlink")
        if stat.S_ISDIR(metadata.st_mode):
            continue
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError(f"{description} contains a nonregular file")
        encoded = relative.encode()
        fingerprint = azure.image_sha256(entry)
        digest.update(len(encoded).to_bytes(4, "big"))
        digest.update(encoded)
        digest.update(metadata.st_size.to_bytes(8, "big"))
        digest.update(bytes.fromhex(fingerprint))
        count += 1
        total += metadata.st_size
    if count == 0:
        raise ValueError(f"{description} is empty")
    return {
        "name": name,
        "sha256": digest.hexdigest(),
        "size": total,
        "files": count,
    }


def git_runtime_record(path):
    original = Path(path)
    metadata = original.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise ValueError("Private Git runtime must be a non-symlink directory")
    root = original.resolve(strict=True)
    executable = None
    loader = None
    libraries = []
    for entry in sorted(root.rglob("*")):
        relative = entry.relative_to(root)
        metadata = entry.lstat()
        if stat.S_ISLNK(metadata.st_mode):
            raise ValueError("Private Git runtime must not contain symlinks")
        if stat.S_ISDIR(metadata.st_mode):
            if relative.parts not in (("bin",), ("lib",)):
                raise ValueError(
                    "Private Git runtime has an unsupported directory"
                )
            continue
        if not stat.S_ISREG(metadata.st_mode) or (
            relative != GIT_EXECUTABLE
            and (
                len(relative.parts) != 2
                or relative.parts[0] != "lib"
            )
        ):
            raise ValueError("Private Git runtime has an unsupported file")
        if relative in (GIT_EXECUTABLE, GIT_LOADER):
            if not os.access(entry, os.X_OK):
                raise ValueError(
                    "Private Git executable or loader is not executable"
                )
        with entry.open("rb") as stream:
            if stream.read(4) != b"\x7fELF":
                raise ValueError(
                    "Private Git runtime members must be native ELF files"
                )
        record = regular_record(
            entry, relative.as_posix(), "Private Git runtime member"
        )
        if relative == GIT_EXECUTABLE:
            executable = record
        elif relative == GIT_LOADER:
            loader = record
        else:
            libraries.append(record)
    if executable is None or loader is None or not libraries:
        raise ValueError(
            "Private Git runtime requires bin/git, lib/loader, and libraries"
        )
    runtime = directory_record(
        root, GIT_RUNTIME, "Private Git runtime"
    )
    return {
        "schema": GIT_RUNTIME_SCHEMA,
        **runtime,
        "executable": executable,
        "loader": loader,
        "libraries": libraries,
    }


def validate_tool_record(value, expected_name):
    value = exact_fields(
        value, ("name", "sha256", "size", "files"),
        "Private build tool fingerprint",
    )
    if (
        value["name"] != expected_name
        or type(value["size"]) is not int
        or value["size"] <= 0
        or type(value["files"]) is not int
        or value["files"] <= 0
    ):
        raise ValueError("Private build tool fingerprint is invalid")
    require_sha256(value["sha256"], "Private build tool fingerprint")
    return dict(value)


def validate_capability_reference(value, capability_raw):
    value = exact_fields(
        value, ("name", "sha256", "size", "receipt"),
        "Public capability reference",
    )
    if (
        value["name"] != CAPABILITY_REFERENCE
        or type(value["size"]) is not int
        or not 0 < value["size"] <= MAX_MANIFEST_BYTES
    ):
        raise ValueError("Public capability reference is invalid")
    require_sha256(value["sha256"], "Public capability reference")
    receipt = exact_fields(
        value["receipt"],
        (
            "schema", "schema_version", "scope", "source",
            "manifest_sha256", "efi_sha256", "raw", "source_vhd",
            "source_boot_evidence",
        ),
        "Public capability receipt",
    )
    if (
        receipt["schema"] != CAPABILITY_REFERENCE_SCHEMA
        or type(receipt["schema_version"]) is not int
        or receipt["schema_version"] != 1
        or receipt["scope"] != (
            "historical nonsecret capability only; "
            "not current private deployment provenance"
        )
    ):
        raise ValueError("Public capability receipt is incompatible")
    source = exact_fields(
        receipt["source"],
        (
            "provider", "repository", "repository_id", "workflow_ref",
            "head_sha", "run_id", "run_attempt", "job",
        ),
        "Public capability source",
    )
    if (
        source["provider"] != "github-actions"
        or not isinstance(source["repository"], str)
        or not re.fullmatch(
            r"[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}",
            source["repository"],
        )
        or type(source["repository_id"]) is not int
        or source["repository_id"] <= 0
        or not isinstance(source["workflow_ref"], str)
        or not source["workflow_ref"].startswith(
            source["repository"] + "/.github/workflows/"
        )
        or not GIT_COMMIT.fullmatch(source["head_sha"])
        or type(source["run_id"]) is not int
        or source["run_id"] <= 0
        or type(source["run_attempt"]) is not int
        or source["run_attempt"] <= 0
        or not isinstance(source["job"], str)
        or not re.fullmatch(r"[A-Za-z0-9_.-]{1,100}", source["job"])
    ):
        raise ValueError("Public capability source is invalid")
    require_sha256(
        receipt["manifest_sha256"], "Public capability manifest"
    )
    require_sha256(receipt["efi_sha256"], "Public capability EFI")
    raw = exact_fields(
        receipt["raw"], ("sha256", "size"), "Public capability raw image"
    )
    source_vhd = exact_fields(
        receipt["source_vhd"], ("sha256", "size"),
        "Public capability fixed VHD",
    )
    if (
        raw != {
            "sha256": capability_raw["sha256"],
            "size": capability_raw["size"],
        }
        or type(source_vhd["size"]) is not int
        or source_vhd["size"] != capability_raw["size"] + 512
    ):
        raise ValueError("Public capability image binding is invalid")
    require_sha256(source_vhd["sha256"], "Public capability fixed VHD")
    evidence = exact_fields(
        receipt["source_boot_evidence"],
        ("boots", "platform_marker", "scope"),
        "Public capability boot evidence",
    )
    if (
        evidence["platform_marker"] != host_runner.PLATFORM_MARKER
        or evidence["scope"] != "platform-only"
    ):
        raise ValueError("Public capability boot evidence is invalid")
    boots = exact_fields(
        evidence["boots"], ("raw", "vhd"), "Public capability boot formats"
    )
    for image, modes in boots.items():
        modes = exact_fields(
            modes, ("legacy-apic", "x2apic"),
            "Public capability boot modes",
        )
        for mode, outcome in modes.items():
            outcome = exact_fields(
                outcome, ("apic_path", "io_ready", "platform_ready"),
                "Public capability boot outcome",
            )
            expected_apic = (
                "legacy-xapic" if mode == "legacy-apic" else "x2apic"
            )
            if outcome != {
                "apic_path": expected_apic,
                "io_ready": False,
                "platform_ready": True,
            }:
                raise ValueError(
                    "Public capability boot outcome is invalid"
                )
    validated = {
        **value,
        "receipt": {
            **receipt,
            "source": dict(source),
            "raw": dict(raw),
            "source_vhd": dict(source_vhd),
            "source_boot_evidence": {
                **evidence,
                "boots": {
                    image: {
                        mode: dict(outcome)
                        for mode, outcome in image_modes.items()
                    }
                    for image, image_modes in boots.items()
                },
            },
        },
    }
    if validated != APPROVED_CAPABILITY_REFERENCE:
        raise ValueError(
            "Public capability reference is not the reviewed known-good source"
        )
    return validated


def validate_private_build(value, provenance, efi, expected_guarded=None):
    value = exact_fields(
        value, ("name", "sha256", "size", "receipt"),
        "Private local build receipt",
    )
    if (
        value["name"] != PRIVATE_BUILD_RECEIPT
        or type(value["size"]) is not int
        or not 0 < value["size"] <= MAX_MANIFEST_BYTES
    ):
        raise ValueError("Private local build receipt is invalid")
    require_sha256(value["sha256"], "Private local build receipt")
    receipt = exact_fields(
        value["receipt"],
        (
            "schema", "schema_version", "result", "source_before",
            "source_after", "invocation", "tools", "output",
            "builder_sha256", "guarded",
        ),
        "Private local build receipt",
    )
    before = validate_provenance(receipt["source_before"])
    after = validate_provenance(receipt["source_after"])
    if (
        receipt["schema"] != PRIVATE_BUILD_SCHEMA
        or type(receipt["schema_version"]) is not int
        or receipt["schema_version"] != PRIVATE_BUILD_SCHEMA_VERSION
        or receipt["result"] != "PASS"
        or before != provenance
        or after != provenance
        or require_sha256(
            receipt["builder_sha256"], "Private build implementation"
        ) != azure.image_sha256(Path(__file__))
    ):
        raise ValueError("Private local build provenance is incompatible")
    guarded = validate_guarded_contract(
        receipt["guarded"],
        GUARDED_BOOT_POLICY if receipt["guarded"] is not None
        else "platform-unavailable-v1",
        provenance["config"]["sha256"],
    )
    if guarded != expected_guarded:
        raise ValueError(
            "Private local build guarded contract is unrelated to the policy"
        )
    invocation = exact_fields(
        receipt["invocation"],
        (
            "engine", "passes", "jobs", "materialization_returncode",
            "recovery", "recovery_returncode", "verification_returncode",
            "app", "profile", "compiler_target", "output",
        ),
        "Private local build invocation",
    )
    expected_invocation = {
        "engine": "zig-native-images-two-pass-v1",
        "passes": 2,
        "jobs": 2,
        "app": "support/apps/hyperv-acceptance",
        "profile": "hyperv-x86_64-efi-netvsc",
        "compiler_target": "x86_64-freestanding-none",
        "output": NATIVE_EFI_NAME,
    }
    materialization_returncode = invocation["materialization_returncode"]
    recovery = invocation["recovery"]
    recovery_returncode = invocation["recovery_returncode"]
    verification_returncode = invocation["verification_returncode"]
    if (
        type(materialization_returncode) is not int
        or materialization_returncode != 0
        or recovery not in ("none", "uk-reloc-v1")
        or (recovery == "none" and recovery_returncode is not None)
        or (
            recovery == "uk-reloc-v1"
            and (
                type(recovery_returncode) is not int
                or recovery_returncode != 0
            )
        )
        or type(verification_returncode) is not int
        or verification_returncode != 0
        or {
            key: value for key, value in invocation.items()
            if key not in (
                "materialization_returncode", "recovery",
                "recovery_returncode", "verification_returncode",
            )
        } != expected_invocation
    ):
        raise ValueError("Private local build invocation is incompatible")
    tools = exact_fields(
        receipt["tools"], BUILD_TOOL_NAMES, "Private local build tools"
    )
    tools = {
        name: (
            validate_git_runtime_record(tools[name])
            if name == "git"
            else validate_tool_record(tools[name], name)
        )
        for name in BUILD_TOOL_NAMES
    }
    if tools["git"] != provenance["git"]:
        raise ValueError(
            "Private build Git runtime is unrelated to provenance"
        )
    output = exact_fields(
        receipt["output"], ("name", "sha256", "size"),
        "Private local build output",
    )
    if output != {
        "name": NATIVE_EFI_NAME,
        "sha256": efi["sha256"],
        "size": efi["size"],
    }:
        raise ValueError("Private local build output is unrelated to the EFI")
    return {
        **value,
        "receipt": {
            **receipt,
            "source_before": before,
            "source_after": after,
            "invocation": dict(invocation),
            "tools": tools,
            "output": dict(output),
            "guarded": guarded,
        },
    }


def load_receipt(path, name, description):
    record = regular_record(path, name, description)
    if record["size"] > MAX_MANIFEST_BYTES:
        raise ValueError(f"{description} is too large")
    raw = azure.read_regular_file(path, MAX_MANIFEST_BYTES, description)
    return {
        **record,
        "receipt": azure.parse_strict_json(raw, description),
    }


def git_environment(git_runtime, isolate_path=True):
    environment = {
        name: value for name, value in os.environ.items()
        if not name.startswith("GIT_")
        and not name.startswith("LD_")
        and name not in ("GCONV_PATH", "GLIBC_TUNABLES", "LOCPATH")
    }
    environment.update({
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_EXEC_PATH": str(Path(git_runtime) / "disabled-exec-path"),
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "HOME": str(Path(git_runtime) / "disabled-home"),
        "XDG_CONFIG_HOME": str(Path(git_runtime) / "disabled-xdg-config"),
        "OPENSSL_CONF": os.devnull,
        "OPENSSL_MODULES": str(
            Path(git_runtime) / "disabled-openssl-modules"
        ),
        "LC_ALL": "C",
    })
    if isolate_path:
        environment["PATH"] = str(Path(git_runtime) / "disabled-path")
    return environment


def bounded_command_output(argv, cwd, environment, timeout, maximum):
    process = subprocess.Popen(
        argv, cwd=cwd, stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env=environment, start_new_session=True,
    )
    outputs = {"stdout": bytearray(), "stderr": bytearray()}
    overflow = threading.Event()
    lock = threading.Lock()
    total = 0

    def drain(name, stream):
        nonlocal total
        for chunk in iter(lambda: stream.read(64 * 1024), b""):
            with lock:
                remaining = maximum - total
                outputs[name].extend(chunk[:max(0, remaining)])
                total += min(len(chunk), max(0, remaining))
                if len(chunk) > remaining:
                    overflow.set()
            if overflow.is_set():
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass

    readers = [
        threading.Thread(target=drain, args=("stdout", process.stdout)),
        threading.Thread(target=drain, args=("stderr", process.stderr)),
    ]
    for reader in readers:
        reader.start()
    try:
        returncode = process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait()
        for reader in readers:
            reader.join()
        process.stdout.close()
        process.stderr.close()
        raise ValueError("Private Git runtime command timed out") from None
    for reader in readers:
        reader.join()
    process.stdout.close()
    process.stderr.close()
    return (
        returncode, bytes(outputs["stdout"]), bytes(outputs["stderr"]),
        overflow.is_set(),
    )


def git_runtime_command(git_runtime, arguments):
    git_runtime = Path(git_runtime)
    return [
        str(git_runtime / GIT_LOADER),
        "--inhibit-cache",
        "--library-path", str(git_runtime / "lib"),
        str(git_runtime / GIT_EXECUTABLE),
        "--no-replace-objects",
        "-c", "core.fsmonitor=false",
        "-c", "core.hooksPath=/dev/null",
        *arguments,
    ]


def validate_git_runtime_resolution(git_runtime, record):
    git_runtime = Path(git_runtime).resolve(strict=True)
    returncode, stdout, stderr, overflow = bounded_command_output(
        [
            str(git_runtime / GIT_LOADER),
            "--inhibit-cache",
            "--library-path", str(git_runtime / "lib"),
            "--list", str(git_runtime / GIT_EXECUTABLE),
        ],
        git_runtime, git_environment(git_runtime), 30, 16 * 1024,
    )
    if returncode or stderr or overflow:
        raise ValueError(
            "Private Git runtime dependency resolution is invalid"
        )
    expected = {
        record["loader"]["name"],
        *(library["name"] for library in record["libraries"]),
    }
    resolved = []
    for line in stdout.splitlines():
        if re.fullmatch(rb"\s*linux-vdso\.so\.1 \(0x[0-9a-fA-F]+\)", line):
            continue
        match = re.fullmatch(
            rb"\s*(\S+) => (.+) \(0x[0-9a-fA-F]+\)", line
        )
        direct = None
        if match is None:
            direct = re.fullmatch(
                rb"\s*(/.+) \(0x[0-9a-fA-F]+\)", line
            )
            if direct is None:
                raise ValueError(
                    "Private Git runtime dependency resolution is invalid"
                )
            dependency = None
            path_bytes = direct.group(1)
        else:
            dependency = match.group(1)
            path_bytes = match.group(2)
        path = Path(os.fsdecode(path_bytes)).resolve(strict=True)
        try:
            relative = path.relative_to(git_runtime).as_posix()
        except ValueError:
            raise ValueError(
                "Private Git runtime resolved an ambient dependency"
            ) from None
        if relative not in expected:
            raise ValueError(
                "Private Git runtime resolved an unknown dependency"
            )
        if (
            relative != GIT_LOADER.as_posix()
            and dependency != os.fsencode(path.name)
        ):
            raise ValueError(
                "Private Git runtime dependency identity is invalid"
            )
        resolved.append(relative)
    if len(resolved) != len(set(resolved)) or set(resolved) != expected:
        raise ValueError(
            "Private Git runtime dependency closure is incomplete"
        )


def preflight_git_runtime(git_runtime):
    git_runtime = Path(git_runtime).resolve(strict=True)
    before = validate_git_runtime_record(
        git_runtime_record(git_runtime)
    )
    validate_git_runtime_resolution(git_runtime, before)
    returncode, stdout, stderr, overflow = bounded_command_output(
        git_runtime_command(git_runtime, ["--version"]),
        git_runtime, git_environment(git_runtime), 30, 256,
    )
    after = validate_git_runtime_record(git_runtime_record(git_runtime))
    if (
        returncode
        or stderr
        or overflow
        or not re.fullmatch(rb"git version [0-9][ -~]{0,200}\n", stdout)
        or after != before
    ):
        raise ValueError(
            "Private Git runtime is not a relocatable Git executable"
        )
    validate_git_runtime_resolution(git_runtime, after)
    return before


def git_output(git_runtime, repository, arguments):
    git_runtime = Path(git_runtime).resolve(strict=True)
    before = validate_git_runtime_record(
        git_runtime_record(git_runtime)
    )
    returncode, stdout, stderr, overflow = bounded_command_output(
        git_runtime_command(
            git_runtime, ["-C", str(repository), *arguments]
        ),
        repository, git_environment(git_runtime), 60, 8 * 1024 * 1024,
    )
    after = validate_git_runtime_record(git_runtime_record(git_runtime))
    if after != before:
        raise RuntimeError("Private Git runtime changed while in use")
    validate_git_runtime_resolution(git_runtime, after)
    if returncode or stderr or overflow:
        raise RuntimeError("Unable to derive local Git source provenance")
    return stdout


def parse_git_tree(raw):
    records = []
    seen = set()
    for item in raw.split(b"\0"):
        if not item:
            continue
        prefix, separator, path = item.partition(b"\t")
        fields = prefix.split(b" ")
        if (
            separator != b"\t"
            or len(fields) != 3
            or fields[0] not in (b"100644", b"100755", b"120000")
            or fields[1] != b"blob"
            or not re.fullmatch(rb"(?:[0-9a-f]{40}|[0-9a-f]{64})", fields[2])
            or not path
            or path.startswith(b"/")
            or any(part in (b"", b".", b"..") for part in path.split(b"/"))
            or path in seen
        ):
            raise ValueError("Tracked Git tree is unsupported or ambiguous")
        seen.add(path)
        records.append((path, fields[0], fields[2]))
        if len(records) > MAX_TRACKED_ENTRIES:
            raise ValueError("Tracked Git tree exceeds the entry limit")
    if not records:
        raise ValueError("Tracked Git tree is empty")
    return records


def verify_git_index(git_runtime, repository, tree_records):
    expected = {
        path: (mode, object_id)
        for path, mode, object_id in tree_records
    }
    staged = {}
    raw = git_output(
        git_runtime, repository, ["ls-files", "-s", "-z"]
    )
    for item in raw.split(b"\0"):
        if not item:
            continue
        prefix, separator, path = item.partition(b"\t")
        fields = prefix.split(b" ")
        if (
            separator != b"\t"
            or len(fields) != 3
            or fields[2] != b"0"
            or path in staged
        ):
            raise ValueError("Git index state is unsupported or ambiguous")
        staged[path] = (fields[0], fields[1])
    if staged != expected:
        raise ValueError("Git index differs from the claimed HEAD tree")
    flags = {}
    raw = git_output(
        git_runtime, repository, ["ls-files", "-v", "-z"]
    )
    for item in raw.split(b"\0"):
        if not item:
            continue
        if len(item) < 3 or item[1:2] != b" " or item[2:] in flags:
            raise ValueError("Git index flags are unsupported or ambiguous")
        flags[item[2:]] = item[:1]
    if set(flags) != set(expected) or any(
        flag != b"H" for flag in flags.values()
    ):
        raise ValueError(
            "Git index concealment flags or nonstandard entries are forbidden"
        )


def stable_metadata(value):
    return (
        value.st_dev, value.st_ino, value.st_mode, value.st_size,
        value.st_mtime_ns, value.st_ctime_ns,
    )


def hash_physical_git_blob(root_fd, path, mode, expected_object):
    if not hasattr(os, "O_NOFOLLOW"):
        raise ValueError("Physical Git tree verification requires O_NOFOLLOW")
    components = path.split(b"/")
    parent_fd = os.dup(root_fd)
    try:
        for component in components[:-1]:
            child_fd = os.open(
                component,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=parent_fd,
            )
            os.close(parent_fd)
            parent_fd = child_fd
        name = components[-1]
        before = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        digest = (
            hashlib.sha1() if len(expected_object) == 40
            else hashlib.sha256()
        )
        if mode == b"120000":
            if not stat.S_ISLNK(before.st_mode):
                raise ValueError("Tracked Git symlink type changed")
            content = os.readlink(name, dir_fd=parent_fd)
            if isinstance(content, str):
                content = os.fsencode(content)
            after = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            if stable_metadata(before) != stable_metadata(after):
                raise ValueError("Tracked Git symlink changed while hashing")
            size = len(content)
            digest.update(f"blob {size}\0".encode())
            digest.update(content)
        else:
            if (
                not stat.S_ISREG(before.st_mode)
                or bool(before.st_mode & 0o111) != (mode == b"100755")
            ):
                raise ValueError("Tracked Git file type or mode changed")
            descriptor = os.open(
                name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent_fd
            )
            try:
                opened = os.fstat(descriptor)
                if stable_metadata(opened) != stable_metadata(before):
                    raise ValueError("Tracked Git file changed before hashing")
                size = opened.st_size
                if not 0 <= size <= MAX_TRACKED_FILE_BYTES:
                    raise ValueError("Tracked Git file exceeds the size limit")
                digest.update(f"blob {size}\0".encode())
                while True:
                    chunk = os.read(descriptor, 1024 * 1024)
                    if not chunk:
                        break
                    digest.update(chunk)
                after = os.fstat(descriptor)
                if stable_metadata(opened) != stable_metadata(after):
                    raise ValueError("Tracked Git file changed while hashing")
            finally:
                os.close(descriptor)
        if not 0 <= size <= MAX_TRACKED_FILE_BYTES:
            raise ValueError("Tracked Git blob exceeds the size limit")
        actual = digest.hexdigest().encode()
        if actual != expected_object:
            raise ValueError(
                "Physical tracked source differs from the claimed HEAD tree"
            )
        return size
    except OSError as error:
        raise ValueError(
            "Physical tracked source cannot be verified safely"
        ) from error
    finally:
        os.close(parent_fd)


def verify_physical_git_tree(repository, tree_records):
    if not hasattr(os, "O_NOFOLLOW"):
        raise ValueError("Physical Git tree verification requires O_NOFOLLOW")
    root_fd = os.open(
        os.fsencode(repository),
        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
    )
    aggregate = hashlib.sha256()
    total = 0
    try:
        for path, mode, object_id in tree_records:
            size = hash_physical_git_blob(
                root_fd, path, mode, object_id
            )
            total += size
            if total > MAX_TRACKED_BYTES:
                raise ValueError("Tracked Git tree exceeds the byte limit")
            aggregate.update(len(path).to_bytes(4, "big"))
            aggregate.update(path)
            aggregate.update(mode)
            aggregate.update(size.to_bytes(8, "big"))
            aggregate.update(bytes.fromhex(object_id.decode()))
    finally:
        os.close(root_fd)
    return {
        "physical_sha256": aggregate.hexdigest(),
        "tracked_entries": len(tree_records),
        "tracked_bytes": total,
    }


def build_provenance(repository, config_path, git_runtime):
    repository = repository.resolve(strict=True)
    if repository != SUPPORT.parent.resolve(strict=True):
        raise ValueError("Source provenance must use this repository worktree")
    git_runtime = Path(git_runtime).resolve(strict=True)
    git = preflight_git_runtime(git_runtime)
    if git_output(
        git_runtime, repository,
        ["for-each-ref", "--format=%(refname)%00", "refs/replace/"],
    ):
        raise ValueError("Git object replacement refs are forbidden")
    if git_output(
        git_runtime, repository,
        ["status", "--porcelain=v1", "--untracked-files=all", "-z"],
    ):
        raise ValueError("Source provenance requires a clean tracked worktree")
    head = git_output(
        git_runtime, repository, ["rev-parse", "--verify", "HEAD^{commit}"]
    ).decode().strip()
    if not GIT_COMMIT.fullmatch(head):
        raise ValueError("Git HEAD identity is invalid")
    tree = git_output(
        git_runtime, repository,
        ["ls-tree", "-r", "--full-tree", "-z", head],
    )
    tree_records = parse_git_tree(tree)
    if any(len(object_id) != len(head) for _, _, object_id in tree_records):
        raise ValueError("Git object format changed within the claimed tree")
    verify_git_index(git_runtime, repository, tree_records)
    physical = verify_physical_git_tree(repository, tree_records)
    verify_git_index(git_runtime, repository, tree_records)
    final_head = git_output(
        git_runtime, repository, ["rev-parse", "--verify", "HEAD^{commit}"]
    ).decode().strip()
    final_status = git_output(
        git_runtime, repository,
        ["status", "--porcelain=v1", "--untracked-files=all", "-z"],
    )
    if (
        final_head != head
        or final_status
        or not tree
        or preflight_git_runtime(git_runtime) != git
    ):
        raise ValueError("Git source provenance is invalid")
    config = regular_record(config_path, SOLVED_CONFIG, "Solved configuration")
    return {
        "scheme": "unikraft.git-physical-tree-v2",
        "head_commit": head,
        "tree_sha256": hashlib.sha256(tree).hexdigest(),
        **physical,
        "config": config,
        "git": git,
    }


def local_tool_record(path, name):
    path = Path(path).resolve(strict=True)
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode):
        raise ValueError(f"Private build tool {name} is not a regular file")
    return {
        "name": name,
        "sha256": azure.image_sha256(path),
        "size": metadata.st_size,
        "files": 1,
    }


def write_tool_wrapper(path, executable, environment=None):
    lines = ["#!/bin/sh", "set -eu"]
    for name, value in (environment or {}).items():
        lines.append(f"export {name}={shlex.quote(str(value))}")
    lines.append(f"exec {shlex.quote(str(executable))} \"$@\"")
    save_private_bytes(path, ("\n".join(lines) + "\n").encode())
    path.chmod(0o700)


def write_git_wrapper(path, git_runtime):
    environment = git_environment(git_runtime)
    lines = ["#!/bin/sh", "set -eu"]
    for name in (
        "GIT_CONFIG_NOSYSTEM", "GIT_CONFIG_GLOBAL", "GIT_EXEC_PATH",
        "GIT_OPTIONAL_LOCKS", "GIT_NO_REPLACE_OBJECTS", "HOME",
        "XDG_CONFIG_HOME", "OPENSSL_CONF", "OPENSSL_MODULES", "LC_ALL",
        "PATH",
    ):
        lines.append(
            f"export {name}={shlex.quote(str(environment[name]))}"
        )
    lines.append(
        "exec "
        + " ".join(
            shlex.quote(value)
            for value in git_runtime_command(git_runtime, [])
        )
        + ' "$@"'
    )
    save_private_bytes(path, ("\n".join(lines) + "\n").encode())
    path.chmod(0o700)


def build_private_image(
    output_directory, repository, config_path, zig_path, make_path,
    python_path, bison_path, flex_path, m4_path, bison_data,
    llvm_directory, git_runtime, timeout,
):
    if type(timeout) is not int or not 1 <= timeout <= 3600:
        raise ValueError("Private local build timeout must be 1-3600 seconds")
    repository = Path(repository).resolve(strict=True)
    output_directory = private_directory(
        output_directory, "Private local build directory", must_exist=False
    )
    output_directory.mkdir(mode=0o700, parents=True, exist_ok=False)
    relocated_git = output_directory / GIT_RUNTIME
    git_record = copy_git_runtime(git_runtime, relocated_git)
    source_before = build_provenance(
        repository, config_path, relocated_git
    )
    guarded = guarded_contract_from_solved_config(config_path)
    if guarded is not None:
        verify_guarded_producer_sources(repository)
        guarded = validate_guarded_contract(
            guarded, GUARDED_BOOT_POLICY,
            source_before["config"]["sha256"],
        )
    tools = {
        "git": git_record,
        "zig": local_tool_record(zig_path, "zig"),
        "make": local_tool_record(make_path, "make"),
        "python": local_tool_record(python_path, "python"),
        "bison": local_tool_record(bison_path, "bison"),
        "flex": local_tool_record(flex_path, "flex"),
        "m4": local_tool_record(m4_path, "m4"),
    }
    if tools["git"] != source_before["git"]:
        raise ValueError("Private Git runtime changed before native build")
    zig_invocation = Path(zig_path).absolute()
    resolved = {
        "git_runtime": relocated_git,
        "git": relocated_git / GIT_EXECUTABLE,
        "zig": zig_invocation,
        "make": Path(make_path).resolve(strict=True),
        "python": Path(python_path).resolve(strict=True),
        "bison": Path(bison_path).resolve(strict=True),
        "flex": Path(flex_path).resolve(strict=True),
        "m4": Path(m4_path).resolve(strict=True),
    }
    llvm_directory = Path(llvm_directory).resolve(strict=True)
    for name in (
        "llvm-nm", "llvm-objcopy", "llvm-objdump", "llvm-readelf",
        "llvm-strip",
    ):
        path = llvm_directory / name
        path.resolve(strict=True)
        tools[name] = local_tool_record(path, name)
        resolved[name] = path
    tools["bison-data"] = directory_record(
        bison_data, "bison-data", "Private build Bison data"
    )
    config = output_directory / SOLVED_CONFIG
    build_output = output_directory / "build"
    wrappers = output_directory / ".tool-bin"
    temporary = output_directory / "tmp"
    cache = output_directory / "cache"
    home = output_directory / "home"
    wrappers.mkdir(mode=0o700)
    temporary.mkdir(mode=0o700)
    cache.mkdir(mode=0o700)
    home.mkdir(mode=0o700)
    copy_record(
        Path(config_path).resolve(strict=True), config,
        source_before["config"],
    )
    wrapper_tools = {
        "zig": ("zig", None),
        "make": ("make", None),
        "python3": ("python", None),
        "bison": (
            "bison",
            {
                "BISON_PKGDATADIR": Path(bison_data).resolve(strict=True),
                "M4": resolved["m4"],
            },
        ),
        "yacc": (
            "bison",
            {
                "BISON_PKGDATADIR": Path(bison_data).resolve(strict=True),
                "M4": resolved["m4"],
            },
        ),
        "flex": ("flex", {"M4": resolved["m4"]}),
        "lex": ("flex", {"M4": resolved["m4"]}),
        "llvm-nm": ("llvm-nm", None),
        "llvm-objcopy": ("llvm-objcopy", None),
        "llvm-objdump": ("llvm-objdump", None),
        "llvm-readelf": ("llvm-readelf", None),
        "llvm-strip": ("llvm-strip", None),
    }
    write_git_wrapper(wrappers / "git", resolved["git_runtime"])
    for wrapper, (tool, environment) in wrapper_tools.items():
        write_tool_wrapper(
            wrappers / wrapper, resolved[tool], environment
        )
    zig = str(zig_invocation)
    command = [
        zig, "build", "native-images", "-j2",
        "-Dapp=" + str(SUPPORT / "apps" / "hyperv-acceptance"),
        "-Dconfig=" + str(config),
        "-Doutput=" + str(build_output),
        "-Dnative-profile=hyperv-x86_64-efi-netvsc",
        f"-Dcompiler={zig} cc -target x86_64-freestanding-none",
        "-Dcompiler-targeted=true",
        f"-Dhost-cc={zig} cc",
        f"-Dhost-cxx={zig} c++",
        "-Dhost-cflags=-fno-sanitize=null",
        f"-Dmake-arg=AR={zig} ar",
        "-Dmake-arg=NM=llvm-nm",
        "-Dmake-arg=OBJCOPY=llvm-objcopy",
        "-Dmake-arg=OBJDUMP=llvm-objdump",
        "-Dmake-arg=READELF=llvm-readelf",
        "-Dmake-arg=STRIP=llvm-strip",
        "-Dmake-arg=UK_CFLAGS=-std=gnu17",
        "-Dmake-arg=UK_LDFLAGS=-rtlib=compiler-rt",
    ]
    environment = git_environment(relocated_git, isolate_path=False)
    environment.pop("OPENSSL_CONF")
    environment.pop("OPENSSL_MODULES")
    environment.update({
        "PATH": str(wrappers) + os.pathsep + environment.get("PATH", ""),
        "TMPDIR": str(temporary),
        "XDG_CACHE_HOME": str(cache / "xdg"),
        "ZIG_GLOBAL_CACHE_DIR": str(cache / "zig-global"),
        "ZIG_LOCAL_CACHE_DIR": str(cache / "zig-local"),
        "PYTHONPYCACHEPREFIX": str(cache / "pycache"),
        "HOME": str(home),
        "XDG_CONFIG_HOME": str(cache / "xdg-config"),
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_EXEC_PATH": str(relocated_git / "disabled-exec-path"),
        "GIT_OPTIONAL_LOCKS": "0",
        "BISON_PKGDATADIR": str(Path(bison_data).resolve(strict=True)),
        "M4": str(resolved["m4"]),
        "LC_ALL": "C",
    })

    log_path = output_directory / "build.log"
    with log_path.open("xb") as log:
        os.chmod(log_path, 0o600)
        overflow = threading.Event()
        written = 0
        deadline = time.monotonic() + timeout

        def run_process(argv, label):
            nonlocal written
            header = f"=== {label} ===\n".encode()
            if written + len(header) > 8 * 1024 * 1024:
                raise RuntimeError(
                    "Private local native build log exceeded 8 MiB"
                )
            log.write(header)
            written += len(header)
            process = subprocess.Popen(
                argv, cwd=repository, stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                env=environment, start_new_session=True,
            )
            output = bytearray()

            def drain_output():
                nonlocal written
                for chunk in iter(
                    lambda: process.stdout.read(64 * 1024), b""
                ):
                    remaining = 8 * 1024 * 1024 - written
                    if remaining > 0:
                        log.write(chunk[:remaining])
                        written += min(len(chunk), remaining)
                    if len(chunk) <= remaining:
                        output.extend(chunk)
                    if len(chunk) > remaining:
                        overflow.set()
                        try:
                            os.killpg(process.pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass

            reader = threading.Thread(target=drain_output, daemon=True)
            reader.start()
            try:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise subprocess.TimeoutExpired(argv, timeout)
                returncode = process.wait(timeout=remaining)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait()
                reader.join()
                process.stdout.close()
                raise RuntimeError(
                    "Private local native build timed out"
                ) from None
            reader.join()
            process.stdout.close()
            if overflow.is_set():
                raise RuntimeError(
                    "Private local native build log exceeded 8 MiB"
                )
            return returncode, bytes(output)

        def failure_commands(output, label):
            try:
                text = output.decode("utf-8")
            except UnicodeDecodeError:
                raise RuntimeError(
                    f"Private local native {label} output is not UTF-8"
                ) from None
            failed = []
            for line in text.splitlines():
                if "failed command:" not in line:
                    continue
                if (
                    not line.startswith("failed command: ")
                    or line.count("failed command:") != 1
                    or not line[len("failed command: "):]
                ):
                    raise RuntimeError(
                        f"Private local native {label} failure evidence "
                        "is ambiguous"
                    )
                failed.append(line[len("failed command: "):])
            return failed

        materialization_returncode, materialization_output = run_process(
            command,
            "native build materialization pass"
        )
        recovery = "none"
        recovery_returncode = None
        failed = failure_commands(
            materialization_output, "materialization pass"
        )
        if materialization_returncode:
            raise RuntimeError(
                "Private local native build failed before verification"
            )
        if failed:
            if len(failed) != 1:
                raise RuntimeError(
                    "Private local native build failed before verification"
                )
            failed_argv = shlex.split(failed[0])
            expected_prefix = [
                "PYTHON=python3",
                "python3",
                str(NATIVE_POSTPROCESS_RUNNER_PATH),
                "uk-reloc",
                "--script",
                str(UK_RELOC_SCRIPT_PATH),
                "--nm",
                "llvm-nm",
                "--readelf",
                "llvm-readelf",
                "--objcopy",
                "llvm-objcopy",
            ]
            if failed_argv[:len(expected_prefix)] != expected_prefix or (
                len(failed_argv) != len(expected_prefix) + 3
            ):
                raise RuntimeError(
                    "Private local native build failed before verification"
                )
            generated = []
            cache_root = cache.resolve(strict=True)
            for value in failed_argv[-3:]:
                candidate = Path(value)
                if not candidate.is_absolute():
                    candidate = repository / candidate
                if candidate.is_symlink():
                    raise RuntimeError(
                        "Private local native build recovery path is invalid"
                    )
                candidate = candidate.resolve(strict=True)
                try:
                    candidate.relative_to(cache_root)
                except ValueError:
                    raise RuntimeError(
                        "Private local native build recovery path is invalid"
                    ) from None
                if not candidate.is_file():
                    raise RuntimeError(
                        "Private local native build recovery path is invalid"
                    )
                generated.append(candidate)
            input_path, relocations_path, output_path = generated
            if (
                input_path.name != "hyperv-validated-final.dbg"
                or output_path.name != NATIVE_EFI_NAME + ".dbg"
                or relocations_path != Path(str(output_path) + ".uk_reloc.bin")
            ):
                raise RuntimeError(
                    "Private local native build recovery path is invalid"
                )
            recovery_command = [
                str(resolved["python"]),
                str(NATIVE_POSTPROCESS_RUNNER_PATH),
                "uk-reloc",
                "--script",
                str(UK_RELOC_SCRIPT_PATH),
                "--nm",
                "llvm-nm",
                "--readelf",
                "llvm-readelf",
                "--objcopy",
                "llvm-objcopy",
                str(input_path),
                str(relocations_path),
                str(output_path),
            ]
            recovery_returncode, recovery_output = run_process(
                recovery_command, "bounded native uk-reloc recovery"
            )
            if (
                recovery_returncode
                or failure_commands(recovery_output, "recovery pass")
            ):
                raise RuntimeError(
                    "Private local native build recovery failed"
                )
            recovery = "uk-reloc-v1"
        verification_returncode, verification_output = run_process(
            command, "native build verification pass"
        )
        log.flush()
        os.fsync(log.fileno())
    if (
        verification_returncode
        or failure_commands(verification_output, "verification pass")
    ):
        raise RuntimeError(
            "Private local native build failed; inspect its owner-only log"
        )
    source_after = build_provenance(
        repository, config, resolved["git_runtime"]
    )
    if source_after != source_before:
        raise RuntimeError("Private source or configuration changed during build")
    if local_tool_record(zig_invocation, "zig") != tools["zig"]:
        raise RuntimeError("Private Zig compiler changed during build")
    efi_path = build_output / NATIVE_EFI_NAME
    output = regular_record(
        efi_path, NATIVE_EFI_NAME, "Private local EFI build output"
    )
    receipt = {
        "schema": PRIVATE_BUILD_SCHEMA,
        "schema_version": PRIVATE_BUILD_SCHEMA_VERSION,
        "result": "PASS",
        "source_before": source_before,
        "source_after": source_after,
        "invocation": {
            "engine": "zig-native-images-two-pass-v1",
            "passes": 2,
            "jobs": 2,
            "materialization_returncode": materialization_returncode,
            "recovery": recovery,
            "recovery_returncode": recovery_returncode,
            "verification_returncode": verification_returncode,
            "app": "support/apps/hyperv-acceptance",
            "profile": "hyperv-x86_64-efi-netvsc",
            "compiler_target": "x86_64-freestanding-none",
            "output": NATIVE_EFI_NAME,
        },
        "tools": tools,
        "output": output,
        "builder_sha256": azure.image_sha256(Path(__file__)),
        "guarded": guarded,
    }
    receipt_path = output_directory / PRIVATE_BUILD_RECEIPT
    save_private_bytes(receipt_path, azure.canonical_json(receipt))
    validate_private_build(
        load_receipt(
            receipt_path, PRIVATE_BUILD_RECEIPT,
            "Private local build receipt",
        ),
        source_before,
        {
            "name": INPUT_NAMES["efi"],
            "sha256": output["sha256"],
            "size": output["size"],
        },
        guarded,
    )
    azure.fsync_directory(output_directory)
    return receipt_path, efi_path


def qemu_closure_records(qemu_root):
    original = Path(qemu_root)
    metadata = original.lstat()
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
        raise ValueError("QEMU closure root must be a non-symlink directory")
    qemu_root = original.resolve(strict=True)
    records = []
    executable = None
    for entry in sorted(qemu_root.rglob("*")):
        relative = entry.relative_to(qemu_root)
        if (
            relative.parts
            and relative.parts[0] not in ("bin", "lib", "share")
        ):
            raise ValueError("QEMU closure has an unsupported top-level path")
        destination = Path("qemu") / relative
        metadata = entry.lstat()
        if stat.S_ISLNK(metadata.st_mode):
            raise ValueError("QEMU closure must not contain symlinks")
        if stat.S_ISDIR(metadata.st_mode):
            continue
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError("QEMU closure contains a nonregular file")
        record = regular_record(
            entry, destination.as_posix(), "QEMU closure member"
        )
        if record["name"] == INPUT_NAMES["qemu"]:
            executable = record
        elif relative.parts[0] == "bin":
            raise ValueError("QEMU closure contains an unexpected executable")
        else:
            records.append({
                "path": record["name"],
                "sha256": record["sha256"],
                "size": record["size"],
            })
    if executable is None:
        raise ValueError(
            "QEMU closure requires bin/qemu-system-x86_64"
        )
    return executable, records


def copy_record(source, destination, record):
    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    azure.copy_regular_file(
        source, destination, record["size"], record["sha256"]
    )


def copy_git_runtime(source, destination, expected=None):
    source = Path(source).resolve(strict=True)
    record = preflight_git_runtime(source)
    if expected is not None and record != expected:
        raise ValueError("Private Git runtime differs from its fingerprint")
    destination.mkdir(mode=0o700, parents=True, exist_ok=False)
    for entry in sorted(source.rglob("*")):
        if not entry.is_file():
            continue
        relative = entry.relative_to(source)
        member = regular_record(
            entry, relative.as_posix(), "Private Git runtime member"
        )
        copy_record(entry, destination / relative, member)
        (destination / relative).chmod(
            0o700 if relative in (GIT_EXECUTABLE, GIT_LOADER) else 0o600
        )
    copied = preflight_git_runtime(destination)
    if copied != record:
        raise ValueError("Copied private Git runtime is inconsistent")
    return copied


def generate_input(
    output_directory, repository, config_path, qemu_root, ovmf_code,
    ovmf_vars, capability_raw, capability_receipt, efi, build_receipt,
    raw, vhd, miz_path, git_runtime, boot_policy,
):
    check_blob_dependency()
    if boot_policy not in BOOT_POLICIES:
        raise ValueError("Unsupported platform-only boot policy")
    provenance = build_provenance(repository, config_path, git_runtime)
    guarded = guarded_contract_from_solved_config(config_path)
    if guarded is not None:
        verify_guarded_producer_sources(repository)
    guarded = validate_guarded_contract(
        guarded, boot_policy, provenance["config"]["sha256"]
    )
    qemu, qemu_support = qemu_closure_records(qemu_root)
    files = {
        "qemu": qemu,
        "ovmf_code": regular_record(
            ovmf_code, INPUT_NAMES["ovmf_code"], "OVMF code"
        ),
        "ovmf_vars": regular_record(
            ovmf_vars, INPUT_NAMES["ovmf_vars"], "OVMF variables"
        ),
        "capability_raw": regular_record(
            capability_raw, INPUT_NAMES["capability_raw"],
            "Public capability raw image",
        ),
        "efi": regular_record(efi, INPUT_NAMES["efi"], "Private EFI"),
        "raw": regular_record(raw, INPUT_NAMES["raw"], "Private raw image"),
        "vhd": regular_record(
            vhd, INPUT_NAMES["vhd"], "Private fixed VHD"
        ),
    }
    if (
        files["capability_raw"]["size"] != azure.VIRTUAL_SIZE
        or files["raw"]["size"] != azure.VIRTUAL_SIZE
        or files["vhd"]["size"] != azure.VIRTUAL_SIZE + 512
    ):
        raise ValueError("Generated raw/fixed-VHD geometry is invalid")
    capability_reference = validate_capability_reference(
        load_receipt(
            capability_receipt, CAPABILITY_REFERENCE,
            "Public capability reference",
        ),
        files["capability_raw"],
    )
    private_build = validate_private_build(
        load_receipt(
            build_receipt, PRIVATE_BUILD_RECEIPT,
            "Private local build receipt",
        ),
        provenance, files["efi"], guarded,
    )
    miz = regular_record(miz_path, "miz", "Pinned miz executable")
    miz["revision"] = azure.MIZ_REVISION
    miz = {
        "name": miz["name"],
        "revision": miz["revision"],
        "sha256": miz["sha256"],
        "size": miz["size"],
    }
    output_directory = private_directory(
        output_directory, "Generated private-preflight input directory",
        must_exist=False,
    )
    output_directory.mkdir(mode=0o700, parents=True, exist_ok=False)
    try:
        for role, record in files.items():
            sources = {
                "ovmf_code": ovmf_code,
                "ovmf_vars": ovmf_vars,
                "capability_raw": capability_raw,
                "efi": efi,
                "raw": raw,
                "vhd": vhd,
            }
            source = (
                qemu_root.resolve(strict=True)
                / Path(record["name"]).relative_to("qemu")
                if role == "qemu" else sources[role]
            )
            copy_record(
                Path(source).resolve(strict=True),
                output_directory / record["name"],
                record,
            )
        for record in qemu_support:
            source = (
                qemu_root.resolve(strict=True)
                / Path(record["path"]).relative_to("qemu")
            )
            copy_record(source, output_directory / record["path"], record)
        copy_record(
            config_path.resolve(strict=True),
            output_directory / SOLVED_CONFIG,
            provenance["config"],
        )
        copy_record(
            Path(capability_receipt).resolve(strict=True),
            output_directory / CAPABILITY_REFERENCE,
            capability_reference,
        )
        copy_record(
            Path(build_receipt).resolve(strict=True),
            output_directory / PRIVATE_BUILD_RECEIPT,
            private_build,
        )
        copy_git_runtime(
            git_runtime, output_directory / GIT_RUNTIME,
            provenance["git"],
        )
        packaging = azure.miz_command(
            miz_path.resolve(strict=True),
            [
                "check-efi-application", "--output=json",
                "--architecture", "x86_64",
                "--expected-efi-sha256", files["efi"]["sha256"],
                "--expected-virtual-size", "66M",
                str(output_directory / INPUT_NAMES["vhd"]),
            ],
            output_directory / "miz-generate-check.log",
            json_output=True,
        )
        (output_directory / "miz-generate-check.log").unlink(missing_ok=True)
        packaging = validate_packaging_report(
            packaging, files["efi"]["sha256"], files["efi"]["size"],
            files["vhd"]["size"],
        )
        if sha256_prefix(
            output_directory / INPUT_NAMES["vhd"], azure.VIRTUAL_SIZE
        ) != files["raw"]["sha256"]:
            raise ValueError("Fixed VHD data region differs from raw image")
        budget = expected_budget(files, qemu_support)
        if budget["remaining_bytes"] < 0:
            raise ValueError("Generated staged closure exceeds 256 MiB")
        manifest = validate_input_manifest({
            "schema": INPUT_SCHEMA,
            "schema_version": INPUT_SCHEMA_VERSION,
            "workload": WORKLOAD,
            "boot_policy": boot_policy,
            "guarded": guarded,
            "raw_size": azure.VIRTUAL_SIZE,
            "provenance": provenance,
            "capability_reference": capability_reference,
            "private_build": private_build,
            "files": files,
            "qemu_support": qemu_support,
            "miz": miz,
            "packaging": dict(packaging),
            "implementation": implementation_contract(),
            "budget": budget,
        })
        manifest_bytes = azure.canonical_json(manifest)
        if len(manifest_bytes) > MAX_MANIFEST_BYTES:
            raise ValueError("Generated private-preflight manifest is too large")
        save_private_bytes(
            output_directory / INPUT_MANIFEST, manifest_bytes
        )
        azure.fsync_directory(output_directory)
        return hashlib.sha256(manifest_bytes).hexdigest()
    except BaseException:
        shutil.rmtree(output_directory, ignore_errors=True)
        raise


def load_input_manifest(input_directory, expected_sha256):
    input_directory = private_directory(
        input_directory, "Private-preflight input directory"
    )
    path = input_directory / INPUT_MANIFEST
    raw = azure.read_regular_file(
        path, MAX_MANIFEST_BYTES, "Private-preflight input manifest"
    )
    if hashlib.sha256(raw).hexdigest() != require_sha256(
        expected_sha256, "Expected private-preflight manifest"
    ):
        raise ValueError("Private-preflight manifest digest does not match")
    expected_names = {
        INPUT_MANIFEST, SOLVED_CONFIG, CAPABILITY_REFERENCE,
        PRIVATE_BUILD_RECEIPT, GIT_RUNTIME, "qemu",
        *(Path(name).parts[0] for role, name in INPUT_NAMES.items()
          if role != "qemu"),
    }
    actual_names = {entry.name for entry in input_directory.iterdir()}
    if actual_names != expected_names:
        raise ValueError("Private-preflight input directory has extra or missing files")
    manifest = validate_input_manifest(
        azure.parse_strict_json(raw, "Private-preflight input manifest")
    )
    expected_qemu = {
        manifest["files"]["qemu"]["name"],
        *(record["path"] for record in manifest["qemu_support"]),
    }
    actual_qemu = {
        str(path.relative_to(input_directory)).replace(os.sep, "/")
        for path in (input_directory / "qemu").rglob("*")
        if path.is_file() or path.is_symlink()
    }
    if actual_qemu != expected_qemu:
        raise ValueError("Private-preflight QEMU closure differs from manifest")
    return input_directory, manifest, raw


def prepare(input_directory, state_directory, miz_path, expected_sha256):
    source, manifest, manifest_bytes = load_input_manifest(
        input_directory, expected_sha256
    )
    check_blob_dependency()
    git_source = source / GIT_RUNTIME
    if preflight_git_runtime(git_source) != manifest["provenance"]["git"]:
        raise ValueError("Pinned Git runtime does not match the manifest")
    if (
        manifest["implementation"] != implementation_contract()
        or build_provenance(
            SUPPORT.parent, source / SOLVED_CONFIG, git_source
        ) != manifest["provenance"]
    ):
        raise ValueError(
            "Private-preflight source, configuration, or dependencies changed"
        )
    guarded = guarded_contract_from_solved_config(source / SOLVED_CONFIG)
    if guarded is not None:
        verify_guarded_producer_sources(SUPPORT.parent)
    if validate_guarded_contract(
        guarded, manifest["boot_policy"],
        manifest["provenance"]["config"]["sha256"],
    ) != manifest["guarded"]:
        raise ValueError("Private-preflight guarded V2 contract changed")
    miz_source = Path(miz_path)
    if stat.S_ISLNK(miz_source.lstat().st_mode):
        raise ValueError("Pinned miz executable must not be a symlink")
    miz_path = miz_source.resolve(strict=True)
    if (
        not miz_path.is_file()
        or not os.access(miz_path, os.X_OK)
        or miz_path.stat().st_size != manifest["miz"]["size"]
        or azure.image_sha256(miz_path) != manifest["miz"]["sha256"]
    ):
        raise ValueError("Pinned miz executable does not match the manifest")
    state_directory = private_directory(
        state_directory, "Private-preflight state directory", must_exist=False
    )
    state_directory.mkdir(mode=0o700, parents=True, exist_ok=False)
    inputs = state_directory / "inputs"
    inputs.mkdir(mode=0o700)
    local_tools = state_directory / "local-tools"
    local_tools.mkdir(mode=0o700)
    try:
        manifest_path = inputs / INPUT_MANIFEST
        with manifest_path.open("xb") as output:
            os.chmod(manifest_path, 0o600)
            output.write(manifest_bytes)
            output.flush()
            os.fsync(output.fileno())
        for role, record in manifest["files"].items():
            copy_record(
                source / record["name"], inputs / record["name"], record
            )
        for record in manifest["qemu_support"]:
            copy_record(
                source / record["path"], inputs / record["path"], record
            )
        copy_record(
            source / SOLVED_CONFIG,
            inputs / SOLVED_CONFIG,
            manifest["provenance"]["config"],
        )
        copy_record(
            source / CAPABILITY_REFERENCE,
            inputs / CAPABILITY_REFERENCE,
            manifest["capability_reference"],
        )
        copy_record(
            source / PRIVATE_BUILD_RECEIPT,
            inputs / PRIVATE_BUILD_RECEIPT,
            manifest["private_build"],
        )
        azure.copy_regular_file(
            miz_path, local_tools / "miz",
            manifest["miz"]["size"], manifest["miz"]["sha256"],
        )
        copied_miz = local_tools / "miz"
        copied_miz.chmod(0o700)
        copy_git_runtime(
            git_source, local_tools / GIT_RUNTIME,
            manifest["provenance"]["git"],
        )
        checked = azure.miz_command(copied_miz, [
            "check-efi-application", "--output=json",
            "--architecture", "x86_64",
            "--expected-efi-sha256", manifest["files"]["efi"]["sha256"],
            "--expected-virtual-size", "66M",
            str(inputs / INPUT_NAMES["vhd"]),
        ], state_directory / "miz-check.log", json_output=True)
        checked = validate_packaging_report(
            checked, manifest["files"]["efi"]["sha256"],
            manifest["files"]["efi"]["size"],
            manifest["files"]["vhd"]["size"],
        )
        if (
            azure.canonical_json(checked)
            != azure.canonical_json(manifest["packaging"])
        ):
            raise ValueError("Pinned miz result differs from the input manifest")
        if sha256_prefix(
            inputs / INPUT_NAMES["vhd"], manifest["raw_size"]
        ) != manifest["files"]["raw"]["sha256"]:
            raise ValueError("Fixed VHD data region does not match the raw image")
        identity = secrets.token_hex(16)
        prefix = "uk-hvp-" + secrets.token_hex(6)
        state = {
            "schema": STATE_SCHEMA,
            "schema_version": STATE_SCHEMA_VERSION,
            "phase": "prepared",
            "identity": identity,
            "name_prefix": prefix,
            "location": LOCATION,
            "vm_size": VM_SIZE,
            "image_sha256": manifest["files"]["vhd"]["sha256"],
            "manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
            "implementation": manifest["implementation"],
            "input_manifest": manifest,
            "staged_input_bytes": 0,
            "control_payload_bytes": 0,
            "evidence_bytes": 0,
            "pending_secret_files": [],
            "cleanup_required": False,
        }
        azure.save_durable_json(state_directory / STATE_FILE, state)
        return state_directory
    except BaseException:
        if not (state_directory / STATE_FILE).exists():
            import shutil
            shutil.rmtree(state_directory, ignore_errors=True)
        raise


def load_state(directory):
    directory = private_directory(
        directory, "Private-preflight state directory"
    )
    path = directory / STATE_FILE
    raw = azure.read_regular_file(
        path, MAX_STATE_BYTES, "Private-preflight private state"
    )
    state = azure.parse_strict_json(raw, "Private-preflight private state")
    legacy_diagnostics = isinstance(state, dict) and any(
        field in state for field in ("primary_failure", "cleanup_failure")
    )
    if legacy_diagnostics:
        if (
            state.get("phase") != "cleanup-failed"
            or state.get("cleanup_required") is not True
        ):
            raise ValueError(
                "Legacy private diagnostics require active cleanup recovery"
            )
        for field in ("primary_failure", "cleanup_failure"):
            state.pop(field, None)
    if any(
        field in state
        for field in (
            "acceptance", "group_precreated", "prepared_image_import",
            "reservation_claim", "resource_group",
        )
    ):
        raise ValueError(
            "Private-preflight state cannot adopt another controller's resources"
        )
    if (
        not isinstance(state, dict)
        or state.get("schema") != STATE_SCHEMA
        or type(state.get("schema_version")) is not int
        or state["schema_version"] != STATE_SCHEMA_VERSION
        or not isinstance(state.get("name_prefix"), str)
        or not re.fullmatch(r"uk-hvp-[0-9a-f]{12}", state["name_prefix"])
        or not isinstance(state.get("identity"), str)
        or not IDENTITY.fullmatch(state["identity"])
        or state.get("location") != LOCATION
        or state.get("vm_size") != VM_SIZE
        or not isinstance(state.get("input_manifest"), dict)
        or not isinstance(state.get("implementation"), dict)
        or type(state.get("staged_input_bytes")) is not int
        or state["staged_input_bytes"] < 0
        or type(state.get("control_payload_bytes")) is not int
        or state["control_payload_bytes"] < 0
        or type(state.get("evidence_bytes")) is not int
        or state["evidence_bytes"] < 0
        or not isinstance(state.get("pending_secret_files"), list)
        or type(state.get("cleanup_required")) is not bool
    ):
        raise ValueError("Private-preflight state is incompatible")
    if any(
        not isinstance(name, str)
        or not re.fullmatch(
            r"\.(?:blob-request|deployment-parameters|run-command)-"
            r"[0-9a-f]{16}\.json",
            name,
        )
        for name in state["pending_secret_files"]
    ) or len(set(state["pending_secret_files"])) != len(
        state["pending_secret_files"]
    ):
        raise ValueError("Private-preflight secret-file obligation is invalid")
    if state.get("failure") is not None:
        state["failure"] = validate_private_failure_record(state["failure"])
    state["input_manifest"] = validate_input_manifest(state["input_manifest"])
    state["implementation"] = validate_implementation(
        state["implementation"]
    )
    require_sha256(state.get("manifest_sha256"), "State manifest fingerprint")
    require_sha256(state.get("image_sha256"), "State image fingerprint")
    if (
        state["image_sha256"]
        != state["input_manifest"]["files"]["vhd"]["sha256"]
        or state["control_payload_bytes"] > MAX_CONTROL_BYTES
        or state["evidence_bytes"] > MAX_EVIDENCE_BYTES
        or state["staged_input_bytes"]
        > state["input_manifest"]["budget"]["remote_input_bytes"]
        or (
            state["staged_input_bytes"]
            + state["input_manifest"]["budget"][
                "firmware_working_copy_bytes"
            ]
            + state["control_payload_bytes"]
            + state["evidence_bytes"]
            > MAX_TOTAL_BYTES
        )
    ):
        raise ValueError("Private-preflight image binding is incompatible")
    obligation = state.get("firewall_obligation")
    if obligation is not None:
        obligation = exact_fields(
            obligation, ("cidr", "phase"), "Private Blob firewall obligation"
        )
        try:
            network = ipaddress.ip_network(obligation["cidr"], strict=True)
        except ValueError:
            raise ValueError("Private Blob firewall obligation is invalid") from None
        if (
            network.version != 4
            or network.prefixlen != 32
            or obligation["phase"] not in (
                "pending-add", "active", "pending-remove"
            )
        ):
            raise ValueError("Private Blob firewall obligation is invalid")
    host_deployment = state.get("host_deployment")
    if host_deployment is not None:
        host_deployment = exact_fields(
            host_deployment,
            (
                "phase", "operation_id", "deployment_id",
                "correlation_id", "vm_id", "vm_uuid", "disk_id",
                "disk_uuid", "shutdown_time",
            ),
            "Private host deployment obligation",
        )
        if (
            host_deployment["phase"] not in (
                "pending", "deployment-succeeded", "resources-verified",
                "deployment-terminal", "vm-verified", "failed-no-compute",
                "not-created-empty",
            )
            or not isinstance(host_deployment["operation_id"], str)
            or str(uuid.UUID(host_deployment["operation_id"]))
            != host_deployment["operation_id"]
            or not isinstance(host_deployment["shutdown_time"], str)
            or not re.fullmatch(r"(?:[01][0-9]|2[0-3])[0-5][0-9]",
                                host_deployment["shutdown_time"])
        ):
            raise ValueError("Private host deployment obligation is invalid")
        for field in ("deployment_id", "vm_id", "disk_id"):
            if not isinstance(host_deployment[field], str):
                raise ValueError("Private host deployment obligation is invalid")
        for field in ("correlation_id", "vm_uuid", "disk_uuid"):
            if host_deployment[field] is not None:
                require_uuid(
                    host_deployment[field],
                    "Private host deployment identity",
                )
        phase = host_deployment["phase"]
        correlation = host_deployment["correlation_id"]
        vm_uuid = host_deployment["vm_uuid"]
        disk_uuid = host_deployment["disk_uuid"]
        if (
            ((vm_uuid is None) != (disk_uuid is None))
            or (phase == "pending" and any(
                value is not None
                for value in (correlation, vm_uuid, disk_uuid)
            ))
            or (
                phase in (
                    "deployment-succeeded", "vm-verified",
                    "resources-verified",
                )
                and any(
                    value is None
                    for value in (correlation, vm_uuid, disk_uuid)
                )
            )
            or (
                phase in (
                    "failed-no-compute", "not-created-empty",
                )
                and (vm_uuid is not None or disk_uuid is not None)
            )
        ):
            raise ValueError(
                "Private host deployment identity anchors are invalid"
            )
    subscription = state.get("subscription")
    if subscription is not None:
        azure.validate_subscription_id(subscription)
        cloud = exact_fields(
            state.get("cloud_preflight"),
            ("subscription", "sku", "image", "nested_virtualization"),
            "Private cloud preflight",
        )
        if (
            cloud["subscription"] != subscription
            or not isinstance(cloud["sku"], dict)
            or not isinstance(cloud["image"], dict)
        ):
            raise ValueError("Private cloud preflight is incompatible")
        validate_nested_capability_admission(
            cloud["nested_virtualization"]
        )
        if (
            type(state.get("deadline_monotonic")) not in (int, float)
            or state["deadline_monotonic"] <= 0
            or not isinstance(state.get("deadline_utc"), str)
        ):
            raise ValueError("Private-preflight deadline binding is invalid")
        storage = state.get("storage_account")
        if not isinstance(storage, str) or not STORAGE_NAME.fullmatch(storage):
            raise ValueError("Private-preflight storage binding is invalid")
        group_id = state.get("resource_group_id")
        if group_id is not None:
            expected_group_id = (
                f"/subscriptions/{subscription}/resourceGroups/"
                f"{state['name_prefix']}-rg"
            )
            if (
                not isinstance(group_id, str)
                or group_id.lower() != expected_group_id.lower()
            ):
                raise ValueError("Private-preflight group binding is invalid")
    if legacy_diagnostics:
        azure.save_durable_json(path, state)
    return state, path


def verify_immutable_inputs(state, state_directory):
    manifest = state["input_manifest"]
    manifest_path = state_directory / "inputs" / INPUT_MANIFEST
    manifest_bytes = azure.read_regular_file(
        manifest_path, MAX_MANIFEST_BYTES,
        "Prepared private-preflight input manifest",
    )
    if (
        hashlib.sha256(manifest_bytes).hexdigest()
        != state["manifest_sha256"]
        or validate_input_manifest(
            azure.parse_strict_json(
                manifest_bytes, "Prepared private-preflight input manifest"
            )
        ) != manifest
        or state["implementation"] != state["input_manifest"]["implementation"]
        or state["implementation"] != implementation_contract()
    ):
        raise ValueError(
            "Private-preflight controller, runner, template, or manifest changed"
        )
    for role, record in manifest["files"].items():
        path = state_directory / "inputs" / record["name"]
        if (
            path.is_symlink()
            or not path.is_file()
            or path.stat().st_size != record["size"]
            or azure.image_sha256(path) != record["sha256"]
        ):
            raise ValueError(f"Prepared {role} input changed")
    for record in manifest["qemu_support"]:
        path = state_directory / "inputs" / record["path"]
        if (
            path.is_symlink()
            or not path.is_file()
            or path.stat().st_size != record["size"]
            or azure.image_sha256(path) != record["sha256"]
        ):
            raise ValueError("Prepared QEMU support closure changed")
    config = manifest["provenance"]["config"]
    config_path = state_directory / "inputs" / config["name"]
    git = state_directory / "local-tools" / GIT_RUNTIME
    if (
        config_path.is_symlink()
        or not config_path.is_file()
        or config_path.stat().st_size != config["size"]
        or azure.image_sha256(config_path) != config["sha256"]
        or preflight_git_runtime(git) != manifest["provenance"]["git"]
        or build_provenance(SUPPORT.parent, config_path, git)
        != manifest["provenance"]
    ):
        raise ValueError("Prepared source or solved configuration changed")
    guarded = guarded_contract_from_solved_config(config_path)
    if guarded is not None:
        verify_guarded_producer_sources(SUPPORT.parent)
    if validate_guarded_contract(
        guarded, manifest["boot_policy"], config["sha256"]
    ) != manifest["guarded"]:
        raise ValueError("Prepared guarded V2 contract changed")
    for name, key, description in (
        (
            CAPABILITY_REFERENCE, "capability_reference",
            "Prepared public capability reference",
        ),
        (
            PRIVATE_BUILD_RECEIPT, "private_build",
            "Prepared private local build receipt",
        ),
    ):
        record = manifest[key]
        path = state_directory / "inputs" / name
        raw = azure.read_regular_file(path, MAX_MANIFEST_BYTES, description)
        if (
            path.is_symlink()
            or path.stat().st_size != record["size"]
            or hashlib.sha256(raw).hexdigest() != record["sha256"]
            or azure.parse_strict_json(raw, description)
            != record["receipt"]
        ):
            raise ValueError(f"{description} changed")
    miz = state_directory / "local-tools" / "miz"
    if (
        miz.is_symlink()
        or not miz.is_file()
        or not os.access(miz, os.X_OK)
        or miz.stat().st_size != manifest["miz"]["size"]
        or azure.image_sha256(miz) != manifest["miz"]["sha256"]
    ):
        raise ValueError("Prepared miz executable changed")


def check_blob_dependency():
    sdk_dependency_contract()
    try:
        from azure.storage.blob import BlobServiceClient
    except ImportError:
        raise RuntimeError(
            "Pinned azure-storage-blob dependency is unavailable"
        ) from None
    return BlobServiceClient


def transfer_source(value):
    if not isinstance(value, str):
        raise ValueError("An explicit transfer source IPv4 address is required")
    try:
        address = ipaddress.IPv4Address(value.removesuffix("/32"))
    except ipaddress.AddressValueError:
        raise ValueError("Transfer source must be one explicit IPv4 /32") from None
    if (
        value not in (str(address), f"{address}/32")
        or not address.is_global
    ):
        raise ValueError("Transfer source must be one explicit public IPv4 /32")
    return f"{address}/32"


def validate_nested_capability_admission(value):
    value = exact_fields(
        value,
        (
            "schema", "schema_version", "location", "vm_size",
            "memory_gb", "metadata", "admission", "authority",
        ),
        "Nested-virtualization capability admission",
    )
    metadata = exact_fields(
        value["metadata"],
        (
            "capability_name", "capability_count",
            "advertised_values", "status",
        ),
        "Nested-virtualization SKU metadata",
    )
    admission = exact_fields(
        value["admission"],
        ("scope", "reason", "runtime_gate"),
        "Nested-virtualization admission boundary",
    )
    authority = exact_fields(
        value["authority"],
        ("url", "source_commit", "updated"),
        "Nested-virtualization public authority",
    )
    advertised = metadata["advertised_values"]
    if advertised == []:
        expected_status = "not-advertised"
        expected_reason = "documented-fixed-sku-runtime-proof-required"
    elif advertised == ["True"]:
        expected_status = "advertised-true"
        expected_reason = "advertised-fixed-sku-runtime-proof-required"
    else:
        raise ValueError(
            "Nested-virtualization metadata is not an admissible assertion"
        )
    if (
        value["schema"] != NESTED_CAPABILITY_ADMISSION_SCHEMA
        or type(value["schema_version"]) is not int
        or value["schema_version"] != NESTED_CAPABILITY_ADMISSION_VERSION
        or value["location"] != LOCATION
        or value["vm_size"] != VM_SIZE
        or type(value["memory_gb"]) is not int
        or value["memory_gb"] != VM_MEMORY_GB
        or metadata["capability_name"] != "NestedVirtualization"
        or type(metadata["capability_count"]) is not int
        or not 1 <= metadata["capability_count"] <= 1024
        or metadata["status"] != expected_status
        or admission["scope"] != "public-capability-smoke-only"
        or admission["reason"] != expected_reason
        or admission["runtime_gate"]
        != "kvm-qemu-two-apic-pass-before-private-transfer"
        or dict(authority) != NESTED_VIRTUALIZATION_REFERENCE
    ):
        raise ValueError(
            "Nested-virtualization capability admission is incompatible"
        )
    return {
        **value,
        "metadata": {
            **metadata,
            "advertised_values": list(advertised),
        },
        "admission": dict(admission),
        "authority": dict(authority),
    }


def nested_capability_admission(location, vm_size, sku_metadata):
    if location != LOCATION or vm_size != VM_SIZE:
        raise RuntimeError(
            "Nested-virtualization admission is limited to the fixed "
            "Standard_D2s_v5 North Europe preflight"
        )
    try:
        if not isinstance(sku_metadata, list) or len(sku_metadata) != 1:
            raise ValueError
        record = exact_fields(
            sku_metadata[0], ("name", "capabilities"),
            "Fixed preflight SKU metadata",
        )
        if (
            record["name"] != VM_SIZE
            or not isinstance(record["capabilities"], list)
            or not 1 <= len(record["capabilities"]) <= 1024
        ):
            raise ValueError
        capabilities = []
        consumed_names = {
            "".join(name.split()).casefold(): name
            for name in FIXED_SKU_CAPABILITY_NAMES
        }
        seen_consumed = set()
        for entry in record["capabilities"]:
            entry = exact_fields(
                entry, ("name", "value"), "Fixed preflight SKU capability"
            )
            if (
                not isinstance(entry["name"], str)
                or not entry["name"]
                or not isinstance(entry["value"], str)
                or not entry["value"]
            ):
                raise ValueError
            normalized_name = "".join(entry["name"].split()).casefold()
            consumed = consumed_names.get(normalized_name)
            if consumed is not None:
                if entry["name"] != consumed or consumed in seen_consumed:
                    raise ValueError
                seen_consumed.add(consumed)
            capabilities.append((entry["name"], entry["value"]))
    except (TypeError, ValueError):
        raise RuntimeError(
            "Azure returned malformed fixed preflight SKU capabilities"
        ) from None

    def values(name):
        return [value for key, value in capabilities if key == name]

    architecture = values("CpuArchitectureType")
    vcpus = values("vCPUs")
    memory = values("MemoryGB")
    generations = values("HyperVGenerations")
    generation_tokens = (
        tuple(generations[0].split(",")) if len(generations) == 1 else ()
    )
    if (
        architecture != ["x64"]
        or vcpus != ["2"]
        or memory != [str(VM_MEMORY_GB)]
        or generation_tokens not in (("V2",), ("V1", "V2"), ("V2", "V1"))
    ):
        raise RuntimeError(
            "The fixed preflight SKU metadata conflicts with its "
            "x64, two-vCPU, 8-GiB, Gen2 envelope"
        )
    nested = values("NestedVirtualization")
    if nested == []:
        status = "not-advertised"
        reason = "documented-fixed-sku-runtime-proof-required"
    elif nested == ["True"]:
        status = "advertised-true"
        reason = "advertised-fixed-sku-runtime-proof-required"
    else:
        raise RuntimeError(
            "The fixed preflight SKU has an explicit, duplicate, "
            "conflicting, or malformed nested-virtualization advertisement"
        )
    return validate_nested_capability_admission({
        "schema": NESTED_CAPABILITY_ADMISSION_SCHEMA,
        "schema_version": NESTED_CAPABILITY_ADMISSION_VERSION,
        "location": LOCATION,
        "vm_size": VM_SIZE,
        "memory_gb": VM_MEMORY_GB,
        "metadata": {
            "capability_name": "NestedVirtualization",
            "capability_count": len(capabilities),
            "advertised_values": nested,
            "status": status,
        },
        "admission": {
            "scope": "public-capability-smoke-only",
            "reason": reason,
            "runtime_gate": (
                "kvm-qemu-two-apic-pass-before-private-transfer"
            ),
        },
        "authority": dict(NESTED_VIRTUALIZATION_REFERENCE),
    })


def check_subscription(subscription):
    subscription = azure.selected_account(subscription)
    for namespace in (
        "Microsoft.Compute", "Microsoft.Network", "Microsoft.Storage",
        "Microsoft.DevTestLab",
    ):
        if azure.azure_cli([
            "provider", "show", "--namespace", namespace,
            "--query", "registrationState",
        ], subscription=subscription, private=True) != "Registered":
            raise RuntimeError("Required Azure providers must already be registered")
    versions = azure.azure_cli([
        "provider", "show", "--namespace", "Microsoft.Compute",
        "--query",
        "resourceTypes[?resourceType=='virtualMachines'].apiVersions | [0]",
    ], subscription=subscription, private=True)
    if (
        not isinstance(versions, list)
        or HOST_COMPUTE_API_VERSION not in versions
    ):
        raise RuntimeError(f"Compute API {HOST_COMPUTE_API_VERSION} is required")
    sku = azure.exact_vm_sku(
        LOCATION, VM_SIZE, subscription, vcpus=2, require_v2=True
    )
    sku_metadata = azure.azure_cli([
        "vm", "list-skus", "--all", "--location", LOCATION,
        "--resource-type", "virtualMachines", "--size", VM_SIZE,
        "--query",
        (
            f"[?name=='{VM_SIZE}']."
            "{name:name,capabilities:capabilities[]."
            "{name:name,value:value}}"
        ),
    ], subscription=subscription, private=True)
    nested = nested_capability_admission(
        LOCATION, VM_SIZE, sku_metadata
    )
    sku = {**sku, "memory_gb": VM_MEMORY_GB}
    image = azure.resolve_peer_image(LOCATION, subscription, ("V2",))
    if image["hyperv_generation"] != "V2":
        raise RuntimeError("The selected immutable Ubuntu image is not Gen2")
    usage = azure.azure_cli([
        "vm", "list-usage", "--location", LOCATION,
        "--query",
        f"[?name.value=='cores' || name.value=='{sku['family']}']",
    ], subscription=subscription, private=True)
    if not isinstance(usage, list):
        raise RuntimeError("Azure returned invalid quota information")
    limits = {
        item.get("name", {}).get("value"): item
        for item in usage if isinstance(item, dict)
    }
    for name in ("cores", sku["family"]):
        if name not in limits or (
            azure.quota_count(limits[name].get("limit"))
            - azure.quota_count(limits[name].get("currentValue"))
        ) < 2:
            raise RuntimeError("Two-vCPU preflight quota is unavailable")
    return {
        "subscription": subscription,
        "sku": sku,
        "image": image,
        "nested_virtualization": nested,
    }


def utc_text(value):
    return value.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace(
        "+00:00", "Z"
    )


def bounded_timeout(deadline, maximum):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise RuntimeError("The private preflight deadline has expired")
    return max(1, min(maximum, int(remaining)))


def run_blob_worker(run, request, sas, deadline):
    check_blob_dependency()
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise RuntimeError(
            "Authenticated private Blob transfer exceeded its deadline"
        )
    environment = os.environ.copy()
    environment["HYPERV_PREFLIGHT_SAS"] = sas
    with run.tracked_private_json(
        "blob-request", request
    ) as request_path:
        process = subprocess.Popen(
            [
                sys.executable, str(BLOB_WORKER_PATH),
                "--request", str(request_path),
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=environment,
            start_new_session=True,
        )
        try:
            stdout, _ = process.communicate(
                timeout=remaining
            )
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
            raise RuntimeError(
                "Authenticated private Blob transfer exceeded its deadline"
            ) from None
        except BaseException:
            process.kill()
            process.wait()
            raise
    if time.monotonic() >= deadline:
        raise RuntimeError(
            "Authenticated private Blob transfer exceeded its deadline"
        )
    if process.returncode or len(stdout) > MAX_MANIFEST_BYTES:
        raise RuntimeError("Authenticated private Blob transfer failed")
    result = azure.parse_strict_json(stdout, "Private Blob worker result")
    result = exact_fields(
        result, ("schema", "result", "bytes"), "Private Blob worker result"
    )
    if (
        type(result["schema"]) is not int
        or result["schema"] != 1
        or result["result"] != "PASS"
        or type(result["bytes"]) is not int
        or result["bytes"] < 0
    ):
        raise RuntimeError("Authenticated private Blob transfer failed")
    return result["bytes"]


def upload_blob_set(
    run, account_url, sas, container, files, *, create_container, deadline
):
    records = []
    expected = 0
    for blob_name, source, expected_size, expected_sha256 in files:
        records.append({
            "blob": blob_name,
            "path": str(source),
            "size": expected_size,
            "sha256": expected_sha256,
        })
        expected += expected_size
    transferred = run_blob_worker(
        run,
        {
            "schema": "unikraft.hyperv.private-preflight-blob-worker",
            "schema_version": 1,
            "action": "upload",
            "account_url": account_url,
            "container": container,
            "files": records,
            "create_container": create_container,
        },
        sas,
        deadline,
    )
    if transferred != expected:
        raise RuntimeError("Private Blob upload byte count is inconsistent")
    return transferred


def download_blob_set(
    run, account_url, sas, container, files, deadline
):
    directory = run.state_path.parent / (
        ".blob-download-" + secrets.token_hex(8)
    )
    directory.mkdir(mode=0o700)
    records = []
    try:
        for index, (blob_name, maximum) in enumerate(files):
            records.append({
                "blob": blob_name,
                "path": str(directory / f"{index:03d}.bin"),
                "maximum": maximum,
            })
        transferred = run_blob_worker(
            run,
            {
                "schema": "unikraft.hyperv.private-preflight-blob-worker",
                "schema_version": 1,
                "action": "download",
                "account_url": account_url,
                "container": container,
                "files": records,
                "create_container": False,
            },
            sas,
            deadline,
        )
        values = [
            azure.read_regular_file(
                directory / f"{index:03d}.bin",
                maximum,
                "Private Blob evidence",
            )
            for index, (_, maximum) in enumerate(files)
        ]
        if sum(map(len, values)) != transferred:
            raise RuntimeError(
                "Private Blob download byte count is inconsistent"
            )
        if time.monotonic() >= deadline:
            raise RuntimeError(
                "Authenticated private Blob transfer exceeded its deadline"
            )
        return values
    finally:
        shutil.rmtree(directory, ignore_errors=True)


def save_private_bytes(path, value):
    with path.open("xb") as output:
        os.chmod(path, 0o600)
        output.write(value)
        output.flush()
        os.fsync(output.fileno())


def bounded_exception_record(error):
    category = getattr(error, "failure_category", type(error).__name__)
    if not isinstance(category, str) or not re.fullmatch(
        r"[A-Za-z][A-Za-z0-9_]{0,79}", category
    ):
        category = "RuntimeError"
    code = getattr(error, "code", None)
    if not isinstance(code, str) or not re.fullmatch(
        r"[A-Za-z][A-Za-z0-9_-]{0,79}", code
    ):
        code = None
    return {"category": category, "code": code}


def bounded_cleanup_failures(error, default_stage="cleanup"):
    failures = getattr(error, "cleanup_failures", None)
    if isinstance(failures, list):
        return [dict(failure) for failure in failures]
    return [{"stage": default_stage, **bounded_exception_record(error)}]


class PrivateHostDeploymentReconciliationError(RuntimeError):
    def __init__(self, primary, reconciliation):
        primary_record = bounded_exception_record(primary)
        self.failure_category = primary_record["category"]
        self.code = primary_record["code"]
        self.reconciliation_failure = bounded_exception_record(
            reconciliation
        )
        super().__init__(
            "Private host deployment failed: "
            f"primary={self.failure_category}({self.code or 'unclassified'}); "
            f"reconciliation={self.reconciliation_failure['category']}"
            f"({self.reconciliation_failure['code'] or 'unclassified'})"
        )


class PrivateCleanupError(RuntimeError):
    def __init__(self, failures):
        self.cleanup_failures = [
            {"stage": stage, **bounded_exception_record(error)}
            for stage, error in failures
        ]
        super().__init__(
            "Private preflight cleanup failed: "
            + ", ".join(
                f"{failure['stage']}="
                f"{failure['category']}"
                f"({failure['code'] or 'unclassified'})"
                for failure in self.cleanup_failures
            )
        )


class PrivateFailurePipelineError(RuntimeError):
    def __init__(self, primary, cleanup, recording):
        primary_record = bounded_exception_record(primary)
        self.failure_category = primary_record["category"]
        self.code = primary_record["code"]
        reconciliation = getattr(
            primary, "reconciliation_failure", None
        )
        self.reconciliation_failure = (
            dict(reconciliation)
            if isinstance(reconciliation, dict) else None
        )
        self.cleanup_failures = (
            bounded_cleanup_failures(cleanup)
            if cleanup is not None else []
        )
        self.recording_failures = [dict(item) for item in recording]
        parts = [
            "primary="
            f"{self.failure_category}({self.code or 'unclassified'})"
        ]
        if self.reconciliation_failure is not None:
            parts.append(
                "reconciliation="
                f"{self.reconciliation_failure['category']}"
                f"({self.reconciliation_failure['code'] or 'unclassified'})"
            )
        parts.extend(
            "cleanup="
            f"{failure['stage']}:{failure['category']}"
            f"({failure['code'] or 'unclassified'})"
            for failure in self.cleanup_failures
        )
        parts.extend(
            "recording="
            f"{failure['stage']}:{failure['category']}"
            f"({failure['code'] or 'unclassified'})"
            for failure in self.recording_failures
        )
        super().__init__("Private failure pipeline: " + "; ".join(parts))


class PrivatePreflightRun(azure.AzureRun):
    def __init__(self, state, state_path):
        super().__init__(state, state_path)
        self.host_vm = self.prefix + "-host"
        self.host_disk = self.prefix + "-host-os"
        self.host_nic = self.prefix + "-host-nic"
        self.storage = state["storage_account"]
        self.container = CONTAINER
        self.deadline = state.get("deadline_monotonic")
        self.cleanup_deadline = None
        self.group_tags.update({
            "purpose": PURPOSE,
            "disposable": "true",
            "private-manifest-sha256": state["manifest_sha256"],
        })

    def private_failure_values(self):
        values = {
            str(self.state_path),
            str(self.state_path.parent),
            self.prefix,
            self.group,
            self.host_vm,
            self.host_disk,
            self.host_nic,
            self.storage,
            self.state.get("identity"),
            self.state.get("subscription"),
            self.state.get("resource_group_id"),
        }
        firewall = self.state.get("firewall_obligation")
        if isinstance(firewall, dict):
            values.add(firewall.get("cidr"))
        deployment = self.state.get("host_deployment")
        if isinstance(deployment, dict):
            values.update(
                value for value in deployment.values()
                if isinstance(value, str)
            )
        for name in self.state.get("pending_secret_files", ()):
            values.add(name)
            values.add(str(self.state_path.parent / name))
        return tuple(
            value for value in values if isinstance(value, str) and value
        )

    def account_bytes(self, category, amount):
        if type(amount) is not int or amount < 0:
            raise ValueError("Private-preflight byte accounting is invalid")
        field = {
            "input": "staged_input_bytes",
            "control": "control_payload_bytes",
            "evidence": "evidence_bytes",
        }.get(category)
        if field is None:
            raise ValueError("Private-preflight byte category is invalid")
        updated = self.state[field] + amount
        if category == "control" and updated > MAX_CONTROL_BYTES:
            raise RuntimeError(
                "Private-preflight control payload exceeds its allowance"
            )
        if category == "evidence" and updated > MAX_EVIDENCE_BYTES:
            raise RuntimeError(
                "Private-preflight evidence exceeds its allowance"
            )
        if (
            category == "input"
            and updated
            > self.state["input_manifest"]["budget"]["remote_input_bytes"]
        ):
            raise RuntimeError(
                "Private-preflight staged inputs exceed their manifest"
            )
        total = (
            (
                updated if category == "input"
                else self.state["staged_input_bytes"]
            )
            + self.state["input_manifest"]["budget"][
                "firmware_working_copy_bytes"
            ]
            + (
                updated if category == "control"
                else self.state["control_payload_bytes"]
            )
            + (
                updated if category == "evidence"
                else self.state["evidence_bytes"]
            )
        )
        if total > MAX_TOTAL_BYTES:
            raise RuntimeError(
                "Private-preflight cumulative byte budget exceeds 256 MiB"
            )
        self.record("accounted-" + category, **{field: updated})

    @contextmanager
    def tracked_private_json(self, kind, value):
        if kind not in (
            "blob-request", "deployment-parameters", "run-command"
        ):
            raise ValueError("Private parameter-file kind is invalid")
        name = "." + kind + "-" + secrets.token_hex(8) + ".json"
        pending = list(self.state["pending_secret_files"])
        pending.append(name)
        self.record(
            "private-parameter-file-pending",
            pending_secret_files=pending,
        )
        path = self.state_path.parent / name
        save_private_bytes(path, azure.canonical_json(value))
        try:
            yield path
        finally:
            path.unlink(missing_ok=True)
            azure.fsync_directory(path.parent)
            pending = [
                item for item in self.state["pending_secret_files"]
                if item != name
            ]
            self.record(
                "private-parameter-file-cleared",
                pending_secret_files=pending,
            )

    @contextmanager
    def private_parameters(self, values):
        document = {
            "$schema": (
                "https://schema.management.azure.com/schemas/"
                "2019-04-01/deploymentParameters.json#"
            ),
            "contentVersion": "1.0.0.0",
            "parameters": {
                key: {"value": value} for key, value in values.items()
            },
        }
        with self.tracked_private_json(
            "deployment-parameters", document
        ) as path:
            yield path

    def clear_private_files(self):
        pending = list(self.state.get("pending_secret_files", []))
        for name in pending:
            if not re.fullmatch(
                r"\.(?:blob-request|deployment-parameters|run-command)-"
                r"[0-9a-f]{16}\.json",
                name,
            ):
                raise RuntimeError(
                    "Private parameter-file obligation is invalid"
                )
            path = self.state_path.parent / name
            try:
                path.unlink(missing_ok=True)
            except OSError:
                raise RuntimeError(
                    "Private parameter-file cleanup failed"
                ) from None
        for path in self.state_path.parent.glob(".azure-state-*"):
            metadata = path.lstat()
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != os.getuid()
                or metadata.st_mode & 0o077
            ):
                raise RuntimeError(
                    "Private state temporary-file cleanup failed"
                )
            path.unlink()
        azure.fsync_directory(self.state_path.parent)
        self.record(
            "private-parameter-files-cleared", pending_secret_files=[]
        )

    def phase_timeout(self, maximum):
        return bounded_timeout(self.state["deadline_monotonic"], maximum)

    def operation_timeout(self, maximum, deadline=None):
        if deadline is None:
            deadline = (
                self.cleanup_deadline
                if self.cleanup_deadline is not None
                else self.state["deadline_monotonic"]
            )
        return bounded_timeout(deadline, maximum)

    def az(self, arguments, **kwargs):
        kwargs.setdefault("private", True)
        if self.cleanup_deadline is not None:
            kwargs["timeout"] = self.operation_timeout(
                kwargs.get("timeout", TRANSFER_TIMEOUT_SECONDS)
            )
        return azure.azure_cli(
            arguments, subscription=self.state["subscription"], **kwargs
        )

    def expected_resource_id(self, provider, resource_type, name):
        group_id = self.state.get("resource_group_id")
        if not isinstance(group_id, str):
            raise RuntimeError("Private resource-group identity is unavailable")
        return (
            group_id.rstrip("/") + f"/providers/{provider}/"
            f"{resource_type}/{name}"
        )

    def operation_tags(self):
        receipt = self.state.get("host_deployment")
        operation_id = (
            receipt.get("operation_id")
            if isinstance(receipt, dict) else None
        )
        if not isinstance(operation_id, str):
            raise RuntimeError("Private host operation identity is unavailable")
        return {**self.tags, "preflight-operation": operation_id}

    def require_operation_owned(self, resource):
        tags = resource.get("tags") or {}
        if any(
            tags.get(key) != value
            for key, value in self.operation_tags().items()
        ):
            raise RuntimeError(
                "Private host resource lacks operation ownership"
            )

    def expected_host_ids(self):
        return {
            "deployment_id": self.expected_resource_id(
                "Microsoft.Resources", "deployments", self.prefix + "-host"
            ),
            "vm_id": self.expected_resource_id(
                "Microsoft.Compute", "virtualMachines", self.host_vm
            ),
            "disk_id": self.expected_resource_id(
                "Microsoft.Compute", "disks", self.host_disk
            ),
            "nic_id": self.expected_resource_id(
                "Microsoft.Network", "networkInterfaces", self.host_nic
            ),
            "nsg_id": self.expected_resource_id(
                "Microsoft.Network", "networkSecurityGroups",
                self.prefix + "-nsg",
            ),
            "vnet_id": self.expected_resource_id(
                "Microsoft.Network", "virtualNetworks",
                self.prefix + "-vnet",
            ),
            "storage_id": self.expected_resource_id(
                "Microsoft.Storage", "storageAccounts", self.storage
            ),
            "schedule_id": self.expected_resource_id(
                "Microsoft.DevTestLab", "schedules",
                "shutdown-computevm-" + self.host_vm,
            ),
        }

    def begin_host_deployment(self, shutdown_time):
        ids = self.expected_host_ids()
        receipt = {
            "phase": "pending",
            "operation_id": str(uuid.uuid4()),
            "deployment_id": ids["deployment_id"],
            "correlation_id": None,
            "vm_id": ids["vm_id"],
            "vm_uuid": None,
            "disk_id": ids["disk_id"],
            "disk_uuid": None,
            "shutdown_time": shutdown_time,
        }
        self.record(
            "host-deployment-pending",
            host_deployment=receipt,
            host_deallocated=False,
        )
        return receipt

    def validate_deployment_identity(self, deployment):
        receipt = self.state["host_deployment"]
        properties = (
            deployment.get("properties")
            if isinstance(deployment, dict) else None
        )
        parameters = (
            properties.get("parameters")
            if isinstance(properties, dict) else None
        )
        expected_parameters = {
            "namePrefix": self.prefix,
            "location": LOCATION,
            "imageSha256": self.state["image_sha256"],
            "storageAccountName": self.storage,
            "hostImageVersion": self.state["cloud_preflight"]["image"][
                "version"
            ],
            "operationId": receipt["operation_id"],
            "shutdownTime": receipt["shutdown_time"],
        }
        if (
            deployment.get("name") != self.prefix + "-host"
            or str(deployment.get("id", "")).lower()
            != receipt["deployment_id"].lower()
            or not isinstance(properties, dict)
            or not isinstance(parameters, dict)
            or any(
                not isinstance(parameters.get(name), dict)
                or parameters[name].get("value") != value
                for name, value in expected_parameters.items()
            )
        ):
            raise RuntimeError("Private host deployment provenance is invalid")
        return properties

    def validate_deployment_result(self, deployment):
        receipt = self.state["host_deployment"]
        properties = self.validate_deployment_identity(deployment)
        if properties.get("provisioningState") != "Succeeded":
            raise RuntimeError("Private host deployment did not succeed")
        correlation = self.require_resource_uuid(
            properties.get("correlationId"),
            "Private host deployment correlation",
        )
        if receipt.get("correlation_id") not in (None, correlation):
            raise RuntimeError(
                "Private host deployment correlation changed"
            )
        outputs = properties.get("outputs")
        if not isinstance(outputs, dict) or set(outputs) != {
            "hostVmUuid", "hostDiskUuid",
        }:
            raise RuntimeError(
                "Private host deployment identity outputs are invalid"
            )
        identities = {}
        for output, field, label in (
            ("hostVmUuid", "vm_uuid", "Private host VM identity"),
            ("hostDiskUuid", "disk_uuid", "Private host disk identity"),
        ):
            value = outputs.get(output)
            if (
                not isinstance(value, dict)
                or set(value) != {"type", "value"}
                or value.get("type") != "String"
            ):
                raise RuntimeError(
                    "Private host deployment identity outputs are invalid"
                )
            identities[field] = self.require_resource_uuid(
                value.get("value"), label
            )
            if receipt.get(field) not in (None, identities[field]):
                raise RuntimeError(
                    "Private host deployment identity anchor changed"
                )
        receipt = {
            **receipt,
            "phase": "deployment-succeeded",
            "correlation_id": correlation,
            **identities,
        }
        self.record(
            "host-deployment-succeeded", host_deployment=receipt
        )
        return receipt

    def capture_host_identity(self, deadline=None):
        receipt = self.state["host_deployment"]
        if (
            receipt.get("phase") not in (
                "deployment-succeeded", "deployment-terminal",
                "vm-verified",
                "resources-verified",
            )
            or receipt.get("correlation_id") is None
            or receipt.get("vm_uuid") is None
            or receipt.get("disk_uuid") is None
        ):
            raise RuntimeError(
                "Private host deployment identities are not anchored"
            )
        vm = self.az([
            "vm", "show", "--resource-group", self.group,
            "--name", self.host_vm,
        ], timeout=self.operation_timeout(
            TRANSFER_TIMEOUT_SECONDS, deadline
        ))
        self.require_operation_owned(vm)
        expected_vm = receipt["vm_id"]
        expected_disk = receipt["disk_id"]
        attached = (
            vm.get("storageProfile", {}).get("osDisk", {})
            .get("managedDisk", {}).get("id")
        )
        if (
            str(vm.get("id", "")).lower() != expected_vm.lower()
            or str(attached or "").lower() != expected_disk.lower()
        ):
            raise RuntimeError("Private host VM provenance is invalid")
        vm_uuid = self.require_resource_uuid(
            vm.get("vmId"), "Private host VM identity"
        )
        if receipt["vm_uuid"] != vm_uuid:
            raise RuntimeError("Private host VM identity changed")
        receipt = {
            **receipt,
            "phase": "vm-verified",
        }
        self.record("host-vm-verified", host_deployment=receipt)
        self.verify_vm_identity()
        disk = self.az([
            "disk", "show", "--resource-group", self.group,
            "--name", self.host_disk,
        ], timeout=self.operation_timeout(
            TRANSFER_TIMEOUT_SECONDS, deadline
        ))
        if (
            str(disk.get("id", "")).lower() != expected_disk.lower()
            or str(disk.get("managedBy") or "").lower()
            != expected_vm.lower()
        ):
            raise RuntimeError("Private host disk provenance is invalid")
        disk_uuid = self.require_resource_uuid(
            disk.get("uniqueId"), "Private host disk identity"
        )
        if receipt["disk_uuid"] != disk_uuid:
            raise RuntimeError("Private host disk identity changed")
        receipt = {**receipt, "phase": "resources-verified"}
        self.record("host-resources-verified", host_deployment=receipt)
        settling_deadline = min(
            (
                deadline if deadline is not None
                else self.state["deadline_monotonic"]
            ),
            time.monotonic() + RECONCILE_TIMEOUT_SECONDS,
        )
        self.settle_host_identity(settling_deadline)
        return receipt

    def verify_vm_identity(self, vm=None, require_attachment=True):
        receipt = self.state.get("host_deployment")
        if (
            not isinstance(receipt, dict)
            or receipt.get("phase") not in (
                "deployment-succeeded", "deployment-terminal",
                "vm-verified", "resources-verified",
            )
            or receipt.get("vm_uuid") is None
            or receipt.get("disk_uuid") is None
        ):
            raise RuntimeError("Private host VM identity is unproven")
        if vm is None:
            vm = self.az([
                "vm", "show", "--resource-group", self.group,
                "--name", self.host_vm,
            ])
        self.require_operation_owned(vm)
        attached = (
            vm.get("storageProfile", {}).get("osDisk", {})
            .get("managedDisk", {}).get("id")
        )
        if (
            str(vm.get("id", "")).lower() != receipt["vm_id"].lower()
            or vm.get("vmId") != receipt["vm_uuid"]
            or (
                require_attachment
                and str(attached or "").lower()
                != receipt["disk_id"].lower()
            )
        ):
            raise RuntimeError("Private host VM identity changed")
        return vm

    def verify_host_identity(self, vm=None, disk=None):
        receipt = self.state.get("host_deployment")
        required = {
            "phase", "operation_id", "deployment_id", "correlation_id",
            "vm_id", "vm_uuid", "disk_id", "disk_uuid", "shutdown_time",
        }
        if (
            not isinstance(receipt, dict)
            or set(receipt) != required
            or receipt["phase"] != "resources-verified"
            or receipt["vm_uuid"] is None
            or receipt["disk_uuid"] is None
        ):
            raise RuntimeError("Private host VM/disk identity is unproven")
        if vm is None:
            vm = self.verify_vm_identity()
        else:
            self.verify_vm_identity(vm)
        if disk is None:
            disk = self.az([
                "disk", "show", "--resource-group", self.group,
                "--name", self.host_disk,
            ])
        self.require_operation_owned(disk)
        attached = (
            vm.get("storageProfile", {}).get("osDisk", {})
            .get("managedDisk", {}).get("id")
        )
        if (
            str(vm.get("id", "")).lower() != receipt["vm_id"].lower()
            or vm.get("vmId") != receipt["vm_uuid"]
            or str(attached or "").lower() != receipt["disk_id"].lower()
            or str(disk.get("id", "")).lower()
            != receipt["disk_id"].lower()
            or disk.get("uniqueId") != receipt["disk_uuid"]
            or str(disk.get("managedBy") or "").lower()
            != receipt["vm_id"].lower()
        ):
            raise RuntimeError(
                "Private host VM/disk identity or attachment changed"
            )
        return vm, disk

    def settle_host_identity(self, deadline):
        while time.monotonic() < deadline:
            try:
                vm, disk = self.verify_host_identity()
                vm_state = vm.get("provisioningState")
                disk_state = disk.get("provisioningState")
                if (
                    vm_state in (None, "Succeeded")
                    and disk_state in (None, "Succeeded")
                ):
                    return vm, disk
                if vm_state in ("Failed", "Canceled") or disk_state in (
                    "Failed", "Canceled",
                ):
                    raise RuntimeError(
                        "Private host provisioning reached a terminal state"
                    )
            except RuntimeError:
                pass
            if deadline - time.monotonic() > 1:
                time.sleep(min(2, deadline - time.monotonic()))
        raise RuntimeError(
            "Private host identity or metadata did not settle"
        ) from None

    def reconcile_host_deployment(self, deadline):
        receipt = self.state.get("host_deployment")
        if not isinstance(receipt, dict) or receipt.get("phase") not in (
            "pending", "deployment-succeeded", "resources-verified",
            "deployment-terminal", "vm-verified", "failed-no-compute",
            "not-created-empty",
        ):
            raise RuntimeError("Private host deployment obligation is invalid")
        if receipt["phase"] == "resources-verified":
            self.settle_host_identity(deadline)
            return True
        if receipt["phase"] == "vm-verified":
            self.capture_host_identity(deadline)
            return True
        if receipt["phase"] == "failed-no-compute":
            return False
        if receipt["phase"] == "not-created-empty":
            return False
        absent_empty = 0
        last_error = None
        while time.monotonic() < deadline:
            try:
                deployment = self.az([
                    "deployment", "group", "show",
                    "--resource-group", self.group,
                    "--name", self.prefix + "-host",
                ], timeout=max(
                    1, min(30, int(deadline - time.monotonic()))
                ))
                properties = (
                    deployment.get("properties")
                    if isinstance(deployment, dict) else None
                )
                self.validate_deployment_identity(deployment)
                provisioned = (
                    properties.get("provisioningState")
                    if isinstance(properties, dict) else None
                )
                if provisioned == "Succeeded":
                    self.validate_deployment_result(deployment)
                    self.capture_host_identity(deadline)
                    return True
                if provisioned in ("Failed", "Canceled"):
                    resources = self.az([
                        "resource", "list", "--resource-group", self.group,
                    ])
                    has_compute = any(
                        str(resource.get("type", "")).lower()
                        in (
                            "microsoft.compute/virtualmachines",
                            "microsoft.compute/disks",
                        )
                        for resource in resources
                    )
                    if has_compute:
                        correlation = self.require_resource_uuid(
                            properties.get("correlationId"),
                            "Private host deployment correlation",
                        )
                        terminal = {
                            **receipt,
                            "phase": "deployment-terminal",
                            "correlation_id": correlation,
                        }
                        self.record(
                            "host-deployment-terminal",
                            host_deployment=terminal,
                        )
                        raise RuntimeError(
                            "Terminal private host deployment left "
                            "unanchored compute resources"
                        )
                    failed = {**receipt, "phase": "failed-no-compute"}
                    self.record(
                        "host-deployment-failed-no-compute",
                        host_deployment=failed,
                    )
                    return False
            except (azure.AzureCliError, azure.AzureCliTimeout) as error:
                last_error = error
                if (
                    isinstance(error, azure.AzureCliError)
                    and error.code in (
                        "ResourceNotFound", "DeploymentNotFound"
                    )
                ):
                    resources = self.az([
                        "resource", "list", "--resource-group", self.group,
                    ])
                    if resources == []:
                        absent_empty += 1
                        if absent_empty >= 3:
                            absent = {
                                **receipt, "phase": "not-created-empty"
                            }
                            self.record(
                                "host-deployment-not-created",
                                host_deployment=absent,
                            )
                            return False
                    else:
                        raise RuntimeError(
                            "Missing deployment has unexpected resources"
                        )
            if deadline - time.monotonic() > 1:
                time.sleep(min(2, deadline - time.monotonic()))
        raise RuntimeError(
            "Private host deployment provenance could not be reconciled"
        ) from None

    def verify_host_security_profile(self):
        receipt = self.state["host_deployment"]
        resource = self.az([
            "resource", "show", "--ids", receipt["vm_id"],
            "--api-version", HOST_COMPUTE_API_VERSION,
        ])
        if (
            not isinstance(resource, dict)
            or str(resource.get("type", "")).lower()
            != "microsoft.compute/virtualmachines"
            or not isinstance(resource.get("properties"), dict)
        ):
            raise RuntimeError("Private host security response is incompatible")
        properties = resource["properties"]
        storage_profile = properties.get("storageProfile")
        if (
            not isinstance(resource.get("tags"), dict)
            or not isinstance(storage_profile, dict)
            or not isinstance(storage_profile.get("osDisk"), dict)
            or not isinstance(
                storage_profile["osDisk"].get("managedDisk"), dict
            )
        ):
            raise RuntimeError("Private host security response is incompatible")
        self.verify_vm_identity({
            **properties,
            "id": resource.get("id"),
            "tags": resource.get("tags"),
        })
        security = properties.get("securityProfile")
        if (
            properties.get("provisioningState") != "Succeeded"
            or not isinstance(security, dict)
            or not set(security).issubset({
                "securityType", "encryptionAtHost", "encryptionIdentity",
                "proxyAgentSettings", "uefiSettings",
            })
            or security.get("securityType") != "Standard"
            or (
                security.get("encryptionAtHost") is not None
                and security["encryptionAtHost"] is not False
            )
            or any(
                security.get(field) is not None
                for field in (
                    "encryptionIdentity", "proxyAgentSettings", "uefiSettings",
                )
            )
        ):
            raise RuntimeError("Private host security profile is incompatible")

    @staticmethod
    def verify_host_disk_size(disk, description):
        if not isinstance(disk, dict):
            raise RuntimeError(
                f"Private preflight {description} size metadata is incompatible"
            )
        # AAZ commands preserve GB; older SDK-based commands emitted Gb.
        sizes = [
            disk[field] for field in ("diskSizeGB", "diskSizeGb")
            if field in disk
        ]
        if (
            not sizes
            or any(type(size) is not int or size != 32 for size in sizes)
        ):
            raise RuntimeError(
                f"Private preflight {description} size metadata is incompatible"
            )

    def verify_deployed_envelope(self):
        receipt = self.state["host_deployment"]
        vm, disk = self.settle_host_identity(min(
            self.state["deadline_monotonic"],
            time.monotonic() + RECONCILE_TIMEOUT_SECONDS,
        ))
        image = self.state["cloud_preflight"]["image"]
        storage_profile = vm.get("storageProfile", {})
        os_disk = storage_profile.get("osDisk", {})
        image_reference = storage_profile.get("imageReference", {})
        interfaces = vm.get("networkProfile", {}).get("networkInterfaces")
        ids = self.expected_host_ids()
        self.verify_host_disk_size(os_disk, "VM OS disk")
        self.verify_host_disk_size(disk, "managed OS disk")
        if (
            vm.get("provisioningState") != "Succeeded"
            or vm.get("location") != LOCATION
            or vm.get("hardwareProfile", {}).get("vmSize") != VM_SIZE
            or storage_profile.get("dataDisks") != []
            or os_disk.get("createOption") != "FromImage"
            or os_disk.get("caching") != "ReadWrite"
            or os_disk.get("deleteOption") != "Delete"
            or any(
                image_reference.get(key) != image[key]
                for key in ("publisher", "offer", "sku", "version")
            )
            or not isinstance(interfaces, list)
            or len(interfaces) != 1
            or str(interfaces[0].get("id", "")).lower()
            != ids["nic_id"].lower()
            or interfaces[0].get("primary") is not True
            or interfaces[0].get("deleteOption") != "Delete"
            or disk.get("location") != LOCATION
            or disk.get("sku", {}).get("name") != "StandardSSD_LRS"
            or disk.get("osType") != "Linux"
            or disk.get("hyperVGeneration") != "V2"
        ):
            raise RuntimeError("Private preflight host envelope is incompatible")
        self.verify_host_security_profile()
        nic = self.az([
            "network", "nic", "show", "--resource-group", self.group,
            "--name", self.host_nic,
        ])
        self.require_operation_owned(nic)
        configurations = nic.get("ipConfigurations")
        subnet_id = (
            ids["vnet_id"] + "/subnets/preflight"
        )
        if (
            str(nic.get("id", "")).lower() != ids["nic_id"].lower()
            or nic.get("location") != LOCATION
            or nic.get("enableAcceleratedNetworking") is not False
            or nic.get("enableIPForwarding") is not False
            or nic.get("networkSecurityGroup") is not None
            or not isinstance(configurations, list)
            or len(configurations) != 1
            or configurations[0].get("name") != "private"
            or configurations[0].get("primary") is not True
            or configurations[0].get("privateIPAddressVersion") != "IPv4"
            or configurations[0].get("publicIPAddress") is not None
            or configurations[0].get("privateIPAllocationMethod") != "Static"
            or configurations[0].get("privateIPAddress") != "10.88.0.4"
            or str(
                configurations[0].get("subnet", {}).get("id", "")
            ).lower() != subnet_id.lower()
        ):
            raise RuntimeError("Private preflight NIC envelope is incompatible")
        nsg = self.az([
            "network", "nsg", "show", "--resource-group", self.group,
            "--name", self.prefix + "-nsg",
        ])
        self.require_operation_owned(nsg)
        expected_rules = {
            "AllowAzurePlatformAgent": (
                120, "Allow", "Outbound", "Tcp", ("80", "32526"),
                "VirtualNetwork", "168.63.129.16/32",
            ),
            "AllowRegionalStorage": (
                130, "Allow", "Outbound", "Tcp", "443",
                "VirtualNetwork", "Storage.NorthEurope",
            ),
            "DenyAllInbound": (
                4095, "Deny", "Inbound", "*", "*", "*", "*",
            ),
            "DenyAllOutbound": (
                4096, "Deny", "Outbound", "*", "*", "*", "*",
            ),
        }
        rules = nsg.get("securityRules")
        if (
            str(nsg.get("id", "")).lower() != ids["nsg_id"].lower()
            or nsg.get("location") != LOCATION
            or not isinstance(rules, list)
            or {rule.get("name") for rule in rules} != set(expected_rules)
        ):
            raise RuntimeError("Private preflight NSG envelope is incompatible")
        for rule in rules:
            expected = expected_rules[rule["name"]]
            destination_ports = (
                tuple(rule.get("destinationPortRanges", ()))
                if expected[4] == ("80", "32526")
                else rule.get("destinationPortRange")
            )
            if (
                (
                    rule.get("priority"), rule.get("access"),
                    rule.get("direction"), rule.get("protocol"),
                    destination_ports, rule.get("sourceAddressPrefix"),
                    rule.get("destinationAddressPrefix"),
                ) != expected
                or rule.get("sourcePortRange") != "*"
                or rule.get("sourcePortRanges") not in (None, [])
                or (
                    expected[4] != ("80", "32526")
                    and rule.get("destinationPortRanges") not in (None, [])
                )
                or rule.get("sourceAddressPrefixes") not in (None, [])
                or rule.get("destinationAddressPrefixes") not in (None, [])
            ):
                raise RuntimeError(
                    "Private preflight NSG rule set is incompatible"
                )
        vnet = self.az([
            "network", "vnet", "show", "--resource-group", self.group,
            "--name", self.prefix + "-vnet",
        ])
        self.require_operation_owned(vnet)
        if (
            str(vnet.get("id", "")).lower() != ids["vnet_id"].lower()
            or vnet.get("location") != LOCATION
            or vnet.get("addressSpace", {}).get("addressPrefixes")
            != ["10.88.0.0/29"]
            or vnet.get("virtualNetworkPeerings") not in (None, [])
            or vnet.get("enableDdosProtection") not in (None, False)
            or not isinstance(vnet.get("subnets"), list)
            or len(vnet["subnets"]) != 1
        ):
            raise RuntimeError("Private preflight VNet envelope is incompatible")
        subnet = self.az([
            "network", "vnet", "subnet", "show",
            "--resource-group", self.group,
            "--vnet-name", self.prefix + "-vnet",
            "--name", "preflight",
        ])
        endpoints = subnet.get("serviceEndpoints")
        if (
            str(subnet.get("id", "")).lower() != subnet_id.lower()
            or subnet.get("addressPrefix") != "10.88.0.0/29"
            or subnet.get("defaultOutboundAccess") is not False
            or subnet.get("natGateway") is not None
            or subnet.get("publicIpAddressPool") is not None
            or subnet.get("ipAllocations") not in (None, [])
            or subnet.get("delegations") not in (None, [])
            or subnet.get("routeTable") is not None
            or subnet.get("applicationGatewayIPConfigurations")
            not in (None, [])
            or subnet.get("serviceEndpointPolicies") not in (None, [])
            or str(
                subnet.get("networkSecurityGroup", {}).get("id", "")
            ).lower() != ids["nsg_id"].lower()
            or not isinstance(endpoints, list)
            or len(endpoints) != 1
            or endpoints[0].get("service") != "Microsoft.Storage"
            or endpoints[0].get("locations") not in (
                ["northeurope", "westeurope"],
                ["westeurope", "northeurope"],
            )
            or endpoints[0].get("provisioningState")
            not in (None, "Succeeded")
        ):
            raise RuntimeError("Private preflight subnet envelope is incompatible")
        storage = self.az([
            "storage", "account", "show", "--resource-group", self.group,
            "--name", self.storage,
        ])
        self.require_operation_owned(storage)
        rules = storage.get("networkRuleSet", {})
        if (
            str(storage.get("id", "")).lower() != ids["storage_id"].lower()
            or storage.get("location") != LOCATION
            or storage.get("kind") != "StorageV2"
            or storage.get("sku", {}).get("name") != "Standard_LRS"
            or storage.get("allowBlobPublicAccess") is not False
            or storage.get("allowSharedKeyAccess") is not True
            or storage.get("defaultToOAuthAuthentication") is not False
            or storage.get("minimumTlsVersion") != "TLS1_2"
            or storage.get("publicNetworkAccess") != "Enabled"
            or storage.get("enableHttpsTrafficOnly") is not True
            or storage.get("privateEndpointConnections") not in (None, [])
            or rules.get("resourceAccessRules") not in (None, [])
        ):
            raise RuntimeError("Private preflight storage envelope is incompatible")
        self.verify_storage_rules()
        schedule = self.az([
            "resource", "show", "--resource-group", self.group,
            "--resource-type", "Microsoft.DevTestLab/schedules",
            "--name", "shutdown-computevm-" + self.host_vm,
            "--api-version", "2018-09-15",
        ])
        self.require_operation_owned(schedule)
        properties = schedule.get("properties", {})
        if (
            properties.get("status") != "Enabled"
            or str(schedule.get("id", "")).lower()
            != ids["schedule_id"].lower()
            or schedule.get("location") != LOCATION
            or properties.get("taskType") != "ComputeVmShutdownTask"
            or str(properties.get("targetResourceId", "")).lower()
            != receipt["vm_id"].lower()
            or properties.get("dailyRecurrence", {}).get("time")
            != receipt["shutdown_time"]
            or properties.get("timeZoneId") != "UTC"
        ):
            raise RuntimeError("Private host auto-shutdown backstop is invalid")
        self.verify_resource_inventory()
        self.record(
            "host-created",
            host_vm_id=receipt["vm_id"],
            host_disk_id=receipt["disk_id"],
            host_nic_id=ids["nic_id"],
            storage_account_id=ids["storage_id"],
            shutdown_schedule_id=schedule["id"],
        )

    def verify_resource_inventory(self):
        resources = self.az([
            "resource", "list", "--resource-group", self.group,
        ])
        if not isinstance(resources, list):
            raise RuntimeError("Azure returned an invalid resource inventory")
        expected = {
            ("microsoft.network/networksecuritygroups", self.prefix + "-nsg"),
            ("microsoft.network/virtualnetworks", self.prefix + "-vnet"),
            ("microsoft.storage/storageaccounts", self.storage),
            ("microsoft.network/networkinterfaces", self.host_nic),
            ("microsoft.compute/virtualmachines", self.host_vm),
            ("microsoft.compute/disks", self.host_disk),
            (
                "microsoft.devtestlab/schedules",
                "shutdown-computevm-" + self.host_vm,
            ),
        }
        actual = {
            (str(resource.get("type", "")).lower(), resource.get("name"))
            for resource in resources
        }
        if actual != expected:
            raise RuntimeError(
                "Private preflight resource inventory is not exact"
            )
        for resource in resources:
            key = (str(resource.get("type", "")).lower(), resource.get("name"))
            if key == (
                "microsoft.compute/disks", self.host_disk
            ):
                self.verify_host_identity()
            else:
                self.require_operation_owned(resource)

    def deploy_host(self, shutdown_time):
        receipt = self.begin_host_deployment(shutdown_time)
        password = "Uk!" + secrets.token_urlsafe(32) + "a7"
        image = self.state["cloud_preflight"]["image"]
        parameters = {
            "namePrefix": self.prefix,
            "location": LOCATION,
            "imageSha256": self.state["image_sha256"],
            "storageAccountName": self.storage,
            "hostImageVersion": image["version"],
            "operationId": receipt["operation_id"],
            "adminPassword": password,
            "shutdownTime": shutdown_time,
        }
        reconciliation_error = None
        try:
            with self.private_parameters(parameters) as parameter_file:
                deployment = self.az([
                    "deployment", "group", "create",
                    "--resource-group", self.group,
                    "--name", self.prefix + "-host", "--mode", "Incremental",
                    "--template-file", str(TEMPLATE_PATH),
                    "--parameters", "@" + str(parameter_file),
                ], timeout=self.phase_timeout(900))
            self.validate_deployment_result(deployment)
            self.capture_host_identity(self.state["deadline_monotonic"])
        except (RuntimeError, ValueError, OSError) as primary:
            reconcile_deadline = min(
                self.deadline,
                time.monotonic() + RECONCILE_TIMEOUT_SECONDS,
            )
            try:
                reconciled = self.reconcile_host_deployment(
                    reconcile_deadline
                )
            except (RuntimeError, ValueError, OSError) as reconciliation:
                reconciliation_error = PrivateHostDeploymentReconciliationError(
                    primary, reconciliation
                )
            else:
                if not reconciled:
                    raise
        finally:
            password = None
        if reconciliation_error is not None:
            raise reconciliation_error
        self.verify_deployed_envelope()

    def verify_storage_rules(self, transfer_cidr=None, *, enforce_deadline=True):
        timeout = (
            self.phase_timeout(TRANSFER_TIMEOUT_SECONDS)
            if enforce_deadline else TRANSFER_TIMEOUT_SECONDS
        )
        storage = self.az([
            "storage", "account", "show", "--resource-group", self.group,
            "--name", self.storage,
        ], timeout=timeout)
        self.require_owned(storage)
        rules = storage.get("networkRuleSet")
        if (
            not isinstance(rules, dict)
            or rules.get("defaultAction") != "Deny"
            or rules.get("bypass") != "None"
            or rules.get("resourceAccessRules") not in (None, [])
        ):
            raise RuntimeError("Private Blob firewall is invalid")
        ip_rules = rules.get("ipRules")
        if not isinstance(ip_rules, list):
            raise RuntimeError("Private Blob firewall IP rules are invalid")
        expected_ip = (
            None if transfer_cidr is None
            else transfer_source(transfer_cidr).removesuffix("/32")
        )
        if (
            len(ip_rules) != (0 if expected_ip is None else 1)
            or any(
                not isinstance(item, dict)
                or set(item) - {"ipAddressOrRange", "action"}
                or item.get("ipAddressOrRange") != expected_ip
                or item.get("action") not in (None, "Allow")
                for item in ip_rules
            )
        ):
            raise RuntimeError("Private Blob transfer firewall is not exact")
        expected_subnet = (
            self.state["resource_group_id"].rstrip("/")
            + "/providers/Microsoft.Network/virtualNetworks/"
            + self.prefix + "-vnet/subnets/preflight"
        )
        subnet_rules = rules.get("virtualNetworkRules")
        if (
            not isinstance(subnet_rules, list)
            or len(subnet_rules) != 1
            or not isinstance(subnet_rules[0], dict)
            or str(
                subnet_rules[0].get("virtualNetworkResourceId", "")
            ).lower() != expected_subnet.lower()
            or subnet_rules[0].get("action") != "Allow"
            or subnet_rules[0].get("state") not in (None, "Succeeded")
        ):
            raise RuntimeError("Private Blob subnet rule is not exact")

    @contextmanager
    def transfer_access(self, transfer_cidr):
        if self.state.get("firewall_obligation") is not None:
            raise RuntimeError(
                "An unresolved private Blob firewall obligation exists"
            )
        transfer_cidr = transfer_source(transfer_cidr)
        obligation = {"cidr": transfer_cidr, "phase": "pending-add"}
        self.record(
            "blob-firewall-add-pending",
            firewall_obligation=obligation,
        )
        try:
            # Storage rejects /32 notation; the durable intent stays CIDR.
            self.az([
                "storage", "account", "network-rule", "add",
                "--resource-group", self.group,
                "--account-name", self.storage,
                "--ip-address", transfer_cidr.removesuffix("/32"),
            ], timeout=self.phase_timeout(TRANSFER_TIMEOUT_SECONDS))
            self.verify_storage_rules(transfer_cidr)
            obligation = {"cidr": transfer_cidr, "phase": "active"}
            self.record(
                "blob-firewall-active",
                firewall_obligation=obligation,
            )
            yield
        finally:
            self.record(
                "blob-firewall-remove-pending",
                firewall_obligation={
                    "cidr": transfer_cidr, "phase": "pending-remove"
                },
            )
            self.clear_firewall_obligation()

    def clear_firewall_obligation(self):
        obligation = self.state.get("firewall_obligation")
        if obligation is None:
            return
        if (
            not isinstance(obligation, dict)
            or set(obligation) != {"cidr", "phase"}
            or obligation["phase"] not in (
                "pending-add", "active", "pending-remove"
            )
        ):
            raise RuntimeError("Private Blob firewall obligation is invalid")
        try:
            network = ipaddress.ip_network(obligation["cidr"], strict=True)
        except ValueError:
            raise RuntimeError("Private Blob firewall CIDR is invalid") from None
        if network.version != 4 or network.prefixlen != 32:
            raise RuntimeError("Private Blob firewall CIDR is invalid")
        cidr = str(network)
        self.record(
            "blob-firewall-remove-pending",
            firewall_obligation={"cidr": cidr, "phase": "pending-remove"},
        )
        if self.az(["group", "exists", "--name", self.group]) is False:
            self.record(
                "blob-firewall-absent", firewall_obligation=None
            )
            return
        group = self.az(["group", "show", "--name", self.group])
        self.require_owned_group(group)
        storage = self.az([
            "storage", "account", "show", "--resource-group", self.group,
            "--name", self.storage,
        ])
        self.require_operation_owned(storage)
        self.az([
            "storage", "account", "network-rule", "remove",
            "--resource-group", self.group,
            "--account-name", self.storage,
            "--ip-address", str(network.network_address),
        ])
        self.verify_storage_rules(enforce_deadline=False)
        self.record("blob-firewall-cleared", firewall_obligation=None)

    def generate_sas(self):
        keys = self.az([
            "storage", "account", "keys", "list",
            "--resource-group", self.group, "--account-name", self.storage,
        ], timeout=self.phase_timeout(TRANSFER_TIMEOUT_SECONDS))
        primary = next((
            item.get("value") for item in keys
            if isinstance(item, dict)
            and item.get("keyName") == "key1"
            and isinstance(item.get("value"), str)
        ), None) if isinstance(keys, list) else None
        if not primary:
            raise RuntimeError("Private Blob signing key is unavailable")
        signing_key_sha256 = hashlib.sha256(primary.encode()).hexdigest()
        self.record(
            "issuing-sas", active_sas=True,
            active_sas_signing_key_sha256=signing_key_sha256,
        )
        expiry = datetime.now(timezone.utc) + timedelta(
            seconds=self.phase_timeout(MAX_ATTEMPT_SECONDS)
        )
        sas = self.az([
            "storage", "account", "generate-sas",
            "--account-name", self.storage,
            "--services", "b", "--resource-types", "sco",
            "--permissions", "rcw",
            "--expiry", utc_text(expiry), "--https-only",
        ], env={"AZURE_STORAGE_KEY": primary},
           timeout=self.phase_timeout(TRANSFER_TIMEOUT_SECONDS))
        if (
            not isinstance(sas, str)
            or not sas
            or len(sas.encode()) > MAX_BLOB_SAS_BYTES
            or any(character.isspace() for character in sas)
        ):
            raise RuntimeError("Azure did not return a bounded private Blob SAS")
        token = {
            "value": sas.lstrip("?"),
            "signing_key_sha256": signing_key_sha256,
        }
        primary = None
        self.record(
            "sas-issued", active_sas=True,
            active_sas_signing_key_sha256=token["signing_key_sha256"],
        )
        return token

    def revoke_sas(self, token):
        self.az([
            "storage", "account", "keys", "renew",
            "--resource-group", self.group, "--account-name", self.storage,
            "--key", "primary",
        ])
        keys = self.az([
            "storage", "account", "keys", "list",
            "--resource-group", self.group, "--account-name", self.storage,
        ])
        primary = next((
            item.get("value") for item in keys
            if isinstance(item, dict)
            and item.get("keyName") == "key1"
            and isinstance(item.get("value"), str)
        ), None) if isinstance(keys, list) else None
        if (
            not primary
            or hashlib.sha256(primary.encode()).hexdigest()
            == token["signing_key_sha256"]
        ):
            raise RuntimeError("Private Blob SAS revocation did not complete")
        self.record(
            "sas-revoked", active_sas=False,
            active_sas_signing_key_sha256=None,
        )

    @contextmanager
    def private_request(self, value):
        with self.tracked_private_json("run-command", value) as path:
            yield path

    def run_host_phase(self, phase, manifest, sas):
        runner_source = azure.read_regular_file(
            RUNNER_PATH, 1024 * 1024, "Private-preflight host runner"
        )
        manifest_bytes = azure.canonical_json(manifest)
        script = "\n".join((
            "set -eu",
            "umask 077",
            "command -v python3 >/dev/null",
            "command -v base64 >/dev/null",
            "command -v timeout >/dev/null",
            "root=/var/lib/unikraft-private-preflight",
            "mkdir -p \"$root\"",
            (
                "printf '%s' "
                + shlex.quote(base64.b64encode(runner_source).decode())
                + " | base64 -d > \"$root/runner.py\""
            ),
            (
                "test \"$#\" -eq 1; "
                "HYPERV_PREFLIGHT_SAS=\"$1\""
                + " timeout --signal=KILL "
                + str(self.phase_timeout(900)) + "s"
                + " python3 \"$root/runner.py\""
                + " --phase " + shlex.quote(phase)
                + " --manifest-b64 "
                + shlex.quote(base64.b64encode(manifest_bytes).decode())
                + " --blob-base-url "
                + shlex.quote(f"https://{self.storage}.blob.core.windows.net")
                + " --container " + shlex.quote(self.container)
            ),
        ))
        request = {
            "commandId": "RunShellScript",
            "script": [script],
            "protectedParameters": [{"name": "sas", "value": sas}],
        }
        request_bytes = azure.canonical_json(request)
        self.account_bytes("control", len(request_bytes))
        url = (
            self.state["host_vm_id"]
            + "/runCommand?api-version=2024-11-01"
        )
        with self.private_request(request) as request_path:
            response = self.az([
                "rest", "--method", "post", "--url", url,
                "--body", "@" + str(request_path),
            ], timeout=self.phase_timeout(900))
        values = response.get("value") if isinstance(response, dict) else None
        if not isinstance(values, list):
            raise RuntimeError("Private RunCommand returned no bounded result")
        stdout = []
        output_bytes = 0
        for item in values:
            if not isinstance(item, dict):
                raise RuntimeError("Private RunCommand result is malformed")
            code = item.get("code")
            message = item.get("message")
            if not isinstance(code, str) or not isinstance(message, str):
                raise RuntimeError("Private RunCommand result is malformed")
            output_bytes += len(message.encode("utf-8"))
            if output_bytes > MAX_MANIFEST_BYTES:
                raise RuntimeError("Private RunCommand result exceeds its size limit")
            if "/StdOut/" in code:
                stdout.append(message)
            elif "/StdErr/" in code and message.strip():
                raise RuntimeError("Private RunCommand reported a private-host failure")
        lines = [
            line.strip() for message in stdout for line in message.splitlines()
            if line.strip().startswith("HYPERV_PRIVATE_PREFLIGHT ")
        ]
        if len(lines) != 1:
            raise RuntimeError("Private RunCommand result is missing or duplicated")
        record = azure.parse_strict_json(
            lines[0].removeprefix("HYPERV_PRIVATE_PREFLIGHT ").encode("utf-8"),
            "Private RunCommand result",
        )
        record = exact_fields(
            record,
            (
                "schema", "phase", "result", "identity",
                "receipt_sha256", "boot_count",
            ),
            "Private RunCommand result",
        )
        expected_boots = 2 if phase == "capability" else 4
        if (
            type(record["schema"]) is not int
            or record["schema"] != 1
            or record["phase"] != phase
            or record["result"] != "PASS"
            or record["identity"] != self.state["identity"]
            or require_sha256(
                record["receipt_sha256"], "Host receipt fingerprint"
            ) != record["receipt_sha256"]
            or type(record["boot_count"]) is not int
            or record["boot_count"] != expected_boots
        ):
            raise RuntimeError("Private RunCommand did not prove its exact phase")
        self.record(
            phase + "-passed",
            **{phase + "_receipt_sha256": record["receipt_sha256"]},
        )
        return record

    def verified_host_disk_for_cleanup(self, resource):
        receipt = self.state.get("host_deployment")
        if (
            not isinstance(receipt, dict)
            or receipt.get("phase") != "resources-verified"
        ):
            raise RuntimeError("Refusing to clean an unproven host OS disk")
        if (
            str(resource.get("id", "")).lower()
            != receipt["disk_id"].lower()
            or resource.get("name") != self.host_disk
            or str(resource.get("type", "")).lower()
            != "microsoft.compute/disks"
        ):
            raise RuntimeError("Refusing to clean an unproven host OS disk")
        self.require_operation_owned(resource)
        self.verify_host_identity()

    def require_owned_vm_child(self, resource):
        receipt = self.state.get("host_deployment")
        if (
            not isinstance(receipt, dict)
            or receipt.get("phase") != "resources-verified"
        ):
            raise RuntimeError(
                "Refusing to clean an unproven host extension child"
            )
        resource_id = str(resource.get("id", ""))
        expected_prefix = receipt["vm_id"].rstrip("/") + "/extensions/"
        child = resource_id[len(expected_prefix):]
        name = resource.get("name")
        if (
            not resource_id.lower().startswith(expected_prefix.lower())
            or not child
            or "/" in child
            or str(resource.get("type", "")).lower()
            != "microsoft.compute/virtualmachines/extensions"
            or name not in (child, self.host_vm + "/" + child)
            or resource.get("location") not in (None, LOCATION)
        ):
            raise RuntimeError(
                "Refusing to clean an unproven host extension child"
            )

    def deallocate_host(self):
        if self.state.get("host_deallocated") is True:
            return
        receipt = self.state.get("host_deployment")
        if not isinstance(receipt, dict):
            return
        if receipt.get("phase") in ("pending", "deployment-terminal"):
            try:
                if not self.reconcile_host_deployment(
                    min(
                        self.cleanup_deadline
                        or self.state["deadline_monotonic"],
                        time.monotonic() + RECONCILE_TIMEOUT_SECONDS,
                    )
                ):
                    return
            except (RuntimeError, ValueError, OSError):
                receipt = self.state.get("host_deployment")
                if (
                    not isinstance(receipt, dict)
                    or receipt.get("phase") not in (
                        "deployment-succeeded", "deployment-terminal",
                        "vm-verified", "resources-verified",
                    )
                    or receipt.get("correlation_id") is None
                    or receipt.get("vm_uuid") is None
                    or receipt.get("disk_uuid") is None
                ):
                    raise
            receipt = self.state["host_deployment"]
        if receipt.get("phase") in (
            "failed-no-compute", "not-created-empty"
        ):
            return
        self.verify_vm_identity(require_attachment=False)
        self.az([
            "vm", "deallocate", "--resource-group", self.group,
            "--name", self.host_vm,
        ], timeout=300)
        self.verify_vm_identity(require_attachment=False)
        view = self.az([
            "vm", "get-instance-view", "--resource-group", self.group,
            "--name", self.host_vm,
        ])
        statuses = view.get("instanceView", {}).get("statuses", [])
        if not any(
            isinstance(item, dict)
            and item.get("code") == "PowerState/deallocated"
            for item in statuses
        ):
            raise RuntimeError("Private host deallocation did not complete")
        self.record("host-deallocated", host_deallocated=True)

    def delete_owned_group(self):
        if self.az(["group", "exists", "--name", self.group]) is False:
            self.record("cleaned", cleanup_required=False)
            return
        group = self.az(["group", "show", "--name", self.group])
        self.require_owned_group(group)
        resources = self.az([
            "resource", "list", "--resource-group", self.group,
        ])
        if not isinstance(resources, list):
            raise RuntimeError("Azure returned an invalid resource inventory")
        receipt = self.state.get("host_deployment")
        if receipt is None:
            if resources:
                raise RuntimeError(
                    "Refusing to delete an unproven nonempty private group"
                )
        elif receipt.get("phase") == "resources-verified":
            self.verify_host_identity()
        elif receipt.get("phase") == "failed-no-compute":
            deployment = self.az([
                "deployment", "group", "show",
                "--resource-group", self.group,
                "--name", self.prefix + "-host",
            ])
            properties = self.validate_deployment_identity(deployment)
            if properties.get("provisioningState") not in (
                "Failed", "Canceled"
            ) or any(
                str(resource.get("type", "")).lower() in (
                    "microsoft.compute/virtualmachines",
                    "microsoft.compute/disks",
                )
                for resource in resources
            ):
                raise RuntimeError(
                    "Refusing to delete an ambiguously provisioned group"
                )
        elif receipt.get("phase") == "not-created-empty":
            if resources:
                raise RuntimeError(
                    "Refusing to delete a nonempty undeployed group"
                )
        else:
            raise RuntimeError(
                "Refusing to delete an unreconciled private host group"
            )
        for resource in resources:
            resource_type = str(resource.get("type", "")).lower()
            if resource_type == "microsoft.compute/disks":
                self.verified_host_disk_for_cleanup(resource)
            elif (
                resource_type
                == "microsoft.compute/virtualmachines/extensions"
            ):
                self.require_owned_vm_child(resource)
            else:
                self.require_operation_owned(resource)
        self.record("deleting-group")
        self.az([
            "group", "delete", "--name", self.group, "--yes",
        ], timeout=900)
        if self.az(["group", "exists", "--name", self.group]) is not False:
            raise RuntimeError("Private resource-group deletion did not complete")
        self.record("cleaned", cleanup_required=False)

    def cleanup(self):
        if self.cleanup_deadline is None:
            self.cleanup_deadline = (
                time.monotonic() + CLEANUP_TIMEOUT_SECONDS
            )
        errors = []
        try:
            self.clear_private_files()
        except (RuntimeError, ValueError, OSError) as error:
            errors.append(("private-files", error))
        if self.state.get("firewall_obligation") is not None:
            try:
                self.clear_firewall_obligation()
            except (RuntimeError, ValueError, OSError) as error:
                errors.append(("firewall", error))
        if self.state.get("active_sas") is True:
            fingerprint = self.state.get("active_sas_signing_key_sha256")
            try:
                self.revoke_sas({"signing_key_sha256": require_sha256(
                    fingerprint, "Active private Blob signing key"
                )})
            except (RuntimeError, ValueError, OSError) as error:
                errors.append(("sas", error))
        try:
            self.deallocate_host()
        except (RuntimeError, ValueError, OSError) as error:
            errors.append(("deallocate", error))
        try:
            self.delete_owned_group()
        except (RuntimeError, ValueError, OSError) as error:
            errors.append(("resource-group", error))
        if errors:
            raise PrivateCleanupError(errors) from None


def host_phase_manifest(state, phase, capability_sha256=None):
    input_manifest = state["input_manifest"]
    roles = PUBLIC_ROLES if phase == "capability" else (
        "qemu", "ovmf_code", "ovmf_vars", *PRIVATE_ROLES
    )
    files = {}
    for role in roles:
        record = input_manifest["files"][role]
        source_phase = "public" if role in PUBLIC_ROLES else "private"
        files[role] = {
            **record,
            "blob": (
                f"inputs/{state['identity']}/{source_phase}/{record['name']}"
            ),
        }
    result = {
        "schema": HOST_PHASE_SCHEMA,
        "schema_version": 3,
        "phase": phase,
        "identity": state["identity"],
        "runner_sha256": state["implementation"]["files"]["runner"][
            "sha256"
        ],
        "input_manifest_sha256": state["manifest_sha256"],
        "workload": WORKLOAD,
        "boot_policy": (
            "platform-unavailable-v1"
            if phase == "capability"
            else input_manifest["boot_policy"]
        ),
        "guarded": (
            None if phase == "capability" else input_manifest["guarded"]
        ),
        "raw_size": input_manifest["raw_size"],
        "files": files,
        "qemu_support": [
            {
                "name": record["path"],
                "size": record["size"],
                "sha256": record["sha256"],
                "blob": (
                    f"inputs/{state['identity']}/public/{record['path']}"
                ),
            }
            for record in input_manifest["qemu_support"]
        ],
        "evidence_prefix": f"evidence/{state['identity']}/{phase}",
    }
    if phase == "private":
        result["capability_manifest_sha256"] = require_sha256(
            capability_sha256, "Capability manifest fingerprint"
        )
    host_runner.parse_manifest(
        base64.b64encode(azure.canonical_json(result)).decode(), phase
    )
    return result


def blob_files(state, state_directory, roles):
    result = []
    for role in roles:
        record = state["input_manifest"]["files"][role]
        phase = "public" if role in PUBLIC_ROLES else "private"
        result.append((
            f"inputs/{state['identity']}/{phase}/{record['name']}",
            state_directory / "inputs" / record["name"],
            record["size"], record["sha256"],
        ))
    if "qemu" in roles:
        known = {item[0] for item in result}
        for record in state["input_manifest"]["qemu_support"]:
            blob = f"inputs/{state['identity']}/public/{record['path']}"
            if blob not in known:
                result.append((
                    blob,
                    state_directory / "inputs" / record["path"],
                    record["size"], record["sha256"],
                ))
    return result


def validate_host_receipt(value, state, phase, manifest, logs):
    value = exact_fields(
        value,
        (
            "schema", "schema_version", "phase", "identity", "result",
            "manifest_sha256", "runner_sha256", "host_boot_id",
            "boot_policy", "acceptance_scope", "storage_result", "boots",
        ),
        "Private host evidence receipt",
    )
    formats = ("capability",) if phase == "capability" else ("raw", "vhd")
    boots = exact_fields(
        value["boots"], formats, "Private host boot formats"
    )
    for image_format in formats:
        modes = exact_fields(
            boots[image_format], ("x2apic", "legacy-apic"),
            "Private host APIC modes",
        )
        for mode in ("x2apic", "legacy-apic"):
            outcome = exact_fields(
                modes[mode], ("result", "log_sha256", "return_code"),
                "Private host boot outcome",
            )
            log_name = f"{image_format}-{mode}.log"
            if (
                outcome["result"] != "PASS"
                or require_sha256(
                    outcome["log_sha256"], "Private boot log fingerprint"
                ) != hashlib.sha256(logs[log_name]).hexdigest()
                or type(outcome["return_code"]) is not int
                or outcome["return_code"] != 0
            ):
                raise ValueError("Private host boot evidence is inconsistent")
    if (
        value["schema"] != HOST_EVIDENCE_SCHEMA
        or type(value["schema_version"]) is not int
        or value["schema_version"] != 2
        or value["phase"] != phase
        or value["identity"] != state["identity"]
        or value["result"] != "PASS"
        or value["manifest_sha256"]
        != hashlib.sha256(azure.canonical_json(manifest)).hexdigest()
        or value["runner_sha256"]
        != state["implementation"]["files"]["runner"]["sha256"]
        or require_uuid(
            value["host_boot_id"], "Private host boot identity"
        ) != value["host_boot_id"]
        or value["boot_policy"] != manifest["boot_policy"]
        or value["acceptance_scope"] != "platform-only"
        or value["storage_result"] != (
            "UNAVAILABLE"
            if manifest["boot_policy"] == GUARDED_BOOT_POLICY
            else "NOT_EVALUATED"
        )
    ):
        raise ValueError("Private host receipt is stale or mismatched")
    return value


def retrieve_phase_evidence(run, transfer_cidr, sas, phase, manifest):
    formats = ("capability",) if phase == "capability" else ("raw", "vhd")
    names = [
        f"{image_format}-{mode}.log"
        for image_format in formats
        for mode in ("x2apic", "legacy-apic")
    ]
    prefix = f"evidence/{run.state['identity']}/{phase}"
    with run.transfer_access(transfer_cidr):
        values = download_blob_set(
            run,
            f"https://{run.storage}.blob.core.windows.net",
            sas,
            run.container,
            [(prefix + "/receipt.json", MAX_MANIFEST_BYTES)] + [
                (prefix + "/" + name, host_runner.MAX_LOG_BYTES)
                for name in names
            ],
            run.deadline,
        )
    receipt_bytes = values[0]
    logs = dict(zip(names, values[1:]))
    run.account_bytes("evidence", sum(map(len, values)))
    receipt = validate_host_receipt(
        azure.parse_strict_json(
            receipt_bytes, "Private host evidence receipt"
        ),
        run.state, phase, manifest, logs,
    )
    if (
        hashlib.sha256(receipt_bytes).hexdigest()
        != run.state.get(phase + "_receipt_sha256")
    ):
        raise ValueError("Private host receipt differs from RunCommand proof")
    evidence_directory = run.state_path.parent / "evidence" / phase
    evidence_directory.mkdir(mode=0o700, parents=True, exist_ok=False)
    for name, content in logs.items():
        path = evidence_directory / name
        save_private_bytes(path, content)
    receipt_path = evidence_directory / "receipt.json"
    save_private_bytes(receipt_path, receipt_bytes)
    azure.fsync_directory(evidence_directory)
    return receipt


def _load_completed_host_evidence(
    state, state_directory, phase, manifest
):
    formats = ("capability",) if phase == "capability" else ("raw", "vhd")
    evidence_directory = state_directory / "evidence" / phase
    receipt_path = evidence_directory / "receipt.json"
    receipt_bytes = azure.read_regular_file(
        receipt_path, MAX_MANIFEST_BYTES,
        "Completed private host evidence receipt",
    )
    logs = {}
    for image_format in formats:
        for mode in ("x2apic", "legacy-apic"):
            name = f"{image_format}-{mode}.log"
            raw = azure.read_regular_file(
                evidence_directory / name, host_runner.MAX_LOG_BYTES,
                "Completed private host boot log",
            )
            try:
                text = raw.decode("utf-8")
            except UnicodeDecodeError:
                raise ValueError(
                    "Completed private host boot log is not UTF-8"
                ) from None
            host_runner.validate_boot_log(
                text,
                (
                    "platform-unavailable-v1"
                    if phase == "capability"
                    else state["input_manifest"]["boot_policy"]
                ),
                mode == "legacy-apic",
                (
                    None
                    if phase == "capability"
                    else state["input_manifest"]["guarded"]
                ),
            )
            logs[name] = raw
    receipt = validate_host_receipt(
        azure.parse_strict_json(
            receipt_bytes, "Completed private host evidence receipt"
        ),
        state, phase, manifest, logs,
    )
    digest = hashlib.sha256(receipt_bytes).hexdigest()
    if digest != require_sha256(
        state.get(phase + "_receipt_sha256"),
        "Completed private host evidence receipt",
    ):
        raise ValueError("Completed private host evidence receipt is stale")
    return receipt, digest, (
        len(receipt_bytes) + sum(len(raw) for raw in logs.values())
    )


def load_completed_receipt(state_directory):
    state, state_path = load_state(state_directory)
    state_directory = state_path.parent
    deployment = state.get("host_deployment")
    if (
        state.get("phase") != "complete"
        or state["cleanup_required"] is not False
        or state["pending_secret_files"] != []
        or state.get("firewall_obligation") is not None
        or state.get("active_sas") is not False
        or "active_sas_signing_key_sha256" not in state
        or state["active_sas_signing_key_sha256"] is not None
        or state.get("host_deallocated") is not True
        or not isinstance(deployment, dict)
        or deployment.get("phase") != "resources-verified"
        or not isinstance(state.get("resource_group_id"), str)
        or state.get("failure") is not None
        or state.get("cleanup_failure") is not None
    ):
        raise ValueError("Private preflight is not completely cleaned")
    verify_immutable_inputs(state, state_directory)
    manifest = state["input_manifest"]
    capability_manifest = host_phase_manifest(state, "capability")
    capability_manifest_sha256 = hashlib.sha256(
        azure.canonical_json(capability_manifest)
    ).hexdigest()
    if capability_manifest_sha256 != require_sha256(
        state.get("capability_manifest_sha256"),
        "Completed capability manifest",
    ):
        raise ValueError("Completed capability manifest is stale")
    private_manifest = host_phase_manifest(
        state, "private", capability_manifest_sha256
    )
    if hashlib.sha256(
        azure.canonical_json(private_manifest)
    ).hexdigest() != require_sha256(
        state.get("private_manifest_sha256"),
        "Completed private manifest",
    ):
        raise ValueError("Completed private manifest is stale")
    (
        capability_receipt,
        capability_receipt_sha256,
        capability_evidence_bytes,
    ) = (
        _load_completed_host_evidence(
            state, state_directory, "capability", capability_manifest
        )
    )
    (
        private_receipt,
        private_receipt_sha256,
        private_evidence_bytes,
    ) = _load_completed_host_evidence(
        state, state_directory, "private", private_manifest
    )
    if (
        capability_receipt["host_boot_id"]
        != private_receipt["host_boot_id"]
        or state["evidence_bytes"]
        != capability_evidence_bytes + private_evidence_bytes
        or state["control_payload_bytes"] <= 0
    ):
        raise ValueError("Completed private host evidence is inconsistent")

    receipt_path = state_directory / "private-receipt.json"
    receipt_bytes = azure.read_regular_file(
        receipt_path, MAX_MANIFEST_BYTES,
        "Completed private-preflight receipt",
    )
    receipt_sha256 = hashlib.sha256(receipt_bytes).hexdigest()
    if receipt_sha256 != require_sha256(
        state.get("final_receipt_sha256"),
        "Completed private-preflight receipt",
    ):
        raise ValueError("Completed private-preflight receipt is stale")
    receipt = exact_fields(
        azure.parse_strict_json(
            receipt_bytes, "Completed private-preflight receipt"
        ),
        (
            "schema", "schema_version", "result", "identity",
            "input_manifest_sha256", "implementation", "provenance",
            "capability_reference", "private_build", "inputs",
            "qemu_support", "miz", "packaging", "budget", "host_image",
            "host_capability_admission", "host",
            "capability_receipt_sha256",
            "private_receipt_sha256", "boot_policy",
            "acceptance_scope", "storage_result", "guarded",
            "capability_boots", "private_boots", "cleanup",
        ),
        "Completed private-preflight receipt",
    )
    inputs = exact_fields(
        receipt["inputs"], ALL_ROLES,
        "Completed private-preflight inputs",
    )
    normalized_inputs = {}
    for role in ALL_ROLES:
        record = exact_fields(
            inputs[role], ("sha256", "size"),
            "Completed private-preflight input",
        )
        expected = manifest["files"][role]
        normalized = {
            "sha256": require_sha256(
                record["sha256"], "Completed private-preflight input"
            ),
            "size": record["size"],
        }
        if (
            type(record["size"]) is not int
            or normalized != {
                "sha256": expected["sha256"],
                "size": expected["size"],
            }
        ):
            raise ValueError("Completed private-preflight input is stale")
        normalized_inputs[role] = normalized

    expected_budget = {
        **manifest["budget"],
        "staged_input_bytes": state["staged_input_bytes"],
        "control_payload_bytes": state["control_payload_bytes"],
        "evidence_bytes": state["evidence_bytes"],
    }
    budget = exact_fields(
        receipt["budget"], tuple(expected_budget),
        "Completed private-preflight budget",
    )
    if (
        dict(budget) != expected_budget
        or state["staged_input_bytes"]
        != manifest["budget"]["remote_input_bytes"]
    ):
        raise ValueError("Completed private-preflight accounting is stale")

    cloud = exact_fields(
        state.get("cloud_preflight"),
        ("subscription", "sku", "image", "nested_virtualization"),
        "Completed private cloud preflight",
    )
    capability_admission = validate_nested_capability_admission(
        receipt["host_capability_admission"]
    )
    image = exact_fields(
        receipt["host_image"],
        (
            "publisher", "offer", "sku", "version", "urn",
            "architecture", "hyperv_generation",
        ),
        "Completed private host image",
    )
    if (
        cloud["subscription"] != state.get("subscription")
        or not isinstance(cloud["sku"], dict)
        or dict(image) != cloud["image"]
        or capability_admission != cloud["nested_virtualization"]
        or any(
            not isinstance(image[field], str) or not image[field]
            for field in ("publisher", "offer", "sku", "version")
        )
        or image["urn"] != (
            f"{image['publisher']}:{image['offer']}:"
            f"{image['sku']}:{image['version']}"
        )
        or image["architecture"] != "x64"
        or image["hyperv_generation"] != "V2"
    ):
        raise ValueError("Completed private host image is stale")

    group_id = state["resource_group_id"].rstrip("/")
    prefix = state["name_prefix"]
    expected_resource_ids = {
        "host_vm_id": deployment["vm_id"],
        "host_disk_id": deployment["disk_id"],
        "host_nic_id": (
            f"{group_id}/providers/Microsoft.Network/"
            f"networkInterfaces/{prefix}-host-nic"
        ),
        "storage_account_id": (
            f"{group_id}/providers/Microsoft.Storage/"
            f"storageAccounts/{state['storage_account']}"
        ),
        "shutdown_schedule_id": (
            f"{group_id}/providers/Microsoft.DevTestLab/schedules/"
            f"shutdown-computevm-{prefix}-host"
        ),
    }
    if any(
        not isinstance(state.get(field), str)
        or state[field].lower() != expected.lower()
        for field, expected in expected_resource_ids.items()
    ):
        raise ValueError("Completed private host resource binding is stale")

    host = exact_fields(
        receipt["host"],
        (
            "operation_id", "deployment_correlation_id", "vm_uuid",
            "disk_uuid", "boot_id",
        ),
        "Completed private host identity",
    )
    if (
        not isinstance(deployment, dict)
        or host["operation_id"] != deployment.get("operation_id")
        or host["deployment_correlation_id"]
        != deployment.get("correlation_id")
        or host["vm_uuid"] != deployment.get("vm_uuid")
        or host["disk_uuid"] != deployment.get("disk_uuid")
        or host["boot_id"] != private_receipt["host_boot_id"]
    ):
        raise ValueError("Completed private host identity is stale")
    for field in (
        "operation_id", "deployment_correlation_id", "vm_uuid",
        "disk_uuid", "boot_id",
    ):
        require_uuid(host[field], "Completed private host identity")

    if (
        receipt["schema"] != RECEIPT_SCHEMA
        or type(receipt["schema_version"]) is not int
        or receipt["schema_version"] != RECEIPT_SCHEMA_VERSION
        or receipt["result"] != "PASS"
        or receipt["identity"] != state["identity"]
        or receipt["input_manifest_sha256"] != state["manifest_sha256"]
        or receipt["implementation"] != manifest["implementation"]
        or receipt["implementation"] != state["implementation"]
        or receipt["provenance"] != manifest["provenance"]
        or receipt["capability_reference"]
        != manifest["capability_reference"]
        or receipt["private_build"] != manifest["private_build"]
        or receipt["qemu_support"] != manifest["qemu_support"]
        or receipt["miz"] != manifest["miz"]
        or receipt["packaging"] != manifest["packaging"]
        or receipt["capability_receipt_sha256"]
        != capability_receipt_sha256
        or receipt["private_receipt_sha256"] != private_receipt_sha256
        or receipt["boot_policy"] != GUARDED_BOOT_POLICY
        or receipt["boot_policy"] != manifest["boot_policy"]
        or receipt["acceptance_scope"] != "platform-only"
        or receipt["storage_result"] != "UNAVAILABLE"
        or receipt["storage_result"] != private_receipt["storage_result"]
        or receipt["guarded"] != manifest["guarded"]
        or receipt["capability_boots"] != capability_receipt["boots"]
        or receipt["private_boots"] != private_receipt["boots"]
        or receipt["cleanup"] != "complete"
    ):
        raise ValueError("Completed private-preflight receipt is incompatible")
    return {
        **receipt,
        "implementation": manifest["implementation"],
        "provenance": manifest["provenance"],
        "capability_reference": manifest["capability_reference"],
        "private_build": manifest["private_build"],
        "inputs": normalized_inputs,
        "qemu_support": manifest["qemu_support"],
        "miz": manifest["miz"],
        "packaging": manifest["packaging"],
        "budget": dict(budget),
        "host_image": dict(image),
        "host_capability_admission": capability_admission,
        "host": dict(host),
        "guarded": manifest["guarded"],
        "capability_boots": capability_receipt["boots"],
        "private_boots": private_receipt["boots"],
    }, receipt_path


def private_failure_record(
    error, phase, *, cleanup=None, recording=()
):
    primary = bounded_exception_record(error)
    failure = {
        **primary,
        "phase": phase,
    }
    reconciliation = getattr(error, "reconciliation_failure", None)
    if isinstance(reconciliation, dict):
        failure["reconciliation"] = dict(reconciliation)
    primary_cleanup = getattr(error, "cleanup_failures", None)
    if cleanup is not None:
        failure["cleanup"] = bounded_cleanup_failures(cleanup)
    elif isinstance(primary_cleanup, list) and primary_cleanup:
        failure["cleanup"] = [
            dict(item) for item in primary_cleanup
        ]
    if recording:
        failure["recording"] = [dict(item) for item in recording]
    return validate_private_failure_record(failure)


def record_private_failure(run, error, phase):
    run.record(
        "failed", failure=private_failure_record(error, phase)
    )


def persist_private_failure(run, error, phase, *, attempt_cleanup):
    recording_failures = []
    initial = private_failure_record(error, phase)
    try:
        run.record("failure-recorded", failure=initial)
    except BaseException as recording:
        recording_failures.append({
            "stage": "initial", **bounded_exception_record(recording),
        })
    cleanup_error = None
    if attempt_cleanup and run.state.get("cleanup_required"):
        try:
            run.cleanup()
        except BaseException as cleanup:
            cleanup_error = cleanup
    final = private_failure_record(
        error, phase, cleanup=cleanup_error,
        recording=recording_failures,
    )
    final_phase = (
        "cleanup-failed" if "cleanup" in final else "failed"
    )
    try:
        run.record(final_phase, failure=final)
    except BaseException as recording:
        recording_failures.append({
            "stage": "final", **bounded_exception_record(recording),
        })
    if cleanup_error is not None or recording_failures:
        return PrivateFailurePipelineError(
            error, cleanup_error, recording_failures
        )
    return None


def run_preflight(
    state_directory, subscription, transfer_ip, approve_transfer_source_ip
):
    state, state_path = load_state(state_directory)
    if state["phase"] != "prepared" or state.get("cleanup_required") is not False:
        raise ValueError("Private preflight requires a fresh prepared state")
    verify_immutable_inputs(state, state_path.parent)
    check_blob_dependency()
    if approve_transfer_source_ip is not True:
        raise ValueError(
            "Explicit uploader /32 transfer authorization is required"
        )
    transfer_cidr = transfer_source(transfer_ip)
    cloud = check_subscription(subscription)
    started = datetime.now(timezone.utc)
    deadline = time.monotonic() + MAX_ATTEMPT_SECONDS
    deadline_utc = started + timedelta(seconds=MAX_ATTEMPT_SECONDS)
    state.update({
        "phase": "cloud-preflight-complete",
        "subscription": cloud["subscription"],
        "cloud_preflight": cloud,
        "deadline_utc": utc_text(deadline_utc),
        "deadline_monotonic": deadline,
        "cleanup_required": True,
        "storage_account": "ukhvp" + secrets.token_hex(8),
        "firewall_obligation": None,
    })
    azure.save_durable_json(state_path, state)
    run = PrivatePreflightRun(state, state_path)
    shutdown_time = deadline_utc.strftime("%H%M")
    pipeline = None
    try:
        with azure.interrupt_as_exception():
            run.create_group()
            run.deploy_host(shutdown_time)
            run.verify_storage_rules()
            account_url = f"https://{run.storage}.blob.core.windows.net"
            public_manifest = host_phase_manifest(state, "capability")
            public_manifest_sha256 = hashlib.sha256(
                azure.canonical_json(public_manifest)
            ).hexdigest()
            public_token = run.generate_sas()
            try:
                with run.transfer_access(transfer_cidr):
                    transferred = upload_blob_set(
                        run,
                        account_url, public_token["value"], run.container,
                        blob_files(state, state_path.parent, PUBLIC_ROLES),
                        create_container=True,
                        deadline=run.deadline,
                    )
                    run.account_bytes("input", transferred)
                run.record(
                    "public-tools-staged",
                    capability_manifest_sha256=public_manifest_sha256,
                )
                run.run_host_phase(
                    "capability", public_manifest, public_token["value"]
                )
                capability_receipt = retrieve_phase_evidence(
                    run, transfer_cidr, public_token["value"],
                    "capability", public_manifest,
                )
            finally:
                run.revoke_sas(public_token)

            private_manifest = host_phase_manifest(
                state, "private", public_manifest_sha256
            )
            private_token = run.generate_sas()
            try:
                with run.transfer_access(transfer_cidr):
                    transferred = upload_blob_set(
                        run,
                        account_url, private_token["value"], run.container,
                        blob_files(state, state_path.parent, PRIVATE_ROLES),
                        create_container=False,
                        deadline=run.deadline,
                    )
                    run.account_bytes("input", transferred)
                run.record(
                    "private-inputs-staged",
                    private_manifest_sha256=hashlib.sha256(
                        azure.canonical_json(private_manifest)
                    ).hexdigest(),
                )
                run.run_host_phase(
                    "private", private_manifest, private_token["value"]
                )
                private_receipt = retrieve_phase_evidence(
                    run, transfer_cidr, private_token["value"],
                    "private", private_manifest,
                )
            finally:
                run.revoke_sas(private_token)
            if (
                private_receipt["host_boot_id"]
                != capability_receipt["host_boot_id"]
            ):
                raise RuntimeError(
                    "Private host restarted after its public capability proof"
                )
            if time.monotonic() >= run.deadline:
                raise RuntimeError(
                    "Private preflight exceeded its absolute deadline"
                )
            if (
                state["staged_input_bytes"]
                != state["input_manifest"]["budget"]["remote_input_bytes"]
            ):
                raise RuntimeError(
                    "Private-preflight staged input accounting is incomplete"
                )
            run.deallocate_host()
            final = {
                "schema": RECEIPT_SCHEMA,
                "schema_version": RECEIPT_SCHEMA_VERSION,
                "result": "PASS",
                "identity": state["identity"],
                "input_manifest_sha256": state["manifest_sha256"],
                "implementation": state["implementation"],
                "provenance": state["input_manifest"]["provenance"],
                "capability_reference": state["input_manifest"][
                    "capability_reference"
                ],
                "private_build": state["input_manifest"]["private_build"],
                "inputs": {
                    role: {
                        "sha256": record["sha256"],
                        "size": record["size"],
                    }
                    for role, record in state["input_manifest"]["files"].items()
                },
                "qemu_support": state["input_manifest"]["qemu_support"],
                "miz": state["input_manifest"]["miz"],
                "packaging": state["input_manifest"]["packaging"],
                "budget": {
                    **state["input_manifest"]["budget"],
                    "staged_input_bytes": state["staged_input_bytes"],
                    "control_payload_bytes": state[
                        "control_payload_bytes"
                    ],
                    "evidence_bytes": state["evidence_bytes"],
                },
                "host_image": state["cloud_preflight"]["image"],
                "host_capability_admission": state["cloud_preflight"][
                    "nested_virtualization"
                ],
                "host": {
                    "operation_id": state["host_deployment"][
                        "operation_id"
                    ],
                    "deployment_correlation_id": state["host_deployment"][
                        "correlation_id"
                    ],
                    "vm_uuid": state["host_deployment"]["vm_uuid"],
                    "disk_uuid": state["host_deployment"]["disk_uuid"],
                    "boot_id": private_receipt["host_boot_id"],
                },
                "capability_receipt_sha256": state[
                    "capability_receipt_sha256"
                ],
                "private_receipt_sha256": state["private_receipt_sha256"],
                "boot_policy": state["input_manifest"]["boot_policy"],
                "acceptance_scope": "platform-only",
                "storage_result": private_receipt["storage_result"],
                "guarded": state["input_manifest"]["guarded"],
                "capability_boots": capability_receipt["boots"],
                "private_boots": private_receipt["boots"],
                "cleanup": "pending",
            }
            final_path = state_path.parent / "private-receipt.json"
            azure.save_durable_json(final_path, final)
            run.record(
                "accepted", final_receipt_sha256=azure.image_sha256(final_path)
            )
    except BaseException as primary:
        primary_phase = state.get("phase", "unknown")
        pipeline = persist_private_failure(
            run, primary, primary_phase, attempt_cleanup=True
        )
        if pipeline is None:
            raise
    if pipeline is not None:
        raise pipeline
    if state.get("cleanup_required"):
        try:
            run.cleanup()
        except BaseException as cleanup_error:
            pipeline = persist_private_failure(
                run, cleanup_error, "cleanup", attempt_cleanup=False
            )
            if pipeline is None:
                raise
        if pipeline is not None:
            raise pipeline
    final["cleanup"] = "complete"
    azure.save_durable_json(state_path.parent / "private-receipt.json", final)
    run.record(
        "complete", cleanup_required=False,
        final_receipt_sha256=azure.image_sha256(
            state_path.parent / "private-receipt.json"
        ),
    )
    return state_path.parent / "private-receipt.json"


def cleanup(state_directory, subscription):
    state, state_path = load_state(state_directory)
    subscription = azure.validate_subscription_id(subscription)
    if not state.get("subscription"):
        if state["phase"] != "prepared":
            raise ValueError("Private state lacks explicit cleanup ownership")
        state["phase"] = "cleaned"
        azure.save_durable_json(state_path, state)
        return
    if state["subscription"] != subscription:
        raise ValueError("Explicit cleanup subscription does not match private state")
    PrivatePreflightRun(state, state_path).cleanup()


def main():
    parser = argparse.ArgumentParser(
        description="Bounded private nested-KVM Hyper-V platform preflight"
    )
    subparsers = parser.add_subparsers(dest="action", required=True)
    build_parser = subparsers.add_parser("build-private")
    build_parser.add_argument("--output-dir", type=Path, required=True)
    build_parser.add_argument(
        "--repository", type=Path, default=SUPPORT.parent
    )
    build_parser.add_argument("--solved-config", type=Path, required=True)
    build_parser.add_argument("--zig", type=Path, required=True)
    build_parser.add_argument("--make", type=Path, required=True)
    build_parser.add_argument("--python", type=Path, required=True)
    build_parser.add_argument("--bison", type=Path, required=True)
    build_parser.add_argument("--flex", type=Path, required=True)
    build_parser.add_argument("--m4", type=Path, required=True)
    build_parser.add_argument("--bison-data", type=Path, required=True)
    build_parser.add_argument("--llvm-bin", type=Path, required=True)
    build_parser.add_argument("--git-runtime", type=Path, required=True)
    build_parser.add_argument("--timeout", type=int, default=1800)
    generate_parser = subparsers.add_parser("generate-input")
    generate_parser.add_argument("--output-dir", type=Path, required=True)
    generate_parser.add_argument(
        "--repository", type=Path, default=SUPPORT.parent
    )
    generate_parser.add_argument("--solved-config", type=Path, required=True)
    generate_parser.add_argument("--qemu-root", type=Path, required=True)
    generate_parser.add_argument("--ovmf-code", type=Path, required=True)
    generate_parser.add_argument("--ovmf-vars", type=Path, required=True)
    generate_parser.add_argument(
        "--capability-raw", type=Path, required=True
    )
    generate_parser.add_argument(
        "--capability-receipt", type=Path, required=True
    )
    generate_parser.add_argument("--private-efi", type=Path, required=True)
    generate_parser.add_argument(
        "--private-build-receipt", type=Path, required=True
    )
    generate_parser.add_argument("--private-raw", type=Path, required=True)
    generate_parser.add_argument("--private-vhd", type=Path, required=True)
    generate_parser.add_argument("--miz", type=Path, required=True)
    generate_parser.add_argument("--git-runtime", type=Path, required=True)
    generate_parser.add_argument(
        "--boot-policy", choices=BOOT_POLICIES, required=True
    )
    prepare_parser = subparsers.add_parser("prepare")
    prepare_parser.add_argument("--input-dir", type=Path, required=True)
    prepare_parser.add_argument("--state-dir", type=Path, required=True)
    prepare_parser.add_argument("--miz", type=Path, required=True)
    prepare_parser.add_argument(
        "--expected-manifest-sha256", required=True
    )
    run_parser = subparsers.add_parser("run")
    run_parser.add_argument("--state-dir", type=Path, required=True)
    run_parser.add_argument("--subscription", required=True)
    run_parser.add_argument("--transfer-source-ip", required=True)
    run_parser.add_argument(
        "--approve-transfer-source-ip", action="store_true",
        help="explicitly authorize the exact temporary uploader /32",
    )
    cleanup_parser = subparsers.add_parser("cleanup")
    cleanup_parser.add_argument("--state-dir", type=Path, required=True)
    cleanup_parser.add_argument("--subscription", required=True)
    args = parser.parse_args()
    failure_message = None
    try:
        if args.action == "build-private":
            build_private_image(
                args.output_dir, args.repository, args.solved_config,
                args.zig, args.make, args.python, args.bison, args.flex,
                args.m4, args.bison_data, args.llvm_bin, args.git_runtime,
                args.timeout,
            )
            print("Private local build completed in owner-only directory")
        elif args.action == "generate-input":
            digest = generate_input(
                args.output_dir,
                args.repository,
                args.solved_config,
                args.qemu_root,
                args.ovmf_code,
                args.ovmf_vars,
                args.capability_raw,
                args.capability_receipt,
                args.private_efi,
                args.private_build_receipt,
                args.private_raw,
                args.private_vhd,
                args.miz,
                args.git_runtime,
                args.boot_policy,
            )
            print(
                "Private preflight input manifest SHA-256: " + digest
            )
        elif args.action == "prepare":
            prepare(
                args.input_dir, args.state_dir, args.miz,
                args.expected_manifest_sha256,
            )
            print("Private preflight inputs prepared in owner-only state")
        elif args.action == "run":
            run_preflight(
                args.state_dir, args.subscription, args.transfer_source_ip,
                args.approve_transfer_source_ip,
            )
            print("Private preflight completed; private receipt retained locally")
        else:
            cleanup(args.state_dir, args.subscription)
            print("Private preflight cleanup completed")
    except subprocess.TimeoutExpired:
        failure_message = (
            "A bounded private-preflight subprocess timed out; details withheld"
        )
    except (OSError, RuntimeError, ValueError, KeyboardInterrupt):
        failure_message = (
            "Private preflight failed; inspect the owner-only state directory"
        )
    if failure_message is not None:
        raise SystemExit(failure_message)


if __name__ == "__main__":
    main()
