#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""Private Hyper-V nested-KVM preflight runner for an owned Azure host."""

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import shutil
import stat
import subprocess
import tempfile
import time
import urllib.parse
import urllib.request


SCHEMA = "unikraft.hyperv.private-preflight-host-phase"
EVIDENCE_SCHEMA = "unikraft.hyperv.private-preflight-host-evidence"
SHA256 = re.compile(r"[0-9a-f]{64}")
IDENTITY = re.compile(r"[0-9a-f]{32}")
BOOT_ID = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-"
    r"[89ab][0-9a-f]{3}-[0-9a-f]{12}"
)
SAFE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,159}")
ANSI_ESCAPE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
MAIN_RETURN = re.compile(
    r"^(?:\[\s*[0-9]+(?:\.[0-9]+)?\]\s+)?"
    r"(?:Info:\s+)?(?:\[[A-Za-z0-9_.-]{1,64}\]\s+)?"
    r"(?:<[^<>\r\n]{1,160}>:?\s+)?main returned (-?[0-9]+)$"
)
LOCAL_BOOT_MODES = (("x2apic", False), ("legacy-apic", True))
TOTAL_BOOT_COUNT = 6
CPU_FEATURES = (
    "host,hv-relaxed,hv-vapic,hv-spinlocks=0x1fff,hv-time,"
    "hv-synic,hv-stimer,hv-vpindex,hv-runtime,hv-frequencies"
)
LEGACY_APIC_MARKER = "Using legacy xAPIC MMIO"
PLATFORM_MARKER = "UK_HYPERV_PLATFORM_READY"
UNAVAILABLE_MARKER = "UK_HYPERV_ACCEPTANCE_UNAVAILABLE:storage+network"
UNAVAILABLE_RECORDS = (
    "HYPERV_ACCEPTANCE PLATFORM_READY PASS cpu_count=1 vmbus_offers=0",
    (
        "HYPERV_ACCEPTANCE STORAGE_INVENTORY UNAVAILABLE "
        "devices=0 offers=0 reason=no-storvsc-offer"
    ),
    "HYPERV_ACCEPTANCE STORAGE_READ UNAVAILABLE reason=no-device",
    (
        "HYPERV_ACCEPTANCE NETWORK_INVENTORY UNAVAILABLE "
        "devices=0 offers=0 reason=no-netvsc-offer"
    ),
    "HYPERV_ACCEPTANCE NETWORK_DHCP_TX UNAVAILABLE reason=no-device",
    "HYPERV_ACCEPTANCE NETWORK_DHCP_RX UNAVAILABLE reason=no-device",
    (
        "HYPERV_ACCEPTANCE FINAL_RESULT UNAVAILABLE "
        "storage=UNAVAILABLE network=UNAVAILABLE"
    ),
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
            "c27812c80714f187c73b3f2327af154889030bf74b1b1cca4e46f42abac0eef9"
        ),
        "size": 1180024,
        "files": 177,
    },
}
GUARDED_PRODUCER_FILES = {
    "Config.uk": (
        "17b791a1bc6709f31846321cb705cd30b141e09eb05f6cd0bcffebb3eba0d50e"
    ),
    "Makefile": (
        "c790738ac50a85be2e7def288a32890a1c2703b9a148ffb2dd633d200305d562"
    ),
    "Makefile.uk": (
        "288bb7b13ca5484812e1fa5c6bdc34724607b61d8542cef08357c4e4988bcf09"
    ),
    "build.zig": (
        "fd59a9880077c16a9e38af777950d46471e1e50332a5644ddaec6ec1ece38bf8"
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
        "0116adde8d137b22230accc9c07731939558b7e5a5eac0637b44d7386375880f"
    ),
    "support/build/lto-symbol-policy.py": (
        "139c967944d7460b92dcad82c8a2149a56d5698a27f7bc1029b1b789da4b19ce"
    ),
    "support/build/merge-linker-scripts.py": (
        "dd39b9cec861bdf4771fba05c0b477aea37e2b2f1d40d843f31d3c1df011ee3a"
    ),
    "support/build/native-config-metadata.py": (
        "a8a98d3eaab01e454fc863d07214aea947baafdf512debf55259807ed96998b7"
    ),
    "support/build/native-config-tool.zig": (
        "30291f034f98c970bbf7879189e9bc4c8bc5aa5a6a19fe1ed247d508641d46a9"
    ),
    "support/build/native-image-data.zig": (
        "159b836c9ae05acf0889bdf37bc385dd3171fa9df6d6be01746376811c5b514c"
    ),
    "support/build/native-library-link.zig": (
        "562a0b713e67e6e3de6897077f6bd18cc0ee135b8522bfaecd6d8c11a61423fe"
    ),
    "support/build/native-lto.zig": (
        "68076583775b233c21447ad580a3a30b653a589c9dd6c8cf994b9eb70cf97974"
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
    "drivers/hyperv/storvsc/Config.uk": (
        "bc4474ee1655396b74359fc0b40fd5036b2e6219a50f6b6fb6787a0e8daeec6a"
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
        "cb9e5afefb8f18612c36b5975b94ed64c0702c4a4e6988ea4edfa9c6bc6da213"
    ),
    "drivers/hyperv/storvsc/storvsc_core.h": (
        "8422dd6de969b13a533fe0291a7019442712ae9b7f6177420e6fd4df22860ab7"
    ),
    "drivers/hyperv/storvsc/storvsc_core.zig": (
        "f4b7f4fa58cca087b9ff7b2e15f372d09cab9ea542210c0a306b9a5880ba9ae6"
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
        "2ab2de7473bca0a886e35559edbe81d7fe71e24ac92f86721068a7b86a2f9e72"
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
        "19f70c5cc056157f329a6b226ead55b74fd3b628eb068b065d2d1e23b6f01bb8"
    ),
    "support/apps/hyperv-acceptance/acceptance_protocol.c": (
        "5ba77f19e204c9bc3b9b579cf6ccd9e0184952fd9e0d14c123f5a19af05dd64e"
    ),
    "support/apps/hyperv-acceptance/acceptance_protocol.h": (
        "1b7d718ca10b760b61df07570b640586cce34d1d3c498c68fbd336a61669db4e"
    ),
    "support/apps/hyperv-acceptance/application_network.c": (
        "b55080d196e6015c7a5a84f2ab2dc76856c978cf6a7ec1793186511616c56ffb"
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
LIVE_IO_MARKERS = (
    "UK_HYPERV_BLOCK_READ_OK",
    "UK_HYPERV_NET_DHCP_OFFER",
    "UK_HYPERV_NET_APP_LEASE",
    "UK_HYPERV_NET_APP_ARP",
    "UK_HYPERV_NET_APP_TCP",
    "UK_HYPERV_NET_APP_UDP",
    "UK_HYPERV_NETWORK_APP_READY",
    "UK_HYPERV_IO_READY",
)
MAX_MANIFEST_BYTES = 64 * 1024
MAX_FILE_BYTES = 128 * 1024 * 1024
MAX_LOG_BYTES = 1024 * 1024
MAX_EVIDENCE_BYTES = 8 * 1024 * 1024
BOOT_TIMEOUT_SECONDS = 120
INPUT_NAMES = {
    "qemu": "qemu/bin/qemu-system-x86_64",
    "ovmf_code": "OVMF_CODE.fd",
    "ovmf_vars": "OVMF_VARS.fd",
    "capability_raw": "capability.raw",
    "raw": "private.raw",
    "vhd": "private.vhd",
}


class RunnerError(RuntimeError):
    def __init__(self, code):
        if not re.fullmatch(r"[a-z0-9-]{3,64}", code):
            code = "internal"
        self.code = code
        super().__init__(code)


def strict_json(value, description):
    def unique(pairs):
        result = {}
        for key, item in pairs:
            if key in result:
                raise RunnerError("duplicate-json-field")
            result[key] = item
        return result

    try:
        parsed = json.loads(value, object_pairs_hook=unique)
    except (json.JSONDecodeError, UnicodeDecodeError, RecursionError):
        raise RunnerError("malformed-json") from None
    if not isinstance(parsed, dict):
        raise RunnerError(f"invalid-{description}")
    return parsed


def exact_fields(value, fields, code):
    if not isinstance(value, dict) or set(value) != set(fields):
        raise RunnerError(code)
    return value


def require_sha256(value):
    if not isinstance(value, str) or not SHA256.fullmatch(value):
        raise RunnerError("invalid-sha256")
    return value


def require_identity(value):
    if not isinstance(value, str) or not IDENTITY.fullmatch(value):
        raise RunnerError("invalid-identity")
    return value


def validate_guarded_contract(value, boot_policy):
    if boot_policy != GUARDED_BOOT_POLICY:
        if value is not None:
            raise RunnerError("unexpected-guarded-contract")
        return None
    value = exact_fields(
        value,
        (
            "schema", "schema_version", "scope", "result", "protocol",
            "identity_policy", "reason", "main_return", "run_id",
            "disk_id", "path", "target", "lun", "sectors",
            "sector_size", "solved_config_sha256", "producer",
        ),
        "invalid-guarded-contract",
    )
    producer = exact_fields(
        value["producer"],
        ("schema", "schema_version", "files", "closures"),
        "invalid-guarded-producer",
    )
    files = exact_fields(
        producer["files"], GUARDED_PRODUCER_FILES,
        "invalid-guarded-producer-files",
    )
    closures = exact_fields(
        producer["closures"], GUARDED_PRODUCER_CLOSURES,
        "invalid-guarded-producer-closures",
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
        or require_identity(value["run_id"]) != value["run_id"]
        or require_identity(value["disk_id"]) != value["disk_id"]
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
        or require_sha256(value["solved_config_sha256"])
        != value["solved_config_sha256"]
        or producer["schema"] != GUARDED_PRODUCER_SCHEMA
        or type(producer["schema_version"]) is not int
        or producer["schema_version"] != GUARDED_PRODUCER_SCHEMA_VERSION
        or dict(files) != GUARDED_PRODUCER_FILES
        or dict(closures) != GUARDED_PRODUCER_CLOSURES
    ):
        raise RunnerError("invalid-guarded-contract")
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


def host_boot_id():
    try:
        value = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    except OSError:
        raise RunnerError("host-boot-id-unavailable") from None
    if not BOOT_ID.fullmatch(value):
        raise RunnerError("host-boot-id-invalid")
    return value


def require_file_record(value):
    value = exact_fields(
        value, ("blob", "name", "sha256", "size"), "invalid-file-record"
    )
    for field in ("blob", "name"):
        text = value[field]
        if (
            not isinstance(text, str)
            or not SAFE_NAME.fullmatch(text)
            or text.startswith("/")
            or ".." in Path(text).parts
        ):
            raise RunnerError("invalid-file-name")
    if type(value["size"]) is not int or not 0 < value["size"] <= MAX_FILE_BYTES:
        raise RunnerError("invalid-file-size")
    require_sha256(value["sha256"])
    return dict(value)


def parse_manifest(encoded, expected_phase):
    try:
        raw = base64.b64decode(encoded, validate=True)
    except (ValueError, TypeError):
        raise RunnerError("invalid-manifest-encoding") from None
    if len(raw) > MAX_MANIFEST_BYTES:
        raise RunnerError("manifest-too-large")
    fields = (
            "schema", "schema_version", "phase", "identity",
            "boot_policy", "raw_size", "files", "evidence_prefix",
            "runner_sha256", "qemu_support", "input_manifest_sha256",
            "workload", "guarded",
        ) + (
            ("capability_manifest_sha256",)
            if expected_phase == "private" else ()
        )
    manifest = exact_fields(
        strict_json(raw, "manifest"),
        fields,
        "invalid-manifest-fields",
    )
    if (
        manifest["schema"] != SCHEMA
        or type(manifest["schema_version"]) is not int
        or manifest["schema_version"] != 3
        or manifest["phase"] != expected_phase
        or manifest["workload"] != "platform-only-v1"
        or manifest["boot_policy"] not in (
            "platform-unavailable-v1", "platform-main-zero-v1",
            GUARDED_BOOT_POLICY,
        )
        or type(manifest["raw_size"]) is not int
        or not 1024 * 1024 <= manifest["raw_size"] <= MAX_FILE_BYTES
        or require_sha256(manifest["runner_sha256"])
        != manifest["runner_sha256"]
        or require_sha256(manifest["input_manifest_sha256"])
        != manifest["input_manifest_sha256"]
    ):
        raise RunnerError("invalid-manifest-contract")
    manifest["guarded"] = validate_guarded_contract(
        manifest["guarded"], manifest["boot_policy"]
    )
    identity = require_identity(manifest["identity"])
    prefix = manifest["evidence_prefix"]
    if (
        not isinstance(prefix, str)
        or prefix != f"evidence/{identity}/{expected_phase}"
    ):
        raise RunnerError("invalid-evidence-prefix")
    expected_files = (
        ("qemu", "ovmf_code", "ovmf_vars", "capability_raw")
        if expected_phase == "capability"
        else ("qemu", "ovmf_code", "ovmf_vars", "raw", "vhd")
    )
    files = exact_fields(
        manifest["files"], expected_files, "invalid-manifest-files"
    )
    manifest["files"] = {
        name: require_file_record(files[name]) for name in expected_files
    }
    for role, record in manifest["files"].items():
        source_phase = (
            "public"
            if role in ("qemu", "ovmf_code", "ovmf_vars", "capability_raw")
            else "private"
        )
        if (
            record["name"] != INPUT_NAMES[role]
            or record["blob"] != (
                f"inputs/{identity}/{source_phase}/{INPUT_NAMES[role]}"
            )
        ):
            raise RunnerError("invalid-file-binding")
    support = manifest["qemu_support"]
    if not isinstance(support, list) or len(support) > 124:
        raise RunnerError("invalid-qemu-support")
    parsed_support = []
    names = set()
    for record in support:
        record = require_file_record(record)
        if (
            not record["name"].startswith("qemu/")
            or len(Path(record["name"]).parts) < 3
            or Path(record["name"]).parts[1] not in ("lib", "share")
            or record["blob"] != (
                f"inputs/{identity}/public/{record['name']}"
            )
            or record["name"] in names
        ):
            raise RunnerError("invalid-qemu-support")
        names.add(record["name"])
        parsed_support.append(record)
    manifest["qemu_support"] = parsed_support
    if expected_phase == "capability":
        if manifest["files"]["capability_raw"]["size"] != manifest["raw_size"]:
            raise RunnerError("invalid-capability-size")
        if manifest["boot_policy"] != "platform-unavailable-v1":
            raise RunnerError("invalid-capability-policy")
        if manifest["guarded"] is not None:
            raise RunnerError("invalid-capability-policy")
    else:
        if (
            manifest["files"]["raw"]["size"] != manifest["raw_size"]
            or manifest["files"]["vhd"]["size"] != manifest["raw_size"] + 512
            or require_sha256(manifest["capability_manifest_sha256"])
            != manifest["capability_manifest_sha256"]
        ):
            raise RunnerError("invalid-private-image-size")
    return manifest, raw


def blob_url(base_url, container, name, sas):
    parsed = urllib.parse.urlsplit(base_url)
    if (
        parsed.scheme != "https"
        or parsed.username is not None
        or parsed.password is not None
        or parsed.port not in (None, 443)
        or not re.fullmatch(r"[a-z0-9]{3,24}\.blob\.core\.windows\.net", parsed.hostname or "")
        or parsed.path not in ("", "/")
        or parsed.query
        or parsed.fragment
        or not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{1,61}[a-z0-9])?", container)
        or not isinstance(sas, str)
        or len(sas) > 4096
        or any(character.isspace() for character in sas)
    ):
        raise RunnerError("invalid-blob-endpoint")
    return (
        f"https://{parsed.hostname}/{container}/"
        f"{urllib.parse.quote(name, safe='/')}?{sas.lstrip('?')}"
    )


def download_file(base_url, container, record, sas, destination):
    request = urllib.request.Request(
        blob_url(base_url, container, record["blob"], sas),
        headers={"x-ms-version": "2023-11-03"},
    )
    digest = hashlib.sha256()
    written = 0
    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    try:
        with urllib.request.urlopen(request, timeout=60) as response, \
                destination.open("xb") as output:
            os.chmod(destination, 0o600)
            while written <= record["size"]:
                chunk = response.read(
                    min(1024 * 1024, record["size"] + 1 - written)
                )
                if not chunk:
                    break
                written += len(chunk)
                if written > record["size"]:
                    raise RunnerError("download-size-mismatch")
                output.write(chunk)
                digest.update(chunk)
            output.flush()
            os.fsync(output.fileno())
    except RunnerError:
        destination.unlink(missing_ok=True)
        raise
    except Exception:
        destination.unlink(missing_ok=True)
        raise RunnerError("blob-download-failed") from None
    if written != record["size"] or digest.hexdigest() != record["sha256"]:
        destination.unlink(missing_ok=True)
        raise RunnerError("download-fingerprint-mismatch")


def upload_file(base_url, container, name, sas, source):
    data = source.read_bytes()
    maximum = MAX_MANIFEST_BYTES if name.endswith("receipt.json") else MAX_LOG_BYTES
    if len(data) > maximum:
        raise RunnerError("evidence-too-large")
    request = urllib.request.Request(
        blob_url(base_url, container, name, sas),
        data=data,
        method="PUT",
        headers={
            "Content-Length": str(len(data)),
            "If-None-Match": "*",
            "x-ms-blob-type": "BlockBlob",
            "x-ms-version": "2023-11-03",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            if response.status not in (200, 201):
                raise RunnerError("blob-upload-failed")
    except RunnerError:
        raise
    except Exception:
        raise RunnerError("blob-upload-failed") from None


def hash_prefix(path, length):
    digest = hashlib.sha256()
    remaining = length
    with path.open("rb") as source:
        while remaining:
            chunk = source.read(min(1024 * 1024, remaining))
            if not chunk:
                raise RunnerError("image-size-mismatch")
            digest.update(chunk)
            remaining -= len(chunk)
    return digest.hexdigest()


def hash_file(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def immutable_identity(path, record, code):
    try:
        metadata = path.lstat()
    except OSError:
        raise RunnerError(code) from None
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_size != record["size"]
        or hash_file(path) != record["sha256"]
    ):
        raise RunnerError(code)
    return metadata.st_dev, metadata.st_ino


def revalidate_boot_image(image, backing, record, identity):
    source_identity = immutable_identity(
        image, record, "boot-image-mutated"
    )
    backing_identity = immutable_identity(
        backing, record, "boot-backing-mutated"
    )
    if source_identity != identity or backing_identity != identity:
        raise RunnerError("boot-image-replaced")


def write_durable(path, value):
    with path.open("xb") as output:
        os.chmod(path, 0o600)
        output.write(value)
        output.flush()
        os.fsync(output.fileno())
    descriptor = os.open(
        path.parent,
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def normalized_lines(text):
    return [
        ANSI_ESCAPE.sub("", line).replace("\0", "").strip()
        for line in text.splitlines()
        if ANSI_ESCAPE.sub("", line).replace("\0", "").strip()
    ]


def validate_boot_log(text, policy, legacy_apic, guarded=None):
    lines = normalized_lines(text)
    guarded = validate_guarded_contract(guarded, policy)
    for marker in (
        "Hyper-V Hv#1 hypercall page enabled",
        "Hyper-V SynIC:", "Powered by", "Calling main(",
    ):
        if sum(marker in line for line in lines) != 1:
            raise RunnerError("missing-hyperv-capability")
    if lines.count(PLATFORM_MARKER) != 1:
        raise RunnerError("invalid-platform-marker")
    if any(
        "Unikraft Crash" in line
        or "Assertion failure" in line
        or "Exception Type" in line
        for line in lines
    ):
        raise RunnerError("guest-crash")
    main = [
        MAIN_RETURN.fullmatch(line) for line in lines if "main returned" in line
    ]
    if len(main) != 1 or main[0] is None:
        raise RunnerError("invalid-main-return")
    expected_return = (
        2 if policy in ("platform-unavailable-v1", GUARDED_BOOT_POLICY)
        else 0
    )
    if int(main[0].group(1)) != expected_return:
        raise RunnerError("unexpected-main-return")
    if policy == GUARDED_BOOT_POLICY:
        start = (
            "HYPERV_PERSISTENCE START PASS "
            f"run={guarded['run_id']} "
            f"address={guarded['path']}:{guarded['target']}:{guarded['lun']} "
            f"sectors={guarded['sectors']} "
            f"sector_size={guarded['sector_size']}"
        )
        select = (
            "HYPERV_PERSISTENCE SELECT UNAVAILABLE "
            f"reason={guarded['reason']} writes=0 flushes=0"
        )
        unavailable = (
            "UK_HYPERV_PERSISTENCE_UNAVAILABLE:"
            f"{guarded['protocol']}:{guarded['identity_policy']}:"
            f"{guarded['reason']}"
        )
        persistence = [
            line for line in lines
            if (
                "HYPERV_PERSISTENCE" in line
                or "UK_HYPERV_PERSISTENCE" in line
            )
        ]
        if persistence != [start, select, unavailable]:
            raise RunnerError("invalid-guarded-unavailable-policy")
        positions = []
        for marker in (
            "Hyper-V Hv#1 hypercall page enabled",
            "Hyper-V SynIC:", "Powered by", "Calling main(",
        ):
            positions.append(next(
                index for index, line in enumerate(lines) if marker in line
            ))
        positions.extend((
            lines.index(start),
            lines.index(select),
            lines.index(PLATFORM_MARKER),
            lines.index(unavailable),
            next(
                index for index, line in enumerate(lines)
                if "main returned" in line
            ),
        ))
        if positions != sorted(positions) or len(set(positions)) != len(positions):
            raise RunnerError("reordered-guarded-unavailable-policy")
        if (
            any("FAIL" in line for line in lines)
            or any(
                line.startswith((
                    "HYPERV_ACCEPTANCE ", "UK_HYPERV_ACCEPTANCE_",
                    "HYPERV_STORAGE ", "HYPERV_NETWORK_APP ",
                ))
                for line in lines
            )
        ):
            raise RunnerError("unexpected-guarded-activity")
    elif policy == "platform-unavailable-v1":
        acceptance = [
            line for line in lines
            if line.startswith("HYPERV_ACCEPTANCE ")
        ]
        unavailable = [
            line for line in lines
            if line.startswith("UK_HYPERV_ACCEPTANCE_")
        ]
        if (
            acceptance != list(UNAVAILABLE_RECORDS)
            or unavailable != [UNAVAILABLE_MARKER]
        ):
            raise RunnerError("invalid-unavailable-policy")
        if any("FAIL" in line for line in lines):
            raise RunnerError("unexpected-guest-failure")
    elif (
        any("FAIL" in line or "UNAVAILABLE" in line for line in lines)
        or "UK_HYPERV_IO_READY" in lines
    ):
        raise RunnerError("unexpected-platform-only-evidence")
    if legacy_apic:
        if sum(LEGACY_APIC_MARKER in line for line in lines) != 1:
            raise RunnerError("missing-legacy-apic")
    elif any(LEGACY_APIC_MARKER in line for line in lines):
        raise RunnerError("unexpected-legacy-apic")
    if (
        any(marker in lines for marker in LIVE_IO_MARKERS)
        or any(
            line.startswith("UK_HYPERV_")
            and (
                (line.endswith("_READY") and line != PLATFORM_MARKER)
                or line.endswith("_READ_OK")
            )
            for line in lines
        )
        or (
            policy != GUARDED_BOOT_POLICY
            and any(
                " PASS" in line
                and line.startswith((
                    "HYPERV_ACCEPTANCE", "HYPERV_NETWORK_APP",
                    "HYPERV_STORAGE",
                ))
                and line != UNAVAILABLE_RECORDS[0]
                for line in lines
            )
        )
    ):
        raise RunnerError("unexpected-live-io")


def run_boot(qemu, ovmf_code, ovmf_code_record, ovmf_vars, ovmf_vars_record,
             image, image_record, raw_size, policy, mode, legacy_apic,
             output_directory, guarded=None):
    work = Path(tempfile.mkdtemp(prefix="boot-", dir=output_directory))
    image_identity = immutable_identity(
        image, image_record, "boot-image-invalid"
    )
    code_identity = immutable_identity(
        ovmf_code, ovmf_code_record, "ovmf-code-invalid"
    )
    variables_identity = immutable_identity(
        ovmf_vars, ovmf_vars_record, "ovmf-vars-invalid"
    )
    backing = work / "disk.img"
    linked = False
    failure = None
    try:
        shutil.copyfile(ovmf_vars, work / "OVMF_VARS.fd")
        immutable_identity(
            work / "OVMF_VARS.fd", ovmf_vars_record,
            "ovmf-vars-copy-invalid",
        )
        (work / "OVMF_VARS.fd").chmod(0o600)
        os.link(image, backing)
        linked = True
        if immutable_identity(
            backing, image_record, "boot-backing-invalid"
        ) != image_identity:
            raise RunnerError("boot-backing-identity-mismatch")
        cpu = CPU_FEATURES + (",x2apic=off" if legacy_apic else "")
        disk = {
            "driver": "raw", "node-name": "hyperv-disk",
            "offset": 0, "size": raw_size, "read-only": True,
            "file": {
                "driver": "file", "filename": "disk.img",
                "read-only": True,
            },
        }
        command = [
            str(qemu), "-machine", "q35,accel=kvm", "-cpu", cpu,
            "-L", str(qemu.parent.parent / "share"),
            "-smp", "1", "-m", "512M",
            "-drive",
            "if=pflash,format=raw,readonly=on,file=" + str(ovmf_code),
            "-drive", "if=pflash,format=raw,file=OVMF_VARS.fd",
            "-blockdev", json.dumps(disk, separators=(",", ":")),
            "-device", "virtio-blk-pci,drive=hyperv-disk",
            "-device", "vmbus-bridge,irq=15",
            "-display", "none", "-serial", "stdio", "-monitor", "none",
            "-no-reboot", "-nic", "none",
        ]
        log_path = output_directory / f"{mode}.log"

        def bound_output():
            resource.setrlimit(
                resource.RLIMIT_FSIZE, (MAX_LOG_BYTES, MAX_LOG_BYTES)
            )

        with log_path.open("xb") as log:
            os.chmod(log_path, 0o600)
            try:
                environment = os.environ.copy()
                qemu_root = qemu.parent.parent
                library = qemu_root / "lib"
                if library.is_dir():
                    environment["LD_LIBRARY_PATH"] = str(library)
                result = subprocess.run(
                    command, cwd=work, stdin=subprocess.DEVNULL,
                    stdout=log, stderr=subprocess.STDOUT,
                    timeout=BOOT_TIMEOUT_SECONDS, check=False,
                    preexec_fn=bound_output,
                    env=environment,
                )
            except subprocess.TimeoutExpired:
                raise RunnerError("qemu-timeout") from None
        if result.returncode:
            raise RunnerError("qemu-failed")
        text = log_path.read_text(errors="replace")
        validate_boot_log(text, policy, legacy_apic, guarded)
        return {
            "result": "PASS",
            "log_sha256": hashlib.sha256(log_path.read_bytes()).hexdigest(),
            "return_code": result.returncode,
        }, log_path
    except BaseException as error:
        failure = error
        raise
    finally:
        try:
            if immutable_identity(
                ovmf_code, ovmf_code_record, "ovmf-code-mutated"
            ) != code_identity:
                raise RunnerError("ovmf-code-replaced")
            if immutable_identity(
                ovmf_vars, ovmf_vars_record, "ovmf-vars-mutated"
            ) != variables_identity:
                raise RunnerError("ovmf-vars-replaced")
            if linked and (backing.exists() or backing.is_symlink()):
                revalidate_boot_image(
                    image, backing, image_record, image_identity
                )
            elif linked:
                immutable_identity(
                    image, image_record, "boot-image-mutated"
                )
                raise RunnerError("boot-backing-replaced")
            else:
                immutable_identity(
                    image, image_record, "boot-image-mutated"
                )
        except RunnerError:
            if failure is None:
                raise
            raise
        finally:
            shutil.rmtree(work, ignore_errors=True)


def execute_phase(phase, manifest, manifest_bytes, base_url, container, sas,
                  root):
    identity = manifest["identity"]
    if (
        hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
        != manifest["runner_sha256"]
    ):
        raise RunnerError("runner-fingerprint-mismatch")
    boot_id = host_boot_id()
    run_root = root / identity
    public_root = run_root / "public"
    phase_root = run_root / phase
    evidence_root = phase_root / "evidence"
    evidence_root.mkdir(mode=0o700, parents=True, exist_ok=False)
    capability_complete = run_root / "capability.complete"
    if phase == "private":
        if capability_complete.is_symlink() or not capability_complete.is_file():
            raise RunnerError("capability-not-complete")
        capability = strict_json(
            capability_complete.read_bytes(), "capability-state"
        )
        capability = exact_fields(
            capability,
            ("identity", "manifest_sha256", "result", "host_boot_id"),
            "invalid-capability-state",
        )
        if capability != {
            "identity": identity,
            "manifest_sha256": manifest["capability_manifest_sha256"],
            "result": "PASS",
            "host_boot_id": boot_id,
        }:
            raise RunnerError("capability-state-mismatch")
    records = manifest["files"]
    paths = {}
    download_records = list(records.items()) + [
        ("support:" + record["name"], record)
        for record in manifest["qemu_support"]
    ]
    for name, record in download_records:
        public_file = name in (
            "qemu", "ovmf_code", "ovmf_vars", "capability_raw"
        ) or name.startswith("support:")
        destination_root = public_root if public_file else phase_root
        destination = destination_root / record["name"]
        if destination.exists():
            if (
                destination.is_symlink()
                or destination.stat().st_size != record["size"]
                or hashlib.sha256(destination.read_bytes()).hexdigest()
                != record["sha256"]
            ):
                raise RunnerError("stale-host-input")
        elif phase == "private" and public_file:
            raise RunnerError("capability-input-missing")
        else:
            download_file(base_url, container, record, sas, destination)
        paths[name] = destination
    qemu = paths["qemu"]
    qemu.chmod(0o700)
    paths["ovmf_code"].chmod(0o400)
    paths["ovmf_vars"].chmod(0o400)
    raw_size = manifest["raw_size"]
    if phase == "private":
        if hash_prefix(paths["vhd"], raw_size) != records["raw"]["sha256"]:
            raise RunnerError("vhd-data-region-mismatch")
        with paths["vhd"].open("rb") as vhd:
            vhd.seek(-512, os.SEEK_END)
            if vhd.read(8) != b"conectix":
                raise RunnerError("invalid-fixed-vhd-footer")
    images = (
        (("capability", paths["capability_raw"]),)
        if phase == "capability"
        else (("raw", paths["raw"]), ("vhd", paths["vhd"]))
    )
    boots = {}
    logs = []
    for image_name, image in images:
        boots[image_name] = {}
        for mode, legacy_apic in LOCAL_BOOT_MODES:
            outcome, log_path = run_boot(
                qemu,
                paths["ovmf_code"], records["ovmf_code"],
                paths["ovmf_vars"], records["ovmf_vars"],
                image,
                records[image_name if image_name != "capability"
                        else "capability_raw"],
                raw_size, manifest["boot_policy"],
                f"{image_name}-{mode}", legacy_apic, evidence_root,
                manifest["guarded"],
            )
            boots[image_name][mode] = outcome
            logs.append(log_path)
    receipt = {
        "schema": EVIDENCE_SCHEMA,
        "schema_version": 2,
        "phase": phase,
        "identity": identity,
        "result": "PASS",
        "manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
        "runner_sha256": manifest["runner_sha256"],
        "host_boot_id": boot_id,
        "boot_policy": manifest["boot_policy"],
        "acceptance_scope": "platform-only",
        "storage_result": (
            "UNAVAILABLE"
            if manifest["boot_policy"] == GUARDED_BOOT_POLICY
            else "NOT_EVALUATED"
        ),
        "boots": boots,
    }
    receipt_path = evidence_root / "receipt.json"
    write_durable(
        receipt_path, (json.dumps(receipt, sort_keys=True) + "\n").encode()
    )
    total = receipt_path.stat().st_size + sum(path.stat().st_size for path in logs)
    if total > MAX_EVIDENCE_BYTES:
        raise RunnerError("evidence-total-too-large")
    prefix = manifest["evidence_prefix"]
    for path in logs:
        upload_file(
            base_url, container, f"{prefix}/{path.name}", sas, path
        )
    upload_file(
        base_url, container, f"{prefix}/receipt.json", sas, receipt_path
    )
    if phase == "capability":
        write_durable(
            capability_complete,
            (json.dumps({
            "identity": identity,
            "manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
            "result": "PASS",
            "host_boot_id": boot_id,
            }, sort_keys=True) + "\n").encode(),
        )
    return hashlib.sha256(receipt_path.read_bytes()).hexdigest(), len(boots) * 2


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--phase", choices=("capability", "private"), required=True)
    parser.add_argument("--manifest-b64", required=True)
    parser.add_argument("--blob-base-url", required=True)
    parser.add_argument("--container", required=True)
    parser.add_argument(
        "--root", type=Path,
        default=Path("/var/lib/unikraft-private-preflight"),
    )
    args = parser.parse_args()
    try:
        sas = os.environ.pop("HYPERV_PREFLIGHT_SAS")
        manifest, manifest_bytes = parse_manifest(
            args.manifest_b64, args.phase
        )
        args.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        receipt_sha256, boot_count = execute_phase(
            args.phase, manifest, manifest_bytes,
            args.blob_base_url, args.container, sas, args.root,
        )
        print("HYPERV_PRIVATE_PREFLIGHT " + json.dumps({
            "schema": 1, "phase": args.phase, "result": "PASS",
            "identity": manifest["identity"],
            "receipt_sha256": receipt_sha256,
            "boot_count": boot_count,
        }, sort_keys=True))
    except (KeyError, OSError, RunnerError, ValueError) as error:
        code = getattr(error, "code", None)
        print("HYPERV_PRIVATE_PREFLIGHT " + json.dumps({
            "schema": 1, "phase": args.phase, "result": "FAIL",
            "reason": code or "internal",
        }, sort_keys=True))
        raise SystemExit(1)


if __name__ == "__main__":
    main()
