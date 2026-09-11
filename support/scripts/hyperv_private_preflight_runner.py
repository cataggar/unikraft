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
            "09f7dc31d0a0e592bfb291e0f72e1162c0c18060d8b6e00e30bc6fb12e73f5ef"
        ),
        "size": 1756781,
        "files": 215,
    },
    "support/kconfig": {
        "name": "support/kconfig",
        "sha256": (
            "1922363c552b45adbe8edf0df83b5a05eed16140d8525c9cd1908b80da5662b3"
        ),
        "size": 692952,
        "files": 111,
    },
    "include": {
        "name": "include",
        "sha256": "66217d6181a72e18b050d0a1f64f4e0a240bb09a87879a3338c0ec48611b61a8",
        "size": 212580,
        "files": 28,
    },
    "arch/x86_64": {
        "name": "arch/x86_64",
        "sha256": "92a9b4fa092aa0578279e2e11bf0c438c0de20ba81b1de12a4d4a151b37365df",
        "size": 43271,
        "files": 3,
    },
    "arch/x86/x86_64": {
        "name": "arch/x86/x86_64",
        "sha256": "07f6b1b676bb3584ecef008463facaa65a5700ea4e64a8f40be73afdc329f223",
        "size": 38133,
        "files": 15,
    },
    "lib/ukalloc": {
        "name": "lib/ukalloc",
        "sha256": "f0e21c13e5760a18c2434934e9bd788568e79693acad5dec57f9ea7ae9644d32",
        "size": 57408,
        "files": 11,
    },
    "lib/ukallocbbuddy": {
        "name": "lib/ukallocbbuddy",
        "sha256": "309cef13de29b1294d6f9b59d9961b15f6d51e505a9224c42d5c3cf8705c3c6a",
        "size": 23686,
        "files": 5,
    },
    "lib/ukallocstack": {
        "name": "lib/ukallocstack",
        "sha256": "982af7a7b990417e5796c1618a40527fa2eb9d63e56d702836e38e341a9d2a84",
        "size": 11229,
        "files": 5,
    },
    "lib/ukboot": {
        "name": "lib/ukboot",
        "sha256": "5571c5e8cf6b62cca4e0fc646bf919431822fb5dc91d80ae9ff2830786b67d13",
        "size": 63826,
        "files": 20,
    },
    "lib/uksched": {
        "name": "lib/uksched",
        "sha256": "740a514996ce0906944a30f52983dd517e83444e3d73dbe0799442241665ff38",
        "size": 119968,
        "files": 20,
    },
    "lib/ukschedcoop": {
        "name": "lib/ukschedcoop",
        "sha256": "cc0686ed80ff4db0566bb729c828e138c7e2975360fd23544f7e46fe7735b9c2",
        "size": 26278,
        "files": 8,
    },
    "lib/isrlib": {
        "name": "lib/isrlib",
        "sha256": "4c46471f21ef93579a0c098109c9e75f49ac1c91688d4e8ec313b960e7384518",
        "size": 11810,
        "files": 4,
    },
    "lib/nolibc": {
        "name": "lib/nolibc",
        "sha256": "d6e9b2341186c26d50c5f80b6365a8e57ed2324082d307036f4d723d171db997",
        "size": 304095,
        "files": 104,
    },
    "lib/ukprint": {
        "name": "lib/ukprint",
        "sha256": "8904ddb0c61fd9a55cf4d1924fd5553fcda9557d07d51e48c09029958b28578d",
        "size": 73165,
        "files": 18,
    },
    "plat/native/arch/x86_64": {
        "name": "plat/native/arch/x86_64",
        "sha256": "2bad585345238b9c440a88956c83d155e598eb68749b4e2ff9e1148699e518a2",
        "size": 105216,
        "files": 19,
    },
}
GUARDED_PRODUCER_FILES = {
    "support/build/hyperv-image-proofs.zig": (
        "dd7b58050e5c2e7fe1a0d6c07bc111bcc5807c46a7b09237f5a9cca94debe0ff"
    ),
    "support/build/hyperv-proof-binding.zig": (
        "8748440c3f6d12b3e1d723fec9f5e8095a54c8f740267260ec09dd0a6772e3fc"
    ),
    "support/build/hyperv-proof-build.zig": (
        "126c878df99bef797d3ccf03f6e011ba326b998d78bedb42d961dac53336f1ac"
    ),
    "support/build/hyperv-proof-disasm.zig": (
        "5968de57f412d9dbf2ec4a16bbb16237d56ac198be81bb712a915fc8d31400e7"
    ),
    "support/build/hyperv-proof-fixtures.zig": (
        "4ebe7456ea3c9aede8e3e3376d54b2e80c1995cffe3587dd17d44af7e7ee06bf"
    ),
    "support/build/hyperv-proof-flow.zig": (
        "ef746e4075bf57c148f6f81911e773ead518eb6277ee9ec4ff5fe7214a91bac4"
    ),
    "support/build/hyperv-proof-image.zig": (
        "3b0a6543f178fde897eb84847663eb611f27cffc58398f170d2aa6f0a0af98f5"
    ),
    "support/build/hyperv-proof-instructions.zig": (
        "06139edf95d95a268460748a4f75796fee81b7b880a349dfaaf7c8b6ed7e8dab"
    ),
    "support/build/hyperv-proof-paths.zig": (
        "9b90a3ccbded4ac7f18f7ea0c2530a69277d555d750248fa963816dac252b900"
    ),
    "support/build/hyperv-proof-tests.zig": (
        "a6620356326c4e3a1d63c029efd4f91c586e7b6ccf690893aad2c2d546cee2f9"
    ),
    "support/build/hyperv-proof-tool.zig": (
        "5320cece80eb649c58200edf8e854dccbbc3340a3f3b4f520716403fd355e759"
    ),
    "support/build/tests/cc-option-test.mk": (
        "a7288ddf1eb5c84dd88e42fcc8720ac10103c0ecdd8aea72e77033787c1c3b27"
    ),
    "support/build/tests/hyperv-proof-fixture.c": (
        "4b1347261f2d7aa5a84726c493b507951572d45703124ba9d05befb5e3effa24"
    ),
    "support/build/tests/hyperv-proof-fixture.lds": (
        "3f5ca3588bef958816510bd88e833daf78d55a38a5012ba66c3beb0ac17663ad"
    ),
    "support/build/tests/hyperv-proof-fixture.zig": (
        "54e350a7d5e2bcc0cc7932bf7713741b18ada4760f2da4a575ebdc2cae646013"
    ),
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
        "897ccd1efd890b3ceed246de4f559737157041fd32507a299c78d69cbfbe052d"
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
        "37825f1139fb4949c16e69b90882ad11df4ac8ffa1043550faf076389a5580bf"
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
    "support/build/hyperv-object-elf.zig": (
        "5f875a510bda0220409fa4bc9c23ae5da19e3d314e5b009aae518e84ad9cd96e"
    ),
    "support/build/hyperv-object-proofs.build.zig": (
        "4fb2d39721bb9e2b656f0257689943d692d2dfc4a5c48fdbf6808aa073be13fc"
    ),
    "support/build/hyperv-object-proofs.zig": (
        "d287564200048482edde82d9eb17ba88f4a09560d550dbf17a554395f59652fa"
    ),
    "support/build/hyperv-object-tests.zig": (
        "8226540d853cb37ae40eb25c3eed1163fd240d224c9f8338d767bfc267f21243"
    ),
    "support/build/hyperv-object-tool-fixture.zig": (
        "1d9aea3e733325ec76cbeeb3d288ff2e3236b785b60bb4e811494481264731a9"
    ),
    "support/build/hyperv-object-tools.zig": (
        "72344d506608f7297a6b8c84aa08dd818609796cc7f88c011c0d98c4dc45d483"
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
    "support/build/native-make-environment.zig": (
        "7db2a3cefd9576efa62e66453d3ff59dabfdc5ae8ae391f1f8cc08f5362eec51"
    ),
    "support/build/native-target-object.zig": (
        "c738d4dcd2acf2085c29716725461822752c8c96bab20ab8ec6e9338f51daa20"
    ),
    "support/build/postprocess-elf.zig": (
        "e227ca4b63adfd76ad5e768b424cf750f7e12d6eac8743b7fe9420e339083180"
    ),
    "support/build/postprocess-files.zig": (
        "246755ac1072ef405b0899eb68383eede069eb5d4d0151e8f54844eb8ad5f33f"
    ),
    "support/build/postprocess-image.zig": (
        "5421eb54f11e132ec71551c724b6713e9bda781bd9ecd584aa5f846457209114"
    ),
    "support/build/symbols/libukrandom-lcpu.localize": (
        "b00d5cfee43ae40b56bda292365bf7339d2c8f4239131d632edbebe623e940c6"
    ),
    "support/build/target/native-profile.zig": (
        "ab321fb4434415ddd6ed4e34e173956a9555af91b91f26557b47673b6fe310de"
    ),
    "support/build/tests/hyperv-object-undefined.c": (
        "13ab823738d09c0b1d479c523c034f891081871a2a7d69f0cc556828346c2793"
    ),
    "support/build/zig-facade-paths.zig": (
        "38325cf826d855004e9808924e2687dc70bc42264b952da98f2dce0ad801b8f0"
    ),
    "support/build/zig-facade-runner.zig": (
        "5ba4f753fd4a0537564009a47298f242d10a1b831fe6fda00b5172023de8db77"
    ),
    "support/tools/hyperv/contracts.zig": (
        "57e37d089f7de3fba56a8415e9451b359cac33b63b816ef5a17639c6d1f8d6e1"
    ),
    "support/tools/hyperv/diagnostics.zig": (
        "94138509d8f0818818591f8fbe6181bd1cee09cbff0970506e46b00c989484b7"
    ),
    "support/tools/hyperv/private_files.zig": (
        "dac40c596ccba73af72af8022b72af614f149d93ff2ccf3c7a9aead9ae08d997"
    ),
    "support/tools/hyperv/process.zig": (
        "89e501b82c888eae5ab0cb716909e1f035d640f693e965073890bbd015811120"
    ),
    "support/tools/hyperv/sensitive.zig": (
        "e5845b7623116f3ef6e6e062463f39c2f3840bec5d36c75ccf413643dfae1eca"
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
    "support/build/native-postprocess-runner.zig": (
        "fedf2fc2a2d8297c3852453f79cf5b02ddb67caad61ba2de92d4de98a7d69dcc"
    ),
    "support/build/native-postprocess.zig": (
        "943fd3dbd2c3328e34696ae4240c8f7f36a3f573ffc31e4c2a02c493ceea89ec"
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
