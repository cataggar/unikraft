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
GUARDED_PRODUCER_SCHEMA_VERSION = 5
GUARDED_PRODUCER_DIRECTORY_EXCLUSIONS = {
    "support/build": ("wamr-native-ci",),
}
# Keep these independently enforced pins aligned with the reviewed guarded
# producer source set. Schema 5 records support/build without the separate
# WAMR native CI controller subtree; that subtree must still be a plain
# non-symlink directory, and no other guarded closure has exclusions.
GUARDED_PRODUCER_CLOSURES = {
    "support/build": {
        "name": "support/build",
        "sha256": (
            "f885005e3760734dbe3dc5458d0ecac2bc3ecf31f4433f3672607066080ec7f0"
        ),
        "size": 1796643,
        "files": 220,
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
        "b2a3d76e24973764467c36a5bb2197dd6d6754309e6c8a4ae102af4d4316ddfa"
    ),
    "support/build/hyperv-proof-binding.zig": (
        "8748440c3f6d12b3e1d723fec9f5e8095a54c8f740267260ec09dd0a6772e3fc"
    ),
    "support/build/hyperv-proof-build.zig": (
        "dd1b0e02ee0dec4ebe8dad8e8fc1b127057f5aad333bb6b2ccc52b5cf39011a2"
    ),
    "support/build/hyperv-proof-disasm.zig": (
        "17102f939527f340d8db18911536de9388b829865ce37cc492364340082b342a"
    ),
    "support/build/hyperv-proof-fixtures.zig": (
        "1e787519bfed589cec80bda089572729158481b09c6e7b90281098fe75205297"
    ),
    "support/build/hyperv-proof-flow.zig": (
        "ef746e4075bf57c148f6f81911e773ead518eb6277ee9ec4ff5fe7214a91bac4"
    ),
    "support/build/hyperv-proof-image.zig": (
        "f351f9643a81884eecdd56e931df9629c4229411882c13a5ce83b3f29160e43f"
    ),
    "support/build/hyperv-proof-instructions.zig": (
        "06139edf95d95a268460748a4f75796fee81b7b880a349dfaaf7c8b6ed7e8dab"
    ),
    "support/build/hyperv-proof-paths.zig": (
        "fc97c3b2c5ee0950cdf7217c04e7cd0e009b770ce75448d2fcd7bd1a71c9c49e"
    ),
    "support/build/hyperv-proof-tests.zig": (
        "0cf66054f049da126c7a4152f5733891d0664f621d863614f801b6ae214f8243"
    ),
    "support/build/hyperv-proof-tool.zig": (
        "33b69f186344f642bc99884f88d7f4c8b20c16adc8c2e5d1af31d013f39c1bae"
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
        "a7dd02562548fd3d56dbd31a297f9677e2f4a098ff03247ebe9dd1456b5e02c2"
    ),
    "Makefile": (
        "7e89ae8423aa78bce6b8316a6e6fe0eda58de8604f9fb525a30ce016b32abeeb"
    ),
    "Makefile.uk": (
        "288bb7b13ca5484812e1fa5c6bdc34724607b61d8542cef08357c4e4988bcf09"
    ),
    "build.zig": (
        "c5de5bf0efe4a9be7acb125db5d02e371ab79222cc3e27cbab91ced6db756d05"
    ),
    "build.zig.zon": (
        "8c9bab9a0d0c3cbd68c3b21bcfc212f7148d03c5a30ed9b3c669f1f68e886fba"
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
        "5345579acb2b4cd24489b0fde25cc219f3d629a3e4ea780a7d0f381f33112991"
    ),
    "support/build/config-submenu.sh": (
        "8036c9d1665fcf577b3ac96d28e0fc6196fada7683077884ba85b8ba4ca5f9cd"
    ),
    "support/build/elf-common-validator.zig": (
        "c671e8949d3f44e8117398c9509dc2c17c0bd46df25d49a440ac40ab212aa7fa"
    ),
    "support/build/final-link.zig": (
        "9a231ece8e661f54800393fc042c5c3635f24c30c7ab47e6eee5c1ba32d7f3d9"
    ),
    "support/build/hyperv-object-elf.zig": (
        "943e9f3a90bd0ea245a57b99b7c64db18fc4a37283958c29619e288e1ab91622"
    ),
    "support/build/hyperv-object-proofs.build.zig": (
        "2cbb8f4013ad9294fe0037127409c293e50ccfd8802debd7313a933509145a6b"
    ),
    "support/build/hyperv-object-proofs.zig": (
        "302be56b22cc509f6616f84660b64fb668c7ab5a24c83a3167cde3a3d334d95d"
    ),
    "support/build/hyperv-object-tests.zig": (
        "fdfc757a2029221c074af3f78f54f7de8889ac67ebc776b3b2845b7e0dfe230d"
    ),
    "support/build/hyperv-object-tool-fixture.zig": (
        "0d6db8aa63bec7a7de4656081d454bc1f070ea83dc5d9eb28c63a89263ca9484"
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
        "562e4c8abf804d79296d2962228c0d6d139d489d9ffe5215a972469f10cdbb08"
    ),
    "support/build/merge-linker-scripts.py": (
        "dd39b9cec861bdf4771fba05c0b477aea37e2b2f1d40d843f31d3c1df011ee3a"
    ),
    "support/build/native-build-tools.zig": (
        "fec22a514bf52fd4b4b8502a61dc056842b7b894f6a2463255c36c22bd164e88"
    ),
    "support/build/native-config-metadata.py": (
        "b6ff513dcfd0cddd55ccd75e3b3c78ddaa286190bfa283621cfe08d9b3fe0ef6"
    ),
    "support/build/native-config-input.zig": (
        "928e68535e0c4288c00ae2630e228474c72e57773bde865f8ab7a77380738e9d"
    ),
    "support/build/native-config-metadata.zig": (
        "7d0091540a533386c64ec451bf1343c74b85b431c433e5a708018f31a8949549"
    ),
    "support/build/native-config-tool.zig": (
        "30291f034f98c970bbf7879189e9bc4c8bc5aa5a6a19fe1ed247d508641d46a9"
    ),
    "support/build/native-image-data.zig": (
        "9ded751a325eb43ab2d09af26c31e1cb666134bb3b36f30ca0f186cb64f4820b"
    ),
    "support/build/native-kconfig-bridge.c": (
        "457137bfa280d69f8c3c819ca059c20b76a6c5dcb190575d10a7e5b1ea05f93a"
    ),
    "support/build/native-library-link.zig": (
        "632a6bdea90ec8837cf80919a85b71f89c3aaffb089c3071c0550507f63a496c"
    ),
    "support/build/native-lto.zig": (
        "09abfbdb180fc98da34b565febd5cfb2f723c5e33d4dd7bf4bf28df624827c2c"
    ),
    "support/build/native-make-environment-contract.zig": (
        "4117515795db6f2de1c8e7169e78e6dd8d43452e859462c40752389e56ee8cab"
    ),
    "support/build/native-make-environment.zig": (
        "481a8e9c2bfad546ecc94647f69b82d9d6dc8d86534d5f284d841d1f39475858"
    ),
    "support/build/native-target-object.zig": (
        "19b26c34bd433a46aa1861a44a15eb2c373b3d6e29e8988898504da1bbb56925"
    ),
    "support/build/postprocess-elf.zig": (
        "a5216c490acbf66c7b9c97cba3ebea8a5cd024416e494e61658d9f505b5b7376"
    ),
    "support/build/postprocess-files.zig": (
        "1073f0dd62d950f97e1c0d3504e1c02d4c6af596b3f73221afb93977db3f4260"
    ),
    "support/build/postprocess-image.zig": (
        "528654fe904ddfa17268a6315c388fb644c4eb8acf3d356a9547b653a9c6b169"
    ),
    "support/build/symbols/libukrandom-lcpu.localize": (
        "b00d5cfee43ae40b56bda292365bf7339d2c8f4239131d632edbebe623e940c6"
    ),
    "support/build/target/native-profile.zig": (
        "5f162fefe617dac9b3507fb19856aa1cc8fde1fb63924d52e3be96bfac440b53"
    ),
    "support/build/tests/hyperv-object-undefined.c": (
        "13ab823738d09c0b1d479c523c034f891081871a2a7d69f0cc556828346c2793"
    ),
    "support/build/zig-facade-paths.zig": (
        "38325cf826d855004e9808924e2687dc70bc42264b952da98f2dce0ad801b8f0"
    ),
    "support/build/zig-facade-runner.zig": (
        "95a227e6bcb263d4e9d721ca3f8b86641b869194c81d2c294e1440050ce6fb07"
    ),
    "support/tools/hyperv/contracts.zig": (
        "a51fe40c42a660ca1218275f88c9ddf5d45bebb41f1c7893de8408cec592a1ce"
    ),
    "support/tools/hyperv/core.zig": (
        "6ea44534c393fad97245488701c74b911cc639f7cbf24275a09a55f8b9b15092"
    ),
    "support/tools/hyperv/diagnostics.zig": (
        "39db3cd37dffe39608220e267b627010c6b0aabcfd0a436b98fe9556f5d92516"
    ),
    "support/tools/hyperv/private_files.zig": (
        "ba0022dcefa33f03edc025749b32e85d913e74f13e19650773e18d7066a20b88"
    ),
    "support/tools/hyperv/process-command-v1.json": (
        "ee1e038f6538beecac8a09d4d52a6c601a9ca1f503fd70a3753bd8d2e3ac904b"
    ),
    "support/tools/hyperv/process.zig": (
        "cd393d5ea9df2f877b837454ddf8a3a937362bef7b79ca3de6af157883b56b2b"
    ),
    "support/tools/hyperv/sensitive.zig": (
        "e5845b7623116f3ef6e6e062463f39c2f3840bec5d36c75ccf413643dfae1eca"
    ),
    "support/tools/hyperv/sha256.zig": (
        "8de8969668fdbe6054960760e866749d097e3cc786a977ef943223c6bfcafc46"
    ),
    "support/tools/hyperv/sha256_clear_upper.S": (
        "b7a0c49539870ecb32d4a36a5409154d15d89fcecba97f98b6918539c81c2834"
    ),
    "support/tools/hyperv/sha256_tests.zig": (
        "f7c9feecf8d6e34f94d225065100c47b72e22a6fc9f7866f970b02de5c03c7fa"
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
    "drivers/firmware/ukefi/include/uk/efi.h": (
        "bfde6e4790460f1fdbb9d7fa74bbd338b826e6276aaca0b29c94910b46bfcab4"
    ),
    "drivers/firmware/ukefi/include/uk/efi/time.h": (
        "5a7e349ed5300c3fe0603740dfb34320e72de1ca3bffcab35e6fa9a728a9162c"
    ),
    "drivers/hyperv/netvsc/Makefile.uk": (
        "1fa21b27ba606ba5dc55962d65c854ccdd718c134a3c53fb0dcbe9d89ffd4722"
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
        "01f528db1d51a740ccf58da7a89be4677321b9f892fc146518f4d3125e3b908e"
    ),
    "drivers/hyperv/storvsc/exportsyms.uk": (
        "96d418ad387c2fa392afc96dfc8b1eb77cc20a0bcdb8a88fbd44038a5fdfa5de"
    ),
    "drivers/hyperv/storvsc/include/uk/storvsc.h": (
        "b21ed97379de228acf41ecc4d5929058dc85368a009a6e0abf742bc5d3096c17"
    ),
    "drivers/hyperv/storvsc/storvsc.c": (
        "1df869b7064df4c912fbe2254091573aa1da0be892390fdf50f6165d4aefb658"
    ),
    "drivers/hyperv/storvsc/storvsc_core.h": (
        "8422dd6de969b13a533fe0291a7019442712ae9b7f6177420e6fd4df22860ab7"
    ),
    "drivers/hyperv/storvsc/storvsc_core.zig": (
        "059b4a6bae2c6ee12503b07e082351dfba7acdc806f31863f6e6b7bf199f1998"
    ),
    "drivers/hyperv/vmbus/Config.uk": (
        "05a880a38a10e130510fafbfa786f080d3da1413feb84ca7fc2a068c04a4d069"
    ),
    "drivers/hyperv/vmbus/Makefile.uk": (
        "415661b84cf6ea6dd5ad944a27c15257e8953e348463f234c075ff635663e644"
    ),
    "drivers/hyperv/vmbus/exportsyms.uk": (
        "f26fc7b7de9220cb994e4a81722bfa44e900c9ed84eefab480db9deedaf3a9bb"
    ),
    "drivers/hyperv/vmbus/include/uk/vmbus.h": (
        "13bc5450a7a8eb9c360e240c35907e1b5d82f683e36c2ee4e9a19f90f4d76bcb"
    ),
    "drivers/hyperv/vmbus/include/uk/vmbus_storage.h": (
        "6be9c46611eb45dfe32ec6f6e11c279452b70db32ec95f4b00948f9f299b49b9"
    ),
    "drivers/hyperv/vmbus/vmbus_bus.c": (
        "2e239f3738b1bcca7ab6c5f25a698586606c8df59068415162024b3783307964"
    ),
    "drivers/hyperv/vmbus/vmbus_channel.c": (
        "088cc06d1db460cb52525aeee56d980a2074be5c0c0d8cdfa15eef72b656cc1c"
    ),
    "drivers/hyperv/vmbus/vmbus_protocol.h": (
        "c00e58790f9d8ece3518fdda9b82b02b843eccb3c2cc90002344192b554e44a9"
    ),
    "drivers/hyperv/vmbus/vmbus_protocol.zig": (
        "4fe45a6d38535195d5433fc557ab7f3f8e4ec61ef1c21230429decb319224f87"
    ),
    "lib/uktimeconv/include/uk/timeconv.h": (
        "022634efc8985d508279fead89c925268df5cd290551d41c2f2aabbeb2e5dd5f"
    ),
    "lib/uktimeconv/timeconv.c": (
        "52310af5a7934859733fa6d8e6164b0a5c29cea051494f240b67a5bad08e21b4"
    ),
    "plat/hyperv/Config.uk": (
        "c5fe6226a426333e2119845366cac6c712b4258d8c7ead82980d7ac57c7c0505"
    ),
    "plat/hyperv/Makefile.uk": (
        "d73b989cc28c7884e4f26156fad52dd92847ed71ff45dba17a12d2feb9120990"
    ),
    "plat/hyperv/hyperv_runtime.zig": (
        "fc12400e185046f5aa8bb7469a68824d3e47ca855f9487f662e600206d9605a2"
    ),
    "plat/hyperv/include/hyperv/clock.h": (
        "378e4b267ca5330d5a7a1fd9da306d1fd59244528e15560d1ef8842ce26eea35"
    ),
    "plat/hyperv/include/hyperv/efi_clock.h": (
        "5927caa03f0ff5bde3df68eb7073c93c345b9ea5920f697dafd0c0370fa39e33"
    ),
    "plat/hyperv/include/hyperv/hyperv.h": (
        "af844d90dea4b706ad00ef50beaa0df54697a6b324888d4d41dc918ae2b57b3c"
    ),
    "plat/hyperv/platform.c": (
        "79b79a74cdc03c3c83bde9da212835e8367a6709d04c4ec9fee156e5139e689b"
    ),
    "plat/hyperv/time.c": (
        "82e672e9659bfb4851d574c0c1ce4a48b55c415e9ffc6bc36eda57dde9e7764b"
    ),
    "support/build/native-image-graph.zig": (
        "dc2c69e762d8030054b7670036e872d377857baf606c626c5be627e55ce38805"
    ),
    "support/build/native-postprocess-runner.py": (
        "3379115753b149a6f16675cb3d5f315c25bfb49bf702720cdc882470434ef0f1"
    ),
    "support/build/native-postprocess-runner.zig": (
        "f7700d90475285230dd5bc1dbf9c4142b1c16c90c931bf4fcc07605e725861d1"
    ),
    "support/build/native-postprocess.zig": (
        "294ffe3767a69e7cb60aecf4a8417924e27eb69996562afe954f7efdc6b57381"
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
        "d44be89b16152994c03fa5fee704e6dcb411ba635263d5f3971193108a97a129"
    ),
    "support/apps/hyperv-acceptance/Makefile.uk": (
        "2e5c23e4ca47bd306a4d4ab6d75b996ccf5b6ddc885698d25f478ead40df4ac3"
    ),
    "support/apps/hyperv-acceptance/acceptance_protocol.c": (
        "c7b8cdd84f21e59fd93454e28ef3f99d03b17438b1d840042f852956af1237df"
    ),
    "support/apps/hyperv-acceptance/acceptance_protocol.h": (
        "392efcb26a97cae7a93131a587318559c7801f7b6fa1646c19482253a5108b7e"
    ),
    "support/apps/hyperv-acceptance/application_network.c": (
        "829b522860c21278eec3c1e849a1b9259c200ee7270f38dbc5872cb5f3c6f82f"
    ),
    "support/apps/hyperv-acceptance/application_network.h": (
        "dba07b1331d6a6f02c3f017c2fabe5a0c1c03f61ffd1df7e07e49c84427d2231"
    ),
    "support/apps/hyperv-acceptance/main.c": (
        "36591c09ecaee3a4dadb03fc194682778f386758df47fc9016f37cb0eacf9400"
    ),
    "support/apps/hyperv-acceptance/persistence.c": (
        "a0fbe85754d6072f3411a498d2c3c13b11214688a625fc70b62795639cfd49c1"
    ),
    "support/apps/hyperv-acceptance/persistence.h": (
        "8ef53f9ed76286b945212ea487bed1e6d51ec161078d4a2283f9054b962bd70f"
    ),
    "support/apps/hyperv-acceptance/persistence_host.h": (
        "29f1f4f0f272225ae1d2578612a4f8320f1bc8d245e9447ce6696300b80ad23c"
    ),
    "support/apps/hyperv-acceptance/storage_target.c": (
        "4bde9ddbcfaf29588c500e00aba2dc4438db8f1e524149982e103b0fc43b5de2"
    ),
    "support/apps/hyperv-acceptance/storage_target.h": (
        "a283195fe8c0cbd8ca91365d7bcf12097d49dbe08ddf970234c62e071ed7dc37"
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
