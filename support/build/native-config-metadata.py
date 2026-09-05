#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause

import argparse
import os
import platform
import re
import sys
from pathlib import Path


FORMAT = "unikraft-native-config-metadata-v1"
ADDPLAT = re.compile(
    r"addplat_s\s*,\s*([A-Za-z0-9_.+-]+)\s*,\s*"
    r"\$\(\s*CONFIG_([A-Za-z0-9_]+)\s*\)",
    re.MULTILINE,
)
CONFIG_ASSIGNMENT = re.compile(r"^CONFIG_([A-Za-z0-9_]+)=(.*)$")


def arguments():
    parser = argparse.ArgumentParser(
        description="Export authoritative Kconfig symbol and platform metadata"
    )
    parser.add_argument("--base", required=True)
    parser.add_argument("--app", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--config", required=True)
    parser.add_argument("--metadata", required=True)
    parser.add_argument("--image-name")
    parser.add_argument("--external-library", action="append", default=[])
    parser.add_argument("--external-platform", action="append", default=[])
    parser.add_argument("--exclude", action="append", default=[])
    return parser.parse_args()


def normalized_host_arch():
    machine = platform.machine().lower()
    if machine in ("aarch64", "arm64"):
        return "arm64"
    if machine.startswith("arm"):
        return "arm"
    if machine in ("x86_64", "amd64"):
        return "x86_64"
    if re.fullmatch(r"i.86", machine):
        return "x86"
    return machine


def raw_config(path):
    values = {}
    with path.open(encoding="utf-8") as stream:
        for line in stream:
            match = CONFIG_ASSIGNMENT.match(line.rstrip("\r\n"))
            if match:
                values[match.group(1)] = match.group(2)
    return values


def unquote(value):
    if len(value) < 2 or not value.startswith('"') or not value.endswith('"'):
        return None
    return re.sub(r"\\(.)", r"\1", value[1:-1])


def target_arch(values):
    if values.get("ARCH_X86_64") == "y":
        return "x86_64"
    if values.get("ARCH_ARM_64") == "y":
        return "arm64"
    if values.get("ARCH_ARM_32") == "y":
        return "arm"
    return normalized_host_arch()


def version_environment(base):
    values = {}
    version_file = base / "version.mk"
    if version_file.is_file():
        for line in version_file.read_text(encoding="utf-8").splitlines():
            match = re.match(r"^(UK_[A-Z]+)\s*[:?]?=\s*(.*)$", line)
            if match:
                values[match.group(1)] = match.group(2).strip()
    version = values.get("UK_VERSION", "")
    subversion = values.get("UK_SUBVERSION", "")
    extraversion = values.get("UK_EXTRAVERSION", "")
    full = ".".join(part for part in (version, subversion) if part) + extraversion
    return full, values.get("UK_CODENAME", "")


def configure_environment(args, base, app, output, config, values):
    kconfig_dir = output / "native-config" / "kconfig"
    kconfig_dir.mkdir(parents=True, exist_ok=True)
    fullversion, codename = version_environment(base)
    configured_name = unquote(values.get("UK_NAME", ""))
    image_name = args.image_name or configured_name or app.name
    excluded = os.pathsep.join(args.exclude)
    os.environ.update(
        {
            "CONFIG_": "CONFIG_",
            "KCONFIG_CONFIG": str(config),
            "HOST_ARCH": normalized_host_arch(),
            "BUILD_DIR": str(output),
            "UK_BASE": str(base),
            "UK_APP": str(app),
            "UK_CONFIG": str(config),
            "UK_FULLVERSION": fullversion,
            "UK_CODENAME": codename,
            "UK_ARCH": target_arch(values),
            "KCONFIG_DIR": str(kconfig_dir),
            "KCONFIG_LIB_BASE": str(base / "lib"),
            "KCONFIG_ELIB_DIRS": os.pathsep.join(args.external_library),
            "KCONFIG_PLAT_BASE": str(base / "plat"),
            "KCONFIG_EPLAT_DIRS": os.pathsep.join(args.external_platform),
            "KCONFIG_DRIV_BASE": str(base / "drivers"),
            "KCONFIG_EAPP_DIR": str(app) if app != base else "",
            "KCONFIG_EXCLUDEDIRS": excluded,
            "UK_NAME": image_name,
        }
    )


def platform_roots(base, external_platforms, exclusions):
    roots = []
    internal = base / "plat"
    if internal.is_dir():
        roots.extend(path for path in sorted(internal.iterdir()) if path.is_dir())
    roots.extend(Path(path).resolve() for path in external_platforms)
    excluded = {Path(path).resolve() for path in exclusions}
    return [root for root in roots if root.resolve() not in excluded]


def platform_metadata(base, external_platforms, exclusions, symbols):
    by_symbol = {}
    by_name = {}
    external = {Path(path).resolve() for path in external_platforms}
    external_seen = set()
    for root in platform_roots(base, external_platforms, exclusions):
        makefile = root / "Makefile.uk"
        if not makefile.is_file():
            if root.resolve() in external:
                raise ValueError(
                    f"external platform root '{root}' has no Makefile.uk"
                )
            continue
        matches = ADDPLAT.findall(makefile.read_text(encoding="utf-8"))
        if root.resolve() in external:
            if not matches:
                raise ValueError(
                    f"external platform root '{root}' has no "
                    "addplat_s(name,$(CONFIG_SYMBOL)) registration"
                )
            external_seen.add(root.resolve())
        for name, symbol in matches:
            if symbol not in symbols:
                raise ValueError(
                    f"platform '{name}' from '{root}' uses CONFIG_{symbol}, "
                    "which is absent from the loaded Config.uk model"
                )
            previous_name = by_symbol.get(symbol)
            if previous_name is not None and previous_name != name:
                raise ValueError(
                    f"platform symbol CONFIG_{symbol} maps to both "
                    f"'{previous_name}' and '{name}'"
                )
            previous_symbol = by_name.get(name)
            if previous_symbol is not None and previous_symbol != symbol:
                raise ValueError(
                    f"platform name '{name}' maps to both CONFIG_{previous_symbol} "
                    f"and CONFIG_{symbol}"
                )
            if previous_name is not None:
                raise ValueError(
                    f"duplicate platform mapping CONFIG_{symbol}={name}"
                )
            by_symbol[symbol] = name
            by_name[name] = symbol
    missing = external - external_seen - {
        Path(path).resolve() for path in exclusions
    }
    if missing:
        raise ValueError(
            "missing platform metadata for: "
            + ", ".join(str(path) for path in sorted(missing, key=str))
        )
    return sorted(by_symbol.items())


def main():
    args = arguments()
    base = Path(args.base).resolve()
    app = Path(args.app).resolve()
    output = Path(args.output).resolve()
    config = Path(args.config).resolve()
    metadata_path = Path(args.metadata).resolve()

    sys.path.insert(0, str(base / "support" / "kconfiglib"))
    import kconfiglib

    values = raw_config(config)
    configure_environment(args, base, app, output, config, values)
    kconf = kconfiglib.Kconfig(
        str(base / "Config.uk"),
        warn=False,
        suppress_traceback=True,
    )
    type_names = {
        kconfiglib.BOOL: "bool",
        kconfiglib.TRISTATE: "tristate",
        kconfiglib.STRING: "string",
        kconfiglib.INT: "int",
        kconfiglib.HEX: "hex",
    }
    symbols = {
        symbol.name: type_names[symbol.orig_type]
        for symbol in kconf.unique_defined_syms
        if symbol.name is not None and symbol.orig_type in type_names
    }
    platforms = platform_metadata(
        base,
        args.external_platform,
        args.exclude,
        symbols,
    )

    lines = [FORMAT]
    lines.extend(
        f"symbol\t{name}\t{symbol_type}"
        for name, symbol_type in sorted(symbols.items())
    )
    lines.extend(
        f"platform\t{symbol}\t{name}" for symbol, name in platforms
    )
    metadata_path.parent.mkdir(parents=True, exist_ok=True)
    contents = "\n".join(lines) + "\n"
    if metadata_path.is_file() and metadata_path.read_text(encoding="utf-8") == contents:
        return
    metadata_path.write_text(contents, encoding="utf-8")


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(
            f"error: unable to export native configuration metadata: {error}",
            file=sys.stderr,
        )
        sys.exit(2)
