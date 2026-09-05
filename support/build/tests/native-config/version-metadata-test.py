#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause

import argparse
import importlib.util
import subprocess
from pathlib import Path


def arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("--base", required=True)
    parser.add_argument("--work-dir", required=True)
    parser.add_argument("--prepare-output", required=True)
    return parser.parse_args()


def load_exporter(base):
    path = base / "support" / "build" / "native-config-metadata.py"
    spec = importlib.util.spec_from_file_location("native_config_metadata", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def expected_version(base):
    values = {}
    for line in (base / "version.mk").read_text(encoding="utf-8").splitlines():
        if "=" not in line:
            continue
        name, value = line.split("=", 1)
        values[name.strip()] = value.strip()
    suffix = subprocess.run(
        [str(base / "support" / "scripts" / "gitsha1")],
        cwd=base,
        check=True,
        stdout=subprocess.PIPE,
        text=True,
    ).stdout.strip()
    full = f"{values['UK_VERSION']}.{values['UK_SUBVERSION']}"
    if values.get("UK_EXTRAVERSION"):
        full += f".{values['UK_EXTRAVERSION']}"
    return full + suffix, values["UK_CODENAME"]


def fake_case(module, work_dir, name, extra, suffix, expected):
    base = work_dir / name
    helper = base / "support" / "scripts" / "gitsha1"
    helper.parent.mkdir(parents=True, exist_ok=True)
    (base / "version.mk").write_text(
        "UK_VERSION = 1\n"
        "UK_SUBVERSION = 2\n"
        f"UK_EXTRAVERSION = {extra}\n"
        "UK_CODENAME = Test Moon\n",
        encoding="utf-8",
    )
    helper.write_text(f"#!/bin/sh\nprintf '%s\\n' '{suffix}'\n", encoding="utf-8")
    helper.chmod(0o755)
    actual, codename = module.version_environment(base)
    if actual != expected or codename != "Test Moon":
        raise AssertionError(
            f"{name}: got version={actual!r}, codename={codename!r}; "
            f"expected version={expected!r}, codename='Test Moon'"
        )


def main():
    args = arguments()
    base = Path(args.base).resolve()
    work_dir = Path(args.work_dir).resolve()
    output = Path(args.prepare_output).resolve()
    work_dir.mkdir(parents=True, exist_ok=True)

    module = load_exporter(base)
    fake_case(module, work_dir, "release-clean", "0", "~abc123", "1.2.0~abc123")
    fake_case(
        module,
        work_dir,
        "release-dirty",
        "",
        "~abc123-custom",
        "1.2~abc123-custom",
    )
    fake_case(module, work_dir, "release-no-git", "rc1", "", "1.2.rc1")

    expected, codename = expected_version(base)
    actual, actual_codename = module.version_environment(base)
    if (actual, actual_codename) != (expected, codename):
        raise AssertionError(
            f"repository metadata mismatch: {(actual, actual_codename)!r} != "
            f"{(expected, codename)!r}"
        )

    fragment = output / "native-config-version" / expected / "Config.uk"
    fragment.parent.mkdir(parents=True, exist_ok=True)
    fragment.write_text(
        'config VERSION_PATH_SYMBOL\n\tstring "Version path symbol"\n',
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
