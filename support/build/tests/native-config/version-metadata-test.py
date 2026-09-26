#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause

import argparse
import importlib.util
import os
import subprocess
from pathlib import Path
from unittest import mock


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


def config_path_defaults(module, base, work_dir):
    args = argparse.Namespace(
        image_name=None, exclude=[], external_library=[], external_platform=[],
    )
    app = work_dir / "separate-app"
    config = base / "support/apps/wamr-aot/defconfig"
    output = work_dir / "config-defaults"
    for flag, defaults in (
        (None, (str(base), str(app))),
        ("1", ("/wamr-ci/source", "/wamr-ci/app")),
    ):
        with mock.patch.dict(os.environ):
            os.environ.pop("WAMR_CI_PORTABLE_CONFIG", None)
            if flag is not None:
                os.environ["WAMR_CI_PORTABLE_CONFIG"] = flag
            module.configure_environment(
                args, base, app, output, config, {"ARCH_X86_64": "y"},
            )
            actual = (os.environ["UK_CONFIG_BASE"], os.environ["UK_CONFIG_APP"])
            if actual != defaults:
                raise AssertionError(f"config path defaults differ: {actual!r}")
            if (os.environ["UK_BASE"], os.environ["UK_APP"]) != (str(base), str(app)):
                raise AssertionError("real Kconfig input paths changed")
    with mock.patch.dict(os.environ, {"WAMR_CI_PORTABLE_CONFIG": "invalid"}):
        try:
            module.configure_environment(
                args, base, app, output, config, {"ARCH_X86_64": "y"},
            )
        except ValueError:
            pass
        else:
            raise AssertionError("invalid portable Kconfig selection accepted")


def main():
    args = arguments()
    base = Path(args.base).resolve()
    work_dir = Path(args.work_dir).resolve()
    output = Path(args.prepare_output).resolve()
    work_dir.mkdir(parents=True, exist_ok=True)

    module = load_exporter(base)
    config_path_defaults(module, base, work_dir)
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
