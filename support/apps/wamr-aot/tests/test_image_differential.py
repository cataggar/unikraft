#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""Differential contract tests for Python and native image commands."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import unittest


CLI = Path(sys.argv[1]).resolve(strict=True)
FIXTURE = Path(sys.argv[2]).resolve(strict=True)
WORKSPACE = Path(sys.argv[3]).resolve() / "image-differential"
sys.argv[1:] = []
APP_SOURCE = Path(__file__).resolve().parents[1]
REVISION = "0123456789abcdef0123456789abcdef01234567"
TOOLS = (
    "zig", "make", "llvm-nm", "llvm-objcopy", "llvm-objdump",
    "llvm-readelf", "llvm-strip", "bison", "flex", "m4", "bash",
    "cp", "mkdir", "python3", "readlink", "git",
)
IMAGES = (
    "wamr_hyperv-x86_64-efi",
    "wamr_hyperv-x86_64-efi.dbg",
    "wamr_hyperv-x86_64-efi.bootinfo",
)


def private_directory(path):
    path.mkdir(parents=True, exist_ok=True)
    path.chmod(0o700)


def private_file(path, data=b""):
    private_directory(path.parent)
    path.write_bytes(data)
    path.chmod(0o600)


def create_repository(path, variant, jit_mode, existing_config=None):
    app = path / "support/apps/wamr-aot"
    private_directory(app)
    for source in APP_SOURCE.iterdir():
        if source.name.startswith(".") or not source.is_file():
            continue
        destination = app / source.name
        shutil.copyfile(source, destination)
        destination.chmod(0o600)
    private_file(
        app / "build/artifacts/identity.json",
        (
            json.dumps(
                {"jit_mode": jit_mode, "variant": variant},
                sort_keys=True,
                indent=2,
            )
            + "\n"
        ).encode(),
    )
    if existing_config is not None:
        private_file(app / ".config", existing_config)
    return app


def environment_for(log, bison_data, explicit=True):
    environment = os.environ.copy()
    for name in tuple(environment):
        if name.startswith("WAMR_CI_TOOL_") or name.startswith(
            "WAMR_IMAGE_FIXTURE_"
        ):
            environment.pop(name)
    environment.update(
        {
            "HOME": str(WORKSPACE / "home"),
            "PATH": os.environ["PATH"],
            "PYTHONDONTWRITEBYTECODE": "1",
            "WAMR_IMAGE_FIXTURE_BISON_DATA": str(bison_data),
            "WAMR_IMAGE_FIXTURE_LOG": str(log),
            "WAMR_IMAGE_FIXTURE_REVISION": REVISION,
        }
    )
    for name in TOOLS:
        environment[
            "WAMR_CI_TOOL_" + name.upper().replace("-", "_")
        ] = str(FIXTURE)
    if explicit:
        environment["BISON_PKGDATADIR"] = str(bison_data)
    else:
        environment.pop("BISON_PKGDATADIR", None)
    private_directory(Path(environment["HOME"]))
    return environment


def command(producer, app, step):
    if producer == "python":
        return [sys.executable, app / "build-image.py", step]
    return [CLI, step, "--repository", app.parents[2]]


def run(producer, app, step, environment):
    return subprocess.run(
        [str(value) for value in command(producer, app, step)],
        cwd=APP_SOURCE,
        env=environment,
        capture_output=True,
        text=True,
        umask=0o077,
    )


def mode(path):
    return stat.S_IMODE(path.stat().st_mode)


def normalize_value(value, repository):
    if isinstance(value, str):
        return value.replace(str(repository), "<repository>")
    if isinstance(value, list):
        return [
            normalize_value(item, repository)
            for item in value
            if not (
                isinstance(item, str)
                and item.startswith("-Dwamr-aot-tool=")
            )
        ]
    if isinstance(value, dict):
        return {
            key: normalize_value(item, repository)
            for key, item in value.items()
        }
    return value


def normalized_log(path, repository):
    normalized = []
    for line in path.read_text().splitlines():
        fields = [
            field.replace(str(repository), "<repository>")
            for field in line.split("\t")
            if not field.startswith("-Dwamr-aot-tool=")
        ]
        normalized.append(fields)
    return normalized


def snapshot(app, log):
    build = app / "build"
    identity_bytes = (build / "image-identity.json").read_bytes()
    return {
        "app_config": (app / ".config").read_bytes(),
        "solved_config": (build / ".config").read_bytes(),
        "environment": (
            build / "native-environment/environment.json"
        ).read_bytes(),
        "identity_bytes": identity_bytes,
        "identity": json.loads(identity_bytes),
        "images": {
            name: ((build / name).read_bytes(), mode(build / name))
            for name in IMAGES
        },
        "modes": {
            "app_config": mode(app / ".config"),
            "solved_config": mode(build / ".config"),
            "environment": mode(
                build / "native-environment/environment.json"
            ),
            "identity": mode(build / "image-identity.json"),
        },
        "log": normalized_log(log, app.parents[2]),
    }


def build_success(producer, repository, case, explicit=True):
    app = create_repository(
        repository,
        case["variant"],
        case.get("jit_mode"),
        case.get("existing_config"),
    )
    bison_data = WORKSPACE / "bison-data"
    log = WORKSPACE / "logs" / f"{case['name']}-{producer}.log"
    private_file(log)
    environment = environment_for(log, bison_data, explicit)
    configured = run(producer, app, "olddefconfig", environment)
    if configured.returncode:
        raise AssertionError(
            f"{producer} olddefconfig failed\n"
            f"stdout={configured.stdout}\nstderr={configured.stderr}"
        )
    private_file(app / "build/image-identity.json", b'{"stale":true}\n')
    built = run(producer, app, "native-images", environment)
    if built.returncode:
        diagnostics = app / "build/native-environment/diagnostics"
        detail = ""
        if diagnostics.is_dir():
            detail = "\n".join(
                f"{path}: {path.read_text(errors='replace')}"
                for path in sorted(diagnostics.rglob("*"))
                if path.is_file()
                and path.suffix in (".json", ".stderr", ".txt")
            )
        raise AssertionError(
            f"{producer} native-images failed\n"
            f"stdout={built.stdout}\nstderr={built.stderr}\n{detail}"
        )
    return snapshot(app, log)


class ImageDifferential(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if WORKSPACE.exists():
            shutil.rmtree(WORKSPACE)
        private_directory(WORKSPACE)
        private_directory(WORKSPACE / "home")
        private_directory(WORKSPACE / "logs")
        private_directory(WORKSPACE / "bison-data")

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(WORKSPACE)

    def test_configs_root_plan_outputs_identities_modes_and_environments(self):
        cases = (
            {"name": "tiny", "variant": "tiny"},
            {"name": "snapshot", "variant": "snapshot"},
            {"name": "sample-aot", "variant": "sample-aot"},
            {"name": "jit-fast", "variant": "jit", "jit_mode": "fast"},
            {"name": "jit-full", "variant": "jit", "jit_mode": "full"},
            {
                "name": "existing-config",
                "variant": "jit",
                "jit_mode": "full",
                "existing_config": b"CONFIG_EXISTING=y\n",
            },
        )
        for index, case in enumerate(cases):
            with self.subTest(case=case["name"]):
                python_repository = (
                    WORKSPACE / "cases" / case["name"] / "python"
                )
                native_repository = (
                    WORKSPACE / "cases" / case["name"] / "native"
                )
                python = build_success(
                    "python",
                    python_repository,
                    case,
                    explicit=index != 1,
                )
                native = build_success(
                    "native",
                    native_repository,
                    case,
                    explicit=index != 1,
                )
                self.assertEqual(python["app_config"], native["app_config"])
                self.assertEqual(
                    python["solved_config"], native["solved_config"]
                )
                self.assertEqual(
                    normalize_value(
                        json.loads(python["environment"]),
                        python_repository,
                    ),
                    normalize_value(
                        json.loads(native["environment"]),
                        native_repository,
                    ),
                )
                self.assertEqual(python["images"], native["images"])
                self.assertEqual(python["modes"], native["modes"])
                self.assertEqual(
                    normalize_value(
                        python["identity"], python_repository
                    ),
                    normalize_value(
                        native["identity"], native_repository
                    ),
                )
                self.assertEqual(python["log"], native["log"])
                self.assertTrue(
                    any(
                        argument.startswith("-Dwamr-aot-tool=")
                        for argument in native["identity"]["command"]
                    )
                )
                self.assertFalse(
                    any(
                        argument.startswith("-Dwamr-aot-tool=")
                        for argument in python["identity"]["command"]
                    )
                )

    def test_bison_root_and_dirty_failures_retain_success_identity(self):
        for producer in ("python", "native"):
            with self.subTest(producer=producer):
                repository = WORKSPACE / "failures" / producer
                app = create_repository(repository, "tiny", None)
                log = WORKSPACE / "logs" / f"failure-{producer}.log"
                private_file(log)
                environment = environment_for(
                    log, WORKSPACE / "bison-data", explicit=False
                )
                configured = run(
                    producer, app, "olddefconfig", environment
                )
                self.assertEqual(0, configured.returncode, configured.stderr)
                sentinel = b'{"sentinel":true}\n'
                private_file(app / "build/image-identity.json", sentinel)

                environment["WAMR_IMAGE_FIXTURE_FAIL"] = "native-images"
                failed = run(
                    producer, app, "native-images", environment
                )
                self.assertNotEqual(0, failed.returncode)
                self.assertEqual(
                    sentinel,
                    (app / "build/image-identity.json").read_bytes(),
                )

                environment.pop("WAMR_IMAGE_FIXTURE_FAIL")
                environment["WAMR_IMAGE_FIXTURE_DIRTY"] = "1"
                dirty = run(
                    producer, app, "native-images", environment
                )
                self.assertNotEqual(0, dirty.returncode)
                self.assertEqual(
                    sentinel,
                    (app / "build/image-identity.json").read_bytes(),
                )
                if producer == "native":
                    self.assertEqual(
                        "wamr_aot_build_failed category=unsupported_input\n",
                        dirty.stderr,
                    )
                    self.assertNotIn(str(WORKSPACE), dirty.stderr)

    def test_invalid_bison_override_never_falls_back(self):
        for value in ("", "relative", str(WORKSPACE / "missing")):
            for producer in ("python", "native"):
                with self.subTest(value=value, producer=producer):
                    repository = (
                        WORKSPACE / "bison-refusals"
                        / hashlib.sha256(value.encode()).hexdigest()
                        / producer
                    )
                    app = create_repository(repository, "tiny", None)
                    log = (
                        WORKSPACE / "logs"
                        / f"bison-{hashlib.sha256(value.encode()).hexdigest()}-{producer}.log"
                    )
                    private_file(log)
                    environment = environment_for(
                        log, WORKSPACE / "bison-data"
                    )
                    environment["BISON_PKGDATADIR"] = value
                    result = run(
                        producer, app, "olddefconfig", environment
                    )
                    self.assertNotEqual(0, result.returncode)
                    self.assertEqual("", log.read_text())
                    self.assertFalse((app / "build/.config").exists())
                    if producer == "native":
                        self.assertNotIn(str(WORKSPACE), result.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
