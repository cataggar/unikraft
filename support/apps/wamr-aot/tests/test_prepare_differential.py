#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""Differential contract tests for the Python and native prepare producers."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tarfile
import unittest


CLI = Path(sys.argv[1]).resolve(strict=True)
FIXTURE = Path(sys.argv[2]).resolve(strict=True)
ZIG_LIB_DIR = Path(sys.argv[3]).resolve(strict=True)
WORKSPACE = Path(sys.argv[4]).resolve() / "prepare-differential"
sys.argv[1:] = []

APP_SOURCE = Path(__file__).resolve().parents[1]
REVISION = "a53205d77be3b880eb8f8b96679512ba58e2331a"
APP_FILES = (
    "prepare.py",
    "build-tool-prepare.zig",
    "fixture.zig",
    "workloads.build.zig",
    "snapshot.zig",
    "sampler.zig",
    "native-services.zig",
    "workloads.h",
    "platform.h",
    "wasi.zig",
)
SOURCE_FILES = {
    "include/wamr_aot.h": b"fixture-header",
    "tests/benchmarks/loop-passes/unroll4.wasm": b"compute-wasm",
    "tests/benchmarks/loop-passes/iv_store.wasm": b"memory-wasm",
    "tests/benchmarks/coremark/coremark_wasi.wasm": b"coremark-wasm",
    "tests/benchmarks/coremark/coremark_wasi_nofp.wasm": b"coremark-nofp-wasm",
    "tests/unikraft-jit/fixture.zig": b"fixture-source",
    "build.zig": b"fixture-build",
}


def private_directory(path):
    path.mkdir(parents=True, exist_ok=True)
    path.chmod(0o700)


def private_file(path, data=b""):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    path.chmod(0o600)


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def create_repository(path):
    app = path / "support/apps/wamr-aot"
    private_directory(app)
    for name in APP_FILES:
        destination = app / name
        shutil.copyfile(APP_SOURCE / name, destination)
        destination.chmod(0o600)
    return app


def create_archive(path):
    private_directory(path.parent)
    with tarfile.open(path, "w", format=tarfile.USTAR_FORMAT) as archive:
        for name, contents in SOURCE_FILES.items():
            entry = tarfile.TarInfo(name)
            entry.mode = 0o644
            entry.uid = os.getuid()
            entry.gid = os.getgid()
            entry.mtime = 0
            entry.size = len(contents)
            archive.addfile(entry, fileobj=BytesReader(contents))
    path.chmod(0o600)


class BytesReader:
    def __init__(self, contents):
        self.contents = contents
        self.offset = 0

    def read(self, size=-1):
        if size < 0:
            size = len(self.contents) - self.offset
        result = self.contents[self.offset:self.offset + size]
        self.offset += len(result)
        return result


def create_source_checkout(path, environment):
    private_directory(path)
    for name, contents in SOURCE_FILES.items():
        private_file(path / name, contents)
        (path / name).chmod(0o644)
    subprocess.run(["git", "init", "--quiet"], cwd=path, env=environment, check=True)
    subprocess.run(["git", "add", "."], cwd=path, env=environment, check=True)
    commit_environment = dict(
        environment,
        GIT_AUTHOR_NAME="Fixture",
        GIT_AUTHOR_EMAIL="fixture@example.invalid",
        GIT_COMMITTER_NAME="Fixture",
        GIT_COMMITTER_EMAIL="fixture@example.invalid",
        GIT_AUTHOR_DATE="2000-01-01T00:00:00+00:00",
        GIT_COMMITTER_DATE="2000-01-01T00:00:00+00:00",
    )
    subprocess.run(
        ["git", "commit", "--quiet", "-m", "fixture"],
        cwd=path,
        env=commit_environment,
        check=True,
    )
    return subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=path,
        env=environment,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def environment_for(repository, log):
    build = repository / "support/apps/wamr-aot/build"
    native = build / "native-environment"
    private_directory(native)
    paths = {
        "TMPDIR": build / "scratch",
        "XDG_CACHE_HOME": native / "xdg_cache",
        "XDG_CONFIG_HOME": native / "xdg_config",
        "ZIG_GLOBAL_CACHE_DIR": native / "zig_global_cache",
        "ZIG_LOCAL_CACHE_DIR": native / "zig_local_cache",
    }
    for path in paths.values():
        private_directory(path)
    private_file(log)
    environment = os.environ.copy()
    for name in (
        "WAMR_PREPARE_FIXTURE_FAIL",
        "WAMR_PREPARE_FIXTURE_MISMATCH",
    ):
        environment.pop(name, None)
    environment.update({name: str(path) for name, path in paths.items()})
    environment.update({
        "HOME": str(WORKSPACE / "home"),
        "PATH": os.environ["PATH"],
        "PYTHONDONTWRITEBYTECODE": "1",
        "WAMR_CI_TOOL_ZIG": str(FIXTURE),
        "WAMR_PREPARE_FIXTURE_LOG": str(log),
        "ZIG_LIB_DIR": str(ZIG_LIB_DIR),
    })
    private_directory(Path(environment["HOME"]))
    return environment


def run(command, environment):
    return subprocess.run(
        [str(argument) for argument in command],
        env=environment,
        capture_output=True,
        text=True,
        umask=0o077,
    )


def prepare_command(producer, repository, source, case):
    app = repository / "support/apps/wamr-aot"
    if producer == "python":
        command = [sys.executable, app / "prepare.py", "prepare"]
    else:
        command = [CLI, "prepare", "--repository", repository]
    if case["input"] == "archive":
        command.extend(["--source-archive", source])
    else:
        command.extend(["--source", source])
    if case["variant"] != "tiny":
        command.extend(["--variant", case["variant"]])
    if case.get("coremark"):
        command.append("--coremark")
    if case.get("jit_mode"):
        command.extend(["--jit-mode", case["jit_mode"]])
    if case.get("development_revision"):
        command.extend(["--development-revision", case["development_revision"]])
    return command


def verify_command(producer, repository):
    app = repository / "support/apps/wamr-aot"
    if producer == "python":
        return [sys.executable, app / "prepare.py", "verify"]
    return [CLI, "verify", "--repository", repository]


def snapshot(repository, log):
    app = repository / "support/apps/wamr-aot"
    build = app / "build"
    artifacts = build / "artifacts"
    identity_bytes = (artifacts / "identity.json").read_bytes()
    return {
        "identity_bytes": identity_bytes,
        "identity": json.loads(identity_bytes),
        "artifacts": {
            path.name: (path.read_bytes(), stat.S_IMODE(path.stat().st_mode))
            for path in sorted(artifacts.iterdir())
            if path.name != "identity.json"
        },
        "identity_mode": stat.S_IMODE((artifacts / "identity.json").stat().st_mode),
        "source_bytes": (build / "source-files.json").read_bytes(),
        "source_mode": stat.S_IMODE((build / "source-files.json").stat().st_mode),
        "directory_modes": {
            name: stat.S_IMODE((build / name).stat().st_mode)
            for name in (
                "artifacts",
                "wamr-source",
                "workload-consumer",
                "scratch",
                "native-environment",
            )
        },
        "environment_log": log.read_text(),
    }


def mutate_first_byte(path):
    original = path.read_bytes()
    path.write_bytes(bytes([original[0] ^ 1]) + original[1:])
    return original


def run_success(producer, repository, source, case, log):
    environment = environment_for(repository, log)
    prepared = run(prepare_command(producer, repository, source, case), environment)
    if prepared.returncode != 0:
        diagnostics = repository / "support/apps/wamr-aot/build/native-environment/diagnostics"
        details = ""
        if diagnostics.is_dir():
            details = "\n".join(
                f"{path.name}: {path.read_text(errors='replace')}"
                for path in sorted(diagnostics.glob("*"))
                if path.suffix in (".json", ".stderr", ".txt")
            )
        raise AssertionError(
            f"{producer} {case['name']} prepare failed\n"
            f"stdout={prepared.stdout}\nstderr={prepared.stderr}\n{details}"
        )
    verified = run(verify_command(producer, repository), environment)
    if verified.returncode != 0:
        raise AssertionError(
            f"{producer} {case['name']} verify failed\n"
            f"stdout={verified.stdout}\nstderr={verified.stderr}"
        )
    observed = snapshot(repository, log)
    outcomes = {}
    if case["name"] == "tiny":
        collision = run(prepare_command(producer, repository, source, case), environment)
        outcomes["collision"] = collision.returncode
        identity_path = repository / "support/apps/wamr-aot/build/artifacts/identity.json"
        outcomes["collision_identity_unchanged"] = (
            identity_path.read_bytes() == observed["identity_bytes"]
        )
        for name, relative in (
            ("artifact_tamper", "build/artifacts/tiny.cwasm"),
            ("source_tamper", "fixture.zig"),
        ):
            path = repository / "support/apps/wamr-aot" / relative
            original = mutate_first_byte(path)
            refused = run(verify_command(producer, repository), environment)
            outcomes[name] = refused.returncode
            path.write_bytes(original)
            path.chmod(0o600)
    observed["outcomes"] = outcomes
    return observed


def normalized_identity(observed):
    identity = dict(observed["identity"])
    identity["prepare_source_sha256"] = "<native-producer>"
    return identity


def reset_build_preserving_cache(repository):
    build = repository / "support/apps/wamr-aot/build"
    if not build.exists():
        return
    for path in build.iterdir():
        if path.name == "native-environment":
            continue
        if path.is_dir():
            shutil.rmtree(path)
        else:
            path.unlink()


class PrepareDifferential(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if WORKSPACE.exists():
            shutil.rmtree(WORKSPACE)
        private_directory(WORKSPACE)
        private_directory(WORKSPACE / "logs")
        cls.base_environment = os.environ.copy()
        cls.base_environment.update({
            "HOME": str(WORKSPACE / "home"),
            "PATH": os.environ["PATH"],
            "PYTHONDONTWRITEBYTECODE": "1",
        })
        private_directory(Path(cls.base_environment["HOME"]))
        cls.archive = WORKSPACE / "source.tar"
        create_archive(cls.archive)
        cls.source = WORKSPACE / "source-checkout"
        cls.development_revision = create_source_checkout(
            cls.source,
            cls.base_environment,
        )

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(WORKSPACE)

    def test_all_variants_outputs_identities_commands_modes_and_environment(self):
        cases = (
            {"name": "tiny", "variant": "tiny", "input": "archive"},
            {"name": "tiny-coremark", "variant": "tiny", "input": "archive", "coremark": True},
            {"name": "snapshot", "variant": "snapshot", "input": "archive"},
            {"name": "sample-aot", "variant": "sample-aot", "input": "archive"},
            {"name": "jit-fast", "variant": "jit", "input": "archive", "jit_mode": "fast"},
            {"name": "jit-full", "variant": "jit", "input": "archive", "jit_mode": "full"},
            {
                "name": "development",
                "variant": "tiny",
                "input": "repository",
                "development_revision": self.development_revision,
            },
        )
        for case in cases:
            with self.subTest(case=case["name"]):
                repository = WORKSPACE / "cases" / case["name"]
                create_repository(repository)
                source = self.archive if case["input"] == "archive" else self.source
                python_log = WORKSPACE / "logs" / f"{case['name']}-python.tsv"
                python = run_success("python", repository, source, case, python_log)
                shutil.rmtree(repository / "support/apps/wamr-aot/build")
                native_log = WORKSPACE / "logs" / f"{case['name']}-native.tsv"
                native = run_success("native", repository, source, case, native_log)

                self.assertEqual(python["artifacts"], native["artifacts"])
                self.assertEqual(python["source_bytes"], native["source_bytes"])
                self.assertEqual(python["source_mode"], native["source_mode"])
                self.assertEqual(python["identity_mode"], native["identity_mode"])
                self.assertEqual(python["directory_modes"], native["directory_modes"])
                self.assertEqual(
                    normalized_identity(python),
                    normalized_identity(native),
                )
                self.assertEqual(
                    python["identity"]["commands"],
                    native["identity"]["commands"],
                )
                self.assertEqual(
                    python["environment_log"],
                    native["environment_log"],
                )
                self.assertEqual(
                    python["identity"]["prepare_source_sha256"],
                    sha256(repository / "support/apps/wamr-aot/prepare.py"),
                )
                self.assertEqual(
                    native["identity"]["prepare_source_sha256"],
                    sha256(repository / "support/apps/wamr-aot/build-tool-prepare.zig"),
                )
                self.assertNotEqual(
                    python["identity"]["prepare_source_sha256"],
                    native["identity"]["prepare_source_sha256"],
                )
                if case["name"] == "tiny":
                    for outcome in ("collision", "artifact_tamper", "source_tamper"):
                        self.assertNotEqual(0, python["outcomes"][outcome])
                        self.assertEqual(2, native["outcomes"][outcome])
                    self.assertTrue(python["outcomes"]["collision_identity_unchanged"])
                    self.assertTrue(native["outcomes"]["collision_identity_unchanged"])

    @unittest.skipUnless(
        os.environ.get("WAMR_DIFFERENTIAL_REAL_SOURCE"),
        "set WAMR_DIFFERENTIAL_REAL_SOURCE to the pinned WAMR checkout",
    )
    def test_real_pinned_outputs_match_for_every_variant(self):
        source = Path(
            os.environ["WAMR_DIFFERENTIAL_REAL_SOURCE"]
        ).resolve(strict=True)
        observed_revision = subprocess.run(
            ["git", "rev-parse", f"{REVISION}^{{commit}}"],
            cwd=source,
            env=self.base_environment,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        self.assertEqual(REVISION, observed_revision)
        archive = WORKSPACE / "real-source.tar"
        subprocess.run(
            [
                "git",
                "archive",
                "--format=tar",
                f"--output={archive}",
                REVISION,
            ],
            cwd=source,
            env=self.base_environment,
            check=True,
        )
        archive.chmod(0o600)
        repository = WORKSPACE / "real-repository"
        create_repository(repository)
        actual_zig = Path(shutil.which("zig")).resolve(strict=True)
        cases = (
            {"name": "real-tiny", "variant": "tiny", "input": "archive"},
            {"name": "real-tiny-coremark", "variant": "tiny", "input": "archive", "coremark": True},
            {"name": "real-snapshot", "variant": "snapshot", "input": "archive"},
            {"name": "real-sample-aot", "variant": "sample-aot", "input": "archive"},
            {"name": "real-jit-fast", "variant": "jit", "input": "archive", "jit_mode": "fast"},
            {"name": "real-jit-full", "variant": "jit", "input": "archive", "jit_mode": "full"},
            {
                "name": "real-development",
                "variant": "tiny",
                "input": "repository",
                "development_revision": REVISION,
            },
        )
        for case in cases:
            with self.subTest(case=case["name"]):
                reset_build_preserving_cache(repository)
                selected_source = archive if case["input"] == "archive" else source
                python_log = WORKSPACE / "logs" / f"{case['name']}-python.tsv"
                python_environment = environment_for(repository, python_log)
                python_environment["WAMR_CI_TOOL_ZIG"] = str(actual_zig)
                prepared = run(
                    prepare_command("python", repository, selected_source, case),
                    python_environment,
                )
                self.assertEqual(
                    0,
                    prepared.returncode,
                    f"python real prepare failed\n{prepared.stdout}\n{prepared.stderr}",
                )
                verified = run(
                    verify_command("python", repository),
                    python_environment,
                )
                self.assertEqual(0, verified.returncode, verified.stderr)
                python = snapshot(repository, python_log)

                reset_build_preserving_cache(repository)
                native_log = WORKSPACE / "logs" / f"{case['name']}-native.tsv"
                native_environment = environment_for(repository, native_log)
                native_environment["WAMR_CI_TOOL_ZIG"] = str(actual_zig)
                prepared = run(
                    prepare_command("native", repository, selected_source, case),
                    native_environment,
                )
                self.assertEqual(
                    0,
                    prepared.returncode,
                    f"native real prepare failed\n{prepared.stdout}\n{prepared.stderr}",
                )
                verified = run(
                    verify_command("native", repository),
                    native_environment,
                )
                self.assertEqual(0, verified.returncode, verified.stderr)
                native = snapshot(repository, native_log)

                self.assertEqual(python["artifacts"], native["artifacts"])
                self.assertEqual(python["source_bytes"], native["source_bytes"])
                self.assertEqual(python["source_mode"], native["source_mode"])
                self.assertEqual(python["identity_mode"], native["identity_mode"])
                self.assertEqual(python["directory_modes"], native["directory_modes"])
                self.assertEqual(
                    normalized_identity(python),
                    normalized_identity(native),
                )
                self.assertEqual(
                    python["identity"]["commands"],
                    native["identity"]["commands"],
                )
                self.assertEqual(
                    python["environment_log"],
                    native["environment_log"],
                )

    def test_refusals_and_failed_children_publish_no_success_identity(self):
        invalid_cases = (
            {
                "name": "coremark-snapshot",
                "variant": "snapshot",
                "input": "archive",
                "coremark": True,
            },
            {"name": "jit-without-mode", "variant": "jit", "input": "archive"},
            {"name": "tiny-with-mode", "variant": "tiny", "input": "archive", "jit_mode": "fast"},
            {
                "name": "archive-development",
                "variant": "tiny",
                "input": "archive",
                "development_revision": self.development_revision,
            },
        )
        for case in invalid_cases:
            with self.subTest(case=case["name"]):
                statuses = {}
                for producer in ("python", "native"):
                    repository = WORKSPACE / "refusals" / case["name"] / producer
                    create_repository(repository)
                    environment = environment_for(
                        repository,
                        WORKSPACE / "logs" / f"{case['name']}-{producer}.tsv",
                    )
                    result = run(
                        prepare_command(producer, repository, self.archive, case),
                        environment,
                    )
                    statuses[producer] = result.returncode
                    identity = (
                        repository
                        / "support/apps/wamr-aot/build/artifacts/identity.json"
                    )
                    self.assertFalse(
                        identity.exists()
                    )
                    if producer == "native":
                        self.assertEqual(
                            "wamr_aot_build_failed category=invalid_invocation\n",
                            result.stderr,
                        )
                        self.assertNotIn(str(WORKSPACE), result.stderr)
                self.assertNotEqual(0, statuses["python"])
                self.assertEqual(2, statuses["native"])

        for name, variant, setting, category in (
            (
                "child-failure",
                "tiny",
                ("WAMR_PREPARE_FIXTURE_FAIL", "workload-build"),
                "command_failed",
            ),
            (
                "matched-mismatch",
                "sample-aot",
                ("WAMR_PREPARE_FIXTURE_MISMATCH", "1"),
                "local_failure",
            ),
        ):
            with self.subTest(case=name):
                for producer in ("python", "native"):
                    repository = WORKSPACE / "failures" / name / producer
                    create_repository(repository)
                    environment = environment_for(
                        repository,
                        WORKSPACE / "logs" / f"{name}-{producer}.tsv",
                    )
                    environment[setting[0]] = setting[1]
                    case = {"name": name, "variant": variant, "input": "archive"}
                    result = run(
                        prepare_command(producer, repository, self.archive, case),
                        environment,
                    )
                    self.assertNotEqual(0, result.returncode)
                    identity = (
                        repository
                        / "support/apps/wamr-aot/build/artifacts/identity.json"
                    )
                    self.assertFalse(
                        identity.exists()
                    )
                    if producer == "native":
                        self.assertEqual(
                            f"wamr_aot_build_failed category={category}\n",
                            result.stderr,
                        )
                        diagnostics = (
                            repository
                            / "support/apps/wamr-aot/build/native-environment/diagnostics"
                        )
                        self.assertTrue(any(diagnostics.iterdir()))
                        self.assertNotIn(str(WORKSPACE), result.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
