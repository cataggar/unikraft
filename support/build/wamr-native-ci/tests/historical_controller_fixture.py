# SPDX-License-Identifier: BSD-3-Clause
"""Test-only immutable Python-v2 compatibility evidence, never a current owner."""
import argparse
import ast
import copy
import hashlib
import importlib.abc
import importlib.util
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import types

REVISION = "e98623f780fa23d05b5797004e4b88160404eb1b"
PACKAGE = "support/build/wamr-native-ci"
COMMAND_CONTRACT = "support/tools/hyperv/process-command-v1.json"
SOURCES = {
    "run.py": (
        "67386d4ab0fc9fb33e675a4232246878f6324c73",
        "988abba2607410b1fb3864e6688b7078b46c1f8c4d167327400925030f55b380",
    ),
    "tests/test_adapter.py": (
        "04c66355c791fd415ff3ad252dcebca0286fdad7",
        "c1369266cd412a712e5fb94729b9cf69bc870213188c806409176aa3597e0cab",
    ),
    COMMAND_CONTRACT: (
        "ad73db8f74d76dfb14a39969b2b0ec8f4bd73419",
        "ee1e038f6538beecac8a09d4d52a6c601a9ca1f503fd70a3753bd8d2e3ac904b",
    ),
}
STAGES = (
    "adapter", "local-boot-tool", "fixtures", "prepare", "config",
    "native-image", "package", "raw-x2apic", "raw-legacy-apic",
    "finalize-qcow2", "qcow2-x2apic", "qcow2-legacy-apic",
    "derive-fixed-vhd", "vpc-x2apic", "vpc-legacy-apic", "inspect",
    "log-validator-x2apic", "log-validator-legacy",
)
ORACLE_REVISION = "c72bd80b024694590912259fb88a4ba06e84f0a2"
ORACLE_SOURCES = {
    "run.py": (
        "bbd27d611f1d52e610e8588138c8a4e6b3903392",
        "5c0335859329a9131defd84bbfe967cfa9009754de1a93807dd7ef9a3fdc0227",
    ),
    "accepted_records.py": (
        "7ff60b1eb83c3ff343885d47d11299d146b1b312",
        "8ded5b670d89620544c02bb9ad0e1f8ac7a9757207d5b05555d7abbebcff9d84",
    ),
    "public_bundle.py": (
        "0915fdad81109e9afdf171ae07c927100aaefda1",
        "68734d9db7ac38eaa41efe6b1c393199033360c5683ab9d26f2fb34ea8ea4536",
    ),
    "handoff.py": (
        "b84b58341248297cd1807dfb21eab4d363b3c060",
        "a8a9eaae6ba41fa7b0643c2af6711f48f7c97e27e13cd9c8bdb5811560edf7d2",
    ),
    COMMAND_CONTRACT: (
        "ad73db8f74d76dfb14a39969b2b0ec8f4bd73419",
        "ee1e038f6538beecac8a09d4d52a6c601a9ca1f503fd70a3753bd8d2e3ac904b",
    ),
}
_SUBPROCESS_RUN = subprocess.run
_ORACLE_BLOB_CACHE = {}
_ORACLE_CODE_CACHE = {}


def _normalize_oracle_relative(name):
    if name == COMMAND_CONTRACT or name.endswith(".py"):
        return name
    return name + ".py"


def oracle_blob(repository=None, relative="handoff.py", git="git", *, run=None):
    relative = _normalize_oracle_relative(relative)
    repository = (
        Path(__file__).resolve().parents[4]
        if repository is None
        else Path(repository).resolve()
    )
    key = (str(repository), str(git), relative)
    if run is None and key in _ORACLE_BLOB_CACHE:
        return _ORACLE_BLOB_CACHE[key]
    oid, expected = ORACLE_SOURCES[relative]
    environment = {
        "PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C",
        "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_TERMINAL_PROMPT": "0", "GIT_NO_REPLACE_OBJECTS": "1",
    }
    executable = (
        shutil.which(str(git), path=environment["PATH"])
        or shutil.which(str(git))
    )
    if executable is None:
        raise RuntimeError("explicit historical oracle Git unavailable")
    runner = _SUBPROCESS_RUN if run is None else run
    argv = [executable, "-C", str(repository), "-c", "core.fsmonitor=false"]
    path = relative if relative == COMMAND_CONTRACT else PACKAGE + "/" + relative
    selected = runner(
        argv + ["rev-parse", ORACLE_REVISION + ":" + path],
        env=environment, capture_output=True, timeout=30, check=True,
    ).stdout
    if selected != (oid + "\n").encode("ascii"):
        raise RuntimeError("historical oracle blob identity changed")
    raw = runner(
        argv + ["cat-file", "blob", oid], env=environment,
        capture_output=True, timeout=30, check=True,
    ).stdout
    if len(raw) > 1024 * 1024 or hashlib.sha256(raw).hexdigest() != expected:
        raise RuntimeError("historical oracle source authentication failed")
    if run is None:
        _ORACLE_BLOB_CACHE[key] = raw
    return raw


def oracle_source(name, repository=None, git="git", *, run=None):
    return oracle_blob(repository, name, git, run=run).decode("utf-8")


def _compile_oracle_code(
    relative, module_file, repository=None, git="git", *, source=None, run=None
):
    relative = _normalize_oracle_relative(relative)
    repository = (
        Path(__file__).resolve().parents[4]
        if repository is None
        else Path(repository).resolve()
    )
    key = (str(repository), str(git), relative, str(module_file))
    if source is None and run is None and key in _ORACLE_CODE_CACHE:
        return _ORACLE_CODE_CACHE[key]
    raw_source = (
        oracle_source(relative, repository, git, run=run)
        if source is None
        else source
    )
    tree = ast.parse(raw_source, filename=str(module_file))
    for index, node in enumerate(tree.body):
        if (
            isinstance(node, ast.Import)
            and len(node.names) == 1
            and node.names[0].name == "importlib.util"
            and node.names[0].asname is None
        ):
            tree.body[index] = ast.copy_location(ast.Pass(), node)
    if relative == "run.py":
        contract = oracle_source(COMMAND_CONTRACT, repository, git, run=run)
        assignments = [
            node for node in tree.body
            if isinstance(node, ast.Assign)
            and any(isinstance(name, ast.Name)
                    and name.id == "COMMAND_CONTRACT"
                    for name in node.targets)
        ]
        if len(assignments) != 1:
            raise RuntimeError("historical oracle protocol schema binding changed")
        assignments[0].value = ast.Call(
            func=ast.Attribute(value=ast.Name(id="json", ctx=ast.Load()),
                               attr="loads", ctx=ast.Load()),
            args=[ast.Constant(value=contract)], keywords=[],
        )
    ast.fix_missing_locations(tree)
    code = compile(tree, str(module_file), "exec")
    if source is None and run is None:
        _ORACLE_CODE_CACHE[key] = code
    return code


class _OracleSpecLoader(importlib.abc.Loader):
    def __init__(self, relative, origin, repository, git, run):
        self.relative = relative
        self.origin = str(origin)
        self.repository = repository
        self.git = git
        self.run = run

    def create_module(self, spec):
        return None

    def exec_module(self, module):
        module.__file__ = self.origin
        code = _compile_oracle_code(
            self.relative,
            self.origin,
            self.repository,
            self.git,
            run=self.run,
        )
        module.__dict__["importlib"] = _oracle_importlib(
            self.repository, self.git, self.run
        )
        exec(code, module.__dict__)


def _oracle_importlib(repository, git="git", run=None):
    def spec_from_file_location(name, location, *args, **kwargs):
        path = Path(location)
        if path.name in ORACLE_SOURCES and path.name.endswith(".py"):
            loader = _OracleSpecLoader(path.name, path, repository, git, run)
            return importlib.util.spec_from_loader(name, loader, origin=str(path))
        return importlib.util.spec_from_file_location(
            name, location, *args, **kwargs
        )

    util = types.SimpleNamespace(
        spec_from_file_location=spec_from_file_location,
        module_from_spec=importlib.util.module_from_spec,
        spec_from_loader=importlib.util.spec_from_loader,
    )
    return types.SimpleNamespace(util=util)


def load_oracle_module(
    name,
    repository=None,
    *,
    producer=None,
    source=None,
    git="git",
    run=None,
    module_name=None,
):
    relative = _normalize_oracle_relative(name)
    repository = (
        Path(__file__).resolve().parents[4]
        if repository is None
        else Path(repository).resolve()
    )
    target = repository if producer is None else Path(producer)
    module_file = str(target / PACKAGE / relative)
    module = types.ModuleType(module_name or relative.removesuffix(".py"))
    module.__file__ = module_file
    module.__dict__["importlib"] = _oracle_importlib(repository, git, run)
    code = _compile_oracle_code(
        relative, module_file, repository, git, source=source, run=run
    )
    exec(code, module.__dict__)
    return module


def run_oracle_cli(name="handoff", repository=None, git="git"):
    relative = _normalize_oracle_relative(name)
    repository = (
        Path(__file__).resolve().parents[4]
        if repository is None
        else Path(repository).resolve()
    )
    module_file = str(repository / PACKAGE / relative)
    sys.argv[0] = module_file
    module = types.ModuleType("__main__")
    module.__file__ = module_file
    module.__dict__["importlib"] = _oracle_importlib(repository, git, None)
    sys.modules["__main__"] = module
    code = _compile_oracle_code(relative, module_file, repository, git)
    exec(code, module.__dict__)


def git_blob(repository, git, relative):
    oid, expected = SOURCES[relative]
    environment = {
        "PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C",
        "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_TERMINAL_PROMPT": "0", "GIT_NO_REPLACE_OBJECTS": "1",
    }
    executable = shutil.which(str(git))
    if executable is None:
        raise RuntimeError("explicit historical fixture Git unavailable")
    argv = [executable, "-C", str(repository), "-c", "core.fsmonitor=false"]
    path = relative if relative == COMMAND_CONTRACT else PACKAGE + "/" + relative
    selected = subprocess.run(
        argv + ["rev-parse", REVISION + ":" + path],
        env=environment, capture_output=True, timeout=30, check=True,
    ).stdout
    if selected != (oid + "\n").encode("ascii"):
        raise RuntimeError("historical fixture blob identity changed")
    raw = subprocess.run(
        argv + ["cat-file", "blob", oid], env=environment,
        capture_output=True, timeout=30, check=True,
    ).stdout
    if len(raw) > 1024 * 1024 or hashlib.sha256(raw).hexdigest() != expected:
        raise RuntimeError("historical fixture source authentication failed")
    return raw


def load_controller(repository, git, producer=None):
    raw = git_blob(repository, git, "run.py")
    contract = git_blob(repository, git, COMMAND_CONTRACT).decode("utf-8")
    module = types.ModuleType("immutable_historical_controller")
    module.__file__ = str(Path(producer or repository) / PACKAGE / "run.py")
    tree = ast.parse(raw)
    assignments = [node for node in tree.body
                   if isinstance(node, ast.Assign)
                   and any(isinstance(name, ast.Name)
                           and name.id == "COMMAND_CONTRACT"
                           for name in node.targets)]
    if len(assignments) != 1:
        raise RuntimeError("historical protocol schema binding changed")
    # The older v1 checkouts predate this neutral protocol schema. Supply the
    # exact authenticated historical JSON, never a current filesystem oracle;
    # the controller's original schema checks and every function stay intact.
    assignments[0].value = ast.Call(
        func=ast.Attribute(value=ast.Name(id="json", ctx=ast.Load()),
                           attr="loads", ctx=ast.Load()),
        args=[ast.Constant(value=contract)], keywords=[])
    ast.fix_missing_locations(tree)
    exec(compile(tree, module.__file__, "exec"), module.__dict__)
    return module


def load_bindings(repository, git, controller, uid=None):
    raw = git_blob(repository, git, "tests/test_adapter.py")
    original = ast.parse(raw)
    evidence = next(node for node in original.body
                    if isinstance(node, ast.ClassDef)
                    and node.name == "Evidence")
    names = {"supervised_binding", "rehash_supervised_binding"}
    methods = [node for node in evidence.body
               if isinstance(node, ast.FunctionDef) and node.name in names]
    if {node.name for node in methods} != names:
        raise RuntimeError("historical fixture helpers missing")
    # Extract only authenticated neutral constructors, not the mixed test
    # module's current PUBLIC/handoff imports or its live qualification tests.
    evidence.bases = []
    evidence.decorator_list = []
    evidence.body = methods
    selected = ast.Module(body=[evidence], type_ignores=[])
    namespace = {
        "ci": controller, "copy": copy, "hashlib": hashlib, "stat": stat,
        "os": os if uid is None else types.SimpleNamespace(getuid=lambda: uid),
    }
    exec(compile(selected, REVISION + ":tests/test_adapter.py", "exec"),
         namespace)
    return namespace["Evidence"]()


def differences(original, changed):
    if isinstance(original, dict) and isinstance(changed, dict):
        if original.keys() != changed.keys():
            raise RuntimeError("historical fixture record schema changed")
        return {
            name: differences(value, changed[name])
            for name, value in original.items() if value != changed[name]
        }
    return changed


def frozen_fixture(repository, git):
    ci = load_controller(repository, git)
    evidence = load_bindings(repository, git, ci, uid=0)

    def neutral_binding(stage, profile=ci.CURRENT_PROFILE):
        record = evidence.supervised_binding(stage, profile)[0]

        def normalize(value):
            if isinstance(value, dict):
                if "content_sha256" in value:
                    # These are synthetic schema vectors, not physical pins.
                    # Keep the role digest while sharing neutral metadata.
                    value.update(inode=1, size=4097, ctime_nanoseconds=1,
                                 mtime_nanoseconds=1)
                else:
                    for member in value.values():
                        normalize(member)
            elif isinstance(value, list):
                for member in value:
                    normalize(member)

        normalize(record)
        evidence.rehash_supervised_binding(record)
        return record

    template = neutral_binding("adapter")
    value = {
        "scope": "synthetic_command_diagnostic_not_acceptance",
        "revision": REVISION,
        "sources": {
            name: {"blob": oid, "sha256": sha256}
            for name, (oid, sha256) in SOURCES.items()
        },
        "supervisor_sources": sorted(ci.SUPERVISOR_SOURCE_FILES),
        "handoff_contract": ci.production_command_contract("handoff-inspect"),
        "binding_template": template,
        "bindings": {
            stage: differences(template, neutral_binding(stage))
            for stage in STAGES
        },
        "legacy_binding": differences(
            template, neutral_binding(
                "handoff-inspect-legacy", profile="tiny-aot-two-boot")),
    }
    arrays = {}

    def intern(value):
        if isinstance(value, list) and len(value) > 5:
            key = hashlib.sha256(json.dumps(
                value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
            arrays[key] = value
            return {"fixture_array": key}
        if isinstance(value, dict):
            return {name: intern(member) for name, member in value.items()}
        return value

    value = intern(value)
    value["arrays"] = arrays
    return value


def frozen_bytes(repository, git):
    return (json.dumps(frozen_fixture(repository, git), sort_keys=True,
                       indent=2) + "\n").encode("ascii")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true", required=True)
    parser.add_argument("--git", default="git")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[4]
    target = root / PACKAGE / "controller/fixtures/historical_controller.json"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(frozen_bytes(root, args.git))
