# SPDX-License-Identifier: BSD-3-Clause
"""Test-only, pinned consumer owner for retained direct/public fixtures."""

import argparse
import contextlib
import hashlib
import importlib.util
import json
import os
import re
import shutil
import stat
import subprocess
import sys
from pathlib import Path

COMMIT = "3599c9a5602f037e9d6c8113067b77b2451cccee"
TREE = "d5292215bf661afaf3bc018b2a44db8cc8521987"
CI = Path("support/build/wamr-native-ci")
SCHEMA = "uk.wamr.historical-fixture-owner"
CHECKOUT = "unikraft"
STAGE_TIMEOUT = 900
STDOUT_LIMIT = 4096
STDERR_LIMIT = 8 * 1024 * 1024


def require(condition, reason):
    if not condition:
        raise ValueError("historical fixture owner refused: " + reason)


def canonical(path):
    path = Path(path)
    require(
        path.is_absolute() and path.resolve(strict=True) == path,
        "canonical existing path required",
    )
    return path


def private(path):
    path = canonical(path)
    info = path.lstat()
    require(
        stat.S_ISDIR(info.st_mode)
        and info.st_uid == os.getuid()
        and stat.S_IMODE(info.st_mode) == 0o700,
        "private directory required",
    )
    for parent in path.parents:
        info = parent.lstat()
        require(
            info.st_uid in (0, os.getuid()) and not info.st_mode & 0o022,
            "unsafe ancestor",
        )
    return path


def metadata(info):
    return [
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_uid,
        info.st_gid,
        info.st_nlink,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    ]


@contextlib.contextmanager
def bound_file(path, executable=False):
    path = canonical(path)
    descriptors = []
    directories = []
    try:
        parent = None
        for directory in (*reversed(path.parents), path):
            last = directory == path
            flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
            flags |= os.O_NONBLOCK if last else os.O_DIRECTORY
            descriptor = os.open(
                str(directory) if parent is None else directory.name,
                flags,
                dir_fd=parent,
            )
            descriptors.append(descriptor)
            info = os.fstat(descriptor)
            require(
                info.st_uid in (0, os.getuid()) and not info.st_mode & 0o022,
                "unsafe file" if last else "unsafe executable ancestor",
            )
            if last:
                require(stat.S_ISREG(info.st_mode), "unsafe file")
                require(
                    not executable or info.st_mode & 0o111,
                    "executable required",
                )
                original = metadata(info)
            else:
                require(stat.S_ISDIR(info.st_mode), "unsafe ancestor")
                # Child creation legitimately changes directory timestamps.
                directories.append(
                    {"path": str(directory), "metadata": metadata(info)[:5]}
                )
            parent = descriptor
        digest = hashlib.sha256()
        offset = 0
        while offset < info.st_size:
            chunk = os.pread(
                descriptor, min(65536, info.st_size - offset), offset
            )
            require(chunk, "file changed during authentication")
            digest.update(chunk)
            offset += len(chunk)
        require(
            not os.pread(descriptor, 1, offset)
            and metadata(os.fstat(descriptor)) == original,
            "file changed during authentication",
        )
        result = {
            "path": str(path),
            "bytes": info.st_size,
            "sha256": digest.hexdigest(),
            "metadata": original,
        }
        if executable:
            result["ancestors"] = directories

        def revalidate():
            for index, saved in enumerate(directories):
                current = Path(saved["path"])
                named = os.stat(
                    str(current) if index == 0 else current.name,
                    dir_fd=None if index == 0 else descriptors[index - 1],
                    follow_symlinks=False,
                )
                require(
                    metadata(named)[:5] == saved["metadata"]
                    and metadata(os.fstat(descriptors[index]))[:5]
                    == saved["metadata"],
                    "executable ancestor binding changed",
                )
            require(
                metadata(os.fstat(descriptor)) == original
                and metadata(
                    os.stat(
                        path.name,
                        dir_fd=descriptors[-2],
                        follow_symlinks=False,
                    )
                )
                == original,
                "file binding changed",
            )

        revalidate()
        try:
            yield descriptor, result
        finally:
            revalidate()
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def file_record(path, executable=False):
    with bound_file(path, executable) as (_, result):
        return result


def supervisor_record(path):
    result = file_record(path, executable=True)
    require(result["bytes"] <= 16 * 1024 * 1024, "oversized supervisor")
    with path.open("rb") as stream:
        header = stream.read(20)
    require(
        len(header) == 20
        and header[:6] == b"\x7fELF\x02\x01"
        and int.from_bytes(header[16:18], "little") in (2, 3)
        and int.from_bytes(header[18:20], "little") in (62, 183),
        "native historical supervisor required",
    )
    return result


def git_environment():
    return {
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_SYSTEM": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_TERMINAL_PROMPT": "0",
        "HOME": "/",
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin",
    }


def git_command(git, *args):
    return [
        str(git),
        "--no-pager",
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        "core.fsmonitor=false",
        "-c",
        "credential.helper=",
        "-c",
        "gc.auto=0",
        "-c",
        "maintenance.auto=false",
        *map(str, args),
    ]


def git_output(git, repository, *args):
    result = command_output(
        git_command(git, *args),
        repository,
        {
            **git_environment(),
            "GIT_CEILING_DIRECTORIES": str(repository.parent),
        },
        120,
        4 * 1024 * 1024,
        STDERR_LIMIT,
    )
    return result.stdout


def materialize(repository, owner, git):
    repository = canonical(repository)
    require(
        not owner.exists() and not owner.is_symlink(),
        "checkout must be create-only",
    )
    require(
        git_output(git, repository, "rev-parse", COMMIT + "^{tree}")
        == (TREE + "\n").encode(),
        "missing or wrong pinned tree",
    )
    owner.mkdir(mode=0o700)
    # A local, non-hardlinked clone retains producer history for old archives,
    # but never borrows that producer's checkout as the consumer owner.
    git_output(
        git,
        repository,
        "clone",
        "--local",
        "--no-hardlinks",
        "--no-checkout",
        "--no-recurse-submodules",
        "--",
        repository,
        owner,
    )
    git_output(git, owner, "checkout", "--detach", "--force", COMMIT)
    verify_checkout(owner, git)


def verify_checkout(owner, git):
    owner = private(owner)
    require(
        (owner / ".git").is_dir() and not (owner / ".git").is_symlink(),
        "independent Git required",
    )
    canonical(owner / ".git/objects")
    for relative in ("objects/info/alternates", "info/grafts"):
        path = owner / ".git" / relative
        require(
            not path.exists() and not path.is_symlink(),
            "borrowed or rewritten history forbidden",
        )
    require(
        git_output(git, owner, "rev-parse", "HEAD") == (COMMIT + "\n").encode(),
        "wrong owner commit",
    )
    require(
        git_output(git, owner, "rev-parse", "HEAD^{tree}")
        == (TREE + "\n").encode(),
        "wrong owner tree",
    )
    git_output(
        git, owner, "fsck", "--strict", "--no-reflogs", "--no-dangling", COMMIT
    )
    tracked = set()
    directories = {Path(".")}
    for entry in git_output(git, owner, "ls-tree", "-rz", COMMIT).split(b"\0"):
        if not entry:
            continue
        header, raw_name = entry.split(b"\t", 1)
        mode, kind, blob = header.split()
        relative = Path(os.fsdecode(raw_name))
        require(
            not relative.is_absolute()
            and ".." not in relative.parts
            and kind == b"blob",
            "unsupported historical entry",
        )
        path = owner / relative
        info = path.lstat()
        require(info.st_uid == os.getuid(), "wrong source owner")
        if mode == b"120000":
            require(stat.S_ISLNK(info.st_mode), "missing historical symlink")
            data = os.fsencode(os.readlink(path))
        else:
            require(
                mode in (b"100644", b"100755")
                and stat.S_ISREG(info.st_mode)
                and info.st_nlink == 1
                and not info.st_mode & 0o022
                and bool(info.st_mode & 0o111) == (mode == b"100755"),
                "wrong source file mode",
            )
            data = path.read_bytes()
        actual = hashlib.sha1(
            b"blob " + str(len(data)).encode() + b"\0" + data
        ).hexdigest()
        require(actual.encode() == blob, "mutated owner blob")
        tracked.add(relative)
        directories.update(relative.parents)
    actual_files = set()
    for current, children, files in os.walk(owner, followlinks=False):
        current = Path(current)
        if current == owner:
            children.remove(".git")
        relative = current.relative_to(owner)
        info = current.lstat()
        require(
            relative in directories
            and info.st_uid == os.getuid()
            and not info.st_mode & 0o022,
            "unexpected source directory: " + str(relative),
        )
        for name in children[:]:
            if (current / name).is_symlink():
                files.append(name)
                children.remove(name)
        actual_files.update(relative / name for name in files)
    require(actual_files == tracked, "missing or extra owner source")


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


bounded_process = module(
    "historical_fixture_bounded_process",
    Path(__file__).with_name("bounded_process.py"),
)


def modules(owner, git):
    verify_checkout(owner, git)
    previous = sys.dont_write_bytecode
    try:
        sys.dont_write_bytecode = True
        handoff = module(
            "historical_fixture_handoff", owner / CI / "handoff.py"
        )
        public = module(
            "historical_fixture_public", owner / CI / "public_bundle.py"
        )
    finally:
        sys.dont_write_bytecode = previous
    handoff.ci.COMMAND_TOOL_PATHS["git"] = str(git)
    require(handoff.ci.REPO == owner, "consumer import escaped owner")
    return handoff, public


def identity(closure):
    return {
        "protocol": "uk.wamr.command-supervisor/1 process-command/1",
        "schema": "uk.wamr.command-supervisor-identity",
        "source_content_closure_sha256": closure,
        "version": 1,
    }


def exact_identity(value, expected):
    return (
        type(value) is dict
        and type(value.get("version")) is int
        and value == expected
    )


def write_json(path, value):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(
            (
                json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n"
            ).encode()
        )


def check_capture(result):
    require(
        result["failure"] is None
        and not result["overflow"]
        and not result["timeout"]
        and result["cleanup"]["complete"]
        and not result["cleanup"]["failures"],
        (result["failure"] or "capture cleanup failed")
        + "; cleanup="
        + json.dumps(result["cleanup"], sort_keys=True),
    )


def command_output(
    command, cwd, environment, seconds, stdout_limit, stderr_limit
):
    with bound_file(command[0], executable=True) as (descriptor, _):
        result = bounded_process.execute(
            command,
            cwd,
            environment,
            descriptor,
            seconds,
            stdout_limit,
            stderr_limit,
        )
    check_capture(result)
    completed = subprocess.CompletedProcess(
        command, result["returncode"], result["stdout"], result["stderr"]
    )
    completed.check_returncode()
    return completed


def capture_file(path):
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
        0o600,
    )
    return os.fdopen(descriptor, "wb")


def run_stage(root, stage, command, cwd, environment):
    root = private(root)
    require(re.fullmatch("[a-z][a-z0-9-]*", stage), "invalid stage")
    receipt = root / (stage + ".capture.json")
    require(not receipt.exists() and not receipt.is_symlink(), "capture reuse")
    result = None
    started = False
    try:
        with bound_file(command[0], executable=True) as (
            descriptor,
            _,
        ), capture_file(root / (stage + ".stdout")) as out, capture_file(
            root / (stage + ".stderr")
        ) as err:
            started = True
            result = bounded_process.execute(
                command,
                cwd,
                environment,
                descriptor,
                STAGE_TIMEOUT,
                STDOUT_LIMIT,
                STDERR_LIMIT,
                out,
                err,
            )
    except BaseException as error:
        if result is None and started:
            result = {
                "returncode": None,
                "cleanup": {
                    "complete": False,
                    "failures": [{"operation": "capture", "error": str(error)}],
                    "processes": [],
                },
            }
        if result is not None:
            result["failure"] = str(error)
            write_json(receipt, result)
        raise
    write_json(receipt, result)
    check_capture(result)
    require(result["returncode"] == 0, stage + " failed; retained diagnostic")
    return (root / (stage + ".stdout")).read_bytes()


def prepare(repository, root, git, zig, packages):
    repository = canonical(repository)
    root = Path(root)
    private(root.parent)
    require(
        root.is_absolute()
        and root.parent / root.name == root
        and root.name not in ("", ".", "..")
        and not root.is_relative_to(repository),
        "external create-only fixture root required",
    )
    tools = {
        name: file_record(path, executable=True)
        for name, path in (("git", git), ("zig", zig))
    }
    packages = canonical(packages)
    require(
        packages.is_dir() and not packages.is_relative_to(repository),
        "external restored packages required",
    )
    root.mkdir(mode=0o700)
    owner = root / CHECKOUT
    stage = "materialize"
    try:
        write_json(
            root / "inputs.json",
            {
                "commit": COMMIT,
                "tree": TREE,
                "tools": tools,
                "repository": str(repository),
                "packages": str(packages),
            },
        )
        materialize(repository, owner, git)
        for name in (
            "home",
            "tmp",
            "global",
            "controller-cache",
            "supervisor-cache",
            "supervisor",
        ):
            (root / name).mkdir(mode=0o700)
        environment = {
            **git_environment(),
            "HOME": str(root / "home"),
            "TMPDIR": str(root / "tmp"),
            "PYTHONDONTWRITEBYTECODE": "1",
            "PATH": str(Path(git).parent) + ":/usr/bin:/bin",
        }
        common = [
            zig,
            "build",
            "--system",
            packages,
            "--global-cache-dir",
            root / "global",
            "-Doptimize=ReleaseSafe",
            "-j1",
        ]
        stage = "closure"
        for name, path in (("git", git), ("zig", zig)):
            require(
                file_record(path, True) == tools[name], "build tool changed"
            )
        raw = run_stage(
            root,
            stage,
            [
                *common,
                "--build-file",
                owner / CI / "build.zig",
                "--cache-dir",
                root / "controller-cache",
                "--prefix",
                root / "controller-tools",
                "run-controller-fixture",
                "--",
                "supervisor-source-closure",
                "--git",
                git,
                "--output",
                "sha256-v1",
            ],
            owner,
            environment,
        )
        require(re.fullmatch(b"[0-9a-f]{64}\n", raw), "invalid old closure")
        closure = raw[:-1].decode("ascii")
        handoff, _ = modules(owner, git)
        require(
            handoff.ci.supervisor_source_map()["content_closure_sha256"]
            == closure,
            "historical consumer/closure mismatch",
        )
        stage = "supervisor"
        for name, path in (("git", git), ("zig", zig)):
            require(
                file_record(path, True) == tools[name], "build tool changed"
            )
        run_stage(
            root,
            stage,
            [
                *common,
                "--build-file",
                owner / CI / "supervisor.build.zig",
                "--cache-dir",
                root / "supervisor-cache",
                "--prefix",
                root / "supervisor",
                "-Dsource-closure-sha256=" + closure,
            ],
            owner,
            environment,
        )
        supervisor = root / "supervisor/bin/wamr-ci-supervisor"
        stage = "identity"
        for name, path in (("git", git), ("zig", zig)):
            require(
                file_record(path, True) == tools[name], "build tool changed"
            )
        raw = run_stage(root, stage, [supervisor, "--identity"], owner, {})
        require(
            exact_identity(json.loads(raw), identity(closure)),
            "wrong historical supervisor identity",
        )
        verify_checkout(owner, git)
        for name, path in (("git", git), ("zig", zig)):
            require(
                file_record(path, executable=True) == tools[name],
                "build tool changed",
            )
        write_json(
            root / "result.json",
            {
                "schema": SCHEMA,
                "version": 1,
                "status": "ready",
                "commit": COMMIT,
                "tree": TREE,
                "tools": tools,
                "identity": identity(closure),
                "supervisor": supervisor_record(supervisor),
            },
        )
    except BaseException as error:
        # Only this invocation's exclusive checkout is removed. Keep immutable
        # inputs and stage diagnostics; a failed root is never reusable.
        if owner.is_dir() and not owner.is_symlink():
            shutil.rmtree(owner)
        write_json(
            root / "result.json",
            {
                "schema": SCHEMA,
                "version": 1,
                "status": "failed",
                "failure": str(error),
                "stage": stage,
                "commit": COMMIT,
                "tree": TREE,
            },
        )
        raise


def load(root=None):
    if root is None:
        require(
            "WAMR_HISTORICAL_FIXTURE_ROOT" in os.environ,
            "explicit historical fixture root required",
        )
        root = os.environ["WAMR_HISTORICAL_FIXTURE_ROOT"]
    root = private(root)
    result_path = root / "result.json"
    file_record(result_path)
    require(result_path.stat().st_size <= 16384, "oversized result")
    result = json.loads(result_path.read_bytes())
    require(
        result["schema"] == SCHEMA
        and type(result["version"]) is int
        and result["version"] == 1
        and result["status"] == "ready"
        and result["commit"] == COMMIT
        and result["tree"] == TREE,
        "incomplete or wrong owner result",
    )
    git = Path(result["tools"]["git"]["path"])
    require(
        file_record(git, executable=True) == result["tools"]["git"],
        "retained Git changed",
    )
    handoff, public = modules(root / CHECKOUT, git)
    closure = handoff.ci.supervisor_source_map()["content_closure_sha256"]
    require(
        exact_identity(result["identity"], identity(closure)),
        "wrong closure identity",
    )
    supervisor = root / "supervisor/bin/wamr-ci-supervisor"
    require(
        supervisor_record(supervisor) == result["supervisor"],
        "supervisor executable changed",
    )
    completed = command_output(
        [supervisor, "--identity"], None, {}, 30, 1024, 1024
    )
    require(
        len(completed.stdout) <= 1024
        and not completed.stderr
        and exact_identity(json.loads(completed.stdout), result["identity"]),
        "wrong supervisor identity",
    )
    require(
        supervisor_record(supervisor) == result["supervisor"],
        "supervisor changed during identity query",
    )
    return handoff, public, supervisor


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("repository", "root", "git", "zig", "packages"):
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    os.umask(0o077)
    prepare(**vars(args))
    load(args.root)


if __name__ == "__main__":
    main()
