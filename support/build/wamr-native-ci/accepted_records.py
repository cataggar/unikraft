# SPDX-License-Identifier: BSD-3-Clause
"""Bounded, fail-closed transport for native records and imported identity."""
import json
import os
from pathlib import Path
import re
import selectors
import signal
import stat
import subprocess
import time


HERE = Path(__file__).resolve().parent
MAX_RECORDS_BYTES = 2 * 1024 * 1024
RECORDS_TIMEOUT_SECONDS = 600
VALIDATOR_BUILD_TIMEOUT_SECONDS = 2100
IMPORT_NATIVE_REVALIDATION_TIMEOUT_SECONDS = VALIDATOR_BUILD_TIMEOUT_SECONDS
CONTROLLER_ENV = "WAMR_CI_CONTROLLER"


def _refuse(reason="native controller records refused"):
    raise ValueError(reason)


def _absolute(path):
    path = Path(path)
    if (not path.is_absolute() or os.path.normpath(str(path)) != str(path)
            or path.resolve(strict=True) != path):
        _refuse()
    return path


def _controller():
    # The caller must separately authenticate this executable; ownership and
    # permissions only rule out obvious unsafe paths, not a substituted binary.
    raw = os.environ.get(CONTROLLER_ENV)
    if not raw:
        _refuse()
    path = _absolute(raw)
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
            or info.st_uid not in (0, os.geteuid())
            or info.st_mode & 0o022 or not info.st_mode & 0o111):
        _refuse()
    return path


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            _refuse()
        result[key] = value
    return result


def _digest(value, length):
    return type(value) is str and re.fullmatch(
        rf"[0-9a-f]{{{length}}}", value) is not None


def _entry(value, fields):
    return type(value) is dict and set(value) == set(fields)


def _decode(raw, context):
    if not raw or len(raw) > MAX_RECORDS_BYTES:
        _refuse()
    try:
        value = json.loads(raw, object_pairs_hook=_unique)
        canonical = (json.dumps(
            value, ensure_ascii=False, allow_nan=False, sort_keys=True,
            separators=(",", ":")) + "\n").encode("utf-8")
    except (TypeError, ValueError, UnicodeError):
        _refuse()
    if raw != canonical or not _entry(value, (
            "schema", "schema_version", "context", "compatibility", "profile",
            "source", "modes", "result", "records", "artifacts",
            "runtime_inputs")):
        _refuse()
    if (value["schema"] != "uk.wamr.native-ci-controller-records"
            or type(value["schema_version"]) is not int
            or value["schema_version"] != 1
            or value["context"] != context
            or not _entry(value["source"], ("revision", "tree"))
            or not all(_digest(item, 40) for item in value["source"].values())):
        _refuse()
    if value["compatibility"] == "tiny-v2":
        if value["profile"] != "qcow2-derived-vhd":
            _refuse()
    elif value["compatibility"] != "tiny-v1" or value["profile"] is not None:
        _refuse()
    if (type(value["modes"]) is not list or not value["modes"]
            or type(value["records"]) is not list
            or not 1 <= len(value["records"]) <= 64
            or type(value["artifacts"]) is not list
            or not 1 <= len(value["artifacts"]) <= 64
            or type(value["runtime_inputs"]) is not list
            or len(value["runtime_inputs"]) > 512
            or (context == "trusted-inner-zip" and value["runtime_inputs"])):
        _refuse()
    result = value["result"]
    if (not _entry(result, ("relative_path", "bytes", "sha256"))
            or result["relative_path"] != (
                "runtime/compute/evidence/result.json"
                if context == "local-runtime" else "artifacts/local_result")
            or type(result["bytes"]) is not int or result["bytes"] < 1
            or not _digest(result["sha256"], 64)):
        _refuse()
    names = set()
    for record in value["records"]:
        if (not _entry(record, ("name", "relative_path", "bytes", "sha256"))
                or type(record["name"]) is not str
                or Path(record["name"]).name != record["name"]
                or not record["name"].endswith(".json")
                or record["name"] in names
                or record["relative_path"] != (
                    ("runtime/compute/evidence/" if context == "local-runtime"
                     else "evidence/") + record["name"])
                or not _digest(record["sha256"], 64)
                or type(record["bytes"]) is not int
                or record["bytes"] < 1):
            _refuse()
        names.add(record["name"])
    for artifact in value["artifacts"]:
        if (not _entry(artifact, (
                "role", "relative_path", "bytes", "sha256", "snapshot"))
                or type(artifact["role"]) is not str or not artifact["role"]
                or type(artifact["relative_path"]) is not str
                or not artifact["relative_path"]
                or type(artifact["bytes"]) is not int or artifact["bytes"] < 1
                or not _digest(artifact["sha256"], 64)
                or type(artifact["snapshot"]) is not list
                or len(artifact["snapshot"]) != 9
                or any(type(item) is not int for item in artifact["snapshot"])):
            _refuse()
    for item in value["runtime_inputs"]:
        if (not _entry(item, ("role", "path", "snapshot"))
                or type(item["role"]) is not str or not item["role"]
                or type(item["path"]) is not str
                or not item["path"].startswith("/")
                or not _entry(item["snapshot"], (
                    "bytes", "sha256", "metadata", "tree"))):
            _refuse()
        snapshot = item["snapshot"]
        if (type(snapshot["bytes"]) is not int or snapshot["bytes"] < 0
                or not _digest(snapshot["sha256"], 64)
                or type(snapshot["metadata"]) is not list
                or len(snapshot["metadata"]) != 9
                or any(type(part) is not int for part in snapshot["metadata"])):
            _refuse()
        if snapshot["tree"] is not None:
            tree = snapshot["tree"]
            if (not _entry(tree, (
                    "files", "directories", "symlinks", "physical_sha256"))
                    or any(type(tree[key]) is not int or tree[key] < 0
                           for key in ("files", "directories", "symlinks"))
                    or not _digest(tree["physical_sha256"], 64)):
                _refuse()
    return value


def _controller_command(arguments, refusal, timeout_seconds=None):
    try:
        controller = _controller()
        if timeout_seconds is None:
            timeout_seconds = RECORDS_TIMEOUT_SECONDS
        deadline = time.monotonic() + timeout_seconds
        process = subprocess.Popen(
            [str(controller), *arguments],
            cwd=HERE.parents[2], stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            start_new_session=True)
        accepted = False
        try:
            output = []
            total = 0
            stderr_seen = False
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ)
                selector.register(process.stderr, selectors.EVENT_READ)
                while selector.get_map():
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        _refuse(refusal)
                    ready = selector.select(remaining)
                    if not ready:
                        _refuse(refusal)
                    for key, unused_events in ready:
                        chunk = os.read(
                            key.fileobj.fileno(),
                            min(65536, MAX_RECORDS_BYTES + 1 - total))
                        if not chunk:
                            selector.unregister(key.fileobj)
                            continue
                        total += len(chunk)
                        if total > MAX_RECORDS_BYTES:
                            _refuse(refusal)
                        if key.fileobj is process.stdout:
                            output.append(chunk)
                        else:
                            stderr_seen = True
            remaining = deadline - time.monotonic()
            if remaining <= 0 or process.wait(timeout=remaining) != 0:
                _refuse(refusal)
            accepted = True
            return b"".join(output), stderr_seen
        finally:
            if not accepted and process.returncode is None:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            if process.poll() is None:
                process.kill()
            try:
                process.wait(timeout=5)
            finally:
                process.stdout.close()
                process.stderr.close()
    except (OSError, subprocess.SubprocessError) as error:
        raise ValueError(refusal) from error


def _records(context, arguments):
    raw, unused_stderr = _controller_command(
        ("records", *arguments, "--output", "handoff-v1"),
        "native controller records refused")
    return _decode(raw, context)


def _completed_output(output, stage, log_bound, refusal):
    try:
        output = _absolute(output)
        for path in (output, output / "private", output / "evidence"):
            info = path.lstat()
            if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid()
                    or stat.S_IMODE(info.st_mode) != 0o700):
                _refuse(refusal)
        for path, bound in (
                (output / f"private/{stage}.log", log_bound),
                (output / f"evidence/command-{stage}.json",
                 MAX_RECORDS_BYTES)):
            minimum = 0 if path.name.endswith(".log") else 1
            info = path.lstat()
            if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                    or info.st_uid != os.geteuid()
                    or stat.S_IMODE(info.st_mode) != 0o600
                    or not minimum <= info.st_size <= bound):
                _refuse(refusal)
    except OSError as error:
        raise ValueError(refusal) from error
    return output


def _runtime_output(
        runtime, output, command, stage, log_bound, refusal,
        timeout_seconds=None):
    runtime, output = map(Path, (runtime, output))
    try:
        runtime = _absolute(runtime)
        _absolute(output.parent)
    except (OSError, ValueError) as error:
        raise ValueError(refusal) from error
    if (not output.is_absolute()
            or os.path.normpath(str(output)) != str(output)
            or os.path.lexists(output)):
        _refuse(refusal)
    raw, stderr_seen = _controller_command((
        command, "--runtime", str(runtime), "--output", str(output)), refusal,
        timeout_seconds=timeout_seconds)
    if raw or stderr_seen:
        _refuse(refusal)
    return _completed_output(output, stage, log_bound, refusal)


def imported_stage(stage_root):
    """Ask the native importer to validate the exact extracted inner tree."""
    stage_root = _absolute(stage_root)
    return _records("trusted-inner-zip", (
        "--stage-root", str(stage_root), "--transport", "trusted-inner-zip"))


def supervisor_import_identity(stage_root, supervisor, git, output):
    """Prove the supplied supervisor against a pristine trusted v2 stage."""
    stage_root, supervisor, git, output = map(
        Path, (stage_root, supervisor, git, output))
    refusal = "native controller import identity refused"
    try:
        stage_root = _absolute(stage_root)
        supervisor = _absolute(supervisor)
        git = _absolute(git)
        _absolute(output.parent)
    except (OSError, ValueError) as error:
        raise ValueError(refusal) from error
    if (not output.is_absolute()
            or os.path.normpath(str(output)) != str(output)
            or os.path.lexists(output)):
        _refuse(refusal)
    raw, stderr_seen = _controller_command((
        "supervisor-import-identity",
        "--stage-root", str(stage_root), "--supervisor", str(supervisor),
        "--git", str(git), "--output", str(output)), refusal)
    if raw or stderr_seen:
        _refuse(refusal)
    try:
        for path in (output, output / "private", output / "evidence"):
            info = path.lstat()
            if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid()
                    or stat.S_IMODE(info.st_mode) != 0o700):
                _refuse(refusal)
        for path, bound in (
                (output / "private/supervisor-import-identity.log", 1024),
                (output / "evidence/command-supervisor-import-identity.json",
                 MAX_RECORDS_BYTES)):
            info = path.lstat()
            if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                    or info.st_uid != os.geteuid()
                    or stat.S_IMODE(info.st_mode) != 0o600
                    or not 0 < info.st_size <= bound):
                _refuse(refusal)
    except OSError as error:
        raise ValueError(refusal) from error
    return output


def handoff_inspect(runtime, output, *, legacy=False):
    """Run the native owner for the local handoff inspection stage."""
    runtime, output = map(Path, (runtime, output))
    refusal = "native controller handoff inspect refused"
    try:
        runtime = _absolute(runtime)
        _absolute(output.parent)
    except (OSError, ValueError) as error:
        raise ValueError(refusal) from error
    if (not output.is_absolute()
            or os.path.normpath(str(output)) != str(output)
            or os.path.lexists(output)):
        _refuse(refusal)
    action = "handoff-inspect-legacy" if legacy else "handoff-inspect"
    log_name = action + ".log"
    record_name = "command-" + action + ".json"
    raw, stderr_seen = _controller_command((
        action, "--runtime", str(runtime),
        "--output", str(output)), refusal)
    if raw or stderr_seen:
        _refuse(refusal)
    try:
        for path in (output, output / "private", output / "evidence"):
            info = path.lstat()
            if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid()
                    or stat.S_IMODE(info.st_mode) != 0o700):
                _refuse(refusal)
        for path, bound in (
                (output / "private" / log_name, 64 * 1024),
                (output / "evidence" / record_name, MAX_RECORDS_BYTES)):
            info = path.lstat()
            if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                    or info.st_uid != os.geteuid()
                    or stat.S_IMODE(info.st_mode) != 0o600
                    or not 0 < info.st_size <= bound):
                _refuse(refusal)
    except OSError as error:
        raise ValueError(refusal) from error
    return output / "private" / log_name, output / "evidence" / record_name


def local_consumer_custody(
        runtime, expected_build_start_sha256, expected_boot_inputs_sha256):
    """Recapture the pinned local v2 source and consumer custody natively."""
    runtime = _absolute(runtime)
    refusal = "native controller local consumer custody refused"
    if (not _digest(expected_build_start_sha256, 64)
            or not _digest(expected_boot_inputs_sha256, 64)):
        _refuse(refusal)
    raw, stderr_seen = _controller_command((
        "local-consumer-custody", "--runtime", str(runtime),
        "--expected-build-start-sha256", expected_build_start_sha256,
        "--expected-boot-inputs-sha256", expected_boot_inputs_sha256),
        refusal)
    if raw or stderr_seen:
        _refuse(refusal)


def import_native_revalidation(stage_root, output):
    """Build and run the fixed native validator for a pristine trusted v2 stage."""
    stage_root, output = map(Path, (stage_root, output))
    refusal = "native controller import revalidation refused"
    try:
        stage_root = _absolute(stage_root)
        _absolute(output.parent)
    except (OSError, ValueError) as error:
        raise ValueError(refusal) from error
    if (not output.is_absolute()
            or os.path.normpath(str(output)) != str(output)
            or os.path.lexists(output)):
        _refuse(refusal)
    raw, stderr_seen = _controller_command((
        "import-native-revalidation",
        "--stage-root", str(stage_root), "--output", str(output)), refusal,
        timeout_seconds=IMPORT_NATIVE_REVALIDATION_TIMEOUT_SECONDS)
    if raw or stderr_seen:
        _refuse(refusal)
    try:
        for path in (output, output / "private", output / "evidence"):
            info = path.lstat()
            if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid()
                    or stat.S_IMODE(info.st_mode) != 0o700):
                _refuse(refusal)
        for path, bound in (
                (output / "private/import-native-revalidation.log", 4096),
                (output / "evidence/command-import-native-revalidation.json",
                 MAX_RECORDS_BYTES)):
            info = path.lstat()
            if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                    or info.st_uid != os.geteuid()
                    or stat.S_IMODE(info.st_mode) != 0o600
                    or not 0 < info.st_size <= bound):
                _refuse(refusal)
        if (output / "private/import-native-revalidation.log").read_bytes() != (
                b"Compute handoff revalidated; authority=not_admitted.\n"):
            _refuse(refusal)
    except OSError as error:
        raise ValueError(refusal) from error
    return output


def local_runtime(runtime):
    """Local handoff requires native v2; historical v1 is import-only."""
    runtime = _absolute(runtime)
    value = _records("local-runtime", ("--runtime", str(runtime)))
    if value["compatibility"] == "tiny-v1":
        raise ValueError("local v1 handoff/export unsupported until native acceptance")
    if value["compatibility"] != "tiny-v2" or not value["runtime_inputs"]:
        _refuse()
    return value


def public_validator_build(runtime, output):
    """Build the public validator for a native-produced run without fallback."""
    return _runtime_output(
        runtime, output, "public-validator-build", "public-validator-build",
        8 * 1024 * 1024 + 1, "native public validator build refused",
        timeout_seconds=VALIDATOR_BUILD_TIMEOUT_SECONDS)


def local_handoff_revalidation(runtime, output):
    """Supervise the fixed native-produced handoff without a Python fallback."""
    return _runtime_output(
        runtime, output, "local-handoff-revalidation",
        "import-native-revalidation", 4097,
        "native local handoff revalidation refused",
        timeout_seconds=900)
