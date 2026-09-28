# SPDX-License-Identifier: BSD-3-Clause
"""Bounded, fail-closed transport for the native accepted-run records."""
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
CONTROLLER_ENV = "WAMR_CI_CONTROLLER"


def _refuse():
    raise ValueError("native controller records refused")


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
            or type(value["records"]) is not list or not value["records"]
            or type(value["artifacts"]) is not list or not value["artifacts"]
            or type(value["runtime_inputs"]) is not list
            or (context == "trusted-inner-zip" and value["runtime_inputs"])):
        _refuse()
    if not _entry(value["result"], ("relative_path", "bytes", "sha256")):
        _refuse()
    for record in value["records"]:
        if (not _entry(record, ("name", "relative_path", "bytes", "sha256"))
                or not _digest(record["sha256"], 64)
                or type(record["bytes"]) is not int
                or record["bytes"] < 1):
            _refuse()
    return value


def imported_stage(stage_root):
    """Ask the native importer to validate the exact extracted inner tree."""
    try:
        stage_root = _absolute(stage_root)
        controller = _controller()
        deadline = time.monotonic() + RECORDS_TIMEOUT_SECONDS
        process = subprocess.Popen(
            [str(controller), "records", "--stage-root", str(stage_root),
             "--transport", "trusted-inner-zip", "--output", "handoff-v1"],
            cwd=HERE.parents[2], stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            start_new_session=True)
        accepted = False
        try:
            output = []
            total = 0
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ)
                selector.register(process.stderr, selectors.EVENT_READ)
                while selector.get_map():
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        _refuse()
                    ready = selector.select(remaining)
                    if not ready:
                        _refuse()
                    for key, unused_events in ready:
                        chunk = os.read(
                            key.fileobj.fileno(),
                            min(65536, MAX_RECORDS_BYTES + 1 - total))
                        if not chunk:
                            selector.unregister(key.fileobj)
                            continue
                        total += len(chunk)
                        if total > MAX_RECORDS_BYTES:
                            _refuse()
                        if key.fileobj is process.stdout:
                            output.append(chunk)
            remaining = deadline - time.monotonic()
            if remaining <= 0 or process.wait(timeout=remaining) != 0:
                _refuse()
            result = _decode(b"".join(output), "trusted-inner-zip")
            accepted = True
            return result
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
        raise ValueError("native controller records refused") from error
