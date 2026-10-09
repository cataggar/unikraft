#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""TEST ONLY: bounded stagewise handoff witness. Never an acceptance/cutover gate."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import stat
import sys
import time
from dataclasses import dataclass

MAX_FILE = 2 * 1024 * 1024 * 1024
MAX_CUSTODY_BYTES = 8 * 1024 * 1024 * 1024
MAX_ENTRIES = 65536
MAX_RECORD = 2 * 1024 * 1024
MAX_LOG = 8 * 1024 * 1024
TIMEOUT = 2400
HERE = Path(__file__).resolve().parent
BOUNDED_PROCESS_PATH = HERE.parents[3] / "support/tools/hyperv/direct/tests/bounded_process.py"
_bounded_spec = importlib.util.spec_from_file_location("wamr_shadow_bounded_process", BOUNDED_PROCESS_PATH)
bounded_process = importlib.util.module_from_spec(_bounded_spec)
_bounded_spec.loader.exec_module(bounded_process)
FLAGS = {
    "direct_specialized_gen2", "os_only_private", "two_boots_only",
    "cleanup_owned_group", "exact_image_and_local_bundle_reviewed",
    "fresh_final_approval",
}
TOOLS = {"producer_controller", "producer_supervisor", "producer_validator",
         "reader_controller", "reader_supervisor", "reader_validator",
         "python", "git", "comparator"}
INPUTS = {
    "approved_stage", "consumer_proof", "custody", "producer_records",
    "upload_metadata", "selection_metadata", "transport_authentication",
    "container", "inner", "serial_first", "serial_second", "serial_incomplete",
}
STAGES = (
    "producer-records", "native-export", "python-export", "compare-export",
    "native-archive", "python-archive-verify", "native-import", "python-import",
    "native-candidate", "python-candidate", "native-inspect", "python-inspect",
    "native-result", "python-result", "native-incomplete", "python-incomplete",
    "compare-candidate",
)
PUBLIC_ENV = {
    "GITHUB_ACTIONS", "GITHUB_REPOSITORY", "GITHUB_JOB", "GITHUB_EVENT_NAME",
    "GITHUB_REPOSITORY_VISIBILITY", "GITHUB_WORKSPACE", "GITHUB_SHA",
    "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT", "GITHUB_WORKFLOW_REF",
}


class Refusal(ValueError):
    pass


def require(condition, reason):
    if not condition:
        raise Refusal(reason)


def encoded(value):
    return (json.dumps(value, ensure_ascii=False, allow_nan=False,
                       sort_keys=True, separators=(",", ":")) + "\n").encode()


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate JSON field")
        result[key] = value
    return result


def decode(raw, canonical=True):
    require(len(raw) <= MAX_RECORD, "record too large")
    value = json.loads(raw, object_pairs_hook=unique,
                       parse_constant=lambda _: (_ for _ in ()).throw(
                           Refusal("nonfinite JSON")))
    require(not canonical or raw == encoded(value), "noncanonical record")
    return value


def fields(value, names):
    require(type(value) is dict and set(value) == set(names), "unexpected fields")
    return value


def absolute(raw, exists=True):
    require(type(raw) is str and raw.startswith("/") and "//" not in raw
            and os.path.normpath(raw) == raw, "canonical absolute path required")
    path = Path(raw)
    require(path.resolve(strict=exists) == path, "symlink path refused")
    return path


def physical(info):
    return [info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns]


def hash_file(path, limit=MAX_FILE):
    path = absolute(str(path))
    before = path.lstat()
    require(stat.S_ISREG(before.st_mode) and before.st_nlink >= 1
            and before.st_uid in (0, os.geteuid()) and not before.st_mode & 0o022
            and before.st_size <= limit, "unsafe or oversized file")
    digest = hashlib.sha256()
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        require(physical(os.fstat(fd)) == physical(before), "replaced input")
        total = 0
        while chunk := os.read(fd, 65536):
            total += len(chunk)
            require(total <= limit, "file grew past bound")
            digest.update(chunk)
        require(total == before.st_size
                and physical(os.fstat(fd)) == physical(before)
                and physical(path.lstat()) == physical(before), "changed input")
    finally:
        os.close(fd)
    return {"path": str(path), "size": total, "sha256": digest.hexdigest(),
            "metadata": physical(before)}


def artifact(path):
    saved = hash_file(path)
    return {key: saved[key] for key in ("path", "sha256", "size")}


def same_bytes(left, right):
    left_pin, right_pin = hash_file(left), hash_file(right)
    require(left_pin["size"] == right_pin["size"]
            and left_pin["sha256"] == right_pin["sha256"], "byte difference")
    with Path(left).open("rb") as a, Path(right).open("rb") as b:
        while chunk := a.read(65536):
            require(chunk == b.read(65536), "byte difference")
        require(not b.read(1), "byte difference")
    require(hash_file(left) == left_pin and hash_file(right) == right_pin,
            "changed comparison input")


def checked_artifact(value):
    fields(value, ("path", "size", "sha256"))
    require(type(value["size"]) is int and 0 <= value["size"] <= MAX_FILE
            and type(value["sha256"]) is str
            and re.fullmatch("[0-9a-f]{64}", value["sha256"]), "invalid input pin")
    path = absolute(value["path"])
    require(artifact(path) == value, "input commitment mismatch")
    return path


def read(path, limit=MAX_RECORD):
    pin = hash_file(path, limit)
    with Path(path).open("rb") as handle:
        raw = handle.read(limit + 1)
    require(len(raw) <= limit and artifact(path) == {
        key: pin[key] for key in ("path", "size", "sha256")}, "changed record")
    return raw


def private(path):
    path = absolute(str(path))
    info = path.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid()
            and stat.S_IMODE(info.st_mode) == 0o700, "owner-private directory required")
    return path


def write(path, raw):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(raw)
        handle.flush()
        os.fsync(handle.fileno())
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def snapshot(root, allow_links=False):
    root = absolute(str(root))
    entries = {}
    total = 0

    def visit(path, depth):
        nonlocal total
        require(depth <= 32 and len(entries) < MAX_ENTRIES, "custody inventory bound")
        info = path.lstat()
        require(info.st_uid in (0, os.geteuid()), "unsafe custody owner")
        key = str(path)
        if stat.S_ISREG(info.st_mode):
            require(allow_links or info.st_nlink == 1, "private hardlink refused")
            entries[key] = hash_file(path)
            total += info.st_size
            require(total <= MAX_CUSTODY_BYTES, "custody byte bound")
        elif stat.S_ISDIR(info.st_mode):
            require(not info.st_mode & 0o022, "unsafe custody directory")
            entries[key] = {"path": key, "metadata": physical(info), "kind": "directory"}
            for name in sorted(os.listdir(path)):
                visit(path / name, depth + 1)
            require(physical(path.lstat()) == physical(info), "changed directory")
        elif stat.S_ISLNK(info.st_mode) and allow_links:
            target = os.readlink(path)
            entries[key] = {"path": key, "kind": "symlink", "metadata": physical(info),
                            "target": target}
            require(physical(path.lstat()) == physical(info), "changed source link")
        else:
            raise Refusal("custody links or special entries refused")

    visit(root, 0)
    return entries


def custody_snapshot(roots):
    paths = set()
    for group in roots.values():
        require(type(group) is list and 0 < len(group) <= 512, "full bounded custody roots required")
        paths.update(str(absolute(path)) for path in group)
    result = {}
    covered = []
    deadline = time.monotonic() + TIMEOUT
    for raw in sorted(paths, key=lambda p: (len(Path(p).parts), p)):
        path = Path(raw)
        if any(path.is_relative_to(parent) for parent in covered):
            continue
        require(time.monotonic() < deadline, "custody snapshot timed out")
        result.update(snapshot(path, allow_links=True))
        covered.append(path)
        require(len(result) <= MAX_ENTRIES
                and sum(entry.get("size", 0) for entry in result.values())
                <= MAX_CUSTODY_BYTES, "aggregate custody bound")
    for entry in result.values():
        if entry.get("kind") == "symlink":
            target = (Path(entry["path"]).parent / entry["target"]).resolve(strict=True)
            require(str(target) in result, "unbound original link target")
    return result


@dataclass(frozen=True)
class Command:
    stage: str
    argv: tuple
    cwd: str
    expected_exit: int = 0
    timeout_seconds: int = TIMEOUT


@dataclass(frozen=True)
class StageTools:
    controller: str
    supervisor: str
    validator: str

    def validation_flags(self, git):
        return ("--git", git, "--supervisor", self.supervisor,
                "--validator", self.validator)


def producer_stage(stage):
    require(stage in STAGES, "unknown tool-binding stage")
    return stage.startswith("python-") or stage in (
        "producer-records", "native-export", "native-archive")


def stage_tools(tools, stage):
    role = "producer" if producer_stage(stage) else "reader"
    return StageTools(*(tools[role + "_" + name] for name in (
        "controller", "supervisor", "validator")))


def stage_repository(stage, producer, reader):
    return producer if producer_stage(stage) else reader


def validate_tool_roles(tools, runtime):
    require(tools["producer_controller"] == tools["producer_supervisor"]
            == str(runtime / "controller/bin/uk-wamr-native-ci"),
            "producer/oracle supervisor must be the original runtime controller")
    require(tools["producer_validator"] == str(
        runtime / "compute/public-source/validator-build/public-source/tools/bin/uk-wamr-direct-validate"),
        "producer/oracle validator must be the original runtime validator")
    require(tools["reader_controller"] == tools["reader_supervisor"],
            "reader supervisor must match the executing reader controller")


def context_flags(context, selected=False):
    if selected:
        names = ("--selected-source", "--selected-tree",
                 "--selected-run-id", "--selected-run-attempt")
    else:
        names = ("--expected-source", "--expected-tree", "--run-id", "--run-attempt")
    return tuple(item for name, key in zip(names, (
        "source_revision", "source_tree", "run_id", "run_attempt"), strict=True)
                 for item in (name, context[key]))


def native_import_command(tools, paths, download, output, source, upload, selected):
    binding = stage_tools(tools, "native-import")
    return (
        binding.controller, "import-public-source-download",
        "--download-root", str(download), "--container-archive", str(paths["container"]),
        "--expected-archive-sha256", upload["inner_sha256"],
        "--artifact-id", upload["artifact_id"], "--container-digest", upload["container_digest"],
        "--selected-artifact-id", selected["artifact_id"],
        "--selected-container-digest", selected["container_digest"],
        "--output", str(output), *binding.validation_flags(tools["git"]),
        *context_flags(source), *context_flags(selected["context"], selected=True),
    )


def execute(command, output, environment):
    """Retain exact command, bounded streams and status even on failed partial execution."""
    require(re.fullmatch("[a-z-]+", command.stage), "invalid stage")
    require(1 <= command.timeout_seconds <= TIMEOUT, "invalid timeout")
    directory = output / command.stage
    directory.mkdir(mode=0o700)
    record = {
        "stage": command.stage, "argv": list(command.argv), "cwd": command.cwd,
        "environment": environment, "timeout_seconds": command.timeout_seconds,
        "expected_exit": command.expected_exit,
    }
    write(directory / "command.json", encoded(record))
    command_custody = hash_file(directory / "command.json")
    started = time.monotonic_ns()
    term = None
    failure = None
    executable = None
    cleanup = {"complete": False, "failures": [], "processes": []}
    try:
        with (directory / "stdout").open("xb") as stdout, \
                (directory / "stderr").open("xb") as stderr:
            os.chmod(directory / "stdout", 0o600)
            os.chmod(directory / "stderr", 0o600)
            path = Path(command.argv[0]).resolve(strict=True)
            executable_pin = hash_file(path)
            executable = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
            require(physical(os.fstat(executable)) == executable_pin["metadata"],
                    "executable custody changed")
            result = bounded_process.execute(
                command.argv, command.cwd, environment, executable,
                command.timeout_seconds, MAX_LOG, MAX_LOG, stdout, stderr)
            term, failure, cleanup = result["returncode"], result["failure"], result["cleanup"]
            record["capture"] = {name: result[name] for name in ("timeout", "overflow", "captured")}
            require(hash_file(path) == executable_pin, "executable custody changed")
    except (OSError, ValueError, RuntimeError) as err:
        if failure is None:
            failure = str(err)
        cleanup["failures"].append({"operation": "capture-wrapper", "error": str(err)})
    finally:
        if executable is not None:
            try:
                os.close(executable)
            except OSError as err:
                cleanup["failures"].append({"operation": "close-executable", "error": str(err)})
        record.update(
            exit_status=term, failure=failure,
            elapsed_ns=time.monotonic_ns() - started,
            stdout=artifact(directory / "stdout"),
            stderr=artifact(directory / "stderr"),
            command_custody=command_custody,
            capture_custody={name: hash_file(directory / name) for name in ("stdout", "stderr")},
            cleanup=cleanup,
        )
        write(directory / "receipt.json", encoded(record))
    require(failure is None and term == command.expected_exit
            and cleanup["complete"] and not cleanup["failures"],
            "failed stage " + command.stage)
    return record


def load_oracle(repository):
    # No monkeypatching, fabricated accepted owners or exception fallback.
    modules = []
    for name in ("handoff", "public_bundle"):
        spec = importlib.util.spec_from_file_location(
            "shadow_frozen_" + name,
            repository / "support/build/wamr-native-ci" / (name + ".py"))
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        modules.append(module)
    return modules


def worker(args):
    staged = decode(read(absolute(args.staged_inputs)))
    require(hash_file(args.staged_inputs)["sha256"] == args.staged_inputs_sha256,
            "worker input changed")
    assert_public_scope(staged)
    tools = {name: str(checked_artifact(value)) for name, value in staged["tools"].items()}
    validate_tool_roles(tools, absolute(staged["runtime"]))
    operations = {
        "python-export": "export", "python-archive-verify": "verify-archive",
        "python-import": "import", "python-candidate": "candidate",
    }
    require(operations.get(args.stage) == args.operation, "worker stage/operation mismatch")
    binding = stage_tools(tools, args.stage)
    require(args.supervisor == binding.supervisor and args.validator == binding.validator
            and os.environ.get("WAMR_CI_CONTROLLER") == binding.controller,
            "worker tools do not match authenticated stage roles")
    for value in staged["inputs"].values():
        if value is not None:
            checked_artifact(value)
    handoff, public = load_oracle(absolute(args.repository))
    output = absolute(args.output, exists=False)
    source = decode(read(absolute(args.context)))
    if args.operation == "export":
        handoff.export(absolute(args.input), output)
    elif args.operation == "verify-archive":
        public.verify_archive(handoff, absolute(args.input), source, args.inner_sha256)
    elif args.operation == "import":
        public.import_bundle(
            handoff, absolute(args.input), output, source, args.inner_sha256,
            absolute(args.validator), absolute(args.supervisor),
            artifact_id=args.artifact_id, container_digest=args.container_digest,
            native_import_revalidation=True)
    elif args.operation == "candidate":
        handoff.candidate_plan(absolute(args.input), output, attempt_id=args.attempt_id)


def verify_candidate(path):
    value = decode(read(path, 65536))
    require(value["authority"] == "not_admitted", "authorizing candidate")
    approval = fields(value["approval"], FLAGS | {"approved_unix", "expires_unix"})
    require(all(approval[key] is False for key in FLAGS)
            and type(approval["approved_unix"]) is int
            and type(approval["expires_unix"]) is int
            and approval["approved_unix"] == approval["expires_unix"] == 0,
            "authorizing approval fields")


def selected_members(handoff, public, root, kind="export"):
    allowed_root = {"artifacts", "boots", "evidence", "private", ".writer.lock", "bundle.json"}
    if kind == "import":
        allowed_root |= {"portable-bundle.json", "public-source.json",
                         "candidate-bundle.json", "transport.json"}
    else:
        require(kind == "export", "unknown selected product")
    require(set(os.listdir(root)) <= allowed_root, "unexpected product member")
    bundle = decode(read(root / "bundle.json", 65536))
    require(bundle["version"] == 2, "only current v2 shadow is supported")
    members = public.members(handoff, bundle, root)
    require(len(members) == 83, "incomplete selected assets")
    inventory = {}
    expected_paths = set()
    expected_directories = {str(root / name) for name in ("artifacts", "boots", "evidence")}
    for name, member in members.items():
        path = root / name
        require(artifact(path) == member, "modified selected payload")
        saved = hash_file(path)
        require(stat.S_IMODE(path.lstat().st_mode) == 0o600
                and path.lstat().st_nlink == 1, "selected member mode or link")
        inventory[name] = saved
        expected_paths.add(str(path))
        expected_directories.update(str(parent) for parent in path.parents
                                    if parent != root and parent.is_relative_to(root))
    # Extra files in any positively selected namespace are never bookkeeping.
    actual_paths = set()
    actual_directories = set()
    for name in ("artifacts", "boots", "evidence"):
        for path, item in snapshot(root / name).items():
            if "sha256" in item:
                actual_paths.add(path)
            else:
                actual_directories.add(path)
    allowed = {str(root / "evidence/command-handoff-inspect.json")}
    require(actual_paths - allowed == expected_paths, "unexpected selected member")
    require(actual_directories == expected_directories, "unexpected selected directory")
    return inventory


def compare_selected(left, right):
    require(left.keys() == right.keys(), "member inventory difference")
    for name in left:
        # Physical identities are recorded, not treated as portable byte identity.
        for key in ("size", "sha256"):
            require(left[name][key] == right[name][key], "selected payload difference " + name)
        require(left[name]["metadata"][2] == right[name]["metadata"][2],
                "selected permission difference " + name)
        same_bytes(left[name]["path"], right[name]["path"])


def archive_members(handoff, public, path, source, digest):
    # The frozen verifier checks ZIP ordering, metadata, CRC and every member hash.
    public.verify_archive(handoff, path, source, digest)
    import zipfile
    with zipfile.ZipFile(path) as zipped:
        require(len(zipped.infolist()) == 85, "incomplete ZIP")
        members = {}
        for item in zipped.infolist():
            digest = hashlib.sha256()
            with zipped.open(item) as stream:
                while chunk := stream.read(65536):
                    digest.update(chunk)
            members[item.filename] = {
                "size": item.file_size, "sha256": digest.hexdigest(),
                "zip_metadata": [item.date_time, item.compress_type, item.create_system,
                                 item.external_attr, item.flag_bits, item.CRC,
                                 item.extra.hex(), item.comment.hex()],
            }
        return members


def authenticate_transport(source, upload, selected, inputs, download):
    fields(upload, ("context", "artifact_id", "container_digest", "inner_sha256"))
    fields(selected, ("context", "artifact_id", "container_digest", "artifact_ids"))
    require(upload["context"] == selected["context"] == source, "transport context mismatch")
    require(type(upload["artifact_id"]) is str
            and re.fullmatch("[1-9][0-9]{0,19}", upload["artifact_id"])
            and selected["artifact_id"] == upload["artifact_id"]
            and selected["artifact_ids"] == [upload["artifact_id"]], "non-exact artifact selection")
    require(upload["container_digest"] == selected["container_digest"]
            == inputs["container"]["sha256"], "container authentication mismatch")
    require(upload["inner_sha256"] == inputs["inner"]["sha256"], "inner authentication mismatch")
    private(download)
    require(os.listdir(download) == ["tiny-aot-public-source.zip"], "download membership")
    require((download / "tiny-aot-public-source.zip").lstat().st_nlink == 1,
            "download hardlink refused")
    require(artifact(download / "tiny-aot-public-source.zip") == inputs["inner"],
            "download does not own supplied inner ZIP")
    # These are independently authenticated, externally approved staging inputs.
    # Their provenance remains an external qualification prerequisite.
    checked_artifact(inputs["transport_authentication"])


def validate_stages(receipts, command_root=None):
    require([r["stage"] for r in receipts] == list(STAGES), "missing, skipped or reordered stage")
    for record in receipts:
        expected = 2 if record["stage"].endswith("-incomplete") else 0
        require(record["failure"] is None and record["exit_status"] == expected
                and record["expected_exit"] == expected, "misleading partial execution")
        require(record["cleanup"]["complete"] and not record["cleanup"]["failures"],
                "misleading cleanup outcome")
        for name in ("stdout", "stderr"):
            checked_artifact(record[name])
        if command_root is not None:
            root = command_root / record["stage"]
            require(read(root / "receipt.json") == encoded(record), "modified execution receipt")
            require(hash_file(root / "command.json") == record["command_custody"],
                    "modified original command")
            for name in ("stdout", "stderr"):
                require(record[name]["path"] == str(root / name)
                        and hash_file(root / name) == record["capture_custody"][name],
                        "replaced command capture")
        if expected == 2:
            require(record["stdout"]["size"] == 0, "incomplete serial published a result")


def assert_public_scope(manifest):
    repository = absolute(manifest["producer_repository"])
    runtime = absolute(manifest["runtime"])
    require(runtime in (repository / ".d/wamr-native-runtime",
                        Path("/d/wamr-ci/wamr-native-runtime")), "arbitrary public runtime")
    require(absolute(manifest["handoff"]) == runtime / "compute/public-source/handoff",
            "shadow handoff is not fixed public scope")
    source = manifest["context"]
    expected = {
        "GITHUB_ACTIONS": "true", "GITHUB_REPOSITORY": "cataggar/unikraft",
        "GITHUB_JOB": "wamr-native-compute", "GITHUB_EVENT_NAME": "pull_request",
        "GITHUB_REPOSITORY_VISIBILITY": "public", "GITHUB_WORKSPACE": str(repository),
        "GITHUB_SHA": source["source_revision"], "GITHUB_RUN_ID": source["run_id"],
        "GITHUB_RUN_ATTEMPT": source["run_attempt"],
    }
    require(all(os.environ.get(k) == v for k, v in expected.items()), "not genuine public CI scope")
    require(os.environ.get("GITHUB_WORKFLOW_REF", "").startswith(
        "cataggar/unikraft/.github/workflows/wamr-native-compute.yaml@"),
        "not public producer workflow")
    require(os.environ.get("WAMR_CI_RUNTIME", str(repository / ".d/wamr-native-runtime"))
            == str(runtime), "runtime environment mismatch")


def run_stagewise(manifest_path, output_path):
    os.umask(0o077)
    manifest_raw = read(absolute(manifest_path))
    manifest = decode(manifest_raw)
    fields(manifest, ("schema", "version", "context", "producer_repository",
                      "reader_repository", "runtime", "handoff", "download_root",
                      "tools", "inputs", "attempt_id"))
    require(manifest["schema"] == "uk.wamr.handoff-shadow-inputs"
            and type(manifest["version"]) is int and manifest["version"] == 1,
            "invalid shadow input contract")
    fields(manifest["tools"], TOOLS)
    fields(manifest["inputs"], INPUTS)
    inputs = manifest["inputs"]
    paths = {name: checked_artifact(value) for name, value in inputs.items()
             if value is not None}
    require(set(paths) >= INPUTS - {"serial_second"}, "missing approved staged input")
    require(all(inputs[name]["size"] > 0 for name in (
        "approved_stage", "consumer_proof", "transport_authentication",
        "producer_records", "upload_metadata", "selection_metadata")),
        "empty qualification prerequisite")
    tools = {name: str(checked_artifact(value)) for name, value in manifest["tools"].items()}
    require(all(Path(path).stat().st_mode & 0o111 for path in tools.values()), "nonexecutable tool")
    require(re.fullmatch("[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}",
                         manifest["attempt_id"]), "explicit UUIDv4 attempt required")
    producer = absolute(manifest["producer_repository"])
    reader = absolute(manifest["reader_repository"])
    runtime = private(manifest["runtime"])
    validate_tool_roles(tools, runtime)
    handoff_root = private(manifest["handoff"])
    download = private(manifest["download_root"])
    frozen, public = load_oracle(producer)
    source = public.context(manifest["context"])
    assert_public_scope(manifest)
    upload = decode(read(paths["upload_metadata"]))
    selected = decode(read(paths["selection_metadata"]))
    for name in ("upload_metadata", "selection_metadata", "transport_authentication",
                 "approved_stage", "consumer_proof"):
        require(not paths[name].is_relative_to(download), "download cannot authenticate its own metadata")
    authenticate_transport(source, upload, selected, inputs, download)
    output = absolute(output_path, exists=False)
    private(output.parent)
    require(not output.exists(), "occupied shadow output")
    for root in (producer, reader, runtime, handoff_root, download):
        require(not output.is_relative_to(root) and not root.is_relative_to(output),
                "outputs overlap genuine inputs")
    custody = decode(read(paths["custody"]))
    fields(custody, ("schema", "version", "roots", "entries"))
    require(custody["schema"] == "uk.wamr.handoff-shadow-custody"
            and type(custody["version"]) is int and custody["version"] == 1,
            "invalid approved custody")
    fields(custody["roots"], ("producer_source", "reader_source", "producer_objects", "runtime", "tool_closure"))
    before = custody_snapshot(custody["roots"])
    for roots in custody["roots"].values():
        for root in roots:
            require(not output.is_relative_to(absolute(root))
                    and not absolute(root).is_relative_to(output), "custody/output overlap")
    require(before == custody["entries"], "approved input custody changed")
    require(str(runtime / "evidence/runtime-cleanup.txt") in before
            and str(runtime / "compute/evidence/result.json") in before
            and read(runtime / "evidence/runtime-cleanup.txt", 128)
            == b"primary=0 cleanup=0\n", "genuine result/cleanup missing")
    require(all(path in before for path in tools.values()), "incomplete tool closure")
    require(str(HERE / "handoff_shadow.py") in before, "unbound test driver")
    require(str(BOUNDED_PROCESS_PATH) in before, "unbound shared capture helper")
    for repository in (producer, reader):
        for name in ("handoff.py", "public_bundle.py", "accepted_records.py", "run.py"):
            require(str(repository / "support/build/wamr-native-ci" / name) in before,
                    "unbound frozen Python oracle closure")
    input_before = {name: hash_file(path) for name, path in paths.items()}
    input_before["manifest"] = hash_file(manifest_path)
    download_before = snapshot(download)
    handoff_before = snapshot(handoff_root)
    output.mkdir(mode=0o700)
    commands = output / "commands"
    commands.mkdir(mode=0o700)
    for name in ("native", "python", "requests"):
        (output / name).mkdir(mode=0o700)
    write(output / "inputs.json", manifest_raw)
    write(output / "custody-before.json", encoded({
        "closure": before, "inputs": input_before, "download": download_before,
        "handoff": handoff_before,
    }))
    write(output / "context.json", encoded(source))
    environment = {key: value for key, value in os.environ.items()
                   if key in PUBLIC_ENV | {"PATH", "HOME", "WAMR_CI_RUNTIME"}}
    environment.update(WAMR_CI_CONTROLLER=tools["reader_controller"], WAMR_CI_GIT=tools["git"],
                       PYTHONDONTWRITEBYTECODE="1")
    require(str(Path(shutil.which("git", path=environment.get("PATH")) or "").resolve())
            == tools["git"], "Python oracle PATH does not select pinned Git")
    receipts = []
    outcome = "refused"
    failure = None
    inventories = {}
    output_pins = {}

    def run(stage, argv, cwd=None, expected=0):
        if cwd is None:
            cwd = stage_repository(stage, producer, reader)
        command = Command(stage, tuple(map(str, argv)), str(cwd), expected)
        stage_environment = dict(environment)
        stage_environment["WAMR_CI_CONTROLLER"] = stage_tools(tools, stage).controller
        try:
            receipt = execute(command, commands, stage_environment)
        except (OSError, ValueError) as err:
            saved = commands / stage / "receipt.json"
            if saved.exists():
                receipts.append(decode(read(saved)))
            raise Refusal(str(err)) from err
        receipts.append(receipt)
        output_pins[str(commands / stage / "receipt.json")] = hash_file(commands / stage / "receipt.json")
        return commands / stage / "stdout"

    def python_stage(stage, operation, repository, input_path, output_path):
        binding = stage_tools(tools, stage)
        return run(stage, (
            tools["python"], "-B", HERE / "handoff_shadow.py", "_worker",
            "--stage", stage, "--operation", operation,
            "--repository", repository, "--input", input_path,
            "--output", output_path, "--context", output / "context.json",
            "--validator", binding.validator, "--supervisor", binding.supervisor,
            "--inner-sha256", inputs["inner"]["sha256"], "--artifact-id", upload["artifact_id"],
            "--container-digest", upload["container_digest"], "--attempt-id", manifest["attempt_id"],
            "--staged-inputs", output / "inputs.json",
            "--staged-inputs-sha256", hashlib.sha256(manifest_raw).hexdigest(),
        ), repository)

    def comparison(stage, mode, roots, records):
        request = output / "requests" / (stage + ".json")
        write(request, encoded({
            "mode": mode, "native_roots": roots["native"], "python_roots": roots["python"],
            "native": records["native"], "python": records["python"],
        }))
        output_pins[str(request)] = hash_file(request)
        run(stage, (tools["comparator"], "--request", request))

    common = stage_tools(tools, "native-import").validation_flags(tools["git"])
    roots = {}
    try:
        observed = run("producer-records", (
            tools["producer_controller"], "records", "--runtime", runtime, "--output", "handoff-v1",
        ), producer)
        require(read(observed) == read(paths["producer_records"]), "producer records changed")
        accepted = frozen.accepted_records._decode(read(observed), "local-runtime")
        require(accepted["source"] == {"revision": source["source_revision"], "tree": source["source_tree"]}
                and accepted["compatibility"] == "tiny-v2", "producer identity mismatch")
        for item in accepted["runtime_inputs"]:
            require(item["path"] in before, "missing genuine producer input closure")
        run("native-export", (tools["producer_controller"], "private-export",
                              "--runtime", runtime, "--output", output / "native/export"), producer)
        python_stage("python-export", "export", producer, runtime, output / "python/export")
        for side in ("native", "python"):
            root = output / side / "export"
            roots[side] = {"bundle": str(root), "candidate": str(output / side / "candidate.json")}
            inventories[side + "-export"] = selected_members(frozen, public, root)
        compare_selected(inventories["native-export"], inventories["python-export"])
        comparison("compare-export", "bundle", roots, {
            side: {"bundle": read(output / side / "export/bundle.json").decode()}
            for side in ("native", "python")
        })
        run("native-archive", (
            tools["producer_controller"], "public-archive", "--stage-root", handoff_root,
            "--validation-output", output / "native/archive-validation",
            "--output", output / "native/archive",
            *stage_tools(tools, "native-archive").validation_flags(tools["git"]),
            *context_flags(source),
        ), producer)
        python_stage("python-archive-verify", "verify-archive", producer,
                     paths["inner"], output / "python/archive-verification")
        native_zip = output / "native/archive/public-inner.zip"
        python_zip = paths["inner"]
        for side, path in (("native", native_zip), ("python", python_zip)):
            inventories[side + "-zip"] = archive_members(frozen, public, path, source, artifact(path)["sha256"])
            output_pins[str(path)] = hash_file(path)
        require(encoded(inventories["native-zip"]) == encoded(inventories["python-zip"]),
                "ZIP member bytes or metadata differ")
        same_bytes(native_zip, python_zip)
        require(artifact(native_zip)["sha256"] == inputs["inner"]["sha256"],
                "archive differs from independently redownloaded artifact")
        run("native-import", native_import_command(
            tools, paths, download, output / "native/import", source, upload, selected))
        python_stage("python-import", "import", producer, paths["inner"], output / "python/import")
        for side in ("native", "python"):
            bundle_root = output / side / "import"
            roots[side]["bundle"] = str(bundle_root)
            inventories[side + "-import"] = selected_members(frozen, public, bundle_root, "import")
            require(read(bundle_root / "candidate-bundle.json", 65536)
                    == read(bundle_root / "bundle.json", 65536), "import publication changed")
            for name in ("portable-bundle.json", "public-source.json"):
                decode(read(bundle_root / name, 65536))
        compare_selected(inventories["native-import"], inventories["python-import"])
        for name in ("portable-bundle.json", "public-source.json"):
            require(read(output / "native/import" / name, 65536)
                    == read(output / "python/import" / name, 65536),
                    "import portable metadata differs")
        candidate = output / "native/candidate.json"
        run("native-candidate", (
            tools["reader_controller"], "candidate", "--bundle", output / "native/import/bundle.json",
            "--output", candidate, "--validation-output", output / "native/candidate-validation",
            "--attempt-id", manifest["attempt_id"], *common,
        ))
        python_stage("python-candidate", "candidate", producer, output / "python/import/bundle.json",
                     output / "python/candidate.json")
        for side in ("native", "python"):
            verify_candidate(output / side / "candidate.json")
        run("native-inspect", (
            tools["reader_controller"], "candidate-inspect", "--bundle", output / "native/import/bundle.json",
            "--candidate", candidate, "--validation-output", output / "native/inspect-validation", *common,
        ))
        run("python-inspect", (stage_tools(tools, "python-inspect").validator,
                               "candidate", output / "python/candidate.json"))
        require(read(commands / "native-inspect/stdout") == read(commands / "python-inspect/stdout"),
                "inspection record differs")
        results = {}
        serial = ("--serial-first", paths["serial_first"])
        py_serial = (paths["serial_first"],)
        if "serial_second" in paths:
            serial += ("--serial-second", paths["serial_second"])
            py_serial += (paths["serial_second"],)
        results["native"] = run("native-result", (
            tools["reader_controller"], "candidate-result", "--bundle", output / "native/import/bundle.json",
            "--candidate", candidate, "--validation-output", output / "native/result-validation", *common, *serial,
        ))
        results["python"] = run("python-result", (
            stage_tools(tools, "python-result").validator, "serial",
            output / "python/candidate.json", *py_serial,
        ))
        run("native-incomplete", (
            tools["reader_controller"], "candidate-result", "--bundle", output / "native/import/bundle.json",
            "--candidate", candidate, "--validation-output", output / "native/incomplete-validation",
            *common, "--serial-first", paths["serial_incomplete"],
        ), expected=2)
        run("python-incomplete", (
            stage_tools(tools, "python-incomplete").validator, "serial",
            output / "python/candidate.json", paths["serial_incomplete"],
        ), expected=2)
        records = {}
        for side in ("native", "python"):
            records[side] = {
                "bundle": read(output / side / "import/bundle.json", 65536).decode(),
                "transport": read(output / side / "import/transport.json", 65536).decode(),
                "candidate": read(output / side / "candidate.json", 65536).decode(),
                "admission": read(output / side / "candidate.json.admission.json", 65536).decode(),
                "result": encoded(decode(read(results[side], 65536), canonical=False)).decode(),
            }
            write(output / side / "canonical-records.json", encoded(records[side]))
            for path in (
                    output / side / "canonical-records.json",
                    output / side / "candidate.json",
                    output / side / "candidate.json.admission.json",
                    output / side / "import/bundle.json",
                    output / side / "import/transport.json",
                    output / side / "import/portable-bundle.json",
                    output / side / "import/public-source.json",
                    output / side / "import/candidate-bundle.json"):
                output_pins[str(path)] = hash_file(path)
        require(read(results["native"]) == read(results["python"]), "raw serial result bytes differ")
        comparison("compare-candidate", "candidate", roots, records)
        validate_stages(receipts, commands)
        outcome = "stagewise_shadow_equal"
    except (OSError, ValueError, KeyError, TypeError) as err:
        failure = str(err)
    finally:
        try:
            after = custody_snapshot(custody["roots"])
            require(after == before, "producer custody changed")
            require(snapshot(download) == download_before
                    and snapshot(handoff_root) == handoff_before, "transport/handoff custody changed")
            require({name: hash_file(path) for name, path in paths.items()}
                    | {"manifest": hash_file(manifest_path)} == input_before, "staged input changed")
            for name, inventory in inventories.items():
                if name.endswith(("-export", "-import")):
                    for entry in inventory.values():
                        require(hash_file(entry["path"]) == entry, "selected output custody changed")
            for path, pin in output_pins.items():
                require(hash_file(path) == pin, "execution/output custody changed")
            write(output / "custody-after.json", encoded({
                "closure": after, "download": snapshot(download), "handoff": snapshot(handoff_root),
            }))
        except (OSError, ValueError) as err:
            outcome, failure = "refused", str(err)
            write(output / "custody-after-failure.json", encoded({"failure": str(err)}))
        write(output / "members.json", encoded(inventories))
        write(output / "executions.json", encoded(receipts))
        write(output / "output-pins.json", encoded(output_pins))
        partial = snapshot(output)
        write(output / "retained-output.json", encoded(partial))
        write(output / "report.json", encoded({
            "schema": "uk.wamr.handoff-shadow-report", "version": 1,
            "outcome": outcome, "failure": failure, "stages": [r["stage"] for r in receipts],
            "acceptance": False, "genuine_producer_parity": False,
            "composition": "stagewise-existing-fixed-handoff",
            "python_archive_oracle": "retained authenticated production inner ZIP; fresh frozen verification, not a new pack",
            "required_before_cutover": "separate authentic fresh native public-export composition and protected review",
            "transport_provenance": "externally authenticated approved inputs; not authenticated by receipt equality",
            "input_manifest": artifact(output / "inputs.json"),
            "executions": artifact(output / "executions.json"),
            "retained_output": artifact(output / "retained-output.json"),
        }))
    require(outcome == "stagewise_shadow_equal", failure or "shadow refused")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    run = sub.add_parser("run-stagewise")
    run.add_argument("--inputs", required=True)
    run.add_argument("--output", required=True)
    worker_parser = sub.add_parser("_worker")
    worker_parser.add_argument("--operation", choices=("export", "verify-archive", "import", "candidate"), required=True)
    for name in ("repository", "input", "output", "context", "validator", "supervisor",
                 "inner-sha256", "artifact-id", "container-digest", "attempt-id",
                 "staged-inputs", "staged-inputs-sha256", "stage"):
        worker_parser.add_argument("--" + name, required=True)
    args = parser.parse_args()
    try:
        if args.command == "_worker":
            worker(args)
        else:
            run_stagewise(args.inputs, args.output)
    except (OSError, ValueError, KeyError, TypeError) as err:
        print("TEST-ONLY shadow refused: " + str(err), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
