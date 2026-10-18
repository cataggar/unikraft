#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""Synthetic comparator/driver refusals ONLY; no producer or live parity claim."""
import argparse
import copy
import ctypes
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import time
import unittest
import uuid
from unittest import mock

import handoff_shadow as shadow

HERE = Path(__file__).resolve().parent
COMPARATOR = None
PUBLICATION_PARSER = None
SCRATCH = None


class ShadowWitness(unittest.TestCase):
    def setUp(self):
        self.root = SCRATCH / ("synthetic-shadow-" + str(uuid.uuid4()))
        self.root.mkdir(mode=0o700)
        self.addCleanup(shutil.rmtree, self.root)
        self.frozen, self.public = shadow.load_oracle(HERE.parents[3])

    def document(self, path, value):
        shadow.write(path, shadow.encoded(value))

    def distinct_tools(self):
        runtime = self.root / "synthetic-original-runtime"
        producer = str(runtime / "controller/bin/uk-wamr-native-ci")
        reader = str(self.root / "synthetic-new-reader/controller")
        tools = {
            "producer_controller": producer, "producer_supervisor": producer,
            "producer_validator": str(
                runtime / "compute/public-source/validator-build/public-source/tools/bin/uk-wamr-direct-validate"),
            "reader_controller": reader, "reader_supervisor": reader,
            "reader_validator": str(self.root / "synthetic-new-reader/validator"),
            "python": sys.executable, "git": "/synthetic/git",
            "comparator": str(COMPARATOR),
        }
        return runtime, tools

    @staticmethod
    def cleanup_python_child(pid, code):
        try:
            descriptor = os.pidfd_open(pid)
        except ProcessLookupError:
            return
        try:
            command_line = Path(f"/proc/{pid}/cmdline").read_bytes()
            expected = os.fsencode(sys.executable) + b"\0-c\0" + code.encode() + b"\0"
            if command_line == expected:
                signal.pidfd_send_signal(descriptor, signal.SIGKILL)
                try:
                    os.waitpid(pid, 0)
                except ChildProcessError:
                    pass
        except (FileNotFoundError, ProcessLookupError):
            pass
        finally:
            os.close(descriptor)

    def fixture(self):
        golden = shadow.decode(shadow.read(
            HERE.parent / "handoff/goldens/root-bound-v2.json"))
        old = "/opt/wamr-handoff-golden-stage"
        result = {
            "version": 1, "workload": "tiny",
            **{key: golden["identity"][key] for key in (
                "wamr_revision", "wasm_sha256", "cwasm_sha256", "runtime_sha256")},
            "platform_status": 0, "checks": 1, "answer": 42, "terminal": 0,
            "detail": 0, "reserved_bytes": 0, "frame_bytes": 0,
            "accessible_bytes": 0, "allocation_bytes": 0,
            "system_page_table_bytes": 0, "error_name": "",
        }
        request = {"mode": "candidate"}
        for side in ("native", "python"):
            directory = self.root / side
            directory.mkdir(mode=0o700)
            bundle = copy.deepcopy(golden)

            def rebase(item):
                if type(item) is dict:
                    for key, value in item.items():
                        if key == "path":
                            self.assertTrue(value.startswith(old + "/"))
                            item[key] = str(directory) + value[len(old):]
                        else:
                            rebase(value)
                elif type(item) is list:
                    for value in item:
                        rebase(value)

            rebase(bundle)
            selected = self.public.members(self.frozen, bundle, directory)
            self.assertEqual(len(selected), 83)
            for member in selected.values():
                path = Path(member["path"])
                path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                shadow.write(path, b"x")
                self.assertEqual(shadow.artifact(path), member)
            self.document(directory / "bundle.json", bundle)
            transport = {
                "schema": "uk.wamr.public-source-transport", "version": 2,
                **bundle["run"], "source_revision": bundle["source_revision"],
                "source_tree": bundle["source_tree"], "artifact_id": "263",
                "container_digest": "a" * 64, "inner_zip_sha256": "b" * 64,
            }
            self.document(directory / "transport.json", transport)
            candidate = self.root / (side + "-candidate.json")
            self.frozen.candidate_plan(
                directory / "bundle.json", candidate,
                attempt_id="11111111-1111-4111-8111-111111111111")
            request[side + "_roots"] = {"bundle": str(directory), "candidate": str(candidate)}
            request[side] = {
                "bundle": shadow.read(directory / "bundle.json").decode(),
                "transport": shadow.read(directory / "transport.json").decode(),
                "candidate": shadow.read(candidate).decode(),
                "admission": shadow.read(Path(str(candidate) + ".admission.json")).decode(),
                "result": shadow.encoded(result).decode(),
            }
        return request

    def comparison(self, request, expected):
        path = self.root / ("request-" + str(uuid.uuid4()) + ".json")
        self.document(path, request)
        observed = subprocess.run(
            (str(COMPARATOR), "--request", str(path)), stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
        self.assertEqual(observed.returncode, expected, observed.stderr.decode())
        if expected == 0:
            self.assertIn(b"not genuine producer acceptance", observed.stdout)
        else:
            self.assertNotIn(b"records equal", observed.stdout)
        return observed

    def change(self, request, record, change):
        altered = copy.deepcopy(request)
        value = shadow.decode(altered["native"][record].encode())
        change(value)
        altered["native"][record] = shadow.encoded(value).decode()
        return altered

    def test_synthetic_root_rebase_recomputes_exact_dependent_commitments(self):
        request = self.fixture()
        self.comparison(request, 0)
        admission = shadow.decode(request["native"]["admission"].encode())
        admission["public_bundle"]["sha256"] = "c" * 64
        altered = copy.deepcopy(request)
        altered["native"]["admission"] = shadow.encoded(admission).decode()
        candidate = shadow.decode(altered["native"]["candidate"].encode())
        candidate["bundle"]["sha256"] = shadow.hashlib.sha256(
            altered["native"]["admission"].encode()).hexdigest()
        candidate["bundle"]["size"] = len(altered["native"]["admission"].encode())
        altered["native"]["candidate"] = shadow.encoded(candidate).decode()
        refused = self.comparison(altered, 1)
        self.assertIn(b"DependentCommitment", refused.stderr)

    def test_synthetic_identity_transport_failure_and_authority_never_normalize(self):
        request = self.fixture()
        changes = (
            ("bundle", lambda v: v["run"].update(run_attempt="2")),
            ("bundle", lambda v: v.update(source_revision="c" * 40)),
            ("transport", lambda v: v.update(artifact_id="264")),
            ("candidate", lambda v: v.update(attempt_id="22222222-2222-4222-8222-222222222222")),
            ("candidate", lambda v: v["approval"].update(fresh_final_approval=True)),
            ("candidate", lambda v: v["approval"].update(approved_unix=1)),
            ("candidate", lambda v: v["approval"].update(extra_authority=False)),
            ("result", lambda v: v.update(error_name="different-failure")),
            ("result", lambda v: v.update(authority="admitted")),
        )
        for name, change in changes:
            with self.subTest(record=name):
                self.comparison(self.change(request, name, change), 1)
        altered = copy.deepcopy(request)
        altered["python"]["candidate"] = altered["python"]["candidate"].rstrip("\n")
        self.assertIn(b"NonCanonical", self.comparison(altered, 1).stderr)

    def test_synthetic_selected_payload_extra_member_and_replacement_refuse(self):
        request = self.fixture()
        roots = {side: Path(request[side + "_roots"]["bundle"]) for side in ("native", "python")}
        inventories = {
            side: shadow.selected_members(self.frozen, self.public, roots[side], "import")
            for side in roots
        }
        shadow.compare_selected(inventories["native"], inventories["python"])
        changed = roots["native"] / "artifacts/efi"
        original = shadow.hash_file(changed)
        changed.write_bytes(b"y")
        with self.assertRaisesRegex(shadow.Refusal, "modified selected payload"):
            shadow.selected_members(self.frozen, self.public, roots["native"], "import")
        changed.write_bytes(b"x")
        self.assertNotEqual(shadow.hash_file(changed), original)
        extra = roots["native"] / "boots/unexpected"
        extra.mkdir(mode=0o700)
        with self.assertRaisesRegex(shadow.Refusal, "unexpected selected directory"):
            shadow.selected_members(self.frozen, self.public, roots["native"], "import")

    def test_synthetic_transport_requires_separate_pins_exact_id_and_raw_container(self):
        download = self.root / "download"
        download.mkdir(mode=0o700)
        inner = download / "tiny-aot-public-source.zip"
        shadow.write(inner, b"inner")
        container = self.root / "container.zip"
        proof = self.root / "externally-authenticated-transport"
        shadow.write(container, b"outer")
        shadow.write(proof, b"synthetic prerequisite, NOT authentication")
        source = {"synthetic": True}
        inputs = {"inner": shadow.artifact(inner), "container": shadow.artifact(container),
                  "transport_authentication": shadow.artifact(proof)}
        upload = {"context": source, "artifact_id": "263",
                  "container_digest": inputs["container"]["sha256"],
                  "inner_sha256": inputs["inner"]["sha256"]}
        selected = {"context": source, "artifact_id": "263",
                    "container_digest": inputs["container"]["sha256"],
                    "artifact_ids": ["263"]}
        shadow.authenticate_transport(source, upload, selected, inputs, download)
        for value in ("264", None):
            altered = dict(selected, artifact_id=value)
            with self.assertRaisesRegex(shadow.Refusal, "non-exact artifact selection"):
                shadow.authenticate_transport(source, upload, altered, inputs, download)
        altered = dict(selected, container_digest=inputs["inner"]["sha256"])
        with self.assertRaisesRegex(shadow.Refusal, "container authentication mismatch"):
            shadow.authenticate_transport(source, upload, altered, inputs, download)
        proof.write_bytes(b"changed external prerequisite")
        with self.assertRaisesRegex(shadow.Refusal, "input commitment mismatch"):
            shadow.authenticate_transport(source, upload, selected, inputs, download)
        shadow.write(download / "metadata.json", b"{}")
        with self.assertRaisesRegex(shadow.Refusal, "download membership"):
            shadow.authenticate_transport(source, upload, selected, inputs, download)

    def test_synthetic_failed_timeout_and_incomplete_commands_retain_original_receipts(self):
        environment = {"PATH": os.environ["PATH"]}
        command = shadow.Command("failed", (sys.executable, "-c",
                                           "import sys;print('partial');sys.exit(7)"),
                                 str(self.root))
        with self.assertRaisesRegex(shadow.Refusal, "failed stage"):
            shadow.execute(command, self.root, environment)
        record = shadow.decode(shadow.read(self.root / "failed/receipt.json"))
        self.assertEqual(record["argv"], list(command.argv))
        self.assertEqual(record["exit_status"], 7)
        self.assertEqual(shadow.read(Path(record["stdout"]["path"])), b"partial\n")
        with self.assertRaises(FileExistsError):
            shadow.execute(command, self.root, environment)
        timed = shadow.Command("timed", (sys.executable, "-c",
                                        "import time,subprocess,sys;"
                                        "p=subprocess.Popen([sys.executable,'-c',"
                                        "'import time;time.sleep(60)'],start_new_session=True);"
                                        "print(p.pid,flush=True);time.sleep(60)"),
                               str(self.root), timeout_seconds=1)
        with self.assertRaisesRegex(shadow.Refusal, "failed stage"):
            shadow.execute(timed, self.root, environment)
        timed_record = shadow.decode(shadow.read(self.root / "timed/receipt.json"))
        self.assertEqual(timed_record["failure"], "command timed out")
        self.assertLess(timed_record["exit_status"], 0)
        self.assertTrue(timed_record["cleanup"]["complete"])
        self.assertEqual(timed_record["cleanup"]["failures"], [])
        descendant = int(shadow.read(self.root / "timed/stdout").strip())
        self.assertFalse(Path(f"/proc/{descendant}").exists(), "descendant not reaped")
        incomplete = shadow.Command("native-incomplete", (sys.executable, "-c",
                                                         "import sys;sys.exit(2)"),
                                    str(self.root), expected_exit=2)
        receipt = shadow.execute(incomplete, self.root, environment)
        self.assertEqual(receipt["exit_status"], 2)
        self.assertEqual(receipt["stdout"]["size"], 0)
        with self.assertRaisesRegex(shadow.Refusal, "missing, skipped or reordered"):
            shadow.validate_stages([receipt])

    def test_synthetic_partial_reports_cannot_hide_skips_failures_or_incomplete_results(self):
        log = self.root / "empty"
        shadow.write(log, b"")
        receipts = [{
            "stage": stage, "failure": None,
            "exit_status": 2 if stage.endswith("-incomplete") else 0,
            "expected_exit": 2 if stage.endswith("-incomplete") else 0,
            "stdout": shadow.artifact(log), "stderr": shadow.artifact(log),
            "cleanup": {"complete": True, "failures": [], "processes": []},
        } for stage in shadow.STAGES]
        shadow.validate_stages(receipts)
        with self.assertRaisesRegex(shadow.Refusal, "missing, skipped or reordered"):
            shadow.validate_stages(receipts[:-1])
        failed = copy.deepcopy(receipts)
        failed[3]["exit_status"] = 1
        with self.assertRaisesRegex(shadow.Refusal, "misleading partial execution"):
            shadow.validate_stages(failed)
        failed = copy.deepcopy(receipts)
        failed[3]["cleanup"]["failures"].append({"operation": "reap", "error": "synthetic failure"})
        with self.assertRaisesRegex(shadow.Refusal, "misleading cleanup outcome"):
            shadow.validate_stages(failed)
        published = self.root / "misleading-result"
        shadow.write(published, b"{}\n")
        failed = copy.deepcopy(receipts)
        failed[-3]["stdout"] = shadow.artifact(published)
        with self.assertRaisesRegex(shadow.Refusal, "incomplete serial published"):
            shadow.validate_stages(failed)
        log.write_bytes(b"changed")
        with self.assertRaisesRegex(shadow.Refusal, "input commitment mismatch"):
            shadow.validate_stages(receipts)

    def test_synthetic_arbitrary_runtime_is_not_genuine_public_composition(self):
        runtime = self.root / "copied-runtime"
        handoff = runtime / "compute/public-source/handoff"
        handoff.mkdir(mode=0o700, parents=True)
        manifest = {
            "producer_repository": str(self.root), "runtime": str(runtime),
            "handoff": str(handoff), "context": {},
        }
        with mock.patch.dict(os.environ, {"GITHUB_ACTIONS": "true"}):
            with self.assertRaisesRegex(shadow.Refusal, "arbitrary public runtime"):
                shadow.assert_public_scope(manifest)

    def test_synthetic_original_source_links_require_pinned_targets_not_private_relabeling(self):
        source = self.root / "source"
        source.mkdir(mode=0o700)
        program = source / "program"
        shadow.write(program, b"original tool bytes")
        alias = source / "alias"
        alias.symlink_to("program")
        os.link(program, source / "original-hardlink")
        roots = {key: [str(source)] for key in (
            "producer_source", "reader_source", "producer_objects", "runtime", "tool_closure")}
        original = shadow.custody_snapshot(roots)
        self.assertEqual(original[str(program)]["metadata"][5], 2)
        self.assertEqual(original[str(alias)]["target"], "program")
        with self.assertRaisesRegex(shadow.Refusal, "link"):
            shadow.snapshot(source)
        outside = self.root / "unbound-tool"
        shadow.write(outside, b"other tool")
        alias.unlink()
        alias.symlink_to(outside)
        with self.assertRaisesRegex(shadow.Refusal, "unbound original link target"):
            shadow.custody_snapshot(roots)
        roots["tool_closure"].append(str(outside))
        changed = shadow.custody_snapshot(roots)
        self.assertNotEqual(original, changed)

    def test_synthetic_import_command_forwards_independent_selected_context_to_actual_parser(self):
        _, tools = self.distinct_tools()
        source = {"source_revision": "a" * 40, "source_tree": "b" * 40,
                  "run_id": "263", "run_attempt": "1"}
        selected_context = {"source_revision": "c" * 40, "source_tree": "d" * 40,
                            "run_id": "264", "run_attempt": "2"}
        upload = {"inner_sha256": "e" * 64, "artifact_id": "100",
                  "container_digest": "f" * 64}
        selected = {"context": selected_context, "artifact_id": "101",
                    "container_digest": "1" * 64}
        command = shadow.native_import_command(
            tools, {"container": self.root / "outer.zip"}, self.root / "download",
            self.root / "import", source, upload, selected)
        flags = dict(zip(command[2::2], command[3::2], strict=True))
        for flag, key in (("--selected-source", "source_revision"), ("--selected-tree", "source_tree"),
                          ("--selected-run-id", "run_id"), ("--selected-run-attempt", "run_attempt")):
            self.assertEqual(flags[flag], selected_context[key])
        self.assertEqual(flags["--expected-source"], source["source_revision"])
        self.assertEqual(flags["--supervisor"], tools["reader_supervisor"])
        if PUBLICATION_PARSER is not None:
            observed = subprocess.run(
                (str(PUBLICATION_PARSER), *command), stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
            self.assertEqual(observed.returncode, 0, observed.stderr.decode())
            parsed = shadow.decode(observed.stdout, canonical=False)
            self.assertEqual(parsed["source_revision"], source["source_revision"])
            self.assertEqual(parsed["selected_source_revision"], selected_context["source_revision"])
            self.assertEqual(parsed["selected_source_tree"], selected_context["source_tree"])
            self.assertEqual(parsed["selected_run_id"], selected_context["run_id"])
            self.assertEqual(parsed["selected_run_attempt"], selected_context["run_attempt"])
            omitted = command[:-8]
            refused = subprocess.run(
                (str(PUBLICATION_PARSER), *omitted), stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
            self.assertEqual(refused.returncode, 1)
            self.assertIn(b"InvalidUsage", refused.stderr)

    def test_synthetic_distinct_producer_oracle_and_reader_bindings_never_alias(self):
        runtime, tools = self.distinct_tools()
        shadow.validate_tool_roles(tools, runtime)
        for stage in ("producer-records", "native-export", "native-archive",
                      "python-export", "python-import", "python-inspect", "python-result"):
            binding = shadow.stage_tools(tools, stage)
            self.assertEqual(binding.controller, tools["producer_controller"])
            self.assertEqual(binding.supervisor, tools["producer_supervisor"])
            self.assertEqual(binding.validator, tools["producer_validator"])
            self.assertEqual(shadow.stage_repository(stage, "/original", "/new-reader"), "/original")
        for stage in ("native-import", "native-candidate", "native-inspect", "native-result"):
            binding = shadow.stage_tools(tools, stage)
            self.assertEqual(binding.controller, tools["reader_controller"])
            self.assertEqual(binding.supervisor, tools["reader_supervisor"])
            self.assertEqual(binding.validator, tools["reader_validator"])
            self.assertEqual(shadow.stage_repository(stage, "/original", "/new-reader"), "/new-reader")
        changed = dict(tools, producer_supervisor=tools["reader_supervisor"])
        with self.assertRaisesRegex(shadow.Refusal, "original runtime controller"):
            shadow.validate_tool_roles(changed, runtime)
        changed = dict(tools, reader_supervisor=tools["producer_supervisor"])
        with self.assertRaisesRegex(shadow.Refusal, "executing reader controller"):
            shadow.validate_tool_roles(changed, runtime)

    def test_synthetic_exited_parent_session_descendant_is_killed_reaped_and_retained(self):
        for stage, child, bound in (
                ("exited-timeout", "import time;time.sleep(60)", None),
                ("exited-capture", "import time,os;time.sleep(0.2);"
                 "os.write(2,b'x'*65536);time.sleep(60)", 1024)):
            code = (
                "import subprocess,sys;"
                f"p=subprocess.Popen([sys.executable,'-c',{child!r}],start_new_session=True);"
                "print(p.pid,flush=True);sys.exit(0)"
            )
            command = shadow.Command(stage, (sys.executable, "-c", code),
                                     str(self.root), timeout_seconds=1)
            try:
                with mock.patch.object(shadow, "MAX_LOG", bound or shadow.MAX_LOG):
                    with self.assertRaisesRegex(shadow.Refusal, "failed stage"):
                        shadow.execute(command, self.root, {"PATH": os.environ["PATH"]})
                receipt = shadow.decode(shadow.read(self.root / stage / "receipt.json"))
                self.assertEqual(receipt["exit_status"], 0, "original parent status changed")
                self.assertEqual(receipt["failure"],
                                 "stderr overflow" if bound else "command timed out")
                self.assertEqual(receipt["capture"]["timeout"], not bool(bound))
                self.assertEqual(receipt["capture"]["overflow"], ["stderr"] if bound else [])
                descendant = int(shadow.read(self.root / stage / "stdout").strip())
                self.assertTrue(receipt["cleanup"]["complete"])
                self.assertEqual(receipt["cleanup"]["failures"], [])
                child_record = next(value for value in receipt["cleanup"]["processes"]
                                    if value["pid"] == descendant)
                self.assertTrue(child_record["reaped"])
                self.assertEqual(child_record["exit_status"], -signal.SIGKILL)
                self.assertFalse(Path(f"/proc/{descendant}").exists())
            finally:
                # Precise emergency cleanup also applies when running this
                # regression against the old, leaking implementation.
                captured = self.root / stage / "stdout"
                if captured.exists() and captured.read_bytes().strip().isdigit():
                    self.cleanup_python_child(int(captured.read_bytes().strip()), child)

    def test_synthetic_preexisting_family_orphan_stays_alive_and_unreaped(self):
        # A caller may already be a subreaper. This controlled family is NOT a
        # descendant of the capture worker, even when it forks after capture starts.
        libc = ctypes.CDLL(None, use_errno=True)
        previous = ctypes.c_int()
        self.assertEqual(libc.prctl(37, ctypes.byref(previous), 0, 0, 0), 0)
        self.assertEqual(libc.prctl(36, 1, 0, 0, 0), 0)
        ready = self.root / "foreign-ready"
        started = self.root / "stage-started"
        orphan = self.root / "foreign-orphan"
        foreign_code = (
            "import os,time;from pathlib import Path;"
            f"Path({str(ready)!r}).write_text('ready');"
            f"gate=Path({str(started)!r});deadline=time.monotonic()+10\n"
            "while not gate.exists():\n"
            " if time.monotonic()>deadline: raise RuntimeError('stage did not start')\n"
            " time.sleep(.01)\n"
            "pid=os.fork()\n"
            "if pid==0:\n"
            " os.setsid();time.sleep(60);os._exit(0)\n"
            f"Path({str(orphan)!r}).write_text(str(pid));os._exit(0)"
        )
        owned_code = "import time;time.sleep(60)"
        stage = "foreign-family"
        stdout = self.root / stage / "stdout"
        foreign = None
        try:
            foreign = subprocess.Popen(
                (sys.executable, "-c", foreign_code), stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
            deadline = time.monotonic() + 5
            while not ready.exists() and time.monotonic() < deadline:
                time.sleep(.01)
            self.assertTrue(ready.exists(), "pre-existing family did not start")
            self.assertIsNone(foreign.poll())
            code = (
                "import time,subprocess,sys;from pathlib import Path;"
                f"Path({str(started)!r}).write_text('started');"
                f"orphan=Path({str(orphan)!r});deadline=time.monotonic()+5\n"
                "while not orphan.exists():\n"
                " if time.monotonic()>deadline: raise RuntimeError('foreign child not created')\n"
                " time.sleep(.01)\n"
                "pid=int(orphan.read_text())\n"
                f"while int(Path(f'/proc/{{pid}}/stat').read_text().rsplit(')',1)[1].split()[1])!={os.getpid()}:\n"
                " if time.monotonic()>deadline: raise RuntimeError('foreign child not orphaned')\n"
                " time.sleep(.01)\n"
                f"p=subprocess.Popen([sys.executable,'-c',{owned_code!r}],start_new_session=True);"
                "print(p.pid,flush=True);sys.exit(0)"
            )
            command = shadow.Command(stage, (sys.executable, "-c", code),
                                     str(self.root), timeout_seconds=3)
            with self.assertRaisesRegex(shadow.Refusal, "failed stage"):
                shadow.execute(command, self.root, {"PATH": os.environ["PATH"]})
            receipt = shadow.decode(shadow.read(self.root / stage / "receipt.json"))
            self.assertEqual(receipt["failure"], "command timed out")
            self.assertEqual(receipt["exit_status"], 0)
            self.assertTrue(receipt["cleanup"]["complete"])
            self.assertEqual(receipt["cleanup"]["failures"], [])
            self.assertEqual(foreign.wait(timeout=5), 0, "foreign parent status changed")
            foreign_pid = int(orphan.read_text())
            self.assertEqual(os.waitpid(foreign_pid, os.WNOHANG), (0, 0),
                             "foreign orphan terminated or was reaped by capture")
            fields = Path(f"/proc/{foreign_pid}/stat").read_text().rsplit(")", 1)[1].split()
            self.assertEqual(int(fields[1]), os.getpid())
            self.assertNotIn(fields[0], ("T", "t", "Z"), "foreign orphan was stopped or killed")
            self.assertNotIn(foreign_pid, [event["pid"] for event in receipt["cleanup"]["processes"]])
            own_pid = int(shadow.read(stdout).strip())
            event = next(value for value in receipt["cleanup"]["processes"] if value["pid"] == own_pid)
            self.assertTrue(event["reaped"])
            self.assertEqual(event["exit_status"], -signal.SIGKILL)
            self.assertFalse(Path(f"/proc/{own_pid}").exists())
            current = ctypes.c_int()
            self.assertEqual(libc.prctl(37, ctypes.byref(current), 0, 0, 0), 0)
            self.assertEqual(current.value, 1, "capture changed caller subreaper state")
        finally:
            try:
                if foreign is not None:
                    if foreign.poll() is None:
                        foreign.kill()
                    foreign.wait(timeout=5)
                if orphan.exists():
                    self.cleanup_python_child(int(orphan.read_text()), foreign_code)
                if stdout.exists() and stdout.read_bytes().strip().isdigit():
                    self.cleanup_python_child(int(stdout.read_bytes().strip()), owned_code)
            finally:
                self.assertEqual(libc.prctl(36, previous.value, 0, 0, 0), 0)

    def test_synthetic_cleanup_failure_preserves_primary_failure_and_refuses_success(self):
        original = signal.pidfd_send_signal
        refused_once = False

        def refuse_stop(descriptor, sig):
            nonlocal refused_once
            if sig == signal.SIGSTOP and not refused_once:
                refused_once = True
                raise PermissionError("synthetic stop refusal")
            return original(descriptor, sig)

        command = shadow.Command(
            "cleanup-failure", (sys.executable, "-c", "import time;time.sleep(60)"),
            str(self.root), timeout_seconds=1)
        with mock.patch.object(shadow.bounded_process.signal, "pidfd_send_signal", side_effect=refuse_stop):
            with self.assertRaisesRegex(shadow.Refusal, "failed stage"):
                shadow.execute(command, self.root, {"PATH": os.environ["PATH"]})
        receipt = shadow.decode(shadow.read(self.root / "cleanup-failure/receipt.json"))
        self.assertEqual(receipt["failure"], "command timed out")
        self.assertTrue(receipt["cleanup"]["complete"])
        self.assertTrue(any("synthetic stop refusal" in entry["error"]
                            for entry in receipt["cleanup"]["failures"]))
        self.assertTrue(all(entry["reaped"] for entry in receipt["cleanup"]["processes"]))

    def test_synthetic_worker_failure_retains_unconfirmed_cleanup_and_refuses_success(self):
        command = shadow.Command(
            "worker-failure", (sys.executable, "-c", "pass"), str(self.root), timeout_seconds=1)
        with mock.patch.object(shadow.bounded_process, "worker",
                               side_effect=lambda *args: os._exit(9)):
            with self.assertRaisesRegex(shadow.Refusal, "failed stage"):
                shadow.execute(command, self.root, {"PATH": os.environ["PATH"]})
        receipt = shadow.decode(shadow.read(self.root / "worker-failure/receipt.json"))
        self.assertEqual(receipt["failure"], "capture worker failed; cleanup unconfirmed")
        self.assertIsNone(receipt["exit_status"], "unexecuted command cannot claim original status")
        self.assertFalse(receipt["cleanup"]["complete"])
        self.assertEqual(receipt["cleanup"]["failures"], [{
            "operation": "capture-wrapper", "error": "capture worker failed; cleanup unconfirmed",
        }])
        self.assertEqual(receipt["stdout"]["size"], 0)
        self.assertEqual(receipt["stderr"]["size"], 0)

    def test_oracle_custody_closure_binds_historical_fixture_and_optional_run_py(self):
        producer = self.root / "producer"
        reader = self.root / "reader"
        for repository in (producer, reader):
            ci_dir = repository / "support/build/wamr-native-ci"
            ci_dir.mkdir(parents=True, exist_ok=True)
            for name in ("handoff.py", "public_bundle.py", "accepted_records.py"):
                (ci_dir / name).write_text("# fixture\n", encoding="utf-8")
        base_before = {
            str(shadow.HERE / "handoff_shadow.py"): {},
            str(shadow.HERE / "historical_controller_fixture.py"): {},
            str(shadow.BOUNDED_PROCESS_PATH): {},
        }
        for repository in (producer, reader):
            for name in ("handoff.py", "public_bundle.py", "accepted_records.py"):
                base_before[str(repository / "support/build/wamr-native-ci" / name)] = {}
        shadow.assert_oracle_custody_closure(base_before, producer, reader)
        for missing_key, expected in (
            (str(shadow.HERE / "handoff_shadow.py"), "unbound test driver"),
            (
                str(shadow.HERE / "historical_controller_fixture.py"),
                "unbound frozen Python oracle closure",
            ),
            (str(shadow.BOUNDED_PROCESS_PATH), "unbound shared capture helper"),
            (
                str(producer / "support/build/wamr-native-ci/handoff.py"),
                "unbound frozen Python oracle closure",
            ),
            (
                str(reader / "support/build/wamr-native-ci/accepted_records.py"),
                "unbound frozen Python oracle closure",
            ),
        ):
            reduced = dict(base_before)
            reduced.pop(missing_key)
            with self.assertRaisesRegex(shadow.Refusal, expected):
                shadow.assert_oracle_custody_closure(reduced, producer, reader)
        legacy_run_py = producer / "support/build/wamr-native-ci/run.py"
        legacy_run_py.write_text("# historical working-tree run.py\n", encoding="utf-8")
        with self.assertRaisesRegex(shadow.Refusal, "unbound frozen Python oracle closure"):
            shadow.assert_oracle_custody_closure(base_before, producer, reader)
        with_legacy = dict(base_before)
        with_legacy[str(legacy_run_py)] = {}
        shadow.assert_oracle_custody_closure(with_legacy, producer, reader)


def main():
    global COMPARATOR, PUBLICATION_PARSER, SCRATCH
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--comparator", required=True)
    parser.add_argument("--scratch", required=True)
    parser.add_argument("--publication-parser")
    args, remaining = parser.parse_known_args()
    COMPARATOR = shadow.absolute(str(Path(args.comparator).resolve(strict=True)))
    if args.publication_parser is not None:
        PUBLICATION_PARSER = shadow.absolute(str(Path(args.publication_parser).resolve(strict=True)))
    SCRATCH = shadow.private(args.scratch)
    print("SYNTHETIC ONLY: comparator/driver validation; genuine parity not run.", flush=True)
    return not unittest.main(argv=[sys.argv[0], *remaining], exit=False).result.wasSuccessful()


if __name__ == "__main__":
    sys.exit(main())
