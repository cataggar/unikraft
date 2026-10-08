#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""Synthetic comparator/driver refusals ONLY; no producer or live parity claim."""
import argparse
import copy
import os
from pathlib import Path
import shutil
import subprocess
import sys
import unittest
import uuid
from unittest import mock

import handoff_shadow as shadow

HERE = Path(__file__).resolve().parent
COMPARATOR = None
SCRATCH = None


class ShadowWitness(unittest.TestCase):
    def setUp(self):
        self.root = SCRATCH / ("synthetic-shadow-" + str(uuid.uuid4()))
        self.root.mkdir(mode=0o700)
        self.addCleanup(shutil.rmtree, self.root)
        self.frozen, self.public = shadow.load_oracle(HERE.parents[3])

    def document(self, path, value):
        shadow.write(path, shadow.encoded(value))

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
        descendant = int(shadow.read(self.root / "timed/stdout").strip())
        status = Path(f"/proc/{descendant}/stat")
        if status.exists():
            self.assertEqual(status.read_text().split()[2], "Z", "detached descendant still running")
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
        } for stage in shadow.STAGES]
        shadow.validate_stages(receipts)
        with self.assertRaisesRegex(shadow.Refusal, "missing, skipped or reordered"):
            shadow.validate_stages(receipts[:-1])
        failed = copy.deepcopy(receipts)
        failed[3]["exit_status"] = 1
        with self.assertRaisesRegex(shadow.Refusal, "misleading partial execution"):
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


def main():
    global COMPARATOR, SCRATCH
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--comparator", required=True)
    parser.add_argument("--scratch", required=True)
    args, remaining = parser.parse_known_args()
    COMPARATOR = shadow.absolute(str(Path(args.comparator).resolve(strict=True)))
    SCRATCH = shadow.private(args.scratch)
    print("SYNTHETIC ONLY: comparator/driver validation; genuine parity not run.", flush=True)
    return not unittest.main(argv=[sys.argv[0], *remaining], exit=False).result.wasSuccessful()


if __name__ == "__main__":
    sys.exit(main())
