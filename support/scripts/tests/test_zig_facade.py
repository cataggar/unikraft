#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause

import json
import os
from pathlib import Path
import shutil
import subprocess
import time
import unittest


REPO = Path(__file__).resolve().parents[3]


class ZigFacadeIntegrationTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        configured_root = os.environ.get("ZIG_FACADE_TEST_ROOT")
        cls.work = (
            Path(configured_root)
            if configured_root
            else REPO / ".cache" / f"zig-facade-tests-{os.getpid()}"
        ).resolve()
        shutil.rmtree(cls.work, ignore_errors=True)
        cls.work.mkdir(parents=True)
        cls.runtime = cls.work / "runtime"
        cls.global_cache = cls.work / "global-cache"
        cls.app = cls.work / "app"
        cls.log = cls.work / "make-events.jsonl"
        for path in (cls.runtime, cls.global_cache, cls.app):
            path.mkdir(parents=True)

        cls.make = cls.work / "fake-make.py"
        cls.make.write_text(
            """#!/usr/bin/env python3
import json
import os
from pathlib import Path
import sys
import time

event = {
    "event": "START",
    "pid": os.getpid(),
    "argv": sys.argv[1:],
}
log = Path(os.environ["ZIG_FACADE_TEST_LOG"])
with log.open("a", encoding="utf-8") as stream:
    stream.write(json.dumps(event) + "\\n")
    stream.flush()
    os.fsync(stream.fileno())
time.sleep(float(os.environ.get("ZIG_FACADE_TEST_SLEEP", "0")))
with log.open("a", encoding="utf-8") as stream:
    stream.write(json.dumps({"event": "END", "pid": os.getpid()}) + "\\n")
""",
            encoding="utf-8",
        )
        cls.make.chmod(0o755)

        cls.checkouts = []
        for name in ("checkout-one", "checkout-two"):
            checkout = cls.work / name
            (checkout / "support/build").mkdir(parents=True)
            for relative in (
                "build.zig",
                "build.zig.zon",
                "support/build/zig-facade-paths.zig",
                "support/build/zig-facade-runner.zig",
            ):
                destination = checkout / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(REPO / relative, destination)
            cls.checkouts.append(checkout)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.work, ignore_errors=True)

    def setUp(self):
        self.log.unlink(missing_ok=True)

    def facade_command(self, checkout, cache, output, *extra, goal="all"):
        return [
            "zig",
            "build",
            "--build-file",
            str(checkout / "build.zig"),
            goal,
            "--cache-dir",
            str(cache),
            "--global-cache-dir",
            str(self.global_cache),
            f"-Dapp={self.app}",
            f"-Doutput={output}",
            f"-Dmake-command={self.make}",
            *extra,
        ]

    def facade_env(self, **overrides):
        env = os.environ.copy()
        env.update(
            {
                "TMPDIR": str(self.runtime),
                "ZIG_GLOBAL_CACHE_DIR": str(self.global_cache),
                "ZIG_FACADE_TEST_LOG": str(self.log),
            }
        )
        env.update(overrides)
        return env

    def run_facade(self, checkout, cache, output, *extra, goal="all"):
        invocation = self.work / f"invoke-{checkout.name}"
        invocation.mkdir(exist_ok=True)
        return subprocess.run(
            self.facade_command(checkout, cache, output, *extra, goal=goal),
            cwd=invocation,
            env=self.facade_env(),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=60,
            check=False,
        )

    def read_events(self):
        if not self.log.exists():
            return []
        return [
            json.loads(line)
            for line in self.log.read_text(encoding="utf-8").splitlines()
        ]

    def test_metacharacters_never_reach_make(self):
        checkout = self.checkouts[0]
        cache = self.work / "metachar-cache"
        safe_output = self.work / "outputs" / "safe-_.+@"
        safe = self.run_facade(
            checkout,
            cache,
            safe_output,
            "-Dimage-name=safe-_.+@name",
            f"-Dexternal-lib={self.work / 'lib-one'}",
            f"-Dexternal-lib={self.work / 'lib_two'}",
        )
        self.assertEqual(safe.returncode, 0, safe.stdout)
        starts = [e for e in self.read_events() if e["event"] == "START"]
        self.assertEqual(len(starts), 1)
        self.assertIn("N=safe-_.+@name", starts[0]["argv"])
        self.assertIn(
            f"L={self.work / 'lib-one'}:{self.work / 'lib_two'}",
            starts[0]["argv"],
        )

        unsafe_suffixes = (
            ";true",
            "$(true)",
            "`true`",
            "*",
            "#comment",
            "%pattern",
            '"quoted',
            "'quoted",
            "\\escaped",
            "\nnext",
        )
        for suffix in unsafe_suffixes:
            with self.subTest(value=suffix):
                before = self.read_events()
                result = self.run_facade(
                    checkout,
                    cache,
                    f"{self.work}/outputs/victim{suffix}",
                    goal="properclean" if suffix == ";true" else "all",
                )
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assertIn("Make-safe character allowlist", result.stdout)
                self.assertEqual(self.read_events(), before)

        forwarded = self.run_facade(
            checkout,
            cache,
            self.work / "outputs" / "forwarded",
            "-Dmake-arg=UK_CFLAGS=$(shell true)",
        )
        self.assertNotEqual(forwarded.returncode, 0, forwarded.stdout)
        self.assertEqual(
            len([e for e in self.read_events() if e["event"] == "START"]),
            1,
        )

    def test_parent_and_nested_outputs_share_one_persistent_lock(self):
        first_checkout, second_checkout = self.checkouts
        first_cache = self.work / "cache-one"
        second_cache = self.work / "cache-two"
        parent_output = self.work / "outputs" / "parent"
        nested_output = parent_output / "nested"

        for checkout, cache, output in (
            (first_checkout, first_cache, parent_output),
            (second_checkout, second_cache, nested_output),
        ):
            result = self.run_facade(checkout, cache, output)
            self.assertEqual(result.returncode, 0, result.stdout)

        self.log.unlink(missing_ok=True)
        first_invocation = self.work / "invoke-concurrent-one"
        second_invocation = self.work / "invoke-concurrent-two"
        first_invocation.mkdir(exist_ok=True)
        second_invocation.mkdir(exist_ok=True)
        first = subprocess.Popen(
            self.facade_command(
                first_checkout,
                first_cache,
                parent_output,
                goal="properclean",
            ),
            cwd=first_invocation,
            env=self.facade_env(ZIG_FACADE_TEST_SLEEP="5"),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        try:
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                if any(e["event"] == "START" for e in self.read_events()):
                    break
                time.sleep(0.05)
            else:
                self.fail("first facade process did not reach the fake Make backend")

            second = subprocess.run(
                self.facade_command(
                    second_checkout,
                    second_cache,
                    nested_output,
                ),
                cwd=second_invocation,
                env=self.facade_env(),
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                timeout=30,
                check=False,
            )
            self.assertNotEqual(second.returncode, 0, second.stdout)
            self.assertIn("another Make-backed Zig facade process", second.stdout)
            self.assertEqual(
                len([e for e in self.read_events() if e["event"] == "START"]),
                1,
            )
        finally:
            first_stdout, _ = first.communicate(timeout=15)
        self.assertEqual(first.returncode, 0, first_stdout)

        lock = self.runtime.resolve() / "unikraft-zig-facade.lock"
        self.assertTrue(lock.is_file())
        self.assertFalse(lock.is_relative_to(parent_output.resolve()))


if __name__ == "__main__":
    unittest.main()
