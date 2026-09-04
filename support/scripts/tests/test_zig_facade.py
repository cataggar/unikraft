#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause

import fcntl
import json
import os
from pathlib import Path
import shutil
import signal
import stat
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
        cls.runtime.chmod(0o755)

        cls.make = cls.work / "fake-make.py"
        cls.make.write_text(
            """#!/usr/bin/env python3
import json
import os
from pathlib import Path
import subprocess
import sys
import time

child_sleep = os.environ.get("ZIG_FACADE_TEST_CHILD_SLEEP")
event = {
    "event": "START",
    "pid": os.getpid(),
    "argv": sys.argv[1:],
}
log = Path(os.environ["ZIG_FACADE_TEST_LOG"])
if child_sleep:
    child_code = '''
import json
import os
from pathlib import Path
import sys
import time

log = Path(sys.argv[1])
with log.open("a", encoding="utf-8") as stream:
    stream.write(json.dumps({"event": "CHILD_START", "pid": os.getpid()}) + "\\\\n")
    stream.flush()
    os.fsync(stream.fileno())
time.sleep(float(sys.argv[2]))
with log.open("a", encoding="utf-8") as stream:
    stream.write(json.dumps({"event": "CHILD_END", "pid": os.getpid()}) + "\\\\n")
'''
    child = subprocess.Popen(
        [sys.executable, "-c", child_code, str(log), child_sleep],
        close_fds=False,
    )
    event["child_pid"] = child.pid
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

    def facade_env(self, runtime_variable="TMPDIR", **overrides):
        env = os.environ.copy()
        for name in ("TMPDIR", "TEMP", "TMP"):
            env.pop(name, None)
        env.update(
            {
                "ZIG_GLOBAL_CACHE_DIR": str(self.global_cache),
                "ZIG_FACADE_TEST_LOG": str(self.log),
            }
        )
        env[runtime_variable] = str(self.runtime)
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

        lock = (
            self.runtime.resolve()
            / f"unikraft-zig-facade-{os.geteuid()}"
            / "build.lock"
        )
        self.assertTrue(lock.is_file())
        self.assertFalse(lock.is_relative_to(parent_output.resolve()))

    def test_backend_tree_retains_lock_after_runner_pid_is_killed(self):
        first_checkout, second_checkout = self.checkouts
        first_cache = self.work / "lifetime-cache-one"
        second_cache = self.work / "lifetime-cache-two"
        output = self.work / "outputs" / "lifetime"

        for checkout, cache in (
            (first_checkout, first_cache),
            (second_checkout, second_cache),
        ):
            result = self.run_facade(checkout, cache, output)
            self.assertEqual(result.returncode, 0, result.stdout)

        self.log.unlink(missing_ok=True)
        invocation = self.work / "invoke-lifetime"
        invocation.mkdir(exist_ok=True)
        first = subprocess.Popen(
            self.facade_command(first_checkout, first_cache, output),
            cwd=invocation,
            env=self.facade_env(
                ZIG_FACADE_TEST_SLEEP="30",
                ZIG_FACADE_TEST_CHILD_SLEEP="4",
            ),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        try:
            deadline = time.monotonic() + 10
            start = None
            while time.monotonic() < deadline:
                start = next(
                    (e for e in self.read_events() if e["event"] == "START"),
                    None,
                )
                if start is not None and start.get("child_pid"):
                    break
                time.sleep(0.05)
            else:
                self.fail("backend did not start its sleeping child")

            os.kill(start["pid"], signal.SIGKILL)
            time.sleep(0.1)
            os.kill(start["child_pid"], 0)
            blocked = self.run_facade(second_checkout, second_cache, output)
            self.assertNotEqual(blocked.returncode, 0, blocked.stdout)
            self.assertIn("another Make-backed Zig facade process", blocked.stdout)
            self.assertEqual(
                len([e for e in self.read_events() if e["event"] == "START"]),
                1,
            )

            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                if any(e["event"] == "CHILD_END" for e in self.read_events()):
                    break
                time.sleep(0.05)
            else:
                self.fail("orphaned backend child did not finish")
        finally:
            first_stdout, _ = first.communicate(timeout=10)
        self.assertNotEqual(first.returncode, 0, first_stdout)

        recovered = self.run_facade(second_checkout, second_cache, output)
        self.assertEqual(recovered.returncode, 0, recovered.stdout)
        self.assertEqual(
            len([e for e in self.read_events() if e["event"] == "START"]),
            2,
        )

    def test_uid_private_runtime_rejects_unsafe_preexisting_state(self):
        checkout = self.checkouts[0]
        cache = self.work / "secure-runtime-cache"
        output = self.work / "outputs" / "secure-runtime"
        private = self.runtime / f"unikraft-zig-facade-{os.geteuid()}"
        simulated_other = self.runtime / f"unikraft-zig-facade-{os.geteuid() + 1}"

        simulated_other.mkdir(mode=0o700)
        other_lock = simulated_other / "build.lock"
        other_lock.touch(mode=0o600)
        other_lock.chmod(0o600)
        default_env = self.facade_env(runtime_variable="TEMP")
        invocation = self.work / "invoke-secure-runtime"
        invocation.mkdir(exist_ok=True)

        with other_lock.open("r+", encoding="utf-8") as other_stream:
            fcntl.flock(other_stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
            first = subprocess.run(
                self.facade_command(checkout, cache, output),
                cwd=invocation,
                env=default_env,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                timeout=60,
                check=False,
            )
        self.assertEqual(first.returncode, 0, first.stdout)
        lock = private / "build.lock"
        self.assertEqual(stat.S_IMODE(private.stat().st_mode), 0o700)
        self.assertEqual(private.stat().st_uid, os.geteuid())
        self.assertEqual(stat.S_IMODE(lock.stat().st_mode), 0o600)
        self.assertEqual(lock.stat().st_uid, os.geteuid())
        self.assertEqual(lock.stat().st_nlink, 1)
        inode = lock.stat().st_ino

        repeated = subprocess.run(
            self.facade_command(checkout, cache, output),
            cwd=invocation,
            env=default_env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=60,
            check=False,
        )
        self.assertEqual(repeated.returncode, 0, repeated.stdout)
        self.assertEqual(lock.stat().st_ino, inode)

        shutil.rmtree(private)
        symlink_target = self.work / "symlink-directory-target"
        symlink_target.mkdir()
        private.symlink_to(symlink_target, target_is_directory=True)
        symlink_directory = subprocess.run(
            self.facade_command(checkout, cache, output),
            cwd=invocation,
            env=default_env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=60,
            check=False,
        )
        self.assertNotEqual(symlink_directory.returncode, 0)
        self.assertIn("insecure UID-scoped", symlink_directory.stdout)
        private.unlink()

        private.mkdir(mode=0o755)
        private.chmod(0o755)
        wrong_directory_mode = subprocess.run(
            self.facade_command(checkout, cache, output),
            cwd=invocation,
            env=default_env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=60,
            check=False,
        )
        self.assertNotEqual(wrong_directory_mode.returncode, 0)
        self.assertIn("current-user-owned 0700", wrong_directory_mode.stdout)
        private.chmod(0o700)

        lock_target = self.work / "symlink-lock-target"
        lock_target.write_text("do not follow", encoding="utf-8")
        lock.symlink_to(lock_target)
        symlink_lock = subprocess.run(
            self.facade_command(checkout, cache, output),
            cwd=invocation,
            env=default_env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=60,
            check=False,
        )
        self.assertNotEqual(symlink_lock.returncode, 0)
        self.assertIn("insecure Zig facade lock file", symlink_lock.stdout)
        lock.unlink()

        lock.touch(mode=0o644)
        lock.chmod(0o644)
        wrong_lock_mode = subprocess.run(
            self.facade_command(checkout, cache, output),
            cwd=invocation,
            env=default_env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=60,
            check=False,
        )
        self.assertNotEqual(wrong_lock_mode.returncode, 0)
        self.assertIn("current-user-owned 0600", wrong_lock_mode.stdout)
        lock.chmod(0o600)

        hardlink = private / "build-link"
        os.link(lock, hardlink)
        hardlinked_lock = subprocess.run(
            self.facade_command(checkout, cache, output),
            cwd=invocation,
            env=default_env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=60,
            check=False,
        )
        self.assertNotEqual(hardlinked_lock.returncode, 0)
        self.assertIn("with one link", hardlinked_lock.stdout)
        hardlink.unlink()
        lock.unlink()

        self.runtime.chmod(0o777)
        unsafe_temp_root = subprocess.run(
            self.facade_command(checkout, cache, output),
            cwd=invocation,
            env=default_env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=60,
            check=False,
        )
        self.assertNotEqual(unsafe_temp_root.returncode, 0)
        self.assertIn("refusing insecure temporary root", unsafe_temp_root.stdout)
        self.runtime.chmod(0o755)

        shutil.rmtree(private)
        recovered = subprocess.run(
            self.facade_command(checkout, cache, output),
            cwd=invocation,
            env=default_env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=60,
            check=False,
        )
        self.assertEqual(recovered.returncode, 0, recovered.stdout)


if __name__ == "__main__":
    unittest.main()
