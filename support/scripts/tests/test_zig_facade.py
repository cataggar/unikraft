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
import threading
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
        configured_exec_root = os.environ.get("ZIG_FACADE_TEST_EXEC_ROOT")
        cls.exec_root = (
            Path(configured_exec_root)
            if configured_exec_root
            else cls.work / "executables"
        ).resolve()
        shutil.rmtree(cls.work, ignore_errors=True)
        if cls.exec_root != cls.work and not cls.exec_root.is_relative_to(cls.work):
            shutil.rmtree(cls.exec_root, ignore_errors=True)
        cls.work.mkdir(parents=True)
        cls.exec_root.mkdir(parents=True)
        cls.exec_root.chmod(0o700)
        cls.runtime = cls.work / "runtime"
        cls.global_cache = cls.work / "global-cache"
        cls.app = cls.work / "app"
        cls.log = cls.work / "make-events.jsonl"
        cls.sleep_control = cls.work / "backend-sleep"
        cls.child_sleep_control = cls.work / "backend-child-sleep"
        cls.exec_gate = cls.work / "exec-gate"
        for path in (cls.runtime, cls.global_cache, cls.app):
            path.mkdir(parents=True)
        cls.runtime.chmod(0o755)

        cls.make = cls.exec_root / "fake-make.py"
        cls.make.write_text(
            """#!/usr/bin/env python3
import json
import os
from pathlib import Path
import subprocess
import sys
import time

log = Path(__LOG_PATH__)
sleep_control = Path(__SLEEP_CONTROL__)
child_sleep_control = Path(__CHILD_SLEEP_CONTROL__)
child_sleep = (
    child_sleep_control.read_text(encoding="utf-8").strip()
    if child_sleep_control.exists()
    else None
)
event = {
    "event": "START",
    "pid": os.getpid(),
    "argv": sys.argv[1:],
    "environment": dict(os.environ),
}
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
sleep_seconds = (
    float(sleep_control.read_text(encoding="utf-8").strip())
    if sleep_control.exists()
    else 0
)
time.sleep(sleep_seconds)
with log.open("a", encoding="utf-8") as stream:
    stream.write(json.dumps({"event": "END", "pid": os.getpid()}) + "\\n")
""".replace("__LOG_PATH__", repr(str(cls.log)))
            .replace("__SLEEP_CONTROL__", repr(str(cls.sleep_control)))
            .replace(
                "__CHILD_SLEEP_CONTROL__",
                repr(str(cls.child_sleep_control)),
            ),
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
            ):
                destination = checkout / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(REPO / relative, destination)
            for source in (REPO / "support/build").glob("*.zig"):
                shutil.copy2(source, checkout / "support/build" / source.name)
            runner = checkout / "support/build/zig-facade-runner.zig"
            runner_source = runner.read_text(encoding="utf-8")
            production_root = "const injected_runtime_root: ?[]const u8 = null;"
            if production_root not in runner_source:
                raise AssertionError("runner runtime-root injection point changed")
            production_gate = "const injected_pre_exec_gate: ?[]const u8 = null;"
            if production_gate not in runner_source:
                raise AssertionError("runner pre-exec gate injection point changed")
            runner.write_text(
                runner_source.replace(
                    production_root,
                    f'const injected_runtime_root: ?[]const u8 = "{cls.runtime}";',
                ).replace(
                    production_gate,
                    f'const injected_pre_exec_gate: ?[]const u8 = "{cls.exec_gate}";',
                ),
                encoding="utf-8",
            )
            cls.checkouts.append(checkout)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.work, ignore_errors=True)
        if cls.exec_root != cls.work and not cls.exec_root.is_relative_to(cls.work):
            shutil.rmtree(cls.exec_root, ignore_errors=True)

    def setUp(self):
        self.log.unlink(missing_ok=True)
        self.sleep_control.unlink(missing_ok=True)
        self.child_sleep_control.unlink(missing_ok=True)
        shutil.rmtree(self.exec_gate, ignore_errors=True)

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
                    goal="all",
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

    def test_make_backend_receives_only_controlled_environment(self):
        checkout = self.checkouts[0]
        cache = self.work / "environment-cache"
        output = self.work / "outputs" / "environment"
        hostile = {
            "MAKEFLAGS": "--eval=fetch\\: properclean",
            "GNUMAKEFLAGS": "--eval=fetch\\: properclean",
            "MAKEFILES": str(self.work / "hostile.mk"),
            "MFLAGS": "-e",
            "MAKEOVERRIDES": "O BUILD_DIR",
            "MAKELEVEL": "99",
            "MAKE_RESTARTS": "99",
            "MAKE_TERMOUT": "hostile",
            "MAKE_TERMERR": "hostile",
            "CC": "hostile-cc",
            "AR": "hostile-ar",
            "BUILD_DIR": "/etc",
            "_O": "/etc",
            "UK_CONFIG": "/etc/passwd",
            "CONFIG_DIR": "/etc",
            "A": "/etc",
            "O": "/etc",
            "C": "/etc/passwd",
            "HOME": str(self.work / "attacker-home"),
        }
        invocation = self.work / "invoke-environment"
        invocation.mkdir(exist_ok=True)
        result = subprocess.run(
            self.facade_command(
                checkout,
                cache,
                output,
                "-Dmake-arg=AR=zig ar",
                goal="fetch",
            ),
            cwd=invocation,
            env=self.facade_env(**hostile),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=60,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout)
        starts = [e for e in self.read_events() if e["event"] == "START"]
        self.assertEqual(len(starts), 1)
        event = starts[0]
        self.assertIn("AR=zig ar", event["argv"])
        for name in hostile:
            if name == "HOME":
                self.assertNotEqual(event["environment"].get(name), hostile[name])
            else:
                self.assertNotIn(name, event["environment"])
        self.assertLessEqual(
            set(event["environment"]),
            {"HOME", "PATH", "LANG", "LC_ALL", "LC_CTYPE"},
        )

        real_make = shutil.which("make")
        self.assertIsNotNone(real_make)
        (checkout / "Makefile").write_text(
            "fetch:\nproperclean:\n\t@rm -rf $(O)\n",
            encoding="utf-8",
        )
        injected_makefile = self.work / "injected.mk"
        injected_makefile.write_text("fetch: properclean\n", encoding="utf-8")
        aliases = {
            "MAKEFLAGS": r"--eval=fetch\:\ properclean",
            "GNUMAKEFLAGS": r"--eval=fetch\:\ properclean",
            "MAKEFILES": str(injected_makefile),
        }
        for channel, value in aliases.items():
            with self.subTest(channel=channel):
                alias_output = self.work / "outputs" / f"alias-{channel}"
                command = self.facade_command(
                    checkout,
                    cache,
                    alias_output,
                    goal="fetch",
                )
                command[
                    next(
                        index
                        for index, argument in enumerate(command)
                        if argument.startswith("-Dmake-command=")
                    )
                ] = f"-Dmake-command={real_make}"
                alias_result = subprocess.run(
                    command,
                    cwd=invocation,
                    env=self.facade_env(**{channel: value}),
                    text=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    timeout=60,
                    check=False,
                )
                self.assertEqual(alias_result.returncode, 0, alias_result.stdout)
                self.assertTrue(
                    (alias_output / ".unikraft-zig-build").is_file(),
                    f"{channel} rewrote fetch into properclean",
                )

    def test_backend_executable_uses_only_sanitized_search_path(self):
        checkout = self.checkouts[0]
        cache = self.work / "executable-resolution-cache"
        invocation = self.work / "invoke-executable-resolution"
        invocation.mkdir(exist_ok=True)
        (checkout / "Makefile").write_text(
            'fetch:\n\t@printf "%s" "$$PATH" > $(O)/backend-path\n',
            encoding="utf-8",
        )
        system_make = shutil.which("make")
        self.assertIsNotNone(system_make)
        self.assertEqual(Path(system_make).resolve(), Path("/usr/bin/make"))
        system_zig = shutil.which("zig")
        self.assertIsNotNone(system_zig)

        hostile_hit = self.work / "hostile-make-ran"
        hostile_bin = self.exec_root / "hostile;rejected-bin"
        hostile_bin.mkdir()
        hostile_bin.chmod(0o700)
        hostile_make = hostile_bin / "make"
        hostile_make.write_text(
            "#!/bin/sh\n"
            f"printf hostile > {str(hostile_hit)!r}\n"
            "exit 0\n",
            encoding="utf-8",
        )
        hostile_make.chmod(0o700)

        safe_hit = self.work / "safe-make-ran"
        safe_bin = self.exec_root / "safe-bin"
        safe_bin.mkdir()
        safe_bin.chmod(0o700)
        safe_make = safe_bin / "make"
        safe_make.write_text(
            "#!/bin/sh\n"
            f"printf safe > {str(safe_hit)!r}\n"
            f"exec {system_make} \"$@\"\n",
            encoding="utf-8",
        )
        safe_make.chmod(0o700)
        non_executable = safe_bin / "not-executable"
        non_executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        non_executable.chmod(0o600)
        symlink_make = safe_bin / "symlink-make"
        symlink_make.symlink_to(system_make)
        writable_bin = self.exec_root / "writable-parent"
        writable_bin.mkdir()
        writable_bin.chmod(0o777)
        writable_make = writable_bin / "make"
        shutil.copy2(system_make, writable_make)
        writable_make.chmod(0o700)
        intermediate_link = self.exec_root / "intermediate-link"
        intermediate_link.symlink_to(safe_bin, target_is_directory=True)

        def command_for(output, make_command):
            command = self.facade_command(
                checkout,
                cache,
                output,
                goal="fetch",
            )
            command[0] = system_zig
            command[
                next(
                    index
                    for index, argument in enumerate(command)
                    if argument.startswith("-Dmake-command=")
                )
            ] = f"-Dmake-command={make_command}"
            return command

        rejected_output = self.work / "outputs" / "rejected-path"
        rejected_path = subprocess.run(
            command_for(rejected_output, "make"),
            cwd=invocation,
            env=self.facade_env(
                PATH=f"{hostile_bin}:/usr/bin:/bin",
            ),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=60,
            check=False,
        )
        self.assertEqual(rejected_path.returncode, 0, rejected_path.stdout)
        self.assertFalse(hostile_hit.exists())
        self.assertEqual(
            (rejected_output / "backend-path").read_text(encoding="utf-8"),
            "/usr/bin:/bin",
        )

        safe_output = self.work / "outputs" / "safe-path"
        safe_path = subprocess.run(
            command_for(safe_output, "make"),
            cwd=invocation,
            env=self.facade_env(PATH=str(safe_bin)),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=60,
            check=False,
        )
        self.assertEqual(safe_path.returncode, 0, safe_path.stdout)
        self.assertEqual(safe_hit.read_text(encoding="utf-8"), "safe")
        self.assertEqual(
            (safe_output / "backend-path").read_text(encoding="utf-8"),
            str(safe_bin),
        )

        symlink_output = self.work / "outputs" / "safe-final-symlink"
        symlink = subprocess.run(
            command_for(symlink_output, "symlink-make"),
            cwd=invocation,
            env=self.facade_env(PATH=str(safe_bin)),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=60,
            check=False,
        )
        self.assertEqual(symlink.returncode, 0, symlink.stdout)
        self.assertEqual(
            (symlink_output / "backend-path").read_text(encoding="utf-8"),
            str(safe_bin),
        )

        for name, make_command, expected_error in (
            ("missing", "missing-make", "BackendExecutableNotFound"),
            ("non-executable", "not-executable", "UnsafeBackendExecutable"),
            ("writable-parent", str(writable_make), "UnsafeBackendExecutable"),
            (
                "intermediate-symlink",
                str(intermediate_link / "make"),
                "UnsafeBackendExecutable",
            ),
        ):
            with self.subTest(candidate=name):
                failed = subprocess.run(
                    command_for(self.work / "outputs" / name, make_command),
                    cwd=invocation,
                    env=self.facade_env(PATH=str(safe_bin)),
                    text=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    timeout=60,
                    check=False,
                )
                self.assertNotEqual(failed.returncode, 0)
                self.assertIn(expected_error, failed.stdout)

        absolute_output = self.work / "outputs" / "absolute-command"
        absolute = subprocess.run(
            command_for(absolute_output, system_make),
            cwd=invocation,
            env=self.facade_env(PATH=f"{hostile_bin}:/usr/bin:/bin"),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=60,
            check=False,
        )
        self.assertEqual(absolute.returncode, 0, absolute.stdout)
        self.assertFalse(hostile_hit.exists())
        self.assertEqual(
            (absolute_output / "backend-path").read_text(encoding="utf-8"),
            "/usr/bin:/bin",
        )

    def test_backend_descriptor_survives_final_entry_replacement(self):
        checkout = self.checkouts[0]
        cache = self.work / "executable-race-cache"
        output = self.work / "outputs" / "executable-race"
        result_file = self.work / "executable-race-result"
        race_bin = self.exec_root / "race-bin"
        race_bin.mkdir()
        race_bin.chmod(0o700)
        backend = race_bin / "make"
        backend.write_text(
            "#!/bin/sh\n"
            f"printf old > {str(result_file)!r}\n",
            encoding="utf-8",
        )
        backend.chmod(0o700)

        self.exec_gate.mkdir()
        (self.exec_gate / "arm").touch()
        invocation = self.work / "invoke-executable-race"
        invocation.mkdir(exist_ok=True)
        command = self.facade_command(
            checkout,
            cache,
            output,
            goal="fetch",
        )
        command[
            next(
                index
                for index, argument in enumerate(command)
                if argument.startswith("-Dmake-command=")
            )
        ] = f"-Dmake-command={backend}"
        process = subprocess.Popen(
            command,
            cwd=invocation,
            env=self.facade_env(),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        try:
            deadline = time.monotonic() + 60
            while time.monotonic() < deadline:
                if (self.exec_gate / "ready").exists():
                    break
                if process.poll() is not None:
                    stdout, _ = process.communicate()
                    self.fail(f"runner exited before pre-exec gate: {stdout}")
                time.sleep(0.01)
            else:
                self.fail("runner did not reach the pre-exec gate")

            backend.unlink()
            backend.write_text(
                "#!/bin/sh\n"
                f"printf new > {str(result_file)!r}\n",
                encoding="utf-8",
            )
            backend.chmod(0o700)
            moved_race_bin = self.exec_root / "race-bin-moved"
            race_bin.rename(moved_race_bin)
            attacker_bin = self.exec_root / "race-bin-attacker"
            attacker_bin.mkdir()
            attacker_bin.chmod(0o700)
            attacker_backend = attacker_bin / "make"
            attacker_backend.write_text(
                "#!/bin/sh\n"
                f"printf attacker > {str(result_file)!r}\n",
                encoding="utf-8",
            )
            attacker_backend.chmod(0o700)
            race_bin.symlink_to(attacker_bin, target_is_directory=True)
            (self.exec_gate / "release").touch()
            stdout, _ = process.communicate(timeout=60)
        finally:
            if process.poll() is None:
                process.kill()
                process.communicate(timeout=10)
        self.assertEqual(process.returncode, 0, stdout)
        self.assertEqual(result_file.read_text(encoding="utf-8"), "old")

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
        self.sleep_control.write_text("5", encoding="utf-8")
        first = subprocess.Popen(
            self.facade_command(
                first_checkout,
                first_cache,
                parent_output,
                goal="all",
            ),
            cwd=first_invocation,
            env=self.facade_env(
                TMPDIR=str(self.work / "ignored-temp-one"),
            ),
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
                env=self.facade_env(
                    TMPDIR=str(self.work / "ignored-temp-two"),
                ),
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
            self.sleep_control.unlink(missing_ok=True)
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
        self.sleep_control.write_text("30", encoding="utf-8")
        self.child_sleep_control.write_text("4", encoding="utf-8")
        first = subprocess.Popen(
            self.facade_command(first_checkout, first_cache, output),
            cwd=invocation,
            env=self.facade_env(),
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
            self.sleep_control.unlink(missing_ok=True)
            self.child_sleep_control.unlink(missing_ok=True)
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
        attacker_temp = self.work / "attacker-selected-temp"
        attacker_private = (
            attacker_temp / f"unikraft-zig-facade-{os.geteuid()}"
        )
        attacker_private.mkdir(parents=True)
        attacker_lock = attacker_private / "build.lock"
        attacker_lock.touch(mode=0o600)
        attacker_lock.chmod(0o600)
        default_env = self.facade_env(
            runtime_variable="TEMP",
            TEMP=str(attacker_temp),
            TMPDIR=str(self.work / "different-attacker-temp"),
            HOME=str(self.work / "attacker-home"),
            XDG_RUNTIME_DIR=str(self.work / "attacker-runtime"),
        )
        invocation = self.work / "invoke-secure-runtime"
        invocation.mkdir(exist_ok=True)

        with (
            other_lock.open("r+", encoding="utf-8") as other_stream,
            attacker_lock.open("r+", encoding="utf-8") as attacker_stream,
        ):
            fcntl.flock(other_stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
            fcntl.flock(attacker_stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
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
        self.assertIn("refusing insecure stable per-user runtime root", unsafe_temp_root.stdout)
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

    def test_build_marker_attacks_fail_without_target_modification(self):
        checkout = self.checkouts[0]
        cache = self.work / "marker-cache"
        output = self.app / "build"
        marker = output / ".unikraft-zig-build"
        victim = self.work / "marker-victim"
        victim.write_text("unchanged", encoding="utf-8")
        victim.chmod(0o600)

        initial = self.run_facade(checkout, cache, output)
        self.assertEqual(initial.returncode, 0, initial.stdout)
        self.assertEqual(marker.read_text(encoding="utf-8"), "unikraft-zig-build-v1\n")

        marker.unlink()
        marker.symlink_to(victim)
        symlink_result = self.run_facade(checkout, cache, output)
        self.assertNotEqual(symlink_result.returncode, 0)
        self.assertIn("refusing unsafe build marker", symlink_result.stdout)
        self.assertEqual(victim.read_text(encoding="utf-8"), "unchanged")
        marker.unlink()

        os.link(victim, marker)
        hardlink_result = self.run_facade(checkout, cache, output)
        self.assertNotEqual(hardlink_result.returncode, 0)
        self.assertIn("single-link regular file", hardlink_result.stdout)
        self.assertEqual(victim.read_text(encoding="utf-8"), "unchanged")
        marker.unlink()

        marker.mkdir()
        directory_result = self.run_facade(checkout, cache, output)
        self.assertNotEqual(directory_result.returncode, 0)
        self.assertIn("refusing unsafe build marker", directory_result.stdout)
        marker.rmdir()

        os.mkfifo(marker, mode=0o600)
        fifo_result = self.run_facade(checkout, cache, output)
        self.assertNotEqual(fifo_result.returncode, 0)
        self.assertIn("refusing unsafe build marker", fifo_result.stdout)
        marker.unlink()

        marker.write_text("wrong marker\n", encoding="utf-8")
        marker.chmod(0o600)
        content_result = self.run_facade(checkout, cache, output)
        self.assertNotEqual(content_result.returncode, 0)
        self.assertIn("exact facade marker content", content_result.stdout)
        marker.unlink()

        marker.write_text("unikraft-zig-build-v1\n", encoding="utf-8")
        marker.chmod(0o622)
        mode_result = self.run_facade(checkout, cache, output)
        self.assertNotEqual(mode_result.returncode, 0)
        self.assertIn("safe permissions", mode_result.stdout)
        marker.unlink()

        race_target = self.work / "marker-race-victim"
        race_target.write_text("race-unchanged", encoding="utf-8")
        stop = threading.Event()

        def replace_marker():
            while not stop.is_set():
                try:
                    marker.unlink(missing_ok=True)
                    marker.symlink_to(race_target)
                    marker.unlink(missing_ok=True)
                    marker.write_text("unikraft-zig-build-v1\n", encoding="utf-8")
                    marker.chmod(0o600)
                except FileExistsError:
                    pass

        attacker = threading.Thread(target=replace_marker)
        attacker.start()
        try:
            race_result = self.run_facade(checkout, cache, output)
            self.assertIn(race_result.returncode, (0, 1))
        finally:
            stop.set()
            attacker.join(timeout=5)
        self.assertFalse(attacker.is_alive())
        self.assertEqual(race_target.read_text(encoding="utf-8"), "race-unchanged")

        if marker.is_symlink() or marker.is_file():
            marker.unlink()
        recovered = self.run_facade(checkout, cache, output)
        self.assertEqual(recovered.returncode, 0, recovered.stdout)

    def test_runner_rejects_output_mismatch_and_phase_replacement(self):
        checkout = self.checkouts[0]
        cache = self.work / "output-identity-cache"
        parent = self.work / "output-identity-parent"
        output = parent / "build"
        initial = self.run_facade(checkout, cache, output)
        self.assertEqual(initial.returncode, 0, initial.stdout)

        runners = [
            path
            for path in cache.rglob("unikraft-zig-make")
            if path.is_file() and os.access(path, os.X_OK)
        ]
        self.assertEqual(len(runners), 1, runners)
        runner = runners[0]
        self.log.unlink(missing_ok=True)

        mismatch = subprocess.run(
            [
                str(runner),
                str(output),
                str(self.make),
                "--no-print-directory",
                "all",
                f"A={self.app.resolve()}",
                f"O={(self.work / 'different-output').resolve()}",
            ],
            cwd=self.work,
            env=self.facade_env(),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=30,
            check=False,
        )
        self.assertNotEqual(mismatch.returncode, 0)
        self.assertIn("output mismatch", mismatch.stdout)
        self.assertEqual(self.read_events(), [])

        moved = self.work / "output-identity-parent-moved"
        victim = self.work / "output-identity-victim"
        victim.mkdir()
        sentinel = victim / "must-survive"
        sentinel.write_text("unchanged", encoding="utf-8")
        parent.rename(moved)
        parent.symlink_to(victim, target_is_directory=True)
        replaced = subprocess.run(
            [
                str(runner),
                str(output),
                str(self.make),
                "--no-print-directory",
                "all",
                f"A={self.app.resolve()}",
                f"O={output}",
            ],
            cwd=self.work,
            env=self.facade_env(),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=30,
            check=False,
        )
        self.assertNotEqual(replaced.returncode, 0)
        self.assertIn("output mismatch", replaced.stdout)
        self.assertEqual(sentinel.read_text(encoding="utf-8"), "unchanged")
        self.assertFalse((victim / "build").exists())
        self.assertEqual(self.read_events(), [])
        parent.unlink()
        moved.rename(parent)

    def test_destructive_steps_refuse_intermediate_path_replacement(self):
        checkout = self.checkouts[0]
        cache = self.work / "destructive-refusal-cache"
        output_parent = self.work / "destructive-output-parent"
        output = output_parent / "build"
        output_victim = self.work / "destructive-output-victim"
        output_victim.mkdir()
        output_sentinel = output_victim / "must-survive"
        output_sentinel.write_text("output-safe", encoding="utf-8")

        initial = self.run_facade(checkout, cache, output)
        self.assertEqual(initial.returncode, 0, initial.stdout)
        before = self.read_events()

        moved_output_parent = self.work / "destructive-output-parent-moved"
        output_parent.rename(moved_output_parent)
        output_parent.symlink_to(output_victim, target_is_directory=True)
        properclean = self.run_facade(
            checkout,
            cache,
            output,
            goal="properclean",
        )
        self.assertNotEqual(properclean.returncode, 0)
        self.assertTrue(output_sentinel.is_file())
        self.assertEqual(output_sentinel.read_text(encoding="utf-8"), "output-safe")
        self.assertEqual(self.read_events(), before)

        output_parent.unlink()
        moved_output_parent.rename(output_parent)
        for goal in ("clean", "clean-libs", "properclean"):
            clean = self.run_facade(checkout, cache, output, goal=goal)
            self.assertNotEqual(clean.returncode, 0)
            self.assertIn("intentionally refused", clean.stdout)
            self.assertEqual(self.read_events(), before)

        config_parent = self.app / "config-parent"
        config_parent.mkdir()
        config = config_parent / ".config"
        config.write_text("CONFIG_SAFE=y\n", encoding="utf-8")
        config_victim_parent = self.work / "destructive-config-victim"
        config_victim_parent.mkdir()
        config_victim = config_victim_parent / ".config"
        config_victim.write_text("CONFIG_VICTIM=y\n", encoding="utf-8")
        moved_config_parent = self.app / "config-parent-moved"
        config_parent.rename(moved_config_parent)
        config_parent.symlink_to(config_victim_parent, target_is_directory=True)

        distclean = self.run_facade(
            checkout,
            cache,
            output,
            f"-Dconfig={config}",
            goal="distclean",
        )
        self.assertNotEqual(distclean.returncode, 0)
        self.assertIn("intentionally refused", distclean.stdout)
        self.assertEqual(
            config_victim.read_text(encoding="utf-8"),
            "CONFIG_VICTIM=y\n",
        )
        self.assertEqual(self.read_events(), before)


if __name__ == "__main__":
    unittest.main()
