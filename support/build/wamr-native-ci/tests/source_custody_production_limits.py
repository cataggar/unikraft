#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""Explicit, resource-bound production limit tests; excluded from discovery."""
import importlib.util
import os
from pathlib import Path, PurePosixPath
import shutil
import subprocess
import unittest

HERE = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("wamr_ci_production_limits",
                                               HERE / "run.py")
ci = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ci)

GIT_INVENTORY_ARGS = (
    "ls-files", "--others", "--ignored", "--exclude-standard",
    "--directory", "-z",
)


class ProductionSourceCustodyLimits(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fixture_parent = Path("/d")
        if fixture_parent.resolve(strict=True) != fixture_parent:
            raise RuntimeError("production limit fixtures require canonical /d")
        cls.fixture = fixture_parent / (
            f"wamr-native-ci-source-custody-limits-{os.getpid()}"
        )
        cls.fixture.mkdir(mode=0o700)
        cls.addClassCleanup(cls._remove_fixture)

    @classmethod
    def _remove_fixture(cls):
        expected = Path(
            f"/d/wamr-native-ci-source-custody-limits-{os.getpid()}"
        )
        if cls.fixture != expected or cls.fixture.parent != Path("/d"):
            raise RuntimeError("refusing non-PID-scoped fixture cleanup")
        if cls.fixture.exists():
            shutil.rmtree(cls.fixture)

    def git(self, repository, *args):
        subprocess.run(
            ci.git_command(*args), cwd=repository, check=True,
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            env=ci.git_environment(),
        )

    def repository(self, name, ignore):
        repository = self.fixture / name
        repository.mkdir(mode=0o700)
        (repository / ".gitignore").write_text(ignore, encoding="ascii")
        (repository / ".gitignore").chmod(0o600)
        self.git(repository, "init", "-q")
        self.git(repository, "add", ".gitignore")
        self.git(
            repository, "-c", "user.name=Fixture",
            "-c", "user.email=fixture@example.invalid",
            "commit", "-qm", "fixture",
        )
        return repository

    def inventory_size(self, repository):
        process = subprocess.Popen(
            ci.git_command(*GIT_INVENTORY_ARGS), cwd=repository,
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env=ci.git_environment(),
        )
        total = 0
        while True:
            chunk = process.stdout.read(64 * 1024)
            if not chunk:
                break
            total += len(chunk)
        process.stdout.close()
        self.assertEqual(process.wait(timeout=60), 0)
        return total

    def create_file(self, directory, name, size=0):
        descriptor = os.open(
            name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600,
            dir_fd=directory,
        )
        try:
            if size:
                os.ftruncate(descriptor, size)
        finally:
            os.close(descriptor)

    def ignored_state_repository(self):
        repository = self.repository(
            "ignored-state",
            "/.d/\n"
            "/.zig-cache/\n"
            "/support/apps/wamr-aot/.config\n"
            "/support/apps/wamr-aot/build/\n",
        )
        app = repository / "support/apps/wamr-aot"
        app.mkdir(parents=True, mode=0o700)
        (app / "defconfig").write_text("CONFIG_FIXTURE=y\n", encoding="ascii")
        (app / "defconfig").chmod(0o600)
        self.git(repository, "add", "support/apps/wamr-aot/defconfig")
        self.git(
            repository, "-c", "user.name=Fixture",
            "-c", "user.email=fixture@example.invalid",
            "commit", "-qm", "tracked application fixture",
        )
        for path in (repository / ".d", repository / ".zig-cache",
                     app / "build"):
            path.mkdir(mode=0o700)
        (app / ".config").touch(mode=0o600)
        return repository, app / "build"

    def boundary_relative(self, parts, size):
        components = [".d"] + ["d"] * (parts - 2) + ["x.ignored"]
        remaining = size - (
            sum(len(component) for component in components) + parts - 1
        )
        self.assertGreaterEqual(remaining, 0)
        for index in range(1, len(components) - 1):
            added = min(remaining, 255 - len(components[index]))
            components[index] += "x" * added
            remaining -= added
        self.assertEqual(remaining, 0)
        relative = PurePosixPath(*components)
        self.assertEqual(len(relative.as_posix().encode("utf-8")), size)
        self.assertEqual(len(relative.parts), parts)
        return relative

    def add_ignored_file(self, repository, relative):
        path = repository.joinpath(*relative.parts)
        path.parent.mkdir(parents=True, mode=0o700)
        path.touch(mode=0o600)

    def test_00_production_constants_are_unmodified(self):
        self.assertEqual(ci.SOURCE_IGNORED_MAX_ENTRIES, 131_072)
        self.assertEqual(ci.SOURCE_IGNORED_MAX_BYTES, 8 * 1024 ** 3)
        self.assertEqual(ci.SOURCE_IGNORED_GIT_MAX_BYTES, 8 * 1024 ** 2)
        self.assertEqual(ci.SOURCE_IGNORED_MAX_PATH, 1024)
        self.assertEqual(ci.SOURCE_IGNORED_MAX_DEPTH, 64)
        self.assertEqual(ci.SOURCE_DIAGNOSTIC_MAX_ROOT_ENTRIES, 128)

    def test_10_real_enumeration_entry_and_sparse_byte_boundaries(self):
        repository, build = self.ignored_state_repository()
        fixed_entries = len(ci.SOURCE_OUTPUT_ROLES)
        sparse_count, remainder = divmod(
            ci.SOURCE_IGNORED_MAX_BYTES, ci.SOURCE_IGNORED_MAX_FILE
        )
        self.assertEqual(remainder, 0)
        build_descriptor = os.open(
            build, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
        )
        try:
            for index in range(
                    ci.SOURCE_IGNORED_MAX_ENTRIES - fixed_entries):
                size = (
                    ci.SOURCE_IGNORED_MAX_FILE
                    if index < sparse_count else 0
                )
                self.create_file(
                    build_descriptor, f"entry-{index:06x}", size,
                )
        finally:
            os.close(build_descriptor)

        sparse = [
            build / f"entry-{index:06x}"
            for index in range(sparse_count)
        ]
        self.assertEqual(
            sum(path.stat().st_size for path in sparse),
            ci.SOURCE_IGNORED_MAX_BYTES,
        )
        self.assertLess(
            sum(path.stat().st_blocks * 512 for path in sparse),
            ci.SOURCE_IGNORED_MAX_BYTES,
        )

        state = ci.ignored_source_state(repository)
        self.assertEqual(state["entries"], ci.SOURCE_IGNORED_MAX_ENTRIES)
        self.assertEqual(state["bytes"], ci.SOURCE_IGNORED_MAX_BYTES)
        self.assertEqual(
            set(state["ignored"]),
            {
                ".d", ".zig-cache", "support/apps/wamr-aot/.config",
                "support/apps/wamr-aot/build",
            },
        )

        byte_excess = build / f"entry-{sparse_count:06x}"
        os.truncate(byte_excess, 1)
        with self.assertRaisesRegex(
                ci.Refusal, "^ignored source byte limit exceeded$"):
            ci.ignored_source_state(repository)
        os.truncate(byte_excess, 0)

        build_descriptor = os.open(
            build, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
        )
        try:
            self.create_file(
                build_descriptor,
                f"entry-{ci.SOURCE_IGNORED_MAX_ENTRIES - fixed_entries:06x}",
            )
        finally:
            os.close(build_descriptor)
        with self.assertRaisesRegex(
                ci.Refusal, "^ignored source entry limit exceeded$"):
            ci.ignored_source_state(repository)

    def test_20_real_git_output_byte_boundary(self):
        repository = self.repository("git-inventory", "*.ignored\n")
        lengths = (191, 190, 190, 182)
        directory = repository / ".d"
        relative_directory = PurePosixPath(".d")
        git_directories = [relative_directory]
        for character, length in zip("abcd", lengths):
            directory /= character * length
            relative_directory /= character * length
            git_directories.append(relative_directory)
        directory.mkdir(parents=True, mode=0o700)
        directory_bytes = sum(
            len(path.as_posix().encode("utf-8")) + 2
            for path in git_directories
        )
        file_prefix_bytes = (
            len(relative_directory.as_posix().encode("utf-8")) + 1
        )
        maximum_record_bytes = file_prefix_bytes + 255 + 1
        full_count, tail_bytes = divmod(
            ci.SOURCE_IGNORED_GIT_MAX_BYTES - directory_bytes,
            maximum_record_bytes,
        )
        full_count -= 1
        tail_bytes += maximum_record_bytes
        self.assertEqual(tail_bytes % 2, 0)
        short_name_bytes = tail_bytes // 2 - file_prefix_bytes - 1
        self.assertGreaterEqual(short_name_bytes, len("short-0-.ignored"))
        descriptor = os.open(
            directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
        )
        long_suffix = ".ignored"
        try:
            for index in range(full_count):
                prefix = f"{index:04x}"
                name = (
                    prefix
                    + "x" * (255 - len(prefix) - len(long_suffix))
                    + long_suffix
                )
                self.create_file(descriptor, name)
            short_names = []
            for index in range(2):
                prefix = f"short-{index}-"
                name = (
                    prefix
                    + "y" * (
                        short_name_bytes - len(prefix) - len(long_suffix)
                    )
                    + long_suffix
                )
                self.create_file(descriptor, name)
                short_names.append(name)
        finally:
            os.close(descriptor)

        self.assertEqual(
            self.inventory_size(repository),
            ci.SOURCE_IGNORED_GIT_MAX_BYTES,
        )
        paths = ci.ignored_git_roots(repository, ci.source_output_policy())
        self.assertEqual(
            sum(path.endswith(long_suffix) for path in paths), full_count + 2
        )

        longer = (
            short_names[0][:-len(long_suffix)] + "z" + long_suffix
        )
        (directory / short_names[0]).rename(directory / longer)
        self.assertEqual(
            self.inventory_size(repository),
            ci.SOURCE_IGNORED_GIT_MAX_BYTES + 1,
        )
        with self.assertRaisesRegex(
                ci.Refusal, "^ignored source inventory too large$"):
            ci.ignored_git_roots(repository, ci.source_output_policy())

    def test_30_real_git_path_and_depth_boundaries(self):
        exact_repository = self.repository("path-depth-exact", "*.ignored\n")
        exact = self.boundary_relative(
            ci.SOURCE_IGNORED_MAX_DEPTH, ci.SOURCE_IGNORED_MAX_PATH
        )
        self.add_ignored_file(exact_repository, exact)
        paths = ci.ignored_git_roots(
            exact_repository, ci.source_output_policy()
        )
        self.assertIn(exact.as_posix(), paths)

        path_repository = self.repository("path-excess", "*.ignored\n")
        path_excess = self.boundary_relative(
            ci.SOURCE_IGNORED_MAX_DEPTH, ci.SOURCE_IGNORED_MAX_PATH + 1
        )
        self.add_ignored_file(path_repository, path_excess)
        with self.assertRaisesRegex(
                ci.Refusal, "^invalid ignored source inventory$"):
            ci.ignored_git_roots(
                path_repository, ci.source_output_policy()
            )

        depth_repository = self.repository("depth-excess", "*.ignored\n")
        depth_excess = PurePosixPath(
            ".d", *(["d"] * (ci.SOURCE_IGNORED_MAX_DEPTH - 1)),
            "x.ignored",
        )
        self.assertEqual(
            len(depth_excess.parts), ci.SOURCE_IGNORED_MAX_DEPTH + 1
        )
        self.assertLessEqual(
            len(depth_excess.as_posix().encode("utf-8")),
            ci.SOURCE_IGNORED_MAX_PATH,
        )
        self.add_ignored_file(depth_repository, depth_excess)
        with self.assertRaisesRegex(
                ci.Refusal, "^invalid ignored source inventory$"):
            ci.ignored_git_roots(
                depth_repository, ci.source_output_policy()
            )

    def test_40_real_root_enumeration_128_and_129(self):
        root = self.fixture / "root-inventory"
        root.mkdir(mode=0o700)
        descriptor = os.open(
            root, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
        )
        try:
            for index in range(ci.SOURCE_DIAGNOSTIC_MAX_ROOT_ENTRIES):
                self.create_file(descriptor, f"entry-{index:03d}")
        finally:
            os.close(descriptor)

        inventory = ci.source_root_inventory(root)
        self.assertEqual(len(inventory),
                         ci.SOURCE_DIAGNOSTIC_MAX_ROOT_ENTRIES)
        self.assertTrue(all(item["kind"] == "file" for item in inventory))

        descriptor = os.open(
            root, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
        )
        try:
            self.create_file(
                descriptor,
                f"entry-{ci.SOURCE_DIAGNOSTIC_MAX_ROOT_ENTRIES:03d}",
            )
        finally:
            os.close(descriptor)
        with self.assertRaisesRegex(
                ci.Refusal, "^source root inventory too large$"):
            ci.source_root_inventory(root)


if __name__ == "__main__":
    unittest.main(verbosity=2)
