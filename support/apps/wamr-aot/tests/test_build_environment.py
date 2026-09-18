# SPDX-License-Identifier: BSD-3-Clause
import importlib.util
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

spec = importlib.util.spec_from_file_location(
    "build_image", Path(__file__).resolve().parents[1] / "build-image.py")
build_image = importlib.util.module_from_spec(spec)
spec.loader.exec_module(build_image)


class NativeMakeEnvironment(unittest.TestCase):
    def test_explicit_private_bison_data_wins(self):
        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory).resolve())
            with mock.patch.dict(os.environ, {"BISON_PKGDATADIR": path}), \
                    mock.patch.object(build_image.subprocess, "check_output") as command:
                self.assertEqual(build_image.bison_data(), path)
                command.assert_not_called()

    def test_default_queries_selected_bison(self):
        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory).resolve())
            with mock.patch.dict(os.environ, {}, clear=True), \
                    mock.patch.object(build_image, "tool", return_value="/fixture/bison"), \
                    mock.patch.object(build_image.subprocess, "check_output",
                                      return_value=path + "\n") as command:
                self.assertEqual(build_image.bison_data(), path)
                command.assert_called_once_with(
                    ["/fixture/bison", "--print-datadir"], text=True)

    def test_invalid_override_never_falls_back(self):
        with tempfile.TemporaryDirectory() as directory:
            file = Path(directory) / "not-a-directory"
            file.write_bytes(b"fixture")
            for value in ("", "relative", str(file), str(file) + "-missing"):
                with self.subTest(value=value), \
                        mock.patch.dict(os.environ, {"BISON_PKGDATADIR": value}), \
                        mock.patch.object(build_image.subprocess, "check_output") as command:
                    with self.assertRaises((ValueError, FileNotFoundError)):
                        build_image.bison_data()
                    command.assert_not_called()

    def test_outer_zig_caches_stay_below_the_precreated_build_root(self):
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory) / "repository"
            root = repository / "support/apps/wamr-aot"
            root.mkdir(parents=True)
            (root / ".config").write_bytes(b"CONFIG_FIXTURE=y\n")
            with mock.patch.object(build_image, "ROOT", root), \
                    mock.patch.object(build_image, "REPO", repository), \
                    mock.patch.object(build_image, "bison_data",
                                      return_value="/tools/bison-data"), \
                    mock.patch.object(build_image, "tool",
                                      side_effect=lambda name: "/tools/" + name), \
                    mock.patch.object(build_image.subprocess, "run") as command, \
                    mock.patch.object(sys, "argv",
                                      ["build-image.py", "olddefconfig"]):
                build_image.main()

            args = command.call_args.args[0]
            state = root / "build/native-environment"
            self.assertEqual(
                args[args.index("--cache-dir") + 1],
                str(state / "zig_local_cache"),
            )
            self.assertEqual(
                args[args.index("--global-cache-dir") + 1],
                str(state / "zig_global_cache"),
            )
            self.assertEqual(command.call_args.kwargs["cwd"], repository)
            self.assertEqual(
                command.call_args.kwargs["env"]["TMPDIR"],
                str(state / "tmp"),
            )
