# SPDX-License-Identifier: BSD-3-Clause
import importlib.util
import os
from pathlib import Path
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
