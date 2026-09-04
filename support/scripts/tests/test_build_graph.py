#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import unittest


REPO = Path(__file__).resolve().parents[3]
SCRIPT = REPO / "support/scripts/build-graph.py"
FIXTURE = REPO / "support/scripts/tests/fixtures/build-graph-app"


class BuildGraphSerializerTest(unittest.TestCase):
    def setUp(self):
        self.work = REPO / "build" / f"build-graph-test-{os.getpid()}"
        self.work.mkdir(parents=True, exist_ok=True)

    def tearDown(self):
        shutil.rmtree(self.work, ignore_errors=True)

    def test_serializer_escapes_and_sorts(self):
        records = self.work / "records"
        output = self.work / "graph.json"
        rows = [
            ["format", "1"],
            ["root", "build", str(self.work)],
            ["root", "unikraft", str(REPO)],
            ["context", "architecture", 'x86_64"quoted'],
            [
                "platform",
                "kvm",
                str(REPO / "plat/kvm"),
                str(REPO / "plat/kvm/Linker.uk"),
            ],
            ["platform-library", "kvm", "libz"],
            [
                "library",
                "libz",
                "platform",
                str(REPO / "lib/ukstore"),
                str(self.work / "libz"),
            ],
            ["library-object", "libz", str(self.work / "libz/z.isr.o")],
            [
                "source",
                "libz",
                str(REPO / r'quote"name.c|isr'),
                str(REPO / r'quote"name.c'),
                "",
                "isr",
                "",
                str(self.work / "libz/z.isr.o"),
            ],
            [
                "source",
                "libz",
                str(REPO / "gen.awk>.h"),
                str(REPO / "gen.awk"),
                ".h",
                "",
                str(self.work / "libz/gen.h"),
            ],
            [
                "source-dependency",
                "libz",
                str(REPO / "gen.awk>.h"),
                "",
                "generated",
                str(REPO / r"input\name"),
            ],
            ["debug-output", str(self.work / "z.dbg")],
            ["image-output", str(self.work / "z")],
        ]
        with records.open("w", encoding="utf-8", newline="\n") as stream:
            for row in rows:
                stream.write("\t".join(row + [""] * (10 - len(row))) + "\n")

        subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                "--input",
                str(records),
                "--output",
                str(output),
            ],
            check=True,
        )
        raw = output.read_text(encoding="utf-8")
        graph = json.loads(raw)

        self.assertIn(r'quote\"name.c', raw)
        self.assertIn(r'input\\name', raw)
        self.assertEqual(graph["schema_version"], 1)
        self.assertEqual(graph["platforms"][0]["libraries"], ["libz"])
        self.assertEqual(
            graph["libraries"][0]["sources"][0]["preprocess_suffix"], ".h"
        )
        self.assertEqual(
            graph["libraries"][0]["sources"][0]["variants"][0][
                "generated_dependencies"
            ],
            [r"$UK_BASE/input\name"],
        )


class BuildGraphMakeTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.work = REPO / "build" / f"build-graph-integration-{os.getpid()}"
        cls.config = cls.work / ".config"
        cls.work.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(FIXTURE / "defconfig", cls.config)
        common = [
            "make",
            "-C",
            str(REPO),
            f"A={FIXTURE}",
            f"O={cls.work}",
            f"C={cls.config}",
        ]
        subprocess.run(
            common + ["build-graph"],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.work, ignore_errors=True)

    def test_make_export_is_stable_and_complete(self):
        output = self.work / "build-graph.json"
        first = output.read_bytes()
        subprocess.run(
            [
                "make",
                "-C",
                str(REPO),
                f"A={FIXTURE}",
                f"O={self.work}",
                f"C={self.config}",
                "build-graph",
            ],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        self.assertEqual(first, output.read_bytes())

        graph = json.loads(first)
        self.assertEqual(graph["context"]["architecture"], "x86_64")
        self.assertEqual(graph["context"]["image_name"], "graph-fixture")
        self.assertEqual([item["name"] for item in graph["platforms"]], ["kvm"])
        self.assertIn("libkvmplat", graph["platforms"][0]["libraries"])

        libraries = {item["name"]: item for item in graph["libraries"]}
        self.assertIn("libgraphfixture", libraries)
        self.assertIn("libkvmplat", libraries)
        fixture_sources = libraries["libgraphfixture"]["sources"]
        main = next(item for item in fixture_sources if item["path"].endswith("/main.c"))
        self.assertEqual(
            [variant["name"] for variant in main["variants"]], ["default", "isr"]
        )
        self.assertTrue(
            all(variant["object"].endswith(".o") for variant in main["variants"])
        )

        generated = next(
            item for item in fixture_sources if item["path"].endswith("/generated.awk")
        )
        self.assertEqual(generated["preprocess_suffix"], ".h")
        self.assertTrue(
            generated["variants"][0]["generated_output"].endswith("/generated.h")
        )
        self.assertTrue(
            any(
                dependency.endswith("/generated-input.txt")
                for dependency in generated["variants"][0]["generated_dependencies"]
            )
        )

        self.assertTrue(graph["linker_scripts"])
        self.assertTrue(any(path.endswith(".lds") for path in graph["linker_scripts"]))
        self.assertTrue(
            any(path.endswith(".dbg") for path in graph["outputs"]["debug"])
        )
        self.assertTrue(
            any("graph-fixture_qemu-x86_64" in path for path in graph["outputs"]["images"])
        )
        self.assertEqual(graph["outputs"]["auxiliary"], ["$BUILD_DIR/compile_commands.json"])


if __name__ == "__main__":
    unittest.main()
