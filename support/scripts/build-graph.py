#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause

import argparse
import json
import os
import re
from pathlib import Path


COLUMNS = 10


def read_records(path):
    records = []
    with path.open(encoding="utf-8", newline="") as stream:
        for line_number, line in enumerate(stream, 1):
            fields = line.rstrip("\n").split("\t")
            if len(fields) != COLUMNS:
                raise ValueError(
                    f"{path}:{line_number}: expected {COLUMNS} tab-separated "
                    f"columns, got {len(fields)}"
                )
            records.append(fields)
    if not records or records[0][:2] != ["format", "1"]:
        raise ValueError(f"{path}: unsupported or missing record format")
    return records[1:]


def is_within(path, root):
    try:
        return os.path.commonpath((path, root)) == root
    except ValueError:
        return False


def root_token(kind, name=None):
    if kind == "build":
        return "$BUILD_DIR"
    if kind == "unikraft":
        return "$UK_BASE"
    if kind == "app":
        return "$APP_DIR"
    label = re.sub(r"[^A-Za-z0-9]+", "_", name).strip("_").upper()
    return f"${kind.upper()}_{label}_BASE"


def path_normalizer(records):
    configured = {}
    for row in records:
        if row[0] == "root" and row[2]:
            configured[row[1]] = os.path.normpath(row[2])

    roots = []
    for kind in ("build", "unikraft", "app"):
        value = configured.get(kind)
        if value and all(value != root for root, _ in roots):
            roots.append((value, root_token(kind)))

    for row in records:
        base_index = 2 if row[0] == "platform" else 3
        if row[0] not in ("library", "platform") or not row[base_index]:
            continue
        name = row[1]
        value = os.path.normpath(row[base_index])
        if not os.path.isabs(value):
            continue
        if any(is_within(value, root) for root, _ in roots):
            continue
        kind = "plat" if row[0] == "platform" else "lib"
        roots.append((value, root_token(kind, name)))

    roots.sort(key=lambda item: len(item[0]), reverse=True)

    def normalize(value):
        if not value or not os.path.isabs(value):
            return value or None
        value = os.path.normpath(value)
        for root, token in roots:
            if value == root:
                return token
            if is_within(value, root):
                return token + "/" + os.path.relpath(value, root).replace(os.sep, "/")
        return value.replace(os.sep, "/")

    return normalize


def sorted_unique(values):
    return sorted({value for value in values if value is not None})


def serialize(records):
    normalize = path_normalizer(records)
    context = {"backend": "gnu-make"}
    platforms = {}
    libraries = {}
    sources = {}
    source_dependencies = {}
    preprocess_outputs = []
    dependency_files = []
    link_dependencies = []
    linker_scripts = []
    debug_outputs = []
    image_outputs = []
    auxiliary_outputs = []

    for row in records:
        kind = row[0]
        if kind == "context":
            context[row[1]] = row[2] or None
        elif kind == "platform":
            platforms[row[1]] = {
                "name": row[1],
                "base": normalize(row[2]),
                "linker_definition": normalize(row[3]),
                "libraries": [],
                "linker_scripts": [],
            }
        elif kind == "platform-library":
            platforms[row[1]]["libraries"].append(row[2])
        elif kind == "platform-linker-script":
            platforms[row[1]]["linker_scripts"].append(normalize(row[2]))
        elif kind == "library":
            libraries[row[1]] = {
                "name": row[1],
                "kind": row[2],
                "base": normalize(row[3]),
                "build_dir": normalize(row[4]),
                "object_library": normalize(row[5]),
                "source_root": normalize(row[6]),
                "platforms": [],
                "objects": [],
                "linker_scripts": [],
                "link_dependencies": [],
                "sources": [],
            }
        elif kind == "library-platform":
            libraries[row[1]]["platforms"].append(row[2])
        elif kind == "library-object":
            libraries[row[1]]["objects"].append(normalize(row[2]))
        elif kind == "library-linker-script":
            libraries[row[1]]["linker_scripts"].append(normalize(row[2]))
        elif kind == "library-link-dependency":
            libraries[row[1]]["link_dependencies"].append(normalize(row[2]))
        elif kind == "source":
            key = (row[1], row[2])
            entry = sources.setdefault(
                key,
                {
                    "definition": normalize(row[2]),
                    "path": normalize(row[3]),
                    "preprocess_suffix": row[4] or None,
                    "variants": [],
                },
            )
            variant_key = (row[1], row[2], row[5])
            deps = source_dependencies.get(variant_key, {})
            variant = {
                "name": row[5] or None,
                "generated_output": normalize(row[6]),
                "object": normalize(row[7]),
                "output": normalize(row[8]),
                "dependency_file": normalize(row[9]),
                "dependencies": sorted_unique(
                    normalize(value) for value in deps.get("build", [])
                ),
                "generated_dependencies": sorted_unique(
                    normalize(value) for value in deps.get("generated", [])
                ),
            }
            entry["variants"].append(variant)
        elif kind == "source-dependency":
            key = (row[1], row[2], row[3])
            source_dependencies.setdefault(key, {}).setdefault(row[4], []).append(
                row[5]
            )
        elif kind == "preprocess-output":
            preprocess_outputs.append(normalize(row[1]))
        elif kind == "dependency-file":
            dependency_files.append(normalize(row[1]))
        elif kind == "link-dependency":
            link_dependencies.append(normalize(row[1]))
        elif kind == "linker-script":
            linker_scripts.append(normalize(row[1]))
        elif kind == "debug-output":
            debug_outputs.append(normalize(row[1]))
        elif kind == "image-output":
            image_outputs.append(normalize(row[1]))
        elif kind == "auxiliary-output":
            auxiliary_outputs.append(normalize(row[1]))
        elif kind == "root":
            pass
        else:
            raise ValueError(f"unknown build graph record type: {kind}")

    # Dependency records are emitted after source records by Make. Attach them
    # in a second pass so record order does not affect the JSON.
    for (library, definition), entry in sources.items():
        for variant in entry["variants"]:
            key = (library, definition, variant["name"] or "")
            deps = source_dependencies.get(key, {})
            variant["dependencies"] = sorted_unique(
                normalize(value) for value in deps.get("build", [])
            )
            variant["generated_dependencies"] = sorted_unique(
                normalize(value) for value in deps.get("generated", [])
            )
        entry["variants"].sort(key=lambda item: item["name"] or "")
        libraries[library]["sources"].append(entry)

    for platform in platforms.values():
        platform["libraries"] = sorted_unique(platform["libraries"])
        platform["linker_scripts"] = sorted_unique(platform["linker_scripts"])

    for library in libraries.values():
        library["platforms"] = sorted_unique(library["platforms"])
        library["objects"] = sorted_unique(library["objects"])
        library["linker_scripts"] = sorted_unique(library["linker_scripts"])
        library["link_dependencies"] = sorted_unique(library["link_dependencies"])
        library["sources"].sort(
            key=lambda item: (item["path"] or "", item["definition"] or "")
        )

    return {
        "schema_version": 1,
        "context": context,
        "platforms": sorted(platforms.values(), key=lambda item: item["name"]),
        "libraries": sorted(libraries.values(), key=lambda item: item["name"]),
        "preprocess_outputs": sorted_unique(preprocess_outputs),
        "dependency_files": sorted_unique(dependency_files),
        "link_dependencies": sorted_unique(link_dependencies),
        "linker_scripts": sorted_unique(linker_scripts),
        "outputs": {
            "auxiliary": sorted_unique(auxiliary_outputs),
            "debug": sorted_unique(debug_outputs),
            "images": sorted_unique(image_outputs),
        },
    }


def main():
    parser = argparse.ArgumentParser(
        description="Serialize Unikraft GNU Make build graph records"
    )
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    graph = serialize(read_records(args.input))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8", newline="\n") as stream:
        json.dump(graph, stream, indent=2, sort_keys=True)
        stream.write("\n")


if __name__ == "__main__":
    main()
