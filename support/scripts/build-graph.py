#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause

import argparse
import json
import os
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
    prefix = "LIB" if kind == "library" else "PLAT"
    encoded_name = name.encode("utf-8").hex().upper()
    return f"${prefix}_{encoded_name}_BASE"


def path_normalizer(records):
    configured = {}
    for row in records:
        if row[0] == "root" and row[2]:
            configured[row[1]] = os.path.normpath(row[2])

    roots = []
    for kind in ("build", "unikraft", "app"):
        value = configured.get(kind)
        if value and all(value != root for root, _, _ in roots):
            roots.append(
                (
                    value,
                    root_token(kind),
                    {"kind": kind, "token": root_token(kind)},
                )
            )

    component_roots = {}
    for row in records:
        base_index = 2 if row[0] == "platform" else 3
        if row[0] not in ("library", "platform") or not row[base_index]:
            continue
        name = row[1]
        value = os.path.normpath(row[base_index])
        if not os.path.isabs(value):
            continue
        if any(is_within(value, root) for root, _, _ in roots):
            continue
        kind = "platform" if row[0] == "platform" else "library"
        identity = (kind, name)
        previous = component_roots.get(identity)
        if previous is not None and previous != value:
            raise ValueError(
                f"{kind} {name!r} has multiple external roots: "
                f"{previous!r} and {value!r}"
            )
        component_roots[identity] = value

    tokens = {}
    for (kind, name), value in sorted(component_roots.items()):
        token = root_token(kind, name)
        previous = tokens.get(token)
        if previous is not None and previous != (kind, name):
            raise ValueError(
                f"path token {token!r} is ambiguous for {previous!r} "
                f"and {(kind, name)!r}"
            )
        tokens[token] = (kind, name)
        roots.append(
            (
                value,
                token,
                {"kind": kind, "name": name, "token": token},
            )
        )

    roots.sort(key=lambda item: len(item[0]), reverse=True)

    def normalize(value):
        if not value or not os.path.isabs(value):
            return value or None
        value = os.path.normpath(value)
        for root, token, _ in roots:
            if value == root:
                return token
            if is_within(value, root):
                return token + "/" + os.path.relpath(value, root).replace(os.sep, "/")
        return value.replace(os.sep, "/")

    path_roots = sorted(
        (metadata for _, _, metadata in roots),
        key=lambda item: item["token"],
    )
    return normalize, path_roots


def sorted_unique(values):
    return sorted({value for value in values if value is not None})


def ordered_unique(values, key=lambda value: value):
    result = []
    seen = set()
    for value in values:
        if value is None:
            continue
        identity = key(value)
        if identity in seen:
            continue
        seen.add(identity)
        result.append(value)
    return result


def serialize(records):
    normalize, path_roots = path_normalizer(records)
    context = {"backend": "gnu-make"}
    platforms = {}
    libraries = {}
    sources = {}
    source_dependencies = {}
    preprocess_outputs = []
    dependency_files = []
    link_dependencies = []
    linker_scripts = []
    final_link_inputs = []
    debug_outputs = []
    image_outputs = []
    auxiliary_outputs = []

    for row in records:
        kind = row[0]
        if kind == "context":
            context[row[1]] = row[2] or None
        elif kind == "platform":
            if row[1] in platforms:
                raise ValueError(f"duplicate platform record: {row[1]}")
            platforms[row[1]] = {
                "name": row[1],
                "base": normalize(row[2]),
                "linker_definition": normalize(row[3]),
                "libraries": [],
                "object_inputs": [],
                "archive_inputs": [],
                "linker_scripts": [],
            }
        elif kind == "platform-library":
            platforms[row[1]]["libraries"].append(row[2])
        elif kind == "platform-object-input":
            platforms[row[1]]["object_inputs"].append(normalize(row[2]))
        elif kind == "platform-archive-input":
            platforms[row[1]]["archive_inputs"].append(normalize(row[2]))
        elif kind == "platform-linker-script":
            platforms[row[1]]["linker_scripts"].append(normalize(row[2]))
        elif kind == "library":
            if row[1] in libraries:
                raise ValueError(f"duplicate library record: {row[1]}")
            libraries[row[1]] = {
                "name": row[1],
                "kind": row[2],
                "base": normalize(row[3]),
                "build_dir": normalize(row[4]),
                "object_library": normalize(row[5]),
                "source_root": normalize(row[6]),
                "platforms": [],
                "objects": [],
                "archives": [],
                "linker_scripts": [],
                "link_dependencies": [],
                "partial_link_inputs": [],
                "sources": [],
            }
        elif kind == "library-platform":
            libraries[row[1]]["platforms"].append(row[2])
        elif kind == "library-object":
            libraries[row[1]]["objects"].append(normalize(row[2]))
        elif kind == "library-archive":
            libraries[row[1]]["archives"].append(normalize(row[2]))
        elif kind == "library-link-input":
            libraries[row[1]]["partial_link_inputs"].append(
                {
                    "stage": row[2],
                    "kind": row[3],
                    "path": normalize(row[4]),
                    "origin": row[5],
                }
            )
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
        elif kind == "final-link-input":
            final_link_inputs.append(
                {
                    "kind": row[1],
                    "path": normalize(row[2]),
                    "scope": row[3],
                    "platform": row[4] or None,
                }
            )
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
        entry["variants"] = ordered_unique(
            entry["variants"],
            key=lambda item: (
                item["name"],
                item["generated_output"],
                item["object"],
                item["output"],
                item["dependency_file"],
            ),
        )
        libraries[library]["sources"].append(entry)

    for platform in platforms.values():
        platform["libraries"] = ordered_unique(platform["libraries"])
        platform["object_inputs"] = ordered_unique(platform["object_inputs"])
        platform["archive_inputs"] = ordered_unique(platform["archive_inputs"])
        platform["linker_scripts"] = ordered_unique(platform["linker_scripts"])

    for library in libraries.values():
        library["platforms"] = ordered_unique(library["platforms"])
        library["objects"] = ordered_unique(library["objects"])
        library["archives"] = ordered_unique(library["archives"])
        library["linker_scripts"] = ordered_unique(library["linker_scripts"])
        library["link_dependencies"] = ordered_unique(library["link_dependencies"])
        library["partial_link_inputs"] = ordered_unique(
            library["partial_link_inputs"],
            key=lambda item: (
                item["stage"],
                item["kind"],
                item["path"],
                item["origin"],
            ),
        )

    final_link_inputs = ordered_unique(
        final_link_inputs,
        key=lambda item: (
            item["kind"],
            item["path"],
            item["scope"],
            item["platform"],
        ),
    )

    return {
        "schema_version": 1,
        "context": context,
        "path_roots": path_roots,
        "platforms": sorted(platforms.values(), key=lambda item: item["name"]),
        "libraries": sorted(libraries.values(), key=lambda item: item["name"]),
        "preprocess_outputs": ordered_unique(preprocess_outputs),
        "dependency_files": ordered_unique(dependency_files),
        "link_dependencies": ordered_unique(link_dependencies),
        "linker_scripts": ordered_unique(linker_scripts),
        "final_link": {
            "inputs": final_link_inputs,
            "objects": [
                item["path"]
                for item in final_link_inputs
                if item["kind"] == "object"
            ],
            "archives": [
                item["path"]
                for item in final_link_inputs
                if item["kind"] == "archive"
            ],
            "linker_scripts": [
                item["path"]
                for item in final_link_inputs
                if item["kind"] == "linker-script"
            ],
        },
        "outputs": {
            "auxiliary": ordered_unique(auxiliary_outputs),
            "debug": ordered_unique(debug_outputs),
            "images": ordered_unique(image_outputs),
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
