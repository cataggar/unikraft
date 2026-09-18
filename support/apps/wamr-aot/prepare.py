#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause
"""Build trusted native bytes ahead of time; never modify the source checkout."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile

ROOT = Path(__file__).resolve().parent
REVISION = "a53205d77be3b880eb8f8b96679512ba58e2331a"
WORKLOAD_REVISION = REVISION
PROFILE = "unikraft-x86_64"
ARTIFACTS = ROOT / "build" / "artifacts"
VARIANTS = {"tiny": 0, "snapshot": 1, "jit": 2, "sample-aot": 3}
WORKLOAD_SOURCES = (
    "workloads.build.zig", "snapshot.zig", "sampler.zig",
    "native-services.zig", "workloads.h", "platform.h", "wasi.zig",
)
JIT_MODES = {None: 0, "fast": 1, "full": 2}
COMMANDS = []
NATIVE_FLAGS = [
    "-target", "x86_64-freestanding-none", "-O", "ReleaseSafe", "-fPIC",
    "-mno-red-zone", "-fno-stack-check", "-fno-stack-protector",
    "-fno-unwind-tables", "-fno-error-tracing", "-fsingle-threaded",
    "-fno-compiler-rt",
]


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def tool(name):
    selected = os.environ.get(
        "WAMR_CI_TOOL_" + name.upper().replace("-", "_"))
    if selected is not None:
        path = Path(selected)
        retained = (
            len(path.parts) == 5
            and path.parts[:2] == ("/", "proc")
            and (path.parts[2] == "self" or path.parts[2].isdigit())
            and path.parts[3] == "fd"
            and path.name.isdigit()
        )
        if (not path.is_absolute() or (not retained
                and path.resolve(strict=True) != path)
                or not path.is_file() or not os.access(path, os.X_OK)):
            raise ValueError(f"invalid recorded build tool: {name}")
        return str(path)
    path = shutil.which(name)
    if path is None:
        raise ValueError(f"required tool unavailable: {name}")
    return str(Path(path).resolve(strict=True))


def run(args, cwd=ROOT, **kwargs):
    COMMANDS.append({"argv": [str(arg) for arg in args], "cwd": str(cwd)})
    return subprocess.run(args, cwd=cwd, check=True, **kwargs)


def capture(args, cwd=ROOT):
    return run(args, cwd, stdout=subprocess.PIPE, text=True).stdout.strip()


def verify():
    manifest = json.loads((ARTIFACTS / "identity.json").read_text())
    variant = manifest.get("variant", "tiny")
    revision = REVISION if variant == "tiny" else WORKLOAD_REVISION
    development = manifest.get("development_only", False)
    if (variant not in VARIANTS or
            type(development) is not bool or
            (not development and manifest["wamr_revision"] != revision) or
            (development and manifest["scope"] != "local-development-build-only-not-supported-lineage") or
            manifest["compiler_profile"] != PROFILE or
            manifest["zig_version"] != "0.16.0"):
        raise ValueError("unsupported native producer identity")
    for filename, expected in manifest["files"].items():
        if Path(filename).name != filename or digest(ARTIFACTS / filename) != expected:
            raise ValueError(f"artifact identity mismatch: {filename}")
    if manifest["fixture_source_sha256"] != digest(ROOT / "fixture.zig"):
        raise ValueError("fixture source changed; rebuild native artifacts")
    if manifest["prepare_source_sha256"] != digest(Path(__file__).resolve()):
        raise ValueError("producer changed; rebuild native artifacts")
    if (manifest["minimal_wasi"] and
            manifest["wasi_bridge_sha256"] != digest(ROOT / "wasi.zig")):
        raise ValueError("minimal WASI bridge changed; rebuild native artifacts")
    if ((variant == "jit" and manifest["jit_mode"] not in ("fast", "full")) or
            (variant != "jit" and manifest["jit_mode"] is not None)):
        raise ValueError("invalid prepared JIT boot mode")
    for name in WORKLOAD_SOURCES:
        if manifest["workload_sources"][name] != digest(ROOT / name):
            raise ValueError(f"workload consumer changed: {name}")
    if manifest["runtime_options"] != NATIVE_FLAGS:
        raise ValueError("unexpected native consumer options")


def embed(name, payload):
    return (
        f"const unsigned char {name}[] = {{\n" +
        ",\n".join(",".join(f"0x{x:02x}" for x in payload[i:i + 16])
                   for i in range(0, len(payload), 16)) +
        f"\n}};\nconst size_t {name}_size = sizeof({name});\n"
    )


def source_identity(work):
    """Canonical actual source file set: relative path, byte count and SHA256."""
    files = {p.relative_to(work).as_posix(): {
        "bytes": p.stat().st_size, "sha256": digest(p),
    } for p in sorted(work.rglob("*")) if p.is_file()}
    canonical = json.dumps(files, sort_keys=True, separators=(",", ":")).encode()
    (ROOT / "build/source-files.json").write_bytes(canonical + b"\n")
    return hashlib.sha256(canonical).hexdigest()


def workload_library(work, variant, coremark, env, zig):
    consumer = ROOT / "build" / "workload-consumer"
    consumer.mkdir(exist_ok=False)
    for name in WORKLOAD_SOURCES:
        shutil.copyfile(ROOT / name, consumer / (
            "build.zig" if name == "workloads.build.zig" else name))
    (consumer / "build.zig.zon").write_text(
        '.{ .name = .wamr_workload_image, .version = "0.0.0", '
        '.fingerprint = 0xcb36ebabb0542062, '
        '.dependencies = .{ .wamr = .{ .path = "../wamr-source" } }, '
        '.paths = .{ "." } }\n')
    if variant == "tiny":
        embedded = ""
    elif variant == "snapshot":
        embedded = ""
        for name, original in (("compute", "unroll4"), ("memory", "iv_store")):
            wasm = ARTIFACTS / f"{name}.wasm"
            aot = ARTIFACTS / f"{name}.cwasm"
            shutil.copyfile(work / "tests/benchmarks/loop-passes" / f"{original}.wasm", wasm)
            run([str(ARTIFACTS / "wamrc"), "compile", "--target=x86_64",
                 f"--profile={PROFILE}", str(wasm), "-o", str(aot)], env=env)
            for path, suffix in ((wasm, "wasm"), (aot, "aot")):
                shutil.copyfile(path, consumer / path.name)
                embedded += f'pub const {name}_{suffix} = @embedFile("{path.name}");\n'
    else:
        # Same tracked source and exact wasm compiler options as the SDK module.
        wasm = ARTIFACTS / "matched.wasm"
        aot = ARTIFACTS / "matched.cwasm"
        run([zig, "build-exe", str(work / "tests/unikraft-jit/fixture.zig"),
             "-target", "wasm32-freestanding", "-O", "ReleaseSmall",
             "-fno-entry", "-rdynamic", "--stack", "16384",
             "--initial-memory=131072", "--max-memory=524288",
             f"-femit-bin={wasm}"], env=env)
        run([str(ARTIFACTS / "wamrc"), "compile", "--target=x86_64",
             f"--profile={PROFILE}", str(wasm), "-o", str(aot)], env=env)
        shutil.copyfile(aot, consumer / aot.name)
        embedded = (f'pub const with_compiler = {str(variant == "jit").lower()};\n'
                    'pub const aot = @embedFile("matched.cwasm");\n')
    (consumer / "artifacts.zig").write_text(embedded)
    run([zig, "build", f"-Dvariant={variant}", f"-Dcoremark={str(coremark).lower()}", "-j2",
         "--prefix", str(consumer / "out")], consumer, env=env)
    if variant in ("jit", "sample-aot") and digest(consumer / "out/matched.wasm") != digest(ARTIFACTS / "matched.wasm"):
        raise ValueError("SDK's actual embedded sampler source differs from the comparator input")
    shutil.copyfile(consumer / "out/lib/libwamr-aot.a", ARTIFACTS / "libwamr-aot.a")


def prepare(source, coremark, variant="tiny", development_revision=None,
            jit_mode=None, source_archive=None):
    zig = tool("zig")
    if capture([zig, "version"]) != "0.16.0":
        raise ValueError("Zig 0.16.0 is required")
    if coremark and variant != "tiny":
        raise ValueError("--coremark belongs to the unchanged tiny image only")
    if ((variant == "jit" and jit_mode not in ("fast", "full")) or
            (variant != "jit" and jit_mode is not None)):
        raise ValueError("--variant jit requires exactly --jit-mode fast or full; other variants forbid it")
    revision = development_revision or (REVISION if variant == "tiny" else WORKLOAD_REVISION)
    if revision is None:
        raise ValueError("optional images await a merged SDK pin; use an explicit "
                         "--development-revision only for local development")
    if source_archive is None:
        if (len(revision) != 40 or any(c not in "0123456789abcdef" for c in revision) or
                capture(["git", "rev-parse", f"{revision}^{{commit}}"], source) != revision):
            raise ValueError("pinned source commit unavailable")
    elif (source is not None or development_revision is not None or
          revision != REVISION or not source_archive.is_absolute()):
        raise ValueError("sealed source archive requires the fixed supported revision")
    ARTIFACTS.mkdir(parents=True, exist_ok=False)
    (ROOT / "build").chmod(0o700)
    ARTIFACTS.chmod(0o700)
    work = ROOT / "build" / "wamr-source"
    work.mkdir(exist_ok=False)
    archive = source_archive
    created_archive = archive is None
    if created_archive:
        archive = ROOT / "build" / "wamr-source.tar"
        with archive.open("wb") as stream:
            run(["git", "archive", revision], source, stdout=stream)
    with tarfile.open(archive) as tar:
        tar.extractall(work, filter="data")
    if created_archive:
        archive.unlink()
    tree_sha256 = source_identity(work)
    # All compiler scratch/output stays under this application's build tree.
    scratch = ROOT / "build" / "scratch"
    scratch.mkdir(exist_ok=True)
    env = dict(os.environ, TMPDIR=str(scratch))
    run([zig, "build", "-Dprofile=unikraft-aot", "-Doptimize=ReleaseSafe",
         "--prefix", str(ROOT / "build" / "runtime"), "-j2"], work, env=env)
    run([zig, "build", "native-aot-fixture", "-Doptimize=ReleaseSafe",
         "--prefix", str(ROOT / "build" / "host"), "-j2"], work, env=env)
    shutil.copyfile(work / "include/wamr_aot.h", ARTIFACTS / "wamr_aot.h")
    shutil.copyfile(ROOT / "build/host/bin/wamrc", ARTIFACTS / "wamrc")
    (ARTIFACTS / "wamrc").chmod(0o700)
    workload_library(work, variant, coremark, env, zig)
    run([zig, "build-exe", str(ROOT / "fixture.zig"),
         "-target", "wasm32-freestanding", "-O", "ReleaseSmall",
         "-fno-entry", "-rdynamic", "--stack", "16384",
         "--initial-memory=131072", "--max-memory=524288",
         f"-femit-bin={ARTIFACTS / 'tiny.wasm'}"], env=env)
    run([str(ARTIFACTS / "wamrc"), "compile", "--target=x86_64",
         f"--profile={PROFILE}", str(ARTIFACTS / "tiny.wasm"),
         "-o", str(ARTIFACTS / "tiny.cwasm")], env=env)
    payload = (ARTIFACTS / "tiny.cwasm").read_bytes()
    embedded = (
        "/* Generated by prepare.py from matching trusted native bytes. */\n"
        "#include <stddef.h>\n" + embed("wamr_fixture", payload))
    if coremark:
        for stem, source_name, symbol in (
                ("coremark", "coremark_wasi.wasm", "wamr_coremark"),
                ("coremark-nofp", "coremark_wasi_nofp.wasm", "wamr_coremark_nofp")):
            wasm = ARTIFACTS / f"{stem}.wasm"
            cwasm = ARTIFACTS / f"{stem}.cwasm"
            shutil.copyfile(work / "tests/benchmarks/coremark" / source_name, wasm)
            run([str(ARTIFACTS / "wamrc"), "compile", "--target=x86_64",
                 f"--profile={PROFILE}", str(wasm), "-o", str(cwasm)], env=env)
            embedded += embed(symbol, cwasm.read_bytes())
    (ARTIFACTS / "embedded.c").write_text(embedded)
    header = (
        f'#define WAMR_REVISION "{revision}"\n'
        f'#define WAMR_APP_VARIANT {VARIANTS[variant]}\n'
        f'#define WAMR_JIT_BOOT_MODE {JIT_MODES[jit_mode]}\n'
        f'#define WAMR_SOURCE_TREE_SHA256 "{tree_sha256}"\n'
        f'#define WAMR_COMPILER_SHA256 "{digest(ARTIFACTS / "wamrc")}"\n'
        f'#define WAMR_HAS_COREMARK {int(coremark)}\n'
        f'#define WAMR_WASM_SHA256 "{digest(ARTIFACTS / "tiny.wasm")}"\n'
        f'#define WAMR_CWASM_SHA256 "{digest(ARTIFACTS / "tiny.cwasm")}"\n'
        f'#define WAMR_LIBRARY_SHA256 "{digest(ARTIFACTS / "libwamr-aot.a")}"\n')
    if coremark:
        for stem in ("coremark", "coremark-nofp"):
            name = stem.upper().replace("-", "_")
            header += f'#define WAMR_{name}_WASM_SHA256 "{digest(ARTIFACTS / (stem + ".wasm"))}"\n'
            header += f'#define WAMR_{name}_CWASM_SHA256 "{digest(ARTIFACTS / (stem + ".cwasm"))}"\n'
    (ARTIFACTS / "identity.h").write_text(header)
    manifest = {
        "schema_version": 1,
        "scope": ("local-development-build-only-not-supported-lineage" if development_revision
                  else "native-build-inputs-not-hardware-qualification"),
        "development_only": bool(development_revision),
        "variant": variant,
        "jit_mode": jit_mode,
        "wamr_revision": revision,
        "source_tree_sha256": tree_sha256,
        "source_identity_recipe": "sorted-compact-json-relative-file-path-to-bytes-and-sha256-v1",
        "source_tracked_diff_sha256": hashlib.sha256(b"").hexdigest(),
        "compiler_profile": PROFILE,
        "zig_version": "0.16.0",
        "runtime_options": NATIVE_FLAGS,
        "compiler_runtime_provider": "unikraft-final-link-not-bundled-in-consumer",
        "commands": COMMANDS,
        "compiler_options": ["optimize=ReleaseSafe"],
        "minimal_wasi": coremark,
        "wasi_bridge_sha256": digest(ROOT / "wasi.zig") if coremark else None,
        "fixture_source_sha256": digest(ROOT / "fixture.zig"),
        "prepare_source_sha256": digest(Path(__file__).resolve()),
        "workload_sources": {name: digest(ROOT / name) for name in WORKLOAD_SOURCES},
        "files": {p.name: digest(p) for p in sorted(ARTIFACTS.iterdir())},
    }
    (ARTIFACTS / "identity.json").write_text(
        json.dumps(manifest, sort_keys=True, indent=2) + "\n")
    verify()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("prepare", "verify"))
    parser.add_argument("--source", type=Path)
    parser.add_argument("--source-archive", type=Path)
    parser.add_argument("--coremark", action="store_true",
                        help="also embed both pinned CoreMarks and minimal WASI")
    parser.add_argument("--variant", choices=VARIANTS, default="tiny")
    parser.add_argument("--jit-mode", choices=("fast", "full"),
                        help="required fixed boot preset for a JIT correctness image")
    parser.add_argument("--development-revision",
                        help="explicit local-only full SDK commit, never supported deployment lineage")
    args = parser.parse_args()
    if args.command == "verify":
        verify()
    elif (args.source is None) == (args.source_archive is None):
        parser.error("prepare requires exactly one of --source or --source-archive")
    else:
        prepare(
            args.source.resolve() if args.source is not None else None,
            args.coremark, args.variant, args.development_revision,
            args.jit_mode,
            args.source_archive.resolve(strict=True)
            if args.source_archive is not None else None,
        )


if __name__ == "__main__":
    main()
