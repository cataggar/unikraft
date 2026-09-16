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
REVISION = "2399694fb7ed11fffff0a34c82172dfdd54d7439"
PROFILE = "unikraft-x86_64"
ARTIFACTS = ROOT / "build" / "artifacts"
NATIVE_FLAGS = [
    "-target", "x86_64-freestanding-none", "-O", "ReleaseSafe", "-fPIC",
    "-mno-red-zone", "-fno-stack-check", "-fno-stack-protector",
    "-fno-unwind-tables", "-fno-error-tracing", "-fsingle-threaded",
    "-fno-compiler-rt",
]


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(args, cwd=ROOT, **kwargs):
    return subprocess.run(args, cwd=cwd, check=True, **kwargs)


def capture(args, cwd=ROOT):
    return run(args, cwd, stdout=subprocess.PIPE, text=True).stdout.strip()


def verify():
    manifest = json.loads((ARTIFACTS / "identity.json").read_text())
    if (manifest["wamr_revision"] != REVISION or
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


def embed(name, payload):
    return (
        f"const unsigned char {name}[] = {{\n" +
        ",\n".join(",".join(f"0x{x:02x}" for x in payload[i:i + 16])
                   for i in range(0, len(payload), 16)) +
        f"\n}};\nconst size_t {name}_size = sizeof({name});\n"
    )


def prepare(source, coremark):
    if capture(["zig", "version"]) != "0.16.0":
        raise ValueError("Zig 0.16.0 is required")
    if capture(["git", "rev-parse", f"{REVISION}^{{commit}}"], source) != REVISION:
        raise ValueError("pinned source commit unavailable")
    ARTIFACTS.mkdir(parents=True, exist_ok=False)
    work = ROOT / "build" / "wamr-source"
    work.mkdir(exist_ok=False)
    archive = ROOT / "build" / "wamr-source.tar"
    with archive.open("wb") as stream:
        run(["git", "archive", REVISION], source, stdout=stream)
    with tarfile.open(archive) as tar:
        tar.extractall(work, filter="data")
    archive.unlink()
    # All compiler scratch/output stays under this application's build tree.
    scratch = ROOT / "build" / "scratch"
    scratch.mkdir(exist_ok=True)
    env = dict(os.environ, TMPDIR=str(scratch))
    run(["zig", "build", "-Dprofile=unikraft-aot", "-Doptimize=ReleaseSafe",
         "--prefix", str(ROOT / "build" / "runtime"), "-j2"], work, env=env)
    run(["zig", "build", "native-aot-fixture", "-Doptimize=ReleaseSafe",
         "--prefix", str(ROOT / "build" / "host"), "-j2"], work, env=env)
    # Baseline's library audit uses non-PIC defaults. The actual EFI library
    # must be PIC for Unikraft's relocatable PIE link; compile the same pinned
    # compiler-free root with the explicit native object ABI, not a host ELF.
    # Unikraft's final link supplies compiler intrinsics; bundling another
    # copy would hide its strong memory helpers from the IRQ binding proof.
    if coremark:
        run(["zig", "build-lib", *NATIVE_FLAGS, "--dep", "wamr-native",
             "--dep", "minimal-wasi", f"-Mroot={ROOT / 'wasi.zig'}",
             *NATIVE_FLAGS, "-Mwamr-native=src/aot_native.zig",
             *NATIVE_FLAGS, "-Mminimal-wasi=src/wasi/minimal.zig",
             f"-femit-bin={ARTIFACTS / 'libwamr-aot.a'}"], work, env=env)
    else:
        run(["zig", "build-lib", "src/aot_native.zig", *NATIVE_FLAGS,
             f"-femit-bin={ARTIFACTS / 'libwamr-aot.a'}"], work, env=env)
    shutil.copyfile(work / "include/wamr_aot.h", ARTIFACTS / "wamr_aot.h")
    shutil.copyfile(ROOT / "build/host/bin/wamrc", ARTIFACTS / "wamrc")
    (ARTIFACTS / "wamrc").chmod(0o700)
    run(["zig", "build-exe", str(ROOT / "fixture.zig"),
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
        f'#define WAMR_REVISION "{REVISION}"\n'
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
        "scope": "native-build-inputs-not-hardware-qualification",
        "wamr_revision": REVISION,
        "compiler_profile": PROFILE,
        "zig_version": "0.16.0",
        "runtime_options": NATIVE_FLAGS,
        "compiler_options": ["optimize=ReleaseSafe"],
        "minimal_wasi": coremark,
        "wasi_bridge_sha256": digest(ROOT / "wasi.zig") if coremark else None,
        "fixture_source_sha256": digest(ROOT / "fixture.zig"),
        "prepare_source_sha256": digest(Path(__file__).resolve()),
        "files": {p.name: digest(p) for p in sorted(ARTIFACTS.iterdir())},
    }
    (ARTIFACTS / "identity.json").write_text(
        json.dumps(manifest, sort_keys=True, indent=2) + "\n")
    verify()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("prepare", "verify"))
    parser.add_argument("--source", type=Path)
    parser.add_argument("--coremark", action="store_true",
                        help="also embed both pinned CoreMarks and minimal WASI")
    args = parser.parse_args()
    if args.command == "verify":
        verify()
    elif args.source is None:
        parser.error("prepare requires --source pointing to a local WAMR checkout")
    else:
        prepare(args.source.resolve(), args.coremark)


if __name__ == "__main__":
    main()
