# SPDX-License-Identifier: BSD-3-Clause
"""Complete local records for the native constructor, never an admission mock."""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def save(path, value):
    path.write_bytes(encoded(value))
    path.chmod(0o600)


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def copy_file(source, target, executable=False):
    target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    shutil.copyfile(source, target)
    target.chmod(0o500 if executable else 0o600)


def stage_git(git, target):
    git, target = map(Path, (git, target))
    copy_file(git, target, True)
    target.chmod(0o700)
    local_lib = target.parent.parent / "lib"
    local_lib.mkdir(mode=0o700, exist_ok=True)
    original_lib = git.parent.parent / "lib"
    if original_lib.is_dir():
        for library in original_lib.iterdir():
            if library.is_file() and ".so" in library.name:
                copy_file(library, local_lib / library.name)
    image = bytearray(target.read_bytes())
    assert image[:6] == b"\x7fELF\x02\x01", "fixture requires little-endian ELF64 Git"
    phoff = struct.unpack_from("<Q", image, 32)[0]
    entsize, count = struct.unpack_from("<HH", image, 54)
    assert entsize == 56 and phoff + count * entsize <= len(image)
    entries = [phoff + index * entsize for index in range(count)
               if struct.unpack_from("<I", image, phoff + index * entsize)[0] == 3]
    assert len(entries) == 1, "fixture requires Git's real ELF interpreter"
    entry = entries[0]
    offset, size = (struct.unpack_from("<Q", image, entry + part)[0]
                    for part in (8, 32))
    assert size > 1 and offset + size <= len(image) and image[offset + size - 1] == 0
    interpreter = Path(os.fsdecode(bytes(image[offset:offset + size - 1]))).resolve(strict=True)
    private_loader = local_lib / interpreter.name
    copy_file(interpreter, private_loader, True)
    private_loader.chmod(0o700)
    # Relocate only PT_INTERP; Git's loaded code and bundled-library RPATH stay intact.
    relocated = os.fsencode(private_loader) + b"\0"
    struct.pack_into("<Q", image, entry + 8, len(image))
    struct.pack_into("<Q", image, entry + 32, len(relocated))
    struct.pack_into("<Q", image, entry + 40, len(relocated))
    image.extend(relocated)
    target.write_bytes(image)


def identity(record):
    dev, ino, mode, uid, unused_gid, unused_links, size, mtime, ctime = record["metadata"]
    return {
        "content_sha256": record["sha256"],
        "device_major": os.major(dev), "device_minor": os.minor(dev),
        "inode": ino, "mode": mode, "uid": uid, "size": size,
        "mtime_seconds": mtime // 10**9, "mtime_nanoseconds": mtime % 10**9,
        "ctime_seconds": ctime // 10**9, "ctime_nanoseconds": ctime % 10**9,
    }


def pin(path):
    info = path.stat()
    return {
        "device_major": os.major(info.st_dev), "device_minor": os.minor(info.st_dev),
        "inode": info.st_ino, "mode": info.st_mode, "uid": info.st_uid,
        "gid": info.st_gid, "nlink": info.st_nlink, "size": info.st_size,
        "mtime_seconds": info.st_mtime_ns // 10**9,
        "mtime_nanoseconds": info.st_mtime_ns % 10**9,
        "ctime_seconds": info.st_ctime_ns // 10**9,
        "ctime_nanoseconds": info.st_ctime_ns % 10**9,
        "sha256": list(bytes.fromhex(digest(path))),
    }


def prepare(args):
    source, stage, work, revision, git, python, zig, fixture, miz, package_cli, log_cli, aot_cli = args
    source, stage, work, miz = map(Path, (source, stage, work, miz))
    repository, runtime = work / "producer", work / "runtime"
    v2 = revision == "e98623f780fa23d05b5797004e4b88160404eb1b"
    package = source / "support/build/wamr-native-ci"
    ci = load("local_ci", package / "run.py")
    witness = load("local_witness", package / "tests/test_adapter.py")
    subprocess.run([git, "init", "-q", str(repository)], check=True)
    subprocess.run([git, "-C", str(repository), "-c", "gc.auto=0",
                    "-c", "maintenance.auto=false", "fetch", "-q", "--depth=1",
                    "--no-tags", str(source), revision], check=True)
    subprocess.run([git, "-C", str(repository), "-c", "gc.auto=0",
                    "-c", "maintenance.auto=false", "checkout", "-q",
                    "--detach", revision], check=True)
    # A shallow, loose HEAD is necessary: a packed duplicate must not hide
    # the real historical-object corruption case.
    object_path = repository / ".git/objects" / revision[:2] / revision[2:]
    pack = repository / ".git/objects/pack"
    if list(pack.glob("*.pack")):
        isolated_pack = repository / ".git/fixture-pack"
        pack.rename(isolated_pack)
        pack.mkdir(mode=0o700)
        for packed in isolated_pack.glob("*.pack"):
            with packed.open("rb") as stream:
                subprocess.run([git, "-C", str(repository), "unpack-objects", "-q"],
                               stdin=stream, check=True)
        shutil.rmtree(isolated_pack)
    assert object_path.is_file()
    object_path.chmod(0o600)

    for part in ("compute/evidence", "compute/private", "compute/package",
                 "compute/tools/bin", "compute/supervisor/bin", "custody",
                 "firmware", "bin/share", "bison", "llvm", "zig",
                 "host-tools", "evidence"):
        (runtime / part).mkdir(mode=0o700, parents=True, exist_ok=True)
    for part in ("original", "compiler-cache", "global", "supervisor-install", "image-records"):
        (work / part).mkdir(mode=0o700)
    (work / "mutated-runtime-role").write_bytes(b"")
    (work / "redirected-runtime").write_bytes(b"")
    app = repository / "support/apps/wamr-aot"
    for role, relative in {
        "efi": "build/wamr_hyperv-x86_64-efi",
        "debug_elf": "build/wamr_hyperv-x86_64-efi.dbg",
        "bootinfo": "build/wamr_hyperv-x86_64-efi.bootinfo", "config": ".config",
        "runtime": "build/artifacts/libwamr-aot.a", "compiler": "build/artifacts/wamrc",
        "wasm": "build/artifacts/tiny.wasm", "cwasm": "build/artifacts/tiny.cwasm",
        "runtime_identity": "build/artifacts/identity.json",
        "image_identity": "build/image-identity.json",
    }.items():
        copy_file(stage / "artifacts" / role, app / relative)
    for part in (".d", ".zig-cache"):
        (repository / part).mkdir(mode=0o700, exist_ok=True)
    if v2:
        data = bytearray(512)
        data[:2] = b"MZ"
        struct.pack_into("<I", data, 0x3c, 0x80)
        data[0x80:0x84] = b"PE\0\0"
        for offset, value in ((0x84, 0x8664), (0x86, 1), (0x94, 0xf0),
                              (0x98, 0x20b), (0xdc, 10)):
            struct.pack_into("<H", data, offset, value)
        (app / "build/wamr_hyperv-x86_64-efi").write_bytes(data)
    else:
        for suffix in ("raw", "vhd"):
            copy_file(stage / "artifacts" / suffix,
                      runtime / "compute/package" / ("unikraft." + suffix))
    for name in ("code.fd", "vars.fd"):
        (runtime / "firmware" / name).write_bytes(name.encode())
    (runtime / "bin/share/firmware").write_bytes(b"recorded qemu data\n")
    (runtime / "bison/skeleton").write_bytes(b"recorded bison data\n")
    (runtime / "llvm/manifest").write_bytes(b"recorded llvm data\n")
    (runtime / "custody/wamr-source.tar").write_bytes(b"recorded source archive\n")

    # Git and Python are genuine executables. Other unexecuted command roles
    # use the purpose-built native command fixture, with its real identity.
    local_git = runtime / "host-tools/git"
    stage_git(git, local_git)
    tools = {}
    names = list(ci.HOST_TOOLS) + ([] if v2 else ["head", "timeout"])
    for name in names:
        if name == "git":
            path = local_git
        elif name == "python3":
            path = Path(python).resolve(strict=True)
        elif name == "zig":
            path = runtime / "zig/zig"
            copy_file(zig, path, True)
        else:
            path = runtime / "host-tools" / name
            copy_file(fixture, path, True)
        tools[name] = path
    ci.REPO = repository
    ci.APP = app
    ci.LOCAL_BOOT = repository / "support/tools/hyperv/local_boot"
    os.environ["GITHUB_SHA"] = revision
    for name in ("build.zig", "build.zig.zon"):
        (ci.LOCAL_BOOT / name).chmod(0o644)
    ci.COMMAND_TOOL_PATHS.update({name: str(path) for name, path in tools.items()})
    source_state = ci.source(repository)
    source_identity = ci.source_identity(source_state)

    compute = runtime / "compute"
    for mode in ci.SIX_MODES if v2 else ci.MODES:
        (compute / ("boot-" + mode)).mkdir(mode=0o700)
    restore = compute / "dependencies"
    restore.mkdir(mode=0o700)
    for name in ("build.zig", "build.zig.zon"):
        copy_file(repository / "support/tools/hyperv/local_boot" / name,
                  restore / name)
    packages = restore / "zig-pkg"
    packages.mkdir(mode=0o700)
    pending, copied = [ci.MIZ_PACKAGE_HASH], set()
    while pending:
        name = pending.pop()
        if name in copied:
            continue
        origin = miz.parent / name
        target = packages / name
        shutil.copytree(origin, target, symlinks=True)
        for directory, dirs, files in os.walk(target):
            Path(directory).chmod(0o700)
            for file in files:
                if not (Path(directory) / file).is_symlink():
                    (Path(directory) / file).chmod(0o600)
        copied.add(name)
        manifest = target / "build.zig.zon"
        if manifest.is_file():
            pending.extend(ci.package_dependencies(manifest.read_bytes()))
    (compute / "private/dependency-restore.log").write_bytes(b"")
    for name in ("build.zig", "build.zig.zon"):
        copy_file(restore / name, work / "global" / name)
    for index, name in enumerate(sorted(copied)):
        hashed = subprocess.run([zig, "fetch", "--global-cache-dir",
                                 str(work / "global"), str(packages / name)],
                                cwd=work / "global",
                                capture_output=True, check=True)
        assert hashed.stdout == (name + "\n").encode(), hashed.stderr
        (compute / "private" / f"dependency-hash-{index:03d}.log").write_bytes(hashed.stdout)
    dependency = ci.dependency_custody(compute)

    boot_paths = {
        "efi": app / "build/wamr_hyperv-x86_64-efi",
        "local_boot_tool": compute / "tools/bin/uk-hyperv-local-boot",
        "package_tool": compute / "tools/bin/wamr-ci-package",
        "qemu": runtime / "bin/qemu-system-x86_64",
        "ovmf_code": runtime / "firmware/code.fd", "ovmf_vars": runtime / "firmware/vars.fd",
    }
    for role in ("local_boot_tool", "qemu"):
        copy_file(fixture, boot_paths[role], True)
    copy_file(package_cli, boot_paths["package_tool"], True)
    if v2:
        boot_paths["log_validator"] = compute / "tools/bin/uk-wamr-log-validate"
        copy_file(aot_cli, compute / "tools/bin/uk-wamr-aot-build", True)
        copy_file(log_cli, boot_paths["log_validator"], True)
        closure = ci.supervisor_source_map()["content_closure_sha256"]
        built = subprocess.run([
            zig, "build", "--build-file", str(repository / "support/build/wamr-native-ci/supervisor.build.zig"),
            "--system", str(miz.parent),
            "--cache-dir", str(work / "compiler-cache"), "--global-cache-dir", str(work / "global"),
            "-p", str(work / "supervisor-install"), "-Doptimize=ReleaseSafe",
            "-Dsource-closure-sha256=" + closure, "-j1",
        ], capture_output=True, check=True)
        assert not built.stdout
        copy_file(work / "supervisor-install/bin/wamr-ci-supervisor",
                  compute / "supervisor/bin/wamr-ci-supervisor", True)
        image_records = prepare_images(ci, compute, boot_paths["efi"],
                                       boot_paths["package_tool"], work / "image-records")
    file_paths = {"tool:" + name: path for name, path in tools.items()}
    file_paths["wamr-source-archive"] = runtime / "custody/wamr-source.tar"
    if v2:
        file_paths.update({
            "command-supervisor": compute / "supervisor/bin/wamr-ci-supervisor",
            ci.WAMR_AOT_BUILD_ROLE: compute / "tools/bin/uk-wamr-aot-build",
            ci.WAMR_LOG_VALIDATOR_ROLE: compute / "tools/bin/uk-wamr-log-validate",
        })
    for path in list(file_paths.values()):
        for library in ci.executable_runtime_paths(path):
            file_paths["runtime:" + str(library)] = library
    stdlib = subprocess.run([str(tools["python3"]), "-c",
                            "import sysconfig; print(sysconfig.get_path('stdlib'))"],
                           capture_output=True, check=True).stdout.strip().decode()
    trees = {"bison": runtime / "bison", "llvm": runtime / "llvm",
             "zig": runtime / "zig", "python-stdlib": Path(stdlib)}
    consumer = ci.record_input_paths(file_paths, trees)
    boot = ci.boot_input_state(runtime, boot_paths)
    start = {
        "source": source_identity, "source_custody": source_state["custody"],
        "tools": {name: digest(path) for name, path in tools.items()},
        "bison_data": ci.bison_inputs(runtime / "bison"),
        "dependencies": dependency, "consumer_inputs": consumer,
    }
    if v2:
        start["command_supervisor"] = ci.command_supervisor_state(runtime, consumer)
    evidence = compute / "evidence"
    save(evidence / "build-start.json", start)
    runtime_identity = json.loads((app / "build/artifacts/identity.json").read_bytes())
    if v2:
        for name in ("embedded.c", "identity.h", "wamr_aot.h"):
            path = app / "build/artifacts" / name
            path.write_bytes(name.encode())
            path.chmod(0o600)
            runtime_identity["files"][name] = digest(path)
        save(app / "build/artifacts/identity.json", runtime_identity)
    image = json.loads((app / "build/image-identity.json").read_bytes())
    image["unikraft_revision"] = revision
    image["files"]["wamr_hyperv-x86_64-efi"] = digest(boot_paths["efi"])
    image["runtime_inputs_sha256"] = digest(app / "build/artifacts/identity.json")
    save(app / "build/image-identity.json", image)
    save(evidence / "build.json", {"source": source_identity, "runtime": runtime_identity, "image": image})
    save(evidence / "boot-inputs.json", boot)
    packaged = image_records["package"] if v2 else json.loads((stage / "evidence/package.json").read_bytes())
    if v2:
        assert packaged.pop("schema_version") == 1
        packaged["image"] = {key: packaged["image"][key] for key in (
            "schema_version", "miz_revision", "efi", "raw", "vhd",
            "footer_sha256", "packaging")}
    packaged["producer_sha256"] = digest(boot_paths["package_tool"])
    save(evidence / "package.json", packaged)

    result = json.loads((stage / "artifacts/local_result").read_bytes())
    if v2:
        result["schema_version"] = 2
        result["profile"] = "qcow2-derived-vhd"
        result["modes"] = list(ci.SIX_MODES)
    summaries = {}
    for mode in result["modes"]:
        old_mode = mode.replace("qcow2-", "raw-")
        directory = compute / ("boot-" + mode)
        request = json.loads((stage / "boots" / old_mode / "request").read_bytes())
        config = request["config"]
        config.update({
            "work_dir": str(directory), "qemu": str(boot_paths["qemu"]),
            "ovmf_code": str(boot_paths["ovmf_code"]), "ovmf_vars": str(boot_paths["ovmf_vars"]),
        })
        image_name = ("unikraft.raw" if mode.startswith("raw-") else
                      "unikraft.qcow2" if mode.startswith("qcow2-") else
                      "unikraft-derived.vhd" if v2 else "unikraft.vhd")
        image_path = compute / "package" / image_name
        config["source"] = {
            "path": str(image_path),
            "kind": "qcow2" if mode.startswith("qcow2-") else "raw_disk" if mode.startswith("raw-") else "fixed_vhd",
        }
        request["schema_version"] = 2
        request["pins"] = [pin(image_path)] + [
            pin(boot_paths[role]) for role in ("ovmf_code", "ovmf_vars", "qemu")]
        save(directory / "request.json", request)
        copy_file(stage / "boots" / old_mode / "report", directory / "report.json")
        copy_file(stage / "boots" / old_mode / "serial", directory / "hyperv-efi-boot.log")
        record = json.loads((stage / "boots" / old_mode / "compute").read_bytes())
        record.update(input_pins=request["pins"], request_sha256=digest(directory / "request.json"))
        save(evidence / (mode + "-compute.json"), record)
        summaries[mode] = {
            "request_sha256": record["request_sha256"], "report_sha256": record["report_sha256"],
            "serial_sha256": digest(directory / "hyperv-efi-boot.log"),
            "compute_sha256": digest(evidence / (mode + "-compute.json")),
        }
    stages = ["adapter", "local-boot-tool", "fixtures", "prepare", "config", "native-image",
              "package", "raw-x2apic", "raw-legacy-apic"]
    if v2:
        stages += ["finalize-qcow2", "qcow2-x2apic", "qcow2-legacy-apic", "derive-fixed-vhd"]
    stages += ["vpc-x2apic", "vpc-legacy-apic", "inspect"]
    for stage_name in stages:
        if v2:
            record, unused = witness.Evidence().supervised_binding(stage_name)
            request = record["supervisor"]["request"]
            identities = {}
            for binding in [request[key] for key in ("supervisor", "native_executable", "command_executable", "interpreter")] + request["retained_executables"]:
                if binding is None:
                    continue
                role = binding["path"]["role"]
                original = boot["files"][role[6:]] if role.startswith("input:") else consumer["files"][role]
                binding["identity"] = identity(original)
                identities[role] = binding["identity"]
            command = record["supervisor"]["result"]["command"]
            command["executable"] = copy.deepcopy(request["native_executable"]["identity"])
            command["retained_executables"] = copy.deepcopy(request["retained_executables"])
            witness.Evidence().rehash_supervised_binding(record)
            ci.validate_supervised_command_binding(record, stage_name, identities,
                                                   transport_context="trusted_inner_zip")
        else:
            record = json.loads((stage / "evidence" / ("command-" + stage_name + ".json")).read_bytes())
        save(evidence / ("command-" + stage_name + ".json"), record)
        (compute / "private" / (stage_name + ".log")).write_bytes(b"")
    if v2:
        chain(ci, evidence, compute, source_identity, packaged, summaries, image_records)
        (runtime / "evidence/runtime-cleanup.txt").write_bytes(b"primary=0 cleanup=0\n")
    result["records"] = {path.name: digest(path) for path in evidence.iterdir()}
    save(evidence / "result.json", result)
    for path in evidence.iterdir():
        copy_file(path, work / "original" / path.name)
    copy_file(compute / "boot-raw-x2apic/request.json", work / "original/request")
    copy_file(compute / "boot-raw-x2apic/hyperv-efi-boot.log", work / "original/serial")
    copy_file(object_path, work / "original/commit")
    # These are actual scans, not acceptance substitutions.
    ci.require_recorded_consumer_inputs(consumer, content=True)
    ci.require_recorded_consumer_inputs(boot, content=True)
    try:
        assert ci.source(repository) == source_state
    except ci.Refusal:
        ignored = subprocess.run(
            [git, "-C", str(repository), "ls-files", "--others", "--ignored",
             "--exclude-standard", "--directory"],
            capture_output=True, check=True,
        ).stdout
        print("actual ignored producer inventory:", ignored.decode(), file=sys.stderr)
        raise


def prepare_images(ci, compute, efi, tool, output):
    def run(command, input_path):
        result = subprocess.run([str(tool), command, str(input_path),
                                 str(compute / "package")],
                                capture_output=True, timeout=150, check=True)
        assert not result.stderr, result.stderr
        return json.loads(result.stdout)
    package = run("package", efi)
    raw = compute / "package/unikraft.raw"
    limits = {
        "max_input_bytes": 66 * ci.MIB, "max_output_bytes": 66 * ci.MIB + 512,
        "max_virtual_bytes": 66 * ci.MIB, "max_partition_array_bytes": ci.MIB,
        "max_metadata_bytes": 128 * 1024, "max_metadata_work": 8194,
        "max_work_bytes": 4 * 66 * ci.MIB, "max_memory_bytes": 512 * ci.MIB,
        "max_workload_bytes": 64 * ci.MIB,
    }
    intent = {
        "schema": "uk.wamr.compute-qcow2-finalization-intent", "schema_version": 1,
        "source_path": str(raw), "expected_source_sha256": digest(raw),
        "expected_source_bytes": raw.stat().st_size, "expected_virtual_bytes": raw.stat().st_size,
        "expected_workload_sha256": digest(efi), "expected_workload_bytes": efi.stat().st_size,
        "timeout_ms": 120000, "limits": limits,
    }
    save(output / "qcow2-finalization-intent.json", intent)
    finalized = run("finalize-qcow2", output / "qcow2-finalization-intent.json")
    qcow = compute / "package/unikraft.qcow2"
    vhd_intent = {
        "schema": "uk.wamr.compute-fixed-vhd-derivation-intent", "schema_version": 1,
        "source_path": str(qcow), "accepted_qcow2_sha256": digest(qcow),
        "expected_source_bytes": qcow.stat().st_size,
        "expected_capacity_bytes": raw.stat().st_size, "timeout_ms": 120000, "limits": limits,
    }
    save(output / "fixed-vhd-derivation-intent.json", vhd_intent)
    derived = run("derive-fixed-vhd", output / "fixed-vhd-derivation-intent.json")
    return {"package": package, "intent": intent, "finalized": finalized,
            "vhd_intent": vhd_intent, "derived": derived}


def chain(ci, evidence, compute, source, package, boots, images):
    raw, qcow, vhd = (compute / "package" / name for name in
                      ("unikraft.raw", "unikraft.qcow2", "unikraft-derived.vhd"))
    efi = package["image"]["efi"]
    def output(path):
        return {"sha256": digest(path), "file_bytes": path.stat().st_size,
                "virtual_bytes": raw.stat().st_size}
    def emit(name, schema, **fields):
        save(evidence / name, {"schema": schema, "schema_version": 1, **fields})
    def ref(name):
        return digest(evidence / name)
    save(evidence / "qcow2-finalization-intent.json", images["intent"])
    save(evidence / "qcow2-finalization.json", images["finalized"])
    emit("qcow2-acceptance.json", "uk.wamr.compute-qcow2-acceptance",
         profile="qcow2-derived-vhd", status="accepted", source=source, accepted_qcow2=output(qcow),
         finalization_sha256=ref("qcow2-finalization.json"), modes=list(ci.SIX_MODES[:4]),
         boots={name: boots[name] for name in ci.SIX_MODES[:4]},
         build_sha256=ref("build.json"), boot_inputs_sha256=ref("boot-inputs.json"))
    save(evidence / "fixed-vhd-derivation-intent.json", images["vhd_intent"])
    emit("fixed-vhd-derivation-gate.json", "uk.wamr.compute-fixed-vhd-derivation-gate",
         profile="qcow2-derived-vhd", status="accepted_qcow2_only",
         accepted_qcow2_sha256=digest(qcow), qcow2_acceptance_sha256=ref("qcow2-acceptance.json"),
         derivation_intent_sha256=ref("fixed-vhd-derivation-intent.json"), derived_output_absent=True)
    save(evidence / "fixed-vhd-derivation.json", images["derived"])
    names = ["build-start.json", "build.json", "boot-inputs.json", "package.json",
             "qcow2-finalization-intent.json", "qcow2-finalization.json", "qcow2-acceptance.json",
             "fixed-vhd-derivation-intent.json", "fixed-vhd-derivation-gate.json", "fixed-vhd-derivation.json"]
    emit("final-inspection.json", "uk.wamr.compute-image-chain-inspection",
         profile="qcow2-derived-vhd", status="complete", source=source,
         artifacts={"efi": {"sha256": efi["sha256"], "file_bytes": efi["size"]},
                    "raw": output(raw), "qcow2": output(qcow), "vhd": output(vhd)},
         records={name: ref(name) for name in names}, modes=list(ci.SIX_MODES), boots=boots)


def mutate(work, case):
    work = Path(work)
    repository, runtime = work / "producer", work / "runtime"
    evidence = runtime / "compute/evidence"
    for original in (work / "original").glob("*.json"):
        copy_file(original, evidence / original.name)
    copy_file(work / "original/request", runtime / "compute/boot-raw-x2apic/request.json")
    copy_file(work / "original/serial", runtime / "compute/boot-raw-x2apic/hyperv-efi-boot.log")
    revision = repository.joinpath(".git/HEAD").read_text().strip()
    object_path = repository / ".git/objects" / revision[:2] / revision[2:]
    copy_file(work / "original/commit", object_path)
    (runtime / "compute/private/config.log").write_bytes(b"")
    if case == "historical-object":
        import zlib
        original = zlib.decompress(object_path.read_bytes())
        header, raw = original.split(b"\0", 1)
        lines = raw.splitlines(keepends=True)
        assert lines[0].startswith(b"tree ")
        lines[0] = b"tree " + b"0" * 40 + b"\n"
        changed = b"".join(lines)
        assert len(raw) == len(changed)
        object_path.write_bytes(zlib.compress(header + b"\0" + changed))
        return
    if case == "dirty-source":
        with (repository / "README.md").open("ab") as stream:
            stream.write(b"\n")
        return
    if case == "command-log":
        (runtime / "compute/private/config.log").write_bytes(b"changed private command output\n")
        return
    if case == "serial":
        with (runtime / "compute/boot-raw-x2apic/hyperv-efi-boot.log").open("r+b") as stream:
            stream.write(b"!")
        return
    result = json.loads((evidence / "result.json").read_bytes())
    def put(name, value):
        save(evidence / name, value)
        result["records"][name] = digest(evidence / name)
    def document(name):
        return json.loads((evidence / name).read_bytes())
    if case == "input-runtime":
        start = json.loads((evidence / "build-start.json").read_bytes())
        ci = load("runtime_oracle", Path(__file__).parents[1] / "run.py")
        libraries = [(role, Path(value["path"])) for role, value in
                     start["consumer_inputs"]["files"].items()
                     if role.startswith("runtime:") and
                     value["path"].startswith(str(runtime / "lib") + "/")]
        assert libraries, "owned real Git runtime library unavailable"
        role, path = libraries[0]
        with path.open("ab") as stream:
            stream.write(b"!")
        (work / "mutated-runtime-role").write_text(role)
        try:
            ci.require_recorded_consumer_inputs(start["consumer_inputs"], content=True)
        except ci.Refusal:
            pass
        else:
            raise AssertionError("real Python runtime oracle accepted mutation")
        return
    if case in ("runtime-path-build", "runtime-path-boot"):
        ci = load("runtime_path_oracle", Path(__file__).parents[1] / "run.py")
        name = "build-start.json" if case == "runtime-path-build" else "boot-inputs.json"
        record = document(name)
        custody = record["consumer_inputs"] if case == "runtime-path-build" else record
        libraries = [(role, Path(value["path"])) for role, value in
                     custody["files"].items() if role.startswith("runtime:")]
        assert libraries, "real discovered runtime library unavailable"
        role, path = libraries[0]
        redirected = work / "redirected-runtime"
        copy_file(path, redirected)
        file_paths = {key: Path(value["path"]) for key, value in custody["files"].items()}
        file_paths[role] = redirected
        tree_paths = {key: Path(value["path"]) for key, value in custody["trees"].items()}
        changed = ci.record_input_paths(
            file_paths, tree_paths, scope="consumer" if case == "runtime-path-build" else "boot")
        assert changed["files"][role]["sha256"] == custody["files"][role]["sha256"]
        assert set(changed["files"]) == set(custody["files"])
        ci.require_recorded_consumer_inputs(changed, content=True)
        if case == "runtime-path-build":
            record["consumer_inputs"] = changed
        else:
            record = changed
        put(name, record)
    elif case in ("source-custody", "extra-tool", "missing-tool",
                "dependency-custody", "bison-custody",
                "supervisor-source", "supervisor-runtime"):
        start = document("build-start.json")
        if case == "source-custody":
            start["source_custody"]["physical_sha256"] = "0" * 64
        elif case == "dependency-custody":
            start["dependencies"]["restore_directory"]["metadata"][1] += 1
        elif case == "bison-custody":
            start["bison_data"]["sha256"] = "0" * 64
        elif case in ("supervisor-source", "supervisor-runtime"):
            ci = load("supervisor_oracle", Path(__file__).parents[1] / "run.py")
            ci.REPO = repository
            ci.COMMAND_TOOL_PATHS["git"] = start["consumer_inputs"]["files"]["tool:git"]["path"]
            key = "source_map" if case == "supervisor-source" else "runtime_map"
            guarded = start["command_supervisor"][key]
            records = guarded["records"]
            records[sorted(records)[0]]["metadata"][1] += 1
            domain = "uk.wamr.command-supervisor-" + ("source" if key == "source_map" else "runtime") + "-v1"
            start["command_supervisor"][key] = ci.guarded_record_map(domain, records)
            assert ci.command_supervisor_state(runtime, start["consumer_inputs"]) != start["command_supervisor"]
        else:
            consumer = start["consumer_inputs"]
            if case == "extra-tool":
                consumer["files"]["tool:unexpected"] = copy.deepcopy(consumer["files"]["tool:git"])
            else:
                del consumer["files"]["tool:make"]
            unsealed = dict(consumer)
            unsealed.pop("aggregate_sha256")
            consumer["aggregate_sha256"] = hashlib.sha256(
                json.dumps(unsealed, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        put("build-start.json", start)
    elif case == "boot-path":
        boot = document("boot-inputs.json")
        boot["files"]["local_boot_tool"]["path"] = boot["files"]["qemu"]["path"]
        unsealed = dict(boot)
        unsealed.pop("aggregate_sha256")
        boot["aggregate_sha256"] = hashlib.sha256(
            json.dumps(unsealed, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        put("boot-inputs.json", boot)
    elif case == "boot-pin":
        request_path = runtime / "compute/boot-raw-x2apic/request.json"
        request = json.loads(request_path.read_bytes())
        request["pins"][3]["inode"] += 1
        save(request_path, request)
        record = document("raw-x2apic-compute.json")
        record["input_pins"] = request["pins"]
        record["request_sha256"] = digest(request_path)
        put("raw-x2apic-compute.json", record)
    elif case == "command-identity":
        package = Path(__file__).parents[1]
        witness = load("mutation_witness", package / "tests/test_adapter.py")
        record = document("command-config.json")
        record["supervisor"]["request"]["supervisor"]["identity"]["inode"] += 1
        witness.Evidence().rehash_supervised_binding(record)
        start = document("build-start.json")
        identities = {role: identity(value) for role, value in start["consumer_inputs"]["files"].items()}
        try:
            witness.ci.validate_supervised_command_binding(
                record, "config", identities, transport_context="trusted_inner_zip")
        except witness.ci.Refusal:
            pass
        else:
            raise AssertionError("real Python identity oracle accepted mutation")
        put("command-config.json", record)
    elif case == "image-chain":
        gate = document("fixed-vhd-derivation-gate.json")
        gate["derived_output_absent"] = False
        put("fixed-vhd-derivation-gate.json", gate)
    else:
        raise AssertionError(case)
    save(evidence / "result.json", result)


if __name__ == "__main__":
    os.umask(0o077)
    if sys.argv[1] == "prepare":
        prepare(sys.argv[2:])
    elif sys.argv[1] == "stage-git":
        stage_git(*sys.argv[2:])
    elif sys.argv[1] == "mutate":
        mutate(*sys.argv[2:])
    else:
        raise AssertionError(sys.argv[1])
