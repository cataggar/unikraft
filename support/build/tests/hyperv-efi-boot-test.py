#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause

import argparse
import os
from pathlib import Path
import shutil
import subprocess
import tempfile


def validate_boot_log(
    text, expected, main_return=0, required_markers=(), forbidden_markers=()
):
    for failure in ("Unikraft Crash", "Assertion failure", "Exception Type"):
        if failure in text:
            raise ValueError(f"guest reported {failure}")
    for marker in (
        "Hyper-V Hv#1 hypercall page enabled",
        "Hyper-V SynIC:",
        "Powered by",
        "Calling main(",
        expected,
        f"main returned {main_return}",
    ):
        if marker not in text:
            raise ValueError(f"missing boot milestone: {marker}")
    for marker in required_markers:
        if marker not in text:
            raise ValueError(f"missing required marker: {marker}")
    for marker in forbidden_markers:
        if marker in text:
            raise ValueError(f"forbidden marker present: {marker}")


def main():
    parser = argparse.ArgumentParser(
        description="Hyper-V EFI application boot with explicit CPU count, not I/O acceptance"
    )
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--image", type=Path)
    source.add_argument(
        "--raw-disk", type=Path,
        help="Boot this exact raw disk read-only instead of a directory-backed ESP",
    )
    parser.add_argument("--ovmf-code", type=Path, required=True)
    parser.add_argument("--ovmf-vars", type=Path, required=True)
    parser.add_argument("--work-dir", type=Path, required=True)
    parser.add_argument("--expect", required=True)
    parser.add_argument("--expect-main-return", type=int, default=0)
    parser.add_argument("--require-marker", action="append", default=[])
    parser.add_argument("--forbid-marker", action="append", default=[])
    parser.add_argument("--qemu", default="qemu-system-x86_64")
    parser.add_argument("--cpus", type=int, default=1)
    parser.add_argument(
        "--disable-x2apic", action="store_true",
        help="Mask x2APIC in CPUID to exercise the legacy APIC fallback",
    )
    parser.add_argument("--timeout", type=float, default=30)
    args = parser.parse_args()
    if args.timeout <= 0:
        parser.error("--timeout must be positive")
    if not 1 <= args.cpus <= 8:
        parser.error("--cpus must be between 1 and 8")
    if args.disable_x2apic and args.cpus != 1:
        parser.error("legacy xAPIC requires exactly one CPU")
    if not args.expect:
        parser.error("--expect must be nonempty")

    args.work_dir.mkdir(parents=True, exist_ok=True)
    work = args.work_dir.resolve()
    log_path = work / "hyperv-efi-boot.log"
    with tempfile.TemporaryDirectory(prefix="efi-boot-", dir=work) as temp:
        root = Path(temp)
        if args.raw_disk is not None:
            disk = args.raw_disk.resolve(strict=True)
            if not disk.is_file():
                parser.error("--raw-disk must be a regular file")
            (root / "disk.raw").symlink_to(disk)
            boot_drive = "if=virtio,format=raw,readonly=on,file=disk.raw"
        else:
            boot = root / "esp/EFI/BOOT"
            boot.mkdir(parents=True)
            shutil.copyfile(args.image, boot / "BOOTX64.EFI")
            boot_drive = "format=raw,file=fat:rw:esp"
        shutil.copyfile(args.ovmf_vars, root / "OVMF_VARS.fd")
        shutil.copyfile(args.ovmf_code, root / "OVMF_CODE.fd")
        cpu = (
            "host,hv-relaxed,hv-vapic,hv-spinlocks=0x1fff,hv-time,"
            "hv-synic,hv-stimer,hv-vpindex,hv-runtime,hv-frequencies"
        )
        if args.disable_x2apic:
            cpu += ",x2apic=off"
        command = [
            args.qemu,
            "-machine", "q35,accel=kvm",
            "-cpu", cpu,
            "-smp", str(args.cpus), "-m", "512M",
            "-drive", "if=pflash,format=raw,readonly=on,file=OVMF_CODE.fd",
            "-drive", "if=pflash,format=raw,file=OVMF_VARS.fd",
            "-drive", boot_drive,
            "-device", "vmbus-bridge,irq=15",
            "-display", "none", "-serial", "stdio",
            "-monitor", "none", "-no-reboot", "-nic", "none",
        ]
        try:
            with log_path.open("wb") as log:
                result = subprocess.run(
                    command, cwd=root,
                    env={**os.environ, "TMPDIR": str(root)},
                    stdout=log, stderr=subprocess.STDOUT,
                    timeout=args.timeout, check=False,
                )
            if result.returncode:
                raise ValueError(f"QEMU exited with {result.returncode}")
            validate_boot_log(
                log_path.read_text(errors="replace").replace("\0", ""),
                args.expect,
                args.expect_main_return,
                args.require_marker,
                args.forbid_marker,
            )
        except (subprocess.TimeoutExpired, ValueError) as error:
            raise SystemExit(f"{error}; guest log: {log_path}") from error
    print(f"Hyper-V application boot/log assertions passed; guest log: {log_path}")
    print("This does not establish VMBus, StorVSC, NetVSC, or Azure acceptance.")


if __name__ == "__main__":
    main()
