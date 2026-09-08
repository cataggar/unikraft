#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-3-Clause

import argparse
import os
from pathlib import Path
import shutil
import subprocess
import tempfile


def validate_boot_log(text, expected):
    for failure in ("Unikraft Crash", "Assertion failure", "Exception Type"):
        if failure in text:
            raise ValueError(f"guest reported {failure}")
    for marker in (
        "Hyper-V Hv#1 hypercall page enabled",
        "Hyper-V SynIC:",
        "Powered by",
        "Calling main(",
        expected,
        "main returned 0",
    ):
        if marker not in text:
            raise ValueError(f"missing boot milestone: {marker}")


def main():
    parser = argparse.ArgumentParser(
        description="Single-CPU Hyper-V EFI application boot, not I/O acceptance"
    )
    parser.add_argument("--image", type=Path, required=True)
    parser.add_argument("--ovmf-code", type=Path, required=True)
    parser.add_argument("--ovmf-vars", type=Path, required=True)
    parser.add_argument("--work-dir", type=Path, required=True)
    parser.add_argument("--expect", required=True)
    parser.add_argument("--qemu", default="qemu-system-x86_64")
    parser.add_argument("--timeout", type=float, default=30)
    args = parser.parse_args()
    if args.timeout <= 0:
        parser.error("--timeout must be positive")
    if not args.expect:
        parser.error("--expect must be nonempty")

    args.work_dir.mkdir(parents=True, exist_ok=True)
    work = args.work_dir.resolve()
    log_path = work / "hyperv-efi-boot.log"
    with tempfile.TemporaryDirectory(prefix="efi-boot-", dir=work) as temp:
        root = Path(temp)
        boot = root / "esp/EFI/BOOT"
        boot.mkdir(parents=True)
        shutil.copyfile(args.image, boot / "BOOTX64.EFI")
        shutil.copyfile(args.ovmf_vars, root / "OVMF_VARS.fd")
        shutil.copyfile(args.ovmf_code, root / "OVMF_CODE.fd")
        command = [
            args.qemu,
            "-machine", "q35,accel=kvm",
            "-cpu", "host,hv-relaxed,hv-vapic,hv-spinlocks=0x1fff,hv-time,"
            "hv-synic,hv-stimer,hv-vpindex,hv-runtime,hv-frequencies",
            "-smp", "1", "-m", "512M",
            "-drive", "if=pflash,format=raw,readonly=on,file=OVMF_CODE.fd",
            "-drive", "if=pflash,format=raw,file=OVMF_VARS.fd",
            "-drive", "format=raw,file=fat:rw:esp",
            "-device", "vmbus-bridge,irq=15",
            "-device", "hv-balloon",
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
            )
        except (subprocess.TimeoutExpired, ValueError) as error:
            raise SystemExit(f"{error}; guest log: {log_path}") from error
    print(f"Hyper-V application boot passed; guest log: {log_path}")
    print("This does not establish VMBus, StorVSC, NetVSC, or Azure acceptance.")


if __name__ == "__main__":
    main()
