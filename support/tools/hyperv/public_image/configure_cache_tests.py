#!/usr/bin/env python3
"""Exercise the public-image configure graph against a private synthetic tree."""
import hashlib
import pathlib
import shutil
import subprocess
import sys


def main():
    if len(sys.argv) != 3:
        raise SystemExit("usage: configure_cache_tests.py ZIG FRESH_PROJECT_DIRECTORY")
    zig = pathlib.Path(sys.argv[1]).resolve(strict=True)
    root = pathlib.Path(sys.argv[2]).absolute()
    if root.exists():
        raise SystemExit("fixture directory must not exist")
    if pathlib.Path.cwd().resolve() not in root.parents:
        raise SystemExit("fixture directory must be inside the current project")
    root.mkdir(mode=0o700, parents=True)
    try:
        package = root / "support/tools/hyperv/public_image"
        package.mkdir(parents=True)
        shutil.copyfile(pathlib.Path(__file__).with_name("build.zig"), package / "build.zig")
        (package / "build.zig.zon").write_text(
            '.{ .name = .unikraft_hyperv_public_image, .version = "0.1.0", '
            '.fingerprint = 0xa451ae17f463e7f9, .minimum_zig_version = "0.17.0", '
            '.dependencies = .{ .miz_source = .{ .path = "../../../../miz" } }, .paths = .{""} }\n'
        )
        miz = root / "miz"
        miz.mkdir()
        (miz / "build.zig.zon").write_text(
            '.{ .name = .miz, .version = "0.0.0", .fingerprint = 0xbba1c9adc2f802c1, .paths = .{""} }\n'
        )
        (miz / "root.zig").write_text("")
        (miz / "build.zig").write_text(
            'const std = @import("std"); pub fn build(b: *std.Build) void { '
            '_ = b.addModule("miz", .{ .root_source_file = b.path("root.zig"), '
            '.target = b.standardTargetOptions(.{}), .optimize = b.standardOptimizeOption(.{}) }); }\n'
        )
        for name in ("core.zig", "local_boot/root.zig"):
            path = package.parent / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("")
        for name in ("kconfig.zig", "postprocess-elf.zig"):
            path = root / "support/build" / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("")
        (package.parent / "sha256_clear_upper.S").write_text("")
        (package / "root.zig").write_text('pub const pins = @import("producer_pins");\n')
        (package / "main.zig").write_text(
            'const std = @import("std"); pub fn main(init: std.process.Init) !void { '
            'const pin = @import("public_image").pins.peer_sha256; '
            'var bytes: [65]u8 = undefined; '
            '@memcpy(bytes[0..64], &std.fmt.bytesToHex(pin, .lower)); bytes[64] = \'\\n\'; '
            'try std.Io.File.stdout().writeStreamingAll(init.io, &bytes); }\n'
        )
        peer = root / "support/scripts/hyperv-network-peer.py"
        peer.parent.mkdir(parents=True)
        command = [
            str(zig), "build", "--build-file", str(package / "build.zig"),
            "--cache-dir", str(root / ".cache"), "--prefix", str(root / "out"),
            "-j2", "install", "--summary", "failures",
        ]
        for mode in ("debug", "safe"):
            selected = command + ["-Doptimize=" + mode]
            for payload in (b"# reviewed peer A\n", b"# reviewed peer B\n"):
                peer.write_bytes(payload)
                subprocess.run(selected, check=True)
                pin = subprocess.check_output([root / "out/bin/uk-hyperv-public-image"]).strip()
                if pin != hashlib.sha256(payload).hexdigest().encode():
                    raise SystemExit("stale configure-time peer commitment")
            peer.unlink()
            refused = subprocess.run(selected, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            if refused.returncode == 0 or b"public peer source unavailable" not in refused.stdout:
                raise SystemExit("deleted peer source was not refused on a warm configure cache")
        print("public-image debug/safe warm configure caches update peer bytes and refuse deletion")
    finally:
        shutil.rmtree(root)


if __name__ == "__main__":
    main()
