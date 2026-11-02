// SPDX-License-Identifier: BSD-3-Clause
const std = @import("std");
const scorecard = @import("scorecard");

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;
    const io = init.io;
    const args = try init.minimal.args.toSlice(init.arena.allocator());

    if (args.len < 2) return error.InvalidArguments;
    const subcmd = args[1];

    if (std.mem.eql(u8, subcmd, "verify")) {
        var dir_a: ?[]const u8 = null;
        var dir_b: ?[]const u8 = null;
        var dbg_rel: []const u8 = "unikraft_hyperv-x86_64.dbg";
        var efi_rel: []const u8 = "BOOTX64.EFI";
        var raw_rel: []const u8 = "unikraft.raw";
        var vhd_rel: []const u8 = "unikraft.vhd";
        var json_out: ?[]const u8 = null;
        var md_out: ?[]const u8 = null;
        var uk_idle_heap: u64 = 98_304;
        var uk_peak_heap: u64 = 131_072;
        var vm_ram_bytes: u64 = 8 * 1024 * 1024 * 1024;

        var idx: usize = 2;
        while (idx < args.len) : (idx += 1) {
            if (std.mem.eql(u8, args[idx], "--dir-a") and idx + 1 < args.len) {
                idx += 1;
                dir_a = args[idx];
            } else if (std.mem.eql(u8, args[idx], "--dir-b") and idx + 1 < args.len) {
                idx += 1;
                dir_b = args[idx];
            } else if (std.mem.eql(u8, args[idx], "--dbg") and idx + 1 < args.len) {
                idx += 1;
                dbg_rel = args[idx];
            } else if (std.mem.eql(u8, args[idx], "--efi") and idx + 1 < args.len) {
                idx += 1;
                efi_rel = args[idx];
            } else if (std.mem.eql(u8, args[idx], "--raw") and idx + 1 < args.len) {
                idx += 1;
                raw_rel = args[idx];
            } else if (std.mem.eql(u8, args[idx], "--vhd") and idx + 1 < args.len) {
                idx += 1;
                vhd_rel = args[idx];
            } else if (std.mem.eql(u8, args[idx], "--uk-idle-heap") and idx + 1 < args.len) {
                idx += 1;
                uk_idle_heap = try std.fmt.parseInt(u64, args[idx], 10);
            } else if (std.mem.eql(u8, args[idx], "--uk-peak-heap") and idx + 1 < args.len) {
                idx += 1;
                uk_peak_heap = try std.fmt.parseInt(u64, args[idx], 10);
            } else if (std.mem.eql(u8, args[idx], "--vm-ram-bytes") and idx + 1 < args.len) {
                idx += 1;
                vm_ram_bytes = try std.fmt.parseInt(u64, args[idx], 10);
            } else if (std.mem.eql(u8, args[idx], "--json-out") and idx + 1 < args.len) {
                idx += 1;
                json_out = args[idx];
            } else if (std.mem.eql(u8, args[idx], "--markdown-out") and idx + 1 < args.len) {
                idx += 1;
                md_out = args[idx];
            } else {
                return error.InvalidArguments;
            }
        }

        const a = dir_a orelse return error.InvalidArguments;
        const b = dir_b orelse return error.InvalidArguments;

        const proof = try scorecard.verifyTwoDirectoryReproducibility(
            allocator,
            io,
            a,
            b,
            dbg_rel,
            efi_rel,
            raw_rel,
            vhd_rel,
        );

        const baseline: scorecard.LinuxBaselineMetadata = .{
            .distro = "24.04 LTS",
            .kernel_release = "6.8.0-azure",
            .installed_packages = 482,
            .shared_libraries_linked = 3,
            .running_services = 29,
            .os_disk_bytes = 32_212_254_720,
            .idle_rss_bytes = 2_097_152,
            .load_peak_rss_bytes = 2_621_440,
        };

        const card = try scorecard.buildScorecard(
            proof,
            uk_idle_heap,
            uk_peak_heap,
            vm_ram_bytes,
            baseline,
            .{},
        );

        const json_bytes = try scorecard.renderScorecardJson(allocator, card);
        defer allocator.free(json_bytes);
        if (json_out) |p| {
            try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = p, .data = json_bytes });
        }

        if (md_out) |p| {
            const md_bytes = try scorecard.renderScorecardMarkdown(allocator, card);
            defer allocator.free(md_bytes);
            try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = p, .data = md_bytes });
        }
        return;
    }

    return error.InvalidArguments;
}
