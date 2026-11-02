// SPDX-License-Identifier: BSD-3-Clause
const std = @import("std");
const scorecard = @import("scorecard");

fn writeSyntheticElf(allocator: std.mem.Allocator, text_payload: []const u8) ![]u8 {
    const shstrtab = "\x00.shstrtab\x00.text\x00.rodata\x00.data\x00.bss\x00";
    const rodata_payload = "UNIKRAFT-RODATA-PAYLOAD";
    const data_payload = "UK-DATA!";
    const bss_size: u64 = 4096;

    const ehdr_size = 64;
    const shdr_size = 64;
    const shnum = 6;
    const shoff = ehdr_size;
    const payloads_off = shoff + shdr_size * shnum;

    const str_off = payloads_off;
    const text_off = str_off + shstrtab.len;
    const rodata_off = text_off + text_payload.len;
    const data_off = rodata_off + rodata_payload.len;
    const total_len = data_off + data_payload.len;

    const buf = try allocator.alloc(u8, total_len);
    @memset(buf, 0);

    buf[0] = 0x7f;
    buf[1] = 'E';
    buf[2] = 'L';
    buf[3] = 'F';
    buf[4] = 2; // ELFCLASS64
    buf[5] = 1; // ELFDATA2LSB
    buf[6] = 1; // EV_CURRENT

    std.mem.writeInt(u16, buf[16..18], 2, .little); // ET_EXEC
    std.mem.writeInt(u16, buf[18..20], 62, .little); // EM_X86_64
    std.mem.writeInt(u32, buf[20..24], 1, .little);
    std.mem.writeInt(u64, buf[40..48], shoff, .little); // e_shoff
    std.mem.writeInt(u16, buf[52..54], ehdr_size, .little);
    std.mem.writeInt(u16, buf[58..60], shdr_size, .little);
    std.mem.writeInt(u16, buf[60..62], shnum, .little);
    std.mem.writeInt(u16, buf[62..64], 1, .little); // e_shstrndx = 1

    // Section 1: .shstrtab (name offset 1)
    writeShdr(buf, shoff + 1 * shdr_size, 1, 3, str_off, shstrtab.len);
    // Section 2: .text (name offset 11)
    writeShdr(buf, shoff + 2 * shdr_size, 11, 1, text_off, text_payload.len);
    // Section 3: .rodata (name offset 17)
    writeShdr(buf, shoff + 3 * shdr_size, 17, 1, rodata_off, rodata_payload.len);
    // Section 4: .data (name offset 25)
    writeShdr(buf, shoff + 4 * shdr_size, 25, 1, data_off, data_payload.len);
    // Section 5: .bss (name offset 31, SHT_NOBITS = 8)
    writeShdr(buf, shoff + 5 * shdr_size, 31, 8, data_off + data_payload.len, bss_size);

    @memcpy(buf[str_off .. str_off + shstrtab.len], shstrtab);
    @memcpy(buf[text_off .. text_off + text_payload.len], text_payload);
    @memcpy(buf[rodata_off .. rodata_off + rodata_payload.len], rodata_payload);
    @memcpy(buf[data_off .. data_off + data_payload.len], data_payload);

    return buf;
}

fn writeShdr(buf: []u8, base: usize, name: u32, sh_type: u32, offset: usize, size: u64) void {
    std.mem.writeInt(u32, buf[base..][0..4], name, .little);
    std.mem.writeInt(u32, buf[base + 4 ..][0..4], sh_type, .little);
    std.mem.writeInt(u64, buf[base + 24 ..][0..8], @intCast(offset), .little);
    std.mem.writeInt(u64, buf[base + 32 ..][0..8], size, .little);
}

fn populateBuildDir(
    allocator: std.mem.Allocator,
    io: std.Io,
    dir: std.Io.Dir,
    sub_dir: []const u8,
    text_payload: []const u8,
    raw_size: u64,
    vhd_size: u64,
) !void {
    try dir.createDirPath(io, sub_dir);
    const elf = try writeSyntheticElf(allocator, text_payload);
    defer allocator.free(elf);

    const dbg_path = try std.fmt.allocPrint(allocator, "{s}/unikraft.dbg", .{sub_dir});
    defer allocator.free(dbg_path);
    const efi_path = try std.fmt.allocPrint(allocator, "{s}/BOOTX64.EFI", .{sub_dir});
    defer allocator.free(efi_path);
    const raw_path = try std.fmt.allocPrint(allocator, "{s}/unikraft.raw", .{sub_dir});
    defer allocator.free(raw_path);
    const vhd_path = try std.fmt.allocPrint(allocator, "{s}/unikraft.vhd", .{sub_dir});
    defer allocator.free(vhd_path);

    try dir.writeFile(io, .{ .sub_path = dbg_path, .data = elf });
    try dir.writeFile(io, .{ .sub_path = efi_path, .data = "MZ-PE32+-BOOTX64-EFI-PAYLOAD" });

    var raw_file = try dir.createFile(io, raw_path, .{});
    defer raw_file.close(io);
    try raw_file.setLength(io, raw_size);

    var vhd_file = try dir.createFile(io, vhd_path, .{});
    defer vhd_file.close(io);
    try vhd_file.setLength(io, vhd_size);
}

test "two-directory reproducibility verifier passes identical builds and rejects drift" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try populateBuildDir(
        allocator,
        io,
        tmp.dir,
        "build-a",
        "UNIKRAFT-TEXT-CODE-V1",
        scorecard.expected_raw_bytes,
        scorecard.expected_vhd_bytes,
    );
    try populateBuildDir(
        allocator,
        io,
        tmp.dir,
        "build-b",
        "UNIKRAFT-TEXT-CODE-V1",
        scorecard.expected_raw_bytes,
        scorecard.expected_vhd_bytes,
    );

    const root_path = try tmp.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(root_path);
    const dir_a = try std.fmt.allocPrint(allocator, "{s}/build-a", .{root_path});
    defer allocator.free(dir_a);
    const dir_b = try std.fmt.allocPrint(allocator, "{s}/build-b", .{root_path});
    defer allocator.free(dir_b);

    const proof = try scorecard.verifyTwoDirectoryReproducibility(
        allocator,
        io,
        dir_a,
        dir_b,
        "unikraft.dbg",
        "BOOTX64.EFI",
        "unikraft.raw",
        "unikraft.vhd",
    );
    try std.testing.expect(proof.reproducible);
    try std.testing.expectEqual(@as(u64, 21), proof.stages.dbg_sections.text_bytes);
    try std.testing.expectEqual(scorecard.expected_raw_bytes, proof.stages.unikraft_raw.size_bytes);
    try std.testing.expectEqual(scorecard.expected_vhd_bytes, proof.stages.unikraft_vhd.size_bytes);

    // Mutate build-b .text section and confirm ReproducibilityMismatch
    try populateBuildDir(
        allocator,
        io,
        tmp.dir,
        "build-b",
        "UNIKRAFT-TEXT-CODE-V2",
        scorecard.expected_raw_bytes,
        scorecard.expected_vhd_bytes,
    );
    try std.testing.expectError(
        error.ReproducibilityMismatch,
        scorecard.verifyTwoDirectoryReproducibility(
            allocator,
            io,
            dir_a,
            dir_b,
            "unikraft.dbg",
            "BOOTX64.EFI",
            "unikraft.raw",
            "unikraft.vhd",
        ),
    );
}

test "component inventory, budget enforcement, and scorecard JSON/Markdown rendering" {
    const allocator = std.testing.allocator;
    const inv = scorecard.extractComponentInventory();
    try std.testing.expect(inv.registered_libraries >= 35);
    try std.testing.expect(inv.registered_objects >= 150);
    try std.testing.expectEqual(@as(usize, 2), inv.http_service_objects);
    try std.testing.expectEqual(@as(usize, 0), inv.shared_libraries_count);

    const elf = try writeSyntheticElf(allocator, "UNIKRAFT-HTTP-KERNEL");
    defer allocator.free(elf);
    const sections = try scorecard.inspectElfSections(elf);

    const proof: scorecard.ReproducibilityProof = .{
        .reproducible = true,
        .stages = .{
            .dbg_elf = .{ .size_bytes = elf.len, .sha256_hex = @splat('a') },
            .dbg_sections = sections,
            .bootx64_efi = .{ .size_bytes = 245_760, .sha256_hex = @splat('b') },
            .unikraft_raw = .{ .size_bytes = scorecard.expected_raw_bytes, .sha256_hex = @splat('c') },
            .unikraft_vhd = .{ .size_bytes = scorecard.expected_vhd_bytes, .sha256_hex = @splat('d') },
        },
    };

    const baseline: scorecard.LinuxBaselineMetadata = .{
        .distro = "24.04 LTS",
        .kernel_release = "6.8.0-1018-azure",
        .installed_packages = 482,
        .shared_libraries_linked = 3,
        .running_services = 29,
        .os_disk_bytes = 32_212_254_720,
        .idle_rss_bytes = 2_097_152,
        .load_peak_rss_bytes = 2_621_440,
    };

    const card = try scorecard.buildScorecard(
        proof,
        98_304,
        131_072,
        8 * 1024 * 1024 * 1024,
        baseline,
        .{},
    );
    try std.testing.expect(card.budget_passed);

    const json_out = try scorecard.renderScorecardJson(allocator, card);
    defer allocator.free(json_out);
    try std.testing.expect(std.mem.indexOf(u8, json_out, "uk.hyperv.footprint-scorecard.v1") != null);
    try std.testing.expect(std.mem.indexOf(u8, json_out, "69206016") != null);
    try std.testing.expect(std.mem.indexOf(u8, json_out, "69206528") != null);

    const md_out = try scorecard.renderScorecardMarkdown(allocator, card);
    defer allocator.free(md_out);
    try std.testing.expect(std.mem.indexOf(u8, md_out, "# Hyper-V Footprint & Reproducible-Build Scorecard") != null);

    // Budget violation check
    try std.testing.expectError(
        error.BudgetExceeded,
        scorecard.buildScorecard(
            proof,
            98_304,
            64 * 1024 * 1024,
            8 * 1024 * 1024 * 1024,
            baseline,
            .{ .max_unikraft_peak_heap_bytes = 16 * 1024 * 1024 },
        ),
    );
}
