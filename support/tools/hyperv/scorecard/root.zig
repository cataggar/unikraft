// SPDX-License-Identifier: BSD-3-Clause
const std = @import("std");
const core = @import("hyperv_core");
const native_image_data = @import("native_image_data");

pub const Allocator = std.mem.Allocator;
pub const Io = std.Io;

pub const schema_version = "uk.hyperv.footprint-scorecard.v1";
pub const expected_raw_bytes: u64 = 69_206_016;
pub const expected_vhd_bytes: u64 = 69_206_528;

pub const Error = error{
    InvalidArguments,
    InvalidElfHeader,
    InvalidSectionTable,
    MissingRequiredSection,
    ArtifactSizeMismatch,
    ReproducibilityMismatch,
    BudgetExceeded,
    InvalidBaselineJson,
    InvalidScorecardJson,
};

pub const ElfSectionMetrics = struct {
    text_bytes: u64,
    rodata_bytes: u64,
    data_bytes: u64,
    bss_bytes: u64,
    text_sha256: [64]u8,
    rodata_sha256: [64]u8,
    data_sha256: [64]u8,
    bss_sha256: [64]u8,
};

pub const StageArtifactDigest = struct {
    size_bytes: u64,
    sha256_hex: [64]u8,
};

pub const BuildStageSet = struct {
    dbg_elf: StageArtifactDigest,
    dbg_sections: ElfSectionMetrics,
    bootx64_efi: StageArtifactDigest,
    unikraft_raw: StageArtifactDigest,
    unikraft_vhd: StageArtifactDigest,
};

pub const ReproducibilityProof = struct {
    reproducible: bool,
    stages: BuildStageSet,
};

pub const ComponentInventory = struct {
    registered_libraries: usize,
    registered_objects: usize,
    network_enabled_libraries: usize,
    network_enabled_objects: usize,
    http_service_objects: usize,
    shared_libraries_count: usize,
    systemd_units_count: usize,
    background_daemons_count: usize,
};

pub const LinuxBaselineMetadata = struct {
    distro: []const u8,
    kernel_release: []const u8,
    installed_packages: u64,
    shared_libraries_linked: u64,
    running_services: u64,
    os_disk_bytes: u64,
    idle_rss_bytes: u64,
    load_peak_rss_bytes: u64,
};

pub const RuntimeMemoryAccounting = struct {
    configured_vm_ram_bytes: u64,
    unikraft_static_image_bytes: u64,
    unikraft_idle_heap_bytes: u64,
    unikraft_load_peak_heap_bytes: u64,
    linux_idle_rss_bytes: u64,
    linux_load_peak_rss_bytes: u64,
};

pub const ArtifactBudgets = struct {
    max_bootx64_efi_bytes: u64 = 2 * 1024 * 1024,
    max_text_bytes: u64 = 1024 * 1024,
    max_rodata_bytes: u64 = 512 * 1024,
    max_data_bytes: u64 = 256 * 1024,
    max_bss_bytes: u64 = 2 * 1024 * 1024,
    exact_raw_bytes: u64 = expected_raw_bytes,
    exact_vhd_bytes: u64 = expected_vhd_bytes,
    max_unikraft_peak_heap_bytes: u64 = 16 * 1024 * 1024,
};

pub const Scorecard = struct {
    proof: ReproducibilityProof,
    inventory: ComponentInventory,
    memory: RuntimeMemoryAccounting,
    linux_baseline: LinuxBaselineMetadata,
    budgets: ArtifactBudgets,
    budget_passed: bool,
};

const Elf64_Ehdr = extern struct {
    e_ident: [16]u8,
    e_type: u16,
    e_machine: u16,
    e_version: u32,
    e_entry: u64,
    e_phoff: u64,
    e_shoff: u64,
    e_flags: u32,
    e_ehsize: u16,
    e_phentsize: u16,
    e_phnum: u16,
    e_shentsize: u16,
    e_shnum: u16,
    e_shstrndx: u16,
};

const Elf64_Shdr = extern struct {
    sh_name: u32,
    sh_type: u32,
    sh_flags: u64,
    sh_addr: u64,
    sh_offset: u64,
    sh_size: u64,
    sh_link: u32,
    sh_info: u32,
    sh_addralign: u64,
    sh_entsize: u64,
};

const SHT_NOBITS: u32 = 8;

pub fn inspectElfSections(bytes: []const u8) Error!ElfSectionMetrics {
    if (bytes.len < @sizeOf(Elf64_Ehdr)) return error.InvalidElfHeader;
    if (!std.mem.eql(u8, bytes[0..4], "\x7fELF")) return error.InvalidElfHeader;
    if (bytes[4] != 2 or bytes[5] != 1) return error.InvalidElfHeader;

    const ehdr = std.mem.bytesAsValue(Elf64_Ehdr, bytes[0..@sizeOf(Elf64_Ehdr)]);
    const shoff: usize = @intCast(ehdr.e_shoff);
    const shentsize: usize = ehdr.e_shentsize;
    const shnum: usize = ehdr.e_shnum;
    const shstrndx: usize = ehdr.e_shstrndx;

    if (shoff == 0 or shentsize < @sizeOf(Elf64_Shdr) or shnum == 0 or shstrndx >= shnum)
        return error.InvalidSectionTable;
    const table_end = std.math.mul(usize, shentsize, shnum) catch return error.InvalidSectionTable;
    if (shoff + table_end > bytes.len) return error.InvalidSectionTable;

    const str_hdr = readShdr(bytes, shoff, shentsize, shstrndx);
    const str_off: usize = @intCast(str_hdr.sh_offset);
    const str_size: usize = @intCast(str_hdr.sh_size);
    if (str_off + str_size > bytes.len) return error.InvalidSectionTable;
    const shstrtab = bytes[str_off .. str_off + str_size];

    var metrics: ElfSectionMetrics = .{
        .text_bytes = 0,
        .rodata_bytes = 0,
        .data_bytes = 0,
        .bss_bytes = 0,
        .text_sha256 = @splat('0'),
        .rodata_sha256 = @splat('0'),
        .data_sha256 = @splat('0'),
        .bss_sha256 = @splat('0'),
    };
    var seen_text = false;
    var seen_rodata = false;
    var seen_data = false;
    var seen_bss = false;

    for (0..shnum) |idx| {
        const shdr = readShdr(bytes, shoff, shentsize, idx);
        if (shdr.sh_name >= shstrtab.len) return error.InvalidSectionTable;
        const name_tail = shstrtab[shdr.sh_name..];
        const nul = std.mem.indexOfScalar(u8, name_tail, 0) orelse return error.InvalidSectionTable;
        const sec_name = name_tail[0..nul];

        if (std.mem.eql(u8, sec_name, ".text")) {
            metrics.text_bytes = shdr.sh_size;
            metrics.text_sha256 = try hashSection(bytes, shdr);
            seen_text = true;
        } else if (std.mem.eql(u8, sec_name, ".rodata")) {
            metrics.rodata_bytes = shdr.sh_size;
            metrics.rodata_sha256 = try hashSection(bytes, shdr);
            seen_rodata = true;
        } else if (std.mem.eql(u8, sec_name, ".data")) {
            metrics.data_bytes = shdr.sh_size;
            metrics.data_sha256 = try hashSection(bytes, shdr);
            seen_data = true;
        } else if (std.mem.eql(u8, sec_name, ".bss")) {
            metrics.bss_bytes = shdr.sh_size;
            metrics.bss_sha256 = try hashSection(bytes, shdr);
            seen_bss = true;
        }
    }

    if (!seen_text or !seen_rodata or !seen_data or !seen_bss)
        return error.MissingRequiredSection;

    return metrics;
}

fn readShdr(bytes: []const u8, shoff: usize, shentsize: usize, idx: usize) Elf64_Shdr {
    const pos = shoff + idx * shentsize;
    var hdr: Elf64_Shdr = undefined;
    @memcpy(std.mem.asBytes(&hdr), bytes[pos .. pos + @sizeOf(Elf64_Shdr)]);
    return hdr;
}

fn sha256Hex(bytes: []const u8) [64]u8 {
    var digest: [32]u8 = undefined;
    core.Sha256.hash(bytes, &digest, .{});
    return std.fmt.bytesToHex(digest, .lower);
}

fn hashSection(bytes: []const u8, shdr: Elf64_Shdr) Error![64]u8 {
    if (shdr.sh_type == SHT_NOBITS) {
        var len_le: [8]u8 = undefined;
        std.mem.writeInt(u64, &len_le, shdr.sh_size, .little);
        return sha256Hex(&len_le);
    }
    const off: usize = @intCast(shdr.sh_offset);
    const sz: usize = @intCast(shdr.sh_size);
    if (off + sz > bytes.len) return error.InvalidSectionTable;
    return sha256Hex(bytes[off .. off + sz]);
}

pub fn inspectBuildDirectory(
    allocator: Allocator,
    io: Io,
    dir_path: []const u8,
    dbg_rel_path: []const u8,
    efi_rel_path: []const u8,
    raw_rel_path: []const u8,
    vhd_rel_path: []const u8,
) !BuildStageSet {
    const dbg_path = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ dir_path, dbg_rel_path });
    defer allocator.free(dbg_path);
    const efi_path = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ dir_path, efi_rel_path });
    defer allocator.free(efi_path);
    const raw_path = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ dir_path, raw_rel_path });
    defer allocator.free(raw_path);
    const vhd_path = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ dir_path, vhd_rel_path });
    defer allocator.free(vhd_path);

    const dbg_bytes = try Io.Dir.cwd().readFileAlloc(io, dbg_path, allocator, .limited(64 * 1024 * 1024));
    defer allocator.free(dbg_bytes);
    const sections = try inspectElfSections(dbg_bytes);
    const dbg_digest: StageArtifactDigest = .{
        .size_bytes = dbg_bytes.len,
        .sha256_hex = sha256Hex(dbg_bytes),
    };

    const efi_digest = try digestFileStreaming(io, efi_path);
    const raw_digest = try digestFileStreaming(io, raw_path);
    const vhd_digest = try digestFileStreaming(io, vhd_path);

    if (raw_digest.size_bytes != expected_raw_bytes) return error.ArtifactSizeMismatch;
    if (vhd_digest.size_bytes != expected_vhd_bytes) return error.ArtifactSizeMismatch;

    return .{
        .dbg_elf = dbg_digest,
        .dbg_sections = sections,
        .bootx64_efi = efi_digest,
        .unikraft_raw = raw_digest,
        .unikraft_vhd = vhd_digest,
    };
}

fn digestFileStreaming(io: Io, path: []const u8) !StageArtifactDigest {
    const file = try Io.Dir.cwd().openFile(io, path, .{});
    defer file.close(io);

    var hasher = core.Sha256.init(.{});
    var rbuf: [64 * 1024]u8 = undefined;
    var chunk: [64 * 1024]u8 = undefined;
    var reader = file.reader(io, &rbuf);
    var total_bytes: u64 = 0;

    while (true) {
        var vec = [_][]u8{&chunk};
        const n = reader.interface.readVec(&vec) catch |err| switch (err) {
            error.EndOfStream => break,
            else => return err,
        };
        if (n == 0) break;
        hasher.update(chunk[0..n]);
        total_bytes += n;
    }

    var digest: [32]u8 = undefined;
    hasher.final(&digest);
    return .{
        .size_bytes = total_bytes,
        .sha256_hex = std.fmt.bytesToHex(digest, .lower),
    };
}

pub fn verifyTwoDirectoryReproducibility(
    allocator: Allocator,
    io: Io,
    dir_a: []const u8,
    dir_b: []const u8,
    dbg_rel_path: []const u8,
    efi_rel_path: []const u8,
    raw_rel_path: []const u8,
    vhd_rel_path: []const u8,
) !ReproducibilityProof {
    const stage_a = try inspectBuildDirectory(allocator, io, dir_a, dbg_rel_path, efi_rel_path, raw_rel_path, vhd_rel_path);
    const stage_b = try inspectBuildDirectory(allocator, io, dir_b, dbg_rel_path, efi_rel_path, raw_rel_path, vhd_rel_path);

    if (!stagesEqual(stage_a, stage_b)) return error.ReproducibilityMismatch;

    return .{
        .reproducible = true,
        .stages = stage_a,
    };
}

pub fn stagesEqual(a: BuildStageSet, b: BuildStageSet) bool {
    return digestEqual(a.dbg_elf, b.dbg_elf) and
        digestEqual(a.bootx64_efi, b.bootx64_efi) and
        digestEqual(a.unikraft_raw, b.unikraft_raw) and
        digestEqual(a.unikraft_vhd, b.unikraft_vhd) and
        a.dbg_sections.text_bytes == b.dbg_sections.text_bytes and
        a.dbg_sections.rodata_bytes == b.dbg_sections.rodata_bytes and
        a.dbg_sections.data_bytes == b.dbg_sections.data_bytes and
        a.dbg_sections.bss_bytes == b.dbg_sections.bss_bytes and
        std.mem.eql(u8, &a.dbg_sections.text_sha256, &b.dbg_sections.text_sha256) and
        std.mem.eql(u8, &a.dbg_sections.rodata_sha256, &b.dbg_sections.rodata_sha256) and
        std.mem.eql(u8, &a.dbg_sections.data_sha256, &b.dbg_sections.data_sha256) and
        std.mem.eql(u8, &a.dbg_sections.bss_sha256, &b.dbg_sections.bss_sha256);
}

fn digestEqual(a: StageArtifactDigest, b: StageArtifactDigest) bool {
    return a.size_bytes == b.size_bytes and std.mem.eql(u8, &a.sha256_hex, &b.sha256_hex);
}

pub fn extractComponentInventory() ComponentInventory {
    const hyperv_extra_libs = [_]native_image_data.Library{
        native_image_data.x86_64_efi_vmbus,
        native_image_data.x86_64_efi_ukblkdev,
        native_image_data.x86_64_efi_storvsc,
        native_image_data.x86_64_efi_uknetdev,
        native_image_data.uklibparam,
        native_image_data.x86_64_efi_netvsc,
        native_image_data.x86_64_efi_ukrandom,
        native_image_data.x86_64_efi_ukrandom_lcpu,
        native_image_data.x86_64_efi_lwip,
    };

    var total_libs: usize = 0;
    var total_objects: usize = 0;
    var http_objects: usize = 0;

    for (native_image_data.x86_64.libraries) |lib| {
        if (std.mem.eql(u8, lib.name, "libvgacons") or
            std.mem.eql(u8, lib.name, "libukintctlr_xpic"))
        {
            continue;
        }
        total_libs += 1;
        if (std.mem.eql(u8, lib.name, "libkvmplat")) {
            total_objects += native_image_data.x86_64_efi_hyperv_platform.objects.len;
        } else if (std.mem.eql(u8, lib.name, "apphelloworld")) {
            total_objects += native_image_data.x86_64_efi_hyperv_acceptance_app.objects.len;
            for (native_image_data.x86_64_efi_hyperv_acceptance_app.objects) |obj| {
                if (std.mem.indexOf(u8, obj, "http_") != null) http_objects += 1;
            }
        } else if (std.mem.eql(u8, lib.name, "libukplat_native")) {
            total_objects += native_image_data.x86_64_efi_native_objects.len;
        } else {
            total_objects += lib.objects.len;
        }
    }

    for (native_image_data.x86_64_efi_libraries) |lib| {
        total_libs += 1;
        total_objects += lib.objects.len;
    }

    for (hyperv_extra_libs) |lib| {
        total_libs += 1;
        total_objects += lib.objects.len;
    }

    return .{
        .registered_libraries = total_libs,
        .registered_objects = total_objects,
        .network_enabled_libraries = total_libs,
        .network_enabled_objects = total_objects,
        .http_service_objects = http_objects,
        .shared_libraries_count = 0,
        .systemd_units_count = 0,
        .background_daemons_count = 0,
    };
}

pub fn checkArtifactBudgets(
    stages: BuildStageSet,
    memory: RuntimeMemoryAccounting,
    budgets: ArtifactBudgets,
) Error!void {
    if (stages.bootx64_efi.size_bytes > budgets.max_bootx64_efi_bytes) return error.BudgetExceeded;
    if (stages.dbg_sections.text_bytes > budgets.max_text_bytes) return error.BudgetExceeded;
    if (stages.dbg_sections.rodata_bytes > budgets.max_rodata_bytes) return error.BudgetExceeded;
    if (stages.dbg_sections.data_bytes > budgets.max_data_bytes) return error.BudgetExceeded;
    if (stages.dbg_sections.bss_bytes > budgets.max_bss_bytes) return error.BudgetExceeded;
    if (stages.unikraft_raw.size_bytes != budgets.exact_raw_bytes) return error.BudgetExceeded;
    if (stages.unikraft_vhd.size_bytes != budgets.exact_vhd_bytes) return error.BudgetExceeded;
    if (memory.unikraft_load_peak_heap_bytes > budgets.max_unikraft_peak_heap_bytes) return error.BudgetExceeded;
}

pub fn buildScorecard(
    proof: ReproducibilityProof,
    uk_idle_heap_bytes: u64,
    uk_load_peak_heap_bytes: u64,
    configured_vm_ram_bytes: u64,
    linux_baseline: LinuxBaselineMetadata,
    budgets: ArtifactBudgets,
) Error!Scorecard {
    const sections = proof.stages.dbg_sections;
    const static_bytes = sections.text_bytes + sections.rodata_bytes + sections.data_bytes + sections.bss_bytes;
    const memory: RuntimeMemoryAccounting = .{
        .configured_vm_ram_bytes = configured_vm_ram_bytes,
        .unikraft_static_image_bytes = static_bytes,
        .unikraft_idle_heap_bytes = uk_idle_heap_bytes,
        .unikraft_load_peak_heap_bytes = uk_load_peak_heap_bytes,
        .linux_idle_rss_bytes = linux_baseline.idle_rss_bytes,
        .linux_load_peak_rss_bytes = linux_baseline.load_peak_rss_bytes,
    };
    try checkArtifactBudgets(proof.stages, memory, budgets);
    return .{
        .proof = proof,
        .inventory = extractComponentInventory(),
        .memory = memory,
        .linux_baseline = linux_baseline,
        .budgets = budgets,
        .budget_passed = true,
    };
}

pub fn renderScorecardJson(allocator: Allocator, card: Scorecard) ![]u8 {
    var out: std.Io.Writer.Allocating = .init(allocator);
    defer out.deinit();

    const s = card.proof.stages;
    const sec = s.dbg_sections;
    const inv = card.inventory;
    const mem = card.memory;
    const lx = card.linux_baseline;

    try out.writer.print(
        \\{{
        \\  "schema_version": "{s}",
        \\  "reproducible_build": {{
        \\    "verified": {},
        \\    "dbg_elf": {{ "size_bytes": {d}, "sha256": "{s}" }},
        \\    "sections": {{
        \\      "text": {{ "size_bytes": {d}, "sha256": "{s}" }},
        \\      "rodata": {{ "size_bytes": {d}, "sha256": "{s}" }},
        \\      "data": {{ "size_bytes": {d}, "sha256": "{s}" }},
        \\      "bss": {{ "size_bytes": {d}, "sha256": "{s}" }}
        \\    }},
        \\    "bootx64_efi": {{ "size_bytes": {d}, "sha256": "{s}" }},
        \\    "unikraft_raw": {{ "size_bytes": {d}, "sha256": "{s}" }},
        \\    "unikraft_vhd": {{ "size_bytes": {d}, "sha256": "{s}" }}
        \\  }},
        \\
    , .{
        schema_version,
        card.proof.reproducible,
        s.dbg_elf.size_bytes,
        s.dbg_elf.sha256_hex[0..],
        sec.text_bytes,
        sec.text_sha256[0..],
        sec.rodata_bytes,
        sec.rodata_sha256[0..],
        sec.data_bytes,
        sec.data_sha256[0..],
        sec.bss_bytes,
        sec.bss_sha256[0..],
        s.bootx64_efi.size_bytes,
        s.bootx64_efi.sha256_hex[0..],
        s.unikraft_raw.size_bytes,
        s.unikraft_raw.sha256_hex[0..],
        s.unikraft_vhd.size_bytes,
        s.unikraft_vhd.sha256_hex[0..],
    });

    try out.writer.print(
        \\  "component_inventory": {{
        \\    "unikraft": {{
        \\      "registered_libraries": {d},
        \\      "registered_objects": {d},
        \\      "network_enabled_libraries": {d},
        \\      "network_enabled_objects": {d},
        \\      "http_service_objects": {d},
        \\      "shared_libraries": {d},
        \\      "systemd_units": {d},
        \\      "background_daemons": {d}
        \\    }},
        \\    "linux_baseline": {{
        \\      "distro": "{s}",
        \\      "kernel_release": "{s}",
        \\      "installed_packages": {d},
        \\      "shared_libraries_linked": {d},
        \\      "running_services": {d},
        \\      "os_disk_bytes": {d}
        \\    }}
        \\  }},
        \\  "runtime_memory": {{
        \\    "configured_vm_ram_bytes": {d},
        \\    "unikraft_static_image_bytes": {d},
        \\    "unikraft_idle_heap_bytes": {d},
        \\    "unikraft_load_peak_heap_bytes": {d},
        \\    "linux_idle_rss_bytes": {d},
        \\    "linux_load_peak_rss_bytes": {d}
        \\  }},
        \\  "budget_check": {{
        \\    "passed": {},
        \\    "max_bootx64_efi_bytes": {d},
        \\    "exact_raw_bytes": {d},
        \\    "exact_vhd_bytes": {d},
        \\    "max_unikraft_peak_heap_bytes": {d}
        \\  }}
        \\}}
        \\
    , .{
        inv.registered_libraries,
        inv.registered_objects,
        inv.network_enabled_libraries,
        inv.network_enabled_objects,
        inv.http_service_objects,
        inv.shared_libraries_count,
        inv.systemd_units_count,
        inv.background_daemons_count,
        lx.distro,
        lx.kernel_release,
        lx.installed_packages,
        lx.shared_libraries_linked,
        lx.running_services,
        lx.os_disk_bytes,
        mem.configured_vm_ram_bytes,
        mem.unikraft_static_image_bytes,
        mem.unikraft_idle_heap_bytes,
        mem.unikraft_load_peak_heap_bytes,
        mem.linux_idle_rss_bytes,
        mem.linux_load_peak_rss_bytes,
        card.budget_passed,
        card.budgets.max_bootx64_efi_bytes,
        card.budgets.exact_raw_bytes,
        card.budgets.exact_vhd_bytes,
        card.budgets.max_unikraft_peak_heap_bytes,
    });

    return try out.toOwnedSlice();
}

pub fn renderScorecardMarkdown(allocator: Allocator, card: Scorecard) ![]u8 {
    var out: std.Io.Writer.Allocating = .init(allocator);
    defer out.deinit();

    const s = card.proof.stages;
    const sec = s.dbg_sections;
    const inv = card.inventory;
    const mem = card.memory;
    const lx = card.linux_baseline;

    try out.writer.print(
        \\# Hyper-V Footprint & Reproducible-Build Scorecard
        \\
        \\- **Schema**: `{s}`
        \\- **Two-Directory Clean Reproducibility**: `{}`
        \\- **Artifact Budget Check**: `{}`
        \\
        \\## 1. Stage-by-Stage Build Artifacts & ELF Sections
        \\
        \\| Stage / Section | Size (Bytes) | Budget / Contract | SHA-256 Digest |
        \\|---|---:|---:|---|
        \\| `.dbg` ELF (`.text`) | {d} | <= {d} | `{s}` |
        \\| `.dbg` ELF (`.rodata`) | {d} | <= {d} | `{s}` |
        \\| `.dbg` ELF (`.data`) | {d} | <= {d} | `{s}` |
        \\| `.dbg` ELF (`.bss`) | {d} | <= {d} | `{s}` |
        \\| `.dbg` ELF (full) | {d} | n/a | `{s}` |
        \\| `BOOTX64.EFI` (stripped) | {d} | <= {d} | `{s}` |
        \\| `unikraft.raw` (ESP image) | {d} | == {d} | `{s}` |
        \\| `unikraft.vhd` (Fixed VHD) | {d} | == {d} | `{s}` |
        \\
    , .{
        schema_version,
        card.proof.reproducible,
        card.budget_passed,
        sec.text_bytes,
        card.budgets.max_text_bytes,
        sec.text_sha256[0..],
        sec.rodata_bytes,
        card.budgets.max_rodata_bytes,
        sec.rodata_sha256[0..],
        sec.data_bytes,
        card.budgets.max_data_bytes,
        sec.data_sha256[0..],
        sec.bss_bytes,
        card.budgets.max_bss_bytes,
        sec.bss_sha256[0..],
        s.dbg_elf.size_bytes,
        s.dbg_elf.sha256_hex[0..],
        s.bootx64_efi.size_bytes,
        card.budgets.max_bootx64_efi_bytes,
        s.bootx64_efi.sha256_hex[0..],
        s.unikraft_raw.size_bytes,
        card.budgets.exact_raw_bytes,
        s.unikraft_raw.sha256_hex[0..],
        s.unikraft_vhd.size_bytes,
        card.budgets.exact_vhd_bytes,
        s.unikraft_vhd.sha256_hex[0..],
    });

    try out.writer.print(
        \\
        \\## 2. Component & Dependency Inventory
        \\
        \\| Metric | Unikraft Hyper-V HTTP Unikernel | Ubuntu {s} Baseline |
        \\|---|---:|---:|
        \\| Linked Unikraft Libraries | {d} (of {d}) | n/a |
        \\| Linked Object Files | {d} (HTTP: {d}) | n/a |
        \\| Installed OS Packages (`dpkg`) | 0 | {d} |
        \\| Dynamic Shared Libraries (`.so`) | {d} | {d} |
        \\| Systemd Units / Daemons | {d} / {d} | {d} |
        \\| Bootable Disk Image Size (B) | {d} | {d} |
        \\
        \\## 3. Runtime Memory Accounting
        \\
        \\| Metric | Unikraft (B) | Ubuntu Baseline (B) |
        \\|---|---:|---:|
        \\| Configured VM RAM | {d} | {d} |
        \\| Static Image (`.text+.rodata+.data+.bss`) | {d} | n/a |
        \\| Idle Dynamic Memory (`ukalloc` / RSS) | {d} | {d} |
        \\| Peak Load Dynamic Memory (`ukalloc` / RSS) | {d} | {d} |
        \\
    , .{
        lx.distro,
        inv.network_enabled_libraries,
        inv.registered_libraries,
        inv.network_enabled_objects,
        inv.http_service_objects,
        lx.installed_packages,
        inv.shared_libraries_count,
        lx.shared_libraries_linked,
        inv.systemd_units_count,
        inv.background_daemons_count,
        lx.running_services,
        s.unikraft_vhd.size_bytes,
        lx.os_disk_bytes,
        mem.configured_vm_ram_bytes,
        mem.configured_vm_ram_bytes,
        mem.unikraft_static_image_bytes,
        mem.unikraft_idle_heap_bytes,
        mem.linux_idle_rss_bytes,
        mem.unikraft_load_peak_heap_bytes,
        mem.linux_load_peak_rss_bytes,
    });

    return try out.toOwnedSlice();
}
