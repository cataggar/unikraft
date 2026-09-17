//! Qualification only: loader-facing equivalence, not debugger equivalence or admission.
const std = @import("std");
pub const core = @import("hyperv_core");
const elf = @import("producer_elf");
const pf = core.private_files;

pub const max_file_bytes = 64 * 1024 * 1024;
pub const max_report_bytes = 32 * 1024;
pub const max_programs = 128;
pub const Role = enum { namespace_helper, namespace_fixture };
pub const LayoutPolicy = enum { identical_program_headers, file_offset_relayout };
pub const Field = enum { e_shoff, e_shnum, e_shstrndx };
const ranges = [_]struct { field: Field, offset: usize, width: usize }{
    .{ .field = .e_shoff, .offset = 40, .width = 8 },
    .{ .field = .e_shnum, .offset = 60, .width = 2 },
    .{ .field = .e_shstrndx, .offset = 62, .width = 2 },
};

pub const Normalization = struct {
    field: Field,
    offset: usize,
    width: usize,
    raw: u64,
    candidate: u64,
    changed: bool,
};
pub const LogicalMapping = struct {
    type: u32,
    flags: u32,
    virtual_address: u64,
    physical_address: u64,
    file_bytes: u64,
    memory_bytes: u64,
    alignment: u64,
};
pub const ProgramMapping = struct {
    index: usize,
    raw_offset: u64,
    candidate_offset: u64,
    changed: bool,
    offset_field_file_offset: u64,
    offset_field_width: u8 = 8,
    logical_mapping: LogicalMapping,
    logical_mapping_sha256: [64]u8,
};
pub const ProgramMappings = struct {
    records: [max_programs]ProgramMapping = undefined,
    len: usize = 0,

    pub fn slice(self: *const ProgramMappings) []const ProgramMapping {
        return self.records[0..self.len];
    }

    pub fn jsonStringify(self: ProgramMappings, writer: anytype) !void {
        try writer.write(self.slice());
    }
};
pub const ContentProof = struct {
    elf_class: enum { elf64 } = .elf64,
    endian: std.builtin.Endian,
    machine: std.elf.EM,
    entry: u64,
    layout_policy: LayoutPolicy,
    load_offset_modulus: u64,
    raw_program_headers_sha256: [64]u8,
    candidate_program_headers_sha256: [64]u8,
    normalized_program_headers_sha256: [64]u8,
    mapped_program_content_sha256: [64]u8,
    mapped_loaded_content_sha256: [64]u8,
    program_mappings: ProgramMappings,
    load_segments: usize,
    loaded_file_bytes: u64,
    removed_debug_sections: usize,
    removed_debug_bytes: u64,
    size_reduction: u64,
    normalization: [ranges.len]Normalization,
};

fn precheck(bytes: []const u8) !void {
    if (bytes.len < 64 or bytes.len > max_file_bytes) return error.InvalidElfSize;
    // Fixture outputs use ordinary ELF64 section indices. Extended numbering
    // would move locator semantics into section zero and is not normalized.
    var reader = std.Io.Reader.fixed(bytes);
    const header = try std.elf.Header.read(&reader);
    if (!header.is_64) return error.UnsupportedClass;
    if (header.shnum == 0 or header.shnum > 4096 or header.shstrndx == 0xffff or
        header.phnum == 0 or header.phnum > max_programs) return error.UnsupportedElfTables;
    if (header.phoff < 64 or header.shoff < 64) return error.InvalidElfTables;
}

fn overlaps(a: u64, size_a: u64, b: u64, size_b: u64) bool {
    if (size_a == 0 or size_b == 0) return false;
    return if (a <= b) b - a < size_a else a - b < size_b;
}

fn debugName(name: []const u8) bool {
    return std.mem.startsWith(u8, name, ".debug_") or std.mem.startsWith(u8, name, ".zdebug_");
}

fn normalizedHeader(bytes: []const u8) [64]u8 {
    var result: [64]u8 = bytes[0..64].*;
    for (ranges) |field| @memset(result[field.offset..][0..field.width], 0);
    return result;
}

const Mask = struct { offset: u64, width: u64 };
const Masks = struct {
    records: [ranges.len + max_programs]Mask = undefined,
    len: usize = 0,

    fn init() Masks {
        var result: Masks = .{};
        for (ranges) |field| {
            result.records[result.len] = .{ .offset = field.offset, .width = field.width };
            result.len += 1;
        }
        return result;
    }

    fn slice(self: *const Masks) []const Mask {
        return self.records[0..self.len];
    }
};

fn compareRange(raw: []const u8, candidate: []const u8, raw_offset: u64, candidate_offset: u64, length: u64, masks: []const Mask) !void {
    const left = try elf.range(raw, raw_offset, length);
    const right = try elf.range(candidate, candidate_offset, length);
    var cursor: usize = 0;
    for (masks) |field| {
        if (!overlaps(raw_offset, length, field.offset, field.width) and
            !overlaps(candidate_offset, length, field.offset, field.width)) continue;
        if (raw_offset != candidate_offset) return error.MetadataMappingChanged;
        const start: usize = @intCast(@max(raw_offset, field.offset) - raw_offset);
        const end: usize = @intCast(@min(raw_offset + length, field.offset + field.width) - raw_offset);
        if (!std.mem.eql(u8, left[cursor..start], right[cursor..start])) return error.LoadedContentChanged;
        cursor = end;
    }
    if (!std.mem.eql(u8, left[cursor..], right[cursor..])) return error.LoadedContentChanged;
}

fn hashRange(sha: *core.Sha256, bytes: []const u8, offset: u64, length: u64, masks: []const Mask) !void {
    const data = try elf.range(bytes, offset, length);
    const zeroes = [_]u8{0} ** 8;
    var cursor: usize = 0;
    for (masks) |field| {
        if (!overlaps(offset, length, field.offset, field.width)) continue;
        const start: usize = @intCast(@max(offset, field.offset) - offset);
        const end: usize = @intCast(@min(offset + length, field.offset + field.width) - offset);
        sha.update(data[cursor..start]);
        sha.update(zeroes[0 .. end - start]);
        cursor = end;
    }
    sha.update(data[cursor..]);
}

fn movableProgram(kind: u32) bool {
    return switch (kind) {
        std.elf.PT_LOAD,
        std.elf.PT_DYNAMIC,
        std.elf.PT_INTERP,
        std.elf.PT_NOTE,
        std.elf.PT_TLS,
        std.elf.PT_GNU_EH_FRAME,
        std.elf.PT_GNU_RELRO,
        => true,
        // PHDR is anchored. NULL, STACK and unknown records have no proven
        // movable file backing in this qualification policy.
        else => false,
    };
}

fn loadOffsetModulus(machine: std.elf.EM) u64 {
    // Preserve offsets for every Linux base page size of the supported target,
    // without pretending that this ELF-only comparison observed a host kernel.
    return if (machine == .AARCH64) 65536 else 4096;
}

fn validateRelayoutLayout(image: elf.Image) !void {
    const table_bytes = image.programs.len * @sizeOf(std.elf.Elf64_Phdr);
    var phdr_seen = false;
    for (image.programs, 0..) |program, index| {
        _ = try elf.add(program.p_vaddr, program.p_filesz);
        _ = try elf.add(program.p_paddr, program.p_memsz);
        if (program.p_align > 1 and
            (!std.math.isPowerOfTwo(program.p_align) or
                program.p_offset % program.p_align != program.p_vaddr % program.p_align))
            return error.InvalidProgramAlignment;
        if (program.p_type == std.elf.PT_PHDR) {
            if (phdr_seen or program.p_offset != image.header.phoff or
                program.p_filesz != table_bytes or program.p_memsz != table_bytes)
                return error.InvalidPhdrMapping;
            phdr_seen = true;
        }
        if (program.p_type == std.elf.PT_LOAD) {
            if (program.p_offset % 4096 != program.p_vaddr % 4096)
                return error.InvalidLoadPageAlignment;
            for (image.programs[0..index]) |other| {
                if (other.p_type != std.elf.PT_LOAD) continue;
                if (overlaps(program.p_offset, program.p_filesz, other.p_offset, other.p_filesz) or
                    overlaps(program.p_vaddr, program.p_memsz, other.p_vaddr, other.p_memsz))
                    return error.AmbiguousLoadMapping;
            }
            if (image.header.entry >= program.p_vaddr and image.header.entry - program.p_vaddr < program.p_filesz) {
                const offset = try elf.add(program.p_offset, image.header.entry - program.p_vaddr);
                if (overlaps(offset, 1, image.header.phoff, table_bytes)) return error.EntryInProgramHeaders;
            }
        } else if (program.p_filesz != 0 and program.p_vaddr != 0) {
            var backed = false;
            for (image.programs) |load| {
                if (load.p_type != std.elf.PT_LOAD or program.p_vaddr < load.p_vaddr or program.p_offset < load.p_offset)
                    continue;
                const delta = program.p_vaddr - load.p_vaddr;
                if (delta == program.p_offset - load.p_offset and delta <= load.p_filesz and
                    program.p_filesz <= load.p_filesz - delta) backed = true;
            }
            if (!backed) return error.UnmappedProgramRecord;
        }
    }
    for (image.sections[1..]) |section| {
        const sh = section.header;
        if (sh.sh_flags & std.elf.SHF_ALLOC != 0 and sh.sh_type != std.elf.SHT_NOBITS and
            overlaps(sh.sh_offset, sh.sh_size, image.header.phoff, table_bytes))
            return error.AllocatedProgramHeaders;
    }
}

fn sameOverlap(raw_a: std.elf.Elf64_Phdr, raw_b: std.elf.Elf64_Phdr, candidate_a: std.elf.Elf64_Phdr, candidate_b: std.elf.Elf64_Phdr) bool {
    const before = overlaps(raw_a.p_offset, raw_a.p_filesz, raw_b.p_offset, raw_b.p_filesz);
    const after = overlaps(candidate_a.p_offset, candidate_a.p_filesz, candidate_b.p_offset, candidate_b.p_filesz);
    if (before != after) return false;
    if (!before) return true;
    // All endpoints have already passed the parser's file bounds checks.
    const start = @max(raw_a.p_offset, raw_b.p_offset);
    const candidate_start = @max(candidate_a.p_offset, candidate_b.p_offset);
    const length = @min(raw_a.p_offset + raw_a.p_filesz, raw_b.p_offset + raw_b.p_filesz) - start;
    const candidate_length = @min(candidate_a.p_offset + candidate_a.p_filesz, candidate_b.p_offset + candidate_b.p_filesz) - candidate_start;
    return length == candidate_length and start - raw_a.p_offset == candidate_start - candidate_a.p_offset and
        start - raw_b.p_offset == candidate_start - candidate_b.p_offset;
}

fn logicalIdentity(index: usize, header_bytes: []const u8) [64]u8 {
    var sha = core.Sha256.init(.{});
    sha.update("hyperv-fixture-logical-program-v2\x00");
    var encoded_index: [8]u8 = undefined;
    std.mem.writeInt(u64, &encoded_index, index, .little);
    sha.update(&encoded_index);
    // The ordered logical identity excludes only the physical file offset.
    sha.update(header_bytes[0..8]);
    sha.update(header_bytes[16..56]);
    return std.fmt.bytesToHex(sha.finalResult(), .lower);
}

fn validateLayout(image: elf.Image) !void {
    const header = image.header;
    const program_bytes = image.programs.len * @sizeOf(std.elf.Elf64_Phdr);
    const section_bytes = image.sections.len * @sizeOf(std.elf.Elf64_Shdr);
    if (overlaps(header.phoff, program_bytes, header.shoff, section_bytes)) return error.OverlappingElfTables;
    var executable_entry = false;
    for (image.programs) |program| {
        if (program.p_type != std.elf.PT_LOAD) continue;
        if (program.p_flags & std.elf.PF_X != 0 and header.entry >= program.p_vaddr and
            header.entry - program.p_vaddr < program.p_filesz)
        {
            const entry_offset = program.p_offset + (header.entry - program.p_vaddr);
            if (entry_offset < 64) return error.EntryInElfHeader;
            executable_entry = true;
        }
        if (overlaps(program.p_offset, program.p_filesz, header.shoff, section_bytes))
            return error.LoadedSectionTable;
    }
    if (!executable_entry) return error.UnmappedEntry;
    for (image.sections[1..]) |section| {
        const sh = section.header;
        if (sh.sh_flags & std.elf.SHF_ALLOC != 0 and sh.sh_type != std.elf.SHT_NOBITS and sh.sh_size != 0) {
            if (overlaps(sh.sh_offset, sh.sh_size, 0, 64)) return error.AllocatedElfHeader;
            try image.requireLoadedSection(section);
        }
    }
}

pub fn compare(allocator: std.mem.Allocator, raw: []const u8, candidate: []const u8) !ContentProof {
    return compareWithPolicy(allocator, raw, candidate, .identical_program_headers);
}

pub fn compareWithPolicy(allocator: std.mem.Allocator, raw: []const u8, candidate: []const u8, policy: LayoutPolicy) !ContentProof {
    try precheck(raw);
    try precheck(candidate);
    var left = try elf.Image.parse(allocator, raw);
    defer left.deinit();
    var right = try elf.Image.parse(allocator, candidate);
    defer right.deinit();
    try validateLayout(left);
    try validateLayout(right);
    if (!std.mem.eql(u8, &normalizedHeader(raw), &normalizedHeader(candidate))) return error.ElfHeaderChanged;
    const phdr_bytes = left.programs.len * @sizeOf(std.elf.Elf64_Phdr);
    const raw_programs = try elf.range(raw, left.header.phoff, phdr_bytes);
    const candidate_programs = try elf.range(candidate, right.header.phoff, phdr_bytes);
    if (policy == .identical_program_headers) {
        if (!std.mem.eql(u8, raw_programs, candidate_programs)) return error.ProgramHeadersChanged;
    } else {
        try validateRelayoutLayout(left);
        try validateRelayoutLayout(right);
    }
    var masks = Masks.init();
    var mappings: ProgramMappings = .{};
    for (left.programs, right.programs, 0..) |program, other, index| {
        const start = index * @sizeOf(std.elf.Elf64_Phdr);
        const before = raw_programs[start..][0..@sizeOf(std.elf.Elf64_Phdr)];
        const after = candidate_programs[start..][0..@sizeOf(std.elf.Elf64_Phdr)];
        if (!std.mem.eql(u8, before[0..8], after[0..8]) or !std.mem.eql(u8, before[16..], after[16..]))
            return error.ProgramHeadersChanged;
        const changed = program.p_offset != other.p_offset;
        const field_offset = left.header.phoff + start + 8;
        if (changed) {
            if (policy != .file_offset_relayout) return error.ProgramHeadersChanged;
            if (program.p_filesz == 0 or !movableProgram(program.p_type)) return error.UnmovableProgramOffset;
            if (program.p_type == std.elf.PT_LOAD and
                program.p_offset % loadOffsetModulus(left.header.machine) != other.p_offset % loadOffsetModulus(left.header.machine))
                return error.LoadPageOffsetChanged;
            if (overlaps(program.p_offset, program.p_filesz, 0, 64) or
                overlaps(other.p_offset, other.p_filesz, 0, 64) or
                overlaps(program.p_offset, program.p_filesz, left.header.phoff, phdr_bytes) or
                overlaps(other.p_offset, other.p_filesz, right.header.phoff, phdr_bytes))
                return error.MetadataMappingChanged;
            for (left.programs) |load| {
                if (load.p_type == std.elf.PT_LOAD and load.p_flags & std.elf.PF_X != 0 and
                    overlaps(load.p_offset, load.p_filesz, field_offset, 8))
                    return error.ExecutableProgramHeaderNormalization;
            }
            masks.records[masks.len] = .{ .offset = field_offset, .width = 8 };
            masks.len += 1;
        }
        if (policy == .file_offset_relayout) {
            for (0..index) |previous| {
                if (!sameOverlap(program, left.programs[previous], other, right.programs[previous]))
                    return error.ProgramBackingChanged;
            }
        }
        mappings.records[index] = .{
            .index = index,
            .raw_offset = program.p_offset,
            .candidate_offset = other.p_offset,
            .changed = changed,
            .offset_field_file_offset = field_offset,
            .logical_mapping = .{
                .type = program.p_type,
                .flags = program.p_flags,
                .virtual_address = program.p_vaddr,
                .physical_address = program.p_paddr,
                .file_bytes = program.p_filesz,
                .memory_bytes = program.p_memsz,
                .alignment = program.p_align,
            },
            .logical_mapping_sha256 = logicalIdentity(index, before),
        };
        mappings.len += 1;
    }
    // These masks are anchored metadata, never a license to ignore bytes at a
    // relocated code/data offset. Overlapping PHDR/LOAD views use the same mask.
    var normalized_phdr = core.Sha256.init(.{});
    try hashRange(&normalized_phdr, raw, left.header.phoff, phdr_bytes, masks.slice());
    const normalized_phdr_hash = normalized_phdr.finalResult();
    var all_binding = core.Sha256.init(.{});
    all_binding.update("hyperv-fixture-mapped-program-content-v2\x00");
    all_binding.update(&normalized_phdr_hash);
    var binding = core.Sha256.init(.{});
    binding.update("hyperv-fixture-mapped-pt-load-v2\x00");
    binding.update(&normalized_phdr_hash);
    var load_segments: usize = 0;
    var loaded_bytes: u64 = 0;
    for (left.programs, right.programs, mappings.slice()) |program, other, mapping| {
        try compareRange(raw, candidate, program.p_offset, other.p_offset, program.p_filesz, masks.slice());
        all_binding.update(&mapping.logical_mapping_sha256);
        try hashRange(&all_binding, raw, program.p_offset, program.p_filesz, masks.slice());
        if (program.p_type != std.elf.PT_LOAD) continue;
        load_segments += 1;
        loaded_bytes += program.p_filesz;
        binding.update(&mapping.logical_mapping_sha256);
        try hashRange(&binding, raw, program.p_offset, program.p_filesz, masks.slice());
    }
    if (load_segments == 0) return error.MissingLoadSegment;
    var removed_sections: usize = 0;
    var removed_bytes: u64 = 0;
    for (left.sections, 0..) |section, index| {
        if (!debugName(section.name) or section.header.sh_size == 0) continue;
        const sh = section.header;
        if (sh.sh_flags & std.elf.SHF_ALLOC != 0 or sh.sh_type == std.elf.SHT_NOBITS) return error.LoadedDebugData;
        for (left.programs) |program|
            if (overlaps(sh.sh_offset, sh.sh_size, program.p_offset, program.p_filesz)) return error.LoadedDebugData;
        for (left.sections, 0..) |other, other_index| {
            if (index == other_index or other.header.sh_type == std.elf.SHT_NOBITS) continue;
            if (overlaps(sh.sh_offset, sh.sh_size, other.header.sh_offset, other.header.sh_size))
                return error.OverlappingDebugData;
        }
        if (overlaps(sh.sh_offset, sh.sh_size, 0, 64) or
            overlaps(sh.sh_offset, sh.sh_size, left.header.phoff, phdr_bytes) or
            overlaps(sh.sh_offset, sh.sh_size, left.header.shoff, left.sections.len * @sizeOf(std.elf.Elf64_Shdr)))
            return error.OverlappingDebugData;
        removed_sections += 1;
        removed_bytes += sh.sh_size;
    }
    for (right.sections) |section|
        if (debugName(section.name) and section.header.sh_size != 0) return error.DebugDataRetained;
    if (removed_bytes == 0) return error.NoDebugData;
    if (candidate.len >= raw.len or raw.len - candidate.len < removed_bytes) return error.InsufficientSizeReduction;
    var normalized: [ranges.len]Normalization = undefined;
    for (ranges, &normalized) |field, *value| {
        const before: u64 = if (field.width == 8) try elf.integer(u64, raw, field.offset, left.header.endian) else try elf.integer(u16, raw, field.offset, left.header.endian);
        const after: u64 = if (field.width == 8) try elf.integer(u64, candidate, field.offset, right.header.endian) else try elf.integer(u16, candidate, field.offset, right.header.endian);
        value.* = .{ .field = field.field, .offset = field.offset, .width = field.width, .raw = before, .candidate = after, .changed = before != after };
    }
    var phdr_hash: [32]u8 = undefined;
    core.Sha256.hash(raw_programs, &phdr_hash, .{});
    var candidate_phdr_hash: [32]u8 = undefined;
    core.Sha256.hash(candidate_programs, &candidate_phdr_hash, .{});
    return .{
        .endian = left.header.endian,
        .machine = left.header.machine,
        .entry = left.header.entry,
        .layout_policy = policy,
        .load_offset_modulus = loadOffsetModulus(left.header.machine),
        .raw_program_headers_sha256 = std.fmt.bytesToHex(phdr_hash, .lower),
        .candidate_program_headers_sha256 = std.fmt.bytesToHex(candidate_phdr_hash, .lower),
        .normalized_program_headers_sha256 = std.fmt.bytesToHex(normalized_phdr_hash, .lower),
        .mapped_program_content_sha256 = std.fmt.bytesToHex(all_binding.finalResult(), .lower),
        .mapped_loaded_content_sha256 = std.fmt.bytesToHex(binding.finalResult(), .lower),
        .program_mappings = mappings,
        .load_segments = load_segments,
        .loaded_file_bytes = loaded_bytes,
        .removed_debug_sections = removed_sections,
        .removed_debug_bytes = removed_bytes,
        .size_reduction = raw.len - candidate.len,
        .normalization = normalized,
    };
}

pub const FileProof = struct {
    path: []const u8,
    size: u64,
    sha256: [64]u8,
    device_major: u32,
    device_minor: u32,
    inode: u64,
    uid: u32,
    mode: u16,
    links: u32,
    stable_identity_and_hash: bool = true,
};

pub const Pinned = struct {
    file: std.Io.File,
    path: []const u8,
    before: pf.Snapshot,
    bytes: []u8,
    hash: [32]u8,

    pub fn open(allocator: std.mem.Allocator, io: std.Io, path: []const u8) !Pinned {
        const file = try pf.openAbsolute(io, path, .artifact);
        errdefer file.close(io);
        const before = try pf.snapshot(file);
        if (before.size == 0 or before.size > max_file_bytes or before.mode & 0o022 != 0 or
            before.mode & 0o6000 != 0 or before.mode & 0o111 == 0) return error.UnsafeExecutable;
        const bytes = try allocator.alloc(u8, @intCast(before.size));
        errdefer allocator.free(bytes);
        if (try file.readPositionalAll(io, bytes, 0) != bytes.len) return error.InputChanged;
        var hash: [32]u8 = undefined;
        core.Sha256.hash(bytes, &hash, .{});
        const result: Pinned = .{ .file = file, .path = path, .before = before, .bytes = bytes, .hash = hash };
        try result.recheck(io);
        return result;
    }

    pub fn close(self: Pinned, allocator: std.mem.Allocator, io: std.Io) void {
        self.file.close(io);
        allocator.free(self.bytes);
    }

    pub fn recheck(self: Pinned, io: std.Io) !void {
        if (!pf.sameSnapshot(self.before, try pf.snapshot(self.file))) return error.InputChanged;
        var hash = core.Sha256.init(.{});
        var buffer: [32 * 1024]u8 = undefined;
        var offset: u64 = 0;
        while (offset < self.before.size) {
            const length: usize = @intCast(@min(buffer.len, self.before.size - offset));
            if (try self.file.readPositionalAll(io, buffer[0..length], offset) != length) return error.InputChanged;
            hash.update(buffer[0..length]);
            offset += length;
        }
        if (try self.file.readPositionalAll(io, buffer[0..1], offset) != 0 or
            !std.mem.eql(u8, &hash.finalResult(), &self.hash) or
            !pf.sameSnapshot(self.before, try pf.snapshot(self.file))) return error.InputChanged;
        const named = try pf.openAbsolute(io, self.path, .artifact);
        defer named.close(io);
        if (!pf.sameSnapshot(self.before, try pf.snapshot(named))) return error.InputChanged;
    }

    pub fn proof(self: Pinned) FileProof {
        return .{
            .path = self.path,
            .size = self.before.size,
            .sha256 = std.fmt.bytesToHex(self.hash, .lower),
            .device_major = self.before.dev_major,
            .device_minor = self.before.dev_minor,
            .inode = self.before.ino,
            .uid = self.before.uid,
            .mode = self.before.mode,
            .links = self.before.nlink,
        };
    }
};

pub const PairProof = struct { role: Role, raw: FileProof, candidate: FileProof, content: ContentProof };
pub const SuiteProof = struct {
    schema: enum { hyperv_fixture_debug_stripping_v2 } = .hyperv_fixture_debug_stripping_v2,
    authority: enum { synthetic_only_not_admitted } = .synthetic_only_not_admitted,
    passed: bool = true,
    synthetic: bool = true,
    admitted: bool = false,
    qualification_only: bool = true,
    layout_policy: LayoutPolicy = .identical_program_headers,
    pairs: [2]PairProof,
    external_fixture: ?FileProof = null,
};

pub const Pair = struct {
    raw: Pinned,
    candidate: Pinned,
    content: ContentProof,

    pub fn open(allocator: std.mem.Allocator, io: std.Io, raw_path: []const u8, candidate_path: []const u8) !Pair {
        return openWithPolicy(allocator, io, raw_path, candidate_path, .identical_program_headers);
    }

    pub fn openWithPolicy(allocator: std.mem.Allocator, io: std.Io, raw_path: []const u8, candidate_path: []const u8, policy: LayoutPolicy) !Pair {
        const raw = try Pinned.open(allocator, io, raw_path);
        errdefer raw.close(allocator, io);
        const candidate = try Pinned.open(allocator, io, candidate_path);
        errdefer candidate.close(allocator, io);
        if (raw.before.ino == candidate.before.ino and raw.before.dev_major == candidate.before.dev_major and
            raw.before.dev_minor == candidate.before.dev_minor) return error.NotDistinctFiles;
        const content = try compareWithPolicy(allocator, raw.bytes, candidate.bytes, policy);
        try raw.recheck(io);
        try candidate.recheck(io);
        return .{ .raw = raw, .candidate = candidate, .content = content };
    }

    pub fn close(self: Pair, allocator: std.mem.Allocator, io: std.Io) void {
        self.raw.close(allocator, io);
        self.candidate.close(allocator, io);
    }

    pub fn recheck(self: Pair, io: std.Io) !void {
        try self.raw.recheck(io);
        try self.candidate.recheck(io);
    }

    pub fn proof(self: Pair, role: Role) PairProof {
        return .{ .role = role, .raw = self.raw.proof(), .candidate = self.candidate.proof(), .content = self.content };
    }
};

pub fn publish(allocator: std.mem.Allocator, io: std.Io, path: []const u8, value: anytype) !void {
    try pf.absoluteFilePath(path);
    const parent = try pf.Directory.open(io, std.fs.path.dirname(path).?);
    defer parent.close(io);
    const json = try std.json.Stringify.valueAlloc(allocator, value, .{});
    defer allocator.free(json);
    if (json.len + 1 > max_report_bytes) return error.ReportTooLarge;
    const file = try parent.dir.createFile(io, std.fs.path.basename(path), .{ .exclusive = true, .permissions = .fromMode(0o600) });
    defer file.close(io);
    try file.writeStreamingAll(io, json);
    try file.writeStreamingAll(io, "\n");
    try file.sync(io);
    try (std.Io.File{ .handle = parent.dir.handle, .flags = .{ .nonblocking = false } }).sync(io);
}
