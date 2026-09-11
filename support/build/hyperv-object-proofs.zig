// SPDX-License-Identifier: BSD-3-Clause

const std = @import("std");
pub const format = @import("hyperv-object-elf.zig");
pub const tools = @import("hyperv-object-tools.zig");
const common = @import("elf-common-validator.zig");

pub const Profile = enum { @"hyperv-runtime", @"vmbus-protocol", @"vmbus-channel", @"storvsc-core", @"netvsc-protocol" };
pub const mapping_names = [_][]const u8{
    "uk_storvsc_mapping_count", "uk_storvsc_mapping_get",              "uk_storvsc_mapping_find",
    "uk_storvsc_inventory_get", "uk_storvsc_inventory_pristine_empty",
};
pub const Page = struct { name: []const u8, symbol: []const u8, nobits: bool };
pub const pages = [_]Page{
    .{ .name = ".text.hyperv_hypercall_page", .symbol = "hyperv_hypercall_page_storage", .nobits = false },
    .{ .name = ".bss.hyperv_simp_page", .symbol = "hyperv_simp_page_storage", .nobits = true },
    .{ .name = ".bss.hyperv_siefp_page", .symbol = "hyperv_siefp_page_storage", .nobits = true },
    .{ .name = ".bss.hyperv_reference_tsc_page", .symbol = "hyperv_reference_tsc_page_storage", .nobits = true },
};

pub fn required(profile: Profile) []const []const u8 {
    return switch (profile) {
        .@"hyperv-runtime" => &.{
            "hyperv_hypercall_page_storage",     "hyperv_runtime_detect",          "hyperv_runtime_enable",
            "hyperv_runtime_disable",            "hyperv_hypercall",               "hyperv_has_post_messages",
            "hyperv_has_signal_events",          "hyperv_time_ref_count",          "hyperv_reference_time",
            "hyperv_synic_enable",               "hyperv_synic_disable",           "hyperv_reference_tsc_enable",
            "hyperv_reference_tsc_disable",      "hyperv_synic_cpu_enable",        "hyperv_synic_cpu_disable",
            "hyperv_synic_message_take",         "hyperv_synic_message_take_page", "hyperv_synic_event_take_word",
            "hyperv_synic_event_take_word_page", "hyperv_vp_index",                "hyperv_max_vp_count",
            "hyperv_x86_irq_to_vector",          "hyperv_stimer0_arm",             "hyperv_stimer0_cancel",
        },
        .@"vmbus-protocol" => &.{
            "vmbus_post_input",       "vmbus_post_message",                 "vmbus_protocol_post_failure", "vmbus_protocol_start",
            "vmbus_protocol_receive", "vmbus_protocol_offer_matches_class", "vmbus_protocol_tick",         "vmbus_protocol_unload",
            "vmbus_protocol_release", "vmbus_protocol_reset",               "vmbus_protocol_state",        "vmbus_protocol_generation",
            "vmbus_protocol_version", "vmbus_protocol_connection_id",
        },
        .@"vmbus-channel" => &.{
            "vmbus_ring_initialize", "vmbus_ring_write",   "vmbus_ring_read",     "vmbus_gpadl_header",
            "vmbus_gpadl_body",      "vmbus_open_message", "vmbus_close_message", "vmbus_gpadl_teardown_message",
            "vmbus_signal_event",
        },
        .@"storvsc-core" => &.{
            "storvsc_core_initialize",              "storvsc_core_start",         "storvsc_core_receive",          "storvsc_core_tick",
            "storvsc_core_prepare_scsi",            "storvsc_core_prepare_block", "storvsc_core_prepare_block_at", "storvsc_core_prepare_block_media",
            "storvsc_core_prepare_block_media_cdb", "storvsc_core_begin_reset",   "storvsc_core_cancel_all",       "storvsc_core_take_completed",
            "storvsc_build_report_luns",            "storvsc_parse_report_luns",  "storvsc_parse_vpd83",           "storvsc_parse_inquiry",
            "storvsc_parse_capacity10",             "storvsc_parse_capacity16",   "storvsc_parse_mode_sense6",     "storvsc_parse_mode_sense10",
        },
        .@"netvsc-protocol" => &.{
            "netvsc_nvs_build_init",            "netvsc_nvs_build_receive_buffer", "netvsc_nvs_parse_receive_buffer_complete",
            "netvsc_nvs_parse_transfer_range",  "netvsc_rndis_build_initialize",   "netvsc_rndis_build_query",
            "netvsc_rndis_build_set",           "netvsc_rndis_build_keepalive",    "netvsc_rndis_build_halt",
            "netvsc_rndis_build_packet_header", "netvsc_rndis_parse_completion",   "netvsc_rndis_parse_packet",
            "netvsc_rndis_parse_status",
        },
    };
}

pub const Options = struct {
    profile: Profile,
    object: []const u8,
    nm: []const u8 = "llvm-nm",
    readelf: []const u8 = "llvm-readelf",
    mappings: std.ArrayList([]const u8) = .empty,
    timeout_ms: u32 = 30000,

    pub fn parse(allocator: std.mem.Allocator, args: []const []const u8) !Options {
        if (args.len == 0 or args.len > 80) return error.InvalidArguments;
        var result: Options = .{
            .profile = std.meta.stringToEnum(Profile, args[0]) orelse return error.InvalidArguments,
            .object = "",
        };
        errdefer result.deinit(allocator);
        var seen_nm = false;
        var seen_readelf = false;
        var seen_timeout = false;
        var index: usize = 1;
        while (index < args.len) : (index += 2) {
            if (index + 1 >= args.len or args[index + 1].len == 0 or args[index + 1].len > 4096) return error.InvalidArguments;
            const flag = args[index];
            const value = args[index + 1];
            if (std.mem.startsWith(u8, value, "--") or std.mem.indexOfScalar(u8, value, 0) != null) return error.InvalidArguments;
            if (std.mem.eql(u8, flag, "--object")) {
                if (result.object.len != 0) return error.InvalidArguments;
                result.object = value;
            } else if (std.mem.eql(u8, flag, "--nm")) {
                if (seen_nm) return error.InvalidArguments;
                seen_nm = true;
                result.nm = value;
            } else if (std.mem.eql(u8, flag, "--readelf")) {
                if (seen_readelf or result.profile != .@"hyperv-runtime") return error.InvalidArguments;
                seen_readelf = true;
                result.readelf = value;
            } else if (std.mem.eql(u8, flag, "--mapping-api-object")) {
                if (result.profile != .@"storvsc-core" or result.mappings.items.len == 32) return error.InvalidArguments;
                try result.mappings.append(allocator, value);
            } else if (std.mem.eql(u8, flag, "--timeout-ms")) {
                if (seen_timeout) return error.InvalidArguments;
                seen_timeout = true;
                result.timeout_ms = std.fmt.parseInt(u32, value, 10) catch return error.InvalidArguments;
                if (result.timeout_ms == 0 or result.timeout_ms > 30000) return error.InvalidArguments;
            } else return error.InvalidArguments;
        }
        if (result.object.len == 0) return error.InvalidArguments;
        return result;
    }

    pub fn deinit(self: *Options, allocator: std.mem.Allocator) void {
        self.mappings.deinit(allocator);
    }
};

pub fn validate(object: format.Object, profile: Profile) !void {
    try object.noUndefined();
    if (try common.findCommonSymbol(object.bytes) != null) return error.CommonSymbol;
    for (required(profile)) |name| _ = try object.definition(name, std.mem.eql(u8, name, pages[0].symbol));
    if (profile == .@"hyperv-runtime") for (pages) |page| {
        const section = try object.section(page.name);
        const sh = section.header;
        // Zig emits the const hypercall storage as PROGBITS/A, not AX. The
        // final image's executable mapping is a separate owner's proof.
        const flags: u64 = std.elf.SHF_ALLOC | (if (page.nobits) @as(u64, std.elf.SHF_WRITE) else 0);
        if (sh.sh_type != @intFromEnum(if (page.nobits) std.elf.SHT.NOBITS else .PROGBITS) or
            sh.sh_size != 4096 or sh.sh_addralign != 4096 or sh.sh_flags != flags or
            sh.sh_addr != 0 or sh.sh_offset % 4096 != 0) return error.InvalidPageSection;
        const symbol = try object.definition(page.symbol, true);
        if (symbol.entry.st_shndx != section.index or symbol.entry.st_value != 0 or symbol.entry.st_size != 4096)
            return error.InvalidPageStorage;
    };
}

pub fn validateMapping(object: format.Object) !void {
    for (mapping_names) |name| _ = try object.reference(name);
}

const Nm = struct { name: []const u8, kind: u8, value: u64, size: u64 };

fn nmRow(line: []const u8) !Nm {
    var words = std.mem.tokenizeAny(u8, line, " \t\r");
    const name = words.next() orelse return error.InvalidNmOutput;
    const kind = words.next() orelse return error.InvalidNmOutput;
    if (kind.len != 1 or !std.ascii.isAlphabetic(kind[0])) return error.InvalidNmOutput;
    const value = words.next();
    const size = words.next();
    if ((value == null) != (size == null) or words.next() != null) return error.InvalidNmOutput;
    if (value == null and kind[0] != 'U' and kind[0] != 'w' and kind[0] != 'v') return error.InvalidNmOutput;
    return .{
        .name = name,
        .kind = kind[0],
        .value = if (value) |text| std.fmt.parseInt(u64, text, 16) catch return error.InvalidNmOutput else 0,
        .size = if (size) |text| std.fmt.parseInt(u64, text, 16) catch return error.InvalidNmOutput else 0,
    };
}

pub fn checkNm(object: format.Object, text: []const u8, names: []const []const u8, mapping: bool) !void {
    if (text.len > tools.output_limit) return error.ToolOutputLimit;
    var found: [32]bool = [_]bool{false} ** 32;
    if (names.len > found.len) return error.InvalidNmOutput;
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |line| {
        if (std.mem.trim(u8, line, " \r\t").len == 0) continue;
        const row = try nmRow(line);
        if (!mapping and (row.kind == 'U' or row.kind == 'w' or row.kind == 'v')) return error.UndefinedSymbol;
        for (names, 0..) |name, index| if (std.mem.eql(u8, row.name, name)) {
            if (found[index]) return error.DuplicateNmSymbol;
            const symbol = try object.symbol(name);
            const expected: u8 = if (mapping) 'U' else if (symbol.entry.st_type() == std.elf.STT_FUNC) 'T' else 'R';
            if (row.kind != expected or (!mapping and (row.value != symbol.entry.st_value or row.size != symbol.entry.st_size)))
                return error.InconsistentNmOutput;
            found[index] = true;
        };
    }
    for (found[0..names.len]) |present| if (!present) return error.MissingNmSymbol;
}

pub fn checkSections(object: format.Object, text: []const u8) !void {
    if (text.len > tools.output_limit) return error.ToolOutputLimit;
    var found: [pages.len]bool = [_]bool{false} ** pages.len;
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |raw| {
        const line = std.mem.trim(u8, raw, " \t\r");
        if (!std.mem.startsWith(u8, line, "[")) continue;
        const close = std.mem.indexOfScalar(u8, line, ']') orelse return error.InvalidReadelfOutput;
        var words = std.mem.tokenizeAny(u8, line[close + 1 ..], " \t");
        const name = words.next() orelse continue;
        for (pages, 0..) |page, index| if (std.mem.eql(u8, page.name, name)) {
            if (found[index]) return error.DuplicateSection;
            const section = try object.section(page.name);
            const number = std.fmt.parseInt(usize, std.mem.trim(u8, line[1..close], " "), 10) catch return error.InvalidReadelfOutput;
            if (number != section.index or !std.mem.eql(u8, words.next() orelse return error.InvalidReadelfOutput, if (page.nobits) "NOBITS" else "PROGBITS"))
                return error.InconsistentReadelfOutput;
            const sh = section.header;
            for ([_]u64{ sh.sh_addr, sh.sh_offset, sh.sh_size, sh.sh_entsize }) |expected| {
                const actual = std.fmt.parseInt(u64, words.next() orelse return error.InvalidReadelfOutput, 16) catch return error.InvalidReadelfOutput;
                if (actual != expected) return error.InconsistentReadelfOutput;
            }
            const flags = words.next() orelse return error.InvalidReadelfOutput;
            if (!std.mem.eql(u8, flags, if (page.nobits) "WA" else "A")) return error.InconsistentReadelfOutput;
            for ([_]u64{ sh.sh_link, sh.sh_info, sh.sh_addralign }) |expected| {
                const actual = std.fmt.parseInt(u64, words.next() orelse return error.InvalidReadelfOutput, 10) catch return error.InvalidReadelfOutput;
                if (actual != expected) return error.InconsistentReadelfOutput;
            }
            if (words.next() != null) return error.InvalidReadelfOutput;
            found[index] = true;
        };
    }
    for (found) |present| if (!present) return error.MissingReadelfSection;
}

pub fn readObject(allocator: std.mem.Allocator, io: std.Io, path: []const u8) ![]u8 {
    const stat = try std.Io.Dir.cwd().statFile(io, path, .{ .follow_symlinks = false });
    if (stat.kind != .file) return error.InvalidObjectFile;
    if (stat.size > format.maximum_file) return error.ObjectTooLarge;
    return std.Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(format.maximum_file));
}

pub fn execute(allocator: std.mem.Allocator, io: std.Io, environment: *const std.process.Environ.Map, args: []const []const u8) !void {
    var options = try Options.parse(allocator, args);
    defer options.deinit(allocator);
    const runner = try tools.Tools.init(allocator, io, environment, options.timeout_ms);
    const input = try readObject(allocator, io, options.object);
    defer allocator.free(input);
    const object = try format.Object.parse(allocator, input);
    defer object.deinit();
    try validate(object, options.profile);
    const object_path = try std.Io.Dir.cwd().realPathFileAlloc(io, options.object, allocator);
    defer allocator.free(object_path);
    var nm = try runner.run(&.{ options.nm, "--format=posix", "--no-demangle", "-n", object_path });
    defer nm.deinit(allocator);
    try checkNm(object, nm.stdout, required(options.profile), false);
    if (options.profile == .@"hyperv-runtime") {
        var sections = try runner.run(&.{ options.readelf, "-SW", object_path });
        defer sections.deinit(allocator);
        try checkSections(object, sections.stdout);
    }
    for (options.mappings.items) |path| {
        const bytes = try readObject(allocator, io, path);
        defer allocator.free(bytes);
        const mapping = try format.Object.parse(allocator, bytes);
        defer mapping.deinit();
        try validateMapping(mapping);
        const mapping_path = try std.Io.Dir.cwd().realPathFileAlloc(io, path, allocator);
        defer allocator.free(mapping_path);
        var references = try runner.run(&.{ options.nm, "-u", "--format=posix", "--no-demangle", mapping_path });
        defer references.deinit(allocator);
        try checkNm(mapping, references.stdout, &mapping_names, true);
    }
}

pub const architecture_notice = "INFO: x86-only hosted Hyper-V IRQ and SMP fixtures require the x86-64 CI job; running portable and freestanding checks on this host\n";

pub fn main(init: std.process.Init) void {
    const allocator = init.arena.allocator();
    const args = init.minimal.args.toSlice(allocator) catch fail(error.InvalidArguments);
    if (args.len == 2 and (std.mem.eql(u8, args[1], "architecture-notice") or std.mem.eql(u8, args[1], "--help"))) {
        var out = std.Io.File.stdout().writer(init.io, &.{});
        out.interface.writeAll(if (std.mem.eql(u8, args[1], "architecture-notice")) architecture_notice else "hyperv-object-proofs PROFILE --object FILE [--nm TOOL] [--readelf TOOL] [--mapping-api-object FILE]... [--timeout-ms N]\n") catch fail(error.OutputFailed);
        return;
    }
    execute(std.heap.page_allocator, init.io, init.environ_map, args[1..]) catch |err| fail(err);
}

fn fail(err: anyerror) noreturn {
    std.debug.print("error: object proof: {s}\n", .{@errorName(err)});
    std.process.exit(if (err == error.InvalidArguments or err == error.InvalidTool) 2 else 1);
}
