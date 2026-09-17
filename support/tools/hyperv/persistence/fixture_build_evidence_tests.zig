const std = @import("std");
const evidence = @import("fixture_build_evidence.zig");
const schema = evidence.schema;
const files = @import("preparation_files");
const qualification = @import("qualification");
const t = std.testing;
const io = t.io;
const a = t.allocator;

var serial: usize = 0;

const Case = struct {
    name: []const u8,
    path: [:0]const u8,
    dir: std.Io.Dir,
    arena: std.heap.ArenaAllocator,

    fn init() !Case {
        serial += 1;
        const name = try std.fmt.allocPrint(a, "collector-unit-{d}-{d}", .{ std.os.linux.getpid(), serial });
        errdefer a.free(name);
        try std.Io.Dir.cwd().createDir(io, name, .fromMode(0o700));
        errdefer std.Io.Dir.cwd().deleteTree(io, name) catch @panic("collector test setup cleanup failed");
        const dir = try std.Io.Dir.cwd().openDir(io, name, .{ .follow_symlinks = false, .iterate = true });
        errdefer dir.close(io);
        const path = try dir.realPathFileAlloc(io, ".", a);
        return .{ .name = name, .path = path, .dir = dir, .arena = std.heap.ArenaAllocator.init(a) };
    }

    fn close(self: *Case) void {
        self.arena.deinit();
        self.dir.close(io);
        std.Io.Dir.cwd().deleteTree(io, self.name) catch @panic("collector test cleanup failed");
        a.free(self.path);
        a.free(self.name);
    }

    fn allocator(self: *Case) std.mem.Allocator {
        return self.arena.allocator();
    }

    fn absolute(self: *Case, name: []const u8) ![]const u8 {
        return std.fs.path.join(self.allocator(), &.{ self.path, name });
    }

    fn write(self: *Case, name: []const u8, bytes: []const u8) !void {
        try self.dir.writeFile(io, .{
            .sub_path = name,
            .data = bytes,
            .flags = .{ .exclusive = true, .permissions = .fromMode(0o600) },
        });
    }

    fn directory(self: *Case, name: []const u8) !void {
        try self.dir.createDir(io, name, .fromMode(0o700));
    }

    fn request(self: *Case) !schema.Request {
        try self.directory("inputs");
        try self.directory("lib");
        try self.write("lib/std.zig", "synthetic library input\n");
        try self.directory("lib/include");
        try self.write("lib/include/header.h", "synthetic non-std input\n");
        try self.directory("build-inputs");
        try self.write("build-inputs/elf.zig", "synthetic parser input\n");
        try self.write("inputs/main.zig", "synthetic parent source\n");
        try self.write("inputs/options.zig", "synthetic generated options\n");
        try self.write("compiler", "synthetic compiler bytes; never executed\n");
        try self.write("collector-source", "synthetic collector bytes; never executed\n");
        const root = try self.absolute("inputs/main.zig");
        const scope = try self.absolute("inputs");
        const modules = try self.allocator().alloc(schema.Module, 1);
        modules[0] = .{ .name = "main", .root = root, .scope = scope };
        return .{
            .source_commit = "1" ** 40,
            .source_tree = "2" ** 40,
            .configured_json = try syntheticConfigured(self.allocator()),
            .parent = "",
            .raw_worker = try self.absolute("raw"),
            .selected_worker = try self.absolute("selected"),
            .compiler = try self.absolute("compiler"),
            .compiler_lib = try self.absolute("lib"),
            .main_options = try self.absolute("inputs/options.zig"),
            .main_source = root,
            .repository_hyperv = scope,
            .repository_build = try self.absolute("build-inputs"),
            .worker_proof = try self.absolute("worker-proof.json"),
            .fixture_log = try self.absolute("fixtures.log"),
            .invocation_exit = try self.absolute("exit.txt"),
            .modules = modules,
        };
    }
};

test "exit marker binds exact ordinary shell status not a fabricated pass" {
    try t.expectEqual(@as(u8, 0), try evidence.parseExit("0\n"));
    try t.expectEqual(@as(u8, 1), try evidence.parseExit("1"));
    try t.expectEqual(@as(u8, 255), try evidence.parseExit("255\n"));
    for ([_][]const u8{ "", "\n", "00", "01\n", "-1", "+0", "256", "0\n\n", "0 ", "0\r\n", "pass", "1x" }) |bad|
        try t.expectError(error.InvalidExitMarker, evidence.parseExit(bad));
}

test "request rejects unsafe paths ambiguous modules identities and parent phase" {
    var fixture = try Case.init();
    defer fixture.close();
    const request = try fixture.request();
    try evidence.validateRequest(request, false);
    var bad = request;
    bad.parent = "/parent";
    try t.expectError(error.InvalidParentPhase, evidence.validateRequest(bad, false));
    try t.expectError(error.UnsafePath, evidence.validateRequest(request, true));
    bad = request;
    bad.source_commit = "X" ** 40;
    try t.expectError(error.InvalidSourceIdentity, evidence.validateRequest(bad, false));
    bad = request;
    bad.compiler = "/a/../compiler";
    try t.expectError(error.UnsafePath, evidence.validateRequest(bad, false));
    bad = request;
    bad.modules = &.{ request.modules[0], request.modules[0] };
    try t.expectError(error.DuplicateModule, evidence.validateRequest(bad, false));
    bad = request;
    bad.modules = &.{.{ .name = "main", .root = "/outside/main.zig", .scope = "/scope" }};
    try t.expectError(error.InvalidModuleScope, evidence.validateRequest(bad, false));
    bad = request;
    bad.parent = "/actual-parent";
    try evidence.requireSameRequest(a, request, bad);
    bad.compiler = "/different/compiler";
    try t.expectError(error.BaselineMismatch, evidence.requireSameRequest(a, request, bad));
}

test "metadata baseline inspects entire tree including non std files and empty directories" {
    var fixture = try Case.init();
    defer fixture.close();
    const request = try fixture.request();
    const before = try evidence.observeTree(a, io, request.compiler_lib, .{}, false);
    try t.expect(before.content_sha256 == null);
    try t.expectEqual(@as(u32, 2), before.files);
    try t.expectEqual(@as(u32, 1), before.directories);
    const hashed = try evidence.observeTree(a, io, request.compiler_lib, .{}, true);
    try t.expectEqualStrings(&before.metadata_sha256, &hashed.metadata_sha256);
    try t.expect(hashed.content_sha256 != null);
    try fixture.directory("lib/empty");
    const directory_changed = try evidence.observeTree(a, io, request.compiler_lib, .{}, false);
    try t.expect(!std.mem.eql(u8, &before.metadata_sha256, &directory_changed.metadata_sha256));
    const writer = try fixture.dir.openFile(io, "lib/include/header.h", .{ .mode = .read_write });
    defer writer.close(io);
    try writer.writePositionalAll(io, "X", 0);
    const changed = try evidence.observeTree(a, io, request.compiler_lib, .{}, true);
    try t.expect(!std.mem.eql(u8, &hashed.content_sha256.?, &changed.content_sha256.?));
    try t.expect(!std.mem.eql(u8, &directory_changed.metadata_sha256, &changed.metadata_sha256));
    try fixture.dir.rename("lib/include/header.h", fixture.dir, "lib/include/renamed.h", io);
    const renamed = try evidence.observeTree(a, io, request.compiler_lib, .{}, true);
    try t.expect(!std.mem.eql(u8, &changed.content_sha256.?, &renamed.content_sha256.?));
    try t.expect(!std.mem.eql(u8, &changed.metadata_sha256, &renamed.metadata_sha256));
}

test "tree metadata refuses symbolic links hard links specials and bounds" {
    var fixture = try Case.init();
    defer fixture.close();
    try fixture.directory("tree");
    try fixture.write("tree/file", "four");
    const path = try fixture.absolute("tree");
    try t.expectError(error.FileTooLarge, evidence.observeTree(a, io, path, .{ .per_file = 3 }, false));
    try t.expectError(error.LimitExceeded, evidence.observeTree(a, io, path, .{ .bytes = 3 }, false));
    try t.expectError(error.LimitExceeded, evidence.observeTree(a, io, path, .{ .files = 0 }, false));
    try fixture.dir.symLink(io, "file", "tree/link", .{});
    try t.expectError(error.UnsafeFile, evidence.observeTree(a, io, path, .{}, false));
    try fixture.dir.deleteFile(io, "tree/link");
    const link_source = try fixture.dir.openFile(io, "tree/file", .{});
    defer link_source.close(io);
    try link_source.hardLink(io, fixture.dir, "tree/hard", .{});
    try t.expectError(error.UnsafeFile, evidence.observeTree(a, io, path, .{}, false));
    try fixture.dir.deleteFile(io, "tree/hard");
    const special = try std.fmt.allocPrintSentinel(fixture.allocator(), "{s}/tree/fifo", .{fixture.path}, 0);
    const rc = std.os.linux.mknodat(std.os.linux.AT.FDCWD, special, std.os.linux.S.IFIFO | 0o600, 0);
    try t.expectEqual(std.os.linux.E.SUCCESS, std.os.linux.errno(rc));
    try t.expectError(error.UnsafeFile, evidence.observeTree(a, io, path, .{}, false));
}

test "held named file checks reject changed contents truncation and replacement" {
    var fixture = try Case.init();
    defer fixture.close();
    try fixture.write("input", "abcdef");
    const path = try fixture.absolute("input");
    const pin = try evidence.testing.Pin.open(a, io, path, 6);
    defer pin.close(a, io);
    const writer = try fixture.dir.openFile(io, "input", .{ .mode = .read_write });
    defer writer.close(io);
    try writer.writePositionalAll(io, "Z", 0);
    try t.expectError(error.SourceChanged, pin.recheck(a, io));
    const current = try evidence.testing.Pin.open(a, io, path, 6);
    defer current.close(a, io);
    try writer.setLength(io, 3);
    try t.expectError(error.SourceChanged, current.hash(a, io));
    const short = try evidence.testing.Pin.open(a, io, path, 6);
    defer short.close(a, io);
    try fixture.dir.rename("input", fixture.dir, "retained", io);
    try fixture.write("input", "Zbc");
    try t.expectError(error.SourceChanged, short.recheck(a, io));
}

test "stream copy reads full EOF refuses existing outputs and preserves primary failure history" {
    var fixture = try Case.init();
    defer fixture.close();
    try fixture.write("input", "complete bytes\n");
    const path = try fixture.absolute("input");
    const copied = try evidence.testing.copy(a, io, path, fixture.dir, "output", 64);
    try t.expectEqual(@as(u64, 15), copied.size);
    const bytes = try fixture.dir.readFileAlloc(io, "output", a, .limited(64));
    defer a.free(bytes);
    try t.expectEqualStrings("complete bytes\n", bytes);
    const output = try fixture.dir.openFile(io, "output", .{});
    defer output.close(io);
    try t.expectEqual(@as(u16, 0o600), (try files.metadata(output)).mode & 0o7777);
    try t.expectError(error.PathAlreadyExists, evidence.testing.copy(a, io, path, fixture.dir, "output", 64));
    try t.expectError(error.FileTooLarge, evidence.testing.copy(a, io, path, fixture.dir, "oversize", 2));
    try t.expectError(error.FileNotFound, fixture.dir.openFile(io, "oversize", .{}));
    try fixture.write("partial", "incomplete");
    try t.expectError(error.PathAlreadyExists, evidence.testing.copy(a, io, path, fixture.dir, "partial", 64));
    const partial = try fixture.dir.readFileAlloc(io, "partial", a, .limited(64));
    defer a.free(partial);
    try t.expectEqualStrings("incomplete", partial);
    try fixture.dir.symLink(io, "input", "alias", .{});
    try t.expectError(error.PathAlreadyExists, evidence.testing.copy(a, io, path, fixture.dir, "alias", 64));
    try t.expectError(error.UnsafeFile, evidence.testing.copy(a, io, try fixture.absolute("alias"), fixture.dir, "bad", 64));
    const large = "a" ** (64 * 1024 + 1);
    try fixture.write("large", large);
    try t.expectError(error.InjectedPrimaryFailure, evidence.testing.partialCopy(a, io, try fixture.absolute("large"), fixture.dir, "interrupted"));
    const interrupted = try fixture.dir.openFile(io, "interrupted", .{});
    defer interrupted.close(io);
    try t.expectEqual(@as(u64, 64 * 1024), (try files.metadata(interrupted)).size);
    try t.expectError(error.PathAlreadyExists, evidence.testing.copy(a, io, try fixture.absolute("large"), fixture.dir, "interrupted", large.len));
}

test "baseline creates fresh private custody without reading or requiring worker files" {
    var fixture = try Case.init();
    defer fixture.close();
    const request = try fixture.request();
    const root = try fixture.absolute("capture");
    try evidence.baseline(a, io, root, request, try fixture.absolute("collector-source"));
    const baseline = try fixture.dir.readFileAlloc(io, "capture/baseline.json", a, .limited(schema.max_plan_bytes));
    defer a.free(baseline);
    try t.expect(std.mem.indexOf(u8, baseline, "\"parent\":\"\"") != null);
    try t.expect(std.mem.indexOf(u8, baseline, "\"content_sha256\":null") != null);
    try t.expectError(error.FileNotFound, fixture.dir.openFile(io, "capture/plan.json", .{}));
    try t.expectError(error.FileNotFound, fixture.dir.openFile(io, "raw", .{}));
    const collector = try fixture.dir.openFile(io, "capture/collector", .{});
    defer collector.close(io);
    try t.expectEqual(@as(u16, 0o700), (try files.metadata(collector)).mode & 0o7777);
    try t.expectError(error.PathAlreadyExists, evidence.baseline(a, io, root, request, try fixture.absolute("collector-source")));
    try fixture.directory("adoption");
    try fixture.write("adoption/retained", "primary failure history");
    try t.expectError(error.PathAlreadyExists, evidence.baseline(a, io, try fixture.absolute("adoption"), request, try fixture.absolute("collector-source")));
    try fixture.dir.symLink(io, "adoption", "symlink-root", .{});
    try t.expectError(error.PathAlreadyExists, evidence.baseline(a, io, try fixture.absolute("symlink-root"), request, try fixture.absolute("collector-source")));
}

test "prepare metadata only creates an immutable plan and refuses changed precompile library" {
    var fixture = try Case.init();
    defer fixture.close();
    var request = try fixture.request();
    const root = try fixture.absolute("capture");
    try evidence.baseline(a, io, root, request, try fixture.absolute("collector-source"));
    try fixture.write("parent", "synthetic non-ELF parent; prepare must not parse");
    try fixture.write("raw", "synthetic non-ELF raw; prepare must not parse");
    try fixture.write("selected", "synthetic non-ELF selected; prepare must not parse");
    request.parent = try fixture.absolute("parent");
    try evidence.prepare(a, io, root, request);
    try t.expectError(error.PathAlreadyExists, evidence.prepare(a, io, root, request));
    const plan = try fixture.dir.readFileAlloc(io, "capture/plan.json", a, .limited(schema.max_plan_bytes));
    defer a.free(plan);
    try t.expect(std.mem.indexOf(u8, plan, "\"parent\":{") != null);
    try t.expect(std.mem.indexOf(u8, plan, "synthetic non-ELF") == null);
    const changed = try fixture.dir.openFile(io, "lib/include/header.h", .{ .mode = .read_write });
    defer changed.close(io);
    try changed.writePositionalAll(io, "X", 0);
    try t.expectError(error.SourceChanged, evidence.prepare(a, io, root, request));
}

test "collector cannot adopt incomplete baseline or missing plan" {
    var fixture = try Case.init();
    defer fixture.close();
    const request = try fixture.request();
    const root = try fixture.absolute("capture");
    try evidence.baseline(a, io, root, request, try fixture.absolute("collector-source"));
    try t.expectError(error.FileNotFound, evidence.collect(a, io, root));
    try fixture.write("capture/plan.json", "{\"marker\":");
    if (evidence.collect(a, io, root)) |_| return error.AcceptedMalformedPlan else |_| {}
    try t.expectError(error.FileNotFound, fixture.dir.openFile(io, "capture/evidence/report.json", .{}));
    const retained = try fixture.dir.readFileAlloc(io, "capture/plan.json", a, .limited(64));
    defer a.free(retained);
    try t.expectEqualStrings("{\"marker\":", retained);
    try fixture.dir.rename("capture", fixture.dir, "renamed-capture", io);
    try t.expectError(error.BaselineMismatch, evidence.collect(a, io, try fixture.absolute("renamed-capture")));
}

fn put(comptime T: type, bytes: []u8, offset: usize, value: T) void {
    std.mem.writeInt(T, bytes[offset..][0..@sizeOf(T)], value, .little);
}

fn workerImage(raw: bool) [768]u8 {
    var bytes = [_]u8{0} ** 768;
    @memcpy(bytes[0..7], "\x7fELF\x02\x01\x01");
    put(u16, &bytes, 16, 2);
    put(u16, &bytes, 18, @intFromEnum(std.elf.EM.AARCH64));
    put(u32, &bytes, 20, 1);
    put(u64, &bytes, 24, 0x400080);
    put(u64, &bytes, 32, 64);
    const table: usize = if (raw) 512 else 320;
    const strings: usize = if (raw) 320 else 256;
    put(u64, &bytes, 40, table);
    put(u16, &bytes, 52, 64);
    put(u16, &bytes, 54, 56);
    put(u16, &bytes, 56, 1);
    put(u16, &bytes, 58, 64);
    put(u16, &bytes, 60, if (raw) 4 else 3);
    put(u16, &bytes, 62, if (raw) 3 else 2);
    put(u32, &bytes, 64, std.elf.PT_LOAD);
    put(u32, &bytes, 68, std.elf.PF_R | std.elf.PF_X);
    put(u64, &bytes, 80, 0x400000);
    put(u64, &bytes, 88, 0x400000);
    put(u64, &bytes, 96, 256);
    put(u64, &bytes, 104, 256);
    put(u64, &bytes, 112, 4096);
    @memset(bytes[128..144], 0x90);
    const names = "\x00.text\x00.debug_info\x00.shstrtab\x00";
    @memcpy(bytes[strings..][0..names.len], names);
    const text = table + 64;
    put(u32, &bytes, text, 1);
    put(u32, &bytes, text + 4, std.elf.SHT_PROGBITS);
    put(u64, &bytes, text + 8, std.elf.SHF_ALLOC | std.elf.SHF_EXECINSTR);
    put(u64, &bytes, text + 16, 0x400080);
    put(u64, &bytes, text + 24, 128);
    put(u64, &bytes, text + 32, 16);
    put(u64, &bytes, text + 48, 16);
    if (raw) {
        @memset(bytes[256..320], 0xd7);
        const debug = table + 128;
        put(u32, &bytes, debug, 7);
        put(u32, &bytes, debug + 4, std.elf.SHT_PROGBITS);
        put(u64, &bytes, debug + 24, 256);
        put(u64, &bytes, debug + 32, 64);
        put(u64, &bytes, debug + 48, 1);
    }
    const names_section = table + (if (raw) @as(usize, 192) else 128);
    put(u32, &bytes, names_section, 19);
    put(u32, &bytes, names_section + 4, std.elf.SHT_STRTAB);
    put(u64, &bytes, names_section + 24, strings);
    put(u64, &bytes, names_section + 32, names.len);
    put(u64, &bytes, names_section + 48, 1);
    return bytes;
}

test "post-run worker proof is rederived from exact synthetic ELF pair not accepted as approval" {
    var fixture = try Case.init();
    defer fixture.close();
    const raw_bytes = workerImage(true);
    const selected_bytes = workerImage(false);
    try fixture.dir.writeFile(io, .{ .sub_path = "raw", .data = &raw_bytes, .flags = .{ .exclusive = true, .permissions = .fromMode(0o700) } });
    try fixture.dir.writeFile(io, .{ .sub_path = "selected", .data = selected_bytes[0..512], .flags = .{ .exclusive = true, .permissions = .fromMode(0o700) } });
    const raw = try fixture.absolute("raw");
    const selected = try fixture.absolute("selected");
    try qualification.qualify(a, io, .{ .raw = raw, .candidate = selected, .report = try fixture.absolute("proof.json") });
    const proof = try fixture.dir.readFileAlloc(io, "proof.json", a, .limited(schema.max_metadata_bytes));
    defer a.free(proof);
    try evidence.testing.proof(fixture.allocator(), io, proof, raw, selected);
    if (evidence.testing.proof(fixture.allocator(), io, "{\"passed\":true}", raw, selected)) |_| return error.AcceptedApproval else |_| {}
    if (evidence.testing.proof(fixture.allocator(), io, proof[0 .. proof.len - 3], raw, selected)) |_| return error.AcceptedTruncation else |_| {}
    const altered = try a.dupe(u8, proof);
    defer a.free(altered);
    const hash_offset = (std.mem.indexOf(u8, altered, "\"sha256\":\"") orelse return error.MissingHash) + "\"sha256\":\"".len;
    altered[hash_offset] = if (altered[hash_offset] == '0') '1' else '0';
    try t.expectError(error.WorkerProofMismatch, evidence.testing.proof(fixture.allocator(), io, altered, raw, selected));
    const writer = try fixture.dir.openFile(io, "selected", .{ .mode = .read_write });
    defer writer.close(io);
    try writer.writePositionalAll(io, &.{0x91}, 140);
    try t.expectError(error.LoadedContentChanged, evidence.testing.proof(fixture.allocator(), io, proof, raw, selected));
}

// Data-only ELF samples exercise the parser. None is executed or represented as
// a qualification run of the real parent, toolchain, or persistence fixtures.
fn parentImage(allocator: std.mem.Allocator, payload: []const u8) ![]u8 {
    const names = "\x00.shstrtab\x00.uk.persistence.build\x00";
    const payload_offset = 256 + names.len;
    const bytes = try allocator.alloc(u8, payload_offset + payload.len);
    @memset(bytes, 0);
    @memcpy(bytes[0..7], "\x7fELF\x02\x01\x01");
    put(u16, bytes, 16, 2);
    put(u16, bytes, 18, switch (@import("builtin").cpu.arch) {
        .aarch64 => @intFromEnum(std.elf.EM.AARCH64),
        .x86_64 => @intFromEnum(std.elf.EM.X86_64),
        else => unreachable,
    });
    put(u32, bytes, 20, 1);
    put(u64, bytes, 40, 64);
    put(u16, bytes, 52, 64);
    put(u16, bytes, 58, 64);
    put(u16, bytes, 60, 3);
    put(u16, bytes, 62, 1);
    put(u32, bytes, 128, 1);
    put(u32, bytes, 132, std.elf.SHT_STRTAB);
    put(u64, bytes, 152, 256);
    put(u64, bytes, 160, names.len);
    put(u64, bytes, 176, 1);
    put(u32, bytes, 192, 11);
    put(u32, bytes, 196, std.elf.SHT_PROGBITS);
    put(u64, bytes, 216, payload_offset);
    put(u64, bytes, 224, payload.len);
    put(u64, bytes, 240, 1);
    @memcpy(bytes[256..][0..names.len], names);
    @memcpy(bytes[payload_offset..], payload);
    return bytes;
}

fn syntheticConfigured(allocator: std.mem.Allocator) ![]const u8 {
    const metadata = @import("fixture_parent_metadata.zig");
    const parent = try std.json.parseFromSliceLeaky(std.json.Value, allocator, &metadata.payload, .{});
    const target = parent.object.get("observed").?.object.get("target").?;
    const value = .{
        .schema = "hyperv_persistence_fixture_configured_build_v1",
        .origin = "actual_parent_Compile_and_rootModule",
        .null_semantics = "unspecified_compiler_default_not_observed_false",
        .source_identity = "user_supplied_not_authenticated",
        .test_selection = "all_unfiltered_35_main_cases",
        .test_filters = [_][]const u8{},
        .test_run_seed = 0,
        .parent_compilation_bookend = "metadata_only_baseline_and_prepare",
        .worker_compiler_bookend = "not_claimed_workers_precede_baseline",
        .module_scope = "configured_reachable_package_envelopes_not_compiler_resolved_import_embed_closure",
        .modules = .{.{ .name = "main", .imports = .{} }},
        .target_query = .{
            .cpu_arch = null,
            .cpu_model = "determined_by_arch_os",
            .explicit_cpu_model = null,
            .cpu_features_add = null,
            .cpu_features_sub = null,
            .os_tag = null,
            .os_version_min = null,
            .os_version_max = null,
            .glibc_version = null,
            .android_api_level = null,
            .abi = null,
            .ofmt = null,
            .dynamic_linker_specified = false,
            .dynamic_linker_path = "omitted_path",
        },
        .resolved_target = target,
        .compile = .{
            .kind = "test",
            .use_llvm = null,
            .use_lld = null,
            .use_new_linker = null,
            .linkage = null,
            .pie = null,
            .lto = null,
            .stack_size = null,
            .rdynamic = null,
            .link_gc_sections = null,
            .link_function_sections = null,
            .link_data_sections = null,
            .compress_debug_sections = null,
            .bundle_compiler_rt = null,
            .bundle_ubsan_rt = null,
            .zig_lib_dir_override = false,
            .custom_test_runner = false,
        },
        .root_module = .{
            .optimize = @tagName(@import("builtin").mode),
            .strip = null,
            .dwarf_format = null,
            .unwind_tables = null,
            .single_threaded = null,
            .stack_protector = null,
            .stack_check = null,
            .sanitize_c = null,
            .sanitize_thread = null,
            .fuzz = null,
            .code_model = null,
            .valgrind = null,
            .pic = null,
            .red_zone = null,
            .omit_frame_pointer = null,
            .error_tracing = null,
            .link_libc = null,
            .link_libcpp = null,
            .no_builtin = null,
        },
    };
    return std.json.Stringify.valueAlloc(allocator, value, .{});
}

test "synthetic parent ELF metadata uses its section rejects malformed bounds and closed schema" {
    var fixture = try Case.init();
    defer fixture.close();
    var request = try fixture.request();
    request.configured_json = try syntheticConfigured(fixture.allocator());
    const payload = &@import("fixture_parent_metadata.zig").payload;
    const bytes = try parentImage(fixture.allocator(), payload);
    const actual = try evidence.parentMetadata(fixture.allocator(), bytes, request);
    try t.expectEqualStrings("actual_tests_zig_compile_builtin", actual.object.get("origin").?.string);
    try t.expectEqualStrings(@tagName(@import("builtin").mode), actual.object.get("observed").?.object.get("mode").?.string);
    if (evidence.parentMetadata(fixture.allocator(), bytes[0 .. bytes.len - 1], request)) |_| return error.AcceptedTruncatedElf else |_| {}
    const malformed = try parentImage(fixture.allocator(), "{\"schema\":\"not_the_parent\"}");
    try t.expectError(error.InvalidBuildMetadata, evidence.parentMetadata(fixture.allocator(), malformed, request));
    const prefix = try parentImage(fixture.allocator(), payload[0 .. payload.len - 1]);
    if (evidence.parentMetadata(fixture.allocator(), prefix, request)) |_| return error.AcceptedIncompletePrefix else |_| {}
    var parent = try std.json.parseFromSliceLeaky(std.json.Value, fixture.allocator(), payload, .{});
    try parent.object.put(fixture.allocator(), "absolute_path", .{ .string = "/private/input" });
    const extra_payload = try std.json.Stringify.valueAlloc(fixture.allocator(), parent, .{});
    const extra = try parentImage(fixture.allocator(), extra_payload);
    try t.expectError(error.InvalidBuildMetadata, evidence.parentMetadata(fixture.allocator(), extra, request));
}

test "synthetic collection retains exact bytes full envelopes and failed original status without admission" {
    var fixture = try Case.init();
    defer fixture.close();
    var request = try fixture.request();
    request.configured_json = try syntheticConfigured(fixture.allocator());
    const payload = &@import("fixture_parent_metadata.zig").payload;
    const parent_bytes = try parentImage(fixture.allocator(), payload);
    const raw_bytes = workerImage(true);
    const selected_bytes = workerImage(false);
    try fixture.write("parent", parent_bytes);
    try fixture.dir.writeFile(io, .{ .sub_path = "raw", .data = &raw_bytes, .flags = .{ .exclusive = true, .permissions = .fromMode(0o700) } });
    try fixture.dir.writeFile(io, .{ .sub_path = "selected", .data = selected_bytes[0..512], .flags = .{ .exclusive = true, .permissions = .fromMode(0o700) } });
    try qualification.qualify(a, io, .{ .raw = request.raw_worker, .candidate = request.selected_worker, .report = request.worker_proof });
    const root = try fixture.absolute("capture");
    try evidence.baseline(a, io, root, request, try fixture.absolute("collector-source"));
    request.parent = try fixture.absolute("parent");
    try evidence.prepare(a, io, root, request);
    const original_log = "synthetic original failure log\n";
    try fixture.write("fixtures.log", original_log);
    try fixture.write("exit.txt", "7\n");
    try evidence.collect(a, io, root);
    const report_bytes = try fixture.dir.readFileAlloc(io, "capture/evidence/report.json", a, .limited(schema.max_metadata_bytes));
    defer a.free(report_bytes);
    const report = try std.json.parseFromSlice(std.json.Value, a, report_bytes, .{});
    defer report.deinit();
    try t.expect(report.value.object.get("diagnostic").?.bool);
    try t.expect(!report.value.object.get("admitted").?.bool and !report.value.object.get("authenticating").?.bool);
    try t.expectEqual(@as(i64, 7), report.value.object.get("invocation_exit").?.object.get("code").?.integer);
    try t.expectEqualStrings("exact_main_parent", report.value.object.get("parent").?.object.get("role").?.string);
    try t.expect(std.mem.indexOf(u8, report_bytes, fixture.path) == null);
    try t.expect(std.mem.indexOf(u8, report_bytes, "\"inode\"") == null);
    try t.expect(std.mem.indexOf(u8, report_bytes, "\"device\"") == null);
    try t.expect(std.mem.indexOf(u8, report_bytes, "\"passed\"") == null);
    const files_expected = [_][]const u8{ parent_bytes, &raw_bytes, selected_bytes[0..512] };
    for ([_][]const u8{ "parent-test", "worker-raw", "worker-selected" }, files_expected) |name, expected| {
        const relative = try std.fmt.allocPrint(fixture.allocator(), "capture/evidence/{s}", .{name});
        const actual = try fixture.dir.readFileAlloc(io, relative, a, .limited(schema.max_parent_bytes));
        defer a.free(actual);
        try t.expectEqualSlices(u8, expected, actual);
    }
    const compiler_lib = report.value.object.get("input_trees").?.array.items[0].object.get("tree").?;
    try t.expectEqual(@as(i64, 2), compiler_lib.object.get("files").?.integer);
    try t.expect(compiler_lib.object.get("content_sha256").? == .string);
    try t.expectError(error.PathAlreadyExists, evidence.collect(a, io, root));
    const retained_log = try fixture.dir.readFileAlloc(io, "fixtures.log", a, .limited(128));
    defer a.free(retained_log);
    try t.expectEqualStrings(original_log, retained_log);
}

test "failed collection retains private copies without publishing CI evidence" {
    var fixture = try Case.init();
    defer fixture.close();
    var request = try fixture.request();
    request.configured_json = try syntheticConfigured(fixture.allocator());
    try fixture.write("parent", try parentImage(fixture.allocator(), &@import("fixture_parent_metadata.zig").payload));
    const raw_bytes = workerImage(true);
    const selected_bytes = workerImage(false);
    try fixture.dir.writeFile(io, .{ .sub_path = "raw", .data = &raw_bytes, .flags = .{ .exclusive = true, .permissions = .fromMode(0o700) } });
    try fixture.dir.writeFile(io, .{ .sub_path = "selected", .data = selected_bytes[0..512], .flags = .{ .exclusive = true, .permissions = .fromMode(0o700) } });
    const root = try fixture.absolute("capture");
    try evidence.baseline(a, io, root, request, try fixture.absolute("collector-source"));
    request.parent = try fixture.absolute("parent");
    try evidence.prepare(a, io, root, request);
    try fixture.write(std.fs.path.basename(request.worker_proof), "{}");
    try fixture.write("fixtures.log", "original fixture failure\n");
    try fixture.write("exit.txt", "1\n");
    try t.expectError(error.InvalidWorkerProof, evidence.collect(a, io, root));
    try t.expectError(error.FileNotFound, fixture.dir.openDir(io, "capture/evidence", .{}));
    const retained = try fixture.dir.openFile(io, "capture/pending/parent-test", .{});
    retained.close(io);
    try t.expectError(error.PathAlreadyExists, evidence.collect(a, io, root));
}
