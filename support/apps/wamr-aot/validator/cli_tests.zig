// SPDX-License-Identifier: BSD-3-Clause
const std = @import("std");
const linux = std.os.linux;

const wamr_rev = "ffffffffffffffffffffffffffffffffffffffff";
const wasm_sha = "0000000000000000000000000000000000000000000000000000000000000000";
const cwasm_sha = "1111111111111111111111111111111111111111111111111111111111111111";
const runtime_sha = "2222222222222222222222222222222222222222222222222222222222222222";
const wasi_wasm_sha = "3333333333333333333333333333333333333333333333333333333333333333";
const wasi_cwasm_sha = "4444444444444444444444444444444444444444444444444444444444444444";

const tiny_identity_json =
    "{\"wamr_revision\": \"" ++ wamr_rev ++ "\", \"minimal_wasi\": false, \"files\": {" ++
    "\"tiny.wasm\": \"" ++ wasm_sha ++ "\", " ++
    "\"tiny.cwasm\": \"" ++ cwasm_sha ++ "\", " ++
    "\"libwamr-aot.a\": \"" ++ runtime_sha ++ "\"}}";

const full_wasi_identity_json =
    "{\"wamr_revision\": \"" ++ wamr_rev ++ "\", \"minimal_wasi\": true, \"files\": {" ++
    "\"tiny.wasm\": \"" ++ wasm_sha ++ "\", " ++
    "\"tiny.cwasm\": \"" ++ cwasm_sha ++ "\", " ++
    "\"libwamr-aot.a\": \"" ++ runtime_sha ++ "\", " ++
    "\"coremark.wasm\": \"" ++ wasi_wasm_sha ++ "\", " ++
    "\"coremark.cwasm\": \"" ++ wasi_cwasm_sha ++ "\", " ++
    "\"coremark-nofp.wasm\": \"" ++ wasi_wasm_sha ++ "\", " ++
    "\"coremark-nofp.cwasm\": \"" ++ wasi_cwasm_sha ++ "\"}}";

const compute_record_json =
    "{\"version\": 1, \"workload\": \"tiny\", \"wamr_revision\": \"" ++ wamr_rev ++ "\", " ++
    "\"wasm_sha256\": \"" ++ wasm_sha ++ "\", " ++
    "\"cwasm_sha256\": \"" ++ cwasm_sha ++ "\", " ++
    "\"runtime_sha256\": \"" ++ runtime_sha ++ "\", " ++
    "\"platform_status\": 0, \"checks\": 2, \"answer\": 42, \"terminal\": 1, \"detail\": 2, " ++
    "\"reserved_bytes\": 0, \"frame_bytes\": 0, \"accessible_bytes\": 0, \"allocation_bytes\": 0, " ++
    "\"error_name\": \"\", \"system_page_table_bytes\": 4096}";

const coremark_stdout_b64 =
    "MksgcGVyZm9ybWFuY2UgcnVuIHBhcmFtZXRlcnMgZm9yIGNvcmVtYXJrLgpDb3JlTWFyayBTaXpl" ++
    "ICAgIDogNjY2ClRvdGFsIHRpY2tzICAgICAgOiAxClRvdGFsIHRpbWUgKHNlY3MpOiAwLjAwMTAw" ++
    "MApJdGVyYXRpb25zL1NlYyAgIDogMTAwMDAwLjAwMDAwMApFUlJPUiEgTXVzdCBleGVjdXRlIGZv" ++
    "ciBhdCBsZWFzdCAxMCBzZWNzIGZvciBhIHZhbGlkIHJlc3VsdCEKSXRlcmF0aW9ucyAgICAgICA6" ++
    "IDEwMApDb21waWxlciB2ZXJzaW9uIDogc3ludGhldGljIGZpeHR1cmUsIG5vdCBleGVjdXRpb24g" ++
    "ZXZpZGVuY2UKQ29tcGlsZXIgZmxhZ3MgICA6IHN5bnRoZXRpYwpNZW1vcnkgbG9jYXRpb24gIDog" ++
    "U1RBQ0sKc2VlZGNyYyAgICAgICAgICA6IDB4ZTlmNQpbMF1jcmNsaXN0ICAgICAgIDogMHhlNzE0" ++
    "ClswXWNyY21hdHJpeCAgICAgOiAweDFmZDcKWzBdY3Jjc3RhdGUgICAgICA6IDB4OGUzYQpbMF1j" ++
    "cmNmaW5hbCAgICAgIDogMHg5ODhjCkVycm9ycyBkZXRlY3RlZAo=";

fn wasiRecordLine(comptime name: []const u8) []const u8 {
    return "WAMR_NATIVE_WASI={\"version\": 1, \"correctness_only\": true, \"workload\": \"" ++ name ++ "\", " ++
        "\"wasm_sha256\": \"" ++ wasi_wasm_sha ++ "\", " ++
        "\"cwasm_sha256\": \"" ++ wasi_cwasm_sha ++ "\", " ++
        "\"terminal\": 2, \"detail\": 0, \"crc_ok\": true, \"output_error\": 0, " ++
        "\"pending_stdout\": 0, \"pending_stderr\": 0, \"unsupported_clock\": 0, " ++
        "\"realtime_supported\": true, \"stdout_base64\": \"" ++ coremark_stdout_b64 ++ "\", " ++
        "\"stderr_base64\": \"\"}\n";
}

const boot_banner =
    "Hyper-V Hv#1 hypercall page enabled\n" ++
    "Hyper-V SynIC:\n" ++
    "Powered by\n" ++
    "Calling main(0, 0)\n";

const end_banner = "[    1.000001] Info: [libukboot] main returned 0\n";
const compute_line = "WAMR_NATIVE_COMPUTE=" ++ compute_record_json ++ "\n";
const aot_ok_line = "WAMR_NATIVE_AOT_OK answer=42 teardown=0\n";

const tiny_raw = boot_banner ++ compute_line ++ aot_ok_line ++ end_banner;
const coremark_wasi_raw = boot_banner ++
    wasiRecordLine("coremark") ++
    wasiRecordLine("coremark-nofp") ++
    compute_line ++
    aot_ok_line ++
    end_banner;

fn shaHex(bytes: []const u8) [64]u8 {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
    return std.fmt.bytesToHex(digest, .lower);
}

fn ensurePrivateDir(io: std.Io, path: []const u8) !void {
    try std.Io.Dir.cwd().createDirPath(io, path);
    var dir = try std.Io.Dir.cwd().openDir(io, path, .{ .follow_symlinks = false, .iterate = true });
    defer dir.close(io);
    if (linux.errno(linux.fchmod(dir.handle, 0o700)) != .SUCCESS) return error.ChmodFailed;
}

fn writePrivate(io: std.Io, path: []const u8, data: []const u8) !void {
    var file = try std.Io.Dir.cwd().createFile(io, path, .{
        .truncate = true,
        .permissions = .fromMode(0o600),
    });
    defer file.close(io);
    if (linux.errno(linux.fchmod(file.handle, 0o600)) != .SUCCESS) return error.ChmodFailed;
    try file.writeStreamingAll(io, data);
}

fn chmodPath(a: std.mem.Allocator, path: []const u8, mode: linux.mode_t) !void {
    const path_z = try a.allocSentinel(u8, path.len, 0);
    @memcpy(path_z, path);
    if (linux.errno(linux.fchmodat(linux.AT.FDCWD, path_z, mode)) != .SUCCESS)
        return error.ChmodFailed;
}

fn symlinkPath(a: std.mem.Allocator, target: []const u8, link_path: []const u8) !void {
    const target_z = try a.allocSentinel(u8, target.len, 0);
    @memcpy(target_z, target);
    const link_z = try a.allocSentinel(u8, link_path.len, 0);
    @memcpy(link_z, link_path);
    if (linux.errno(linux.symlinkat(target_z, linux.AT.FDCWD, link_z)) != .SUCCESS)
        return error.SymlinkFailed;
}

const RunResult = struct {
    code: u8,
    stdout: []const u8,
    stderr: []const u8,
};

fn invoke(
    a: std.mem.Allocator,
    io: std.Io,
    binary: []const u8,
    extra_args: []const []const u8,
) !RunResult {
    var argv: std.ArrayList([]const u8) = .empty;
    try argv.append(a, binary);
    try argv.appendSlice(a, extra_args);
    var env = std.process.Environ.Map.init(a);
    defer env.deinit();
    try env.put("PATH", "/nonexistent");
    const res = try std.process.run(a, io, .{
        .argv = argv.items,
        .environ_map = &env,
        .stdout_limit = .limited(256 * 1024),
        .stderr_limit = .limited(256 * 1024),
    });
    const code: u8 = switch (res.term) {
        .exited => |c| c,
        else => return error.ProcessDidNotExitCleanly,
    };
    return .{
        .code = code,
        .stdout = res.stdout,
        .stderr = res.stderr,
    };
}

fn expectStringField(obj: std.json.ObjectMap, key: []const u8, want: []const u8) !void {
    const val = obj.get(key) orelse return error.MissingJsonField;
    switch (val) {
        .string => |s| if (!std.mem.eql(u8, s, want)) return error.JsonFieldMismatch,
        else => return error.JsonFieldTypeMismatch,
    }
}

fn expectIntField(obj: std.json.ObjectMap, key: []const u8, want: i64) !void {
    const val = obj.get(key) orelse return error.MissingJsonField;
    switch (val) {
        .integer => |i| if (i != want) return error.JsonFieldMismatch,
        else => return error.JsonFieldTypeMismatch,
    }
}

fn replaceOnce(a: std.mem.Allocator, haystack: []const u8, needle: []const u8, replacement: []const u8) ![]u8 {
    const idx = std.mem.indexOf(u8, haystack, needle) orelse return error.NeedleNotFound;
    var out: std.ArrayList(u8) = .empty;
    try out.appendSlice(a, haystack[0..idx]);
    try out.appendSlice(a, replacement);
    try out.appendSlice(a, haystack[idx + needle.len ..]);
    return try out.toOwnedSlice(a);
}

fn replaceAll(a: std.mem.Allocator, haystack: []const u8, needle: []const u8, replacement: []const u8) ![]u8 {
    const size = std.mem.replacementSize(u8, haystack, needle, replacement);
    const out = try a.alloc(u8, size);
    _ = std.mem.replace(u8, haystack, needle, replacement, out);
    return out;
}

fn accepted(
    a: std.mem.Allocator,
    io: std.Io,
    binary: []const u8,
    command: []const []const u8,
    raw: []const u8,
    identity_path: []const u8,
    log_path: []const u8,
    mode: []const u8,
    expect_compute: bool,
) !void {
    const before_identity = try std.Io.Dir.cwd().readFileAlloc(io, identity_path, a, .limited(256 * 1024));
    const before_log = try std.Io.Dir.cwd().readFileAlloc(io, log_path, a, .limited(8 * 1024 * 1024));
    var args: std.ArrayList([]const u8) = .empty;
    try args.appendSlice(a, command);
    try args.appendSlice(a, &.{ "--output", "json-v1" });
    const res = try invoke(a, io, binary, args.items);
    if (res.code != 0 or res.stderr.len != 0) return error.AcceptedCommandFailed;
    if (!std.mem.endsWith(u8, res.stdout, "\n") or std.mem.count(u8, res.stdout, "\n") != 1)
        return error.AcceptedOutputFramingInvalid;

    const parsed = try std.json.parseFromSlice(std.json.Value, a, res.stdout, .{});
    const obj = switch (parsed.value) {
        .object => |o| o,
        else => return error.JsonNotObject,
    };
    try expectStringField(obj, "schema", "uk.wamr.log-validation");
    try expectIntField(obj, "schema_version", 1);
    try expectStringField(obj, "mode", mode);
    try expectIntField(obj, "raw_serial_bytes", @intCast(raw.len));
    const raw_sha = shaHex(raw);
    try expectStringField(obj, "raw_serial_sha256", &raw_sha);
    if (expect_compute) {
        const compute_val = obj.get("compute") orelse return error.MissingComputeField;
        const compute_obj = switch (compute_val) {
            .object => |o| o,
            else => return error.ComputeFieldNotObject,
        };
        try expectIntField(compute_obj, "version", 1);
        try expectStringField(compute_obj, "workload", "tiny");
        try expectStringField(compute_obj, "wamr_revision", wamr_rev);
        try expectStringField(compute_obj, "wasm_sha256", wasm_sha);
        try expectStringField(compute_obj, "cwasm_sha256", cwasm_sha);
        try expectStringField(compute_obj, "runtime_sha256", runtime_sha);
        try expectIntField(compute_obj, "answer", 42);
        try expectIntField(compute_obj, "system_page_table_bytes", 4096);
    } else {
        if (obj.contains("compute")) return error.UnexpectedComputeField;
    }

    const after_identity = try std.Io.Dir.cwd().readFileAlloc(io, identity_path, a, .limited(256 * 1024));
    const after_log = try std.Io.Dir.cwd().readFileAlloc(io, log_path, a, .limited(8 * 1024 * 1024));
    if (!std.mem.eql(u8, before_identity, after_identity)) return error.IdentityModified;
    if (!std.mem.eql(u8, before_log, raw) or !std.mem.eql(u8, after_log, raw)) return error.LogModified;
}

fn refused(
    a: std.mem.Allocator,
    io: std.Io,
    binary: []const u8,
    command: []const []const u8,
    category: ?[]const u8,
) !void {
    var args: std.ArrayList([]const u8) = .empty;
    try args.appendSlice(a, command);
    try args.appendSlice(a, &.{ "--output", "json-v1" });
    const res = try invoke(a, io, binary, args.items);
    if (res.code != 1 or res.stdout.len != 0) return error.RefusalExitCodeOrStdoutMismatch;
    if (!std.mem.startsWith(u8, res.stderr, "WAMR_LOG_VALIDATION_REFUSED category="))
        return error.RefusalPrefixMismatch;
    if (std.mem.count(u8, res.stderr, "\n") != 1 or !std.mem.endsWith(u8, res.stderr, "\n"))
        return error.RefusalFramingMismatch;
    if (res.stderr.len >= 160 or std.mem.indexOfScalar(u8, res.stderr, '/') != null)
        return error.RefusalSanitizationFailed;
    if (category) |cat| {
        const needle = try std.fmt.allocPrint(a, "category={s}", .{cat});
        if (std.mem.indexOf(u8, res.stderr, needle) == null)
            return error.RefusalCategoryMismatch;
    }
}

fn usage(
    a: std.mem.Allocator,
    io: std.Io,
    binary: []const u8,
    args: []const []const u8,
) !void {
    const res = try invoke(a, io, binary, args);
    if (res.code != 2 or res.stdout.len != 0) return error.UsageExitCodeOrStdoutMismatch;
    if (!std.mem.startsWith(u8, res.stderr, "usage: uk-wamr-log-validate "))
        return error.UsagePrefixMismatch;
    if (std.mem.indexOfScalar(u8, res.stderr, '/') != null or res.stderr.len >= 400)
        return error.UsageSanitizationFailed;
}

pub fn main(init: std.process.Init) !void {
    _ = linux.syscall1(.umask, 0o077);
    const a = init.arena.allocator();
    const io = init.io;
    const argv = try init.minimal.args.toSlice(a);
    if (argv.len != 2) return error.InvalidArguments;
    const binary = argv[1];

    const base_tmp = init.environ_map.get("TMPDIR") orelse
        init.environ_map.get("ZIG_LOCAL_CACHE_DIR") orelse
        ".d";
    var nonce: [8]u8 = undefined;
    io.random(&nonce);
    const tmp_rel = try std.fmt.allocPrint(
        a,
        "{s}/validator-cli-fixtures/private-{s}",
        .{ base_tmp, std.fmt.bytesToHex(nonce, .lower) },
    );
    try ensurePrivateDir(io, tmp_rel);
    const root = try std.Io.Dir.cwd().realPathFileAlloc(io, tmp_rel, a);
    defer std.Io.Dir.cwd().deleteTree(io, root) catch {};

    const log = try std.fs.path.join(a, &.{ root, "serial.bin" });
    const identity = try std.fs.path.join(a, &.{ root, "identity.json" });
    try writePrivate(io, log, tiny_raw);
    try writePrivate(io, identity, tiny_identity_json);

    const tiny_cmd: []const []const u8 = &.{ "tiny", "--log", log, "--identity", identity };
    try accepted(a, io, binary, tiny_cmd, tiny_raw, identity, log, "tiny", true);

    const human = try invoke(a, io, binary, tiny_cmd);
    if (human.code != 0 or human.stderr.len != 0 or
        !std.mem.eql(u8, human.stdout, "Compute records match; no hardware or benchmark qualification.\n"))
        return error.TinyHumanValidationFailed;

    const framed = try replaceAll(a, tiny_raw, "\n", "\x1b[0m\r\n\x00");
    try writePrivate(io, log, framed);
    try accepted(a, io, binary, tiny_cmd, framed, identity, log, "tiny", true);
    try writePrivate(io, log, tiny_raw);

    const legacy = try replaceOnce(a, tiny_raw, "Powered by\n", "Powered by\nUsing legacy xAPIC MMIO\n");
    try writePrivate(io, log, legacy);
    try accepted(
        a,
        io,
        binary,
        &.{ "tiny", "--log", log, "--identity", identity, "--legacy-apic", "required" },
        legacy,
        identity,
        log,
        "tiny",
        true,
    );
    try refused(
        a,
        io,
        binary,
        &.{ "tiny", "--log", log, "--identity", identity, "--legacy-apic", "forbidden" },
        "transcript",
    );
    try writePrivate(io, log, tiny_raw);
    try refused(
        a,
        io,
        binary,
        &.{ "tiny", "--log", log, "--identity", identity, "--legacy-apic", "required" },
        "transcript",
    );

    const Mutation = struct { before: []const u8, after: []const u8 };
    for ([_]Mutation{
        .{ .before = "\"answer\": 42", .after = "\"answer\": 41" },
        .{ .before = "\"system_page_table_bytes\": 4096", .after = "\"system_page_table_bytes\": 3" },
        .{ .before = "WAMR_NATIVE_AOT_OK answer=42 teardown=0", .after = "WAMR_NATIVE_AOT_FAIL" },
        .{ .before = "\"version\": 1", .after = "\"version\": true" },
        .{ .before = "\"version\": 1", .after = "\"version\": 1, \"version\": 1" },
        .{ .before = "WAMR_NATIVE_COMPUTE=", .after = "echo WAMR_NATIVE_COMPUTE=" },
        .{ .before = "WAMR_NATIVE_AOT_OK answer=42 teardown=0\n", .after = "" },
    }) |m| {
        const bad = try replaceOnce(a, tiny_raw, m.before, m.after);
        try writePrivate(io, log, bad);
        try refused(a, io, binary, tiny_cmd, null);
    }

    for ([_][]const u8{
        tiny_raw ++ aot_ok_line,
        tiny_raw ++ compute_line,
        try replaceOnce(a, tiny_raw, "Calling main(0, 0)\n", ""),
        tiny_raw ++ "HYPERV_ACCEPTANCE NETWORK_APP_FINAL PASS\n",
        tiny_raw ++ "WAMR_NATIVE_WASI={}\n",
        tiny_raw ++ "\x1b[0\x00m\n",
    }) |bad| {
        try writePrivate(io, log, bad);
        try refused(a, io, binary, tiny_cmd, null);
    }

    try writePrivate(io, log, tiny_raw);
    const bad_identity = try replaceOnce(a, tiny_identity_json, "\"minimal_wasi\": false", "\"minimal_wasi\": true");
    try writePrivate(io, identity, bad_identity);
    try refused(a, io, binary, tiny_cmd, null);
    try writePrivate(io, identity, tiny_identity_json);

    try writePrivate(io, log, coremark_wasi_raw);
    try writePrivate(io, identity, full_wasi_identity_json);
    try accepted(a, io, binary, tiny_cmd, coremark_wasi_raw, identity, log, "tiny", true);
    for ([_]Mutation{
        .{ .before = "\"crc_ok\": true", .after = "\"crc_ok\": false" },
        .{ .before = "\"realtime_supported\": true", .after = "\"realtime_supported\": false" },
        .{ .before = "\"stdout_base64\": \"", .after = "\"stdout_base64\": \"@@" },
        .{ .before = "\"output_error\": 0", .after = "\"output_error\": 1" },
        .{ .before = "\"terminal\": 2", .after = "\"terminal\": 1" },
    }) |m| {
        const changed = try replaceOnce(a, coremark_wasi_raw, m.before, m.after);
        try writePrivate(io, log, changed);
        try refused(a, io, binary, tiny_cmd, null);
    }

    const ModeFixture = struct {
        mode: []const u8,
        log_bytes: []const u8,
        id_bytes: []const u8,
    };
    for ([_]ModeFixture{
        .{
            .mode = "snapshot",
            .log_bytes = @embedFile("optional-fixtures/snapshot.log"),
            .id_bytes = @embedFile("optional-fixtures/snapshot.identity.json"),
        },
        .{
            .mode = "aot",
            .log_bytes = @embedFile("optional-fixtures/aot.log"),
            .id_bytes = @embedFile("optional-fixtures/aot.identity.json"),
        },
        .{
            .mode = "fast",
            .log_bytes = @embedFile("optional-fixtures/fast.log"),
            .id_bytes = @embedFile("optional-fixtures/fast.identity.json"),
        },
        .{
            .mode = "full",
            .log_bytes = @embedFile("optional-fixtures/full.log"),
            .id_bytes = @embedFile("optional-fixtures/full.identity.json"),
        },
    }) |f| {
        try writePrivate(io, log, f.log_bytes);
        try writePrivate(io, identity, f.id_bytes);
        const cmd: []const []const u8 = &.{ "workload", "--mode", f.mode, "--log", log, "--identity", identity };
        try accepted(a, io, binary, cmd, f.log_bytes, identity, log, f.mode, false);
        const w_human = try invoke(a, io, binary, cmd);
        if (w_human.code != 0 or w_human.stderr.len != 0 or
            !std.mem.eql(u8, w_human.stdout, "Optional workload correctness records valid; no boot or measurement qualification.\n"))
            return error.WorkloadHumanValidationFailed;

        const w_framed = try replaceAll(a, f.log_bytes, "\n", "\x1b[0m\r\n\x00");
        try writePrivate(io, log, w_framed);
        try accepted(a, io, binary, cmd, w_framed, identity, log, f.mode, false);
        try writePrivate(io, log, f.log_bytes);

        if (std.mem.eql(u8, f.mode, "aot")) {
            const missing_mode = try replaceOnce(a, f.id_bytes, ", \"jit_mode\": null", "");
            try writePrivate(io, identity, missing_mode);
            try refused(a, io, binary, cmd, "record");
            try writePrivate(io, identity, f.id_bytes);
        }

        const corrupt = try replaceOnce(a, f.log_bytes, "\"correctness_only\": true", "\"correctness_only\": false");
        try writePrivate(io, log, corrupt);
        try refused(a, io, binary, cmd, null);

        const doubled = try std.fmt.allocPrint(a, "{s}{s}", .{ f.log_bytes, f.log_bytes });
        const with_bench = try std.fmt.allocPrint(a, "{s}WAMR_BENCH_RESULT={{}}\n", .{f.log_bytes});
        const with_ff = try std.fmt.allocPrint(a, "{s}\xff\n", .{f.log_bytes});
        const with_crash = try std.fmt.allocPrint(a, "{s}Unikraft Crash\n", .{f.log_bytes});
        for ([_][]const u8{ doubled, with_bench, with_ff, with_crash }) |bad| {
            try writePrivate(io, log, bad);
            try refused(a, io, binary, cmd, null);
        }

        try writePrivate(io, log, f.log_bytes[0 .. f.log_bytes.len - 1]);
        try refused(a, io, binary, cmd, null);
    }

    try writePrivate(io, log, tiny_raw);
    try writePrivate(io, identity, tiny_identity_json);

    for ([_][]const []const u8{
        &.{},
        &.{"other"},
        &.{ "tiny", "--log", log },
        &.{ "tiny", "--log", log, "--identity", identity, "--log", log },
        &.{ "tiny", "--log", log, "--identity", identity, "--mode", "snapshot" },
        &.{ "tiny", "--log", log, "--identity", identity, "--legacy-apic", "ignored" },
        &.{ "tiny", "--log", log, "--identity", identity, "--output", "invalid" },
        &.{ "tiny", "--log", log, "--identity", identity, "--output", "json-v1", "--output", "json-v1" },
        &.{ "workload", "--mode", "wrong", "--log", log, "--identity", identity },
        &.{ "workload", "--log", log, "--identity", identity },
    }) |u_args| {
        try usage(a, io, binary, u_args);
    }

    const outside = try std.fs.path.join(a, &.{ root, "outside" });
    try writePrivate(io, outside, tiny_raw);
    try std.Io.Dir.cwd().deleteFile(io, log);
    try symlinkPath(a, outside, log);
    try refused(a, io, binary, tiny_cmd, "input-snapshot");
    try std.Io.Dir.cwd().deleteFile(io, log);
    try writePrivate(io, log, tiny_raw);
    try chmodPath(a, log, 0o622);
    try refused(a, io, binary, tiny_cmd, "input-snapshot");
    try chmodPath(a, log, 0o600);

    try std.Io.Dir.cwd().deleteFile(io, identity);
    try symlinkPath(a, outside, identity);
    try refused(a, io, binary, tiny_cmd, "input-snapshot");
    try std.Io.Dir.cwd().deleteFile(io, identity);
    try writePrivate(io, identity, "{\"minimal_wasi\":false,\"minimal_wasi\":false}");
    try refused(a, io, binary, tiny_cmd, null);
    try writePrivate(io, identity, tiny_identity_json);

    const four_mib = try a.alloc(u8, 4 * 1024 * 1024);
    @memset(four_mib, 'x');
    try writePrivate(io, log, four_mib);
    try refused(a, io, binary, tiny_cmd, "input-bound");

    var stdout_buf: [256]u8 = undefined;
    var stdout = std.Io.File.stdout().writerStreaming(io, &stdout_buf);
    try stdout.interface.writeAll(
        "installed native validator CLI: tiny, four workload modes, refusal and raw hash fixtures\n",
    );
    try stdout.interface.flush();
}
