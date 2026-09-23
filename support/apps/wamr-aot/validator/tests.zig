// SPDX-License-Identifier: BSD-3-Clause
const std = @import("std");
const linux = std.os.linux;
const validator = @import("wamr_log_validator");
const t = std.testing;
const a = t.allocator;
const io = t.io;

fn normalized(raw: []const u8, mode: validator.serial.Normalization) ![]u8 {
    return validator.serial.normalizeWithOptions(a, raw, mode);
}

test "WAMR normalization preserves the local-boot contract and raw framing order" {
    const raw = "\x00\x1b[1;32mWAMR_NATIVE_COMPUTE={}\x1b[0m\r\n\x00";
    const local = try validator.serial.normalize(a, raw);
    defer a.free(local);
    try t.expectEqualStrings("WAMR_NATIVE_COMPUTE={}\r\n", local);
    const tiny = try normalized(raw, .tiny);
    defer a.free(tiny);
    try t.expectEqualStrings("WAMR_NATIVE_COMPUTE={}\n", tiny);
    const optional = try normalized(raw, .optional);
    defer a.free(optional);
    try t.expectEqualStrings("WAMR_NATIVE_COMPUTE={}\n", optional);
    try t.expectEqualStrings("\x00\x1b[1;32mWAMR_NATIVE_COMPUTE={}\x1b[0m\r\n\x00", raw);
    const across_escape = try normalized("text\r\x1b[0m\n", .optional);
    defer a.free(across_escape);
    try t.expectEqualStrings("text\n", across_escape);
    const standalone = try normalized("text\r", .tiny);
    defer a.free(standalone);
    try t.expectEqualStrings("text\r", standalone);
    try t.expectError(error.InvalidSerial, normalized("text\r", .optional));
}

test "the existing local boot terminal and milestone grammar is unchanged" {
    const text = "Hyper-V Hv#1 hypercall page enabled\nHyper-V SynIC:\n" ++
        "Powered by\nCalling main(1, ['synthetic'])\nHello world!\n" ++
        "Info: [libukboot] main returned 0\n";
    try validator.serial.validateEnvelope(a, text, "Hello world!", 0, &.{}, &.{});
    const framed = try std.mem.replaceOwned(u8, a, text, "main returned 0", "\x1b[0m\x00main returned 0\r");
    defer a.free(framed);
    try validator.serial.validateEnvelope(a, framed, "Hello world!", 0, &.{}, &.{});
}

test "raw UTF-8 and CSI grammar refuse malformed bytes before they can be hidden" {
    for ([_][]const u8{
        "\xff",        "\xc2\x00\xa3",   "\xc0\xaf", "\xe2", "\x1b", "\x1b[",
        "\x1b[0\x00m", "\x1b]title\x07", "\x1b[0\n", "\x07", "\x0b", "\x0c",
    }) |bad| {
        try t.expectError(error.InvalidSerial, normalized(bad, .tiny));
        try t.expectError(error.InvalidSerial, normalized(bad, .optional));
    }
    for ([_][]const u8{
        "\x7f",         "\xc2\x85",         "\xe2\x80\xa8", "\xe2\x80\xa9",
        "\xe2\x80\x8b", "\xc2\xa0",         "\xcd\xb8",     "\xe3\x80\x80",
        "\xee\x80\x80", "\xf3\xa0\x80\x81",
    }) |bad| {
        try t.expectError(error.InvalidSerial, normalized(bad, .optional));
    }
    const allowed = try normalized("plain\tUTF-8 \xc3\xa9\n", .optional);
    defer a.free(allowed);
    try t.expectEqualStrings("plain\tUTF-8 \xc3\xa9\n", allowed);
    try t.expectError(error.SerialLineLimit, normalized("x" ** 8193 ++ "\n", .tiny));
    const exact = try normalized("x" ** 8192 ++ "\n", .tiny);
    defer a.free(exact);
    try t.expectEqual(@as(usize, 8193), exact.len);
}

test "optional pins Unicode 15 printable boundary without changing tiny or local boot" {
    for ([_][]const u8{
        "\u{0897}\n",  "\u{1b4e}\n",  "\u{1b4f}\n",
        "\u{10d40}\n", "\u{10d65}\n", "\u{11380}\n",
        "\u{13460}\n", "\u{143fa}\n", "\u{1cc00}\n",
        "\u{1ccf9}\n", "\u{1cd00}\n", "\u{1ceb3}\n",
        "\u{1fabe}\n", "\u{1fae9}\n", "\u{2ebf0}\n",
        "\u{2ee5d}\n",
    }) |new_in_16| {
        try t.expectError(error.InvalidSerial, normalized(new_in_16, .optional));
        for ([_]validator.serial.Normalization{ .tiny, .local_boot }) |mode| {
            const unchanged = try normalized(new_in_16, mode);
            defer a.free(unchanged);
            try t.expectEqualStrings(new_in_16, unchanged);
        }
    }
    for ([_][]const u8{
        "\u{00e9}\n",  "\u{1b7e}\n",  "\u{1f600}\n",
        "\u{1f8b1}\n", "\u{1fabd}\n", "\u{1fabf}\n",
    }) |printable_in_15| {
        const accepted = try normalized(printable_in_15, .optional);
        defer a.free(accepted);
        try t.expectEqualStrings(printable_in_15, accepted);
    }
}

test "mode-specific raw bounds and deterministic one-byte mutation refusals" {
    try t.expectError(error.SerialLimit, normalized("", .local_boot));
    try t.expectError(error.SerialLimit, normalized("x\n" ** (2 * 1024 * 1024), .tiny));
    try t.expectError(error.SerialLimit, normalized("x\n" ** (1024 * 1024) ++ "x", .optional));
    const boundary = try normalized("x\n" ** (1024 * 1024), .optional);
    defer a.free(boundary);
    try t.expectEqual(@as(usize, 2 * 1024 * 1024), boundary.len);
    const small = "WAMR_JIT_SAMPLE={}\n";
    for (0..small.len) |at| {
        var mutated = small.*;
        mutated[at] = 0x1b;
        try t.expectError(error.InvalidSerial, normalized(&mutated, .optional));
    }
}

test "canonical bounded base64 accepts only standard padded byte-for-byte spelling" {
    for ([_][]const u8{ "", "Zg==", "Zm8=", "Zm9v", "AP8=", "AAECAwQ=" }) |source| {
        const decoded = try validator.base64.decode(a, source, 8);
        defer a.free(decoded);
        const encoded = try a.alloc(u8, std.base64.standard.Encoder.calcSize(decoded.len));
        defer a.free(encoded);
        try t.expectEqualStrings(source, std.base64.standard.Encoder.encode(encoded, decoded));
    }
    for ([_][]const u8{ "Zg", "Zg=", "Zg==\n", "Zh==", "_/8=", "Zg== ", "Zm9v=", "====" }) |source|
        try t.expectError(error.InvalidBase64, validator.base64.decode(a, source, 8));
    try t.expectError(error.Base64Limit, validator.base64.decode(a, "Zm9v", 2));
    try t.expectError(error.Base64Limit, validator.base64.decode(a, "AAECAwQ=", 4));
    for (0..256) |index| {
        var candidate = [4]u8{ 'Z', 'g', '=', '=' };
        candidate[1] = @intCast(index);
        if (validator.base64.decode(a, &candidate, 1)) |decoded| {
            defer a.free(decoded);
            try t.expectEqual(@as(usize, 1), decoded.len);
            var canonical: [4]u8 = undefined;
            try t.expectEqualStrings(&candidate, std.base64.standard.Encoder.encode(&canonical, decoded));
        } else |_| {}
    }
}

fn write(dir: std.Io.Dir, name: []const u8, contents: []const u8) !void {
    const file = try dir.createFile(io, name, .{ .permissions = .fromMode(0o600) });
    defer file.close(io);
    try file.writePositionalAll(io, contents, 0);
}

fn changeContents(_: std.Io, path: []const u8) !void {
    const file = try std.Io.Dir.cwd().createFile(io, path, .{ .permissions = .fromMode(0o600) });
    defer file.close(io);
    try file.writePositionalAll(io, "DIFFERENT", 0);
}

fn truncateContents(_: std.Io, path: []const u8) !void {
    const file = try std.Io.Dir.cwd().createFile(io, path, .{ .permissions = .fromMode(0o600) });
    file.close(io);
}

fn replaceName(_: std.Io, path: []const u8) !void {
    const replacement = try std.fmt.allocPrint(a, "{s}.replacement", .{path});
    defer a.free(replacement);
    try std.Io.Dir.cwd().rename(replacement, std.Io.Dir.cwd(), path, io);
}

fn read(path: []const u8, kind: validator.input.Kind) !validator.input.Input {
    return validator.input.read(a, io, path, kind);
}

test "relative and absolute regular input retains original bytes/hash and never rewrites" {
    var fixture = t.tmpDir(.{});
    defer fixture.cleanup();
    const raw = "\x00\x1b[32mrecord\x1b[0m\r\n";
    try write(fixture.dir, "serial.log", raw);
    const relative = try std.fmt.allocPrint(a, ".zig-cache/tmp/{s}/serial.log", .{fixture.sub_path});
    defer a.free(relative);
    const absolute = try fixture.dir.realPathFileAlloc(io, "serial.log", a);
    defer a.free(absolute);
    var expected: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(raw, &expected, .{});
    for ([_][]const u8{ relative, absolute }) |name| {
        var input = try read(name, .tiny_serial);
        defer input.deinit();
        try t.expectEqualStrings(raw, input.bytes);
        try t.expectEqualSlices(u8, &expected, &input.sha256);
        const text = try normalized(input.bytes, .tiny);
        defer a.free(text);
        try t.expectEqualStrings("record\n", text);
    }
    const actual = try fixture.dir.readFileAlloc(io, "serial.log", a, .limited(1024));
    defer a.free(actual);
    try t.expectEqualStrings(raw, actual);
}

test "input kind limits, symlinks, writable/nonregular entries and invalid paths refuse" {
    var fixture = t.tmpDir(.{});
    defer fixture.cleanup();
    try write(fixture.dir, "small", "v");
    try fixture.dir.symLink(io, "small", "alias", .{});
    try fixture.dir.symLink(io, "missing", "dangling", .{});
    try fixture.dir.createDir(io, "directory", .fromMode(0o700));
    try t.expectEqual(.SUCCESS, linux.errno(linux.mknodat(fixture.dir.handle, "fifo", linux.S.IFIFO | 0o600, 0)));
    const base = try fixture.dir.realPathFileAlloc(io, ".", a);
    defer a.free(base);
    for ([_][]const u8{ "alias", "dangling", "directory", "fifo" }) |name| {
        const path = try std.fs.path.join(a, &.{ base, name });
        defer a.free(path);
        if (read(path, .tiny_serial)) |accepted| {
            var unexpected = accepted;
            unexpected.deinit();
            return error.UnsafeInputAccepted;
        } else |_| {}
    }
    const file = try fixture.dir.openFile(io, "small", .{ .mode = .write_only });
    try file.setPermissions(io, .fromMode(0o622));
    file.close(io);
    const small = try std.fs.path.join(a, &.{ base, "small" });
    defer a.free(small);
    try t.expectError(error.UnsafeFile, read(small, .tiny_serial));
    try t.expectError(error.UnsafePath, read("", .identity));
    try t.expectError(error.UnsafePath, read("invalid\x00name", .identity));
    try t.expectError(error.UnsafePath, read("a" ** 4096, .identity));
    try write(fixture.dir, "empty", "");
    const empty = try std.fs.path.join(a, &.{ base, "empty" });
    defer a.free(empty);
    try t.expectError(error.InputLimit, read(empty, .identity));
    try write(fixture.dir, "identity", "v" ** (64 * 1024));
    const identity = try std.fs.path.join(a, &.{ base, "identity" });
    defer a.free(identity);
    var accepted = try read(identity, .identity);
    accepted.deinit();
    try write(fixture.dir, "oversized", "v" ** (64 * 1024 + 1));
    const oversized = try std.fs.path.join(a, &.{ base, "oversized" });
    defer a.free(oversized);
    try t.expectError(error.InputLimit, read(oversized, .identity));
    try write(fixture.dir, "optional", "v" ** (2 * 1024 * 1024));
    const optional = try std.fs.path.join(a, &.{ base, "optional" });
    defer a.free(optional);
    var exact = try read(optional, .optional_serial);
    exact.deinit();
    try t.expectError(error.InputLimit, read(optional, .identity));
    try write(fixture.dir, "tiny-bound", "v" ** (4 * 1024 * 1024 - 1));
    const tiny_bound = try std.fs.path.join(a, &.{ base, "tiny-bound" });
    defer a.free(tiny_bound);
    var last = try read(tiny_bound, .tiny_serial);
    last.deinit();
    try write(fixture.dir, "tiny-over", "v" ** (4 * 1024 * 1024));
    const tiny_over = try std.fs.path.join(a, &.{ base, "tiny-over" });
    defer a.free(tiny_over);
    try t.expectError(error.InputLimit, read(tiny_over, .tiny_serial));
}

test "injected before/open/read/close mutations never produce an accepted snapshot" {
    for ([_]validator.input.Stage{ .before_open, .after_open, .after_read, .after_close }) |stage| {
        var fixture = t.tmpDir(.{});
        defer fixture.cleanup();
        try write(fixture.dir, "selected", "original");
        try write(fixture.dir, "selected.replacement", "replacement");
        const selected = try fixture.dir.realPathFileAlloc(io, "selected", a);
        defer a.free(selected);
        const hook: validator.input.Fault = .{
            .stage = stage,
            .action = if (stage == .before_open or stage == .after_close) replaceName else changeContents,
        };
        try t.expectError(error.FileChanged, validator.input.readFault(a, io, selected, .tiny_serial, hook));
    }
    var fixture = t.tmpDir(.{});
    defer fixture.cleanup();
    try write(fixture.dir, "short", "original");
    const short = try fixture.dir.realPathFileAlloc(io, "short", a);
    defer a.free(short);
    try t.expectError(error.FileChanged, validator.input.readFault(a, io, short, .tiny_serial, .{
        .stage = .after_open,
        .action = truncateContents,
    }));
}
