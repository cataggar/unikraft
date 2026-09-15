// SPDX-License-Identifier: BSD-3-Clause
//! Offline fixture plumbing only. No production controller imports this module.
const std = @import("std");
pub const files = @import("hyperv_core").private_files;
pub const marker = "direct-two-boot-offline-only\n";
pub const sentinel = "PRIVATE_FIXTURE_SAS";
pub const owner = "aaaaaaaa-aaaa-4aaa-aaaa-aaaaaaaaaaaa";
pub const subscription = "bbbbbbbb-bbbb-4bbb-bbbb-bbbbbbbbbbbb";
pub const prefix = "fixture-direct";
pub const group_id = "/subscriptions/" ++ subscription ++ "/resourceGroups/" ++ prefix ++ "-rg";
pub const vm_id = group_id ++ "/providers/Microsoft.Compute/virtualMachines/" ++ prefix ++ "-vm";
pub const os_id = group_id ++ "/providers/Microsoft.Compute/disks/" ++ prefix ++ "-os";
pub const data_id = group_id ++ "/providers/Microsoft.Compute/disks/" ++ prefix ++ "-data";
pub const nic_id = group_id ++ "/providers/Microsoft.Network/networkInterfaces/" ++ prefix ++ "-nic";
pub const image_sha = "a" ** 64;
pub const tags = .{ .@"managed-by" = "unikraft-hyperv", .@"uk-direct-run" = owner, .@"unikraft-run" = prefix, .@"image-sha256" = image_sha };

pub fn expect(ok: bool) !void {
    if (!ok) return error.FixtureAssertionFailed;
}
pub fn eq(a: []const u8, b: []const u8) bool {
    return std.mem.eql(u8, a, b);
}
pub fn oneOf(name: []const u8, names: []const []const u8) bool {
    for (names) |candidate| if (eq(name, candidate)) return true;
    return false;
}
pub fn starts(name: []const u8, pre: []const u8) bool {
    return std.mem.startsWith(u8, name, pre);
}
pub fn hash(bytes: []const u8) [64]u8 {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
    return std.fmt.bytesToHex(digest, .lower);
}
pub fn now(io: std.Io) i64 {
    return std.Io.Clock.real.now(io).toSeconds();
}
pub fn privateUmask() void {
    _ = std.os.linux.syscall1(.umask, 0o077);
}
pub fn json(a: std.mem.Allocator, value: anytype) ![]u8 {
    return std.json.Stringify.valueAlloc(a, value, .{});
}
pub fn parse(a: std.mem.Allocator, bytes: []const u8) !std.json.Value {
    return (try std.json.parseFromSlice(std.json.Value, a, bytes, .{ .allocate = .alloc_always })).value;
}
pub fn field(value: std.json.Value, name: []const u8) !std.json.Value {
    if (value != .object) return error.ExpectedObject;
    return value.object.get(name) orelse error.MissingField;
}
pub fn string(value: std.json.Value) ![]const u8 {
    if (value != .string) return error.ExpectedString;
    return value.string;
}
pub fn number(value: std.json.Value) !i64 {
    if (value != .integer) return error.ExpectedInteger;
    return value.integer;
}
pub fn boolean(value: std.json.Value) !bool {
    if (value != .bool) return error.ExpectedBoolean;
    return value.bool;
}
pub fn str(value: std.json.Value, name: []const u8) ![]const u8 {
    return string(try field(value, name));
}
pub fn num(value: std.json.Value, name: []const u8) !i64 {
    return number(try field(value, name));
}
pub fn yes(value: std.json.Value, name: []const u8) !bool {
    return boolean(try field(value, name));
}

pub const Context = struct {
    a: std.mem.Allocator,
    io: std.Io,
    root: []const u8,

    pub fn path(c: Context, relative: []const u8) ![]const u8 {
        const result = try std.fs.path.join(c.a, &.{ c.root, relative });
        try files.absoluteFilePath(result);
        try expect(starts(result, try std.mem.concat(c.a, u8, &.{ c.root, "/" })));
        return result;
    }
    pub fn read(c: Context, relative: []const u8) ![]const u8 {
        var data = try files.readSensitiveAbsolute(c.io, c.a, try c.path(relative), 16 * 1024 * 1024, null);
        defer data.deinit();
        return c.a.dupe(u8, data.bytes());
    }
    pub fn document(c: Context, relative: []const u8) !std.json.Value {
        return parse(c.a, try c.read(relative));
    }
    pub fn mkdir(c: Context, relative: []const u8) !void {
        const path_ = try c.path(relative);
        const parent = try files.Directory.open(c.io, std.fs.path.dirname(path_).?);
        defer parent.close(c.io);
        try parent.dir.createDir(c.io, std.fs.path.basename(path_), .fromMode(0o700));
    }
    pub fn create(c: Context, relative: []const u8) !std.Io.File {
        const path_ = try c.path(relative);
        const parent = try files.Directory.open(c.io, std.fs.path.dirname(path_).?);
        defer parent.close(c.io);
        return parent.dir.createFile(c.io, std.fs.path.basename(path_), .{ .exclusive = true, .permissions = .fromMode(0o600) });
    }
    pub fn write(c: Context, relative: []const u8, data: []const u8) !void {
        const file = try c.create(relative);
        defer file.close(c.io);
        try file.writeStreamingAll(c.io, data);
        try file.sync(c.io);
    }
    pub fn writeJson(c: Context, relative: []const u8, value: anytype) !void {
        try c.write(relative, try json(c.a, value));
    }
    pub fn append(c: Context, relative: []const u8, data: []const u8) !void {
        const path_ = try c.path(relative);
        const parent = try files.Directory.open(c.io, std.fs.path.dirname(path_).?);
        defer parent.close(c.io);
        const checked = try parent.openFile(c.io, std.fs.path.basename(path_));
        defer checked.close(c.io);
        const file = try parent.dir.openFile(c.io, std.fs.path.basename(path_), .{ .mode = .read_write, .follow_symlinks = false });
        defer file.close(c.io);
        try expect(files.sameSnapshot(try files.snapshot(checked), try files.snapshot(file)));
        try file.writePositionalAll(c.io, data, (try file.stat(c.io)).size);
        try file.sync(c.io);
    }
    pub fn replaceJson(c: Context, relative: []const u8, value: anytype) !void {
        const next = try std.mem.concat(c.a, u8, &.{ relative, ".next" });
        try c.writeJson(next, value);
        try std.Io.Dir.renameAbsolute(try c.path(next), try c.path(relative), c.io);
    }
    pub fn exists(c: Context, relative: []const u8) !bool {
        const path_ = try c.path(relative);
        _ = std.Io.Dir.cwd().statFile(c.io, path_, .{ .follow_symlinks = false }) catch |err| {
            if (err == error.FileNotFound) return false;
            return err;
        };
        return true;
    }
    pub fn log(c: Context, line: []const u8) !void {
        try c.append("calls", try std.mem.concat(c.a, u8, &.{ line, "\n" }));
    }
    pub fn timestamp(c: Context, relative: []const u8) !void {
        // The reference may enter cleanup twice only in separate failed runs.
        if (!try c.exists(relative)) try c.write(relative, try std.fmt.allocPrint(c.a, "{d}\n", .{now(c.io)}));
    }
    pub fn digest(c: Context, relative: []const u8) ![64]u8 {
        return hash(try c.read(relative));
    }
    pub fn validate(c: Context) !void {
        try files.absoluteFilePath(c.root);
        try expect(std.mem.indexOf(u8, c.root, "/.d/") != null);
        const dir = try files.Directory.open(c.io, c.root);
        defer dir.close(c.io);
        try expect(eq(try c.read("ISOLATED_OFFLINE_FIXTURE"), marker));
    }
    pub fn confined(c: Context, path_: []const u8) !void {
        try files.absoluteFilePath(path_);
        try expect(starts(path_, try std.mem.concat(c.a, u8, &.{ c.root, "/" })));
    }
};

pub fn serialLog(comptime boot: u8) []const u8 {
    return "UK_HYPERV_PLATFORM_READY\n" ++
        "HYPERV_PERSISTENCE START PASS run=11111111111111111111111111111111 address=0:0:7 sectors=8388608 sector_size=512\n" ++
        "HYPERV_PERSISTENCE SELECT PASS id=1 controller=1 state=" ++ (if (boot == 1) "0" else "2") ++ "\n" ++
        "UK_HYPERV_PERSISTENCE_IDENTITY:1:2:11111111111111111111111111111111:22222222222222222222222222222222:33333333333333333333333333333333:0:0:7:8388608:512:16:1:3:0:44444444444444444444444444444444\n" ++
        "HYPERV_PERSISTENCE " ++ (if (boot == 1) "BOOT1_WRITE" else "BOOT2_READ") ++ " PASS run=11111111111111111111111111111111\n" ++
        "UK_HYPERV_PERSISTENCE_IO:1:" ++ (if (boot == 1) "1:11111111111111111111111111111111:5:3:" else "2:11111111111111111111111111111111:0:0:") ++ "receipt-verified\n" ++
        "UK_HYPERV_PERSISTENCE_BOOT" ++ (if (boot == 1) "1" else "2") ++ "_COMPLETE:11111111111111111111111111111111\n" ++
        "HYPERV_PERSISTENCE FINAL PASS rc=0\nmain returned 0\n";
}
