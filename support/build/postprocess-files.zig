// SPDX-License-Identifier: BSD-3-Clause

//! Check every destination before mutation, work in private staging directories,
//! and publish without following destination symlinks. Cleanup owns only staging.
const std = @import("std");
const builtin = @import("builtin");

const Identity = struct {
    device: u64,
    inode: u64,

    fn eql(a: Identity, b: Identity) bool {
        return a.device == b.device and a.inode == b.inode;
    }
};

const Source = struct {
    path: []const u8,
    file: std.Io.File,
    identity: Identity,
};

const Output = struct {
    parent: std.Io.Dir,
    parent_identity: Identity,
    basename: []const u8,
    stage: ?std.Io.Dir = null,
    stage_name: ?[]const u8 = null,
    stage_path: ?[]const u8 = null,

    fn deinit(self: *Output, allocator: std.mem.Allocator, io: std.Io) void {
        if (self.stage) |stage| {
            stage.deleteFile(io, "output") catch |err| cleanupError(err);
            stage.close(io);
        }
        if (self.stage_name) |name| {
            self.parent.deleteDir(io, name) catch |err| cleanupError(err);
            allocator.free(name);
        }
        if (self.stage_path) |path| allocator.free(path);
        self.parent.close(io);
    }

    fn existingIdentity(self: Output, io: std.Io) !?Identity {
        const stat = self.parent.statFile(io, self.basename, .{ .follow_symlinks = false }) catch |err| switch (err) {
            error.FileNotFound => return null,
            else => return err,
        };
        if (stat.kind == .sym_link) return error.OutputSymlink;
        if (stat.kind != .file) return error.InvalidOutputFile;
        const file = try self.parent.openFile(io, self.basename, .{
            .follow_symlinks = false,
            .path_only = true,
        });
        defer file.close(io);
        return try regularIdentity(file, io);
    }

    fn prepare(self: *Output, allocator: std.mem.Allocator, io: std.Io) !void {
        while (true) {
            var random: [16]u8 = undefined;
            try io.randomSecure(&random);
            const name = try std.fmt.allocPrint(allocator, ".native-postprocess-{x}", .{random});
            self.parent.createDir(io, name, .fromMode(0o700)) catch |err| {
                allocator.free(name);
                if (err == error.PathAlreadyExists) continue;
                return err;
            };
            self.stage_name = name;
            self.stage = try self.parent.openDir(io, name, .{ .follow_symlinks = false });
            var buffer: [std.fs.max_path_bytes]u8 = undefined;
            const length = try self.stage.?.realPath(io, &buffer);
            self.stage_path = try std.fs.path.join(allocator, &.{ buffer[0..length], "output" });
            return;
        }
    }
};

pub const Files = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    sources: std.ArrayList(Source) = .empty,
    source_identities: std.ArrayList(Identity) = .empty,
    outputs: std.ArrayList(Output) = .empty,

    pub fn init(
        allocator: std.mem.Allocator,
        io: std.Io,
        inputs: []const []const u8,
        outputs: []const []const u8,
    ) !Files {
        var self: Files = .{ .allocator = allocator, .io = io };
        errdefer self.deinit();
        for (inputs) |input_path| {
            if (input_path.len == 0) return error.InvalidArguments;
            const file = try std.Io.Dir.cwd().openFile(io, input_path, .{});
            errdefer file.close(io);
            const id = try regularIdentity(file, io);
            try self.source_identities.append(allocator, id);
            try self.sources.append(allocator, .{ .path = input_path, .file = file, .identity = id });
        }
        for (outputs) |output_path| {
            const basename = std.fs.path.basename(output_path);
            if (basename.len == 0 or std.mem.eql(u8, basename, ".") or std.mem.eql(u8, basename, ".."))
                return error.InvalidArguments;
            const parent = try std.Io.Dir.cwd().openDir(io, std.fs.path.dirname(output_path) orelse ".", .{});
            errdefer parent.close(io);
            try self.outputs.append(allocator, .{
                .parent = parent,
                .parent_identity = try identity(.{ .handle = parent.handle, .flags = .{ .nonblocking = false } }),
                .basename = basename,
            });
        }
        try self.checkOutputs();
        for (self.outputs.items) |*output| try output.prepare(allocator, io);
        return self;
    }

    pub fn deinit(self: *Files) void {
        for (self.outputs.items) |*output| output.deinit(self.allocator, self.io);
        self.outputs.deinit(self.allocator);
        for (self.sources.items) |source| source.file.close(self.io);
        self.sources.deinit(self.allocator);
        self.source_identities.deinit(self.allocator);
    }

    pub fn readInput(self: Files, index: usize) ![]u8 {
        var reader = self.sources.items[index].file.reader(self.io, &.{});
        return reader.interface.allocRemaining(self.allocator, .limited(1024 * 1024 * 1024)) catch |err| switch (err) {
            error.ReadFailed => return reader.err.?,
            else => return err,
        };
    }

    /// Compilation database fragments are inputs too, not just its ELF dependency.
    pub fn addInput(self: *Files, file: std.Io.File) !void {
        const id = try regularIdentity(file, self.io);
        for (self.outputs.items) |output| {
            if (try output.existingIdentity(self.io)) |existing| {
                if (existing.eql(id)) return error.InPlaceMutation;
            }
        }
        try self.source_identities.append(self.allocator, id);
    }

    pub fn path(self: Files, index: usize) []const u8 {
        return self.outputs.items[index].stage_path.?;
    }

    pub fn write(self: Files, index: usize, bytes: []const u8) !void {
        const file = try self.outputs.items[index].stage.?.createFile(self.io, "output", .{ .exclusive = true });
        defer file.close(self.io);
        try file.writePositionalAll(self.io, bytes, 0);
    }

    pub fn commit(self: Files) !void {
        for (self.sources.items) |source| {
            const current = try std.Io.Dir.cwd().openFile(self.io, source.path, .{ .path_only = true });
            defer current.close(self.io);
            if (!(try regularIdentity(current, self.io)).eql(source.identity)) return error.InputChanged;
        }
        try self.checkOutputs();
        // Validate the entire set before publishing any member of a multi-output
        // operation. No error path ever unlinks a requested destination.
        for (self.outputs.items) |output| {
            const file = try output.stage.?.openFile(self.io, "output", .{ .follow_symlinks = false, .path_only = true });
            defer file.close(self.io);
            const id = try regularIdentity(file, self.io);
            for (self.source_identities.items) |source| {
                if (source.eql(id)) return error.InPlaceMutation;
            }
        }
        for (self.outputs.items) |output|
            try output.stage.?.rename("output", output.parent, output.basename, self.io);
    }

    fn checkOutputs(self: Files) !void {
        for (self.outputs.items, 0..) |output, index| {
            const existing = try output.existingIdentity(self.io);
            if (existing) |id| {
                for (self.source_identities.items) |source| {
                    if (id.eql(source)) return error.InPlaceMutation;
                }
            }
            for (self.outputs.items[0..index]) |previous| {
                if (output.parent_identity.eql(previous.parent_identity) and
                    std.mem.eql(u8, output.basename, previous.basename))
                    return error.AliasedOutputs;
                if (existing) |id| {
                    if (try previous.existingIdentity(self.io)) |previous_id| {
                        if (id.eql(previous_id)) return error.AliasedOutputs;
                    }
                }
            }
        }
    }
};

fn regularIdentity(file: std.Io.File, io: std.Io) !Identity {
    if ((try file.stat(io)).kind != .file) return error.NotRegularFile;
    return identity(file);
}

// std.Io.File.Stat omits the filesystem device. Use the facade's statx/fstat
// approach so equal inode numbers on different devices are not false aliases.
fn identity(file: std.Io.File) !Identity {
    if (comptime builtin.os.tag == .linux) {
        var stat: std.os.linux.Statx = undefined;
        while (true) {
            switch (std.os.linux.errno(std.os.linux.statx(file.handle, "", std.os.linux.AT.EMPTY_PATH, .BASIC_STATS, &stat))) {
                .SUCCESS => {
                    if (!stat.mask.INO) return error.IncompleteMetadata;
                    return .{ .device = (@as(u64, stat.dev_major) << 32) | stat.dev_minor, .inode = stat.ino };
                },
                .INTR => continue,
                else => |err| return std.posix.unexpectedErrno(err),
            }
        }
    } else if (comptime builtin.os.tag == .windows or builtin.os.tag == .wasi) {
        return error.UnsupportedFileIdentity;
    } else {
        var stat = std.mem.zeroes(std.posix.Stat);
        while (true) {
            switch (std.posix.errno(std.posix.system.fstat(file.handle, &stat))) {
                .SUCCESS => return .{ .device = @intCast(stat.dev), .inode = @intCast(stat.ino) },
                .INTR => continue,
                else => |err| return std.posix.unexpectedErrno(err),
            }
        }
    }
}

fn cleanupError(err: anyerror) void {
    if (err == error.FileNotFound) return;
    std.debug.print("error: unable to clean native post-processing staging: {s}\n", .{@errorName(err)});
}

test "file identity includes the device as well as the inode" {
    const original = Identity{ .device = 1, .inode = 42 };
    try std.testing.expect(original.eql(.{ .device = 1, .inode = 42 }));
    try std.testing.expect(!original.eql(.{ .device = 2, .inode = 42 }));
    try std.testing.expect(!original.eql(.{ .device = 1, .inode = 43 }));
}
