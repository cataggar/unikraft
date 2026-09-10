// SPDX-License-Identifier: BSD-3-Clause

const std = @import("std");
pub const process = @import("hyperv_process");
pub const output_limit = 4 * 1024 * 1024;

pub const Tools = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    environment: *const std.process.Environ.Map,
    deadline: process.Deadline,

    pub fn init(allocator: std.mem.Allocator, io: std.Io, environment: *const std.process.Environ.Map, milliseconds: u32) !Tools {
        try process.initialize();
        return .{ .allocator = allocator, .io = io, .environment = environment, .deadline = try process.Deadline.afterMilliseconds(milliseconds) };
    }

    pub fn run(self: Tools, argv: []const []const u8) !process.Result {
        if (argv.len == 0) return error.InvalidTool;
        const executable = try self.resolve(argv[0]);
        defer self.allocator.free(executable);
        const command = try self.allocator.dupe([]const u8, argv);
        defer self.allocator.free(command);
        command[0] = executable;
        var empty = std.process.Environ.Map.init(self.allocator);
        defer empty.deinit();
        var result = try process.run(self.allocator, self.io, .{
            .argv = command,
            .cwd = .cwd(),
            .environment = &empty,
            .deadline = self.deadline,
            .stdout_limit = output_limit,
            .stderr_limit = 64 * 1024,
        });
        errdefer result.deinit(self.allocator);
        try checkResult(result);
        return result;
    }

    pub fn resolve(self: Tools, command: []const u8) ![]u8 {
        if (command.len == 0 or command.len > 4096 or std.mem.indexOfScalar(u8, command, 0) != null)
            return error.InvalidTool;
        if (std.mem.indexOfScalar(u8, command, '/') != null) {
            const stat = try std.Io.Dir.cwd().statFile(self.io, command, .{});
            if (stat.kind != .file or stat.permissions.toMode() & 0o111 == 0) return error.InvalidTool;
            return self.absolute(command);
        }
        const path = self.environment.get("PATH") orelse return error.ToolNotFound;
        if (path.len > 64 * 1024) return error.InvalidTool;
        var entries = std.mem.splitScalar(u8, path, ':');
        var count: usize = 0;
        while (entries.next()) |entry| {
            count += 1;
            if (count > 256) return error.InvalidTool;
            const candidate = try std.fs.path.join(self.allocator, &.{ if (entry.len == 0) "." else entry, command });
            defer self.allocator.free(candidate);
            const stat = std.Io.Dir.cwd().statFile(self.io, candidate, .{}) catch |err| switch (err) {
                error.FileNotFound, error.NotDir => continue,
                else => return err,
            };

            if (stat.kind != .file or stat.permissions.toMode() & 0o111 == 0) continue;
            return self.absolute(candidate);
        }
        return error.ToolNotFound;
    }

    fn absolute(self: Tools, path: []const u8) ![]u8 {
        if (std.fs.path.isAbsolute(path)) return self.allocator.dupe(u8, path);
        const cwd = try std.Io.Dir.cwd().realPathFileAlloc(self.io, ".", self.allocator);
        defer self.allocator.free(cwd);
        // Preserve argv[0]'s basename: llvm-readelf is a multicall symlink.
        return std.fs.path.join(self.allocator, &.{ cwd, path });
    }
};

pub fn checkResult(result: process.Result) !void {
    if (!result.cleanup_complete or result.failures.cleanup != null) return error.ToolCleanupFailed;
    if (result.failures.primary) |failure| return switch (failure.category) {
        .output_limit => error.ToolOutputLimit,
        .timeout => error.ToolTimeout,
        else => error.ToolFailed,
    };
}
