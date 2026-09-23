// SPDX-License-Identifier: BSD-3-Clause
const std = @import("std");
const linux = std.os.linux;
const core = @import("hyperv_core");
const paths = @import("facade_paths");

pub const Deadline = core.process.Deadline;
pub const CommandResult = core.process.CommandResult;
pub const CommandPrimary = core.process.CommandPrimary;
pub const CommandCleanup = core.process.CommandCleanup;
pub const maximum_diagnostic_bytes = 8 * 1024 * 1024;

pub const Tool = struct {
    name: []const u8,
    path: []u8,
    executable: core.process.Executable,

    pub fn close(self: *Tool, allocator: std.mem.Allocator, io: std.Io) void {
        self.executable.close(io);
        allocator.free(self.path);
        self.* = undefined;
    }
};

pub fn resolveTool(
    allocator: std.mem.Allocator,
    io: std.Io,
    environment: *const std.process.Environ.Map,
    name: []const u8,
) !Tool {
    try toolName(name);
    const variable = try variableName(allocator, name);
    defer allocator.free(variable);
    if (environment.get(variable)) |explicit|
        return validateExplicit(allocator, io, name, explicit);
    return searchPath(allocator, io, environment.get("PATH"), name);
}

pub fn openTool(
    allocator: std.mem.Allocator,
    io: std.Io,
    name: []const u8,
    path: []const u8,
) !Tool {
    try toolName(name);
    if (!std.fs.path.isAbsolute(path)) return error.InvalidToolOverride;
    const canonical = paths.canonicalizeNearestExisting(allocator, io, path) catch
        return error.InvalidToolOverride;
    defer allocator.free(canonical.path);
    if (!canonical.exists or !std.mem.eql(u8, path, canonical.path))
        return error.InvalidToolOverride;
    return openCanonical(allocator, io, name, canonical.path);
}

pub const RunOptions = struct {
    argv: []const []const u8,
    allow_named_argv0: bool = false,
    environment: *const std.process.Environ.Map,
    cwd: std.Io.Dir,
    primary_deadline: Deadline,
    cleanup_deadline: Deadline,
    stdout_file: ?std.Io.File = null,
    snapshot_executable: bool = true,
    stdout_bytes: usize = maximum_diagnostic_bytes,
    stderr_bytes: usize = maximum_diagnostic_bytes,
};

pub fn initialize() !void {
    try core.process.initialize();
}

pub fn run(
    allocator: std.mem.Allocator,
    io: std.Io,
    tool: Tool,
    options: RunOptions,
) !CommandResult {
    if (options.argv.len == 0) return error.InvalidArguments;
    return core.process.runCommand(allocator, io, .{
        .executable = tool.executable,
        .argv = options.argv,
        .allow_named_argv0 = options.allow_named_argv0,
        .environment = options.environment,
        .cwd = options.cwd,
        .primary_deadline = options.primary_deadline,
        .cleanup_deadline = options.cleanup_deadline,
        .stdout_file = options.stdout_file,
        .snapshot_executable = options.snapshot_executable,
        .limits = .{
            .stdout_bytes = options.stdout_bytes,
            .stderr_bytes = options.stderr_bytes,
        },
    });
}

pub fn requireSuccess(result: CommandResult) !void {
    if (!result.succeeded()) return error.ToolFailed;
}

fn validateExplicit(
    allocator: std.mem.Allocator,
    io: std.Io,
    name: []const u8,
    explicit: []const u8,
) !Tool {
    if (retainedDescriptorPath(explicit)) {
        const file = std.Io.Dir.openFileAbsolute(io, explicit, .{
            .mode = .read_only,
            .follow_symlinks = true,
        }) catch return error.InvalidToolOverride;
        defer file.close(io);
        const executable = core.process.Executable.fromFile(io, file) catch
            return error.InvalidToolOverride;
        errdefer executable.close(io);
        return .{
            .name = name,
            .path = try allocator.dupe(u8, explicit),
            .executable = executable,
        };
    }
    if (!std.fs.path.isAbsolute(explicit)) return error.InvalidToolOverride;
    const canonical = paths.canonicalizeNearestExisting(allocator, io, explicit) catch
        return error.InvalidToolOverride;
    defer allocator.free(canonical.path);
    if (!canonical.exists or !std.mem.eql(u8, explicit, canonical.path))
        return error.InvalidToolOverride;
    return openCanonical(allocator, io, name, canonical.path) catch
        return error.InvalidToolOverride;
}

fn searchPath(
    allocator: std.mem.Allocator,
    io: std.Io,
    configured_path: ?[]const u8,
    name: []const u8,
) !Tool {
    const search = configured_path orelse "/bin:/usr/bin";
    const cwd = try std.process.currentPathAlloc(io, allocator);
    defer allocator.free(cwd);
    var entries = std.mem.splitScalar(u8, search, ':');
    while (entries.next()) |entry| {
        const directory = if (entry.len == 0) cwd else entry;
        const candidate = std.fs.path.resolve(allocator, &.{ directory, name }) catch
            return error.ToolUnavailable;
        defer allocator.free(candidate);
        std.Io.Dir.accessAbsolute(io, candidate, .{ .execute = true }) catch continue;
        const stat = std.Io.Dir.cwd().statFile(io, candidate, .{ .follow_symlinks = true }) catch continue;
        if (stat.kind != .file) continue;
        const canonical = paths.canonicalizeNearestExisting(allocator, io, candidate) catch
            return error.ToolUnavailable;
        defer allocator.free(canonical.path);
        if (!canonical.exists) return error.ToolUnavailable;
        return openCanonical(allocator, io, name, canonical.path);
    }
    return error.ToolUnavailable;
}

fn openCanonical(
    allocator: std.mem.Allocator,
    io: std.Io,
    name: []const u8,
    path: []const u8,
) !Tool {
    std.Io.Dir.accessAbsolute(io, path, .{ .execute = true }) catch return error.ToolUnavailable;
    const owned_path = try allocator.dupe(u8, path);
    errdefer allocator.free(owned_path);
    const executable = try core.process.Executable.open(io, path);
    errdefer executable.close(io);
    return .{
        .name = name,
        .path = owned_path,
        .executable = executable,
    };
}

fn variableName(allocator: std.mem.Allocator, name: []const u8) ![]u8 {
    const result = try allocator.alloc(u8, "WAMR_CI_TOOL_".len + name.len);
    @memcpy(result[0.."WAMR_CI_TOOL_".len], "WAMR_CI_TOOL_");
    for (name, "WAMR_CI_TOOL_".len..) |byte, index|
        result[index] = if (byte == '-') '_' else std.ascii.toUpper(byte);
    return result;
}

fn toolName(name: []const u8) !void {
    if (name.len == 0 or name.len > 128) return error.InvalidToolName;
    for (name) |byte| if (!std.ascii.isAlphanumeric(byte) and byte != '-' and byte != '_')
        return error.InvalidToolName;
}

pub fn retainedDescriptorPath(path: []const u8) bool {
    if (!std.mem.startsWith(u8, path, "/proc/")) return false;
    var components = std.mem.splitScalar(u8, path["/proc/".len..], '/');
    const process = components.next() orelse return false;
    if (!std.mem.eql(u8, process, "self")) {
        if (process.len == 0) return false;
        for (process) |byte| if (!std.ascii.isDigit(byte)) return false;
    }
    if (!std.mem.eql(u8, components.next() orelse return false, "fd"))
        return false;
    const descriptor = components.next() orelse return false;
    if (descriptor.len == 0 or components.next() != null) return false;
    for (descriptor) |byte| if (!std.ascii.isDigit(byte)) return false;
    const value = std.fmt.parseInt(linux.fd_t, descriptor, 10) catch return false;
    return value >= 0;
}
