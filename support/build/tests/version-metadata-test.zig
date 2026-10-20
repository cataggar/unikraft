const std = @import("std");
const metadata = @import("native_config_metadata");

const Options = struct {
    base: ?[]const u8 = null,
    work_dir: ?[]const u8 = null,
    prepare_output: ?[]const u8 = null,
    metadata_tool: ?[]const u8 = null,
};

fn parseArgs(a: std.mem.Allocator, args: std.process.Args) !Options {
    const argv = try args.toSlice(a);
    var opts: Options = .{};
    var index: usize = 1;
    while (index < argv.len) : (index += 2) {
        if (index + 1 >= argv.len) return error.MissingOptionValue;
        const flag = argv[index];
        const value = argv[index + 1];
        if (std.mem.eql(u8, flag, "--base") or std.mem.eql(u8, flag, "--root")) {
            opts.base = value;
        } else if (std.mem.eql(u8, flag, "--work-dir")) {
            opts.work_dir = value;
        } else if (std.mem.eql(u8, flag, "--prepare-output")) {
            opts.prepare_output = value;
        } else if (std.mem.eql(u8, flag, "--metadata-tool")) {
            opts.metadata_tool = value;
        } else {
            return error.UnknownOption;
        }
    }
    return opts;
}

fn writeModeFile(io: std.Io, path: []const u8, contents: []const u8, mode: u32) !void {
    if (std.fs.path.dirname(path)) |parent| {
        try std.Io.Dir.cwd().createDirPath(io, parent);
    }
    var file = try std.Io.Dir.cwd().createFile(io, path, .{
        .truncate = true,
        .permissions = .fromMode(mode),
    });
    defer file.close(io);
    if (std.os.linux.errno(std.os.linux.fchmod(file.handle, mode)) != .SUCCESS)
        return error.ChmodFailed;
    try file.writeStreamingAll(io, contents);
}

fn runGitsha1(a: std.mem.Allocator, io: std.Io, root: []const u8) ![]const u8 {
    const script = try std.fs.path.join(a, &.{ root, "support/scripts/gitsha1" });
    const result = try std.process.run(a, io, .{
        .argv = &.{script},
        .cwd = .{ .path = root },
        .stdout_limit = .limited(4096),
        .stderr_limit = .limited(4096),
    });
    switch (result.term) {
        .exited => |code| if (code != 0) return error.Gitsha1Failed,
        else => return error.Gitsha1Failed,
    }
    return result.stdout;
}

fn fakeCase(
    a: std.mem.Allocator,
    io: std.Io,
    work_dir: []const u8,
    name: []const u8,
    extra: []const u8,
    suffix: []const u8,
    expected: []const u8,
) !void {
    const root = try std.fs.path.join(a, &.{ work_dir, name });
    const script_path = try std.fs.path.join(a, &.{ root, "support/scripts/gitsha1" });
    const script_text = try std.fmt.allocPrint(a, "#!/bin/sh\nprintf '%s\\n' '{s}'\n", .{suffix});
    try writeModeFile(io, script_path, script_text, 0o755);

    const version_mk_path = try std.fs.path.join(a, &.{ root, "version.mk" });
    const version_mk_text = try std.fmt.allocPrint(
        a,
        "UK_VERSION = 1\nUK_SUBVERSION = 2\nUK_EXTRAVERSION = {s}\nUK_CODENAME = Test Moon\n",
        .{extra},
    );
    try writeModeFile(io, version_mk_path, version_mk_text, 0o600);

    const git_out = try runGitsha1(a, io, root);
    const actual = try metadata.versionAlloc(a, version_mk_text, git_out);
    if (!std.mem.eql(u8, actual.full, expected)) return error.FakeVersionMismatch;
    if (!std.mem.eql(u8, actual.codename, "Test Moon")) return error.FakeCodenameMismatch;
}

fn checkPortableConfigDefaults(
    a: std.mem.Allocator,
    io: std.Io,
    base_Env: *const std.process.Environ.Map,
    work_dir: []const u8,
    metadata_tool: []const u8,
) !void {
    const case_dir = try std.fs.path.join(a, &.{ work_dir, "portable-config-check" });
    try writeModeFile(
        io,
        try std.fs.path.join(a, &.{ case_dir, "version.mk" }),
        "UK_VERSION = 1\nUK_SUBVERSION = 2\nUK_EXTRAVERSION = 0\nUK_CODENAME = Test Moon\n",
        0o600,
    );
    try writeModeFile(
        io,
        try std.fs.path.join(a, &.{ case_dir, "support/scripts/gitsha1" }),
        "#!/bin/sh\nprintf '\\n'\n",
        0o755,
    );
    try writeModeFile(
        io,
        try std.fs.path.join(a, &.{ case_dir, "Config.uk" }),
        "mainmenu \"Test\"\n",
        0o600,
    );
    const config_path = try std.fs.path.join(a, &.{ case_dir, "test.config" });
    try writeModeFile(io, config_path, "", 0o600);
    const app_dir = try std.fs.path.join(a, &.{ case_dir, "app" });
    try std.Io.Dir.cwd().createDirPath(io, app_dir);
    const out_dir = try std.fs.path.join(a, &.{ case_dir, "out" });
    try std.Io.Dir.cwd().createDirPath(io, out_dir);

    {
        var env = try base_Env.clone(a);
        _ = env.swapRemove("WAMR_CI_PORTABLE_CONFIG");
        const json_path = try std.fs.path.join(a, &.{ out_dir, "default.json" });
        const res = try std.process.run(a, io, .{
            .argv = &.{
                metadata_tool,
                "--base",
                case_dir,
                "--app",
                app_dir,
                "--output",
                out_dir,
                "--config",
                config_path,
                "--json-output",
                json_path,
            },
            .environ_map = &env,
            .stdout_limit = .limited(64 * 1024),
            .stderr_limit = .limited(64 * 1024),
        });
        switch (res.term) {
            .exited => |code| if (code != 0) return error.DefaultMetadataToolFailed,
            else => return error.DefaultMetadataToolFailed,
        }
        const exported = try std.Io.Dir.cwd().readFileAlloc(io, json_path, a, .limited(64 * 1024));
        const want_base = try std.fmt.allocPrint(a, "\"UK_CONFIG_BASE\":\"{s}\"", .{case_dir});
        const want_app = try std.fmt.allocPrint(a, "\"UK_CONFIG_APP\":\"{s}\"", .{app_dir});
        if (std.mem.indexOf(u8, exported, want_base) == null) return error.DefaultConfigBaseMismatch;
        if (std.mem.indexOf(u8, exported, want_app) == null) return error.DefaultConfigAppMismatch;
    }

    {
        var env = try base_Env.clone(a);
        try env.put("WAMR_CI_PORTABLE_CONFIG", "1");
        const json_path = try std.fs.path.join(a, &.{ out_dir, "portable.json" });
        const res = try std.process.run(a, io, .{
            .argv = &.{
                metadata_tool,
                "--base",
                case_dir,
                "--app",
                app_dir,
                "--output",
                out_dir,
                "--config",
                config_path,
                "--json-output",
                json_path,
            },
            .environ_map = &env,
            .stdout_limit = .limited(64 * 1024),
            .stderr_limit = .limited(64 * 1024),
        });
        switch (res.term) {
            .exited => |code| if (code != 0) return error.PortableMetadataToolFailed,
            else => return error.PortableMetadataToolFailed,
        }
        const exported = try std.Io.Dir.cwd().readFileAlloc(io, json_path, a, .limited(64 * 1024));
        if (std.mem.indexOf(u8, exported, "\"UK_CONFIG_BASE\":\"/wamr-ci/source\"") == null)
            return error.PortableConfigBaseMismatch;
        if (std.mem.indexOf(u8, exported, "\"UK_CONFIG_APP\":\"/wamr-ci/app\"") == null)
            return error.PortableConfigAppMismatch;
    }

    {
        var env = try base_Env.clone(a);
        try env.put("WAMR_CI_PORTABLE_CONFIG", "invalid");
        const json_path = try std.fs.path.join(a, &.{ out_dir, "invalid.json" });
        const res = try std.process.run(a, io, .{
            .argv = &.{
                metadata_tool,
                "--base",
                case_dir,
                "--app",
                app_dir,
                "--output",
                out_dir,
                "--config",
                config_path,
                "--json-output",
                json_path,
            },
            .environ_map = &env,
            .stdout_limit = .limited(64 * 1024),
            .stderr_limit = .limited(64 * 1024),
        });
        switch (res.term) {
            .exited => |code| if (code == 0) return error.InvalidPortableConfigAccepted,
            else => {},
        }
    }
}

fn expectedVersion(
    a: std.mem.Allocator,
    io: std.Io,
    base: []const u8,
) !struct { full: []const u8, codename: []const u8, source: []const u8, git_out: []const u8 } {
    const version_mk_path = try std.fs.path.join(a, &.{ base, "version.mk" });
    const source = try std.Io.Dir.cwd().readFileAlloc(io, version_mk_path, a, .limited(64 * 1024));

    var major: ?[]const u8 = null;
    var minor: ?[]const u8 = null;
    var extra: ?[]const u8 = null;
    var codename: ?[]const u8 = null;

    var lines = std.mem.splitScalar(u8, source, '\n');
    while (lines.next()) |raw_line| {
        const line = std.mem.trim(u8, raw_line, " \t\r");
        if (line.len == 0 or line[0] == '#') continue;
        const eq = std.mem.indexOfScalar(u8, line, '=') orelse continue;
        const key = std.mem.trim(u8, line[0..eq], " \t\r");
        const value = std.mem.trim(u8, line[eq + 1 ..], " \t\r");
        if (std.mem.eql(u8, key, "UK_VERSION")) {
            major = value;
        } else if (std.mem.eql(u8, key, "UK_SUBVERSION")) {
            minor = value;
        } else if (std.mem.eql(u8, key, "UK_EXTRAVERSION")) {
            extra = value;
        } else if (std.mem.eql(u8, key, "UK_CODENAME")) {
            codename = value;
        }
    }

    const git_out = try runGitsha1(a, io, base);
    const suffix = std.mem.trim(u8, git_out, " \t\r\n");
    const ext = extra orelse return error.MissingExtraversion;
    const full = if (ext.len != 0)
        try std.fmt.allocPrint(a, "{s}.{s}.{s}{s}", .{
            major orelse return error.MissingVersion,
            minor orelse return error.MissingSubversion,
            ext,
            suffix,
        })
    else
        try std.fmt.allocPrint(a, "{s}.{s}{s}", .{
            major orelse return error.MissingVersion,
            minor orelse return error.MissingSubversion,
            suffix,
        });

    return .{
        .full = full,
        .codename = codename orelse return error.MissingCodename,
        .source = source,
        .git_out = git_out,
    };
}

pub fn main(init: std.process.Init) !void {
    const a = init.arena.allocator();
    const io = init.io;
    const opts = try parseArgs(a, init.minimal.args);
    const base_arg = opts.base orelse return error.MissingBase;
    const work_arg = opts.work_dir orelse return error.MissingWorkDir;
    const output_arg = opts.prepare_output orelse return error.MissingPrepareOutput;

    const base = try std.Io.Dir.cwd().realPathFileAlloc(io, base_arg, a);
    try std.Io.Dir.cwd().createDirPath(io, work_arg);
    const work_dir = try std.Io.Dir.cwd().realPathFileAlloc(io, work_arg, a);
    try std.Io.Dir.cwd().createDirPath(io, output_arg);
    const output = try std.Io.Dir.cwd().realPathFileAlloc(io, output_arg, a);

    try fakeCase(a, io, work_dir, "release-clean", "0", "~abc123", "1.2.0~abc123");
    try fakeCase(a, io, work_dir, "release-dirty", "", "~abc123-custom", "1.2~abc123-custom");
    try fakeCase(a, io, work_dir, "release-no-git", "rc1", "", "1.2.rc1");

    if (opts.metadata_tool) |tool_arg| {
        const tool = try std.Io.Dir.cwd().realPathFileAlloc(io, tool_arg, a);
        try checkPortableConfigDefaults(a, io, init.environ_map, work_dir, tool);
    }

    const expected = try expectedVersion(a, io, base);
    const actual = try metadata.versionAlloc(a, expected.source, expected.git_out);
    if (!std.mem.eql(u8, actual.full, expected.full)) return error.RepositoryVersionMismatch;
    if (!std.mem.eql(u8, actual.codename, expected.codename)) return error.RepositoryCodenameMismatch;

    const fragment = try std.fs.path.join(
        a,
        &.{ output, "native-config-version", expected.full, "Config.uk" },
    );
    try writeModeFile(
        io,
        fragment,
        "config VERSION_PATH_SYMBOL\n\tstring \"Version path symbol\"\n",
        0o600,
    );
}
