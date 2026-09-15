// SPDX-License-Identifier: BSD-3-Clause
//! Native fake adapter controls. No controller, runtime, clock, or admission
//! bypass: these exercise the same grant/template guards used by the fake CLI.
const std = @import("std");
const f = @import("lifecycle_fixture_support.zig");
const linux = std.os.linux;
const Counts = struct { assertions: usize, processes: usize };

fn expectError(expected: anyerror, result: anyerror!void) !void {
    if (result) |_| return error.AdapterRegressionAccepted else |err| {
        if (err != expected) return err;
    }
}

fn context(base: f.Context, name: []const u8) !f.Context {
    try base.mkdir(name);
    const c: f.Context = .{ .a = base.a, .io = base.io, .root = try base.path(name) };
    try c.write("ISOLATED_OFFLINE_FIXTURE", f.marker);
    try c.writeJson("fixture-backend.json", .{ .backend = "native" });
    try c.write("scenario", "success\n");
    try c.write("calls", "");
    try c.writeJson("fake-cloud.json", .{
        .exists = true,
        .boots = 0,
        .power = "deallocated",
        .os = .{ .created = true, .uploaded = true },
        .data = .{ .created = true, .uploaded = true },
    });
    return c;
}

fn remove(c: f.Context, name: []const u8) !void {
    try std.Io.Dir.deleteFileAbsolute(c.io, try c.path(name));
}

fn environment(c: f.Context) !std.process.Environ.Map {
    var result = std.process.Environ.Map.init(c.a);
    try result.put("UK_DIRECT_FIXTURE_ROOT", c.root);
    try result.put("AZURE_CORE_COLLECT_TELEMETRY", "0");
    return result;
}

fn grant(c: f.Context, fake: []const u8, pipe: bool, mode: u16, allowed: bool) !void {
    var env = try environment(c);
    defer env.deinit();
    const capture = try c.create("capture.json");
    defer capture.close(c.io);
    const stderr = try c.create("stderr");
    defer stderr.close(c.io);
    var read_end: ?std.Io.File = null;
    defer if (read_end) |file| file.close(c.io);
    var write_end: ?std.Io.File = null;
    defer if (write_end) |file| file.close(c.io);
    if (pipe) {
        var descriptors: [2]linux.fd_t = undefined;
        if (linux.errno(linux.pipe2(&descriptors, .{ .CLOEXEC = true })) != .SUCCESS) return error.PipeCreationFailed;
        read_end = .{ .handle = descriptors[0], .flags = .{ .nonblocking = false } };
        write_end = .{ .handle = descriptors[1], .flags = .{ .nonblocking = false } };
        try write_end.?.setPermissions(c.io, .fromMode(mode));
    } else try capture.setPermissions(c.io, .fromMode(mode));
    var child = try std.process.spawn(c.io, .{
        .argv = &.{
            fake,             "disk",  "grant-access",          "--resource-group", f.prefix ++ "-rg", "--name",       f.prefix ++ "-os",
            "--access-level", "Write", "--duration-in-seconds", "1800",             "--subscription",  f.subscription, "--only-show-errors",
            "--output",       "json",
        },
        .environ_map = &env,
        .stdin = .ignore,
        .stdout = .{ .file = write_end orelse capture },
        .stderr = .{ .file = stderr },
    });
    defer child.kill(c.io);
    if (write_end) |file| {
        file.close(c.io);
        write_end = null;
    }
    if (read_end) |file| {
        var buffer: [4096]u8 = undefined;
        var total: usize = 0;
        while (true) {
            const count = file.readStreaming(c.io, &.{&buffer}) catch |err| {
                if (err == error.EndOfStream) break;
                return err;
            };
            if (count == 0) break;
            total += count;
            try f.expect(total <= buffer.len);
            try capture.writeStreamingAll(c.io, buffer[0..count]);
        }
    }
    const status = try child.wait(c.io);
    try capture.setPermissions(c.io, .fromMode(0o600));
    try capture.sync(c.io);
    try f.expect(status == .exited and status.exited == @as(u8, if (allowed) 0 else 90));
    const bytes = try c.read("capture.json");
    const errors = try c.read("stderr");
    try f.expect(std.mem.indexOf(u8, errors, f.sentinel) == null);
    if (allowed) {
        const response = try f.parse(c.a, bytes);
        try f.expect(f.eq(try f.str(response, "accessSAS"), "https://fixture.blob.core.windows.net/upload?sv=fixture&sig=" ++ f.sentinel));
    } else try f.expect(bytes.len == 0);
    // Even the positive adapter control leaves no synthetic grant on disk.
    try remove(c, "capture.json");
}

fn outputControls(base: f.Context, fake: []const u8) !Counts {
    var count: usize = 0;
    inline for (.{
        .{ "native-pipe", true, 0o600, true },
        .{ "native-file", false, 0o600, true },
        .{ "native-public-pipe", true, 0o644, false },
        .{ "native-public-file", false, 0o644, false },
        .{ "native-read-only-pipe", true, 0o400, false },
        .{ "native-read-only-file", false, 0o400, false },
        .{ "native-group-pipe", true, 0o660, false },
        .{ "native-group-file", false, 0o660, false },
    }) |test_case| {
        try grant(try context(base, test_case[0]), fake, test_case[1], test_case[2], test_case[3]);
        count += 1;
    }
    const retired = try context(base, "retired-backend");
    try retired.replaceJson("fixture-backend.json", .{ .backend = "reference" });
    try grant(retired, fake, true, 0o600, false);
    count += 1;
    const missing = try context(base, "missing-backend");
    try remove(missing, "fixture-backend.json");
    try grant(missing, fake, true, 0o600, false);
    const unknown = try context(base, "unknown-backend");
    try unknown.replaceJson("fixture-backend.json", .{ .backend = "automatic" });
    try grant(unknown, fake, true, 0o600, false);
    const extra = try context(base, "ambiguous-backend");
    try extra.replaceJson("fixture-backend.json", .{ .backend = "native", .fallback = true });
    try grant(extra, fake, true, 0o600, false);
    count += 3;

    const public = try context(base, "public-backend");
    const selection = try f.files.openAbsolute(base.io, try public.path("fixture-backend.json"), .private);
    defer selection.close(base.io);
    try selection.setPermissions(base.io, .fromMode(0o644));
    try grant(public, fake, true, 0o600, false);
    try selection.setPermissions(base.io, .fromMode(0o600));
    const duplicate = try context(base, "duplicate-backend");
    try remove(duplicate, "fixture-backend.json");
    try duplicate.write("fixture-backend.json", "{\"backend\":\"native\",\"backend\":\"reference\"}");
    try grant(duplicate, fake, true, 0o600, false);
    const alias = try context(base, "symlink-backend");
    try std.Io.Dir.renameAbsolute(try alias.path("fixture-backend.json"), try alias.path("original-backend.json"), base.io);
    const alias_dir = try f.files.Directory.open(base.io, alias.root);
    defer alias_dir.close(base.io);
    try alias_dir.dir.symLink(base.io, "original-backend.json", "fixture-backend.json", .{});
    try grant(alias, fake, true, 0o600, false);
    try remove(alias, "fixture-backend.json");
    try std.Io.Dir.renameAbsolute(try alias.path("original-backend.json"), try alias.path("fixture-backend.json"), base.io);
    const linked = try context(base, "hardlink-backend");
    const linked_dir = try f.files.Directory.open(base.io, linked.root);
    defer linked_dir.close(base.io);
    try f.expect(linux.errno(linux.linkat(linked_dir.dir.handle, "fixture-backend.json", linked_dir.dir.handle, "backend-link.json", 0)) == .SUCCESS);
    try grant(linked, fake, true, 0o600, false);
    try remove(linked, "backend-link.json");
    count += 4;
    const processes = count;

    const file = try base.create("metadata");
    defer file.close(base.io);
    const original = try f.files.snapshot(file);
    // Synthetic metadata avoids opening public devices or network sockets.
    inline for (.{ 0o020600, 0o060600, 0o140600, 0o040600, 0o000600 }) |mode| {
        var changed = original;
        changed.mode = mode;
        try expectError(error.UnsafeFixtureGrantOutput, f.grantOutputMetadata(changed, linux.getuid()));
        count += 1;
    }
    inline for (.{ 0o100600, 0o010600 }) |mode| {
        var changed = original;
        changed.mode = mode;
        changed.uid = linux.getuid() ^ 1;
        try expectError(error.UnsafeFixtureGrantOutput, f.grantOutputMetadata(changed, linux.getuid()));
        changed.uid = linux.getuid();
        changed.nlink = 2;
        try expectError(error.UnsafeFixtureGrantOutput, f.grantOutputMetadata(changed, linux.getuid()));
        changed.nlink = 1;
        changed.mode |= 0o4000;
        try expectError(error.UnsafeFixtureGrantOutput, f.grantOutputMetadata(changed, linux.getuid()));
        count += 3;
    }
    return .{ .assertions = count, .processes = processes };
}

fn deployment(c: f.Context, fake: []const u8, path: []const u8, allowed: bool) !void {
    try c.writeJson("attempt/deployment-parameters.json", .{ .parameters = .{
        .namePrefix = .{ .value = f.prefix },
        .location = .{ .value = "fixture" },
        .ownerRun = .{ .value = f.owner },
        .imageSha256 = .{ .value = f.image_sha },
        .osDiskId = .{ .value = f.os_id },
        .dataDiskId = .{ .value = f.data_id },
        .vmSize = .{ .value = "Standard_D2s_v5" },
    } });
    var env = try environment(c);
    defer env.deinit();
    const stdout = try c.create("stdout");
    defer stdout.close(c.io);
    const stderr = try c.create("stderr");
    defer stderr.close(c.io);
    var child = try std.process.spawn(c.io, .{
        .argv = &.{
            fake,              "deployment", "group",        "create",                                                                                 "--resource-group", f.prefix ++ "-rg", "--name",             f.prefix,
            "--template-file", path,         "--parameters", try std.mem.concat(c.a, u8, &.{ "@", try c.path("attempt/deployment-parameters.json") }), "--subscription",   f.subscription,    "--only-show-errors", "--output",
            "json",
        },
        .environ_map = &env,
        .stdin = .ignore,
        .stdout = .{ .file = stdout },
        .stderr = .{ .file = stderr },
    });
    defer child.kill(c.io);
    const status = try child.wait(c.io);
    try f.expect(status == .exited and status.exited == @as(u8, if (allowed) 0 else 90));
    try f.expect(try f.num(try c.document("fake-cloud.json"), "boots") == @as(i64, if (allowed) 1 else 0));
    try f.expect(std.mem.indexOf(u8, try c.read("stdout"), f.sentinel) == null and std.mem.indexOf(u8, try c.read("stderr"), f.sentinel) == null);
    if (!allowed) try f.expect((try c.read("calls")).len == 0);
}

fn templateContext(base: f.Context, name: []const u8) !f.Context {
    const c = try context(base, name);
    try c.mkdir("attempt");
    return c;
}

fn templateControls(base: f.Context, fake: []const u8) !Counts {
    const bytes = try f.repositoryTemplate(base);
    const native = try templateContext(base, "native-template");
    try native.write(f.private_template, bytes);
    try f.deploymentTemplate(native, try native.path(f.private_template));
    try deployment(native, fake, try native.path(f.private_template), true);
    var count: usize = 2;

    const retired = try templateContext(base, "retired-template-backend");
    try retired.replaceJson("fixture-backend.json", .{ .backend = "reference" });
    try retired.write(f.private_template, bytes);
    try deployment(retired, fake, try retired.path(f.private_template), false);
    const installed = try templateContext(base, "native-installed-template");
    try deployment(installed, fake, try f.repositoryTemplatePath(installed), false);
    const wrong_name = try templateContext(base, "wrong-template-name");
    try wrong_name.write("attempt/other-template.json", bytes);
    try deployment(wrong_name, fake, try wrong_name.path("attempt/other-template.json"), false);
    const traversal = try templateContext(base, "template-traversal");
    try traversal.write(f.private_template, bytes);
    try deployment(traversal, fake, try std.mem.concat(base.a, u8, &.{ traversal.root, "/attempt/../", f.private_template }), false);
    const outside = try templateContext(base, "template-outside-attempt");
    try outside.write("deployment-template.json", bytes);
    try deployment(outside, fake, try outside.path("deployment-template.json"), false);
    count += 5;

    const changed = try templateContext(base, "changed-template");
    try changed.write(f.private_template, try std.mem.concat(base.a, u8, &.{ bytes, "\n" }));
    try deployment(changed, fake, try changed.path(f.private_template), false);
    const oversized = try templateContext(base, "oversized-template");
    const large = try base.a.alloc(u8, f.template_limit + 1);
    @memset(large, ' ');
    try oversized.write(f.private_template, large);
    try deployment(oversized, fake, try oversized.path(f.private_template), false);
    const public = try templateContext(base, "public-template");
    const public_file = try public.create(f.private_template);
    defer public_file.close(base.io);
    try public_file.writeStreamingAll(base.io, bytes);
    try public_file.setPermissions(base.io, .fromMode(0o644));
    try deployment(public, fake, try public.path(f.private_template), false);
    try public_file.setPermissions(base.io, .fromMode(0o600));
    count += 3;

    const alias = try templateContext(base, "symlink-template");
    try alias.write("attempt/original.json", bytes);
    const alias_dir = try f.files.Directory.open(base.io, try alias.path("attempt"));
    defer alias_dir.close(base.io);
    try alias_dir.dir.symLink(base.io, "original.json", std.fs.path.basename(f.private_template), .{});
    try deployment(alias, fake, try alias.path(f.private_template), false);
    try remove(alias, f.private_template);
    const linked = try templateContext(base, "hardlink-template");
    try linked.write(f.private_template, bytes);
    const linked_dir = try f.files.Directory.open(base.io, try linked.path("attempt"));
    defer linked_dir.close(base.io);
    const template_name = try base.a.dupeZ(u8, std.fs.path.basename(f.private_template));
    try f.expect(linux.errno(linux.linkat(linked_dir.dir.handle, template_name, linked_dir.dir.handle, "extra-link.json", 0)) == .SUCCESS);
    try deployment(linked, fake, try linked.path(f.private_template), false);
    try remove(linked, "attempt/extra-link.json");
    const directory = try templateContext(base, "directory-template");
    try directory.mkdir(f.private_template);
    try deployment(directory, fake, try directory.path(f.private_template), false);
    count += 3;

    inline for (.{ "prefixed-template", "truncated-template", "empty-template", "absent-template", "mutated-template" }) |name| {
        const c = try templateContext(base, name);
        if (comptime !f.eq(name, "absent-template")) {
            const contents = if (comptime f.eq(name, "prefixed-template"))
                try std.mem.concat(base.a, u8, &.{ " ", bytes })
            else if (comptime f.eq(name, "truncated-template"))
                bytes[0 .. bytes.len - 1]
            else if (comptime f.eq(name, "empty-template"))
                ""
            else blk: {
                const altered = try base.a.dupe(u8, bytes);
                const at = std.mem.indexOf(u8, altered, "Standard") orelse return error.MissingTemplateControl;
                altered[at] = 's';
                break :blk altered;
            };
            try c.write(f.private_template, contents);
        }
        try deployment(c, fake, try c.path(f.private_template), false);
        count += 1;
    }
    inline for (.{ .{ "read-only-template", 0o400 }, .{ "group-template", 0o660 }, .{ "setuid-template", 0o4600 } }) |test_case| {
        const c = try templateContext(base, test_case[0]);
        const file = try c.create(f.private_template);
        defer file.close(base.io);
        try file.writeStreamingAll(base.io, bytes);
        try file.setPermissions(base.io, .fromMode(test_case[1]));
        try deployment(c, fake, try c.path(f.private_template), false);
        try file.setPermissions(base.io, .fromMode(0o600));
        count += 1;
    }
    const wrong_directory = try templateContext(base, "wrong-template-directory");
    try wrong_directory.mkdir("other");
    try wrong_directory.write("other/deployment-template.json", bytes);
    try deployment(wrong_directory, fake, try wrong_directory.path("other/deployment-template.json"), false);
    const no_selection = try templateContext(base, "template-missing-backend");
    try no_selection.write(f.private_template, bytes);
    try remove(no_selection, "fixture-backend.json");
    try deployment(no_selection, fake, try no_selection.path(f.private_template), false);
    const ambiguous = try templateContext(base, "template-ambiguous-backend");
    try ambiguous.write(f.private_template, bytes);
    try ambiguous.replaceJson("fixture-backend.json", .{ .backend = "native", .fallback = true });
    try deployment(ambiguous, fake, try ambiguous.path(f.private_template), false);
    const fifo = try templateContext(base, "fifo-template");
    const fifo_dir = try f.files.Directory.open(base.io, try fifo.path("attempt"));
    defer fifo_dir.close(base.io);
    try f.expect(linux.errno(linux.mknodat(fifo_dir.dir.handle, template_name, 0o010600, 0)) == .SUCCESS);
    try deployment(fifo, fake, try fifo.path(f.private_template), false);
    try remove(fifo, f.private_template);
    count += 4;
    return .{ .assertions = count, .processes = count - 1 };
}

pub fn run(base: f.Context, fake: []const u8) !usize {
    try base.mkdir("native-adapter-controls");
    const c: f.Context = .{ .a = base.a, .io = base.io, .root = try base.path("native-adapter-controls") };
    const output = try outputControls(c, fake);
    const templates = try templateControls(c, fake);
    try base.writeJson("native-adapter-regressions.json", .{
        .output_assertions = output.assertions,
        .template_assertions = templates.assertions,
        .real_adapter_processes = output.processes + templates.processes,
        .metadata_only_assertions = output.assertions - output.processes,
        .direct_template_assertions = templates.assertions - templates.processes,
    });
    return output.assertions + templates.assertions;
}
