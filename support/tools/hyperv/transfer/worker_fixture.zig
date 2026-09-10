const std = @import("std");
const core = @import("hyperv");
const sdk = @import("azure_sdk_core");
const Mode = enum {
    pass,
    partial,
    blocked,
    blocked_lock_failure,
    final_lock_failure,
    malformed,
    stale,
    flood,
    stderr_secret,
    metadata,
    cleanup_failure,
    recording_failure,
    changed_request,
    pending_forgery,
    counter_forgery,
    reject,
    reject_second,
    container_body_failure,
    early_accept,
    short_source,
    growing_source,
    disconnect,
    block_footer,
};

pub fn main(init: std.process.Init) void {
    run(init) catch std.process.exit(2);
}

fn run(init: std.process.Init) !void {
    if (init.environ_map.count() != 0) return error.InheritedEnvironment;
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    for (args) |arg| if (std.mem.indexOf(u8, arg, "sig=") != null) return error.SecretInArguments;
    if (args.len == 6 and std.mem.eql(u8, args[1], "__capture-cli"))
        return captureCli(init.io, init.arena.allocator(), args[2..]);
    if (args.len != 3 or !std.mem.eql(u8, args[1], "__transfer-worker")) return error.InvalidArguments;
    var wiping: core.sensitive.Allocator = .{ .backing = std.heap.page_allocator };
    const allocator = wiping.allocator();
    const directory = try core.private_files.Directory.openWorkerCwd(init.io);
    defer directory.close(init.io);
    var mode_bytes = try directory.readSensitive(init.io, allocator, "fixture-mode", 64, null);
    defer mode_bytes.deinit();
    const mode = std.meta.stringToEnum(Mode, mode_bytes.bytes()) orelse return error.InvalidMode;
    var invocations: u64 = 0;
    if (directory.readSensitive(init.io, allocator, "invocations", 32, null)) |owned| {
        var previous = owned;
        defer previous.deinit();
        invocations = try std.fmt.parseInt(u64, previous.bytes(), 10);
    } else |err| if (err != error.FileNotFound) return err;
    var count_buffer: [32]u8 = undefined;
    try directory.dir.writeFile(init.io, .{
        .sub_path = "invocations",
        .data = try std.fmt.bufPrint(&count_buffer, "{d}", .{invocations + 1}),
        .flags = .{ .permissions = .fromMode(0o600) },
    });
    if (mode == .changed_request) {
        const file = try directory.dir.openFile(init.io, "request.json", .{ .mode = .write_only });
        defer file.close(init.io);
        try file.writePositionalAll(init.io, " ", (try file.stat(init.io)).size);
    }
    var mock: Mock = .{ .allocator = allocator, .io = init.io, .directory = directory, .mode = mode };
    var crypto = sdk.crypto.StdCryptoProvider.init(init.io);
    var report = core.transfer.worker.execute(allocator, init.io, args[2], .init(
        .{ .context = &mock, .vtable = &.{ .send = Mock.send, .open = Mock.open } },
        crypto.asProvider(),
    ));
    var stdout = std.Io.File.stdout().writer(init.io, &.{});
    if (mode == .final_lock_failure) try invalidateLock(init.io, directory);
    if (mode == .counter_forgery) {
        var raw = try directory.readSensitive(init.io, allocator, core.transfer.job.state_name, core.transfer.worker.protocol.maximum_result, null);
        defer raw.deinit();
        const corrupt = try replaceOne(allocator, raw.bytes(), "\"bytes_accepted\":17", "\"bytes_accepted\":0");
        defer allocator.free(corrupt);
        var lock = try directory.lock(init.io);
        defer lock.close(init.io);
        const saved = try lock.commit(init.io, core.transfer.job.state_name, corrupt);
        if (saved.status != .durable) return error.RecordingFailed;
        try stdout.interface.writeAll(corrupt);
    } else if (mode == .malformed) {
        try stdout.interface.writeAll("{\"unexpected\":\"SYNTHETIC_SECRET?sig=PRIVATE\"}\n");
    } else if (mode == .flood) {
        while (true) try stdout.interface.writeAll("SYNTHETIC_SECRET?sig=PRIVATE\n");
    } else {
        if (mode == .stale) report.attempt_id = [_]u8{0} ** 32;
        if (mode == .stderr_secret) {
            var stderr = std.Io.File.stderr().writer(init.io, &.{});
            try stderr.interface.writeAll("SYNTHETIC_SECRET?sig=PRIVATE\n");
        }
        try report.write(&stdout.interface);
    }
}

// Preserve the actual CLI's failure JSON without changing the supervisor's
// policy of discarding nonzero-exit pipe output. No additional child is spawned.
fn captureCli(io: std.Io, allocator: std.mem.Allocator, args: []const []const u8) !void {
    if (!std.fs.path.isAbsolute(args[0])) return error.InvalidArguments;
    const internal = std.mem.eql(u8, args[1], "__transfer-worker");
    if (!internal and !std.mem.eql(u8, args[1], "transfer")) return error.InvalidArguments;
    const directory = try core.private_files.Directory.openWorkerCwd(io);
    defer directory.close(io);
    const file = try directory.dir.createFile(io, "cli-output.json", .{ .exclusive = true, .permissions = .fromMode(0o600) });
    defer file.close(io);
    try file.setPermissions(io, .fromMode(0o600));
    if (std.os.linux.errno(std.os.linux.dup3(file.handle, 1, 0)) != .SUCCESS) return error.RedirectFailed;
    var environment = std.process.Environ.Map.init(allocator);
    defer environment.deinit();
    return std.process.replace(io, .{
        .argv = if (internal) &.{ args[0], args[1], args[3] } else args,
        .environ_map = &environment,
    });
}

fn replaceOne(allocator: std.mem.Allocator, raw: []const u8, before: []const u8, after: []const u8) ![]u8 {
    if (std.mem.count(u8, raw, before) != 1) return error.InvalidMutationFixture;
    return std.mem.replaceOwned(u8, allocator, raw, before, after);
}

fn invalidateLock(io: std.Io, directory: core.private_files.Directory) !void {
    const file = try directory.dir.openFile(io, ".writer.lock", .{});
    defer file.close(io);
    try file.setPermissions(io, .fromMode(0o644));
}

const Mock = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    directory: core.private_files.Directory,
    mode: Mode,
    calls: usize = 0,

    fn send(_: *anyopaque, _: *sdk.http.Request) !sdk.http.Response {
        return error.BufferedTransportForbidden;
    }

    fn open(context: *anyopaque, request: *sdk.http.Request, options: sdk.http.OpenOptions) !*sdk.http.HttpOperation {
        const self: *Mock = @ptrCast(@alignCast(context));
        self.calls += 1;
        if (request.retryable or request.redirect_policy != .not_allowed or request.getHeader("Authorization") != null)
            return error.UnsafeRequest;
        if (self.mode == .blocked or self.mode == .blocked_lock_failure or self.mode == .pending_forgery or
            (self.mode == .block_footer and request.method == .GET))
        {
            try self.directory.dir.writeFile(self.io, .{
                .sub_path = "entered",
                .data = "native",
                .flags = .{ .exclusive = true, .permissions = .fromMode(0o600) },
            });
            if (self.mode == .blocked_lock_failure) try invalidateLock(self.io, self.directory);
            if (self.mode == .pending_forgery) {
                var raw = try self.directory.readSensitive(self.io, self.allocator, core.transfer.job.state_name, core.transfer.worker.protocol.maximum_result, null);
                defer raw.deinit();
                const corrupt = try replaceOne(self.allocator, raw.bytes(), "\"side_effect\":\"unknown\"", "\"side_effect\":\"not_started\"");
                defer self.allocator.free(corrupt);
                const file = try self.directory.dir.openFile(self.io, core.transfer.job.state_name, .{ .mode = .write_only });
                defer file.close(self.io);
                try file.setLength(self.io, corrupt.len);
                try file.writePositionalAll(self.io, corrupt, 0);
                try file.sync(self.io);
            }
            while (true) {
                const duration: std.os.linux.timespec = .{ .sec = 1, .nsec = 0 };
                _ = std.os.linux.nanosleep(&duration, null);
            }
        }
        if (self.mode == .disconnect or (self.mode == .partial and self.calls == 2)) return error.SyntheticDisconnected;
        if (self.mode == .short_source or self.mode == .growing_source) {
            const file = try self.directory.dir.openFile(self.io, "source", .{ .mode = .read_write });
            defer file.close(self.io);
            if (self.mode == .short_source) {
                try file.setLength(self.io, 0);
            } else try file.writePositionalAll(self.io, "SYNTHETIC_GROWTH", (try file.stat(self.io)).size);
        }
        if (options.body != null and self.mode != .early_accept) {
            const body = options.body.?;
            var buffer: [4093]u8 = undefined;
            defer std.crypto.secureZero(u8, &buffer);
            var count: u64 = 0;
            var md5 = std.crypto.hash.Md5.init(.{});
            while (true) {
                var slices = [_][]u8{&buffer};
                const n = body.reader.readVec(&slices) catch |err| switch (err) {
                    error.EndOfStream => break,
                    else => return err,
                };
                count += n;
                md5.update(buffer[0..n]);
            }
            if (count != body.content_length.?) return error.WrongLength;
            var digest: [16]u8 = undefined;
            var encoded: [24]u8 = undefined;
            md5.final(&digest);
            if (!std.mem.eql(u8, request.getHeader("Content-MD5") orelse return error.MissingMd5, std.base64.standard.Encoder.encode(&encoded, &digest)))
                return error.WrongMd5;
        }
        if (self.mode == .recording_failure) {
            try self.directory.dir.deleteFile(self.io, core.transfer.job.state_name);
            try self.directory.dir.createDir(self.io, core.transfer.job.state_name, .fromMode(0o700));
        }
        if (self.mode == .cleanup_failure) {
            try self.directory.dir.deleteFile(self.io, "download");
            try self.directory.dir.createDir(self.io, "download", .fromMode(0o700));
        }
        const operation = try self.allocator.create(Operation);
        errdefer self.allocator.destroy(operation);
        operation.* = .{ .allocator = self.allocator, .interface = undefined, .reader = undefined };
        const footer = request.getHeader("x-ms-range-get-content-md5") != null;
        const response: []const u8 = if (request.method == .GET)
            (if (footer) &operation.footer else "synthetic evidence")
        else if (self.mode == .metadata or (self.mode == .container_body_failure and self.calls == 1))
            "SYNTHETIC_SECRET?sig=PRIVATE"
        else
            "";
        operation.reader = .fixed(response);
        var headers = sdk.http.ResponseHeaders.init(self.allocator);
        errdefer headers.deinit();
        if (footer) {
            var digest: [16]u8 = undefined;
            var encoded: [24]u8 = undefined;
            std.crypto.hash.Md5.hash(&operation.footer, &digest, .{});
            try headers.append("Content-MD5", std.base64.standard.Encoder.encode(&encoded, &digest));
            try headers.append("Content-Length", "512");
            try headers.append("Content-Range", "bytes 0-511/512");
        }
        if (self.mode == .metadata) try headers.append("x-ms-error-code", "AuthorizationServiceMismatch");
        if (self.mode == .cleanup_failure) try headers.append("Content-MD5", "AAAAAAAAAAAAAAAAAAAAAA==");
        operation.interface = .{
            .status_code = if (self.mode == .reject or (self.mode == .reject_second and self.calls == 2)) 412 else if (self.mode == .metadata) 403 else if (request.method == .GET) (if (footer) @as(u16, 206) else 200) else 201,
            .headers = std.StringHashMap([]const u8).init(self.allocator),
            .response_headers = headers,
            .body_reader = &operation.reader,
            .finishFn = Operation.finish,
            .abortFn = Operation.abort,
            .cancelFn = Operation.abort,
            .deinitFn = Operation.deinit,
        };
        return &operation.interface;
    }
};

const Operation = struct {
    allocator: std.mem.Allocator,
    interface: sdk.http.HttpOperation,
    reader: std.Io.Reader,
    footer: [512]u8 = [_]u8{0x5a} ** 512,

    fn finish(_: *sdk.http.HttpOperation) !void {
        return error.UnboundedFinishForbidden;
    }
    fn abort(_: *sdk.http.HttpOperation) void {}
    fn deinit(interface: *sdk.http.HttpOperation) void {
        const self: *Operation = @alignCast(@fieldParentPtr("interface", interface));
        self.interface.response_headers.deinit();
        self.interface.headers.deinit();
        self.allocator.destroy(self);
    }
};
