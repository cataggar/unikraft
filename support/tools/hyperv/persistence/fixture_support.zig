//! Offline model only. Metadata-sized 4-GiB results are not real uploads or boots.
const std = @import("std");
const core = @import("hyperv_core");
const transfer = @import("hyperv_transfer");
const p = @import("root.zig");

pub const Mode = enum { good, boot2_write, prefix_changed, wrong_vm, deny_absence, unknown_upload, block_upload, malformed_output, secret_failure, partial_pages, output_limit, malformed_create, replaced_after_create, unstarted_grant };
pub const ids: p.model.Originals = .{
    .os = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".*,
    .data = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb".*,
    .vm = "cccccccc-cccc-4ccc-8ccc-cccccccccccc".*,
};
pub fn input() p.contract.Contract {
    const authority: @import("hyperv_azure").scope.Authority = .{
        .tenant = "11111111-1111-4111-8111-111111111111".*,
        .subscription = "22222222-2222-4222-8222-222222222222".*,
        .principal = "33333333-3333-4333-8333-333333333333".*,
        .client = "44444444-4444-4444-8444-444444444444".*,
        .owner_run = "55555555-5555-4555-8555-555555555555".*,
        .group = "synthetic-rg",
        .location = "northeurope",
    };
    return .{
        .run_id = "0123456789abcdef0123456789abcdef".*,
        .disk_id = "66666666666646668666666666666666".*,
        .authority = authority,
        .cleanup_authority = authority,
        .prefix = "synthetic",
        .guest = .{ .path = "/synthetic-public-fixture/guest.vhd", .size = 66 * 1024 * 1024 + 512, .sha256 = [_]u8{'1'} ** 64, .footer_sha256 = [_]u8{'2'} ** 64 },
        .data = .{ .path = "/synthetic-public-fixture/data.vhd", .size = p.contract.data_bytes + 512, .sha256 = [_]u8{'3'} ** 64, .footer_sha256 = [_]u8{'4'} ** 64 },
        .bindings = .{
            .source = [_]u8{'1'} ** 64,
            .producer = [_]u8{'2'} ** 64,
            .preparation = [_]u8{'3'} ** 64,
            .preflight = [_]u8{'4'} ** 64,
            .image = [_]u8{'5'} ** 64,
            .authority = [_]u8{'6'} ** 64,
            .route = [_]u8{'7'} ** 64,
            .trust = [_]u8{'8'} ** 64,
        },
        .runtime_seconds = 60,
        .cleanup_seconds = 60,
        .operation_ms = 1000,
        .grant_seconds = 60,
        .stage_bytes = 128 * 1024 * 1024,
        .control_bytes = 1024,
    };
}
pub fn segment(a: std.mem.Allocator, boot: u8, writes: u8) ![]u8 {
    const spec = input();
    return std.fmt.allocPrint(a, "synthetic protocol fixture, not boot evidence\n" ++
        "HYPERV_PERSISTENCE START PASS run={s} address=0:0:7 sectors=8388608 sector_size=512\n" ++
        "HYPERV_PERSISTENCE SELECT PASS id=1 controller=2 state={d}\n" ++
        "UK_HYPERV_PERSISTENCE_IDENTITY:1:2:{s}:{s}:77777777777747778777777777777777:0:3:7:8388608:512:4:1:3:0:11223344\n" ++
        "HYPERV_PERSISTENCE BOOT{d}_{s} PASS run={s}\n" ++
        "UK_HYPERV_PERSISTENCE_IO:1:{d}:{s}:{d}:{d}:receipt-verified\n" ++
        "UK_HYPERV_PERSISTENCE_BOOT{d}_COMPLETE:{s}\n" ++
        "HYPERV_PERSISTENCE FINAL PASS rc=0\nmain returned 0\n", .{ spec.run_id, @as(u8, if (boot == 1) 0 else 2), spec.run_id, spec.disk_id, boot, if (boot == 1) @as([]const u8, "WRITE") else "READ", spec.run_id, boot, spec.run_id, writes, @as(u8, if (boot == 1) 3 else 0), boot, spec.run_id });
}
pub fn serial(a: std.mem.Allocator, step: p.model.Step, mode: Mode) ![]u8 {
    const first = try segment(a, 1, 5);
    if (step == .serial_boot1) return first;
    defer a.free(first);
    const second = try segment(a, 2, if (mode == .boot2_write) 1 else 0);
    defer a.free(second);
    const full = try std.mem.concat(a, u8, &.{ first, second });
    if (mode == .prefix_changed) full[0] = 'X';
    return full;
}
pub const Model = struct {
    allocator: std.mem.Allocator,
    mode: Mode = .good,
    fail_at: ?p.model.Step = null,
    calls: [p.model.step_count]u8 = [_]u8{0} ** p.model.step_count,
    denied_execution: bool = false,
    denied_cleanup: bool = false,
    pub fn options(self: *Model) p.engine.Options {
        return .{ .trusted = .{ .context = self, .validateFn = validate }, .driver = .{ .context = self, .executeFn = execute, .serialFn = readSerial } };
    }
    fn validate(context: *anyopaque, _: p.contract.Contract, _: p.local.Hash, lane: p.contract.TrustedInputs.Lane) !void {
        const self: *Model = @ptrCast(@alignCast(context));
        if (if (lane == .execution) self.denied_execution else self.denied_cleanup) return error.SyntheticAuthorityExpired;
    }
    fn execute(context: *anyopaque, job: p.model.Job) !p.engine.Reply {
        const self: *Model = @ptrCast(@alignCast(context));
        self.calls[@intFromEnum(job.step)] += 1;
        return .{ .value = try self.result(job) };
    }
    pub fn result(self: *Model, job: p.model.Job) !p.model.Result {
        var out = try p.native.initial(self.allocator, job);
        out.effect = if (job.step.mutation()) .accepted else .not_applicable;
        out.complete = true;
        if (self.fail_at == job.step or (self.mode == .unknown_upload and job.step == .data_upload)) {
            out.complete = false;
            out.effect = if (job.step.mutation()) .unknown else .not_applicable;
            out.failures.primary = .{ .stage = .arm, .category = .transport };
            return out;
        }
        if (self.mode == .unstarted_grant and job.step == .data_grant) {
            out.complete = false;
            out.effect = .not_started;
            out.http_status = 403;
            out.failures.primary = .{ .stage = .arm, .category = .authorization, .http_status = 403 };
            return out;
        }
        switch (job.step) {
            .os_create => out.observation.originals.os = ids.os,
            .data_create => out.observation.originals.data = ids.data,
            .deploy_boot1 => out.observation.originals.vm = ids.vm,
            .os_upload, .data_upload => {
                const source = if (job.step == .os_upload) job.input.guest else job.input.data;
                const outcome: transfer.Outcome = .{
                    .completion = .complete,
                    .side_effect = .accepted,
                    .diagnostic = .{ .stage = .footer_readback, .category = .none, .status = 206 },
                    .bytes_streamed = source.size,
                    .bytes_accepted = source.size,
                    .sha256 = try core.contracts.parseSha256(&source.sha256),
                    .footer_sha256 = try core.contracts.parseSha256(&source.footer_sha256),
                };
                out.transfer = outcome;
                // A metadata-only model of the shared journal, not page I/O.
                const mutations = (source.size - 1) / transfer.client.page_chunk_size + 1;
                out.page_report = try p.model.PageReport.capture(.{
                    .admitted_plan = .{ .bytes = source.size, .download_bytes = 512, .mutations = mutations, .requests = mutations + 1 },
                    .attempt_id = try core.contracts.parseSha256(&job.nonce),
                    .job_sha256 = try core.contracts.parseSha256(&out.job_sha256),
                    .kind = .pages,
                    .phase = .finished,
                    .outcome = outcome,
                    .side_effect = .accepted,
                    .delivery_complete = true,
                    .progress = .{ .bytes_attempted = source.size, .bytes_confirmed = source.size, .mutations_attempted = mutations, .mutations_confirmed = mutations, .requests_attempted = mutations + 1, .responses_observed = mutations + 1, .stage = .footer_readback, .status = 206, .previous_effect = .accepted },
                });
            },
            .observe_boot1, .observe_boot2, .observe_deallocated, .observe_final_deallocated, .cleanup_observe => {
                out.observation = .{ .group = .present, .originals = job.originals, .owned_inventory = true, .envelope = true, .power = if (job.step == .observe_boot1 or job.step == .observe_boot2) .running else .deallocated };
                if (self.mode == .wrong_vm and job.step == .observe_boot2)
                    out.observation.originals.vm = "dddddddd-dddd-4ddd-8ddd-dddddddddddd".*;
                if (self.mode == .replaced_after_create and job.step == .cleanup_observe)
                    out.observation.originals.os = "dddddddd-dddd-4ddd-8ddd-dddddddddddd".*;
            },
            .serial_boot1, .serial_boot2 => {
                const bytes = try serial(self.allocator, job.step, self.mode);
                defer self.allocator.free(bytes);
                out.serial = .{ .name = "serial.bin", .bytes = @intCast(bytes.len), .sha256 = p.local.hash(bytes) };
            },
            .os_access_closed, .data_access_closed, .cleanup_os_access, .cleanup_data_access => {
                out.access_closed = true;
                out.http_status = 403;
                out.service_code = .AuthenticationFailed;
                out.access_metadata = .{ .state = .known, .header = .known, .body = .known, .code = .AuthenticationFailed, .header_code = .AuthenticationFailed, .body_code = .AuthenticationFailed };
            },
            .cleanup_absence => {
                out.observation.group = if (self.mode == .deny_absence) .unknown else .absent;
                out.http_status = if (self.mode == .deny_absence) 403 else 404;
                out.service_code = if (self.mode == .deny_absence) .AuthorizationFailure else .ResourceGroupNotFound;
                if (self.mode == .deny_absence) {
                    out.complete = false;
                    out.failures.cleanup = .{ .stage = .cleanup, .category = .authorization, .http_status = 403, .service_code = .AuthorizationFailure };
                }
            },
            .cleanup_dispose => out.secrets_disposed = true,
            else => {},
        }
        return out;
    }
    fn readSerial(context: *anyopaque, a: std.mem.Allocator, step: p.model.Step, _: p.model.Serial) ![]u8 {
        const self: *Model = @ptrCast(@alignCast(context));
        return serial(a, step, self.mode);
    }
};

pub fn makeJob(a: std.mem.Allocator, step: p.model.Step, deadline: u64) !p.model.Job {
    const bytes = try p.local.encode(a, input());
    defer a.free(bytes);
    return .{ .input = input(), .input_sha256 = p.local.hash(bytes), .nonce = [_]u8{'8'} ** 64, .step = step, .originals = ids, .parent_pid = @intCast(std.os.linux.getpid()), .deadline_ns = deadline, .authority_lane = if (step.cleanup()) .cleanup else .execution, .boot1 = null, .creation_intent = .{ true, true, true }, .network_intent = .{ true, true, true }, .group_intent = true };
}

pub const Fixture = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    root: core.private_files.Directory,
    directory: core.private_files.Directory,
    name: [40]u8,
    path: []u8,
    pub fn init(a: std.mem.Allocator, io: std.Io, root_path: []const u8) !Fixture {
        const root = try core.private_files.Directory.open(io, root_path);
        errdefer root.close(io);
        var nonce: [16]u8 = undefined;
        io.random(&nonce);
        const name = ("persist-" ++ std.fmt.bytesToHex(nonce, .lower)).*;
        try root.dir.createDir(io, &name, .fromMode(0o700));
        const path = try std.fs.path.join(a, &.{ root_path, &name });
        errdefer a.free(path);
        const directory = try core.private_files.Directory.open(io, path);
        return .{ .allocator = a, .io = io, .root = root, .directory = directory, .name = name, .path = path };
    }
    pub fn deinit(self: Fixture) void {
        self.directory.close(self.io);
        self.root.dir.deleteTree(self.io, &self.name) catch @panic("synthetic fixture cleanup failed");
        self.root.close(self.io);
        self.allocator.free(self.path);
    }
};
