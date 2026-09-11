//! This executable is never installed or selectable by production job data.
const std = @import("std");
const core = @import("hyperv_core");
const p = @import("root.zig");
const f = @import("fixture_support.zig");

pub fn main(init: std.process.Init) void {
    run(init) catch {
        std.debug.print("synthetic persistence worker failure\n", .{});
        std.process.exit(1);
    };
}
fn run(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len != 2 or !std.mem.eql(u8, args[1], "__persistence-worker")) return error.InvalidArguments;
    var context = Context{ .allocator = std.heap.page_allocator, .io = init.io };
    try p.worker.child(context.allocator, init.io, .{ .context = &context, .executeFn = Context.execute });
}
const Context = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    fn execute(context: *anyopaque, job: p.model.Job, directory: core.private_files.Directory, lock: *core.private_files.Locked) !p.model.Result {
        const self: *Context = @ptrCast(@alignCast(context));
        const raw = try directory.read(self.io, self.allocator, "fixture-mode", 64, null);
        defer self.allocator.free(raw);
        const mode = std.meta.stringToEnum(f.Mode, raw) orelse return error.InvalidMode;
        if (job.step == .data_upload and mode == .output_limit) {
            var output = std.Io.File.stdout().writer(self.io, &.{});
            for (0..1024) |_| try output.interface.writeAll("synthetic-output-bound\n");
            std.process.exit(0);
        }
        if (job.step == .data_upload and mode == .partial_pages) {
            const transfer = @import("hyperv_transfer");
            const initial = try p.native.initial(self.allocator, job);
            const count = (job.input.data.size - 1) / transfer.client.page_chunk_size + 1;
            const intent: transfer.worker.protocol.Intent = .{
                .attempt_id = try core.contracts.parseSha256(&job.nonce),
                .job_sha256 = try core.contracts.parseSha256(&initial.job_sha256),
                .request_sha256 = [_]u8{1} ** 32,
                .sas_sha256 = [_]u8{2} ** 32,
                .kind = .pages,
                .plan = .{ .bytes = job.input.data.size, .download_bytes = 512, .mutations = count, .requests = count + 1 },
                .deadline_ns = job.deadline_ns,
                .parent_pid = job.parent_pid,
            };
            var buffer: [4096]u8 = undefined;
            var writer = std.Io.Writer.fixed(&buffer);
            try intent.write(&writer);
            if ((try lock.createImmutable(self.io, transfer.job.intent_name, writer.buffered())).status != .durable)
                return error.RecordingFailed;
            var report = transfer.worker.protocol.Report.initial(intent);
            report.phase = .in_flight;
            report.side_effect = .unknown;
            report.progress = .{ .bytes_attempted = 2 * transfer.client.page_chunk_size, .bytes_confirmed = transfer.client.page_chunk_size, .mutations_attempted = 2, .mutations_confirmed = 1, .pending = true, .pending_bytes = transfer.client.page_chunk_size, .pending_mutation = true, .previous_effect = .incomplete, .requests_attempted = 2, .responses_observed = 1, .stage = .page_put };
            writer = .fixed(&buffer);
            try report.write(&writer);
            if ((try lock.createImmutable(self.io, transfer.job.state_name, writer.buffered())).status != .durable)
                return error.RecordingFailed;
            std.process.exit(9);
        }
        if (job.step == .data_upload and mode == .block_upload) while (true) {
            const delay = std.os.linux.timespec{ .sec = 10, .nsec = 0 };
            _ = std.os.linux.nanosleep(&delay, null);
        };
        if (job.step == .data_upload and mode == .secret_failure) {
            std.debug.print("SYNTHETIC_SECRET?sig=fixture-only\n", .{});
            std.process.exit(7);
        }
        var model = f.Model{ .allocator = self.allocator, .mode = mode };
        const result = try model.result(job);
        if (job.step == .serial_boot1 or job.step == .serial_boot2) {
            const bytes = try f.serial(self.allocator, job.step, mode);
            defer self.allocator.free(bytes);
            const saved = try lock.createImmutable(self.io, "serial.bin", bytes);
            if (saved.status != .durable) return error.RecordingFailed;
        }
        if ((job.step == .data_upload and mode == .malformed_output) or
            (job.step == .os_create and (mode == .malformed_create or mode == .replaced_after_create)))
        {
            const bytes = try p.local.encode(self.allocator, result);
            defer self.allocator.free(bytes);
            const saved = try lock.createImmutable(self.io, "result.json", bytes);
            if (saved.status != .durable) return error.RecordingFailed;
            var stdout = std.Io.File.stdout().writer(self.io, &.{});
            try stdout.interface.writeAll("{\"not-a-worker-ack\":true}\n");
            std.process.exit(0);
        }
        return result;
    }
};
