//! Synthetic worker qualification only; no production or ledger admission.
const std = @import("std");
pub const gate = @import("equivalence");

pub const Options = struct {
    raw: []const u8,
    candidate: []const u8,
    layout_policy: gate.LayoutPolicy = .identical_program_headers,
    report: ?[]const u8 = null,

    pub fn parse(args: []const []const u8) !Options {
        if (args.len < 3 or args.len > 7 or args.len % 2 != 1) return error.InvalidArguments;
        var result: Options = .{ .raw = args[1], .candidate = args[2] };
        try gate.core.private_files.absoluteFilePath(result.raw);
        try gate.core.private_files.absoluteFilePath(result.candidate);
        var policy_seen = false;
        var index: usize = 3;
        while (index < args.len) : (index += 2) {
            if (std.mem.eql(u8, args[index], "--layout-policy") and !policy_seen) {
                result.layout_policy = std.meta.stringToEnum(gate.LayoutPolicy, args[index + 1]) orelse return error.InvalidArguments;
                policy_seen = true;
            } else if (std.mem.eql(u8, args[index], "--report") and result.report == null) {
                try gate.core.private_files.absoluteFilePath(args[index + 1]);
                result.report = args[index + 1];
            } else return error.InvalidArguments;
        }
        return result;
    }
};

pub const WorkerProof = struct {
    role: enum { persistence_worker } = .persistence_worker,
    raw: gate.FileProof,
    candidate: gate.FileProof,
    content: gate.ContentProof,
};

pub const Proof = struct {
    schema: enum { hyperv_persistence_fixture_debug_stripping_v1 } = .hyperv_persistence_fixture_debug_stripping_v1,
    authority: enum { synthetic_only_not_admitted } = .synthetic_only_not_admitted,
    passed: bool = true,
    synthetic: bool = true,
    admitted: bool = false,
    qualification_only: bool = true,
    layout_policy: gate.LayoutPolicy,
    worker: WorkerProof,
};

pub fn qualify(allocator: std.mem.Allocator, io: std.Io, options: Options) !void {
    const pair = try gate.Pair.openWithPolicy(allocator, io, options.raw, options.candidate, options.layout_policy);
    defer pair.close(allocator, io);
    try pair.recheck(io);
    if (options.report) |path| {
        const proof: Proof = .{
            .layout_policy = pair.content.layout_policy,
            .worker = .{ .raw = pair.raw.proof(), .candidate = pair.candidate.proof(), .content = pair.content },
        };
        try gate.publish(allocator, io, path, proof);
        // Read back through the private single-link policy after publication.
        // This is a fresh observation, not custody against later owner mutation.
        const directory = try gate.core.private_files.Directory.open(io, std.fs.path.dirname(path).?);
        defer directory.close(io);
        const actual = try directory.read(io, allocator, std.fs.path.basename(path), gate.max_report_bytes, null);
        defer allocator.free(actual);
        const expected = try std.json.Stringify.valueAlloc(allocator, proof, .{});
        defer allocator.free(expected);
        if (actual.len != expected.len + 1 or actual[actual.len - 1] != '\n' or
            !std.mem.eql(u8, actual[0..expected.len], expected)) return error.ReportChanged;
        try pair.recheck(io);
    }
}
