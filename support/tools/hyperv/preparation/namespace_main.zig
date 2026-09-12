// SPDX-License-Identifier: BSD-3-Clause
const std = @import("std");
const namespace = @import("namespace.zig");
const c = @import("contracts.zig");
const git_entry = @import("git_entry.zig");

pub fn main(init: std.process.Init.Minimal) void {
    // Close inherited descriptors even when invoked other than by core.process.
    if (std.os.linux.errno(std.os.linux.close_range(3, std.math.maxInt(std.os.linux.fd_t), @bitCast(@as(u32, 0)))) != .SUCCESS)
        fail(error.DescriptorIsolationUnavailable);
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    const allocator = arena.allocator();
    var threaded: std.Io.Threaded = .init_single_threaded;
    const args = init.args.toSlice(allocator) catch |err| fail(err);
    if (args.len != 0 and std.mem.eql(u8, std.fs.path.basename(args[0]), "git"))
        git_entry.run(allocator, threaded.io(), args[1..]) catch |err| fail(err);
    if (args.len != 4) fail(error.InvalidArguments);
    const status_file = namespace.StatusFile.openParent(allocator, args[3]) catch |err| fail(err);
    const digest = c.sha(args[2]) catch {
        finish(status_file, .{ .primary = .setup_failed });
    };
    const status = namespace.runRequest(allocator, threaded.io(), args[1], digest, status_file) catch
        namespace.Status{ .primary = .setup_failed };
    finish(status_file, status);
}

fn finish(file: namespace.StatusFile, status: namespace.Status) noreturn {
    file.write(status) catch |err| fail(err);
    file.close();
    std.os.linux.exit_group(0);
}

fn fail(err: anyerror) noreturn {
    git_entry.fail(err);
}
