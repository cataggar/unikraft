// SPDX-License-Identifier: BSD-3-Clause
const std = @import("std");
const core = @import("hyperv_core");
const Sha256 = core.Sha256;
const files = core.private_files;
const inputs = @import("controller_source_closure");
pub const Entry = inputs.Entry;

// The embedded bytes make this executable's own compile-time source inputs
// independently checkable. Git revision/clean-tree admission is owned by PR 02.
pub const closure = inputs.entries;

pub fn contentClosure() [Sha256.digest_length]u8 {
    var hash = Sha256.init(.{});
    hash.update("uk.wamr.controller-source-v1\x00");
    for (closure) |entry| {
        var length: [8]u8 = undefined;
        std.mem.writeInt(u64, &length, entry.name.len, .big);
        hash.update(&length);
        hash.update(entry.name);
        std.mem.writeInt(u64, &length, entry.content.len, .big);
        hash.update(&length);
        hash.update(entry.content);
    }
    return hash.finalResult();
}

pub fn verifyContent(expected: Entry, observed: []const u8) !void {
    if (observed.len != expected.content.len or !std.mem.eql(u8, observed, expected.content))
        return error.SourceChanged;
}

pub fn verifyPhysical(io: std.Io, allocator: std.mem.Allocator, repository: []const u8) !void {
    const dir = try files.openDirectory(io, repository, .artifact);
    defer dir.close(io);
    if (std.os.linux.geteuid() == 0) return error.RootUser;
    for (closure) |entry| {
        const path = try std.fs.path.join(allocator, &.{ repository, entry.name });
        defer allocator.free(path);
        var retained = try files.RetainedFile.open(io, path, .artifact);
        defer retained.close(io);
        const before = retained.file_snapshot;
        if (before.nlink != 1 or before.uid != std.os.linux.geteuid() or
            before.mode & std.os.linux.S.IFMT != std.os.linux.S.IFREG or
            before.mode & 0o022 != 0 or before.size != entry.content.len)
            return error.UnsafeSource;
        var contents = try files.readSensitiveFile(io, allocator, retained.file, 64 * 1024 * 1024, .artifact);
        defer contents.deinit();
        try verifyContent(entry, contents.bytes());
        try retained.verify(io);
    }
}
