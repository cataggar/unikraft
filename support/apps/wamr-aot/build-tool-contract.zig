// SPDX-License-Identifier: BSD-3-Clause
const std = @import("std");

pub const files = @import("build-tool-files.zig");
pub const json = @import("build-tool-json.zig");
pub const process = @import("build-tool-process.zig");
pub const prepare = @import("build-tool-prepare.zig");
pub const image = @import("build-tool-image.zig");

pub const revision = "a53205d77be3b880eb8f8b96679512ba58e2331a";
pub const workload_revision = revision;
pub const compiler_profile = "unikraft-x86_64";
pub const zig_version = "0.16.0";
pub const source_identity_recipe = "sorted-compact-json-relative-file-path-to-bytes-and-sha256-v1";
pub const development_scope = "local-development-build-only-not-supported-lineage";
pub const supported_scope = "native-build-inputs-not-hardware-qualification";
pub const compiler_runtime_provider = "unikraft-final-link-not-bundled-in-consumer";
pub const native_flags = [_][]const u8{
    "-target",
    "x86_64-freestanding-none",
    "-O",
    "ReleaseSafe",
    "-fPIC",
    "-mno-red-zone",
    "-fno-stack-check",
    "-fno-stack-protector",
    "-fno-unwind-tables",
    "-fno-error-tracing",
    "-fsingle-threaded",
    "-fno-compiler-rt",
};

pub const Command = enum { prepare, verify, olddefconfig, native_images };
pub const Variant = enum { tiny, snapshot, jit, sample_aot };
pub const JitMode = enum { fast, full };

pub const Arguments = struct {
    command: Command,
    repository: []const u8,
    source: ?[]const u8 = null,
    source_archive: ?[]const u8 = null,
    coremark: bool = false,
    variant: Variant = .tiny,
    jit_mode: ?JitMode = null,
    development_revision: ?[]const u8 = null,
};

pub fn parseArguments(arguments: []const []const u8) !Arguments {
    if (arguments.len == 0) return error.InvalidArguments;
    var result: Arguments = .{
        .command = parseCommand(arguments[0]) catch return error.InvalidArguments,
        .repository = "",
    };
    var repository = false;
    var source = false;
    var source_archive = false;
    var coremark = false;
    var variant = false;
    var jit_mode = false;
    var development_revision = false;
    var index: usize = 1;
    while (index < arguments.len) {
        const raw = arguments[index];
        const option = splitOption(raw);
        if (std.mem.eql(u8, option.name, "--coremark")) {
            if (option.value != null) return error.InvalidArguments;
            if (coremark) return error.DuplicateOption;
            coremark = true;
            result.coremark = true;
            index += 1;
            continue;
        }
        const value = option.value orelse value: {
            index += 1;
            if (index >= arguments.len) return error.MissingOption;
            break :value arguments[index];
        };
        if (std.mem.eql(u8, option.name, "--repository")) {
            if (repository) return error.DuplicateOption;
            repository = true;
            result.repository = value;
        } else if (std.mem.eql(u8, option.name, "--source")) {
            if (source) return error.DuplicateOption;
            source = true;
            result.source = value;
        } else if (std.mem.eql(u8, option.name, "--source-archive")) {
            if (source_archive) return error.DuplicateOption;
            source_archive = true;
            result.source_archive = value;
        } else if (std.mem.eql(u8, option.name, "--variant")) {
            if (variant) return error.DuplicateOption;
            variant = true;
            result.variant = parseVariant(value) catch return error.InvalidArguments;
        } else if (std.mem.eql(u8, option.name, "--jit-mode")) {
            if (jit_mode) return error.DuplicateOption;
            jit_mode = true;
            result.jit_mode = parseJitMode(value) catch return error.InvalidArguments;
        } else if (std.mem.eql(u8, option.name, "--development-revision")) {
            if (development_revision) return error.DuplicateOption;
            development_revision = true;
            try validateRevision(value);
            result.development_revision = value;
        } else {
            return error.InvalidArguments;
        }
        index += 1;
    }
    if (!repository) return error.MissingOption;
    try absolute(result.repository);
    switch (result.command) {
        .prepare => {
            if ((result.source == null) == (result.source_archive == null))
                return error.UnsupportedCombination;
            if (result.source) |path| try absolute(path);
            if (result.source_archive) |path| {
                try absolute(path);
                if (result.development_revision != null)
                    return error.UnsupportedCombination;
            }
            if (result.coremark and result.variant != .tiny)
                return error.UnsupportedCombination;
            if ((result.variant == .jit) != (result.jit_mode != null))
                return error.UnsupportedCombination;
        },
        .verify, .olddefconfig, .native_images => {
            if (result.source != null or result.source_archive != null or
                result.coremark or variant or
                result.jit_mode != null or result.development_revision != null)
                return error.UnsupportedCombination;
        },
    }
    return result;
}

const Option = struct { name: []const u8, value: ?[]const u8 };

fn splitOption(argument: []const u8) Option {
    if (std.mem.indexOfScalar(u8, argument, '=')) |separator|
        return .{ .name = argument[0..separator], .value = argument[separator + 1 ..] };
    return .{ .name = argument, .value = null };
}

fn parseCommand(value: []const u8) !Command {
    if (std.mem.eql(u8, value, "prepare")) return .prepare;
    if (std.mem.eql(u8, value, "verify")) return .verify;
    if (std.mem.eql(u8, value, "olddefconfig")) return .olddefconfig;
    if (std.mem.eql(u8, value, "native-images")) return .native_images;
    return error.InvalidCommand;
}

fn parseVariant(value: []const u8) !Variant {
    if (std.mem.eql(u8, value, "tiny")) return .tiny;
    if (std.mem.eql(u8, value, "snapshot")) return .snapshot;
    if (std.mem.eql(u8, value, "jit")) return .jit;
    if (std.mem.eql(u8, value, "sample-aot")) return .sample_aot;
    return error.InvalidVariant;
}

fn parseJitMode(value: []const u8) !JitMode {
    if (std.mem.eql(u8, value, "fast")) return .fast;
    if (std.mem.eql(u8, value, "full")) return .full;
    return error.InvalidJitMode;
}

pub fn validateRevision(value: []const u8) !void {
    if (value.len != 40) return error.InvalidRevision;
    for (value) |byte| if (!std.ascii.isDigit(byte) and !(byte >= 'a' and byte <= 'f'))
        return error.InvalidRevision;
}

pub fn absolute(path: []const u8) !void {
    if (path.len < 2 or path.len > 4095 or !std.fs.path.isAbsolute(path) or
        path[path.len - 1] == '/')
        return error.UnsafePath;
    var components = std.mem.splitScalar(u8, path[1..], '/');
    while (components.next()) |component| {
        if (component.len == 0 or component.len > 255 or
            std.mem.eql(u8, component, ".") or std.mem.eql(u8, component, ".."))
            return error.UnsafePath;
        for (component) |byte| if (byte == 0 or byte == '\\' or byte < 0x20 or byte == 0x7f)
            return error.UnsafePath;
    }
}

test {
    std.testing.refAllDecls(@This());
}
