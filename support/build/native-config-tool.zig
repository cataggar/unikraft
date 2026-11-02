const std = @import("std");
const kconfig = @import("kconfig.zig");

pub fn main(init: std.process.Init) !void {
    const allocator = init.arena.allocator();
    const args = try init.minimal.args.toSlice(allocator);
    if (args.len < 4) return usage();

    const command = args[1];
    const config_path = args[2];
    const metadata_path = args[3];
    const metadata_source = std.Io.Dir.cwd().readFileAlloc(
        init.io,
        metadata_path,
        allocator,
        .limited(64 * 1024 * 1024),
    ) catch |err| {
        std.debug.print("error: unable to read Kconfig metadata '{s}': {s}\n", .{
            metadata_path,
            @errorName(err),
        });
        std.process.exit(2);
    };
    var metadata = kconfig.Metadata.parse(allocator, metadata_source) catch |err| {
        std.debug.print("error: invalid Kconfig metadata '{s}': {s}\n", .{
            metadata_path,
            @errorName(err),
        });
        std.process.exit(2);
    };
    defer metadata.deinit();

    const source = std.Io.Dir.cwd().readFileAlloc(
        init.io,
        config_path,
        allocator,
        .limited(64 * 1024 * 1024),
    ) catch |err| {
        std.debug.print("error: unable to read configuration '{s}': {s}\n", .{
            config_path,
            @errorName(err),
        });
        std.process.exit(2);
    };

    var parse_diagnostic: kconfig.Diagnostic = .{};
    var config = kconfig.parseWithMetadata(
        allocator,
        source,
        &metadata,
        &parse_diagnostic,
    ) catch |err| switch (err) {
        error.InvalidConfig => {
            printParseDiagnostic(config_path, parse_diagnostic);
            std.process.exit(2);
        },
        else => return err,
    };
    defer config.deinit();

    if (std.mem.eql(u8, command, "inspect") or std.mem.eql(u8, command, "validate")) {
        var validation_diagnostic: kconfig.ValidationDiagnostic = .{};
        const target = kconfig.deriveTargetWithPlatforms(
            &config,
            metadata.platforms.items,
            &validation_diagnostic,
        ) catch {
            printValidationDiagnostic(config_path, validation_diagnostic);
            std.process.exit(2);
        };
        if (std.mem.eql(u8, command, "inspect")) {
            std.debug.print(
                "config={s}\narchitecture={s}\narchitecture_family={s}\nplatform={s}\n",
                .{
                    config_path,
                    target.architecture.name,
                    target.architecture.family,
                    target.platform.name,
                },
            );
        }
        return;
    }

    if (std.mem.eql(u8, command, "header")) {
        if (args.len != 5) return usage();
        try writeHeader(init.io, allocator, args[4], &config);
        std.debug.print("generated {s}\n", .{args[4]});
        return;
    }
    return usage();
}

fn usage() noreturn {
    std.debug.print(
        "usage: native-config-tool inspect|validate CONFIG METADATA\n" ++
            "       native-config-tool header CONFIG METADATA OUTPUT\n",
        .{},
    );
    std.process.exit(2);
}

fn writeHeader(
    io: std.Io,
    allocator: std.mem.Allocator,
    path: []const u8,
    config: *const kconfig.Document,
) !void {
    const contents = try config.headerAlloc(allocator);
    const parent = std.fs.path.dirname(path) orelse ".";
    try std.Io.Dir.cwd().createDirPath(io, parent);

    const existing = std.Io.Dir.cwd().readFileAlloc(
        io,
        path,
        allocator,
        .limited(contents.len + 1),
    ) catch null;
    if (existing) |old| {
        if (std.mem.eql(u8, old, contents)) return;
    }

    const file = try std.Io.Dir.cwd().createFile(io, path, .{
        .truncate = true,
    });
    defer file.close(io);
    try file.writePositionalAll(io, contents, 0);
}

fn printParseDiagnostic(path: []const u8, diagnostic: kconfig.Diagnostic) void {
    const description = switch (diagnostic.kind) {
        .malformed_line => "malformed .config line; expected CONFIG_NAME=value or '# CONFIG_NAME is not set'",
        .invalid_symbol => "invalid symbol name; use letters, digits, and underscores",
        .invalid_value => "invalid value; expected y, m, n, a quoted string, decimal integer, or hexadecimal integer",
        .malformed_string => "malformed quoted string; escape embedded quotes and backslashes",
        .ambiguous_numeric => "ambiguous bare numeric value; authoritative int/hex Kconfig metadata is required",
        .type_mismatch => "value does not match the authoritative Kconfig symbol type",
        .duplicate_entry => "duplicate configuration entry",
        .conflicting_entry => "conflicting configuration entry",
    };
    std.debug.print("{s}:{d}:{d}: error: {s}", .{
        path,
        diagnostic.line,
        diagnostic.column,
        description,
    });
    if (diagnostic.symbol.len != 0) std.debug.print(" for CONFIG_{s}", .{diagnostic.symbol});
    if (diagnostic.previous_line) |line| std.debug.print(" (previously set on line {d})", .{line});
    std.debug.print("\n", .{});
}

fn printValidationDiagnostic(
    path: []const u8,
    diagnostic: kconfig.ValidationDiagnostic,
) void {
    switch (diagnostic.kind) {
        .missing_architecture => std.debug.print(
            "{s}: error: select exactly one supported architecture (CONFIG_ARCH_X86_64, CONFIG_ARCH_ARM_64, or CONFIG_ARCH_ARM_32)\n",
            .{path},
        ),
        .multiple_architectures => std.debug.print(
            "{s}: error: multiple architectures selected: CONFIG_{s} and CONFIG_{s}\n",
            .{ path, diagnostic.symbol, diagnostic.other_symbol },
        ),
        .unsupported_architecture => std.debug.print(
            "{s}: error: unsupported architecture selection CONFIG_{s}\n",
            .{ path, diagnostic.symbol },
        ),
        .missing_platform => std.debug.print(
            "{s}: error: select exactly one supported target platform\n",
            .{path},
        ),
        .multiple_platforms => std.debug.print(
            "{s}: error: multiple target platforms selected: CONFIG_{s} and CONFIG_{s}\n",
            .{ path, diagnostic.symbol, diagnostic.other_symbol },
        ),
        .unsupported_platform => std.debug.print(
            "{s}: error: unsupported target platform selection CONFIG_{s}\n",
            .{ path, diagnostic.symbol },
        ),
        .missing_boot_entry => std.debug.print(
            "{s}: error: no boot-entry provider is selected (CONFIG_HAVE_BOOTENTRY=y is required)\n",
            .{path},
        ),
    }
}
