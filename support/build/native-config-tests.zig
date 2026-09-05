const std = @import("std");
const kconfig = @import("kconfig.zig");

fn checkFixture(
    source: []const u8,
    expected_header: []const u8,
    expected_architecture: []const u8,
    expected_family: []const u8,
    expected_platform: []const u8,
) !void {
    const allocator = std.testing.allocator;
    var parse_diagnostic: kconfig.Diagnostic = .{};
    var validation_diagnostic: kconfig.ValidationDiagnostic = .{};
    var config = try kconfig.parse(allocator, source, &parse_diagnostic);
    defer config.deinit();

    const target = try kconfig.deriveTarget(&config, &validation_diagnostic);
    try std.testing.expectEqualStrings(expected_architecture, target.architecture.name);
    try std.testing.expectEqualStrings(expected_family, target.architecture.family);
    try std.testing.expectEqualStrings(expected_platform, target.platform.name);

    const header = try config.headerAlloc(allocator);
    defer allocator.free(header);
    try std.testing.expectEqualStrings(expected_header, header);
}

test "x86_64 KVM fixture matches current Kconfig header semantics" {
    try checkFixture(
        @embedFile("tests/native-config/x86_64-kvm.config"),
        @embedFile("tests/native-config/x86_64-kvm.h"),
        "x86_64",
        "x86",
        "kvm",
    );
}

test "ARM64 KVM fixture matches current Kconfig header semantics" {
    try checkFixture(
        @embedFile("tests/native-config/arm64-kvm.config"),
        @embedFile("tests/native-config/arm64-kvm.h"),
        "arm64",
        "arm",
        "kvm",
    );
}

test "escaping fixture matches Kconfig unescape and header escape behavior" {
    const allocator = std.testing.allocator;
    var diagnostic: kconfig.Diagnostic = .{};
    var config = try kconfig.parse(
        allocator,
        @embedFile("tests/native-config/escaping.config"),
        &diagnostic,
    );
    defer config.deinit();
    const header = try config.headerAlloc(allocator);
    defer allocator.free(header);
    try std.testing.expectEqualStrings(
        @embedFile("tests/native-config/escaping.h"),
        header,
    );
}

test "duplicate fixture is rejected with both source locations" {
    var diagnostic: kconfig.Diagnostic = .{};
    try std.testing.expectError(
        error.InvalidConfig,
        kconfig.parse(
            std.testing.allocator,
            @embedFile("tests/native-config/duplicate.config"),
            &diagnostic,
        ),
    );
    try std.testing.expectEqual(kconfig.Diagnostic.Kind.duplicate_entry, diagnostic.kind);
    try std.testing.expectEqual(@as(usize, 2), diagnostic.line);
    try std.testing.expectEqual(@as(?usize, 1), diagnostic.previous_line);
}

test "target validation rejects ambiguous selections and missing boot entry" {
    const allocator = std.testing.allocator;
    var parse_diagnostic: kconfig.Diagnostic = .{};
    var validation_diagnostic: kconfig.ValidationDiagnostic = .{};
    var multiple = try kconfig.parse(
        allocator,
        "CONFIG_ARCH_X86_64=y\nCONFIG_ARCH_ARM_64=y\nCONFIG_PLAT_KVM=y\nCONFIG_HAVE_BOOTENTRY=y\n",
        &parse_diagnostic,
    );
    defer multiple.deinit();
    try std.testing.expectError(
        error.InvalidTarget,
        kconfig.deriveTarget(&multiple, &validation_diagnostic),
    );
    try std.testing.expectEqual(
        kconfig.ValidationDiagnostic.Kind.multiple_architectures,
        validation_diagnostic.kind,
    );

    var no_boot = try kconfig.parse(
        allocator,
        "CONFIG_ARCH_X86_64=y\nCONFIG_PLAT_KVM=y\n# CONFIG_HAVE_BOOTENTRY is not set\n",
        &parse_diagnostic,
    );
    defer no_boot.deinit();
    try std.testing.expectError(
        error.InvalidTarget,
        kconfig.deriveTarget(&no_boot, &validation_diagnostic),
    );
    try std.testing.expectEqual(
        kconfig.ValidationDiagnostic.Kind.missing_boot_entry,
        validation_diagnostic.kind,
    );
}
