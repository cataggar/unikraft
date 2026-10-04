// SPDX-License-Identifier: BSD-3-Clause
const std = @import("std");
const core = @import("hyperv_core");
const contracts = core.contracts;
const files = core.private_files;
const inputs = @import("input_custody.zig");
const records = @import("records.zig");
const source = @import("source_custody.zig");
const physical = @import("custody_files.zig");
const dependencies = @import("dependency_custody.zig");

const SourcePolicy = enum { compiled_producer, recorded_producer };
const legacy_host_tools = inputs.host_tools ++ [_][]const u8{ "head", "timeout" };

fn get(value: std.json.Value, key: []const u8) !std.json.Value {
    if (value != .object) return error.InvalidInputCustody;
    return value.object.get(key) orelse error.InvalidInputCustody;
}

fn notCancelled(signal: ?*core.process.SignalCancellation) !void {
    if (signal) |active|
        if (active.flag().load(.acquire)) return error.Cancelled;
}

fn sameValue(allocator: std.mem.Allocator, expected: std.json.Value, actual: anytype) !void {
    const first = try records.canonicalAlloc(allocator, try std.json.Stringify.valueAlloc(allocator, expected, .{}));
    const second = try records.canonicalAlloc(allocator, try std.json.Stringify.valueAlloc(allocator, actual, .{}));
    if (!std.mem.eql(u8, first, second)) return error.RecordedCustodyChanged;
}

fn recordedPath(map: std.json.Value, role: []const u8) ![]const u8 {
    const path = try contracts.string(try get(try get(map, role), "path"));
    try files.absoluteFilePath(path);
    return path;
}

fn nativeProducer(allocator: std.mem.Allocator, runtime: []const u8, files_map: std.json.Value) !bool {
    const supervisor = try recordedPath(files_map, "command-supervisor");
    const native = try std.fs.path.join(allocator, &.{ runtime, "controller/bin/uk-wamr-native-ci" });
    defer allocator.free(native);
    if (std.mem.eql(u8, supervisor, native)) return true;
    const python = try std.fs.path.join(allocator, &.{ runtime, "compute/supervisor/bin/wamr-ci-supervisor" });
    defer allocator.free(python);
    if (std.mem.eql(u8, supervisor, python)) return false;
    return error.UnexpectedInputPath;
}

fn fixedPath(
    allocator: std.mem.Allocator,
    map: std.json.Value,
    role: []const u8,
    root: []const u8,
    relative: []const u8,
) !void {
    const expected = try std.fs.path.join(allocator, &.{ root, relative });
    if (!std.mem.eql(u8, try recordedPath(map, role), expected))
        return error.UnexpectedInputPath;
}

fn buildStartDigest(bytes: []const u8, expected: contracts.Sha256) !void {
    if (!std.meta.eql(records.fileIdentity(bytes), expected))
        return error.BuildStartDigestMismatch;
}

fn bootInputsDigest(bytes: []const u8, expected: contracts.Sha256) !void {
    if (!std.meta.eql(records.fileIdentity(bytes), expected))
        return error.BootInputsDigestMismatch;
}

fn addRole(allowed: *std.StringHashMap(void), role: []const u8) !void {
    if (allowed.contains(role)) return error.DuplicateInputRole;
    try allowed.put(role, {});
}

fn addRuntime(
    allocator: std.mem.Allocator,
    io: std.Io,
    allowed: *std.StringHashMap(void),
    executable: []const u8,
) !void {
    const paths = try inputs.executableRuntimePaths(allocator, io, executable);
    defer {
        for (paths) |path| allocator.free(path);
        allocator.free(paths);
    }
    for (paths) |path| {
        const role = try std.fmt.allocPrint(allocator, "runtime:{s}", .{path});
        if (!allowed.contains(role)) try addRole(allowed, role);
    }
}

fn exactRoles(allowed: *std.StringHashMap(void), map: std.json.Value) !void {
    if (map != .object or map.object.count() != allowed.count())
        return error.UnexpectedInputRole;
    for (map.object.keys()) |name| {
        if (!allowed.contains(name)) return error.UnexpectedInputRole;
        if (std.mem.startsWith(u8, name, "runtime:") and
            !std.mem.eql(u8, name["runtime:".len..], try recordedPath(map, name)))
            return error.UnexpectedInputPath;
    }
}

fn buildRoles(
    allocator: std.mem.Allocator,
    io: std.Io,
    repository: []const u8,
    runtime: []const u8,
    start: std.json.Value,
    signal: ?*core.process.SignalCancellation,
    legacy: bool,
) !void {
    const consumer = try get(start, "consumer_inputs");
    const files_map = try get(consumer, "files");
    const tree_map = try get(consumer, "trees");
    const tools = try get(start, "tools");
    const native = !legacy and try nativeProducer(allocator, runtime, files_map);
    const host_tools: []const []const u8 = if (legacy) &legacy_host_tools else &inputs.host_tools;
    if (files_map != .object or files_map.object.count() > 256 or
        tree_map != .object or tree_map.object.count() != 4 or
        tools != .object or tools.object.count() != host_tools.len)
        return error.InvalidInputCustody;
    var allowed: std.StringHashMap(void) = .init(allocator);
    defer allowed.deinit();
    for (host_tools) |name| {
        try notCancelled(signal);
        const role = try std.fmt.allocPrint(allocator, "tool:{s}", .{name});
        try addRole(&allowed, role);
        const entry = try get(files_map, role);
        if (!std.mem.eql(u8, try contracts.string(try get(entry, "sha256")), try contracts.string(try get(tools, name))))
            return error.RecordedCustodyChanged;
        try addRuntime(allocator, io, &allowed, try recordedPath(files_map, role));
    }
    for ([_]struct { role: []const u8, relative: []const u8 }{
        .{ .role = "command-supervisor", .relative = if (native) "controller/bin/uk-wamr-native-ci" else "compute/supervisor/bin/wamr-ci-supervisor" },
        .{ .role = "native:wamr-aot-build", .relative = "compute/tools/bin/uk-wamr-aot-build" },
        .{ .role = "native:wamr-log-validate", .relative = "compute/tools/bin/uk-wamr-log-validate" },
        .{ .role = "native:wamr-native-ci-fixtures", .relative = "compute/tools/bin/wamr-native-ci-fixtures" },
        .{ .role = "native:wamr-ci-package", .relative = "compute/tools/bin/wamr-ci-package" },
        .{ .role = "native:wamr-ci-supervisor-fixture", .relative = "compute/tools/bin/wamr-ci-supervisor-fixture" },
        .{ .role = "wamr-source-archive", .relative = "custody/wamr-source.tar" },
    }) |item| {
        if (legacy and !std.mem.eql(u8, item.role, "wamr-source-archive"))
            continue;
        if (!native and (std.mem.eql(u8, item.role, "native:wamr-native-ci-fixtures") or
            std.mem.eql(u8, item.role, "native:wamr-ci-package") or
            std.mem.eql(u8, item.role, "native:wamr-ci-supervisor-fixture")))
            continue;
        try addRole(&allowed, item.role);
        try fixedPath(allocator, files_map, item.role, runtime, item.relative);
        if (!std.mem.eql(u8, item.role, "wamr-source-archive")) {
            try notCancelled(signal);
            try addRuntime(allocator, io, &allowed, try recordedPath(files_map, item.role));
        }
    }
    try exactRoles(&allowed, files_map);
    var trees: std.StringHashMap(void) = .init(allocator);
    defer trees.deinit();
    for ([_][]const u8{ "bison", "llvm", "python-stdlib", "zig" }) |role|
        try addRole(&trees, role);
    try exactRoles(&trees, tree_map);
    try fixedPath(allocator, tree_map, "bison", runtime, "bison");
    try fixedPath(allocator, tree_map, "llvm", runtime, "llvm");
    const zig_root = std.fs.path.dirname(try recordedPath(files_map, "tool:zig")) orelse return error.UnsafePath;
    if (!std.mem.eql(u8, try recordedPath(tree_map, "zig"), zig_root))
        return error.UnexpectedInputPath;
    try notCancelled(signal);
    const expected_stdlib = try inputs.pythonStdlib(
        allocator,
        io,
        repository,
        try recordedPath(files_map, "tool:python3"),
        if (signal) |active| active.flag() else null,
    );
    defer allocator.free(expected_stdlib);
    if (!std.mem.eql(u8, try recordedPath(tree_map, "python-stdlib"), expected_stdlib))
        return error.UnexpectedInputPath;
}

fn bootRoles(
    allocator: std.mem.Allocator,
    io: std.Io,
    repository: []const u8,
    runtime: []const u8,
    boot: std.json.Value,
    native: bool,
    signal: ?*core.process.SignalCancellation,
    legacy: bool,
) !void {
    const files_map = try get(boot, "files");
    const tree_map = try get(boot, "trees");
    if (files_map != .object or files_map.object.count() > 256 or
        tree_map != .object or tree_map.object.count() != 1)
        return error.InvalidInputCustody;
    var allowed: std.StringHashMap(void) = .init(allocator);
    defer allowed.deinit();
    for ([_]struct { role: []const u8, root: []const u8, relative: []const u8 }{
        .{ .role = "efi", .root = repository, .relative = "support/apps/wamr-aot/build/wamr_hyperv-x86_64-efi" },
        .{ .role = "local_boot_tool", .root = runtime, .relative = if (native) "compute/local-boot-tools/bin/uk-hyperv-local-boot" else "compute/tools/bin/uk-hyperv-local-boot" },
        .{ .role = "log_validator", .root = runtime, .relative = "compute/tools/bin/uk-wamr-log-validate" },
        .{ .role = "package_tool", .root = runtime, .relative = "compute/tools/bin/wamr-ci-package" },
        .{ .role = "qemu", .root = runtime, .relative = "bin/qemu-system-x86_64" },
        .{ .role = "ovmf_code", .root = runtime, .relative = "firmware/code.fd" },
        .{ .role = "ovmf_vars", .root = runtime, .relative = "firmware/vars.fd" },
    }) |item| {
        if (legacy and std.mem.eql(u8, item.role, "log_validator"))
            continue;
        if (!native and std.mem.eql(u8, item.role, "log_validator") and files_map.object.get("log_validator") == null)
            continue;
        try addRole(&allowed, item.role);
        try fixedPath(allocator, files_map, item.role, item.root, item.relative);
        if (std.mem.eql(u8, item.role, "local_boot_tool") or
            std.mem.eql(u8, item.role, "log_validator") or
            std.mem.eql(u8, item.role, "package_tool") or
            std.mem.eql(u8, item.role, "qemu"))
        {
            try notCancelled(signal);
            try addRuntime(allocator, io, &allowed, try recordedPath(files_map, item.role));
        }
    }
    try exactRoles(&allowed, files_map);
    var trees: std.StringHashMap(void) = .init(allocator);
    defer trees.deinit();
    try addRole(&trees, "qemu-data");
    try exactRoles(&trees, tree_map);
    try fixedPath(allocator, tree_map, "qemu-data", runtime, "bin/share");
}

fn recapture(allocator: std.mem.Allocator, io: std.Io, expected: std.json.Value) !void {
    const files_map = try get(expected, "files");
    const tree_map = try get(expected, "trees");
    if (files_map != .object or files_map.object.count() == 0 or files_map.object.count() > 256 or
        tree_map != .object or tree_map.object.count() == 0 or tree_map.object.count() > 16)
        return error.InvalidInputCustody;
    const file_paths = try allocator.alloc(inputs.Binding, files_map.object.count());
    defer allocator.free(file_paths);
    const tree_paths = try allocator.alloc(inputs.Binding, tree_map.object.count());
    defer allocator.free(tree_paths);
    for (files_map.object.keys(), 0..) |role, i|
        file_paths[i] = .{ .role = role, .path = try recordedPath(files_map, role) };
    for (tree_map.object.keys(), 0..) |role, i|
        tree_paths[i] = .{ .role = role, .path = try recordedPath(tree_map, role) };
    var current = try inputs.capture(allocator, io, file_paths, tree_paths);
    defer current.deinit(allocator);
    const recorded = try records.canonicalAlloc(allocator, try std.json.Stringify.valueAlloc(allocator, expected, .{}));
    const observed = try current.canonical(allocator);
    if (!std.mem.eql(u8, recorded, observed)) return error.RecordedCustodyChanged;
}

fn recordedSource(
    allocator: std.mem.Allocator,
    io: std.Io,
    repository: []const u8,
    git: []const u8,
    start: std.json.Value,
    policy: SourcePolicy,
) !source.Source {
    if (policy == .compiled_producer)
        try source.verifyPhysical(io, allocator, repository);
    const current = try source.source(allocator, io, repository, git);
    try sameValue(allocator, try get(start, "source"), .{ .revision = current.revision, .tree = current.tree });
    try sameValue(allocator, try get(start, "source_custody"), current.custody);
    return current;
}

fn guardedMap(allocator: std.mem.Allocator, domain: []const u8, map: std.json.Value) !std.json.Value {
    var content = core.Sha256.init(.{});
    content.update(try std.fmt.allocPrint(allocator, "{s}-content\x00", .{domain}));
    var metadata = core.Sha256.init(.{});
    metadata.update(try std.fmt.allocPrint(allocator, "{s}-physical\x00", .{domain}));
    const names = try allocator.dupe([]const u8, map.object.keys());
    std.mem.sort([]const u8, names, {}, struct {
        fn less(_: void, first: []const u8, second: []const u8) bool {
            return std.mem.lessThan(u8, first, second);
        }
    }.less);
    var bytes: u64 = 0;
    for (names) |name| {
        const item = try get(map, name);
        const size = try contracts.integer(u64, try get(item, "bytes"));
        bytes = try std.math.add(u64, bytes, size);
        try physical.bind(allocator, &content, .{ name, size, try get(item, "sha256") });
        try physical.bind(allocator, &metadata, .{ name, try get(item, "metadata") });
    }
    return std.json.parseFromSliceLeaky(std.json.Value, allocator, try std.json.Stringify.valueAlloc(allocator, .{
        .count = names.len,
        .bytes = bytes,
        .content_closure_sha256 = physical.hex(&content),
        .physical_closure_sha256 = physical.hex(&metadata),
        .records = map,
    }, .{}), .{ .parse_numbers = false });
}

fn physicalRecord(allocator: std.mem.Allocator, io: std.Io, path: []const u8) !std.json.Value {
    const file = try physical.readFile(io, path, @import("custody_limits.zig").input_file, false);
    return std.json.parseFromSliceLeaky(std.json.Value, allocator, try std.json.Stringify.valueAlloc(allocator, .{
        .bytes = file.bytes,
        .sha256 = file.sha256,
        .metadata = file.metadata,
    }, .{}), .{ .parse_numbers = false });
}

fn recordedSupervisor(
    allocator: std.mem.Allocator,
    io: std.Io,
    repository: []const u8,
    start: std.json.Value,
    signal: ?*core.process.SignalCancellation,
) !void {
    const expected = try get(start, "command_supervisor");
    const source_map = try get(expected, "source_map");
    const names = try get(source_map, "records");
    try @import("import_supervisor_identity.zig").validateSourceNames(names);
    var current_source = std.json.Value{ .object = .empty };
    for (names.object.keys()) |name| {
        try notCancelled(signal);
        try current_source.object.put(allocator, name, try physicalRecord(allocator, io, try std.fs.path.join(allocator, &.{ repository, name })));
    }
    try sameValue(allocator, source_map, try guardedMap(allocator, "uk.wamr.command-supervisor-source-v1", current_source));
    const files_map = try get(try get(start, "consumer_inputs"), "files");
    const executable = try recordedPath(files_map, "command-supervisor");
    var current_runtime = std.json.Value{ .object = .empty };
    try current_runtime.object.put(allocator, "executable", try physicalRecord(allocator, io, executable));
    const paths = try inputs.executableRuntimePaths(allocator, io, executable);
    defer {
        for (paths) |path| allocator.free(path);
        allocator.free(paths);
    }
    for (paths) |path| {
        try notCancelled(signal);
        try current_runtime.object.put(allocator, try std.fmt.allocPrint(allocator, "runtime:{s}", .{path}), try physicalRecord(allocator, io, path));
    }
    try sameValue(allocator, try get(expected, "runtime_map"), try guardedMap(allocator, "uk.wamr.command-supervisor-runtime-v1", current_runtime));
}

pub const Fixture = if (@import("builtin").is_test) struct {
    pub fn producer(allocator: std.mem.Allocator, runtime: []const u8, files_map: std.json.Value) !bool {
        return nativeProducer(allocator, runtime, files_map);
    }

    pub fn requireBuildStartDigest(bytes: []const u8, expected: contracts.Sha256) !void {
        try buildStartDigest(bytes, expected);
    }

    pub fn requireBootInputsDigest(bytes: []const u8, expected: contracts.Sha256) !void {
        try bootInputsDigest(bytes, expected);
    }

    pub fn requirePythonStdlibTree(
        allocator: std.mem.Allocator,
        io: std.Io,
        repository: []const u8,
        files_map: std.json.Value,
        tree_map: std.json.Value,
    ) !void {
        const expected_stdlib = try inputs.pythonStdlib(
            allocator,
            io,
            repository,
            try recordedPath(files_map, "tool:python3"),
            null,
        );
        defer allocator.free(expected_stdlib);
        if (!std.mem.eql(u8, try recordedPath(tree_map, "python-stdlib"), expected_stdlib))
            return error.UnexpectedInputPath;
    }

    pub fn recaptureDocument(allocator: std.mem.Allocator, io: std.Io, expected: std.json.Value) !void {
        try recapture(allocator, io, expected);
    }

    pub fn requireRecordedSource(
        allocator: std.mem.Allocator,
        io: std.Io,
        repository: []const u8,
        git: []const u8,
        start: std.json.Value,
        read_only: bool,
    ) !source.Source {
        return recordedSource(allocator, io, repository, git, start, if (read_only) .recorded_producer else .compiled_producer);
    }

    pub fn exactRoleSet(allowed: *std.StringHashMap(void), map: std.json.Value) !void {
        try exactRoles(allowed, map);
    }

    pub fn fixedRolePath(
        allocator: std.mem.Allocator,
        map: std.json.Value,
        role: []const u8,
        root: []const u8,
        relative: []const u8,
    ) !void {
        try fixedPath(allocator, map, role, root, relative);
    }
} else struct {};

pub fn run(
    allocator: std.mem.Allocator,
    io: std.Io,
    repository: []const u8,
    runtime: []const u8,
    expected_build_start_sha256: contracts.Sha256,
    expected_boot_inputs_sha256: contracts.Sha256,
    signal: ?*core.process.SignalCancellation,
) !void {
    return runWithPolicy(allocator, io, repository, runtime, expected_build_start_sha256, expected_boot_inputs_sha256, signal, .compiled_producer, false);
}

pub fn runReadOnly(
    allocator: std.mem.Allocator,
    io: std.Io,
    repository: []const u8,
    runtime: []const u8,
    expected_build_start_sha256: contracts.Sha256,
    expected_boot_inputs_sha256: contracts.Sha256,
    signal: ?*core.process.SignalCancellation,
) !void {
    return runWithPolicy(allocator, io, repository, runtime, expected_build_start_sha256, expected_boot_inputs_sha256, signal, .recorded_producer, false);
}

pub fn runLegacyReadOnly(
    allocator: std.mem.Allocator,
    io: std.Io,
    repository: []const u8,
    runtime: []const u8,
    expected_build_start_sha256: contracts.Sha256,
    expected_boot_inputs_sha256: contracts.Sha256,
    signal: ?*core.process.SignalCancellation,
) !void {
    return runWithPolicy(allocator, io, repository, runtime, expected_build_start_sha256, expected_boot_inputs_sha256, signal, .recorded_producer, true);
}

fn runWithPolicy(
    allocator: std.mem.Allocator,
    io: std.Io,
    repository: []const u8,
    runtime: []const u8,
    expected_build_start_sha256: contracts.Sha256,
    expected_boot_inputs_sha256: contracts.Sha256,
    signal: ?*core.process.SignalCancellation,
    policy: SourcePolicy,
    legacy: bool,
) !void {
    try files.absoluteFilePath(repository);
    try files.absoluteFilePath(runtime);
    const root = try files.openDirectory(io, runtime, .private);
    defer root.close(io);
    const start_path = try std.fs.path.join(allocator, &.{ runtime, "compute/evidence/build-start.json" });
    var pinned_start = try files.RetainedFile.open(io, start_path, .private);
    defer pinned_start.close(io);
    var start_bytes = try files.readSensitiveFile(io, allocator, pinned_start.file, records.max_record_bytes, .private);
    defer start_bytes.deinit();
    try buildStartDigest(start_bytes.bytes(), expected_build_start_sha256);
    var start_doc = try contracts.Document.parse(allocator, start_bytes.bytes(), .{
        .bytes = records.max_record_bytes,
        .depth = 32,
        .items = 4096,
        .tokens = 65536,
    });
    defer start_doc.deinit();
    try start_doc.requireCanonical(allocator, start_bytes.bytes());
    const start = start_doc.value();
    _ = try contracts.exactFields(start, if (legacy)
        &.{ "source", "source_custody", "tools", "bison_data", "dependencies", "consumer_inputs" }
    else
        &.{ "source", "source_custody", "tools", "bison_data", "dependencies", "consumer_inputs", "command_supervisor" });
    const boot_path = try std.fs.path.join(allocator, &.{ runtime, "compute/evidence/boot-inputs.json" });
    var pinned_boot = try files.RetainedFile.open(io, boot_path, .private);
    defer pinned_boot.close(io);
    var boot_bytes = try files.readSensitiveFile(io, allocator, pinned_boot.file, records.max_record_bytes, .private);
    defer boot_bytes.deinit();
    try bootInputsDigest(boot_bytes.bytes(), expected_boot_inputs_sha256);
    var boot_doc = try contracts.Document.parse(allocator, boot_bytes.bytes(), .{
        .bytes = records.max_record_bytes,
        .depth = 32,
        .items = 4096,
        .tokens = 65536,
    });
    defer boot_doc.deinit();
    try boot_doc.requireCanonical(allocator, boot_bytes.bytes());
    const boot = boot_doc.value();
    const consumer = try get(start, "consumer_inputs");
    const git_path = try recordedPath(try get(consumer, "files"), "tool:git");
    var git = try files.RetainedFile.open(io, git_path, .tool);
    defer git.close(io);
    try notCancelled(signal);
    const before = try recordedSource(allocator, io, repository, git_path, start, policy);
    try buildRoles(allocator, io, repository, runtime, start, signal, legacy);
    try bootRoles(allocator, io, repository, runtime, boot, !legacy and try nativeProducer(allocator, runtime, try get(consumer, "files")), signal, legacy);
    try notCancelled(signal);
    var dependency = try dependencies.capture(allocator, io, repository, git_path, try std.fs.path.join(allocator, &.{ runtime, "compute" }));
    defer dependency.deinit(allocator);
    try sameValue(allocator, try get(start, "dependencies"), try std.json.parseFromSliceLeaky(std.json.Value, allocator, try dependency.canonical(allocator), .{ .parse_numbers = false }));
    try notCancelled(signal);
    try sameValue(allocator, try get(start, "bison_data"), try inputs.bison(allocator, io, try std.fs.path.join(allocator, &.{ runtime, "bison" })));
    if (!legacy) try recordedSupervisor(allocator, io, repository, start, signal);
    try notCancelled(signal);
    try recapture(allocator, io, consumer);
    try notCancelled(signal);
    try recapture(allocator, io, boot);
    try notCancelled(signal);
    const after = try recordedSource(allocator, io, repository, git_path, start, policy);
    if (!before.same(after)) return error.SourceChanged;
    try pinned_start.verify(io);
    try pinned_boot.verify(io);
    try git.verify(io);
}
