const std = @import("std");
pub const p = @import("preparation");
pub const c = p.contracts;
pub const fs = p.files;
pub const rt = p.runtime;
pub const ns = p.namespace;
pub const private = c.core.private_files;
pub const Sha = c.Sha;
pub const maximum_document = 4 * 1024 * 1024;

pub const ToolSpec = struct {
    directory: []const u8,
    role: rt.Role,
    target: @FieldType(rt.Tool, "target"),
    executable: ?[]const u8,
    loader: ?[]const u8,
    libraries: []const []const u8,
    origin: rt.Origin,
};
pub const Locations = struct {
    repository: []const u8,
    producer: []const u8,
    compiler: []const u8,
    git: []const u8,
    trust: []const u8,
    dependencies: []const struct { name: []const u8, directory: []const u8 },
    git_scratch: []const u8,
};
pub const Spec = struct {
    schema: enum { hyperv_native_integration_spec_v1 },
    repository: []const u8,
    actor_directory: []const u8,
    facade_runtime: []const u8,
    guard: p.config.Guard,
    initial_config: ?[]const u8,
    initial_metadata: ?[]const u8,
    native: []const struct { name: p.producer.Alias, tool: ToolSpec },
    git: ToolSpec,
    packages: ToolSpec,
    bison_data: ToolSpec,
    trust: ToolSpec,
    trust_bundle: []const u8,
    dependencies: []const struct { name: []const u8, package_hash: []const u8, origin: rt.Origin },
};
pub const Bundle = struct {
    schema: enum { hyperv_native_integration_material_v1 },
    authority: enum { not_admitted },
    guard: p.config.Guard,
    provenance: p.provenance.Record,
    initial_metadata: ?c.File,
    locations: Locations,
    binding: p.producer.Binding,
};
pub const Phase = enum { prepare, configure, build, package, generate };
pub const Stage = struct {
    schema: enum { hyperv_native_integration_stage_v1 },
    authority: enum { not_admitted },
    phase: enum { configure, build },
    bootstrap_sha256: Sha,
    parent_sha256: Sha,
    execution: p.producer.Binding,
    inspection: p.producer.Binding,
    inspection_basis: enum { externally_supplied_expected_config, unchanged_built_config },
};
pub const Review = struct {
    schema: enum { hyperv_native_integration_review_v1 },
    phase: Phase,
    material_sha256: Sha,
    provenance_sha256: Sha,
    parent_sha256: ?Sha,
    execution_sha256: ?Sha,
    inspection_sha256: ?Sha,
    selection_sha256: ?Sha,
    capability_provenance_sha256: ?Sha,

    pub fn validate(self: Review, phase: Phase) !void {
        if (self.phase != phase) return error.WrongPhase;
        _ = try c.sha(&self.material_sha256);
        _ = try c.sha(&self.provenance_sha256);
        inline for (.{ "parent_sha256", "execution_sha256", "inspection_sha256", "selection_sha256", "capability_provenance_sha256" }) |name| {
            if (@field(self, name)) |hash| _ = try c.sha(&hash);
        }
        const execution = phase == .configure or phase == .build;
        if ((self.parent_sha256 != null) != (phase != .prepare) or
            (self.execution_sha256 != null) != execution or
            (self.inspection_sha256 != null) != execution or
            (self.selection_sha256 != null) != (phase == .generate) or
            (self.capability_provenance_sha256 != null) != (phase == .generate))
            return error.InvalidReview;
    }
};

pub fn synthetic(guard: p.config.Guard) !void {
    try p.config.validateGuardPurpose(guard, .synthetic);
    if (guard.sectors > 4096 or guard.lun != 0) return error.NonSyntheticInput;
}

pub fn inspectionBinding(binding: p.producer.Binding, expected: c.File) !p.producer.Binding {
    var result = binding;
    result.config = try inspectionConfig(binding.config, expected);
    return result;
}

pub fn inspectionConfig(current: c.File, expected: c.File) !c.File {
    if (expected.mode != 0o600 or expected.size == 0 or expected.size > p.config.config_cap)
        return error.InvalidInspectionExpectation;
    _ = try c.sha(&expected.sha256);
    var result = expected;
    result.path = current.path;
    return result;
}

pub const World = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    deadline: c.core.process.Deadline,
    failures: c.Failure = .{},
    directories: std.ArrayList(fs.Directory) = .empty,

    pub fn deinit(self: *World) void {
        for (self.directories.items) |directory| directory.close(self.allocator, self.io);
        self.directories.deinit(self.allocator);
    }
    pub fn open(self: *World, path: []const u8) !fs.Directory {
        for (self.directories.items) |directory|
            if (std.mem.eql(u8, path, directory.path)) return directory;
        if (self.directories.items.len >= 1024) return error.LimitExceeded;
        const directory = try fs.Directory.open(self.allocator, self.io, path);
        errdefer directory.close(self.allocator, self.io);
        try self.directories.append(self.allocator, directory);
        return directory;
    }
    pub fn child(self: *World, parent: fs.Directory, name: []const u8) !fs.Directory {
        try c.relative(name);
        return self.open(try std.fs.path.join(self.allocator, &.{ parent.path, name }));
    }
    pub fn state(self: *World, directory: fs.Directory) !private.Directory {
        const validated = try private.Directory.open(self.io, directory.path);
        defer validated.close(self.io);
        if (!std.meta.eql(try fs.metadata(.{ .handle = validated.dir.handle, .flags = .{ .nonblocking = false } }), try fs.metadata(.{ .handle = directory.dir.handle, .flags = .{ .nonblocking = false } })))
            return error.SourceChanged;
        return .{ .dir = directory.dir };
    }
    pub fn merge(self: *World, failures: c.Failure) !void {
        inline for (.{ "primary", "cleanup", "recording" }) |name|
            if (@field(failures, name)) |value| {
                if (@field(self.failures, name) == null) @field(self.failures, name) = value;
            };
    }
    pub fn read(self: *World, comptime T: type, directory: fs.Directory, name: []const u8, expected: ?Sha) !struct { value: T, sha256: Sha } {
        _ = try self.state(directory);
        const bytes = try directory.read(self.allocator, self.io, name, maximum_document, .private);
        const hash = c.digest(bytes);
        if (expected) |wanted| if (!std.meta.eql(hash, wanted)) return error.UnreviewedInput;
        const parsed = try c.parse(T, self.allocator, bytes);
        return .{ .value = parsed.value, .sha256 = hash };
    }
    pub fn publish(self: *World, lock: *private.Locked, name: []const u8, value: anytype) !c.File {
        const bytes = try c.canonical(self.allocator, value);
        const result = try fs.publish(lock, self.io, name, bytes);
        try self.merge(result.failures);
        if (result.status != .durable or result.failures.primary != null or result.failures.cleanup != null or result.failures.recording != null)
            return error.PublicationIncomplete;
        return .{ .path = name, .size = bytes.len, .sha256 = c.digest(bytes), .mode = 0o600 };
    }
    pub fn tool(self: *World, spec: ToolSpec) !rt.Bound {
        if (spec.libraries.len > 256) return error.LimitExceeded;
        const directory = try self.open(spec.directory);
        const library = try self.allocator.alloc(c.File, spec.libraries.len);
        for (spec.libraries, library) |path, *file|
            file.* = try directory.record(self.allocator, self.io, path, 256 * 1024 * 1024, .artifact);
        const bound: rt.Bound = .{ .directory = directory, .contract = .{
            .role = spec.role,
            .target = spec.target,
            .origin = spec.origin,
            .tree = (try fs.inventory(self.allocator, self.io, directory, 100000, 4 * 1024 * 1024 * 1024)).tree,
            .executable = if (spec.executable) |path| try directory.record(self.allocator, self.io, path, 1024 * 1024 * 1024, .executable) else null,
            .loader = if (spec.loader) |path| try directory.record(self.allocator, self.io, path, 64 * 1024 * 1024, .executable) else null,
            .libraries = library,
        } };
        try bound.validate(self.allocator, self.io);
        return bound;
    }
    pub fn git(self: *World, bound: rt.Bound, scratch: []const u8) !*rt.Git {
        const result = try self.allocator.create(rt.Git);
        result.* = .{
            .allocator = self.allocator,
            .io = self.io,
            .runtime = bound,
            .deadline = self.deadline,
            .environment = .{ .scratch = scratch, .path = try std.fs.path.join(self.allocator, &.{ bound.directory.path, "bin" }) },
        };
        return result;
    }
    pub fn provenanceBindings(self: *World, locations: Locations) !p.provenance.Bindings {
        const dependencies = try self.allocator.alloc(p.provenance.Dependencies, locations.dependencies.len);
        for (locations.dependencies, dependencies) |item, *bound|
            bound.* = .{ .name = item.name, .directory = try self.open(item.directory) };
        return .{
            .producer = try self.open(locations.producer),
            .compiler = try self.open(locations.compiler),
            .git = try self.open(locations.git),
            .trust = try self.open(locations.trust),
            .dependencies = dependencies,
        };
    }
    pub fn context(self: *World, bundle: Bundle, reviewed: Sha) !p.receipts.Context {
        try synthetic(bundle.guard);
        const bindings = try self.provenanceBindings(bundle.locations);
        const result: p.receipts.Context = .{
            .allocator = self.allocator,
            .io = self.io,
            .repository = try self.open(bundle.locations.repository),
            .git = try self.git(.{ .directory = bindings.git, .contract = bundle.provenance.git }, bundle.locations.git_scratch),
            .review = bundle.provenance,
            .bindings = bindings,
            .reviewed_provenance_sha256 = reviewed,
            .guard = bundle.guard,
            .purpose = .synthetic,
            .configuration_directory = try self.open(bundle.binding.workspace.path),
        };
        try self.requireActor(.{ .directory = bindings.producer, .contract = bundle.provenance.producer });
        return result;
    }
    pub fn metadata(self: *World, bundle: Bundle) !?p.config.Metadata {
        const expected = bundle.initial_metadata orelse return null;
        const requests = try self.child(try self.open(bundle.binding.workspace.path), "requests");
        try fs.requireFile(try requests.record(self.allocator, self.io, expected.path, p.config.config_cap, .private), expected);
        const bytes = try requests.read(self.allocator, self.io, expected.path, p.config.config_cap, .private);
        return try p.config.Metadata.parse(self.allocator, bytes);
    }
    pub fn requireActor(self: *World, actor: rt.Bound) !void {
        const actual = try std.Io.Dir.openFileAbsolute(self.io, "/proc/self/exe", .{});
        defer actual.close(self.io);
        const selected = try actor.directory.openFile(self.io, (actor.contract.executable orelse return error.InvalidRuntime).path, .executable);
        defer selected.close(self.io);
        if (!std.meta.eql(try fs.metadata(actual), try fs.metadata(selected))) return error.WrongPhysicalActor;
    }
    pub fn receipt(self: *World, directory: fs.Directory, phase: c.Phase, expected: Sha) !p.receipts.Link {
        const name = try std.fmt.allocPrint(self.allocator, "{s}.receipt.json", .{@tagName(phase)});
        const record = try self.read(p.receipts.Receipt, directory, name, expected);
        const result: p.receipts.Link = .{ .receipt = record.value, .sha256 = record.sha256 };
        try p.receipts.requireLink(self.allocator, result);
        return result;
    }
    pub fn inputs(self: *World, binding: p.producer.Binding) !p.producer.Inputs {
        try p.producer.validateBindingStructure(self.allocator, binding);
        const value = try p.producer.reopenBinding(self.allocator, self.io, binding);
        // reopenBinding returns owned descriptors; retain them for this command.
        for (value.tools.native) |native| try self.directories.append(self.allocator, native.bound.directory);
        for ([_]fs.Directory{ value.repository, value.workspace.directory, value.workspace.output, value.workspace.scratch, value.tools.git.directory, value.tools.packages.directory, value.tools.bison_data.directory, value.tools.trust.directory }) |directory|
            try self.directories.append(self.allocator, directory);
        if (value.tools.path) |directory| try self.directories.append(self.allocator, directory);
        if (value.isolation) |isolation| {
            try self.directories.append(self.allocator, isolation.helper.directory);
            try self.directories.append(self.allocator, isolation.facade_runtime);
            for (isolation.git_metadata) |tree| try self.directories.append(self.allocator, tree.directory);
        }
        return value;
    }
};
