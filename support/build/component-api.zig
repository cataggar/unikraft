// SPDX-License-Identifier: BSD-3-Clause

//! Typed metadata for Unikraft's prospective native Zig build graph.
//!
//! This API models registrations only. It intentionally does not execute tools
//! or compile sources. Registrations preserve insertion order because that
//! order can affect partial and final linking.

const std = @import("std");

pub const ConfigQuery = struct {
    context: ?*const anyopaque = null,
    is_enabled_fn: *const fn (?*const anyopaque, []const u8) bool,
    value_fn: *const fn (?*const anyopaque, []const u8) ?[]const u8,

    pub fn isEnabled(self: ConfigQuery, name: []const u8) bool {
        return self.is_enabled_fn(self.context, name);
    }

    pub fn value(self: ConfigQuery, name: []const u8) ?[]const u8 {
        return self.value_fn(self.context, name);
    }
};

pub const Condition = union(enum) {
    always,
    config_enabled: []const u8,
    config_disabled: []const u8,
    config_equals: ConfigEquals,

    pub const ConfigEquals = struct {
        name: []const u8,
        value: []const u8,
    };

    pub fn matches(self: Condition, config: ConfigQuery) bool {
        return switch (self) {
            .always => true,
            .config_enabled => |name| config.isEnabled(name),
            .config_disabled => |name| !config.isEnabled(name),
            .config_equals => |expected| if (config.value(expected.name)) |actual|
                std.mem.eql(u8, actual, expected.value)
            else
                false,
        };
    }
};

pub const Architecture = enum {
    x86_64,
    arm64,
    arm32,
    riscv64,
    other,
};

pub const ArchitectureFamily = enum {
    x86,
    arm,
    riscv,
    other,
};

pub const Target = struct {
    architecture: Architecture,
    family: ArchitectureFamily,
    abi: []const u8,
    triple: []const u8,
};

pub const SourceLanguage = enum {
    c,
    cpp,
    assembler,
    rust,
    linker_script,
    dts,
    generated,
    no_op,
};

pub const IncludeKind = enum {
    normal,
    system,
    quote,
};

pub const Include = struct {
    path: []const u8,
    kind: IncludeKind = .normal,
    languages: []const SourceLanguage = &.{},
};

pub const FlagSet = struct {
    common: []const []const u8 = &.{},
    c: []const []const u8 = &.{},
    cpp: []const []const u8 = &.{},
    assembler: []const []const u8 = &.{},
    rust: []const []const u8 = &.{},
    linker: []const []const u8 = &.{},
};

pub const CompilerKind = enum {
    gcc,
    clang,
    zig_cc,
    other,
};

pub const LinkerKind = enum {
    bfd,
    gold,
    lld,
    mold,
    compiler_driver,
    other,
};

pub const PartialLinkMode = enum {
    driver,
    raw,
};

pub const ToolCapability = enum {
    response_files,
    thin_archives,
    linker_script_insert,
    relocatable_link,
    gc_sections,
    build_id,
    target_flag,
};

pub const ToolRole = enum {
    compiler_driver,
    partial_linker,
    final_linker,
    archiver,
    objcopy,
    strip,
    nm,
    objdump,
    host_cc,
    host_cxx,
    awk,
    m4,
    dtc,
    python,
};

pub const VersionRelation = enum {
    less_than,
    at_least,
    exactly,
};

pub const VersionPredicate = struct {
    role: ToolRole,
    relation: VersionRelation,
    version: std.SemanticVersion,
};

pub const Tool = struct {
    command: []const u8,
    version: ?std.SemanticVersion = null,
};

pub const CompilerDriver = struct {
    tool: Tool,
    kind: CompilerKind,
    already_targets_triple: bool = false,
};

pub const PartialLinker = struct {
    tool: Tool,
    kind: LinkerKind,
    mode: PartialLinkMode,
};

pub const FinalLinker = struct {
    tool: Tool,
    kind: LinkerKind,
};

pub const Binutils = struct {
    ar: Tool,
    objcopy: Tool,
    strip: Tool,
    nm: Tool,
    objdump: ?Tool = null,
};

pub const HostTools = struct {
    cc: ?Tool = null,
    cxx: ?Tool = null,
    awk: ?Tool = null,
    m4: ?Tool = null,
    dtc: ?Tool = null,
    python: ?Tool = null,
};

pub const Toolchain = struct {
    target_triple: []const u8,
    compiler: CompilerDriver,
    partial_linker: PartialLinker,
    final_linker: FinalLinker,
    binutils: Binutils,
    host: HostTools = .{},
    capabilities: []const ToolCapability = &.{},

    pub fn hasCapability(self: Toolchain, wanted: ToolCapability) bool {
        for (self.capabilities) |capability| {
            if (capability == wanted) return true;
        }
        return false;
    }

    pub fn satisfies(self: Toolchain, predicate: VersionPredicate) bool {
        const actual = self.versionFor(predicate.role) orelse return false;
        return switch (predicate.relation) {
            .less_than => actual.order(predicate.version) == .lt,
            .at_least => actual.order(predicate.version) != .lt,
            .exactly => actual.order(predicate.version) == .eq,
        };
    }

    pub fn versionFor(self: Toolchain, role: ToolRole) ?std.SemanticVersion {
        return switch (role) {
            .compiler_driver => self.compiler.tool.version,
            .partial_linker => self.partial_linker.tool.version,
            .final_linker => self.final_linker.tool.version,
            .archiver => self.binutils.ar.version,
            .objcopy => self.binutils.objcopy.version,
            .strip => self.binutils.strip.version,
            .nm => self.binutils.nm.version,
            .objdump => if (self.binutils.objdump) |tool| tool.version else null,
            .host_cc => if (self.host.cc) |tool| tool.version else null,
            .host_cxx => if (self.host.cxx) |tool| tool.version else null,
            .awk => if (self.host.awk) |tool| tool.version else null,
            .m4 => if (self.host.m4) |tool| tool.version else null,
            .dtc => if (self.host.dtc) |tool| tool.version else null,
            .python => if (self.host.python) |tool| tool.version else null,
        };
    }
};

pub const Roots = struct {
    base: []const u8,
    app: []const u8,
    output: []const u8,
    config: []const u8,
};

pub const InternalCategory = enum {
    architecture,
    core,
    driver,
    library,
    platform,
    application,
};

pub const Origin = union(enum) {
    internal: InternalCategory,
    external: External,

    pub const External = struct {
        package_name: []const u8,
        root: []const u8,
    };
};

pub const SubBuildLayout = union(enum) {
    ordinary: Ordinary,
    tree: Tree,

    pub const Ordinary = struct {
        build_subdir: []const u8,
    };

    pub const Tree = struct {
        build_subdir: []const u8,
        source_root: []const u8,
    };
};

pub const ComponentKind = enum {
    library,
    platform_library,
};

pub const DependencyKind = enum {
    build,
    link,
    runtime,
};

pub const ComponentDependency = struct {
    name: []const u8,
    kind: DependencyKind = .build,
    condition: Condition = .always,
};

pub const RegisteredArtifact = struct {
    path: []const u8,
    condition: Condition = .always,
};

pub const Dependency = union(enum) {
    file: []const u8,
    generated_output: []const u8,
    component: []const u8,
};

pub const PreprocessKind = union(enum) {
    awk,
    m4,
    generated,
    custom: []const u8,
};

pub const PreprocessStep = struct {
    name: []const u8,
    kind: PreprocessKind,
    output: []const u8,
    condition: Condition = .always,
    flags: []const []const u8 = &.{},
    includes: []const []const u8 = &.{},
    dependencies: []const Dependency = &.{},
    subbuild: ?[]const u8 = null,
};

pub const VariantName = union(enum) {
    default,
    isr,
    named: []const u8,

    pub fn eql(a: VariantName, b: VariantName) bool {
        if (std.meta.activeTag(a) != std.meta.activeTag(b)) return false;
        return switch (a) {
            .default, .isr => true,
            .named => |name| std.mem.eql(u8, name, b.named),
        };
    }
};

pub const SourceOutputKind = enum {
    object,
    linker_script,
    device_tree_blob,
    generated,
    no_op,
};

pub const SourceOutput = struct {
    path: []const u8,
    kind: SourceOutputKind,
    dependency_file: ?[]const u8 = null,
};

pub const SourceVariant = struct {
    name: VariantName = .default,
    condition: Condition = .always,
    flags: FlagSet = .{},
    includes: []const Include = &.{},
    dependencies: []const Dependency = &.{},
    subbuild: ?[]const u8 = null,
    preprocess: []const PreprocessStep = &.{},
    output: ?SourceOutput = null,
};

pub const Source = struct {
    name: []const u8,
    path: []const u8,
    language: SourceLanguage,
    condition: Condition = .always,
    flags: FlagSet = .{},
    includes: []const Include = &.{},
    dependencies: []const Dependency = &.{},
    subbuild: ?[]const u8 = null,
    preprocess: []const PreprocessStep = &.{},
    variants: []const SourceVariant = &.{},

    pub fn effectiveInput(self: Source, variant: SourceVariant) []const u8 {
        if (lastPreprocessOutput(variant.preprocess)) |output| return output;
        if (lastPreprocessOutput(self.preprocess)) |output| return output;
        return self.path;
    }
};

fn lastPreprocessOutput(steps: []const PreprocessStep) ?[]const u8 {
    if (steps.len == 0) return null;
    return steps[steps.len - 1].output;
}

pub const LibrarySpec = struct {
    name: []const u8,
    kind: ComponentKind = .library,
    origin: Origin,
    enable: Condition = .always,
    layout: SubBuildLayout,
    platforms: []const []const u8 = &.{},
    dependencies: []const ComponentDependency = &.{},
    exports: []const []const u8 = &.{},
    locals: []const []const u8 = &.{},
    archives: []const RegisteredArtifact = &.{},
    raw_objects: []const RegisteredArtifact = &.{},
    custom_link_dependencies: []const RegisteredArtifact = &.{},
    linker_scripts: []const RegisteredArtifact = &.{},
    sources: []const Source = &.{},
};

pub const Library = LibrarySpec;
pub const ComponentSpec = LibrarySpec;
pub const Component = Library;

pub const ArtifactReference = union(enum) {
    path: []const u8,
    generated_output: []const u8,
    component_output: ComponentOutput,
    stage_output: StageOutput,

    pub const ComponentOutput = struct {
        component: []const u8,
        path: []const u8,
    };

    pub const StageOutput = struct {
        platform: []const u8,
        stage: []const u8,
    };
};

pub const LinkInputKind = enum {
    object,
    archive,
    linker_script,
    intermediate,
    custom_link_dependency,
};

pub const LinkInput = struct {
    kind: LinkInputKind,
    artifact: ArtifactReference,
};

pub const LinkTransformation = union(enum) {
    partial_link,
    objcopy_localize,
    final_link,
    custom: []const u8,
};

pub const LinkStage = struct {
    name: []const u8,
    transformation: LinkTransformation,
    output: []const u8,
    condition: Condition = .always,
    inputs: []const LinkInput = &.{},
    flags: []const []const u8 = &.{},
};

pub const PostProcessKind = union(enum) {
    strip,
    symbols,
    bootinfo,
    multiboot,
    efi,
    linux_header,
    compile_database,
    custom: []const u8,
};

pub const PostProcessArtifact = struct {
    name: []const u8,
    kind: PostProcessKind,
    input: ArtifactReference,
    output: []const u8,
    condition: Condition = .always,
};

pub const PlatformSpec = struct {
    name: []const u8,
    origin: Origin,
    enable: Condition = .always,
    linker_definition: ?[]const u8 = null,
    libraries: []const []const u8 = &.{},
    object_inputs: []const ArtifactReference = &.{},
    archive_inputs: []const ArtifactReference = &.{},
    linker_scripts: []const ArtifactReference = &.{},
    custom_link_dependencies: []const ArtifactReference = &.{},
    link_stages: []const LinkStage = &.{},
    post_process: []const PostProcessArtifact = &.{},
};

pub const Platform = PlatformSpec;

pub const RegistrationError = error{
    OutOfMemory,
    AlreadyFinalized,
    DuplicateLibrary,
    DuplicatePlatform,
    ConflictingRegistration,
};

pub const ValidationError = error{
    OutOfMemory,
    NoSelectedPlatform,
    MultipleSelectedPlatforms,
    DuplicateName,
    DuplicateOutput,
    InvalidReference,
    ConflictingRegistration,
    InvalidModel,
};

pub const InitOptions = struct {
    roots: Roots,
    target: Target,
    toolchain: Toolchain,
    global_flags: FlagSet = .{},
    global_includes: []const Include = &.{},
    config: ConfigQuery,
};

pub const RegistrationKind = enum {
    component,
    platform,
};

pub const Registration = struct {
    order: usize,
    kind: RegistrationKind,
    name: []const u8,
};

pub const FinalizedGraph = struct {
    roots: Roots,
    target: Target,
    toolchain: Toolchain,
    global_flags: FlagSet,
    global_includes: []const Include,
    libraries: []const Library,
    platforms: []const Platform,
    registrations: []const Registration,
    selected_platform_index: usize,

    pub fn selectedPlatform(self: FinalizedGraph) *const Platform {
        return &self.platforms[self.selected_platform_index];
    }
};

pub const BuildContext = struct {
    allocator: std.mem.Allocator,
    arena: *std.heap.ArenaAllocator,
    roots: Roots,
    target: Target,
    toolchain: Toolchain,
    global_flags: FlagSet,
    global_includes: []const Include,
    config: ConfigQuery,
    libraries: std.array_list.Managed(Library),
    platforms: std.array_list.Managed(Platform),
    registrations: std.array_list.Managed(Registration),
    finalized: bool = false,
    diagnostic: ?[]const u8 = null,

    pub fn init(allocator: std.mem.Allocator, options: InitOptions) !BuildContext {
        const arena = try allocator.create(std.heap.ArenaAllocator);
        errdefer allocator.destroy(arena);
        arena.* = std.heap.ArenaAllocator.init(allocator);
        errdefer arena.deinit();
        const owned = arena.allocator();
        return .{
            .allocator = allocator,
            .arena = arena,
            .roots = try copyRoots(owned, options.roots),
            .target = try copyTarget(owned, options.target),
            .toolchain = try copyToolchain(owned, options.toolchain),
            .global_flags = try copyFlagSet(owned, options.global_flags),
            .global_includes = try copyIncludes(owned, options.global_includes),
            .config = options.config,
            .libraries = std.array_list.Managed(Library).init(allocator),
            .platforms = std.array_list.Managed(Platform).init(allocator),
            .registrations = std.array_list.Managed(Registration).init(allocator),
        };
    }

    pub fn deinit(self: *BuildContext) void {
        self.libraries.deinit();
        self.platforms.deinit();
        self.registrations.deinit();
        self.arena.deinit();
        self.allocator.destroy(self.arena);
        self.* = undefined;
    }

    pub fn registerLibrary(self: *BuildContext, spec: LibrarySpec) RegistrationError!void {
        if (self.finalized) {
            try self.setDiagnostic("cannot register library '{s}' after finalize", .{spec.name});
            return error.AlreadyFinalized;
        }
        if (self.findLibrary(spec.name) != null) {
            try self.setDiagnostic("duplicate library registration for '{s}'", .{spec.name});
            return error.DuplicateLibrary;
        }
        if (self.findPlatform(spec.name) != null) {
            try self.setDiagnostic(
                "component '{s}' conflicts with an existing platform of the same name",
                .{spec.name},
            );
            return error.ConflictingRegistration;
        }
        self.libraries.ensureUnusedCapacity(1) catch return error.OutOfMemory;
        self.registrations.ensureUnusedCapacity(1) catch return error.OutOfMemory;
        const library = copyLibrary(self.arena.allocator(), spec) catch return error.OutOfMemory;
        self.libraries.appendAssumeCapacity(library);
        self.registrations.appendAssumeCapacity(.{
            .order = self.registrations.items.len,
            .kind = .component,
            .name = library.name,
        });
    }

    pub fn registerComponent(self: *BuildContext, spec: ComponentSpec) RegistrationError!void {
        return self.registerLibrary(spec);
    }

    pub fn registerPlatform(self: *BuildContext, spec: PlatformSpec) RegistrationError!void {
        if (self.finalized) {
            try self.setDiagnostic("cannot register platform '{s}' after finalize", .{spec.name});
            return error.AlreadyFinalized;
        }
        if (self.findPlatform(spec.name) != null) {
            try self.setDiagnostic("duplicate platform registration for '{s}'", .{spec.name});
            return error.DuplicatePlatform;
        }
        if (self.findLibrary(spec.name) != null) {
            try self.setDiagnostic(
                "platform '{s}' conflicts with an existing component of the same name",
                .{spec.name},
            );
            return error.ConflictingRegistration;
        }
        self.platforms.ensureUnusedCapacity(1) catch return error.OutOfMemory;
        self.registrations.ensureUnusedCapacity(1) catch return error.OutOfMemory;
        const platform = copyPlatform(self.arena.allocator(), spec) catch return error.OutOfMemory;
        self.platforms.appendAssumeCapacity(platform);
        self.registrations.appendAssumeCapacity(.{
            .order = self.registrations.items.len,
            .kind = .platform,
            .name = platform.name,
        });
    }

    pub fn finalize(self: *BuildContext) ValidationError!FinalizedGraph {
        self.diagnostic = null;
        try self.validateLibraries();
        try self.validatePlatforms();
        try self.validateOutputs();

        var selected_index: ?usize = null;
        for (self.platforms.items, 0..) |platform, index| {
            if (!platform.enable.matches(self.config)) continue;
            if (selected_index != null) {
                try self.setDiagnostic(
                    "multiple platforms are selected ('{s}' and '{s}'); exactly one platform must be enabled",
                    .{ self.platforms.items[selected_index.?].name, platform.name },
                );
                return error.MultipleSelectedPlatforms;
            }
            selected_index = index;
        }
        if (selected_index == null) {
            try self.setDiagnostic("no platform is selected; exactly one platform must be enabled", .{});
            return error.NoSelectedPlatform;
        }

        self.finalized = true;
        return .{
            .roots = self.roots,
            .target = self.target,
            .toolchain = self.toolchain,
            .global_flags = self.global_flags,
            .global_includes = self.global_includes,
            .libraries = self.libraries.items,
            .platforms = self.platforms.items,
            .registrations = self.registrations.items,
            .selected_platform_index = selected_index.?,
        };
    }

    pub fn lastDiagnostic(self: BuildContext) ?[]const u8 {
        return self.diagnostic;
    }

    fn findLibrary(self: BuildContext, name: []const u8) ?usize {
        for (self.libraries.items, 0..) |library, index| {
            if (std.mem.eql(u8, library.name, name)) return index;
        }
        return null;
    }

    fn findPlatform(self: BuildContext, name: []const u8) ?usize {
        for (self.platforms.items, 0..) |platform, index| {
            if (std.mem.eql(u8, platform.name, name)) return index;
        }
        return null;
    }

    fn validateLibraries(self: *BuildContext) ValidationError!void {
        for (self.libraries.items) |library| {
            if (library.name.len == 0) {
                try self.setDiagnostic("library names cannot be empty", .{});
                return error.InvalidModel;
            }
            if (library.kind == .platform_library and library.platforms.len == 0) {
                try self.setDiagnostic(
                    "platform library '{s}' must name at least one platform",
                    .{library.name},
                );
                return error.ConflictingRegistration;
            }
            for (library.platforms, 0..) |platform_name, index| {
                if (containsString(library.platforms[0..index], platform_name)) {
                    try self.setDiagnostic(
                        "library '{s}' repeats platform registration '{s}'",
                        .{ library.name, platform_name },
                    );
                    return error.DuplicateName;
                }
            }
            try self.validateUniqueSourceNames(library);
            for (library.platforms) |platform_name| {
                const platform_index = self.findPlatform(platform_name) orelse {
                    try self.setDiagnostic(
                        "library '{s}' references unknown platform '{s}'",
                        .{ library.name, platform_name },
                    );
                    return error.InvalidReference;
                };
                if (!containsString(self.platforms.items[platform_index].libraries, library.name)) {
                    try self.setDiagnostic(
                        "platform library '{s}' names platform '{s}', but the platform does not register that library",
                        .{ library.name, platform_name },
                    );
                    return error.ConflictingRegistration;
                }
            }
            for (library.dependencies) |dependency| {
                if (self.findLibrary(dependency.name) == null) {
                    try self.setDiagnostic(
                        "library '{s}' depends on unknown library '{s}'",
                        .{ library.name, dependency.name },
                    );
                    return error.InvalidReference;
                }
            }
            for (library.sources) |source| {
                try self.validateSource(library, source);
            }
        }
    }

    fn validateUniqueSourceNames(self: *BuildContext, library: Library) ValidationError!void {
        for (library.sources, 0..) |source, index| {
            for (library.sources[0..index]) |previous| {
                if (std.mem.eql(u8, previous.name, source.name)) {
                    try self.setDiagnostic(
                        "library '{s}' registers source name '{s}' more than once",
                        .{ library.name, source.name },
                    );
                    return error.DuplicateName;
                }
            }
        }
    }

    fn validateSource(self: *BuildContext, library: Library, source: Source) ValidationError!void {
        if (source.name.len == 0 or source.path.len == 0) {
            try self.setDiagnostic(
                "library '{s}' has a source with an empty name or path",
                .{library.name},
            );
            return error.InvalidModel;
        }
        try self.validatePreprocess(library.name, source.name, "source", source.preprocess);
        for (source.variants, 0..) |variant, index| {
            for (source.variants[0..index]) |previous| {
                if (previous.name.eql(variant.name)) {
                    try self.setDiagnostic(
                        "library '{s}' source '{s}' registers the same variant more than once",
                        .{ library.name, source.name },
                    );
                    return error.DuplicateName;
                }
            }
            try self.validatePreprocess(library.name, source.name, "variant", variant.preprocess);
            try self.validateDependencies(library.name, source.name, variant.dependencies);
            for (variant.preprocess) |step| {
                try self.validateDependencies(library.name, source.name, step.dependencies);
            }
        }
        try self.validateDependencies(library.name, source.name, source.dependencies);
        for (source.preprocess) |step| {
            try self.validateDependencies(library.name, source.name, step.dependencies);
        }
    }

    fn validatePreprocess(
        self: *BuildContext,
        library_name: []const u8,
        source_name: []const u8,
        scope: []const u8,
        steps: []const PreprocessStep,
    ) ValidationError!void {
        for (steps, 0..) |step, index| {
            if (step.name.len == 0 or step.output.len == 0) {
                try self.setDiagnostic(
                    "library '{s}' source '{s}' has a {s} preprocessing step with an empty name or output",
                    .{ library_name, source_name, scope },
                );
                return error.InvalidModel;
            }
            for (steps[0..index]) |previous| {
                if (std.mem.eql(u8, previous.name, step.name)) {
                    try self.setDiagnostic(
                        "library '{s}' source '{s}' repeats preprocessing step name '{s}'",
                        .{ library_name, source_name, step.name },
                    );
                    return error.DuplicateName;
                }
            }
        }
    }

    fn validateDependencies(
        self: *BuildContext,
        library_name: []const u8,
        source_name: []const u8,
        dependencies: []const Dependency,
    ) ValidationError!void {
        for (dependencies) |dependency| {
            switch (dependency) {
                .file => {},
                .component => |name| {
                    if (self.findLibrary(name) == null) {
                        try self.setDiagnostic(
                            "library '{s}' source '{s}' references unknown component dependency '{s}'",
                            .{ library_name, source_name, name },
                        );
                        return error.InvalidReference;
                    }
                },
                .generated_output => |path| {
                    if (!self.isGeneratedOutput(path)) {
                        try self.setDiagnostic(
                            "library '{s}' source '{s}' references unknown generated output '{s}'",
                            .{ library_name, source_name, path },
                        );
                        return error.InvalidReference;
                    }
                },
            }
        }
    }

    fn validatePlatforms(self: *BuildContext) ValidationError!void {
        for (self.platforms.items) |platform| {
            if (platform.name.len == 0) {
                try self.setDiagnostic("platform names cannot be empty", .{});
                return error.InvalidModel;
            }
            for (platform.libraries) |library_name| {
                const library_index = self.findLibrary(library_name) orelse {
                    try self.setDiagnostic(
                        "platform '{s}' references unknown library '{s}'",
                        .{ platform.name, library_name },
                    );
                    return error.InvalidReference;
                };
                const library = self.libraries.items[library_index];
                if (library.kind != .platform_library or
                    !containsString(library.platforms, platform.name))
                {
                    try self.setDiagnostic(
                        "platform '{s}' and library '{s}' have conflicting platform-library registrations",
                        .{ platform.name, library_name },
                    );
                    return error.ConflictingRegistration;
                }
            }
            for (platform.libraries, 0..) |library_name, index| {
                if (containsString(platform.libraries[0..index], library_name)) {
                    try self.setDiagnostic(
                        "platform '{s}' repeats library registration '{s}'",
                        .{ platform.name, library_name },
                    );
                    return error.DuplicateName;
                }
            }
            for (platform.link_stages, 0..) |stage, stage_index| {
                for (platform.link_stages[0..stage_index]) |previous| {
                    if (std.mem.eql(u8, previous.name, stage.name)) {
                        try self.setDiagnostic(
                            "platform '{s}' repeats link stage name '{s}'",
                            .{ platform.name, stage.name },
                        );
                        return error.DuplicateName;
                    }
                }
                for (stage.inputs) |input| {
                    try self.validateArtifactReference(platform.name, stage_index, input.artifact);
                }
            }
            for (platform.post_process, 0..) |artifact, index| {
                for (platform.post_process[0..index]) |previous| {
                    if (std.mem.eql(u8, previous.name, artifact.name)) {
                        try self.setDiagnostic(
                            "platform '{s}' repeats post-processing name '{s}'",
                            .{ platform.name, artifact.name },
                        );
                        return error.DuplicateName;
                    }
                }
                try self.validateArtifactReference(
                    platform.name,
                    platform.link_stages.len,
                    artifact.input,
                );
            }
            for (platform.object_inputs) |artifact| {
                try self.validateArtifactReference(platform.name, platform.link_stages.len, artifact);
            }
            for (platform.archive_inputs) |artifact| {
                try self.validateArtifactReference(platform.name, platform.link_stages.len, artifact);
            }
            for (platform.linker_scripts) |artifact| {
                try self.validateArtifactReference(platform.name, platform.link_stages.len, artifact);
            }
            for (platform.custom_link_dependencies) |artifact| {
                try self.validateArtifactReference(platform.name, platform.link_stages.len, artifact);
            }
        }
    }

    fn validateArtifactReference(
        self: *BuildContext,
        current_platform: []const u8,
        before_stage_index: usize,
        reference: ArtifactReference,
    ) ValidationError!void {
        switch (reference) {
            .path => {},
            .generated_output => |path| {
                if (!self.isGeneratedOutput(path)) {
                    try self.setDiagnostic(
                        "platform '{s}' references unknown generated output '{s}'",
                        .{ current_platform, path },
                    );
                    return error.InvalidReference;
                }
            },
            .component_output => |output| {
                const library_index = self.findLibrary(output.component) orelse {
                    try self.setDiagnostic(
                        "platform '{s}' references output from unknown library '{s}'",
                        .{ current_platform, output.component },
                    );
                    return error.InvalidReference;
                };
                if (!libraryProduces(self.libraries.items[library_index], output.path)) {
                    try self.setDiagnostic(
                        "platform '{s}' references undeclared output '{s}' from library '{s}'",
                        .{ current_platform, output.path, output.component },
                    );
                    return error.InvalidReference;
                }
            },
            .stage_output => |output| {
                if (!std.mem.eql(u8, output.platform, current_platform)) {
                    try self.setDiagnostic(
                        "platform '{s}' cannot consume stage output from platform '{s}'",
                        .{ current_platform, output.platform },
                    );
                    return error.InvalidReference;
                }
                const platform_index = self.findPlatform(output.platform) orelse {
                    try self.setDiagnostic(
                        "stage reference names unknown platform '{s}'",
                        .{output.platform},
                    );
                    return error.InvalidReference;
                };
                const stages = self.platforms.items[platform_index].link_stages;
                var found: ?usize = null;
                for (stages, 0..) |stage, index| {
                    if (std.mem.eql(u8, stage.name, output.stage)) {
                        found = index;
                        break;
                    }
                }
                if (found == null or found.? >= before_stage_index) {
                    try self.setDiagnostic(
                        "platform '{s}' stage reference '{s}' must name an earlier stage",
                        .{ current_platform, output.stage },
                    );
                    return error.InvalidReference;
                }
            },
        }
    }

    fn validateOutputs(self: *BuildContext) ValidationError!void {
        var outputs = std.array_list.Managed([]const u8).init(self.allocator);
        defer outputs.deinit();

        for (self.libraries.items) |library| {
            for (library.archives) |artifact| try self.recordOutput(&outputs, artifact.path);
            for (library.raw_objects) |artifact| try self.recordOutput(&outputs, artifact.path);
            for (library.sources) |source| {
                for (source.preprocess) |step| try self.recordOutput(&outputs, step.output);
                for (source.variants) |variant| {
                    for (variant.preprocess) |step| try self.recordOutput(&outputs, step.output);
                    if (variant.output) |output| {
                        if (output.kind != .no_op) try self.recordOutput(&outputs, output.path);
                        if (output.dependency_file) |path| try self.recordOutput(&outputs, path);
                    }
                }
            }
        }
        for (self.platforms.items) |platform| {
            for (platform.link_stages) |stage| try self.recordOutput(&outputs, stage.output);
            for (platform.post_process) |artifact| try self.recordOutput(&outputs, artifact.output);
        }
    }

    fn recordOutput(
        self: *BuildContext,
        outputs: *std.array_list.Managed([]const u8),
        path: []const u8,
    ) ValidationError!void {
        if (path.len == 0) {
            try self.setDiagnostic("registered output paths cannot be empty", .{});
            return error.InvalidModel;
        }
        for (outputs.items) |previous| {
            if (std.mem.eql(u8, previous, path)) {
                try self.setDiagnostic("output '{s}' is registered more than once", .{path});
                return error.DuplicateOutput;
            }
        }
        outputs.append(path) catch return error.OutOfMemory;
    }

    fn isGeneratedOutput(self: BuildContext, path: []const u8) bool {
        for (self.libraries.items) |library| {
            for (library.sources) |source| {
                for (source.preprocess) |step| {
                    if (std.mem.eql(u8, step.output, path)) return true;
                }
                for (source.variants) |variant| {
                    for (variant.preprocess) |step| {
                        if (std.mem.eql(u8, step.output, path)) return true;
                    }
                    if (variant.output) |output| {
                        if (output.kind == .generated and std.mem.eql(u8, output.path, path)) return true;
                    }
                }
            }
        }
        return false;
    }

    fn setDiagnostic(self: *BuildContext, comptime format: []const u8, args: anytype) error{OutOfMemory}!void {
        self.diagnostic = std.fmt.allocPrint(self.arena.allocator(), format, args) catch
            return error.OutOfMemory;
    }
};

pub fn registerLibrary(context: *BuildContext, spec: LibrarySpec) RegistrationError!void {
    return context.registerLibrary(spec);
}

pub fn registerComponent(context: *BuildContext, spec: ComponentSpec) RegistrationError!void {
    return context.registerComponent(spec);
}

pub fn registerPlatform(context: *BuildContext, spec: PlatformSpec) RegistrationError!void {
    return context.registerPlatform(spec);
}

fn containsString(values: []const []const u8, wanted: []const u8) bool {
    for (values) |value| {
        if (std.mem.eql(u8, value, wanted)) return true;
    }
    return false;
}

fn libraryProduces(library: Library, path: []const u8) bool {
    for (library.archives) |artifact| {
        if (std.mem.eql(u8, artifact.path, path)) return true;
    }
    for (library.raw_objects) |artifact| {
        if (std.mem.eql(u8, artifact.path, path)) return true;
    }
    for (library.sources) |source| {
        for (source.preprocess) |step| {
            if (std.mem.eql(u8, step.output, path)) return true;
        }
        for (source.variants) |variant| {
            for (variant.preprocess) |step| {
                if (std.mem.eql(u8, step.output, path)) return true;
            }
            if (variant.output) |output| {
                if (std.mem.eql(u8, output.path, path)) return true;
            }
        }
    }
    return false;
}

fn copyRoots(allocator: std.mem.Allocator, roots: Roots) !Roots {
    return .{
        .base = try allocator.dupe(u8, roots.base),
        .app = try allocator.dupe(u8, roots.app),
        .output = try allocator.dupe(u8, roots.output),
        .config = try allocator.dupe(u8, roots.config),
    };
}

fn copyTarget(allocator: std.mem.Allocator, target: Target) !Target {
    return .{
        .architecture = target.architecture,
        .family = target.family,
        .abi = try allocator.dupe(u8, target.abi),
        .triple = try allocator.dupe(u8, target.triple),
    };
}

fn copyTool(allocator: std.mem.Allocator, tool: Tool) !Tool {
    return .{
        .command = try allocator.dupe(u8, tool.command),
        .version = tool.version,
    };
}

fn copyOptionalTool(allocator: std.mem.Allocator, tool: ?Tool) !?Tool {
    return if (tool) |value| try copyTool(allocator, value) else null;
}

fn copyToolchain(allocator: std.mem.Allocator, toolchain: Toolchain) !Toolchain {
    return .{
        .target_triple = try allocator.dupe(u8, toolchain.target_triple),
        .compiler = .{
            .tool = try copyTool(allocator, toolchain.compiler.tool),
            .kind = toolchain.compiler.kind,
            .already_targets_triple = toolchain.compiler.already_targets_triple,
        },
        .partial_linker = .{
            .tool = try copyTool(allocator, toolchain.partial_linker.tool),
            .kind = toolchain.partial_linker.kind,
            .mode = toolchain.partial_linker.mode,
        },
        .final_linker = .{
            .tool = try copyTool(allocator, toolchain.final_linker.tool),
            .kind = toolchain.final_linker.kind,
        },
        .binutils = .{
            .ar = try copyTool(allocator, toolchain.binutils.ar),
            .objcopy = try copyTool(allocator, toolchain.binutils.objcopy),
            .strip = try copyTool(allocator, toolchain.binutils.strip),
            .nm = try copyTool(allocator, toolchain.binutils.nm),
            .objdump = try copyOptionalTool(allocator, toolchain.binutils.objdump),
        },
        .host = .{
            .cc = try copyOptionalTool(allocator, toolchain.host.cc),
            .cxx = try copyOptionalTool(allocator, toolchain.host.cxx),
            .awk = try copyOptionalTool(allocator, toolchain.host.awk),
            .m4 = try copyOptionalTool(allocator, toolchain.host.m4),
            .dtc = try copyOptionalTool(allocator, toolchain.host.dtc),
            .python = try copyOptionalTool(allocator, toolchain.host.python),
        },
        .capabilities = try allocator.dupe(ToolCapability, toolchain.capabilities),
    };
}

fn copyStringList(allocator: std.mem.Allocator, values: []const []const u8) ![]const []const u8 {
    const result = try allocator.alloc([]const u8, values.len);
    for (values, 0..) |value, index| result[index] = try allocator.dupe(u8, value);
    return result;
}

fn copyFlagSet(allocator: std.mem.Allocator, flags: FlagSet) !FlagSet {
    return .{
        .common = try copyStringList(allocator, flags.common),
        .c = try copyStringList(allocator, flags.c),
        .cpp = try copyStringList(allocator, flags.cpp),
        .assembler = try copyStringList(allocator, flags.assembler),
        .rust = try copyStringList(allocator, flags.rust),
        .linker = try copyStringList(allocator, flags.linker),
    };
}

fn copyIncludes(allocator: std.mem.Allocator, includes: []const Include) ![]const Include {
    const result = try allocator.alloc(Include, includes.len);
    for (includes, 0..) |include, index| {
        result[index] = .{
            .path = try allocator.dupe(u8, include.path),
            .kind = include.kind,
            .languages = try allocator.dupe(SourceLanguage, include.languages),
        };
    }
    return result;
}

fn copyCondition(allocator: std.mem.Allocator, condition: Condition) !Condition {
    return switch (condition) {
        .always => .always,
        .config_enabled => |name| .{ .config_enabled = try allocator.dupe(u8, name) },
        .config_disabled => |name| .{ .config_disabled = try allocator.dupe(u8, name) },
        .config_equals => |expected| .{ .config_equals = .{
            .name = try allocator.dupe(u8, expected.name),
            .value = try allocator.dupe(u8, expected.value),
        } },
    };
}

fn copyOrigin(allocator: std.mem.Allocator, origin: Origin) !Origin {
    return switch (origin) {
        .internal => |category| .{ .internal = category },
        .external => |external| .{ .external = .{
            .package_name = try allocator.dupe(u8, external.package_name),
            .root = try allocator.dupe(u8, external.root),
        } },
    };
}

fn copyLayout(allocator: std.mem.Allocator, layout: SubBuildLayout) !SubBuildLayout {
    return switch (layout) {
        .ordinary => |ordinary| .{ .ordinary = .{
            .build_subdir = try allocator.dupe(u8, ordinary.build_subdir),
        } },
        .tree => |tree| .{ .tree = .{
            .build_subdir = try allocator.dupe(u8, tree.build_subdir),
            .source_root = try allocator.dupe(u8, tree.source_root),
        } },
    };
}

fn copyDependencies(
    allocator: std.mem.Allocator,
    dependencies: []const Dependency,
) ![]const Dependency {
    const result = try allocator.alloc(Dependency, dependencies.len);
    for (dependencies, 0..) |dependency, index| {
        result[index] = switch (dependency) {
            .file => |path| .{ .file = try allocator.dupe(u8, path) },
            .generated_output => |path| .{ .generated_output = try allocator.dupe(u8, path) },
            .component => |name| .{ .component = try allocator.dupe(u8, name) },
        };
    }
    return result;
}

fn copyPreprocessKind(allocator: std.mem.Allocator, kind: PreprocessKind) !PreprocessKind {
    return switch (kind) {
        .awk => .awk,
        .m4 => .m4,
        .generated => .generated,
        .custom => |name| .{ .custom = try allocator.dupe(u8, name) },
    };
}

fn copyPreprocess(
    allocator: std.mem.Allocator,
    steps: []const PreprocessStep,
) ![]const PreprocessStep {
    const result = try allocator.alloc(PreprocessStep, steps.len);
    for (steps, 0..) |step, index| {
        result[index] = .{
            .name = try allocator.dupe(u8, step.name),
            .kind = try copyPreprocessKind(allocator, step.kind),
            .output = try allocator.dupe(u8, step.output),
            .condition = try copyCondition(allocator, step.condition),
            .flags = try copyStringList(allocator, step.flags),
            .includes = try copyStringList(allocator, step.includes),
            .dependencies = try copyDependencies(allocator, step.dependencies),
            .subbuild = if (step.subbuild) |path| try allocator.dupe(u8, path) else null,
        };
    }
    return result;
}

fn copyVariantName(allocator: std.mem.Allocator, name: VariantName) !VariantName {
    return switch (name) {
        .default => .default,
        .isr => .isr,
        .named => |value| .{ .named = try allocator.dupe(u8, value) },
    };
}

fn copySourceOutput(allocator: std.mem.Allocator, output: ?SourceOutput) !?SourceOutput {
    return if (output) |value| .{
        .path = try allocator.dupe(u8, value.path),
        .kind = value.kind,
        .dependency_file = if (value.dependency_file) |path| try allocator.dupe(u8, path) else null,
    } else null;
}

fn copySourceVariants(
    allocator: std.mem.Allocator,
    variants: []const SourceVariant,
) ![]const SourceVariant {
    const result = try allocator.alloc(SourceVariant, variants.len);
    for (variants, 0..) |variant, index| {
        result[index] = .{
            .name = try copyVariantName(allocator, variant.name),
            .condition = try copyCondition(allocator, variant.condition),
            .flags = try copyFlagSet(allocator, variant.flags),
            .includes = try copyIncludes(allocator, variant.includes),
            .dependencies = try copyDependencies(allocator, variant.dependencies),
            .subbuild = if (variant.subbuild) |path| try allocator.dupe(u8, path) else null,
            .preprocess = try copyPreprocess(allocator, variant.preprocess),
            .output = try copySourceOutput(allocator, variant.output),
        };
    }
    return result;
}

fn copySources(allocator: std.mem.Allocator, sources: []const Source) ![]const Source {
    const result = try allocator.alloc(Source, sources.len);
    for (sources, 0..) |source, index| {
        result[index] = .{
            .name = try allocator.dupe(u8, source.name),
            .path = try allocator.dupe(u8, source.path),
            .language = source.language,
            .condition = try copyCondition(allocator, source.condition),
            .flags = try copyFlagSet(allocator, source.flags),
            .includes = try copyIncludes(allocator, source.includes),
            .dependencies = try copyDependencies(allocator, source.dependencies),
            .subbuild = if (source.subbuild) |path| try allocator.dupe(u8, path) else null,
            .preprocess = try copyPreprocess(allocator, source.preprocess),
            .variants = try copySourceVariants(allocator, source.variants),
        };
    }
    return result;
}

fn copyRegisteredArtifacts(
    allocator: std.mem.Allocator,
    artifacts: []const RegisteredArtifact,
) ![]const RegisteredArtifact {
    const result = try allocator.alloc(RegisteredArtifact, artifacts.len);
    for (artifacts, 0..) |artifact, index| {
        result[index] = .{
            .path = try allocator.dupe(u8, artifact.path),
            .condition = try copyCondition(allocator, artifact.condition),
        };
    }
    return result;
}

fn copyComponentDependencies(
    allocator: std.mem.Allocator,
    dependencies: []const ComponentDependency,
) ![]const ComponentDependency {
    const result = try allocator.alloc(ComponentDependency, dependencies.len);
    for (dependencies, 0..) |dependency, index| {
        result[index] = .{
            .name = try allocator.dupe(u8, dependency.name),
            .kind = dependency.kind,
            .condition = try copyCondition(allocator, dependency.condition),
        };
    }
    return result;
}

fn copyLibrary(allocator: std.mem.Allocator, library: LibrarySpec) !Library {
    return .{
        .name = try allocator.dupe(u8, library.name),
        .kind = library.kind,
        .origin = try copyOrigin(allocator, library.origin),
        .enable = try copyCondition(allocator, library.enable),
        .layout = try copyLayout(allocator, library.layout),
        .platforms = try copyStringList(allocator, library.platforms),
        .dependencies = try copyComponentDependencies(allocator, library.dependencies),
        .exports = try copyStringList(allocator, library.exports),
        .locals = try copyStringList(allocator, library.locals),
        .archives = try copyRegisteredArtifacts(allocator, library.archives),
        .raw_objects = try copyRegisteredArtifacts(allocator, library.raw_objects),
        .custom_link_dependencies = try copyRegisteredArtifacts(
            allocator,
            library.custom_link_dependencies,
        ),
        .linker_scripts = try copyRegisteredArtifacts(allocator, library.linker_scripts),
        .sources = try copySources(allocator, library.sources),
    };
}

fn copyArtifactReference(
    allocator: std.mem.Allocator,
    reference: ArtifactReference,
) !ArtifactReference {
    return switch (reference) {
        .path => |path| .{ .path = try allocator.dupe(u8, path) },
        .generated_output => |path| .{ .generated_output = try allocator.dupe(u8, path) },
        .component_output => |output| .{ .component_output = .{
            .component = try allocator.dupe(u8, output.component),
            .path = try allocator.dupe(u8, output.path),
        } },
        .stage_output => |output| .{ .stage_output = .{
            .platform = try allocator.dupe(u8, output.platform),
            .stage = try allocator.dupe(u8, output.stage),
        } },
    };
}

fn copyArtifactReferences(
    allocator: std.mem.Allocator,
    references: []const ArtifactReference,
) ![]const ArtifactReference {
    const result = try allocator.alloc(ArtifactReference, references.len);
    for (references, 0..) |reference, index| {
        result[index] = try copyArtifactReference(allocator, reference);
    }
    return result;
}

fn copyLinkTransformation(
    allocator: std.mem.Allocator,
    transformation: LinkTransformation,
) !LinkTransformation {
    return switch (transformation) {
        .partial_link => .partial_link,
        .objcopy_localize => .objcopy_localize,
        .final_link => .final_link,
        .custom => |name| .{ .custom = try allocator.dupe(u8, name) },
    };
}

fn copyLinkStages(allocator: std.mem.Allocator, stages: []const LinkStage) ![]const LinkStage {
    const result = try allocator.alloc(LinkStage, stages.len);
    for (stages, 0..) |stage, index| {
        const inputs = try allocator.alloc(LinkInput, stage.inputs.len);
        for (stage.inputs, 0..) |input, input_index| {
            inputs[input_index] = .{
                .kind = input.kind,
                .artifact = try copyArtifactReference(allocator, input.artifact),
            };
        }
        result[index] = .{
            .name = try allocator.dupe(u8, stage.name),
            .transformation = try copyLinkTransformation(allocator, stage.transformation),
            .output = try allocator.dupe(u8, stage.output),
            .condition = try copyCondition(allocator, stage.condition),
            .inputs = inputs,
            .flags = try copyStringList(allocator, stage.flags),
        };
    }
    return result;
}

fn copyPostProcessKind(
    allocator: std.mem.Allocator,
    kind: PostProcessKind,
) !PostProcessKind {
    return switch (kind) {
        .strip => .strip,
        .symbols => .symbols,
        .bootinfo => .bootinfo,
        .multiboot => .multiboot,
        .efi => .efi,
        .linux_header => .linux_header,
        .compile_database => .compile_database,
        .custom => |name| .{ .custom = try allocator.dupe(u8, name) },
    };
}

fn copyPostProcess(
    allocator: std.mem.Allocator,
    artifacts: []const PostProcessArtifact,
) ![]const PostProcessArtifact {
    const result = try allocator.alloc(PostProcessArtifact, artifacts.len);
    for (artifacts, 0..) |artifact, index| {
        result[index] = .{
            .name = try allocator.dupe(u8, artifact.name),
            .kind = try copyPostProcessKind(allocator, artifact.kind),
            .input = try copyArtifactReference(allocator, artifact.input),
            .output = try allocator.dupe(u8, artifact.output),
            .condition = try copyCondition(allocator, artifact.condition),
        };
    }
    return result;
}

fn copyPlatform(allocator: std.mem.Allocator, platform: PlatformSpec) !Platform {
    return .{
        .name = try allocator.dupe(u8, platform.name),
        .origin = try copyOrigin(allocator, platform.origin),
        .enable = try copyCondition(allocator, platform.enable),
        .linker_definition = if (platform.linker_definition) |path|
            try allocator.dupe(u8, path)
        else
            null,
        .libraries = try copyStringList(allocator, platform.libraries),
        .object_inputs = try copyArtifactReferences(allocator, platform.object_inputs),
        .archive_inputs = try copyArtifactReferences(allocator, platform.archive_inputs),
        .linker_scripts = try copyArtifactReferences(allocator, platform.linker_scripts),
        .custom_link_dependencies = try copyArtifactReferences(
            allocator,
            platform.custom_link_dependencies,
        ),
        .link_stages = try copyLinkStages(allocator, platform.link_stages),
        .post_process = try copyPostProcess(allocator, platform.post_process),
    };
}

fn testConfigEnabled(_: ?*const anyopaque, name: []const u8) bool {
    return std.mem.eql(u8, name, "CONFIG_PLAT_KVM") or
        std.mem.eql(u8, name, "CONFIG_LIBUKBOOT");
}

fn testConfigValue(_: ?*const anyopaque, name: []const u8) ?[]const u8 {
    if (std.mem.eql(u8, name, "CONFIG_UK_ARCH")) return "x86_64";
    return null;
}

fn testConfig() ConfigQuery {
    return .{
        .is_enabled_fn = testConfigEnabled,
        .value_fn = testConfigValue,
    };
}

fn testToolchain() Toolchain {
    return .{
        .target_triple = "x86_64-unknown-none",
        .compiler = .{
            .tool = .{
                .command = "clang",
                .version = .{ .major = 18, .minor = 1, .patch = 0 },
            },
            .kind = .clang,
        },
        .partial_linker = .{
            .tool = .{ .command = "ld.lld", .version = .{ .major = 18, .minor = 1, .patch = 0 } },
            .kind = .lld,
            .mode = .raw,
        },
        .final_linker = .{
            .tool = .{ .command = "clang", .version = .{ .major = 18, .minor = 1, .patch = 0 } },
            .kind = .compiler_driver,
        },
        .binutils = .{
            .ar = .{ .command = "llvm-ar" },
            .objcopy = .{ .command = "llvm-objcopy" },
            .strip = .{ .command = "llvm-strip" },
            .nm = .{ .command = "llvm-nm" },
        },
        .host = .{
            .awk = .{ .command = "awk" },
            .m4 = .{ .command = "m4" },
            .dtc = .{ .command = "dtc" },
        },
        .capabilities = &.{ .response_files, .relocatable_link },
    };
}

fn testContext() !BuildContext {
    return BuildContext.init(std.testing.allocator, .{
        .roots = .{
            .base = "/src/unikraft",
            .app = "/src/app",
            .output = "/src/app/build",
            .config = "/src/app/build/.config",
        },
        .target = .{
            .architecture = .x86_64,
            .family = .x86,
            .abi = "none",
            .triple = "x86_64-unknown-none",
        },
        .toolchain = testToolchain(),
        .global_flags = .{ .common = &.{"-ffreestanding"} },
        .global_includes = &.{.{ .path = "/src/unikraft/include" }},
        .config = testConfig(),
    });
}

test "ukboot variants retain registration order" {
    var context = try testContext();
    defer context.deinit();

    try context.registerLibrary(.{
        .name = "libukboot",
        .origin = .{ .internal = .core },
        .enable = .{ .config_enabled = "CONFIG_LIBUKBOOT" },
        .layout = .{ .ordinary = .{ .build_subdir = "libukboot" } },
        .sources = &.{
            .{
                .name = "shutdown_req",
                .path = "/src/unikraft/lib/ukboot/shutdown_req.c",
                .language = .c,
                .variants = &.{
                    .{
                        .name = .default,
                        .output = .{ .path = "/src/app/build/libukboot/shutdown_req.o", .kind = .object },
                    },
                    .{
                        .name = .isr,
                        .flags = .{ .c = &.{"-mgeneral-regs-only"} },
                        .output = .{ .path = "/src/app/build/libukboot/shutdown_req.isr.o", .kind = .object },
                    },
                    .{
                        .name = .{ .named = "trace" },
                        .output = .{ .path = "/src/app/build/libukboot/shutdown_req.trace.o", .kind = .object },
                    },
                },
            },
        },
    });
    try context.registerPlatform(.{
        .name = "kvm",
        .origin = .{ .internal = .platform },
        .enable = .{ .config_enabled = "CONFIG_PLAT_KVM" },
    });

    const graph = try context.finalize();
    try std.testing.expectEqualStrings("libukboot", graph.libraries[0].name);
    try std.testing.expect(graph.libraries[0].sources[0].variants[0].name == .default);
    try std.testing.expect(graph.libraries[0].sources[0].variants[1].name == .isr);
    try std.testing.expectEqualStrings(
        "trace",
        graph.libraries[0].sources[0].variants[2].name.named,
    );
    try std.testing.expectEqual(@as(usize, 0), graph.registrations[0].order);
    try std.testing.expect(graph.registrations[0].kind == .component);
    try std.testing.expectEqualStrings("libukboot", graph.registrations[0].name);
    try std.testing.expect(graph.registrations[1].kind == .platform);
}

test "syscall AWK generated output wires dependencies" {
    var context = try testContext();
    defer context.deinit();

    try context.registerLibrary(.{
        .name = "libsyscall_shim",
        .origin = .{ .internal = .core },
        .layout = .{ .tree = .{
            .build_subdir = "libsyscall_shim",
            .source_root = "/src/unikraft/lib/syscall_shim",
        } },
        .sources = &.{
            .{
                .name = "provided",
                .path = "/src/unikraft/lib/syscall_shim/syscall_provided.awk",
                .language = .generated,
                .preprocess = &.{
                    .{
                        .name = "awk",
                        .kind = .awk,
                        .output = "/src/app/build/libsyscall_shim/include/uk/bits/syscall_provided.h",
                        .includes = &.{"/src/app/build/libsyscall_shim/provided_syscalls.in"},
                        .dependencies = &.{.{ .file = "/src/app/build/libsyscall_shim/provided_syscalls.in" }},
                        .subbuild = "include/uk/bits",
                    },
                },
                .variants = &.{
                    .{
                        .dependencies = &.{.{ .generated_output = "/src/app/build/libsyscall_shim/include/uk/bits/syscall_provided.h" }},
                        .output = .{
                            .path = "/src/app/build/libsyscall_shim/generated.marker",
                            .kind = .generated,
                        },
                    },
                },
            },
        },
    });
    try context.registerPlatform(.{
        .name = "kvm",
        .origin = .{ .internal = .platform },
        .enable = .{ .config_enabled = "CONFIG_PLAT_KVM" },
    });

    const graph = try context.finalize();
    const source = graph.libraries[0].sources[0];
    try std.testing.expectEqualStrings(
        "/src/app/build/libsyscall_shim/include/uk/bits/syscall_provided.h",
        source.effectiveInput(source.variants[0]),
    );
    try std.testing.expect(source.variants[0].dependencies[0] == .generated_output);
}

test "KVM and Xen link pipelines preserve ordered inputs" {
    var context = try testContext();
    defer context.deinit();

    try context.registerLibrary(.{
        .name = "libkvmplat",
        .kind = .platform_library,
        .origin = .{ .internal = .platform },
        .layout = .{ .ordinary = .{ .build_subdir = "libkvmplat" } },
        .platforms = &.{"kvm"},
        .archives = &.{.{ .path = "/build/libkvmplat.a" }},
    });
    try context.registerLibrary(.{
        .name = "libxenplat",
        .kind = .platform_library,
        .origin = .{ .internal = .platform },
        .layout = .{ .ordinary = .{ .build_subdir = "libxenplat" } },
        .platforms = &.{"xen"},
        .archives = &.{.{ .path = "/build/libxenplat.a" }},
    });
    try context.registerPlatform(.{
        .name = "kvm",
        .origin = .{ .internal = .platform },
        .enable = .{ .config_enabled = "CONFIG_PLAT_KVM" },
        .libraries = &.{"libkvmplat"},
        .link_stages = &.{
            .{
                .name = "final-link",
                .transformation = .final_link,
                .output = "/build/app_kvm.dbg",
                .inputs = &.{
                    .{ .kind = .object, .artifact = .{ .path = "/build/first.o" } },
                    .{ .kind = .archive, .artifact = .{ .component_output = .{
                        .component = "libkvmplat",
                        .path = "/build/libkvmplat.a",
                    } } },
                    .{ .kind = .linker_script, .artifact = .{ .path = "/src/unikraft/plat/kvm/link64.lds" } },
                },
            },
        },
        .post_process = &.{
            .{
                .name = "strip",
                .kind = .strip,
                .input = .{ .stage_output = .{ .platform = "kvm", .stage = "final-link" } },
                .output = "/build/app_kvm",
            },
        },
    });
    try context.registerPlatform(.{
        .name = "xen",
        .origin = .{ .internal = .platform },
        .enable = .{ .config_disabled = "CONFIG_PLAT_KVM" },
        .libraries = &.{"libxenplat"},
        .link_stages = &.{
            .{
                .name = "partial-link",
                .transformation = .partial_link,
                .output = "/build/app_xen.ld.o",
                .inputs = &.{
                    .{ .kind = .object, .artifact = .{ .path = "/build/xen-first.o" } },
                    .{ .kind = .archive, .artifact = .{ .component_output = .{
                        .component = "libxenplat",
                        .path = "/build/libxenplat.a",
                    } } },
                },
            },
            .{
                .name = "localize",
                .transformation = .objcopy_localize,
                .output = "/build/app_xen.o",
                .inputs = &.{.{ .kind = .intermediate, .artifact = .{ .stage_output = .{
                    .platform = "xen",
                    .stage = "partial-link",
                } } }},
            },
            .{
                .name = "final-link",
                .transformation = .final_link,
                .output = "/build/app_xen.dbg",
                .inputs = &.{
                    .{ .kind = .linker_script, .artifact = .{ .path = "/src/unikraft/plat/xen/link64.lds" } },
                    .{ .kind = .intermediate, .artifact = .{ .stage_output = .{
                        .platform = "xen",
                        .stage = "localize",
                    } } },
                },
            },
        },
    });

    const graph = try context.finalize();
    try std.testing.expectEqualStrings("kvm", graph.selectedPlatform().name);
    try std.testing.expectEqualStrings("final-link", graph.platforms[0].link_stages[0].name);
    try std.testing.expect(graph.platforms[0].link_stages[0].inputs[0].kind == .object);
    try std.testing.expect(graph.platforms[0].link_stages[0].inputs[1].kind == .archive);
    try std.testing.expectEqualStrings("partial-link", graph.platforms[1].link_stages[0].name);
    try std.testing.expectEqualStrings("localize", graph.platforms[1].link_stages[1].name);
    try std.testing.expectEqualStrings("final-link", graph.platforms[1].link_stages[2].name);
}

test "duplicate registration and validation failures are actionable" {
    var context = try testContext();
    defer context.deinit();

    const library = LibrarySpec{
        .name = "libdup",
        .origin = .{ .external = .{ .package_name = "dup", .root = "/external/dup" } },
        .layout = .{ .ordinary = .{ .build_subdir = "libdup" } },
        .raw_objects = &.{.{ .path = "/build/shared.o" }},
    };
    try context.registerLibrary(library);
    try std.testing.expectError(error.DuplicateLibrary, context.registerLibrary(library));
    try std.testing.expect(std.mem.indexOf(u8, context.lastDiagnostic().?, "libdup") != null);

    try context.registerLibrary(.{
        .name = "libother",
        .origin = .{ .internal = .library },
        .layout = .{ .ordinary = .{ .build_subdir = "libother" } },
        .archives = &.{.{ .path = "/build/shared.o" }},
    });
    try context.registerPlatform(.{
        .name = "kvm",
        .origin = .{ .internal = .platform },
        .enable = .{ .config_enabled = "CONFIG_PLAT_KVM" },
    });

    try std.testing.expectError(error.DuplicateOutput, context.finalize());
    try std.testing.expect(std.mem.indexOf(u8, context.lastDiagnostic().?, "/build/shared.o") != null);
}

test "finalize requires exactly one selected platform and validates references" {
    var no_platform = try testContext();
    defer no_platform.deinit();
    try std.testing.expectError(error.NoSelectedPlatform, no_platform.finalize());

    var multiple = try testContext();
    defer multiple.deinit();
    try multiple.registerPlatform(.{
        .name = "kvm",
        .origin = .{ .internal = .platform },
        .enable = .always,
    });
    try multiple.registerPlatform(.{
        .name = "xen",
        .origin = .{ .internal = .platform },
        .enable = .always,
    });
    try std.testing.expectError(error.MultipleSelectedPlatforms, multiple.finalize());

    var bad_reference = try testContext();
    defer bad_reference.deinit();
    try bad_reference.registerLibrary(.{
        .name = "libbroken",
        .origin = .{ .internal = .library },
        .layout = .{ .ordinary = .{ .build_subdir = "libbroken" } },
        .dependencies = &.{.{ .name = "libmissing" }},
    });
    try bad_reference.registerPlatform(.{
        .name = "kvm",
        .origin = .{ .internal = .platform },
        .enable = .always,
    });
    try std.testing.expectError(error.InvalidReference, bad_reference.finalize());
    try std.testing.expect(std.mem.indexOf(
        u8,
        bad_reference.lastDiagnostic().?,
        "libmissing",
    ) != null);
}

test "toolchain capability and version predicates use declared metadata" {
    const toolchain = testToolchain();
    try std.testing.expect(toolchain.hasCapability(.relocatable_link));
    try std.testing.expect(!toolchain.hasCapability(.thin_archives));
    try std.testing.expect(toolchain.satisfies(.{
        .role = .compiler_driver,
        .relation = .at_least,
        .version = .{ .major = 18, .minor = 0, .patch = 0 },
    }));
    try std.testing.expect(!toolchain.satisfies(.{
        .role = .objcopy,
        .relation = .at_least,
        .version = .{ .major = 1, .minor = 0, .patch = 0 },
    }));
}
