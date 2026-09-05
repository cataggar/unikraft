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
    all: []const Condition,
    any: []const Condition,

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
            .all => |conditions| conditionsMatchAll(conditions, config),
            .any => |conditions| conditionsMatchAny(conditions, config),
        };
    }
};

fn conditionsMatchAll(conditions: []const Condition, config: ConfigQuery) bool {
    for (conditions) |condition| {
        if (!condition.matches(config)) return false;
    }
    return true;
}

fn conditionsMatchAny(conditions: []const Condition, config: ConfigQuery) bool {
    for (conditions) |condition| {
        if (condition.matches(config)) return true;
    }
    return false;
}

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

pub const LinkProvenance = enum {
    library_local,
    each_library,
    platform,
    global,
    direct,
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

    pub fn isActive(self: Source, config: ConfigQuery) bool {
        return self.condition.matches(config);
    }

    pub fn isVariantActive(
        self: Source,
        config: ConfigQuery,
        variant: SourceVariant,
    ) bool {
        return self.isActive(config) and variant.condition.matches(config);
    }

    pub fn hasActiveVariant(self: Source, config: ConfigQuery) bool {
        if (!self.isActive(config)) return false;
        if (self.variants.len == 0) return true;
        for (self.variants) |variant| {
            if (self.isVariantActive(config, variant)) return true;
        }
        return false;
    }

    pub fn isSourcePreprocessStepActive(
        self: Source,
        config: ConfigQuery,
        step: PreprocessStep,
    ) bool {
        return self.hasActiveVariant(config) and step.condition.matches(config);
    }

    pub fn isVariantPreprocessStepActive(
        self: Source,
        config: ConfigQuery,
        variant: SourceVariant,
        step: PreprocessStep,
    ) bool {
        return self.isVariantActive(config, variant) and step.condition.matches(config);
    }

    pub fn effectiveInput(
        self: Source,
        config: ConfigQuery,
        variant: SourceVariant,
    ) []const u8 {
        if (!self.isVariantActive(config, variant)) return self.path;

        var input = self.path;
        for (self.preprocess) |step| {
            if (self.isSourcePreprocessStepActive(config, step)) input = step.output;
        }
        for (variant.preprocess) |step| {
            if (self.isVariantPreprocessStepActive(config, variant, step)) {
                input = step.output;
            }
        }
        return input;
    }
};

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
    object_pipeline: ?LibraryObjectPipeline = null,
};

pub const Library = LibrarySpec;
pub const ComponentSpec = LibrarySpec;
pub const Component = Library;

pub const ArtifactReference = union(enum) {
    path: []const u8,
    generated_output: []const u8,
    component_output: ComponentOutput,
    library_partial_output: []const u8,
    library_final_object: []const u8,
    stage_output: StageOutput,
    post_process_output: PostProcessOutput,

    pub const ComponentOutput = struct {
        component: []const u8,
        path: []const u8,
    };

    pub const StageOutput = struct {
        platform: []const u8,
        stage: []const u8,
    };

    pub const PostProcessOutput = struct {
        platform: []const u8,
        transformation: []const u8,
        output: []const u8,
    };
};

pub const LinkArtifactKind = enum {
    object,
    archive,
    linker_script,
    intermediate,
    custom_link_dependency,
};

pub const LinkArtifact = struct {
    kind: LinkArtifactKind,
    artifact: ArtifactReference,
    provenance: LinkProvenance = .direct,
};

pub const ToolModeFlag = struct {
    driver: ?[]const u8,
    raw: ?[]const u8,

    pub fn forMode(self: ToolModeFlag, mode: PartialLinkMode) ?[]const u8 {
        return switch (mode) {
            .driver => self.driver,
            .raw => self.raw,
        };
    }
};

pub const LinkSequenceItem = union(enum) {
    artifact: LinkArtifact,
    literal_flag: []const u8,
    tool_mode_flag: ToolModeFlag,
    group_start,
    group_end,
    library_argument: []const u8,
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
    output_role: ArtifactRole = .intermediate,
    condition: Condition = .always,
    sequence: []const LinkSequenceItem = &.{},
};

pub const SymbolTransformAction = enum {
    keep_global,
    localize,
};

pub const SymbolTransform = struct {
    action: SymbolTransformAction,
    symbols_file: []const u8,
    provenance: LinkProvenance,
    condition: Condition = .always,
};

pub const ObjectTransformItem = union(enum) {
    symbol_file: SymbolTransform,
    literal_flag: []const u8,
};

pub const LibraryObjectTransform = struct {
    input: ArtifactReference,
    output: []const u8,
    sequence: []const ObjectTransformItem = &.{},
};

pub const LibraryObjectPipeline = struct {
    partial_link_output: []const u8,
    partial_link_sequence: []const LinkSequenceItem,
    transform: LibraryObjectTransform,
};

pub const PostProcessKind = union(enum) {
    strip,
    objcopy_binary,
    symbols,
    bootinfo,
    multiboot,
    efi,
    linux_header,
    gzip,
    compile_database,
    custom: []const u8,
};

pub const ArtifactRole = enum {
    image,
    debug,
    auxiliary,
    side,
    intermediate,
};

pub const PostProcessEffect = union(enum) {
    create: Created,
    mutate_input: Mutated,

    pub const Created = struct {
        name: []const u8,
        path: []const u8,
        role: ArtifactRole,
    };

    pub const Mutated = struct {
        name: []const u8,
        role: ArtifactRole,
        input_index: usize = 0,
    };
};

pub const PostProcessTransformation = struct {
    name: []const u8,
    kind: PostProcessKind,
    input: ArtifactReference,
    additional_inputs: []const ArtifactReference = &.{},
    condition: Condition = .always,
    effects: []const PostProcessEffect,
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
    post_process: []const PostProcessTransformation = &.{},
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

        try self.validateLibraries();
        try self.validatePlatforms(selected_index.?);
        try self.validateOutputs(selected_index.?);

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
                if (!library.enable.matches(self.config) or
                    !dependency.condition.matches(self.config)) continue;
                const dependency_index = self.findLibrary(dependency.name) orelse {
                    try self.setDiagnostic(
                        "library '{s}' depends on unknown library '{s}'",
                        .{ library.name, dependency.name },
                    );
                    return error.InvalidReference;
                };
                if (!self.libraries.items[dependency_index].enable.matches(self.config)) {
                    try self.setDiagnostic(
                        "active library '{s}' depends on inactive library '{s}'",
                        .{ library.name, dependency.name },
                    );
                    return error.InvalidReference;
                }
            }
            for (library.sources) |source| {
                try self.validateSource(library, source);
            }
            if (library.object_pipeline) |pipeline| {
                try self.validateLibraryPipeline(library, pipeline);
            }
        }
    }

    fn validateLibraryPipeline(
        self: *BuildContext,
        library: Library,
        pipeline: LibraryObjectPipeline,
    ) ValidationError!void {
        if (pipeline.partial_link_output.len == 0 or pipeline.transform.output.len == 0) {
            try self.setDiagnostic(
                "library '{s}' object pipeline has an empty partial or final output",
                .{library.name},
            );
            return error.InvalidModel;
        }
        switch (pipeline.transform.input) {
            .library_partial_output => |name| {
                if (!std.mem.eql(u8, name, library.name)) {
                    try self.setDiagnostic(
                        "library '{s}' object transform must consume its own partial-link output",
                        .{library.name},
                    );
                    return error.InvalidReference;
                }
            },
            else => {
                try self.setDiagnostic(
                    "library '{s}' object transform input must be a typed library partial output",
                    .{library.name},
                );
                return error.InvalidReference;
            },
        }
        try self.validateLinkSequence(
            library.name,
            null,
            0,
            pipeline.partial_link_sequence,
            library.enable.matches(self.config),
        );
        for (pipeline.partial_link_sequence) |item| {
            if (item != .artifact) continue;
            switch (item.artifact.artifact) {
                .library_partial_output, .library_final_object => |name| {
                    if (std.mem.eql(u8, name, library.name)) {
                        try self.setDiagnostic(
                            "library '{s}' partial link cannot consume its own intermediate or final output",
                            .{library.name},
                        );
                        return error.InvalidReference;
                    }
                },
                else => {},
            }
        }
        for (pipeline.transform.sequence) |item| {
            switch (item) {
                .symbol_file => |symbol| {
                    if (symbol.symbols_file.len == 0) {
                        try self.setDiagnostic(
                            "library '{s}' has an empty symbol transform file",
                            .{library.name},
                        );
                        return error.InvalidModel;
                    }
                },
                .literal_flag => |flag| {
                    if (flag.len == 0) {
                        try self.setDiagnostic(
                            "library '{s}' has an empty objcopy flag",
                            .{library.name},
                        );
                        return error.InvalidModel;
                    }
                },
            }
        }
    }

    fn validateLinkSequence(
        self: *BuildContext,
        owner: []const u8,
        current_platform: ?[]const u8,
        before_stage_index: usize,
        sequence: []const LinkSequenceItem,
        validate_references: bool,
    ) ValidationError!void {
        var group_depth: usize = 0;
        for (sequence) |item| {
            switch (item) {
                .artifact => |artifact| {
                    if (validate_references) {
                        try self.validateArtifactReference(
                            current_platform,
                            before_stage_index,
                            0,
                            artifact.artifact,
                        );
                    }
                },
                .literal_flag => |flag| {
                    if (flag.len == 0) {
                        try self.setDiagnostic(
                            "link sequence '{s}' contains an empty literal flag",
                            .{owner},
                        );
                        return error.InvalidModel;
                    }
                },
                .tool_mode_flag => |flag| {
                    if (flag.driver == null and flag.raw == null) {
                        try self.setDiagnostic(
                            "link sequence '{s}' has a tool-mode flag with no representation",
                            .{owner},
                        );
                        return error.InvalidModel;
                    }
                },
                .group_start => group_depth += 1,
                .group_end => {
                    if (group_depth == 0) {
                        try self.setDiagnostic(
                            "link sequence '{s}' closes an archive group before opening one",
                            .{owner},
                        );
                        return error.InvalidModel;
                    }
                    group_depth -= 1;
                },
                .library_argument => |argument| {
                    if (argument.len == 0) {
                        try self.setDiagnostic(
                            "link sequence '{s}' contains an empty library argument",
                            .{owner},
                        );
                        return error.InvalidModel;
                    }
                },
            }
        }
        if (group_depth != 0) {
            try self.setDiagnostic(
                "link sequence '{s}' has an unterminated archive group",
                .{owner},
            );
            return error.InvalidModel;
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
        const source_active = library.enable.matches(self.config) and
            source.hasActiveVariant(self.config);
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
            if (library.enable.matches(self.config) and
                source.isVariantActive(self.config, variant))
            {
                try self.validateDependencies(library.name, source.name, variant.dependencies);
            }
            for (variant.preprocess) |step| {
                if (library.enable.matches(self.config) and
                    source.isVariantPreprocessStepActive(self.config, variant, step))
                {
                    try self.validateDependencies(library.name, source.name, step.dependencies);
                }
            }
        }
        if (source_active) {
            try self.validateDependencies(library.name, source.name, source.dependencies);
        }
        for (source.preprocess) |step| {
            if (source_active and source.isSourcePreprocessStepActive(self.config, step)) {
                try self.validateDependencies(library.name, source.name, step.dependencies);
            }
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
                    const dependency_index = self.findLibrary(name) orelse {
                        try self.setDiagnostic(
                            "library '{s}' source '{s}' references unknown component dependency '{s}'",
                            .{ library_name, source_name, name },
                        );
                        return error.InvalidReference;
                    };
                    if (!self.libraries.items[dependency_index].enable.matches(self.config)) {
                        try self.setDiagnostic(
                            "library '{s}' source '{s}' references inactive component '{s}'",
                            .{ library_name, source_name, name },
                        );
                        return error.InvalidReference;
                    }
                },
                .generated_output => |path| {
                    if (!self.isGeneratedOutputActive(path)) {
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

    fn validatePlatforms(self: *BuildContext, selected_platform_index: usize) ValidationError!void {
        for (self.platforms.items, 0..) |platform, platform_index| {
            if (platform.name.len == 0) {
                try self.setDiagnostic("platform names cannot be empty", .{});
                return error.InvalidModel;
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
            if (platform_index == selected_platform_index) {
                for (platform.libraries) |library_name| {
                    const library_index = self.findLibrary(library_name) orelse {
                        try self.setDiagnostic(
                            "selected platform '{s}' references unknown library '{s}'",
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
                    if (!library.enable.matches(self.config)) {
                        try self.setDiagnostic(
                            "selected platform '{s}' registers inactive platform library '{s}'",
                            .{ platform.name, library_name },
                        );
                        return error.InvalidReference;
                    }
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
                if (platform_index == selected_platform_index and
                    stage.condition.matches(self.config))
                {
                    try self.validateLinkSequence(
                        stage.name,
                        platform.name,
                        stage_index,
                        stage.sequence,
                        true,
                    );
                }
            }
            for (platform.post_process, 0..) |transformation, index| {
                for (platform.post_process[0..index]) |previous| {
                    if (std.mem.eql(u8, previous.name, transformation.name)) {
                        try self.setDiagnostic(
                            "platform '{s}' repeats post-processing name '{s}'",
                            .{ platform.name, transformation.name },
                        );
                        return error.DuplicateName;
                    }
                }
                if (transformation.effects.len == 0) {
                    try self.setDiagnostic(
                        "platform '{s}' post-processing '{s}' declares no outputs or mutation",
                        .{ platform.name, transformation.name },
                    );
                    return error.InvalidModel;
                }
                for (transformation.effects, 0..) |effect, effect_index| {
                    const effect_name = postEffectName(effect);
                    if (effect_name.len == 0) {
                        try self.setDiagnostic(
                            "platform '{s}' post-processing '{s}' has an unnamed output",
                            .{ platform.name, transformation.name },
                        );
                        return error.InvalidModel;
                    }
                    switch (effect) {
                        .create => |created| {
                            if (created.path.len == 0) {
                                try self.setDiagnostic(
                                    "platform '{s}' post-processing '{s}' has an empty output path",
                                    .{ platform.name, transformation.name },
                                );
                                return error.InvalidModel;
                            }
                        },
                        .mutate_input => |mutated| {
                            if (mutated.input_index > transformation.additional_inputs.len) {
                                try self.setDiagnostic(
                                    "platform '{s}' post-processing '{s}' mutates missing input index {d}",
                                    .{ platform.name, transformation.name, mutated.input_index },
                                );
                                return error.InvalidReference;
                            }
                        },
                    }
                    for (transformation.effects[0..effect_index]) |previous| {
                        if (std.mem.eql(u8, postEffectName(previous), effect_name)) {
                            try self.setDiagnostic(
                                "platform '{s}' post-processing '{s}' repeats output name '{s}'",
                                .{ platform.name, transformation.name, effect_name },
                            );
                            return error.DuplicateName;
                        }
                    }
                }
                if (platform_index == selected_platform_index and
                    transformation.condition.matches(self.config))
                {
                    try self.validateArtifactReference(
                        platform.name,
                        platform.link_stages.len,
                        index,
                        transformation.input,
                    );
                    for (transformation.additional_inputs) |input| {
                        try self.validateArtifactReference(
                            platform.name,
                            platform.link_stages.len,
                            index,
                            input,
                        );
                    }
                }
            }
            if (platform_index == selected_platform_index) {
                for (platform.object_inputs) |artifact| {
                    try self.validateArtifactReference(platform.name, platform.link_stages.len, 0, artifact);
                }
                for (platform.archive_inputs) |artifact| {
                    try self.validateArtifactReference(platform.name, platform.link_stages.len, 0, artifact);
                }
                for (platform.linker_scripts) |artifact| {
                    try self.validateArtifactReference(platform.name, platform.link_stages.len, 0, artifact);
                }
                for (platform.custom_link_dependencies) |artifact| {
                    try self.validateArtifactReference(platform.name, platform.link_stages.len, 0, artifact);
                }
            }
        }
    }

    fn validateArtifactReference(
        self: *BuildContext,
        current_platform: ?[]const u8,
        before_stage_index: usize,
        before_post_process_index: usize,
        reference: ArtifactReference,
    ) ValidationError!void {
        switch (reference) {
            .path => {},
            .generated_output => |path| {
                if (!self.isGeneratedOutputActive(path)) {
                    try self.setDiagnostic(
                        "active link pipeline references unknown generated output '{s}'",
                        .{path},
                    );
                    return error.InvalidReference;
                }
            },
            .component_output => |output| {
                const library_index = self.findLibrary(output.component) orelse {
                    try self.setDiagnostic(
                        "active link pipeline references output from unknown library '{s}'",
                        .{output.component},
                    );
                    return error.InvalidReference;
                };
                const library = self.libraries.items[library_index];
                if (!library.enable.matches(self.config) or
                    !self.libraryProducesActive(library, output.path))
                {
                    try self.setDiagnostic(
                        "active link pipeline references unavailable output '{s}' from library '{s}'",
                        .{ output.path, output.component },
                    );
                    return error.InvalidReference;
                }
            },
            .library_partial_output, .library_final_object => |component| {
                const library_index = self.findLibrary(component) orelse {
                    try self.setDiagnostic(
                        "active link pipeline references object pipeline from unknown library '{s}'",
                        .{component},
                    );
                    return error.InvalidReference;
                };
                const library = self.libraries.items[library_index];
                if (!library.enable.matches(self.config) or library.object_pipeline == null) {
                    try self.setDiagnostic(
                        "active link pipeline references unavailable object pipeline from library '{s}'",
                        .{component},
                    );
                    return error.InvalidReference;
                }
            },
            .stage_output => |output| {
                const platform_name = current_platform orelse {
                    try self.setDiagnostic(
                        "library object pipelines cannot reference platform stage '{s}'",
                        .{output.stage},
                    );
                    return error.InvalidReference;
                };
                if (!std.mem.eql(u8, output.platform, platform_name)) {
                    try self.setDiagnostic(
                        "platform '{s}' cannot consume stage output from platform '{s}'",
                        .{ platform_name, output.platform },
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
                if (found == null or found.? >= before_stage_index or
                    !stages[found.?].condition.matches(self.config))
                {
                    try self.setDiagnostic(
                        "platform '{s}' stage reference '{s}' must name an earlier stage",
                        .{ platform_name, output.stage },
                    );
                    return error.InvalidReference;
                }
            },
            .post_process_output => |output| {
                const platform_name = current_platform orelse {
                    try self.setDiagnostic(
                        "library object pipelines cannot reference post-processing output '{s}'",
                        .{output.output},
                    );
                    return error.InvalidReference;
                };
                if (!std.mem.eql(u8, output.platform, platform_name)) {
                    try self.setDiagnostic(
                        "platform '{s}' cannot consume post-processing output from platform '{s}'",
                        .{ platform_name, output.platform },
                    );
                    return error.InvalidReference;
                }
                const platform_index = self.findPlatform(output.platform) orelse {
                    try self.setDiagnostic(
                        "post-processing reference names unknown platform '{s}'",
                        .{output.platform},
                    );
                    return error.InvalidReference;
                };
                const transformations = self.platforms.items[platform_index].post_process;
                var found: ?usize = null;
                for (transformations, 0..) |transformation, index| {
                    if (std.mem.eql(u8, transformation.name, output.transformation)) {
                        found = index;
                        break;
                    }
                }
                if (found == null or found.? >= before_post_process_index or
                    !transformations[found.?].condition.matches(self.config) or
                    !postEffectExists(transformations[found.?], output.output))
                {
                    try self.setDiagnostic(
                        "platform '{s}' post-processing reference '{s}.{s}' must name an earlier active output",
                        .{ platform_name, output.transformation, output.output },
                    );
                    return error.InvalidReference;
                }
            },
        }
    }

    fn validateOutputs(
        self: *BuildContext,
        selected_platform_index: usize,
    ) ValidationError!void {
        var outputs = std.array_list.Managed([]const u8).init(self.allocator);
        defer outputs.deinit();

        for (self.libraries.items) |library| {
            if (!library.enable.matches(self.config)) continue;
            for (library.archives) |artifact| {
                if (artifact.condition.matches(self.config)) {
                    try self.recordOutput(&outputs, artifact.path);
                }
            }
            for (library.raw_objects) |artifact| {
                if (artifact.condition.matches(self.config)) {
                    try self.recordOutput(&outputs, artifact.path);
                }
            }
            for (library.sources) |source| {
                if (!source.hasActiveVariant(self.config)) continue;
                for (source.preprocess) |step| {
                    if (source.isSourcePreprocessStepActive(self.config, step)) {
                        try self.recordOutput(&outputs, step.output);
                    }
                }
                for (source.variants) |variant| {
                    if (!source.isVariantActive(self.config, variant)) continue;
                    for (variant.preprocess) |step| {
                        if (source.isVariantPreprocessStepActive(self.config, variant, step)) {
                            try self.recordOutput(&outputs, step.output);
                        }
                    }
                    if (variant.output) |output| {
                        if (output.kind != .no_op) try self.recordOutput(&outputs, output.path);
                        if (output.dependency_file) |path| try self.recordOutput(&outputs, path);
                    }
                }
            }
            if (library.object_pipeline) |pipeline| {
                try self.recordOutput(&outputs, pipeline.partial_link_output);
                try self.recordOutput(&outputs, pipeline.transform.output);
            }
        }
        const platform = self.platforms.items[selected_platform_index];
        for (platform.link_stages) |stage| {
            if (stage.condition.matches(self.config)) {
                try self.recordOutput(&outputs, stage.output);
            }
        }
        for (platform.post_process) |transformation| {
            if (!transformation.condition.matches(self.config)) continue;
            for (transformation.effects) |effect| {
                switch (effect) {
                    .create => |created| try self.recordOutput(&outputs, created.path),
                    .mutate_input => |mutated| {
                        if (mutated.name.len == 0) {
                            try self.setDiagnostic(
                                "platform '{s}' post-processing '{s}' has an unnamed in-place output",
                                .{ platform.name, transformation.name },
                            );
                            return error.InvalidModel;
                        }
                    },
                }
            }
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

    fn isGeneratedOutputActive(self: BuildContext, path: []const u8) bool {
        for (self.libraries.items) |library| {
            if (!library.enable.matches(self.config)) continue;
            for (library.sources) |source| {
                if (!source.hasActiveVariant(self.config)) continue;
                for (source.preprocess) |step| {
                    if (source.isSourcePreprocessStepActive(self.config, step) and
                        std.mem.eql(u8, step.output, path)) return true;
                }
                for (source.variants) |variant| {
                    if (!source.isVariantActive(self.config, variant)) continue;
                    for (variant.preprocess) |step| {
                        if (source.isVariantPreprocessStepActive(self.config, variant, step) and
                            std.mem.eql(u8, step.output, path)) return true;
                    }
                    if (variant.output) |output| {
                        if (output.kind == .generated and std.mem.eql(u8, output.path, path)) return true;
                    }
                }
            }
        }
        return false;
    }

    fn libraryProducesActive(
        self: BuildContext,
        library: Library,
        path: []const u8,
    ) bool {
        for (library.archives) |artifact| {
            if (artifact.condition.matches(self.config) and
                std.mem.eql(u8, artifact.path, path)) return true;
        }
        for (library.raw_objects) |artifact| {
            if (artifact.condition.matches(self.config) and
                std.mem.eql(u8, artifact.path, path)) return true;
        }
        for (library.sources) |source| {
            if (!source.hasActiveVariant(self.config)) continue;
            for (source.preprocess) |step| {
                if (source.isSourcePreprocessStepActive(self.config, step) and
                    std.mem.eql(u8, step.output, path)) return true;
            }
            for (source.variants) |variant| {
                if (!source.isVariantActive(self.config, variant)) continue;
                for (variant.preprocess) |step| {
                    if (source.isVariantPreprocessStepActive(self.config, variant, step) and
                        std.mem.eql(u8, step.output, path)) return true;
                }
                if (variant.output) |output| {
                    if (std.mem.eql(u8, output.path, path)) return true;
                }
            }
        }
        if (library.object_pipeline) |pipeline| {
            if (std.mem.eql(u8, pipeline.partial_link_output, path) or
                std.mem.eql(u8, pipeline.transform.output, path)) return true;
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

fn postEffectName(effect: PostProcessEffect) []const u8 {
    return switch (effect) {
        .create => |created| created.name,
        .mutate_input => |mutated| mutated.name,
    };
}

fn postEffectExists(
    transformation: PostProcessTransformation,
    wanted: []const u8,
) bool {
    for (transformation.effects) |effect| {
        if (std.mem.eql(u8, postEffectName(effect), wanted)) return true;
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
    if (library.object_pipeline) |pipeline| {
        if (std.mem.eql(u8, pipeline.partial_link_output, path) or
            std.mem.eql(u8, pipeline.transform.output, path)) return true;
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
    const command = try allocator.dupe(u8, tool.command);
    errdefer allocator.free(command);
    return .{
        .command = command,
        .version = if (tool.version) |version|
            try copySemanticVersion(allocator, version)
        else
            null,
    };
}

fn copySemanticVersion(
    allocator: std.mem.Allocator,
    version: std.SemanticVersion,
) !std.SemanticVersion {
    const pre = if (version.pre) |value| try allocator.dupe(u8, value) else null;
    errdefer if (pre) |value| allocator.free(value);
    const build = if (version.build) |value| try allocator.dupe(u8, value) else null;
    errdefer if (build) |value| allocator.free(value);
    return .{
        .major = version.major,
        .minor = version.minor,
        .patch = version.patch,
        .pre = pre,
        .build = build,
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

fn copyCondition(
    allocator: std.mem.Allocator,
    condition: Condition,
) error{OutOfMemory}!Condition {
    return switch (condition) {
        .always => .always,
        .config_enabled => |name| .{ .config_enabled = try allocator.dupe(u8, name) },
        .config_disabled => |name| .{ .config_disabled = try allocator.dupe(u8, name) },
        .config_equals => |expected| .{ .config_equals = .{
            .name = try allocator.dupe(u8, expected.name),
            .value = try allocator.dupe(u8, expected.value),
        } },
        .all => |conditions| .{ .all = try copyConditions(allocator, conditions) },
        .any => |conditions| .{ .any = try copyConditions(allocator, conditions) },
    };
}

fn copyConditions(
    allocator: std.mem.Allocator,
    conditions: []const Condition,
) error{OutOfMemory}![]const Condition {
    const result = try allocator.alloc(Condition, conditions.len);
    for (conditions, 0..) |condition, index| {
        result[index] = try copyCondition(allocator, condition);
    }
    return result;
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
        .object_pipeline = if (library.object_pipeline) |pipeline|
            try copyLibraryObjectPipeline(allocator, pipeline)
        else
            null,
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
        .library_partial_output => |component| .{
            .library_partial_output = try allocator.dupe(u8, component),
        },
        .library_final_object => |component| .{
            .library_final_object = try allocator.dupe(u8, component),
        },
        .stage_output => |output| .{ .stage_output = .{
            .platform = try allocator.dupe(u8, output.platform),
            .stage = try allocator.dupe(u8, output.stage),
        } },
        .post_process_output => |output| .{ .post_process_output = .{
            .platform = try allocator.dupe(u8, output.platform),
            .transformation = try allocator.dupe(u8, output.transformation),
            .output = try allocator.dupe(u8, output.output),
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

fn copyToolModeFlag(allocator: std.mem.Allocator, flag: ToolModeFlag) !ToolModeFlag {
    return .{
        .driver = if (flag.driver) |value| try allocator.dupe(u8, value) else null,
        .raw = if (flag.raw) |value| try allocator.dupe(u8, value) else null,
    };
}

fn copyLinkSequence(
    allocator: std.mem.Allocator,
    sequence: []const LinkSequenceItem,
) ![]const LinkSequenceItem {
    const result = try allocator.alloc(LinkSequenceItem, sequence.len);
    for (sequence, 0..) |item, index| {
        result[index] = switch (item) {
            .artifact => |artifact| .{ .artifact = .{
                .kind = artifact.kind,
                .artifact = try copyArtifactReference(allocator, artifact.artifact),
                .provenance = artifact.provenance,
            } },
            .literal_flag => |flag| .{ .literal_flag = try allocator.dupe(u8, flag) },
            .tool_mode_flag => |flag| .{ .tool_mode_flag = try copyToolModeFlag(allocator, flag) },
            .group_start => .group_start,
            .group_end => .group_end,
            .library_argument => |argument| .{
                .library_argument = try allocator.dupe(u8, argument),
            },
        };
    }
    return result;
}

fn copyLinkStages(allocator: std.mem.Allocator, stages: []const LinkStage) ![]const LinkStage {
    const result = try allocator.alloc(LinkStage, stages.len);
    for (stages, 0..) |stage, index| {
        result[index] = .{
            .name = try allocator.dupe(u8, stage.name),
            .transformation = try copyLinkTransformation(allocator, stage.transformation),
            .output = try allocator.dupe(u8, stage.output),
            .output_role = stage.output_role,
            .condition = try copyCondition(allocator, stage.condition),
            .sequence = try copyLinkSequence(allocator, stage.sequence),
        };
    }
    return result;
}

fn copyObjectTransformSequence(
    allocator: std.mem.Allocator,
    sequence: []const ObjectTransformItem,
) ![]const ObjectTransformItem {
    const result = try allocator.alloc(ObjectTransformItem, sequence.len);
    for (sequence, 0..) |item, index| {
        result[index] = switch (item) {
            .symbol_file => |symbol| .{ .symbol_file = .{
                .action = symbol.action,
                .symbols_file = try allocator.dupe(u8, symbol.symbols_file),
                .provenance = symbol.provenance,
                .condition = try copyCondition(allocator, symbol.condition),
            } },
            .literal_flag => |flag| .{ .literal_flag = try allocator.dupe(u8, flag) },
        };
    }
    return result;
}

fn copyLibraryObjectPipeline(
    allocator: std.mem.Allocator,
    pipeline: LibraryObjectPipeline,
) !LibraryObjectPipeline {
    return .{
        .partial_link_output = try allocator.dupe(u8, pipeline.partial_link_output),
        .partial_link_sequence = try copyLinkSequence(allocator, pipeline.partial_link_sequence),
        .transform = .{
            .input = try copyArtifactReference(allocator, pipeline.transform.input),
            .output = try allocator.dupe(u8, pipeline.transform.output),
            .sequence = try copyObjectTransformSequence(
                allocator,
                pipeline.transform.sequence,
            ),
        },
    };
}

fn copyPostProcessKind(
    allocator: std.mem.Allocator,
    kind: PostProcessKind,
) !PostProcessKind {
    return switch (kind) {
        .strip => .strip,
        .objcopy_binary => .objcopy_binary,
        .symbols => .symbols,
        .bootinfo => .bootinfo,
        .multiboot => .multiboot,
        .efi => .efi,
        .linux_header => .linux_header,
        .gzip => .gzip,
        .compile_database => .compile_database,
        .custom => |name| .{ .custom = try allocator.dupe(u8, name) },
    };
}

fn copyPostProcessEffects(
    allocator: std.mem.Allocator,
    effects: []const PostProcessEffect,
) ![]const PostProcessEffect {
    const result = try allocator.alloc(PostProcessEffect, effects.len);
    for (effects, 0..) |effect, index| {
        result[index] = switch (effect) {
            .create => |created| .{ .create = .{
                .name = try allocator.dupe(u8, created.name),
                .path = try allocator.dupe(u8, created.path),
                .role = created.role,
            } },
            .mutate_input => |mutated| .{ .mutate_input = .{
                .name = try allocator.dupe(u8, mutated.name),
                .role = mutated.role,
                .input_index = mutated.input_index,
            } },
        };
    }
    return result;
}

fn copyPostProcess(
    allocator: std.mem.Allocator,
    transformations: []const PostProcessTransformation,
) ![]const PostProcessTransformation {
    const result = try allocator.alloc(PostProcessTransformation, transformations.len);
    for (transformations, 0..) |transformation, index| {
        result[index] = .{
            .name = try allocator.dupe(u8, transformation.name),
            .kind = try copyPostProcessKind(allocator, transformation.kind),
            .input = try copyArtifactReference(allocator, transformation.input),
            .additional_inputs = try copyArtifactReferences(
                allocator,
                transformation.additional_inputs,
            ),
            .condition = try copyCondition(allocator, transformation.condition),
            .effects = try copyPostProcessEffects(allocator, transformation.effects),
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
        std.mem.eql(u8, name, "CONFIG_LIBUKBOOT") or
        std.mem.eql(u8, name, "CONFIG_KVM_BOOT_PROTO_MULTIBOOT") or
        std.mem.eql(u8, name, "CONFIG_OPTIMIZE_SYMFILE") or
        std.mem.eql(u8, name, "CONFIG_OPTIMIZE_COMPRESS");
}

fn testConfigEnabledXen(_: ?*const anyopaque, name: []const u8) bool {
    return std.mem.eql(u8, name, "CONFIG_PLAT_XEN") or
        std.mem.eql(u8, name, "CONFIG_OPTIMIZE_SYMFILE") or
        std.mem.eql(u8, name, "CONFIG_OPTIMIZE_COMPRESS");
}

fn testConfigEnabledKvmArm64(_: ?*const anyopaque, name: []const u8) bool {
    return std.mem.eql(u8, name, "CONFIG_PLAT_KVM") or
        std.mem.eql(u8, name, "CONFIG_KVM_BOOT_PROTO_LXBOOT") or
        std.mem.eql(u8, name, "CONFIG_OPTIMIZE_COMPRESS");
}

fn testConfigValue(_: ?*const anyopaque, name: []const u8) ?[]const u8 {
    if (std.mem.eql(u8, name, "CONFIG_UK_ARCH")) return "x86_64";
    return null;
}

fn testConfigValueArm64(_: ?*const anyopaque, name: []const u8) ?[]const u8 {
    if (std.mem.eql(u8, name, "CONFIG_UK_ARCH")) return "arm64";
    return null;
}

fn testConfig() ConfigQuery {
    return .{
        .is_enabled_fn = testConfigEnabled,
        .value_fn = testConfigValue,
    };
}

fn testXenConfig() ConfigQuery {
    return .{
        .is_enabled_fn = testConfigEnabledXen,
        .value_fn = testConfigValue,
    };
}

fn testKvmArm64Config() ConfigQuery {
    return .{
        .is_enabled_fn = testConfigEnabledKvmArm64,
        .value_fn = testConfigValueArm64,
    };
}

fn testXenArm64Config() ConfigQuery {
    return .{
        .is_enabled_fn = testConfigEnabledXen,
        .value_fn = testConfigValueArm64,
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

fn testArm64Toolchain() Toolchain {
    var toolchain = testToolchain();
    toolchain.target_triple = "aarch64-unknown-none";
    return toolchain;
}

fn initTestContextForTarget(
    allocator: std.mem.Allocator,
    config: ConfigQuery,
    toolchain: Toolchain,
    target: Target,
) !BuildContext {
    return BuildContext.init(allocator, .{
        .roots = .{
            .base = "/src/unikraft",
            .app = "/src/app",
            .output = "/src/app/build",
            .config = "/src/app/build/.config",
        },
        .target = target,
        .toolchain = toolchain,
        .global_flags = .{ .common = &.{"-ffreestanding"} },
        .global_includes = &.{.{ .path = "/src/unikraft/include" }},
        .config = config,
    });
}

fn initTestContext(
    allocator: std.mem.Allocator,
    config: ConfigQuery,
    toolchain: Toolchain,
) !BuildContext {
    return initTestContextForTarget(allocator, config, toolchain, .{
        .architecture = .x86_64,
        .family = .x86,
        .abi = "none",
        .triple = "x86_64-unknown-none",
    });
}

fn testArm64ContextWithConfig(config: ConfigQuery) !BuildContext {
    return initTestContextForTarget(
        std.testing.allocator,
        config,
        testArm64Toolchain(),
        .{
            .architecture = .arm64,
            .family = .arm,
            .abi = "none",
            .triple = "aarch64-unknown-none",
        },
    );
}

fn testContextWithConfig(config: ConfigQuery) !BuildContext {
    return initTestContext(std.testing.allocator, config, testToolchain());
}

fn testContextWith(config: ConfigQuery, toolchain: Toolchain) !BuildContext {
    return initTestContext(std.testing.allocator, config, toolchain);
}

fn testContext() !BuildContext {
    return testContextWithConfig(testConfig());
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
        source.effectiveInput(context.config, source.variants[0]),
    );
    try std.testing.expect(source.variants[0].dependencies[0] == .generated_output);
}

test "effective source input selects the last active preprocessing step" {
    const config = testConfig();
    const default_variant = SourceVariant{};

    const disabled_final = Source{
        .name = "disabled-final",
        .path = "/src/input.c",
        .language = .generated,
        .preprocess = &.{
            .{ .name = "active", .kind = .awk, .output = "/build/active.c" },
            .{
                .name = "disabled",
                .kind = .m4,
                .output = "/build/disabled.c",
                .condition = .{ .config_enabled = "CONFIG_NEVER" },
            },
        },
    };
    try std.testing.expectEqualStrings(
        "/build/active.c",
        disabled_final.effectiveInput(config, default_variant),
    );

    const disabled_middle = Source{
        .name = "disabled-middle",
        .path = "/src/input.c",
        .language = .generated,
        .preprocess = &.{
            .{ .name = "first", .kind = .awk, .output = "/build/first.c" },
            .{
                .name = "middle",
                .kind = .m4,
                .output = "/build/middle.c",
                .condition = .{ .config_enabled = "CONFIG_NEVER" },
            },
            .{ .name = "last", .kind = .generated, .output = "/build/last.c" },
        },
    };
    try std.testing.expectEqualStrings(
        "/build/last.c",
        disabled_middle.effectiveInput(config, default_variant),
    );

    const variant_source = Source{
        .name = "variant",
        .path = "/src/variant.c",
        .language = .generated,
        .preprocess = &.{.{
            .name = "source",
            .kind = .awk,
            .output = "/build/source.c",
        }},
    };
    const active_variant = SourceVariant{
        .condition = .{ .config_enabled = "CONFIG_PLAT_KVM" },
        .preprocess = &.{.{
            .name = "variant",
            .kind = .m4,
            .output = "/build/variant.c",
        }},
    };
    try std.testing.expectEqualStrings(
        "/build/variant.c",
        variant_source.effectiveInput(config, active_variant),
    );
    const inactive_variant = SourceVariant{
        .condition = .{ .config_enabled = "CONFIG_NEVER" },
        .preprocess = active_variant.preprocess,
    };
    try std.testing.expectEqualStrings(
        "/src/variant.c",
        variant_source.effectiveInput(config, inactive_variant),
    );
    const inactive_source = Source{
        .name = "inactive-source",
        .path = "/src/inactive.c",
        .language = .generated,
        .condition = .{ .config_enabled = "CONFIG_NEVER" },
        .preprocess = variant_source.preprocess,
    };
    try std.testing.expectEqualStrings(
        "/src/inactive.c",
        inactive_source.effectiveInput(config, default_variant),
    );

    const no_active_step = Source{
        .name = "none",
        .path = "/src/original.c",
        .language = .generated,
        .preprocess = &.{.{
            .name = "disabled",
            .kind = .awk,
            .output = "/build/disabled.c",
            .condition = .{ .config_enabled = "CONFIG_NEVER" },
        }},
    };
    try std.testing.expectEqualStrings(
        "/src/original.c",
        no_active_step.effectiveInput(config, default_variant),
    );
}

test "conditional preprocessing references only active generated outputs" {
    var valid = try testContext();
    defer valid.deinit();
    try valid.registerLibrary(.{
        .name = "libgenerated",
        .origin = .{ .internal = .library },
        .layout = .{ .ordinary = .{ .build_subdir = "libgenerated" } },
        .sources = &.{.{
            .name = "generated",
            .path = "/src/input.awk",
            .language = .generated,
            .preprocess = &.{
                .{ .name = "active", .kind = .awk, .output = "/build/active.c" },
                .{
                    .name = "disabled-final",
                    .kind = .m4,
                    .output = "/build/disabled.c",
                    .condition = .{ .config_enabled = "CONFIG_NEVER" },
                },
            },
            .variants = &.{.{
                .dependencies = &.{.{ .generated_output = "/build/active.c" }},
                .output = .{ .path = "/build/generated.o", .kind = .object },
            }},
        }},
    });
    try valid.registerPlatform(.{
        .name = "kvm",
        .origin = .{ .internal = .platform },
        .enable = .always,
    });
    _ = try valid.finalize();

    var invalid = try testContext();
    defer invalid.deinit();
    try invalid.registerLibrary(.{
        .name = "libgenerated",
        .origin = .{ .internal = .library },
        .layout = .{ .ordinary = .{ .build_subdir = "libgenerated" } },
        .sources = &.{.{
            .name = "generated",
            .path = "/src/input.awk",
            .language = .generated,
            .preprocess = &.{.{
                .name = "disabled",
                .kind = .awk,
                .output = "/build/disabled.c",
                .condition = .{ .config_enabled = "CONFIG_NEVER" },
            }},
            .variants = &.{.{
                .dependencies = &.{.{ .generated_output = "/build/disabled.c" }},
                .output = .{ .path = "/build/generated.o", .kind = .object },
            }},
        }},
    });
    try invalid.registerPlatform(.{
        .name = "kvm",
        .origin = .{ .internal = .platform },
        .enable = .always,
    });
    try std.testing.expectError(error.InvalidReference, invalid.finalize());
}

fn registerRepresentativeModel(
    context: *BuildContext,
    architecture: Architecture,
) !void {
    const xen_arm = architecture == .arm64 or architecture == .arm32;
    const xen_image = if (xen_arm) "/build/app_xen.elf" else "/build/app_xen";
    const xen_debug = if (xen_arm) "/build/app_xen.elf.dbg" else "/build/app_xen.dbg";
    const xen_bootinfo = if (xen_arm) "/build/app_xen.elf.bootinfo" else "/build/app_xen.bootinfo";
    const xen_symbols = if (xen_arm) "/build/app_xen.elf.sym" else "/build/app_xen.sym";
    try context.registerLibrary(.{
        .name = "libcore",
        .origin = .{ .internal = .core },
        .layout = .{ .ordinary = .{ .build_subdir = "libcore" } },
        .exports = &.{"/src/unikraft/lib/core/exportsyms.uk"},
        .locals = &.{"/src/unikraft/lib/core/localsyms.uk"},
        .raw_objects = &.{.{ .path = "/build/libcore/main.o" }},
        .archives = &.{.{ .path = "/build/libcore/local.a" }},
        .object_pipeline = .{
            .partial_link_output = "/build/libcore.ld.o",
            .partial_link_sequence = &.{
                .{ .tool_mode_flag = .{
                    .driver = "-Wl,--gc-sections",
                    .raw = "--gc-sections",
                } },
                .{ .artifact = .{
                    .kind = .object,
                    .artifact = .{ .component_output = .{
                        .component = "libcore",
                        .path = "/build/libcore/main.o",
                    } },
                    .provenance = .library_local,
                } },
                .{ .artifact = .{
                    .kind = .object,
                    .artifact = .{ .path = "/build/each-global.o" },
                    .provenance = .each_library,
                } },
                .group_start,
                .{ .artifact = .{
                    .kind = .archive,
                    .artifact = .{ .component_output = .{
                        .component = "libcore",
                        .path = "/build/libcore/local.a",
                    } },
                    .provenance = .library_local,
                } },
                .{ .artifact = .{
                    .kind = .archive,
                    .artifact = .{ .path = "/build/each-global.a" },
                    .provenance = .each_library,
                } },
                .group_end,
            },
            .transform = .{
                .input = .{ .library_partial_output = "libcore" },
                .output = "/build/libcore.o",
                .sequence = &.{
                    .{ .symbol_file = .{
                        .action = .keep_global,
                        .symbols_file = "/src/unikraft/lib/core/exportsyms.uk",
                        .provenance = .library_local,
                    } },
                    .{ .symbol_file = .{
                        .action = .keep_global,
                        .symbols_file = "/build/each-exportsyms.uk",
                        .provenance = .each_library,
                    } },
                    .{ .symbol_file = .{
                        .action = .localize,
                        .symbols_file = "/src/unikraft/lib/core/localsyms.uk",
                        .provenance = .library_local,
                    } },
                    .{ .literal_flag = "--wildcard" },
                },
            },
        },
    });
    try context.registerLibrary(.{
        .name = "libkvmplat",
        .kind = .platform_library,
        .origin = .{ .internal = .platform },
        .enable = .{ .config_enabled = "CONFIG_PLAT_KVM" },
        .layout = .{ .ordinary = .{ .build_subdir = "libkvmplat" } },
        .platforms = &.{"kvm"},
        .archives = &.{.{ .path = "/build/libkvmplat.a" }},
        .object_pipeline = .{
            .partial_link_output = "/build/libkvmplat.ld.o",
            .partial_link_sequence = &.{
                .{ .artifact = .{
                    .kind = .archive,
                    .artifact = .{ .component_output = .{
                        .component = "libkvmplat",
                        .path = "/build/libkvmplat.a",
                    } },
                    .provenance = .library_local,
                } },
            },
            .transform = .{
                .input = .{ .library_partial_output = "libkvmplat" },
                .output = "/build/libkvmplat.o",
            },
        },
    });
    try context.registerLibrary(.{
        .name = "libxenplat",
        .kind = .platform_library,
        .origin = .{ .internal = .platform },
        .enable = .{ .config_enabled = "CONFIG_PLAT_XEN" },
        .layout = .{ .ordinary = .{ .build_subdir = "libxenplat" } },
        .platforms = &.{"xen"},
        .archives = &.{.{ .path = "/build/libxenplat.a" }},
        .object_pipeline = .{
            .partial_link_output = "/build/libxenplat.ld.o",
            .partial_link_sequence = &.{
                .{ .artifact = .{
                    .kind = .archive,
                    .artifact = .{ .component_output = .{
                        .component = "libxenplat",
                        .path = "/build/libxenplat.a",
                    } },
                    .provenance = .library_local,
                } },
            },
            .transform = .{
                .input = .{ .library_partial_output = "libxenplat" },
                .output = "/build/libxenplat.o",
            },
        },
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
                .output_role = .debug,
                .sequence = &.{
                    .{ .literal_flag = "-Wl,--entry=_multiboot_entry" },
                    .{ .artifact = .{
                        .kind = .object,
                        .artifact = .{ .library_final_object = "libkvmplat" },
                        .provenance = .platform,
                    } },
                    .{ .artifact = .{
                        .kind = .object,
                        .artifact = .{ .library_final_object = "libcore" },
                        .provenance = .global,
                    } },
                    .group_start,
                    .{ .artifact = .{
                        .kind = .archive,
                        .artifact = .{ .path = "/build/kvm-platform.a" },
                        .provenance = .platform,
                    } },
                    .{ .artifact = .{
                        .kind = .archive,
                        .artifact = .{ .path = "/build/global.a" },
                        .provenance = .global,
                    } },
                    .group_end,
                    .{ .library_argument = "-lgcc" },
                    .{ .literal_flag = "-Wl,--build-id=none" },
                    .{ .artifact = .{
                        .kind = .linker_script,
                        .artifact = .{ .path = "/src/unikraft/plat/kvm/link64.lds" },
                        .provenance = .platform,
                    } },
                },
            },
        },
        .post_process = &.{
            .{
                .name = "strip",
                .kind = .strip,
                .input = .{ .stage_output = .{ .platform = "kvm", .stage = "final-link" } },
                .effects = &.{.{ .create = .{
                    .name = "image",
                    .path = "/build/app_kvm",
                    .role = .image,
                } }},
            },
            .{
                .name = "bootinfo",
                .kind = .bootinfo,
                .input = .{ .post_process_output = .{
                    .platform = "kvm",
                    .transformation = "strip",
                    .output = "image",
                } },
                .effects = &.{
                    .{ .create = .{
                        .name = "bootinfo",
                        .path = "/build/app_kvm.bootinfo",
                        .role = .side,
                    } },
                    .{ .mutate_input = .{ .name = "image", .role = .image } },
                },
            },
            .{
                .name = "multiboot",
                .kind = .multiboot,
                .condition = .{ .config_enabled = "CONFIG_KVM_BOOT_PROTO_MULTIBOOT" },
                .input = .{ .post_process_output = .{
                    .platform = "kvm",
                    .transformation = "bootinfo",
                    .output = "image",
                } },
                .effects = &.{.{ .mutate_input = .{ .name = "image", .role = .image } }},
            },
            .{
                .name = "efi",
                .kind = .efi,
                .condition = .{ .config_enabled = "CONFIG_KVM_BOOT_PROTO_EFI_STUB" },
                .input = .{ .post_process_output = .{
                    .platform = "kvm",
                    .transformation = "bootinfo",
                    .output = "image",
                } },
                .additional_inputs = &.{.{ .stage_output = .{
                    .platform = "kvm",
                    .stage = "final-link",
                } }},
                .effects = &.{.{ .mutate_input = .{ .name = "image", .role = .image } }},
            },
            .{
                .name = "linux-binary",
                .kind = .objcopy_binary,
                .condition = .{ .all = &.{
                    .{ .config_enabled = "CONFIG_KVM_BOOT_PROTO_LXBOOT" },
                    .{ .config_equals = .{ .name = "CONFIG_UK_ARCH", .value = "arm64" } },
                } },
                .input = .{ .post_process_output = .{
                    .platform = "kvm",
                    .transformation = "bootinfo",
                    .output = "image",
                } },
                .effects = &.{.{ .mutate_input = .{ .name = "image", .role = .image } }},
            },
            .{
                .name = "linux-header",
                .kind = .linux_header,
                .condition = .{ .all = &.{
                    .{ .config_enabled = "CONFIG_KVM_BOOT_PROTO_LXBOOT" },
                    .{ .config_equals = .{ .name = "CONFIG_UK_ARCH", .value = "arm64" } },
                } },
                .input = .{ .post_process_output = .{
                    .platform = "kvm",
                    .transformation = "linux-binary",
                    .output = "image",
                } },
                .additional_inputs = &.{.{ .stage_output = .{
                    .platform = "kvm",
                    .stage = "final-link",
                } }},
                .effects = &.{.{ .mutate_input = .{ .name = "image", .role = .image } }},
            },
            .{
                .name = "symbols",
                .kind = .symbols,
                .condition = .{ .config_enabled = "CONFIG_OPTIMIZE_SYMFILE" },
                .input = .{ .stage_output = .{ .platform = "kvm", .stage = "final-link" } },
                .effects = &.{.{ .create = .{
                    .name = "sym",
                    .path = "/build/app_kvm.sym",
                    .role = .image,
                } }},
            },
            .{
                .name = "gzip",
                .kind = .gzip,
                .condition = .{ .config_enabled = "CONFIG_OPTIMIZE_COMPRESS" },
                .input = .{ .post_process_output = .{
                    .platform = "kvm",
                    .transformation = "bootinfo",
                    .output = "image",
                } },
                .effects = &.{.{ .create = .{
                    .name = "gz",
                    .path = "/build/app_kvm.gz",
                    .role = .image,
                } }},
            },
            .{
                .name = "compile-db",
                .kind = .compile_database,
                .input = .{ .post_process_output = .{
                    .platform = "kvm",
                    .transformation = "bootinfo",
                    .output = "image",
                } },
                .effects = &.{.{ .create = .{
                    .name = "database",
                    .path = "/build/compile_commands.json",
                    .role = .auxiliary,
                } }},
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
                .sequence = &.{
                    .{ .tool_mode_flag = .{ .driver = "-Wl,-r", .raw = "-r" } },
                    .{ .artifact = .{
                        .kind = .object,
                        .artifact = .{ .library_final_object = "libxenplat" },
                        .provenance = .platform,
                    } },
                    .{ .artifact = .{
                        .kind = .object,
                        .artifact = .{ .library_final_object = "libcore" },
                        .provenance = .global,
                    } },
                    .group_start,
                    .{ .artifact = .{
                        .kind = .archive,
                        .artifact = .{ .path = "/build/xen-platform.a" },
                        .provenance = .platform,
                    } },
                    .{ .artifact = .{
                        .kind = .archive,
                        .artifact = .{ .path = "/build/global.a" },
                        .provenance = .global,
                    } },
                    .group_end,
                    .{ .library_argument = "-lgcc" },
                },
            },
            .{
                .name = "localize",
                .transformation = .objcopy_localize,
                .output = "/build/app_xen.o",
                .sequence = &.{
                    .{ .literal_flag = "-w" },
                    .{ .literal_flag = "-G" },
                    .{ .literal_flag = "xenos_*" },
                    .{ .artifact = .{
                        .kind = .intermediate,
                        .artifact = .{ .stage_output = .{
                            .platform = "xen",
                            .stage = "partial-link",
                        } },
                    } },
                },
            },
            .{
                .name = "final-link",
                .transformation = .final_link,
                .output = xen_debug,
                .output_role = .debug,
                .sequence = &.{
                    .{ .literal_flag = "-Wl,--build-id=none" },
                    .{ .artifact = .{
                        .kind = .linker_script,
                        .artifact = .{ .path = "/src/unikraft/plat/xen/link64.lds" },
                        .provenance = .platform,
                    } },
                    .{ .artifact = .{
                        .kind = .intermediate,
                        .artifact = .{ .stage_output = .{
                            .platform = "xen",
                            .stage = "localize",
                        } },
                    } },
                },
            },
        },
        .post_process = &.{
            .{
                .name = "strip",
                .kind = .strip,
                .input = .{ .stage_output = .{ .platform = "xen", .stage = "final-link" } },
                .effects = &.{.{ .create = .{
                    .name = "image",
                    .path = xen_image,
                    .role = .image,
                } }},
            },
            .{
                .name = "bootinfo",
                .kind = .bootinfo,
                .input = .{ .post_process_output = .{
                    .platform = "xen",
                    .transformation = "strip",
                    .output = "image",
                } },
                .effects = &.{
                    .{ .create = .{
                        .name = "bootinfo",
                        .path = xen_bootinfo,
                        .role = .side,
                    } },
                    .{ .mutate_input = .{ .name = "image", .role = .image } },
                },
            },
            .{
                .name = "raw-image-arm",
                .kind = .objcopy_binary,
                .condition = .{ .config_equals = .{ .name = "CONFIG_UK_ARCH", .value = "arm" } },
                .input = .{ .post_process_output = .{
                    .platform = "xen",
                    .transformation = "bootinfo",
                    .output = "image",
                } },
                .effects = &.{.{ .create = .{
                    .name = "raw",
                    .path = "/build/app_xen",
                    .role = .image,
                } }},
            },
            .{
                .name = "raw-image-arm64",
                .kind = .objcopy_binary,
                .condition = .{ .config_equals = .{ .name = "CONFIG_UK_ARCH", .value = "arm64" } },
                .input = .{ .post_process_output = .{
                    .platform = "xen",
                    .transformation = "bootinfo",
                    .output = "image",
                } },
                .effects = &.{.{ .create = .{
                    .name = "raw",
                    .path = "/build/app_xen",
                    .role = .image,
                } }},
            },
            .{
                .name = "symbols",
                .kind = .symbols,
                .condition = .{ .config_enabled = "CONFIG_OPTIMIZE_SYMFILE" },
                .input = .{ .stage_output = .{ .platform = "xen", .stage = "final-link" } },
                .effects = &.{.{ .create = .{
                    .name = "sym",
                    .path = xen_symbols,
                    .role = .image,
                } }},
            },
            .{
                .name = "gzip-x86",
                .kind = .gzip,
                .condition = .{ .all = &.{
                    .{ .config_enabled = "CONFIG_OPTIMIZE_COMPRESS" },
                    .{ .config_equals = .{ .name = "CONFIG_UK_ARCH", .value = "x86_64" } },
                } },
                .input = .{ .post_process_output = .{
                    .platform = "xen",
                    .transformation = "bootinfo",
                    .output = "image",
                } },
                .effects = &.{.{ .create = .{
                    .name = "gz",
                    .path = "/build/app_xen.gz",
                    .role = .image,
                } }},
            },
            .{
                .name = "gzip-arm",
                .kind = .gzip,
                .condition = .{ .all = &.{
                    .{ .config_enabled = "CONFIG_OPTIMIZE_COMPRESS" },
                    .{ .config_equals = .{ .name = "CONFIG_UK_ARCH", .value = "arm" } },
                } },
                .input = .{ .post_process_output = .{
                    .platform = "xen",
                    .transformation = "raw-image-arm",
                    .output = "raw",
                } },
                .effects = &.{.{ .create = .{
                    .name = "gz",
                    .path = "/build/app_xen.gz",
                    .role = .image,
                } }},
            },
            .{
                .name = "gzip-arm64",
                .kind = .gzip,
                .condition = .{ .all = &.{
                    .{ .config_enabled = "CONFIG_OPTIMIZE_COMPRESS" },
                    .{ .config_equals = .{ .name = "CONFIG_UK_ARCH", .value = "arm64" } },
                } },
                .input = .{ .post_process_output = .{
                    .platform = "xen",
                    .transformation = "raw-image-arm64",
                    .output = "raw",
                } },
                .effects = &.{.{ .create = .{
                    .name = "gz",
                    .path = "/build/app_xen.gz",
                    .role = .image,
                } }},
            },
            .{
                .name = "compile-db",
                .kind = .compile_database,
                .input = .{ .post_process_output = .{
                    .platform = "xen",
                    .transformation = "bootinfo",
                    .output = "image",
                } },
                .effects = &.{.{ .create = .{
                    .name = "database",
                    .path = "/build/compile_commands.json",
                    .role = .auxiliary,
                } }},
            },
        },
    });
}

test "library and KVM pipelines preserve every ordered argument" {
    var context = try testContext();
    defer context.deinit();
    try registerRepresentativeModel(&context, .x86_64);

    const graph = try context.finalize();
    try std.testing.expectEqualStrings("kvm", graph.selectedPlatform().name);
    const library_pipeline = graph.libraries[0].object_pipeline.?;
    try std.testing.expect(library_pipeline.partial_link_sequence[0] == .tool_mode_flag);
    try std.testing.expectEqualStrings(
        "--gc-sections",
        library_pipeline.partial_link_sequence[0].tool_mode_flag.forMode(.raw).?,
    );
    try std.testing.expect(
        library_pipeline.partial_link_sequence[1].artifact.provenance == .library_local,
    );
    try std.testing.expect(
        library_pipeline.partial_link_sequence[2].artifact.provenance == .each_library,
    );
    try std.testing.expect(library_pipeline.partial_link_sequence[3] == .group_start);
    try std.testing.expect(library_pipeline.partial_link_sequence[6] == .group_end);
    try std.testing.expectEqualStrings("/build/libcore.ld.o", library_pipeline.partial_link_output);
    try std.testing.expectEqualStrings("/build/libcore.o", library_pipeline.transform.output);

    try std.testing.expectEqualStrings("final-link", graph.platforms[0].link_stages[0].name);
    const kvm_sequence = graph.platforms[0].link_stages[0].sequence;
    try std.testing.expect(kvm_sequence[0] == .literal_flag);
    try std.testing.expect(kvm_sequence[1].artifact.artifact == .library_final_object);
    try std.testing.expectEqualStrings(
        "libkvmplat",
        kvm_sequence[1].artifact.artifact.library_final_object,
    );
    try std.testing.expect(kvm_sequence[3] == .group_start);
    try std.testing.expect(kvm_sequence[6] == .group_end);
    try std.testing.expect(kvm_sequence[7] == .library_argument);

    const kvm_post = graph.platforms[0].post_process;
    try std.testing.expectEqualStrings("strip", kvm_post[0].name);
    try std.testing.expectEqualStrings("bootinfo", kvm_post[1].name);
    try std.testing.expect(kvm_post[1].effects[0] == .create);
    try std.testing.expect(kvm_post[1].effects[1] == .mutate_input);
    try std.testing.expectEqual(@as(usize, 1), kvm_post[2].effects.len);
    try std.testing.expect(kvm_post[2].effects[0] == .mutate_input);
    try std.testing.expectEqualStrings("efi", kvm_post[3].name);
    try std.testing.expectEqual(@as(usize, 1), kvm_post[3].additional_inputs.len);
    try std.testing.expect(kvm_post[3].effects[0] == .mutate_input);
    try std.testing.expectEqualStrings("linux-binary", kvm_post[4].name);
    try std.testing.expect(kvm_post[4].effects[0] == .mutate_input);
    try std.testing.expectEqualStrings("linux-header", kvm_post[5].name);
    try std.testing.expectEqual(@as(usize, 1), kvm_post[5].additional_inputs.len);
    try std.testing.expect(kvm_post[5].effects[0] == .mutate_input);
    try std.testing.expectEqualStrings("symbols", kvm_post[6].name);
    try std.testing.expectEqualStrings("gzip", kvm_post[7].name);
    try std.testing.expectEqualStrings("compile-db", kvm_post[kvm_post.len - 1].name);
}

test "Xen pipeline and inactive KVM duplicate outputs validate" {
    var context = try testContextWithConfig(testXenConfig());
    defer context.deinit();
    try registerRepresentativeModel(&context, .x86_64);

    const graph = try context.finalize();
    try std.testing.expectEqualStrings("xen", graph.selectedPlatform().name);
    try std.testing.expectEqualStrings("partial-link", graph.platforms[1].link_stages[0].name);
    try std.testing.expectEqualStrings("localize", graph.platforms[1].link_stages[1].name);
    try std.testing.expectEqualStrings("final-link", graph.platforms[1].link_stages[2].name);
    const partial_sequence = graph.platforms[1].link_stages[0].sequence;
    try std.testing.expectEqualStrings(
        "-r",
        partial_sequence[0].tool_mode_flag.forMode(graph.toolchain.partial_linker.mode).?,
    );
    try std.testing.expect(partial_sequence[3] == .group_start);
    try std.testing.expect(partial_sequence[6] == .group_end);
    const xen_post = graph.platforms[1].post_process;
    const kvm_post = graph.platforms[0].post_process;
    try std.testing.expectEqualStrings("gzip-x86", xen_post[5].name);
    try std.testing.expectEqualStrings(
        "bootinfo",
        xen_post[5].input.post_process_output.transformation,
    );
    try std.testing.expectEqualStrings(
        "/build/compile_commands.json",
        xen_post[xen_post.len - 1].effects[0].create.path,
    );
    try std.testing.expectEqualStrings(
        kvm_post[kvm_post.len - 1].effects[0].create.path,
        xen_post[xen_post.len - 1].effects[0].create.path,
    );
}

test "arm64 KVM protocol and Linux header steps mutate the image in order" {
    var context = try testArm64ContextWithConfig(testKvmArm64Config());
    defer context.deinit();
    try registerRepresentativeModel(&context, .arm64);

    const graph = try context.finalize();
    try std.testing.expect(graph.target.architecture == .arm64);
    try std.testing.expectEqualStrings("kvm", graph.selectedPlatform().name);
    const post = graph.platforms[0].post_process;
    try std.testing.expectEqualStrings("linux-binary", post[4].name);
    try std.testing.expect(post[4].condition.matches(context.config));
    try std.testing.expect(post[4].effects[0] == .mutate_input);
    try std.testing.expectEqualStrings(
        "bootinfo",
        post[4].input.post_process_output.transformation,
    );
    try std.testing.expectEqualStrings("linux-header", post[5].name);
    try std.testing.expect(post[5].condition.matches(context.config));
    try std.testing.expect(post[5].effects[0] == .mutate_input);
    try std.testing.expectEqualStrings(
        "linux-binary",
        post[5].input.post_process_output.transformation,
    );
    try std.testing.expectEqual(@as(usize, 1), post[5].additional_inputs.len);
    try std.testing.expect(post[5].additional_inputs[0] == .stage_output);
}

test "arm64 Xen gzip consumes the separate raw image" {
    var context = try testArm64ContextWithConfig(testXenArm64Config());
    defer context.deinit();
    try registerRepresentativeModel(&context, .arm64);

    const graph = try context.finalize();
    try std.testing.expectEqualStrings("xen", graph.selectedPlatform().name);
    const post = graph.platforms[1].post_process;
    try std.testing.expectEqualStrings("/build/app_xen.elf", post[0].effects[0].create.path);
    try std.testing.expectEqualStrings("raw-image-arm64", post[3].name);
    try std.testing.expect(post[3].condition.matches(context.config));
    try std.testing.expectEqualStrings("/build/app_xen", post[3].effects[0].create.path);
    try std.testing.expectEqualStrings("gzip-arm64", post[7].name);
    try std.testing.expect(post[7].condition.matches(context.config));
    try std.testing.expectEqualStrings(
        "raw-image-arm64",
        post[7].input.post_process_output.transformation,
    );
    try std.testing.expectEqualStrings("/build/app_xen.gz", post[7].effects[0].create.path);
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

test "post-processing rejects conflicting producers but permits in-place mutation" {
    var valid = try testContext();
    defer valid.deinit();
    try valid.registerPlatform(.{
        .name = "kvm",
        .origin = .{ .internal = .platform },
        .enable = .always,
        .link_stages = &.{.{
            .name = "link",
            .transformation = .final_link,
            .output = "/build/debug",
        }},
        .post_process = &.{
            .{
                .name = "strip",
                .kind = .strip,
                .input = .{ .stage_output = .{ .platform = "kvm", .stage = "link" } },
                .effects = &.{.{ .create = .{
                    .name = "image",
                    .path = "/build/image",
                    .role = .image,
                } }},
            },
            .{
                .name = "metadata",
                .kind = .bootinfo,
                .input = .{ .post_process_output = .{
                    .platform = "kvm",
                    .transformation = "strip",
                    .output = "image",
                } },
                .effects = &.{.{ .mutate_input = .{ .name = "image", .role = .image } }},
            },
        },
    });
    _ = try valid.finalize();

    var conflict = try testContext();
    defer conflict.deinit();
    try conflict.registerPlatform(.{
        .name = "kvm",
        .origin = .{ .internal = .platform },
        .enable = .always,
        .link_stages = &.{.{
            .name = "link",
            .transformation = .final_link,
            .output = "/build/debug",
        }},
        .post_process = &.{
            .{
                .name = "first",
                .kind = .strip,
                .input = .{ .stage_output = .{ .platform = "kvm", .stage = "link" } },
                .effects = &.{.{ .create = .{
                    .name = "image",
                    .path = "/build/image",
                    .role = .image,
                } }},
            },
            .{
                .name = "second",
                .kind = .gzip,
                .input = .{ .stage_output = .{ .platform = "kvm", .stage = "link" } },
                .effects = &.{.{ .create = .{
                    .name = "other",
                    .path = "/build/image",
                    .role = .image,
                } }},
            },
        },
    });
    try std.testing.expectError(error.DuplicateOutput, conflict.finalize());
}

test "post-processing and typed library outputs reject forward or missing references" {
    var forward = try testContext();
    defer forward.deinit();
    try forward.registerPlatform(.{
        .name = "kvm",
        .origin = .{ .internal = .platform },
        .enable = .always,
        .post_process = &.{
            .{
                .name = "first",
                .kind = .gzip,
                .input = .{ .post_process_output = .{
                    .platform = "kvm",
                    .transformation = "later",
                    .output = "image",
                } },
                .effects = &.{.{ .create = .{
                    .name = "gz",
                    .path = "/build/image.gz",
                    .role = .image,
                } }},
            },
            .{
                .name = "later",
                .kind = .strip,
                .input = .{ .path = "/build/debug" },
                .effects = &.{.{ .create = .{
                    .name = "image",
                    .path = "/build/image",
                    .role = .image,
                } }},
            },
        },
    });
    try std.testing.expectError(error.InvalidReference, forward.finalize());

    var missing_library = try testContext();
    defer missing_library.deinit();
    try missing_library.registerPlatform(.{
        .name = "kvm",
        .origin = .{ .internal = .platform },
        .enable = .always,
        .link_stages = &.{.{
            .name = "link",
            .transformation = .final_link,
            .output = "/build/debug",
            .sequence = &.{.{ .artifact = .{
                .kind = .object,
                .artifact = .{ .library_final_object = "libmissing" },
            } }},
        }},
    });
    try std.testing.expectError(error.InvalidReference, missing_library.finalize());
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

fn expectOwnedVersionMetadata(tool: Tool) !void {
    const version = tool.version.?;
    try std.testing.expectEqualStrings("rc.1", version.pre.?);
    try std.testing.expectEqualStrings("vendor.7", version.build.?);
}

test "tool versions own prerelease and build metadata" {
    const allocator = std.testing.allocator;
    const pre = try allocator.dupe(u8, "rc.1");
    const build = try allocator.dupe(u8, "vendor.7");
    var inputs_freed = false;
    defer if (!inputs_freed) {
        allocator.free(pre);
        allocator.free(build);
    };

    const version = std.SemanticVersion{
        .major = 19,
        .minor = 0,
        .patch = 0,
        .pre = pre,
        .build = build,
    };
    var toolchain = testToolchain();
    toolchain.compiler.tool.version = version;
    toolchain.partial_linker.tool.version = version;
    toolchain.final_linker.tool.version = version;
    toolchain.binutils.ar.version = version;
    toolchain.binutils.objcopy.version = version;
    toolchain.binutils.strip.version = version;
    toolchain.binutils.nm.version = version;
    toolchain.binutils.objdump = .{ .command = "llvm-objdump", .version = version };
    toolchain.host = .{
        .cc = .{ .command = "cc", .version = version },
        .cxx = .{ .command = "c++", .version = version },
        .awk = .{ .command = "awk", .version = version },
        .m4 = .{ .command = "m4", .version = version },
        .dtc = .{ .command = "dtc", .version = version },
        .python = .{ .command = "python3", .version = version },
    };

    var context = try testContextWith(testConfig(), toolchain);
    defer context.deinit();

    @memset(pre, 'x');
    @memset(build, 'y');
    allocator.free(pre);
    allocator.free(build);
    inputs_freed = true;

    try expectOwnedVersionMetadata(context.toolchain.compiler.tool);
    try expectOwnedVersionMetadata(context.toolchain.partial_linker.tool);
    try expectOwnedVersionMetadata(context.toolchain.final_linker.tool);
    try expectOwnedVersionMetadata(context.toolchain.binutils.ar);
    try expectOwnedVersionMetadata(context.toolchain.binutils.objcopy);
    try expectOwnedVersionMetadata(context.toolchain.binutils.strip);
    try expectOwnedVersionMetadata(context.toolchain.binutils.nm);
    try expectOwnedVersionMetadata(context.toolchain.binutils.objdump.?);
    try expectOwnedVersionMetadata(context.toolchain.host.cc.?);
    try expectOwnedVersionMetadata(context.toolchain.host.cxx.?);
    try expectOwnedVersionMetadata(context.toolchain.host.awk.?);
    try expectOwnedVersionMetadata(context.toolchain.host.m4.?);
    try expectOwnedVersionMetadata(context.toolchain.host.dtc.?);
    try expectOwnedVersionMetadata(context.toolchain.host.python.?);
}

fn exerciseVersionCopyFailurePaths(allocator: std.mem.Allocator) !void {
    const version = std.SemanticVersion{
        .major = 19,
        .minor = 0,
        .patch = 0,
        .pre = "rc.1",
        .build = "vendor.7",
    };
    var toolchain = testToolchain();
    toolchain.compiler.tool.version = version;
    toolchain.partial_linker.tool.version = version;
    toolchain.final_linker.tool.version = version;
    toolchain.binutils.ar.version = version;
    toolchain.binutils.objcopy.version = version;
    toolchain.binutils.strip.version = version;
    toolchain.binutils.nm.version = version;
    toolchain.binutils.objdump = .{ .command = "llvm-objdump", .version = version };
    toolchain.host.cc = .{ .command = "cc", .version = version };
    toolchain.host.python = .{ .command = "python3", .version = version };

    var context = try initTestContext(allocator, testConfig(), toolchain);
    defer context.deinit();
    try expectOwnedVersionMetadata(context.toolchain.compiler.tool);
}

test "tool version partial-copy failures release all allocations" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        exerciseVersionCopyFailurePaths,
        .{},
    );
}
