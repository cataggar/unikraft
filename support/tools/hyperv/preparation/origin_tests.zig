const std = @import("std");
const c = @import("contracts.zig");
const o = @import("origin.zig");
const fixture = @import("origin_fixture.zig");
const fs = @import("files.zig");
const rt = @import("runtime.zig");

const DataFixture = struct {
    temporary: std.testing.TmpDir,
    root: fs.Directory,
    bound: rt.Bound,
    allocator: std.mem.Allocator,

    fn init(a: std.mem.Allocator, bytes: []const u8) !DataFixture {
        const io = std.testing.io;
        var temporary = std.testing.tmpDir(.{ .iterate = true });
        errdefer temporary.cleanup();
        try temporary.dir.setPermissions(io, .fromMode(0o700));
        try temporary.dir.createDir(io, "runtime", .fromMode(0o700));
        const path = try temporary.dir.realPathFileAlloc(io, "runtime", a);
        const root = try fs.Directory.open(a, io, path);
        _ = try fixture.write(a, io, root, "tool", bytes);
        const synthetic = try fixture.distribution(a, io, root);
        return .{
            .temporary = temporary,
            .root = root,
            .allocator = a,
            .bound = .{ .directory = root, .contract = .{
                .role = .firmware,
                .target = .data,
                .origin = synthetic.origin,
                .evidence = synthetic.evidence,
                .tree = (try fs.inventory(a, io, root, 256, c.total_cap)).tree,
                .executable = null,
                .loader = null,
                .libraries = &.{},
            } },
        };
    }
    fn deinit(self: *DataFixture) void {
        self.root.close(self.allocator, std.testing.io);
        self.temporary.cleanup();
    }
    fn evidence(self: *DataFixture) !fs.Directory {
        return fs.Directory.open(self.allocator, std.testing.io, self.bound.contract.evidence[0].directory.path);
    }
    fn catalog(self: *DataFixture) !o.Catalog {
        const dir = try self.evidence();
        defer dir.close(self.allocator, std.testing.io);
        const bytes = try o.readFile(self.allocator, std.testing.io, dir, self.bound.contract.evidence[0].set.catalog, 4 * 1024 * 1024);
        return (try c.parse(o.Catalog, self.allocator, bytes)).value;
    }
    fn artifact(self: *DataFixture) !o.Artifact {
        return (try self.catalog()).artifacts[0];
    }
    fn policy(self: *DataFixture) *o.Policy {
        return &@constCast(self.bound.contract.evidence[0].policy)[0];
    }
    fn validate(self: *DataFixture) !void {
        try self.bound.validate(self.allocator, std.testing.io);
    }
    fn rebind(self: *DataFixture, artifacts: []const o.Artifact) !void {
        const dir = try self.evidence();
        defer dir.close(self.allocator, std.testing.io);
        const binding = &@constCast(self.bound.contract.evidence)[0];
        const bytes = try c.canonical(self.allocator, o.Catalog{ .schema = .hyperv_runtime_origin_evidence_v1, .artifacts = artifacts });
        const file = try dir.dir.createFile(std.testing.io, "catalog.json", .{ .permissions = .fromMode(0o600) });
        defer file.close(std.testing.io);
        try file.writeStreamingAll(std.testing.io, bytes);
        binding.set.catalog = try dir.record(self.allocator, std.testing.io, "catalog.json", 4 * 1024 * 1024, .artifact);
        binding.set.tree = (try fs.inventory(self.allocator, std.testing.io, dir, 256, c.total_cap)).tree;
        binding.physical_sha256 = try fs.physicalDigest(self.allocator, std.testing.io, dir);
        self.bound.contract.origin.payload.distribution.evidence_set_sha256 = try o.hash(self.allocator, binding.set);
    }
    fn realization(self: *DataFixture, payload: o.RealizationPayload, name: []const u8) !void {
        var artifact_record = try self.artifact();
        const dir = try self.evidence();
        defer dir.close(self.allocator, std.testing.io);
        const previous_bytes = try o.readFile(self.allocator, std.testing.io, dir, artifact_record.realizations[0].verification, 4 * 1024 * 1024);
        var verified = (try c.parse(o.ArchiveVerification, self.allocator, previous_bytes)).value;
        verified.realization_payload_sha256 = try o.hash(self.allocator, payload);
        const proof = try fixture.write(self.allocator, std.testing.io, dir, name, try c.canonical(self.allocator, verified));
        const realizations = try self.allocator.alloc(o.Realization, 1);
        realizations[0] = .{ .payload = payload, .verification = proof };
        artifact_record.realizations = realizations;
        @constCast(self.policy().realization_verification_sha256)[0] = proof.sha256;
        try self.rebind(&.{artifact_record});
    }
};

test "Origin exact tagged payload roundtrip and legacy rejection" {
    const a = std.testing.allocator;
    const encoded = try c.canonical(a, fixture.local());
    defer a.free(encoded);
    const parsed = try c.parse(o.Origin, a, encoded);
    defer parsed.deinit();
    try std.testing.expectEqualStrings("1" ** 40, parsed.value.payload.local_build.source_revision);
    for ([_][]const u8{
        "{\"payload\":{},\"schema\":\"hyperv_runtime_origin_v2\"}\n",
        "{\"payload\":null,\"schema\":\"hyperv_runtime_origin_v2\"}\n",
        "{\"payload\":{\"unknown\":{}},\"schema\":\"hyperv_runtime_origin_v2\"}\n",
        "{\"payload\":{\"distribution\":{},\"local_build\":{}},\"schema\":\"hyperv_runtime_origin_v2\"}\n",
    }) |bytes| try std.testing.expectError(error.InvalidUnion, c.parse(o.Origin, a, bytes));
}

test "declared prefix relocation binary padding and literal text are exact" {
    const a = std.testing.allocator;
    const result = try o.relocate(a, "a/placeholder/lib:/placeholder/x\x00tail", "/placeholder", "/new", .binary);
    defer a.free(result);
    try std.testing.expectEqualStrings("a/new/lib:/new/x" ++ "\x00" ** 17 ++ "tail", result);
    const text = try o.relocate(a, "/placeholder/lib", "/placeholder", "/new", .text);
    defer a.free(text);
    try std.testing.expectEqualStrings("/new/lib", text);
    const longer = try o.relocate(a, "/old/lib", "/old", "/a/longer/prefix", .text);
    defer a.free(longer);
    try std.testing.expectEqualStrings("/a/longer/prefix/lib", longer);
    try std.testing.expectError(error.InvalidRelocation, o.relocate(a, "/placeholder/lib", "/placeholder", "/new", .binary));
    try std.testing.expectError(error.InvalidRelocation, o.relocate(a, "/old\x00", "/old", "/longer", .binary));
    try std.testing.expectError(error.InvalidRelocation, o.relocate(a, "absent\x00", "/old", "/new", .binary));
}

test "Origin rejects wrong null extra payload fields legacy epoch and data disguises" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    for ([_][]const u8{
        "{\"schema\":\"hyperv_runtime_origin_v1\",\"payload\":{\"local_build\":{\"source_revision\":\"1111111111111111111111111111111111111111\",\"source_physical_sha256\":\"1111111111111111111111111111111111111111111111111111111111111111\",\"compiler_executable_sha256\":\"2222222222222222222222222222222222222222222222222222222222222222\"}}}",
        "{\"schema\":\"hyperv_runtime_origin_v2\",\"payload\":{\"local_build\":null}}",
        "{\"schema\":\"hyperv_runtime_origin_v2\",\"payload\":{\"local_build\":{\"revision\":\"wrong\",\"source_sha256\":null,\"producer_sha256\":null}}}",
        "{\"schema\":\"hyperv_runtime_origin_v2\",\"payload\":{\"distribution\":{\"runtime_revision\":\"0.16.0\",\"evidence_set_sha256\":null,\"components\":[]}}}",
        "{\"schema\":\"hyperv_runtime_origin_v2\",\"payload\":{\"zig_packages\":{\"packages\":[],\"verified\":true}}}",
        "{\"scheme\":\"authenticated_distribution\",\"revision\":\"0.16.0\",\"source_sha256\":null,\"producer_sha256\":null}",
    }) |raw| {
        const parsed = try std.json.parseFromSlice(std.json.Value, a, raw, .{});
        const bytes = try c.canonical(a, parsed.value);
        if (c.parse(o.Origin, a, bytes)) |_| return error.AcceptedInvalidOrigin else |_| {}
    }
    try std.testing.expectError(error.InvalidOrigin, o.validate(fixture.shapePackage(), rt.Role.zig, @FieldType(rt.Tool, "target").aarch64_linux));
    inline for (.{ rt.Role.firmware, .bison_data, .trust }) |role|
        try std.testing.expectError(error.InvalidOrigin, o.validate(fixture.shapePackage(), role, @FieldType(rt.Tool, "target").data));
    var compiler = fixture.shapeDistribution();
    try o.validate(compiler, rt.Role.zig, @FieldType(rt.Tool, "target").aarch64_linux);
    compiler.payload.distribution.runtime_revision = "0.15.2";
    try std.testing.expectError(error.CompilerMismatch, o.validate(compiler, rt.Role.zig, @FieldType(rt.Tool, "target").aarch64_linux));
    compiler.payload.distribution.runtime_revision = c.compiler_version;
    try std.testing.expectError(error.CompilerMismatch, o.validate(compiler, rt.Role.zig, @FieldType(rt.Tool, "target").data));
}

test "Origin local actor and helper require the actual source HEAD snapshot and compiler kind" {
    const source: c.Source = .{
        .scheme = .git_physical_native_v1,
        .head = "1" ** 40,
        .tree = "2" ** 40,
        .tree_sha256 = c.digest("tree"),
        .physical = .{ .sha256 = c.digest("physical"), .files = 1, .bytes = 1 },
    };
    const compiler: c.File = .{ .path = "zig", .sha256 = c.digest("actual compiler executable"), .size = 1, .mode = 0o700 };
    var local: o.Origin = .{ .payload = .{ .local_build = .{
        .source_revision = source.head,
        .source_physical_sha256 = source.physical.sha256,
        .compiler_executable_sha256 = compiler.sha256,
    } } };
    try local.requireLocal(source, compiler);
    for (0..3) |i| {
        var wrong = local;
        switch (i) {
            0 => wrong.payload.local_build.source_revision = "3" ** 40,
            1 => wrong.payload.local_build.source_physical_sha256 = source.tree_sha256,
            2 => wrong.payload.local_build.compiler_executable_sha256 = c.digest("archive not compiler"),
            else => unreachable,
        }
        try std.testing.expectError(error.UnreviewedInput, wrong.requireLocal(source, compiler));
    }
    local = fixture.shapeDistribution();
    try std.testing.expectError(error.UnreviewedInput, local.requireLocal(source, compiler));
}

test "Origin mixed Git DSO and non ELF scopes cover selected bytes exactly once and stay compact" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var entries: [5]c.File = undefined;
    for ([_][]const u8{ "bin/git", "lib/libcrypto.so.3", "lib/libc.so.6", "lib/loader", "share/templates" }, &entries) |path, *file|
        file.* = .{ .path = path, .size = 1, .mode = 0o644, .sha256 = c.digest(path) };
    var components = [_]o.Component{
        .{ .artifact_id = "git", .selected_tree = fixture.tree, .scope = .{ .selected = &.{ .{ .file = "bin/git" }, .{ .subtree = "share" } } } },
        .{ .artifact_id = "openssl", .selected_tree = fixture.tree, .scope = .{ .selected = &.{.{ .file = "lib/libcrypto.so.3" }} } },
        .{ .artifact_id = "glibc", .selected_tree = fixture.tree, .scope = .{ .selected = &.{ .{ .file = "lib/libc.so.6" }, .{ .file = "lib/loader" } } } },
    };
    try o.requireCoverage(&entries, &components);
    try std.testing.expectError(error.OriginGap, o.requireCoverage(&entries, components[0..2]));
    const saved = components[2];
    components[2].scope = .{ .selected = &.{.{ .subtree = "lib" }} };
    try std.testing.expectError(error.OriginOverlap, o.requireCoverage(&entries, &components));
    components[2] = saved;
    const extra = entries ++ [_]c.File{.{ .path = "uncovered", .size = 1, .mode = 0o644, .sha256 = c.digest("extra") }};
    try std.testing.expectError(error.OriginGap, o.requireCoverage(&extra, &components));
    components[2].scope = .{ .selected = &.{ .{ .subtree = "lib" }, .{ .file = "absent" } } };
    try std.testing.expectError(error.OriginExtra, o.requireCoverage(entries[2..4], components[2..]));
    const zig_files = try a.alloc(c.File, 19546);
    for (zig_files, 0..) |*file, i| file.* = .{ .path = try std.fmt.allocPrint(a, "lib/file-{d}.zig", .{i}), .size = 1, .mode = 0o644, .sha256 = c.digest("synthetic Zig support") };
    const zig = [_]o.Component{.{ .artifact_id = "zig-release", .scope = .{ .whole = .{} }, .selected_tree = .{ .sha256 = c.digest("synthetic complete tree"), .files = 19546, .bytes = 19546 } }};
    try o.requireCoverage(zig_files, &zig);
    try std.testing.expect((try c.canonical(a, zig)).len < 1024);
}

test "Origin physical distribution requires immutable evidence and independently pinned subject authority and method" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var data = try DataFixture.init(a, "synthetic installed distribution\n");
    defer data.deinit();
    try data.validate();
    const original = data.bound;
    data.bound.contract.evidence = &.{};
    try std.testing.expectError(error.MissingWitness, data.validate());
    data.bound = original;
    const artifact = try data.artifact();
    data.policy().authority.publisher_https_sha256.publisher = "unapproved.invalid";
    try std.testing.expectError(error.WrongAuthority, data.validate());
    data.policy().authority.publisher_https_sha256.publisher = artifact.subject.publisher;
    data.policy().authority = .{ .pinned_key_signature = .{ .publisher = artifact.subject.publisher, .repository = artifact.subject.repository, .key_id = "required-existing-key" } };
    try std.testing.expectError(error.RequiredAuthenticationMethod, data.validate());
    data.policy().authority = .{ .publisher_https_sha256 = .{ .publisher = artifact.subject.publisher, .repository = artifact.subject.repository } };
    var wrong = artifact;
    wrong.authentication.publisher_https_sha256.subject.artifact_sha256 = c.digest("different package");
    data.policy().authentication_sha256 = try o.hash(a, wrong.authentication);
    try data.rebind(&.{wrong});
    try std.testing.expectError(error.WrongSubject, data.validate());
    data.policy().authentication_sha256 = try o.hash(a, artifact.authentication);
    try data.rebind(&.{artifact});
    try data.validate();
    const evidence = try data.evidence();
    defer evidence.close(a, std.testing.io);
    const file = try evidence.dir.openFile(std.testing.io, "transcript.txt", .{ .mode = .read_write });
    defer file.close(std.testing.io);
    try file.writePositionalAll(std.testing.io, "X", 0);
    try std.testing.expectError(error.SourceChanged, data.validate());
}

test "Origin pinned signature binds exact signature bytes key verification and forbids failure to absence downgrade" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var data = try DataFixture.init(a, "synthetic signed artifact member");
    defer data.deinit();
    var artifact = try data.artifact();
    const unsigned = artifact.authentication;
    const evidence = try data.evidence();
    defer evidence.close(a, std.testing.io);
    const signature = try fixture.write(a, std.testing.io, evidence, "signature.raw", "synthetic detached signature, not cryptographic evidence");
    const transcript = try evidence.record(a, std.testing.io, "transcript.txt", 4096, .artifact);
    const verification: o.SignatureVerification = .{
        .schema = .hyperv_origin_signature_verification_v1,
        .subject_sha256 = try o.hash(a, artifact.subject),
        .signed_bytes_sha256 = signature.sha256,
        .key_id = "independently-selected-fixture-key",
        .verifier = .{ .name = "synthetic", .version = "fixture", .executable_sha256 = c.digest("synthetic verifier"), .transcript = transcript },
    };
    artifact.authentication = .{ .pinned_key_signature = .{
        .subject = artifact.subject,
        .key_id = verification.key_id,
        .signature = signature,
        .verification = try fixture.write(a, std.testing.io, evidence, "signature-verification.json", try c.canonical(a, verification)),
    } };
    data.policy().authority = .{ .pinned_key_signature = .{ .publisher = artifact.subject.publisher, .repository = artifact.subject.repository, .key_id = verification.key_id } };
    data.policy().authentication_sha256 = try o.hash(a, artifact.authentication);
    try data.rebind(&.{artifact});
    try data.validate();
    var wrong = artifact;
    wrong.authentication.pinned_key_signature.key_id = "self-selected-key";
    data.policy().authentication_sha256 = try o.hash(a, wrong.authentication);
    try data.rebind(&.{wrong});
    try std.testing.expectError(error.WrongAuthority, data.validate());
    wrong.authentication = unsigned;
    data.policy().authentication_sha256 = try o.hash(a, unsigned);
    try data.rebind(&.{wrong});
    try std.testing.expectError(error.RequiredAuthenticationMethod, data.validate());
    wrong = artifact;
    wrong.authentication.pinned_key_signature.signature.sha256 = c.digest("different detached signature");
    data.policy().authentication_sha256 = try o.hash(a, wrong.authentication);
    try data.rebind(&.{wrong});
    try std.testing.expectError(error.HashMismatch, data.validate());
}

test "Origin signed repository metadata needs independently approved existing authority and retained index" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var data = try DataFixture.init(a, "synthetic repository package member");
    defer data.deinit();
    var artifact = try data.artifact();
    const evidence = try data.evidence();
    defer evidence.close(a, std.testing.io);
    const metadata = try fixture.write(a, std.testing.io, evidence, "InRelease.raw", "synthetic signed metadata, NOT an actual OpenPGP envelope");
    const index = try fixture.write(a, std.testing.io, evidence, "Packages.raw", "synthetic exact package index");
    const transcript = try evidence.record(a, std.testing.io, "transcript.txt", 4096, .artifact);
    const verification: o.SignatureVerification = .{
        .schema = .hyperv_origin_signature_verification_v1,
        .subject_sha256 = try o.hash(a, artifact.subject),
        .signed_bytes_sha256 = metadata.sha256,
        .key_id = "synthetic-existing-repository-key",
        .verifier = .{ .name = "synthetic", .version = "fixture", .executable_sha256 = c.digest("synthetic OpenPGP verifier"), .transcript = transcript },
    };
    artifact.authentication = .{ .signed_repository_metadata = .{
        .subject = artifact.subject,
        .key_id = verification.key_id,
        .metadata = metadata,
        .index = index,
        .verification = try fixture.write(a, std.testing.io, evidence, "index-verification.json", try c.canonical(a, verification)),
    } };
    data.policy().authority = .{ .signed_repository_metadata = .{ .publisher = artifact.subject.publisher, .repository = artifact.subject.repository, .key_id = verification.key_id } };
    data.policy().authentication_sha256 = try o.hash(a, artifact.authentication);
    try data.rebind(&.{artifact});
    try data.validate();
    data.policy().authority.signed_repository_metadata.key_id = "unapproved-new-key";
    try std.testing.expectError(error.WrongAuthority, data.validate());
    data.policy().authority.signed_repository_metadata.key_id = verification.key_id;
    try evidence.dir.deleteFile(std.testing.io, "Packages.raw");
    try std.testing.expectError(error.SourceChanged, data.validate());
}

test "Origin exact authenticated conda paths declaration original and result bytes constrain prefix replay" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const original = "header/placeholder/lib\x00tail";
    const installed = try o.relocate(a, original, "/placeholder", "/new", .binary);
    var data = try DataFixture.init(a, installed);
    defer data.deinit();
    const artifact = try data.artifact();
    const evidence = try data.evidence();
    defer evidence.close(a, std.testing.io);
    const member: c.File = .{ .path = "bin/tool", .size = original.len, .sha256 = c.digest(original), .mode = 0o600 };
    const declared = try fixture.write(a, std.testing.io, evidence, "paths.json", try c.canonical(a, .{
        .paths_version = @as(u32, 1),
        .paths = .{.{
            ._path = member.path,
            .sha256 = member.sha256,
            .size_in_bytes = member.size,
            .prefix_placeholder = "/placeholder",
            .file_mode = "binary",
            .path_type = "hardlink",
        }},
    }));
    const relocation: o.Relocation = .{
        .member = member,
        .original = try fixture.write(a, std.testing.io, evidence, "original.bin", original),
        .destination = try data.root.record(a, std.testing.io, "tool", 4096, .artifact),
        .placeholder = "/placeholder",
        .mode = .binary,
        .installed_prefix = "/new",
    };
    const relocations = try a.alloc(o.Relocation, 1);
    relocations[0] = relocation;
    const payload: o.RealizationPayload = .{ .declared_prefix_relocation = .{
        .artifact_sha256 = artifact.subject.artifact_sha256,
        .selected_tree = data.bound.contract.tree,
        .declaration = declared,
        .declaration_member = "info/paths.json",
        .unchanged = &.{},
        .relocated = relocations,
    } };
    try data.realization(payload, "prefix-proof.json");
    try data.validate();
    for (0..8) |i| {
        relocations[0] = relocation;
        var changed = payload;
        switch (i) {
            0 => relocations[0].placeholder = "/different",
            1 => relocations[0].member.size += 1,
            2 => relocations[0].member.sha256 = c.digest("wrong original"),
            3 => relocations[0].destination.size += 1,
            4 => relocations[0].destination.sha256 = c.digest("wrong result"),
            5 => relocations[0].installed_prefix = "/too-long-for-placeholder",
            6 => changed.declared_prefix_relocation.declaration_member = "hooks/post-link.sh",
            7 => relocations[0].mode = .text,
            else => unreachable,
        }
        try data.realization(changed, try std.fmt.allocPrint(a, "bad-prefix-{d}.json", .{i}));
        try std.testing.expectError(error.InvalidRelocation, data.validate());
    }
}

test "Origin Zig package singleton aggregate manifest pins roots and complete coverage are physical" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const io = std.testing.io;
    var temporary = std.testing.tmpDir(.{ .iterate = true });
    defer temporary.cleanup();
    try temporary.dir.setPermissions(io, .fromMode(0o700));
    try temporary.dir.createDir(io, "packages", .fromMode(0o700));
    try temporary.dir.createDir(io, "packages/pkg-pinned", .fromMode(0o700));
    const manifest = try fs.Directory.open(a, io, try temporary.dir.realPathFileAlloc(io, ".", a));
    defer manifest.close(a, io);
    const aggregate = try fs.Directory.open(a, io, try temporary.dir.realPathFileAlloc(io, "packages", a));
    defer aggregate.close(a, io);
    const singleton = try fs.Directory.open(a, io, try temporary.dir.realPathFileAlloc(io, "packages/pkg-pinned", a));
    defer singleton.close(a, io);
    _ = try fixture.write(a, io, singleton, "source.zig", "pub const dependency = true;\n");
    const bytes = ".{ .dependencies = .{ .data = .{ .url = \"https://synthetic.invalid/archive/7d70ce8.tar.gz\", .hash = \"pkg-pinned\", .lazy = true } } }\n";
    const declaration = try fixture.write(a, io, manifest, "build.zig.zon", bytes);
    var packages = [_]o.Package{.{
        .package_hash = "pkg-pinned",
        .locator = "https://synthetic.invalid/archive/7d70ce8.tar.gz",
        .revision = .{ .archive_selector = "7d70ce8" },
        .declaration = .{ .directory = try o.Identity.directory(manifest), .file = declaration, .entry = "data" },
        .scope = .{ .whole = .{} },
        .selected_tree = (try fs.inventory(a, io, singleton, 256, c.total_cap)).tree,
    }};
    var tool: rt.Tool = .{
        .role = .dependencies,
        .target = .data,
        .origin = .{ .payload = .{ .zig_packages = .{ .packages = &packages } } },
        .tree = packages[0].selected_tree,
        .executable = null,
        .loader = null,
        .libraries = &.{},
    };
    try (rt.Bound{ .directory = singleton, .contract = tool }).validate(a, io);
    packages[0].scope = .{ .selected = &.{.{ .subtree = "pkg-pinned" }} };
    packages[0].selected_tree = try fs.selectedTree(a, io, aggregate, packages[0].scope);
    tool.tree = (try fs.inventory(a, io, aggregate, 256, c.total_cap)).tree;
    try (rt.Bound{ .directory = aggregate, .contract = tool }).validate(a, io);
    packages[0].declaration.entry = "not_data";
    try std.testing.expectError(error.InvalidPackageDeclaration, (rt.Bound{ .directory = aggregate, .contract = tool }).validate(a, io));
    packages[0].declaration.entry = "data";
    packages[0].revision = .{ .git_commit = "7d70ce8" };
    try std.testing.expectError(error.InvalidObjectId, o.validate(tool.origin, tool.role, tool.target));
    packages[0].revision = .{ .archive_selector = "7d70ce8" };
    packages[0].locator = "https://wrong.invalid/archive/7d70ce8.tar.gz";
    try std.testing.expectError(error.InvalidPackageDeclaration, (rt.Bound{ .directory = aggregate, .contract = tool }).validate(a, io));
    packages[0].locator = "https://synthetic.invalid/archive/7d70ce8.tar.gz";
    const duplicate = packages ++ packages;
    tool.origin.payload.zig_packages.packages = &duplicate;
    try std.testing.expectError(error.InvalidOrigin, o.validate(tool.origin, tool.role, tool.target));
    tool.origin.payload.zig_packages.packages = &packages;
    packages[0].scope = .{ .whole = .{} };
    try std.testing.expectError(error.PackageRootMismatch, (rt.Bound{ .directory = aggregate, .contract = tool }).validate(a, io));
    const nested = ".{ .dependencies = .{ .data = .{ .fake = .{ .url = \"https://synthetic.invalid/archive/7d70ce8.tar.gz\", .hash = \"pkg-pinned\" } } } }\n";
    try std.testing.expectError(error.InvalidPackageDeclaration, o.requirePackageDeclaration(a, nested, packages[0]));
}

test "Origin unchanged member maps cannot borrow a proof or omit overlap escape or change selected bytes" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var data = try DataFixture.init(a, "unchanged member");
    defer data.deinit();
    var artifact = try data.artifact();
    const member = try data.root.record(a, std.testing.io, "tool", 4096, .artifact);
    var maps = [_]o.Map{.{ .file = .{ .member = member, .destination = member } }};
    const payload: o.RealizationPayload = .{ .unchanged_extraction = .{
        .artifact_sha256 = artifact.subject.artifact_sha256,
        .selected_tree = data.bound.contract.tree,
        .maps = &maps,
    } };
    try data.realization(payload, "file-proof.json");
    try data.validate();
    artifact = try data.artifact();
    const borrowed = try a.dupe(o.Realization, artifact.realizations);
    borrowed[0].payload.unchanged_extraction.artifact_sha256 = c.digest("wrong authenticated artifact");
    artifact.realizations = borrowed;
    try data.rebind(&.{artifact});
    try std.testing.expectError(error.WrongSubject, data.validate());
    try data.realization(payload, "restored-proof.json");
    maps[0].file.member.sha256 = c.digest("wrong archive member");
    try data.realization(payload, "wrong-member-proof.json");
    try std.testing.expectError(error.HashMismatch, data.validate());
    maps[0].file.member = member;
    maps[0].file.member.path = "../escape";
    try data.realization(payload, "escape-proof.json");
    try std.testing.expectError(error.UnsafePath, data.validate());
    maps[0].file.member = member;
    var duplicate = payload;
    const duplicates = maps ++ maps;
    duplicate.unchanged_extraction.maps = &duplicates;
    try data.realization(duplicate, "overlap-proof.json");
    try std.testing.expectError(error.OriginOverlap, data.validate());
    try std.testing.expectError(error.InvalidUnion, c.parse(o.RealizationPayload, a, "{\"run_hooks\":{}}\n"));
    try std.testing.expectError(error.InvalidUnion, c.parse(o.RealizationPayload, a, "{\"reviewed\":{}}\n"));
}

test "Origin firmware named asset held roots and every evidence copy are mandatory and charged" {
    const inputs = @import("inputs.zig");
    const budget = @import("budget.zig");
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const io = std.testing.io;
    var code = try DataFixture.init(a, "synthetic firmware code");
    defer code.deinit();
    var vars = try DataFixture.init(a, "synthetic firmware variables");
    defer vars.deinit();
    const code_file = try code.root.record(a, io, "tool", 4096, .artifact);
    const vars_file = try vars.root.record(a, io, "tool", 4096, .artifact);
    var assets: std.ArrayList(inputs.Asset) = .empty;
    var bindings: std.ArrayList(inputs.Binding) = .empty;
    try assets.appendSlice(a, &.{
        .{ .id = "code", .role = .firmware_code, .source = code_file, .destination = "firmware/code", .placement = .staged },
        .{ .id = "vars", .role = .firmware_vars, .source = vars_file, .destination = "firmware/vars", .placement = .staged },
    });
    try bindings.appendSlice(a, &.{ .{ .id = "code", .directory = code.root }, .{ .id = "vars", .directory = vars.root } });
    const evidence = [_]fs.Directory{ try code.evidence(), try vars.evidence() };
    defer for (evidence) |directory| directory.close(a, io);
    for (evidence) |directory| {
        const inventory = try fs.inventory(a, io, directory, 256, c.control_cap);
        for (inventory.entries) |file| {
            const id = try std.fmt.allocPrint(a, "evidence-{d}", .{assets.items.len});
            try assets.append(a, .{ .id = id, .role = .publication_control, .source = file, .destination = id, .placement = .staged });
            try bindings.append(a, .{ .id = id, .directory = directory });
        }
    }
    for (0..inputs.firmware_copy_count) |i| {
        const id = try std.fmt.allocPrint(a, "vars-copy-{d}", .{i});
        try assets.append(a, .{ .id = id, .role = .firmware_working_copy, .source = vars_file, .destination = id, .placement = .future_copy });
        try bindings.append(a, .{ .id = id, .directory = vars.root });
    }
    var plan: inputs.Plan = undefined;
    plan.assets = assets.items;
    plan.firmware_origins = .{
        .code = .{ .asset_id = "code", .directory = try o.Identity.directory(code.root), .physical_sha256 = try fs.physicalDigest(a, io, code.root), .tool = code.bound.contract, .member = code_file },
        .vars = .{ .asset_id = "vars", .directory = try o.Identity.directory(vars.root), .physical_sha256 = try fs.physicalDigest(a, io, vars.root), .tool = vars.bound.contract, .member = vars_file },
    };
    try inputs.requireFirmwareOrigins(a, io, plan, bindings.items);
    plan.firmware_origins.code.asset_id = "vars";
    try std.testing.expectError(error.InvalidFirmwareOrigin, inputs.requireFirmwareOrigins(a, io, plan, bindings.items));
    plan.firmware_origins.code.asset_id = "code";
    plan.firmware_origins.code.directory.inode += 1;
    try std.testing.expectError(error.SourceChanged, inputs.requireFirmwareOrigins(a, io, plan, bindings.items));
    plan.firmware_origins.code.directory.inode -= 1;
    const evidence_asset = assets.items[2];
    assets.items[2].placement = .baked;
    try std.testing.expectError(error.MissingControlBinding, inputs.requireFirmwareOrigins(a, io, plan, bindings.items));
    assets.items[2] = evidence_asset;
    const ledger = try a.alloc(budget.Entry, assets.items.len);
    var evidence_bytes: u64 = 0;
    for (assets.items, ledger) |asset, *entry| {
        entry.* = .{ .id = asset.id, .artifact = asset.destination, .role = asset.role, .source = asset.source, .reserved = 0 };
        if (asset.role == .publication_control) evidence_bytes += asset.source.size;
    }
    const totals = try budget.compute(ledger);
    try std.testing.expectEqual(evidence_bytes, totals.control);
    try std.testing.expectEqual(code_file.size + vars_file.size * 7 + evidence_bytes, totals.used);
    try code.root.dir.deleteFile(io, "tool");
    _ = try fixture.write(a, io, code.root, "tool", "synthetic firmware code");
    try fs.requireTree((try fs.inventory(a, io, code.root, 256, c.total_cap)).tree, plan.firmware_origins.code.tool.tree);
    try std.testing.expectError(error.SourceChanged, inputs.requireFirmwareOrigins(a, io, plan, bindings.items));
}
