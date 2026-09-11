//! Physical witness validation, NOT a signature verifier or acquisition client.
//! Expected witness commitments and authorities are independently reviewed.
const std = @import("std");
const c = @import("contracts.zig");
const fs = @import("files.zig");

pub const Selector = union(enum) { file: []const u8, subtree: []const u8 };
pub const Scope = union(enum) { whole: struct {}, selected: []const Selector };
pub const LocalBuild = struct {
    source_revision: []const u8,
    source_physical_sha256: c.Sha,
    compiler_executable_sha256: c.Sha,
};
pub const Component = struct { artifact_id: []const u8, selected_tree: c.Tree, scope: Scope };
pub const Declaration = struct { directory: Identity, file: c.File, entry: []const u8 };
pub const Package = struct {
    package_hash: []const u8,
    locator: []const u8,
    revision: union(enum) { git_commit: []const u8, archive_selector: []const u8 },
    declaration: Declaration,
    selected_tree: c.Tree,
    scope: Scope,
};
pub const Origin = struct {
    schema: enum { hyperv_runtime_origin_v2 } = .hyperv_runtime_origin_v2,
    payload: union(enum) {
        local_build: LocalBuild,
        distribution: struct { runtime_revision: []const u8, evidence_set_sha256: c.Sha, components: []const Component },
        zig_packages: struct { packages: []const Package },
    },

    pub fn revision(self: Origin) ![]const u8 {
        return switch (self.payload) {
            .local_build => |v| v.source_revision,
            .distribution => |v| v.runtime_revision,
            .zig_packages => |v| if (v.packages.len == 1) switch (v.packages[0].revision) {
                inline else => |r| r,
            } else error.InvalidOrigin,
        };
    }
    pub fn requireLocal(self: Origin, source: c.Source, compiler: c.File) !void {
        const local = switch (self.payload) {
            .local_build => |v| v,
            else => return error.UnreviewedInput,
        };
        if (!std.mem.eql(u8, local.source_revision, source.head) or
            !std.meta.eql(local.source_physical_sha256, source.physical.sha256) or
            !std.meta.eql(local.compiler_executable_sha256, compiler.sha256)) return error.UnreviewedInput;
    }
};

pub const Identity = struct {
    path: []const u8,
    device: u64,
    inode: u64,
    mode: u16,
    uid: u32,

    pub fn directory(dir: fs.Directory) !Identity {
        const m = try fs.metadata(.{ .handle = dir.dir.handle, .flags = .{ .nonblocking = false } });
        return .{ .path = dir.path, .device = m.device, .inode = m.inode, .mode = m.mode, .uid = m.uid };
    }
    pub fn require(self: Identity, actual: Identity) !void {
        if (!std.mem.eql(u8, self.path, actual.path) or self.device != actual.device or self.inode != actual.inode or
            self.mode != actual.mode or self.uid != actual.uid) return error.SourceChanged;
    }
};
pub const Subject = struct {
    publisher: []const u8,
    repository: []const u8,
    asset_id: []const u8,
    locator: []const u8,
    revision: []const u8,
    artifact_sha256: c.Sha,
};
pub const Authentication = union(enum) {
    pinned_key_signature: struct { subject: Subject, key_id: []const u8, signature: c.File, verification: c.File },
    publisher_https_sha256: struct { subject: Subject, metadata: c.File, metadata_url: []const u8, acquisition: c.File },
    signed_repository_metadata: struct { subject: Subject, key_id: []const u8, metadata: c.File, index: c.File, verification: c.File },
};
pub const Authority = union(enum) {
    pinned_key_signature: struct { publisher: []const u8, repository: []const u8, key_id: []const u8 },
    publisher_https_sha256: struct { publisher: []const u8, repository: []const u8 },
    signed_repository_metadata: struct { publisher: []const u8, repository: []const u8, key_id: []const u8 },
};
pub const Policy = struct {
    artifact_id: []const u8,
    authority: Authority,
    authentication_sha256: c.Sha,
    realization_verification_sha256: []const c.Sha,
};
pub const Set = struct { tree: c.Tree, catalog: c.File };
pub const Binding = struct {
    directory: Identity,
    set: Set,
    physical_sha256: c.Sha,
    /// Transported expectations, compared with the independently supplied runtime
    /// review before bootstrap; subsequent full reviews bind these unchanged.
    policy: []const Policy,
};
pub const Map = union(enum) {
    file: struct { member: c.File, destination: c.File },
    tree: struct { member_prefix: []const u8, destination_prefix: []const u8, tree: c.Tree },
};
pub const Relocation = struct {
    member: c.File,
    original: c.File,
    destination: c.File,
    placeholder: []const u8,
    mode: enum { binary, text },
    installed_prefix: []const u8,
};
pub const RealizationPayload = union(enum) {
    unchanged_extraction: struct { artifact_sha256: c.Sha, selected_tree: c.Tree, maps: []const Map },
    declared_prefix_relocation: struct {
        artifact_sha256: c.Sha,
        selected_tree: c.Tree,
        declaration: c.File,
        declaration_member: []const u8,
        unchanged: []const Map,
        relocated: []const Relocation,
    },
};
pub const Realization = struct { payload: RealizationPayload, verification: c.File };
pub const Artifact = struct { id: []const u8, subject: Subject, authentication: Authentication, realizations: []const Realization };
pub const Catalog = struct {
    schema: enum { hyperv_runtime_origin_evidence_v1 },
    artifacts: []const Artifact,
};
pub const Verifier = struct { name: []const u8, version: []const u8, executable_sha256: c.Sha, transcript: c.File };
pub const SignatureVerification = struct {
    schema: enum { hyperv_origin_signature_verification_v1 },
    subject_sha256: c.Sha,
    signed_bytes_sha256: c.Sha,
    key_id: []const u8,
    verifier: Verifier,
};
pub const Acquisition = struct {
    schema: enum { hyperv_origin_https_acquisition_v1 },
    subject_sha256: c.Sha,
    metadata_sha256: c.Sha,
    url: []const u8,
    tls_peer_name: []const u8,
    tls_peer_certificate_sha256: c.Sha,
    acquired_at: []const u8,
    transport_evidence: c.File,
};
pub const ArchiveVerification = struct {
    schema: enum { hyperv_origin_archive_verification_v1 },
    artifact_sha256: c.Sha,
    realization_payload_sha256: c.Sha,
    verifier: Verifier,
};

pub fn hash(allocator: std.mem.Allocator, value: anytype) !c.Sha {
    const bytes = try c.canonical(allocator, value);
    defer allocator.free(bytes);
    return c.digest(bytes);
}
fn text(value: []const u8) !void {
    if (value.len == 0 or value.len > 8192 or std.mem.indexOfScalar(u8, value, 0) != null) return error.InvalidOrigin;
}
fn prefix(value: []const u8) !void {
    if (value.len != 0) try c.relative(value);
}
fn https(value: []const u8) !void {
    try text(value);
    if (!std.mem.startsWith(u8, value, "https://") or value.len <= 8) return error.InvalidOrigin;
}
fn subject(value: Subject) !void {
    inline for (.{ "publisher", "repository", "asset_id", "revision" }) |field| try text(@field(value, field));
    try https(value.locator);
    _ = try c.sha(&value.artifact_sha256);
}
pub fn validate(value: Origin, role: anytype, target: anytype) !void {
    switch (value.payload) {
        .local_build => |local| {
            try c.objectId(local.source_revision);
            _ = try c.sha(&local.source_physical_sha256);
            _ = try c.sha(&local.compiler_executable_sha256);
            if (target == .data or role == .zig) return error.InvalidOrigin;
        },
        .distribution => |distribution| {
            try text(distribution.runtime_revision);
            if (distribution.runtime_revision.len > 256) return error.InvalidOrigin;
            _ = try c.sha(&distribution.evidence_set_sha256);
            if (distribution.components.len == 0 or distribution.components.len > 128 or role == .dependencies)
                return error.InvalidOrigin;
            if (role == .zig and (target == .data or !std.mem.eql(u8, distribution.runtime_revision, c.compiler_version)))
                return error.CompilerMismatch;
            for (distribution.components, 0..) |component, i| {
                try c.core.private_files.basename(component.artifact_id);
                try validTree(component.selected_tree);
                try validScope(component.scope, distribution.components.len);
                for (distribution.components[0..i]) |previous|
                    if (std.mem.eql(u8, previous.artifact_id, component.artifact_id)) return error.InvalidOrigin;
            }
        },
        .zig_packages => |packages| {
            if (role != .dependencies or target != .data or packages.packages.len == 0 or packages.packages.len > 128)
                return error.InvalidOrigin;
            for (packages.packages, 0..) |package, i| {
                try c.core.private_files.basename(package.package_hash);
                try c.core.private_files.basename(package.declaration.entry);
                try c.relative(package.declaration.file.path);
                if (!std.mem.eql(u8, std.fs.path.basename(package.declaration.file.path), "build.zig.zon"))
                    return error.InvalidPackageDeclaration;
                if (std.mem.eql(u8, package.declaration.entry, "miz_source") and
                    (!std.mem.eql(u8, package.package_hash, c.miz_package_hash) or package.revision != .git_commit or
                        !std.mem.eql(u8, package.revision.git_commit, c.miz_revision))) return error.UnreviewedInput;
                try validScope(package.scope, packages.packages.len);
                try validTree(package.selected_tree);
                switch (package.revision) {
                    .git_commit => |commit| {
                        try c.objectId(commit);
                        if (!std.mem.startsWith(u8, package.locator, "git+https://") or
                            !std.mem.endsWith(u8, package.locator, commit) or
                            package.locator.len <= commit.len or package.locator[package.locator.len - commit.len - 1] != '#')
                            return error.InvalidOrigin;
                    },
                    .archive_selector => |selector| {
                        try https(package.locator);
                        try text(selector);
                        if (selector.len > 256) return error.InvalidOrigin;
                        if (std.mem.indexOf(u8, package.locator, selector) == null) return error.InvalidOrigin;
                    },
                }
                for (packages.packages[0..i]) |previous|
                    if (std.mem.eql(u8, previous.package_hash, package.package_hash)) return error.InvalidOrigin;
            }
        },
    }
    if (role == .miz and !std.mem.eql(u8, try value.revision(), c.miz_revision)) return error.UnreviewedInput;
}
fn validTree(tree: c.Tree) !void {
    _ = try c.sha(&tree.sha256);
    if (tree.files == 0) return error.InvalidOrigin;
}
pub fn matches(selector: Selector, path: []const u8) bool {
    return switch (selector) {
        .file => |file| std.mem.eql(u8, file, path),
        .subtree => |tree| under(tree, path),
    };
}
pub fn under(parent: []const u8, path: []const u8) bool {
    return parent.len == 0 or (std.mem.startsWith(u8, path, parent) and path.len > parent.len and path[parent.len] == '/');
}
pub fn requireSeparate(evidence: []const Binding, roots: []const []const u8) !void {
    for (evidence) |binding| for (roots) |root| {
        if (under(root, binding.directory.path) or under(binding.directory.path, root) or
            std.mem.eql(u8, root, binding.directory.path)) return error.InvalidOrigin;
    };
}
pub fn includes(scope: Scope, path: []const u8) bool {
    return switch (scope) {
        .whole => true,
        .selected => |selectors| blk: {
            for (selectors) |selector| if (matches(selector, path)) break :blk true;
            break :blk false;
        },
    };
}
fn validScope(scope: Scope, count: usize) !void {
    switch (scope) {
        .whole => if (count != 1) return error.InvalidOrigin,
        .selected => |selectors| {
            if (selectors.len == 0 or selectors.len > 256) return error.InvalidOrigin;
            for (selectors, 0..) |selector, i| {
                const path = switch (selector) {
                    inline else => |v| v,
                };
                try c.relative(path);
                for (selectors[0..i]) |previous| {
                    const other = switch (previous) {
                        inline else => |v| v,
                    };
                    if (std.mem.eql(u8, path, other) or matches(previous, path) or matches(selector, other))
                        return error.OriginOverlap;
                }
            }
        },
    }
}
pub fn requireCoverage(entries: []const c.File, components: anytype) !void {
    for (entries) |entry| {
        var count: usize = 0;
        for (components) |component| if (includes(component.scope, entry.path)) {
            count += 1;
        };
        if (count != 1) return if (count == 0) error.OriginGap else error.OriginOverlap;
    }
    for (components) |component| if (component.scope == .selected) {
        for (component.scope.selected) |selector| {
            var found = false;
            for (entries) |entry| found = found or matches(selector, entry.path);
            if (!found) return error.OriginExtra;
        }
    };
}

pub fn readFile(allocator: std.mem.Allocator, io: std.Io, directory: fs.Directory, file: c.File, cap: usize) ![]u8 {
    try fs.requireFile(try directory.record(allocator, io, file.path, cap, .artifact), file);
    const bytes = try directory.read(allocator, io, file.path, cap, .artifact);
    if (!std.meta.eql(c.digest(bytes), file.sha256)) return error.HashMismatch;
    return bytes;
}
fn document(comptime T: type, allocator: std.mem.Allocator, io: std.Io, directory: fs.Directory, file: c.File) !T {
    return (try c.parse(T, allocator, try readFile(allocator, io, directory, file, 4 * 1024 * 1024))).value;
}
fn verifier(allocator: std.mem.Allocator, io: std.Io, directory: fs.Directory, value: Verifier) !void {
    try text(value.name);
    try text(value.version);
    _ = try c.sha(&value.executable_sha256);
    if (value.transcript.size == 0) return error.MissingWitness;
    _ = try readFile(allocator, io, directory, value.transcript, 4 * 1024 * 1024);
}
fn retained(allocator: std.mem.Allocator, io: std.Io, directory: fs.Directory, file: c.File) !void {
    if (file.size == 0) return error.MissingWitness;
    const observed = try directory.record(allocator, io, file.path, 1024 * 1024 * 1024, .artifact);
    defer allocator.free(observed.path);
    try fs.requireFile(observed, file);
}
fn authentication(allocator: std.mem.Allocator, io: std.Io, directory: fs.Directory, artifact: Artifact, policy: Policy) !void {
    try subject(artifact.subject);
    if (!std.meta.eql(try hash(allocator, artifact.authentication), policy.authentication_sha256)) return error.UnreviewedInput;
    switch (artifact.authentication) {
        inline else => |auth, tag| {
            if (std.meta.activeTag(policy.authority) != @field(std.meta.Tag(Authority), @tagName(tag))) return error.RequiredAuthenticationMethod;
            const authority = @field(policy.authority, @tagName(tag));
            if (!std.mem.eql(u8, authority.publisher, artifact.subject.publisher) or
                !std.mem.eql(u8, authority.repository, artifact.subject.repository)) return error.WrongAuthority;
            if (!std.meta.eql(try hash(allocator, auth.subject), try hash(allocator, artifact.subject))) return error.WrongSubject;
            if (comptime tag == .publisher_https_sha256) {
                try https(auth.metadata_url);
                try retained(allocator, io, directory, auth.metadata);
                const acquisition = try document(Acquisition, allocator, io, directory, auth.acquisition);
                if (!std.meta.eql(acquisition.subject_sha256, try hash(allocator, artifact.subject)) or
                    !std.meta.eql(acquisition.metadata_sha256, auth.metadata.sha256) or
                    !std.mem.eql(u8, acquisition.url, auth.metadata_url)) return error.WrongSubject;
                const end = std.mem.indexOfScalarPos(u8, acquisition.url, 8, '/') orelse acquisition.url.len;
                if (!std.mem.eql(u8, acquisition.tls_peer_name, acquisition.url[8..end])) return error.WrongAuthority;
                _ = try c.sha(&acquisition.tls_peer_certificate_sha256);
                try text(acquisition.acquired_at);
                if (acquisition.transport_evidence.size == 0) return error.MissingWitness;
                _ = try readFile(allocator, io, directory, acquisition.transport_evidence, 4 * 1024 * 1024);
            } else {
                if (!std.mem.eql(u8, auth.key_id, authority.key_id)) return error.WrongAuthority;
                try text(auth.key_id);
                const witness = if (comptime tag == .pinned_key_signature) auth.signature else auth.metadata;
                try retained(allocator, io, directory, witness);
                const signed_bytes_sha256 = if (comptime tag == .pinned_key_signature)
                    artifact.subject.artifact_sha256
                else
                    auth.metadata.sha256;
                if (comptime tag == .signed_repository_metadata)
                    try retained(allocator, io, directory, auth.index);
                const verified = try document(SignatureVerification, allocator, io, directory, auth.verification);
                if (!std.meta.eql(verified.subject_sha256, try hash(allocator, artifact.subject)) or
                    !std.meta.eql(verified.signed_bytes_sha256, signed_bytes_sha256) or
                    !std.mem.eql(u8, verified.key_id, auth.key_id)) return error.WrongSubject;
                try verifier(allocator, io, directory, verified.verifier);
            }
        },
    }
}

pub fn validateEvidence(allocator: std.mem.Allocator, io: std.Io, binding: Binding) !Catalog {
    const directory = try fs.Directory.open(allocator, io, binding.directory.path);
    defer directory.close(allocator, io);
    try binding.directory.require(try Identity.directory(directory));
    if (!std.meta.eql(binding.physical_sha256, try fs.physicalDigest(allocator, io, directory))) return error.SourceChanged;
    try fs.requireTree((try fs.inventory(allocator, io, directory, 100000, 4 * 1024 * 1024 * 1024)).tree, binding.set.tree);
    const catalog = try document(Catalog, allocator, io, directory, binding.set.catalog);
    if (catalog.artifacts.len == 0 or catalog.artifacts.len > 128 or catalog.artifacts.len != binding.policy.len)
        return error.MissingWitness;
    for (catalog.artifacts, 0..) |artifact, i| {
        try c.core.private_files.basename(artifact.id);
        for (catalog.artifacts[0..i]) |previous|
            if (std.mem.eql(u8, previous.id, artifact.id)) return error.InvalidOrigin;
        var expected: ?Policy = null;
        for (binding.policy) |policy| if (std.mem.eql(u8, policy.artifact_id, artifact.id)) {
            if (expected != null) return error.InvalidOrigin;
            expected = policy;
        };
        const policy = expected orelse return error.WrongAuthority;
        try authentication(allocator, io, directory, artifact, policy);
        if (artifact.realizations.len == 0 or artifact.realizations.len > 256 or
            policy.realization_verification_sha256.len != artifact.realizations.len) return error.MissingWitness;
        for (artifact.realizations, 0..) |realization, n| {
            if (!std.meta.eql(realization.verification.sha256, policy.realization_verification_sha256[n]))
                return error.UnreviewedInput;
            const proof = try document(ArchiveVerification, allocator, io, directory, realization.verification);
            if (!std.meta.eql(proof.artifact_sha256, artifact.subject.artifact_sha256) or
                !std.meta.eql(proof.realization_payload_sha256, try hash(allocator, realization.payload))) return error.WrongSubject;
            try verifier(allocator, io, directory, proof.verifier);
            switch (realization.payload) {
                inline else => |payload| if (!std.meta.eql(payload.artifact_sha256, artifact.subject.artifact_sha256))
                    return error.WrongSubject,
            }
        }
    }
    try binding.directory.require(try Identity.directory(directory));
    return catalog;
}

fn mapped(allocator: std.mem.Allocator, io: std.Io, root: fs.Directory, map: Map, observed: fs.Inventory, covered: []u8, scope: Scope) !void {
    const selector: Selector = switch (map) {
        .file => |file| blk: {
            try c.relative(file.member.path);
            var expected = file.member;
            expected.path = file.destination.path;
            try fs.requireFile(expected, file.destination);
            try fs.requireFile(try root.record(allocator, io, file.destination.path, 1024 * 1024 * 1024, .artifact), file.destination);
            break :blk .{ .file = file.destination.path };
        },
        .tree => |tree| blk: {
            try prefix(tree.member_prefix);
            try prefix(tree.destination_prefix);
            const directory = if (tree.destination_prefix.len == 0) root else try fs.Directory.open(allocator, io, try std.fs.path.join(allocator, &.{ root.path, tree.destination_prefix }));
            defer if (tree.destination_prefix.len != 0) directory.close(allocator, io);
            try fs.requireTree(if (tree.destination_prefix.len == 0) observed.tree else (try fs.inventory(allocator, io, directory, 100000, 4 * 1024 * 1024 * 1024)).tree, tree.tree);
            break :blk .{ .subtree = tree.destination_prefix };
        },
    };
    try cover(observed.entries, covered, scope, selector);
}
fn cover(entries: []const c.File, covered: []u8, scope: Scope, selector: Selector) !void {
    var found = false;
    for (entries, covered) |entry, *count| if (matches(selector, entry.path)) {
        if (!includes(scope, entry.path)) return error.OriginExtra;
        if (count.* != 0) return error.OriginOverlap;
        count.* = 1;
        found = true;
    };
    if (!found) return error.OriginExtra;
}

/// Conda's Unix binary prefix rule replaces every occurrence within a
/// NUL-terminated string and appends the aggregate shortening as NUL padding.
/// Text mode is literal replacement; no shebang rewriting or hooks are accepted.
pub fn relocate(allocator: std.mem.Allocator, original: []const u8, placeholder: []const u8, installed: []const u8, mode: @FieldType(Relocation, "mode")) ![]u8 {
    if (placeholder.len < 2 or installed.len < 2 or placeholder[0] != '/' or installed[0] != '/' or
        std.mem.indexOfScalar(u8, placeholder, 0) != null or std.mem.indexOfScalar(u8, installed, 0) != null or
        (mode == .binary and installed.len > placeholder.len) or std.mem.eql(u8, installed, placeholder)) return error.InvalidRelocation;
    try c.relative(placeholder[1..]);
    try c.relative(installed[1..]);
    if (std.mem.indexOf(u8, original, placeholder) == null) return error.InvalidRelocation;
    var output: std.ArrayList(u8) = .empty;
    errdefer output.deinit(allocator);
    var start: usize = 0;
    while (start < original.len) {
        const end = if (mode == .binary) (std.mem.indexOfScalarPos(u8, original, start, 0) orelse original.len) else original.len;
        const segment = original[start..end];
        var cursor: usize = 0;
        var padding: usize = 0;
        while (std.mem.indexOfPos(u8, segment, cursor, placeholder)) |at| {
            if (mode == .binary and end == original.len) return error.InvalidRelocation;
            try output.appendSlice(allocator, segment[cursor..at]);
            try output.appendSlice(allocator, installed);
            if (mode == .binary) padding += placeholder.len - installed.len;
            cursor = at + placeholder.len;
        }
        try output.appendSlice(allocator, segment[cursor..]);
        if (mode == .binary) try output.appendNTimes(allocator, 0, padding);
        if (end < original.len) try output.append(allocator, 0);
        start = end + 1;
    }
    return output.toOwnedSlice(allocator);
}

fn declaration(allocator: std.mem.Allocator, bytes: []const u8, relocation: Relocation) !void {
    const doc = try c.c.Document.parse(allocator, bytes, .{ .bytes = 4 * 1024 * 1024, .depth = 32, .items = 4096, .tokens = 65536, .string_bytes = 8192 });
    defer doc.deinit();
    const value = doc.value();
    if (value != .object) return error.InvalidRelocation;
    if (try c.c.integer(u32, value.object.get("paths_version") orelse return error.InvalidRelocation) != 1) return error.InvalidRelocation;
    const list = value.object.get("paths") orelse return error.InvalidRelocation;
    if (list != .array) return error.InvalidRelocation;
    var found = false;
    for (list.array.items, 0..) |item, i| {
        if (item != .object) return error.InvalidRelocation;
        const path = try c.c.string(item.object.get("_path") orelse return error.InvalidRelocation);
        try c.relative(path);
        for (list.array.items[0..i]) |previous|
            if (std.mem.eql(u8, path, try c.c.string(previous.object.get("_path") orelse return error.InvalidRelocation))) return error.InvalidRelocation;
        if (!std.mem.eql(u8, path, relocation.member.path)) continue;
        found = true;
        if (!std.mem.eql(u8, try c.c.string(item.object.get("sha256") orelse return error.InvalidRelocation), &relocation.member.sha256) or
            try c.c.integer(u64, item.object.get("size_in_bytes") orelse return error.InvalidRelocation) != relocation.member.size or
            !std.mem.eql(u8, try c.c.string(item.object.get("prefix_placeholder") orelse return error.InvalidRelocation), relocation.placeholder) or
            !std.mem.eql(u8, try c.c.string(item.object.get("file_mode") orelse return error.InvalidRelocation), @tagName(relocation.mode)) or
            !std.mem.eql(u8, try c.c.string(item.object.get("path_type") orelse return error.InvalidRelocation), "hardlink"))
            return error.InvalidRelocation;
    }
    if (!found) return error.InvalidRelocation;
}

fn realize(allocator: std.mem.Allocator, io: std.Io, evidence: fs.Directory, root: fs.Directory, realization: Realization, component: Component, observed: fs.Inventory) !void {
    const entries = observed.entries;
    const covered = try allocator.alloc(u8, entries.len);
    @memset(covered, 0);
    switch (realization.payload) {
        .unchanged_extraction => |payload| {
            if (payload.maps.len == 0 or payload.maps.len > 256) return error.InvalidOrigin;
            for (payload.maps) |map| try mapped(allocator, io, root, map, observed, covered, component.scope);
        },
        .declared_prefix_relocation => |payload| {
            if (!std.mem.eql(u8, payload.declaration_member, "info/paths.json") or
                payload.relocated.len == 0 or payload.relocated.len > 256 or payload.unchanged.len > 256) return error.InvalidRelocation;
            const declared = try readFile(allocator, io, evidence, payload.declaration, 4 * 1024 * 1024);
            for (payload.unchanged) |map| try mapped(allocator, io, root, map, observed, covered, component.scope);
            for (payload.relocated) |relocation| {
                try declaration(allocator, declared, relocation);
                var original_record = relocation.member;
                original_record.path = relocation.original.path;
                try fs.requireFile(original_record, relocation.original);
                const original = try readFile(allocator, io, evidence, relocation.original, 1024 * 1024 * 1024);
                const result = try relocate(allocator, original, relocation.placeholder, relocation.installed_prefix, relocation.mode);
                if (result.len != relocation.destination.size or !std.meta.eql(c.digest(result), relocation.destination.sha256) or
                    relocation.member.mode != relocation.destination.mode) return error.InvalidRelocation;
                const installed = try readFile(allocator, io, root, relocation.destination, 1024 * 1024 * 1024);
                if (!std.mem.eql(u8, installed, result)) return error.InvalidRelocation;
                try cover(entries, covered, component.scope, .{ .file = relocation.destination.path });
            }
        },
    }
    for (entries, covered) |entry, count|
        if (includes(component.scope, entry.path) and count != 1) return error.OriginGap;
}

pub fn requirePhysical(allocator: std.mem.Allocator, io: std.Io, root: fs.Directory, value: Origin, bindings: []const Binding, observed: fs.Inventory) !void {
    switch (value.payload) {
        .local_build => if (bindings.len != 0) return error.InvalidOrigin,
        .distribution => |distribution| {
            if (bindings.len != 1) return error.MissingWitness;
            try requireCoverage(observed.entries, distribution.components);
            var evidence: ?Binding = null;
            for (bindings) |binding| if (std.meta.eql(try hash(allocator, binding.set), distribution.evidence_set_sha256)) {
                if (evidence != null) return error.InvalidOrigin;
                evidence = binding;
            };
            const binding = evidence orelse return error.MissingWitness;
            if (under(root.path, binding.directory.path) or under(binding.directory.path, root.path) or
                std.mem.eql(u8, root.path, binding.directory.path)) return error.InvalidOrigin;
            const catalog = try validateEvidence(allocator, io, binding);
            const directory = try fs.Directory.open(allocator, io, binding.directory.path);
            defer directory.close(allocator, io);
            try binding.directory.require(try Identity.directory(directory));
            for (distribution.components) |component| {
                try fs.requireTree(if (component.scope == .whole) observed.tree else try fs.selectedTree(allocator, io, root, component.scope), component.selected_tree);
                var found = false;
                for (catalog.artifacts) |artifact| if (std.mem.eql(u8, artifact.id, component.artifact_id)) {
                    for (artifact.realizations) |realization| {
                        const tree = switch (realization.payload) {
                            inline else => |payload| payload.selected_tree,
                        };
                        if (!std.meta.eql(tree, component.selected_tree)) continue;
                        if (found) return error.InvalidOrigin;
                        found = true;
                        try realize(allocator, io, directory, root, realization, component, observed);
                    }
                };
                if (!found) return error.MissingWitness;
            }
        },
        .zig_packages => |packages| {
            if (bindings.len != 0) return error.InvalidOrigin;
            try requireCoverage(observed.entries, packages.packages);
            for (packages.packages) |package| {
                try fs.requireTree(if (package.scope == .whole) observed.tree else try fs.selectedTree(allocator, io, root, package.scope), package.selected_tree);
                switch (package.scope) {
                    .whole => if (!std.mem.eql(u8, std.fs.path.basename(root.path), package.package_hash)) return error.PackageRootMismatch,
                    .selected => |selectors| {
                        if (selectors.len != 1 or selectors[0] != .subtree or !std.mem.eql(u8, selectors[0].subtree, package.package_hash))
                            return error.PackageRootMismatch;
                    },
                }
                const dir = try fs.Directory.open(allocator, io, package.declaration.directory.path);
                defer dir.close(allocator, io);
                try package.declaration.directory.require(try Identity.directory(dir));
                const bytes = try readFile(allocator, io, dir, package.declaration.file, 4 * 1024 * 1024);
                try requirePackageDeclaration(allocator, bytes, package);
            }
        },
    }
}

/// Parse and validate literal ZON. No manifest or root build is executed.
pub fn requirePackageDeclaration(backing_allocator: std.mem.Allocator, bytes: []const u8, package: Package) !void {
    if (bytes.len > 4 * 1024 * 1024) return error.LimitExceeded;
    var arena = std.heap.ArenaAllocator.init(backing_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const terminated = try allocator.dupeZ(u8, bytes);
    defer allocator.free(terminated);
    // Bound work before parsing; ZonGen then rejects non-ZON expressions and
    // duplicate fields throughout the entire manifest, not just the selected pin.
    var tokenizer = std.zig.Tokenizer.init(terminated);
    var token_count: usize = 0;
    var nesting: usize = 0;
    while (true) {
        const token = tokenizer.next();
        if (token.tag == .eof) break;
        if (token_count >= 65536 or token.loc.end - token.loc.start > 8192) return error.LimitExceeded;
        token_count += 1;
        switch (token.tag) {
            .l_brace, .l_paren, .l_bracket => {
                nesting += 1;
                if (nesting > 32) return error.LimitExceeded;
            },
            .r_brace, .r_paren, .r_bracket => {
                if (nesting == 0) return error.InvalidPackageDeclaration;
                nesting -= 1;
            },
            else => {},
        }
    }
    var ast = try std.zig.Ast.parse(allocator, terminated, .zon);
    defer ast.deinit(allocator);
    if (ast.errors.len != 0) return error.InvalidPackageDeclaration;
    const zoir = try std.zig.ZonGen.generate(allocator, ast, .{});
    defer zoir.deinit(allocator);
    if (zoir.hasCompileErrors()) return error.InvalidPackageDeclaration;
    if (zoir.nodes.len > 4096) return error.LimitExceeded;
    const root = std.zig.Zoir.Node.Index.root.get(zoir);
    if (root != .struct_literal) return error.InvalidPackageDeclaration;
    var dependencies: ?std.zig.Zoir.Node = null;
    for (root.struct_literal.names, 0..) |name, i| {
        if (std.mem.eql(u8, name.get(zoir), "dependencies"))
            dependencies = root.struct_literal.vals.at(@intCast(i)).get(zoir);
    }
    const list = dependencies orelse return error.InvalidPackageDeclaration;
    if (list != .struct_literal) return error.InvalidPackageDeclaration;
    var found = false;
    for (list.struct_literal.names, 0..) |name, i| {
        const node = list.struct_literal.vals.at(@intCast(i));
        if (node.get(zoir) != .struct_literal) return error.InvalidPackageDeclaration;
        if (!std.mem.eql(u8, name.get(zoir), package.declaration.entry)) continue;
        found = true;
        const Pin = struct { url: []const u8, hash: []const u8, lazy: bool = false };
        const pin = std.zon.parse.fromZoirNodeAlloc(Pin, allocator, ast, zoir, node, null, .{}) catch |err| switch (err) {
            error.ParseZon => return error.InvalidPackageDeclaration,
            else => return err,
        };
        if (!std.mem.eql(u8, pin.url, package.locator) or
            !std.mem.eql(u8, pin.hash, package.package_hash)) return error.InvalidPackageDeclaration;
    }
    if (!found) return error.InvalidPackageDeclaration;
}
