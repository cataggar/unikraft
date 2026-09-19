const std = @import("std");
const c = @import("contracts.zig");
const f = @import("files.zig");
const p = c.core.private_files;
const miz = c.boot.miz;
const linux = std.os.linux;

pub const qcow2_name = "unikraft.qcow2";
pub const qcow2_record_name = "qcow2-finalization.json";
pub const vhd_name = "unikraft-derived.vhd";
pub const vhd_record_name = "fixed-vhd-derivation.json";
pub const qcow2_stage_name = "qcow2-finalization-stage";
pub const vhd_stage_name = "fixed-vhd-derivation-stage";
pub const Outcome = enum { succeeded, refused, partial };

const cluster_size: u64 = 64 * 1024;
const cluster_bits: u32 = 16;
const l2_entries: u64 = cluster_size / @sizeOf(u64);
const refcount_table_entries: u64 = cluster_size / @sizeOf(u64);
const fixed_header_bytes: u64 = 112;
const header_terminator_bytes: u64 = 8;
const hard_max_partition_array_bytes: u64 = 1024 * 1024;
const hard_max_metadata_bytes: u64 = 2 * 1024 * 1024;
const hard_max_metadata_work: u64 = 64 * 1024;
const hard_max_memory_bytes: u64 = 1024 * 1024 * 1024;
const min_memory_bytes: u64 = 128 * 1024 * 1024;
const sector_size: u64 = 512;
const allocation_unit: u64 = 512;
const workload_path = miz.efi_application_image.fallback_x86_64;
const config_domain = "uk.wamr.compute-image-config-v1\x00";
const partition_domain = "uk.wamr.compute-partitions-v1\x00";
const unique_id_domain = "uk.wamr.compute-vhd-unique-id-v1\x00";

pub const Limits = struct {
    max_input_bytes: u64,
    max_output_bytes: u64,
    max_virtual_bytes: u64,
    max_partition_array_bytes: u64,
    max_metadata_bytes: u64,
    max_metadata_work: u64,
    max_work_bytes: u64,
    max_memory_bytes: u64,
    max_workload_bytes: u64 = c.max_efi,

    pub fn validate(self: Limits, source_bytes: u64, virtual_bytes: u64) !void {
        if (source_bytes == 0 or source_bytes > self.max_input_bytes or
            self.max_input_bytes == 0 or self.max_input_bytes > c.boot.config.max_input or
            self.max_output_bytes == 0 or self.max_output_bytes > c.boot.config.max_input + miz.vhd.footer_size or
            virtual_bytes == 0 or virtual_bytes > self.max_virtual_bytes or
            self.max_virtual_bytes == 0 or self.max_virtual_bytes > c.boot.config.max_virtual or
            virtual_bytes % sector_size != 0)
        {
            return error.InvalidGeometryLimit;
        }
        if (self.max_partition_array_bytes < miz.gpt.default_num_partition_entries * miz.gpt.partition_entry_size or
            self.max_partition_array_bytes > hard_max_partition_array_bytes)
        {
            return error.InvalidPartitionArrayLimit;
        }
        const minimum_metadata = try minimumMetadataBytes(self.max_virtual_bytes);
        if (self.max_metadata_bytes < minimum_metadata or self.max_metadata_bytes > hard_max_metadata_bytes)
            return error.InvalidMetadataLimit;
        const minimum_work = try minimumMetadataWork(self.max_virtual_bytes);
        if (self.max_metadata_work < minimum_work or self.max_metadata_work > hard_max_metadata_work)
            return error.InvalidMetadataWorkLimit;
        const minimum_byte_work = std.math.mul(u64, virtual_bytes, 4) catch
            return error.InvalidWorkLimit;
        if (self.max_work_bytes < minimum_byte_work or
            self.max_work_bytes > 8 * c.boot.config.max_virtual)
        {
            return error.InvalidWorkLimit;
        }
        if (self.max_memory_bytes < min_memory_bytes or
            self.max_memory_bytes > hard_max_memory_bytes)
        {
            return error.InvalidMemoryLimit;
        }
        if (self.max_workload_bytes == 0 or self.max_workload_bytes > c.max_efi)
            return error.InvalidWorkloadLimit;
    }
};

pub const FinalizeIntent = struct {
    schema: []const u8 = "uk.wamr.compute-qcow2-finalization-intent",
    schema_version: u8 = 1,
    source_path: []const u8,
    expected_source_sha256: []const u8,
    expected_source_bytes: u64,
    expected_virtual_bytes: u64,
    expected_workload_sha256: []const u8,
    expected_workload_bytes: u64,
    timeout_ms: u32,
    limits: Limits,

    pub fn validate(self: FinalizeIntent) !void {
        if (!std.mem.eql(u8, self.schema, "uk.wamr.compute-qcow2-finalization-intent") or
            self.schema_version != 1 or self.timeout_ms == 0 or self.timeout_ms > c.package_timeout_ms or
            self.expected_source_bytes != self.expected_virtual_bytes or
            self.expected_workload_bytes == 0 or
            self.expected_workload_bytes > self.limits.max_workload_bytes)
        {
            return error.InvalidIntent;
        }
        try p.absoluteFilePath(self.source_path);
        _ = try c.sha(self.expected_source_sha256);
        _ = try c.sha(self.expected_workload_sha256);
        try self.limits.validate(self.expected_source_bytes, self.expected_virtual_bytes);
    }
};

pub const DeriveIntent = struct {
    schema: []const u8 = "uk.wamr.compute-fixed-vhd-derivation-intent",
    schema_version: u8 = 1,
    source_path: []const u8,
    accepted_qcow2_sha256: []const u8,
    expected_source_bytes: u64,
    expected_capacity_bytes: u64,
    timeout_ms: u32,
    limits: Limits,

    pub fn validate(self: DeriveIntent) !void {
        if (!std.mem.eql(u8, self.schema, "uk.wamr.compute-fixed-vhd-derivation-intent") or
            self.schema_version != 1 or self.timeout_ms == 0 or self.timeout_ms > c.package_timeout_ms)
        {
            return error.InvalidIntent;
        }
        try p.absoluteFilePath(self.source_path);
        _ = try c.sha(self.accepted_qcow2_sha256);
        try self.limits.validate(self.expected_source_bytes, self.expected_capacity_bytes);
        const target = try alignedCapacity(self.expected_capacity_bytes);
        const file_size = std.math.add(u64, target, miz.vhd.footer_size) catch
            return error.InvalidGeometryLimit;
        if (file_size > self.limits.max_output_bytes) return error.InvalidOutputLimit;
    }
};

pub fn readFinalizeIntent(a: std.mem.Allocator, bytes: []const u8) !FinalizeIntent {
    const result = try c.read(FinalizeIntent, a, bytes);
    try result.validate();
    return result;
}

pub fn readDeriveIntent(a: std.mem.Allocator, bytes: []const u8) !DeriveIntent {
    const result = try c.read(DeriveIntent, a, bytes);
    try result.validate();
    return result;
}

pub const PinnedArtifact = struct {
    artifact: c.File,
    pin: c.boot.files.Pin,

    pub fn validate(self: PinnedArtifact, maximum: u64) !void {
        try self.artifact.validate(maximum);
        try self.pin.validate();
        if (self.artifact.size != self.pin.size or
            !std.mem.eql(u8, &try c.sha(self.artifact.sha256), &self.pin.sha256))
        {
            return error.InvalidArtifactPin;
        }
    }
};

pub fn bindExpected(
    a: std.mem.Allocator,
    io: std.Io,
    path: []const u8,
    size: u64,
    sha256: []const u8,
    maximum: u64,
) !PinnedArtifact {
    const expected: c.File = .{
        .path = try a.dupe(u8, path),
        .size = size,
        .sha256 = try a.dupe(u8, sha256),
    };
    try expected.validate(maximum);
    const file = try p.openAbsolute(io, path, .artifact);
    defer file.close(io);
    const before = try c.boot.files.snapshot(file);
    const digest = try c.boot.files.digest(io, file, before);
    if (before.size != size or !std.mem.eql(u8, &digest, &try c.sha(sha256)))
        return error.ArtifactChanged;
    const pin = try c.boot.files.Pin.init(before, digest);
    const named = try p.openAbsolute(io, path, .artifact);
    defer named.close(io);
    if (!pin.matches(try c.boot.files.snapshot(named))) return error.ArtifactChanged;
    return .{ .artifact = expected, .pin = pin };
}

pub fn verifyPinned(io: std.Io, pinned: PinnedArtifact, maximum: u64) !void {
    const retained = try RetainedArtifact.open(io, pinned, maximum);
    defer retained.close(io);
    try retained.verify(io);
}

const RetainedArtifact = struct {
    file: std.Io.File,
    pinned: PinnedArtifact,

    fn open(io: std.Io, pinned: PinnedArtifact, maximum: u64) !RetainedArtifact {
        try pinned.validate(maximum);
        const file = try p.openAbsolute(io, pinned.artifact.path, .artifact);
        errdefer file.close(io);
        if (!pinned.pin.matches(try c.boot.files.snapshot(file)) or
            !std.mem.eql(u8, &try c.boot.files.digest(io, file, try c.boot.files.snapshot(file)), &pinned.pin.sha256))
        {
            return error.ArtifactChanged;
        }
        return .{ .file = file, .pinned = pinned };
    }

    fn verify(self: RetainedArtifact, io: std.Io) !void {
        const current = try p.openAbsolute(io, self.pinned.artifact.path, .artifact);
        defer current.close(io);
        if (!self.pinned.pin.matches(try c.boot.files.snapshot(self.file)) or
            !self.pinned.pin.matches(try c.boot.files.snapshot(current)) or
            !std.mem.eql(
                u8,
                &try c.boot.files.digest(io, self.file, try c.boot.files.snapshot(self.file)),
                &self.pinned.pin.sha256,
            ))
        {
            return error.ArtifactChanged;
        }
    }

    fn close(self: RetainedArtifact, io: std.Io) void {
        self.file.close(io);
    }
};

pub const AllocationState = enum { available, unavailable };
pub const Allocation = struct {
    state: AllocationState,
    bytes: ?u64,

    pub fn validate(self: Allocation) !void {
        switch (self.state) {
            .available => if (self.bytes == null) return error.InvalidAllocation,
            .unavailable => if (self.bytes != null) return error.InvalidAllocation,
        }
    }
};

pub const Artifact = struct {
    sha256: []const u8,
    file_bytes: u64,
    allocated: Allocation,
    virtual_bytes: u64,

    pub fn validate(self: Artifact) !void {
        _ = try c.sha(self.sha256);
        if (self.file_bytes == 0 or self.virtual_bytes == 0) return error.InvalidArtifact;
        try self.allocated.validate();
    }
};

pub const DiskIdentity = struct {
    disk_guid: []const u8,
    partition_array_sha256: []const u8,
    partition_contents_sha256: []const u8,
    partition_count: u32,
    esp_partition_guid: []const u8,
    esp_offset_bytes: u64,
    esp_length_bytes: u64,
    esp_volume_id: u32,
    workload_path: []const u8 = workload_path,
    workload_bytes: u64,
    workload_sha256: []const u8,

    pub fn validate(self: DiskIdentity) !void {
        if (self.disk_guid.len != 32 or self.esp_partition_guid.len != 32 or
            self.partition_count == 0 or self.esp_length_bytes == 0 or
            self.workload_bytes == 0 or !std.mem.eql(u8, self.workload_path, workload_path))
        {
            return error.InvalidDiskIdentity;
        }
        _ = try c.sha(self.partition_array_sha256);
        _ = try c.sha(self.partition_contents_sha256);
        _ = try c.sha(self.workload_sha256);
    }
};

pub const Provenance = struct {
    producer_sha256: []const u8,
    producer_bytes: u64,
    miz_revision: []const u8 = c.miz_revision,
    config_sha256: []const u8,
    parent_kind: []const u8,
    parent_sha256: []const u8,

    pub fn validate(self: Provenance, parent_kind: []const u8, parent_sha256: []const u8) !void {
        _ = try c.sha(self.producer_sha256);
        _ = try c.sha(self.config_sha256);
        _ = try c.sha(self.parent_sha256);
        if (self.producer_bytes == 0 or !std.mem.eql(u8, self.miz_revision, c.miz_revision) or
            !std.mem.eql(u8, self.parent_kind, parent_kind) or
            !std.mem.eql(u8, self.parent_sha256, parent_sha256))
        {
            return error.InvalidProvenance;
        }
    }
};

pub const Qcow2Profile = struct {
    format: []const u8 = "qcow2",
    version: u32 = 3,
    cluster_bytes: u64 = cluster_size,
    compression: []const u8 = "zstd",
    incompatible_features: u64 = miz.qcow2.incompatible_compression,
    compatible_features: u64 = 0,
    autoclear_features: u64 = 0,
    header_extensions: bool = false,
    extended_l2: bool = false,
    encryption: bool = false,
    snapshots: u32 = 0,
    backing_file: bool = false,
    external_data_file: bool = false,
    standalone: bool = true,

    pub fn validate(self: Qcow2Profile) !void {
        if (!std.mem.eql(u8, self.format, "qcow2") or self.version != 3 or
            self.cluster_bytes != cluster_size or !std.mem.eql(u8, self.compression, "zstd") or
            self.incompatible_features != miz.qcow2.incompatible_compression or
            self.compatible_features != 0 or self.autoclear_features != 0 or
            self.header_extensions or self.extended_l2 or self.encryption or
            self.snapshots != 0 or self.backing_file or
            self.external_data_file or !self.standalone)
        {
            return error.InvalidQcow2Profile;
        }
    }
};

pub const FinalizationRecord = struct {
    schema: []const u8 = "uk.wamr.compute-qcow2-finalization",
    schema_version: u8 = 1,
    status: []const u8 = "succeeded",
    source_sha256: []const u8,
    source_bytes: u64,
    output: Artifact,
    identity: DiskIdentity,
    profile: Qcow2Profile = .{},
    limits: Limits,
    provenance: Provenance,

    pub fn validate(self: FinalizationRecord) !void {
        if (!std.mem.eql(u8, self.schema, "uk.wamr.compute-qcow2-finalization") or
            self.schema_version != 1 or !std.mem.eql(u8, self.status, "succeeded"))
        {
            return error.InvalidRecord;
        }
        _ = try c.sha(self.source_sha256);
        try self.output.validate();
        try self.identity.validate();
        try self.profile.validate();
        try self.limits.validate(self.source_bytes, self.output.virtual_bytes);
        try self.provenance.validate("raw", self.source_sha256);
        if (self.source_bytes != self.output.virtual_bytes or
            self.output.file_bytes > self.limits.max_output_bytes)
        {
            return error.InvalidRecord;
        }
    }
};

pub const Footer = struct {
    sha256: []const u8,
    checksum: u32,
    creator: []const u8 = "miz ",
    creator_version: u32 = 0x0001_0000,
    timestamp: u32 = 0,
    cylinders: u16,
    heads: u8,
    sectors_per_track: u8,
    unique_id: []const u8,

    pub fn validate(self: Footer, capacity: u64) !void {
        if (!std.mem.eql(u8, self.creator, "miz ") or self.creator_version != 0x0001_0000 or
            self.timestamp != 0 or self.unique_id.len != 32)
        {
            return error.InvalidFooter;
        }
        var unique_id: [16]u8 = undefined;
        _ = std.fmt.hexToBytes(&unique_id, self.unique_id) catch return error.InvalidFooter;
        const expected_bytes = miz.vhd.Footer.forFixedDisk(capacity, unique_id, 0).encode();
        const expected_sha256 = std.fmt.bytesToHex(c.hash(&expected_bytes), .lower);
        if (!std.mem.eql(u8, self.sha256, &expected_sha256) or
            self.checksum != std.mem.readInt(u32, expected_bytes[64..68], .big))
        {
            return error.InvalidFooter;
        }
        const geometry = miz.vhd.calculateGeometry(capacity / sector_size);
        if (self.cylinders != geometry.cylinders or self.heads != geometry.heads or
            self.sectors_per_track != geometry.sectors_per_track)
        {
            return error.InvalidFooter;
        }
    }
};

pub const Relocation = struct {
    was_relocated: bool,
    old_backup_lba: u64,
    new_backup_lba: u64,
    old_last_usable_lba: u64,
    new_last_usable_lba: u64,
    allowed_differences: []const u8 = "protective-mbr,primary-gpt,relocated-backup-gpt,zero-padding",
};

pub const DerivationRecord = struct {
    schema: []const u8 = "uk.wamr.compute-fixed-vhd-derivation",
    schema_version: u8 = 1,
    status: []const u8 = "succeeded",
    accepted_qcow2: Artifact,
    accepted_qcow2_decoded_sha256: []const u8,
    accepted_qcow2_profile: Qcow2Profile = .{},
    source_identity: DiskIdentity,
    output: Artifact,
    output_identity: DiskIdentity,
    footer: Footer,
    relocation: Relocation,
    limits: Limits,
    provenance: Provenance,

    pub fn validate(self: DerivationRecord) !void {
        if (!std.mem.eql(u8, self.schema, "uk.wamr.compute-fixed-vhd-derivation") or
            self.schema_version != 1 or !std.mem.eql(u8, self.status, "succeeded") or
            self.output.file_bytes != self.output.virtual_bytes + miz.vhd.footer_size)
        {
            return error.InvalidRecord;
        }
        try self.accepted_qcow2.validate();
        _ = try c.sha(self.accepted_qcow2_decoded_sha256);
        try self.accepted_qcow2_profile.validate();
        try self.source_identity.validate();
        try self.output.validate();
        try self.output_identity.validate();
        try self.footer.validate(self.output.virtual_bytes);
        try self.limits.validate(self.accepted_qcow2.file_bytes, self.accepted_qcow2.virtual_bytes);
        try self.provenance.validate("qcow2", self.accepted_qcow2.sha256);
        const expected_unique_id = uniqueId(
            try c.sha(self.accepted_qcow2.sha256),
            self.accepted_qcow2.virtual_bytes,
        );
        const expected_unique_id_text = std.fmt.bytesToHex(expected_unique_id, .lower);
        if (self.output.virtual_bytes != try alignedCapacity(self.accepted_qcow2.virtual_bytes) or
            !sameDiskIdentity(self.source_identity, self.output_identity) or
            !std.mem.eql(u8, self.footer.unique_id, &expected_unique_id_text) or
            self.accepted_qcow2.file_bytes > self.limits.max_input_bytes or
            self.output.file_bytes > self.limits.max_output_bytes or
            self.relocation.was_relocated != (self.output.virtual_bytes != self.accepted_qcow2.virtual_bytes) or
            !std.mem.eql(
                u8,
                self.relocation.allowed_differences,
                "protective-mbr,primary-gpt,relocated-backup-gpt,zero-padding",
            ) or
            self.relocation.old_backup_lba != self.accepted_qcow2.virtual_bytes / sector_size - 1 or
            self.relocation.new_backup_lba != self.output.virtual_bytes / sector_size - 1 or
            (self.relocation.was_relocated and
                (self.relocation.old_backup_lba >= self.relocation.new_backup_lba or
                    self.relocation.old_last_usable_lba > self.relocation.new_last_usable_lba)) or
            (!self.relocation.was_relocated and
                (self.relocation.old_backup_lba != self.relocation.new_backup_lba or
                    self.relocation.old_last_usable_lba != self.relocation.new_last_usable_lba)))
        {
            return error.InvalidRecord;
        }
    }
};

pub fn readFinalizationRecord(a: std.mem.Allocator, bytes: []const u8) !FinalizationRecord {
    const result = try c.read(FinalizationRecord, a, bytes);
    try result.validate();
    return result;
}

pub fn readDerivationRecord(a: std.mem.Allocator, bytes: []const u8) !DerivationRecord {
    const result = try c.read(DerivationRecord, a, bytes);
    try result.validate();
    return result;
}

pub const FinalizeOptions = struct {
    source: PinnedArtifact,
    expected_virtual_bytes: u64,
    expected_workload_sha256: c.Hash,
    expected_workload_bytes: u64,
    limits: Limits,
    producer: c.File,
    config_sha256: c.Hash,
};

pub const DeriveOptions = struct {
    source: PinnedArtifact,
    expected_capacity_bytes: u64,
    limits: Limits,
    producer: c.File,
    config_sha256: c.Hash,
};

pub fn finalizeQcow2(
    a: std.mem.Allocator,
    io: std.Io,
    root: p.Directory,
    options: FinalizeOptions,
) !FinalizationRecord {
    try options.source.validate(options.limits.max_input_bytes);
    try options.producer.validate(c.max_tool);
    try f.verify(a, io, options.producer, c.max_tool, true);
    try options.limits.validate(options.source.artifact.size, options.expected_virtual_bytes);
    if (options.source.artifact.size != options.expected_virtual_bytes or
        options.expected_workload_bytes == 0 or
        options.expected_workload_bytes > options.limits.max_workload_bytes)
    {
        return error.InvalidGeometry;
    }
    try ensureAbsent(io, root, qcow2_name);
    try ensureAbsent(io, root, qcow2_record_name);
    try createStage(io, root, qcow2_stage_name);

    const retained = try RetainedArtifact.open(io, options.source, options.limits.max_input_bytes);
    defer retained.close(io);
    var work = WorkBudget{ .remaining = options.limits.max_work_bytes };
    var raw = miz.Image{
        .file = retained.file,
        .format = .raw,
        .data_offset = 0,
        .virtual_size = options.expected_virtual_bytes,
    };
    const source_identity = try inspectDisk(a, io, &raw, options.limits, &work);
    if (source_identity.workload_bytes != options.expected_workload_bytes or
        !std.mem.eql(u8, &try c.sha(source_identity.workload_sha256), &options.expected_workload_sha256))
    {
        return error.WorkloadMismatch;
    }

    const stage = try root.dir.openDir(io, qcow2_stage_name, .{ .follow_symlinks = false, .iterate = true });
    defer stage.close(io);
    const output_path = try stagePath(a, io, stage, "miz-output.qcow2");
    const finalized = try miz.artifact_pipeline.finalizeQcow2(a, io, .{
        .input_path = options.source.artifact.path,
        .expected_input_sha256 = options.source.pin.sha256,
        .max_input_size = options.limits.max_input_bytes,
        .source_format = .raw,
        .expected_virtual_size = options.expected_virtual_bytes,
        .max_virtual_size = options.limits.max_virtual_bytes,
        .output_path = output_path,
        .max_output_size = options.limits.max_output_bytes,
        .qemu_img_path = "",
        .compression = .zstd,
        .cluster_size = cluster_size,
    });
    if (finalized.virtual_size != options.expected_virtual_bytes or
        finalized.cluster_size != cluster_size or finalized.compression != .zstd)
    {
        return error.InvalidFinalization;
    }
    try retained.verify(io);

    var output_image = try openBoundedQcow2(io, stage, "miz-output.qcow2", options.limits, options.expected_virtual_bytes);
    defer output_image.close(io);
    const output_snapshot = try c.boot.files.snapshot(output_image.file);
    const output_digest = try c.boot.files.digest(io, output_image.file, output_snapshot);
    if (!std.mem.eql(u8, &output_digest, &finalized.artifact.sha256) or
        output_snapshot.size != finalized.artifact.size)
    {
        return error.InvalidFinalization;
    }
    const decoded = try hashImage(io, output_image, &work);
    if (!std.mem.eql(u8, &decoded, &options.source.pin.sha256)) return error.PayloadMismatch;
    const output_identity = try inspectDisk(a, io, &output_image, options.limits, &work);
    try sameIdentity(a, source_identity, output_identity);
    const host_allocation = try allocation(output_snapshot);
    const output_artifact: Artifact = .{
        .sha256 = try c.hex(a, output_digest),
        .file_bytes = output_snapshot.size,
        .allocated = host_allocation,
        .virtual_bytes = output_image.virtual_size,
    };
    const record: FinalizationRecord = .{
        .source_sha256 = options.source.artifact.sha256,
        .source_bytes = options.source.artifact.size,
        .output = output_artifact,
        .identity = output_identity,
        .limits = options.limits,
        .provenance = .{
            .producer_sha256 = options.producer.sha256,
            .producer_bytes = options.producer.size,
            .config_sha256 = try c.hex(a, options.config_sha256),
            .parent_kind = "raw",
            .parent_sha256 = options.source.artifact.sha256,
        },
    };
    try record.validate();
    try retained.verify(io);
    try f.verify(a, io, options.producer, c.max_tool, true);
    try verifyOpenArtifact(io, output_image.file, output_snapshot, output_digest);
    try publish(a, io, root, stage, "miz-output.qcow2", qcow2_name, qcow2_record_name, record);
    return record;
}

pub fn deriveFixedVhd(
    a: std.mem.Allocator,
    io: std.Io,
    root: p.Directory,
    options: DeriveOptions,
) !DerivationRecord {
    try options.source.validate(options.limits.max_input_bytes);
    try options.producer.validate(c.max_tool);
    try f.verify(a, io, options.producer, c.max_tool, true);
    try options.limits.validate(options.source.artifact.size, options.expected_capacity_bytes);
    const target_capacity = try alignedCapacity(options.expected_capacity_bytes);
    if (target_capacity + miz.vhd.footer_size > options.limits.max_output_bytes)
        return error.InvalidOutputLimit;
    try ensureAbsent(io, root, vhd_name);
    try ensureAbsent(io, root, vhd_record_name);
    try createStage(io, root, vhd_stage_name);

    const retained = try RetainedArtifact.open(io, options.source, options.limits.max_input_bytes);
    defer retained.close(io);
    var work = WorkBudget{ .remaining = options.limits.max_work_bytes };
    var source_image = try openPinnedQcow2(io, retained, options.limits, options.expected_capacity_bytes);
    defer source_image.close(io);
    const source_identity = try inspectDisk(a, io, &source_image, options.limits, &work);
    const source_decoded = try hashImage(io, source_image, &work);
    const source_snapshot = try c.boot.files.snapshot(source_image.file);
    const source_artifact: Artifact = .{
        .sha256 = options.source.artifact.sha256,
        .file_bytes = options.source.artifact.size,
        .allocated = try allocation(source_snapshot),
        .virtual_bytes = source_image.virtual_size,
    };

    const stage = try root.dir.openDir(io, vhd_stage_name, .{ .follow_symlinks = false, .iterate = true });
    defer stage.close(io);
    const output_path = try stagePath(a, io, stage, "miz-output.vhd");
    const expected_unique_id = uniqueId(options.source.pin.sha256, options.expected_capacity_bytes);
    const derived = try miz.azure.deriveFixedVhd(a, io, .{
        .input_path = options.source.artifact.path,
        .expected_input_sha256 = options.source.pin.sha256,
        .max_input_size = options.limits.max_input_bytes,
        .expected_virtual_size = options.expected_capacity_bytes,
        .max_virtual_size = options.limits.max_virtual_bytes,
        .output_path = output_path,
        .max_output_size = options.limits.max_output_bytes,
        .max_partition_array_bytes = options.limits.max_partition_array_bytes,
        .unique_id = expected_unique_id,
        .timestamp_unix = 0,
    });
    if (derived.source_virtual_size != options.expected_capacity_bytes or
        derived.virtual_size != target_capacity)
    {
        return error.InvalidDerivation;
    }
    try retained.verify(io);

    const output_file = try stage.openFile(io, "miz-output.vhd", .{
        .mode = .read_only,
        .allow_directory = false,
        .follow_symlinks = false,
    });
    var output_image = try miz.Image.openFile(io, output_file);
    defer output_image.close(io);
    const output_info = try output_image.info(io);
    if (output_info.format != .vhd or output_info.subformat != .fixed or
        output_info.virtual_size != target_capacity or
        output_info.file_size != target_capacity + miz.vhd.footer_size)
    {
        return error.InvalidFixedVhd;
    }
    const check = try output_image.check(io);
    if (!check.ok) return error.InvalidFixedVhd;
    const footer_report = try inspectFooter(a, io, output_image.file, target_capacity, expected_unique_id);
    const output_identity = try inspectDisk(a, io, &output_image, options.limits, &work);
    try sameIdentity(a, source_identity, output_identity);
    try validateAllowedDifferences(a, io, source_image, output_image, options.limits, derived.relocation, &work);
    const output_snapshot = try c.boot.files.snapshot(output_image.file);
    const output_digest = try c.boot.files.digest(io, output_image.file, output_snapshot);
    if (!std.mem.eql(u8, &output_digest, &derived.artifact.sha256) or
        output_snapshot.size != derived.artifact.size)
    {
        return error.InvalidDerivation;
    }
    const record: DerivationRecord = .{
        .accepted_qcow2 = source_artifact,
        .accepted_qcow2_decoded_sha256 = try c.hex(a, source_decoded),
        .source_identity = source_identity,
        .output = .{
            .sha256 = try c.hex(a, output_digest),
            .file_bytes = output_snapshot.size,
            .allocated = try allocation(output_snapshot),
            .virtual_bytes = output_image.virtual_size,
        },
        .output_identity = output_identity,
        .footer = footer_report,
        .relocation = .{
            .was_relocated = derived.relocation.was_relocated,
            .old_backup_lba = derived.relocation.old_backup_lba,
            .new_backup_lba = derived.relocation.new_backup_lba,
            .old_last_usable_lba = derived.relocation.old_last_usable_lba,
            .new_last_usable_lba = derived.relocation.new_last_usable_lba,
        },
        .limits = options.limits,
        .provenance = .{
            .producer_sha256 = options.producer.sha256,
            .producer_bytes = options.producer.size,
            .config_sha256 = try c.hex(a, options.config_sha256),
            .parent_kind = "qcow2",
            .parent_sha256 = options.source.artifact.sha256,
        },
    };
    try record.validate();
    try retained.verify(io);
    try f.verify(a, io, options.producer, c.max_tool, true);
    try verifyOpenArtifact(io, output_image.file, output_snapshot, output_digest);
    try publish(a, io, root, stage, "miz-output.vhd", vhd_name, vhd_record_name, record);
    return record;
}

fn minimumMetadataBytes(max_virtual: u64) !u64 {
    const guest_clusters = std.math.divCeil(u64, max_virtual, cluster_size) catch
        return error.InvalidMetadataLimit;
    const l1_entries_count = @max(@as(u64, 1), std.math.divCeil(u64, guest_clusters, l2_entries) catch
        return error.InvalidMetadataLimit);
    const l1_bytes = std.math.mul(u64, l1_entries_count, @sizeOf(u64)) catch
        return error.InvalidMetadataLimit;
    return std.math.add(
        u64,
        fixed_header_bytes + header_terminator_bytes,
        std.math.add(u64, l1_bytes, cluster_size) catch return error.InvalidMetadataLimit,
    ) catch return error.InvalidMetadataLimit;
}

fn minimumMetadataWork(max_virtual: u64) !u64 {
    _ = max_virtual;
    return refcount_table_entries + 2;
}

fn alignedCapacity(capacity: u64) !u64 {
    const rounded = std.math.add(u64, capacity, c.mib - 1) catch
        return error.InvalidGeometry;
    return rounded / c.mib * c.mib;
}

fn qcow2Limits(limits: Limits, max_file_bytes: u64) !miz.Qcow2StandaloneOpenLimits {
    const guest_clusters = std.math.divCeil(u64, limits.max_virtual_bytes, cluster_size) catch
        return error.InvalidGeometry;
    const l1_count = @max(@as(u64, 1), std.math.divCeil(u64, guest_clusters, l2_entries) catch
        return error.InvalidGeometry);
    return .{
        .max_file_bytes = max_file_bytes,
        .max_virtual_size = limits.max_virtual_bytes,
        .min_cluster_bits = cluster_bits,
        .max_cluster_bits = cluster_bits,
        .max_l1_entries = l1_count,
        .max_l1_table_bytes = try std.math.mul(u64, l1_count, @sizeOf(u64)),
        .max_refcount_table_clusters = 1,
        .max_refcount_table_bytes = cluster_size,
        .max_refcount_table_entries = refcount_table_entries,
        .max_snapshot_count = 0,
        .max_snapshot_table_bytes = 0,
        .max_snapshot_l1_entries = 0,
        .max_snapshot_l1_table_bytes = 0,
        .max_metadata_bytes = limits.max_metadata_bytes,
        .max_metadata_work = limits.max_metadata_work,
    };
}

fn openBoundedQcow2(
    io: std.Io,
    dir: std.Io.Dir,
    name: []const u8,
    limits: Limits,
    expected_virtual: u64,
) !miz.Image {
    const file = try dir.openFile(io, name, .{
        .mode = .read_only,
        .allow_directory = false,
        .follow_symlinks = false,
    });
    var transferred = false;
    defer if (!transferred) file.close(io);
    var image = try miz.Image.openStandaloneQcow2FileWithLimits(
        io,
        file,
        try qcow2Limits(limits, limits.max_output_bytes),
    );
    transferred = true;
    errdefer image.close(io);
    try validateQcow2ProfileWithIo(io, image, expected_virtual);
    return image;
}

fn openPinnedQcow2(
    io: std.Io,
    retained: RetainedArtifact,
    limits: Limits,
    expected_virtual: u64,
) !miz.Image {
    const file = try p.openAbsolute(io, retained.pinned.artifact.path, .artifact);
    var transferred = false;
    defer if (!transferred) file.close(io);
    if (!retained.pinned.pin.matches(try c.boot.files.snapshot(file))) return error.ArtifactChanged;
    var image = try miz.Image.openStandaloneQcow2FileWithLimits(
        io,
        file,
        try qcow2Limits(limits, limits.max_input_bytes),
    );
    transferred = true;
    errdefer image.close(io);
    try validateQcow2ProfileWithIo(io, image, expected_virtual);
    return image;
}

fn validateQcow2ProfileWithIo(io: std.Io, image: miz.Image, expected_virtual: u64) !void {
    const info = image.qcow2 orelse return error.InvalidQcow2;
    const snapshot = try c.boot.files.snapshot(image.file);
    var header: [fixed_header_bytes + header_terminator_bytes]u8 = undefined;
    if (try image.file.readPositionalAll(io, &header, 0) != header.len or
        std.mem.readInt(u64, header[80..88], .big) != 0 or
        std.mem.readInt(u64, header[88..96], .big) != 0 or
        !std.mem.allEqual(u8, header[105..], 0))
    {
        return error.InvalidQcow2;
    }
    if (image.format != .qcow2 or image.virtual_size != expected_virtual or
        info.file_size != snapshot.size or
        info.version != 3 or info.cluster_bits != cluster_bits or info.cluster_size != cluster_size or
        info.header_length != fixed_header_bytes or info.l2_entries != l2_entries or
        info.refcount_order != miz.qcow2.default_refcount_order or
        info.refcount_table_clusters != 1 or info.refcount_table_capacity_blocks != refcount_table_entries or
        info.refcount_block_count != 1 or
        info.incompatible_features != miz.qcow2.incompatible_compression or
        info.compression_type != 1 or info.crypt_method != 0 or
        info.snapshot_count != 0 or info.snapshots_offset != 0 or
        info.source_path_len != 0 or info.data_file_len != 0 or
        info.data_file_size != 0 or info.backing_file_len != 0 or info.backing_depth != 0)
    {
        return error.InvalidQcow2;
    }
    const guest_clusters = std.math.divCeil(u64, expected_virtual, cluster_size) catch
        return error.InvalidQcow2;
    const expected_l1 = @max(@as(u64, 1), std.math.divCeil(u64, guest_clusters, l2_entries) catch
        return error.InvalidQcow2);
    if (info.l1_size != expected_l1 or info.active_l1_table_offset != info.l1_table_offset)
        return error.InvalidQcow2;
    const checked = try image.check(io);
    if (!checked.ok) return error.InvalidQcow2;
}

const WorkBudget = struct {
    remaining: u64,

    fn charge(self: *WorkBudget, bytes: u64) !void {
        if (bytes > self.remaining) return error.WorkLimitExceeded;
        self.remaining -= bytes;
    }
};

fn hashImage(io: std.Io, image: miz.Image, work: *WorkBudget) !c.Hash {
    try work.charge(image.virtual_size);
    var sha = c.boot.files.Sha256.init(.{});
    var buffer: [64 * 1024]u8 = undefined;
    var offset: u64 = 0;
    while (offset < image.virtual_size) {
        const count: usize = @intCast(@min(buffer.len, image.virtual_size - offset));
        if (try image.pread(io, buffer[0..count], offset) != count) return error.InvalidImage;
        sha.update(buffer[0..count]);
        offset += count;
    }
    return sha.finalResult();
}

fn inspectDisk(
    a: std.mem.Allocator,
    io: std.Io,
    image: *miz.Image,
    limits: Limits,
    work: *WorkBudget,
) !DiskIdentity {
    var table = try miz.gpt.readVerifiedGpt(image.*, io, a, limits.max_partition_array_bytes);
    defer table.deinit(a);
    if (table.partitions.len == 0 or table.partitions.len > std.math.maxInt(u32))
        return error.InvalidGpt;
    var partitions = c.boot.files.Sha256.init(.{});
    partitions.update(partition_domain);
    var buffer: [64 * 1024]u8 = undefined;
    var esp: ?miz.gpt.PartitionEntry = null;
    for (table.partitions) |partition| {
        var fields: [44]u8 = undefined;
        std.mem.writeInt(u32, fields[0..4], partition.table_index, .little);
        fields[4..20].* = partition.partition_type_guid;
        fields[20..36].* = partition.unique_partition_guid;
        std.mem.writeInt(u64, fields[36..44], partition.first_lba, .little);
        partitions.update(&fields);
        const sectors = std.math.add(u64, partition.last_lba - partition.first_lba, 1) catch
            return error.InvalidGpt;
        const length = std.math.mul(u64, sectors, sector_size) catch return error.InvalidGpt;
        const start = std.math.mul(u64, partition.first_lba, sector_size) catch return error.InvalidGpt;
        try work.charge(length);
        var offset: u64 = 0;
        while (offset < length) {
            const count: usize = @intCast(@min(buffer.len, length - offset));
            if (try image.pread(io, buffer[0..count], start + offset) != count)
                return error.InvalidImage;
            partitions.update(buffer[0..count]);
            offset += count;
        }
        if (std.mem.eql(u8, &partition.partition_type_guid, &miz.guid.esp)) {
            if (esp != null) return error.MultipleEspPartitions;
            esp = partition;
        }
    }
    const selected = esp orelse return error.MissingEspPartition;
    const esp_sectors = std.math.add(u64, selected.last_lba - selected.first_lba, 1) catch
        return error.InvalidGpt;
    const esp_length = std.math.mul(u64, esp_sectors, sector_size) catch return error.InvalidGpt;
    const esp_offset = std.math.mul(u64, selected.first_lba, sector_size) catch return error.InvalidGpt;
    var filesystem = try miz.fat32.open(image, io, .{ .offset = esp_offset, .length = esp_length });
    var tree = try miz.fat32.scanTree(&filesystem, io, a, .{
        .max_nodes = 16,
        .max_file_bytes = limits.max_workload_bytes,
        .max_total_bytes = limits.max_workload_bytes,
        .max_scan_metadata_bytes = 64 * 1024,
    });
    defer tree.deinit();
    var has_efi = false;
    var has_boot = false;
    var workload: ?miz.fat32.TreeEntry = null;
    for (0..tree.nodeCount()) |index| {
        const entry = tree.entryAt(index);
        if (std.mem.eql(u8, entry.path, "EFI") and entry.kind == .directory)
            has_efi = true
        else if (std.mem.eql(u8, entry.path, "EFI/BOOT") and entry.kind == .directory)
            has_boot = true
        else if (std.mem.eql(u8, entry.path, workload_path) and entry.kind == .file)
            workload = entry
        else
            return error.UnexpectedEspContents;
    }
    if (!has_efi or !has_boot or tree.nodeCount() != 3) return error.UnexpectedEspContents;
    const payload = workload orelse return error.MissingWorkload;
    if (payload.size == 0 or payload.size > limits.max_workload_bytes)
        return error.InvalidWorkload;
    try work.charge(payload.size);
    const reader = payload.content orelse return error.InvalidWorkload;
    var workload_hash = c.boot.files.Sha256.init(.{});
    var position: u64 = 0;
    while (position < payload.size) {
        const count: usize = @intCast(@min(buffer.len, payload.size - position));
        if (try reader.readAt(buffer[0..count], position) != count) return error.InvalidWorkload;
        workload_hash.update(buffer[0..count]);
        position += count;
    }
    const volume = filesystem.volumeMetadata();
    if (!std.mem.eql(u8, &volume.volume_label, "MIZ EFI APP"))
        return error.InvalidEspIdentity;
    return .{
        .disk_guid = try a.dupe(u8, &std.fmt.bytesToHex(table.primary_header.disk_guid, .lower)),
        .partition_array_sha256 = try c.hex(a, c.hash(table.partition_array)),
        .partition_contents_sha256 = try c.hex(a, partitions.finalResult()),
        .partition_count = @intCast(table.partitions.len),
        .esp_partition_guid = try a.dupe(u8, &std.fmt.bytesToHex(selected.unique_partition_guid, .lower)),
        .esp_offset_bytes = esp_offset,
        .esp_length_bytes = esp_length,
        .esp_volume_id = volume.volume_id,
        .workload_bytes = payload.size,
        .workload_sha256 = try c.hex(a, workload_hash.finalResult()),
    };
}

fn sameIdentity(a: std.mem.Allocator, left: DiskIdentity, right: DiskIdentity) !void {
    try left.validate();
    try right.validate();
    try f.same(a, left, right);
}

fn sameDiskIdentity(left: DiskIdentity, right: DiskIdentity) bool {
    return std.mem.eql(u8, left.disk_guid, right.disk_guid) and
        std.mem.eql(u8, left.partition_array_sha256, right.partition_array_sha256) and
        std.mem.eql(u8, left.partition_contents_sha256, right.partition_contents_sha256) and
        left.partition_count == right.partition_count and
        std.mem.eql(u8, left.esp_partition_guid, right.esp_partition_guid) and
        left.esp_offset_bytes == right.esp_offset_bytes and
        left.esp_length_bytes == right.esp_length_bytes and
        left.esp_volume_id == right.esp_volume_id and
        std.mem.eql(u8, left.workload_path, right.workload_path) and
        left.workload_bytes == right.workload_bytes and
        std.mem.eql(u8, left.workload_sha256, right.workload_sha256);
}

fn allocation(snapshot: p.Snapshot) !Allocation {
    if (!snapshot.mask.BLOCKS) return .{ .state = .unavailable, .bytes = null };
    return .{
        .state = .available,
        .bytes = std.math.mul(u64, snapshot.blocks, allocation_unit) catch
            return error.InvalidAllocation,
    };
}

fn verifyOpenArtifact(
    io: std.Io,
    file: std.Io.File,
    expected: p.Snapshot,
    expected_sha256: c.Hash,
) !void {
    const before = try c.boot.files.snapshot(file);
    if (!p.sameSnapshot(expected, before) or
        !std.mem.eql(u8, &try c.boot.files.digest(io, file, before), &expected_sha256))
    {
        return error.ArtifactChanged;
    }
}

fn uniqueId(source_sha256: c.Hash, capacity: u64) [16]u8 {
    var sha = c.boot.files.Sha256.init(.{});
    sha.update(unique_id_domain);
    sha.update(&source_sha256);
    var bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &bytes, capacity, .little);
    sha.update(&bytes);
    return sha.finalResult()[0..16].*;
}

fn inspectFooter(
    a: std.mem.Allocator,
    io: std.Io,
    file: std.Io.File,
    capacity: u64,
    expected_unique_id: [16]u8,
) !Footer {
    var bytes: [miz.vhd.footer_size]u8 = undefined;
    if (try file.readPositionalAll(io, &bytes, capacity) != bytes.len)
        return error.InvalidFooter;
    const decoded = try miz.vhd.Footer.decode(&bytes);
    const geometry = miz.vhd.calculateGeometry(capacity / sector_size);
    if (decoded.features != 2 or decoded.file_format_version != 0x0001_0000 or
        decoded.data_offset != std.math.maxInt(u64) or decoded.timestamp != 0 or
        !std.mem.eql(u8, &decoded.creator_application, &miz.vhd.creator_app_miz) or
        decoded.creator_version != 0x0001_0000 or
        !std.mem.allEqual(u8, &decoded.creator_host_os, 0) or
        decoded.original_size != capacity or decoded.current_size != capacity or
        decoded.geometry.cylinders != geometry.cylinders or decoded.geometry.heads != geometry.heads or
        decoded.geometry.sectors_per_track != geometry.sectors_per_track or
        decoded.disk_type != .fixed or !std.mem.eql(u8, &decoded.unique_id, &expected_unique_id) or
        decoded.saved_state != 0 or !std.mem.allEqual(u8, bytes[85..], 0))
    {
        return error.InvalidFooter;
    }
    return .{
        .sha256 = try c.hex(a, c.hash(&bytes)),
        .checksum = std.mem.readInt(u32, bytes[64..68], .big),
        .cylinders = decoded.geometry.cylinders,
        .heads = decoded.geometry.heads,
        .sectors_per_track = decoded.geometry.sectors_per_track,
        .unique_id = try a.dupe(u8, &std.fmt.bytesToHex(decoded.unique_id, .lower)),
    };
}

const Range = struct {
    start: u64,
    end: u64,

    fn contains(self: Range, offset: u64) bool {
        return offset >= self.start and offset < self.end;
    }
};

fn validateAllowedDifferences(
    a: std.mem.Allocator,
    io: std.Io,
    source: miz.Image,
    output: miz.Image,
    limits: Limits,
    relocation: miz.gpt.RelocationResult,
    work: *WorkBudget,
) !void {
    var source_gpt = try miz.gpt.readVerifiedGpt(source, io, a, limits.max_partition_array_bytes);
    defer source_gpt.deinit(a);
    var output_gpt = try miz.gpt.readVerifiedGpt(output, io, a, limits.max_partition_array_bytes);
    defer output_gpt.deinit(a);
    if (!std.mem.eql(u8, source_gpt.partition_array, output_gpt.partition_array) or
        source_gpt.partitions.len != output_gpt.partitions.len)
    {
        return error.PartitionChanged;
    }
    for (source_gpt.partitions, output_gpt.partitions) |before, after| {
        if (before.table_index != after.table_index or before.first_lba != after.first_lba or
            before.last_lba != after.last_lba or
            !std.mem.eql(u8, &before.partition_type_guid, &after.partition_type_guid) or
            !std.mem.eql(u8, &before.unique_partition_guid, &after.unique_partition_guid))
        {
            return error.PartitionChanged;
        }
    }
    if (relocation.was_relocated != (output.virtual_size != source.virtual_size) or
        relocation.old_backup_lba != source_gpt.primary_header.backup_lba or
        relocation.new_backup_lba != output_gpt.primary_header.backup_lba)
    {
        return error.InvalidRelocation;
    }
    var allowed: [4]Range = undefined;
    var allowed_len: usize = 0;
    if (relocation.was_relocated) {
        const source_array_bytes: u64 = @intCast(source_gpt.partition_array.len);
        const source_array_sectors = std.math.divCeil(u64, source_array_bytes, sector_size) catch
            return error.InvalidRelocation;
        allowed[0] = .{ .start = 0, .end = sector_size };
        allowed[1] = .{ .start = sector_size, .end = 2 * sector_size };
        allowed[2] = try backupGptRange(relocation.old_backup_lba, source_array_sectors);
        allowed[3] = try backupGptRange(relocation.new_backup_lba, source_array_sectors);
        allowed_len = allowed.len;
    }
    try work.charge(source.virtual_size);
    var source_buffer: [64 * 1024]u8 = undefined;
    var output_buffer: [64 * 1024]u8 = undefined;
    var offset: u64 = 0;
    while (offset < source.virtual_size) {
        const count: usize = @intCast(@min(source_buffer.len, source.virtual_size - offset));
        if (try source.pread(io, source_buffer[0..count], offset) != count or
            try output.pread(io, output_buffer[0..count], offset) != count)
        {
            return error.InvalidImage;
        }
        for (source_buffer[0..count], output_buffer[0..count], 0..) |before, after, index| {
            if (before == after) continue;
            const absolute = offset + index;
            var accepted = false;
            for (allowed[0..allowed_len]) |range| {
                if (range.contains(absolute)) {
                    accepted = true;
                    break;
                }
            }
            if (!accepted) return error.UnexpectedPayloadDifference;
        }
        offset += count;
    }
    if (output.virtual_size > source.virtual_size) {
        try work.charge(output.virtual_size - source.virtual_size);
        offset = source.virtual_size;
        while (offset < output.virtual_size) {
            const count: usize = @intCast(@min(output_buffer.len, output.virtual_size - offset));
            if (try output.pread(io, output_buffer[0..count], offset) != count)
                return error.InvalidImage;
            for (output_buffer[0..count], 0..) |byte, index| {
                if (byte == 0) continue;
                const absolute = offset + index;
                var accepted = false;
                for (allowed[0..allowed_len]) |range| {
                    if (range.contains(absolute)) {
                        accepted = true;
                        break;
                    }
                }
                if (!accepted) return error.UnexpectedPayloadDifference;
            }
            offset += count;
        }
    }
}

fn backupGptRange(backup_lba: u64, array_sectors: u64) !Range {
    const first_lba = std.math.sub(u64, backup_lba, array_sectors) catch
        return error.InvalidRelocation;
    const after_lba = std.math.add(u64, backup_lba, 1) catch
        return error.InvalidRelocation;
    return .{
        .start = std.math.mul(u64, first_lba, sector_size) catch
            return error.InvalidRelocation,
        .end = std.math.mul(u64, after_lba, sector_size) catch
            return error.InvalidRelocation,
    };
}

fn ensureAbsent(io: std.Io, root: p.Directory, name: []const u8) !void {
    const existing = root.dir.openFile(io, name, .{
        .mode = .read_only,
        .allow_directory = false,
        .follow_symlinks = false,
    }) catch |err| switch (err) {
        error.FileNotFound => return,
        else => return err,
    };
    existing.close(io);
    return error.PathAlreadyExists;
}

fn createStage(io: std.Io, root: p.Directory, name: []const u8) !void {
    try root.dir.createDir(io, name, .fromMode(0o700));
    try f.sync(io, root.dir);
}

fn stagePath(a: std.mem.Allocator, io: std.Io, stage: std.Io.Dir, name: []const u8) ![]const u8 {
    var buffer: [4096]u8 = undefined;
    const path = buffer[0..try stage.realPath(io, &buffer)];
    return f.path(a, path, name);
}

fn publish(
    a: std.mem.Allocator,
    io: std.Io,
    root: p.Directory,
    stage: std.Io.Dir,
    staged_output: []const u8,
    output_name: []const u8,
    record_name: []const u8,
    record: anytype,
) !void {
    const encoded = try c.encode(a, record);
    const record_file = try stage.createFile(io, "result.json", .{
        .exclusive = true,
        .permissions = .fromMode(0o600),
    });
    defer record_file.close(io);
    try record_file.writePositionalAll(io, encoded, 0);
    try record_file.sync(io);
    const output = try stage.openFile(io, staged_output, .{
        .mode = .read_write,
        .allow_directory = false,
        .follow_symlinks = false,
    });
    defer output.close(io);
    try output.setPermissions(io, .fromMode(0o600));
    try output.sync(io);
    try f.sync(io, stage);
    try stage.renamePreserve(staged_output, root.dir, output_name, io);
    var output_visible = true;
    var record_visible = false;
    var complete = false;
    errdefer if (!complete) {
        if (record_visible) root.dir.deleteFile(io, record_name) catch {};
        if (output_visible) root.dir.deleteFile(io, output_name) catch {};
        f.sync(io, root.dir) catch {};
    };
    try stage.renamePreserve("result.json", root.dir, record_name, io);
    record_visible = true;
    try f.sync(io, stage);
    try f.sync(io, root.dir);
    complete = true;
    output_visible = false;
}

pub fn configHash(bytes: []const u8) c.Hash {
    var sha = c.boot.files.Sha256.init(.{});
    sha.update(config_domain);
    sha.update(bytes);
    return sha.finalResult();
}

pub fn applyWorkerLimits(limits: Limits) !void {
    const file_size: linux.rlimit = .{
        .cur = limits.max_output_bytes,
        .max = limits.max_output_bytes,
    };
    const address_space: linux.rlimit = .{
        .cur = limits.max_memory_bytes,
        .max = limits.max_memory_bytes,
    };
    const no_core: linux.rlimit = .{ .cur = 0, .max = 0 };
    if (linux.errno(linux.setrlimit(.FSIZE, &file_size)) != .SUCCESS or
        linux.errno(linux.setrlimit(.AS, &address_space)) != .SUCCESS or
        linux.errno(linux.setrlimit(.CORE, &no_core)) != .SUCCESS)
    {
        return error.LimitFailed;
    }
}

test "allocation unavailable is explicit and records reject tampering" {
    const unavailable: Allocation = .{ .state = .unavailable, .bytes = null };
    try unavailable.validate();
    try std.testing.expectError(
        error.InvalidAllocation,
        (Allocation{ .state = .unavailable, .bytes = 0 }).validate(),
    );
}
