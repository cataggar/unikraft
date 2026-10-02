// SPDX-License-Identifier: BSD-3-Clause
const std = @import("std");

pub const repository = "cataggar/unikraft";
pub const workload = "tiny";
pub const current_profile = "qcow2-derived-vhd";
pub const wamr_revision = "a53205d77be3b880eb8f8b96679512ba58e2331a";
pub const authority = "not_admitted";
pub const canonicalization = "utf8-byte-sorted-keys-compact-lf-v1";

pub const Compatibility = enum {
    frozen_tiny_v1,
    tiny_qcow2_derived_vhd_v2,

    pub fn version(self: Compatibility) u8 {
        return switch (self) {
            .frozen_tiny_v1 => 1,
            .tiny_qcow2_derived_vhd_v2 => 2,
        };
    }
};

pub const ProfileSpec = enum { @"qcow2-derived-vhd" };

pub const Mode = enum {
    @"raw-x2apic",
    @"raw-legacy-apic",
    @"qcow2-x2apic",
    @"qcow2-legacy-apic",
    @"vpc-x2apic",
    @"vpc-legacy-apic",
};

pub const legacy_modes = [_]Mode{
    .@"raw-x2apic", .@"raw-legacy-apic", .@"vpc-x2apic", .@"vpc-legacy-apic",
};
pub const production_modes = [_]Mode{
    .@"raw-x2apic",        .@"raw-legacy-apic", .@"qcow2-x2apic",
    .@"qcow2-legacy-apic", .@"vpc-x2apic",      .@"vpc-legacy-apic",
};

pub const SourceIdentity = struct { revision: []const u8, tree: []const u8 };
pub const legacy_v1_without_external_archive_digest = [_]SourceIdentity{
    .{ .revision = "34e5c88a165c4da878b3122b8b91716116d65d4b", .tree = "54f8e118146c78c24e7c802657c6ec62b268a5de" },
    .{ .revision = "993e4d0d394c08202c0d0c57ea97450a19a4f394", .tree = "54f8e118146c78c24e7c802657c6ec62b268a5de" },
    .{ .revision = "b5a8fdbee033349f7145fbc76aebfee29b2fa04f", .tree = "54f8e118146c78c24e7c802657c6ec62b268a5de" },
};
pub const pre_supervisor_with_external_archive_digest = [_]SourceIdentity{
    .{ .revision = "0711a0b6bf2285a4ba6ab6dd3bd4088478d665e1", .tree = "3d9def2872f41248b518a850a48a5c462e158890" },
    .{ .revision = "3c6d5d98dc5736d86e97884184b26be39c3f11d5", .tree = "feb57a66615a6083378c7261e1e53c37730e0650" },
    .{ .revision = "c9c00535399354063486957611bf6e09c8ae4592", .tree = "02827e49c25d06eba21bb2157833fc135811eedb" },
};

pub fn modes(compat: Compatibility) []const Mode {
    return switch (compat) {
        .frozen_tiny_v1 => &legacy_modes,
        .tiny_qcow2_derived_vhd_v2 => &production_modes,
    };
}

pub fn profileName(compat: Compatibility) ?[]const u8 {
    return switch (compat) {
        .frozen_tiny_v1 => null,
        .tiny_qcow2_derived_vhd_v2 => current_profile,
    };
}

pub fn compatibility(version: u8, profile: ?[]const u8) !Compatibility {
    if (version == 1 and profile == null) return .frozen_tiny_v1;
    if (version == 2 and profile != null and std.mem.eql(u8, profile.?, current_profile))
        return .tiny_qcow2_derived_vhd_v2;
    return error.UnsupportedCompatibility;
}

pub fn productionProfile(spec: ProfileSpec) Compatibility {
    return switch (spec) {
        .@"qcow2-derived-vhd" => .tiny_qcow2_derived_vhd_v2,
    };
}

pub fn omitsExternalArchiveDigest(source: SourceIdentity) bool {
    return containsSource(&legacy_v1_without_external_archive_digest, source);
}

pub fn hasPreSupervisorRecordExceptions(source: SourceIdentity) bool {
    return containsSource(&pre_supervisor_with_external_archive_digest, source);
}

pub fn historicalCompatibility(source: SourceIdentity) ?enum { legacy_v1, pre_supervisor } {
    if (omitsExternalArchiveDigest(source)) return .legacy_v1;
    if (hasPreSupervisorRecordExceptions(source)) return .pre_supervisor;
    return null;
}

fn containsSource(table: []const SourceIdentity, source: SourceIdentity) bool {
    for (table) |item| {
        if (std.mem.eql(u8, item.revision, source.revision) and
            std.mem.eql(u8, item.tree, source.tree)) return true;
    }
    return false;
}
