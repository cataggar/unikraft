//! Private fixture build capture. No production or admission interface.
const std = @import("std");

pub const section_name = ".uk.persistence.build";
pub const max_parent_bytes: u64 = 96 * 1024 * 1024;
pub const max_raw_worker_bytes: u64 = 64 * 1024 * 1024;
pub const max_selected_worker_bytes: u64 = 16 * 1024 * 1024;
pub const max_compiler_bytes: u64 = 256 * 1024 * 1024;
pub const max_lib_bytes: u64 = 256 * 1024 * 1024;
pub const max_lib_file_bytes: u64 = 16 * 1024 * 1024;
pub const max_tree_files: usize = 32768;
pub const max_modules: usize = 32;
pub const max_metadata_bytes: usize = 32768;
pub const max_plan_bytes: usize = 4 * 1024 * 1024;
pub const max_log_bytes: u64 = 64 * 1024 * 1024;
pub const max_collection_bytes: u64 = 256 * 1024 * 1024;

pub const Module = struct {
    name: []const u8,
    root: []const u8,
    scope: []const u8,
};

/// Absolute paths are internal custody data, never exported metadata.
pub const Request = struct {
    source_commit: []const u8,
    source_tree: []const u8,
    configured_json: []const u8,
    parent: []const u8,
    raw_worker: []const u8,
    selected_worker: []const u8,
    compiler: []const u8,
    compiler_lib: []const u8,
    main_options: []const u8,
    main_source: []const u8,
    repository_hyperv: []const u8,
    repository_build: []const u8,
    worker_proof: []const u8,
    fixture_log: []const u8,
    invocation_exit: []const u8,
    modules: []const Module,
};

pub fn validateIdentity(value: []const u8) !void {
    if (value.len != 40) return error.InvalidSourceIdentity;
    for (value) |byte| if (!std.ascii.isDigit(byte) and (byte < 'a' or byte > 'f'))
        return error.InvalidSourceIdentity;
}

pub fn validateModuleName(value: []const u8) !void {
    if (value.len == 0 or value.len > 64) return error.InvalidModuleName;
    for (value) |byte| if (!std.ascii.isAlphanumeric(byte) and byte != '_')
        return error.InvalidModuleName;
}
