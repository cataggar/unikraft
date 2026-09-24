// SPDX-License-Identifier: BSD-3-Clause
const std = @import("std");
const records = @import("wamr_log_validator").records;

// Synthetic parser data only; never an execution or benchmark observation.
pub const stdout =
    "2K performance run parameters for coremark.\n" ++
    "CoreMark Size    : 666\n" ++
    "Total ticks      : 1\n" ++
    "Total time (secs): 0.001000\n" ++
    "Iterations/Sec   : 100000.000000\n" ++
    "ERROR! Must execute for at least 10 secs for a valid result!\n" ++
    "Iterations       : 100\n" ++
    "Compiler version : synthetic fixture, not execution evidence\n" ++
    "Compiler flags   : synthetic\n" ++
    "Memory location  : STACK\n" ++
    "seedcrc          : 0xe9f5\n" ++
    "[0]crclist       : 0xe714\n" ++
    "[0]crcmatrix     : 0x1fd7\n" ++
    "[0]crcstate      : 0x8e3a\n" ++
    "[0]crcfinal      : 0x988c\n" ++
    "Errors detected\n";

pub const identity = records.Identity{
    .wamr_revision = "ffffffffffffffffffffffffffffffffffffffff",
    .minimal_wasi = true,
    .tiny_wasm = "0000000000000000000000000000000000000000000000000000000000000000",
    .tiny_cwasm = "1111111111111111111111111111111111111111111111111111111111111111",
    .runtime = "2222222222222222222222222222222222222222222222222222222222222222",
    .coremark_wasm = "3333333333333333333333333333333333333333333333333333333333333333",
    .coremark_cwasm = "4444444444444444444444444444444444444444444444444444444444444444",
    .nofp_wasm = "5555555555555555555555555555555555555555555555555555555555555555",
    .nofp_cwasm = "6666666666666666666666666666666666666666666666666666666666666666",
};

pub const identity_json =
    "{\"wamr_revision\":\"" ++ identity.wamr_revision ++
    "\",\"minimal_wasi\":true,\"files\":{\"tiny.wasm\":\"" ++ identity.tiny_wasm ++
    "\",\"tiny.cwasm\":\"" ++ identity.tiny_cwasm ++
    "\",\"libwamr-aot.a\":\"" ++ identity.runtime ++
    "\",\"coremark.wasm\":\"" ++ identity.coremark_wasm ++
    "\",\"coremark.cwasm\":\"" ++ identity.coremark_cwasm ++
    "\",\"coremark-nofp.wasm\":\"" ++ identity.nofp_wasm ++
    "\",\"coremark-nofp.cwasm\":\"" ++ identity.nofp_cwasm ++ "\"}}";

pub fn wasi(allocator: std.mem.Allocator, name: []const u8, wasm: []const u8, cwasm: []const u8) ![]u8 {
    const encoded = try allocator.alloc(u8, std.base64.standard.Encoder.calcSize(stdout.len));
    defer allocator.free(encoded);
    _ = std.base64.standard.Encoder.encode(encoded, stdout);
    return std.fmt.allocPrint(allocator, "WAMR_NATIVE_WASI={{\"version\":1,\"correctness_only\":true,\"workload\":\"{s}\",\"wasm_sha256\":\"{s}\",\"cwasm_sha256\":\"{s}\",\"terminal\":2,\"detail\":0,\"crc_ok\":true,\"output_error\":0,\"pending_stdout\":0,\"pending_stderr\":0,\"unsupported_clock\":0,\"realtime_supported\":true,\"stdout_base64\":\"{s}\",\"stderr_base64\":\"\"}}\n", .{ name, wasm, cwasm, encoded });
}

pub fn serial(allocator: std.mem.Allocator, with_wasi: bool) ![]u8 {
    const first = if (with_wasi) try wasi(allocator, "coremark", identity.coremark_wasm, identity.coremark_cwasm) else try allocator.dupe(u8, "");
    defer allocator.free(first);
    const second = if (with_wasi) try wasi(allocator, "coremark-nofp", identity.nofp_wasm, identity.nofp_cwasm) else try allocator.dupe(u8, "");
    defer allocator.free(second);
    return std.fmt.allocPrint(allocator, "Hyper-V Hv#1 hypercall page enabled\nHyper-V SynIC:\nPowered by\nCalling main(0, 0)\n{s}{s}" ++
        "WAMR_NATIVE_COMPUTE={{\"version\":1,\"workload\":\"tiny\",\"wamr_revision\":\"{s}\",\"wasm_sha256\":\"{s}\",\"cwasm_sha256\":\"{s}\",\"runtime_sha256\":\"{s}\",\"platform_status\":0,\"checks\":2,\"answer\":42,\"terminal\":1,\"detail\":2,\"reserved_bytes\":0,\"frame_bytes\":0,\"accessible_bytes\":0,\"allocation_bytes\":0,\"system_page_table_bytes\":4096,\"error_name\":\"\"}}\n" ++
        "WAMR_NATIVE_AOT_OK answer=42 teardown=0\n[    1.000001] Info: [libukboot] main returned 0\n", .{ first, second, identity.wamr_revision, identity.tiny_wasm, identity.tiny_cwasm, identity.runtime });
}
