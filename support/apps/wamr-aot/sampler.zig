// SPDX-License-Identifier: BSD-3-Clause
const std = @import("std");
// The build imports exactly ONE public sampler root under this local alias.
const native = @import("sampler");
const workload = @import("wamr-jit-workload");
const fixture = @import("workload-artifacts");
const services = @import("native-services.zig");
const c = services.c;
pub const std_options: std.Options = if (fixture.with_compiler) native.std_options else .{};

export fn wamr_workload_run(config: *const c.wamr_aot_config, facts: *const c.struct_wamr_workload_facts, mode: c_uint) c_int {
    run(config, facts, mode) catch return 1;
    return 0;
}

fn run(config: *const c.wamr_aot_config, facts: *const c.struct_wamr_workload_facts, mode: c_uint) !void {
    var platform: services.Services(native.aot) = .{ .config = config };
    var storage: [16384]u8 = undefined;
    var writer = std.Io.Writer.fixed(&storage);
    const challenge = if (fixture.with_compiler) switch (mode) {
        1 => "wamr-native-correctness-only-v1\nfast\n",
        2 => "wamr-native-correctness-only-v1\nfull\n",
        else => return error.InvalidMode,
    } else if (mode == 0) "wamr-native-correctness-only-v1\naot\n" else return error.InvalidMode;
    var hash: [64]u8 = undefined;
    const request_hash = services.identify(challenge, &hash);
    // Keep Capture in place: its report slices borrow its own hash storage.
    var capture: native.sample.Capture = .{};
    const result = if (fixture.with_compiler)
        native.sample.run(platform.allocator(), platform.platform(), workload.wasm, if (mode == 1) .fast else .full, request_hash, 100, &capture)
    else
        native.sample.run(platform.allocator(), platform.platform(), workload.wasm, fixture.aot, request_hash, 100, &capture);
    try capture.writeRecord(&writer);
    try services.transmit(&writer);
    try services.factsRecord(&writer, facts, if (fixture.with_compiler) "jit" else "sample-aot", platform.observations());
    try result;
    if (capture.report.failure != null) return error.SampleFailed;
}
