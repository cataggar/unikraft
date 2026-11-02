// SPDX-License-Identifier: BSD-3-Clause
//! Compile-only production API anchors; this object is never installed or run.
const core = @import("hyperv_core");
const runtime = @import("runtime.zig");
const custody = @import("custody.zig");

export fn compileRuntime(adapter: *runtime.Runtime, lock: *core.private_files.Locked) bool {
    const result = adapter.run(.primary, .validator, &.{}, lock, "out", "err") catch return false;
    return result.succeeded();
}

export fn compileFinalization(store: *custody.Store, completion: *const custody.Completion) u8 {
    return store.finish(completion.*).exit_code;
}
