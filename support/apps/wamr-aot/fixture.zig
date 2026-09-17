//! Correctness only: generated wasm is compiled by the pinned host wamrc.
export fn answer() u32 {
    return 42;
}

export fn grow(pages: u32) i32 {
    return @intCast(@wasmMemoryGrow(0, pages));
}

export fn trap() void {
    @trap();
}
