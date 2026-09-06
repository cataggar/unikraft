const config = @cImport({
    @cInclude("uk/bits/config.h");
    @cInclude("issue34-fixture.h");
});

export fn issue34_zig_target_value() callconv(.c) u32 {
    return config.CONFIG_ISSUE34_VALUE + config.ISSUE34_INCLUDE_VALUE;
}
