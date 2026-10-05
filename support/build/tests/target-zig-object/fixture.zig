const config = @import("config");

export fn issue34_zig_target_value() callconv(.c) u32 {
    return config.CONFIG_ISSUE34_VALUE + config.ISSUE34_INCLUDE_VALUE + config.ISSUE34_OBJECT_VALUE;
}

export fn issue34_zig_fixture_checksum(value: config.struct_issue34_fixture) callconv(.c) u32 {
    return value.value + value.tag + value.lane;
}
