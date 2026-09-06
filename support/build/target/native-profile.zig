const config = @cImport({
    @cInclude("uk/bits/config.h");
});

export fn uk_target_zig_config_marker() callconv(.c) u32 {
    return if (@hasDecl(config, "CONFIG_OPTIMIZE_PIE"))
        config.CONFIG_OPTIMIZE_PIE
    else
        0;
}
