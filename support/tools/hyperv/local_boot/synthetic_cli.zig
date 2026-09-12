//! Uninstalled fixture root; the installed main has no diagnostic declaration.
pub const local_boot_synthetic_diagnostics = true;
pub const main = @import("main.zig").main;
