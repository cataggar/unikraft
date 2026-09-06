// SPDX-License-Identifier: BSD-3-Clause

//! Direct metadata for the registered hello-world native image profiles.
//! The normalized GNU Make graph is retained separately as test fixtures.

pub const PathRoot = enum { base, app, output };

pub const Path = struct {
    root: PathRoot,
    relative: []const u8,
};

pub const Origin = enum { architecture, driver, library, platform, application };

pub const Library = struct {
    name: []const u8,
    origin: Origin,
    objects: []const []const u8,
    archives: []const Path = &.{},
    linker_scripts: []const Path = &.{},
    export_symbols: ?Path = null,
};

pub const Profile = struct {
    libraries: []const Library,
    linker_script_inputs: []const Path,
    final_output: []const u8,
};

pub const x86_64_efi_kvm_objects = [_][]const u8{
    "libkvmplat/efi_entry64.x86.o",
    "libkvmplat/efi_post.isr.o",
    "libkvmplat/pagetable64.o",
    "libkvmplat/cpu_vectors_x86_64.o",
    "libkvmplat/setup.o",
    "libkvmplat/lcpu_start.o",
    "libkvmplat/tscclock.o",
    "libkvmplat/time.o",
    "libkvmplat/qemu.x86.o",
    "libkvmplat/memory.o",
    "libkvmplat/memory.common.o",
    "libkvmplat/efi.isr.o",
    "libkvmplat/bootinfo.common.o",
    "libkvmplat/libinfo.libuklibid.o",
};

pub const x86_64_efi_native_objects = [_][]const u8{
    "libukplat_native/addr.isr.o",
    "libukplat_native/paging.isr.o",
    "libukplat_native/pt.isr.o",
    "libukplat_native/ectx.isr.o",
    "libukplat_native/except.isr.o",
    "libukplat_native/sysctx_auxsp.o",
    "libukplat_native/lcpu_pm.o",
    "libukplat_native/start.o",
    "libukplat_native/libinfo.libuklibid.o",
};

pub const x86_64_efi_libraries = [_]Library{
    .{
        .name = "libukreloc",
        .origin = .library,
        .objects = &.{
            "libukreloc/reloc.o",
            "libukreloc/libinfo.libuklibid.o",
        },
        .linker_scripts = &.{
            .{ .root = .output, .relative = "libukreloc/reloc.lds" },
        },
    },
    .{
        .name = "libukefi",
        .origin = .library,
        .objects = &.{"libukefi/libinfo.libuklibid.o"},
    },
    .{
        .name = "libukacpi",
        .origin = .library,
        .objects = &.{
            "libukacpi/acpi.o",
            "libukacpi/madt.o",
            "libukacpi/libinfo.libuklibid.o",
        },
    },
    .{
        .name = "libukfalloc",
        .origin = .library,
        .objects = &.{"libukfalloc/libinfo.libuklibid.o"},
    },
    .{
        .name = "libukfallocbuddy",
        .origin = .library,
        .objects = &.{
            "libukfallocbuddy/fallocbuddy.isr.o",
            "libukfallocbuddy/libinfo.libuklibid.o",
        },
    },
    .{
        .name = "libukpaging",
        .origin = .library,
        .objects = &.{
            "libukpaging/paging.isr.o",
            "libukpaging/arch.isr.o",
            "libukpaging/libinfo.libuklibid.o",
        },
    },
};

pub const x86_64 = Profile{
    .libraries = &.{
        .{
            .name = "libkvmplat",
            .origin = .platform,
            .objects = &.{
                "libkvmplat/multiboot.x86.o",
                "libkvmplat/multiboot.o",
                "libkvmplat/pagetable64.o",
                "libkvmplat/cpu_vectors_x86_64.o",
                "libkvmplat/setup.o",
                "libkvmplat/lcpu_start.o",
                "libkvmplat/tscclock.o",
                "libkvmplat/time.o",
                "libkvmplat/qemu.x86.o",
                "libkvmplat/memory.o",
                "libkvmplat/memory.common.o",
                "libkvmplat/bootinfo.common.o",
                "libkvmplat/libinfo.libuklibid.o",
            },
            .linker_scripts = &.{
                .{ .root = .output, .relative = "libkvmplat/link64.lds" },
                .{ .root = .output, .relative = "libkvmplat/bootinfo.lds" },
            },
        },
        .{
            .name = "apphelloworld",
            .origin = .application,
            .objects = &.{
                "apphelloworld/main.o",
                "apphelloworld/libinfo.libuklibid.o",
            },
        },
        .{
            .name = "libisrlib",
            .origin = .library,
            .objects = &.{
                "libisrlib/string.isr.o",
                "libisrlib/libinfo.libuklibid.o",
            },
        },
        .{
            .name = "libnolibc",
            .origin = .library,
            .objects = &.{
                "libnolibc/errno.o",
                "libnolibc/stdio.o",
                "libnolibc/ctype.o",
                "libnolibc/stdlib.o",
                "libnolibc/string.o",
                "libnolibc/strsignal.o",
                "libnolibc/strstr.o",
                "libnolibc/psignal.o",
                "libnolibc/__month_to_secs.o",
                "libnolibc/__secs_to_tm.o",
                "libnolibc/timegm.o",
                "libnolibc/__tm_to_secs.o",
                "libnolibc/__year_to_secs.o",
                "libnolibc/htonl.o",
                "libnolibc/ntohl.o",
                "libnolibc/htons.o",
                "libnolibc/ntohs.o",
                "libnolibc/h_errno.o",
                "libnolibc/getopt.o",
                "libnolibc/sscanf.o",
                "libnolibc/scanf.o",
                "libnolibc/asprintf.o",
                "libnolibc/random.o",
                "libnolibc/qsort.o",
                "libnolibc/libinfo.libuklibid.o",
            },
            .export_symbols = .{ .root = .base, .relative = "lib/nolibc/exportsyms.uk" },
        },
        .{
            .name = "libukalloc",
            .origin = .library,
            .objects = &.{
                "libukalloc/alloc.o",
                "libukalloc/libinfo.libuklibid.o",
            },
            .export_symbols = .{ .root = .base, .relative = "lib/ukalloc/exportsyms.uk" },
        },
        .{
            .name = "libukallocbbuddy",
            .origin = .library,
            .objects = &.{
                "libukallocbbuddy/bbuddy.o",
                "libukallocbbuddy/libinfo.libuklibid.o",
            },
            .export_symbols = .{ .root = .base, .relative = "lib/ukallocbbuddy/exportsyms.uk" },
        },
        .{
            .name = "libukargparse",
            .origin = .library,
            .objects = &.{
                "libukargparse/argparse.o",
                "libukargparse/libinfo.libuklibid.o",
            },
            .export_symbols = .{ .root = .base, .relative = "lib/ukargparse/exportsyms.uk" },
        },
        .{
            .name = "libukatomic",
            .origin = .library,
            .objects = &.{
                "libukatomic/libinfo.libuklibid.o",
            },
        },
        .{
            .name = "libukbitops",
            .origin = .library,
            .objects = &.{
                "libukbitops/libinfo.libuklibid.o",
            },
        },
        .{
            .name = "libukboot",
            .origin = .library,
            .objects = &.{
                "libukboot/boot.o",
                "libukboot/early_init.o",
                "libukboot/version.o",
                "libukboot/banner.o",
                "libukboot/libinfo.libuklibid.o",
            },
            .linker_scripts = &.{
                .{ .root = .output, .relative = "libukboot/earlytab.lds" },
            },
            .export_symbols = .{ .root = .base, .relative = "lib/ukboot/exportsyms.uk" },
        },
        .{
            .name = "libukboot_main",
            .origin = .library,
            .objects = &.{
                "libukboot_main/weak_main.o",
                "libukboot_main/libinfo.libuklibid.o",
            },
            .export_symbols = .{ .root = .base, .relative = "lib/ukboot/exportsyms.uk" },
        },
        .{
            .name = "libukbus",
            .origin = .library,
            .objects = &.{
                "libukbus/bus.o",
                "libukbus/libinfo.libuklibid.o",
            },
            .export_symbols = .{ .root = .base, .relative = "lib/ukbus/exportsyms.uk" },
        },
        .{
            .name = "libukconsole",
            .origin = .library,
            .objects = &.{
                "libukconsole/console.isr.o",
                "libukconsole/libinfo.libuklibid.o",
            },
            .export_symbols = .{ .root = .base, .relative = "lib/ukconsole/exportsyms.uk" },
        },
        .{
            .name = "libukdebug",
            .origin = .library,
            .objects = &.{
                "libukdebug/crashsup.o",
                "libukdebug/dumpsup.o",
                "libukdebug/crashdump.o",
                "libukdebug/crash.o",
                "libukdebug/libinfo.libuklibid.o",
            },
            .export_symbols = .{ .root = .base, .relative = "lib/ukdebug/exportsyms.uk" },
        },
        .{
            .name = "libuklibid",
            .origin = .library,
            .objects = &.{
                "libuklibid/namemap.o",
                "libuklibid/selfids.o",
                "libuklibid/rtmap.o",
                "libuklibid/libinfo.global.o",
                "libuklibid/libinfo.libuklibid.o",
            },
            .linker_scripts = &.{
                .{ .root = .base, .relative = "lib/uklibid/infosec.ld" },
            },
            .export_symbols = .{ .root = .output, .relative = "libuklibid/exportsyms.uk" },
        },
        .{
            .name = "libukintctlr",
            .origin = .library,
            .objects = &.{
                "libukintctlr/ukintctlr.o",
                "libukintctlr/libinfo.libuklibid.o",
            },
            .export_symbols = .{ .root = .base, .relative = "lib/ukintctlr/exportsyms.uk" },
        },
        .{
            .name = "libuklock",
            .origin = .library,
            .objects = &.{
                "libuklock/semaphore.o",
                "libuklock/mutex.o",
                "libuklock/rwlock.o",
                "libuklock/libinfo.libuklibid.o",
            },
            .export_symbols = .{ .root = .base, .relative = "lib/uklock/exportsyms.uk" },
        },
        .{
            .name = "libukprint",
            .origin = .library,
            .objects = &.{
                "libukprint/print.o",
                "libukprint/print.isr.o",
                "libukprint/snprintf.isr.o",
                "libukprint/outf.o",
                "libukprint/hexdump.o",
                "libukprint/console.o",
                "libukprint/libinfo.libuklibid.o",
            },
            .export_symbols = .{ .root = .base, .relative = "lib/ukprint/exportsyms.uk" },
        },
        .{
            .name = "libuksched",
            .origin = .library,
            .objects = &.{
                "libuksched/sched.o",
                "libuksched/thread.o",
                "libuksched/isrwake.isr.o",
                "libuksched/libinfo.libuklibid.o",
            },
            .linker_scripts = &.{
                .{ .root = .base, .relative = "lib/uksched/extra.ld" },
            },
            .export_symbols = .{ .root = .base, .relative = "lib/uksched/exportsyms.uk" },
        },
        .{
            .name = "libukschedcoop",
            .origin = .library,
            .objects = &.{
                "libukschedcoop/schedcoop.o",
                "libukschedcoop/isrwoken.isr.o",
                "libukschedcoop/libinfo.libuklibid.o",
            },
            .export_symbols = .{ .root = .base, .relative = "lib/ukschedcoop/exportsyms.uk" },
        },
        .{
            .name = "libuksglist",
            .origin = .library,
            .objects = &.{
                "libuksglist/sglist.o",
                "libuksglist/libinfo.libuklibid.o",
            },
            .export_symbols = .{ .root = .base, .relative = "lib/uksglist/exportsyms.uk" },
        },
        .{
            .name = "libuktimeconv",
            .origin = .library,
            .objects = &.{
                "libuktimeconv/timeconv.o",
                "libuktimeconv/libinfo.libuklibid.o",
            },
            .export_symbols = .{ .root = .base, .relative = "lib/uktimeconv/exportsyms.uk" },
        },
        .{
            .name = "libukallocstack",
            .origin = .library,
            .objects = &.{
                "libukallocstack/stack.o",
                "libukallocstack/libinfo.libuklibid.o",
            },
            .export_symbols = .{ .root = .base, .relative = "lib/ukallocstack/exportsyms.uk" },
        },
        .{
            .name = "libukpal",
            .origin = .library,
            .objects = &.{
                "libukpal/libinfo.libuklibid.o",
            },
        },
        .{
            .name = "libuklcpu",
            .origin = .library,
            .objects = &.{
                "libuklcpu/lcpu.o",
                "libuklcpu/libinfo.libuklibid.o",
            },
            .export_symbols = .{ .root = .base, .relative = "lib/uklcpu/exportsyms.uk" },
        },
        .{
            .name = "libukpm",
            .origin = .library,
            .objects = &.{
                "libukpm/pm.o",
                "libukpm/libinfo.libuklibid.o",
            },
            .export_symbols = .{ .root = .base, .relative = "lib/ukpm/exportsyms.uk" },
        },
        .{
            .name = "libukpcpuvar",
            .origin = .library,
            .objects = &.{
                "libukpcpuvar/pcpuvar.o",
                "libukpcpuvar/libinfo.libuklibid.o",
            },
            .linker_scripts = &.{
                .{ .root = .output, .relative = "libukpcpuvar/pcpuvar.lds" },
            },
            .export_symbols = .{ .root = .base, .relative = "lib/ukpcpuvar/exportsyms.uk" },
        },
        .{
            .name = "libcontext",
            .origin = .architecture,
            .objects = &.{
                "libcontext/ctx.isr.o",
                "libcontext/execenv.x86_64.o",
                "libcontext/ctx.x86_64.o",
                "libcontext/tls.x86_64.o",
                "libcontext/libinfo.libuklibid.o",
            },
        },
        .{
            .name = "libns16550",
            .origin = .driver,
            .objects = &.{
                "libns16550/com.isr.o",
                "libns16550/libinfo.libuklibid.o",
            },
            .export_symbols = .{ .root = .base, .relative = "drivers/ukconsole/ns16550/exportsyms.uk" },
        },
        .{
            .name = "libvgacons",
            .origin = .driver,
            .objects = &.{
                "libvgacons/vga.o",
                "libvgacons/libinfo.libuklibid.o",
            },
            .export_symbols = .{ .root = .base, .relative = "drivers/ukconsole/vgacons/exportsyms.uk" },
        },
        .{
            .name = "libukintctlr_xpic",
            .origin = .driver,
            .objects = &.{
                "libukintctlr_xpic/pic.o",
                "libukintctlr_xpic/ukintctlr.o",
                "libukintctlr_xpic/libinfo.libuklibid.o",
            },
            .export_symbols = .{ .root = .base, .relative = "drivers/ukintctlr/xpic/exportsyms.uk" },
        },
        .{
            .name = "libukplat_native",
            .origin = .platform,
            .objects = &.{
                "libukplat_native/ectx.isr.o",
                "libukplat_native/except.isr.o",
                "libukplat_native/sysctx_auxsp.o",
                "libukplat_native/lcpu_pm.o",
                "libukplat_native/start.o",
                "libukplat_native/libinfo.libuklibid.o",
            },
            .export_symbols = .{ .root = .base, .relative = "plat/native/exportsyms.uk" },
        },
    },
    .linker_script_inputs = &.{
        .{ .root = .output, .relative = "libkvmplat/link64.lds" },
        .{ .root = .output, .relative = "libkvmplat/bootinfo.lds" },
        .{ .root = .output, .relative = "libukboot/earlytab.lds" },
        .{ .root = .base, .relative = "lib/uklibid/infosec.ld" },
        .{ .root = .base, .relative = "lib/uksched/extra.ld" },
        .{ .root = .output, .relative = "libukpcpuvar/pcpuvar.lds" },
    },
    .final_output = "helloworld_qemu-x86_64.dbg",
};

pub const arm64 = Profile{
    .libraries = &.{
        .{
            .name = "libkvmplat",
            .origin = .platform,
            .objects = &.{
                "libkvmplat/cache64.common.o",
                "libkvmplat/time.common.o",
                "libkvmplat/generic_timer.common.o",
                "libkvmplat/qemu_bpt64.arm.o",
                "libkvmplat/entry64.isr.o",
                "libkvmplat/exceptions.isr.o",
                "libkvmplat/pagetable64.isr.o",
                "libkvmplat/setup.o",
                "libkvmplat/memory.o",
                "libkvmplat/memory.common.o",
                "libkvmplat/bootinfo.common.o",
                "libkvmplat/bootinfo_fdt.common.o",
                "libkvmplat/libinfo.libuklibid.o",
            },
            .linker_scripts = &.{
                .{ .root = .output, .relative = "libkvmplat/link64.lds" },
                .{ .root = .output, .relative = "libkvmplat/bootinfo.lds" },
            },
        },
        .{
            .name = "apphelloworld",
            .origin = .application,
            .objects = &.{
                "apphelloworld/main.o",
                "apphelloworld/libinfo.libuklibid.o",
            },
        },
        .{
            .name = "libfdt",
            .origin = .library,
            .objects = &.{
                "libfdt/fdt.o",
                "libfdt/fdt_addresses.o",
                "libfdt/fdt_empty_tree.o",
                "libfdt/fdt_overlay.o",
                "libfdt/fdt_ro.o",
                "libfdt/fdt_rw.o",
                "libfdt/fdt_strerror.o",
                "libfdt/fdt_sw.o",
                "libfdt/fdt_wip.o",
                "libfdt/libinfo.libuklibid.o",
            },
            .export_symbols = .{ .root = .base, .relative = "lib/fdt/exportsyms.uk" },
        },
        .{
            .name = "libisrlib",
            .origin = .library,
            .objects = &.{
                "libisrlib/string.isr.o",
                "libisrlib/libinfo.libuklibid.o",
            },
        },
        .{
            .name = "libnolibc",
            .origin = .library,
            .objects = &.{
                "libnolibc/errno.o",
                "libnolibc/stdio.o",
                "libnolibc/ctype.o",
                "libnolibc/stdlib.o",
                "libnolibc/string.o",
                "libnolibc/strsignal.o",
                "libnolibc/strstr.o",
                "libnolibc/psignal.o",
                "libnolibc/__month_to_secs.o",
                "libnolibc/__secs_to_tm.o",
                "libnolibc/timegm.o",
                "libnolibc/__tm_to_secs.o",
                "libnolibc/__year_to_secs.o",
                "libnolibc/htonl.o",
                "libnolibc/ntohl.o",
                "libnolibc/htons.o",
                "libnolibc/ntohs.o",
                "libnolibc/h_errno.o",
                "libnolibc/getopt.o",
                "libnolibc/sscanf.o",
                "libnolibc/scanf.o",
                "libnolibc/asprintf.o",
                "libnolibc/random.o",
                "libnolibc/qsort.o",
                "libnolibc/libinfo.libuklibid.o",
            },
            .export_symbols = .{ .root = .base, .relative = "lib/nolibc/exportsyms.uk" },
        },
        .{
            .name = "libukalloc",
            .origin = .library,
            .objects = &.{
                "libukalloc/alloc.o",
                "libukalloc/libinfo.libuklibid.o",
            },
            .export_symbols = .{ .root = .base, .relative = "lib/ukalloc/exportsyms.uk" },
        },
        .{
            .name = "libukallocbbuddy",
            .origin = .library,
            .objects = &.{
                "libukallocbbuddy/bbuddy.o",
                "libukallocbbuddy/libinfo.libuklibid.o",
            },
            .export_symbols = .{ .root = .base, .relative = "lib/ukallocbbuddy/exportsyms.uk" },
        },
        .{
            .name = "libukargparse",
            .origin = .library,
            .objects = &.{
                "libukargparse/argparse.o",
                "libukargparse/libinfo.libuklibid.o",
            },
            .export_symbols = .{ .root = .base, .relative = "lib/ukargparse/exportsyms.uk" },
        },
        .{
            .name = "libukatomic",
            .origin = .library,
            .objects = &.{
                "libukatomic/libinfo.libuklibid.o",
            },
        },
        .{
            .name = "libukbitops",
            .origin = .library,
            .objects = &.{
                "libukbitops/libinfo.libuklibid.o",
            },
        },
        .{
            .name = "libukboot",
            .origin = .library,
            .objects = &.{
                "libukboot/boot.o",
                "libukboot/early_init.o",
                "libukboot/version.o",
                "libukboot/banner.o",
                "libukboot/libinfo.libuklibid.o",
            },
            .linker_scripts = &.{
                .{ .root = .output, .relative = "libukboot/earlytab.lds" },
            },
            .export_symbols = .{ .root = .base, .relative = "lib/ukboot/exportsyms.uk" },
        },
        .{
            .name = "libukboot_main",
            .origin = .library,
            .objects = &.{
                "libukboot_main/weak_main.o",
                "libukboot_main/libinfo.libuklibid.o",
            },
            .export_symbols = .{ .root = .base, .relative = "lib/ukboot/exportsyms.uk" },
        },
        .{
            .name = "libukbus",
            .origin = .library,
            .objects = &.{
                "libukbus/bus.o",
                "libukbus/libinfo.libuklibid.o",
            },
            .export_symbols = .{ .root = .base, .relative = "lib/ukbus/exportsyms.uk" },
        },
        .{
            .name = "libukconsole",
            .origin = .library,
            .objects = &.{
                "libukconsole/console.isr.o",
                "libukconsole/libinfo.libuklibid.o",
            },
            .export_symbols = .{ .root = .base, .relative = "lib/ukconsole/exportsyms.uk" },
        },
        .{
            .name = "libukdebug",
            .origin = .library,
            .objects = &.{
                "libukdebug/crashsup.o",
                "libukdebug/dumpsup.o",
                "libukdebug/crashdump.o",
                "libukdebug/crash.o",
                "libukdebug/libinfo.libuklibid.o",
            },
            .export_symbols = .{ .root = .base, .relative = "lib/ukdebug/exportsyms.uk" },
        },
        .{
            .name = "libuklibid",
            .origin = .library,
            .objects = &.{
                "libuklibid/namemap.o",
                "libuklibid/selfids.o",
                "libuklibid/rtmap.o",
                "libuklibid/libinfo.global.o",
                "libuklibid/libinfo.libuklibid.o",
            },
            .linker_scripts = &.{
                .{ .root = .base, .relative = "lib/uklibid/infosec.ld" },
            },
            .export_symbols = .{ .root = .output, .relative = "libuklibid/exportsyms.uk" },
        },
        .{
            .name = "libukintctlr",
            .origin = .library,
            .objects = &.{
                "libukintctlr/ukintctlr.o",
                "libukintctlr/libinfo.libuklibid.o",
            },
            .export_symbols = .{ .root = .base, .relative = "lib/ukintctlr/exportsyms.uk" },
        },
        .{
            .name = "libuklock",
            .origin = .library,
            .objects = &.{
                "libuklock/semaphore.o",
                "libuklock/mutex.o",
                "libuklock/rwlock.o",
                "libuklock/libinfo.libuklibid.o",
            },
            .export_symbols = .{ .root = .base, .relative = "lib/uklock/exportsyms.uk" },
        },
        .{
            .name = "libukprint",
            .origin = .library,
            .objects = &.{
                "libukprint/print.o",
                "libukprint/print.isr.o",
                "libukprint/snprintf.isr.o",
                "libukprint/outf.o",
                "libukprint/hexdump.o",
                "libukprint/console.o",
                "libukprint/libinfo.libuklibid.o",
            },
            .export_symbols = .{ .root = .base, .relative = "lib/ukprint/exportsyms.uk" },
        },
        .{
            .name = "libuksched",
            .origin = .library,
            .objects = &.{
                "libuksched/sched.o",
                "libuksched/thread.o",
                "libuksched/isrwake.isr.o",
                "libuksched/libinfo.libuklibid.o",
            },
            .linker_scripts = &.{
                .{ .root = .base, .relative = "lib/uksched/extra.ld" },
            },
            .export_symbols = .{ .root = .base, .relative = "lib/uksched/exportsyms.uk" },
        },
        .{
            .name = "libukschedcoop",
            .origin = .library,
            .objects = &.{
                "libukschedcoop/schedcoop.o",
                "libukschedcoop/isrwoken.isr.o",
                "libukschedcoop/libinfo.libuklibid.o",
            },
            .export_symbols = .{ .root = .base, .relative = "lib/ukschedcoop/exportsyms.uk" },
        },
        .{
            .name = "libuksglist",
            .origin = .library,
            .objects = &.{
                "libuksglist/sglist.o",
                "libuksglist/libinfo.libuklibid.o",
            },
            .export_symbols = .{ .root = .base, .relative = "lib/uksglist/exportsyms.uk" },
        },
        .{
            .name = "libuktimeconv",
            .origin = .library,
            .objects = &.{
                "libuktimeconv/timeconv.o",
                "libuktimeconv/libinfo.libuklibid.o",
            },
            .export_symbols = .{ .root = .base, .relative = "lib/uktimeconv/exportsyms.uk" },
        },
        .{
            .name = "libukofw",
            .origin = .library,
            .objects = &.{
                "libukofw/fdt.o",
                "libukofw/libinfo.libuklibid.o",
            },
            .export_symbols = .{ .root = .base, .relative = "lib/ukofw/exportsyms.uk" },
        },
        .{
            .name = "libukallocstack",
            .origin = .library,
            .objects = &.{
                "libukallocstack/stack.o",
                "libukallocstack/libinfo.libuklibid.o",
            },
            .export_symbols = .{ .root = .base, .relative = "lib/ukallocstack/exportsyms.uk" },
        },
        .{
            .name = "libukpal",
            .origin = .library,
            .objects = &.{
                "libukpal/libinfo.libuklibid.o",
            },
        },
        .{
            .name = "libuklcpu",
            .origin = .library,
            .objects = &.{
                "libuklcpu/lcpu.o",
                "libuklcpu/libinfo.libuklibid.o",
            },
            .export_symbols = .{ .root = .base, .relative = "lib/uklcpu/exportsyms.uk" },
        },
        .{
            .name = "libukpm",
            .origin = .library,
            .objects = &.{
                "libukpm/pm.o",
                "libukpm/libinfo.libuklibid.o",
            },
            .export_symbols = .{ .root = .base, .relative = "lib/ukpm/exportsyms.uk" },
        },
        .{
            .name = "libukpcpuvar",
            .origin = .library,
            .objects = &.{
                "libukpcpuvar/pcpuvar.o",
                "libukpcpuvar/libinfo.libuklibid.o",
            },
            .linker_scripts = &.{
                .{ .root = .output, .relative = "libukpcpuvar/pcpuvar.lds" },
            },
            .export_symbols = .{ .root = .base, .relative = "lib/ukpcpuvar/exportsyms.uk" },
        },
        .{
            .name = "libarm64arch",
            .origin = .architecture,
            .objects = &.{
                "libarm64arch/libinfo.libuklibid.o",
            },
        },
        .{
            .name = "libcontext",
            .origin = .architecture,
            .objects = &.{
                "libcontext/ctx.isr.o",
                "libcontext/execenv.arm64.o",
                "libcontext/ctx.arm64.o",
                "libcontext/tls.arm64.o",
                "libcontext/libinfo.libuklibid.o",
            },
        },
        .{
            .name = "libukbus_platform",
            .origin = .driver,
            .objects = &.{
                "libukbus_platform/platform_bus.o",
                "libukbus_platform/libinfo.libuklibid.o",
            },
            .export_symbols = .{ .root = .base, .relative = "drivers/ukbus/platform/exportsyms.uk" },
        },
        .{
            .name = "libpl011",
            .origin = .driver,
            .objects = &.{
                "libpl011/pl011.isr.o",
                "libpl011/libinfo.libuklibid.o",
            },
            .export_symbols = .{ .root = .base, .relative = "drivers/ukconsole/pl011/exportsyms.uk" },
        },
        .{
            .name = "libukintctlr_gic",
            .origin = .driver,
            .objects = &.{
                "libukintctlr_gic/ukintctlr.o",
                "libukintctlr_gic/gic-common.o",
                "libukintctlr_gic/gic-v2.o",
                "libukintctlr_gic/libinfo.libuklibid.o",
            },
            .export_symbols = .{ .root = .base, .relative = "drivers/ukintctlr/gic/exportsyms.uk" },
        },
        .{
            .name = "libukrtc_pl031",
            .origin = .driver,
            .objects = &.{
                "libukrtc_pl031/pl031.o",
                "libukrtc_pl031/rtc.o",
                "libukrtc_pl031/libinfo.libuklibid.o",
            },
            .export_symbols = .{ .root = .base, .relative = "drivers/ukrtc/pl031/exportsyms.uk" },
        },
        .{
            .name = "libukpsci",
            .origin = .driver,
            .objects = &.{
                "libukpsci/psci.o",
                "libukpsci/libinfo.libuklibid.o",
            },
            .export_symbols = .{ .root = .base, .relative = "drivers/firmware/ukpsci/exportsyms.uk" },
        },
        .{
            .name = "libuksmccc",
            .origin = .driver,
            .objects = &.{
                "libuksmccc/smccc.o",
                "libuksmccc/smccc_invoke.o",
                "libuksmccc/libinfo.libuklibid.o",
            },
            .export_symbols = .{ .root = .base, .relative = "drivers/firmware/uksmccc/exportsyms.uk" },
        },
        .{
            .name = "libukplat_native",
            .origin = .platform,
            .objects = &.{
                "libukplat_native/auxsp.o",
                "libukplat_native/ectx.isr.o",
                "libukplat_native/except.isr.o",
                "libukplat_native/lcpu_pm.o",
                "libukplat_native/sysctx.isr.o",
                "libukplat_native/start.o",
                "libukplat_native/libinfo.libuklibid.o",
            },
            .export_symbols = .{ .root = .base, .relative = "plat/native/exportsyms.uk" },
        },
    },
    .linker_script_inputs = &.{
        .{ .root = .output, .relative = "libkvmplat/link64.lds" },
        .{ .root = .output, .relative = "libkvmplat/bootinfo.lds" },
        .{ .root = .output, .relative = "libukboot/earlytab.lds" },
        .{ .root = .base, .relative = "lib/uklibid/infosec.ld" },
        .{ .root = .base, .relative = "lib/uksched/extra.ld" },
        .{ .root = .output, .relative = "libukpcpuvar/pcpuvar.lds" },
    },
    .final_output = "helloworld_qemu-arm64.dbg",
};
