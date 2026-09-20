// SPDX-License-Identifier: BSD-3-Clause
//! Explicit offline fake, never a dispatcher to Azure, transfer, or hash tools.
const std = @import("std");
const f = @import("lifecycle_fixture_support.zig");
const inventory = @import("lifecycle_fixture_cases.zig");
const seams = @import("lifecycle_fixture_seams.zig");
const eq = f.eq;
const one = f.oneOf;
const starts = f.starts;
const State = struct {
    exists: bool = false,
    boots: u8 = 0,
    power: []const u8 = "deallocated",
    cleanup: bool = false,
    boot2_reads: u8 = 0,
    serial_reads: u8 = 0,
    os: Disk = .{},
    data: Disk = .{},
    const Disk = struct { created: bool = false, uploaded: bool = false };
};
const Fake = struct {
    c: f.Context,
    scenario: []const u8,
    state: State,

    fn is(self: Fake, name: []const u8) bool {
        return eq(self.scenario, name);
    }
    fn save(self: Fake) !void {
        try self.c.replaceJson("fake-cloud.json", self.state);
    }
    fn output(self: Fake, bytes: []const u8) !void {
        if (std.mem.indexOf(u8, bytes, f.sentinel) != null) {
            try f.grantOutput(self.c, std.Io.File.stdout());
        }
        var out = std.Io.File.stdout().writerStreaming(self.c.io, &.{});
        try out.interface.writeAll(bytes);
    }
    fn emit(self: Fake, value: anytype) !void {
        try self.output(try std.mem.concat(self.c.a, u8, &.{ try f.json(self.c.a, value), "\n" }));
    }
    fn serial(self: Fake, bytes: []const u8) !void {
        try self.emit(bytes);
    }
    fn replace(self: Fake, bytes: []const u8, before: []const u8, after: []const u8) ![]const u8 {
        try f.expect(std.mem.indexOf(u8, bytes, before) != null);
        return std.mem.replaceOwned(u8, self.c.a, bytes, before, after);
    }
    fn tamper(self: Fake, relative: []const u8, suffix: []const u8) !void {
        try self.c.write(try std.mem.concat(self.c.a, u8, &.{ "tamper-original-", std.fs.path.basename(relative) }), try self.c.read(relative));
        try self.c.append(relative, suffix);
    }
    fn disk(self: Fake, role: []const u8) !std.json.Value {
        try f.expect(one(role, &.{ "os", "data" }));
        const os = eq(role, "os");
        const saved = if (os) self.state.os else self.state.data;
        var uuid: []const u8 = if (os) "original-os" else "original-data";
        if ((f.compute or !os) and ((self.is("identity-drift") and self.state.boots == 2) or
            (self.is("diagnostics-disk-identity-drift") and self.state.cleanup))) uuid = "replacement";
        var state: []const u8 = if (self.state.boots == 0)
            (if (saved.uploaded) "Unattached" else "ReadyToUpload")
        else if (eq(self.state.power, "deallocated")) "Reserved" else "Attached";
        if (self.is("running-reserved") and !os and eq(state, "Attached")) state = "Reserved";
        if (self.is("retained-attached") and !os and self.state.boots == 1 and eq(state, "Reserved")) state = "Attached";
        if (self.is("final-attached") and os and self.state.boots == 2 and eq(state, "Reserved")) state = "Attached";
        if (self.is("retained-unattached") and !os and self.state.boots == 1 and eq(state, "Reserved")) state = "Unattached";
        // Provider numeric strings are intentional and independent of the
        // production observation parser; do not canonicalize them to numbers.
        return f.parse(self.c.a, try f.json(self.c.a, .{
            .id = if (os) f.os_id else f.data_id,
            .name = if (os) f.prefix ++ "-os" else f.prefix ++ "-data",
            .type = "Microsoft.Compute/disks",
            .tags = f.tags,
            .uniqueId = uuid,
            .osType = @as(?[]const u8, if (os) "Linux" else null),
            .hyperVGeneration = @as(?[]const u8, if (os) "V2" else null),
            .sku = .{ .name = "StandardSSD_LRS" },
            .logicalSectorSize = "512",
            .diskSizeBytes = if (os) (if (f.compute) "69206016" else "1048576") else "4294967296",
            .diskState = state,
            .managedBy = @as(?[]const u8, if (self.state.boots > 0) f.vm_id else null),
            .creationData = .{ .createOption = "Upload", .uploadSizeBytes = if (self.is("numeric-exponent")) "1e6" else if (os) (if (f.compute) "69206528" else "1049088") else "4294967808" },
        }));
    }
    fn vm(self: Fake) !std.json.Value {
        return f.parse(self.c.a, try f.json(self.c.a, .{
            .id = f.vm_id,
            .name = f.prefix ++ "-vm",
            .type = "Microsoft.Compute/virtualMachines",
            .tags = f.tags,
            .vmId = if (self.is("diagnostics-vm-identity-drift") and self.state.cleanup) "replacement" else "original-vm",
            .securityProfile = .{ .securityType = "Standard" },
            .hardwareProfile = .{ .vmSize = if (self.is("diagnostics-unknown-vm")) "unapproved-size" else "Standard_D2s_v5" },
            .diagnosticsProfile = .{ .bootDiagnostics = .{ .enabled = true } },
            .networkProfile = .{ .networkInterfaces = .{.{ .id = f.nic_id }} },
            .storageProfile = .{
                .diskControllerType = "SCSI",
                .osDisk = .{ .createOption = "Attach", .caching = "ReadOnly", .deleteOption = "Detach", .managedDisk = .{ .id = f.os_id } },
                .dataDisks = if (f.compute) .{} else .{.{
                    .lun = "7",
                    .createOption = "Attach",
                    .caching = "None",
                    .deleteOption = "Detach",
                    .managedDisk = .{ .id = if (self.is("attachment-mismatch")) f.group_id ++ "/providers/Microsoft.Compute/disks/replacement" else f.data_id },
                }},
            },
        }));
    }
    fn bootLog(self: *Fake) !void {
        const c = self.c;
        const boot = self.state.boots;
        try f.expect(boot == 1 or boot == 2);
        const original = try c.read(if (boot == 1) "boot1.log" else "boot2.log");
        if (self.state.cleanup) {
            try c.log("failure diagnostics");
            try c.timestamp("diagnostics.seconds");
            if (one(self.scenario, &.{ "diagnostics-read-failure", "diagnostics-read-delete-failure" })) {
                var err = std.Io.File.stderr().writerStreaming(c.io, &.{});
                try err.interface.writeAll("fixture diagnostic read failure\n");
                std.process.exit(23);
            }
            if (self.is("diagnostics-decode-failure")) return self.emit(.{ .unexpected = "not a JSON string" });
            if (self.is("diagnostics-timeout")) try std.Io.sleep(c.io, .fromSeconds(35), .awake);
            return self.serial(original);
        }
        if (boot == 2) {
            self.state.boot2_reads += 1;
            try f.expect(self.state.boot2_reads <= 60);
            try self.save();
            const reads = self.state.boot2_reads;
            const first = try c.read("boot1.log");
            if (self.is("boot1-mutated-after-start")) try self.tamper("attempt/boot1.log", "benign-looking appended line\n");
            if (self.is("stale-boot1-log") or (self.is("azure-cached-then-fresh") and reads == 1)) return self.serial(first);
            if (self.is("azure-no-advance-then-fresh") and reads <= 3) {
                if (reads == 3) return self.serial(first);
                const body = try c.read("boot1-body.log");
                return self.serial(if (reads == 1) body else try std.mem.concat(c.a, u8, &.{ body, "\x00" }));
            }
            if (self.is("azure-padding-only")) return self.serial(try std.mem.concat(c.a, u8, &.{ try c.read("boot1-body.log"), "\x00" }));
            if (one(self.scenario, &.{ "azure-prefix-changed", "cumulative-prefix-drift" })) {
                // sed's original 1s changes only the first platform occurrence.
                const platform = "UK_HYPERV_PLATFORM_READY";
                try f.expect(starts(original, platform));
                return self.serial(try std.mem.concat(c.a, u8, &.{ "UK_HYPERV_PLATFORM_DRIFT", original[platform.len..] }));
            }
            if (self.is("azure-prefix-truncated")) {
                const body = try c.read("boot1-body.log");
                return self.serial(body[0 .. body.len - 1]);
            }
            if (self.is("azure-interior-nul-removed")) return self.serial(try self.replace(original, "\x00", ""));
            if (self.is("azure-missing-prefix")) return self.serial(try c.read("boot2-body.log"));
            if (self.is("azure-wrong-boot")) return self.serial(try std.mem.concat(c.a, u8, &.{ try c.read("boot1-body.log"), first }));
            if (one(self.scenario, &.{ "different-boot1-log", "cumulative-different-boot1" }))
                return self.serial(try self.replace(first, "SELECT PASS id=1", "SELECT PASS id=2"));
            if (one(self.scenario, &.{ "cached-then-fresh", "cumulative-cached-then-fresh" }) or starts(self.scenario, "cache-")) {
                if (reads == 1) return self.serial(first);
                if (self.is("cache-boot1-mutated")) try self.tamper("attempt/boot1.log", "changed during cache wait\n");
                if (self.is("cache-capture-mutated")) try self.tamper("attempt/boot1-capture.json", " \n");
                if (self.is("cache-scope-mutated")) try self.tamper("attempt/scope.json", " \n");
                if (self.is("cache-admission-mutated")) try self.tamper("attempt/boot2-admission.json", " \n");
                if (self.is("cache-then-wrong-identity")) return self.serial(try self.replace(original, "4" ** 32, "5" ** 32));
                if (self.is("cache-then-failure")) return self.serial("UK_HYPERV_ACCEPTANCE_FAIL:fixture\n");
                if (starts(self.scenario, "cache-")) return self.serial(first);
            }
        }
        if (boot == 1 and one(self.scenario, &.{ "azure-all-zero-boot1", "azure-incomplete-boot1" })) {
            self.state.serial_reads += 1;
            try self.save();
            return self.serial(if (self.state.serial_reads != 1) "UK_HYPERV_ACCEPTANCE_FAIL:fixture\n" else if (self.is("azure-all-zero-boot1")) "\x00\x00" else "UK_HYPERV_PLATFORM_READY\n\x00\x00");
        }
        if (self.is("incomplete-serial") and self.state.serial_reads == 0) {
            self.state.serial_reads = 1;
            try self.save();
            return self.serial("");
        }
        if (one(self.scenario, &.{ "serial-failure", "stopped-bad-serial" })) return self.serial("UK_HYPERV_ACCEPTANCE_FAIL:fixture\n");
        if (self.is("boot2-writes") and boot == 2) return self.serial(try self.replace(original, ":0:0:receipt-verified", ":1:0:receipt-verified"));
        return self.serial(original);
    }
    fn cloud(self: *Fake, args: []const []const u8) !void {
        const options = try Options.parse(self.c, args);
        const cmd = options.command;
        const role: []const u8 = if (eq(options.name, f.prefix ++ "-os")) "os" else "data";
        try self.c.log(try std.fmt.allocPrint(self.c.a, "{s} {s} {s}", .{ args[0], args[1], options.name }));
        if (eq(cmd, "group exists")) return self.emit(self.is("preexisting-group") or self.state.exists);
        if (eq(cmd, "group create")) {
            try f.expect(!self.state.exists and self.state.boots == 0);
            self.state.exists = true;
            try self.save();
            return self.emit(.{ .id = f.group_id, .tags = f.tags });
        }
        if (eq(cmd, "group show")) {
            try self.c.timestamp("cleanup.seconds");
            self.state.cleanup = true;
            try self.save();
            if (!self.state.exists) std.process.exit(3);
            if (one(self.scenario, &.{ "cleanup-unowned", "diagnostics-unowned-group" })) return self.emit(.{ .id = f.group_id, .tags = .{} });
            return self.emit(.{ .id = f.group_id, .tags = f.tags });
        }
        if (eq(cmd, "group delete")) {
            try self.c.timestamp("delete.seconds");
            if (one(self.scenario, &.{ "delete-failure", "diagnostics-delete-failure", "diagnostics-read-delete-failure" })) std.process.exit(17);
            self.state.exists = false;
            return self.save();
        }
        if (eq(cmd, "disk create")) {
            const saved_disk = if (eq(role, "os")) &self.state.os else &self.state.data;
            try f.expect(!saved_disk.created and self.state.exists);
            saved_disk.* = .{ .created = true };
            try self.save();
            return self.output("{}\n");
        }
        if (eq(cmd, "disk show")) return self.emit(try self.disk(role));
        if (eq(cmd, "disk grant-access")) {
            if (self.is("ambiguous-grant")) std.process.exit(18);
            if (self.is("duplicate-grant")) return self.output("{\"accessSAS\":\"first\",\"accessSAS\":\"second\"}\n");
            if (self.is("both-grants")) return self.output("{\"accessSAS\":\"secret\",\"accessSas\":\"secret\"}\n");
            if (self.is("unknown-grant")) return self.output("{\"accessSAS\":\"secret\",\"unexpected\":true}\n");
            const url = if (self.is("storage-azure-grant"))
                "https://md-fixture.z99.blob.storage.azure.net/upload?sv=fixture&sig=" ++ f.sentinel
            else
                "https://fixture.blob.core.windows.net/upload?sv=fixture&sig=" ++ f.sentinel;
            if (self.is("lowercase-grant")) return self.emit(.{ .accessSas = url });
            return self.emit(.{ .accessSAS = url });
        }
        if (eq(cmd, "disk revoke-access")) {
            if (self.is("revoke-failure")) {
                var err = std.Io.File.stderr().writerStreaming(self.c.io, &.{});
                try err.interface.writeAll("InvalidVhd\n");
                std.process.exit(19);
            }
            const saved_disk = if (eq(role, "os")) &self.state.os else &self.state.data;
            saved_disk.uploaded = true;
            return self.save();
        }
        if (eq(cmd, "deployment group")) {
            try f.expect(self.state.boots == 0 and self.state.os.uploaded and (f.compute or self.state.data.uploaded));
            self.state.boots = 1;
            self.state.power = "running";
            try self.save();
            if (one(self.scenario, &.{ "process-signal-term", "process-output-overflow" })) {
                try self.c.write("process.pid", try std.fmt.allocPrint(self.c.a, "{d}\n", .{std.os.linux.getpid()}));
                if (self.is("process-signal-term")) {
                    try std.Io.sleep(self.c.io, .fromSeconds(35), .awake);
                } else {
                    return seams.Overflow.emit(self.c);
                }
                return error.ProcessFaultDidNotTerminate;
            }
            if (self.is("ambiguous-deploy")) std.process.exit(20);
            return self.output("{}\n");
        }
        if (eq(cmd, "vm show")) return self.emit(try self.vm());
        if (eq(cmd, "vm get-instance-view")) {
            var power = self.state.power;
            const boot = self.state.boots;
            if (eq(power, "running")) {
                if ((boot == 1 and one(self.scenario, &.{ "stopped-boot1", "stopped-bad-serial" })) or
                    (boot == 2 and self.is("stopped-boot2")) or self.is("stopped-both")) power = "stopped";
                if (boot == 1 and (self.is("unexpected-boot1-power") or starts(self.scenario, "diagnostics-"))) power = "starting";
                if (boot == 2 and self.is("unexpected-boot2-power")) power = "deallocating";
            } else if (eq(power, "deallocated") and ((boot == 1 and self.is("retained-stopped")) or (boot == 2 and self.is("final-stopped")))) power = "stopped";
            const code: ?[]const u8 = if (self.is("malformed-power")) null else try std.mem.concat(self.c.a, u8, &.{ "PowerState/", power });
            return self.emit(.{ .instanceView = .{ .statuses = .{ .{ .code = "ProvisioningState/succeeded" }, .{ .code = code } } } });
        }
        if (eq(cmd, "vm deallocate")) {
            self.state.power = "deallocated";
            try self.save();
            if (self.is("boot1-mutated-before-start") and self.state.boots == 1) try self.tamper("attempt/boot1.log", "benign-looking appended line\n");
            if (self.is("ambiguous-deallocate")) std.process.exit(21);
            return;
        }
        if (eq(cmd, "vm start")) {
            try f.expect(self.state.boots == 1);
            const admission = try self.c.document("attempt/boot2-admission.json");
            try f.expect(try f.num(admission, "reserved_boots") == 2 and eq(try f.str(admission, "vm_id"), f.vm_id) and (try f.str(admission, "original_boot1_sha256")).len == 64);
            try self.c.timestamp("boot2-start.seconds");
            self.state.boots = 2;
            self.state.power = "running";
            self.state.boot2_reads = 0;
            try self.save();
            if (self.is("boot2-admission-mutated")) try self.tamper("attempt/boot2-admission.json", " \n");
            if (self.is("ambiguous-start")) std.process.exit(22);
            return;
        }
        if (eq(cmd, "vm boot-diagnostics")) return self.bootLog();
        if (eq(cmd, "resource list")) {
            var values: std.ArrayList(std.json.Value) = .empty;
            if (self.state.os.created) try values.append(self.c.a, try self.disk("os"));
            if (self.state.data.created) try values.append(self.c.a, try self.disk("data"));
            if (self.state.boots > 0) try values.append(self.c.a, try self.vm());
            if (one(self.scenario, &.{ "foreign-resource", "diagnostics-foreign-resource" }))
                try values.append(self.c.a, try f.parse(self.c.a, "{\"id\":\"foreign\",\"name\":\"foreign\",\"type\":\"Microsoft.Compute/disks\",\"tags\":{}}"));
            return self.emit(values.items);
        }
        return error.UnknownCommand;
    }
};

const Options = struct {
    command: []const u8,
    name: []const u8 = "",
    fn parse(c: f.Context, args: []const []const u8) !Options {
        try f.expect(args.len >= 2);
        const command = try std.mem.concat(c.a, u8, &.{ args[0], " ", args[1] });
        try f.expect(one(command, &.{
            "group exists",      "group create",        "group show",       "group delete", "disk create",          "disk show",
            "disk grant-access", "disk revoke-access",  "deployment group", "vm show",      "vm get-instance-view", "vm deallocate",
            "vm start",          "vm boot-diagnostics", "resource list",
        }));
        var result: Options = .{ .command = command };
        var flags: std.StringHashMap([]const u8) = .init(c.a);
        var i: usize = 2;
        if (eq(command, "deployment group")) {
            try f.expect(i < args.len and eq(args[i], "create"));
            i += 1;
        }
        if (eq(command, "vm boot-diagnostics")) {
            try f.expect(i < args.len and eq(args[i], "get-boot-log"));
            i += 1;
        }
        while (i < args.len) {
            const flag = args[i];
            i += 1;
            try f.expect(!flags.contains(flag));
            if (one(flag, &.{ "--yes", "--only-show-errors" })) {
                try flags.put(flag, "");
                continue;
            }
            if (eq(flag, "--tags")) {
                var found: u4 = 0;
                while (i < args.len and !starts(args[i], "--")) : (i += 1) {
                    const tags = [_][]const u8{
                        "managed-by=unikraft-hyperv", "uk-direct-run=" ++ f.owner,
                        "unikraft-run=" ++ f.prefix,  "image-sha256=" ++ f.image_sha,
                    };
                    var matched = false;
                    for (tags, 0..) |tag, index| if (eq(args[i], tag)) {
                        const bit = @as(u4, 1) << @as(u2, @intCast(index));
                        try f.expect(found & bit == 0);
                        found |= bit;
                        matched = true;
                    };
                    try f.expect(matched);
                }
                try f.expect(found == 15);
                try flags.put(flag, "");
                continue;
            }
            try f.expect(one(flag, &.{
                "--name",              "--resource-group", "--subscription", "--output",             "--location",     "--upload-type",
                "--upload-size-bytes", "--sku",            "--os-type",      "--hyper-v-generation", "--access-level", "--duration-in-seconds",
                "--template-file",     "--parameters",
            }) and i < args.len);
            const value = args[i];
            i += 1;
            try flags.put(flag, value);
            if (eq(flag, "--name")) {
                result.name = value;
                try f.expect(one(value, &.{ f.prefix, f.prefix ++ "-rg", f.prefix ++ "-vm", f.prefix ++ "-os", f.prefix ++ "-data" }));
            } else if (eq(flag, "--resource-group")) {
                try f.expect(eq(value, f.prefix ++ "-rg"));
            } else if (eq(flag, "--subscription")) {
                try f.expect(eq(value, f.subscription));
            } else if (eq(flag, "--output")) {
                try f.expect(eq(value, "json"));
            } else if (eq(flag, "--parameters")) {
                try f.expect(eq(value, try std.mem.concat(c.a, u8, &.{ "@", try c.path("attempt/deployment-parameters.json") })));
                const document = try c.document("attempt/deployment-parameters.json");
                const parameters = try f.field(document, "parameters");
                try f.expect(document.object.count() == 1 and parameters.object.count() == @as(usize, if (f.compute) 6 else 7));
                inline for (.{ .{ "ownerRun", f.owner }, .{ "osDiskId", f.os_id }, .{ "dataDiskId", f.data_id }, .{ "namePrefix", f.prefix }, .{ "imageSha256", f.image_sha }, .{ "location", f.location }, .{ "vmSize", "Standard_D2s_v5" } }) |parameter| {
                    if (f.compute and comptime eq(parameter[0], "dataDiskId")) continue;
                    const item = try f.field(parameters, parameter[0]);
                    try f.expect(item.object.count() == 1 and eq(try f.str(item, "value"), parameter[1]));
                }
            } else if (eq(flag, "--template-file")) {
                try f.deploymentTemplate(c, value);
            } else {
                const expected: []const u8 = if (eq(flag, "--location")) f.location else if (eq(flag, "--upload-type")) "Upload" else if (eq(flag, "--sku")) "StandardSSD_LRS" else if (eq(flag, "--os-type")) "Linux" else if (eq(flag, "--hyper-v-generation")) "V2" else if (eq(flag, "--access-level")) "Write" else if (eq(flag, "--duration-in-seconds")) "1800" else "";
                if (eq(flag, "--upload-size-bytes")) {
                    try f.expect(one(value, &.{ if (f.compute) "69206528" else "1049088", "4294967808" }));
                } else try f.expect(eq(value, expected));
            }
        }
        try f.expect(flags.contains("--subscription") and flags.contains("--output") and flags.contains("--only-show-errors"));
        if (eq(args[0], "group")) try f.expect(eq(result.name, f.prefix ++ "-rg"));
        if (eq(args[0], "disk")) try f.expect(one(result.name, &.{ f.prefix ++ "-os", f.prefix ++ "-data" }));
        if (eq(args[0], "vm")) try f.expect(eq(result.name, f.prefix ++ "-vm"));
        if (eq(command, "disk create")) {
            const size = flags.get("--upload-size-bytes") orelse return error.MissingUploadSize;
            try f.expect(eq(size, if (eq(result.name, f.prefix ++ "-os")) (if (f.compute) "69206528" else "1049088") else "4294967808"));
        }
        const required: []const []const u8 = if (eq(command, "group create"))
            &.{ "--name", "--location", "--tags" }
        else if (eq(command, "group delete"))
            &.{ "--name", "--yes" }
        else if (eq(args[0], "group"))
            &.{"--name"}
        else if (eq(command, "disk create"))
            (if (eq(result.name, f.prefix ++ "-os"))
                &.{ "--resource-group", "--name", "--location", "--upload-type", "--upload-size-bytes", "--sku", "--os-type", "--hyper-v-generation", "--tags" }
            else
                &.{ "--resource-group", "--name", "--location", "--upload-type", "--upload-size-bytes", "--sku", "--tags" })
        else if (eq(command, "disk grant-access"))
            &.{ "--resource-group", "--name", "--access-level", "--duration-in-seconds" }
        else if (eq(command, "deployment group"))
            &.{ "--resource-group", "--name", "--template-file", "--parameters" }
        else if (eq(command, "resource list"))
            &.{"--resource-group"}
        else
            &.{ "--resource-group", "--name" };
        try f.expect(flags.count() == required.len + 3);
        for (required) |flag| try f.expect(flags.contains(flag));
        return result;
    }
};

fn executable(io: std.Io, path: []const u8) !void {
    const file = try f.files.openAbsolute(io, path, .artifact);
    defer file.close(io);
    const stat = try f.files.snapshot(file);
    try f.expect(stat.mode & 0o111 != 0 and stat.nlink == 1);
    var bytes: [4]u8 = undefined;
    try f.expect(try file.readPositionalAll(io, &bytes, 0) == 4 and eq(&bytes, "\x7fELF"));
}

pub fn main(init: std.process.Init) void {
    f.privateUmask();
    run(init) catch |err| {
        var out = std.Io.File.stderr().writerStreaming(init.io, &.{});
        out.interface.print("offline fixture refused: {s}\n", .{@errorName(err)}) catch {};
        std.process.exit(90);
    };
}
fn run(init: std.process.Init) !void {
    const a = init.arena.allocator();
    const argv = try init.minimal.args.toSlice(a);
    const c: f.Context = .{ .a = a, .io = init.io, .root = init.environ_map.get("UK_DIRECT_FIXTURE_ROOT") orelse return error.NoFixtureRoot };
    try c.validate();
    const scenario = std.mem.trimEnd(u8, try c.read("scenario"), "\n");
    var known = false;
    for (inventory.all_cases) |case| if (eq(case.name, scenario)) {
        known = true;
    };
    try f.expect(known);
    var fake: Fake = .{ .c = c, .scenario = scenario, .state = (try std.json.parseFromSlice(State, a, try c.read("fake-cloud.json"), .{})).value };
    const args = argv[1..];
    for (argv) |arg| try f.expect(std.mem.indexOf(u8, arg, f.sentinel) == null);
    try f.expect(args.len > 0);
    if (eq(args[0], "version")) {
        try f.expect(args.len == 4 and eq(args[1], "--output") and eq(args[2], "json") and eq(args[3], "--only-show-errors"));
        for ([_][]const u8{ "PYTHONPATH", "PYTHONHOME", "LD_PRELOAD", "LD_LIBRARY_PATH", "PATH" }) |key|
            try f.expect(init.environ_map.get(key) == null);
        // This confined fixture control is not recognized by production.
        const control = c.read("cli-version-control") catch |err| switch (err) {
            error.FileNotFound => "success",
            else => return err,
        };
        const dir = try f.files.Directory.open(init.io, try c.path("ledger"));
        defer dir.close(init.io);
        var it = dir.dir.iterate();
        try f.expect(try it.next(init.io) == null);
        try c.write("cli-version-called", "before-consumption\n");
        if (eq(control, "fail")) std.process.exit(29);
        if (eq(control, "malformed")) return fake.output("{\"azure-cli\":\"2.0.0\"}\n");
        if (eq(control, "overflow")) return fake.output(try a.dupe(u8, &([_]u8{'x'} ** 8192)));
        if (eq(control, "timeout") or eq(control, "expire"))
            try std.Io.sleep(init.io, .fromSeconds(if (eq(control, "timeout")) 20 else 6), .awake);
        if (eq(control, "stderr")) {
            var stderr = std.Io.File.stderr().writerStreaming(init.io, &.{});
            try stderr.interface.writeAll("private synthetic startup diagnostic\n");
        } else try f.expect(one(control, &.{ "success", "timeout", "expire" }));
        if (init.environ_map.get("AZ_PYTHON")) |python| try f.expect(eq(python, argv[0]));
        return fake.output("{\"azure-cli\":\"2.80.0\",\"azure-cli-core\":\"2.80.0\",\"azure-cli-telemetry\":\"1.1.0\",\"extensions\":{}}\n");
    }
    if (eq(args[0], "__overflow-payload")) {
        try f.expect(args.len == 1 and fake.is("process-output-overflow"));
        return seams.Overflow.emit(c);
    }
    if (one(args[0], &.{ "scope", "candidate", "legacy-scope", "ledger", "legacy-ledger", "json", "serial", "inputs" })) {
        try f.expect(args.len >= 2);
        for (args[1..]) |path| try c.confined(path);
        if (eq(args[0], "inputs")) {
            try f.expect(args.len == 2);
            const scope = try c.document(args[1][c.root.len + 1 ..]);
            inline for (f.input_names) |item|
                try f.expect(eq(try f.str(try f.field(scope, item[0]), "path"), try c.path(item[1])));
            try f.expect(eq(try f.str(scope, "attempt_id"), f.owner) and eq(try f.str(scope, "subscription"), f.subscription));
            if (fake.is("bad-input")) std.process.exit(1);
            return;
        }
        const native = init.environ_map.get("UK_DIRECT_FIXTURE_VALIDATOR") orelse return error.NoNativeValidator;
        try f.expect(eq(std.fs.path.basename(native), f.validator_name));
        try executable(init.io, native);
        if (eq(args[0], "serial")) try c.log("validator serial");
        var environment = std.process.Environ.Map.init(a);
        const delegated = try std.mem.concat(a, []const u8, &.{ &.{native}, args });
        return std.process.replace(init.io, .{ .argv = delegated, .environ_map = &environment });
    }
    if (eq(args[0], "transfer")) {
        try f.expect(args.len == 3 and eq(args[2], "job.json"));
        try f.expect(eq(args[1], try c.path("attempt/upload-os")) or eq(args[1], try c.path("attempt/upload-data")));
        const upload: f.Context = .{ .a = a, .io = init.io, .root = args[1] };
        const dir = try f.files.Directory.open(init.io, upload.root);
        defer dir.close(init.io);
        try f.expect(eq(try upload.read("sas.txt"), "sv=fixture&sig=" ++ f.sentinel));
        const request = try upload.document("request.json");
        const os = std.mem.endsWith(u8, upload.root, "-os");
        try f.expect(request.object.count() == 6);
        try f.expect(eq(try f.str(request, "schema"), "unikraft.hyperv.managed-disk-page-worker") and try f.num(request, "schema_version") == 1);
        try f.expect(eq(try f.str(request, "path"), try c.path(if (os) "os.vhd" else "seed.vhd")));
        try f.expect(try f.num(request, "size") == @as(i64, if (os) f.os_size else 4294967808) and eq(try f.str(request, "sha256"), f.image_sha));
        try f.expect(eq(try f.str(request, "endpoint"), if (fake.is("storage-azure-grant")) "https://md-fixture.z99.blob.storage.azure.net/upload" else "https://fixture.blob.core.windows.net/upload"));
        const job = try upload.document("job.json");
        try f.expect(job.object.count() == 7 and eq(try f.str(job, "contract"), "uk.hyperv.transfer-job") and try f.num(job, "schema_version") == 1);
        try f.expect(eq(try f.str(job, "kind"), "pages") and eq(try f.str(job, "request"), "request.json") and eq(try f.str(job, "sas"), "sas.txt"));
        try f.expect(try f.num(job, "cleanup_ms") == 5000 and try f.num(job, "timeout_ms") >= 1000 and try f.num(job, "timeout_ms") <= 33000);
        try c.log("transfer");
        if (fake.is("upload-failure")) std.process.exit(12);
        return fake.emit(.{ .succeeded = true });
    }
    try f.expect(eq(init.environ_map.get("AZURE_CORE_COLLECT_TELEMETRY") orelse "", "0"));
    return fake.cloud(args);
}
