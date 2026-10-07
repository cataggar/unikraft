// SPDX-License-Identifier: BSD-3-Clause
const std = @import("std");
const controller = @import("wamr_controller");
const handoff = @import("wamr_handoff");

pub fn main(init: std.process.Init) void {
    _ = std.os.linux.syscall1(.umask, 0o077);
    const allocator = init.arena.allocator();
    const args = init.minimal.args.toSlice(allocator) catch refused(init.io);
    const command = controller.cli.parse(args) catch usage(init.io);
    if (controller.cli.isPublic(command.action)) {
        publicCommand(init, command);
        return;
    }
    if (command.action == .@"--identity") {
        const closure = controller.import_supervisor_identity.nativeSourceContentClosure(allocator) catch refused(init.io);
        const encoded = controller.import_supervisor_identity.identityBytes(allocator, &closure) catch refused(init.io);
        std.Io.File.stdout().writeStreamingAll(init.io, encoded) catch refused(init.io);
        return;
    }
    if (command.action == .describe) {
        const closure = std.fmt.bytesToHex(controller.source_custody.contentClosure(), .lower);
        const raw = std.json.Stringify.valueAlloc(allocator, .{
            .schema = "uk.wamr.native-ci-describe",
            .schema_version = 1,
            .recorded_executable_target = controller.profile.executable_target,
            .source_closure_sha256 = closure[0..],
        }, .{}) catch refused(init.io);
        const encoded = controller.records.canonicalAlloc(allocator, raw) catch refused(init.io);
        var stdout = std.Io.File.stdout().writerStreaming(init.io, &.{});
        stdout.interface.writeAll(encoded) catch refused(init.io);
        return;
    }
    if (command.action == .@"supervisor-source-closure" or command.action == .@"reader-source-closure") {
        const repository = std.process.currentPathAlloc(init.io, allocator) catch refused(init.io);
        const closure = (if (command.action == .@"reader-source-closure")
            controller.import_supervisor_identity.currentReaderSourceContentClosure(
                allocator,
                init.io,
                repository,
                command.git.?,
            )
        else
            controller.import_supervisor_identity.supervisorSourceContentClosure(
                allocator,
                init.io,
                repository,
                command.git.?,
            )) catch |err| failed(init.io, @tagName(command.action), "", err);
        var stdout = std.Io.File.stdout().writerStreaming(init.io, &.{});
        stdout.interface.print("{s}\n", .{closure[0..]}) catch refused(init.io);
        return;
    }
    if (command.action == .records or command.action == .@"readonly-records") {
        const repository = std.process.currentPathAlloc(init.io, allocator) catch refused(init.io);
        const root = command.runtime orelse command.stage_root.?;
        const directory = controller.layout.runtime(init.io, root) catch refused(init.io);
        defer directory.close(init.io);
        var accepted = if (command.action == .@"readonly-records" and command.git != null)
            controller.accepted_run.openAndValidateReadOnlyWithGit(
                allocator,
                init.io,
                init.minimal.environ,
                &directory,
                root,
                repository,
                command.git.?,
                null,
            ) catch |err| failed(init.io, "readonly-records", "", err)
        else if (command.action == .@"readonly-records")
            controller.accepted_run.openAndValidateReadOnlyWithSignal(
                allocator,
                init.io,
                init.minimal.environ,
                &directory,
                root,
                repository,
                null,
            ) catch |err| failed(init.io, "readonly-records", "", err)
        else if (command.runtime != null)
            controller.accepted_run.openAndValidate(
                allocator,
                init.io,
                init.minimal.environ,
                &directory,
                root,
                repository,
            ) catch |err| failed(init.io, "records", "", err)
        else
            controller.accepted_run.openImportedStage(
                allocator,
                init.io,
                &directory,
                root,
            ) catch |err| failed(init.io, "records", "", err);
        defer accepted.deinit();
        accepted.revalidate() catch |err| failed(init.io, "records", "", err);
        const encoded = accepted.handoffV1() catch |err| failed(init.io, "records", "", err);
        var stdout = std.Io.File.stdout().writerStreaming(init.io, &.{});
        stdout.interface.writeAll(encoded) catch refused(init.io);
        return;
    }
    if (command.action == .@"local-consumer-custody") {
        const repository = std.process.currentPathAlloc(init.io, allocator) catch refused(init.io);
        var signal = controller.build_pipeline.installCancellation() catch refused(init.io);
        defer signal.deinit();
        controller.local_consumer_custody.run(
            allocator,
            init.io,
            repository,
            command.runtime.?,
            command.expected_build_start_sha256.?,
            command.expected_boot_inputs_sha256.?,
            &signal,
        ) catch |err| failed(init.io, @tagName(command.action), "", err);
        return;
    }
    if (command.action == .@"private-export") {
        const repository = std.process.currentPathAlloc(init.io, allocator) catch refused(init.io);
        var signal = controller.build_pipeline.installCancellation() catch refused(init.io);
        defer signal.deinit();
        switch (handoff.export_state.run(.{
            .allocator = allocator,
            .io = init.io,
            .environ = init.minimal.environ,
            .runtime_path = command.runtime.?,
            .repository_path = repository,
            .output_path = command.output.?,
            .signal = &signal,
        })) {
            .success => {},
            .refused, .poisoned => |diagnostic| {
                var stderr = std.Io.File.stderr().writerStreaming(init.io, &.{});
                stderr.interface.print(
                    "WAMR_CI_FAILED_STAGE: private-export/{s}; cause: {s}; publication: {s}; private partial state retained; no resume.\n",
                    .{ @tagName(diagnostic.phase), @errorName(diagnostic.err), @tagName(diagnostic.publication) },
                ) catch {};
                std.process.exit(1);
            },
        }
        std.Io.File.stdout().writeStreamingAll(init.io, "Private handoff exported; authority=not_admitted.\n") catch refused(init.io);
        return;
    }
    if (command.action == .@"private-validate") {
        const stage = @tagName(command.action);
        const repository = std.process.currentPathAlloc(init.io, allocator) catch refused(init.io);
        const root = command.stage_root.?;
        const directory = controller.layout.runtime(init.io, root) catch refused(init.io);
        defer directory.close(init.io);
        var signal = controller.build_pipeline.installCancellation() catch refused(init.io);
        defer signal.deinit();
        var bundle = controller.accepted_run.PrivateBundle.open(
            allocator,
            init.io,
            &directory,
            root,
            repository,
            .{ .git = command.git.?, .supervisor = command.supervisor.?, .validator = command.validator.? },
            &signal,
        ) catch |err| failed(init.io, stage, "", err);
        defer bundle.deinit();
        controller.import_validator_build.runPrivate(allocator, init.io, &bundle, command.output.?, &signal) catch |err| failed(init.io, stage, "", err);
        std.Io.File.stdout().writeStreamingAll(init.io, "Compute handoff revalidated; authority=not_admitted.\n") catch refused(init.io);
        return;
    }
    if (command.action == .@"supervisor-import-identity") {
        const stage = @tagName(command.action);
        const repository = std.process.currentPathAlloc(init.io, allocator) catch refused(init.io);
        const root = command.stage_root.?;
        const directory = controller.layout.runtime(init.io, root) catch refused(init.io);
        defer directory.close(init.io);
        var signal = controller.build_pipeline.installCancellation() catch refused(init.io);
        defer signal.deinit();
        var accepted = controller.accepted_run.openImportedStage(
            allocator,
            init.io,
            &directory,
            root,
        ) catch |err| failed(init.io, stage, "", err);
        defer accepted.deinit();
        controller.import_supervisor_identity.run(
            allocator,
            init.io,
            &accepted,
            repository,
            command.git.?,
            command.supervisor.?,
            command.output.?,
            &signal,
        ) catch |err| failed(init.io, stage, "", err);
        return;
    }
    if (command.action == .@"import-validator-build" or command.action == .@"import-native-revalidation" or command.action == .@"import-handoff-revalidation") {
        const stage = @tagName(command.action);
        const repository = std.process.currentPathAlloc(init.io, allocator) catch refused(init.io);
        const root = command.stage_root.?;
        const directory = controller.layout.runtime(init.io, root) catch refused(init.io);
        defer directory.close(init.io);
        var signal = controller.build_pipeline.installCancellation() catch refused(init.io);
        defer signal.deinit();
        var accepted = controller.accepted_run.openImportedStage(
            allocator,
            init.io,
            &directory,
            root,
        ) catch |err| failed(init.io, stage, "", err);
        defer accepted.deinit();
        if (command.action == .@"import-handoff-revalidation") {
            controller.import_validator_build.runPortable(
                allocator,
                init.io,
                &accepted,
                repository,
                command.output.?,
                .{ .git = command.git.?, .supervisor = command.supervisor.?, .validator = command.validator.? },
                &signal,
            ) catch |err| failed(init.io, stage, "", err);
            return;
        }
        controller.import_validator_build.run(
            allocator,
            init.io,
            &accepted,
            repository,
            command.output.?,
            command.action == .@"import-native-revalidation",
            &signal,
        ) catch |err| failed(init.io, stage, "", err);
        return;
    }
    if (command.action == .@"handoff-inspect" or command.action == .@"handoff-inspect-legacy" or command.action == .@"public-validator-build" or command.action == .@"local-handoff-revalidation") {
        const stage = @tagName(command.action);
        const repository = std.process.currentPathAlloc(init.io, allocator) catch refused(init.io);
        const root = command.runtime.?;
        const runtime = controller.layout.runtime(init.io, root) catch refused(init.io);
        defer runtime.close(init.io);
        var signal = controller.build_pipeline.installCancellation() catch refused(init.io);
        defer signal.deinit();
        var accepted = if (command.action == .@"handoff-inspect" or command.action == .@"handoff-inspect-legacy")
            controller.accepted_run.openAndValidateReadOnlyWithSignal(
                allocator,
                init.io,
                init.minimal.environ,
                &runtime,
                root,
                repository,
                &signal,
            ) catch |err| failed(init.io, stage, "", err)
        else
            controller.accepted_run.openAndValidateWithSignal(
                allocator,
                init.io,
                init.minimal.environ,
                &runtime,
                root,
                repository,
                &signal,
            ) catch |err| failed(init.io, stage, "", err);
        defer accepted.deinit();
        const result = switch (command.action) {
            .@"handoff-inspect" => controller.handoff_inspect.run(
                allocator,
                init.io,
                &accepted,
                command.output.?,
                false,
                &signal,
            ),
            .@"handoff-inspect-legacy" => controller.handoff_inspect.run(
                allocator,
                init.io,
                &accepted,
                command.output.?,
                true,
                &signal,
            ),
            .@"public-validator-build" => controller.public_validator_build.run(
                allocator,
                init.io,
                &accepted,
                command.output.?,
                &signal,
            ),
            .@"local-handoff-revalidation" => controller.public_validator_build.revalidateHandoff(
                allocator,
                init.io,
                &accepted,
                command.output.?,
                &signal,
            ),
            else => unreachable,
        };
        _ = result catch |err| failed(init.io, stage, "", err);
        return;
    }
    const runtime = controller.layout.runtime(init.io, command.runtime.?) catch refused(init.io);
    defer runtime.close(init.io);
    const repository = std.process.currentPathAlloc(init.io, allocator) catch refused(init.io);
    const compute = std.fs.path.join(allocator, &.{ command.runtime.?, "compute" }) catch refused(init.io);
    var signal = controller.build_pipeline.installCancellation() catch refused(init.io);
    defer signal.deinit();
    var context: controller.build_pipeline.Context = .{
        .allocator = allocator,
        .io = init.io,
        .environ = init.minimal.environ,
        .runtime = command.runtime.?,
        .repository = repository,
        .wamr = command.wamr_source orelse "",
        .compute = compute,
        .git = undefined,
        .tools = undefined,
        .roots = undefined,
        .signal = &signal,
    };
    switch (command.action) {
        .build => _ = controller.build_pipeline.run(&context) catch |err| failed(init.io, context.failed_stage, context.failed_operation, err),
        .boot => {
            var boot_context: controller.boot_pipeline.Context = .{
                .build_context = &context,
                .pinned = std.StringHashMap(controller.custody_files.File).init(allocator),
            };
            _ = controller.boot_pipeline.run(&boot_context) catch |err| {
                if (err == error.KvmUnavailable) refusedWithMessage(init.io, "x86 KVM unavailable");
                failed(init.io, context.failed_stage, context.failed_operation, err);
            };
        },
        .diagnostics => {
            var boot_context: controller.boot_pipeline.Context = .{
                .build_context = &context,
                .pinned = std.StringHashMap(controller.custody_files.File).init(allocator),
            };
            controller.boot_pipeline.diagnostics(&boot_context) catch |err| failed(init.io, "diagnostics", "", err);
        },
        .describe => unreachable,
        .@"supervisor-source-closure" => unreachable,
        .@"reader-source-closure" => unreachable,
        .records => unreachable,
        .@"readonly-records" => unreachable,
        .@"local-consumer-custody" => unreachable,
        .@"handoff-inspect" => unreachable,
        .@"handoff-inspect-legacy" => unreachable,
        .@"public-validator-build" => unreachable,
        .@"local-handoff-revalidation" => unreachable,
        .@"supervisor-import-identity", .@"--identity" => unreachable,
        .@"import-validator-build" => unreachable,
        .@"import-native-revalidation" => unreachable,
        .@"import-handoff-revalidation" => unreachable,
        .@"private-export", .@"private-validate" => unreachable,
        .@"public-export", .@"public-archive", .@"verify-public-source-bundle", .@"stage-public-source-upload", .@"import-public-source-bundle", .@"import-public-source-download" => unreachable,
    }
}

fn publicCommand(init: std.process.Init, command: controller.cli.Command) void {
    const allocator = init.arena.allocator();
    const stage = @tagName(command.action);
    const repository = std.process.currentPathAlloc(init.io, allocator) catch refused(init.io);
    var signal = controller.build_pipeline.installCancellation() catch refused(init.io);
    defer signal.deinit();
    const archive = handoff.public_archive;
    const transport = handoff.public_transport;
    const product = handoff.public_products;
    const context: archive.Context = .{
        .source_revision = command.source_revision.?,
        .source_tree = command.source_tree.?,
        .run_id = command.run_id.?,
        .run_attempt = command.run_attempt.?,
    };
    if (command.action == .@"public-export" or command.action == .@"public-archive") {
        const result = product.exportArchive(.{
            .allocator = allocator,
            .io = init.io,
            .environ = init.minimal.environ,
            .repository = repository,
            .runtime = command.runtime,
            .handoff = command.stage_root.?,
            .validation_output = command.validation_output.?,
            .archive_output = command.output.?,
            .context = context,
            .signal = &signal,
            .tools = .{ .git = command.git.?, .supervisor = command.supervisor.?, .validator = command.validator.? },
        });
        const published = switch (result) {
            .success => |value| value,
            .refused, .poisoned => |diagnostic| publicFailed(init.io, stage, diagnostic),
        };
        var stdout = std.Io.File.stdout().writerStreaming(init.io, &.{});
        stdout.interface.print("Public source archive SHA-256: {s}\nPublic source tree: {s}\n", .{
            std.fmt.bytesToHex(published.sha256, .lower), context.source_tree,
        }) catch refused(init.io);
        return;
    }
    if (command.action == .@"verify-public-source-bundle" or command.action == .@"stage-public-source-upload") {
        var retained = archive.Archive.open(
            allocator,
            init.io,
            command.archive.?,
            context,
            command.inner_digest.?,
            signal.flag(),
        ) catch |err| failed(init.io, stage, "", err);
        defer retained.deinit(init.io);
        if (command.action == .@"stage-public-source-upload") {
            const result = transport.stageUpload(.{
                .allocator = allocator,
                .io = init.io,
                .source = &retained,
                .context = context,
                .inner_digest = .{ .bytes = command.inner_digest.? },
                .output_path = command.output.?,
                .cancel = signal.flag(),
            });
            var staged = switch (result) {
                .success => |value| value,
                .refused, .poisoned => |diagnostic| publicFailed(init.io, stage, diagnostic),
            };
            defer staged.deinit(init.io);
            staged.revalidate(init.io, signal.flag()) catch |err| failed(init.io, stage, "", err);
        }
        retained.revalidate(init.io, signal.flag()) catch |err| failed(init.io, stage, "", err);
        var stdout = std.Io.File.stdout().writerStreaming(init.io, &.{});
        stdout.interface.print("Public source archive SHA-256: {s}\n", .{std.fmt.bytesToHex(retained.digest, .lower)}) catch refused(init.io);
        return;
    }
    const input: product.Input = if (command.action == .@"import-public-source-bundle")
        .{ .historical_archive = .{
            .path = command.archive.?,
            .context = context,
            .digest = if (command.inner_digest) |digest| .{ .bytes = digest } else null,
        } }
    else blk: {
        const expected: transport.Expected = .{
            .upload = .{
                .context = context,
                .artifact_id = transport.ArtifactId.parse(command.artifact_id.?) catch refused(init.io),
                .container_digest = .{ .bytes = command.container_digest.? },
            },
            .inner_digest = .{ .bytes = command.inner_digest.? },
        };
        break :blk .{ .exact_download = .{
            .path = command.download_root.?,
            .container_path = command.container_archive.?,
            .expected = expected,
            .selection = .{ .upload = .{
                .context = context,
                .artifact_id = transport.ArtifactId.parse(command.selected_artifact_id.?) catch refused(init.io),
                .container_digest = .{ .bytes = command.selected_container_digest.? },
            } },
        } };
    };
    const result = product.importBundle(.{
        .allocator = allocator,
        .io = init.io,
        .repository = repository,
        .input = input,
        .output = command.output.?,
        .signal = &signal,
        .tools = .{ .git = command.git.?, .supervisor = command.supervisor.?, .validator = command.validator.? },
    });
    const imported = switch (result) {
        .success => |owner| owner,
        .refused, .poisoned => |diagnostic| publicFailed(init.io, stage, diagnostic),
    };
    defer imported.deinit();
    imported.revalidate(&signal) catch |err| failed(init.io, stage, "", err);
    std.Io.File.stdout().writeStreamingAll(init.io, "Public source handoff imported; authority=not_admitted.\n") catch refused(init.io);
}

fn publicFailed(io: std.Io, stage: []const u8, diagnostic: anytype) noreturn {
    var stderr = std.Io.File.stderr().writerStreaming(io, &.{});
    stderr.interface.print(
        "WAMR_CI_FAILED_STAGE: {s}/{s}; cause: {s}; publication: {s}; private partial state retained; no resume.\n",
        .{ stage, @tagName(diagnostic.phase), @errorName(diagnostic.err), @tagName(diagnostic.publication) },
    ) catch {};
    std.process.exit(1);
}

fn usage(io: std.Io) noreturn {
    var stderr = std.Io.File.stderr().writerStreaming(io, &.{});
    stderr.interface.writeAll(
        "usage: uk-wamr-native-ci build --runtime ABS --wamr-source ABS\n" ++
            "       uk-wamr-native-ci boot|diagnostics --runtime ABS\n" ++
            "       uk-wamr-native-ci describe --output json-v1\n" ++
            "       uk-wamr-native-ci supervisor-source-closure --git /usr/bin/git --output sha256-v1\n" ++
            "       uk-wamr-native-ci reader-source-closure --git /usr/bin/git --output sha256-v1\n" ++
            "       uk-wamr-native-ci readonly-records --runtime /private/runtime --output handoff-v1\n" ++
            "       uk-wamr-native-ci records --runtime ABS --output handoff-v1\n" ++
            "       uk-wamr-native-ci records --stage-root ABS --transport trusted-inner-zip --output handoff-v1\n" ++
            "       uk-wamr-native-ci import-handoff-revalidation --stage-root ABS --git ABS --supervisor ABS --validator ABS --output ABS\n" ++
            "       uk-wamr-native-ci private-export --runtime ABS --output ABS\n" ++
            "       uk-wamr-native-ci private-validate --stage-root ABS --git ABS --supervisor ABS --validator ABS --output ABS\n" ++
            "       uk-wamr-native-ci public-export|public-archive --stage-root ABS --validation-output ABS --output ABS --git ABS --supervisor ABS --validator ABS --expected-source COMMIT --expected-tree TREE --run-id ID --run-attempt ID [--runtime ABS for public-export]\n" ++
            "       uk-wamr-native-ci verify-public-source-bundle|stage-public-source-upload --archive ABS --expected-source COMMIT --expected-tree TREE --run-id ID --run-attempt ID --expected-archive-sha256 HEX [--output ABS for upload]\n" ++
            "       uk-wamr-native-ci import-public-source-bundle --archive ABS --output ABS --git ABS --supervisor ABS --validator ABS --expected-source COMMIT --expected-tree TREE --run-id ID --run-attempt ID [--expected-archive-sha256 HEX] (historical v1 only)\n" ++
            "       uk-wamr-native-ci import-public-source-download --download-root ABS --container-archive ABS --output ABS --git ABS --supervisor ABS --validator ABS --expected-source COMMIT --expected-tree TREE --run-id ID --run-attempt ID --expected-archive-sha256 HEX --artifact-id ID --container-digest HEX --selected-artifact-id ID --selected-container-digest HEX\n" ++
            "       uk-wamr-native-ci local-consumer-custody --runtime ABS --expected-build-start-sha256 HEX --expected-boot-inputs-sha256 HEX\n" ++
            "       uk-wamr-native-ci handoff-inspect --runtime ABS --output ABS\n" ++
            "       uk-wamr-native-ci handoff-inspect-legacy --runtime ABS --output ABS\n" ++
            "       uk-wamr-native-ci public-validator-build --runtime ABS --output ABS\n" ++
            "       uk-wamr-native-ci local-handoff-revalidation --runtime ABS --output ABS\n" ++
            "       uk-wamr-native-ci supervisor-import-identity --stage-root ABS --supervisor ABS --git ABS --output ABS\n" ++
            "       uk-wamr-native-ci import-validator-build --stage-root ABS --output ABS\n" ++
            "       uk-wamr-native-ci import-native-revalidation --stage-root ABS --output ABS\n",
    ) catch {};
    std.process.exit(2);
}

fn refused(io: std.Io) noreturn {
    refusedWithMessage(io, "controller stage unavailable");
}

fn refusedWithMessage(io: std.Io, message: []const u8) noreturn {
    var stderr = std.Io.File.stderr().writerStreaming(io, &.{});
    stderr.interface.print("WAMR_CI_REFUSED: {s}\n", .{message}) catch {};
    std.process.exit(1);
}

fn failed(io: std.Io, stage: []const u8, operation: []const u8, reason: anyerror) noreturn {
    var stderr = std.Io.File.stderr().writerStreaming(io, &.{});
    if (std.mem.eql(u8, stage, "dependency-restore")) {
        stderr.interface.print(
            "WAMR_CI_FAILED_STAGE: {s}; operation: {s}; cause: {s}; bounded private logs retained.\n",
            .{ stage, operation, @errorName(reason) },
        ) catch {};
    } else {
        stderr.interface.print(
            "WAMR_CI_FAILED_STAGE: {s}; cause: {s}; bounded private logs retained.\n",
            .{ stage, @errorName(reason) },
        ) catch {};
    }
    std.process.exit(1);
}
