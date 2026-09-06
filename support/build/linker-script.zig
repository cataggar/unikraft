// SPDX-License-Identifier: BSD-3-Clause

const std = @import("std");

pub const MergeError = error{
    OutOfMemory,
    UnterminatedComment,
    UnterminatedString,
    UnmatchedBrace,
    MissingPrimarySections,
    AmbiguousPrimarySections,
    UnsupportedSupplement,
    MissingInsertDirective,
    EmptyAugmentation,
    MissingAnchor,
    AmbiguousAnchor,
    DuplicatePhdr,
};

const Block = struct {
    opening: usize,
    closing: usize,
};

const InsertMode = enum {
    before,
    after,
};

const Insertion = struct {
    mode: InsertMode,
    anchor: []const u8,
    bodies: std.array_list.Managed([]const u8),

    fn deinit(self: *Insertion) void {
        self.bodies.deinit();
    }
};

const Edit = struct {
    offset: usize,
    order: usize,
    text: []const u8,
};

pub fn mergeAlloc(
    allocator: std.mem.Allocator,
    primary: []const u8,
    supplements: []const []const u8,
) MergeError![]u8 {
    const primary_mask = try maskAlloc(allocator, primary);
    defer allocator.free(primary_mask);
    try validateBraces(primary_mask);

    var primary_sections: ?Block = null;
    var primary_phdrs: ?Block = null;
    var position: usize = 0;
    while (findTopLevelNamedBlock(primary_mask, "SECTIONS", position)) |block| {
        if (primary_sections != null) return error.AmbiguousPrimarySections;
        primary_sections = block;
        position = block.closing + 1;
    }
    position = 0;
    while (findTopLevelNamedBlock(primary_mask, "PHDRS", position)) |block| {
        if (primary_phdrs != null) return error.DuplicatePhdr;
        primary_phdrs = block;
        position = block.closing + 1;
    }
    const sections = primary_sections orelse return error.MissingPrimarySections;

    var phdr_bodies = std.array_list.Managed([]const u8).init(allocator);
    defer phdr_bodies.deinit();
    var insertions = std.array_list.Managed(Insertion).init(allocator);
    defer {
        for (insertions.items) |*insertion| insertion.deinit();
        insertions.deinit();
    }

    for (supplements) |supplement| {
        try parseSupplement(allocator, supplement, &phdr_bodies, &insertions);
    }

    if (phdr_bodies.items.len != 0) {
        var phdr_names = std.StringHashMap(void).init(allocator);
        defer {
            var iterator = phdr_names.keyIterator();
            while (iterator.next()) |name| allocator.free(name.*);
            phdr_names.deinit();
        }
        if (primary_phdrs) |block| {
            try collectPhdrNames(allocator, primary_mask, block, &phdr_names);
        }
        for (phdr_bodies.items) |body| {
            const body_mask = try maskAlloc(allocator, body);
            defer allocator.free(body_mask);
            try collectPhdrNames(allocator, body_mask, .{
                .opening = 0,
                .closing = body_mask.len,
            }, &phdr_names);
        }
    }

    var edits = std.array_list.Managed(Edit).init(allocator);
    defer edits.deinit();
    var edit_texts = std.array_list.Managed([]u8).init(allocator);
    defer {
        for (edit_texts.items) |text| allocator.free(text);
        edit_texts.deinit();
    }

    if (phdr_bodies.items.len != 0) {
        const text = try joinBodies(allocator, phdr_bodies.items);
        try edit_texts.append(text);
        if (primary_phdrs) |block| {
            try edits.append(.{
                .offset = block.closing,
                .order = 0,
                .text = text,
            });
        } else {
            const wrapper = try std.fmt.allocPrint(
                allocator,
                "PHDRS\n{{{s}\n}}\n",
                .{text},
            );
            try edit_texts.append(wrapper);
            try edits.append(.{
                .offset = 0,
                .order = 0,
                .text = wrapper,
            });
        }
    }

    for (insertions.items, 0..) |insertion, index| {
        const bounds = try findSectionBounds(
            primary_mask,
            sections,
            insertion.anchor,
        );
        const text = try joinBodies(allocator, insertion.bodies.items);
        try edit_texts.append(text);
        try edits.append(.{
            .offset = switch (insertion.mode) {
                .before => bounds.start,
                .after => bounds.end,
            },
            .order = index + 1,
            .text = text,
        });
    }

    std.mem.sort(Edit, edits.items, {}, struct {
        fn lessThan(_: void, a: Edit, b: Edit) bool {
            return a.offset < b.offset or
                (a.offset == b.offset and a.order < b.order);
        }
    }.lessThan);

    var result = std.array_list.Managed(u8).init(allocator);
    errdefer result.deinit();
    var cursor: usize = 0;
    for (edits.items) |edit| {
        try result.appendSlice(primary[cursor..edit.offset]);
        try result.appendSlice(edit.text);
        cursor = edit.offset;
    }
    try result.appendSlice(primary[cursor..]);
    return result.toOwnedSlice();
}

fn parseSupplement(
    allocator: std.mem.Allocator,
    source: []const u8,
    phdr_bodies: *std.array_list.Managed([]const u8),
    insertions: *std.array_list.Managed(Insertion),
) MergeError!void {
    const clean = try maskAlloc(allocator, source);
    defer allocator.free(clean);
    try validateBraces(clean);

    var cursor: usize = 0;
    var augmented = false;
    while (true) {
        skipWhitespace(clean, &cursor);
        if (cursor == clean.len) break;

        if (namedBlockAt(clean, "PHDRS", cursor)) |block| {
            const clean_body = std.mem.trim(
                u8,
                clean[block.opening + 1 .. block.closing],
                " \t\r\n",
            );
            if (clean_body.len == 0) return error.EmptyAugmentation;
            const body = std.mem.trim(u8, source[block.opening + 1 .. block.closing], " \t\r\n");
            try phdr_bodies.append(body);
            augmented = true;
            cursor = block.closing + 1;
            continue;
        }

        if (namedBlockAt(clean, "SECTIONS", cursor)) |block| {
            const clean_body = std.mem.trim(
                u8,
                clean[block.opening + 1 .. block.closing],
                " \t\r\n",
            );
            if (clean_body.len == 0) return error.EmptyAugmentation;
            const body = std.mem.trim(u8, source[block.opening + 1 .. block.closing], " \t\r\n");
            cursor = block.closing + 1;
            skipWhitespace(clean, &cursor);
            if (!consumeKeyword(clean, &cursor, "INSERT")) {
                return error.MissingInsertDirective;
            }
            skipWhitespace(clean, &cursor);
            const mode: InsertMode = if (consumeKeyword(clean, &cursor, "BEFORE"))
                .before
            else if (consumeKeyword(clean, &cursor, "AFTER"))
                .after
            else
                return error.MissingInsertDirective;
            skipWhitespace(clean, &cursor);
            const anchor_start = cursor;
            while (cursor < clean.len and isAnchorByte(clean[cursor])) cursor += 1;
            if (cursor == anchor_start) return error.MissingInsertDirective;
            const anchor = source[anchor_start..cursor];
            skipWhitespace(clean, &cursor);
            if (cursor < clean.len and clean[cursor] == ';') cursor += 1;

            const insertion = try findOrAddInsertion(
                allocator,
                insertions,
                mode,
                anchor,
            );
            try insertion.bodies.append(body);
            augmented = true;
            continue;
        }

        return error.UnsupportedSupplement;
    }
    if (!augmented) return error.EmptyAugmentation;
}

fn findOrAddInsertion(
    allocator: std.mem.Allocator,
    insertions: *std.array_list.Managed(Insertion),
    mode: InsertMode,
    anchor: []const u8,
) MergeError!*Insertion {
    for (insertions.items) |*insertion| {
        if (insertion.mode == mode and std.mem.eql(u8, insertion.anchor, anchor)) {
            return insertion;
        }
    }
    try insertions.append(.{
        .mode = mode,
        .anchor = anchor,
        .bodies = std.array_list.Managed([]const u8).init(allocator),
    });
    return &insertions.items[insertions.items.len - 1];
}

fn joinBodies(
    allocator: std.mem.Allocator,
    bodies: []const []const u8,
) MergeError![]u8 {
    var result = std.array_list.Managed(u8).init(allocator);
    errdefer result.deinit();
    try result.append('\n');
    for (bodies) |body| {
        try result.appendSlice(body);
        try result.append('\n');
    }
    return result.toOwnedSlice();
}

fn maskAlloc(allocator: std.mem.Allocator, source: []const u8) MergeError![]u8 {
    const result = try allocator.dupe(u8, source);
    errdefer allocator.free(result);
    var index: usize = 0;
    while (index < source.len) {
        if (source[index] == '/' and index + 1 < source.len and source[index + 1] == '*') {
            result[index] = ' ';
            result[index + 1] = ' ';
            index += 2;
            var terminated = false;
            while (index < source.len) : (index += 1) {
                if (source[index] == '*' and index + 1 < source.len and source[index + 1] == '/') {
                    result[index] = ' ';
                    result[index + 1] = ' ';
                    index += 2;
                    terminated = true;
                    break;
                }
                if (source[index] != '\n') result[index] = ' ';
            }
            if (!terminated) return error.UnterminatedComment;
            continue;
        }
        if (source[index] == '/' and index + 1 < source.len and source[index + 1] == '/') {
            result[index] = ' ';
            result[index + 1] = ' ';
            index += 2;
            while (index < source.len and source[index] != '\n') : (index += 1) {
                result[index] = ' ';
            }
            continue;
        }
        if (source[index] == '"' or source[index] == '\'') {
            const quote = source[index];
            result[index] = ' ';
            index += 1;
            var terminated = false;
            while (index < source.len) : (index += 1) {
                if (source[index] == '\\' and index + 1 < source.len) {
                    result[index] = ' ';
                    if (source[index + 1] != '\n') result[index + 1] = ' ';
                    index += 1;
                    continue;
                }
                if (source[index] == quote) {
                    result[index] = ' ';
                    index += 1;
                    terminated = true;
                    break;
                }
                if (source[index] != '\n') result[index] = ' ';
            }
            if (!terminated) return error.UnterminatedString;
            continue;
        }
        index += 1;
    }
    return result;
}

fn validateBraces(clean: []const u8) MergeError!void {
    var depth: usize = 0;
    for (clean) |byte| {
        if (byte == '{') {
            depth += 1;
        } else if (byte == '}') {
            if (depth == 0) return error.UnmatchedBrace;
            depth -= 1;
        }
    }
    if (depth != 0) return error.UnmatchedBrace;
}

fn findTopLevelNamedBlock(
    clean: []const u8,
    name: []const u8,
    start: usize,
) ?Block {
    var cursor = start;
    var depth: usize = 0;
    while (cursor < clean.len) : (cursor += 1) {
        if (clean[cursor] == '{') {
            depth += 1;
            continue;
        }
        if (clean[cursor] == '}') {
            depth -= 1;
            continue;
        }
        if (depth == 0) {
            if (namedBlockAt(clean, name, cursor)) |block| return block;
        }
    }
    return null;
}

fn namedBlockAt(clean: []const u8, name: []const u8, start: usize) ?Block {
    if (!keywordAt(clean, start, name)) return null;
    var cursor = start + name.len;
    skipWhitespace(clean, &cursor);
    if (cursor >= clean.len or clean[cursor] != '{') return null;
    return .{
        .opening = cursor,
        .closing = matchingBrace(clean, cursor) orelse return null,
    };
}

fn matchingBrace(clean: []const u8, opening: usize) ?usize {
    var depth: usize = 0;
    var cursor = opening;
    while (cursor < clean.len) : (cursor += 1) {
        if (clean[cursor] == '{') {
            depth += 1;
        } else if (clean[cursor] == '}') {
            depth -= 1;
            if (depth == 0) return cursor;
        }
    }
    return null;
}

fn keywordAt(source: []const u8, start: usize, keyword: []const u8) bool {
    if (start + keyword.len > source.len) return false;
    if (!std.mem.eql(u8, source[start .. start + keyword.len], keyword)) return false;
    if (start != 0 and isIdentifierByte(source[start - 1])) return false;
    if (start + keyword.len < source.len and isIdentifierByte(source[start + keyword.len])) {
        return false;
    }
    return true;
}

fn consumeKeyword(source: []const u8, cursor: *usize, keyword: []const u8) bool {
    if (!keywordAt(source, cursor.*, keyword)) return false;
    cursor.* += keyword.len;
    return true;
}

fn skipWhitespace(source: []const u8, cursor: *usize) void {
    while (cursor.* < source.len and std.ascii.isWhitespace(source[cursor.*])) {
        cursor.* += 1;
    }
}

fn isIdentifierByte(byte: u8) bool {
    return std.ascii.isAlphanumeric(byte) or byte == '_';
}

fn isAnchorByte(byte: u8) bool {
    return std.ascii.isAlphanumeric(byte) or
        byte == '_' or byte == '.' or byte == '$' or byte == '/' or
        byte == '+' or byte == '-';
}

const SectionBounds = struct {
    start: usize,
    end: usize,
};

fn findSectionBounds(
    clean: []const u8,
    sections: Block,
    anchor: []const u8,
) MergeError!SectionBounds {
    var found: ?SectionBounds = null;
    var cursor = sections.opening + 1;
    var depth: usize = 0;
    while (cursor < sections.closing) : (cursor += 1) {
        switch (clean[cursor]) {
            '{' => depth += 1,
            '}' => depth -= 1,
            else => {},
        }
        if (depth != 0 or !tokenAt(clean, cursor, anchor)) continue;
        const bounds = outputSectionAt(clean, sections.closing, cursor) orelse continue;
        if (found != null) return error.AmbiguousAnchor;
        found = bounds;
        cursor = bounds.end - 1;
    }
    return found orelse error.MissingAnchor;
}

fn tokenAt(source: []const u8, start: usize, token: []const u8) bool {
    if (start + token.len > source.len) return false;
    if (!std.mem.eql(u8, source[start .. start + token.len], token)) return false;
    if (start != 0 and isAnchorByte(source[start - 1])) return false;
    if (start + token.len < source.len and isAnchorByte(source[start + token.len])) {
        return false;
    }
    return true;
}

fn outputSectionAt(clean: []const u8, limit: usize, start: usize) ?SectionBounds {
    var cursor = start;
    var paren_depth: usize = 0;
    var saw_colon = false;
    while (cursor < limit) : (cursor += 1) {
        switch (clean[cursor]) {
            '(' => paren_depth += 1,
            ')' => {
                if (paren_depth == 0) return null;
                paren_depth -= 1;
            },
            ':' => if (paren_depth == 0) {
                saw_colon = true;
            },
            ';' => if (!saw_colon and paren_depth == 0) return null,
            '{' => {
                if (!saw_colon or paren_depth != 0) return null;
                const closing = matchingBrace(clean, cursor) orelse return null;
                return .{
                    .start = start,
                    .end = consumeSectionTrailer(clean, limit, closing + 1),
                };
            },
            '}' => return null,
            else => {},
        }
    }
    return null;
}

fn consumeSectionTrailer(clean: []const u8, limit: usize, initial: usize) usize {
    var cursor = initial;
    while (true) {
        const before_ws = cursor;
        skipWhitespaceLimited(clean, limit, &cursor);
        if (cursor >= limit) return before_ws;

        if (clean[cursor] == ':') {
            cursor += 1;
            skipWhitespaceLimited(clean, limit, &cursor);
            if (!consumeName(clean, limit, &cursor)) return before_ws;
            continue;
        }
        if (clean[cursor] == '>') {
            cursor += 1;
            skipWhitespaceLimited(clean, limit, &cursor);
            if (!consumeName(clean, limit, &cursor)) return before_ws;
            continue;
        }
        if (keywordAt(clean, cursor, "AT")) {
            cursor += 2;
            skipWhitespaceLimited(clean, limit, &cursor);
            if (cursor < limit and clean[cursor] == '>') {
                cursor += 1;
                skipWhitespaceLimited(clean, limit, &cursor);
                if (!consumeName(clean, limit, &cursor)) return before_ws;
                continue;
            }
            if (cursor < limit and clean[cursor] == '(') {
                cursor = matchingParen(clean, cursor, limit) orelse return before_ws;
                continue;
            }
            return before_ws;
        }
        if (clean[cursor] == '=') {
            cursor += 1;
            skipWhitespaceLimited(clean, limit, &cursor);
            while (cursor < limit and
                !std.ascii.isWhitespace(clean[cursor]) and
                clean[cursor] != ';') : (cursor += 1)
            {}
            continue;
        }
        if (clean[cursor] == ';') return cursor + 1;
        return before_ws;
    }
}

fn skipWhitespaceLimited(source: []const u8, limit: usize, cursor: *usize) void {
    while (cursor.* < limit and std.ascii.isWhitespace(source[cursor.*])) {
        cursor.* += 1;
    }
}

fn consumeName(source: []const u8, limit: usize, cursor: *usize) bool {
    const start = cursor.*;
    while (cursor.* < limit and isAnchorByte(source[cursor.*])) cursor.* += 1;
    return cursor.* != start;
}

fn matchingParen(source: []const u8, opening: usize, limit: usize) ?usize {
    var depth: usize = 0;
    var cursor = opening;
    while (cursor < limit) : (cursor += 1) {
        if (source[cursor] == '(') {
            depth += 1;
        } else if (source[cursor] == ')') {
            depth -= 1;
            if (depth == 0) return cursor + 1;
        }
    }
    return null;
}

fn collectPhdrNames(
    allocator: std.mem.Allocator,
    clean: []const u8,
    block: Block,
    names: *std.StringHashMap(void),
) MergeError!void {
    var cursor = if (block.opening < clean.len and clean[block.opening] == '{')
        block.opening + 1
    else
        block.opening;
    const limit = block.closing;
    while (cursor < limit) {
        skipWhitespaceLimited(clean, limit, &cursor);
        if (cursor == limit) break;
        const start = cursor;
        if (!consumeName(clean, limit, &cursor)) return error.UnsupportedSupplement;
        const name = clean[start..cursor];
        while (cursor < limit and clean[cursor] != ';') : (cursor += 1) {}
        if (cursor == limit) return error.UnsupportedSupplement;
        if (names.contains(name)) return error.DuplicatePhdr;
        const owned_name = try allocator.dupe(u8, name);
        names.put(owned_name, {}) catch |err| {
            allocator.free(owned_name);
            return err;
        };
        cursor += 1;
    }
}

pub fn main(init: std.process.Init) !void {
    const allocator = init.arena.allocator();
    const args = try init.minimal.args.toSlice(allocator);
    if (args.len < 3) {
        std.debug.print(
            "usage: linker-script OUTPUT PRIMARY SUPPLEMENT...\n",
            .{},
        );
        std.process.exit(2);
    }

    const primary = try std.Io.Dir.cwd().readFileAlloc(
        init.io,
        args[2],
        allocator,
        .limited(64 * 1024 * 1024),
    );
    const supplements = try allocator.alloc([]const u8, args.len - 3);
    for (args[3..], 0..) |path, index| {
        supplements[index] = try std.Io.Dir.cwd().readFileAlloc(
            init.io,
            path,
            allocator,
            .limited(64 * 1024 * 1024),
        );
    }
    const result = mergeAlloc(allocator, primary, supplements) catch |err| {
        std.debug.print("error: cannot merge linker scripts: {s}\n", .{@errorName(err)});
        std.process.exit(2);
    };
    const parent = std.fs.path.dirname(args[1]) orelse ".";
    try std.Io.Dir.cwd().createDirPath(init.io, parent);
    const output = try std.Io.Dir.cwd().createFile(init.io, args[1], .{
        .truncate = true,
    });
    defer output.close(init.io);
    try output.writePositionalAll(init.io, result, 0);
}

test "comments strings braces PHDRS and ordered inserts merge deterministically" {
    const primary =
        \\OUTPUT_FORMAT("elf64-{not-a-brace}")
        \\PHDRS {
        \\  text PT_LOAD;
        \\}
        \\SECTIONS {
        \\  .text : { *(.text) /* } */ } :text
        \\  .data : { BYTE('{') }
        \\  .bss : { *(.bss) }
        \\}
        \\
    ;
    const supplements = [_][]const u8{
        \\PHDRS { dynamic PT_DYNAMIC; }
        \\SECTIONS { .before_one : { *(.before.one) } } INSERT BEFORE .data;
        \\SECTIONS { .after_one : { *(.after.one) } } INSERT AFTER .data;
        ,
        \\SECTIONS { .before_two : { *(.before.two) } } INSERT BEFORE .data
        \\SECTIONS { .after_two : { *(.after.two) } } INSERT AFTER .data
        ,
    };
    const first = try mergeAlloc(std.testing.allocator, primary, &supplements);
    defer std.testing.allocator.free(first);
    const second = try mergeAlloc(std.testing.allocator, primary, &supplements);
    defer std.testing.allocator.free(second);
    try std.testing.expectEqualStrings(first, second);
    try expectOrdered(first, &.{
        "text PT_LOAD;",
        "dynamic PT_DYNAMIC;",
        ".before_one",
        ".before_two",
        ".data",
        ".after_one",
        ".after_two",
        ".bss",
    });
}

test "supplemental PHDRS is added when the primary has none" {
    const result = try mergeAlloc(
        std.testing.allocator,
        "SECTIONS { .text : { *(.text) } }\n",
        &.{"PHDRS { text PT_LOAD; }\nSECTIONS { .meta : { *(.meta) } } INSERT AFTER .text;"},
    );
    defer std.testing.allocator.free(result);
    try std.testing.expect(std.mem.startsWith(u8, result, "PHDRS\n{"));
    try expectOrdered(result, &.{ "text PT_LOAD;", ".text", ".meta" });
}

test "INSERT AFTER preserves a spaced section fill expression" {
    const result = try mergeAlloc(
        std.testing.allocator,
        \\SECTIONS {
        \\  .text : { *(.text) } :text = 0x9090
        \\  .data : { *(.data) }
        \\}
        \\
    ,
        &.{"SECTIONS { .extra : { *(.extra) } } INSERT AFTER .text;"},
    );
    defer std.testing.allocator.free(result);

    try expectOrdered(result, &.{
        "} :text = 0x9090",
        ".extra",
        ".data",
    });
    try std.testing.expect(std.mem.indexOf(
        u8,
        result,
        "= \n.extra",
    ) == null);
}

test "missing and ambiguous anchors are rejected" {
    try std.testing.expectError(
        error.MissingAnchor,
        mergeAlloc(
            std.testing.allocator,
            "SECTIONS { .text : { *(.text) } }\n",
            &.{"SECTIONS { .extra : { *(.extra) } } INSERT AFTER .missing;"},
        ),
    );
    try std.testing.expectError(
        error.AmbiguousAnchor,
        mergeAlloc(
            std.testing.allocator,
            "SECTIONS { .text : { *(.a) } .text : { *(.b) } }\n",
            &.{"SECTIONS { .extra : { *(.extra) } } INSERT AFTER .text;"},
        ),
    );
}

test "malformed non-augmenting and unsupported supplements are rejected" {
    const primary = "SECTIONS { .text : { *(.text) } }\n";
    try std.testing.expectError(
        error.UnmatchedBrace,
        mergeAlloc(std.testing.allocator, primary, &.{"SECTIONS {"}),
    );
    try std.testing.expectError(
        error.EmptyAugmentation,
        mergeAlloc(std.testing.allocator, primary, &.{"/* only a comment */"}),
    );
    try std.testing.expectError(
        error.EmptyAugmentation,
        mergeAlloc(
            std.testing.allocator,
            primary,
            &.{"SECTIONS { /* no augmentation */ } INSERT AFTER .text;"},
        ),
    );
    try std.testing.expectError(
        error.UnterminatedString,
        mergeAlloc(
            std.testing.allocator,
            primary,
            &.{"SECTIONS { .extra : { \"unterminated } } INSERT AFTER .text;"},
        ),
    );
    try std.testing.expectError(
        error.MissingInsertDirective,
        mergeAlloc(
            std.testing.allocator,
            primary,
            &.{"SECTIONS { .extra : { *(.extra) } }"},
        ),
    );
    try std.testing.expectError(
        error.UnsupportedSupplement,
        mergeAlloc(
            std.testing.allocator,
            primary,
            &.{"ENTRY(foo)\nSECTIONS { .extra : { *(.extra) } } INSERT AFTER .text;"},
        ),
    );
    try std.testing.expectError(
        error.AmbiguousPrimarySections,
        mergeAlloc(
            std.testing.allocator,
            primary ++ "SECTIONS { .data : { *(.data) } }\n",
            &.{"SECTIONS { .extra : { *(.extra) } } INSERT AFTER .text;"},
        ),
    );
}

test "duplicate PHDR names are rejected" {
    try std.testing.expectError(
        error.DuplicatePhdr,
        mergeAlloc(
            std.testing.allocator,
            "PHDRS { text PT_LOAD; }\nSECTIONS { .text : { *(.text) } }\n",
            &.{"PHDRS { text PT_DYNAMIC; }"},
        ),
    );
}

fn expectOrdered(haystack: []const u8, needles: []const []const u8) !void {
    var offset: usize = 0;
    for (needles) |needle| {
        const relative = std.mem.indexOfPos(u8, haystack, offset, needle) orelse {
            return error.TestExpectedEqual;
        };
        offset = relative + needle.len;
    }
}
