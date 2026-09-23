const std = @import("std");
const c = @import("config.zig");

pub const milestones = [_][]const u8{ "Hyper-V Hv#1 hypercall page enabled", "Hyper-V SynIC:", "Powered by", "Calling main(" };

pub fn validate(a: std.mem.Allocator, raw: []const u8, config: c.Config) !void {
    try config.validate();
    return validateEnvelope(a, raw, config.expect, config.expect_main_return, config.required, config.forbidden);
}

/// Shared guest framing only; this carries no boot or cloud authority.
pub fn validateEnvelope(a: std.mem.Allocator, raw: []const u8, expect: []const u8, expect_main_return: i32, required: []const []const u8, forbidden_markers: []const []const u8) !void {
    const text = try normalize(a, raw);
    defer a.free(text);
    for ([_][]const u8{ "Unikraft Crash", "Assertion failure", "Exception Type" }) |failure|
        if (std.mem.indexOf(u8, text, failure) != null) return error.GuestCrash;
    for (forbidden_markers) |forbidden|
        if (std.mem.indexOf(u8, text, forbidden) != null) return error.ForbiddenMarker;
    var position: usize = 0;
    for (milestones, 0..) |milestone, i| {
        const found = std.mem.indexOf(u8, text, milestone) orelse return error.MissingMilestone;
        if (i != 0 and found <= position) return error.ReorderedMilestone;
        position = found;
    }
    const expected = std.mem.indexOf(u8, text, expect) orelse return error.MissingExpected;
    if (expected <= position) return error.ReorderedMilestone;
    var terminal: ?usize = null;
    var lines = std.mem.splitScalar(u8, text, '\n');
    var offset: usize = 0;
    while (lines.next()) |raw_line| {
        const line = std.mem.trim(u8, raw_line, " \t\r");
        if (std.mem.indexOf(u8, line, "main returned") != null) {
            const body = terminalBody(line) orelse return error.InvalidMainReturn;
            if (try c.integer(i32, body["main returned ".len..]) != expect_main_return) return error.UnexpectedMainReturn;
            if (terminal != null) return error.DuplicateMainReturn;
            terminal = offset;
        }
        offset += raw_line.len + 1;
    }
    const end = terminal orelse return error.MissingMainReturn;
    if (end <= expected) return error.ReorderedMilestone;
    var previous: ?usize = null;
    for (required) |marker| {
        const found = std.mem.indexOf(u8, text, marker) orelse return error.MissingRequired;
        if (found >= end or (previous != null and found <= previous.?)) return error.ReorderedRequired;
        previous = found;
    }
}

pub fn normalize(a: std.mem.Allocator, raw: []const u8) ![]u8 {
    return normalizeWithOptions(a, raw, .local_boot);
}

pub const Normalization = enum {
    local_boot,
    tiny,
    optional,
};

/// Raw bytes are never modified; only WAMR callers request CRLF folding and
/// optional-transcript printable character checks.
pub fn normalizeWithOptions(a: std.mem.Allocator, raw: []const u8, mode: Normalization) ![]u8 {
    const limit: usize = switch (mode) {
        .local_boot => c.max_serial,
        .tiny => c.max_serial - 1,
        .optional => 2 * 1024 * 1024,
    };
    if (raw.len == 0 or raw.len > limit) return error.SerialLimit;
    if (!std.unicode.utf8ValidateSlice(raw)) return error.InvalidSerial;
    const output = try a.alloc(u8, raw.len);
    errdefer a.free(output);
    var used: usize = 0;
    var at: usize = 0;
    var line: usize = 0;
    while (at < raw.len) {
        const byte = raw[at];
        at += 1;
        if (byte == 0) continue;
        if (byte == 0x1b) {
            if (at >= raw.len or raw[at] != '[') return error.InvalidSerial;
            at += 1;
            while (at < raw.len and raw[at] >= 0x30 and raw[at] <= 0x3f) : (at += 1) {}
            while (at < raw.len and raw[at] >= 0x20 and raw[at] <= 0x2f) : (at += 1) {}
            if (at == raw.len or raw[at] < 0x40 or raw[at] > 0x7e) return error.InvalidSerial;
            at += 1;
            continue;
        }
        if (byte < 0x20 and std.mem.indexOfScalar(u8, "\n\r\t", byte) == null) return error.InvalidSerial;
        if (byte == '\n') line = 0 else line += 1;
        if (line > 8192) return error.SerialLineLimit;
        output[used] = byte;
        used += 1;
    }
    if (mode != .local_boot) {
        var write: usize = 0;
        for (output[0..used], 0..) |byte, read| {
            if (byte == '\r' and read + 1 < used and output[read + 1] == '\n') continue;
            output[write] = byte;
            write += 1;
        }
        used = write;
    }
    if (mode == .optional) try checkOptionalCharacters(output[0..used]);
    return a.realloc(output, used);
}

fn checkOptionalCharacters(text: []const u8) !void {
    var at: usize = 0;
    while (at < text.len) {
        const size = try std.unicode.utf8ByteSequenceLength(text[at]);
        const cp = try std.unicode.utf8Decode(text[at..][0..size]);
        at += size;
        if (cp == '\n' or cp == '\t' or cp == ' ') continue;
        if (cp < 0x20 or cp == 0x7f or (cp >= 0x80 and cp <= 0x9f) or
            cp == 0xa0 or cp == 0xad or cp == 0x1680 or cp == 0x180e or
            (cp >= 0x2000 and cp <= 0x200f) or (cp >= 0x2028 and cp <= 0x202f) or
            (cp >= 0x2060 and cp <= 0x206f) or cp == 0x205f or cp == 0x3000 or
            cp == 0xfeff or (cp >= 0xfff9 and cp <= 0xfffb) or
            (cp >= 0xe000 and cp <= 0xf8ff) or
            (cp >= 0xf0000 and cp <= 0xffffd) or (cp >= 0x100000 and cp <= 0x10fffd) or
            (cp >= 0x600 and cp <= 0x605) or cp == 0x61c or cp == 0x6dd or
            cp == 0x70f or (cp >= 0x890 and cp <= 0x891) or cp == 0x8e2 or
            cp == 0x110bd or cp == 0x110cd or (cp >= 0x13430 and cp <= 0x1343f) or
            (cp >= 0x1bca0 and cp <= 0x1bca3) or (cp >= 0x1d173 and cp <= 0x1d17a) or
            cp == 0xe0001 or (cp >= 0xe0020 and cp <= 0xe007f) or unassignedCodepoint(cp))
            return error.InvalidSerial;
    }
}

// Unicode 16 General_Category=Cn; reject Unicode 16-only additions below to
// match Python 3.12/Unicode 15 isprintable() used by the production reference.
// Each sorted interval is two fixed-width hex scalars.
const unassigned =
    "00037800037900038000038300038b00038b00038d00038d0003a20003a200053000053000055700055800058b00058c0005900005900005c80005cf" ++
    "0005eb0005ee0005f50005ff00070e00070e00074b00074c0007b20007bf0007fb0007fc00082e00082f00083f00083f00085c00085d00085f00085f" ++
    "00086b00086f00088f00088f00089200089600098400098400098d00098e0009910009920009a90009a90009b10009b10009b30009b50009ba0009bb" ++
    "0009c50009c60009c90009ca0009cf0009d60009d80009db0009de0009de0009e40009e50009ff000a00000a04000a04000a0b000a0e000a11000a12" ++
    "000a29000a29000a31000a31000a34000a34000a37000a37000a3a000a3b000a3d000a3d000a43000a46000a49000a4a000a4e000a50000a52000a58" ++
    "000a5d000a5d000a5f000a65000a77000a80000a84000a84000a8e000a8e000a92000a92000aa9000aa9000ab1000ab1000ab4000ab4000aba000abb" ++
    "000ac6000ac6000aca000aca000ace000acf000ad1000adf000ae4000ae5000af2000af8000b00000b00000b04000b04000b0d000b0e000b11000b12" ++
    "000b29000b29000b31000b31000b34000b34000b3a000b3b000b45000b46000b49000b4a000b4e000b54000b58000b5b000b5e000b5e000b64000b65" ++
    "000b78000b81000b84000b84000b8b000b8d000b91000b91000b96000b98000b9b000b9b000b9d000b9d000ba0000ba2000ba5000ba7000bab000bad" ++
    "000bba000bbd000bc3000bc5000bc9000bc9000bce000bcf000bd1000bd6000bd8000be5000bfb000bff000c0d000c0d000c11000c11000c29000c29" ++
    "000c3a000c3b000c45000c45000c49000c49000c4e000c54000c57000c57000c5b000c5c000c5e000c5f000c64000c65000c70000c76000c8d000c8d" ++
    "000c91000c91000ca9000ca9000cb4000cb4000cba000cbb000cc5000cc5000cc9000cc9000cce000cd4000cd7000cdc000cdf000cdf000ce4000ce5" ++
    "000cf0000cf0000cf4000cff000d0d000d0d000d11000d11000d45000d45000d49000d49000d50000d53000d64000d65000d80000d80000d84000d84" ++
    "000d97000d99000db2000db2000dbc000dbc000dbe000dbf000dc7000dc9000dcb000dce000dd5000dd5000dd7000dd7000de0000de5000df0000df1" ++
    "000df5000e00000e3b000e3e000e5c000e80000e83000e83000e85000e85000e8b000e8b000ea4000ea4000ea6000ea6000ebe000ebf000ec5000ec5" ++
    "000ec7000ec7000ecf000ecf000eda000edb000ee0000eff000f48000f48000f6d000f70000f98000f98000fbd000fbd000fcd000fcd000fdb000fff" ++
    "0010c60010c60010c80010cc0010ce0010cf00124900124900124e00124f00125700125700125900125900125e00125f00128900128900128e00128f" ++
    "0012b10012b10012b60012b70012bf0012bf0012c10012c10012c60012c70012d70012d700131100131100131600131700135b00135c00137d00137f" ++
    "00139a00139f0013f60013f70013fe0013ff00169d00169f0016f90016ff00171600171e00173700173f00175400175f00176d00176d001771001771" ++
    "00177400177f0017de0017df0017ea0017ef0017fa0017ff00181a00181f00187900187f0018ab0018af0018f60018ff00191f00191f00192c00192f" ++
    "00193c00193f00194100194300196e00196f00197500197f0019ac0019af0019ca0019cf0019db0019dd001a1c001a1d001a5f001a5f001a7d001a7e" ++
    "001a8a001a8f001a9a001a9f001aae001aaf001acf001aff001b4d001b4d001bf4001bfb001c38001c3a001c4a001c4c001c8b001c8f001cbb001cbc" ++
    "001cc8001ccf001cfb001cff001f16001f17001f1e001f1f001f46001f47001f4e001f4f001f58001f58001f5a001f5a001f5c001f5c001f5e001f5e" ++
    "001f7e001f7f001fb5001fb5001fc5001fc5001fd4001fd5001fdc001fdc001ff0001ff1001ff5001ff5001fff001fff002065002065002072002073" ++
    "00208f00208f00209d00209f0020c10020cf0020f10020ff00218c00218f00242a00243f00244b00245f002b74002b75002b96002b96002cf4002cf8" ++
    "002d26002d26002d28002d2c002d2e002d2f002d68002d6e002d71002d7e002d97002d9f002da7002da7002daf002daf002db7002db7002dbf002dbf" ++
    "002dc7002dc7002dcf002dcf002dd7002dd7002ddf002ddf002e5e002e7f002e9a002e9a002ef4002eff002fd6002fef003040003040003097003098" ++
    "00310000310400313000313000318f00318f0031e60031ee00321f00321f00a48d00a48f00a4c700a4cf00a62c00a63f00a6f800a6ff00a7ce00a7cf" ++
    "00a7d200a7d200a7d400a7d400a7dd00a7f100a82d00a82f00a83a00a83f00a87800a87f00a8c600a8cd00a8da00a8df00a95400a95e00a97d00a97f" ++
    "00a9ce00a9ce00a9da00a9dd00a9ff00a9ff00aa3700aa3f00aa4e00aa4f00aa5a00aa5b00aac300aada00aaf700ab0000ab0700ab0800ab0f00ab10" ++
    "00ab1700ab1f00ab2700ab2700ab2f00ab2f00ab6c00ab6f00abee00abef00abfa00abff00d7a400d7af00d7c700d7ca00d7fc00d7ff00fa6e00fa6f" ++
    "00fada00faff00fb0700fb1200fb1800fb1c00fb3700fb3700fb3d00fb3d00fb3f00fb3f00fb4200fb4200fb4500fb4500fbc300fbd200fd9000fd91" ++
    "00fdc800fdce00fdd000fdef00fe1a00fe1f00fe5300fe5300fe6700fe6700fe6c00fe6f00fe7500fe7500fefd00fefe00ff0000ff0000ffbf00ffc1" ++
    "00ffc800ffc900ffd000ffd100ffd800ffd900ffdd00ffdf00ffe700ffe700ffef00fff800fffe00ffff01000c01000c01002701002701003b01003b" ++
    "01003e01003e01004e01004f01005e01007f0100fb0100ff01010301010601013401013601018f01018f01019d01019f0101a10101cf0101fe01027f" ++
    "01029d01029f0102d10102df0102fc0102ff01032401032c01034b01034f01037b01037f01039e01039e0103c40103c70103d60103ff01049e01049f" ++
    "0104aa0104af0104d40104d70104fc0104ff01052801052f01056401056e01057b01057b01058b01058b0105930105930105960105960105a20105a2" ++
    "0105b20105b20105ba0105ba0105bd0105bf0105f40105ff01073701073f01075601075f01076801077f0107860107860107b10107b10107bb0107ff" ++
    "01080601080701080901080901083601083601083901083b01083d01083e01085601085601089f0108a60108b00108df0108f30108f30108f60108fa" ++
    "01091c01091e01093a01093e01094001097f0109b80109bb0109d00109d1010a04010a04010a07010a0b010a14010a14010a18010a18010a36010a37" ++
    "010a3b010a3e010a49010a4f010a59010a5f010aa0010abf010ae7010aea010af7010aff010b36010b38010b56010b57010b73010b77010b92010b98" ++
    "010b9d010ba8010bb0010bff010c49010c7f010cb3010cbf010cf3010cf9010d28010d2f010d3a010d3f010d66010d68010d86010d8d010d90010e5f" ++
    "010e7f010e7f010eaa010eaa010eae010eaf010eb2010ec1010ec5010efb010f28010f2f010f5a010f6f010f8a010faf010fcc010fdf010ff7010fff" ++
    "01104e01105101107601107e0110c30110cc0110ce0110cf0110e90110ef0110fa0110ff01113501113501114801114f01117701117f0111e00111e0" ++
    "0111f50111ff01121201121201124201127f01128701128701128901128901128e01128e01129e01129e0112aa0112af0112eb0112ef0112fa0112ff" ++
    "01130401130401130d01130e01131101131201132901132901133101133101133401133401133a01133a01134501134601134901134a01134e01134f" ++
    "01135101135601135801135c01136401136501136d01136f01137501137f01138a01138a01138c01138d01138f01138f0113b60113b60113c10113c1" ++
    "0113c30113c40113c60113c60113cb0113cb0113d60113d60113d90113e00113e30113ff01145c01145c01146201147f0114c80114cf0114da01157f" ++
    "0115b60115b70115de0115ff01164501164f01165a01165f01166d01167f0116ba0116bf0116ca0116cf0116e40116ff01171b01171c01172c01172f" ++
    "0117470117ff01183c01189f0118f30118fe01190701190801190a01190b01191401191401191701191701193601193601193901193a01194701194f" ++
    "01195a01199f0119a80119a90119d80119d90119e50119ff011a48011a4f011aa3011aaf011af9011aff011b0a011bbf011be2011bef011bfa011bff" ++
    "011c09011c09011c37011c37011c46011c4f011c6d011c6f011c90011c91011ca8011ca8011cb7011cff011d07011d07011d0a011d0a011d37011d39" ++
    "011d3b011d3b011d3e011d3e011d48011d4f011d5a011d5f011d66011d66011d69011d69011d8f011d8f011d92011d92011d99011d9f011daa011edf" ++
    "011ef9011eff011f11011f11011f3b011f3d011f5b011faf011fb1011fbf011ff2011ffe01239a0123ff01246f01246f01247501247f012544012f8f" ++
    "012ff3012fff01345601345f0143fb0143ff0146470160ff01613a0167ff016a39016a3f016a5f016a5f016a6a016a6d016abf016abf016aca016acf" ++
    "016aee016aef016af6016aff016b46016b4f016b5a016b5a016b62016b62016b78016b7c016b90016d3f016d7a016e3f016e9b016eff016f4b016f4e" ++
    "016f88016f8e016fa0016fdf016fe5016fef016ff2016fff0187f80187ff018cd6018cfe018d0901afef01aff401aff401affc01affc01afff01afff" ++
    "01b12301b13101b13301b14f01b15301b15401b15601b16301b16801b16f01b2fc01bbff01bc6b01bc6f01bc7d01bc7f01bc8901bc8f01bc9a01bc9b" ++
    "01bca401cbff01ccfa01ccff01ceb401ceff01cf2e01cf2f01cf4701cf4f01cfc401cfff01d0f601d0ff01d12701d12801d1eb01d1ff01d24601d2bf" ++
    "01d2d401d2df01d2f401d2ff01d35701d35f01d37901d3ff01d45501d45501d49d01d49d01d4a001d4a101d4a301d4a401d4a701d4a801d4ad01d4ad" ++
    "01d4ba01d4ba01d4bc01d4bc01d4c401d4c401d50601d50601d50b01d50c01d51501d51501d51d01d51d01d53a01d53a01d53f01d53f01d54501d545" ++
    "01d54701d54901d55101d55101d6a601d6a701d7cc01d7cd01da8c01da9a01daa001daa001dab001deff01df1f01df2401df2b01dfff01e00701e007" ++
    "01e01901e01a01e02201e02201e02501e02501e02b01e02f01e06e01e08e01e09001e0ff01e12d01e12f01e13e01e13f01e14a01e14d01e15001e28f" ++
    "01e2af01e2bf01e2fa01e2fe01e30001e4cf01e4fa01e5cf01e5fb01e5fe01e60001e7df01e7e701e7e701e7ec01e7ec01e7ef01e7ef01e7ff01e7ff" ++
    "01e8c501e8c601e8d701e8ff01e94c01e94f01e95a01e95d01e96001ec7001ecb501ed0001ed3e01edff01ee0401ee0401ee2001ee2001ee2301ee23" ++
    "01ee2501ee2601ee2801ee2801ee3301ee3301ee3801ee3801ee3a01ee3a01ee3c01ee4101ee4301ee4601ee4801ee4801ee4a01ee4a01ee4c01ee4c" ++
    "01ee5001ee5001ee5301ee5301ee5501ee5601ee5801ee5801ee5a01ee5a01ee5c01ee5c01ee5e01ee5e01ee6001ee6001ee6301ee6301ee6501ee66" ++
    "01ee6b01ee6b01ee7301ee7301ee7801ee7801ee7d01ee7d01ee7f01ee7f01ee8a01ee8a01ee9c01eea001eea401eea401eeaa01eeaa01eebc01eeef" ++
    "01eef201efff01f02c01f02f01f09401f09f01f0af01f0b001f0c001f0c001f0d001f0d001f0f601f0ff01f1ae01f1e501f20301f20f01f23c01f23f" ++
    "01f24901f24f01f25201f25f01f26601f2ff01f6d801f6db01f6ed01f6ef01f6fd01f6ff01f77701f77a01f7da01f7df01f7ec01f7ef01f7f101f7ff" ++
    "01f80c01f80f01f84801f84f01f85a01f85f01f88801f88f01f8ae01f8af01f8bc01f8bf01f8c201f8ff01fa5401fa5f01fa6e01fa6f01fa7d01fa7f" ++
    "01fa8a01fa8e01fac701facd01fadd01fade01faea01faef01faf901faff01fb9301fb9301fbfa01ffff02a6e002a6ff02b73a02b73f02b81e02b81f" ++
    "02cea202ceaf02ebe102ebef02ee5e02f7ff02fa1e02ffff03134b03134f0323b00e00000e00020e001f0e00800e00ff0e01f00effff0ffffe0fffff" ++
    "10fffe10ffff";

// Printable in Unicode 16 but unassigned in Unicode 15. Derived from
// UnicodeData.txt 15.0.0 (SHA-256 806e9aed65037197f1ec85e12be6e8cd870fc5608b4de0fffd990f689f376a73).
// All 5,812 code points are covered by these 50 intervals.
const assigned_in_16 =
    "000897000897001b4e001b4f001b7f001b7f001c89001c8a002427002429002ffc002fff0031e40031e50031ef0031ef" ++
    "00a7cb00a7cd00a7da00a7dc0105c00105f3010d40010d65010d69010d85010d8e010d8f010ec2010ec4010efc010efc" ++
    "01138001138901138b01138b01138e01138e0113900113b50113b70113c00113c20113c20113c50113c50113c70113ca" ++
    "0113cc0113d50113d70113d80113e10113e20116d00116e3011bc0011be1011bf0011bf9011f5a011f5a0134600143fa" ++
    "016100016139016d40016d79018cff018cff01cc0001ccf901cd0001ceb301e5d001e5fa01e5ff01e5ff01f8b201f8bb" ++
    "01f8c001f8c101fa8901fa8901fa8f01fa8f01fabe01fabe01fac601fac601fadc01fadc01fadf01fadf01fae901fae9" ++
    "01fbcb01fbef02ebf002ee5d";

fn unassignedCodepoint(cp: u21) bool {
    if (cp < 0x378) return false;
    return inRanges(cp, &unassigned_ranges) or inRanges(cp, &new_in_16_ranges);
}

fn inRanges(cp: u21, ranges: []const [2]u21) bool {
    var lo: usize = 0;
    var hi: usize = ranges.len;
    while (lo < hi) {
        const mid = lo + (hi - lo) / 2;
        const first = ranges[mid][0];
        const last = ranges[mid][1];
        if (cp < first) {
            hi = mid;
        } else if (cp > last) {
            lo = mid + 1;
        } else return true;
    }
    return false;
}

const unassigned_ranges = parseRanges(unassigned);
const new_in_16_ranges = parseRanges(assigned_in_16);

fn parseRanges(comptime text: []const u8) [text.len / 12][2]u21 {
    @setEvalBranchQuota(200_000);
    if (text.len % 12 != 0) @compileError("invalid Unicode interval table");
    var ranges: [text.len / 12][2]u21 = undefined;
    for (&ranges, 0..) |*entry, i| {
        const pair = text[i * 12 ..][0..12];
        entry.* = .{
            std.fmt.parseInt(u21, pair[0..6], 16) catch unreachable,
            std.fmt.parseInt(u21, pair[6..12], 16) catch unreachable,
        };
        if (entry.*[0] > entry.*[1] or (i != 0 and entry.*[0] <= ranges[i - 1][1]))
            @compileError("overlapping or unordered Unicode intervals");
    }
    return ranges;
}

// Terminal-only grammar from ukprint/console.c and snprintf.c. Other local
// assertions remain bounded substring markers, not host admission policies.
fn terminalBody(line: []const u8) ?[]const u8 {
    if (std.mem.startsWith(u8, line, "main returned ")) return line;
    if (line.len > 256) return null;
    var rest = line;
    if (std.mem.startsWith(u8, rest, "[")) {
        const end = std.mem.indexOf(u8, rest, "] ") orelse return null;
        const time = rest[1..end];
        const dot = std.mem.indexOfScalar(u8, time, '.') orelse return null;
        if (!padded(time[0..dot], 5, 20) or time.len - dot - 1 != 6) return null;
        for (time[dot + 1 ..]) |byte| if (!std.ascii.isDigit(byte)) return null;
        rest = rest[end + 2 ..];
    }
    if (!std.mem.startsWith(u8, rest, "Info: ")) return null;
    rest = rest["Info: ".len..];
    if (std.mem.startsWith(u8, rest, "<<n/a>> ")) {
        rest = rest["<<n/a>> ".len..];
    } else if (std.mem.startsWith(u8, rest, "<")) {
        const end = std.mem.indexOf(u8, rest, "> ") orelse return null;
        const thread = rest[1..end];
        if (!std.mem.eql(u8, thread, "main") and !std.mem.eql(u8, thread, "init") and !pointer(thread)) return null;
        rest = rest[end + 2 ..];
    }
    if (std.mem.startsWith(u8, rest, "{r:")) {
        const end = std.mem.indexOf(u8, rest, "} ") orelse return null;
        const caller = rest[3..end];
        const comma = std.mem.indexOf(u8, caller, ",f:") orelse return null;
        if (!pointer(caller[0..comma]) or !pointer(caller[comma + 3 ..])) return null;
        rest = rest[end + 2 ..];
    }
    if (!std.mem.startsWith(u8, rest, "[libukboot] ")) return null;
    rest = rest["[libukboot] ".len..];
    if (std.mem.startsWith(u8, rest, "<boot.c @ ")) {
        const end = std.mem.indexOf(u8, rest, "> ") orelse return null;
        const number = rest["<boot.c @ ".len..end];
        if (!padded(number, 4, 5) or std.mem.eql(u8, std.mem.trimStart(u8, number, " "), "0")) return null;
        rest = rest[end + 2 ..];
    }
    return if (std.mem.startsWith(u8, rest, "main returned ")) rest else null;
}

fn padded(text: []const u8, width: usize, maximum: usize) bool {
    const digits = std.mem.trimStart(u8, text, " ");
    if (digits.len == 0 or digits.len > maximum or text.len != @max(width, digits.len) or
        (digits.len > 1 and digits[0] == '0')) return false;
    for (digits) |byte| if (!std.ascii.isDigit(byte)) return false;
    _ = std.fmt.parseInt(u64, digits, 10) catch return false;
    return true;
}
fn pointer(text: []const u8) bool {
    if (std.mem.eql(u8, text, "0")) return true;
    if (text.len < 3 or text.len > 18 or !std.mem.startsWith(u8, text, "0x") or text[2] == '0') return false;
    for (text[2..]) |byte| if (!std.ascii.isDigit(byte) and (byte < 'a' or byte > 'f')) return false;
    return true;
}
