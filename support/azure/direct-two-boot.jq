# SPDX-License-Identifier: BSD-3-Clause
# ARM sometimes renders integer fields as decimal strings. Reject fractional
# numbers, signed/whitespace/exponent/leading-zero strings, null, or booleans.
def uint:
  if type == "number" then
    if . >= 0 and . <= 9007199254740991 and floor == . then . else error("integer") end
  elif type == "string" and test("^(0|[1-9][0-9]*)$") then
    tonumber | if . <= 9007199254740991 then . else error("integer range") end
  else error("integer type") end;
def owned($id; $owner; $prefix; $sha):
  .id == $id and .tags["uk-direct-run"] == $owner and
  .tags["unikraft-run"] == $prefix and .tags["image-sha256"] == $sha and
  .tags["managed-by"] == "unikraft-hyperv";
def grant:
  if type == "object" and ((keys == ["accessSAS"]) or (keys == ["accessSas"])) then
    .[] | if type == "string" and
      test("^https://[a-z0-9][a-z0-9.-]+\\.blob\\.(core\\.windows\\.net|storage\\.azure\\.net)(:443|:8443)?/[^?#[:space:]]+\\?[^?#[:space:]]+$")
      then . else error("grant value") end
  else error("grant shape") end;
def power:
  (if has("instanceView") and (has("statuses") | not) then .instanceView.statuses
   elif has("statuses") and (has("instanceView") | not) then .statuses
   else error("power shape") end) |
  map(select(.code | startswith("PowerState/"))) |
  if length == 1 then .[0].code else error("power count") end;
