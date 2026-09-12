def integer:
  if type == "number" then . >= 0 and floor == . else false end;
def positive_integer:
  integer and . > 0;
def sha256:
  if type == "string" then test("^[0-9a-f]{64}$") else false end;
def file_proof:
  if type != "object" then false
  else
    keys == ([
      "path", "sha256", "size", "device_major", "device_minor", "inode",
      "uid", "mode", "links", "stable_identity_and_hash"
    ] | sort) and
    (.path | if type == "string" then startswith("/") else false end) and
    (.sha256 | sha256) and (.size | positive_integer) and
    (.device_major | integer) and (.device_minor | integer) and
    (.inode | positive_integer) and (.links | positive_integer) and
    .uid == $uid and (.mode | integer) and
    .mode >= 32768 and .mode < 36864 and .stable_identity_and_hash == true
  end;
def pair:
  if type != "object" then false
  elif keys != (["role", "raw", "candidate", "content"] | sort) then false
  elif (.raw | file_proof | not) or (.candidate | file_proof | not) then false
  elif (.content | type) != "object" then false
  else
    .candidate.size < .raw.size and .candidate.sha256 != .raw.sha256 and
    (.content.program_headers_sha256 | sha256) and
    (.content.loaded_content_sha256 | sha256) and
    (.content.load_segments | positive_integer) and
    (.content.loaded_file_bytes | positive_integer) and
    (.content.removed_debug_sections | positive_integer) and
    (.content.removed_debug_bytes | positive_integer) and
    .content.size_reduction == (.raw.size - .candidate.size)
  end;
if length != 1 then false
else .[0] |
if type != "object" then false
elif keys != ([
  "schema", "authority", "passed", "synthetic", "admitted",
  "qualification_only", "pairs", "external_fixture"
] | sort) then false
elif (.pairs | type) != "array" then false
else
  .schema == "hyperv_fixture_debug_stripping_v1" and
  .authority == "synthetic_only_not_admitted" and
  .passed == true and .synthetic == true and .admitted == false and
  .qualification_only == true and .external_fixture == null and
  (.pairs | length) == 2 and
  (.pairs | map(.role)) == ["namespace_helper", "namespace_fixture"] and
  all(.pairs[]; pair) and
  .pairs[1].candidate.sha256 == $fixture_sha and
  .pairs[1].candidate.size == $fixture_size
end
end
