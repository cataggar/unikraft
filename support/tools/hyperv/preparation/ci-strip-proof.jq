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
    (.sha256 | sha256) and (.size | positive_integer) and .size <= 67108864 and
    (.device_major | integer) and (.device_minor | integer) and
    (.inode | positive_integer) and (.links | positive_integer) and
    .uid == $uid and (.mode | integer) and
    .mode >= 32768 and .mode < 36864 and .stable_identity_and_hash == true
  end;
def logical_mapping:
  if type != "object" then false
  else
    keys == (["type", "flags", "virtual_address", "physical_address",
      "file_bytes", "memory_bytes", "alignment"] | sort) and
    all(.[]; integer)
  end;
def program_mapping:
  if type != "object" then false
  elif keys != (["index", "raw_offset", "candidate_offset", "changed",
    "offset_field_file_offset", "offset_field_width",
    "logical_mapping", "logical_mapping_sha256"] | sort) then false
  elif (.logical_mapping | logical_mapping | not) then false
  else
    (.index | integer) and (.raw_offset | integer) and
    (.candidate_offset | integer) and
    (.offset_field_file_offset | positive_integer) and .offset_field_width == 8 and
    (.logical_mapping_sha256 | sha256) and
    .changed == (.raw_offset != .candidate_offset) and
    (if .changed then
      $layout_policy == "file_offset_relayout" and .logical_mapping.file_bytes > 0
    else true end)
  end;
def content_proof:
  if type != "object" then false
  elif (.program_mappings | type) != "array" then false
  else
    .elf_class == "elf64" and (.endian == "little" or .endian == "big") and
    .layout_policy == $layout_policy and
    (.raw_program_headers_sha256 | sha256) and
    (.candidate_program_headers_sha256 | sha256) and
    (.normalized_program_headers_sha256 | sha256) and
    (.mapped_program_content_sha256 | sha256) and
    (.mapped_loaded_content_sha256 | sha256) and
    (.program_mappings | length) > 0 and (.program_mappings | length) <= 128 and
    (.program_mappings | to_entries |
      all(.[]; .key == .value.index and (.value | program_mapping))) and
    ((.program_mappings | any(.[]; .changed)) ==
      (.raw_program_headers_sha256 != .candidate_program_headers_sha256)) and
    (if .machine == "X86_64" then .load_offset_modulus == 4096
     elif .machine == "AARCH64" then .load_offset_modulus == 65536
     else false end) and
    (.load_segments | positive_integer) and
    (.loaded_file_bytes | positive_integer) and
    (.removed_debug_sections | positive_integer) and
    (.removed_debug_bytes | positive_integer)
  end;
def pair:
  if type != "object" then false
  elif keys != (["role", "raw", "candidate", "content"] | sort) then false
  elif (.raw | file_proof | not) or (.candidate | file_proof | not) then false
  elif (.content | content_proof | not) then false
  else
    . as $pair |
    .candidate.size < .raw.size and .candidate.sha256 != .raw.sha256 and
    all(.content.program_mappings[];
      (.raw_offset + .logical_mapping.file_bytes) <= $pair.raw.size and
      (.candidate_offset + .logical_mapping.file_bytes) <= $pair.candidate.size and
      (.offset_field_file_offset + .offset_field_width) <= $pair.raw.size and
      (.offset_field_file_offset + .offset_field_width) <= $pair.candidate.size) and
    .content.size_reduction == (.raw.size - .candidate.size)
  end;
if length != 1 then false
else .[0] |
if type != "object" then false
elif keys != ([
  "schema", "authority", "passed", "synthetic", "admitted",
  "qualification_only", "layout_policy", "pairs", "external_fixture"
] | sort) then false
elif (.pairs | type) != "array" then false
else
  .schema == "hyperv_fixture_debug_stripping_v2" and
  .authority == "synthetic_only_not_admitted" and
  .passed == true and .synthetic == true and .admitted == false and
  .qualification_only == true and .external_fixture == null and
  .layout_policy == $layout_policy and
  (.pairs | length) == 2 and
  (.pairs | map(.role)) == ["namespace_helper", "namespace_fixture"] and
  all(.pairs[]; pair) and
  .pairs[1].candidate.sha256 == $fixture_sha and
  .pairs[1].candidate.size == $fixture_size
end
end
