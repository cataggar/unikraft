if length != 1 then false
else .[0] |
  type == "object" and
  keys == (["schema", "authority", "vm_uuid", "nonce", "test_user", "uid", "gid",
    "source_root", "test_root", "image_sha256", "kernel_sha256", "initrd_sha256",
    "python_guard"] | sort) and
  .schema == "unikraft_fixture_vm_v1" and
  .authority == "disposable_test_only_not_admitted" and
  (.vm_uuid | test("^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")) and
  (.nonce | test("^[0-9a-f]{32}$")) and
  .test_user == "uktest" and .uid == 1001 and .gid == 1001 and
  .source_root == "/work/unikraft" and
  .test_root == "/work/hyperv-ci/native-preparation" and
  .image_sha256 == "612b2c0cc1bc413a6cb8c38fd611794caf0f2b436c50013d8b3794db12ad7354" and
  .kernel_sha256 == "0066409132868538bc0c9076f60131025775d5bbd8617df074d059f91b584918" and
  .initrd_sha256 == "e7732308dee547d2455f6203b664d4ff47da050227fd6f2ad6a331dbff4ec0d2" and
  .python_guard == true
end
