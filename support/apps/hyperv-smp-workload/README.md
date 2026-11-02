# Hyper-V fixed scheduled-SMP workload proof

This opt-in image keeps device and control workers on the BSP and runs three
separate bounded proofs on CPU 1:

- `UK_HYPERV_AP_EXEC`: an ISR-context `uk_lcpu_run()` callback;
- `UK_HYPERV_SCHED_THREAD`: a persistent cooperative-scheduler thread with
  isolated, stable TLS;
- `UK_HYPERV_REMOTE_WAKE`: repeated worker block, AP idle, BSP publication and
  wake IPI, AP resume, and AP-to-BSP completion.

`UK_HYPERV_SMP_WORKLOAD_READY PASS` is emitted only after all three pass. A
hosted fixture or an exact-image build is not a substitute for this marker
from a real Hyper-V guest.

The application retains the native image graph's `apphelloworld` compatibility
library name; its serial markers and behavior are scheduled-SMP-specific.

The supplied configuration requires two CPUs. Use `--cpus 2` with
`support/build/tests/hyperv-efi-boot-test.py` and require all three stage
markers plus `UK_HYPERV_SMP_WORKLOAD_READY PASS`. That helper defaults to one
CPU for existing smoke callers and rejects multi-CPU legacy-xAPIC requests.

CI packages the exact EFI payload into a raw GPT disk with the pinned `miz`
tool and passes `--raw-disk` to boot that same disk read-only. This avoids
QEMU's `fat:` protocol, which is absent from the pinned minimal QEMU bundle.
The existing `--image` convenience path still requires that protocol.
