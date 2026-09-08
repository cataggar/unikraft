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
