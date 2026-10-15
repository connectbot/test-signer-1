# Checked Hermit 0.13 compatibility fixes

The build helper copies the kernel from the exact Hermit dependency in Cargo.lock.
It checks upstream file hashes before applying replacements; it does not edit the
Cargo checkout. `upstream-sha256.json` and `replacements.json` are the patch inputs.
The guest build refuses an unpatched entropy implementation, and the build helper
also checks the linked binary for the strict entropy diagnostic and absence of
the old fallback warning.

- Entropy: fail stop if secure entropy cannot be read. The upstream syscall
  substituted a predictable Park-Miller generator. The application also checks
  real CPUID because the Rust Hermit target assumes RDSEED at compile time.
- TCP connect: bound the kernel's synchronous connect to 15 seconds. Hyper's
  Hermit connector performs it in a Tokio blocking task and propagates errors.
- TCP drop: abort nonblocking connections rather than waiting for the peer from
  their destructor. This avoids blocking the async executor; a client interrupted
  during close may need to retry.
- Executor timeout: convert Unix-epoch deadlines to remaining relative durations
  before waiting on a futex. The original passed an epoch deadline as a duration,
  causing requests to stall until another packet woke the guest.
- Scheduler wake: ignore a second wake notification for a task already made ready
  by its timer. The futex registration may remain briefly after timer expiry;
  the original assumed the task still appeared in the blocked queue and panicked.
- VirtIO network MTU: add the Ethernet header to receive/transmit buffer sizes
  and smoltcp's Ethernet frame limit. VirtIO advertises the IP MTU; smoltcp's
  Ethernet device limit includes the 14-byte link header. The original dropped
  packets above 8986 bytes with an advertised IP MTU of 9000.

These fixes were exercised with a real Hermit guest under QEMU TCG, including an
external collector outage without extra traffic to wake the guest. The negative
boot test without RDSEED halts before loading signing keys. Re-evaluate these
patches against upstream when upgrading the kernel; changed upstream files fail
the hash check deliberately.
