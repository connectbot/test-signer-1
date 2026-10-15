#!/usr/bin/env python3
"""Exercise the prepared kernel's actual eventfd code with cancelled poll waits."""
import argparse
import pathlib
import subprocess
import tempfile

p = argparse.ArgumentParser(description=__doc__)
p.add_argument("--kernel", required=True, type=pathlib.Path)
a = p.parse_args()
source = (a.kernel / "src/fd/eventfd.rs").read_text()
with tempfile.TemporaryDirectory(prefix="signer-eventfd-test-") as temporary:
    root = pathlib.Path(temporary)
    (root / "src").mkdir()
    (root / "Cargo.toml").write_text('''[package]
name = "signer-eventfd-regression"
version = "0.0.0"
edition = "2024"
[dependencies]
async-lock = "=3.4.2"
async-trait = "=0.1.89"
bitflags = "=2.11.0"
''')
    (root / "src/eventfd.rs").write_text(source)
    (root / "src/lib.rs").write_text(r'''
extern crate alloc;
macro_rules! debug { ($($arg:tt)*) => {}; }
mod errno { #[derive(Debug)] pub enum Errno { Inval, Again } }
mod io { pub type Result<T> = core::result::Result<T, crate::errno::Errno>; }
mod fd {
    bitflags::bitflags! {
        #[derive(Clone, Copy)]
        pub struct EventFlags: u32 { const EFD_NONBLOCK = 1; const EFD_SEMAPHORE = 2; }
        #[derive(Clone, Copy)]
        pub struct PollEvent: u32 {
            const POLLIN = 1; const POLLRDNORM = 2; const POLLRDBAND = 4;
            const POLLOUT = 8; const POLLWRNORM = 16; const POLLWRBAND = 32;
        }
    }
    #[async_trait::async_trait]
    pub trait ObjectInterface: Send + Sync {
        async fn read(&self, buf: &mut [u8]) -> crate::io::Result<usize>;
        async fn write(&self, buf: &[u8]) -> crate::io::Result<usize>;
        async fn poll(&self, event: PollEvent) -> crate::io::Result<PollEvent>;
    }
}
mod eventfd;
#[cfg(test)]
mod tests {
    use super::{eventfd::EventFd, fd::{EventFlags, ObjectInterface, PollEvent}};
    use std::{future::Future, pin::pin, sync::{Arc, atomic::{AtomicUsize, Ordering}}, task::{Context, Wake, Waker}};
    #[derive(Default)]
    struct Notifications(AtomicUsize);
    impl Wake for Notifications {
        fn wake(self: Arc<Self>) { self.0.fetch_add(1, Ordering::SeqCst); }
        fn wake_by_ref(self: &Arc<Self>) { self.0.fetch_add(1, Ordering::SeqCst); }
    }
    #[test]
    fn cancelled_poll_cannot_consume_live_waiters_notification() {
        for flags in [EventFlags::EFD_NONBLOCK, EventFlags::EFD_NONBLOCK | EventFlags::EFD_SEMAPHORE] {
            let fd = EventFd::new(0, flags);
            let old = Waker::from(Arc::new(Notifications::default()));
            // Match poll_fds: an unrelated descriptor becomes ready, dropping
            // this pending future. Its registration must not steal a wake.
            for _ in 0..16 {
                let mut cancelled = fd.poll(PollEvent::POLLIN);
                assert!(cancelled.as_mut().poll(&mut Context::from_waker(&old)).is_pending());
            }
            let live = Arc::new(Notifications::default());
            let waker = Waker::from(live.clone());
            let mut cx = Context::from_waker(&waker);
            let mut current = fd.poll(PollEvent::POLLIN);
            assert!(current.as_mut().poll(&mut cx).is_pending());
            let bytes = 1_u64.to_ne_bytes();
            assert!(pin!(fd.write(&bytes)).poll(&mut cx).is_ready());
            assert!(live.0.load(Ordering::SeqCst) > 0, "live reactor must wake");
            assert!(current.as_mut().poll(&mut cx).is_ready(), "readiness must be recomputed");
        }
    }
    #[test]
    fn draining_counter_wakes_blocked_writer() {
        let fd = EventFd::new(0, EventFlags::empty());
        let notifications = Arc::new(Notifications::default());
        let waker = Waker::from(notifications.clone());
        let mut cx = Context::from_waker(&waker);
        let full = (u64::MAX - 1).to_ne_bytes();
        assert!(pin!(fd.write(&full)).poll(&mut cx).is_ready());
        let one = 1_u64.to_ne_bytes();
        let mut writer = fd.write(&one);
        assert!(writer.as_mut().poll(&mut cx).is_pending());
        let mut buffer = [0; 8];
        assert!(pin!(fd.read(&mut buffer)).poll(&mut cx).is_ready());
        assert!(notifications.0.load(Ordering::SeqCst) > 0);
        assert!(writer.as_mut().poll(&mut cx).is_ready());
    }
}
''')
    subprocess.run(["cargo", "test", "--offline", "--manifest-path", str(root / "Cargo.toml")], check=True)
