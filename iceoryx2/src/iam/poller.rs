// Copyright (c) 2026 Contributors to the Eclipse Foundation
//
// See the NOTICE file(s) distributed with this work for additional
// information regarding copyright ownership.
//
// This program and the accompanying materials are made available under the
// terms of the Apache Software License 2.0 which is available at
// https://www.apache.org/licenses/LICENSE-2.0, or the MIT license
// which is available at https://opensource.org/licenses/MIT.
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Readiness polling for the IAM server thread.
//!
//! The IAM server used to sleep 10 ms between passes and, on every pass, try a non-blocking
//! receive on every session. With thousands of sessions that costs O(sessions) syscalls a hundred
//! times per second even when nobody talks to the server, and every request/response round trip
//! waits for the next pass (10 ms + pass time). On Linux the server instead waits in `epoll` for
//! the listener and the session sockets that actually have data, and is woken immediately for
//! shutdown.

#[cfg(target_os = "linux")]
mod imp {
    use alloc::vec::Vec;
    use core::time::Duration;
    use iceoryx2_pal_os_api::linux;
    use iceoryx2_pal_posix::posix;

    /// Marks the wake-up socket in epoll's event data (file descriptors are never negative).
    const WAKE_TOKEN: u64 = u64::MAX;
    const MAX_EVENTS: usize = 1024;

    /// epoll set over the IAM listener and session sockets plus a wake-up socket pair.
    #[derive(Debug)]
    pub(crate) struct Poller {
        epoll_fd: i32,
        wake_rx: i32,
        wake_tx: i32,
    }

    // SAFETY: the descriptors are plain integers owned by this struct; epoll_ctl/epoll_wait and
    // write are thread safe.
    unsafe impl Send for Poller {}
    unsafe impl Sync for Poller {}

    impl Poller {
        /// Creates the poller, or `None` if epoll or the socket pair cannot be created (the
        /// server then falls back to periodic polling).
        pub(crate) fn new() -> Option<Self> {
            let epoll_fd = unsafe { linux::epoll_create1(linux::EPOLL_CLOEXEC as _) };
            if epoll_fd < 0 {
                return None;
            }
            let mut fds: [posix::int; 2] = [-1, -1];
            let rc = unsafe {
                posix::socketpair(
                    posix::AF_UNIX as _,
                    posix::SOCK_STREAM | posix::SOCK_NONBLOCK,
                    0,
                    fds.as_mut_ptr(),
                )
            };
            if rc != 0 {
                unsafe { posix::close(epoll_fd) };
                return None;
            }
            let poller = Self {
                epoll_fd,
                wake_rx: fds[0],
                wake_tx: fds[1],
            };
            if !poller.ctl_add(poller.wake_rx, WAKE_TOKEN) {
                return None;
            }
            Some(poller)
        }

        fn ctl_add(&self, fd: i32, token: u64) -> bool {
            let mut event: linux::epoll_event = unsafe { core::mem::zeroed() };
            event.events = linux::EPOLL_EVENTS_EPOLLIN as u32;
            event.u64 = token;
            unsafe {
                linux::epoll_ctl(self.epoll_fd, linux::EPOLL_CTL_ADD as _, fd, &mut event) == 0
            }
        }

        /// Watches `fd` for readability (data, a pending connection, EOF or an error).
        pub(crate) fn add(&self, fd: i32) -> bool {
            fd >= 0 && self.ctl_add(fd, fd as u64)
        }

        /// Stops watching `fd`. Must be called before `fd` is closed.
        pub(crate) fn remove(&self, fd: i32) {
            if fd >= 0 {
                unsafe {
                    linux::epoll_ctl(
                        self.epoll_fd,
                        linux::EPOLL_CTL_DEL as _,
                        fd,
                        core::ptr::null_mut(),
                    )
                };
            }
        }

        /// Waits up to `timeout` and appends the ready descriptors to `ready`. Returns `true` if
        /// [`wake`](Self::wake) was called.
        pub(crate) fn wait(&self, timeout: Duration, ready: &mut Vec<i32>) -> bool {
            let mut events: Vec<linux::epoll_event> = Vec::with_capacity(MAX_EVENTS);
            let timeout_ms = timeout.as_millis().min(i32::MAX as u128) as i32;
            let n = unsafe {
                linux::epoll_wait(
                    self.epoll_fd,
                    events.as_mut_ptr(),
                    MAX_EVENTS as _,
                    timeout_ms,
                )
            };
            if n <= 0 {
                return false;
            }
            unsafe { events.set_len(n as usize) };
            let mut woken = false;
            for event in &events {
                let token = event.u64;
                if token == WAKE_TOKEN {
                    woken = true;
                    let mut buffer = [0u8; 64];
                    while unsafe {
                        posix::read(self.wake_rx, buffer.as_mut_ptr().cast(), buffer.len())
                    } > 0
                    {}
                } else {
                    ready.push(token as i32);
                }
            }
            woken
        }

        /// Interrupts a [`wait`](Self::wait) in another thread.
        pub(crate) fn wake(&self) {
            let byte = 1u8;
            unsafe { posix::write(self.wake_tx, (&byte as *const u8).cast(), 1) };
        }
    }

    impl Drop for Poller {
        fn drop(&mut self) {
            unsafe {
                posix::close(self.wake_tx);
                posix::close(self.wake_rx);
                posix::close(self.epoll_fd);
            }
        }
    }
}

#[cfg(not(target_os = "linux"))]
mod imp {
    use alloc::vec::Vec;
    use core::time::Duration;

    /// Placeholder: other platforms keep the periodic polling loop.
    #[derive(Debug)]
    pub(crate) struct Poller;

    impl Poller {
        pub(crate) fn new() -> Option<Self> {
            None
        }
        pub(crate) fn add(&self, _fd: i32) -> bool {
            false
        }
        pub(crate) fn remove(&self, _fd: i32) {}
        pub(crate) fn wait(&self, _timeout: Duration, _ready: &mut Vec<i32>) -> bool {
            false
        }
        pub(crate) fn wake(&self) {}
    }
}

pub(crate) use imp::Poller;
