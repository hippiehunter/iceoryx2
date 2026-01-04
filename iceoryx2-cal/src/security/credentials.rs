// Copyright (c) 2024 Contributors to the Eclipse Foundation
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

//! Process credentials for authentication and authorization.
//!
//! This module provides [`ProcessCredentials`], which represents the identity of a process
//! including its process ID (PID), user ID (UID), and group ID (GID).

extern crate alloc;

use core::fmt::Debug;

/// Process credentials containing identity information.
///
/// - `pid`: The process ID
/// - `uid`: The user ID of the process owner
/// - `gid`: The group ID of the process owner
/// - `start_time` (Unix only): Optional process start time for PID reuse detection
/// - `user_sid` (Windows only): Optional user Security Identifier (SID)
/// - `group_sids` (Windows only): Optional group SIDs the user belongs to
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct ProcessCredentials {
    pid: u32,
    uid: u32,
    gid: u32,
    #[cfg(unix)]
    start_time: Option<u64>,
    #[cfg(windows)]
    user_sid: Option<alloc::vec::Vec<u8>>,
    #[cfg(windows)]
    group_sids: Option<alloc::vec::Vec<alloc::vec::Vec<u8>>>,
}

impl ProcessCredentials {
    /// Creates new [`ProcessCredentials`] from the specified values.
    #[cfg(unix)]
    #[inline]
    pub const fn new(pid: u32, uid: u32, gid: u32) -> Self {
        Self {
            pid,
            uid,
            gid,
            start_time: None,
        }
    }

    /// Creates new [`ProcessCredentials`] from the specified values.
    #[cfg(windows)]
    #[inline]
    pub fn new(pid: u32, uid: u32, gid: u32) -> Self {
        Self {
            pid,
            uid,
            gid,
            user_sid: None,
            group_sids: None,
        }
    }

    /// Creates new [`ProcessCredentials`] from the specified values.
    #[cfg(not(any(unix, windows)))]
    #[inline]
    pub const fn new(pid: u32, uid: u32, gid: u32) -> Self {
        Self { pid, uid, gid }
    }

    /// Creates new [`ProcessCredentials`] with a start time for PID reuse detection.
    #[cfg(unix)]
    #[inline]
    pub const fn with_start_time(pid: u32, uid: u32, gid: u32, start_time: u64) -> Self {
        Self {
            pid,
            uid,
            gid,
            start_time: Some(start_time),
        }
    }

    /// Creates new [`ProcessCredentials`] with Windows SIDs.
    ///
    /// # Arguments
    /// * `pid` - Process ID
    /// * `user_sid` - The user's Security Identifier in binary form
    /// * `group_sids` - The group SIDs the user belongs to, each in binary form
    #[cfg(windows)]
    #[inline]
    pub fn with_sids(
        pid: u32,
        user_sid: alloc::vec::Vec<u8>,
        group_sids: alloc::vec::Vec<alloc::vec::Vec<u8>>,
    ) -> Self {
        Self {
            pid,
            uid: 0,
            gid: 0,
            user_sid: Some(user_sid),
            group_sids: Some(group_sids),
        }
    }

    /// Creates [`ProcessCredentials`] for the current process.
    #[cfg(unix)]
    #[inline]
    pub fn from_self() -> Self {
        use iceoryx2_bb_posix::process::Process;
        use iceoryx2_bb_posix::user::User;

        let process = Process::from_self();
        let pid = process.id().value() as u32;

        // Get uid and gid from user - fallback to 0 if unavailable
        let (uid, gid) = match User::from_self() {
            Ok(user) => {
                let uid = user.uid().value();
                let gid = user.details().map(|d| d.gid().value()).unwrap_or(0);
                (uid, gid)
            }
            Err(_) => (0, 0),
        };

        Self {
            pid,
            uid,
            gid,
            start_time: None,
        }
    }

    /// Creates [`ProcessCredentials`] for the current process.
    #[cfg(windows)]
    #[inline]
    pub fn from_self() -> Self {
        use iceoryx2_bb_posix::process::Process;
        use iceoryx2_bb_posix::user::User;

        let process = Process::from_self();
        let pid = process.id().value() as u32;

        // Get uid and gid from user - fallback to 0 if unavailable
        let (uid, gid) = match User::from_self() {
            Ok(user) => {
                let uid = user.uid().value();
                let gid = user.details().map(|d| d.gid().value()).unwrap_or(0);
                (uid, gid)
            }
            Err(_) => (0, 0),
        };

        Self {
            pid,
            uid,
            gid,
            user_sid: None,
            group_sids: None,
        }
    }

    /// Creates [`ProcessCredentials`] for the current process.
    #[cfg(not(any(unix, windows)))]
    #[inline]
    pub fn from_self() -> Self {
        use iceoryx2_bb_posix::process::Process;
        use iceoryx2_bb_posix::user::User;

        let process = Process::from_self();
        let pid = process.id().value() as u32;

        // Get uid and gid from user - fallback to 0 if unavailable
        let (uid, gid) = match User::from_self() {
            Ok(user) => {
                let uid = user.uid().value();
                let gid = user.details().map(|d| d.gid().value()).unwrap_or(0);
                (uid, gid)
            }
            Err(_) => (0, 0),
        };

        Self { pid, uid, gid }
    }

    /// Creates [`ProcessCredentials`] for the current process with start time.
    #[cfg(unix)]
    pub fn from_self_with_start_time() -> Option<Self> {
        use iceoryx2_bb_posix::process::Process;
        use iceoryx2_bb_posix::user::User;

        let process = Process::from_self();
        let pid = process.id().value() as u32;

        // Get uid and gid from user - fallback to 0 if unavailable
        let (uid, gid) = match User::from_self() {
            Ok(user) => {
                let uid = user.uid().value();
                let gid = user.details().map(|d| d.gid().value()).unwrap_or(0);
                (uid, gid)
            }
            Err(_) => (0, 0),
        };

        let start_time = Self::read_start_time_for_pid(pid)?;

        Some(Self {
            pid,
            uid,
            gid,
            start_time: Some(start_time),
        })
    }

    /// Reads the start time for a given process ID from `/proc/<pid>/stat`.
    #[cfg(target_os = "linux")]
    fn read_start_time_for_pid(pid: u32) -> Option<u64> {
        use std::fs;
        use std::io::Read;

        let path = if pid == std::process::id() {
            "/proc/self/stat".to_string()
        } else {
            format!("/proc/{}/stat", pid)
        };

        let mut file = fs::File::open(&path).ok()?;
        let mut contents = String::new();
        file.read_to_string(&mut contents).ok()?;

        // Find closing paren to skip comm field (may contain spaces)
        let closing_paren = contents.rfind(')')?;
        let after_comm = &contents[closing_paren + 2..];

        // Field 19 after comm is starttime
        let fields: Vec<&str> = after_comm.split_whitespace().collect();
        if fields.len() > 19 {
            fields[19].parse().ok()
        } else {
            None
        }
    }

    /// Fallback for non-Linux Unix systems
    #[cfg(all(unix, not(target_os = "linux")))]
    fn read_start_time_for_pid(_pid: u32) -> Option<u64> {
        None
    }

    /// Returns the process ID.
    #[inline]
    pub const fn pid(&self) -> u32 {
        self.pid
    }

    /// Returns the user ID.
    #[inline]
    pub const fn uid(&self) -> u32 {
        self.uid
    }

    /// Returns the group ID.
    #[inline]
    pub const fn gid(&self) -> u32 {
        self.gid
    }

    /// Returns the process start time if available.
    #[cfg(unix)]
    #[inline]
    pub const fn start_time(&self) -> Option<u64> {
        self.start_time
    }

    /// Returns `None` on non-Unix platforms.
    #[cfg(not(unix))]
    #[inline]
    pub const fn start_time(&self) -> Option<u64> {
        None
    }

    /// Returns the user's Security Identifier (SID) if available.
    ///
    /// This is only available on Windows when SIDs were successfully extracted
    /// from the process token.
    #[cfg(windows)]
    #[inline]
    pub fn user_sid(&self) -> Option<&[u8]> {
        self.user_sid.as_deref()
    }

    /// Returns `None` on non-Windows platforms.
    #[cfg(not(windows))]
    #[inline]
    pub fn user_sid(&self) -> Option<&[u8]> {
        None
    }

    /// Returns the group SIDs if available.
    ///
    /// This is only available on Windows when SIDs were successfully extracted
    /// from the process token.
    #[cfg(windows)]
    #[inline]
    pub fn group_sids(&self) -> Option<&[alloc::vec::Vec<u8>]> {
        self.group_sids.as_deref()
    }

    /// Returns `None` on non-Windows platforms.
    #[cfg(not(windows))]
    #[inline]
    pub fn group_sids(&self) -> Option<&[alloc::vec::Vec<u8>]> {
        None
    }

    /// Checks if the process is a member of the specified group SID.
    ///
    /// # Arguments
    /// * `group_sid` - The group SID to check membership for (in binary form)
    ///
    /// # Returns
    /// * `true` if the process is a member of the group
    /// * `false` if the process is not a member or SIDs are not available
    #[cfg(windows)]
    #[inline]
    pub fn is_member_of(&self, group_sid: &[u8]) -> bool {
        match &self.group_sids {
            Some(groups) => groups.iter().any(|sid| sid.as_slice() == group_sid),
            None => false,
        }
    }

    /// Always returns `false` on non-Windows platforms.
    #[cfg(not(windows))]
    #[inline]
    pub fn is_member_of(&self, _group_sid: &[u8]) -> bool {
        false
    }

    /// Checks if this process is likely still the same process.
    #[cfg(unix)]
    pub fn is_same_process(&self) -> bool {
        match self.start_time {
            Some(stored_start_time) => match Self::read_start_time_for_pid(self.pid) {
                Some(current_start_time) => stored_start_time == current_start_time,
                None => false,
            },
            None => true,
        }
    }

    /// On non-Unix platforms, always returns `true`.
    #[cfg(not(unix))]
    #[inline]
    pub fn is_same_process(&self) -> bool {
        true
    }
}

impl Debug for ProcessCredentials {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let mut debug_struct = f.debug_struct("ProcessCredentials");
        debug_struct
            .field("pid", &self.pid)
            .field("uid", &self.uid)
            .field("gid", &self.gid);

        #[cfg(unix)]
        {
            debug_struct.field("start_time", &self.start_time);
        }

        #[cfg(windows)]
        {
            debug_struct.field("user_sid", &self.user_sid.as_ref().map(|s| s.len()));
            debug_struct.field("group_sids", &self.group_sids.as_ref().map(|g| g.len()));
        }

        debug_struct.finish()
    }
}

impl core::fmt::Display for ProcessCredentials {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "ProcessCredentials {{ pid: {}, uid: {}, gid: {} }}",
            self.pid, self.uid, self.gid
        )
    }
}
