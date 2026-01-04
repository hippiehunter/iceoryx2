// Copyright (c) 2023 Contributors to the Eclipse Foundation
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

//! Provides an abstraction of [`Process`]es in a POSIX system.
//!
//! # Scheduler & Priorities
//!
//! The priority is independent of the scheduler and 0 is
//! always the lowest and 255 always the highest priority. Internally, the scheduler dependent
//! priority is mapped to the scheduler independent range from 0..255.
//! A disadvantage can arise when the schedulers dependent priority range is either much more
//! fine grained or coarse. But this should be negligible since most scheduler priorities have
//! a range of about 50.
//! The granularity of a [`Scheduler`] can be acquired with [`Scheduler::priority_granularity()`].
//!
//! # Examples
//!
//! ```no_run
//! # extern crate iceoryx2_loggers;
//!
//! use iceoryx2_bb_posix::process::*;
//! use iceoryx2_bb_posix::scheduler::*;
//!
//! let it_represents_my_process = Process::from_self();
//! let it_represents_my_processes_parent = Process::from_parent();
//! let mut process = Process::from_pid(ProcessId::new(123));
//!
//! process.set_scheduler(Scheduler::Fifo).expect("failed to set scheduler");
//! process.set_priority(100).expect("failed to set priority");
//!
//! println!("pid: {:?}, scheduler: {:?}, prio: {}", process.id(),
//!             process.get_scheduler().expect("failed to get scheduler"),
//!             process.get_priority().expect("failed to get priority"));
//! ```
use core::fmt::Display;

use alloc::format;

use iceoryx2_bb_elementary::enum_gen;
use iceoryx2_bb_system_types::file_path::*;
use iceoryx2_log::{fail, trace};
use iceoryx2_pal_posix::posix::{errno::Errno, MemZeroedStruct};
use iceoryx2_pal_posix::*;

use crate::file_descriptor::{FileDescriptor, FileDescriptorBased, FileDescriptorManagement};
use crate::{
    scheduler::{Scheduler, SchedulerConversionError},
    signal::Signal,
};

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum ProcessExecutablePathError {
    ContainsInvalidCharacters,
    UnableToRead,
}

enum_gen! { ProcessSendSignalError
  entry:
    InsufficientPermissions,
    UnknownProcessId,
    UnknownError(i32)
}

enum_gen! { ProcessGetSchedulerError
  entry:
    InsufficientPermissions,
    UnknownProcessId,
    UnknownError(i32)

  mapping:
    SchedulerConversionError
}

enum_gen! { ProcessSetSchedulerError
  entry:
    InsufficientPermissions,
    UnknownProcessId,
    UnknownError(i32)

  mapping:
    SchedulerConversionError
}

/// Error that can occur when creating a PidFd.
#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
pub enum PidFdCreationError {
    /// The process does not exist.
    ProcessDoesNotExist,
    /// Insufficient permissions to open pidfd.
    InsufficientPermissions,
    /// The per-process file handle limit was reached.
    PerProcessFileHandleLimitReached,
    /// The system-wide file handle limit was reached.
    SystemWideFileHandleLimitReached,
    /// Insufficient memory.
    InsufficientMemory,
    /// pidfd_open is not supported (requires Linux 5.3+).
    NotSupported,
    /// Failed to read start_time from /proc.
    FailedToReadStartTime,
    /// Unknown error.
    UnknownError(i32),
}

enum_gen! {
    /// The ProcessError enum is a generalization when one doesn't require the fine-grained error
    /// handling enums. One can forward ProcessError as more generic return value when a method
    /// returns a Process***Error.
    /// On a higher level it is again convertable to [`crate::Error`].
    ProcessError
  generalization:
    FailedToSetSchedulerSettings <= ProcessSetSchedulerError,
    FailedToGetSchedulerSettings <= ProcessGetSchedulerError,
    FailedToSendSignal <= ProcessSendSignalError,
    PidFdFailed <= PidFdCreationError
}

/// Trait to be able to convert integers into processes by interpreting their value as the
/// process id
pub trait ProcessExt {
    fn as_process(&self) -> Process;
}

impl ProcessExt for posix::pid_t {
    fn as_process(&self) -> Process {
        Process::from_pid(ProcessId::new(*self))
    }
}

/// Represents a process id.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct ProcessId(posix::pid_t);

impl ProcessId {
    /// Creates a new process id.
    pub fn new(value: posix::pid_t) -> Self {
        ProcessId(value)
    }

    /// Returns the underlying integer value of the process id
    pub fn value(&self) -> posix::pid_t {
        self.0
    }
}

impl Display for ProcessId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Represent a process in a POSIX system.
#[derive(Debug)]
pub struct Process {
    pid: ProcessId,
}

impl Process {
    /// Creates a process from a provided id. The process does not have to exists at the time of
    /// creation. But all other methods may fail when the process does not exist.
    pub fn from_pid(pid: ProcessId) -> Process {
        Process { pid }
    }

    /// Create a process object from own process.
    pub fn from_self() -> Process {
        Process {
            pid: unsafe { ProcessId::new(posix::getpid()) },
        }
    }

    /// Create a process object from the parents process.
    pub fn from_parent() -> Process {
        Process {
            pid: unsafe { ProcessId::new(posix::getppid()) },
        }
    }

    /// Checks if the process is still alive
    pub fn is_alive(&self) -> bool {
        unsafe { posix::kill(self.pid.0, 0_i32) == 0 }
    }

    /// Returns the id of the process.
    pub fn id(&self) -> ProcessId {
        self.pid
    }

    /// Returns the executable path of the [`Process`].
    pub fn executable(&self) -> Result<FilePath, ProcessExecutablePathError> {
        let msg = "Unable to read executable path";
        let mut buffer = [0u8; FilePath::max_len()];
        let path_len =
            unsafe { posix::proc_pidpath(self.pid.0, buffer.as_mut_ptr().cast(), buffer.len()) };
        if path_len < 0 {
            fail!(from self, with ProcessExecutablePathError::UnableToRead,
                "{} since the name could not be acquired.", msg);
        }

        let path = fail!(from self,
                            when FilePath::new(&buffer[..(path_len as usize)]),
                            with ProcessExecutablePathError::ContainsInvalidCharacters,
                            "{} since the acquired name contains invalid characters.", msg);

        Ok(path)
    }

    /// Sends a signal to the process.
    pub fn send_signal(&self, signal: Signal) -> Result<(), ProcessSendSignalError> {
        if unsafe { posix::kill(self.pid.0, signal as i32) } == 0 {
            return Ok(());
        }

        let msg = "Unable to send signal to process";
        handle_errno!(ProcessSendSignalError, from self,
            Errno::EPERM => (InsufficientPermissions, "{} due to insufficient permissions.", msg),
            Errno::ESRCH => (UnknownProcessId, "{} since the process does not exist.", msg),
            v => (UnknownError(v as i32), "{} since an unknown error occurred ({}).", msg,v)
        );
    }

    /// Returns the priority of the process. 0 is the lowest and 255 the highest priority.
    pub fn get_priority(&self) -> Result<u8, ProcessGetSchedulerError> {
        let msg = "Unable to acquire priority of process";
        let scheduler = fail!(from self, when self.get_scheduler(), "{} due to a failure while getting the current scheduler of the process.", msg);

        let mut param = posix::sched_param::new_zeroed();
        if unsafe { posix::sched_getparam(self.pid.0, &mut param) } == 0 {
            return Ok(scheduler.get_priority_from(&param));
        }

        handle_errno!(ProcessGetSchedulerError, from self,
            Errno::EPERM => (InsufficientPermissions, "{} due to insufficient permissions.", msg),
            Errno::ESRCH => (UnknownProcessId, "{} since the process cannot be found on the system.", msg),
            v => (UnknownError(v as i32), "{} since an unknown error occurred ({}).", msg, v)
        );
    }

    /// Set the priority of the process. 0 is the lowest priority and 255 the highest.
    pub fn set_priority(&mut self, priority: u8) -> Result<(), ProcessGetSchedulerError> {
        let msg = "Unable to set process priority";
        let scheduler = fail!(from self, when self.get_scheduler(), "{} due to a failure while acquiring the current process scheduler.", msg);
        let mut param = posix::sched_param::new_zeroed();
        param.sched_priority = scheduler.policy_specific_priority(priority);

        if unsafe { posix::sched_setparam(self.pid.0, &param) } == 0 {
            return Ok(());
        }

        handle_errno!(ProcessGetSchedulerError, from self,
            Errno::EPERM => (InsufficientPermissions, "{} due to insufficient permissions.", msg),
            Errno::ESRCH => (UnknownProcessId, "{} since the process cannot be found on the system.", msg),
            v => (UnknownError(v as i32), "{} since an unknown error occurred ({}).", msg, v)
        );
    }

    /// Returns the currently in use [`Scheduler`] by the process.
    pub fn get_scheduler(&self) -> Result<Scheduler, ProcessGetSchedulerError> {
        let msg = "Unable to acquire scheduler of process";
        let v = unsafe { posix::sched_getscheduler(self.pid.0) };
        if v != -1 {
            return Ok(
                fail!(from self, when Scheduler::from_int(v), "{} since the scheduler seems to be unknown.", msg),
            );
        }

        handle_errno!(ProcessGetSchedulerError, from self,
            Errno::EPERM => (InsufficientPermissions, "{} due to insufficient permissions.", msg),
            Errno::ESRCH => (UnknownProcessId, "{} since the process cannot be found on the system.", msg),
            v => (UnknownError(v as i32), "{} since an unknown error occurred ({}).", msg, v)
        );
    }

    /// Sets a new [`Scheduler`] for the process and returns the formerly used [`Scheduler`]
    /// on success.
    pub fn set_scheduler(
        &mut self,
        scheduler: Scheduler,
    ) -> Result<Scheduler, ProcessSetSchedulerError> {
        let msg = "Unable to set scheduler of process";
        let mut param = posix::sched_param::new_zeroed();
        param.sched_priority = scheduler.policy_specific_priority(0);
        let former_scheduler =
            unsafe { posix::sched_setscheduler(self.pid.0, scheduler as i32, &param) };

        if former_scheduler != -1 {
            return Ok(fail!(from self, when Scheduler::from_int(former_scheduler),
                    "The previous set up scheduler is not supported. New scheduler was successfully set but cannot reverted to previous scheduler."));
        }

        handle_errno!(ProcessSetSchedulerError, from self,
            Errno::EPERM => (InsufficientPermissions, "{} due to insufficient permissions.", msg),
            Errno::ESRCH => (UnknownProcessId, "{} since the process cannot be found on the system.", msg),
            v => (UnknownError(v as i32), "{} since an unknown error occurred ({}).", msg,v)
        );
    }
}

/// Represents a unique identity for a process, combining PID and start_time.
/// This allows for reliable process identification even after PID reuse.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ProcessIdentity {
    /// The process ID.
    pid: ProcessId,
    /// The start time of the process (from /proc/[pid]/stat field 22).
    start_time: u64,
}

impl ProcessIdentity {
    /// Returns the process ID.
    pub fn pid(&self) -> ProcessId {
        self.pid
    }

    /// Returns the start time.
    pub fn start_time(&self) -> u64 {
        self.start_time
    }
}

impl Display for ProcessIdentity {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "ProcessIdentity {{ pid: {}, start_time: {} }}",
            self.pid, self.start_time
        )
    }
}

/// A PidFd wraps a file descriptor obtained from pidfd_open.
/// It provides a race-free way to refer to a process and check if it's still alive.
/// The PidFd also stores the process start_time for reliable identification.
///
/// # Example
///
/// ```ignore
/// use iceoryx2_bb_posix::process::*;
///
/// // Create a PidFd for a known process
/// let pidfd = PidFd::new(ProcessId::new(1234)).expect("failed to create pidfd");
///
/// println!("PID: {:?}", pidfd.pid());
/// println!("Start time: {}", pidfd.start_time());
/// println!("Is alive: {}", pidfd.is_alive());
///
/// // Create a PidFd for the current process
/// let self_pidfd = PidFd::from_self().expect("failed to create self pidfd");
/// ```
#[derive(Debug)]
pub struct PidFd {
    file_descriptor: FileDescriptor,
    pid: ProcessId,
    start_time: u64,
}

impl PidFd {
    /// Creates a new PidFd for the given process ID.
    /// Also reads the start_time from /proc/[pid]/stat for reliable identification.
    pub fn new(pid: ProcessId) -> Result<Self, PidFdCreationError> {
        let msg = "Unable to create PidFd";

        // Open the pidfd
        let raw_fd = unsafe { posix::pidfd_open(pid.value(), 0) };

        if raw_fd < 0 {
            handle_errno!(PidFdCreationError, from "PidFd::new",
                Errno::ESRCH => (ProcessDoesNotExist, "{} since the process does not exist.", msg),
                Errno::EPERM => (InsufficientPermissions, "{} due to insufficient permissions.", msg),
                Errno::EMFILE => (PerProcessFileHandleLimitReached, "{} since the per-process limit of file descriptors was reached.", msg),
                Errno::ENFILE => (SystemWideFileHandleLimitReached, "{} since the system-wide limit of file descriptors was reached.", msg),
                Errno::ENOMEM => (InsufficientMemory, "{} due to insufficient memory.", msg),
                Errno::ENOSYS => (NotSupported, "{} since pidfd_open is not supported (requires Linux 5.3+).", msg),
                v => (UnknownError(v as i32), "{} since an unknown error occurred ({}).", msg, v)
            );
        }

        let fd = FileDescriptor::new(raw_fd).expect("pidfd_open returned invalid fd");

        // Read start_time from /proc/[pid]/stat
        let start_time = Self::read_start_time(pid)?;

        let pidfd = PidFd {
            file_descriptor: fd,
            pid,
            start_time,
        };

        trace!(from pidfd, "created");
        Ok(pidfd)
    }

    /// Creates a PidFd for the current process.
    pub fn from_self() -> Result<Self, PidFdCreationError> {
        let pid = unsafe { ProcessId::new(posix::getpid()) };
        Self::new(pid)
    }

    /// Returns the process ID.
    pub fn pid(&self) -> ProcessId {
        self.pid
    }

    /// Returns the start time of the process.
    pub fn start_time(&self) -> u64 {
        self.start_time
    }

    /// Returns the process identity (pid + start_time).
    pub fn identity(&self) -> ProcessIdentity {
        ProcessIdentity {
            pid: self.pid,
            start_time: self.start_time,
        }
    }

    /// Checks if the process is still alive.
    /// This uses the pidfd to check, which is race-free.
    pub fn is_alive(&self) -> bool {
        // Using kill(pid, 0) with the pidfd's pid is a simple check
        // For a more thorough check, we could use poll() on the pidfd
        // When a process exits, the pidfd becomes readable
        unsafe { posix::kill(self.pid.value(), 0) == 0 }
    }

    /// Reads the start_time (field 22, 0-indexed field 21) from /proc/[pid]/stat.
    /// The stat file format includes fields that may contain parentheses and spaces
    /// in the comm field, so we need to parse carefully.
    fn read_start_time(pid: ProcessId) -> Result<u64, PidFdCreationError> {
        let path = format!("/proc/{}/stat\0", pid.value());
        let mut buffer = [0u8; 1024];

        // Open and read the stat file
        // Note: Ideally we'd use O_CLOEXEC, but it's not exposed in the PAL.
        // The fd is closed immediately after reading, so this is acceptable.
        let fd = unsafe { posix::open(path.as_ptr() as *const _, posix::O_RDONLY) };
        if fd < 0 {
            fail!(from "PidFd::read_start_time", with PidFdCreationError::FailedToReadStartTime,
                "Unable to open /proc/{}/stat for reading.", pid.value());
        }

        let bytes_read =
            unsafe { posix::read(fd, buffer.as_mut_ptr() as *mut posix::void, buffer.len()) };
        unsafe { posix::close(fd) };

        // Bounds checking to prevent buffer overflow
        if bytes_read <= 0 || bytes_read as usize > buffer.len() {
            fail!(from "PidFd::read_start_time", with PidFdCreationError::FailedToReadStartTime,
                "Unable to read /proc/{}/stat.", pid.value());
        }

        let content = &buffer[..(bytes_read as usize).min(buffer.len())];

        // The format of /proc/[pid]/stat is:
        // pid (comm) state ppid pgrp session tty_nr tpgid flags minflt cminflt majflt cmajflt
        // utime stime cutime cstime priority nice num_threads itrealvalue starttime ...
        //
        // Field 22 (1-indexed) is starttime, which is field 21 (0-indexed).
        // The comm field (field 2) is enclosed in parentheses and may contain spaces.
        //
        // We need to find the closing parenthesis and then count fields from there.

        // Find the last ')' which marks the end of the comm field
        let mut last_paren_idx = None;
        for (i, &byte) in content.iter().enumerate() {
            if byte == b')' {
                last_paren_idx = Some(i);
            }
        }

        let last_paren_idx = match last_paren_idx {
            Some(idx) => idx,
            None => {
                fail!(from "PidFd::read_start_time", with PidFdCreationError::FailedToReadStartTime,
                    "Failed to parse /proc/{}/stat: no closing parenthesis found.", pid.value());
            }
        };

        // After the ')' is field 3 (state). starttime is field 22.
        // From field 3, we need to skip 19 more fields to get to field 22 (22 - 3 = 19).
        // Fields are space-separated.

        let after_comm = &content[last_paren_idx + 1..];
        let fields_str = match core::str::from_utf8(after_comm) {
            Ok(s) => s,
            Err(_) => {
                fail!(from "PidFd::read_start_time", with PidFdCreationError::FailedToReadStartTime,
                    "Failed to parse /proc/{}/stat: invalid UTF-8.", pid.value());
            }
        };

        // Split by whitespace and get field index 19 (0-indexed from after comm)
        // Field 3 is index 0 after splitting, so starttime (field 22) is index 19
        let mut field_count = 0;
        for field in fields_str.split_whitespace() {
            if field_count == 19 {
                // This is starttime
                match field.parse::<u64>() {
                    Ok(start_time) => return Ok(start_time),
                    Err(_) => {
                        fail!(from "PidFd::read_start_time", with PidFdCreationError::FailedToReadStartTime,
                            "Failed to parse starttime field in /proc/{}/stat.", pid.value());
                    }
                }
            }
            field_count += 1;
        }

        fail!(from "PidFd::read_start_time", with PidFdCreationError::FailedToReadStartTime,
            "Failed to parse /proc/{}/stat: not enough fields.", pid.value());
    }
}

impl FileDescriptorBased for PidFd {
    fn file_descriptor(&self) -> &FileDescriptor {
        &self.file_descriptor
    }
}

impl FileDescriptorManagement for PidFd {}
