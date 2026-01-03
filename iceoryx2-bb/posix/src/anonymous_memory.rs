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

//! Provides access to anonymous memory via `memfd_create`. Anonymous memory is backed by
//! a file descriptor that can be passed between processes via Unix domain sockets.
//!
//! # Features
//!
//! - Memory sealing support (F_SEAL_SEAL, F_SEAL_SHRINK, F_SEAL_GROW, F_SEAL_WRITE)
//! - Transferable via IPC (file descriptor passing)
//! - Memory mapped for direct access
//!
//! # Examples
//!
//! ## Create anonymous memory
//!
//! ```ignore
//! use iceoryx2_bb_posix::anonymous_memory::*;
//!
//! let mut memory = AnonymousMemoryBuilder::new()
//!     .name("my_shm")
//!     .size(4096)
//!     .access_mode(AccessMode::ReadWrite)
//!     .seals(Seals::new().seal_shrink().seal_grow())
//!     .create()
//!     .expect("failed to create anonymous memory");
//!
//! println!("size: {}", memory.size());
//! println!("address: {:?}", memory.base_address());
//!
//! // Write to memory
//! memory.as_mut_slice()[0] = 42;
//! ```
//!
//! ## Pass anonymous memory between processes
//!
//! ```ignore
//! use iceoryx2_bb_posix::anonymous_memory::*;
//! use iceoryx2_bb_posix::unix_stream_socket::*;
//! use iceoryx2_bb_posix::socket_ancillary::*;
//!
//! // Create memory and get file descriptor
//! let memory = AnonymousMemoryBuilder::new()
//!     .name("shared")
//!     .size(4096)
//!     .create()
//!     .unwrap();
//!
//! let fd = memory.into_file_descriptor();
//!
//! // Send fd over socket...
//!
//! // On receiving end:
//! // let received_fd = ...;
//! let memory = AnonymousMemory::from_file_descriptor(received_fd, AccessMode::ReadWrite)
//!     .expect("failed to map received memory");
//! ```

use core::mem::ManuallyDrop;
use core::ptr::NonNull;

use iceoryx2_bb_elementary::enum_gen;
use iceoryx2_log::{fail, fatal_panic, trace};
use iceoryx2_pal_posix::posix::errno::Errno;
use iceoryx2_pal_posix::*;

pub use crate::access_mode::AccessMode;
use crate::file_descriptor::{FileDescriptor, FileDescriptorBased, FileDescriptorManagement};
use crate::file::FileTruncateError;
use crate::handle_errno;
use crate::memory_mapping::{
    MappingBehavior, MemoryMapping, MemoryMappingBuilder,
    MemoryMappingCreationError,
};

/// Seal flags for anonymous memory.
#[derive(Debug, Clone, Copy, Default)]
pub struct Seals {
    /// If set, no further seals can be added
    pub seal_seal: bool,
    /// If set, the memory cannot be shrunk
    pub seal_shrink: bool,
    /// If set, the memory cannot grow
    pub seal_grow: bool,
    /// If set, the memory cannot be written
    pub seal_write: bool,
}

impl Seals {
    /// Creates a new empty Seals structure.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the seal_seal flag (prevents adding more seals).
    pub fn seal_seal(mut self) -> Self {
        self.seal_seal = true;
        self
    }

    /// Sets the seal_shrink flag (prevents shrinking).
    pub fn seal_shrink(mut self) -> Self {
        self.seal_shrink = true;
        self
    }

    /// Sets the seal_grow flag (prevents growing).
    pub fn seal_grow(mut self) -> Self {
        self.seal_grow = true;
        self
    }

    /// Sets the seal_write flag (prevents writing).
    pub fn seal_write(mut self) -> Self {
        self.seal_write = true;
        self
    }

    /// Returns true if no seals are set.
    pub fn is_empty(&self) -> bool {
        !self.seal_seal && !self.seal_shrink && !self.seal_grow && !self.seal_write
    }

    fn to_flags(&self) -> posix::int {
        let mut flags = 0;
        if self.seal_seal {
            flags |= posix::F_SEAL_SEAL;
        }
        if self.seal_shrink {
            flags |= posix::F_SEAL_SHRINK;
        }
        if self.seal_grow {
            flags |= posix::F_SEAL_GROW;
        }
        if self.seal_write {
            flags |= posix::F_SEAL_WRITE;
        }
        flags
    }

    fn from_flags(flags: posix::int) -> Self {
        Self {
            seal_seal: (flags & posix::F_SEAL_SEAL) != 0,
            seal_shrink: (flags & posix::F_SEAL_SHRINK) != 0,
            seal_grow: (flags & posix::F_SEAL_GROW) != 0,
            seal_write: (flags & posix::F_SEAL_WRITE) != 0,
        }
    }
}

enum_gen! {
    /// Error that can occur when creating anonymous memory.
    AnonymousMemoryCreationError
  entry:
    InsufficientPermissions,
    InsufficientMemory,
    InsufficientResources,
    PerProcessFileHandleLimitReached,
    SystemWideFileHandleLimitReached,
    MemfdCreateNotSupported,
    InvalidName,
    SizeIsZero,
    UnknownError(i32)
  mapping:
    FileTruncateError,
    MemoryMappingCreationError,
    AnonymousMemorySealError
}

/// Error that can occur when adding seals.
#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
pub enum AnonymousMemorySealError {
    /// The memory is already sealed against adding new seals.
    AlreadySealed,
    /// Cannot add write seal while memory is mapped writable.
    WriteSealWithWritableMapping,
    /// Insufficient permissions.
    InsufficientPermissions,
    /// Unknown error.
    UnknownError(i32),
}

enum_gen! {
    /// Error that can occur when creating anonymous memory from an existing file descriptor.
    AnonymousMemoryFromFdError
  entry:
    InvalidFileDescriptor,
    NotAMemfd,
    SealMismatch,
    InsufficientPermissions,
    InsufficientMemory,
    InsufficientResources,
    UnknownError(i32)
  mapping:
    MemoryMappingCreationError
}

/// Builder for creating [`AnonymousMemory`].
#[derive(Debug)]
pub struct AnonymousMemoryBuilder {
    name: [u8; 250],
    name_len: usize,
    size: usize,
    seals: Seals,
    access_mode: AccessMode,
}

impl Default for AnonymousMemoryBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl AnonymousMemoryBuilder {
    /// Creates a new builder with default settings.
    pub fn new() -> Self {
        Self {
            name: [0u8; 250],
            name_len: 0,
            size: 0,
            seals: Seals::new(),
            access_mode: AccessMode::ReadWrite,
        }
    }

    /// Sets the name for the anonymous memory (for debugging purposes).
    /// The name is visible in /proc/[pid]/fd/[fd] as memfd:[name].
    pub fn name(mut self, name: &str) -> Self {
        let bytes = name.as_bytes();
        let len = bytes.len().min(249);
        self.name[..len].copy_from_slice(&bytes[..len]);
        self.name[len] = 0; // null terminate
        self.name_len = len;
        self
    }

    /// Sets the size of the anonymous memory.
    pub fn size(mut self, size: usize) -> Self {
        self.size = size;
        self
    }

    /// Sets the seals to be applied after creation.
    pub fn seals(mut self, seals: Seals) -> Self {
        self.seals = seals;
        self
    }

    /// Sets the access mode for the memory mapping.
    pub fn access_mode(mut self, mode: AccessMode) -> Self {
        self.access_mode = mode;
        self
    }

    /// Creates the anonymous memory.
    pub fn create(self) -> Result<AnonymousMemory, AnonymousMemoryCreationError> {
        let msg = "Unable to create anonymous memory";

        if self.size == 0 {
            fail!(from self, with AnonymousMemoryCreationError::SizeIsZero,
                "{} since size is zero.", msg);
        }

        // Create memfd with MFD_CLOEXEC | MFD_ALLOW_SEALING
        let flags = posix::MFD_CLOEXEC | posix::MFD_ALLOW_SEALING;
        let raw_fd = unsafe { posix::memfd_create(self.name.as_ptr() as *const _, flags) };

        if raw_fd < 0 {
            handle_errno!(AnonymousMemoryCreationError, from self,
                Errno::EFAULT => (InvalidName, "{} since the name is invalid.", msg),
                Errno::EINVAL => (InvalidName, "{} since the name or flags are invalid.", msg),
                Errno::EMFILE => (PerProcessFileHandleLimitReached, "{} since the per-process limit of file descriptors was reached.", msg),
                Errno::ENFILE => (SystemWideFileHandleLimitReached, "{} since the system-wide limit of file descriptors was reached.", msg),
                Errno::ENOMEM => (InsufficientMemory, "{} due to insufficient memory.", msg),
                Errno::ENOSYS => (MemfdCreateNotSupported, "{} since memfd_create is not supported on this system.", msg),
                v => (UnknownError(v as i32), "{} since an unknown error occurred ({}).", msg, v)
            );
        }

        let fd = FileDescriptor::new(raw_fd).expect("memfd_create returned invalid fd");

        // Set size via ftruncate
        if unsafe { posix::ftruncate(fd.native_handle(), self.size as posix::off_t) } != 0 {
            let err = Errno::get();
            fail!(from self, with AnonymousMemoryCreationError::InsufficientResources,
                "{} since ftruncate failed ({:?}).", msg, err);
        }

        // Create memory mapping
        let mapping = fail!(from self,
            when MemoryMappingBuilder::from_file_descriptor(fd.clone())
                .mapping_behavior(MappingBehavior::Shared)
                .initial_mapping_permission(self.access_mode.into())
                .size(self.size)
                .create(),
            "{} since the memory mapping failed.", msg);

        let mut memory = AnonymousMemory {
            file_descriptor: ManuallyDrop::new(fd),
            memory_mapping: mapping,
        };

        // Apply seals if any
        if !self.seals.is_empty() {
            fail!(from self, when memory.add_seals(self.seals),
                "{} since the seals could not be applied.", msg);
        }

        trace!(from memory, "create");
        Ok(memory)
    }
}

/// Anonymous memory backed by memfd_create. Can be passed between processes via IPC.
#[derive(Debug)]
pub struct AnonymousMemory {
    file_descriptor: ManuallyDrop<FileDescriptor>,
    memory_mapping: MemoryMapping,
}

impl Drop for AnonymousMemory {
    fn drop(&mut self) {
        // SAFETY: We only drop the file descriptor here, once.
        // The ManuallyDrop wrapper allows us to move out the FD in into_file_descriptor().
        unsafe {
            ManuallyDrop::drop(&mut self.file_descriptor);
        }
    }
}

impl AnonymousMemory {
    /// Creates an [`AnonymousMemory`] from an existing file descriptor (e.g., received via IPC).
    ///
    /// If `expected_seals` is provided, this function will verify that the file descriptor
    /// is a memfd and that the expected seals are set.
    pub fn from_file_descriptor(
        fd: FileDescriptor,
        access_mode: AccessMode,
        expected_seals: Option<Seals>,
    ) -> Result<Self, AnonymousMemoryFromFdError> {
        let msg = "Unable to create anonymous memory from file descriptor";

        // Verify it's a memfd by checking F_GET_SEALS works
        let current_seals_flags = unsafe {
            posix::fcntl_int(fd.native_handle(), posix::F_GET_SEALS, 0)
        };
        if current_seals_flags < 0 {
            fail!(from "AnonymousMemory::from_file_descriptor",
                with AnonymousMemoryFromFdError::NotAMemfd,
                "{} since the file descriptor is not a memfd (F_GET_SEALS failed).", msg);
        }

        // If expected seals are specified, verify they're set
        if let Some(expected) = expected_seals {
            let current = Seals::from_flags(current_seals_flags);
            if expected.seal_seal && !current.seal_seal {
                fail!(from "AnonymousMemory::from_file_descriptor",
                    with AnonymousMemoryFromFdError::SealMismatch,
                    "{} since expected F_SEAL_SEAL but it is not set.", msg);
            }
            if expected.seal_shrink && !current.seal_shrink {
                fail!(from "AnonymousMemory::from_file_descriptor",
                    with AnonymousMemoryFromFdError::SealMismatch,
                    "{} since expected F_SEAL_SHRINK but it is not set.", msg);
            }
            if expected.seal_grow && !current.seal_grow {
                fail!(from "AnonymousMemory::from_file_descriptor",
                    with AnonymousMemoryFromFdError::SealMismatch,
                    "{} since expected F_SEAL_GROW but it is not set.", msg);
            }
            if expected.seal_write && !current.seal_write {
                fail!(from "AnonymousMemory::from_file_descriptor",
                    with AnonymousMemoryFromFdError::SealMismatch,
                    "{} since expected F_SEAL_WRITE but it is not set.", msg);
            }
        }

        // Get the size of the memfd
        let size = {
            let result = unsafe { posix::lseek(fd.native_handle(), 0, posix::SEEK_END) };
            if result < 0 {
                fail!(from "AnonymousMemory::from_file_descriptor",
                    with AnonymousMemoryFromFdError::InvalidFileDescriptor,
                    "{} since the file descriptor size could not be determined.", msg);
            }
            // Seek back to beginning
            unsafe { posix::lseek(fd.native_handle(), 0, posix::SEEK_SET) };
            result as usize
        };

        // Create memory mapping
        let mapping = fail!(from "AnonymousMemory::from_file_descriptor",
            when MemoryMappingBuilder::from_file_descriptor(fd.clone())
                .mapping_behavior(MappingBehavior::Shared)
                .initial_mapping_permission(access_mode.into())
                .size(size)
                .create(),
            "{} since the memory mapping failed.", msg);

        let memory = AnonymousMemory {
            file_descriptor: ManuallyDrop::new(fd),
            memory_mapping: mapping,
        };

        trace!(from memory, "created from file descriptor");
        Ok(memory)
    }

    /// Adds seals to the anonymous memory.
    /// Once F_SEAL_SEAL is set, no more seals can be added.
    pub fn add_seals(&mut self, seals: Seals) -> Result<(), AnonymousMemorySealError> {
        let flags = seals.to_flags();
        if flags == 0 {
            return Ok(());
        }

        let result = unsafe {
            posix::fcntl_int(
                self.file_descriptor.native_handle(),
                posix::F_ADD_SEALS,
                flags,
            )
        };

        if result == 0 {
            return Ok(());
        }

        let msg = "Unable to add seals";
        handle_errno!(AnonymousMemorySealError, from self,
            Errno::EBUSY => (WriteSealWithWritableMapping, "{} since F_SEAL_WRITE cannot be set while memory is mapped writable.", msg),
            Errno::EPERM => (AlreadySealed, "{} since F_SEAL_SEAL is already set.", msg),
            Errno::EACCES => (InsufficientPermissions, "{} due to insufficient permissions.", msg),
            v => (UnknownError(v as i32), "{} since an unknown error occurred ({}).", msg, v)
        );
    }

    /// Gets the current seals on the anonymous memory.
    pub fn get_seals(&self) -> Result<Seals, AnonymousMemorySealError> {
        let result = unsafe {
            posix::fcntl_int(self.file_descriptor.native_handle(), posix::F_GET_SEALS, 0)
        };

        if result >= 0 {
            return Ok(Seals::from_flags(result));
        }

        let msg = "Unable to get seals";
        handle_errno!(AnonymousMemorySealError, from self,
            Errno::EACCES => (InsufficientPermissions, "{} due to insufficient permissions.", msg),
            v => (UnknownError(v as i32), "{} since an unknown error occurred ({}).", msg, v)
        );
    }

    /// Returns the size of the anonymous memory.
    pub fn size(&self) -> usize {
        self.memory_mapping.size()
    }

    /// Returns the base address of the memory mapping.
    pub fn base_address(&self) -> NonNull<u8> {
        match NonNull::new(self.memory_mapping.base_address() as *mut u8) {
            Some(v) => v,
            None => {
                fatal_panic!(from self,
                    "This should never happen! A valid anonymous memory should never contain a base address with null value.");
            }
        }
    }

    /// Returns a slice to the memory.
    pub fn as_slice(&self) -> &[u8] {
        self.memory_mapping.as_slice()
    }

    /// Returns a mutable slice to the memory.
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        self.memory_mapping.as_mut_slice()
    }

    /// Consumes the AnonymousMemory and returns the underlying file descriptor.
    /// This is useful for passing the memory to another process via IPC.
    /// Note: The memory mapping will be unmapped when this is called.
    pub fn into_file_descriptor(mut self) -> FileDescriptor {
        // SAFETY: We take the file descriptor out of ManuallyDrop.
        // The Drop impl checks if the value is still present, but since we're using
        // ManuallyDrop::take, the Drop impl will try to drop an already-taken value.
        // To avoid this, we need a different approach.
        //
        // We take the FD first, then use ptr::read to get the mapping for manual drop,
        // and finally forget self to prevent the Drop impl from running.
        let fd = unsafe { ManuallyDrop::take(&mut self.file_descriptor) };

        // Manually drop the memory_mapping by reading it out
        let mapping = unsafe { core::ptr::read(&self.memory_mapping) };
        // Forget self to prevent Drop from running (which would try to drop already-taken fd)
        core::mem::forget(self);
        // Now drop the mapping explicitly
        drop(mapping);

        fd
    }
}

impl FileDescriptorBased for AnonymousMemory {
    fn file_descriptor(&self) -> &FileDescriptor {
        &self.file_descriptor
    }
}

impl FileDescriptorManagement for AnonymousMemory {}
