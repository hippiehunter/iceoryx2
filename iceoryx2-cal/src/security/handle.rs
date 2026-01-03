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

//! Platform-specific handle types with RAII semantics.
//!
//! This module provides [`PlatformHandle`], a safe wrapper around OS-level file descriptors
//! that ensures proper resource cleanup. It also provides [`AccessRights`] for specifying
//! read/write permissions and [`HandleBundle`] for bundling handles with segment metadata.

use core::fmt::Debug;

use std::os::unix::io::AsRawFd;
use std::os::unix::io::FromRawFd;
use std::os::unix::io::IntoRawFd;
use std::os::unix::io::OwnedFd;
use std::os::unix::io::RawFd;

use crate::shm_allocator::SegmentId;

use super::error::HandleError;

/// Platform-specific handle with RAII semantics.
///
/// On Unix systems, this wraps an [`OwnedFd`] which represents ownership of a file descriptor.
/// The file descriptor is automatically closed when the [`PlatformHandle`] is dropped.
///
/// # Example
///
/// ```ignore
/// use iceoryx2_cal::security::PlatformHandle;
///
/// // Create from a raw file descriptor (unsafe)
/// let handle = unsafe { PlatformHandle::from_raw_fd(fd) };
///
/// // Clone the handle (duplicates the underlying fd)
/// let cloned = handle.try_clone().expect("Failed to clone handle");
///
/// // Access the raw fd (for syscalls)
/// let raw_fd = handle.as_raw_fd();
/// ```
#[derive(Debug)]
pub struct PlatformHandle {
    inner: OwnedFd,
}

impl PlatformHandle {
    /// Creates a [`PlatformHandle`] from a raw file descriptor.
    ///
    /// # Safety
    ///
    /// - The caller must ensure that `fd` is a valid, open file descriptor.
    /// - The caller must transfer ownership of the file descriptor to this [`PlatformHandle`].
    /// - The file descriptor must not be closed by any other code after this call.
    /// - The file descriptor must remain valid for the lifetime of the [`PlatformHandle`].
    #[inline]
    pub unsafe fn from_raw_fd(fd: RawFd) -> Self {
        Self {
            inner: OwnedFd::from_raw_fd(fd),
        }
    }

    /// Duplicates the handle, creating a new independent [`PlatformHandle`].
    ///
    /// The new handle refers to the same underlying resource but has independent
    /// ownership. Closing one handle does not affect the other.
    ///
    /// # Errors
    ///
    /// Returns [`HandleError::DuplicationFailed`] if the underlying `dup()` syscall fails,
    /// which can happen if:
    /// - The process has reached its file descriptor limit
    /// - The system-wide file descriptor limit has been reached
    /// - The file descriptor is invalid
    pub fn try_clone(&self) -> Result<Self, HandleError> {
        self.inner
            .try_clone()
            .map(|fd| Self { inner: fd })
            .map_err(|_| HandleError::DuplicationFailed)
    }

    /// Returns the raw file descriptor without transferring ownership.
    ///
    /// The returned file descriptor is valid only as long as this [`PlatformHandle`]
    /// exists and has not been consumed by [`into_raw_fd`](Self::into_raw_fd).
    #[inline]
    pub fn as_raw_fd(&self) -> RawFd {
        self.inner.as_raw_fd()
    }

    /// Consumes the [`PlatformHandle`] and returns the raw file descriptor.
    ///
    /// After calling this method, the caller is responsible for closing the
    /// file descriptor. The [`PlatformHandle`] will not close it on drop.
    #[inline]
    pub fn into_raw_fd(self) -> RawFd {
        self.inner.into_raw_fd()
    }
}

impl AsRawFd for PlatformHandle {
    #[inline]
    fn as_raw_fd(&self) -> RawFd {
        self.inner.as_raw_fd()
    }
}

impl IntoRawFd for PlatformHandle {
    #[inline]
    fn into_raw_fd(self) -> RawFd {
        self.inner.into_raw_fd()
    }
}

impl FromRawFd for PlatformHandle {
    /// Creates a [`PlatformHandle`] from a raw file descriptor.
    ///
    /// # Safety
    ///
    /// See [`PlatformHandle::from_raw_fd`] for safety requirements.
    #[inline]
    unsafe fn from_raw_fd(fd: RawFd) -> Self {
        Self::from_raw_fd(fd)
    }
}

/// Access rights for a handle.
///
/// Specifies whether a handle grants read and/or write access to the underlying resource.
/// This is used to track and enforce permissions when passing handles between processes.
///
/// # Example
///
/// ```
/// use iceoryx2_cal::security::AccessRights;
///
/// // Create read-only access
/// let read_only = AccessRights::read_only();
/// assert!(read_only.read);
/// assert!(!read_only.write);
///
/// // Create read-write access
/// let read_write = AccessRights::read_write();
/// assert!(read_write.read);
/// assert!(read_write.write);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AccessRights {
    /// Whether read access is granted.
    pub read: bool,
    /// Whether write access is granted.
    pub write: bool,
}

impl AccessRights {
    /// Creates [`AccessRights`] with no access.
    ///
    /// Both read and write are set to `false`.
    #[inline]
    pub const fn none() -> Self {
        Self {
            read: false,
            write: false,
        }
    }

    /// Creates [`AccessRights`] with read-only access.
    ///
    /// Read is set to `true`, write is set to `false`.
    #[inline]
    pub const fn read_only() -> Self {
        Self {
            read: true,
            write: false,
        }
    }

    /// Creates [`AccessRights`] with read and write access.
    ///
    /// Both read and write are set to `true`.
    #[inline]
    pub const fn read_write() -> Self {
        Self {
            read: true,
            write: true,
        }
    }

    /// Returns `true` if any access is granted.
    #[inline]
    pub const fn has_any(&self) -> bool {
        self.read || self.write
    }

    /// Returns `true` if write access is granted.
    #[inline]
    pub const fn can_write(&self) -> bool {
        self.write
    }

    /// Returns `true` if read access is granted.
    #[inline]
    pub const fn can_read(&self) -> bool {
        self.read
    }
}

impl Default for AccessRights {
    /// Returns [`AccessRights::none()`] as the default.
    #[inline]
    fn default() -> Self {
        Self::none()
    }
}

/// Bundle of handles for a data-plane resource.
///
/// A [`HandleBundle`] combines a platform handle with metadata about the segment it represents:
/// - The segment identifier for tracking in dynamic segment scenarios
/// - The access rights granted for the segment
/// - The size of the segment in bytes
///
/// This is used when IAM passes handles to clients, providing all necessary information
/// to map and use the shared memory segment.
///
/// # Example
///
/// ```ignore
/// use iceoryx2_cal::security::{HandleBundle, PlatformHandle, AccessRights};
/// use iceoryx2_cal::shm_allocator::SegmentId;
///
/// let bundle = HandleBundle {
///     segment: handle,
///     segment_id: SegmentId::new(0),
///     access: AccessRights::read_only(),
///     size: 4096,
/// };
/// ```
#[derive(Debug)]
pub struct HandleBundle {
    /// The platform handle for the segment.
    pub segment: PlatformHandle,
    /// The segment identifier for dynamic segment tracking.
    pub segment_id: SegmentId,
    /// The access rights granted for this segment.
    pub access: AccessRights,
    /// The size of the segment in bytes.
    pub size: usize,
}

impl HandleBundle {
    /// Creates a new [`HandleBundle`] with the specified components.
    ///
    /// # Arguments
    ///
    /// * `segment` - The platform handle for the segment
    /// * `segment_id` - The segment identifier
    /// * `access` - The access rights for the segment
    /// * `size` - The size of the segment in bytes
    #[inline]
    pub fn new(
        segment: PlatformHandle,
        segment_id: SegmentId,
        access: AccessRights,
        size: usize,
    ) -> Self {
        Self {
            segment,
            segment_id,
            access,
            size,
        }
    }

    /// Returns a reference to the platform handle.
    #[inline]
    pub fn handle(&self) -> &PlatformHandle {
        &self.segment
    }

    /// Returns the segment identifier.
    #[inline]
    pub fn segment_id(&self) -> SegmentId {
        self.segment_id
    }

    /// Returns the access rights.
    #[inline]
    pub fn access(&self) -> AccessRights {
        self.access
    }

    /// Returns the size of the segment in bytes.
    #[inline]
    pub fn size(&self) -> usize {
        self.size
    }

    /// Consumes the bundle and returns the platform handle.
    #[inline]
    pub fn into_handle(self) -> PlatformHandle {
        self.segment
    }
}
