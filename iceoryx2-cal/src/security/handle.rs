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
//! (Unix) or handles (Windows) that ensures proper resource cleanup. It also provides
//! [`AccessRights`] for specifying read/write permissions and [`HandleBundle`] for bundling
//! handles with segment metadata.

use core::fmt::Debug;

use serde::{Deserialize, Serialize};

#[cfg(all(feature = "std", unix))]
use std::os::unix::io::AsRawFd;
#[cfg(all(feature = "std", unix))]
use std::os::unix::io::FromRawFd;
#[cfg(all(feature = "std", unix))]
use std::os::unix::io::IntoRawFd;
#[cfg(all(feature = "std", unix))]
use std::os::unix::io::OwnedFd;
#[cfg(all(feature = "std", unix))]
use std::os::unix::io::RawFd;

#[cfg(all(feature = "std", windows))]
use std::os::windows::io::AsRawHandle;
#[cfg(all(feature = "std", windows))]
use std::os::windows::io::FromRawHandle;
#[cfg(all(feature = "std", windows))]
use std::os::windows::io::IntoRawHandle;
#[cfg(all(feature = "std", windows))]
use std::os::windows::io::OwnedHandle;
#[cfg(all(feature = "std", windows))]
use std::os::windows::io::RawHandle;

#[cfg(all(not(feature = "std"), unix))]
type RawFd = iceoryx2_pal_posix::posix::int;
#[cfg(all(not(feature = "std"), windows))]
type RawHandle = *mut core::ffi::c_void;

use crate::shm_allocator::SegmentId;

use super::error::HandleError;

// ============================================================================
// PlatformHandle - Unix Implementation
// ============================================================================

/// Platform-specific handle with RAII semantics.
///
/// On Unix systems, this wraps an [`OwnedFd`] which represents ownership of a file descriptor.
/// On Windows, this wraps an [`OwnedHandle`] which represents ownership of a Windows handle.
/// The handle is automatically closed when the [`PlatformHandle`] is dropped.
///
/// # Example
///
/// ```ignore
/// use iceoryx2_cal::security::PlatformHandle;
///
/// // Unix: Create from a raw file descriptor (unsafe)
/// #[cfg(unix)]
/// let handle = unsafe { PlatformHandle::from_raw_fd(fd) };
///
/// // Windows: Create from a raw handle (unsafe)
/// #[cfg(windows)]
/// let handle = unsafe { PlatformHandle::from_raw_handle(handle) };
///
/// // Clone the handle (duplicates the underlying resource)
/// let cloned = handle.try_clone().expect("Failed to clone handle");
/// ```
#[cfg(feature = "std")]
#[derive(Debug)]
pub struct PlatformHandle {
    #[cfg(unix)]
    inner: OwnedFd,
    #[cfg(windows)]
    inner: OwnedHandle,
}

#[cfg(not(feature = "std"))]
#[derive(Debug)]
pub struct PlatformHandle {
    #[cfg(unix)]
    raw_fd: RawFd,
    #[cfg(windows)]
    raw_handle: RawHandle,
}

// Unix implementation
#[cfg(all(feature = "std", unix))]
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

#[cfg(all(feature = "std", unix))]
impl AsRawFd for PlatformHandle {
    #[inline]
    fn as_raw_fd(&self) -> RawFd {
        self.inner.as_raw_fd()
    }
}

#[cfg(all(feature = "std", unix))]
impl IntoRawFd for PlatformHandle {
    #[inline]
    fn into_raw_fd(self) -> RawFd {
        self.inner.into_raw_fd()
    }
}

#[cfg(all(feature = "std", unix))]
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

// ============================================================================
// PlatformHandle - Windows Implementation
// ============================================================================

#[cfg(all(feature = "std", windows))]
impl PlatformHandle {
    /// Creates a [`PlatformHandle`] from a raw Windows handle.
    ///
    /// # Safety
    ///
    /// - The caller must ensure that `handle` is a valid, open Windows handle.
    /// - The caller must transfer ownership of the handle to this [`PlatformHandle`].
    /// - The handle must not be closed by any other code after this call.
    /// - The handle must remain valid for the lifetime of the [`PlatformHandle`].
    /// - The handle must be closeable with `CloseHandle` (not a pseudo-handle).
    #[inline]
    pub unsafe fn from_raw_handle(handle: RawHandle) -> Self {
        Self {
            inner: OwnedHandle::from_raw_handle(handle),
        }
    }

    /// Duplicates the handle, creating a new independent [`PlatformHandle`].
    ///
    /// The new handle refers to the same underlying resource but has independent
    /// ownership. Closing one handle does not affect the other.
    ///
    /// # Errors
    ///
    /// Returns [`HandleError::DuplicationFailed`] if the underlying `DuplicateHandle`
    /// call fails, which can happen if:
    /// - The process has reached its handle limit
    /// - The handle is invalid
    /// - Insufficient privileges to duplicate the handle
    pub fn try_clone(&self) -> Result<Self, HandleError> {
        self.inner
            .try_clone()
            .map(|h| Self { inner: h })
            .map_err(|_| HandleError::DuplicationFailed)
    }

    /// Returns the raw Windows handle without transferring ownership.
    ///
    /// The returned handle is valid only as long as this [`PlatformHandle`]
    /// exists and has not been consumed by [`into_raw_handle`](Self::into_raw_handle).
    #[inline]
    pub fn as_raw_handle(&self) -> RawHandle {
        self.inner.as_raw_handle()
    }

    /// Consumes the [`PlatformHandle`] and returns the raw Windows handle.
    ///
    /// After calling this method, the caller is responsible for closing the
    /// handle with `CloseHandle`. The [`PlatformHandle`] will not close it on drop.
    #[inline]
    pub fn into_raw_handle(self) -> RawHandle {
        self.inner.into_raw_handle()
    }
}

#[cfg(all(feature = "std", windows))]
impl AsRawHandle for PlatformHandle {
    #[inline]
    fn as_raw_handle(&self) -> RawHandle {
        self.inner.as_raw_handle()
    }
}

#[cfg(all(feature = "std", windows))]
impl IntoRawHandle for PlatformHandle {
    #[inline]
    fn into_raw_handle(self) -> RawHandle {
        self.inner.into_raw_handle()
    }
}

#[cfg(all(feature = "std", windows))]
impl FromRawHandle for PlatformHandle {
    /// Creates a [`PlatformHandle`] from a raw Windows handle.
    ///
    /// # Safety
    ///
    /// See [`PlatformHandle::from_raw_handle`] for safety requirements.
    #[inline]
    unsafe fn from_raw_handle(handle: RawHandle) -> Self {
        Self::from_raw_handle(handle)
    }
}

// ============================================================================
// PlatformHandle - no_std Placeholder
// ============================================================================

#[cfg(all(not(feature = "std"), unix))]
impl PlatformHandle {
    /// Creates a [`PlatformHandle`] from a raw file descriptor.
    ///
    /// # Safety
    ///
    /// - The caller must ensure that `fd` is a valid, open file descriptor.
    /// - The caller must transfer ownership of the file descriptor to this [`PlatformHandle`].
    #[inline]
    pub unsafe fn from_raw_fd(fd: RawFd) -> Self {
        Self { raw_fd: fd }
    }

    /// Duplicates the handle by calling `dup()`.
    pub fn try_clone(&self) -> Result<Self, HandleError> {
        let fd = unsafe { iceoryx2_pal_posix::posix::dup(self.raw_fd) };
        if fd < 0 {
            return Err(HandleError::DuplicationFailed);
        }

        Ok(Self { raw_fd: fd })
    }

    /// Returns the raw file descriptor without transferring ownership.
    #[inline]
    pub fn as_raw_fd(&self) -> RawFd {
        self.raw_fd
    }

    /// Consumes the [`PlatformHandle`] and returns the raw file descriptor.
    #[inline]
    pub fn into_raw_fd(self) -> RawFd {
        let fd = self.raw_fd;
        core::mem::forget(self);
        fd
    }
}

#[cfg(all(not(feature = "std"), unix))]
impl Drop for PlatformHandle {
    fn drop(&mut self) {
        if self.raw_fd >= 0 {
            unsafe {
                iceoryx2_pal_posix::posix::close(self.raw_fd);
            }
        }
    }
}

#[cfg(all(not(feature = "std"), windows))]
impl PlatformHandle {
    /// Creates a [`PlatformHandle`] from a raw Windows handle.
    ///
    /// # Safety
    ///
    /// - The caller must ensure that `handle` is a valid, open Windows handle.
    /// - The caller must transfer ownership of the handle to this [`PlatformHandle`].
    #[inline]
    pub unsafe fn from_raw_handle(handle: RawHandle) -> Self {
        Self { raw_handle: handle }
    }

    /// Placeholder implementation that does not duplicate the handle.
    pub fn try_clone(&self) -> Result<Self, HandleError> {
        Err(HandleError::DuplicationFailed)
    }

    /// Returns the raw Windows handle without transferring ownership.
    #[inline]
    pub fn as_raw_handle(&self) -> RawHandle {
        self.raw_handle
    }

    /// Consumes the [`PlatformHandle`] and returns the raw Windows handle.
    #[inline]
    pub fn into_raw_handle(self) -> RawHandle {
        let handle = self.raw_handle;
        core::mem::forget(self);
        handle
    }
}

// ============================================================================
// AccessRights
// ============================================================================

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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
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

// ============================================================================
// HandleBundle
// ============================================================================

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

// ============================================================================
// Tests
// ============================================================================

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;

    #[test]
    fn test_access_rights_none() {
        let rights = AccessRights::none();
        assert!(!rights.read);
        assert!(!rights.write);
        assert!(!rights.has_any());
        assert!(!rights.can_read());
        assert!(!rights.can_write());
    }

    #[test]
    fn test_access_rights_read_only() {
        let rights = AccessRights::read_only();
        assert!(rights.read);
        assert!(!rights.write);
        assert!(rights.has_any());
        assert!(rights.can_read());
        assert!(!rights.can_write());
    }

    #[test]
    fn test_access_rights_read_write() {
        let rights = AccessRights::read_write();
        assert!(rights.read);
        assert!(rights.write);
        assert!(rights.has_any());
        assert!(rights.can_read());
        assert!(rights.can_write());
    }

    #[test]
    fn test_access_rights_default() {
        let rights = AccessRights::default();
        assert_eq!(rights, AccessRights::none());
    }

    #[test]
    fn test_access_rights_clone_copy() {
        let rights = AccessRights::read_write();
        let cloned = rights.clone();
        let copied = rights;
        assert_eq!(rights, cloned);
        assert_eq!(rights, copied);
    }

    #[test]
    fn test_access_rights_hash() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(AccessRights::none());
        set.insert(AccessRights::read_only());
        set.insert(AccessRights::read_write());
        assert_eq!(set.len(), 3);
    }

    #[cfg(unix)]
    mod unix_tests {
        use super::*;

        #[test]
        fn test_platform_handle_from_pipe() {
            // Create a pipe to get valid file descriptors
            let mut fds = [0i32; 2];
            unsafe {
                libc::pipe(fds.as_mut_ptr());
            }

            let read_fd = fds[0];
            let write_fd = fds[1];

            // Create handles
            let read_handle = unsafe { PlatformHandle::from_raw_fd(read_fd) };
            let write_handle = unsafe { PlatformHandle::from_raw_fd(write_fd) };

            // Verify raw fd access
            assert_eq!(read_handle.as_raw_fd(), read_fd);
            assert_eq!(write_handle.as_raw_fd(), write_fd);

            // Handles are closed on drop
        }

        #[test]
        fn test_platform_handle_try_clone() {
            let mut fds = [0i32; 2];
            unsafe {
                libc::pipe(fds.as_mut_ptr());
            }

            let handle = unsafe { PlatformHandle::from_raw_fd(fds[0]) };
            let cloned = handle.try_clone().expect("Clone should succeed");

            // Both should be valid but different fds
            assert_ne!(handle.as_raw_fd(), cloned.as_raw_fd());

            // Close the write end
            unsafe { libc::close(fds[1]) };
        }

        #[test]
        fn test_platform_handle_into_raw_fd() {
            let mut fds = [0i32; 2];
            unsafe {
                libc::pipe(fds.as_mut_ptr());
            }

            let handle = unsafe { PlatformHandle::from_raw_fd(fds[0]) };
            let raw = handle.into_raw_fd();

            assert_eq!(raw, fds[0]);

            // Manual cleanup since we took ownership
            unsafe {
                libc::close(raw);
                libc::close(fds[1]);
            }
        }
    }

    #[cfg(windows)]
    mod windows_tests {
        use super::*;
        use std::os::windows::io::AsRawHandle;

        #[test]
        fn test_platform_handle_from_event() {
            use windows_sys::Win32::Foundation::CloseHandle;
            use windows_sys::Win32::System::Threading::CreateEventW;

            // Create an event to get a valid handle
            let handle = unsafe {
                CreateEventW(
                    core::ptr::null(),
                    1, // manual reset
                    0, // initial state = non-signaled
                    core::ptr::null(),
                )
            };
            assert!(handle != 0, "Failed to create event");

            let platform_handle = unsafe { PlatformHandle::from_raw_handle(handle as *mut _) };

            // Verify raw handle access
            assert_eq!(platform_handle.as_raw_handle(), handle as *mut _);

            // Handle is closed on drop
        }

        #[test]
        fn test_platform_handle_try_clone() {
            use windows_sys::Win32::System::Threading::CreateEventW;

            let handle = unsafe { CreateEventW(core::ptr::null(), 1, 0, core::ptr::null()) };
            assert!(handle != 0, "Failed to create event");

            let platform_handle = unsafe { PlatformHandle::from_raw_handle(handle as *mut _) };
            let cloned = platform_handle.try_clone().expect("Clone should succeed");

            // Both should be valid but different handles
            assert_ne!(platform_handle.as_raw_handle(), cloned.as_raw_handle());
        }

        #[test]
        fn test_platform_handle_into_raw_handle() {
            use windows_sys::Win32::Foundation::CloseHandle;
            use windows_sys::Win32::System::Threading::CreateEventW;

            let handle = unsafe { CreateEventW(core::ptr::null(), 1, 0, core::ptr::null()) };
            assert!(handle != 0, "Failed to create event");

            let platform_handle = unsafe { PlatformHandle::from_raw_handle(handle as *mut _) };
            let raw = platform_handle.into_raw_handle();

            assert_eq!(raw, handle as *mut _);

            // Manual cleanup since we took ownership
            unsafe { CloseHandle(raw as isize) };
        }
    }
}
