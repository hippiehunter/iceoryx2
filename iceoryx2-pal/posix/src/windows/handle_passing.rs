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

//! Windows handle duplication for inter-process handle passing.
//!
//! This module provides safe abstractions over Windows handle duplication APIs,
//! enabling handles to be passed between processes. This is essential for
//! implementing secure IPC where handles are created by a privileged process
//! and passed to clients.
//!
//! # Overview
//!
//! On Windows, handles are process-local and cannot be directly used by other processes.
//! To pass a handle to another process, you must use `DuplicateHandle` to create a copy
//! in the target process's handle table.
//!
//! # Example
//!
//! ```ignore
//! use iceoryx2_pal_posix::windows::handle_passing::*;
//!
//! // Duplicate a handle to another process
//! let options = DuplicateOptions::same_access();
//! let new_handle = duplicate_handle_to_process(my_handle, target_pid, options)?;
//! ```
//!
//! # Security Considerations
//!
//! - The calling process must have `PROCESS_DUP_HANDLE` access to the target process.
//! - Handle duplication can be used to escalate privileges if not carefully controlled.
//! - Always validate the target process before duplicating handles to it.

#![allow(non_camel_case_types)]
#![allow(clippy::missing_safety_doc)]

use core::fmt::{self, Display, Formatter};
use core::hash::Hash;

// Windows API imports
#[cfg(windows)]
use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, BOOL, ERROR_ACCESS_DENIED, ERROR_INVALID_HANDLE,
    ERROR_INVALID_PARAMETER, FALSE, HANDLE, INVALID_HANDLE_VALUE,
};

#[cfg(windows)]
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcess, PROCESS_DUP_HANDLE};

#[cfg(windows)]
use windows_sys::Win32::Foundation::DuplicateHandle;

#[cfg(windows)]
use windows_sys::Win32::Foundation::{DUPLICATE_CLOSE_SOURCE, DUPLICATE_SAME_ACCESS};

// ============================================================================
// Error Types
// ============================================================================

/// Errors that can occur during handle duplication.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HandleDuplicationError {
    /// The target process could not be found or opened.
    ProcessNotFound,
    /// Access to the target process was denied.
    AccessDenied,
    /// The source handle is invalid.
    InvalidSourceHandle,
    /// An invalid parameter was provided.
    InvalidParameter,
    /// An internal Windows error occurred.
    InternalError(u32),
}

impl HandleDuplicationError {
    /// Converts a Win32 error code to a [`HandleDuplicationError`].
    #[cfg(windows)]
    pub fn from_win32(error_code: u32) -> Self {
        match error_code {
            ERROR_ACCESS_DENIED => HandleDuplicationError::AccessDenied,
            ERROR_INVALID_HANDLE => HandleDuplicationError::InvalidSourceHandle,
            ERROR_INVALID_PARAMETER => HandleDuplicationError::InvalidParameter,
            _ => HandleDuplicationError::InternalError(error_code),
        }
    }

    /// Stub implementation for non-Windows platforms.
    #[cfg(not(windows))]
    pub fn from_win32(error_code: u32) -> Self {
        HandleDuplicationError::InternalError(error_code)
    }
}

impl Display for HandleDuplicationError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            HandleDuplicationError::ProcessNotFound => {
                write!(f, "Target process not found or could not be opened")
            }
            HandleDuplicationError::AccessDenied => {
                write!(f, "Access denied to target process")
            }
            HandleDuplicationError::InvalidSourceHandle => {
                write!(f, "Source handle is invalid")
            }
            HandleDuplicationError::InvalidParameter => {
                write!(f, "Invalid parameter provided")
            }
            HandleDuplicationError::InternalError(code) => {
                write!(f, "Internal error (code: {})", code)
            }
        }
    }
}

impl core::error::Error for HandleDuplicationError {}

// ============================================================================
// DuplicateOptions
// ============================================================================

/// Options for handle duplication.
///
/// Controls how a handle is duplicated, including access rights and whether
/// the source handle should be closed after duplication.
///
/// # Example
///
/// ```ignore
/// use iceoryx2_pal_posix::windows::handle_passing::DuplicateOptions;
///
/// // Use same access as source handle
/// let options = DuplicateOptions::same_access();
///
/// // Use specific access rights
/// let options = DuplicateOptions::with_access(GENERIC_READ | GENERIC_WRITE);
///
/// // Close source after duplication
/// let options = DuplicateOptions::same_access().close_source();
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DuplicateOptions {
    /// If true, the new handle has the same access as the source handle.
    /// If false, `desired_access` specifies the access rights.
    pub same_access: bool,
    /// If true, the source handle is closed after successful duplication.
    pub close_source: bool,
    /// The desired access rights for the new handle.
    /// Only used if `same_access` is false.
    pub desired_access: u32,
}

impl DuplicateOptions {
    /// Creates options that duplicate with the same access as the source handle.
    #[inline]
    pub const fn same_access() -> Self {
        Self {
            same_access: true,
            close_source: false,
            desired_access: 0,
        }
    }

    /// Creates options with specific access rights.
    ///
    /// # Arguments
    /// * `access` - The desired access rights for the duplicated handle
    #[inline]
    pub const fn with_access(access: u32) -> Self {
        Self {
            same_access: false,
            close_source: false,
            desired_access: access,
        }
    }

    /// Returns a copy of these options that will close the source handle after duplication.
    #[inline]
    pub const fn close_source(self) -> Self {
        Self {
            same_access: self.same_access,
            close_source: true,
            desired_access: self.desired_access,
        }
    }

    /// Returns the flags to pass to `DuplicateHandle`.
    #[cfg(windows)]
    fn to_flags(&self) -> u32 {
        let mut flags = 0;
        if self.same_access {
            flags |= DUPLICATE_SAME_ACCESS;
        }
        if self.close_source {
            flags |= DUPLICATE_CLOSE_SOURCE;
        }
        flags
    }
}

impl Default for DuplicateOptions {
    /// Returns [`DuplicateOptions::same_access()`] as the default.
    fn default() -> Self {
        Self::same_access()
    }
}

// ============================================================================
// Windows Implementation
// ============================================================================

/// Duplicates a handle from the current process to a target process.
///
/// This function creates a duplicate of `source_handle` in the handle table
/// of the process identified by `target_process_id`. The returned handle value
/// is valid only in the target process.
///
/// # Arguments
///
/// * `source_handle` - The handle to duplicate (must be valid in the current process)
/// * `target_process_id` - The process ID of the target process
/// * `options` - Options controlling the duplication (access rights, close source, etc.)
///
/// # Returns
///
/// * `Ok(handle)` - The handle value in the target process's handle table
/// * `Err(HandleDuplicationError)` - If duplication failed
///
/// # Errors
///
/// * [`HandleDuplicationError::ProcessNotFound`] - Target process doesn't exist or can't be opened
/// * [`HandleDuplicationError::AccessDenied`] - Insufficient privileges to duplicate to target
/// * [`HandleDuplicationError::InvalidSourceHandle`] - The source handle is invalid
/// * [`HandleDuplicationError::InvalidParameter`] - Invalid options provided
///
/// # Example
///
/// ```ignore
/// let options = DuplicateOptions::same_access();
/// let remote_handle = duplicate_handle_to_process(my_handle, target_pid, options)?;
/// // remote_handle is now valid in the target process
/// ```
#[cfg(windows)]
pub fn duplicate_handle_to_process(
    source_handle: HANDLE,
    target_process_id: u32,
    options: DuplicateOptions,
) -> Result<HANDLE, HandleDuplicationError> {
    // SAFETY: OpenProcess is called with PROCESS_DUP_HANDLE which is the minimum
    // required access right for DuplicateHandle. FALSE for bInheritHandle means
    // the returned handle is not inheritable by child processes.
    let target_process = unsafe { OpenProcess(PROCESS_DUP_HANDLE, FALSE, target_process_id) };

    if target_process == 0 {
        let error = unsafe { GetLastError() };
        return Err(if error == ERROR_ACCESS_DENIED {
            HandleDuplicationError::AccessDenied
        } else {
            HandleDuplicationError::ProcessNotFound
        });
    }

    // SAFETY: GetCurrentProcess returns a pseudo-handle to the current process.
    // This pseudo-handle does not need to be closed.
    let current_process = unsafe { GetCurrentProcess() };

    let mut new_handle: HANDLE = 0;
    let flags = options.to_flags();
    let access = if options.same_access {
        0
    } else {
        options.desired_access
    };

    // SAFETY: DuplicateHandle is called with valid process handles.
    // - source_process: current process pseudo-handle (always valid)
    // - source_handle: caller-provided, validity is checked by the API
    // - target_process: opened successfully above
    // - new_handle: pointer to stack variable for output
    let result = unsafe {
        DuplicateHandle(
            current_process,
            source_handle,
            target_process,
            &mut new_handle,
            access,
            FALSE, // bInheritHandle - new handle is not inheritable
            flags,
        )
    };

    // SAFETY: CloseHandle is called with a valid handle obtained from OpenProcess.
    unsafe { CloseHandle(target_process) };

    if result == 0 {
        let error = unsafe { GetLastError() };
        return Err(HandleDuplicationError::from_win32(error));
    }

    Ok(new_handle)
}

/// Duplicates a handle from a source process to the current process.
///
/// This function creates a duplicate of a handle from the source process
/// in the current process's handle table. This is used when receiving
/// handles from another process.
///
/// # Arguments
///
/// * `source_process_id` - The process ID of the source process
/// * `source_handle` - The handle value in the source process
/// * `options` - Options controlling the duplication (access rights, close source, etc.)
///
/// # Returns
///
/// * `Ok(handle)` - The handle value in the current process's handle table
/// * `Err(HandleDuplicationError)` - If duplication failed
///
/// # Errors
///
/// * [`HandleDuplicationError::ProcessNotFound`] - Source process doesn't exist or can't be opened
/// * [`HandleDuplicationError::AccessDenied`] - Insufficient privileges to duplicate from source
/// * [`HandleDuplicationError::InvalidSourceHandle`] - The source handle is invalid
/// * [`HandleDuplicationError::InvalidParameter`] - Invalid options provided
///
/// # Example
///
/// ```ignore
/// let options = DuplicateOptions::same_access();
/// let local_handle = duplicate_handle_from_process(source_pid, remote_handle, options)?;
/// // local_handle is now valid in the current process
/// ```
#[cfg(windows)]
pub fn duplicate_handle_from_process(
    source_process_id: u32,
    source_handle: HANDLE,
    options: DuplicateOptions,
) -> Result<HANDLE, HandleDuplicationError> {
    // SAFETY: OpenProcess is called with PROCESS_DUP_HANDLE which is the minimum
    // required access right for DuplicateHandle. FALSE for bInheritHandle means
    // the returned handle is not inheritable by child processes.
    let source_process = unsafe { OpenProcess(PROCESS_DUP_HANDLE, FALSE, source_process_id) };

    if source_process == 0 {
        let error = unsafe { GetLastError() };
        return Err(if error == ERROR_ACCESS_DENIED {
            HandleDuplicationError::AccessDenied
        } else {
            HandleDuplicationError::ProcessNotFound
        });
    }

    // SAFETY: GetCurrentProcess returns a pseudo-handle to the current process.
    // This pseudo-handle does not need to be closed.
    let current_process = unsafe { GetCurrentProcess() };

    let mut new_handle: HANDLE = 0;
    let flags = options.to_flags();
    let access = if options.same_access {
        0
    } else {
        options.desired_access
    };

    // SAFETY: DuplicateHandle is called with valid process handles.
    // - source_process: opened successfully above
    // - source_handle: provided by caller, validity is checked by the API
    // - target_process: current process pseudo-handle (always valid)
    // - new_handle: pointer to stack variable for output
    let result = unsafe {
        DuplicateHandle(
            source_process,
            source_handle,
            current_process,
            &mut new_handle,
            access,
            FALSE, // bInheritHandle - new handle is not inheritable
            flags,
        )
    };

    // SAFETY: CloseHandle is called with a valid handle obtained from OpenProcess.
    unsafe { CloseHandle(source_process) };

    if result == 0 {
        let error = unsafe { GetLastError() };
        return Err(HandleDuplicationError::from_win32(error));
    }

    Ok(new_handle)
}

/// Duplicates a handle within the current process.
///
/// This is a convenience function for duplicating a handle to create an
/// independent copy within the same process. This is useful for creating
/// multiple references to the same underlying resource.
///
/// # Arguments
///
/// * `handle` - The handle to duplicate
/// * `options` - Options controlling the duplication
///
/// # Returns
///
/// * `Ok(handle)` - The new handle value
/// * `Err(HandleDuplicationError)` - If duplication failed
///
/// # Example
///
/// ```ignore
/// let options = DuplicateOptions::same_access();
/// let cloned = duplicate_handle_local(original_handle, options)?;
/// // cloned is an independent handle to the same resource
/// ```
#[cfg(windows)]
pub fn duplicate_handle_local(
    handle: HANDLE,
    options: DuplicateOptions,
) -> Result<HANDLE, HandleDuplicationError> {
    // SAFETY: GetCurrentProcess returns a pseudo-handle to the current process.
    let current_process = unsafe { GetCurrentProcess() };

    let mut new_handle: HANDLE = 0;
    let flags = options.to_flags();
    let access = if options.same_access {
        0
    } else {
        options.desired_access
    };

    // SAFETY: DuplicateHandle is called with the current process as both source and target.
    let result = unsafe {
        DuplicateHandle(
            current_process,
            handle,
            current_process,
            &mut new_handle,
            access,
            FALSE,
            flags,
        )
    };

    if result == 0 {
        let error = unsafe { GetLastError() };
        return Err(HandleDuplicationError::from_win32(error));
    }

    Ok(new_handle)
}

// ============================================================================
// Non-Windows Stub Implementation
// ============================================================================

/// Stub implementation for non-Windows platforms.
#[cfg(not(windows))]
pub fn duplicate_handle_to_process(
    _source_handle: isize,
    _target_process_id: u32,
    _options: DuplicateOptions,
) -> Result<isize, HandleDuplicationError> {
    Err(HandleDuplicationError::InternalError(0))
}

/// Stub implementation for non-Windows platforms.
#[cfg(not(windows))]
pub fn duplicate_handle_from_process(
    _source_process_id: u32,
    _source_handle: isize,
    _options: DuplicateOptions,
) -> Result<isize, HandleDuplicationError> {
    Err(HandleDuplicationError::InternalError(0))
}

/// Stub implementation for non-Windows platforms.
#[cfg(not(windows))]
pub fn duplicate_handle_local(
    _handle: isize,
    _options: DuplicateOptions,
) -> Result<isize, HandleDuplicationError> {
    Err(HandleDuplicationError::InternalError(0))
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_duplicate_options_same_access() {
        let options = DuplicateOptions::same_access();
        assert!(options.same_access);
        assert!(!options.close_source);
        assert_eq!(options.desired_access, 0);
    }

    #[test]
    fn test_duplicate_options_with_access() {
        let options = DuplicateOptions::with_access(0x1234);
        assert!(!options.same_access);
        assert!(!options.close_source);
        assert_eq!(options.desired_access, 0x1234);
    }

    #[test]
    fn test_duplicate_options_close_source() {
        let options = DuplicateOptions::same_access().close_source();
        assert!(options.same_access);
        assert!(options.close_source);
    }

    #[test]
    fn test_duplicate_options_default() {
        let options = DuplicateOptions::default();
        assert!(options.same_access);
        assert!(!options.close_source);
        assert_eq!(options.desired_access, 0);
    }

    #[test]
    fn test_error_display() {
        assert_eq!(
            format!("{}", HandleDuplicationError::ProcessNotFound),
            "Target process not found or could not be opened"
        );
        assert_eq!(
            format!("{}", HandleDuplicationError::AccessDenied),
            "Access denied to target process"
        );
        assert_eq!(
            format!("{}", HandleDuplicationError::InvalidSourceHandle),
            "Source handle is invalid"
        );
        assert_eq!(
            format!("{}", HandleDuplicationError::InvalidParameter),
            "Invalid parameter provided"
        );
        assert_eq!(
            format!("{}", HandleDuplicationError::InternalError(42)),
            "Internal error (code: 42)"
        );
    }

    #[test]
    fn test_error_traits() {
        // Test Clone
        let error = HandleDuplicationError::AccessDenied;
        let cloned = error.clone();
        assert_eq!(error, cloned);

        // Test Copy
        let copied = error;
        assert_eq!(error, copied);

        // Test Hash (via HashSet)
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(HandleDuplicationError::ProcessNotFound);
        set.insert(HandleDuplicationError::AccessDenied);
        assert_eq!(set.len(), 2);
    }

    #[cfg(windows)]
    #[test]
    fn test_duplicate_options_to_flags() {
        let options = DuplicateOptions::same_access();
        assert_eq!(options.to_flags(), DUPLICATE_SAME_ACCESS);

        let options = DuplicateOptions::with_access(0).close_source();
        assert_eq!(options.to_flags(), DUPLICATE_CLOSE_SOURCE);

        let options = DuplicateOptions::same_access().close_source();
        assert_eq!(
            options.to_flags(),
            DUPLICATE_SAME_ACCESS | DUPLICATE_CLOSE_SOURCE
        );
    }

    #[cfg(windows)]
    #[test]
    fn test_error_from_win32() {
        assert_eq!(
            HandleDuplicationError::from_win32(ERROR_ACCESS_DENIED),
            HandleDuplicationError::AccessDenied
        );
        assert_eq!(
            HandleDuplicationError::from_win32(ERROR_INVALID_HANDLE),
            HandleDuplicationError::InvalidSourceHandle
        );
        assert_eq!(
            HandleDuplicationError::from_win32(ERROR_INVALID_PARAMETER),
            HandleDuplicationError::InvalidParameter
        );
        assert!(matches!(
            HandleDuplicationError::from_win32(9999),
            HandleDuplicationError::InternalError(9999)
        ));
    }

    #[cfg(not(windows))]
    #[test]
    fn test_stub_implementations_return_errors() {
        let options = DuplicateOptions::same_access();
        assert!(duplicate_handle_to_process(0, 0, options).is_err());
        assert!(duplicate_handle_from_process(0, 0, options).is_err());
        assert!(duplicate_handle_local(0, options).is_err());
    }

    // Windows-specific integration tests
    #[cfg(windows)]
    mod windows_tests {
        use super::*;
        use windows_sys::Win32::System::Threading::GetCurrentProcessId;

        #[test]
        fn test_duplicate_handle_local_with_event() {
            use windows_sys::Win32::Foundation::CloseHandle;
            use windows_sys::Win32::System::Threading::CreateEventW;

            // SAFETY: CreateEventW with NULL parameters creates a manual-reset event
            let event = unsafe { CreateEventW(core::ptr::null(), 1, 0, core::ptr::null()) };
            assert!(event != 0, "Failed to create event");

            let options = DuplicateOptions::same_access();
            let result = duplicate_handle_local(event, options);

            // Clean up original handle
            unsafe { CloseHandle(event) };

            match result {
                Ok(duplicated) => {
                    // Clean up duplicated handle
                    unsafe { CloseHandle(duplicated) };
                }
                Err(e) => {
                    panic!("Failed to duplicate local handle: {}", e);
                }
            }
        }

        #[test]
        fn test_duplicate_to_current_process() {
            use windows_sys::Win32::Foundation::CloseHandle;
            use windows_sys::Win32::System::Threading::CreateEventW;

            let event = unsafe { CreateEventW(core::ptr::null(), 1, 0, core::ptr::null()) };
            assert!(event != 0, "Failed to create event");

            let current_pid = unsafe { GetCurrentProcessId() };
            let options = DuplicateOptions::same_access();
            let result = duplicate_handle_to_process(event, current_pid, options);

            unsafe { CloseHandle(event) };

            match result {
                Ok(duplicated) => {
                    unsafe { CloseHandle(duplicated) };
                }
                Err(e) => {
                    panic!("Failed to duplicate handle to current process: {}", e);
                }
            }
        }

        #[test]
        fn test_duplicate_invalid_handle() {
            let options = DuplicateOptions::same_access();
            let result = duplicate_handle_local(INVALID_HANDLE_VALUE, options);
            assert!(result.is_err());
        }

        #[test]
        fn test_duplicate_to_nonexistent_process() {
            use windows_sys::Win32::Foundation::CloseHandle;
            use windows_sys::Win32::System::Threading::CreateEventW;

            let event = unsafe { CreateEventW(core::ptr::null(), 1, 0, core::ptr::null()) };
            assert!(event != 0, "Failed to create event");

            // Use an invalid PID (0 is always invalid on Windows)
            let options = DuplicateOptions::same_access();
            let result = duplicate_handle_to_process(event, 0, options);

            unsafe { CloseHandle(event) };

            assert!(result.is_err());
        }
    }
}
