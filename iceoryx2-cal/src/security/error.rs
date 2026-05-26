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

//! Error types for security handle operations.
//!
//! This module defines the error types that can occur when working with
//! platform handles and handle-based resource access.

use core::fmt::Debug;

/// Errors that can occur during handle operations.
///
/// This enum represents the various failure modes when working with
/// [`PlatformHandle`](super::PlatformHandle) instances.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HandleError {
    /// Failed to duplicate the handle.
    ///
    /// This can occur when:
    /// - The process has reached its file descriptor limit
    /// - The system-wide file descriptor limit has been reached
    /// - The source handle is invalid
    DuplicationFailed,

    /// The handle is invalid or has been closed.
    ///
    /// This can occur when:
    /// - The handle was never valid
    /// - The handle has already been closed
    /// - The handle refers to a resource that no longer exists
    InvalidHandle,

    /// Insufficient permissions to perform the operation.
    ///
    /// This can occur when:
    /// - The process lacks the necessary capabilities
    /// - The handle was opened with insufficient access rights
    InsufficientPermissions,

    /// An internal error occurred.
    ///
    /// This is a catch-all for unexpected errors that don't fit other categories.
    InternalError,
}

impl core::fmt::Display for HandleError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "HandleError::{self:?}")
    }
}

impl core::error::Error for HandleError {}

/// Errors that can occur when opening a resource from a handle.
///
/// This enum represents the failure modes when using handle-based resource
/// access, such as opening shared memory from a passed file descriptor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HandleBasedOpenError {
    /// The provided handle is invalid.
    ///
    /// The handle may be closed, corrupted, or refer to an incompatible resource type.
    InvalidHandle,

    /// Failed to map the resource into the process address space.
    ///
    /// This can occur when:
    /// - Insufficient virtual memory is available
    /// - The mapping parameters are invalid
    /// - The system limit on mappings has been reached
    MappingFailed,

    /// The resource was created with an incompatible allocator.
    ///
    /// When opening shared memory, the allocator type must match what was used
    /// to create the segment.
    WrongAllocatorSelected,

    /// Insufficient permissions to access the resource.
    ///
    /// The handle may not have the required access rights (read/write) for
    /// the requested operation.
    InsufficientPermissions,

    /// The resource size does not match expectations.
    ///
    /// The segment may be smaller than required or have an unexpected size.
    SizeMismatch,

    /// An internal error occurred.
    ///
    /// This is a catch-all for unexpected errors that don't fit other categories.
    InternalError,
}

impl core::fmt::Display for HandleBasedOpenError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "HandleBasedOpenError::{self:?}")
    }
}

impl core::error::Error for HandleBasedOpenError {}

impl From<HandleError> for HandleBasedOpenError {
    fn from(error: HandleError) -> Self {
        match error {
            HandleError::DuplicationFailed => HandleBasedOpenError::InternalError,
            HandleError::InvalidHandle => HandleBasedOpenError::InvalidHandle,
            HandleError::InsufficientPermissions => HandleBasedOpenError::InsufficientPermissions,
            HandleError::InternalError => HandleBasedOpenError::InternalError,
        }
    }
}
