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

//! Security primitives for iceoryx2 secured services.
//!
//! This module provides platform-agnostic types for handle-based resource access,
//! which is the foundation for the IAM (Identity and Access Management) security model.
//!
//! # Core Types
//!
//! - [`PlatformHandle`] - RAII wrapper around OS file descriptors/handles
//! - [`AccessRights`] - Read/write permission flags for a handle
//! - [`HandleBundle`] - Bundle of a handle with segment metadata
//!
//! # Traits
//!
//! - [`HandleBasedConcept`] - Resources that can be opened from platform handles
//! - [`HandleBasedConceptBuilder`] - Builder pattern for handle-based resources
//!
//! # Error Types
//!
//! - [`HandleError`] - Errors that can occur during handle operations
//! - [`HandleBasedOpenError`] - Errors when opening resources from handles

#[cfg(feature = "std")]
pub mod credentials;
pub mod error;
pub mod handle;
mod handle_fd;
pub mod mode;
pub mod traits;

#[cfg(feature = "std")]
pub use credentials::*;
pub use error::*;
pub use handle::*;
pub(crate) use handle_fd::platform_handle_into_fd;
pub use mode::*;
pub use traits::*;
