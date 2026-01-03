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

//! Traits for handle-based resource access.
//!
//! This module provides the core traits for resources that can be opened from OS handles
//! rather than by name. This is the foundation for the IAM security model.

use core::fmt::Debug;

use super::handle::PlatformHandle;

/// A resource that can be opened from a platform handle.
///
/// This trait is implemented by resources that support handle-based access,
/// for use with the IAM security model where handles are passed from a
/// privileged daemon to authorized clients.
pub trait HandleBasedConcept: Debug + Sized {
    /// Configuration required to open the resource from a handle.
    type Configuration;

    /// Error type returned when opening from a handle fails.
    type OpenError: Debug;

    /// Opens the resource from a platform handle.
    ///
    /// Takes ownership of the handle and attempts to construct the resource.
    fn open_from_handle(
        handle: PlatformHandle,
        config: &Self::Configuration,
    ) -> Result<Self, Self::OpenError>;
}

/// Builder pattern for constructing handle-based resources.
///
/// Provides a fluent interface for opening resources from handles,
/// following the same pattern as [`crate::named_concept::NamedConceptBuilder`].
pub trait HandleBasedConceptBuilder<T: HandleBasedConcept>: Sized {
    /// Creates a new builder from a platform handle.
    ///
    /// Takes ownership of the handle.
    fn from_handle(handle: PlatformHandle) -> Self;

    /// Sets the configuration for opening the resource.
    fn config(self, config: &T::Configuration) -> Self;

    /// Consumes the builder and attempts to open the resource.
    fn open(self) -> Result<T, T::OpenError>;
}
