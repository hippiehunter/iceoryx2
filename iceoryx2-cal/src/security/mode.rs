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

//! Security mode configuration for services.
//!
//! This module provides [`SecurityMode`], which determines whether a service operates
//! in public mode (default, no authentication required) or secured mode (IAM-controlled access).

use iceoryx2_bb_derive_macros::ZeroCopySend;
use iceoryx2_bb_elementary_traits::zero_copy_send::ZeroCopySend;
use serde::{Deserialize, Serialize};

/// Determines the security mode of a service.
///
/// - [`SecurityMode::Public`]: Default mode. No authentication required.
/// - [`SecurityMode::Secured`]: Requires IAM authentication.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize, ZeroCopySend,
)]
#[serde(rename_all = "kebab-case")]
#[repr(C)]
pub enum SecurityMode {
    /// Public mode - no authentication required.
    #[default]
    Public,

    /// Secured mode - IAM authentication required.
    Secured,
}

impl SecurityMode {
    /// Returns `true` if this mode requires IAM authentication.
    #[inline]
    pub const fn requires_iam(&self) -> bool {
        matches!(self, SecurityMode::Secured)
    }

    /// Returns `true` if this is public mode.
    #[inline]
    pub const fn is_public(&self) -> bool {
        matches!(self, SecurityMode::Public)
    }

    /// Returns `true` if this is secured mode.
    #[inline]
    pub const fn is_secured(&self) -> bool {
        matches!(self, SecurityMode::Secured)
    }
}

impl core::fmt::Display for SecurityMode {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            SecurityMode::Public => write!(f, "public"),
            SecurityMode::Secured => write!(f, "secured"),
        }
    }
}
