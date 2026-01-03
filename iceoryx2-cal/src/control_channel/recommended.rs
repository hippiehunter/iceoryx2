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

//! Platform-specific recommended [`ControlChannel`] implementations.
//!
//! This module provides type aliases for the recommended control channel
//! implementation on each platform.
//!
//! # Unix
//!
//! On Unix-like systems (Linux, macOS, etc.), the recommended implementation
//! is [`unix_stream::Channel`] which uses Unix domain stream sockets.
//! This provides:
//! - Peer credential verification via SO_PEERCRED
//! - File descriptor passing via SCM_RIGHTS
//!
//! # Example
//!
//! ```ignore
//! use iceoryx2_cal::control_channel::recommended::Ipc;
//! use iceoryx2_cal::control_channel::*;
//! use iceoryx2_cal::named_concept::NamedConceptBuilder;
//! use iceoryx2_bb_system_types::file_name::FileName;
//! use iceoryx2_bb_container::semantic_string::SemanticString;
//!
//! // Use the recommended control channel for IPC
//! let name = FileName::new(b"my_channel").unwrap();
//! let listener = <Ipc as ControlChannel>::ListenerBuilder::new(&name)
//!     .create()
//!     .unwrap();
//! ```

/// Recommended [`ControlChannel`] implementation for inter-process communication.
///
/// On Unix systems, this is [`unix_stream::Channel`](super::unix_stream::Channel).
#[cfg(unix)]
pub type Ipc = crate::control_channel::unix_stream::Channel;
