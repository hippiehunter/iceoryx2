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

//! Identity and Access Management (IAM) for secured iceoryx2 services.
//!
//! This module provides the protocol and error types for IAM client-server
//! communication in secured inter-process communication scenarios.
//!
//! # Overview
//!
//! The IAM system provides:
//! - **Protocol types**: Message formats for client-server communication
//! - **Error types**: Error handling for server and client operations
//!
//! # Protocol
//!
//! Communication between IAM clients and the IAM server uses a request-response
//! protocol with the following message types:
//!
//! - [`IamRequest`]: Requests sent from clients to the server
//! - [`IamResponse`]: Responses sent from the server to clients
//! - [`IamNotification`]: Asynchronous notifications from the server
//!
//! # Errors
//!
//! - [`IamServerError`]: Errors that can occur in server operations
//! - [`IamClientError`]: Errors that can occur in client operations
//!
//! # Example
//!
//! ```ignore
//! use iceoryx2::iam::{IamRequest, IamResponse, ProtocolVersion, SessionId};
//!
//! // Create a handshake request
//! let request = IamRequest::Hello {
//!     protocol_version: ProtocolVersion::CURRENT,
//!     node_id: node.unique_system_id(),
//! };
//!
//! // Check protocol version compatibility
//! let client_version = ProtocolVersion::new(1, 0);
//! let server_version = ProtocolVersion::new(1, 1);
//! assert!(client_version.is_compatible_with(&server_version));
//! ```

pub mod error;
pub mod protocol;

// Re-export error types
pub use error::{IamClientError, IamServerError};

// Re-export protocol types
pub use protocol::{
    DenialReason, IamNotification, IamRequest, IamResponse, MessagingPatternKind, PortType,
    ProtocolVersion, SegmentInfo, SessionId, INVALID_SESSION_ID,
    MAX_ERROR_MESSAGE_LENGTH, MAX_HANDLES_PER_MESSAGE, MAX_SEGMENTS_PER_ATTACH,
};
