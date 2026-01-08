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

//! Error types for IAM (Identity and Access Management) operations.
//!
//! This module defines the error types that can occur in IAM server and client
//! operations during secured inter-process communication.

/// Errors that can occur in IAM server operations.
///
/// This enum represents the various failure modes when the IAM server
/// handles client requests and manages shared memory segments.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IamServerError {
    /// Failed to create a listener for incoming client connections.
    ListenerCreationFailed,

    /// Failed to accept an incoming client connection.
    AcceptFailed,

    /// Failed to send a response to a client.
    SendFailed,

    /// Failed to receive a request from a client.
    ReceiveFailed,

    /// Failed to pass a handle to a client.
    HandlePassingFailed,

    /// Failed to create a shared memory segment.
    SegmentCreationFailed,

    /// The requested segment was not found.
    SegmentNotFound,

    /// The requested session was not found.
    SessionNotFound,

    /// Policy evaluation failed for the request.
    PolicyEvaluationFailed,

    /// Failed to serialize or deserialize protocol messages.
    SerializationError,

    /// Failed to retrieve client credentials.
    CredentialsFailed,

    /// A resource limit has been exceeded.
    ResourceLimitExceeded,

    /// Invalid segment size (zero or exceeds maximum).
    InvalidSegmentSize,

    /// An internal error occurred.
    InternalError,
}

impl core::fmt::Display for IamServerError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "IamServerError::{self:?}")
    }
}

impl core::error::Error for IamServerError {}

/// Errors that can occur in IAM client operations.
///
/// This enum represents the various failure modes when a client
/// communicates with the IAM server.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IamClientError {
    /// Failed to establish a connection to the IAM server.
    ConnectionFailed,

    /// The handshake with the IAM server failed.
    HandshakeFailed,

    /// Protocol version mismatch between client and server.
    VersionMismatch,

    /// The request was denied by the IAM server.
    RequestDenied,

    /// Failed to send a request to the server.
    SendFailed,

    /// Failed to receive a response from the server.
    ReceiveFailed,

    /// Failed to receive a handle from the server.
    HandleReceiveFailed,

    /// The operation timed out.
    Timeout,

    /// The session is invalid or has expired.
    SessionInvalid,

    /// Failed to serialize or deserialize protocol messages.
    SerializationError,

    /// A protocol error occurred.
    ProtocolError,

    /// An internal error occurred.
    InternalError,
}

impl core::fmt::Display for IamClientError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "IamClientError::{self:?}")
    }
}

impl core::error::Error for IamClientError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_iam_server_error_display() {
        let error = IamServerError::ListenerCreationFailed;
        assert_eq!(
            format!("{}", error),
            "IamServerError::ListenerCreationFailed"
        );

        let error = IamServerError::AcceptFailed;
        assert_eq!(format!("{}", error), "IamServerError::AcceptFailed");

        let error = IamServerError::SendFailed;
        assert_eq!(format!("{}", error), "IamServerError::SendFailed");

        let error = IamServerError::ReceiveFailed;
        assert_eq!(format!("{}", error), "IamServerError::ReceiveFailed");

        let error = IamServerError::HandlePassingFailed;
        assert_eq!(format!("{}", error), "IamServerError::HandlePassingFailed");

        let error = IamServerError::SegmentCreationFailed;
        assert_eq!(
            format!("{}", error),
            "IamServerError::SegmentCreationFailed"
        );

        let error = IamServerError::SegmentNotFound;
        assert_eq!(format!("{}", error), "IamServerError::SegmentNotFound");

        let error = IamServerError::SessionNotFound;
        assert_eq!(format!("{}", error), "IamServerError::SessionNotFound");

        let error = IamServerError::PolicyEvaluationFailed;
        assert_eq!(
            format!("{}", error),
            "IamServerError::PolicyEvaluationFailed"
        );

        let error = IamServerError::SerializationError;
        assert_eq!(format!("{}", error), "IamServerError::SerializationError");

        let error = IamServerError::CredentialsFailed;
        assert_eq!(format!("{}", error), "IamServerError::CredentialsFailed");

        let error = IamServerError::ResourceLimitExceeded;
        assert_eq!(
            format!("{}", error),
            "IamServerError::ResourceLimitExceeded"
        );

        let error = IamServerError::InternalError;
        assert_eq!(format!("{}", error), "IamServerError::InternalError");
    }

    #[test]
    fn test_iam_client_error_display() {
        let error = IamClientError::ConnectionFailed;
        assert_eq!(format!("{}", error), "IamClientError::ConnectionFailed");

        let error = IamClientError::HandshakeFailed;
        assert_eq!(format!("{}", error), "IamClientError::HandshakeFailed");

        let error = IamClientError::VersionMismatch;
        assert_eq!(format!("{}", error), "IamClientError::VersionMismatch");

        let error = IamClientError::RequestDenied;
        assert_eq!(format!("{}", error), "IamClientError::RequestDenied");

        let error = IamClientError::SendFailed;
        assert_eq!(format!("{}", error), "IamClientError::SendFailed");

        let error = IamClientError::ReceiveFailed;
        assert_eq!(format!("{}", error), "IamClientError::ReceiveFailed");

        let error = IamClientError::HandleReceiveFailed;
        assert_eq!(format!("{}", error), "IamClientError::HandleReceiveFailed");

        let error = IamClientError::Timeout;
        assert_eq!(format!("{}", error), "IamClientError::Timeout");

        let error = IamClientError::SessionInvalid;
        assert_eq!(format!("{}", error), "IamClientError::SessionInvalid");

        let error = IamClientError::SerializationError;
        assert_eq!(format!("{}", error), "IamClientError::SerializationError");

        let error = IamClientError::ProtocolError;
        assert_eq!(format!("{}", error), "IamClientError::ProtocolError");

        let error = IamClientError::InternalError;
        assert_eq!(format!("{}", error), "IamClientError::InternalError");
    }

    #[test]
    fn test_iam_server_error_equality() {
        assert_eq!(
            IamServerError::ListenerCreationFailed,
            IamServerError::ListenerCreationFailed
        );
        assert_ne!(
            IamServerError::ListenerCreationFailed,
            IamServerError::AcceptFailed
        );
    }

    #[test]
    fn test_iam_client_error_equality() {
        assert_eq!(
            IamClientError::ConnectionFailed,
            IamClientError::ConnectionFailed
        );
        assert_ne!(
            IamClientError::ConnectionFailed,
            IamClientError::HandshakeFailed
        );
    }

    #[test]
    fn test_iam_server_error_clone_copy() {
        let error = IamServerError::InternalError;
        let cloned = error.clone();
        let copied = error;
        assert_eq!(error, cloned);
        assert_eq!(error, copied);
    }

    #[test]
    fn test_iam_client_error_clone_copy() {
        let error = IamClientError::InternalError;
        let cloned = error.clone();
        let copied = error;
        assert_eq!(error, cloned);
        assert_eq!(error, copied);
    }

    #[test]
    fn test_iam_server_error_hash() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(IamServerError::ListenerCreationFailed);
        set.insert(IamServerError::AcceptFailed);
        set.insert(IamServerError::SendFailed);
        assert_eq!(set.len(), 3);
    }

    #[test]
    fn test_iam_client_error_hash() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(IamClientError::ConnectionFailed);
        set.insert(IamClientError::HandshakeFailed);
        set.insert(IamClientError::Timeout);
        assert_eq!(set.len(), 3);
    }
}
