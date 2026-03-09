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

//! Wire format helpers for IAM protocol messages.
//!
//! This module provides helper functions for serializing and deserializing IAM
//! protocol messages over CAL control channel connections. The functions handle:
//!
//! - Message framing with length prefixes
//! - Serialization via postcard
//! - Error mapping from CAL to IAM error types
//! - Handle passing between processes
//!
//! # Wire Format
//!
//! Messages are framed with a 4-byte little-endian length prefix:
//!
//! ```text
//! +--------+--------+--------+--------+-------------------+
//! |  len (4 bytes, little-endian)     |  payload (len)    |
//! +--------+--------+--------+--------+-------------------+
//! ```
//!
//! # Usage
//!
//! These functions are used internally by [`crate::iam::IamServer`] and
//! [`crate::iam::IamClient`] to communicate over CAL control channels.

use alloc::vec::Vec;

use iceoryx2_cal::control_channel::{
    ControlChannelClient, ControlChannelConnection, ControlChannelCredentialsError,
    ControlChannelReceiveError, ControlChannelSendError,
};
use iceoryx2_cal::security::PlatformHandle;
use iceoryx2_cal::serialize::{postcard::Postcard, Serialize as CalSerialize};
use serde::{de::DeserializeOwned, Serialize};

use super::error::{IamClientError, IamServerError};

/// Initial buffer capacity for message serialization/deserialization.
const INITIAL_BUFFER_CAPACITY: usize = 4096;

/// Maximum message size to prevent DoS attacks (16 MB).
const MAX_MESSAGE_SIZE: usize = 16 * 1024 * 1024;

// ============================================================================
// Server-side helper functions (for ControlChannelConnection)
// ============================================================================

/// Sends a serializable message over a CAL connection with length framing.
///
/// The message is serialized using postcard and prefixed with a 4-byte
/// little-endian length field.
///
/// # Arguments
/// * `conn` - The CAL connection to send on
/// * `msg` - The message to serialize and send
///
/// # Errors
/// Returns `IamServerError::SerializationError` if serialization fails.
/// Returns `IamServerError::SendFailed` if the send operation fails.
pub(crate) fn send_message<C: ControlChannelConnection, T: Serialize>(
    conn: &C,
    msg: &T,
) -> Result<(), IamServerError> {
    let payload = Postcard::serialize(msg).map_err(|_| IamServerError::SerializationError)?;

    // Validate payload size before casting to u32
    if payload.len() > MAX_MESSAGE_SIZE {
        return Err(IamServerError::SerializationError);
    }

    // Create framed message: length prefix + payload
    let len = payload.len() as u32;
    let mut framed = Vec::with_capacity(4 + payload.len());
    framed.extend_from_slice(&len.to_le_bytes());
    framed.extend_from_slice(&payload);

    conn.send(&framed).map_err(map_send_error_server)
}

/// Tries to receive and deserialize a message from a CAL connection (non-blocking).
///
/// This function attempts to read a complete framed message. If no data is
/// available, it returns `Ok(None)`.
///
/// # Arguments
/// * `conn` - The CAL connection to receive from
/// * `buffer` - A reusable buffer for receiving data
///
/// # Errors
/// Returns `IamServerError::SerializationError` if deserialization fails.
/// Returns `IamServerError::ReceiveFailed` if the receive operation fails.
pub(crate) fn try_receive_message<C: ControlChannelConnection, T: DeserializeOwned>(
    conn: &C,
    buffer: &mut Vec<u8>,
) -> Result<Option<T>, IamServerError> {
    // Ensure buffer has capacity for length prefix
    buffer.clear();
    buffer.resize(4, 0);

    // Try to receive the length prefix
    let bytes_read = conn.try_receive(buffer).map_err(map_receive_error_server)?;

    if bytes_read == 0 {
        return Ok(None);
    }

    // If we got a partial length prefix, read the rest (blocking)
    let mut total_header_read = bytes_read as usize;
    while total_header_read < 4 {
        let additional = conn
            .receive(&mut buffer[total_header_read..4])
            .map_err(map_receive_error_server)?;
        if additional == 0 {
            return Err(IamServerError::ReceiveFailed);
        }
        total_header_read += additional as usize;
    }

    // Parse the length prefix
    let len = u32::from_le_bytes([buffer[0], buffer[1], buffer[2], buffer[3]]) as usize;

    // Validate message size (must be > 0 and <= MAX_MESSAGE_SIZE)
    if len == 0 || len > MAX_MESSAGE_SIZE {
        return Err(IamServerError::SerializationError);
    }

    // Resize buffer to hold the payload
    buffer.resize(len, 0);

    // Read the complete payload
    let mut total_read = 0;
    while total_read < len {
        let bytes_read = conn
            .receive(&mut buffer[total_read..])
            .map_err(map_receive_error_server)?;
        if bytes_read == 0 {
            return Err(IamServerError::ReceiveFailed);
        }
        total_read += bytes_read as usize;
    }

    // Deserialize the message
    Postcard::deserialize(buffer).map_err(|_| IamServerError::SerializationError).map(Some)
}

/// Sends platform handles over a CAL connection.
///
/// Converts from `&[PlatformHandle]` to `&[&PlatformHandle]` as required by
/// the CAL interface.
///
/// # Arguments
/// * `conn` - The CAL connection to send on
/// * `handles` - The handles to send
///
/// # Errors
/// Returns `IamServerError::HandlePassingFailed` if the send operation fails.
pub(crate) fn send_handles<C: ControlChannelConnection>(
    conn: &C,
    handles: &[PlatformHandle],
) -> Result<(), IamServerError> {
    // Convert &[PlatformHandle] to Vec<&PlatformHandle> for CAL interface
    let handle_refs: Vec<&PlatformHandle> = handles.iter().collect();
    conn.send_handles(&handle_refs)
        .map_err(|_| IamServerError::HandlePassingFailed)
}

/// Gets peer credentials from a CAL connection.
///
/// # Arguments
/// * `conn` - The CAL connection to get credentials from
///
/// # Errors
/// Returns `IamServerError::CredentialsFailed` if getting credentials fails.
pub(crate) fn peer_credentials<C: ControlChannelConnection>(
    conn: &C,
) -> Result<iceoryx2_cal::security::ProcessCredentials, IamServerError> {
    conn.peer_credentials().map_err(map_credentials_error)
}

// ============================================================================
// Client-side helper functions (for ControlChannelClient)
// ============================================================================

/// Sends a serializable message over a CAL client connection with length framing.
///
/// The message is serialized using postcard and prefixed with a 4-byte
/// little-endian length field.
///
/// # Arguments
/// * `client` - The CAL client connection to send on
/// * `msg` - The message to serialize and send
///
/// # Errors
/// Returns `IamClientError::SerializationError` if serialization fails.
/// Returns `IamClientError::SendFailed` if the send operation fails.
pub(crate) fn client_send_message<C: ControlChannelClient, T: Serialize>(
    client: &C,
    msg: &T,
) -> Result<(), IamClientError> {
    let payload = Postcard::serialize(msg).map_err(|_| IamClientError::SerializationError)?;

    // Validate payload size before casting to u32
    if payload.len() > MAX_MESSAGE_SIZE {
        return Err(IamClientError::SerializationError);
    }

    // Create framed message: length prefix + payload
    let len = payload.len() as u32;
    let mut framed = Vec::with_capacity(4 + payload.len());
    framed.extend_from_slice(&len.to_le_bytes());
    framed.extend_from_slice(&payload);

    client.send(&framed).map_err(map_send_error_client)
}

/// Receives and deserializes a message from a CAL client connection (blocking).
///
/// This function blocks until a complete framed message is received.
///
/// # Arguments
/// * `client` - The CAL client connection to receive from
/// * `buffer` - A reusable buffer for receiving data
///
/// # Errors
/// Returns `IamClientError::SerializationError` if deserialization fails.
/// Returns `IamClientError::ReceiveFailed` if the receive operation fails.
pub(crate) fn client_receive_message<C: ControlChannelClient, T: DeserializeOwned>(
    client: &C,
    buffer: &mut Vec<u8>,
) -> Result<T, IamClientError> {
    // Ensure buffer has capacity for length prefix
    buffer.clear();
    buffer.resize(4, 0);

    // Receive the length prefix (blocking)
    let mut total_read = 0;
    while total_read < 4 {
        let bytes_read = client
            .receive(&mut buffer[total_read..4])
            .map_err(map_receive_error_client)?;
        if bytes_read == 0 {
            return Err(IamClientError::ReceiveFailed);
        }
        total_read += bytes_read as usize;
    }

    // Parse the length prefix
    let len = u32::from_le_bytes([buffer[0], buffer[1], buffer[2], buffer[3]]) as usize;

    // Validate message size (must be > 0 and <= MAX_MESSAGE_SIZE)
    if len == 0 || len > MAX_MESSAGE_SIZE {
        return Err(IamClientError::SerializationError);
    }

    // Resize buffer to hold the payload
    buffer.resize(len, 0);

    // Read the complete payload
    let mut total_read = 0;
    while total_read < len {
        let bytes_read = client
            .receive(&mut buffer[total_read..])
            .map_err(map_receive_error_client)?;
        if bytes_read == 0 {
            return Err(IamClientError::ReceiveFailed);
        }
        total_read += bytes_read as usize;
    }

    // Deserialize the message
    Postcard::deserialize(buffer).map_err(|_| IamClientError::SerializationError)
}

/// Tries to receive and deserialize a message from a CAL client connection (non-blocking).
///
/// This function attempts to read a complete framed message. If no data is
/// available, it returns `Ok(None)`.
///
/// # Arguments
/// * `client` - The CAL client connection to receive from
/// * `buffer` - A reusable buffer for receiving data
///
/// # Returns
/// * `Ok(Some(message))` - A complete message was received
/// * `Ok(None)` - No data is available (would block)
///
/// # Errors
/// Returns `IamClientError::SerializationError` if deserialization fails.
/// Returns `IamClientError::ReceiveFailed` if the receive operation fails.
pub(crate) fn client_try_receive_message<C: ControlChannelClient, T: DeserializeOwned>(
    client: &C,
    buffer: &mut Vec<u8>,
) -> Result<Option<T>, IamClientError> {
    // Ensure buffer has capacity for length prefix
    buffer.clear();
    buffer.resize(4, 0);

    // Try to receive the length prefix (non-blocking)
    let bytes_read = client.try_receive(buffer).map_err(map_receive_error_client)?;

    if bytes_read == 0 {
        return Ok(None); // No data available
    }

    // If we got partial data, complete the read (blocking for remainder)
    let mut total_header_read = bytes_read as usize;
    while total_header_read < 4 {
        let additional = client
            .receive(&mut buffer[total_header_read..4])
            .map_err(map_receive_error_client)?;
        if additional == 0 {
            return Err(IamClientError::ReceiveFailed);
        }
        total_header_read += additional as usize;
    }

    // Parse the length prefix
    let len = u32::from_le_bytes([buffer[0], buffer[1], buffer[2], buffer[3]]) as usize;

    // Validate message size (must be > 0 and <= MAX_MESSAGE_SIZE)
    if len == 0 || len > MAX_MESSAGE_SIZE {
        return Err(IamClientError::SerializationError);
    }

    // Resize buffer to hold the payload
    buffer.resize(len, 0);

    // Read the complete payload
    let mut total_read = 0;
    while total_read < len {
        let bytes_read = client
            .receive(&mut buffer[total_read..])
            .map_err(map_receive_error_client)?;
        if bytes_read == 0 {
            return Err(IamClientError::ReceiveFailed);
        }
        total_read += bytes_read as usize;
    }

    // Deserialize the message
    Postcard::deserialize(buffer)
        .map_err(|_| IamClientError::SerializationError)
        .map(Some)
}

/// Tries to receive platform handles from a CAL client connection (non-blocking).
///
/// # Arguments
/// * `client` - The CAL client connection to receive from
///
/// # Returns
/// * `Ok(Some(handles))` - Handles were received
/// * `Ok(None)` - No handles available
///
/// # Errors
/// Returns `IamClientError::HandleReceiveFailed` if the receive operation fails.
pub(crate) fn client_try_receive_handles<C: ControlChannelClient>(
    client: &C,
) -> Result<Option<Vec<PlatformHandle>>, IamClientError> {
    client
        .try_receive_handles()
        .map_err(|_| IamClientError::HandleReceiveFailed)
}

/// Receives platform handles from a CAL client connection (blocking).
///
/// # Arguments
/// * `client` - The CAL client connection to receive from
///
/// # Errors
/// Returns `IamClientError::HandleReceiveFailed` if the receive operation fails
/// or no handles were received.
pub(crate) fn client_receive_handles<C: ControlChannelClient>(
    client: &C,
) -> Result<Vec<PlatformHandle>, IamClientError> {
    client
        .receive_handles()
        .map_err(|_| IamClientError::HandleReceiveFailed)?
        .ok_or(IamClientError::HandleReceiveFailed)
}

/// Sends platform handles from a CAL client connection to the server.
///
/// This is used by producers (publisher/server) to send segment handles
/// to the IAM server for brokering to consumers.
///
/// # Arguments
/// * `client` - The CAL client connection to send on
/// * `handles` - The handles to send
///
/// # Errors
/// Returns `IamClientError::HandleSendFailed` if the send operation fails.
pub(crate) fn client_send_handles<C: ControlChannelClient>(
    client: &C,
    handles: &[PlatformHandle],
) -> Result<(), IamClientError> {
    let handle_refs: Vec<&PlatformHandle> = handles.iter().collect();
    client
        .send_handles(&handle_refs)
        .map_err(|_| IamClientError::HandleSendFailed)
}

/// Receives platform handles from a client connection (server-side).
///
/// This is used by the IAM server to receive segment handles sent by
/// producers during segment registration.
///
/// # Arguments
/// * `conn` - The CAL connection to receive from
///
/// # Errors
/// Returns `IamServerError::HandlePassingFailed` if the receive operation fails
/// or no handles were received.
pub(crate) fn receive_handles_from_client<C: ControlChannelConnection>(
    conn: &C,
) -> Result<Vec<PlatformHandle>, IamServerError> {
    conn.receive_handles()
        .map_err(|_| IamServerError::HandlePassingFailed)?
        .ok_or(IamServerError::HandlePassingFailed)
}

/// Creates a new buffer with the initial capacity for receiving messages.
pub(crate) fn new_receive_buffer() -> Vec<u8> {
    Vec::with_capacity(INITIAL_BUFFER_CAPACITY)
}

// ============================================================================
// Error mapping functions
// ============================================================================

/// Maps a CAL send error to an IAM server error.
fn map_send_error_server(e: ControlChannelSendError) -> IamServerError {
    match e {
        ControlChannelSendError::MessageTooLarge => IamServerError::SendFailed,
        ControlChannelSendError::ConnectionReset => IamServerError::SendFailed,
        ControlChannelSendError::Interrupt => IamServerError::SendFailed,
        ControlChannelSendError::IoError => IamServerError::SendFailed,
        ControlChannelSendError::InsufficientPermissions => IamServerError::SendFailed,
        ControlChannelSendError::InsufficientResources => IamServerError::SendFailed,
        ControlChannelSendError::InsufficientMemory => IamServerError::SendFailed,
        ControlChannelSendError::NotConnected => IamServerError::SendFailed,
        ControlChannelSendError::BrokenPipe => IamServerError::SendFailed,
        ControlChannelSendError::WouldBlock => IamServerError::SendFailed,
        ControlChannelSendError::InternalFailure => IamServerError::InternalError,
    }
}

/// Maps a CAL receive error to an IAM server error.
fn map_receive_error_server(e: ControlChannelReceiveError) -> IamServerError {
    match e {
        ControlChannelReceiveError::ConnectionReset => IamServerError::ReceiveFailed,
        ControlChannelReceiveError::Interrupt => IamServerError::ReceiveFailed,
        ControlChannelReceiveError::IoError => IamServerError::ReceiveFailed,
        ControlChannelReceiveError::InsufficientResources => IamServerError::ReceiveFailed,
        ControlChannelReceiveError::InsufficientMemory => IamServerError::ReceiveFailed,
        ControlChannelReceiveError::NotConnected => IamServerError::ReceiveFailed,
        ControlChannelReceiveError::WouldBlock => IamServerError::ReceiveFailed,
        ControlChannelReceiveError::ReceivedInvalidFileDescriptor => IamServerError::ReceiveFailed,
        ControlChannelReceiveError::InternalFailure => IamServerError::InternalError,
    }
}

/// Maps a CAL credentials error to an IAM server error.
fn map_credentials_error(_e: ControlChannelCredentialsError) -> IamServerError {
    IamServerError::CredentialsFailed
}

/// Maps a CAL send error to an IAM client error.
fn map_send_error_client(e: ControlChannelSendError) -> IamClientError {
    match e {
        ControlChannelSendError::MessageTooLarge => IamClientError::SendFailed,
        ControlChannelSendError::ConnectionReset => IamClientError::SendFailed,
        ControlChannelSendError::Interrupt => IamClientError::SendFailed,
        ControlChannelSendError::IoError => IamClientError::SendFailed,
        ControlChannelSendError::InsufficientPermissions => IamClientError::SendFailed,
        ControlChannelSendError::InsufficientResources => IamClientError::SendFailed,
        ControlChannelSendError::InsufficientMemory => IamClientError::SendFailed,
        ControlChannelSendError::NotConnected => IamClientError::SendFailed,
        ControlChannelSendError::BrokenPipe => IamClientError::SendFailed,
        ControlChannelSendError::WouldBlock => IamClientError::SendFailed,
        ControlChannelSendError::InternalFailure => IamClientError::InternalError,
    }
}

/// Maps a CAL receive error to an IAM client error.
fn map_receive_error_client(e: ControlChannelReceiveError) -> IamClientError {
    match e {
        ControlChannelReceiveError::ConnectionReset => IamClientError::ReceiveFailed,
        ControlChannelReceiveError::Interrupt => IamClientError::ReceiveFailed,
        ControlChannelReceiveError::IoError => IamClientError::ReceiveFailed,
        ControlChannelReceiveError::InsufficientResources => IamClientError::ReceiveFailed,
        ControlChannelReceiveError::InsufficientMemory => IamClientError::ReceiveFailed,
        ControlChannelReceiveError::NotConnected => IamClientError::ReceiveFailed,
        ControlChannelReceiveError::WouldBlock => IamClientError::ReceiveFailed,
        ControlChannelReceiveError::ReceivedInvalidFileDescriptor => IamClientError::ReceiveFailed,
        ControlChannelReceiveError::InternalFailure => IamClientError::InternalError,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::iam::protocol::{IamRequest, IamResponse, ProtocolVersion, SessionId};
    use iceoryx2_bb_posix::unique_system_id::UniqueSystemId;

    #[test]
    fn test_serialization_roundtrip_request() {
        let node_id = UniqueSystemId::new().unwrap();
        let request = IamRequest::Hello {
            protocol_version: ProtocolVersion::CURRENT,
            node_id,
        };

        // Serialize using Postcard trait
        let payload = Postcard::serialize(&request).unwrap();
        let len = payload.len() as u32;
        let mut framed = Vec::with_capacity(4 + payload.len());
        framed.extend_from_slice(&len.to_le_bytes());
        framed.extend_from_slice(&payload);

        // Verify framing
        assert_eq!(framed.len(), 4 + payload.len());

        // Parse length prefix
        let parsed_len =
            u32::from_le_bytes([framed[0], framed[1], framed[2], framed[3]]) as usize;
        assert_eq!(parsed_len, payload.len());

        // Deserialize using Postcard trait
        let deserialized: IamRequest = Postcard::deserialize(&framed[4..]).unwrap();
        match deserialized {
            IamRequest::Hello {
                protocol_version,
                node_id: deser_node_id,
            } => {
                assert_eq!(protocol_version, ProtocolVersion::CURRENT);
                assert_eq!(deser_node_id, node_id);
            }
            _ => panic!("Expected Hello request"),
        }
    }

    #[test]
    fn test_serialization_roundtrip_response() {
        let response = IamResponse::HelloOk {
            negotiated_version: ProtocolVersion::CURRENT,
            session_id: SessionId::from_value(42),
        };

        // Serialize using Postcard trait
        let payload = Postcard::serialize(&response).unwrap();
        let len = payload.len() as u32;
        let mut framed = Vec::with_capacity(4 + payload.len());
        framed.extend_from_slice(&len.to_le_bytes());
        framed.extend_from_slice(&payload);

        // Verify framing
        assert_eq!(framed.len(), 4 + payload.len());

        // Parse length prefix
        let parsed_len =
            u32::from_le_bytes([framed[0], framed[1], framed[2], framed[3]]) as usize;
        assert_eq!(parsed_len, payload.len());

        // Deserialize using Postcard trait
        let deserialized: IamResponse = Postcard::deserialize(&framed[4..]).unwrap();
        match deserialized {
            IamResponse::HelloOk {
                negotiated_version,
                session_id,
            } => {
                assert_eq!(negotiated_version, ProtocolVersion::CURRENT);
                assert_eq!(session_id.value(), 42);
            }
            _ => panic!("Expected HelloOk response"),
        }
    }

    #[test]
    fn test_new_receive_buffer_capacity() {
        let buffer = new_receive_buffer();
        assert!(buffer.capacity() >= INITIAL_BUFFER_CAPACITY);
        assert!(buffer.is_empty());
    }

    #[test]
    fn test_max_message_size_limit() {
        // Verify the limit is reasonable
        assert_eq!(MAX_MESSAGE_SIZE, 16 * 1024 * 1024);
    }
}
