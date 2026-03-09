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

//! IAM client library for secure service communication.
//!
//! This module provides the [`IamClient`] which enables secure communication
//! with the IAM server for authenticated and authorized service operations.
//!
//! # Overview
//!
//! The client handles:
//! - Connection establishment to the IAM server via control channel
//! - Protocol handshake with version negotiation
//! - Service operations (create, attach, detach)
//! - Segment operations (add segment, acknowledge retirement)
//! - Handle reception for shared memory access
//!
//! # Connection Lifecycle
//!
//! 1. Create client with [`IamClient::new()`]
//! 2. Perform handshake with [`IamClient::handshake()`]
//! 3. Use service operations as needed
//! 4. Disconnect automatically on drop or explicitly with [`IamClient::disconnect()`]
//!
//! # Thread Safety
//!
//! `IamClient` is `Send` but not `Sync`. It is designed for single-threaded use.
//! For multi-threaded scenarios, each thread should have its own client instance.
//!
//! # Example
//!
//! ```ignore
//! use iceoryx2::iam::client::IamClient;
//! use iceoryx2::iam::ProtocolVersion;
//!
//! // Create a client with a control channel connection
//! let connection = MyControlChannelConnection::connect()?;
//! let mut client = IamClient::new(connection);
//!
//! // Perform handshake
//! let node_id = node.unique_system_id();
//! client.handshake(node_id)?;
//!
//! // Create a service
//! let service_name = ServiceName::new("my/service")?;
//! let service_id = client.create_service(&service_name, MessagingPatternKind::PublishSubscribe)?;
//!
//! // Attach as publisher
//! let (port_id, segments, handles) = client.attach_publisher(&service_id, 8, 1024)?;
//! ```

use alloc::vec::Vec;

use iceoryx2_bb_posix::unique_system_id::UniqueSystemId;
use iceoryx2_cal::control_channel::ControlChannelClient as CalClient;
use iceoryx2_cal::security::handle::PlatformHandle;
use iceoryx2_cal::shm_allocator::SegmentId;

use super::error::IamClientError;
use super::protocol::{
    DenialReason, IamRequest, IamResponse, MessagingPatternKind, ProtocolVersion, SegmentInfo,
    SessionId, INVALID_SESSION_ID, MAX_HANDLES_PER_MESSAGE, MAX_SEGMENTS_PER_ATTACH,
};
use super::wire::{
    client_receive_handles, client_receive_message, client_send_handles, client_send_message,
    new_receive_buffer,
};
use crate::service::service_id::ServiceId;
use crate::service::service_name::ServiceName;

// ============================================================================
// ConnectionState
// ============================================================================

/// The state of the client connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConnectionState {
    /// Connection established but handshake not yet completed.
    Connected,
    /// Handshake completed, session is active.
    Active,
    /// Connection has been closed.
    Disconnected,
}

// ============================================================================
// IamClient
// ============================================================================

/// Client for communicating with the IAM server.
///
/// The client manages the connection lifecycle and provides methods for
/// all IAM operations including service creation, port attachment, and
/// segment management.
///
/// # Type Parameters
///
/// * `C` - The CAL control channel client type
///
/// # Connection Lifecycle
///
/// The client progresses through the following states:
/// 1. `Connected` - After [`IamClient::new()`], connection established
/// 2. `Active` - After [`IamClient::handshake()`], ready for operations
/// 3. `Disconnected` - After [`IamClient::disconnect()`] or drop
///
/// # Drop Behavior
///
/// When dropped, if the client is in the `Active` state, the connection
/// is closed automatically through Drop.
pub struct IamClient<C: CalClient> {
    /// The control channel connection to the server (None if disconnected).
    connection: Option<C>,
    /// Reusable buffer for receiving messages.
    receive_buffer: Vec<u8>,
    /// The session ID assigned during handshake.
    session_id: SessionId,
    /// The negotiated protocol version.
    protocol_version: ProtocolVersion,
    /// The current connection state.
    state: ConnectionState,
}

impl<C: CalClient> IamClient<C> {
    /// Creates a new IAM client with the given connection.
    ///
    /// The client is created in the `Connected` state. You must call
    /// [`handshake()`](Self::handshake) before performing any operations.
    ///
    /// # Arguments
    ///
    /// * `connection` - The CAL control channel client to the IAM server
    ///
    /// # Returns
    ///
    /// A new `IamClient` instance in the `Connected` state.
    #[must_use]
    pub fn new(connection: C) -> Self {
        Self {
            connection: Some(connection),
            receive_buffer: new_receive_buffer(),
            session_id: INVALID_SESSION_ID,
            protocol_version: ProtocolVersion::CURRENT,
            state: ConnectionState::Connected,
        }
    }

    /// Returns the session ID assigned during handshake.
    ///
    /// Returns [`INVALID_SESSION_ID`] if handshake has not completed.
    #[must_use]
    pub const fn session_id(&self) -> SessionId {
        self.session_id
    }

    /// Returns the negotiated protocol version.
    ///
    /// Before handshake, returns [`ProtocolVersion::CURRENT`].
    /// After handshake, returns the version negotiated with the server.
    #[must_use]
    pub const fn protocol_version(&self) -> ProtocolVersion {
        self.protocol_version
    }

    /// Returns true if the client is connected and ready for operations.
    #[must_use]
    pub const fn is_active(&self) -> bool {
        matches!(self.state, ConnectionState::Active)
    }

    /// Returns true if the client is connected (but may not have completed handshake).
    #[must_use]
    pub const fn is_connected(&self) -> bool {
        !matches!(self.state, ConnectionState::Disconnected)
    }

    // ========================================================================
    // Connection Lifecycle
    // ========================================================================

    /// Performs the handshake with the IAM server.
    ///
    /// This method sends a Hello request with the client's protocol version
    /// and node ID, and receives a Welcome response with the negotiated
    /// version and assigned session ID.
    ///
    /// # Arguments
    ///
    /// * `node_id` - The unique system ID of the client's node
    ///
    /// # Returns
    ///
    /// On success, returns the assigned session ID.
    ///
    /// # Errors
    ///
    /// - [`IamClientError::HandshakeFailed`] - General handshake failure
    /// - [`IamClientError::VersionMismatch`] - Protocol version incompatible
    /// - [`IamClientError::SendFailed`] - Failed to send Hello request
    /// - [`IamClientError::ReceiveFailed`] - Failed to receive response
    /// - [`IamClientError::RequestDenied`] - Server denied the connection
    pub fn handshake(&mut self, node_id: UniqueSystemId) -> Result<SessionId, IamClientError> {
        if self.state != ConnectionState::Connected {
            return Err(IamClientError::HandshakeFailed);
        }

        // Get connection reference (split borrow to allow mutable access to receive_buffer)
        let conn = self.connection.as_ref().ok_or(IamClientError::SendFailed)?;

        // Send Hello request
        let request = IamRequest::Hello {
            protocol_version: ProtocolVersion::CURRENT,
            node_id,
        };
        client_send_message(conn, &request)?;

        // Receive response
        let response: IamResponse = client_receive_message(conn, &mut self.receive_buffer)?;

        match response {
            IamResponse::HelloOk {
                negotiated_version,
                session_id,
            } => {
                // Verify version compatibility
                if !ProtocolVersion::CURRENT.is_compatible_with(&negotiated_version) {
                    self.disconnect();
                    return Err(IamClientError::VersionMismatch);
                }

                // Validate session ID is valid
                if !session_id.is_valid() {
                    self.disconnect();
                    return Err(IamClientError::HandshakeFailed);
                }

                self.protocol_version = negotiated_version;
                self.session_id = session_id;
                self.state = ConnectionState::Active;
                Ok(session_id)
            }
            IamResponse::Denied { reason, .. } => {
                if reason == DenialReason::VersionMismatch {
                    Err(IamClientError::VersionMismatch)
                } else {
                    Err(IamClientError::RequestDenied)
                }
            }
            IamResponse::ProtocolError { .. } => Err(IamClientError::ProtocolError),
            _ => Err(IamClientError::HandshakeFailed),
        }
    }

    /// Disconnects from the IAM server.
    ///
    /// This method closes the connection cleanly. After calling this method,
    /// the client cannot be used for further operations.
    ///
    /// If the client is already disconnected, this method does nothing.
    pub fn disconnect(&mut self) {
        if self.state != ConnectionState::Disconnected {
            // Drop the connection by taking it (closes via Drop)
            self.connection = None;
            self.state = ConnectionState::Disconnected;
            self.session_id = INVALID_SESSION_ID;
        }
    }

    // ========================================================================
    // Service Operations
    // ========================================================================

    /// Creates a new service on the IAM server.
    ///
    /// # Arguments
    ///
    /// * `service_name` - The name of the service to create
    /// * `messaging_pattern` - The messaging pattern for the service
    ///
    /// # Returns
    ///
    /// On success, returns the assigned service ID.
    ///
    /// # Errors
    ///
    /// - [`IamClientError::SessionInvalid`] - Client is not in active state
    /// - [`IamClientError::RequestDenied`] - Server denied the request
    /// - [`IamClientError::SendFailed`] - Failed to send request
    /// - [`IamClientError::ReceiveFailed`] - Failed to receive response
    pub fn create_service(
        &mut self,
        service_name: &ServiceName,
        messaging_pattern: MessagingPatternKind,
    ) -> Result<ServiceId, IamClientError> {
        self.ensure_active()?;

        // Get connection reference (split borrow to allow mutable access to receive_buffer)
        let conn = self.connection.as_ref().ok_or(IamClientError::SendFailed)?;

        let request = IamRequest::CreateService {
            service_name: service_name.clone(),
            messaging_pattern,
        };
        client_send_message(conn, &request)?;

        let response: IamResponse = client_receive_message(conn, &mut self.receive_buffer)?;
        Self::handle_create_service_response(response)
    }

    /// Handles the response to a CreateService request.
    fn handle_create_service_response(
        response: IamResponse,
    ) -> Result<ServiceId, IamClientError> {
        match response {
            IamResponse::CreateServiceOk { service_id } => Ok(service_id),
            IamResponse::Denied { .. } => Err(IamClientError::RequestDenied),
            IamResponse::ProtocolError { .. } => Err(IamClientError::ProtocolError),
            _ => Err(IamClientError::ProtocolError),
        }
    }


    // ========================================================================
    // Attach Operations
    // ========================================================================

    /// Attaches as a publisher to a service.
    ///
    /// # Arguments
    ///
    /// * `service_id` - The service to attach to
    /// * `history_size` - The history size for the publisher
    /// * `max_slice_len` - The maximum slice length for samples
    ///
    /// # Returns
    ///
    /// On success, returns a tuple of:
    /// - Port ID assigned by the server
    /// - Segment information for the publisher's segments
    /// - Platform handles for the segments
    ///
    /// # Errors
    ///
    /// - [`IamClientError::SessionInvalid`] - Client is not in active state
    /// - [`IamClientError::RequestDenied`] - Server denied the request
    /// - [`IamClientError::HandleReceiveFailed`] - Failed to receive handles
    pub fn attach_publisher(
        &mut self,
        service_id: &ServiceId,
        history_size: usize,
        max_slice_len: usize,
    ) -> Result<(u128, Vec<SegmentInfo>, Vec<PlatformHandle>), IamClientError> {
        self.ensure_active()?;

        // Get connection reference (split borrow to allow mutable access to receive_buffer)
        let conn = self.connection.as_ref().ok_or(IamClientError::SendFailed)?;

        let request = IamRequest::AttachPublisher {
            service_id: *service_id,
            history_size,
            max_slice_len,
        };
        client_send_message(conn, &request)?;

        let response: IamResponse = client_receive_message(conn, &mut self.receive_buffer)?;
        Self::handle_attach_response(conn, response)
    }

    /// Attaches as a subscriber to a service.
    ///
    /// # Arguments
    ///
    /// * `service_id` - The service to attach to
    /// * `buffer_size` - The buffer size for the subscriber
    ///
    /// # Returns
    ///
    /// On success, returns a tuple of:
    /// - Port ID assigned by the server
    /// - Segment information for the service's segments
    /// - Platform handles for the segments
    ///
    /// # Errors
    ///
    /// - [`IamClientError::SessionInvalid`] - Client is not in active state
    /// - [`IamClientError::RequestDenied`] - Server denied the request
    /// - [`IamClientError::HandleReceiveFailed`] - Failed to receive handles
    /// - [`IamClientError::ProtocolError`] - Protocol violation (e.g., exceeds limits)
    pub fn attach_subscriber(
        &mut self,
        service_id: &ServiceId,
        buffer_size: usize,
    ) -> Result<(u128, Vec<SegmentInfo>, Vec<PlatformHandle>), IamClientError> {
        self.ensure_active()?;

        let conn = self.connection.as_ref().ok_or(IamClientError::SendFailed)?;

        let request = IamRequest::AttachSubscriber {
            service_id: *service_id,
            buffer_size,
        };
        client_send_message(conn, &request)?;

        let response: IamResponse = client_receive_message(conn, &mut self.receive_buffer)?;
        Self::handle_attach_response(conn, response)
    }

    /// Attaches as a server to a request-response service.
    ///
    /// # Arguments
    ///
    /// * `service_id` - The service to attach to
    /// * `max_active_requests` - The maximum number of active requests
    ///
    /// # Returns
    ///
    /// On success, returns a tuple of:
    /// - Port ID assigned by the server
    /// - Segment information for the service's segments
    /// - Platform handles for the segments
    ///
    /// # Errors
    ///
    /// - [`IamClientError::SessionInvalid`] - Client is not in active state
    /// - [`IamClientError::RequestDenied`] - Server denied the request
    /// - [`IamClientError::HandleReceiveFailed`] - Failed to receive handles
    /// - [`IamClientError::ProtocolError`] - Protocol violation (e.g., exceeds limits)
    pub fn attach_server(
        &mut self,
        service_id: &ServiceId,
        max_active_requests: usize,
    ) -> Result<(u128, Vec<SegmentInfo>, Vec<PlatformHandle>), IamClientError> {
        self.ensure_active()?;

        let conn = self.connection.as_ref().ok_or(IamClientError::SendFailed)?;

        let request = IamRequest::AttachServer {
            service_id: *service_id,
            max_active_requests,
        };
        client_send_message(conn, &request)?;

        let response: IamResponse = client_receive_message(conn, &mut self.receive_buffer)?;
        Self::handle_attach_response(conn, response)
    }

    /// Attaches as a client to a request-response service.
    ///
    /// # Arguments
    ///
    /// * `service_id` - The service to attach to
    /// * `max_pending_responses` - The maximum number of pending responses
    ///
    /// # Returns
    ///
    /// On success, returns a tuple of:
    /// - Port ID assigned by the server
    /// - Segment information for the service's segments
    /// - Platform handles for the segments
    ///
    /// # Errors
    ///
    /// - [`IamClientError::SessionInvalid`] - Client is not in active state
    /// - [`IamClientError::RequestDenied`] - Server denied the request
    /// - [`IamClientError::HandleReceiveFailed`] - Failed to receive handles
    /// - [`IamClientError::ProtocolError`] - Protocol violation (e.g., exceeds limits)
    pub fn attach_client(
        &mut self,
        service_id: &ServiceId,
        max_pending_responses: usize,
    ) -> Result<(u128, Vec<SegmentInfo>, Vec<PlatformHandle>), IamClientError> {
        self.ensure_active()?;

        let conn = self.connection.as_ref().ok_or(IamClientError::SendFailed)?;

        let request = IamRequest::AttachClient {
            service_id: *service_id,
            max_pending_responses,
        };
        client_send_message(conn, &request)?;

        let response: IamResponse = client_receive_message(conn, &mut self.receive_buffer)?;
        Self::handle_attach_response(conn, response)
    }

    /// Handles the response to an attach request.
    fn handle_attach_response(
        conn: &C,
        response: IamResponse,
    ) -> Result<(u128, Vec<SegmentInfo>, Vec<PlatformHandle>), IamClientError> {
        match response {
            IamResponse::AttachOk {
                port_id,
                segment_info,
                handle_count,
            } => {
                // Validate against protocol limits to prevent DoS
                if segment_info.len() > MAX_SEGMENTS_PER_ATTACH {
                    return Err(IamClientError::ProtocolError);
                }
                if handle_count > MAX_HANDLES_PER_MESSAGE {
                    return Err(IamClientError::ProtocolError);
                }

                // Receive handles if any
                let handles = if handle_count > 0 {
                    let received = client_receive_handles(conn)?;
                    if received.len() != handle_count {
                        return Err(IamClientError::HandleReceiveFailed);
                    }
                    received
                } else {
                    Vec::new()
                };

                Ok((port_id, segment_info, handles))
            }
            IamResponse::Denied { .. } => Err(IamClientError::RequestDenied),
            IamResponse::ProtocolError { .. } => Err(IamClientError::ProtocolError),
            _ => Err(IamClientError::ProtocolError),
        }
    }

    /// Detaches from a service.
    ///
    /// # Arguments
    ///
    /// * `service_id` - The service to detach from
    /// * `port_id` - The port ID to detach
    ///
    /// # Returns
    ///
    /// `Ok(())` on success.
    ///
    /// # Errors
    ///
    /// - [`IamClientError::SessionInvalid`] - Client is not in active state
    /// - [`IamClientError::RequestDenied`] - Server denied the request
    pub fn detach(&mut self, service_id: &ServiceId, port_id: u128) -> Result<(), IamClientError> {
        self.ensure_active()?;

        let conn = self.connection.as_ref().ok_or(IamClientError::SendFailed)?;

        let request = IamRequest::Detach {
            service_id: *service_id,
            port_id,
        };
        client_send_message(conn, &request)?;

        let response: IamResponse = client_receive_message(conn, &mut self.receive_buffer)?;

        match response {
            IamResponse::DetachOk => Ok(()),
            IamResponse::Denied { .. } => Err(IamClientError::RequestDenied),
            IamResponse::ProtocolError { .. } => Err(IamClientError::ProtocolError),
            _ => Err(IamClientError::ProtocolError),
        }
    }

    // ========================================================================
    // Segment Operations
    // ========================================================================

    /// Adds a new segment for a port.
    ///
    /// Publishers can request additional segments when they need more memory
    /// for larger samples or increased history.
    ///
    /// # Arguments
    ///
    /// * `service_id` - The service the port belongs to
    /// * `port_id` - The port requesting the segment
    /// * `requested_size` - The requested size for the new segment
    ///
    /// # Returns
    ///
    /// On success, returns a tuple of:
    /// - The assigned segment ID
    /// - The actual size allocated
    /// - Platform handles for the segment
    ///
    /// # Errors
    ///
    /// - [`IamClientError::SessionInvalid`] - Client is not in active state
    /// - [`IamClientError::RequestDenied`] - Server denied the request (e.g., resource limits)
    /// - [`IamClientError::HandleReceiveFailed`] - Failed to receive handles
    pub fn add_segment(
        &mut self,
        service_id: &ServiceId,
        port_id: u128,
        requested_size: usize,
        bucket_size: usize,
        bucket_align: usize,
    ) -> Result<(SegmentId, usize, Vec<PlatformHandle>), IamClientError> {
        self.ensure_active()?;

        let conn = self.connection.as_ref().ok_or(IamClientError::SendFailed)?;

        let request = IamRequest::AddSegment {
            service_id: *service_id,
            port_id,
            requested_size,
            bucket_size,
            bucket_align,
        };
        client_send_message(conn, &request)?;

        let response: IamResponse = client_receive_message(conn, &mut self.receive_buffer)?;

        match response {
            IamResponse::AddSegmentOk {
                segment_id,
                size,
                handle_count,
            } => {
                // Validate against protocol limits to prevent DoS
                if handle_count > MAX_HANDLES_PER_MESSAGE {
                    return Err(IamClientError::ProtocolError);
                }

                // Receive handles if any
                let handles = if handle_count > 0 {
                    let received = client_receive_handles(conn)?;
                    if received.len() != handle_count {
                        return Err(IamClientError::HandleReceiveFailed);
                    }
                    received
                } else {
                    Vec::new()
                };

                Ok((segment_id, size, handles))
            }
            IamResponse::Denied { .. } => Err(IamClientError::RequestDenied),
            IamResponse::ProtocolError { .. } => Err(IamClientError::ProtocolError),
            _ => Err(IamClientError::ProtocolError),
        }
    }

    /// Acknowledges a segment retirement notification.
    ///
    /// When the server notifies a client that a segment is being retired,
    /// the client must acknowledge receipt of the notification after it
    /// has stopped using the segment.
    ///
    /// # Arguments
    ///
    /// * `service_id` - The service the segment belongs to
    /// * `segment_id` - The segment being retired
    ///
    /// # Returns
    ///
    /// `Ok(())` on success.
    ///
    /// # Errors
    ///
    /// - [`IamClientError::SessionInvalid`] - Client is not in active state
    /// - [`IamClientError::RequestDenied`] - Server denied the request
    pub fn ack_retirement(
        &mut self,
        service_id: &ServiceId,
        segment_id: SegmentId,
    ) -> Result<(), IamClientError> {
        self.ensure_active()?;

        let conn = self.connection.as_ref().ok_or(IamClientError::SendFailed)?;

        let request = IamRequest::AckSegmentRetirement {
            service_id: *service_id,
            segment_id,
        };
        client_send_message(conn, &request)?;

        let response: IamResponse = client_receive_message(conn, &mut self.receive_buffer)?;

        match response {
            IamResponse::AckOk => Ok(()),
            IamResponse::Denied { .. } => Err(IamClientError::RequestDenied),
            IamResponse::ProtocolError { .. } => Err(IamClientError::ProtocolError),
            _ => Err(IamClientError::ProtocolError),
        }
    }

    // ========================================================================
    // Segment Handle Registration & Request
    // ========================================================================

    /// Registers a producer's segment handle with the IAM server.
    ///
    /// After creating an anonymous shared memory segment, the producer
    /// (publisher/server) sends the handle to the IAM server so it can
    /// be brokered to authorized consumers.
    ///
    /// # Arguments
    ///
    /// * `service_id` - The service this segment belongs to
    /// * `port_id` - The producer port that owns the segment
    /// * `segment_size` - The size of the segment in bytes
    /// * `handle` - The platform handle for the anonymous segment
    ///
    /// # Returns
    ///
    /// The segment ID assigned by the IAM server.
    pub fn register_segment(
        &mut self,
        service_id: &ServiceId,
        port_id: u128,
        segment_size: usize,
        handle: &PlatformHandle,
    ) -> Result<SegmentId, IamClientError> {
        self.ensure_active()?;

        let conn = self.connection.as_ref().ok_or(IamClientError::SendFailed)?;

        let request = IamRequest::RegisterSegment {
            service_id: *service_id,
            port_id,
            segment_size,
            handle_count: 1,
        };
        client_send_message(conn, &request)?;

        // Send the handle to the server via SCM_RIGHTS (Unix) or equivalent
        let clone = handle
            .try_clone()
            .map_err(|_| IamClientError::HandleSendFailed)?;
        client_send_handles(conn, &[clone])?;

        let response: IamResponse = client_receive_message(conn, &mut self.receive_buffer)?;

        match response {
            IamResponse::RegisterSegmentOk { segment_id } => Ok(segment_id),
            IamResponse::Denied { .. } => Err(IamClientError::RequestDenied),
            IamResponse::ProtocolError { .. } => Err(IamClientError::ProtocolError),
            _ => Err(IamClientError::ProtocolError),
        }
    }

    /// Requests a segment handle for a sender port's data segment.
    ///
    /// Consumers (subscriber/client) use this to obtain handles to producer
    /// data segments brokered through the IAM server.
    ///
    /// # Arguments
    ///
    /// * `service_id` - The service the port belongs to
    /// * `sender_port_id` - The producer port whose segment handle is requested
    ///
    /// # Returns
    ///
    /// `Ok(Some((segment_info, handle)))` if the handle is available,
    /// `Ok(None)` if the producer has not yet registered its segment,
    /// or an error on communication failure.
    pub fn request_segment_handle(
        &mut self,
        service_id: &ServiceId,
        sender_port_id: u128,
    ) -> Result<Option<(SegmentInfo, PlatformHandle)>, IamClientError> {
        self.ensure_active()?;

        let conn = self.connection.as_ref().ok_or(IamClientError::SendFailed)?;

        let request = IamRequest::RequestSegmentHandle {
            service_id: *service_id,
            sender_port_id,
        };
        client_send_message(conn, &request)?;

        let response: IamResponse = client_receive_message(conn, &mut self.receive_buffer)?;

        match response {
            IamResponse::SegmentHandleOk {
                segment_info,
                handle_count,
            } => {
                if handle_count == 0 || handle_count > MAX_HANDLES_PER_MESSAGE {
                    return Err(IamClientError::ProtocolError);
                }
                let handles = client_receive_handles(conn)?;
                if handles.is_empty() {
                    return Err(IamClientError::HandleReceiveFailed);
                }
                let handle = handles.into_iter().next().unwrap();
                Ok(Some((segment_info, handle)))
            }
            IamResponse::SegmentHandleNotFound => Ok(None),
            IamResponse::Denied { .. } => Err(IamClientError::RequestDenied),
            IamResponse::ProtocolError { .. } => Err(IamClientError::ProtocolError),
            _ => Err(IamClientError::ProtocolError),
        }
    }

    /// Registers a dynamic segment handle at a specific index with the IAM server.
    ///
    /// Dynamic segments use indexes (0 for initial, 1+ for reallocations) to track
    /// multiple segments per port. The producer (publisher/server) sends the handle
    /// to the IAM server so it can be brokered to authorized consumers.
    ///
    /// # Arguments
    ///
    /// * `service_id` - The service this segment belongs to
    /// * `port_id` - The producer port that owns the segment
    /// * `segment_index` - The index within the dynamic segment set (0-based)
    /// * `segment_size` - The size of the segment in bytes
    /// * `handle` - The platform handle for the anonymous segment
    ///
    /// # Returns
    ///
    /// The segment index that was registered.
    pub fn register_dynamic_segment(
        &mut self,
        service_id: &ServiceId,
        port_id: u128,
        segment_index: u8,
        segment_size: usize,
        handle: &PlatformHandle,
    ) -> Result<u8, IamClientError> {
        self.ensure_active()?;

        let conn = self.connection.as_ref().ok_or(IamClientError::SendFailed)?;

        let request = IamRequest::RegisterDynamicSegment {
            service_id: *service_id,
            port_id,
            segment_id: segment_index,
            segment_size,
            handle_count: 1,
        };
        client_send_message(conn, &request)?;

        // Send the handle to the server via SCM_RIGHTS (Unix) or equivalent
        let clone = handle
            .try_clone()
            .map_err(|_| IamClientError::HandleSendFailed)?;
        client_send_handles(conn, &[clone])?;

        let response: IamResponse = client_receive_message(conn, &mut self.receive_buffer)?;

        match response {
            IamResponse::RegisterDynamicSegmentOk { segment_id } => Ok(segment_id),
            IamResponse::Denied { .. } => Err(IamClientError::RequestDenied),
            IamResponse::ProtocolError { .. } => Err(IamClientError::ProtocolError),
            _ => Err(IamClientError::ProtocolError),
        }
    }

    /// Requests a specific dynamic segment handle by index from a sender port.
    ///
    /// Consumers (subscriber/client) use this to obtain handles to specific segments
    /// within a producer's dynamic segment set, identified by the segment index.
    ///
    /// # Arguments
    ///
    /// * `service_id` - The service the port belongs to
    /// * `sender_port_id` - The producer port whose segment handle is requested
    /// * `segment_index` - The index of the dynamic segment (0-based)
    ///
    /// # Returns
    ///
    /// * `Ok(Some((segment_info, handle)))` if the handle is available
    /// * `Ok(None)` if the producer has not yet registered this segment index
    ///   (race condition - retry later)
    /// * Error on communication failure
    pub fn request_dynamic_segment_handle(
        &mut self,
        service_id: &ServiceId,
        sender_port_id: u128,
        segment_index: u8,
    ) -> Result<Option<(SegmentInfo, PlatformHandle)>, IamClientError> {
        self.ensure_active()?;

        let conn = self.connection.as_ref().ok_or(IamClientError::SendFailed)?;

        let request = IamRequest::RequestDynamicSegmentHandle {
            service_id: *service_id,
            sender_port_id,
            segment_id: segment_index,
        };
        client_send_message(conn, &request)?;

        let response: IamResponse = client_receive_message(conn, &mut self.receive_buffer)?;

        match response {
            IamResponse::DynamicSegmentHandleOk {
                segment_info,
                handle_count,
            } => {
                if handle_count == 0 || handle_count > MAX_HANDLES_PER_MESSAGE {
                    return Err(IamClientError::ProtocolError);
                }
                let handles = client_receive_handles(conn)?;
                if handles.is_empty() {
                    return Err(IamClientError::HandleReceiveFailed);
                }
                let handle = handles.into_iter().next().unwrap();
                Ok(Some((segment_info, handle)))
            }
            IamResponse::DynamicSegmentPending => Ok(None),
            IamResponse::Denied { .. } => Err(IamClientError::RequestDenied),
            IamResponse::ProtocolError { .. } => Err(IamClientError::ProtocolError),
            _ => Err(IamClientError::ProtocolError),
        }
    }

    // ========================================================================
    // Notification Operations
    // ========================================================================

    /// Tries to receive a pending notification without blocking.
    ///
    /// This method polls for server-pushed notifications such as:
    /// - `SegmentUpdate`: A producer added a new segment
    /// - `SegmentRetiring`: A producer is retiring a segment
    /// - `PortJoined`/`PortLeft`: Connection topology changes
    ///
    /// # Returns
    ///
    /// * `Ok(Some((notification, handles)))` - A notification was received along with
    ///   any associated handles (e.g., segment handles for SegmentUpdate)
    /// * `Ok(None)` - No notification is pending
    /// * `Err(...)` - An error occurred during receive
    ///
    /// # Example
    ///
    /// ```ignore
    /// while let Some((notif, handles)) = client.try_receive_notification()? {
    ///     if let IamNotification::SegmentUpdate { segment_id, .. } = notif {
    ///         // Process the new segment handle
    ///     }
    /// }
    /// ```
    pub fn try_receive_notification(
        &mut self,
    ) -> Result<Option<(super::protocol::IamNotification, Vec<PlatformHandle>)>, IamClientError> {
        self.ensure_active()?;

        let conn = self.connection.as_ref().ok_or(IamClientError::SendFailed)?;

        // Try non-blocking receive
        let notification: Option<super::protocol::IamNotification> =
            super::wire::client_try_receive_message(conn, &mut self.receive_buffer)?;

        match notification {
            Some(notif) => {
                // Check if notification has associated handles
                let handle_count = match &notif {
                    super::protocol::IamNotification::SegmentUpdate { handle_count, .. } => {
                        *handle_count
                    }
                    _ => 0,
                };

                let handles = if handle_count > 0 {
                    super::wire::client_try_receive_handles(conn)?.unwrap_or_default()
                } else {
                    Vec::new()
                };

                Ok(Some((notif, handles)))
            }
            None => Ok(None),
        }
    }

    // ========================================================================
    // Helper Methods
    // ========================================================================

    /// Ensures the client is in the active state with a valid session.
    fn ensure_active(&self) -> Result<(), IamClientError> {
        if !matches!(self.state, ConnectionState::Active) || !self.session_id.is_valid() {
            Err(IamClientError::SessionInvalid)
        } else {
            Ok(())
        }
    }
}

impl<C: CalClient> Drop for IamClient<C> {
    fn drop(&mut self) {
        // Disconnect if still connected
        self.disconnect();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::collections::VecDeque;
    use alloc::vec;
    use core::cell::RefCell;
    use core::time::Duration;
    use iceoryx2_bb_system_types::file_name::FileName;
    use iceoryx2_cal::control_channel::{
        ControlChannelClient, ControlChannelCredentialsError, ControlChannelReceiveError,
        ControlChannelSendError,
    };
    use iceoryx2_cal::named_concept::NamedConcept;
    use iceoryx2_cal::security::credentials::ProcessCredentials;
    use iceoryx2_cal::serialize::{postcard::Postcard, Serialize as CalSerialize};

    // ========================================================================
    // Mock Types for Testing
    // ========================================================================

    /// Mock connection for testing that implements CAL's ControlChannelClient trait.
    ///
    /// This mock stores raw bytes rather than typed messages, matching the actual
    /// CAL interface. Responses are queued as length-framed serialized bytes.
    struct MockConnection {
        /// Raw bytes that have been sent via send().
        sent_data: RefCell<Vec<Vec<u8>>>,
        /// Raw bytes to return on receive (FIFO queue).
        /// Each entry is a complete framed message (4-byte length prefix + payload).
        receive_queue: RefCell<VecDeque<Vec<u8>>>,
        /// Current position within the first receive_queue entry (for partial reads).
        receive_offset: RefCell<usize>,
        /// Handles to return on next receive_handles call.
        handles_to_return: RefCell<Vec<PlatformHandle>>,
        /// Credentials to return from peer_credentials().
        credentials: ProcessCredentials,
        /// Error to return on send (if any).
        send_error: RefCell<Option<ControlChannelSendError>>,
        /// Error to return on receive (if any).
        receive_error: RefCell<Option<ControlChannelReceiveError>>,
    }

    impl MockConnection {
        fn new() -> Self {
            Self {
                sent_data: RefCell::new(Vec::new()),
                receive_queue: RefCell::new(VecDeque::new()),
                receive_offset: RefCell::new(0),
                handles_to_return: RefCell::new(Vec::new()),
                credentials: ProcessCredentials::new(1234, 1000, 1000),
                send_error: RefCell::new(None),
                receive_error: RefCell::new(None),
            }
        }

        /// Queues a response to be received by the client.
        /// The response is serialized and length-framed.
        fn add_response(&self, response: IamResponse) {
            let payload = Postcard::serialize(&response).unwrap();
            let len = payload.len() as u32;
            let mut framed = Vec::with_capacity(4 + payload.len());
            framed.extend_from_slice(&len.to_le_bytes());
            framed.extend_from_slice(&payload);
            self.receive_queue.borrow_mut().push_back(framed);
        }

        fn set_send_error(&self, error: IamClientError) {
            let cal_error = match error {
                IamClientError::SendFailed => ControlChannelSendError::IoError,
                _ => ControlChannelSendError::InternalFailure,
            };
            *self.send_error.borrow_mut() = Some(cal_error);
        }

        fn set_receive_error(&self, error: IamClientError) {
            let cal_error = match error {
                IamClientError::ReceiveFailed => ControlChannelReceiveError::IoError,
                _ => ControlChannelReceiveError::InternalFailure,
            };
            *self.receive_error.borrow_mut() = Some(cal_error);
        }

        /// Returns the requests that have been sent, deserializing from raw bytes.
        fn get_sent_requests(&self) -> Vec<IamRequest> {
            self.sent_data
                .borrow()
                .iter()
                .filter_map(|data| {
                    // Skip the 4-byte length prefix and deserialize the payload
                    if data.len() < 4 {
                        return None;
                    }
                    Postcard::deserialize(&data[4..]).ok()
                })
                .collect()
        }
    }

    impl core::fmt::Debug for MockConnection {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            f.debug_struct("MockConnection").finish()
        }
    }

    impl NamedConcept for MockConnection {
        fn name(&self) -> &FileName {
            static NAME: FileName = unsafe { FileName::new_unchecked_const(b"mock_connection") };
            &NAME
        }
    }

    impl ControlChannelClient for MockConnection {
        fn peer_credentials(&self) -> Result<ProcessCredentials, ControlChannelCredentialsError> {
            Ok(self.credentials.clone())
        }

        fn send_handles(
            &self,
            _handles: &[&PlatformHandle],
        ) -> Result<(), ControlChannelSendError> {
            Ok(())
        }

        fn try_send_handles(
            &self,
            _handles: &[&PlatformHandle],
        ) -> Result<bool, ControlChannelSendError> {
            Ok(true)
        }

        fn receive_handles(
            &self,
        ) -> Result<Option<Vec<PlatformHandle>>, ControlChannelReceiveError> {
            let handles = self.handles_to_return.borrow_mut().drain(..).collect::<Vec<_>>();
            if handles.is_empty() {
                Ok(None)
            } else {
                Ok(Some(handles))
            }
        }

        fn try_receive_handles(
            &self,
        ) -> Result<Option<Vec<PlatformHandle>>, ControlChannelReceiveError> {
            self.receive_handles()
        }

        fn timed_receive_handles(
            &self,
            _timeout: Duration,
        ) -> Result<Option<Vec<PlatformHandle>>, ControlChannelReceiveError> {
            self.receive_handles()
        }

        fn blocking_receive_handles(
            &self,
        ) -> Result<Vec<PlatformHandle>, ControlChannelReceiveError> {
            self.receive_handles()
                .and_then(|opt| opt.ok_or(ControlChannelReceiveError::IoError))
        }

        fn send(&self, data: &[u8]) -> Result<(), ControlChannelSendError> {
            if let Some(error) = self.send_error.borrow_mut().take() {
                return Err(error);
            }
            self.sent_data.borrow_mut().push(data.to_vec());
            Ok(())
        }

        fn try_send(&self, data: &[u8]) -> Result<u64, ControlChannelSendError> {
            self.send(data)?;
            Ok(data.len() as u64)
        }

        fn receive(&self, buffer: &mut [u8]) -> Result<u64, ControlChannelReceiveError> {
            if let Some(error) = self.receive_error.borrow_mut().take() {
                return Err(error);
            }

            let mut queue = self.receive_queue.borrow_mut();
            let offset = *self.receive_offset.borrow();

            if queue.is_empty() {
                return Err(ControlChannelReceiveError::WouldBlock);
            }

            let front = queue.front().unwrap();
            let remaining = &front[offset..];
            let to_copy = core::cmp::min(remaining.len(), buffer.len());
            buffer[..to_copy].copy_from_slice(&remaining[..to_copy]);

            if offset + to_copy >= front.len() {
                // Finished this message, move to next
                queue.pop_front();
                *self.receive_offset.borrow_mut() = 0;
            } else {
                *self.receive_offset.borrow_mut() = offset + to_copy;
            }

            Ok(to_copy as u64)
        }

        fn try_receive(&self, buffer: &mut [u8]) -> Result<u64, ControlChannelReceiveError> {
            if self.receive_queue.borrow().is_empty() {
                return Ok(0);
            }
            self.receive(buffer)
        }
    }

    // ========================================================================
    // Basic Client Tests
    // ========================================================================

    #[test]
    fn test_client_new() {
        let connection = MockConnection::new();
        let client = IamClient::new(connection);

        assert_eq!(client.session_id(), INVALID_SESSION_ID);
        assert_eq!(client.protocol_version(), ProtocolVersion::CURRENT);
        assert!(client.is_connected());
        assert!(!client.is_active());
    }

    #[test]
    fn test_client_handshake_success() {
        let connection = MockConnection::new();
        let expected_session_id = SessionId::from_value(42);
        connection.add_response(IamResponse::HelloOk {
            negotiated_version: ProtocolVersion::CURRENT,
            session_id: expected_session_id,
        });

        let mut client = IamClient::new(connection);
        let node_id = UniqueSystemId::new().unwrap();

        let result = client.handshake(node_id);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), expected_session_id);
        assert_eq!(client.session_id(), expected_session_id);
        assert!(client.is_active());
    }

    #[test]
    fn test_client_handshake_version_mismatch() {
        let connection = MockConnection::new();
        connection.add_response(IamResponse::Denied {
            reason: DenialReason::VersionMismatch,
            message: alloc::string::String::from("Version mismatch"),
        });

        let mut client = IamClient::new(connection);
        let node_id = UniqueSystemId::new().unwrap();

        let result = client.handshake(node_id);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), IamClientError::VersionMismatch);
        assert!(!client.is_active());
    }

    #[test]
    fn test_client_handshake_denied() {
        let connection = MockConnection::new();
        connection.add_response(IamResponse::Denied {
            reason: DenialReason::Unauthorized,
            message: alloc::string::String::from("Not authorized"),
        });

        let mut client = IamClient::new(connection);
        let node_id = UniqueSystemId::new().unwrap();

        let result = client.handshake(node_id);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), IamClientError::RequestDenied);
    }

    #[test]
    fn test_client_handshake_send_failed() {
        let connection = MockConnection::new();
        connection.set_send_error(IamClientError::SendFailed);

        let mut client = IamClient::new(connection);
        let node_id = UniqueSystemId::new().unwrap();

        let result = client.handshake(node_id);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), IamClientError::SendFailed);
    }

    #[test]
    fn test_client_handshake_receive_failed() {
        let connection = MockConnection::new();
        connection.set_receive_error(IamClientError::ReceiveFailed);

        let mut client = IamClient::new(connection);
        let node_id = UniqueSystemId::new().unwrap();

        let result = client.handshake(node_id);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), IamClientError::ReceiveFailed);
    }

    #[test]
    fn test_client_handshake_already_active() {
        let connection = MockConnection::new();
        connection.add_response(IamResponse::HelloOk {
            negotiated_version: ProtocolVersion::CURRENT,
            session_id: SessionId::from_value(42),
        });

        let mut client = IamClient::new(connection);
        let node_id = UniqueSystemId::new().unwrap();

        // First handshake succeeds
        assert!(client.handshake(node_id).is_ok());

        // Second handshake fails (already active)
        let result = client.handshake(node_id);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), IamClientError::HandshakeFailed);
    }

    // ========================================================================
    // Disconnect Tests
    // ========================================================================

    #[test]
    fn test_client_disconnect() {
        let connection = MockConnection::new();
        connection.add_response(IamResponse::HelloOk {
            negotiated_version: ProtocolVersion::CURRENT,
            session_id: SessionId::from_value(42),
        });

        let mut client = IamClient::new(connection);
        let node_id = UniqueSystemId::new().unwrap();
        client.handshake(node_id).unwrap();

        assert!(client.is_active());
        client.disconnect();
        assert!(!client.is_active());
        assert!(!client.is_connected());
        assert_eq!(client.session_id(), INVALID_SESSION_ID);
    }

    #[test]
    fn test_client_disconnect_idempotent() {
        let connection = MockConnection::new();
        let mut client = IamClient::new(connection);

        client.disconnect();
        client.disconnect(); // Should not panic
        assert!(!client.is_connected());
    }

    #[test]
    fn test_client_drop_closes_connection() {
        let connection = MockConnection::new();
        connection.add_response(IamResponse::HelloOk {
            negotiated_version: ProtocolVersion::CURRENT,
            session_id: SessionId::from_value(42),
        });

        // We need a way to check if close was called after drop
        // Create client in a scope to trigger drop
        {
            let mut client = IamClient::new(connection);
            let node_id = UniqueSystemId::new().unwrap();
            client.handshake(node_id).unwrap();
            // client is dropped here
        }
        // Connection is moved into client, so we can't check it directly
        // This test just ensures drop doesn't panic
    }

    // ========================================================================
    // Create Service Tests
    // ========================================================================

    #[test]
    fn test_client_create_service_not_active() {
        let connection = MockConnection::new();
        let mut client = IamClient::new(connection);

        let service_name = ServiceName::new("test/service").unwrap();
        let result = client.create_service(&service_name, MessagingPatternKind::PublishSubscribe);

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), IamClientError::SessionInvalid);
    }

    #[test]
    fn test_client_create_service_success() {
        use crate::service::messaging_pattern::MessagingPattern;
        use iceoryx2_cal::hash::sha1::Sha1;

        let connection = MockConnection::new();
        let service_name = ServiceName::new("test/service").unwrap();
        let expected_service_id =
            ServiceId::new::<Sha1>(&service_name, MessagingPattern::PublishSubscribe);

        connection.add_response(IamResponse::CreateServiceOk {
            service_id: expected_service_id,
        });

        let mut client = IamClient {
            connection: Some(connection),
            receive_buffer: new_receive_buffer(),
            session_id: SessionId::from_value(42),
            protocol_version: ProtocolVersion::CURRENT,
            state: ConnectionState::Active,
        };

        let result = client.create_service(&service_name, MessagingPatternKind::PublishSubscribe);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), expected_service_id);
    }

    #[test]
    fn test_client_create_service_denied() {
        let connection = MockConnection::new();
        connection.add_response(IamResponse::Denied {
            reason: DenialReason::Unauthorized,
            message: alloc::string::String::from("Not authorized"),
        });

        let mut client = IamClient {
            connection: Some(connection),
            receive_buffer: new_receive_buffer(),
            session_id: SessionId::from_value(42),
            protocol_version: ProtocolVersion::CURRENT,
            state: ConnectionState::Active,
        };

        let service_name = ServiceName::new("test/service").unwrap();
        let result = client.create_service(&service_name, MessagingPatternKind::PublishSubscribe);

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), IamClientError::RequestDenied);
    }

    // ========================================================================
    // Attach Tests
    // ========================================================================

    #[test]
    fn test_client_attach_publisher_success() {
        use crate::service::messaging_pattern::MessagingPattern;
        use iceoryx2_cal::hash::sha1::Sha1;

        let connection = MockConnection::new();
        let service_name = ServiceName::new("test/service").unwrap();
        let service_id = ServiceId::new::<Sha1>(&service_name, MessagingPattern::PublishSubscribe);

        connection.add_response(IamResponse::AttachOk {
            port_id: 123,
            segment_info: vec![],
            handle_count: 0,
        });

        let mut client = IamClient {
            connection: Some(connection),
            receive_buffer: new_receive_buffer(),
            session_id: SessionId::from_value(42),
            protocol_version: ProtocolVersion::CURRENT,
            state: ConnectionState::Active,
        };

        let result = client.attach_publisher(&service_id, 8, 1024);
        assert!(result.is_ok());

        let (port_id, segments, handles) = result.unwrap();
        assert_eq!(port_id, 123);
        assert!(segments.is_empty());
        assert!(handles.is_empty());
    }

    #[test]
    fn test_client_attach_publisher_with_segments() {
        use crate::service::messaging_pattern::MessagingPattern;
        use iceoryx2_cal::hash::sha1::Sha1;
        use iceoryx2_cal::security::AccessRights;

        let connection = MockConnection::new();
        let service_name = ServiceName::new("test/service").unwrap();
        let service_id = ServiceId::new::<Sha1>(&service_name, MessagingPattern::PublishSubscribe);

        let segment_info = vec![SegmentInfo::new(
            SegmentId::new(1),
            4096,
            AccessRights::read_write(),
        )];

        connection.add_response(IamResponse::AttachOk {
            port_id: 456,
            segment_info: segment_info.clone(),
            handle_count: 0, // No actual handles in this test
        });

        let mut client = IamClient {
            connection: Some(connection),
            receive_buffer: new_receive_buffer(),
            session_id: SessionId::from_value(42),
            protocol_version: ProtocolVersion::CURRENT,
            state: ConnectionState::Active,
        };

        let result = client.attach_publisher(&service_id, 8, 1024);
        assert!(result.is_ok());

        let (port_id, segments, _handles) = result.unwrap();
        assert_eq!(port_id, 456);
        assert_eq!(segments.len(), 1);
        assert_eq!(segments[0].segment_id().value(), 1);
    }

    #[test]
    fn test_client_attach_subscriber_success() {
        use crate::service::messaging_pattern::MessagingPattern;
        use iceoryx2_cal::hash::sha1::Sha1;

        let connection = MockConnection::new();
        let service_name = ServiceName::new("test/service").unwrap();
        let service_id = ServiceId::new::<Sha1>(&service_name, MessagingPattern::PublishSubscribe);

        connection.add_response(IamResponse::AttachOk {
            port_id: 789,
            segment_info: vec![],
            handle_count: 0,
        });

        let mut client = IamClient {
            connection: Some(connection),
            receive_buffer: new_receive_buffer(),
            session_id: SessionId::from_value(42),
            protocol_version: ProtocolVersion::CURRENT,
            state: ConnectionState::Active,
        };

        let result = client.attach_subscriber(&service_id, 16);
        assert!(result.is_ok());

        let (port_id, _, _) = result.unwrap();
        assert_eq!(port_id, 789);
    }

    #[test]
    fn test_client_attach_server_success() {
        use crate::service::messaging_pattern::MessagingPattern;
        use iceoryx2_cal::hash::sha1::Sha1;

        let connection = MockConnection::new();
        let service_name = ServiceName::new("test/service").unwrap();
        let service_id = ServiceId::new::<Sha1>(&service_name, MessagingPattern::RequestResponse);

        connection.add_response(IamResponse::AttachOk {
            port_id: 111,
            segment_info: vec![],
            handle_count: 0,
        });

        let mut client = IamClient {
            connection: Some(connection),
            receive_buffer: new_receive_buffer(),
            session_id: SessionId::from_value(42),
            protocol_version: ProtocolVersion::CURRENT,
            state: ConnectionState::Active,
        };

        let result = client.attach_server(&service_id, 10);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().0, 111);
    }

    #[test]
    fn test_client_attach_client_success() {
        use crate::service::messaging_pattern::MessagingPattern;
        use iceoryx2_cal::hash::sha1::Sha1;

        let connection = MockConnection::new();
        let service_name = ServiceName::new("test/service").unwrap();
        let service_id = ServiceId::new::<Sha1>(&service_name, MessagingPattern::RequestResponse);

        connection.add_response(IamResponse::AttachOk {
            port_id: 222,
            segment_info: vec![],
            handle_count: 0,
        });

        let mut client = IamClient {
            connection: Some(connection),
            receive_buffer: new_receive_buffer(),
            session_id: SessionId::from_value(42),
            protocol_version: ProtocolVersion::CURRENT,
            state: ConnectionState::Active,
        };

        let result = client.attach_client(&service_id, 5);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().0, 222);
    }

    #[test]
    fn test_client_attach_denied() {
        use crate::service::messaging_pattern::MessagingPattern;
        use iceoryx2_cal::hash::sha1::Sha1;

        let connection = MockConnection::new();
        let service_name = ServiceName::new("test/service").unwrap();
        let service_id = ServiceId::new::<Sha1>(&service_name, MessagingPattern::PublishSubscribe);

        connection.add_response(IamResponse::Denied {
            reason: DenialReason::ResourceLimitExceeded,
            message: alloc::string::String::from("Too many ports"),
        });

        let mut client = IamClient {
            connection: Some(connection),
            receive_buffer: new_receive_buffer(),
            session_id: SessionId::from_value(42),
            protocol_version: ProtocolVersion::CURRENT,
            state: ConnectionState::Active,
        };

        let result = client.attach_publisher(&service_id, 8, 1024);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), IamClientError::RequestDenied);
    }

    // ========================================================================
    // Detach Tests
    // ========================================================================

    #[test]
    fn test_client_detach_success() {
        use crate::service::messaging_pattern::MessagingPattern;
        use iceoryx2_cal::hash::sha1::Sha1;

        let connection = MockConnection::new();
        let service_name = ServiceName::new("test/service").unwrap();
        let service_id = ServiceId::new::<Sha1>(&service_name, MessagingPattern::PublishSubscribe);

        connection.add_response(IamResponse::DetachOk);

        let mut client = IamClient {
            connection: Some(connection),
            receive_buffer: new_receive_buffer(),
            session_id: SessionId::from_value(42),
            protocol_version: ProtocolVersion::CURRENT,
            state: ConnectionState::Active,
        };

        let result = client.detach(&service_id, 123);
        assert!(result.is_ok());
    }

    #[test]
    fn test_client_detach_not_active() {
        use crate::service::messaging_pattern::MessagingPattern;
        use iceoryx2_cal::hash::sha1::Sha1;

        let connection = MockConnection::new();
        let service_name = ServiceName::new("test/service").unwrap();
        let service_id = ServiceId::new::<Sha1>(&service_name, MessagingPattern::PublishSubscribe);

        let mut client = IamClient::new(connection);

        let result = client.detach(&service_id, 123);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), IamClientError::SessionInvalid);
    }

    // ========================================================================
    // Add Segment Tests
    // ========================================================================

    #[test]
    fn test_client_add_segment_success() {
        use crate::service::messaging_pattern::MessagingPattern;
        use iceoryx2_cal::hash::sha1::Sha1;

        let connection = MockConnection::new();
        let service_name = ServiceName::new("test/service").unwrap();
        let service_id = ServiceId::new::<Sha1>(&service_name, MessagingPattern::PublishSubscribe);

        connection.add_response(IamResponse::AddSegmentOk {
            segment_id: SegmentId::new(5),
            size: 8192,
            handle_count: 0,
        });

        let mut client = IamClient {
            connection: Some(connection),
            receive_buffer: new_receive_buffer(),
            session_id: SessionId::from_value(42),
            protocol_version: ProtocolVersion::CURRENT,
            state: ConnectionState::Active,
        };

        let result = client.add_segment(&service_id, 123, 8192, 1024, 8);
        assert!(result.is_ok());

        let (segment_id, size, handles) = result.unwrap();
        assert_eq!(segment_id.value(), 5);
        assert_eq!(size, 8192);
        assert!(handles.is_empty());
    }

    #[test]
    fn test_client_add_segment_denied() {
        use crate::service::messaging_pattern::MessagingPattern;
        use iceoryx2_cal::hash::sha1::Sha1;

        let connection = MockConnection::new();
        let service_name = ServiceName::new("test/service").unwrap();
        let service_id = ServiceId::new::<Sha1>(&service_name, MessagingPattern::PublishSubscribe);

        connection.add_response(IamResponse::Denied {
            reason: DenialReason::ResourceLimitExceeded,
            message: alloc::string::String::from("Maximum segments reached"),
        });

        let mut client = IamClient {
            connection: Some(connection),
            receive_buffer: new_receive_buffer(),
            session_id: SessionId::from_value(42),
            protocol_version: ProtocolVersion::CURRENT,
            state: ConnectionState::Active,
        };

        let result = client.add_segment(&service_id, 123, 8192, 1024, 8);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), IamClientError::RequestDenied);
    }

    // ========================================================================
    // Ack Retirement Tests
    // ========================================================================

    #[test]
    fn test_client_ack_retirement_success() {
        use crate::service::messaging_pattern::MessagingPattern;
        use iceoryx2_cal::hash::sha1::Sha1;

        let connection = MockConnection::new();
        let service_name = ServiceName::new("test/service").unwrap();
        let service_id = ServiceId::new::<Sha1>(&service_name, MessagingPattern::PublishSubscribe);

        connection.add_response(IamResponse::AckOk);

        let mut client = IamClient {
            connection: Some(connection),
            receive_buffer: new_receive_buffer(),
            session_id: SessionId::from_value(42),
            protocol_version: ProtocolVersion::CURRENT,
            state: ConnectionState::Active,
        };

        let result = client.ack_retirement(&service_id, SegmentId::new(7));
        assert!(result.is_ok());
    }

    #[test]
    fn test_client_ack_retirement_denied() {
        use crate::service::messaging_pattern::MessagingPattern;
        use iceoryx2_cal::hash::sha1::Sha1;

        let connection = MockConnection::new();
        let service_name = ServiceName::new("test/service").unwrap();
        let service_id = ServiceId::new::<Sha1>(&service_name, MessagingPattern::PublishSubscribe);

        connection.add_response(IamResponse::Denied {
            reason: DenialReason::Unauthorized,
            message: alloc::string::String::from("Not authorized for segment"),
        });

        let mut client = IamClient {
            connection: Some(connection),
            receive_buffer: new_receive_buffer(),
            session_id: SessionId::from_value(42),
            protocol_version: ProtocolVersion::CURRENT,
            state: ConnectionState::Active,
        };

        let result = client.ack_retirement(&service_id, SegmentId::new(7));
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), IamClientError::RequestDenied);
    }

    // ========================================================================
    // Security Validation Tests
    // ========================================================================

    #[test]
    fn test_client_handshake_invalid_session_id() {
        let connection = MockConnection::new();
        // Server returns invalid session_id (0)
        connection.add_response(IamResponse::HelloOk {
            negotiated_version: ProtocolVersion::CURRENT,
            session_id: INVALID_SESSION_ID,
        });

        let mut client = IamClient::new(connection);
        let node_id = UniqueSystemId::new().unwrap();

        let result = client.handshake(node_id);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), IamClientError::HandshakeFailed);
        assert!(!client.is_active());
    }

    #[test]
    fn test_client_attach_handle_count_exceeds_limit() {
        use crate::service::messaging_pattern::MessagingPattern;
        use iceoryx2_cal::hash::sha1::Sha1;

        let connection = MockConnection::new();
        let service_name = ServiceName::new("test/service").unwrap();
        let service_id = ServiceId::new::<Sha1>(&service_name, MessagingPattern::PublishSubscribe);

        // Server claims to send more handles than protocol allows (DoS attempt)
        connection.add_response(IamResponse::AttachOk {
            port_id: 123,
            segment_info: vec![],
            handle_count: MAX_HANDLES_PER_MESSAGE + 1,
        });

        let mut client = IamClient {
            connection: Some(connection),
            receive_buffer: new_receive_buffer(),
            session_id: SessionId::from_value(42),
            protocol_version: ProtocolVersion::CURRENT,
            state: ConnectionState::Active,
        };

        let result = client.attach_publisher(&service_id, 8, 1024);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), IamClientError::ProtocolError);
    }

    #[test]
    fn test_client_attach_segment_count_exceeds_limit() {
        use crate::service::messaging_pattern::MessagingPattern;
        use iceoryx2_cal::hash::sha1::Sha1;
        use iceoryx2_cal::security::AccessRights;

        let connection = MockConnection::new();
        let service_name = ServiceName::new("test/service").unwrap();
        let service_id = ServiceId::new::<Sha1>(&service_name, MessagingPattern::PublishSubscribe);

        // Server sends more segments than protocol allows (DoS attempt)
        let too_many_segments: Vec<SegmentInfo> = (0..MAX_SEGMENTS_PER_ATTACH + 1)
            .map(|i| SegmentInfo::new(SegmentId::new(i as u8), 4096, AccessRights::read_write()))
            .collect();

        connection.add_response(IamResponse::AttachOk {
            port_id: 123,
            segment_info: too_many_segments,
            handle_count: 0,
        });

        let mut client = IamClient {
            connection: Some(connection),
            receive_buffer: new_receive_buffer(),
            session_id: SessionId::from_value(42),
            protocol_version: ProtocolVersion::CURRENT,
            state: ConnectionState::Active,
        };

        let result = client.attach_publisher(&service_id, 8, 1024);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), IamClientError::ProtocolError);
    }

    #[test]
    fn test_client_add_segment_handle_count_exceeds_limit() {
        use crate::service::messaging_pattern::MessagingPattern;
        use iceoryx2_cal::hash::sha1::Sha1;

        let connection = MockConnection::new();
        let service_name = ServiceName::new("test/service").unwrap();
        let service_id = ServiceId::new::<Sha1>(&service_name, MessagingPattern::PublishSubscribe);

        // Server claims to send more handles than protocol allows (DoS attempt)
        connection.add_response(IamResponse::AddSegmentOk {
            segment_id: SegmentId::new(5),
            size: 8192,
            handle_count: MAX_HANDLES_PER_MESSAGE + 1,
        });

        let mut client = IamClient {
            connection: Some(connection),
            receive_buffer: new_receive_buffer(),
            session_id: SessionId::from_value(42),
            protocol_version: ProtocolVersion::CURRENT,
            state: ConnectionState::Active,
        };

        let result = client.add_segment(&service_id, 123, 8192, 1024, 8);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), IamClientError::ProtocolError);
    }

    // ========================================================================
    // Protocol Error Tests
    // ========================================================================

    #[test]
    fn test_client_protocol_error_response() {
        use crate::service::messaging_pattern::MessagingPattern;
        use iceoryx2_cal::hash::sha1::Sha1;

        let connection = MockConnection::new();
        let service_name = ServiceName::new("test/service").unwrap();
        let service_id = ServiceId::new::<Sha1>(&service_name, MessagingPattern::PublishSubscribe);

        connection.add_response(IamResponse::ProtocolError {
            message: alloc::string::String::from("Unexpected error"),
        });

        let mut client = IamClient {
            connection: Some(connection),
            receive_buffer: new_receive_buffer(),
            session_id: SessionId::from_value(42),
            protocol_version: ProtocolVersion::CURRENT,
            state: ConnectionState::Active,
        };

        let result = client.attach_publisher(&service_id, 8, 1024);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), IamClientError::ProtocolError);
    }

    // ========================================================================
    // Send Trait Tests
    // ========================================================================

    #[test]
    fn test_client_is_send() {
        fn assert_send<T: Send>() {}
        assert_send::<IamClient<MockConnection>>();
    }

    // ========================================================================
    // Request Verification Tests
    // ========================================================================

    #[test]
    fn test_client_sends_correct_handshake_request() {
        let connection = MockConnection::new();
        connection.add_response(IamResponse::HelloOk {
            negotiated_version: ProtocolVersion::CURRENT,
            session_id: SessionId::from_value(42),
        });

        let mut client = IamClient::new(connection);
        let node_id = UniqueSystemId::new().unwrap();
        client.handshake(node_id).unwrap();

        let requests = client.connection.as_ref().unwrap().get_sent_requests();
        assert_eq!(requests.len(), 1);

        match &requests[0] {
            IamRequest::Hello {
                protocol_version,
                node_id: sent_node_id,
            } => {
                assert_eq!(*protocol_version, ProtocolVersion::CURRENT);
                assert_eq!(*sent_node_id, node_id);
            }
            _ => panic!("Expected Hello request"),
        }
    }

    #[test]
    fn test_client_sends_correct_create_service_request() {
        use crate::service::messaging_pattern::MessagingPattern;
        use iceoryx2_cal::hash::sha1::Sha1;

        let connection = MockConnection::new();
        let service_name = ServiceName::new("test/service").unwrap();
        let expected_service_id =
            ServiceId::new::<Sha1>(&service_name, MessagingPattern::PublishSubscribe);

        connection.add_response(IamResponse::CreateServiceOk {
            service_id: expected_service_id,
        });

        let mut client = IamClient {
            connection: Some(connection),
            receive_buffer: new_receive_buffer(),
            session_id: SessionId::from_value(42),
            protocol_version: ProtocolVersion::CURRENT,
            state: ConnectionState::Active,
        };

        client
            .create_service(&service_name, MessagingPatternKind::PublishSubscribe)
            .unwrap();

        let requests = client.connection.as_ref().unwrap().get_sent_requests();
        assert_eq!(requests.len(), 1);

        match &requests[0] {
            IamRequest::CreateService {
                service_name: sent_name,
                messaging_pattern,
            } => {
                assert_eq!(*sent_name, service_name);
                assert_eq!(*messaging_pattern, MessagingPatternKind::PublishSubscribe);
            }
            _ => panic!("Expected CreateService request"),
        }
    }
}
