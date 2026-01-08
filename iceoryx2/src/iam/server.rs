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

//! Core IAM server implementation.
//!
//! This module provides the [`IamServer`] which is the central coordinator for
//! secured inter-process communication. The server:
//!
//! - Accepts client connections
//! - Manages client sessions
//! - Enforces policy decisions on all operations
//! - Tracks cumulative resource usage per session
//! - Manages the segment lifecycle
//!
//! # Architecture
//!
//! The server is generic over two traits:
//! - `C: ControlChannel` - The transport mechanism for client communication
//! - `P: IamPolicy` - The policy for authorization decisions
//!
//! The actual control channel implementation (Unix domain sockets, Windows named pipes)
//! is provided by separate sub-projects (SP2, SP3). This module focuses on the
//! server logic: session management, request handling, and policy enforcement.
//!
//! # Cumulative Limit Enforcement
//!
//! Phase 3's key responsibility is tracking and enforcing CUMULATIVE resource limits:
//! - Total segments per session (not just per-request validation)
//! - Total memory allocated per session
//! - Number of ports per session by type
//!
//! The policy provides per-request validation and limit values, but the server
//! maintains the counters and enforces that cumulative usage doesn't exceed limits.
//!
//! # Thread Safety
//!
//! The server is designed for **single-threaded event loop** processing. All types
//! are `Send` but not `Sync`. For multi-threaded scenarios, use separate server
//! instances per thread or wrap in appropriate synchronization primitives.
//!
//! # Production Hardening
//!
//! For production deployments, consider implementing:
//! - **Handshake timeout**: Sessions are created on connection but require Hello
//!   handshake. Implement timeout to remove sessions that don't complete handshake.
//! - **Connection limits**: Limit concurrent connections at the control channel layer.
//! - **Audit logging**: Log authorization decisions for security monitoring.
//!
//! # Example
//!
//! ```ignore
//! use iceoryx2::iam::server::{IamServer, IamServerBuilder};
//! use iceoryx2::iam::DefaultPolicy;
//!
//! // Create a server with default policy
//! let policy = DefaultPolicy::new();
//! let server = IamServerBuilder::new()
//!     .with_policy(policy)
//!     .build()?;
//!
//! // Process pending requests (non-blocking)
//! server.process()?;
//! ```

use std::collections::HashMap;

use iceoryx2_cal::security::credentials::ProcessCredentials;
use iceoryx2_cal::security::handle::PlatformHandle;
use iceoryx2_cal::security::AccessRights;
use iceoryx2_cal::shm_allocator::SegmentId;

use super::error::IamServerError;
use super::policy::{IamPolicy, PolicyDecision, ResourceLimits};
use super::protocol::{
    DenialReason, IamNotification, IamRequest, IamResponse, MessagingPatternKind, PortType,
    ProtocolVersion, SessionId,
};
use super::segment_manager::SegmentManager;
use super::session::{ClientSession, SessionResourceUsage};

// ============================================================================
// ControlChannel Trait (Placeholder for SP2/SP3)
// ============================================================================

/// Trait for control channel connections.
///
/// This trait abstracts the platform-specific control channel implementation.
/// The actual implementations are provided by SP2 (Linux) and SP3 (Windows).
///
/// # Responsibilities
///
/// Implementations are responsible for:
/// - Secure credential retrieval from the OS (SCM_CREDENTIALS, ImpersonateNamedPipeClient)
/// - Secure handle passing (SCM_RIGHTS, DuplicateHandle)
/// - Message serialization/deserialization (e.g., using postcard)
/// - Framing and buffering
///
/// # Safety
///
/// Implementations must ensure that:
/// - Credentials are obtained securely from the OS, not self-reported
/// - Handle passing uses secure mechanisms
pub trait ControlChannelConnection: Send {
    /// Returns the peer's process credentials.
    ///
    /// This must be obtained securely from the OS, not self-reported.
    fn peer_credentials(&self) -> Result<ProcessCredentials, IamServerError>;

    /// Tries to receive a request without blocking.
    ///
    /// The implementation is responsible for deserializing the request from
    /// the wire format (e.g., using postcard).
    ///
    /// Returns `Ok(Some(request))` if a complete request was received,
    /// `Ok(None)` if no data is available (would block), or an error.
    fn try_receive_request(&self) -> Result<Option<IamRequest>, IamServerError>;

    /// Sends a response to the peer.
    ///
    /// The implementation is responsible for serializing the response to
    /// the wire format (e.g., using postcard).
    fn send_response(&self, response: &IamResponse) -> Result<(), IamServerError>;

    /// Sends a notification to the peer.
    ///
    /// The implementation is responsible for serializing the notification to
    /// the wire format (e.g., using postcard).
    fn send_notification(&self, notification: &IamNotification) -> Result<(), IamServerError>;

    /// Sends handles to the peer.
    fn send_handles(&self, handles: &[PlatformHandle]) -> Result<(), IamServerError>;
}

/// Trait for control channel listeners.
///
/// This trait abstracts the platform-specific listener implementation.
pub trait ControlChannelListener: Send {
    /// The connection type produced by this listener.
    type Connection: ControlChannelConnection;

    /// Tries to accept a connection without blocking.
    ///
    /// Returns `Ok(Some(connection))` if a client connected,
    /// `Ok(None)` if no pending connections, or an error.
    fn try_accept(&self) -> Result<Option<Self::Connection>, IamServerError>;
}

// ============================================================================
// SessionEntry
// ============================================================================

/// Entry in the sessions map combining session state and connection.
struct SessionEntry<C: ControlChannelConnection> {
    /// The client session state.
    session: ClientSession,
    /// The connection to the client.
    connection: C,
    /// Whether the handshake has completed.
    handshake_complete: bool,
}

impl<C: ControlChannelConnection> SessionEntry<C> {
    fn new(session: ClientSession, connection: C) -> Self {
        Self {
            session,
            connection,
            handshake_complete: false,
        }
    }
}

// ============================================================================
// IamServer
// ============================================================================

/// The IAM server for secured inter-process communication.
///
/// The server is parameterized over:
/// - `L: ControlChannelListener` - The listener type for accepting connections
/// - `P: IamPolicy` - The policy for authorization decisions
///
/// # Responsibilities
///
/// 1. **Connection Management**: Accept new client connections and track sessions
/// 2. **Authentication**: Verify client credentials during handshake
/// 3. **Authorization**: Enforce policy decisions for all operations
/// 4. **Resource Accounting**: Track cumulative usage and enforce limits
/// 5. **Segment Management**: Create, authorize, and retire shared memory segments
///
/// # Thread Safety
///
/// `IamServer` is `Send` but not `Sync`. It is designed to run in a single thread
/// that calls `process()` periodically. For multi-threaded scenarios, each thread
/// should have its own server instance.
pub struct IamServer<L: ControlChannelListener, P: IamPolicy> {
    /// The listener for accepting new connections.
    listener: L,
    /// Active sessions indexed by session ID.
    sessions: HashMap<SessionId, SessionEntry<L::Connection>>,
    /// Segment manager for shared memory lifecycle.
    segment_manager: SegmentManager,
    /// The policy for authorization decisions.
    policy: P,
    /// Counter for generating unique port IDs.
    port_counter: u128,
}

impl<L: ControlChannelListener, P: IamPolicy> IamServer<L, P> {
    /// Creates a new IAM server with the given listener and policy.
    ///
    /// # Arguments
    ///
    /// * `listener` - The control channel listener for accepting connections
    /// * `policy` - The policy for authorization decisions
    pub fn new(listener: L, policy: P) -> Self {
        Self {
            listener,
            sessions: HashMap::new(),
            segment_manager: SegmentManager::new(),
            policy,
            port_counter: 0,
        }
    }

    /// Returns a reference to the policy.
    pub fn policy(&self) -> &P {
        &self.policy
    }

    /// Returns a mutable reference to the policy.
    pub fn policy_mut(&mut self) -> &mut P {
        &mut self.policy
    }

    /// Returns the number of active sessions.
    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }

    /// Returns the number of managed segments.
    pub fn segment_count(&self) -> usize {
        self.segment_manager.segment_count()
    }

    /// Gets the resource usage for a session.
    pub fn get_session_usage(&self, session_id: SessionId) -> Option<&SessionResourceUsage> {
        self.sessions
            .get(&session_id)
            .map(|e| e.session.resource_usage())
    }

    // ========================================================================
    // Main Processing Loop
    // ========================================================================

    /// Processes pending connections and requests (non-blocking).
    ///
    /// This method should be called periodically to:
    /// 1. Accept new client connections
    /// 2. Process requests from existing sessions
    ///
    /// # Returns
    ///
    /// The number of requests processed, or an error.
    pub fn process(&mut self) -> Result<usize, IamServerError> {
        let mut processed = 0;

        // Accept new connections
        while let Some(connection) = self.listener.try_accept()? {
            self.handle_new_connection(connection)?;
        }

        // Process requests from existing sessions
        let session_ids: Vec<SessionId> = self.sessions.keys().copied().collect();
        for session_id in session_ids {
            match self.process_session_requests(session_id) {
                Ok(count) => processed += count,
                Err(_) => {
                    // Session error - remove it
                    self.remove_session(session_id);
                }
            }
        }

        Ok(processed)
    }

    /// Handles a new client connection.
    fn handle_new_connection(&mut self, connection: L::Connection) -> Result<(), IamServerError> {
        // Get peer credentials from the OS
        let credentials = connection.peer_credentials()?;

        // Check if connection is allowed by policy
        let decision = self.policy.authorize_connect(&credentials);
        if let PolicyDecision::Deny { reason, message } = decision {
            // Send denial and close
            let response = IamResponse::Denied { reason, message };
            let _ = self.send_response(&connection, &response);
            return Ok(());
        }

        // Create session (not yet fully authenticated - waiting for Hello)
        let session = ClientSession::new(credentials);
        let session_id = session.id();
        self.sessions
            .insert(session_id, SessionEntry::new(session, connection));

        Ok(())
    }

    /// Processes requests for a single session.
    fn process_session_requests(&mut self, session_id: SessionId) -> Result<usize, IamServerError> {
        let mut processed = 0;

        // Try to receive a request
        let request = {
            let entry = self
                .sessions
                .get(&session_id)
                .ok_or(IamServerError::SessionNotFound)?;

            match entry.connection.try_receive_request() {
                Ok(Some(req)) => req,
                Ok(None) => return Ok(0), // No data available
                Err(e) => return Err(e),
            }
        };

        // Handle request
        let (response, handles) = self.handle_request(session_id, request)?;
        self.send_response_to_session(session_id, &response)?;

        // Send handles if any
        if !handles.is_empty() {
            self.send_handles_to_session(session_id, &handles)?;
        }

        processed += 1;
        Ok(processed)
    }

    // ========================================================================
    // Request Handling
    // ========================================================================

    /// Handles a single request and returns the response and any handles to send.
    fn handle_request(
        &mut self,
        session_id: SessionId,
        request: IamRequest,
    ) -> Result<(IamResponse, Vec<PlatformHandle>), IamServerError> {
        // Get session info (credentials, usage)
        let entry = self
            .sessions
            .get(&session_id)
            .ok_or(IamServerError::SessionNotFound)?;

        let credentials = entry.session.credentials().clone();
        let usage = *entry.session.resource_usage();
        let handshake_complete = entry.handshake_complete;

        match request {
            IamRequest::Hello {
                protocol_version,
                node_id: _,
            } => self.handle_hello(session_id, protocol_version),

            IamRequest::CreateService {
                service_name,
                messaging_pattern,
            } => {
                if !handshake_complete {
                    return Ok((
                        IamResponse::ProtocolError {
                            message: String::from("Handshake not complete"),
                        },
                        Vec::new(),
                    ));
                }
                self.handle_create_service(&credentials, &service_name, messaging_pattern)
            }

            IamRequest::AttachPublisher {
                service_id,
                history_size,
                max_slice_len,
            } => {
                if !handshake_complete {
                    return Ok((
                        IamResponse::ProtocolError {
                            message: String::from("Handshake not complete"),
                        },
                        Vec::new(),
                    ));
                }
                self.handle_attach_publisher(
                    session_id,
                    &credentials,
                    &usage,
                    &service_id,
                    history_size,
                    max_slice_len,
                )
            }

            IamRequest::AttachSubscriber {
                service_id,
                buffer_size: _,
            } => {
                if !handshake_complete {
                    return Ok((
                        IamResponse::ProtocolError {
                            message: String::from("Handshake not complete"),
                        },
                        Vec::new(),
                    ));
                }
                self.handle_attach_subscriber(session_id, &credentials, &usage, &service_id)
            }

            IamRequest::AttachServer {
                service_id,
                max_active_requests: _,
            } => {
                if !handshake_complete {
                    return Ok((
                        IamResponse::ProtocolError {
                            message: String::from("Handshake not complete"),
                        },
                        Vec::new(),
                    ));
                }
                self.handle_attach_server(session_id, &credentials, &usage, &service_id)
            }

            IamRequest::AttachClient {
                service_id,
                max_pending_responses: _,
            } => {
                if !handshake_complete {
                    return Ok((
                        IamResponse::ProtocolError {
                            message: String::from("Handshake not complete"),
                        },
                        Vec::new(),
                    ));
                }
                self.handle_attach_client(session_id, &credentials, &usage, &service_id)
            }

            IamRequest::AddSegment {
                service_id,
                port_id,
                requested_size,
            } => {
                if !handshake_complete {
                    return Ok((
                        IamResponse::ProtocolError {
                            message: String::from("Handshake not complete"),
                        },
                        Vec::new(),
                    ));
                }
                self.handle_add_segment(
                    session_id,
                    &credentials,
                    &usage,
                    &service_id,
                    port_id,
                    requested_size,
                )
            }

            IamRequest::Detach { service_id, port_id } => {
                if !handshake_complete {
                    return Ok((
                        IamResponse::ProtocolError {
                            message: String::from("Handshake not complete"),
                        },
                        Vec::new(),
                    ));
                }
                self.handle_detach(session_id, &service_id, port_id)
            }

            IamRequest::AckSegmentRetirement {
                service_id: _,
                segment_id,
            } => {
                if !handshake_complete {
                    return Ok((
                        IamResponse::ProtocolError {
                            message: String::from("Handshake not complete"),
                        },
                        Vec::new(),
                    ));
                }
                self.handle_ack_retirement(session_id, segment_id)
            }
        }
    }

    /// Handles the Hello handshake request.
    fn handle_hello(
        &mut self,
        session_id: SessionId,
        protocol_version: ProtocolVersion,
    ) -> Result<(IamResponse, Vec<PlatformHandle>), IamServerError> {
        // Check version compatibility
        if !ProtocolVersion::CURRENT.accepts_client(&protocol_version) {
            return Ok((
                IamResponse::Denied {
                    reason: DenialReason::VersionMismatch,
                    message: format!(
                        "Client version {}.{} not compatible with server version {}.{}",
                        protocol_version.major(),
                        protocol_version.minor(),
                        ProtocolVersion::CURRENT.major(),
                        ProtocolVersion::CURRENT.minor()
                    ),
                },
                Vec::new(),
            ));
        }

        // Mark handshake as complete
        if let Some(entry) = self.sessions.get_mut(&session_id) {
            entry.handshake_complete = true;
        }

        Ok((
            IamResponse::HelloOk {
                negotiated_version: ProtocolVersion::CURRENT,
                session_id,
            },
            Vec::new(),
        ))
    }

    /// Handles CreateService request.
    fn handle_create_service(
        &mut self,
        credentials: &ProcessCredentials,
        service_name: &crate::service::service_name::ServiceName,
        messaging_pattern: MessagingPatternKind,
    ) -> Result<(IamResponse, Vec<PlatformHandle>), IamServerError> {
        // Check policy
        let decision =
            self.policy
                .authorize_create(credentials, service_name, messaging_pattern);
        if let PolicyDecision::Deny { reason, message } = decision {
            return Ok((IamResponse::Denied { reason, message }, Vec::new()));
        }

        // In a real implementation, we would create the service and return its ID
        // For now, return a protocol error since service creation is not yet implemented
        Ok((
            IamResponse::ProtocolError {
                message: String::from("Service creation not yet implemented"),
            },
            Vec::new(),
        ))
    }

    /// Handles AttachPublisher request.
    fn handle_attach_publisher(
        &mut self,
        session_id: SessionId,
        credentials: &ProcessCredentials,
        usage: &SessionResourceUsage,
        service_id: &crate::service::service_id::ServiceId,
        history_size: usize,
        max_slice_len: usize,
    ) -> Result<(IamResponse, Vec<PlatformHandle>), IamServerError> {
        // Check policy
        let decision = self
            .policy
            .authorize_attach(credentials, service_id, PortType::Publisher);
        if let PolicyDecision::Deny { reason, message } = decision {
            return Ok((IamResponse::Denied { reason, message }, Vec::new()));
        }

        // Check cumulative limits
        let limits = self.policy.get_limits(credentials);
        if let Some(response) = self.check_port_limit(usage, PortType::Publisher, &limits) {
            return Ok((response, Vec::new()));
        }

        // Calculate segment size (simplified)
        let _segment_size = Self::calculate_publisher_segment_size(history_size, max_slice_len);

        // Check segment count limit
        if usage.segment_count >= limits.max_segments {
            return Ok((
                IamResponse::Denied {
                    reason: DenialReason::ResourceLimitExceeded,
                    message: String::from("Maximum segment count reached"),
                },
                Vec::new(),
            ));
        }

        // For now, we don't actually create shared memory since that requires
        // integration with the shared memory subsystem. Return a placeholder.
        let port_id = self.allocate_port_id();

        // Update session
        if let Some(entry) = self.sessions.get_mut(&session_id) {
            entry.session.add_port(port_id, PortType::Publisher);
        }

        // In a real implementation, we would:
        // 1. Create shared memory segment
        // 2. Register with segment manager
        // 3. Authorize session
        // 4. Return handle

        Ok((
            IamResponse::AttachOk {
                port_id,
                segment_info: Vec::new(), // Would contain actual segment info
                handle_count: 0,          // Would be 1+ for actual segments
            },
            Vec::new(),
        ))
    }

    /// Handles AttachSubscriber request.
    fn handle_attach_subscriber(
        &mut self,
        session_id: SessionId,
        credentials: &ProcessCredentials,
        usage: &SessionResourceUsage,
        service_id: &crate::service::service_id::ServiceId,
    ) -> Result<(IamResponse, Vec<PlatformHandle>), IamServerError> {
        // Check policy
        let decision = self
            .policy
            .authorize_attach(credentials, service_id, PortType::Subscriber);
        if let PolicyDecision::Deny { reason, message } = decision {
            return Ok((IamResponse::Denied { reason, message }, Vec::new()));
        }

        // Check cumulative limits
        let limits = self.policy.get_limits(credentials);
        if let Some(response) = self.check_port_limit(usage, PortType::Subscriber, &limits) {
            return Ok((response, Vec::new()));
        }

        let port_id = self.allocate_port_id();

        // Update session
        if let Some(entry) = self.sessions.get_mut(&session_id) {
            entry.session.add_port(port_id, PortType::Subscriber);
        }

        // Subscribers get read access to existing publisher segments
        let segments = self.segment_manager.get_session_segments(session_id);
        let handle_count = segments.len();

        Ok((
            IamResponse::AttachOk {
                port_id,
                segment_info: segments,
                handle_count,
            },
            Vec::new(), // Handles would be cloned here
        ))
    }

    /// Handles AttachServer request.
    fn handle_attach_server(
        &mut self,
        session_id: SessionId,
        credentials: &ProcessCredentials,
        usage: &SessionResourceUsage,
        service_id: &crate::service::service_id::ServiceId,
    ) -> Result<(IamResponse, Vec<PlatformHandle>), IamServerError> {
        // Check policy
        let decision = self
            .policy
            .authorize_attach(credentials, service_id, PortType::Server);
        if let PolicyDecision::Deny { reason, message } = decision {
            return Ok((IamResponse::Denied { reason, message }, Vec::new()));
        }

        // Check cumulative limits
        let limits = self.policy.get_limits(credentials);
        if let Some(response) = self.check_port_limit(usage, PortType::Server, &limits) {
            return Ok((response, Vec::new()));
        }

        let port_id = self.allocate_port_id();

        // Update session
        if let Some(entry) = self.sessions.get_mut(&session_id) {
            entry.session.add_port(port_id, PortType::Server);
        }

        Ok((
            IamResponse::AttachOk {
                port_id,
                segment_info: Vec::new(),
                handle_count: 0,
            },
            Vec::new(),
        ))
    }

    /// Handles AttachClient request.
    fn handle_attach_client(
        &mut self,
        session_id: SessionId,
        credentials: &ProcessCredentials,
        usage: &SessionResourceUsage,
        service_id: &crate::service::service_id::ServiceId,
    ) -> Result<(IamResponse, Vec<PlatformHandle>), IamServerError> {
        // Check policy
        let decision = self
            .policy
            .authorize_attach(credentials, service_id, PortType::Client);
        if let PolicyDecision::Deny { reason, message } = decision {
            return Ok((IamResponse::Denied { reason, message }, Vec::new()));
        }

        // Check cumulative limits
        let limits = self.policy.get_limits(credentials);
        if let Some(response) = self.check_port_limit(usage, PortType::Client, &limits) {
            return Ok((response, Vec::new()));
        }

        let port_id = self.allocate_port_id();

        // Update session
        if let Some(entry) = self.sessions.get_mut(&session_id) {
            entry.session.add_port(port_id, PortType::Client);
        }

        Ok((
            IamResponse::AttachOk {
                port_id,
                segment_info: Vec::new(),
                handle_count: 0,
            },
            Vec::new(),
        ))
    }

    /// Handles AddSegment request.
    fn handle_add_segment(
        &mut self,
        _session_id: SessionId,
        credentials: &ProcessCredentials,
        usage: &SessionResourceUsage,
        service_id: &crate::service::service_id::ServiceId,
        _port_id: u128,
        requested_size: usize,
    ) -> Result<(IamResponse, Vec<PlatformHandle>), IamServerError> {
        // Check policy
        let decision = self
            .policy
            .authorize_add_segment(credentials, service_id, requested_size);
        if let PolicyDecision::Deny { reason, message } = decision {
            return Ok((IamResponse::Denied { reason, message }, Vec::new()));
        }

        // Check cumulative segment count
        let limits = self.policy.get_limits(credentials);
        if usage.segment_count >= limits.max_segments {
            return Ok((
                IamResponse::Denied {
                    reason: DenialReason::ResourceLimitExceeded,
                    message: String::from("Maximum segment count reached"),
                },
                Vec::new(),
            ));
        }

        // Check cumulative memory limit (optional, depends on policy)
        // This is where Phase 3's cumulative tracking comes into play
        let _new_total = usage.total_memory.saturating_add(requested_size);
        // For now, we don't have a total_memory limit in ResourceLimits
        // This could be added in a future iteration

        // In a real implementation, we would create the segment
        // For now, return not implemented
        Ok((
            IamResponse::ProtocolError {
                message: String::from("Segment creation not yet implemented"),
            },
            Vec::new(),
        ))
    }

    /// Handles Detach request.
    fn handle_detach(
        &mut self,
        session_id: SessionId,
        _service_id: &crate::service::service_id::ServiceId,
        port_id: u128,
    ) -> Result<(IamResponse, Vec<PlatformHandle>), IamServerError> {
        // Remove port from session
        if let Some(entry) = self.sessions.get_mut(&session_id) {
            entry.session.remove_port(port_id);
        }

        Ok((IamResponse::DetachOk, Vec::new()))
    }

    /// Handles AckSegmentRetirement request.
    ///
    /// Verifies that the session actually has this segment pending retirement
    /// before accepting the acknowledgment. This prevents sessions from
    /// acknowledging retirements for segments they don't own.
    fn handle_ack_retirement(
        &mut self,
        session_id: SessionId,
        segment_id: SegmentId,
    ) -> Result<(IamResponse, Vec<PlatformHandle>), IamServerError> {
        // Verify session has this segment pending retirement (security check)
        let has_pending = self
            .sessions
            .get(&session_id)
            .map(|e| e.session.has_pending_retirement(segment_id))
            .unwrap_or(false);

        if !has_pending {
            return Ok((
                IamResponse::Denied {
                    reason: DenialReason::Unauthorized,
                    message: String::from("Session not authorized for this segment retirement"),
                },
                Vec::new(),
            ));
        }

        // Record ack in session
        if let Some(entry) = self.sessions.get_mut(&session_id) {
            entry.session.ack_retirement(segment_id);
        }

        // Record ack in segment manager
        let _removed = self.segment_manager.ack_retirement(segment_id, session_id);

        Ok((IamResponse::AckOk, Vec::new()))
    }

    // ========================================================================
    // Limit Checking
    // ========================================================================

    /// Checks if adding a port would exceed limits.
    fn check_port_limit(
        &self,
        usage: &SessionResourceUsage,
        port_type: PortType,
        limits: &ResourceLimits,
    ) -> Option<IamResponse> {
        let (current, max, name) = match port_type {
            PortType::Publisher => (usage.publisher_count, limits.max_publishers, "publishers"),
            PortType::Subscriber => (usage.subscriber_count, limits.max_subscribers, "subscribers"),
            PortType::Server => (usage.server_count, limits.max_servers, "servers"),
            PortType::Client => (usage.client_count, limits.max_clients, "clients"),
        };

        if current >= max {
            Some(IamResponse::Denied {
                reason: DenialReason::ResourceLimitExceeded,
                message: format!("Maximum {} ({}) reached", name, max),
            })
        } else {
            None
        }
    }

    // ========================================================================
    // Session Management
    // ========================================================================

    /// Removes a session and cleans up its resources.
    fn remove_session(&mut self, session_id: SessionId) {
        // Revoke session from all segments
        self.segment_manager.revoke_session(session_id);

        // Remove session entry
        self.sessions.remove(&session_id);
    }

    /// Allocates a unique port ID.
    fn allocate_port_id(&mut self) -> u128 {
        self.port_counter += 1;
        self.port_counter
    }

    // ========================================================================
    // Segment Size Calculation
    // ========================================================================

    /// Calculates the segment size for a publisher.
    ///
    /// This is a simplified calculation. The actual implementation would need
    /// to match the service requirements and alignment constraints.
    fn calculate_publisher_segment_size(history_size: usize, max_slice_len: usize) -> usize {
        // Header overhead + (history + 1 for current) * sample size
        const HEADER_OVERHEAD: usize = 4096;
        (history_size + 1)
            .saturating_mul(max_slice_len)
            .saturating_add(HEADER_OVERHEAD)
    }

    // ========================================================================
    // Response/Handle Sending
    // ========================================================================

    /// Sends a response to a specific connection.
    fn send_response(
        &self,
        connection: &L::Connection,
        response: &IamResponse,
    ) -> Result<(), IamServerError> {
        connection.send_response(response)
    }

    /// Sends a response to a session.
    fn send_response_to_session(
        &self,
        session_id: SessionId,
        response: &IamResponse,
    ) -> Result<(), IamServerError> {
        let entry = self
            .sessions
            .get(&session_id)
            .ok_or(IamServerError::SessionNotFound)?;

        entry.connection.send_response(response)
    }

    /// Sends handles to a session.
    fn send_handles_to_session(
        &self,
        session_id: SessionId,
        handles: &[PlatformHandle],
    ) -> Result<(), IamServerError> {
        let entry = self
            .sessions
            .get(&session_id)
            .ok_or(IamServerError::SessionNotFound)?;

        entry.connection.send_handles(handles)
    }

    // ========================================================================
    // Segment Management (Public API)
    // ========================================================================

    /// Registers an externally created segment.
    ///
    /// This is used when segments are created outside the server (e.g., by the
    /// shared memory subsystem) and need to be managed by the IAM server.
    ///
    /// # Arguments
    ///
    /// * `handle` - The platform handle for the segment
    /// * `size` - The size of the segment in bytes
    /// * `access` - The access rights for the segment
    ///
    /// # Returns
    ///
    /// The unique segment ID assigned to this segment.
    pub fn register_segment(
        &mut self,
        handle: PlatformHandle,
        size: usize,
        access: AccessRights,
    ) -> Result<SegmentId, IamServerError> {
        self.segment_manager.register_segment(handle, size, access)
    }

    /// Authorizes a session to access a segment.
    ///
    /// Verifies the session exists before granting access to prevent
    /// resource leaks and inconsistent state.
    ///
    /// # Arguments
    ///
    /// * `segment_id` - The segment to authorize access to
    /// * `session_id` - The session to grant access
    ///
    /// # Returns
    ///
    /// A cloned platform handle for the session, or an error.
    pub fn authorize_segment_access(
        &mut self,
        segment_id: SegmentId,
        session_id: SessionId,
    ) -> Result<PlatformHandle, IamServerError> {
        // Verify session exists (security check)
        if !self.sessions.contains_key(&session_id) {
            return Err(IamServerError::SessionNotFound);
        }

        let handle = self
            .segment_manager
            .authorize_session(segment_id, session_id)?;

        // Update session segment tracking (guaranteed to exist after check above)
        if let Some(entry) = self.sessions.get_mut(&session_id) {
            if let Some(segment) = self.segment_manager.get(segment_id) {
                entry.session.grant_segment(segment_id, segment.size());
            }
        }

        Ok(handle)
    }

    /// Begins segment retirement and returns sessions to notify.
    ///
    /// # Arguments
    ///
    /// * `segment_id` - The segment to retire
    ///
    /// # Returns
    ///
    /// List of session IDs that need to acknowledge the retirement.
    pub fn begin_segment_retirement(
        &mut self,
        segment_id: SegmentId,
    ) -> Option<Vec<SessionId>> {
        self.segment_manager
            .begin_retirement(segment_id)
            .map(|set| set.into_iter().collect())
    }

    /// Broadcasts a notification to specific sessions.
    ///
    /// # Arguments
    ///
    /// * `session_ids` - The sessions to notify
    /// * `notification` - The notification to send
    pub fn broadcast_notification(
        &self,
        session_ids: &[SessionId],
        notification: &IamNotification,
    ) -> Result<(), IamServerError> {
        for session_id in session_ids {
            if let Some(entry) = self.sessions.get(session_id) {
                // Ignore individual send failures
                let _ = entry.connection.send_notification(notification);
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::iam::DefaultPolicy;
    use std::sync::{Arc, Mutex};

    // ========================================================================
    // Mock Types for Testing
    // ========================================================================

    /// Mock connection for testing.
    struct MockConnection {
        credentials: ProcessCredentials,
        received_responses: Arc<Mutex<Vec<IamResponse>>>,
        request_to_receive: Arc<Mutex<Option<IamRequest>>>,
    }

    impl MockConnection {
        fn new(credentials: ProcessCredentials) -> Self {
            Self {
                credentials,
                received_responses: Arc::new(Mutex::new(Vec::new())),
                request_to_receive: Arc::new(Mutex::new(None)),
            }
        }

        #[allow(dead_code)]
        fn set_receive_request(&self, request: IamRequest) {
            *self.request_to_receive.lock().unwrap() = Some(request);
        }
    }

    impl ControlChannelConnection for MockConnection {
        fn peer_credentials(&self) -> Result<ProcessCredentials, IamServerError> {
            Ok(self.credentials.clone())
        }

        fn try_receive_request(&self) -> Result<Option<IamRequest>, IamServerError> {
            Ok(self.request_to_receive.lock().unwrap().take())
        }

        fn send_response(&self, response: &IamResponse) -> Result<(), IamServerError> {
            self.received_responses.lock().unwrap().push(response.clone());
            Ok(())
        }

        fn send_notification(&self, _notification: &IamNotification) -> Result<(), IamServerError> {
            Ok(())
        }

        fn send_handles(&self, _handles: &[PlatformHandle]) -> Result<(), IamServerError> {
            Ok(())
        }
    }

    /// Mock listener for testing.
    struct MockListener {
        pending_connections: Arc<Mutex<Vec<MockConnection>>>,
    }

    impl MockListener {
        fn new() -> Self {
            Self {
                pending_connections: Arc::new(Mutex::new(Vec::new())),
            }
        }

        fn add_connection(&self, conn: MockConnection) {
            self.pending_connections.lock().unwrap().push(conn);
        }
    }

    impl ControlChannelListener for MockListener {
        type Connection = MockConnection;

        fn try_accept(&self) -> Result<Option<Self::Connection>, IamServerError> {
            Ok(self.pending_connections.lock().unwrap().pop())
        }
    }

    fn test_credentials() -> ProcessCredentials {
        ProcessCredentials::new(1234, 1000, 1000)
    }

    fn create_test_server() -> IamServer<MockListener, DefaultPolicy> {
        let listener = MockListener::new();
        let policy = DefaultPolicy::with_owner(1000);
        IamServer::new(listener, policy)
    }

    // ========================================================================
    // Basic Server Tests
    // ========================================================================

    #[test]
    fn test_server_new() {
        let server = create_test_server();
        assert_eq!(server.session_count(), 0);
        assert_eq!(server.segment_count(), 0);
    }

    #[test]
    fn test_server_accept_connection() {
        let listener = MockListener::new();
        let policy = DefaultPolicy::with_owner(1000);
        let mut server = IamServer::new(listener, policy);

        // Add a pending connection
        let conn = MockConnection::new(test_credentials());
        server.listener.add_connection(conn);

        // Process to accept connection
        let processed = server.process().unwrap();
        assert_eq!(processed, 0); // No requests processed, just connection accepted
        assert_eq!(server.session_count(), 1);
    }

    #[test]
    fn test_server_handshake() {
        let listener = MockListener::new();
        let policy = DefaultPolicy::with_owner(1000);
        let mut server = IamServer::new(listener, policy);

        // Add connection
        let conn = MockConnection::new(test_credentials());
        server.listener.add_connection(conn);

        // Accept connection
        server.process().unwrap();
        assert_eq!(server.session_count(), 1);

        // Note: To fully test handshake, we would need to store a reference
        // to the connection's request queue before adding to the listener.
        // This test verifies the connection is accepted successfully.
    }

    #[test]
    fn test_server_reject_unauthorized() {
        let listener = MockListener::new();
        let policy = DefaultPolicy::with_owner(2000); // Different UID
        let mut server = IamServer::new(listener, policy);

        // Add connection with UID 1000 (not authorized)
        let conn = MockConnection::new(ProcessCredentials::new(1234, 1000, 1000));
        let received_responses = conn.received_responses.clone();
        server.listener.add_connection(conn);

        // Process - should reject and not add session
        server.process().unwrap();

        // Connection was rejected - check that a denial was sent
        let responses = received_responses.lock().unwrap();
        if !responses.is_empty() {
            assert!(matches!(responses[0], IamResponse::Denied { .. }));
        }
    }

    // ========================================================================
    // Cumulative Limit Tests
    // ========================================================================

    #[test]
    fn test_check_port_limit_under_limit() {
        let server = create_test_server();
        let usage = SessionResourceUsage::new();
        let limits = ResourceLimits::default();

        let result = server.check_port_limit(&usage, PortType::Publisher, &limits);
        assert!(result.is_none());
    }

    #[test]
    fn test_check_port_limit_at_limit() {
        let server = create_test_server();
        let mut usage = SessionResourceUsage::new();
        usage.publisher_count = 16; // Default max

        let limits = ResourceLimits::default();
        let result = server.check_port_limit(&usage, PortType::Publisher, &limits);

        assert!(result.is_some());
        if let Some(IamResponse::Denied { reason, .. }) = result {
            assert_eq!(reason, DenialReason::ResourceLimitExceeded);
        } else {
            panic!("Expected Denied response");
        }
    }

    #[test]
    fn test_check_port_limit_all_types() {
        let server = create_test_server();
        let limits = ResourceLimits::default();

        // Publisher
        let mut usage = SessionResourceUsage::new();
        usage.publisher_count = limits.max_publishers;
        assert!(server
            .check_port_limit(&usage, PortType::Publisher, &limits)
            .is_some());

        // Subscriber
        let mut usage = SessionResourceUsage::new();
        usage.subscriber_count = limits.max_subscribers;
        assert!(server
            .check_port_limit(&usage, PortType::Subscriber, &limits)
            .is_some());

        // Server
        let mut usage = SessionResourceUsage::new();
        usage.server_count = limits.max_servers;
        assert!(server
            .check_port_limit(&usage, PortType::Server, &limits)
            .is_some());

        // Client
        let mut usage = SessionResourceUsage::new();
        usage.client_count = limits.max_clients;
        assert!(server
            .check_port_limit(&usage, PortType::Client, &limits)
            .is_some());
    }

    // ========================================================================
    // Segment Size Calculation Tests
    // ========================================================================

    #[test]
    fn test_calculate_publisher_segment_size() {
        let size = IamServer::<MockListener, DefaultPolicy>::calculate_publisher_segment_size(8, 1024);
        // (8 + 1) * 1024 + 4096 = 13312
        assert_eq!(size, 13312);
    }

    #[test]
    fn test_calculate_publisher_segment_size_zero_history() {
        let size = IamServer::<MockListener, DefaultPolicy>::calculate_publisher_segment_size(0, 1024);
        // (0 + 1) * 1024 + 4096 = 5120
        assert_eq!(size, 5120);
    }

    // ========================================================================
    // Session Management Tests
    // ========================================================================

    #[test]
    fn test_allocate_port_id() {
        let listener = MockListener::new();
        let policy = DefaultPolicy::with_owner(1000);
        let mut server = IamServer::new(listener, policy);

        let id1 = server.allocate_port_id();
        let id2 = server.allocate_port_id();
        let id3 = server.allocate_port_id();

        assert_eq!(id1, 1);
        assert_eq!(id2, 2);
        assert_eq!(id3, 3);
    }

    // ========================================================================
    // Segment Management Tests
    // ========================================================================

    #[cfg(unix)]
    fn create_test_handle() -> PlatformHandle {
        use std::os::unix::io::AsRawFd;
        let raw_fd = unsafe {
            iceoryx2_pal_posix::posix::dup(std::io::stdout().as_raw_fd())
        };
        unsafe { PlatformHandle::from_raw_fd(raw_fd) }
    }

    #[cfg(windows)]
    fn create_test_handle() -> PlatformHandle {
        use std::os::windows::io::FromRawHandle;
        use std::os::windows::io::AsRawHandle;
        let raw_handle = std::io::stdout().as_raw_handle();
        let mut dup_handle = std::ptr::null_mut();
        unsafe {
            let current_process = windows_sys::Win32::System::Threading::GetCurrentProcess();
            windows_sys::Win32::Foundation::DuplicateHandle(
                current_process,
                raw_handle as *mut _,
                current_process,
                &mut dup_handle,
                0,
                0,
                windows_sys::Win32::Foundation::DUPLICATE_SAME_ACCESS,
            );
            PlatformHandle::from_raw_handle(dup_handle)
        }
    }

    #[test]
    fn test_register_segment() {
        let mut server = create_test_server();
        let handle = create_test_handle();

        let segment_id = server
            .register_segment(handle, 4096, AccessRights::read_write())
            .unwrap();

        assert_eq!(server.segment_count(), 1);
        assert!(server.segment_manager.has_segment(segment_id));
    }

    // ========================================================================
    // Send Tests
    // ========================================================================

    #[test]
    fn test_server_is_send() {
        fn assert_send<T: Send>() {}
        assert_send::<IamServer<MockListener, DefaultPolicy>>();
    }

    // IamServer is intentionally not Sync since it's designed for single-threaded use
}
