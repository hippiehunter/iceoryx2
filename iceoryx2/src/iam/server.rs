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

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use std::collections::HashMap;

use iceoryx2_cal::control_channel::{
    ControlChannelConnection as CalConnection, ControlChannelListener as CalListener,
};
use iceoryx2_cal::security::AccessRights;
use iceoryx2_cal::security::credentials::ProcessCredentials;
use iceoryx2_cal::security::handle::PlatformHandle;
use iceoryx2_cal::shm_allocator::SegmentId;

use super::audit::{AuditEvent, AuditEventKind, AuditLogger};
use super::error::IamServerError;
use super::policy::{IamPolicy, PolicyDecision, ResourceLimits};
use super::protocol::{
    DenialReason, IamNotification, IamRequest, IamResponse, MessagingPatternKind, PortType,
    ProtocolVersion, SessionId,
};
use super::segment_factory::{NoSegmentFactory, SegmentFactory};
use super::segment_manager::SegmentManager;
use super::session::{ClientSession, SessionResourceUsage};
use super::wire::{
    new_receive_buffer, peer_credentials, receive_handles_from_client, send_handles, send_message,
    try_receive_message,
};

use crate::service::service_hash::ServiceHash;

// ============================================================================
// SessionEntry
// ============================================================================

/// Entry in the sessions map combining session state and connection.
struct SessionEntry<C: CalConnection> {
    /// The client session state.
    session: ClientSession,
    /// The connection to the client (CAL type stored directly).
    connection: C,
    /// Whether the handshake has completed.
    handshake_complete: bool,
    /// The node id the peer announced in its Hello (`None` before the handshake).
    node_id: Option<u128>,
    /// The (iceoryx2) producer port ids this session registered segments / channels for. A
    /// producer port belongs to exactly one session; its handles are reaped with the session.
    producer_ports: Vec<u128>,
    /// Segments (count, bytes) registered per producer port, given back to the session's usage
    /// when the port is detached.
    producer_port_usage: HashMap<u128, (usize, usize)>,
}

impl<C: CalConnection> SessionEntry<C> {
    fn new(session: ClientSession, connection: C) -> Self {
        Self {
            session,
            connection,
            handshake_complete: false,
            node_id: None,
            producer_ports: Vec::new(),
            producer_port_usage: HashMap::new(),
        }
    }

    fn has_port_type(&self, types: &[PortType]) -> bool {
        self.session.ports().any(|p| types.contains(&p.port_type))
    }
}

/// Port types whose ports produce (and register) data segments and connection channels.
const PRODUCER_PORT_TYPES: [PortType; 3] =
    [PortType::Publisher, PortType::Server, PortType::Client];
/// Port types whose ports consume data segments of producers.
const CONSUMER_PORT_TYPES: [PortType; 3] =
    [PortType::Subscriber, PortType::Server, PortType::Client];

/// How long the handles of a departed peer's producer ports stay brokerable before the
/// departure is handled. Consumers that had not yet mapped the producer's segments (e.g. a
/// subscriber that has not called `receive()` since the producer's last `send()`) can still
/// obtain them, so samples sent right before a producer exits or dies are not lost.
const PEER_DEPARTURE_RETENTION: core::time::Duration = core::time::Duration::from_secs(2);

/// How long the server keeps checking whether a departed peer's node is dead before it assumes
/// that the peer closed its connection gracefully (and deregistered its ports itself).
const PEER_DEPARTURE_GRACE: core::time::Duration = core::time::Duration::from_secs(10);

/// Result of a [`PeerDepartureHandler`] invocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerDepartureOutcome {
    /// The departure was handled (or there was nothing to do).
    Completed,
    /// The departure cannot be decided yet (e.g. the peer process is still exiting); call again.
    Retry,
}

/// Invoked by the server when the last session of a peer node closed (gracefully or because the
/// peer died). Receives the announced node id and the kernel-verified credentials of the peer.
pub type PeerDepartureHandler =
    Box<dyn FnMut(u128, &ProcessCredentials) -> PeerDepartureOutcome + Send>;

/// A peer node whose last session closed and whose departure is still being handled.
struct PendingDeparture {
    node_id: u128,
    credentials: ProcessCredentials,
    since: std::time::Instant,
    /// Producer ports of the departed sessions whose handles are kept until the departure was
    /// handled.
    orphaned_ports: Vec<u128>,
}

// ============================================================================
// IamServerBuilder
// ============================================================================

/// Builder for constructing an [`IamServer`] with optional configuration.
///
/// # Required
/// - `listener` and `policy` (passed to `new()`)
///
/// # Optional
/// - `service_name` - For audit log entries
/// - `audit_logger` - Audit logging backend
/// - `segment_factory` - For IAM-managed segment creation
///
/// # Example
///
/// ```ignore
/// let server = IamServerBuilder::new(listener, policy)
///     .service_name("my/service")
///     .audit_logger(Box::new(FileAuditLogger::new(&path)?))
///     .build();
/// ```
pub struct IamServerBuilder<L: CalListener, P: IamPolicy> {
    listener: L,
    policy: P,
    service_name: String,
    audit_logger: Option<Box<dyn AuditLogger>>,
    segment_factory: Arc<dyn SegmentFactory>,
    departure_handler: Option<PeerDepartureHandler>,
    departure_timing: (core::time::Duration, core::time::Duration),
}

impl<L: CalListener, P: IamPolicy> IamServerBuilder<L, P> {
    /// Creates a new builder with the required listener and policy.
    pub fn new(listener: L, policy: P) -> Self {
        Self {
            listener,
            policy,
            service_name: String::new(),
            audit_logger: None,
            segment_factory: Arc::new(NoSegmentFactory),
            departure_handler: None,
            departure_timing: (PEER_DEPARTURE_RETENTION, PEER_DEPARTURE_GRACE),
        }
    }

    /// Overrides how long the handles of a departed peer stay brokerable (`retention`) and how
    /// long the server keeps asking the departure handler (`grace`).
    pub fn peer_departure_timing(
        mut self,
        retention: core::time::Duration,
        grace: core::time::Duration,
    ) -> Self {
        self.departure_timing = (retention, grace);
        self
    }

    /// Sets the handler that is invoked when the last session of a peer node closed.
    pub fn peer_departure_handler(mut self, handler: PeerDepartureHandler) -> Self {
        self.departure_handler = Some(handler);
        self
    }

    /// Sets the service name for audit events.
    pub fn service_name(mut self, name: impl Into<String>) -> Self {
        self.service_name = name.into();
        self
    }

    /// Sets the audit logger.
    pub fn audit_logger(mut self, logger: Box<dyn AuditLogger>) -> Self {
        self.audit_logger = Some(logger);
        self
    }

    /// Sets the segment factory for IAM-managed segment creation.
    pub fn segment_factory(mut self, factory: Arc<dyn SegmentFactory>) -> Self {
        self.segment_factory = factory;
        self
    }

    /// Builds the [`IamServer`].
    pub fn build(self) -> IamServer<L, P> {
        IamServer {
            listener: self.listener,
            sessions: HashMap::new(),
            segment_manager: SegmentManager::new(),
            policy: self.policy,
            port_counter: 0,
            receive_buffer: new_receive_buffer(),
            audit_logger: self.audit_logger,
            service_name: self.service_name,
            segment_factory: self.segment_factory,
            port_to_service: HashMap::new(),
            service_consumers: HashMap::new(),
            producer_port_owner: HashMap::new(),
            departure_handler: self.departure_handler,
            pending_departures: Vec::new(),
            departure_timing: self.departure_timing,
        }
    }
}

// ============================================================================
// IamServer
// ============================================================================

/// The IAM server for secured inter-process communication.
///
/// The server is parameterized over:
/// - `L: CalListener` - The CAL listener type for accepting connections
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
pub struct IamServer<L: CalListener, P: IamPolicy> {
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
    /// Shared receive buffer for deserializing messages.
    receive_buffer: Vec<u8>,
    /// Optional audit logger for recording authorization decisions.
    audit_logger: Option<Box<dyn AuditLogger>>,
    /// Service name for audit events.
    service_name: String,
    /// Factory for creating shared memory segments (IAM-managed mode).
    segment_factory: Arc<dyn SegmentFactory>,
    /// Mapping from producer port ID to its service ID.
    /// Used for Phase 8 push-based segment notifications.
    port_to_service: HashMap<u128, ServiceHash>,
    /// Mapping from service ID to consumer sessions: (session_id, port_id).
    /// Used for Phase 8 push-based segment notifications to broadcast
    /// SegmentUpdate notifications to all consumers of a service.
    service_consumers: HashMap<ServiceHash, Vec<(SessionId, u128)>>,
    /// The session that owns a producer port (the first session that registered a segment or
    /// channel for it). Prevents other sessions from registering handles under that port.
    producer_port_owner: HashMap<u128, SessionId>,
    /// Invoked when the last session of a peer node closed.
    departure_handler: Option<PeerDepartureHandler>,
    /// Departed peer nodes whose handling is still pending.
    pending_departures: Vec<PendingDeparture>,
    /// (retention, grace) of departed peers, see [`PEER_DEPARTURE_RETENTION`] and
    /// [`PEER_DEPARTURE_GRACE`].
    departure_timing: (core::time::Duration, core::time::Duration),
}

impl<L: CalListener, P: IamPolicy> IamServer<L, P> {
    /// Creates a new IAM server with the given listener and policy.
    ///
    /// Uses a `NoSegmentFactory` which will return errors if segment creation
    /// is attempted. Use `new_with_factory` for services that need IAM-managed
    /// segment creation.
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
            receive_buffer: new_receive_buffer(),
            audit_logger: None,
            service_name: String::new(),
            segment_factory: Arc::new(NoSegmentFactory),
            port_to_service: HashMap::new(),
            service_consumers: HashMap::new(),
            producer_port_owner: HashMap::new(),
            departure_handler: None,
            pending_departures: Vec::new(),
            departure_timing: (PEER_DEPARTURE_RETENTION, PEER_DEPARTURE_GRACE),
        }
    }

    /// Creates a new IAM server with a segment factory.
    ///
    /// The segment factory is used to create shared memory segments when
    /// producers request dynamic segment allocation in IAM-managed mode.
    ///
    /// # Arguments
    ///
    /// * `listener` - The control channel listener for accepting connections
    /// * `policy` - The policy for authorization decisions
    /// * `segment_factory` - Factory for creating shared memory segments
    pub fn new_with_factory(
        listener: L,
        policy: P,
        segment_factory: Arc<dyn SegmentFactory>,
    ) -> Self {
        Self {
            listener,
            sessions: HashMap::new(),
            segment_manager: SegmentManager::new(),
            policy,
            port_counter: 0,
            receive_buffer: new_receive_buffer(),
            audit_logger: None,
            service_name: String::new(),
            segment_factory,
            port_to_service: HashMap::new(),
            service_consumers: HashMap::new(),
            producer_port_owner: HashMap::new(),
            departure_handler: None,
            pending_departures: Vec::new(),
            departure_timing: (PEER_DEPARTURE_RETENTION, PEER_DEPARTURE_GRACE),
        }
    }

    /// Creates a new IAM server with audit logging.
    ///
    /// # Arguments
    ///
    /// * `listener` - The control channel listener for accepting connections
    /// * `policy` - The policy for authorization decisions
    /// * `service_name` - The service name for audit events
    /// * `audit_logger` - Optional audit logger for recording decisions
    pub fn new_with_audit(
        listener: L,
        policy: P,
        service_name: String,
        audit_logger: Option<Box<dyn AuditLogger>>,
    ) -> Self {
        Self {
            listener,
            sessions: HashMap::new(),
            segment_manager: SegmentManager::new(),
            policy,
            port_counter: 0,
            receive_buffer: new_receive_buffer(),
            audit_logger,
            service_name,
            segment_factory: Arc::new(NoSegmentFactory),
            port_to_service: HashMap::new(),
            service_consumers: HashMap::new(),
            producer_port_owner: HashMap::new(),
            departure_handler: None,
            pending_departures: Vec::new(),
            departure_timing: (PEER_DEPARTURE_RETENTION, PEER_DEPARTURE_GRACE),
        }
    }

    /// Creates a new IAM server with all options.
    ///
    /// # Arguments
    ///
    /// * `listener` - The control channel listener for accepting connections
    /// * `policy` - The policy for authorization decisions
    /// * `service_name` - The service name for audit events
    /// * `audit_logger` - Optional audit logger for recording decisions
    /// * `segment_factory` - Factory for creating shared memory segments
    pub fn new_with_all(
        listener: L,
        policy: P,
        service_name: String,
        audit_logger: Option<Box<dyn AuditLogger>>,
        segment_factory: Arc<dyn SegmentFactory>,
    ) -> Self {
        Self {
            listener,
            sessions: HashMap::new(),
            segment_manager: SegmentManager::new(),
            policy,
            port_counter: 0,
            receive_buffer: new_receive_buffer(),
            audit_logger,
            service_name,
            segment_factory,
            port_to_service: HashMap::new(),
            service_consumers: HashMap::new(),
            producer_port_owner: HashMap::new(),
            departure_handler: None,
            pending_departures: Vec::new(),
            departure_timing: (PEER_DEPARTURE_RETENTION, PEER_DEPARTURE_GRACE),
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

    /// Records an audit event if an audit logger is configured.
    fn audit(
        &self,
        kind: AuditEventKind,
        credentials: &ProcessCredentials,
        decision: &PolicyDecision,
    ) {
        if let Some(ref logger) = self.audit_logger {
            logger.log(&AuditEvent::new(
                kind,
                credentials.clone(),
                self.service_name.clone(),
                decision.clone(),
            ));
        }
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
        while let Some(connection) = self
            .listener
            .try_accept()
            .map_err(|_| IamServerError::AcceptFailed)?
        {
            self.handle_new_connection(connection)?;
        }

        // Process requests from existing sessions
        let session_ids: Vec<SessionId> = self.sessions.keys().copied().collect();
        for session_id in session_ids {
            match self.process_session_requests(session_id) {
                Ok(count) => {
                    processed += count;
                }
                Err(_) => {
                    self.remove_session(session_id);
                }
            }
        }

        self.process_departures();

        Ok(processed)
    }

    /// Hands every departed peer node to the departure handler (after the retention period)
    /// until it completed or the grace period expired, then releases the handles of the
    /// departed producer ports.
    fn process_departures(&mut self) {
        if self.pending_departures.is_empty() {
            return;
        }

        let (retention, grace) = self.departure_timing;
        let mut finished = Vec::new();
        let mut pending = core::mem::take(&mut self.pending_departures);
        pending.retain(|departure| {
            let reconnected = self
                .sessions
                .values()
                .any(|e| e.node_id == Some(departure.node_id));
            let done = if reconnected {
                // the node is alive and opened the service again; its old ports are gone
                true
            } else if departure.since.elapsed() < retention {
                false
            } else {
                match self.departure_handler.as_mut() {
                    Some(handler) => match handler(departure.node_id, &departure.credentials) {
                        PeerDepartureOutcome::Completed => true,
                        PeerDepartureOutcome::Retry => departure.since.elapsed() >= grace,
                    },
                    None => true,
                }
            };
            if done {
                finished.extend(departure.orphaned_ports.iter().copied());
            }
            !done
        });
        self.pending_departures = pending;

        for port_id in finished {
            self.reap_producer_port(port_id);
        }
    }

    /// Releases every handle registered under the (iceoryx2) producer port `port_id`.
    fn reap_producer_port(&mut self, port_id: u128) {
        self.segment_manager.remove_all_segments_for_port(port_id);
        self.segment_manager.remove_mgmt_segment_for_port(port_id);
        self.segment_manager
            .remove_channels_for_sender_port(port_id);
        self.port_to_service.remove(&port_id);
        self.producer_port_owner.remove(&port_id);
    }

    /// Handles a new client connection.
    fn handle_new_connection(&mut self, connection: L::Connection) -> Result<(), IamServerError> {
        // Get peer credentials from the OS using wire helper
        let credentials = peer_credentials(&connection)?;

        // Check if connection is allowed by policy
        let decision = self.policy.authorize_connect(&credentials);

        // Audit the connection decision
        self.audit(AuditEventKind::Connect, &credentials, &decision);

        if let PolicyDecision::Deny { reason, message } = decision {
            // Send denial and close using wire helper
            let response = IamResponse::Denied { reason, message };
            let _ = send_message(&connection, &response);
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

        // Try to receive a request using wire helper
        let request = {
            let entry = self
                .sessions
                .get(&session_id)
                .ok_or(IamServerError::SessionNotFound)?;

            // Use wire helper to receive and deserialize request
            match try_receive_message::<_, IamRequest>(&entry.connection, &mut self.receive_buffer)
            {
                Ok(Some(req)) => req,
                Ok(None) => return Ok(0), // No data available
                Err(e) => return Err(e),
            }
        };

        // RegisterSegment requires receiving handles from the client connection
        // before producing a response, so handle it here with connection access.
        if let IamRequest::RegisterSegment {
            ref service_id,
            port_id,
            segment_size,
            handle_count,
        } = request
        {
            let (response, handles) = self.handle_register_segment(
                session_id,
                service_id.clone(),
                port_id,
                segment_size,
                handle_count,
            )?;
            self.send_response_to_session(session_id, &response)?;
            if !handles.is_empty() {
                self.send_handles_to_session(session_id, &handles)?;
            }
            processed += 1;
            return Ok(processed);
        }

        // RegisterDynamicSegment also requires receiving handles from the client connection.
        if let IamRequest::RegisterDynamicSegment {
            ref service_id,
            port_id,
            segment_id,
            segment_size,
            handle_count,
        } = request
        {
            let (response, handles) = self.handle_register_dynamic_segment(
                session_id,
                service_id.clone(),
                port_id,
                segment_id,
                segment_size,
                handle_count,
            )?;
            self.send_response_to_session(session_id, &response)?;
            if !handles.is_empty() {
                self.send_handles_to_session(session_id, &handles)?;
            }
            processed += 1;
            return Ok(processed);
        }

        // RegisterChannel also requires receiving a handle (the connection-channel fd)
        // from the client connection out-of-band, so it is handled here rather than in
        // the plain `handle_request` match.
        if let IamRequest::RegisterChannel {
            ref service_id,
            sender_port_id,
            receiver_port_id,
            channel_size,
            handle_count,
        } = request
        {
            let (response, handles) = self.handle_register_channel(
                session_id,
                service_id.clone(),
                sender_port_id,
                receiver_port_id,
                channel_size,
                handle_count,
            )?;
            self.send_response_to_session(session_id, &response)?;
            if !handles.is_empty() {
                self.send_handles_to_session(session_id, &handles)?;
            }
            processed += 1;
            return Ok(processed);
        }

        // RegisterMgmtSegment also requires receiving a handle (the management-segment fd)
        // from the client connection out-of-band, so it is handled here rather than in
        // the plain `handle_request` match.
        if let IamRequest::RegisterMgmtSegment {
            ref service_id,
            port_id,
            mgmt_size,
            handle_count,
        } = request
        {
            let (response, handles) = self.handle_register_mgmt_segment(
                session_id,
                service_id.clone(),
                port_id,
                mgmt_size,
                handle_count,
            )?;
            self.send_response_to_session(session_id, &response)?;
            if !handles.is_empty() {
                self.send_handles_to_session(session_id, &handles)?;
            }
            processed += 1;
            return Ok(processed);
        }

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
                node_id,
            } => {
                let response = self.handle_hello(session_id, protocol_version)?;
                if matches!(response.0, IamResponse::HelloOk { .. })
                    && let Some(entry) = self.sessions.get_mut(&session_id)
                {
                    entry.node_id = Some(node_id.value());
                }
                Ok(response)
            }

            IamRequest::AttachNotifier { service_id }
            | IamRequest::AttachListener { service_id }
                if !handshake_complete =>
            {
                let _ = service_id;
                Ok((
                    IamResponse::ProtocolError {
                        message: String::from("Handshake not complete"),
                    },
                    Vec::new(),
                ))
            }

            IamRequest::AttachNotifier { service_id } => self.handle_attach_event_port(
                session_id,
                &credentials,
                &usage,
                &service_id,
                PortType::Notifier,
            ),

            IamRequest::AttachListener { service_id } => self.handle_attach_event_port(
                session_id,
                &credentials,
                &usage,
                &service_id,
                PortType::Listener,
            ),

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
                bucket_size,
                bucket_align,
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
                    bucket_size,
                    bucket_align,
                )
            }

            IamRequest::Detach {
                service_id,
                port_id,
            } => {
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

            // RegisterSegment is handled before handle_request in process_session_requests
            // because it needs connection access to receive handles from the client.
            IamRequest::RegisterSegment { .. } => Ok((
                IamResponse::ProtocolError {
                    message: String::from("RegisterSegment must be handled in dispatch loop"),
                },
                Vec::new(),
            )),

            IamRequest::RequestSegmentHandle {
                service_id: _,
                sender_port_id,
            } => {
                if !handshake_complete {
                    return Ok((
                        IamResponse::ProtocolError {
                            message: String::from("Handshake not complete"),
                        },
                        Vec::new(),
                    ));
                }
                self.handle_request_segment_handle(session_id, sender_port_id)
            }

            // RegisterDynamicSegment is handled before handle_request in process_session_requests
            // because it needs connection access to receive handles from the client.
            IamRequest::RegisterDynamicSegment { .. } => Ok((
                IamResponse::ProtocolError {
                    message: String::from(
                        "RegisterDynamicSegment must be handled in dispatch loop",
                    ),
                },
                Vec::new(),
            )),

            IamRequest::RequestDynamicSegmentHandle {
                service_id: _,
                sender_port_id,
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
                self.handle_request_dynamic_segment_handle(session_id, sender_port_id, segment_id)
            }

            // RegisterChannel is handled before handle_request in process_session_requests
            // because it needs connection access to receive the channel handle from the client.
            IamRequest::RegisterChannel { .. } => Ok((
                IamResponse::ProtocolError {
                    message: String::from("RegisterChannel must be handled in dispatch loop"),
                },
                Vec::new(),
            )),

            IamRequest::RequestChannelHandle {
                service_id: _,
                sender_port_id,
                receiver_port_id,
            } => {
                if !handshake_complete {
                    return Ok((
                        IamResponse::ProtocolError {
                            message: String::from("Handshake not complete"),
                        },
                        Vec::new(),
                    ));
                }
                self.handle_request_channel_handle(session_id, sender_port_id, receiver_port_id)
            }

            // RegisterMgmtSegment is handled before handle_request in process_session_requests
            // because it needs connection access to receive the handle from the client.
            IamRequest::RegisterMgmtSegment { .. } => Ok((
                IamResponse::ProtocolError {
                    message: String::from("RegisterMgmtSegment must be handled in dispatch loop"),
                },
                Vec::new(),
            )),

            IamRequest::RequestMgmtSegmentHandle {
                service_id: _,
                port_id,
            } => {
                if !handshake_complete {
                    return Ok((
                        IamResponse::ProtocolError {
                            message: String::from("Handshake not complete"),
                        },
                        Vec::new(),
                    ));
                }
                self.handle_request_mgmt_segment_handle(session_id, port_id)
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
        let decision = self
            .policy
            .authorize_create(credentials, service_name, messaging_pattern);

        // Audit the create decision
        self.audit(
            AuditEventKind::Create { messaging_pattern },
            credentials,
            &decision,
        );

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
        service_id: &crate::service::service_hash::ServiceHash,
        history_size: usize,
        max_slice_len: usize,
    ) -> Result<(IamResponse, Vec<PlatformHandle>), IamServerError> {
        // Check policy
        let decision = self
            .policy
            .authorize_attach(credentials, service_id, PortType::Publisher);

        // Audit the attach decision
        self.audit(
            AuditEventKind::Attach {
                port_type: PortType::Publisher,
                port_id: 0,
            },
            credentials,
            &decision,
        );

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

        // Track producer port -> service mapping for Phase 8 push notifications
        self.port_to_service.insert(port_id, *service_id);

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
        service_id: &crate::service::service_hash::ServiceHash,
    ) -> Result<(IamResponse, Vec<PlatformHandle>), IamServerError> {
        // Check policy
        let decision = self
            .policy
            .authorize_attach(credentials, service_id, PortType::Subscriber);

        // Audit the attach decision
        self.audit(
            AuditEventKind::Attach {
                port_type: PortType::Subscriber,
                port_id: 0,
            },
            credentials,
            &decision,
        );

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

        // Track consumer session for Phase 8 push notifications
        self.service_consumers
            .entry(*service_id)
            .or_default()
            .push((session_id, port_id));

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

    /// Handles AttachNotifier / AttachListener requests of event services. Event ports carry no
    /// data segments; the attach is purely an authorization gate (`notifier` / `listener` roles).
    fn handle_attach_event_port(
        &mut self,
        session_id: SessionId,
        credentials: &ProcessCredentials,
        usage: &SessionResourceUsage,
        service_id: &crate::service::service_hash::ServiceHash,
        port_type: PortType,
    ) -> Result<(IamResponse, Vec<PlatformHandle>), IamServerError> {
        let decision = self
            .policy
            .authorize_attach(credentials, service_id, port_type);

        self.audit(
            AuditEventKind::Attach {
                port_type,
                port_id: 0,
            },
            credentials,
            &decision,
        );

        if let PolicyDecision::Deny { reason, message } = decision {
            return Ok((IamResponse::Denied { reason, message }, Vec::new()));
        }

        let limits = self.policy.get_limits(credentials);
        if let Some(response) = self.check_port_limit(usage, port_type, &limits) {
            return Ok((response, Vec::new()));
        }

        let port_id = self.allocate_port_id();
        if let Some(entry) = self.sessions.get_mut(&session_id) {
            entry.session.add_port(port_id, port_type);
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

    /// Binds the (iceoryx2) producer `port_id` to `session_id` before the session may register
    /// handles for it. Only sessions that attached a producer port (publisher, server, client)
    /// may register handles at all, and a port that is already bound to another session cannot
    /// be taken over - otherwise a principal could inject segments into another producer's port.
    fn claim_producer_port(&mut self, session_id: SessionId, port_id: u128) -> Option<IamResponse> {
        let (credentials, is_producer) = match self.sessions.get(&session_id) {
            Some(entry) => (
                entry.session.credentials().clone(),
                entry.has_port_type(&PRODUCER_PORT_TYPES),
            ),
            None => {
                return Some(IamResponse::ProtocolError {
                    message: String::from("Unknown session"),
                });
            }
        };

        let decision = if !is_producer {
            PolicyDecision::deny(
                DenialReason::Unauthorized,
                "The session has not attached a producer port (publisher, server or client)",
            )
        } else {
            match self.producer_port_owner.get(&port_id) {
                Some(owner) if *owner != session_id => PolicyDecision::deny(
                    DenialReason::Unauthorized,
                    "The producer port is owned by another session",
                ),
                _ => PolicyDecision::Allow,
            }
        };

        if let PolicyDecision::Deny { reason, message } = decision {
            self.audit(
                AuditEventKind::RegisterHandle { port_id },
                &credentials,
                &PolicyDecision::Deny {
                    reason,
                    message: message.clone(),
                },
            );
            return Some(IamResponse::Denied { reason, message });
        }

        self.producer_port_owner.insert(port_id, session_id);
        if let Some(entry) = self.sessions.get_mut(&session_id)
            && !entry.producer_ports.contains(&port_id)
        {
            entry.producer_ports.push(port_id);
        }
        None
    }

    /// Only sessions that attached a consumer port (subscriber, server, client) - and thereby
    /// passed the policy's role check - may obtain handles to producer resources. A principal
    /// that may only publish never receives another publisher's data segment.
    fn authorize_consumer(
        &self,
        session_id: SessionId,
        sender_port_id: u128,
    ) -> Option<IamResponse> {
        let entry = self.sessions.get(&session_id)?;
        if entry.has_port_type(&CONSUMER_PORT_TYPES) {
            return None;
        }
        let decision = PolicyDecision::deny(
            DenialReason::Unauthorized,
            "The session has not attached a consumer port (subscriber, server or client)",
        );
        self.audit(
            AuditEventKind::AccessHandle {
                port_id: sender_port_id,
            },
            entry.session.credentials(),
            &decision,
        );
        match decision {
            PolicyDecision::Deny { reason, message } => {
                Some(IamResponse::Denied { reason, message })
            }
            PolicyDecision::Allow => None,
        }
    }

    /// Handles AttachServer request.
    fn handle_attach_server(
        &mut self,
        session_id: SessionId,
        credentials: &ProcessCredentials,
        usage: &SessionResourceUsage,
        service_id: &crate::service::service_hash::ServiceHash,
    ) -> Result<(IamResponse, Vec<PlatformHandle>), IamServerError> {
        // Check policy
        let decision = self
            .policy
            .authorize_attach(credentials, service_id, PortType::Server);

        // Audit the attach decision
        self.audit(
            AuditEventKind::Attach {
                port_type: PortType::Server,
                port_id: 0,
            },
            credentials,
            &decision,
        );

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

        // Track producer port -> service mapping for Phase 8 push notifications
        // (Server ports are producers in request-response pattern)
        self.port_to_service.insert(port_id, *service_id);

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
        service_id: &crate::service::service_hash::ServiceHash,
    ) -> Result<(IamResponse, Vec<PlatformHandle>), IamServerError> {
        // Check policy
        let decision = self
            .policy
            .authorize_attach(credentials, service_id, PortType::Client);

        // Audit the attach decision
        self.audit(
            AuditEventKind::Attach {
                port_type: PortType::Client,
                port_id: 0,
            },
            credentials,
            &decision,
        );

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

        // Track consumer session for Phase 8 push notifications
        // (Client ports are consumers in request-response pattern)
        self.service_consumers
            .entry(*service_id)
            .or_default()
            .push((session_id, port_id));

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
    ///
    /// This creates a shared memory segment using the configured segment factory,
    /// registers it with the segment manager, and returns the handle to the producer.
    fn handle_add_segment(
        &mut self,
        session_id: SessionId,
        credentials: &ProcessCredentials,
        usage: &SessionResourceUsage,
        service_id: &crate::service::service_hash::ServiceHash,
        port_id: u128,
        requested_size: usize,
        bucket_size: usize,
        bucket_align: usize,
    ) -> Result<(IamResponse, Vec<PlatformHandle>), IamServerError> {
        // Check policy
        let decision = self
            .policy
            .authorize_add_segment(credentials, service_id, requested_size);

        // Audit the add segment decision
        self.audit(
            AuditEventKind::AddSegment {
                size: requested_size,
            },
            credentials,
            &decision,
        );

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

        // Validate segment size
        if requested_size == 0 {
            return Ok((
                IamResponse::Denied {
                    reason: DenialReason::InvalidRequest,
                    message: String::from("Segment size cannot be zero"),
                },
                Vec::new(),
            ));
        }

        // Allocate a segment ID
        let segment_id = self.segment_manager.allocate_segment_id()?;

        // Create the segment using the factory
        let (handle, actual_size) = match self.segment_factory.create_segment(
            segment_id,
            requested_size,
            bucket_size,
            bucket_align,
        ) {
            Ok(result) => result,
            Err(IamServerError::SegmentCreationNotSupported) => {
                return Ok((
                    IamResponse::Denied {
                        reason: DenialReason::InvalidRequest,
                        message: String::from("Segment creation not supported by this service"),
                    },
                    Vec::new(),
                ));
            }
            Err(IamServerError::SegmentCreationFailed) => {
                return Ok((
                    IamResponse::Denied {
                        reason: DenialReason::InternalError,
                        message: String::from("Failed to create segment"),
                    },
                    Vec::new(),
                ));
            }
            Err(e) => return Err(e),
        };

        // Register the segment with the segment manager
        // We need to clone the handle for registration since we return one to the producer
        let handle_clone = handle
            .try_clone()
            .map_err(|_| IamServerError::HandlePassingFailed)?;

        self.segment_manager.register_segment_with_id(
            segment_id,
            handle_clone,
            actual_size,
            AccessRights::read_write(),
        )?;

        // Associate segment with the port at its explicit SegmentId index.
        //
        // The producer's resizable memory inserts this IAM-returned segment into its slotmap
        // at `key = segment_id.value()` and stamps that value into every PointerOffset it
        // produces; the consumer then requests the handle by `offset.segment_id().value()`.
        // Placing it at `port_segments[segment_id.value()]` (rather than appending) keeps the
        // handle lookup aligned with the producer's segment id even for multi-producer
        // services, where the global segment-id counter diverges from per-port push order.
        self.segment_manager.associate_segment_with_port_at_index(
            segment_id,
            port_id,
            segment_id.value(),
        )?;

        // Update session resource usage
        if let Some(entry) = self.sessions.get_mut(&session_id) {
            let usage = entry.session.resource_usage_mut();
            usage.segment_count += 1;
            usage.total_memory = usage.total_memory.saturating_add(actual_size);
            let port_usage = entry.producer_port_usage.entry(port_id).or_default();
            port_usage.0 += 1;
            port_usage.1 = port_usage.1.saturating_add(actual_size);
        }

        // Phase 8: Broadcast SegmentUpdate notification to consumer sessions
        // Look up the service ID for this producer port and broadcast to all
        // consumers subscribed to that service.
        if let Some(service_id) = self.port_to_service.get(&port_id).cloned() {
            // Clone handle for broadcasting (the original goes to the producer)
            if let Ok(broadcast_handle) = handle.try_clone() {
                let _notified = self.broadcast_segment_to_consumers(
                    &service_id,
                    segment_id,
                    actual_size,
                    &broadcast_handle,
                );
            }
        }

        Ok((
            IamResponse::AddSegmentOk {
                segment_id,
                size: actual_size,
                handle_count: 1,
            },
            vec![handle],
        ))
    }

    /// Handles Detach request.
    fn handle_detach(
        &mut self,
        session_id: SessionId,
        _service_id: &crate::service::service_hash::ServiceHash,
        port_id: u128,
    ) -> Result<(IamResponse, Vec<PlatformHandle>), IamServerError> {
        // A session may only detach what it owns: one of its attached (IAM) ports or one of the
        // producer ports it registered handles for. Reaping by an arbitrary id would let a
        // principal release another producer's handles.
        let (owns_attached_port, owns_producer_port) = match self.sessions.get(&session_id) {
            Some(entry) => (
                entry.session.has_port(port_id),
                entry.producer_ports.contains(&port_id),
            ),
            None => (false, false),
        };
        if owns_producer_port {
            if let Some(entry) = self.sessions.get_mut(&session_id) {
                entry.producer_ports.retain(|p| *p != port_id);
                if let Some((count, bytes)) = entry.producer_port_usage.remove(&port_id) {
                    let usage = entry.session.resource_usage_mut();
                    usage.segment_count = usage.segment_count.saturating_sub(count);
                    usage.total_memory = usage.total_memory.saturating_sub(bytes);
                }
            }
            self.reap_producer_port(port_id);
        }
        if !owns_attached_port {
            return Ok((IamResponse::DetachOk, Vec::new()));
        }

        // Get port type and credentials before removal for cleanup and audit
        let (port_type, credentials) = self
            .sessions
            .get(&session_id)
            .map(|entry| {
                let pt = entry
                    .session
                    .ports()
                    .find(|p| p.port_id == port_id)
                    .map(|p| p.port_type);
                (pt, entry.session.credentials().clone())
            })
            .unwrap_or((None, ProcessCredentials::new(0, 0, 0)));

        // Remove port from session
        if let Some(entry) = self.sessions.get_mut(&session_id) {
            entry.session.remove_port(port_id);
        }

        // Audit the detach event
        self.audit(
            AuditEventKind::Detach { port_id },
            &credentials,
            &PolicyDecision::Allow,
        );

        // R1: RESOURCE REAPING is unconditional per port. Every one of the four reap operations
        // is a keyed remove/retain that is a harmless no-op when the port holds nothing in that
        // role, so we run all four for EVERY detaching port regardless of its PortType. Branching
        // the reaping by role was unsound: in request-response a CLIENT is ALSO a producer (it
        // registers a request data segment, a resizable management segment, and the request
        // connection channel as SENDER, all keyed by its own client port), and a SERVER is ALSO a
        // consumer (the request channel where it is the receiver). Reaping only one role's
        // resources therefore leaked the port's other-role fds and global SegmentIds — reopening
        // the id-exhaustion DoS (F2) via clients.
        self.segment_manager.remove_all_segments_for_port(port_id);
        self.segment_manager.remove_mgmt_segment_for_port(port_id);
        self.segment_manager
            .remove_channels_for_sender_port(port_id);
        self.segment_manager
            .remove_channels_for_receiver_port(port_id);

        // Phase 8: non-reaping tracking bookkeeping remains PortType-specific.
        if let Some(pt) = port_type {
            match pt {
                PortType::Publisher | PortType::Server => {
                    // Producer port: remove from port_to_service.
                    self.port_to_service.remove(&port_id);
                }
                PortType::Subscriber | PortType::Client => {
                    // Consumer port: remove from service_consumers.
                    for consumers in self.service_consumers.values_mut() {
                        consumers.retain(|(sid, pid)| !(*sid == session_id && *pid == port_id));
                    }
                    // Clean up empty entries
                    self.service_consumers.retain(|_, v| !v.is_empty());
                }
                PortType::Notifier | PortType::Listener => {}
            }
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
    // Segment Handle Registration/Request Handlers
    // ========================================================================

    /// Handles `RegisterSegment` — receives a handle from the client and registers it.
    ///
    /// This handler is called from `process_session_requests` (not from `handle_request`)
    /// because it needs connection access to receive handles from the client.
    fn handle_register_segment(
        &mut self,
        session_id: SessionId,
        service_id: crate::service::service_hash::ServiceHash,
        port_id: u128,
        segment_size: usize,
        handle_count: usize,
    ) -> Result<(IamResponse, Vec<PlatformHandle>), IamServerError> {
        // Verify session exists and handshake is complete
        let entry = self
            .sessions
            .get(&session_id)
            .ok_or(IamServerError::SessionNotFound)?;
        if !entry.handshake_complete {
            return Ok((
                IamResponse::ProtocolError {
                    message: String::from("Handshake not complete"),
                },
                Vec::new(),
            ));
        }

        let credentials = entry.session.credentials().clone();
        let usage = *entry.session.resource_usage();

        if let Some(denied) = self.claim_producer_port(session_id, port_id) {
            // the client sends its handle(s) right after the request; drain them so that they
            // are closed and the stream stays in sync
            if handle_count > 0
                && let Some(entry) = self.sessions.get(&session_id)
            {
                let _ = receive_handles_from_client(&entry.connection);
            }
            return Ok((denied, Vec::new()));
        }

        // Check policy
        let decision = self
            .policy
            .authorize_add_segment(&credentials, &service_id, segment_size);

        self.audit(
            AuditEventKind::AddSegment { size: segment_size },
            &credentials,
            &decision,
        );

        if let PolicyDecision::Deny { reason, message } = decision {
            return Ok((IamResponse::Denied { reason, message }, Vec::new()));
        }

        // Check cumulative segment count
        let limits = self.policy.get_limits(&credentials);
        if usage.segment_count >= limits.max_segments {
            return Ok((
                IamResponse::Denied {
                    reason: DenialReason::ResourceLimitExceeded,
                    message: String::from("Maximum segment count reached"),
                },
                Vec::new(),
            ));
        }

        // Receive handle(s) from the client connection
        if handle_count == 0 {
            return Ok((
                IamResponse::ProtocolError {
                    message: String::from("RegisterSegment requires at least one handle"),
                },
                Vec::new(),
            ));
        }

        let entry = self
            .sessions
            .get(&session_id)
            .ok_or(IamServerError::SessionNotFound)?;
        let handles = receive_handles_from_client(&entry.connection)?;
        if handles.is_empty() {
            return Err(IamServerError::HandlePassingFailed);
        }

        // Take the first handle for registration
        let handle = handles.into_iter().next().unwrap();
        let segment_id = self.segment_manager.register_segment_for_port(
            port_id,
            handle,
            segment_size,
            AccessRights::read_only(),
        )?;

        // Update session resource usage
        if let Some(entry) = self.sessions.get_mut(&session_id) {
            let usage = entry.session.resource_usage_mut();
            usage.segment_count += 1;
            usage.total_memory = usage.total_memory.saturating_add(segment_size);
            let port_usage = entry.producer_port_usage.entry(port_id).or_default();
            port_usage.0 += 1;
            port_usage.1 = port_usage.1.saturating_add(segment_size);
        }

        Ok((IamResponse::RegisterSegmentOk { segment_id }, Vec::new()))
    }

    /// Handles `RequestSegmentHandle` — looks up and returns a segment handle for a consumer.
    fn handle_request_segment_handle(
        &mut self,
        session_id: SessionId,
        sender_port_id: u128,
    ) -> Result<(IamResponse, Vec<PlatformHandle>), IamServerError> {
        if let Some(denied) = self.authorize_consumer(session_id, sender_port_id) {
            return Ok((denied, Vec::new()));
        }
        match self
            .segment_manager
            .get_segment_handle_for_consumer(sender_port_id, session_id)
        {
            Some((info, handle)) => Ok((
                IamResponse::SegmentHandleOk {
                    segment_info: info,
                    handle_count: 1,
                },
                vec![handle],
            )),
            None => Ok((IamResponse::SegmentHandleNotFound, Vec::new())),
        }
    }

    /// Handles `RegisterDynamicSegment` — receives a handle from the client and registers it
    /// at a specific index within the port's dynamic segment set.
    ///
    /// This handler is called from `process_session_requests` (not from `handle_request`)
    /// because it needs connection access to receive handles from the client.
    fn handle_register_dynamic_segment(
        &mut self,
        session_id: SessionId,
        service_id: crate::service::service_hash::ServiceHash,
        port_id: u128,
        segment_index: u8,
        segment_size: usize,
        handle_count: usize,
    ) -> Result<(IamResponse, Vec<PlatformHandle>), IamServerError> {
        // Verify session exists and handshake is complete
        let entry = self
            .sessions
            .get(&session_id)
            .ok_or(IamServerError::SessionNotFound)?;
        if !entry.handshake_complete {
            return Ok((
                IamResponse::ProtocolError {
                    message: String::from("Handshake not complete"),
                },
                Vec::new(),
            ));
        }

        let credentials = entry.session.credentials().clone();
        let usage = *entry.session.resource_usage();

        if let Some(denied) = self.claim_producer_port(session_id, port_id) {
            // the client sends its handle(s) right after the request; drain them so that they
            // are closed and the stream stays in sync
            if handle_count > 0
                && let Some(entry) = self.sessions.get(&session_id)
            {
                let _ = receive_handles_from_client(&entry.connection);
            }
            return Ok((denied, Vec::new()));
        }

        // Check policy
        let decision = self
            .policy
            .authorize_add_segment(&credentials, &service_id, segment_size);

        self.audit(
            AuditEventKind::AddSegment { size: segment_size },
            &credentials,
            &decision,
        );

        if let PolicyDecision::Deny { reason, message } = decision {
            return Ok((IamResponse::Denied { reason, message }, Vec::new()));
        }

        // Check cumulative segment count
        let limits = self.policy.get_limits(&credentials);
        if usage.segment_count >= limits.max_segments {
            return Ok((
                IamResponse::Denied {
                    reason: DenialReason::ResourceLimitExceeded,
                    message: String::from("Maximum segment count reached"),
                },
                Vec::new(),
            ));
        }

        // Receive handle(s) from the client connection
        if handle_count == 0 {
            return Ok((
                IamResponse::ProtocolError {
                    message: String::from("RegisterDynamicSegment requires at least one handle"),
                },
                Vec::new(),
            ));
        }

        let entry = self
            .sessions
            .get(&session_id)
            .ok_or(IamServerError::SessionNotFound)?;
        let handles = receive_handles_from_client(&entry.connection)?;
        if handles.is_empty() {
            return Err(IamServerError::HandlePassingFailed);
        }

        // Take the first handle for registration at the specified index
        let handle = handles.into_iter().next().unwrap();
        let _segment_id = self.segment_manager.register_dynamic_segment_for_port(
            port_id,
            segment_index,
            handle,
            segment_size,
            AccessRights::read_only(),
        )?;

        // Update session resource usage
        if let Some(entry) = self.sessions.get_mut(&session_id) {
            let usage = entry.session.resource_usage_mut();
            usage.segment_count += 1;
            usage.total_memory = usage.total_memory.saturating_add(segment_size);
            let port_usage = entry.producer_port_usage.entry(port_id).or_default();
            port_usage.0 += 1;
            port_usage.1 = port_usage.1.saturating_add(segment_size);
        }

        Ok((
            IamResponse::RegisterDynamicSegmentOk {
                segment_id: segment_index,
            },
            Vec::new(),
        ))
    }

    /// Handles `RequestDynamicSegmentHandle` — looks up and returns a specific dynamic
    /// segment handle for a consumer by index.
    fn handle_request_dynamic_segment_handle(
        &mut self,
        session_id: SessionId,
        sender_port_id: u128,
        segment_index: u8,
    ) -> Result<(IamResponse, Vec<PlatformHandle>), IamServerError> {
        if let Some(denied) = self.authorize_consumer(session_id, sender_port_id) {
            return Ok((denied, Vec::new()));
        }
        match self.segment_manager.get_dynamic_segment_handle(
            sender_port_id,
            segment_index,
            session_id,
        ) {
            Some((info, handle)) => Ok((
                IamResponse::DynamicSegmentHandleOk {
                    segment_info: info,
                    handle_count: 1,
                },
                vec![handle],
            )),
            None => Ok((IamResponse::DynamicSegmentPending, Vec::new())),
        }
    }

    /// Handles `RegisterChannel` — receives a connection-channel handle from the client
    /// and registers it, keyed by the `(sender, receiver)` port pair.
    ///
    /// This handler is called from `process_session_requests` (not from `handle_request`)
    /// because it needs connection access to receive the handle from the client out-of-band.
    ///
    /// **Access rights hazard:** the channel is stored (in
    /// [`SegmentManager::register_channel`]) with **read+write** access, unlike data
    /// segments (which are read-only), because the consumer's receiver end writes the
    /// zero-copy connection's completion ring.
    fn handle_register_channel(
        &mut self,
        session_id: SessionId,
        service_id: crate::service::service_hash::ServiceHash,
        sender_port_id: u128,
        receiver_port_id: u128,
        channel_size: usize,
        handle_count: usize,
    ) -> Result<(IamResponse, Vec<PlatformHandle>), IamServerError> {
        // Verify session exists and handshake is complete
        let entry = self
            .sessions
            .get(&session_id)
            .ok_or(IamServerError::SessionNotFound)?;
        if !entry.handshake_complete {
            return Ok((
                IamResponse::ProtocolError {
                    message: String::from("Handshake not complete"),
                },
                Vec::new(),
            ));
        }

        let credentials = entry.session.credentials().clone();
        let usage = *entry.session.resource_usage();

        if let Some(denied) = self.claim_producer_port(session_id, sender_port_id) {
            // the client sends its handle(s) right after the request; drain them so that they
            // are closed and the stream stays in sync
            if handle_count > 0
                && let Some(entry) = self.sessions.get(&session_id)
            {
                let _ = receive_handles_from_client(&entry.connection);
            }
            return Ok((denied, Vec::new()));
        }

        // Check policy — reuse the add-segment authorization since a connection channel
        // is a brokered shared-memory resource owned by the producer.
        let decision =
            self.policy
                .authorize_add_segment(&credentials, &service_id, channel_size.max(1));

        self.audit(
            AuditEventKind::AddSegment { size: channel_size },
            &credentials,
            &decision,
        );

        if let PolicyDecision::Deny { reason, message } = decision {
            return Ok((IamResponse::Denied { reason, message }, Vec::new()));
        }

        // Check cumulative segment count
        let limits = self.policy.get_limits(&credentials);
        if usage.segment_count >= limits.max_segments {
            return Ok((
                IamResponse::Denied {
                    reason: DenialReason::ResourceLimitExceeded,
                    message: String::from("Maximum segment count reached"),
                },
                Vec::new(),
            ));
        }

        // Receive handle(s) from the client connection
        if handle_count == 0 {
            return Ok((
                IamResponse::ProtocolError {
                    message: String::from("RegisterChannel requires at least one handle"),
                },
                Vec::new(),
            ));
        }

        let entry = self
            .sessions
            .get(&session_id)
            .ok_or(IamServerError::SessionNotFound)?;
        let handles = receive_handles_from_client(&entry.connection)?;
        if handles.is_empty() {
            return Err(IamServerError::HandlePassingFailed);
        }

        // Take the first handle for registration. register_channel stores it with
        // AccessRights::read_write() (see the access-rights hazard above).
        let handle = handles.into_iter().next().unwrap();
        self.segment_manager.register_channel(
            sender_port_id,
            receiver_port_id,
            handle,
            channel_size,
        )?;

        // Update session resource usage
        if let Some(entry) = self.sessions.get_mut(&session_id) {
            let usage = entry.session.resource_usage_mut();
            usage.segment_count += 1;
            usage.total_memory = usage.total_memory.saturating_add(channel_size);
            let port_usage = entry.producer_port_usage.entry(sender_port_id).or_default();
            port_usage.0 += 1;
            port_usage.1 = port_usage.1.saturating_add(channel_size);
        }

        Ok((IamResponse::RegisterChannelOk, Vec::new()))
    }

    /// Handles `RequestChannelHandle` — looks up and returns the connection-channel handle
    /// for a `(sender, receiver)` pair. The returned handle carries read+write access.
    fn handle_request_channel_handle(
        &mut self,
        session_id: SessionId,
        sender_port_id: u128,
        receiver_port_id: u128,
    ) -> Result<(IamResponse, Vec<PlatformHandle>), IamServerError> {
        if let Some(denied) = self.authorize_consumer(session_id, sender_port_id) {
            return Ok((denied, Vec::new()));
        }
        match self.segment_manager.get_channel_handle_for_consumer(
            sender_port_id,
            receiver_port_id,
            session_id,
        ) {
            Some((info, handle)) => Ok((
                IamResponse::ChannelHandleOk {
                    segment_info: info,
                    handle_count: 1,
                },
                vec![handle],
            )),
            None => Ok((IamResponse::ChannelHandleNotFound, Vec::new())),
        }
    }

    /// Handles `RegisterMgmtSegment` — receives a resizable-memory management-segment handle
    /// from the client and registers it, keyed by the producer `port_id`.
    ///
    /// This handler is called from `process_session_requests` (not from `handle_request`)
    /// because it needs connection access to receive the handle from the client out-of-band.
    ///
    /// **Access rights:** the management segment is stored (in
    /// [`SegmentManager::register_mgmt_segment`]) with **read-only** access. The consumer's
    /// `DynamicView` maps it purely as a keep-alive token and never reads or writes it, and
    /// `SharedMemory::open_from_handle` requires only read access — so read-only (matching
    /// data segments, unlike the read+write connection channels) is sufficient.
    fn handle_register_mgmt_segment(
        &mut self,
        session_id: SessionId,
        service_id: crate::service::service_hash::ServiceHash,
        port_id: u128,
        mgmt_size: usize,
        handle_count: usize,
    ) -> Result<(IamResponse, Vec<PlatformHandle>), IamServerError> {
        // Verify session exists and handshake is complete
        let entry = self
            .sessions
            .get(&session_id)
            .ok_or(IamServerError::SessionNotFound)?;
        if !entry.handshake_complete {
            return Ok((
                IamResponse::ProtocolError {
                    message: String::from("Handshake not complete"),
                },
                Vec::new(),
            ));
        }

        let credentials = entry.session.credentials().clone();
        let usage = *entry.session.resource_usage();

        if let Some(denied) = self.claim_producer_port(session_id, port_id) {
            // the client sends its handle(s) right after the request; drain them so that they
            // are closed and the stream stays in sync
            if handle_count > 0
                && let Some(entry) = self.sessions.get(&session_id)
            {
                let _ = receive_handles_from_client(&entry.connection);
            }
            return Ok((denied, Vec::new()));
        }

        // Check policy — reuse the add-segment authorization since the management segment
        // is a brokered shared-memory resource owned by the producer.
        let decision =
            self.policy
                .authorize_add_segment(&credentials, &service_id, mgmt_size.max(1));

        self.audit(
            AuditEventKind::AddSegment { size: mgmt_size },
            &credentials,
            &decision,
        );

        if let PolicyDecision::Deny { reason, message } = decision {
            return Ok((IamResponse::Denied { reason, message }, Vec::new()));
        }

        // Check cumulative segment count
        let limits = self.policy.get_limits(&credentials);
        if usage.segment_count >= limits.max_segments {
            return Ok((
                IamResponse::Denied {
                    reason: DenialReason::ResourceLimitExceeded,
                    message: String::from("Maximum segment count reached"),
                },
                Vec::new(),
            ));
        }

        // Receive handle(s) from the client connection
        if handle_count == 0 {
            return Ok((
                IamResponse::ProtocolError {
                    message: String::from("RegisterMgmtSegment requires at least one handle"),
                },
                Vec::new(),
            ));
        }

        let entry = self
            .sessions
            .get(&session_id)
            .ok_or(IamServerError::SessionNotFound)?;
        let handles = receive_handles_from_client(&entry.connection)?;
        if handles.is_empty() {
            return Err(IamServerError::HandlePassingFailed);
        }

        // Take the first handle for registration. register_mgmt_segment stores it with
        // AccessRights::read_only() (see the access-rights note above).
        let handle = handles.into_iter().next().unwrap();
        self.segment_manager
            .register_mgmt_segment(port_id, handle, mgmt_size)?;

        // Update session resource usage
        if let Some(entry) = self.sessions.get_mut(&session_id) {
            let usage = entry.session.resource_usage_mut();
            usage.segment_count += 1;
            usage.total_memory = usage.total_memory.saturating_add(mgmt_size);
            let port_usage = entry.producer_port_usage.entry(port_id).or_default();
            port_usage.0 += 1;
            port_usage.1 = port_usage.1.saturating_add(mgmt_size);
        }

        Ok((IamResponse::RegisterMgmtSegmentOk, Vec::new()))
    }

    /// Handles `RequestMgmtSegmentHandle` — looks up and returns the management-segment handle
    /// for a producer `port_id`. The returned handle carries read-only access.
    fn handle_request_mgmt_segment_handle(
        &mut self,
        session_id: SessionId,
        port_id: u128,
    ) -> Result<(IamResponse, Vec<PlatformHandle>), IamServerError> {
        if let Some(denied) = self.authorize_consumer(session_id, port_id) {
            return Ok((denied, Vec::new()));
        }
        match self
            .segment_manager
            .get_mgmt_segment_handle_for_consumer(port_id, session_id)
        {
            Some((info, handle)) => Ok((
                IamResponse::MgmtSegmentHandleOk {
                    segment_info: info,
                    handle_count: 1,
                },
                vec![handle],
            )),
            None => Ok((IamResponse::MgmtSegmentHandleNotFound, Vec::new())),
        }
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
            PortType::Subscriber => (
                usage.subscriber_count,
                limits.max_subscribers,
                "subscribers",
            ),
            PortType::Server => (usage.server_count, limits.max_servers, "servers"),
            PortType::Client => (usage.client_count, limits.max_clients, "clients"),
            PortType::Notifier => (usage.notifier_count, limits.max_notifiers, "notifiers"),
            PortType::Listener => (usage.listener_count, limits.max_listeners, "listeners"),
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
        // Phase 8: Clean up tracking mappings before removing the session
        if let Some(entry) = self.sessions.get(&session_id) {
            // Collect ports and their types for cleanup
            let ports: Vec<_> = entry
                .session
                .ports()
                .map(|p| (p.port_id, p.port_type))
                .collect();

            for (port_id, port_type) in ports {
                // R1: reap ALL resource classes for EVERY port unconditionally (see
                // handle_detach). Each reap is a keyed no-op in the wrong role; branching by
                // PortType leaked the request-response client's producer resources (data segment +
                // management segment + request channel as sender) and, symmetrically, the server's
                // consumer request channel.
                self.segment_manager.remove_all_segments_for_port(port_id);
                self.segment_manager.remove_mgmt_segment_for_port(port_id);
                self.segment_manager
                    .remove_channels_for_sender_port(port_id);
                self.segment_manager
                    .remove_channels_for_receiver_port(port_id);

                // Non-reaping tracking bookkeeping remains PortType-specific.
                match port_type {
                    PortType::Publisher | PortType::Server => {
                        // Producer port: remove from port_to_service.
                        self.port_to_service.remove(&port_id);
                    }
                    PortType::Subscriber | PortType::Client => {
                        // Consumer port: service_consumers is cleaned up below.
                    }
                    PortType::Notifier | PortType::Listener => {}
                }
            }
        }

        // The handles registered under the session's (iceoryx2) producer ports are released
        // once the peer's departure was handled (see `process_departures`), so that consumers
        // can still map what the producer sent right before it went away. Without a known node
        // (no handshake) or departure handler they are released right away.
        let (node_id, credentials, producer_ports) = match self.sessions.get(&session_id) {
            Some(entry) => (
                entry.node_id,
                entry.session.credentials().clone(),
                entry.producer_ports.clone(),
            ),
            None => (None, ProcessCredentials::new(0, 0, 0), Vec::new()),
        };
        match node_id {
            Some(node_id) if self.departure_handler.is_some() => {
                // Another session of the same node (the node opened the service twice) keeps
                // the node registered; only the last session triggers the departure handling.
                let node_has_other_sessions = self
                    .sessions
                    .iter()
                    .any(|(sid, e)| *sid != session_id && e.node_id == Some(node_id));
                match self
                    .pending_departures
                    .iter_mut()
                    .find(|d| d.node_id == node_id)
                {
                    Some(departure) => departure.orphaned_ports.extend(producer_ports),
                    None if node_has_other_sessions => {
                        for port_id in producer_ports {
                            self.reap_producer_port(port_id);
                        }
                    }
                    None => self.pending_departures.push(PendingDeparture {
                        node_id,
                        credentials,
                        since: std::time::Instant::now(),
                        orphaned_ports: producer_ports,
                    }),
                }
            }
            _ => {
                for port_id in producer_ports {
                    self.reap_producer_port(port_id);
                }
            }
        }

        // Remove this session from all service_consumers entries
        for consumers in self.service_consumers.values_mut() {
            consumers.retain(|(sid, _)| *sid != session_id);
        }
        // Clean up empty entries
        self.service_consumers.retain(|_, v| !v.is_empty());

        // Revoke session from all segments
        self.segment_manager.revoke_session(session_id);

        // Remove session entry
        self.sessions.remove(&session_id);
    }

    /// Broadcasts a segment update notification to all consumers of a service.
    ///
    /// This is used by Phase 8 to proactively push segment handles to consumers
    /// when a producer adds a new dynamic segment, avoiding the need for
    /// pull-based discovery.
    ///
    /// # Arguments
    ///
    /// * `service_id` - The service whose consumers should be notified
    /// * `segment_id` - The segment identifier for the new segment
    /// * `segment_size` - The size of the segment in bytes
    /// * `handle` - The platform handle to clone for each consumer
    ///
    /// # Returns
    ///
    /// The number of consumers successfully notified.
    fn broadcast_segment_to_consumers(
        &mut self,
        service_id: &ServiceHash,
        segment_id: SegmentId,
        segment_size: usize,
        handle: &PlatformHandle,
    ) -> usize {
        // Get list of consumer sessions for this service
        let consumers = match self.service_consumers.get(service_id) {
            Some(c) => c.clone(),
            None => return 0,
        };

        let mut notified_count = 0;

        for (consumer_session_id, _port_id) in consumers {
            // Clone the handle for this consumer
            let cloned_handle = match handle.try_clone() {
                Ok(h) => h,
                Err(_) => continue, // Skip consumer if handle clone fails
            };

            // Authorize the session in segment_manager
            // (This allows the consumer to access the segment data)
            if self
                .segment_manager
                .authorize_session(segment_id, consumer_session_id)
                .is_err()
            {
                continue; // Skip if authorization fails
            }

            // Send SegmentUpdate notification
            let notification = IamNotification::SegmentUpdate {
                segment_id,
                size: segment_size,
                handle_count: 1,
            };

            if let Some(entry) = self.sessions.get(&consumer_session_id) {
                // Send the notification message
                if send_message(&entry.connection, &notification).is_ok() {
                    // Send the handle
                    if send_handles(&entry.connection, &[cloned_handle]).is_ok() {
                        notified_count += 1;
                    }
                }
            }
        }

        notified_count
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

    /// Sends a response to a session using wire helper.
    fn send_response_to_session(
        &self,
        session_id: SessionId,
        response: &IamResponse,
    ) -> Result<(), IamServerError> {
        let entry = self
            .sessions
            .get(&session_id)
            .ok_or(IamServerError::SessionNotFound)?;

        send_message(&entry.connection, response)
    }

    /// Sends handles to a session using wire helper.
    fn send_handles_to_session(
        &self,
        session_id: SessionId,
        handles: &[PlatformHandle],
    ) -> Result<(), IamServerError> {
        let entry = self
            .sessions
            .get(&session_id)
            .ok_or(IamServerError::SessionNotFound)?;

        send_handles(&entry.connection, handles)
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
    pub fn begin_segment_retirement(&mut self, segment_id: SegmentId) -> Option<Vec<SessionId>> {
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
                // Ignore individual send failures, use wire helper
                let _ = send_message(&entry.connection, notification);
            }
        }

        Ok(())
    }
}

// ============================================================================
// Type Erasure for IamServer
// ============================================================================

use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, JoinHandle};
use std::time::Duration;

/// Type-erased trait for IAM server operations.
///
/// This trait hides the generic parameters (`L: CalListener`, `P: IamPolicy`)
/// to allow storing the server in non-generic service state.
/// Must be `Send + Sync` since it's stored in `Arc<ServiceState>`.
pub(crate) trait ErasedIamServer: Send + Sync {
    /// Processes pending connections and requests.
    ///
    /// Returns the number of requests processed.
    fn process(&self) -> Result<usize, IamServerError>;

    /// Shuts down the server, clearing all sessions.
    ///
    /// After shutdown, `process()` will return 0 immediately.
    fn shutdown(&self);

    /// Returns true if the server has active sessions.
    fn has_active_sessions(&self) -> bool;
}

/// Inner wrapper that provides interior mutability for IamServer.
struct IamServerInner<L: CalListener, P: IamPolicy> {
    server: Mutex<Option<IamServer<L, P>>>,
}

impl<L, P> ErasedIamServer for IamServerInner<L, P>
where
    L: CalListener + Send + 'static,
    L::Connection: Send,
    P: IamPolicy + Send + 'static,
{
    fn process(&self) -> Result<usize, IamServerError> {
        let mut guard = self
            .server
            .lock()
            .map_err(|_| IamServerError::InternalError)?;
        match guard.as_mut() {
            Some(server) => server.process(),
            None => Ok(0), // Already shut down
        }
    }

    fn shutdown(&self) {
        if let Ok(mut guard) = self.server.lock() {
            // Take the server to drop it, clearing all sessions
            let _ = guard.take();
        }
    }

    fn has_active_sessions(&self) -> bool {
        self.server
            .lock()
            .ok()
            .and_then(|guard| guard.as_ref().map(|s| s.session_count() > 0))
            .unwrap_or(false)
    }
}

/// Type-erased IAM server container with background processing.
///
/// This wrapper hides the generic parameters of [`IamServer`] to allow storing
/// it in non-generic service state structures. It automatically spawns a
/// background thread to process IAM requests, allowing client connections
/// to be handled asynchronously.
///
/// # Thread Safety
///
/// `TypeErasedIamServer` is `Send` and the underlying server operations are
/// protected by a Mutex. The background thread continuously processes
/// connections and requests.
///
/// # Lifecycle
///
/// When dropped, the server signals the background thread to stop and waits
/// for it to complete before returning.
pub(crate) struct TypeErasedIamServer {
    inner: Arc<dyn ErasedIamServer>,
    shutdown_flag: Arc<AtomicBool>,
    processing_thread: Option<JoinHandle<()>>,
}

/// How often to poll for new connections/requests (in milliseconds).
const PROCESSING_INTERVAL_MS: u64 = 10;

impl TypeErasedIamServer {
    /// Creates a new type-erased IAM server with background processing.
    ///
    /// Spawns a background thread that continuously processes connections
    /// and requests from IAM clients.
    pub fn new<L, P>(server: IamServer<L, P>) -> Self
    where
        L: CalListener + Send + 'static,
        L::Connection: Send,
        P: IamPolicy + Send + 'static,
    {
        let inner: Arc<dyn ErasedIamServer> = Arc::new(IamServerInner {
            server: Mutex::new(Some(server)),
        });
        let shutdown_flag = Arc::new(AtomicBool::new(false));

        // Clone for the processing thread
        let inner_clone = Arc::clone(&inner);
        let shutdown_clone = Arc::clone(&shutdown_flag);

        // Spawn background processing thread
        let processing_thread = thread::spawn(move || {
            while !shutdown_clone.load(Ordering::Relaxed) {
                // Process pending connections and requests
                if let Err(_e) = inner_clone.process() {
                    // Log error but continue processing
                    // In production, we might want to limit error rates
                }
                // Sleep briefly to avoid busy-waiting
                thread::sleep(Duration::from_millis(PROCESSING_INTERVAL_MS));
            }
        });

        Self {
            inner,
            shutdown_flag,
            processing_thread: Some(processing_thread),
        }
    }

    /// Shuts down the server, clearing all sessions.
    ///
    /// This stops the background processing thread and clears all sessions.
    /// Called automatically when the service is dropped.
    pub fn shutdown(&self) {
        self.shutdown_flag.store(true, Ordering::Relaxed);
        self.inner.shutdown()
    }

    /// Returns true if the server has active sessions.
    pub fn has_active_sessions(&self) -> bool {
        self.inner.has_active_sessions()
    }
}

impl Drop for TypeErasedIamServer {
    fn drop(&mut self) {
        // Signal the processing thread to stop
        self.shutdown_flag.store(true, Ordering::Relaxed);

        // Wait for the processing thread to finish
        if let Some(thread) = self.processing_thread.take() {
            let _ = thread.join();
        }
    }
}

impl std::fmt::Debug for TypeErasedIamServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TypeErasedIamServer")
            .field("has_active_sessions", &self.has_active_sessions())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::iam::DefaultPolicy;
    use core::time::Duration;
    use iceoryx2_bb_system_types::file_name::FileName;
    use iceoryx2_cal::control_channel::{
        ControlChannelAcceptError, ControlChannelCredentialsError, ControlChannelReceiveError,
        ControlChannelSendError,
    };
    use iceoryx2_cal::named_concept::NamedConcept;
    use iceoryx2_cal::serialize::{Serialize as CalSerialize, postcard::Postcard};
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};

    // ========================================================================
    // Mock Types for Testing
    // ========================================================================

    /// Mock connection for testing that implements CAL's ControlChannelConnection trait.
    ///
    /// This mock stores raw bytes rather than typed messages, matching the actual
    /// CAL interface. Requests/responses are serialized with length framing.
    struct MockConnection {
        credentials: ProcessCredentials,
        /// Raw bytes sent by the server (responses serialized with length prefix).
        sent_data: Arc<Mutex<Vec<Vec<u8>>>>,
        /// Raw bytes to return on receive (requests serialized with length prefix).
        receive_queue: Arc<Mutex<VecDeque<Vec<u8>>>>,
        /// Current position within the first receive_queue entry (for partial reads).
        receive_offset: Arc<Mutex<usize>>,
    }

    impl MockConnection {
        fn new(credentials: ProcessCredentials) -> Self {
            Self {
                credentials,
                sent_data: Arc::new(Mutex::new(Vec::new())),
                receive_queue: Arc::new(Mutex::new(VecDeque::new())),
                receive_offset: Arc::new(Mutex::new(0)),
            }
        }

        /// Queues a request to be received by the server (simulating client sending).
        #[allow(dead_code)]
        fn set_receive_request(&self, request: IamRequest) {
            let payload = Postcard::serialize(&request).unwrap();
            let len = payload.len() as u32;
            let mut framed = Vec::with_capacity(4 + payload.len());
            framed.extend_from_slice(&len.to_le_bytes());
            framed.extend_from_slice(&payload);
            self.receive_queue.lock().unwrap().push_back(framed);
        }

        /// Returns the responses that have been sent, deserializing from raw bytes.
        #[allow(dead_code)]
        fn get_sent_responses(&self) -> Vec<IamResponse> {
            self.sent_data
                .lock()
                .unwrap()
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

    impl CalConnection for MockConnection {
        fn peer_credentials(&self) -> Result<ProcessCredentials, ControlChannelCredentialsError> {
            Ok(self.credentials.clone())
        }

        fn send_handles(&self, handles: &[&PlatformHandle]) -> Result<(), ControlChannelSendError> {
            // We can't clone handles, but for testing we track how many were "sent"
            let _ = handles;
            Ok(())
        }

        fn try_send_handles(
            &self,
            handles: &[&PlatformHandle],
        ) -> Result<bool, ControlChannelSendError> {
            self.send_handles(handles)?;
            Ok(true)
        }

        fn receive_handles(
            &self,
        ) -> Result<Option<Vec<PlatformHandle>>, ControlChannelReceiveError> {
            Ok(None)
        }

        fn try_receive_handles(
            &self,
        ) -> Result<Option<Vec<PlatformHandle>>, ControlChannelReceiveError> {
            Ok(None)
        }

        fn timed_receive_handles(
            &self,
            _timeout: Duration,
        ) -> Result<Option<Vec<PlatformHandle>>, ControlChannelReceiveError> {
            Ok(None)
        }

        fn blocking_receive_handles(
            &self,
        ) -> Result<Vec<PlatformHandle>, ControlChannelReceiveError> {
            Ok(Vec::new())
        }

        fn send(&self, data: &[u8]) -> Result<(), ControlChannelSendError> {
            self.sent_data.lock().unwrap().push(data.to_vec());
            Ok(())
        }

        fn try_send(&self, data: &[u8]) -> Result<u64, ControlChannelSendError> {
            self.send(data)?;
            Ok(data.len() as u64)
        }

        fn receive(&self, buffer: &mut [u8]) -> Result<u64, ControlChannelReceiveError> {
            let mut queue = self.receive_queue.lock().unwrap();
            let mut offset = self.receive_offset.lock().unwrap();

            if queue.is_empty() {
                return Err(ControlChannelReceiveError::WouldBlock);
            }

            let front = queue.front().unwrap();
            let remaining = &front[*offset..];
            let to_copy = core::cmp::min(remaining.len(), buffer.len());
            buffer[..to_copy].copy_from_slice(&remaining[..to_copy]);

            if *offset + to_copy >= front.len() {
                // Finished this message, move to next
                queue.pop_front();
                *offset = 0;
            } else {
                *offset += to_copy;
            }

            Ok(to_copy as u64)
        }

        fn try_receive(&self, buffer: &mut [u8]) -> Result<u64, ControlChannelReceiveError> {
            if self.receive_queue.lock().unwrap().is_empty() {
                return Ok(0);
            }
            self.receive(buffer)
        }
    }

    /// Mock listener for testing that implements CAL's ControlChannelListener trait.
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

    impl core::fmt::Debug for MockListener {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            f.debug_struct("MockListener").finish()
        }
    }

    impl NamedConcept for MockListener {
        fn name(&self) -> &FileName {
            static NAME: FileName = unsafe { FileName::new_unchecked_const(b"mock_listener") };
            &NAME
        }
    }

    impl CalListener for MockListener {
        type Connection = MockConnection;

        fn try_accept(&self) -> Result<Option<Self::Connection>, ControlChannelAcceptError> {
            Ok(self.pending_connections.lock().unwrap().pop())
        }

        fn timed_accept(
            &self,
            _timeout: Duration,
        ) -> Result<Option<Self::Connection>, ControlChannelAcceptError> {
            self.try_accept()
        }

        fn blocking_accept(&self) -> Result<Self::Connection, ControlChannelAcceptError> {
            self.try_accept()?
                .ok_or(ControlChannelAcceptError::WouldBlock)
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
        let sent_data = conn.sent_data.clone();
        server.listener.add_connection(conn);

        // Process - should reject and not add session
        server.process().unwrap();

        // Connection was rejected - check that a denial was sent
        let raw_responses = sent_data.lock().unwrap();
        if !raw_responses.is_empty() {
            // Deserialize the response from raw bytes (skip 4-byte length prefix)
            if raw_responses[0].len() > 4 {
                if let Ok(response) = Postcard::deserialize::<IamResponse>(&raw_responses[0][4..]) {
                    assert!(matches!(response, IamResponse::Denied { .. }));
                }
            }
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
        assert!(
            server
                .check_port_limit(&usage, PortType::Publisher, &limits)
                .is_some()
        );

        // Subscriber
        let mut usage = SessionResourceUsage::new();
        usage.subscriber_count = limits.max_subscribers;
        assert!(
            server
                .check_port_limit(&usage, PortType::Subscriber, &limits)
                .is_some()
        );

        // Server
        let mut usage = SessionResourceUsage::new();
        usage.server_count = limits.max_servers;
        assert!(
            server
                .check_port_limit(&usage, PortType::Server, &limits)
                .is_some()
        );

        // Client
        let mut usage = SessionResourceUsage::new();
        usage.client_count = limits.max_clients;
        assert!(
            server
                .check_port_limit(&usage, PortType::Client, &limits)
                .is_some()
        );
    }

    // ========================================================================
    // Segment Size Calculation Tests
    // ========================================================================

    #[test]
    fn test_calculate_publisher_segment_size() {
        let size =
            IamServer::<MockListener, DefaultPolicy>::calculate_publisher_segment_size(8, 1024);
        // (8 + 1) * 1024 + 4096 = 13312
        assert_eq!(size, 13312);
    }

    #[test]
    fn test_calculate_publisher_segment_size_zero_history() {
        let size =
            IamServer::<MockListener, DefaultPolicy>::calculate_publisher_segment_size(0, 1024);
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
        let raw_fd = unsafe { iceoryx2_pal_posix::posix::dup(std::io::stdout().as_raw_fd()) };
        unsafe { PlatformHandle::from_raw_fd(raw_fd) }
    }

    #[cfg(windows)]
    fn create_test_handle() -> PlatformHandle {
        use std::os::windows::io::AsRawHandle;
        let raw_handle = std::io::stdout().as_raw_handle();
        let mut dup_handle: isize = 0;
        unsafe {
            let current_process = windows_sys::Win32::System::Threading::GetCurrentProcess();
            windows_sys::Win32::Foundation::DuplicateHandle(
                current_process,
                raw_handle as isize,
                current_process,
                &mut dup_handle,
                0,
                0,
                windows_sys::Win32::Foundation::DUPLICATE_SAME_ACCESS,
            );
            PlatformHandle::from_raw_handle(dup_handle as *mut _)
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

    // ========================================================================
    // Phase 8: Push-Based Segment Notification Tests
    // ========================================================================

    #[test]
    fn test_port_to_service_mapping_initialized_empty() {
        let server = create_test_server();
        assert!(server.port_to_service.is_empty());
    }

    #[test]
    fn test_service_consumers_mapping_initialized_empty() {
        let server = create_test_server();
        assert!(server.service_consumers.is_empty());
    }

    #[test]
    fn test_producer_port_tracking_on_attach_publisher() {
        use crate::service::messaging_pattern::MessagingPattern;
        use iceoryx2_cal::hash::sha1::Sha1;

        let listener = MockListener::new();
        let policy = DefaultPolicy::with_owner(1000);
        let mut server = IamServer::new(listener, policy);

        // Create a session
        let conn = MockConnection::new(test_credentials());
        server.listener.add_connection(conn);
        server.process().unwrap();

        // Get the session ID
        let session_id = *server.sessions.keys().next().unwrap();

        // Mark handshake complete
        if let Some(entry) = server.sessions.get_mut(&session_id) {
            entry.handshake_complete = true;
        }

        // Create a service ID for testing
        let service_name =
            crate::service::service_name::ServiceName::new("test/pub_tracking").unwrap();
        let service_id = crate::service::service_hash::ServiceHash::new::<Sha1>(
            &service_name,
            MessagingPattern::PublishSubscribe,
        );

        let usage = SessionResourceUsage::new();
        let _ = server.handle_attach_publisher(
            session_id,
            &test_credentials(),
            &usage,
            &service_id,
            8,
            1024,
        );

        // Verify port_to_service mapping was populated
        assert!(!server.port_to_service.is_empty());
        let port_id = server.port_counter; // Last allocated port
        assert_eq!(server.port_to_service.get(&port_id), Some(&service_id));
    }

    #[test]
    fn test_consumer_tracking_on_attach_subscriber() {
        use crate::service::messaging_pattern::MessagingPattern;
        use iceoryx2_cal::hash::sha1::Sha1;

        let listener = MockListener::new();
        let policy = DefaultPolicy::with_owner(1000);
        let mut server = IamServer::new(listener, policy);

        // Create a session
        let conn = MockConnection::new(test_credentials());
        server.listener.add_connection(conn);
        server.process().unwrap();

        // Get the session ID
        let session_id = *server.sessions.keys().next().unwrap();

        // Mark handshake complete
        if let Some(entry) = server.sessions.get_mut(&session_id) {
            entry.handshake_complete = true;
        }

        // Create a service ID for testing
        let service_name =
            crate::service::service_name::ServiceName::new("test/sub_tracking").unwrap();
        let service_id = crate::service::service_hash::ServiceHash::new::<Sha1>(
            &service_name,
            MessagingPattern::PublishSubscribe,
        );

        let usage = SessionResourceUsage::new();
        let _ =
            server.handle_attach_subscriber(session_id, &test_credentials(), &usage, &service_id);

        // Verify service_consumers mapping was populated
        assert!(!server.service_consumers.is_empty());
        let consumers = server.service_consumers.get(&service_id).unwrap();
        assert_eq!(consumers.len(), 1);
        let port_id = server.port_counter;
        assert_eq!(consumers[0], (session_id, port_id));
    }

    #[test]
    fn test_detach_cleans_up_producer_mapping() {
        use crate::service::messaging_pattern::MessagingPattern;
        use iceoryx2_cal::hash::sha1::Sha1;

        let listener = MockListener::new();
        let policy = DefaultPolicy::with_owner(1000);
        let mut server = IamServer::new(listener, policy);

        // Create a session
        let conn = MockConnection::new(test_credentials());
        server.listener.add_connection(conn);
        server.process().unwrap();

        let session_id = *server.sessions.keys().next().unwrap();
        if let Some(entry) = server.sessions.get_mut(&session_id) {
            entry.handshake_complete = true;
        }

        let service_name =
            crate::service::service_name::ServiceName::new("test/detach_producer").unwrap();
        let service_id = crate::service::service_hash::ServiceHash::new::<Sha1>(
            &service_name,
            MessagingPattern::PublishSubscribe,
        );

        let usage = SessionResourceUsage::new();
        let (response, _) = server
            .handle_attach_publisher(
                session_id,
                &test_credentials(),
                &usage,
                &service_id,
                8,
                1024,
            )
            .unwrap();

        // Extract port_id from response
        let port_id = match response {
            IamResponse::AttachOk { port_id, .. } => port_id,
            _ => panic!("Expected AttachOk"),
        };

        // Verify mapping exists
        assert!(server.port_to_service.contains_key(&port_id));

        // Detach
        let _ = server.handle_detach(session_id, &service_id, port_id);

        // Verify mapping was removed
        assert!(!server.port_to_service.contains_key(&port_id));
    }

    // F2: a producer port's data segments must be reaped on Detach so their dup'd fds do not leak
    // and the SegmentId space is not exhausted over repeated producer create/drop cycles.
    #[test]
    fn test_detach_reaps_producer_data_segments() {
        use crate::service::messaging_pattern::MessagingPattern;
        use iceoryx2_cal::hash::sha1::Sha1;

        let listener = MockListener::new();
        let policy = DefaultPolicy::with_owner(1000);
        let mut server = IamServer::new(listener, policy);

        let conn = MockConnection::new(test_credentials());
        server.listener.add_connection(conn);
        server.process().unwrap();

        let session_id = *server.sessions.keys().next().unwrap();
        if let Some(entry) = server.sessions.get_mut(&session_id) {
            entry.handshake_complete = true;
        }

        let service_name =
            crate::service::service_name::ServiceName::new("test/detach_reap_seg").unwrap();
        let service_id = crate::service::service_hash::ServiceHash::new::<Sha1>(
            &service_name,
            MessagingPattern::PublishSubscribe,
        );

        let usage = SessionResourceUsage::new();
        let (response, _) = server
            .handle_attach_publisher(
                session_id,
                &test_credentials(),
                &usage,
                &service_id,
                8,
                1024,
            )
            .unwrap();
        let port_id = match response {
            IamResponse::AttachOk { port_id, .. } => port_id,
            _ => panic!("Expected AttachOk"),
        };

        // Register two data segments for the producer port (as add_segment would).
        let seg0 = server
            .segment_manager
            .register_segment_for_port(
                port_id,
                create_test_handle(),
                4096,
                AccessRights::read_write(),
            )
            .unwrap();
        let seg1 = server
            .segment_manager
            .register_segment_for_port(
                port_id,
                create_test_handle(),
                8192,
                AccessRights::read_write(),
            )
            .unwrap();
        assert_eq!(server.segment_count(), 2);
        assert!(server.segment_manager.has_segment(seg0));
        assert!(server.segment_manager.has_segment(seg1));

        // Detach must reap the producer's data segments.
        let _ = server.handle_detach(session_id, &service_id, port_id);

        assert_eq!(server.segment_count(), 0);
        assert!(!server.segment_manager.has_segment(seg0));
        assert!(!server.segment_manager.has_segment(seg1));
        assert!(
            server
                .segment_manager
                .get_segments_for_port(port_id)
                .is_empty()
        );
    }

    // F2: the same reaping must also happen when the whole session is torn down.
    #[test]
    fn test_session_removal_reaps_producer_data_segments() {
        use crate::service::messaging_pattern::MessagingPattern;
        use iceoryx2_cal::hash::sha1::Sha1;

        let listener = MockListener::new();
        let policy = DefaultPolicy::with_owner(1000);
        let mut server = IamServer::new(listener, policy);

        let conn = MockConnection::new(test_credentials());
        server.listener.add_connection(conn);
        server.process().unwrap();

        let session_id = *server.sessions.keys().next().unwrap();
        if let Some(entry) = server.sessions.get_mut(&session_id) {
            entry.handshake_complete = true;
        }

        let service_name =
            crate::service::service_name::ServiceName::new("test/session_reap_seg").unwrap();
        let service_id = crate::service::service_hash::ServiceHash::new::<Sha1>(
            &service_name,
            MessagingPattern::PublishSubscribe,
        );

        let usage = SessionResourceUsage::new();
        let (response, _) = server
            .handle_attach_publisher(
                session_id,
                &test_credentials(),
                &usage,
                &service_id,
                8,
                1024,
            )
            .unwrap();
        let port_id = match response {
            IamResponse::AttachOk { port_id, .. } => port_id,
            _ => panic!("Expected AttachOk"),
        };

        let seg = server
            .segment_manager
            .register_segment_for_port(
                port_id,
                create_test_handle(),
                4096,
                AccessRights::read_write(),
            )
            .unwrap();
        assert_eq!(server.segment_count(), 1);
        assert!(server.segment_manager.has_segment(seg));

        server.remove_session(session_id);

        assert_eq!(server.segment_count(), 0);
        assert!(!server.segment_manager.has_segment(seg));
        assert!(
            server
                .segment_manager
                .get_segments_for_port(port_id)
                .is_empty()
        );
    }

    #[test]
    fn test_detach_cleans_up_consumer_mapping() {
        use crate::service::messaging_pattern::MessagingPattern;
        use iceoryx2_cal::hash::sha1::Sha1;

        let listener = MockListener::new();
        let policy = DefaultPolicy::with_owner(1000);
        let mut server = IamServer::new(listener, policy);

        // Create a session
        let conn = MockConnection::new(test_credentials());
        server.listener.add_connection(conn);
        server.process().unwrap();

        let session_id = *server.sessions.keys().next().unwrap();
        if let Some(entry) = server.sessions.get_mut(&session_id) {
            entry.handshake_complete = true;
        }

        let service_name =
            crate::service::service_name::ServiceName::new("test/detach_consumer").unwrap();
        let service_id = crate::service::service_hash::ServiceHash::new::<Sha1>(
            &service_name,
            MessagingPattern::PublishSubscribe,
        );

        let usage = SessionResourceUsage::new();
        let (response, _) = server
            .handle_attach_subscriber(session_id, &test_credentials(), &usage, &service_id)
            .unwrap();

        let port_id = match response {
            IamResponse::AttachOk { port_id, .. } => port_id,
            _ => panic!("Expected AttachOk"),
        };

        // Verify mapping exists
        assert!(server.service_consumers.contains_key(&service_id));

        // Detach
        let _ = server.handle_detach(session_id, &service_id, port_id);

        // Verify mapping was cleaned up (empty entries are removed)
        assert!(!server.service_consumers.contains_key(&service_id));
    }

    #[test]
    fn test_session_removal_cleans_up_mappings() {
        use crate::service::messaging_pattern::MessagingPattern;
        use iceoryx2_cal::hash::sha1::Sha1;

        let listener = MockListener::new();
        let policy = DefaultPolicy::with_owner(1000);
        let mut server = IamServer::new(listener, policy);

        // Create a session
        let conn = MockConnection::new(test_credentials());
        server.listener.add_connection(conn);
        server.process().unwrap();

        let session_id = *server.sessions.keys().next().unwrap();
        if let Some(entry) = server.sessions.get_mut(&session_id) {
            entry.handshake_complete = true;
        }

        // Attach a publisher
        let service_name1 =
            crate::service::service_name::ServiceName::new("test/session_rm_pub").unwrap();
        let service_id1 = crate::service::service_hash::ServiceHash::new::<Sha1>(
            &service_name1,
            MessagingPattern::PublishSubscribe,
        );

        let usage = SessionResourceUsage::new();
        let (response, _) = server
            .handle_attach_publisher(
                session_id,
                &test_credentials(),
                &usage,
                &service_id1,
                8,
                1024,
            )
            .unwrap();

        let pub_port_id = match response {
            IamResponse::AttachOk { port_id, .. } => port_id,
            _ => panic!("Expected AttachOk"),
        };

        // Attach a subscriber
        let service_name2 =
            crate::service::service_name::ServiceName::new("test/session_rm_sub").unwrap();
        let service_id2 = crate::service::service_hash::ServiceHash::new::<Sha1>(
            &service_name2,
            MessagingPattern::PublishSubscribe,
        );

        let _ =
            server.handle_attach_subscriber(session_id, &test_credentials(), &usage, &service_id2);

        // Verify mappings exist
        assert!(server.port_to_service.contains_key(&pub_port_id));
        assert!(server.service_consumers.contains_key(&service_id2));

        // Remove session
        server.remove_session(session_id);

        // Verify all mappings were cleaned up
        assert!(!server.port_to_service.contains_key(&pub_port_id));
        assert!(!server.service_consumers.contains_key(&service_id2));
    }

    #[test]
    fn test_broadcast_to_no_consumers_returns_zero() {
        use crate::service::messaging_pattern::MessagingPattern;
        use iceoryx2_cal::hash::sha1::Sha1;

        let listener = MockListener::new();
        let policy = DefaultPolicy::with_owner(1000);
        let mut server = IamServer::new(listener, policy);

        let service_name =
            crate::service::service_name::ServiceName::new("test/no_consumers").unwrap();
        let service_id = crate::service::service_hash::ServiceHash::new::<Sha1>(
            &service_name,
            MessagingPattern::PublishSubscribe,
        );

        let handle = create_test_handle();
        let segment_id = SegmentId::new(0);

        // Broadcast with no consumers
        let notified =
            server.broadcast_segment_to_consumers(&service_id, segment_id, 4096, &handle);

        assert_eq!(notified, 0);
    }

    #[test]
    fn test_server_tracking_on_attach_server_request_response() {
        use crate::service::messaging_pattern::MessagingPattern;
        use iceoryx2_cal::hash::sha1::Sha1;

        let listener = MockListener::new();
        let policy = DefaultPolicy::with_owner(1000);
        let mut server = IamServer::new(listener, policy);

        // Create a session
        let conn = MockConnection::new(test_credentials());
        server.listener.add_connection(conn);
        server.process().unwrap();

        let session_id = *server.sessions.keys().next().unwrap();
        if let Some(entry) = server.sessions.get_mut(&session_id) {
            entry.handshake_complete = true;
        }

        let service_name =
            crate::service::service_name::ServiceName::new("test/server_tracking").unwrap();
        let service_id = crate::service::service_hash::ServiceHash::new::<Sha1>(
            &service_name,
            MessagingPattern::RequestResponse,
        );

        let usage = SessionResourceUsage::new();
        let _ = server.handle_attach_server(session_id, &test_credentials(), &usage, &service_id);

        // Server ports are producers, should be in port_to_service
        assert!(!server.port_to_service.is_empty());
    }

    #[test]
    fn test_client_tracking_on_attach_client_request_response() {
        use crate::service::messaging_pattern::MessagingPattern;
        use iceoryx2_cal::hash::sha1::Sha1;

        let listener = MockListener::new();
        let policy = DefaultPolicy::with_owner(1000);
        let mut server = IamServer::new(listener, policy);

        // Create a session
        let conn = MockConnection::new(test_credentials());
        server.listener.add_connection(conn);
        server.process().unwrap();

        let session_id = *server.sessions.keys().next().unwrap();
        if let Some(entry) = server.sessions.get_mut(&session_id) {
            entry.handshake_complete = true;
        }

        let service_name =
            crate::service::service_name::ServiceName::new("test/client_tracking").unwrap();
        let service_id = crate::service::service_hash::ServiceHash::new::<Sha1>(
            &service_name,
            MessagingPattern::RequestResponse,
        );

        let usage = SessionResourceUsage::new();
        let _ = server.handle_attach_client(session_id, &test_credentials(), &usage, &service_id);

        // Client ports are consumers, should be in service_consumers
        assert!(!server.service_consumers.is_empty());
        assert!(server.service_consumers.contains_key(&service_id));
    }

    // R1: a request-response CLIENT is ALSO a producer — it registers a request data segment, a
    // resizable management segment, and the request connection channel as SENDER, all keyed by
    // its own client port. Its teardown runs through the PortType::Client branch, which formerly
    // reaped only receiver-side channels, so all three producer resources leaked (fds +
    // global SegmentIds), reopening the id-exhaustion DoS. Detach must now reap all of them.
    #[test]
    fn test_detach_reaps_request_response_client_producer_resources() {
        use crate::service::messaging_pattern::MessagingPattern;
        use iceoryx2_cal::hash::sha1::Sha1;

        let listener = MockListener::new();
        let policy = DefaultPolicy::with_owner(1000);
        let mut server = IamServer::new(listener, policy);

        let conn = MockConnection::new(test_credentials());
        server.listener.add_connection(conn);
        server.process().unwrap();

        let session_id = *server.sessions.keys().next().unwrap();
        if let Some(entry) = server.sessions.get_mut(&session_id) {
            entry.handshake_complete = true;
        }

        let service_name =
            crate::service::service_name::ServiceName::new("test/client_reap").unwrap();
        let service_id = crate::service::service_hash::ServiceHash::new::<Sha1>(
            &service_name,
            MessagingPattern::RequestResponse,
        );

        let usage = SessionResourceUsage::new();
        let (response, _) = server
            .handle_attach_client(session_id, &test_credentials(), &usage, &service_id)
            .unwrap();
        let client_port = match response {
            IamResponse::AttachOk { port_id, .. } => port_id,
            _ => panic!("Expected AttachOk"),
        };
        // The peer server port the client's request channel is addressed to (client is SENDER).
        let server_port: u128 = 0x5E27E7;

        // Register the client's producer resources exactly as the client-side plumbing does.
        let request_seg = server
            .segment_manager
            .register_segment_for_port(
                client_port,
                create_test_handle(),
                4096,
                AccessRights::read_write(),
            )
            .unwrap();
        server
            .segment_manager
            .register_mgmt_segment(client_port, create_test_handle(), 4096)
            .unwrap();
        server
            .segment_manager
            .register_channel(client_port, server_port, create_test_handle(), 4096)
            .unwrap();

        // Baseline: all three producer resources are present for the client port.
        assert_eq!(server.segment_count(), 1);
        assert!(server.segment_manager.has_segment(request_seg));
        assert!(
            !server
                .segment_manager
                .get_segments_for_port(client_port)
                .is_empty()
        );
        assert_eq!(server.segment_manager.mgmt_segment_count(), 1);
        assert_eq!(server.segment_manager.channel_count(), 1);

        // Detaching the client port must reap ALL of its producer resources.
        let _ = server.handle_detach(session_id, &service_id, client_port);

        assert_eq!(server.segment_count(), 0);
        assert!(!server.segment_manager.has_segment(request_seg));
        assert!(
            server
                .segment_manager
                .get_segments_for_port(client_port)
                .is_empty()
        );
        assert_eq!(server.segment_manager.mgmt_segment_count(), 0);
        assert_eq!(server.segment_manager.channel_count(), 0);
    }

    // R1 (symmetric): a request-response SERVER is ALSO a consumer — the request channel where it
    // is the RECEIVER is keyed (client_port, server_port). Its teardown runs through the
    // PortType::Server branch, which formerly reaped only sender-side channels, so this
    // consumer-side channel leaked. Session removal must now reap it too.
    #[test]
    fn test_session_removal_reaps_request_response_server_consumer_channel() {
        use crate::service::messaging_pattern::MessagingPattern;
        use iceoryx2_cal::hash::sha1::Sha1;

        let listener = MockListener::new();
        let policy = DefaultPolicy::with_owner(1000);
        let mut server = IamServer::new(listener, policy);

        let conn = MockConnection::new(test_credentials());
        server.listener.add_connection(conn);
        server.process().unwrap();

        let session_id = *server.sessions.keys().next().unwrap();
        if let Some(entry) = server.sessions.get_mut(&session_id) {
            entry.handshake_complete = true;
        }

        let service_name =
            crate::service::service_name::ServiceName::new("test/server_reap").unwrap();
        let service_id = crate::service::service_hash::ServiceHash::new::<Sha1>(
            &service_name,
            MessagingPattern::RequestResponse,
        );

        let usage = SessionResourceUsage::new();
        let (response, _) = server
            .handle_attach_server(session_id, &test_credentials(), &usage, &service_id)
            .unwrap();
        let server_port = match response {
            IamResponse::AttachOk { port_id, .. } => port_id,
            _ => panic!("Expected AttachOk"),
        };
        // A remote client whose request channel targets this server (server is the RECEIVER).
        let client_port: u128 = 0xC11E27;

        // The request connection channel where the server is the consumer/receiver.
        server
            .segment_manager
            .register_channel(client_port, server_port, create_test_handle(), 4096)
            .unwrap();
        assert_eq!(server.segment_manager.channel_count(), 1);

        // Session removal (server-as-producer branch) must ALSO reap the consumer-side channel.
        server.remove_session(session_id);

        assert_eq!(server.segment_manager.channel_count(), 0);
    }

    // ========================================================================
    // Multi-user hardening: role gating, producer port binding, departures
    // ========================================================================

    fn mu_service_id() -> ServiceHash {
        use crate::service::messaging_pattern::MessagingPattern;
        use iceoryx2_cal::hash::sha1::Sha1;
        let name = crate::service::service_name::ServiceName::new("test/multi_user").unwrap();
        ServiceHash::new::<Sha1>(&name, MessagingPattern::PublishSubscribe)
    }

    /// Accepts a new mock connection with the given credentials and completes its handshake.
    fn mu_session<P: IamPolicy>(
        server: &mut IamServer<MockListener, P>,
        credentials: ProcessCredentials,
        node_id: Option<u128>,
    ) -> SessionId {
        let before: Vec<SessionId> = server.sessions.keys().copied().collect();
        server
            .listener
            .add_connection(MockConnection::new(credentials));
        server.process().unwrap();
        let session_id = *server
            .sessions
            .keys()
            .find(|id| !before.contains(id))
            .unwrap();
        let entry = server.sessions.get_mut(&session_id).unwrap();
        entry.handshake_complete = true;
        entry.node_id = node_id;
        session_id
    }

    fn mu_attach<P: IamPolicy>(
        server: &mut IamServer<MockListener, P>,
        session_id: SessionId,
        port_type: PortType,
    ) -> IamResponse {
        let credentials = server.sessions[&session_id].session.credentials().clone();
        let usage = *server.sessions[&session_id].session.resource_usage();
        let service_id = mu_service_id();
        match port_type {
            PortType::Publisher => {
                server
                    .handle_attach_publisher(session_id, &credentials, &usage, &service_id, 0, 8)
                    .unwrap()
                    .0
            }
            PortType::Subscriber => {
                server
                    .handle_attach_subscriber(session_id, &credentials, &usage, &service_id)
                    .unwrap()
                    .0
            }
            t => {
                server
                    .handle_attach_event_port(session_id, &credentials, &usage, &service_id, t)
                    .unwrap()
                    .0
            }
        }
    }

    fn sip_policy() -> crate::iam::configured_policy::ConfiguredPolicy {
        let toml = r#"
[service]
name = "test/multi_user"

[[allow]]
principal = { uid = 2000 }
roles = ["subscriber", "listener"]

[[allow]]
principal = { gid = 3000 }
roles = ["publisher", "notifier"]
"#;
        let file: crate::iam::configured_policy::PolicyFile = toml::from_str(toml).unwrap();
        crate::iam::configured_policy::ConfiguredPolicy::from_policy_file(file, 2000)
    }

    fn writer_credentials(uid: u32) -> ProcessCredentials {
        // primary group is the user's own group, the grant comes from a supplementary group
        ProcessCredentials::new(uid, uid, uid).with_supplementary_gids(vec![3000])
    }

    #[test]
    fn test_mu_supplementary_group_grants_publisher_and_notifier_only() {
        let mut server = IamServer::new(MockListener::new(), sip_policy());
        let writer = mu_session(&mut server, writer_credentials(2001), None);

        assert!(matches!(
            mu_attach(&mut server, writer, PortType::Publisher),
            IamResponse::AttachOk { .. }
        ));
        assert!(matches!(
            mu_attach(&mut server, writer, PortType::Notifier),
            IamResponse::AttachOk { .. }
        ));
        assert!(matches!(
            mu_attach(&mut server, writer, PortType::Subscriber),
            IamResponse::Denied {
                reason: DenialReason::Unauthorized,
                ..
            }
        ));
        assert!(matches!(
            mu_attach(&mut server, writer, PortType::Listener),
            IamResponse::Denied {
                reason: DenialReason::Unauthorized,
                ..
            }
        ));

        // without the supplementary group nothing is granted
        let stranger = mu_session(&mut server, ProcessCredentials::new(7, 2003, 2003), None);
        for port_type in [
            PortType::Publisher,
            PortType::Subscriber,
            PortType::Notifier,
            PortType::Listener,
        ] {
            assert!(matches!(
                mu_attach(&mut server, stranger, port_type),
                IamResponse::Denied { .. }
            ));
        }
    }

    #[test]
    fn test_mu_publisher_only_session_cannot_obtain_producer_handles() {
        let mut server = IamServer::new(MockListener::new(), sip_policy());
        let writer_a = mu_session(&mut server, writer_credentials(2001), None);
        let writer_b = mu_session(&mut server, writer_credentials(2002), None);
        let broker = mu_session(&mut server, ProcessCredentials::new(9, 2000, 2000), None);
        mu_attach(&mut server, writer_a, PortType::Publisher);
        mu_attach(&mut server, writer_b, PortType::Publisher);
        mu_attach(&mut server, broker, PortType::Subscriber);

        // writer A's producer port registers a data segment, a management segment and a channel
        let port_a: u128 = 0xA;
        assert!(server.claim_producer_port(writer_a, port_a).is_none());
        server
            .segment_manager
            .register_segment_for_port(
                port_a,
                create_test_handle(),
                4096,
                AccessRights::read_only(),
            )
            .unwrap();
        server
            .segment_manager
            .register_mgmt_segment(port_a, create_test_handle(), 128)
            .unwrap();
        server
            .segment_manager
            .register_channel(port_a, 0xB0, create_test_handle(), 128)
            .unwrap();

        // writer B holds no consumer role: every handle request is refused
        let denied = |r: IamResponse| matches!(r, IamResponse::Denied { .. });
        assert!(denied(
            server
                .handle_request_segment_handle(writer_b, port_a)
                .unwrap()
                .0
        ));
        assert!(denied(
            server
                .handle_request_dynamic_segment_handle(writer_b, port_a, 0)
                .unwrap()
                .0
        ));
        assert!(denied(
            server
                .handle_request_mgmt_segment_handle(writer_b, port_a)
                .unwrap()
                .0
        ));
        assert!(denied(
            server
                .handle_request_channel_handle(writer_b, port_a, 0xB0)
                .unwrap()
                .0
        ));

        // the broker (subscriber role) obtains them
        assert!(matches!(
            server
                .handle_request_segment_handle(broker, port_a)
                .unwrap()
                .0,
            IamResponse::SegmentHandleOk { .. }
        ));
        assert!(matches!(
            server
                .handle_request_mgmt_segment_handle(broker, port_a)
                .unwrap()
                .0,
            IamResponse::MgmtSegmentHandleOk { .. }
        ));
        assert!(matches!(
            server
                .handle_request_channel_handle(broker, port_a, 0xB0)
                .unwrap()
                .0,
            IamResponse::ChannelHandleOk { .. }
        ));
    }

    #[test]
    fn test_mu_producer_port_cannot_be_claimed_by_other_session_or_non_producer() {
        let mut server = IamServer::new(MockListener::new(), sip_policy());
        let writer_a = mu_session(&mut server, writer_credentials(2001), None);
        let writer_b = mu_session(&mut server, writer_credentials(2002), None);
        let broker = mu_session(&mut server, ProcessCredentials::new(9, 2000, 2000), None);
        mu_attach(&mut server, writer_a, PortType::Publisher);
        mu_attach(&mut server, writer_b, PortType::Publisher);
        mu_attach(&mut server, broker, PortType::Subscriber);

        assert!(server.claim_producer_port(writer_a, 0xA).is_none());
        // idempotent for the owner
        assert!(server.claim_producer_port(writer_a, 0xA).is_none());
        // another producer cannot inject handles under A's port
        assert!(matches!(
            server.claim_producer_port(writer_b, 0xA),
            Some(IamResponse::Denied { .. })
        ));
        // a session without a producer port cannot register handles at all
        assert!(matches!(
            server.claim_producer_port(broker, 0xC),
            Some(IamResponse::Denied { .. })
        ));
    }

    #[test]
    fn test_mu_detach_only_releases_own_producer_ports() {
        let mut server = IamServer::new(MockListener::new(), sip_policy());
        let writer_a = mu_session(&mut server, writer_credentials(2001), None);
        let writer_b = mu_session(&mut server, writer_credentials(2002), None);
        mu_attach(&mut server, writer_a, PortType::Publisher);
        mu_attach(&mut server, writer_b, PortType::Publisher);

        assert!(server.claim_producer_port(writer_a, 0xA).is_none());
        let segment = server
            .segment_manager
            .register_segment_for_port(0xA, create_test_handle(), 4096, AccessRights::read_only())
            .unwrap();

        // B detaching A's port is a no-op
        server
            .handle_detach(writer_b, &mu_service_id(), 0xA)
            .unwrap();
        assert!(server.segment_manager.has_segment(segment));

        // A detaching its own port releases the handles
        server
            .handle_detach(writer_a, &mu_service_id(), 0xA)
            .unwrap();
        assert!(!server.segment_manager.has_segment(segment));
        assert!(!server.producer_port_owner.contains_key(&0xA));
    }

    #[test]
    fn test_mu_detach_returns_attach_quota() {
        let mut server = IamServer::new(MockListener::new(), sip_policy());
        let writer = mu_session(&mut server, writer_credentials(2001), None);
        // far more attach/detach cycles than max_publishers (16)
        for _ in 0..64 {
            let port_id = match mu_attach(&mut server, writer, PortType::Publisher) {
                IamResponse::AttachOk { port_id, .. } => port_id,
                r => panic!("attach #{} failed: {r:?}", 0),
            };
            server
                .handle_detach(writer, &mu_service_id(), port_id)
                .unwrap();
        }
        assert_eq!(
            server.sessions[&writer]
                .session
                .resource_usage()
                .publisher_count,
            0
        );
    }

    #[test]
    fn test_mu_departure_handler_gets_dead_peer_and_handles_are_retained_until_then() {
        use std::sync::atomic::AtomicUsize;

        let calls = Arc::new(Mutex::new(Vec::<(u128, u32)>::new()));
        let calls_clone = Arc::clone(&calls);
        let outcome = Arc::new(AtomicUsize::new(1)); // 1 = Retry, 0 = Completed
        let outcome_clone = Arc::clone(&outcome);
        let mut server = IamServerBuilder::new(MockListener::new(), sip_policy())
            .peer_departure_handler(Box::new(move |node_id, credentials| {
                calls_clone
                    .lock()
                    .unwrap()
                    .push((node_id, credentials.uid()));
                if outcome_clone.load(Ordering::Relaxed) == 0 {
                    PeerDepartureOutcome::Completed
                } else {
                    PeerDepartureOutcome::Retry
                }
            }))
            .peer_departure_timing(Duration::ZERO, Duration::from_secs(60))
            .build();

        let writer = mu_session(&mut server, writer_credentials(2001), Some(0x77));
        mu_attach(&mut server, writer, PortType::Publisher);
        assert!(server.claim_producer_port(writer, 0xA).is_none());
        let segment = server
            .segment_manager
            .register_segment_for_port(0xA, create_test_handle(), 4096, AccessRights::read_only())
            .unwrap();

        // the peer disappears (e.g. SIGKILL closes its socket)
        server.remove_session(writer);
        assert_eq!(server.session_count(), 0);
        // its producer handles stay brokerable while the departure is pending
        assert!(server.segment_manager.has_segment(segment));

        server.process().unwrap();
        assert_eq!(calls.lock().unwrap().as_slice(), &[(0x77, 2001)]);
        assert!(server.segment_manager.has_segment(segment));

        outcome.store(0, Ordering::Relaxed);
        server.process().unwrap();
        assert_eq!(calls.lock().unwrap().len(), 2);
        assert!(!server.segment_manager.has_segment(segment));
        assert!(server.pending_departures.is_empty());
    }

    #[test]
    fn test_mu_departure_waits_for_last_session_of_the_node() {
        let calls = Arc::new(Mutex::new(0usize));
        let calls_clone = Arc::clone(&calls);
        let mut server = IamServerBuilder::new(MockListener::new(), sip_policy())
            .peer_departure_handler(Box::new(move |_, _| {
                *calls_clone.lock().unwrap() += 1;
                PeerDepartureOutcome::Completed
            }))
            .peer_departure_timing(Duration::ZERO, Duration::ZERO)
            .build();

        let first = mu_session(&mut server, writer_credentials(2001), Some(0x77));
        let second = mu_session(&mut server, writer_credentials(2001), Some(0x77));
        server.remove_session(first);
        server.process().unwrap();
        assert_eq!(*calls.lock().unwrap(), 0);

        server.remove_session(second);
        server.process().unwrap();
        assert_eq!(*calls.lock().unwrap(), 1);
    }
}
