# SP5: IAM Service Core - Multi-Phase Implementation Plan

## Overview

This document outlines the implementation plan for Sub-Project 5: IAM Service Core. The implementation is broken into 5 phases, each reviewed by 3 independent Sonnet reviewers before proceeding.

## Dependencies Verification

**Status: ALL VERIFIED COMPLETE**

| Sub-Project | Status | Key Components |
|-------------|--------|----------------|
| SP1: Core Security | COMPLETE | PlatformHandle, HandleBundle, AccessRights, ProcessCredentials, SecurityMode |
| SP2: Linux Control | COMPLETE | UnixStreamControlChannel, SCM_RIGHTS, SCM_CREDENTIALS, memfd_create |
| SP3: Windows Control | COMPLETE | NamedPipeControlChannel, ImpersonateNamedPipeClient, DuplicateHandle, SID support |
| SP4: Handle-Based Access | COMPLETE | open_from_handle on SharedMemory/ZeroCopyConnection, create_anonymous |

## Module Structure

```
iceoryx2/src/iam/
├── mod.rs                 # Public exports
├── error.rs               # All IAM error types
├── protocol.rs            # Protocol version, requests, responses, notifications
├── policy.rs              # IamPolicy trait, PolicyDecision, DefaultPolicy
├── server.rs              # IamServer implementation
├── client.rs              # IamClient implementation
├── session.rs             # ClientSession, SessionId types
├── segment_manager.rs     # ManagedSegment, segment lifecycle
└── tests/
    ├── mod.rs
    ├── protocol_tests.rs
    ├── policy_tests.rs
    └── integration_tests.rs
```

---

## Phase 1: IAM Protocol Definition

**Location**: `iceoryx2/src/iam/protocol.rs`, `iceoryx2/src/iam/error.rs`

### 1.1 Protocol Version

```rust
// iceoryx2/src/iam/protocol.rs

use serde::{Serialize, Deserialize};

/// IAM protocol version for compatibility checking
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(C)]
pub struct ProtocolVersion {
    pub major: u16,
    pub minor: u16,
}

impl ProtocolVersion {
    /// Current protocol version
    pub const CURRENT: Self = Self { major: 1, minor: 0 };

    /// Check if this version is compatible with another
    pub fn is_compatible_with(&self, other: &Self) -> bool {
        self.major == other.major && self.minor >= other.minor
    }
}
```

### 1.2 Request Types

```rust
/// All IAM request types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IamRequest {
    /// Initial handshake
    Hello {
        protocol_version: ProtocolVersion,
        node_id: UniqueSystemId,
    },
    /// Create a new secured service
    CreateService {
        service_name: ServiceName,
        messaging_pattern: MessagingPatternKind,
    },
    /// Attach as publisher
    AttachPublisher {
        service_id: ServiceId,
        history_size: usize,
        max_slice_len: usize,
    },
    /// Attach as subscriber
    AttachSubscriber {
        service_id: ServiceId,
        buffer_size: usize,
    },
    /// Attach as server (request-response)
    AttachServer {
        service_id: ServiceId,
        max_active_requests: usize,
    },
    /// Attach as client (request-response)
    AttachClient {
        service_id: ServiceId,
        max_pending_responses: usize,
    },
    /// Request additional segment
    AddSegment {
        service_id: ServiceId,
        port_id: UniquePortId,
        requested_size: usize,
    },
    /// Detach from service
    Detach {
        service_id: ServiceId,
        port_id: UniquePortId,
    },
    /// Acknowledge segment retirement
    AckSegmentRetirement {
        service_id: ServiceId,
        segment_id: SegmentId,
    },
}
```

### 1.3 Response Types

```rust
/// IAM response types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IamResponse {
    /// Handshake accepted
    HelloOk {
        negotiated_version: ProtocolVersion,
        session_id: SessionId,
    },
    /// Service created successfully
    CreateServiceOk {
        service_id: ServiceId,
    },
    /// Attach succeeded
    AttachOk {
        port_id: UniquePortId,
        segment_info: Vec<SegmentInfo>,
        /// Number of handles that will follow via control channel
        handle_count: usize,
    },
    /// Segment added successfully
    AddSegmentOk {
        segment_id: SegmentId,
        size: usize,
        handle_count: usize,
    },
    /// Detach acknowledged
    DetachOk,
    /// Retirement acknowledged
    AckOk,
    /// Request denied
    Denied {
        reason: DenialReason,
        message: String,
    },
    /// Protocol error
    ProtocolError {
        message: String,
    },
}

/// Segment metadata sent with attach response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SegmentInfo {
    pub segment_id: SegmentId,
    pub size: usize,
    pub access: AccessRights,
}
```

### 1.4 Notification Types

```rust
/// Asynchronous notifications from IAM to clients
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IamNotification {
    /// New segment available
    SegmentUpdate {
        segment_id: SegmentId,
        size: usize,
        handle_count: usize,
    },
    /// Segment being retired - client must acknowledge
    SegmentRetiring {
        segment_id: SegmentId,
    },
    /// New port joined the service
    PortJoined {
        port_id: UniquePortId,
        port_type: PortType,
    },
    /// Port left the service
    PortLeft {
        port_id: UniquePortId,
    },
    /// Service is shutting down
    ServiceStopping,
}

/// Port type for notifications
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PortType {
    Publisher,
    Subscriber,
    Server,
    Client,
}
```

### 1.5 Supporting Types

```rust
/// Reason for request denial
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DenialReason {
    /// Credentials not authorized for this operation
    Unauthorized,
    /// Service does not exist
    ServiceNotFound,
    /// Service already exists (for create)
    ServiceAlreadyExists,
    /// Resource limit exceeded
    ResourceLimitExceeded,
    /// Requested QoS incompatible with service
    IncompatibleQos,
    /// Policy explicitly denies this request
    PolicyViolation,
    /// Internal error during processing
    InternalError,
    /// Protocol version incompatible
    VersionMismatch,
    /// Session not found or expired
    SessionNotFound,
}

/// Unique session identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SessionId(pub u64);

/// Unique port identifier (reuses existing type)
pub type UniquePortId = u128;

/// Messaging pattern kind
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MessagingPatternKind {
    PublishSubscribe,
    RequestResponse,
    Event,
}
```

### 1.6 Error Types

```rust
// iceoryx2/src/iam/error.rs

use core::fmt;

/// IAM server errors
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IamServerError {
    /// Failed to create control channel listener
    ListenerCreationFailed,
    /// Failed to accept client connection
    AcceptFailed,
    /// Failed to send response
    SendFailed,
    /// Failed to receive request
    ReceiveFailed,
    /// Handle passing failed
    HandlePassingFailed,
    /// Segment creation failed
    SegmentCreationFailed,
    /// Policy evaluation failed
    PolicyEvaluationFailed,
    /// Serialization/deserialization error
    SerializationError,
    /// Internal error
    InternalError,
}

impl fmt::Display for IamServerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "IamServerError::{self:?}")
    }
}

impl core::error::Error for IamServerError {}

/// IAM client errors
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IamClientError {
    /// Failed to connect to IAM endpoint
    ConnectionFailed,
    /// Handshake failed
    HandshakeFailed,
    /// Version incompatible
    VersionMismatch,
    /// Request was denied
    RequestDenied,
    /// Failed to send request
    SendFailed,
    /// Failed to receive response
    ReceiveFailed,
    /// Failed to receive handles
    HandleReceiveFailed,
    /// Timeout waiting for response
    Timeout,
    /// Session expired or invalid
    SessionInvalid,
    /// Serialization error
    SerializationError,
    /// Internal error
    InternalError,
}

impl fmt::Display for IamClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "IamClientError::{self:?}")
    }
}

impl core::error::Error for IamClientError {}
```

### Phase 1 Deliverables

1. `iceoryx2/src/iam/mod.rs` - Module exports
2. `iceoryx2/src/iam/protocol.rs` - All protocol types (~350 lines)
3. `iceoryx2/src/iam/error.rs` - Error types (~100 lines)
4. Unit tests for serialization round-trips
5. Unit tests for version compatibility

### Phase 1 Review Criteria

- [ ] All types derive appropriate traits (Debug, Clone, Serialize, Deserialize)
- [ ] Error types follow codebase pattern (Copy, Display, Error)
- [ ] Protocol version compatibility logic is correct
- [ ] Serialization round-trips work correctly
- [ ] No Copy types contain heap-allocated data
- [ ] Types are repr(C) where needed for cross-process use
- [ ] Naming follows codebase conventions

---

## Phase 2: IAM Policy Trait and DefaultPolicy

**Location**: `iceoryx2/src/iam/policy.rs`

### 2.1 Policy Trait

```rust
// iceoryx2/src/iam/policy.rs

use crate::iam::protocol::{DenialReason, MessagingPatternKind, PortType};
use iceoryx2_cal::security::credentials::ProcessCredentials;

/// Result of policy evaluation
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyDecision {
    /// Request is allowed
    Allow,
    /// Request is denied with reason
    Deny { reason: DenialReason, message: String },
}

impl PolicyDecision {
    pub fn is_allowed(&self) -> bool {
        matches!(self, PolicyDecision::Allow)
    }

    pub fn is_denied(&self) -> bool {
        matches!(self, PolicyDecision::Deny { .. })
    }
}

/// Resource limits for a principal
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceLimits {
    /// Maximum publishers this principal can create
    pub max_publishers: usize,
    /// Maximum subscribers this principal can create
    pub max_subscribers: usize,
    /// Maximum servers this principal can create
    pub max_servers: usize,
    /// Maximum clients this principal can create
    pub max_clients: usize,
    /// Maximum total segments across all ports
    pub max_segments: usize,
    /// Maximum size per segment in bytes
    pub max_segment_size: usize,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            max_publishers: 16,
            max_subscribers: 256,
            max_servers: 16,
            max_clients: 256,
            max_segments: 64,
            max_segment_size: 64 * 1024 * 1024, // 64 MB
        }
    }
}

/// Policy trait for IAM authorization decisions
pub trait IamPolicy: Send + Sync {
    /// Check if credentials are allowed to create the service
    fn authorize_create(
        &self,
        credentials: &ProcessCredentials,
        service_name: &ServiceName,
        messaging_pattern: MessagingPatternKind,
    ) -> PolicyDecision;

    /// Check if credentials are allowed to attach with given role
    fn authorize_attach(
        &self,
        credentials: &ProcessCredentials,
        service_id: &ServiceId,
        port_type: PortType,
    ) -> PolicyDecision;

    /// Check if credentials are allowed to add a segment
    fn authorize_add_segment(
        &self,
        credentials: &ProcessCredentials,
        service_id: &ServiceId,
        port_id: UniquePortId,
        requested_size: usize,
    ) -> PolicyDecision;

    /// Get resource limits for a principal
    fn get_limits(&self, credentials: &ProcessCredentials) -> ResourceLimits;

    /// Called when a client connects - can reject early
    fn authorize_connect(&self, credentials: &ProcessCredentials) -> PolicyDecision {
        // Default: allow all connections, authorize per-operation
        PolicyDecision::Allow
    }
}
```

### 2.2 Default Policy

```rust
/// Default policy: allow all same-UID/owner processes
pub struct DefaultPolicy {
    owner_uid: u32,
    limits: ResourceLimits,
}

impl DefaultPolicy {
    /// Create default policy for current process owner
    pub fn new() -> Self {
        let credentials = ProcessCredentials::from_self();
        Self {
            owner_uid: credentials.uid(),
            limits: ResourceLimits::default(),
        }
    }

    /// Create default policy with specific owner
    pub fn with_owner(owner_uid: u32) -> Self {
        Self {
            owner_uid,
            limits: ResourceLimits::default(),
        }
    }

    /// Create with custom limits
    pub fn with_limits(owner_uid: u32, limits: ResourceLimits) -> Self {
        Self { owner_uid, limits }
    }
}

impl IamPolicy for DefaultPolicy {
    fn authorize_create(
        &self,
        credentials: &ProcessCredentials,
        _service_name: &ServiceName,
        _messaging_pattern: MessagingPatternKind,
    ) -> PolicyDecision {
        if credentials.uid() == self.owner_uid {
            PolicyDecision::Allow
        } else {
            PolicyDecision::Deny {
                reason: DenialReason::Unauthorized,
                message: format!(
                    "Only owner (uid={}) can create services, got uid={}",
                    self.owner_uid, credentials.uid()
                ),
            }
        }
    }

    fn authorize_attach(
        &self,
        credentials: &ProcessCredentials,
        _service_id: &ServiceId,
        _port_type: PortType,
    ) -> PolicyDecision {
        if credentials.uid() == self.owner_uid {
            PolicyDecision::Allow
        } else {
            PolicyDecision::Deny {
                reason: DenialReason::Unauthorized,
                message: format!(
                    "Only same-uid processes can attach (expected {}, got {})",
                    self.owner_uid, credentials.uid()
                ),
            }
        }
    }

    fn authorize_add_segment(
        &self,
        credentials: &ProcessCredentials,
        _service_id: &ServiceId,
        _port_id: UniquePortId,
        requested_size: usize,
    ) -> PolicyDecision {
        if credentials.uid() != self.owner_uid {
            return PolicyDecision::Deny {
                reason: DenialReason::Unauthorized,
                message: "Not authorized".to_string(),
            };
        }

        if requested_size > self.limits.max_segment_size {
            return PolicyDecision::Deny {
                reason: DenialReason::ResourceLimitExceeded,
                message: format!(
                    "Requested size {} exceeds limit {}",
                    requested_size, self.limits.max_segment_size
                ),
            };
        }

        PolicyDecision::Allow
    }

    fn get_limits(&self, _credentials: &ProcessCredentials) -> ResourceLimits {
        self.limits.clone()
    }
}
```

### 2.3 Policy Errors

```rust
/// Error creating or loading policy
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyError {
    /// Policy file not found
    NotFound,
    /// Policy file parse error
    ParseError(String),
    /// Invalid policy configuration
    InvalidConfiguration(String),
}

impl fmt::Display for PolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PolicyError::NotFound => write!(f, "PolicyError::NotFound"),
            PolicyError::ParseError(msg) => write!(f, "PolicyError::ParseError({})", msg),
            PolicyError::InvalidConfiguration(msg) => {
                write!(f, "PolicyError::InvalidConfiguration({})", msg)
            }
        }
    }
}

impl core::error::Error for PolicyError {}
```

### Phase 2 Deliverables

1. `iceoryx2/src/iam/policy.rs` - Policy types and DefaultPolicy (~250 lines)
2. Unit tests for DefaultPolicy authorization
3. Unit tests for ResourceLimits

### Phase 2 Review Criteria

- [ ] IamPolicy trait is Send + Sync for thread-safety
- [ ] DefaultPolicy correctly enforces same-UID restriction
- [ ] Resource limits are correctly enforced
- [ ] PolicyDecision has appropriate helper methods
- [ ] Default limits are reasonable for production use
- [ ] Error messages are descriptive and useful for debugging

---

## Phase 3: IAM Server Core

**Location**: `iceoryx2/src/iam/server.rs`, `iceoryx2/src/iam/session.rs`, `iceoryx2/src/iam/segment_manager.rs`

### 3.1 Session Management

```rust
// iceoryx2/src/iam/session.rs

use std::collections::{HashMap, HashSet};
use std::time::Instant;

/// Unique session identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SessionId(u64);

impl SessionId {
    pub fn new() -> Self {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(1);
        Self(COUNTER.fetch_add(1, Ordering::Relaxed))
    }

    pub fn value(&self) -> u64 {
        self.0
    }
}

/// Client session state
#[derive(Debug)]
pub struct ClientSession {
    pub id: SessionId,
    pub credentials: ProcessCredentials,
    pub authenticated_at: Instant,
    pub attached_ports: Vec<UniquePortId>,
    pub granted_segments: HashSet<SegmentId>,
    pub pending_retirements: HashSet<SegmentId>,
}

impl ClientSession {
    pub fn new(credentials: ProcessCredentials) -> Self {
        Self {
            id: SessionId::new(),
            credentials,
            authenticated_at: Instant::now(),
            attached_ports: Vec::new(),
            granted_segments: HashSet::new(),
            pending_retirements: HashSet::new(),
        }
    }

    pub fn add_port(&mut self, port_id: UniquePortId) {
        self.attached_ports.push(port_id);
    }

    pub fn remove_port(&mut self, port_id: UniquePortId) {
        self.attached_ports.retain(|p| *p != port_id);
    }

    pub fn grant_segment(&mut self, segment_id: SegmentId) {
        self.granted_segments.insert(segment_id);
    }
}
```

### 3.2 Segment Manager

```rust
// iceoryx2/src/iam/segment_manager.rs

use std::collections::{HashMap, HashSet};

/// Managed segment state
#[derive(Debug)]
pub struct ManagedSegment {
    pub id: SegmentId,
    pub handle: PlatformHandle,
    pub size: usize,
    pub access: AccessRights,
    pub authorized_sessions: HashSet<SessionId>,
    pub retiring: bool,
    pub pending_acks: HashSet<SessionId>,
}

/// Manages segment lifecycle and authorization
#[derive(Debug)]
pub struct SegmentManager {
    segments: HashMap<SegmentId, ManagedSegment>,
    next_id: u8,
}

impl SegmentManager {
    pub fn new() -> Self {
        Self {
            segments: HashMap::new(),
            next_id: 0,
        }
    }

    /// Create a new segment
    pub fn create_segment(
        &mut self,
        size: usize,
        access: AccessRights,
    ) -> Result<SegmentId, IamServerError> {
        let id = SegmentId(self.next_id);
        self.next_id = self.next_id.checked_add(1)
            .ok_or(IamServerError::ResourceLimitExceeded)?;

        // Create anonymous shared memory
        let (shm, handle) = SharedMemory::create_anonymous(size)
            .map_err(|_| IamServerError::SegmentCreationFailed)?;

        self.segments.insert(id, ManagedSegment {
            id,
            handle,
            size,
            access,
            authorized_sessions: HashSet::new(),
            retiring: false,
            pending_acks: HashSet::new(),
        });

        Ok(id)
    }

    /// Authorize a session for a segment, returns cloned handle
    pub fn authorize_session(
        &mut self,
        segment_id: SegmentId,
        session_id: SessionId,
    ) -> Result<PlatformHandle, IamServerError> {
        let segment = self.segments.get_mut(&segment_id)
            .ok_or(IamServerError::SegmentNotFound)?;

        segment.authorized_sessions.insert(session_id);
        segment.handle.try_clone()
            .map_err(|_| IamServerError::HandlePassingFailed)
    }

    /// Begin segment retirement
    pub fn begin_retirement(&mut self, segment_id: SegmentId) -> Option<HashSet<SessionId>> {
        let segment = self.segments.get_mut(&segment_id)?;
        segment.retiring = true;
        segment.pending_acks = segment.authorized_sessions.clone();
        Some(segment.pending_acks.clone())
    }

    /// Acknowledge retirement from a session
    pub fn ack_retirement(
        &mut self,
        segment_id: SegmentId,
        session_id: SessionId,
    ) -> bool {
        if let Some(segment) = self.segments.get_mut(&segment_id) {
            segment.pending_acks.remove(&session_id);
            if segment.pending_acks.is_empty() && segment.retiring {
                // All acks received, can remove segment
                self.segments.remove(&segment_id);
                return true;
            }
        }
        false
    }

    /// Revoke session access (on disconnect)
    pub fn revoke_session(&mut self, session_id: SessionId) {
        for segment in self.segments.values_mut() {
            segment.authorized_sessions.remove(&session_id);
            segment.pending_acks.remove(&session_id);
        }
    }

    /// Get segment info
    pub fn get_segment_info(&self, segment_id: SegmentId) -> Option<SegmentInfo> {
        self.segments.get(&segment_id).map(|s| SegmentInfo {
            segment_id: s.id,
            size: s.size,
            access: s.access,
        })
    }

    /// Get all segment info for a session
    pub fn get_session_segments(&self, session_id: SessionId) -> Vec<SegmentInfo> {
        self.segments.values()
            .filter(|s| s.authorized_sessions.contains(&session_id))
            .map(|s| SegmentInfo {
                segment_id: s.id,
                size: s.size,
                access: s.access,
            })
            .collect()
    }
}
```

### 3.3 IAM Server

```rust
// iceoryx2/src/iam/server.rs

use std::collections::HashMap;
use iceoryx2_cal::control_channel::{ControlChannel, ControlChannelListener, ControlChannelConnection};
use iceoryx2_cal::serialize::Serialize;

/// IAM server state
pub struct IamServer<C: ControlChannel, P: IamPolicy> {
    service_id: ServiceId,
    listener: C::Listener,
    sessions: HashMap<SessionId, (ClientSession, C::Connection)>,
    segment_manager: SegmentManager,
    policy: P,
    port_counter: u128,
}

impl<C: ControlChannel, P: IamPolicy> IamServer<C, P> {
    /// Create IAM server for a secured service
    pub fn new(
        service_id: ServiceId,
        endpoint_name: &FileName,
        policy: P,
    ) -> Result<Self, IamServerError> {
        let listener = C::ListenerBuilder::new(endpoint_name)
            .create()
            .map_err(|_| IamServerError::ListenerCreationFailed)?;

        Ok(Self {
            service_id,
            listener,
            sessions: HashMap::new(),
            segment_manager: SegmentManager::new(),
            policy,
            port_counter: 0,
        })
    }

    /// Process pending connections and requests (non-blocking)
    pub fn process(&mut self) -> Result<(), IamServerError> {
        // Accept new connections
        while let Some(connection) = self.listener.try_accept()
            .map_err(|_| IamServerError::AcceptFailed)?
        {
            self.handle_new_connection(connection)?;
        }

        // Process requests from existing sessions
        let session_ids: Vec<_> = self.sessions.keys().copied().collect();
        for session_id in session_ids {
            self.process_session_requests(session_id)?;
        }

        Ok(())
    }

    /// Handle a new client connection
    fn handle_new_connection(&mut self, connection: C::Connection) -> Result<(), IamServerError> {
        // Get peer credentials
        let credentials = connection.peer_credentials()
            .map_err(|_| IamServerError::CredentialsFailed)?;

        // Check if connection is allowed by policy
        let decision = self.policy.authorize_connect(&credentials);
        if decision.is_denied() {
            // Send denial and close
            self.send_response(&connection, IamResponse::Denied {
                reason: DenialReason::Unauthorized,
                message: "Connection not authorized".to_string(),
            })?;
            return Ok(());
        }

        // Create session (not yet authenticated - waiting for Hello)
        let session = ClientSession::new(credentials);
        let session_id = session.id;
        self.sessions.insert(session_id, (session, connection));

        Ok(())
    }

    /// Process requests for a session
    fn process_session_requests(&mut self, session_id: SessionId) -> Result<(), IamServerError> {
        let mut buffer = [0u8; 4096];

        // Try to receive a request
        let (session, connection) = match self.sessions.get_mut(&session_id) {
            Some(s) => s,
            None => return Ok(()),
        };

        let received = match connection.try_receive(&mut buffer) {
            Ok(Some(n)) => n,
            Ok(None) => return Ok(()), // No data available
            Err(_) => {
                // Connection error - remove session
                self.remove_session(session_id);
                return Ok(());
            }
        };

        // Deserialize request
        let request: IamRequest = match postcard::from_bytes(&buffer[..received]) {
            Ok(r) => r,
            Err(_) => {
                self.send_response_to_session(session_id, IamResponse::ProtocolError {
                    message: "Failed to deserialize request".to_string(),
                })?;
                return Ok(());
            }
        };

        // Handle request
        let response = self.handle_request(session_id, request)?;
        self.send_response_to_session(session_id, response)?;

        Ok(())
    }

    /// Handle a single request
    fn handle_request(
        &mut self,
        session_id: SessionId,
        request: IamRequest,
    ) -> Result<IamResponse, IamServerError> {
        let (session, _connection) = self.sessions.get(&session_id)
            .ok_or(IamServerError::SessionNotFound)?;
        let credentials = &session.credentials;

        match request {
            IamRequest::Hello { protocol_version, node_id } => {
                if !protocol_version.is_compatible_with(&ProtocolVersion::CURRENT) {
                    return Ok(IamResponse::Denied {
                        reason: DenialReason::VersionMismatch,
                        message: format!(
                            "Version {}.{} not compatible with {}.{}",
                            protocol_version.major, protocol_version.minor,
                            ProtocolVersion::CURRENT.major, ProtocolVersion::CURRENT.minor
                        ),
                    });
                }

                Ok(IamResponse::HelloOk {
                    negotiated_version: ProtocolVersion::CURRENT,
                    session_id,
                })
            }

            IamRequest::AttachPublisher { service_id, history_size, max_slice_len } => {
                // Check authorization
                let decision = self.policy.authorize_attach(
                    credentials,
                    &service_id,
                    PortType::Publisher,
                );

                if let PolicyDecision::Deny { reason, message } = decision {
                    return Ok(IamResponse::Denied { reason, message });
                }

                // Allocate port ID
                let port_id = self.allocate_port_id();

                // Create or get segment
                let segment_size = Self::calculate_publisher_segment_size(history_size, max_slice_len);
                let segment_id = self.segment_manager.create_segment(
                    segment_size,
                    AccessRights::read_write(),
                )?;

                // Authorize session for segment
                let _handle = self.segment_manager.authorize_session(segment_id, session_id)?;

                // Update session
                let (session, _) = self.sessions.get_mut(&session_id).unwrap();
                session.add_port(port_id);
                session.grant_segment(segment_id);

                Ok(IamResponse::AttachOk {
                    port_id,
                    segment_info: vec![SegmentInfo {
                        segment_id,
                        size: segment_size,
                        access: AccessRights::read_write(),
                    }],
                    handle_count: 1,
                })
            }

            IamRequest::AttachSubscriber { service_id, buffer_size } => {
                // Similar to publisher but with read-only access
                let decision = self.policy.authorize_attach(
                    credentials,
                    &service_id,
                    PortType::Subscriber,
                );

                if let PolicyDecision::Deny { reason, message } = decision {
                    return Ok(IamResponse::Denied { reason, message });
                }

                let port_id = self.allocate_port_id();

                // Subscribers get read access to existing segments
                let segments = self.segment_manager.get_session_segments(session_id);
                let handle_count = segments.len();

                let (session, _) = self.sessions.get_mut(&session_id).unwrap();
                session.add_port(port_id);

                Ok(IamResponse::AttachOk {
                    port_id,
                    segment_info: segments,
                    handle_count,
                })
            }

            IamRequest::Detach { service_id, port_id } => {
                let (session, _) = self.sessions.get_mut(&session_id).unwrap();
                session.remove_port(port_id);
                Ok(IamResponse::DetachOk)
            }

            IamRequest::AckSegmentRetirement { service_id, segment_id } => {
                let retired = self.segment_manager.ack_retirement(segment_id, session_id);
                Ok(IamResponse::AckOk)
            }

            _ => Ok(IamResponse::ProtocolError {
                message: "Request type not yet implemented".to_string(),
            }),
        }
    }

    /// Send handles after response
    fn send_handles_to_session(
        &mut self,
        session_id: SessionId,
        handles: &[PlatformHandle],
    ) -> Result<(), IamServerError> {
        let (_, connection) = self.sessions.get(&session_id)
            .ok_or(IamServerError::SessionNotFound)?;

        connection.send_handles(handles)
            .map_err(|_| IamServerError::HandlePassingFailed)
    }

    /// Broadcast notification to all sessions with a segment
    pub fn broadcast_segment_update(
        &mut self,
        segment_id: SegmentId,
    ) -> Result<(), IamServerError> {
        let segment = self.segment_manager.get_segment_info(segment_id)
            .ok_or(IamServerError::SegmentNotFound)?;

        let notification = IamNotification::SegmentUpdate {
            segment_id,
            size: segment.size,
            handle_count: 1,
        };

        let bytes = postcard::to_allocvec(&notification)
            .map_err(|_| IamServerError::SerializationError)?;

        // Get all sessions authorized for this segment
        let authorized: Vec<_> = self.sessions.iter()
            .filter(|(_, (session, _))| session.granted_segments.contains(&segment_id))
            .map(|(id, _)| *id)
            .collect();

        for session_id in authorized {
            if let Some((_, connection)) = self.sessions.get(&session_id) {
                let _ = connection.send(&bytes); // Ignore individual failures
            }
        }

        Ok(())
    }

    fn allocate_port_id(&mut self) -> UniquePortId {
        self.port_counter += 1;
        self.port_counter
    }

    fn calculate_publisher_segment_size(history_size: usize, max_slice_len: usize) -> usize {
        // Rough calculation - actual implementation should match service requirements
        (history_size + 1) * max_slice_len + 4096 // Header overhead
    }

    fn remove_session(&mut self, session_id: SessionId) {
        self.segment_manager.revoke_session(session_id);
        self.sessions.remove(&session_id);
    }

    fn send_response_to_session(
        &self,
        session_id: SessionId,
        response: IamResponse,
    ) -> Result<(), IamServerError> {
        let (_, connection) = self.sessions.get(&session_id)
            .ok_or(IamServerError::SessionNotFound)?;

        let bytes = postcard::to_allocvec(&response)
            .map_err(|_| IamServerError::SerializationError)?;

        connection.send(&bytes)
            .map_err(|_| IamServerError::SendFailed)
    }
}
```

### Phase 3 Deliverables

1. `iceoryx2/src/iam/session.rs` - Session management (~100 lines)
2. `iceoryx2/src/iam/segment_manager.rs` - Segment lifecycle (~200 lines)
3. `iceoryx2/src/iam/server.rs` - IAM server (~500 lines)
4. Unit tests for session management
5. Unit tests for segment manager

### Phase 3 Review Criteria

- [ ] Server handles concurrent sessions correctly
- [ ] Session cleanup is complete on disconnect
- [ ] Segment authorization is properly tracked
- [ ] Handle cloning for multiple clients works
- [ ] Retirement protocol is correctly implemented
- [ ] Error handling is comprehensive
- [ ] No resource leaks (handles, memory)
- [ ] Policy is correctly enforced at all decision points

---

## Phase 4: IAM Client Library

**Location**: `iceoryx2/src/iam/client.rs`

### 4.1 IAM Client

```rust
// iceoryx2/src/iam/client.rs

use std::collections::HashMap;
use iceoryx2_cal::control_channel::{ControlChannel, ControlChannelClient};

/// IAM client for connecting to secured services
pub struct IamClient<C: ControlChannel> {
    connection: C::Client,
    session_id: Option<SessionId>,
    received_segments: HashMap<SegmentId, PlatformHandle>,
    pending_notifications: Vec<IamNotification>,
}

impl<C: ControlChannel> IamClient<C> {
    /// Connect to IAM endpoint
    pub fn connect(endpoint_name: &FileName) -> Result<Self, IamClientError> {
        let connection = C::ClientBuilder::new(endpoint_name)
            .connect()
            .map_err(|_| IamClientError::ConnectionFailed)?;

        Ok(Self {
            connection,
            session_id: None,
            received_segments: HashMap::new(),
            pending_notifications: Vec::new(),
        })
    }

    /// Connect with timeout
    pub fn try_connect(
        endpoint_name: &FileName,
        timeout: Duration,
    ) -> Result<Self, IamClientError> {
        let connection = C::ClientBuilder::new(endpoint_name)
            .try_connect(timeout)
            .map_err(|_| IamClientError::ConnectionFailed)?
            .ok_or(IamClientError::Timeout)?;

        Ok(Self {
            connection,
            session_id: None,
            received_segments: HashMap::new(),
            pending_notifications: Vec::new(),
        })
    }

    /// Perform handshake
    pub fn handshake(&mut self, node_id: UniqueSystemId) -> Result<SessionId, IamClientError> {
        let request = IamRequest::Hello {
            protocol_version: ProtocolVersion::CURRENT,
            node_id,
        };

        let response = self.send_request(request)?;

        match response {
            IamResponse::HelloOk { negotiated_version, session_id } => {
                self.session_id = Some(session_id);
                Ok(session_id)
            }
            IamResponse::Denied { reason, message } => {
                Err(IamClientError::HandshakeFailed)
            }
            _ => Err(IamClientError::ProtocolError),
        }
    }

    /// Attach as publisher
    pub fn attach_publisher(
        &mut self,
        service_id: ServiceId,
        history_size: usize,
        max_slice_len: usize,
    ) -> Result<AttachResult, IamClientError> {
        let request = IamRequest::AttachPublisher {
            service_id,
            history_size,
            max_slice_len,
        };

        let response = self.send_request(request)?;
        self.process_attach_response(response)
    }

    /// Attach as subscriber
    pub fn attach_subscriber(
        &mut self,
        service_id: ServiceId,
        buffer_size: usize,
    ) -> Result<AttachResult, IamClientError> {
        let request = IamRequest::AttachSubscriber {
            service_id,
            buffer_size,
        };

        let response = self.send_request(request)?;
        self.process_attach_response(response)
    }

    /// Request additional segment
    pub fn add_segment(
        &mut self,
        service_id: ServiceId,
        port_id: UniquePortId,
        requested_size: usize,
    ) -> Result<HandleBundle, IamClientError> {
        let request = IamRequest::AddSegment {
            service_id,
            port_id,
            requested_size,
        };

        let response = self.send_request(request)?;

        match response {
            IamResponse::AddSegmentOk { segment_id, size, handle_count } => {
                let handles = self.receive_handles(handle_count)?;
                let handle = handles.into_iter().next()
                    .ok_or(IamClientError::HandleReceiveFailed)?;

                self.received_segments.insert(segment_id, handle.try_clone()
                    .map_err(|_| IamClientError::HandleReceiveFailed)?);

                Ok(HandleBundle::new(
                    handle,
                    segment_id,
                    AccessRights::read_write(),
                    size,
                ))
            }
            IamResponse::Denied { reason, message } => {
                Err(IamClientError::RequestDenied)
            }
            _ => Err(IamClientError::ProtocolError),
        }
    }

    /// Acknowledge segment retirement
    pub fn ack_retirement(
        &mut self,
        service_id: ServiceId,
        segment_id: SegmentId,
    ) -> Result<(), IamClientError> {
        let request = IamRequest::AckSegmentRetirement {
            service_id,
            segment_id,
        };

        let response = self.send_request(request)?;

        match response {
            IamResponse::AckOk => {
                self.received_segments.remove(&segment_id);
                Ok(())
            }
            _ => Err(IamClientError::ProtocolError),
        }
    }

    /// Detach from service
    pub fn detach(
        &mut self,
        service_id: ServiceId,
        port_id: UniquePortId,
    ) -> Result<(), IamClientError> {
        let request = IamRequest::Detach {
            service_id,
            port_id,
        };

        let response = self.send_request(request)?;

        match response {
            IamResponse::DetachOk => Ok(()),
            _ => Err(IamClientError::ProtocolError),
        }
    }

    /// Poll for notifications (non-blocking)
    pub fn poll_notification(&mut self) -> Result<Option<IamNotification>, IamClientError> {
        // Check pending queue first
        if !self.pending_notifications.is_empty() {
            return Ok(Some(self.pending_notifications.remove(0)));
        }

        // Try to receive
        let mut buffer = [0u8; 4096];
        match self.connection.try_receive(&mut buffer) {
            Ok(Some(n)) => {
                let notification: IamNotification = postcard::from_bytes(&buffer[..n])
                    .map_err(|_| IamClientError::SerializationError)?;
                Ok(Some(notification))
            }
            Ok(None) => Ok(None),
            Err(_) => Err(IamClientError::ReceiveFailed),
        }
    }

    /// Get handle for a segment
    pub fn get_segment_handle(&self, segment_id: SegmentId) -> Option<&PlatformHandle> {
        self.received_segments.get(&segment_id)
    }

    /// Take ownership of a segment handle
    pub fn take_segment_handle(&mut self, segment_id: SegmentId) -> Option<PlatformHandle> {
        self.received_segments.remove(&segment_id)
    }

    // Internal helpers

    fn send_request(&mut self, request: IamRequest) -> Result<IamResponse, IamClientError> {
        let bytes = postcard::to_allocvec(&request)
            .map_err(|_| IamClientError::SerializationError)?;

        self.connection.send(&bytes)
            .map_err(|_| IamClientError::SendFailed)?;

        self.receive_response()
    }

    fn receive_response(&mut self) -> Result<IamResponse, IamClientError> {
        let mut buffer = [0u8; 4096];
        let n = self.connection.blocking_receive(&mut buffer)
            .map_err(|_| IamClientError::ReceiveFailed)?;

        postcard::from_bytes(&buffer[..n])
            .map_err(|_| IamClientError::SerializationError)
    }

    fn receive_handles(&mut self, count: usize) -> Result<Vec<PlatformHandle>, IamClientError> {
        self.connection.blocking_receive_handles(count)
            .map_err(|_| IamClientError::HandleReceiveFailed)
    }

    fn process_attach_response(
        &mut self,
        response: IamResponse,
    ) -> Result<AttachResult, IamClientError> {
        match response {
            IamResponse::AttachOk { port_id, segment_info, handle_count } => {
                let handles = self.receive_handles(handle_count)?;

                // Store handles with segment IDs
                let mut bundles = Vec::new();
                for (info, handle) in segment_info.iter().zip(handles.into_iter()) {
                    self.received_segments.insert(info.segment_id, handle.try_clone()
                        .map_err(|_| IamClientError::HandleReceiveFailed)?);

                    bundles.push(HandleBundle::new(
                        handle,
                        info.segment_id,
                        info.access,
                        info.size,
                    ));
                }

                Ok(AttachResult {
                    port_id,
                    segments: bundles,
                })
            }
            IamResponse::Denied { reason, message } => {
                Err(IamClientError::RequestDenied)
            }
            _ => Err(IamClientError::ProtocolError),
        }
    }
}

/// Result of successful attach operation
#[derive(Debug)]
pub struct AttachResult {
    pub port_id: UniquePortId,
    pub segments: Vec<HandleBundle>,
}
```

### Phase 4 Deliverables

1. `iceoryx2/src/iam/client.rs` - IAM client (~350 lines)
2. Unit tests for client handshake
3. Unit tests for attach operations
4. Unit tests for notification handling

### Phase 4 Review Criteria

- [ ] Client handles connection failures gracefully
- [ ] Handshake properly validates versions
- [ ] Handles are correctly received and stored
- [ ] Segment retirement acknowledgment works
- [ ] Notification polling is non-blocking
- [ ] Error mapping is complete
- [ ] No handle leaks on error paths

---

## Phase 5: Integration Tests

**Location**: `iceoryx2/src/iam/tests/`

### 5.1 End-to-End Tests

```rust
// iceoryx2/src/iam/tests/integration_tests.rs

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn test_single_publisher_subscriber() {
        // Create server with default policy
        let policy = DefaultPolicy::new();
        let mut server = IamServer::<UnixStreamControlChannel, _>::new(
            ServiceId::new(),
            &FileName::new(b"test_iam").unwrap(),
            policy,
        ).unwrap();

        // Spawn server thread
        let server_handle = thread::spawn(move || {
            for _ in 0..100 {
                server.process().unwrap();
                thread::sleep(Duration::from_millis(10));
            }
        });

        // Connect publisher client
        let mut pub_client = IamClient::<UnixStreamControlChannel>::connect(
            &FileName::new(b"test_iam").unwrap(),
        ).unwrap();

        let session_id = pub_client.handshake(UniqueSystemId::new()).unwrap();
        let pub_result = pub_client.attach_publisher(
            ServiceId::new(),
            8,  // history
            1024, // max_slice_len
        ).unwrap();

        assert!(!pub_result.segments.is_empty());

        // Connect subscriber client
        let mut sub_client = IamClient::<UnixStreamControlChannel>::connect(
            &FileName::new(b"test_iam").unwrap(),
        ).unwrap();

        sub_client.handshake(UniqueSystemId::new()).unwrap();
        let sub_result = sub_client.attach_subscriber(
            ServiceId::new(),
            16, // buffer_size
        ).unwrap();

        // Verify subscriber received handles
        assert!(!sub_result.segments.is_empty());

        server_handle.join().unwrap();
    }

    #[test]
    fn test_unauthorized_attach_denied() {
        // Create server with restrictive policy
        let policy = DefaultPolicy::with_owner(99999); // Non-existent UID
        let mut server = IamServer::<UnixStreamControlChannel, _>::new(
            ServiceId::new(),
            &FileName::new(b"test_deny").unwrap(),
            policy,
        ).unwrap();

        thread::spawn(move || {
            for _ in 0..50 {
                server.process().unwrap();
                thread::sleep(Duration::from_millis(10));
            }
        });

        let mut client = IamClient::<UnixStreamControlChannel>::connect(
            &FileName::new(b"test_deny").unwrap(),
        ).unwrap();

        client.handshake(UniqueSystemId::new()).unwrap();
        let result = client.attach_publisher(
            ServiceId::new(),
            8,
            1024,
        );

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), IamClientError::RequestDenied));
    }

    #[test]
    fn test_segment_retirement_protocol() {
        // Test that segment retirement acks work correctly
        // ...
    }

    #[test]
    fn test_multiple_concurrent_clients() {
        // Test with N concurrent clients
        // ...
    }

    #[test]
    fn test_client_disconnect_cleanup() {
        // Verify session cleanup on disconnect
        // ...
    }
}
```

### Phase 5 Deliverables

1. `iceoryx2/src/iam/tests/integration_tests.rs` (~400 lines)
2. Multi-threaded test infrastructure
3. Stress tests with many clients
4. Error scenario coverage

### Phase 5 Review Criteria

- [ ] Tests cover happy path for all operations
- [ ] Tests cover error scenarios
- [ ] Tests verify credential enforcement
- [ ] Tests verify handle passing works
- [ ] Tests don't have race conditions
- [ ] Tests clean up resources properly
- [ ] Tests run on both Linux and Windows (where applicable)

---

## Review Process

For each phase:

1. **Implementation Agent** creates the code following this plan
2. **3 Sonnet Reviewers** independently review for:
   - Correctness (does it match spec?)
   - Idiomatic Rust (follows codebase patterns?)
   - Performance (no unnecessary allocations/copies?)
   - Safety (no UB, proper error handling?)
   - Security (authorization checks complete?)
3. **Decision**:
   - If all 3 approve: proceed to next phase
   - If any reject: loop back with specific changes
   - Rejection must include concrete fix suggestions

### Reviewer Guidelines

Reviewers must NOT be positively biased. The goal is quality, not approval. Each reviewer should:

1. Actively look for problems
2. Question design decisions
3. Check edge cases
4. Verify error handling completeness
5. Look for potential panics
6. Check for resource leaks
7. Verify thread safety where applicable

A "pass" means "I cannot find issues that would cause problems in production."
A "fail" means "I found specific issues that must be fixed before this code is acceptable."

---

## Estimated Total Scope

| Phase | Lines | Files |
|-------|-------|-------|
| Phase 1: Protocol | ~450 | 3 |
| Phase 2: Policy | ~250 | 1 |
| Phase 3: Server | ~800 | 3 |
| Phase 4: Client | ~400 | 1 |
| Phase 5: Tests | ~400 | 1 |
| **Total** | **~2300** | **9** |

This aligns with the proposal's estimate of 3000-4000 lines for SP5 (accounting for additional error handling, documentation, and edge cases discovered during implementation).
