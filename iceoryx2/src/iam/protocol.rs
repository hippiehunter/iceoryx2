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

//! IAM protocol types for client-server communication.
//!
//! This module defines the protocol messages exchanged between IAM clients
//! and the IAM server for secured inter-process communication.
//!
//! # Protocol Limits
//!
//! The protocol enforces the following limits to prevent resource exhaustion:
//! - Maximum segments per attach response: 256
//! - Maximum handles per message: 64
//! - Maximum error message length: 512 bytes
//!
//! Implementations MUST validate these limits when deserializing messages
//! from untrusted sources.

use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use iceoryx2_bb_posix::unique_system_id::UniqueSystemId;
use iceoryx2_cal::security::AccessRights;
use iceoryx2_cal::shm_allocator::SegmentId;
use serde::{Deserialize, Serialize};

use crate::service::service_id::ServiceId;
use crate::service::service_name::ServiceName;

// ============================================================================
// Protocol Constants
// ============================================================================

/// Maximum number of segments that can be returned in a single attach response.
pub const MAX_SEGMENTS_PER_ATTACH: usize = 256;

/// Maximum number of handles that can be passed in a single message.
pub const MAX_HANDLES_PER_MESSAGE: usize = 64;

/// Maximum length of error messages in bytes.
pub const MAX_ERROR_MESSAGE_LENGTH: usize = 512;

// ============================================================================
// ProtocolVersion
// ============================================================================

/// The protocol version for IAM client-server communication.
///
/// Used during the handshake phase to negotiate a compatible protocol version
/// between the client and server.
///
/// # Version Compatibility
///
/// Protocol versions follow semantic versioning principles:
/// - Major version changes indicate breaking protocol changes
/// - Minor version changes add features while remaining backward compatible
///
/// A client with version X.Y can communicate with a server with version X.Z
/// if and only if Y <= Z. This allows servers to support older clients.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ProtocolVersion {
    major: u16,
    minor: u16,
}

impl ProtocolVersion {
    /// The current protocol version (1.0).
    pub const CURRENT: ProtocolVersion = ProtocolVersion { major: 1, minor: 0 };

    /// Creates a new protocol version with the given major and minor numbers.
    pub const fn new(major: u16, minor: u16) -> Self {
        Self { major, minor }
    }

    /// Returns the major version number.
    pub const fn major(&self) -> u16 {
        self.major
    }

    /// Returns the minor version number.
    pub const fn minor(&self) -> u16 {
        self.minor
    }

    /// Checks if a client with this version can communicate with a server.
    ///
    /// A client is compatible with a server when:
    /// - Major versions match exactly
    /// - Client minor version is less than or equal to server minor version
    ///
    /// This method should be called as `client_version.is_compatible_with(&server_version)`.
    ///
    /// # Example
    /// ```
    /// use iceoryx2::iam::ProtocolVersion;
    ///
    /// let client_v1_0 = ProtocolVersion::new(1, 0);
    /// let server_v1_1 = ProtocolVersion::new(1, 1);
    ///
    /// // Client 1.0 can talk to server 1.1
    /// assert!(client_v1_0.is_compatible_with(&server_v1_1));
    ///
    /// // But client 1.1 cannot talk to server 1.0 (missing features)
    /// assert!(!server_v1_1.is_compatible_with(&client_v1_0));
    /// ```
    pub const fn is_compatible_with(&self, server: &ProtocolVersion) -> bool {
        self.major == server.major && self.minor <= server.minor
    }

    /// Checks if this server version can accept a client version.
    ///
    /// This is a convenience method equivalent to `client.is_compatible_with(self)`.
    pub const fn accepts_client(&self, client: &ProtocolVersion) -> bool {
        client.major == self.major && client.minor <= self.minor
    }
}

impl Default for ProtocolVersion {
    fn default() -> Self {
        Self::CURRENT
    }
}

// ============================================================================
// SessionId
// ============================================================================

/// A unique identifier for an IAM session.
///
/// Sessions are established during the handshake and used to track client
/// connections throughout their lifetime.
///
/// # Session ID Generation
///
/// Session IDs are generated using a monotonically increasing atomic counter.
/// The counter starts at 1 (0 is reserved as an invalid/uninitialized value).
/// In the extremely unlikely event of counter exhaustion (after 2^64-1 sessions),
/// the server must be restarted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SessionId(u64);

/// Reserved value indicating an invalid or uninitialized session.
pub const INVALID_SESSION_ID: SessionId = SessionId(0);

impl SessionId {
    /// Creates a new unique session ID using an atomic counter.
    ///
    /// # Panics
    ///
    /// Panics if the session ID counter has wrapped around to 0, which would
    /// only occur after 2^64-1 session creations. This indicates the IAM
    /// server must be restarted.
    pub fn new() -> Self {
        static COUNTER: AtomicU64 = AtomicU64::new(1);
        let id = COUNTER.fetch_add(1, Ordering::Relaxed);

        // Check for counter wrap-around (would take ~584 million years at 1M sessions/sec)
        // but we still guard against it for correctness
        if id == 0 {
            panic!("SessionId counter overflow - IAM server must be restarted");
        }

        Self(id)
    }

    /// Creates a session ID from a raw value.
    ///
    /// This is primarily used for deserialization and testing.
    /// A value of 0 represents an invalid session.
    pub const fn from_value(value: u64) -> Self {
        Self(value)
    }

    /// Returns the underlying value of the session ID.
    pub const fn value(&self) -> u64 {
        self.0
    }

    /// Returns true if this is a valid session ID (non-zero).
    pub const fn is_valid(&self) -> bool {
        self.0 != 0
    }
}

impl Default for SessionId {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// SegmentInfo
// ============================================================================

/// Information about a shared memory segment.
///
/// This structure contains metadata about a segment that is passed to clients
/// when they attach to a service.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SegmentInfo {
    /// The unique identifier of the segment.
    segment_id: SegmentId,
    /// The size of the segment in bytes.
    size: usize,
    /// The access rights granted for this segment.
    access: AccessRights,
}

impl SegmentInfo {
    /// Creates a new segment info with the given parameters.
    pub const fn new(segment_id: SegmentId, size: usize, access: AccessRights) -> Self {
        Self {
            segment_id,
            size,
            access,
        }
    }

    /// Returns the segment identifier.
    pub const fn segment_id(&self) -> SegmentId {
        self.segment_id
    }

    /// Returns the size of the segment in bytes.
    pub const fn size(&self) -> usize {
        self.size
    }

    /// Returns the access rights for the segment.
    pub const fn access(&self) -> AccessRights {
        self.access
    }
}

// ============================================================================
// Enums
// ============================================================================

/// The type of communication port.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PortType {
    /// A publisher port that sends data to subscribers.
    Publisher,
    /// A subscriber port that receives data from publishers.
    Subscriber,
    /// A server port that responds to client requests.
    Server,
    /// A client port that sends requests to servers.
    Client,
}

/// The kind of messaging pattern for a service.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MessagingPatternKind {
    /// Publish-subscribe messaging pattern.
    PublishSubscribe,
    /// Request-response messaging pattern.
    RequestResponse,
    /// Event-based messaging pattern.
    Event,
}

/// Reasons why a request may be denied.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DenialReason {
    /// The client is not authorized to perform the requested action.
    Unauthorized,
    /// The requested service was not found.
    ServiceNotFound,
    /// A service with the same name already exists.
    ServiceAlreadyExists,
    /// A resource limit has been exceeded.
    ResourceLimitExceeded,
    /// The requested QoS settings are incompatible.
    IncompatibleQos,
    /// The request violates a policy.
    PolicyViolation,
    /// An internal error occurred.
    InternalError,
    /// Protocol version mismatch.
    VersionMismatch,
    /// The session was not found or has expired.
    SessionNotFound,
    /// The request contains invalid parameters.
    InvalidRequest,
}

// ============================================================================
// IamRequest
// ============================================================================

/// Requests that can be sent from an IAM client to the IAM server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IamRequest {
    /// Initial handshake request to establish a session.
    Hello {
        /// The protocol version supported by the client.
        protocol_version: ProtocolVersion,
        /// The unique identifier of the client's node.
        node_id: UniqueSystemId,
    },

    /// Request to create a new secured service.
    CreateService {
        /// The name of the service to create.
        service_name: ServiceName,
        /// The messaging pattern for the service.
        messaging_pattern: MessagingPatternKind,
    },

    /// Request to attach a publisher to a service.
    AttachPublisher {
        /// The service to attach to.
        service_id: ServiceId,
        /// The history size for the publisher.
        history_size: usize,
        /// The maximum slice length for samples.
        max_slice_len: usize,
    },

    /// Request to attach a subscriber to a service.
    AttachSubscriber {
        /// The service to attach to.
        service_id: ServiceId,
        /// The buffer size for the subscriber.
        buffer_size: usize,
    },

    /// Request to attach a server to a service.
    AttachServer {
        /// The service to attach to.
        service_id: ServiceId,
        /// The maximum number of active requests.
        max_active_requests: usize,
    },

    /// Request to attach a client to a service.
    AttachClient {
        /// The service to attach to.
        service_id: ServiceId,
        /// The maximum number of pending responses.
        max_pending_responses: usize,
    },

    /// Request to add a new segment for a port.
    ///
    /// IAM creates the segment and returns a handle to the producer.
    AddSegment {
        /// The service the port belongs to.
        service_id: ServiceId,
        /// The port identifier.
        port_id: u128,
        /// The requested size for the new segment (payload size).
        requested_size: usize,
        /// The bucket size for the pool allocator.
        bucket_size: usize,
        /// The bucket alignment for the pool allocator.
        bucket_align: usize,
    },

    /// Request to detach a port from a service.
    Detach {
        /// The service the port belongs to.
        service_id: ServiceId,
        /// The port identifier.
        port_id: u128,
    },

    /// Acknowledge that a segment has been retired.
    AckSegmentRetirement {
        /// The service the segment belongs to.
        service_id: ServiceId,
        /// The segment identifier.
        segment_id: SegmentId,
    },

    /// Register a segment handle created by a producer port.
    ///
    /// The producer (publisher/server) creates an anonymous shared memory
    /// segment locally and sends the handle to the IAM server for brokering
    /// to authorized consumers.
    RegisterSegment {
        /// The service the port belongs to.
        service_id: ServiceId,
        /// The producer port identifier.
        port_id: u128,
        /// The size of the segment in bytes.
        segment_size: usize,
        /// The number of handles that will follow this message.
        handle_count: usize,
    },

    /// Request a segment handle for a sender port's data segment.
    ///
    /// Consumers (subscriber/client) use this to obtain handles to producer
    /// data segments brokered through the IAM server.
    RequestSegmentHandle {
        /// The service the port belongs to.
        service_id: ServiceId,
        /// The producer port whose segment handle is requested.
        sender_port_id: u128,
    },

    /// Register a dynamic segment handle created by a producer port.
    ///
    /// Used for resizable shared memory segments. The producer creates an
    /// anonymous segment and registers it with an index (segment_id) within
    /// its dynamic segment set.
    RegisterDynamicSegment {
        /// The service the port belongs to.
        service_id: ServiceId,
        /// The producer port identifier.
        port_id: u128,
        /// Index within the dynamic segment set (0 for initial, 1+ for reallocations).
        segment_id: u8,
        /// The size of the segment in bytes.
        segment_size: usize,
        /// The number of handles that will follow this message.
        handle_count: usize,
    },

    /// Request a specific dynamic segment handle from a producer port.
    ///
    /// Consumers use this to obtain handles to specific segments within a
    /// producer's dynamic segment set, identified by segment_id index.
    RequestDynamicSegmentHandle {
        /// The service the port belongs to.
        service_id: ServiceId,
        /// The producer port whose segment handle is requested.
        sender_port_id: u128,
        /// The index of the dynamic segment to retrieve.
        segment_id: u8,
    },
}

// ============================================================================
// IamResponse
// ============================================================================

/// Responses sent from the IAM server to clients.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IamResponse {
    /// Successful response to a Hello request.
    HelloOk {
        /// The negotiated protocol version.
        negotiated_version: ProtocolVersion,
        /// The assigned session identifier.
        session_id: SessionId,
    },

    /// Successful response to a CreateService request.
    CreateServiceOk {
        /// The assigned service identifier.
        service_id: ServiceId,
    },

    /// Successful response to an attach request.
    AttachOk {
        /// The assigned port identifier.
        port_id: u128,
        /// Information about the segments for this port.
        segment_info: Vec<SegmentInfo>,
        /// The number of handles that will be passed.
        handle_count: usize,
    },

    /// Successful response to an AddSegment request.
    AddSegmentOk {
        /// The identifier of the new segment.
        segment_id: SegmentId,
        /// The actual size of the segment.
        size: usize,
        /// The number of handles that will be passed.
        handle_count: usize,
    },

    /// Successful response to a Detach request.
    DetachOk,

    /// Successful response to an AckSegmentRetirement request.
    AckOk,

    /// The request was denied.
    Denied {
        /// The reason for denial.
        reason: DenialReason,
        /// A human-readable message explaining the denial.
        message: String,
    },

    /// A protocol error occurred.
    ProtocolError {
        /// A human-readable message explaining the error.
        message: String,
    },

    /// Successful response to a RegisterSegment request.
    RegisterSegmentOk {
        /// The segment ID assigned to the registered segment.
        segment_id: SegmentId,
    },

    /// Successful response to a RequestSegmentHandle request — handle available.
    SegmentHandleOk {
        /// Metadata about the segment being provided.
        segment_info: SegmentInfo,
        /// The number of handles that will follow this message.
        handle_count: usize,
    },

    /// Response to a RequestSegmentHandle request — no handle available yet.
    ///
    /// This typically means the producer has not yet registered its segment.
    /// The consumer should retry later.
    SegmentHandleNotFound,

    /// Successful response to a RegisterDynamicSegment request.
    RegisterDynamicSegmentOk {
        /// The segment ID index that was registered.
        segment_id: u8,
    },

    /// Successful response to a RequestDynamicSegmentHandle request — handle available.
    DynamicSegmentHandleOk {
        /// Metadata about the segment being provided.
        segment_info: SegmentInfo,
        /// The number of handles that will follow this message.
        handle_count: usize,
    },

    /// Response to a RequestDynamicSegmentHandle request — segment not registered yet.
    ///
    /// The producer may not have registered this segment index yet. This can occur
    /// during a race condition when a consumer receives an offset referencing a
    /// newly allocated segment before the producer has registered it with IAM.
    /// The consumer should retry later.
    DynamicSegmentPending,
}

// ============================================================================
// IamNotification
// ============================================================================

/// Notifications sent from the IAM server to clients.
///
/// These are asynchronous messages that inform clients about changes
/// in the system.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IamNotification {
    /// A segment has been updated.
    SegmentUpdate {
        /// The segment identifier.
        segment_id: SegmentId,
        /// The new size of the segment.
        size: usize,
        /// The number of handles that will be passed.
        handle_count: usize,
    },

    /// A segment is being retired and should no longer be used.
    SegmentRetiring {
        /// The segment identifier.
        segment_id: SegmentId,
    },

    /// A new port has joined the service.
    PortJoined {
        /// The port identifier.
        port_id: u128,
        /// The type of the port.
        port_type: PortType,
    },

    /// A port has left the service.
    PortLeft {
        /// The port identifier.
        port_id: u128,
    },

    /// The service is stopping and clients should disconnect.
    ServiceStopping,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_protocol_version_current() {
        let version = ProtocolVersion::CURRENT;
        assert_eq!(version.major(), 1);
        assert_eq!(version.minor(), 0);
    }

    #[test]
    fn test_protocol_version_compatibility() {
        let v1_0 = ProtocolVersion::new(1, 0);
        let v1_1 = ProtocolVersion::new(1, 1);
        let v1_2 = ProtocolVersion::new(1, 2);
        let v2_0 = ProtocolVersion::new(2, 0);

        // Same version is compatible
        assert!(v1_0.is_compatible_with(&v1_0));

        // Lower minor is compatible with higher minor (same major)
        assert!(v1_0.is_compatible_with(&v1_1));
        assert!(v1_0.is_compatible_with(&v1_2));
        assert!(v1_1.is_compatible_with(&v1_2));

        // Higher minor is not compatible with lower minor
        assert!(!v1_1.is_compatible_with(&v1_0));
        assert!(!v1_2.is_compatible_with(&v1_0));
        assert!(!v1_2.is_compatible_with(&v1_1));

        // Different major versions are incompatible
        assert!(!v1_0.is_compatible_with(&v2_0));
        assert!(!v2_0.is_compatible_with(&v1_0));
    }

    #[test]
    fn test_protocol_version_serialization_roundtrip() {
        let version = ProtocolVersion::new(1, 2);
        let serialized = postcard::to_allocvec(&version).unwrap();
        let deserialized: ProtocolVersion = postcard::from_bytes(&serialized).unwrap();
        assert_eq!(version, deserialized);
    }

    #[test]
    fn test_session_id_unique() {
        let id1 = SessionId::new();
        let id2 = SessionId::new();
        let id3 = SessionId::new();
        assert_ne!(id1, id2);
        assert_ne!(id2, id3);
        assert_ne!(id1, id3);
    }

    #[test]
    fn test_session_id_from_value() {
        let id = SessionId::from_value(42);
        assert_eq!(id.value(), 42);
    }

    #[test]
    fn test_session_id_serialization_roundtrip() {
        let id = SessionId::from_value(12345);
        let serialized = postcard::to_allocvec(&id).unwrap();
        let deserialized: SessionId = postcard::from_bytes(&serialized).unwrap();
        assert_eq!(id, deserialized);
    }

    #[test]
    fn test_segment_info_accessors() {
        let info = SegmentInfo::new(SegmentId::new(5), 4096, AccessRights::read_write());
        assert_eq!(info.segment_id().value(), 5);
        assert_eq!(info.size(), 4096);
        assert!(info.access().can_read());
        assert!(info.access().can_write());
    }

    #[test]
    fn test_segment_info_serialization_roundtrip() {
        let info = SegmentInfo::new(SegmentId::new(3), 8192, AccessRights::read_only());
        let serialized = postcard::to_allocvec(&info).unwrap();
        let deserialized: SegmentInfo = postcard::from_bytes(&serialized).unwrap();
        // Now we can directly compare since SegmentInfo derives PartialEq
        assert_eq!(info, deserialized);
    }

    #[test]
    fn test_segment_info_copy() {
        let info = SegmentInfo::new(SegmentId::new(1), 4096, AccessRights::read_write());
        let copied = info; // Copy
        assert_eq!(info, copied);
    }

    #[test]
    fn test_port_type_serialization_roundtrip() {
        let types = [
            PortType::Publisher,
            PortType::Subscriber,
            PortType::Server,
            PortType::Client,
        ];
        for port_type in types {
            let serialized = postcard::to_allocvec(&port_type).unwrap();
            let deserialized: PortType = postcard::from_bytes(&serialized).unwrap();
            assert_eq!(port_type, deserialized);
        }
    }

    #[test]
    fn test_messaging_pattern_kind_serialization_roundtrip() {
        let patterns = [
            MessagingPatternKind::PublishSubscribe,
            MessagingPatternKind::RequestResponse,
            MessagingPatternKind::Event,
        ];
        for pattern in patterns {
            let serialized = postcard::to_allocvec(&pattern).unwrap();
            let deserialized: MessagingPatternKind = postcard::from_bytes(&serialized).unwrap();
            assert_eq!(pattern, deserialized);
        }
    }

    #[test]
    fn test_denial_reason_serialization_roundtrip() {
        let reasons = [
            DenialReason::Unauthorized,
            DenialReason::ServiceNotFound,
            DenialReason::ServiceAlreadyExists,
            DenialReason::ResourceLimitExceeded,
            DenialReason::IncompatibleQos,
            DenialReason::PolicyViolation,
            DenialReason::InternalError,
            DenialReason::VersionMismatch,
            DenialReason::SessionNotFound,
        ];
        for reason in reasons {
            let serialized = postcard::to_allocvec(&reason).unwrap();
            let deserialized: DenialReason = postcard::from_bytes(&serialized).unwrap();
            assert_eq!(reason, deserialized);
        }
    }

    #[test]
    fn test_iam_request_hello_serialization_roundtrip() {
        let node_id = UniqueSystemId::new().unwrap();
        let request = IamRequest::Hello {
            protocol_version: ProtocolVersion::CURRENT,
            node_id,
        };
        let serialized = postcard::to_allocvec(&request).unwrap();
        let deserialized: IamRequest = postcard::from_bytes(&serialized).unwrap();
        match deserialized {
            IamRequest::Hello {
                protocol_version,
                node_id: deserialized_node_id,
            } => {
                assert_eq!(protocol_version, ProtocolVersion::CURRENT);
                assert_eq!(deserialized_node_id, node_id);
            }
            _ => panic!("Expected Hello request"),
        }
    }

    #[test]
    fn test_iam_response_hello_ok_serialization_roundtrip() {
        let response = IamResponse::HelloOk {
            negotiated_version: ProtocolVersion::CURRENT,
            session_id: SessionId::from_value(100),
        };
        let serialized = postcard::to_allocvec(&response).unwrap();
        let deserialized: IamResponse = postcard::from_bytes(&serialized).unwrap();
        match deserialized {
            IamResponse::HelloOk {
                negotiated_version,
                session_id,
            } => {
                assert_eq!(negotiated_version, ProtocolVersion::CURRENT);
                assert_eq!(session_id.value(), 100);
            }
            _ => panic!("Expected HelloOk response"),
        }
    }

    #[test]
    fn test_iam_response_denied_serialization_roundtrip() {
        let response = IamResponse::Denied {
            reason: DenialReason::Unauthorized,
            message: String::from("Access denied"),
        };
        let serialized = postcard::to_allocvec(&response).unwrap();
        let deserialized: IamResponse = postcard::from_bytes(&serialized).unwrap();
        match deserialized {
            IamResponse::Denied { reason, message } => {
                assert_eq!(reason, DenialReason::Unauthorized);
                assert_eq!(message, "Access denied");
            }
            _ => panic!("Expected Denied response"),
        }
    }

    #[test]
    fn test_iam_notification_segment_update_serialization_roundtrip() {
        let notification = IamNotification::SegmentUpdate {
            segment_id: SegmentId::new(7),
            size: 16384,
            handle_count: 2,
        };
        let serialized = postcard::to_allocvec(&notification).unwrap();
        let deserialized: IamNotification = postcard::from_bytes(&serialized).unwrap();
        match deserialized {
            IamNotification::SegmentUpdate {
                segment_id,
                size,
                handle_count,
            } => {
                assert_eq!(segment_id.value(), 7);
                assert_eq!(size, 16384);
                assert_eq!(handle_count, 2);
            }
            _ => panic!("Expected SegmentUpdate notification"),
        }
    }

    #[test]
    fn test_iam_notification_port_joined_serialization_roundtrip() {
        let notification = IamNotification::PortJoined {
            port_id: 0xDEADBEEF_CAFEBABE,
            port_type: PortType::Publisher,
        };
        let serialized = postcard::to_allocvec(&notification).unwrap();
        let deserialized: IamNotification = postcard::from_bytes(&serialized).unwrap();
        match deserialized {
            IamNotification::PortJoined { port_id, port_type } => {
                assert_eq!(port_id, 0xDEADBEEF_CAFEBABE);
                assert_eq!(port_type, PortType::Publisher);
            }
            _ => panic!("Expected PortJoined notification"),
        }
    }

    #[test]
    fn test_iam_notification_service_stopping_serialization_roundtrip() {
        let notification = IamNotification::ServiceStopping;
        let serialized = postcard::to_allocvec(&notification).unwrap();
        let deserialized: IamNotification = postcard::from_bytes(&serialized).unwrap();
        assert!(matches!(deserialized, IamNotification::ServiceStopping));
    }

    #[test]
    fn test_session_id_is_valid() {
        let valid_id = SessionId::from_value(42);
        assert!(valid_id.is_valid());

        let invalid_id = SessionId::from_value(0);
        assert!(!invalid_id.is_valid());

        assert!(!INVALID_SESSION_ID.is_valid());
    }

    #[test]
    fn test_protocol_version_accepts_client() {
        let server_v1_1 = ProtocolVersion::new(1, 1);
        let client_v1_0 = ProtocolVersion::new(1, 0);
        let client_v1_1 = ProtocolVersion::new(1, 1);
        let client_v1_2 = ProtocolVersion::new(1, 2);

        // Server 1.1 accepts clients 1.0 and 1.1
        assert!(server_v1_1.accepts_client(&client_v1_0));
        assert!(server_v1_1.accepts_client(&client_v1_1));

        // Server 1.1 does not accept client 1.2 (client is newer)
        assert!(!server_v1_1.accepts_client(&client_v1_2));
    }

    #[test]
    fn test_iam_request_create_service_serialization_roundtrip() {
        let service_name = ServiceName::new("test/service").unwrap();
        let request = IamRequest::CreateService {
            service_name: service_name.clone(),
            messaging_pattern: MessagingPatternKind::PublishSubscribe,
        };
        let serialized = postcard::to_allocvec(&request).unwrap();
        let deserialized: IamRequest = postcard::from_bytes(&serialized).unwrap();
        match deserialized {
            IamRequest::CreateService {
                service_name: deser_name,
                messaging_pattern,
            } => {
                assert_eq!(deser_name, service_name);
                assert_eq!(messaging_pattern, MessagingPatternKind::PublishSubscribe);
            }
            _ => panic!("Expected CreateService request"),
        }
    }

    #[test]
    fn test_iam_response_create_service_ok_serialization_roundtrip() {
        use crate::service::messaging_pattern::MessagingPattern;
        use iceoryx2_cal::hash::sha1::Sha1;

        // Create a service ID for testing
        let service_name = ServiceName::new("test/roundtrip").unwrap();
        let service_id = ServiceId::new::<Sha1>(&service_name, MessagingPattern::PublishSubscribe);

        let response = IamResponse::CreateServiceOk { service_id };
        let serialized = postcard::to_allocvec(&response).unwrap();
        let deserialized: IamResponse = postcard::from_bytes(&serialized).unwrap();
        match deserialized {
            IamResponse::CreateServiceOk { service_id: deser_id } => {
                assert_eq!(deser_id, service_id);
            }
            _ => panic!("Expected CreateServiceOk response"),
        }
    }

    #[test]
    fn test_iam_request_register_segment_serialization_roundtrip() {
        use crate::service::messaging_pattern::MessagingPattern;
        use iceoryx2_cal::hash::sha1::Sha1;

        let service_name = ServiceName::new("test/register_segment").unwrap();
        let service_id = ServiceId::new::<Sha1>(&service_name, MessagingPattern::PublishSubscribe);

        let request = IamRequest::RegisterSegment {
            service_id,
            port_id: 0xDEAD_BEEF,
            segment_size: 65536,
            handle_count: 1,
        };
        let serialized = postcard::to_allocvec(&request).unwrap();
        let deserialized: IamRequest = postcard::from_bytes(&serialized).unwrap();
        match deserialized {
            IamRequest::RegisterSegment {
                service_id: deser_id,
                port_id,
                segment_size,
                handle_count,
            } => {
                assert_eq!(deser_id, service_id);
                assert_eq!(port_id, 0xDEAD_BEEF);
                assert_eq!(segment_size, 65536);
                assert_eq!(handle_count, 1);
            }
            _ => panic!("Expected RegisterSegment request"),
        }
    }

    #[test]
    fn test_iam_request_request_segment_handle_serialization_roundtrip() {
        use crate::service::messaging_pattern::MessagingPattern;
        use iceoryx2_cal::hash::sha1::Sha1;

        let service_name = ServiceName::new("test/request_handle").unwrap();
        let service_id = ServiceId::new::<Sha1>(&service_name, MessagingPattern::PublishSubscribe);

        let request = IamRequest::RequestSegmentHandle {
            service_id,
            sender_port_id: 42,
        };
        let serialized = postcard::to_allocvec(&request).unwrap();
        let deserialized: IamRequest = postcard::from_bytes(&serialized).unwrap();
        match deserialized {
            IamRequest::RequestSegmentHandle {
                service_id: deser_id,
                sender_port_id,
            } => {
                assert_eq!(deser_id, service_id);
                assert_eq!(sender_port_id, 42);
            }
            _ => panic!("Expected RequestSegmentHandle request"),
        }
    }

    #[test]
    fn test_iam_response_register_segment_ok_serialization_roundtrip() {
        let response = IamResponse::RegisterSegmentOk {
            segment_id: SegmentId::new(7),
        };
        let serialized = postcard::to_allocvec(&response).unwrap();
        let deserialized: IamResponse = postcard::from_bytes(&serialized).unwrap();
        match deserialized {
            IamResponse::RegisterSegmentOk { segment_id } => {
                assert_eq!(segment_id.value(), 7);
            }
            _ => panic!("Expected RegisterSegmentOk response"),
        }
    }

    #[test]
    fn test_iam_response_segment_handle_ok_serialization_roundtrip() {
        let info = SegmentInfo::new(SegmentId::new(3), 8192, AccessRights::read_only());
        let response = IamResponse::SegmentHandleOk {
            segment_info: info,
            handle_count: 1,
        };
        let serialized = postcard::to_allocvec(&response).unwrap();
        let deserialized: IamResponse = postcard::from_bytes(&serialized).unwrap();
        match deserialized {
            IamResponse::SegmentHandleOk {
                segment_info,
                handle_count,
            } => {
                assert_eq!(segment_info, info);
                assert_eq!(handle_count, 1);
            }
            _ => panic!("Expected SegmentHandleOk response"),
        }
    }

    #[test]
    fn test_iam_response_segment_handle_not_found_serialization_roundtrip() {
        let response = IamResponse::SegmentHandleNotFound;
        let serialized = postcard::to_allocvec(&response).unwrap();
        let deserialized: IamResponse = postcard::from_bytes(&serialized).unwrap();
        assert!(matches!(deserialized, IamResponse::SegmentHandleNotFound));
    }

    #[test]
    fn test_protocol_constants() {
        // Verify constants are reasonable
        assert!(MAX_SEGMENTS_PER_ATTACH > 0);
        assert!(MAX_HANDLES_PER_MESSAGE > 0);
        assert!(MAX_ERROR_MESSAGE_LENGTH > 0);

        // Verify constants match documented values
        assert_eq!(MAX_SEGMENTS_PER_ATTACH, 256);
        assert_eq!(MAX_HANDLES_PER_MESSAGE, 64);
        assert_eq!(MAX_ERROR_MESSAGE_LENGTH, 512);
    }
}
