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

//! Session management for IAM server.
//!
//! This module provides types for tracking client sessions in the IAM server.
//! Each connected client has a [`ClientSession`] that tracks their credentials,
//! attached ports, granted segments, and pending segment retirements.
//!
//! # Session Lifecycle
//!
//! 1. A session is created when a client connects and completes the Hello handshake
//! 2. The session tracks all ports the client attaches to services
//! 3. The session tracks all segments the client has been granted access to
//! 4. When segments are retired, the session tracks pending acknowledgments
//! 5. The session is destroyed when the client disconnects
//!
//! # Example
//!
//! ```ignore
//! use iceoryx2::iam::session::ClientSession;
//! use iceoryx2_cal::security::credentials::ProcessCredentials;
//!
//! let credentials = ProcessCredentials::from_self();
//! let mut session = ClientSession::new(credentials);
//!
//! // Track attached ports
//! session.add_port(42);
//! assert!(session.has_port(42));
//! session.remove_port(42);
//! ```

use std::collections::BTreeSet;
use std::time::Instant;

use iceoryx2_cal::security::credentials::ProcessCredentials;
use iceoryx2_cal::shm_allocator::SegmentId;

/// Type alias for segment ID underlying value used in sets.
/// We use the underlying u8 value since SegmentId doesn't implement Hash/Ord.
type SegmentIdValue = u8;

use super::protocol::SessionId;
use super::PortType;

// ============================================================================
// PortInfo
// ============================================================================

/// Information about an attached port.
///
/// Tracks the port identifier and type for resource accounting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PortInfo {
    /// The unique port identifier (u128 from protocol).
    pub port_id: u128,
    /// The type of port (Publisher, Subscriber, etc.).
    pub port_type: PortType,
}

impl PortInfo {
    /// Creates a new port info entry.
    pub const fn new(port_id: u128, port_type: PortType) -> Self {
        Self { port_id, port_type }
    }
}

// ============================================================================
// SessionResourceUsage
// ============================================================================

/// Tracks cumulative resource usage for a session.
///
/// The IAM server uses this to enforce per-session resource limits.
/// These counters are maintained by the server as ports and segments are
/// created/destroyed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SessionResourceUsage {
    /// Number of publisher ports currently attached.
    pub publisher_count: usize,
    /// Number of subscriber ports currently attached.
    pub subscriber_count: usize,
    /// Number of server ports currently attached.
    pub server_count: usize,
    /// Number of client ports currently attached.
    pub client_count: usize,
    /// Total number of segments granted to this session.
    pub segment_count: usize,
    /// Total memory (in bytes) allocated across all granted segments.
    pub total_memory: usize,
}

impl SessionResourceUsage {
    /// Creates a new usage tracker with all counts at zero.
    pub const fn new() -> Self {
        Self {
            publisher_count: 0,
            subscriber_count: 0,
            server_count: 0,
            client_count: 0,
            segment_count: 0,
            total_memory: 0,
        }
    }

    /// Increments the port count for the given port type.
    pub fn increment_port(&mut self, port_type: PortType) {
        match port_type {
            PortType::Publisher => self.publisher_count += 1,
            PortType::Subscriber => self.subscriber_count += 1,
            PortType::Server => self.server_count += 1,
            PortType::Client => self.client_count += 1,
        }
    }

    /// Decrements the port count for the given port type.
    ///
    /// Uses saturating subtraction to prevent underflow.
    pub fn decrement_port(&mut self, port_type: PortType) {
        match port_type {
            PortType::Publisher => self.publisher_count = self.publisher_count.saturating_sub(1),
            PortType::Subscriber => self.subscriber_count = self.subscriber_count.saturating_sub(1),
            PortType::Server => self.server_count = self.server_count.saturating_sub(1),
            PortType::Client => self.client_count = self.client_count.saturating_sub(1),
        }
    }

    /// Records a segment grant of the given size.
    pub fn add_segment(&mut self, size: usize) {
        self.segment_count += 1;
        self.total_memory = self.total_memory.saturating_add(size);
    }

    /// Records a segment revocation of the given size.
    ///
    /// Uses saturating subtraction to prevent underflow.
    pub fn remove_segment(&mut self, size: usize) {
        self.segment_count = self.segment_count.saturating_sub(1);
        self.total_memory = self.total_memory.saturating_sub(size);
    }
}

// ============================================================================
// ClientSession
// ============================================================================

/// Client session state tracked by the IAM server.
///
/// Each connected client has a session that tracks:
/// - The unique session identifier
/// - The client's process credentials (PID, UID, GID)
/// - When the client authenticated
/// - All ports the client has attached
/// - All segments the client has been granted access to
/// - Segments pending retirement acknowledgment
/// - Cumulative resource usage for limit enforcement
///
/// # Thread Safety
///
/// `ClientSession` is not `Sync` - it is designed to be owned by a single
/// server instance. The server is responsible for synchronizing access if needed.
#[derive(Debug)]
pub struct ClientSession {
    /// The unique session identifier.
    id: SessionId,
    /// The client's process credentials.
    credentials: ProcessCredentials,
    /// When the session was created (client authenticated).
    authenticated_at: Instant,
    /// Ports the client has attached to.
    attached_ports: Vec<PortInfo>,
    /// Segments the client has been granted access to (stored as underlying values).
    granted_segments: BTreeSet<SegmentIdValue>,
    /// Segments pending retirement acknowledgment from this client (stored as underlying values).
    pending_retirements: BTreeSet<SegmentIdValue>,
    /// Cumulative resource usage for limit enforcement.
    resource_usage: SessionResourceUsage,
}

impl ClientSession {
    /// Creates a new client session with the given credentials.
    ///
    /// A unique session ID is automatically generated.
    ///
    /// # Arguments
    ///
    /// * `credentials` - The process credentials of the connecting client
    pub fn new(credentials: ProcessCredentials) -> Self {
        Self {
            id: SessionId::new(),
            credentials,
            authenticated_at: Instant::now(),
            attached_ports: Vec::new(),
            granted_segments: BTreeSet::new(),
            pending_retirements: BTreeSet::new(),
            resource_usage: SessionResourceUsage::new(),
        }
    }

    /// Returns the session identifier.
    pub fn id(&self) -> SessionId {
        self.id
    }

    /// Returns a reference to the client's credentials.
    pub fn credentials(&self) -> &ProcessCredentials {
        &self.credentials
    }

    /// Returns when the session was authenticated.
    pub fn authenticated_at(&self) -> Instant {
        self.authenticated_at
    }

    /// Returns a reference to the resource usage tracker.
    pub fn resource_usage(&self) -> &SessionResourceUsage {
        &self.resource_usage
    }

    /// Returns a mutable reference to the resource usage tracker.
    pub fn resource_usage_mut(&mut self) -> &mut SessionResourceUsage {
        &mut self.resource_usage
    }

    // ========================================================================
    // Port Management
    // ========================================================================

    /// Adds a port to the session's attached ports.
    ///
    /// Also updates the resource usage counters. If the port already exists,
    /// this is a no-op to prevent counter corruption.
    ///
    /// # Arguments
    ///
    /// * `port_id` - The unique port identifier
    /// * `port_type` - The type of port being attached
    ///
    /// # Returns
    ///
    /// `true` if the port was newly added, `false` if it already existed.
    pub fn add_port(&mut self, port_id: u128, port_type: PortType) -> bool {
        // Check for duplicate to prevent counter corruption
        if self.attached_ports.iter().any(|p| p.port_id == port_id) {
            return false;
        }
        self.attached_ports.push(PortInfo::new(port_id, port_type));
        self.resource_usage.increment_port(port_type);
        true
    }

    /// Removes a port from the session's attached ports.
    ///
    /// Also updates the resource usage counters if the port was found.
    ///
    /// # Arguments
    ///
    /// * `port_id` - The unique port identifier to remove
    ///
    /// # Returns
    ///
    /// `true` if the port was found and removed, `false` otherwise.
    pub fn remove_port(&mut self, port_id: u128) -> bool {
        if let Some(pos) = self.attached_ports.iter().position(|p| p.port_id == port_id) {
            let port_info = self.attached_ports.remove(pos);
            self.resource_usage.decrement_port(port_info.port_type);
            true
        } else {
            false
        }
    }

    /// Checks if the session has a specific port attached.
    pub fn has_port(&self, port_id: u128) -> bool {
        self.attached_ports.iter().any(|p| p.port_id == port_id)
    }

    /// Returns the number of attached ports.
    pub fn port_count(&self) -> usize {
        self.attached_ports.len()
    }

    /// Returns an iterator over attached port information.
    pub fn ports(&self) -> impl Iterator<Item = &PortInfo> {
        self.attached_ports.iter()
    }

    // ========================================================================
    // Segment Management
    // ========================================================================

    /// Grants the session access to a segment.
    ///
    /// Also updates the resource usage counters.
    ///
    /// # Arguments
    ///
    /// * `segment_id` - The segment identifier
    /// * `size` - The size of the segment in bytes
    ///
    /// # Returns
    ///
    /// `true` if the segment was newly added, `false` if already granted.
    pub fn grant_segment(&mut self, segment_id: SegmentId, size: usize) -> bool {
        if self.granted_segments.insert(segment_id.value()) {
            self.resource_usage.add_segment(size);
            true
        } else {
            false
        }
    }

    /// Revokes the session's access to a segment.
    ///
    /// Also updates the resource usage counters if the segment was found.
    ///
    /// # Arguments
    ///
    /// * `segment_id` - The segment identifier to revoke
    /// * `size` - The size of the segment in bytes (for resource tracking)
    ///
    /// # Returns
    ///
    /// `true` if the segment was found and revoked, `false` otherwise.
    pub fn revoke_segment(&mut self, segment_id: SegmentId, size: usize) -> bool {
        if self.granted_segments.remove(&segment_id.value()) {
            self.resource_usage.remove_segment(size);
            // Also remove from pending retirements if present
            self.pending_retirements.remove(&segment_id.value());
            true
        } else {
            false
        }
    }

    /// Checks if the session has access to a segment.
    pub fn has_segment(&self, segment_id: SegmentId) -> bool {
        self.granted_segments.contains(&segment_id.value())
    }

    /// Returns the number of granted segments.
    pub fn segment_count(&self) -> usize {
        self.granted_segments.len()
    }

    /// Returns an iterator over granted segment IDs.
    pub fn segments(&self) -> impl Iterator<Item = SegmentId> + '_ {
        self.granted_segments.iter().copied().map(SegmentId::new)
    }

    // ========================================================================
    // Retirement Management
    // ========================================================================

    /// Marks a segment as pending retirement acknowledgment.
    ///
    /// # Arguments
    ///
    /// * `segment_id` - The segment identifier pending retirement
    ///
    /// # Returns
    ///
    /// `true` if the segment was added to pending retirements, `false` if already pending.
    pub fn add_pending_retirement(&mut self, segment_id: SegmentId) -> bool {
        self.pending_retirements.insert(segment_id.value())
    }

    /// Acknowledges a segment retirement.
    ///
    /// Removes the segment from pending retirements.
    ///
    /// # Arguments
    ///
    /// * `segment_id` - The segment identifier to acknowledge
    ///
    /// # Returns
    ///
    /// `true` if the segment was pending and is now acknowledged, `false` otherwise.
    pub fn ack_retirement(&mut self, segment_id: SegmentId) -> bool {
        self.pending_retirements.remove(&segment_id.value())
    }

    /// Checks if a segment is pending retirement acknowledgment.
    pub fn has_pending_retirement(&self, segment_id: SegmentId) -> bool {
        self.pending_retirements.contains(&segment_id.value())
    }

    /// Returns the number of pending retirement acknowledgments.
    pub fn pending_retirement_count(&self) -> usize {
        self.pending_retirements.len()
    }

    /// Returns an iterator over pending retirement segment IDs.
    pub fn pending_retirements(&self) -> impl Iterator<Item = SegmentId> + '_ {
        self.pending_retirements.iter().copied().map(SegmentId::new)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_credentials() -> ProcessCredentials {
        ProcessCredentials::new(1234, 1000, 1000)
    }

    // ========================================================================
    // SessionResourceUsage Tests
    // ========================================================================

    #[test]
    fn test_resource_usage_new() {
        let usage = SessionResourceUsage::new();
        assert_eq!(usage.publisher_count, 0);
        assert_eq!(usage.subscriber_count, 0);
        assert_eq!(usage.server_count, 0);
        assert_eq!(usage.client_count, 0);
        assert_eq!(usage.segment_count, 0);
        assert_eq!(usage.total_memory, 0);
    }

    #[test]
    fn test_resource_usage_default() {
        let usage = SessionResourceUsage::default();
        assert_eq!(usage, SessionResourceUsage::new());
    }

    #[test]
    fn test_resource_usage_increment_port() {
        let mut usage = SessionResourceUsage::new();

        usage.increment_port(PortType::Publisher);
        assert_eq!(usage.publisher_count, 1);

        usage.increment_port(PortType::Subscriber);
        usage.increment_port(PortType::Subscriber);
        assert_eq!(usage.subscriber_count, 2);

        usage.increment_port(PortType::Server);
        assert_eq!(usage.server_count, 1);

        usage.increment_port(PortType::Client);
        assert_eq!(usage.client_count, 1);
    }

    #[test]
    fn test_resource_usage_decrement_port() {
        let mut usage = SessionResourceUsage::new();
        usage.publisher_count = 2;
        usage.subscriber_count = 1;

        usage.decrement_port(PortType::Publisher);
        assert_eq!(usage.publisher_count, 1);

        usage.decrement_port(PortType::Subscriber);
        assert_eq!(usage.subscriber_count, 0);

        // Saturating subtraction - should not underflow
        usage.decrement_port(PortType::Subscriber);
        assert_eq!(usage.subscriber_count, 0);
    }

    #[test]
    fn test_resource_usage_add_segment() {
        let mut usage = SessionResourceUsage::new();

        usage.add_segment(4096);
        assert_eq!(usage.segment_count, 1);
        assert_eq!(usage.total_memory, 4096);

        usage.add_segment(8192);
        assert_eq!(usage.segment_count, 2);
        assert_eq!(usage.total_memory, 12288);
    }

    #[test]
    fn test_resource_usage_remove_segment() {
        let mut usage = SessionResourceUsage::new();
        usage.segment_count = 2;
        usage.total_memory = 12288;

        usage.remove_segment(4096);
        assert_eq!(usage.segment_count, 1);
        assert_eq!(usage.total_memory, 8192);

        // Saturating subtraction
        usage.remove_segment(10000);
        assert_eq!(usage.segment_count, 0);
        assert_eq!(usage.total_memory, 0);
    }

    // ========================================================================
    // ClientSession Tests
    // ========================================================================

    #[test]
    fn test_session_new() {
        let credentials = test_credentials();
        let session = ClientSession::new(credentials.clone());

        assert!(session.id().is_valid());
        assert_eq!(session.credentials().pid(), credentials.pid());
        assert_eq!(session.credentials().uid(), credentials.uid());
        assert_eq!(session.credentials().gid(), credentials.gid());
        assert_eq!(session.port_count(), 0);
        assert_eq!(session.segment_count(), 0);
        assert_eq!(session.pending_retirement_count(), 0);
    }

    #[test]
    fn test_session_unique_ids() {
        let credentials = test_credentials();
        let session1 = ClientSession::new(credentials.clone());
        let session2 = ClientSession::new(credentials);

        assert_ne!(session1.id(), session2.id());
    }

    #[test]
    fn test_session_add_port() {
        let mut session = ClientSession::new(test_credentials());

        session.add_port(100, PortType::Publisher);
        assert!(session.has_port(100));
        assert_eq!(session.port_count(), 1);
        assert_eq!(session.resource_usage().publisher_count, 1);

        session.add_port(200, PortType::Subscriber);
        assert!(session.has_port(200));
        assert_eq!(session.port_count(), 2);
        assert_eq!(session.resource_usage().subscriber_count, 1);
    }

    #[test]
    fn test_session_add_port_duplicate_prevention() {
        let mut session = ClientSession::new(test_credentials());

        // First add should succeed
        assert!(session.add_port(100, PortType::Publisher));
        assert_eq!(session.port_count(), 1);
        assert_eq!(session.resource_usage().publisher_count, 1);

        // Adding same port again should fail and not increment counters
        assert!(!session.add_port(100, PortType::Publisher));
        assert_eq!(session.port_count(), 1);
        assert_eq!(session.resource_usage().publisher_count, 1);

        // Adding same port ID with different type should also fail
        assert!(!session.add_port(100, PortType::Subscriber));
        assert_eq!(session.port_count(), 1);
        assert_eq!(session.resource_usage().subscriber_count, 0);
    }

    #[test]
    fn test_session_remove_port() {
        let mut session = ClientSession::new(test_credentials());
        session.add_port(100, PortType::Publisher);
        session.add_port(200, PortType::Subscriber);

        assert!(session.remove_port(100));
        assert!(!session.has_port(100));
        assert_eq!(session.port_count(), 1);
        assert_eq!(session.resource_usage().publisher_count, 0);

        // Removing non-existent port
        assert!(!session.remove_port(999));
    }

    #[test]
    fn test_session_ports_iterator() {
        let mut session = ClientSession::new(test_credentials());
        session.add_port(100, PortType::Publisher);
        session.add_port(200, PortType::Subscriber);

        let port_ids: Vec<u128> = session.ports().map(|p| p.port_id).collect();
        assert!(port_ids.contains(&100));
        assert!(port_ids.contains(&200));
    }

    #[test]
    fn test_session_grant_segment() {
        let mut session = ClientSession::new(test_credentials());
        let segment_id = SegmentId::new(1);

        assert!(session.grant_segment(segment_id, 4096));
        assert!(session.has_segment(segment_id));
        assert_eq!(session.segment_count(), 1);
        assert_eq!(session.resource_usage().segment_count, 1);
        assert_eq!(session.resource_usage().total_memory, 4096);

        // Granting same segment again returns false
        assert!(!session.grant_segment(segment_id, 4096));
        assert_eq!(session.segment_count(), 1);
    }

    #[test]
    fn test_session_revoke_segment() {
        let mut session = ClientSession::new(test_credentials());
        let segment_id = SegmentId::new(1);
        session.grant_segment(segment_id, 4096);
        session.add_pending_retirement(segment_id);

        assert!(session.revoke_segment(segment_id, 4096));
        assert!(!session.has_segment(segment_id));
        assert!(!session.has_pending_retirement(segment_id));
        assert_eq!(session.segment_count(), 0);
        assert_eq!(session.resource_usage().segment_count, 0);
        assert_eq!(session.resource_usage().total_memory, 0);

        // Revoking non-existent segment
        assert!(!session.revoke_segment(segment_id, 4096));
    }

    #[test]
    fn test_session_segments_iterator() {
        let mut session = ClientSession::new(test_credentials());
        session.grant_segment(SegmentId::new(1), 4096);
        session.grant_segment(SegmentId::new(2), 8192);

        let segment_ids: Vec<SegmentId> = session.segments().collect();
        assert_eq!(segment_ids.len(), 2);
    }

    #[test]
    fn test_session_pending_retirement() {
        let mut session = ClientSession::new(test_credentials());
        let segment_id = SegmentId::new(1);

        assert!(session.add_pending_retirement(segment_id));
        assert!(session.has_pending_retirement(segment_id));
        assert_eq!(session.pending_retirement_count(), 1);

        // Adding same retirement again returns false
        assert!(!session.add_pending_retirement(segment_id));

        assert!(session.ack_retirement(segment_id));
        assert!(!session.has_pending_retirement(segment_id));
        assert_eq!(session.pending_retirement_count(), 0);

        // Acknowledging non-existent retirement
        assert!(!session.ack_retirement(segment_id));
    }

    #[test]
    fn test_session_pending_retirements_iterator() {
        let mut session = ClientSession::new(test_credentials());
        session.add_pending_retirement(SegmentId::new(1));
        session.add_pending_retirement(SegmentId::new(2));

        let retirements: Vec<SegmentId> = session.pending_retirements().collect();
        assert_eq!(retirements.len(), 2);
    }

    #[test]
    fn test_session_authenticated_at() {
        let before = Instant::now();
        let session = ClientSession::new(test_credentials());
        let after = Instant::now();

        assert!(session.authenticated_at() >= before);
        assert!(session.authenticated_at() <= after);
    }

    #[test]
    fn test_port_info() {
        let info = PortInfo::new(42, PortType::Publisher);
        assert_eq!(info.port_id, 42);
        assert_eq!(info.port_type, PortType::Publisher);
    }

    // ========================================================================
    // Send/Sync Tests
    // ========================================================================

    #[test]
    fn test_session_is_send() {
        fn assert_send<T: Send>() {}
        assert_send::<ClientSession>();
    }

    // ClientSession is intentionally not Sync since it's designed for
    // single-threaded use within the server

    #[test]
    fn test_resource_usage_is_send_sync() {
        fn assert_send<T: Send>() {}
        fn assert_sync<T: Sync>() {}
        assert_send::<SessionResourceUsage>();
        assert_sync::<SessionResourceUsage>();
    }

    #[test]
    fn test_port_info_is_send_sync() {
        fn assert_send<T: Send>() {}
        fn assert_sync<T: Sync>() {}
        assert_send::<PortInfo>();
        assert_sync::<PortInfo>();
    }
}
