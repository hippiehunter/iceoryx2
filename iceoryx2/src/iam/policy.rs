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

//! IAM policy types for authorization decisions.
//!
//! This module defines the policy trait and types for making authorization
//! decisions in secured inter-process communication scenarios.
//!
//! # Overview
//!
//! The policy system provides:
//! - [`PolicyDecision`]: The result of a policy evaluation (allow/deny)
//! - [`ResourceLimits`]: Limits on resources a principal can consume
//! - [`IamPolicy`]: Trait for implementing authorization policies
//! - [`DefaultPolicy`]: A default implementation allowing same-UID processes
//!
//! # Example
//!
//! ```ignore
//! use iceoryx2::iam::{DefaultPolicy, IamPolicy, PolicyDecision};
//!
//! // Create a default policy for the current user
//! let policy = DefaultPolicy::new();
//!
//! // Check if a request is allowed
//! let credentials = ProcessCredentials::from_self();
//! let decision = policy.authorize_connect(&credentials);
//! assert!(decision.is_allowed());
//! ```

use alloc::string::String;

use iceoryx2_cal::security::credentials::ProcessCredentials;

use crate::service::service_id::ServiceId;
use crate::service::service_name::ServiceName;

use super::protocol::{DenialReason, MessagingPatternKind, PortType};

// ============================================================================
// PolicyDecision
// ============================================================================

/// Result of policy evaluation.
///
/// This enum represents the outcome of an authorization check, indicating
/// whether a request is allowed or denied with a specific reason.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyDecision {
    /// Request is allowed.
    Allow,
    /// Request is denied with reason.
    Deny {
        /// The reason for denial.
        reason: DenialReason,
        /// A human-readable message explaining the denial.
        message: String,
    },
}

impl PolicyDecision {
    /// Creates an allow decision.
    #[must_use]
    pub fn allow() -> Self {
        Self::Allow
    }

    /// Creates a deny decision with the specified reason and message.
    #[must_use]
    pub fn deny(reason: DenialReason, message: impl Into<String>) -> Self {
        Self::Deny {
            reason,
            message: message.into(),
        }
    }

    /// Returns `true` if the decision is [`PolicyDecision::Allow`].
    #[must_use]
    pub fn is_allowed(&self) -> bool {
        matches!(self, PolicyDecision::Allow)
    }

    /// Returns `true` if the decision is [`PolicyDecision::Deny`].
    #[must_use]
    pub fn is_denied(&self) -> bool {
        matches!(self, PolicyDecision::Deny { .. })
    }
}

// ============================================================================
// ResourceLimits
// ============================================================================

/// Resource limits for a principal.
///
/// This struct defines the maximum resources a principal (identified by
/// credentials) is allowed to consume. These limits are used to prevent
/// resource exhaustion and ensure fair resource allocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ResourceLimits {
    /// Maximum number of publishers a principal can create.
    pub max_publishers: usize,
    /// Maximum number of subscribers a principal can create.
    pub max_subscribers: usize,
    /// Maximum number of servers a principal can create.
    pub max_servers: usize,
    /// Maximum number of clients a principal can create.
    pub max_clients: usize,
    /// Maximum number of segments a principal can allocate.
    ///
    /// Note: This limit is enforced by the IAM server (Phase 3), not by the
    /// stateless policy. The policy validates individual segment requests.
    pub max_segments: usize,
    /// Maximum size of a single segment in bytes (inclusive).
    ///
    /// Segment requests up to and including this size are allowed.
    /// Requests exceeding this size are denied with [`DenialReason::ResourceLimitExceeded`].
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

/// Maximum reasonable segment size (1 GB) for validation purposes.
/// This prevents accidental misconfiguration that could cause memory exhaustion.
pub const MAX_REASONABLE_SEGMENT_SIZE: usize = 1024 * 1024 * 1024;

// ============================================================================
// QosBounds
// ============================================================================

/// Quality of Service bounds for policy enforcement.
///
/// These bounds constrain the QoS parameters that clients can request
/// when attaching to a service. Values of `None` indicate no constraint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct QosBounds {
    /// Maximum buffer size (in elements) a port may request.
    pub max_buffer_size: Option<usize>,
    /// Maximum history depth a subscriber may request.
    pub max_history: Option<usize>,
}

impl Default for QosBounds {
    fn default() -> Self {
        Self {
            max_buffer_size: None,
            max_history: None,
        }
    }
}

impl QosBounds {
    /// Creates unbounded QoS (no constraints).
    pub const fn unbounded() -> Self {
        Self {
            max_buffer_size: None,
            max_history: None,
        }
    }

    /// Creates QoS bounds with explicit limits.
    pub const fn new(max_buffer_size: Option<usize>, max_history: Option<usize>) -> Self {
        Self {
            max_buffer_size,
            max_history,
        }
    }

    /// Checks whether a requested buffer size is within bounds.
    pub fn check_buffer_size(&self, requested: usize) -> bool {
        match self.max_buffer_size {
            Some(max) => requested <= max,
            None => true,
        }
    }

    /// Checks whether a requested history depth is within bounds.
    pub fn check_history(&self, requested: usize) -> bool {
        match self.max_history {
            Some(max) => requested <= max,
            None => true,
        }
    }
}

impl ResourceLimits {
    /// Creates a new ResourceLimits with the specified values.
    ///
    /// # Arguments
    /// * `max_publishers` - Maximum number of publishers
    /// * `max_subscribers` - Maximum number of subscribers
    /// * `max_servers` - Maximum number of servers
    /// * `max_clients` - Maximum number of clients
    /// * `max_segments` - Maximum number of segments
    /// * `max_segment_size` - Maximum size of a single segment in bytes
    pub const fn new(
        max_publishers: usize,
        max_subscribers: usize,
        max_servers: usize,
        max_clients: usize,
        max_segments: usize,
        max_segment_size: usize,
    ) -> Self {
        Self {
            max_publishers,
            max_subscribers,
            max_servers,
            max_clients,
            max_segments,
            max_segment_size,
        }
    }

    /// Checks if the resource limits are valid.
    ///
    /// Returns `true` if all limits are sensible:
    /// - `max_segment_size` must be greater than 0 (otherwise no segments can be created)
    /// - `max_segment_size` must not exceed [`MAX_REASONABLE_SEGMENT_SIZE`] (1 GB)
    ///
    /// # Returns
    /// `true` if the limits are valid, `false` otherwise.
    pub const fn is_valid(&self) -> bool {
        // max_segment_size of 0 would prevent any segments from being created
        // max_segment_size > 1GB is likely a misconfiguration
        self.max_segment_size > 0 && self.max_segment_size <= MAX_REASONABLE_SEGMENT_SIZE
    }
}

// ============================================================================
// IamPolicy Trait
// ============================================================================

/// Policy trait for IAM authorization decisions.
///
/// Implementations must be `Send + Sync` for use in multi-threaded servers.
/// This trait defines the interface for making authorization decisions about
/// various operations in the IAM system.
///
/// # Implementing Custom Policies
///
/// To implement a custom policy, implement this trait and provide logic for
/// each authorization method. The default implementation of [`authorize_connect`]
/// allows all connections, deferring authorization to per-operation checks.
///
/// # Thread Safety
///
/// All implementations must be thread-safe as they may be called concurrently
/// from multiple threads in the IAM server.
///
/// # Security Considerations
///
/// **Root/Administrator Access**: The [`DefaultPolicy`] uses UID-based checks only.
/// Processes running as root (UID 0) on Unix or as Administrator on Windows have
/// elevated privileges and can bypass many system-level access controls. Custom
/// policies may need to explicitly handle root/admin credentials if stricter
/// isolation is required.
///
/// **GID/Group Checks**: The default policy does NOT check group IDs (GIDs).
/// If group-based access control is needed, implement a custom policy that
/// examines `credentials.gid()`.
///
/// **Policy Complexity**: For production deployments with complex access control
/// requirements, consider implementing a custom policy with:
/// - Explicit allow/deny lists for UIDs
/// - Service-specific access rules
/// - Role-based access control (RBAC)
/// - Audit logging of authorization decisions
pub trait IamPolicy: Send + Sync {
    /// Check if credentials are allowed to create the service.
    ///
    /// # Arguments
    /// * `credentials` - The credentials of the requesting process
    /// * `service_name` - The name of the service to create
    /// * `messaging_pattern` - The messaging pattern for the service
    ///
    /// # Returns
    /// A [`PolicyDecision`] indicating whether the request is allowed or denied.
    fn authorize_create(
        &self,
        credentials: &ProcessCredentials,
        service_name: &ServiceName,
        messaging_pattern: MessagingPatternKind,
    ) -> PolicyDecision;

    /// Check if credentials are allowed to attach with given role.
    ///
    /// # Arguments
    /// * `credentials` - The credentials of the requesting process
    /// * `service_id` - The ID of the service to attach to
    /// * `port_type` - The type of port being attached
    ///
    /// # Returns
    /// A [`PolicyDecision`] indicating whether the request is allowed or denied.
    fn authorize_attach(
        &self,
        credentials: &ProcessCredentials,
        service_id: &ServiceId,
        port_type: PortType,
    ) -> PolicyDecision;

    /// Check if credentials are allowed to add a segment.
    ///
    /// # Arguments
    /// * `credentials` - The credentials of the requesting process
    /// * `service_id` - The ID of the service
    /// * `requested_size` - The requested size for the new segment
    ///
    /// # Returns
    /// A [`PolicyDecision`] indicating whether the request is allowed or denied.
    fn authorize_add_segment(
        &self,
        credentials: &ProcessCredentials,
        service_id: &ServiceId,
        requested_size: usize,
    ) -> PolicyDecision;

    /// Get resource limits for a principal.
    ///
    /// # Arguments
    /// * `credentials` - The credentials of the requesting process
    ///
    /// # Returns
    /// The [`ResourceLimits`] for the principal identified by the credentials.
    fn get_limits(&self, credentials: &ProcessCredentials) -> ResourceLimits;

    /// Called when a client connects - can reject early.
    ///
    /// # Arguments
    /// * `credentials` - The credentials of the connecting process
    ///
    /// # Returns
    /// A [`PolicyDecision`] indicating whether the connection is allowed.
    ///
    /// The default implementation allows all connections, deferring
    /// authorization to per-operation checks.
    fn authorize_connect(&self, _credentials: &ProcessCredentials) -> PolicyDecision {
        // Default: allow all connections, authorize per-operation
        PolicyDecision::Allow
    }

    /// Get QoS bounds for a principal.
    ///
    /// # Arguments
    /// * `credentials` - The credentials of the requesting process
    ///
    /// # Returns
    /// The [`QosBounds`] for the principal. Default: unbounded.
    fn get_qos_bounds(&self, _credentials: &ProcessCredentials) -> QosBounds {
        QosBounds::unbounded()
    }
}

// ============================================================================
// DefaultPolicy
// ============================================================================

/// Default policy: allow all same-UID/owner processes.
///
/// This policy allows operations only from processes that have the same
/// user ID (UID) as the owner. This provides basic isolation between
/// different users on the same system.
///
/// # Example
///
/// ```ignore
/// use iceoryx2::iam::DefaultPolicy;
///
/// // Create a policy for the current user
/// let policy = DefaultPolicy::new();
///
/// // Or with a specific owner UID
/// let policy = DefaultPolicy::with_owner(1000);
///
/// // Or with custom limits
/// let limits = ResourceLimits::default();
/// let policy = DefaultPolicy::with_limits(1000, limits);
/// ```
///
/// # Design Notes
///
/// This policy is **stateless** - it evaluates each request in isolation without
/// tracking cumulative resource usage. Actual enforcement of cumulative limits
/// (total segments allocated, total memory used, etc.) is the responsibility of
/// the IAM server which maintains per-principal usage counters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DefaultPolicy {
    owner_uid: u32,
    limits: ResourceLimits,
}

impl DefaultPolicy {
    /// Create default policy for current process owner.
    pub fn new() -> Self {
        let credentials = ProcessCredentials::from_self();
        Self {
            owner_uid: credentials.uid(),
            limits: ResourceLimits::default(),
        }
    }

    /// Create default policy with specific owner.
    ///
    /// # Arguments
    /// * `owner_uid` - The user ID that will be allowed access
    pub fn with_owner(owner_uid: u32) -> Self {
        Self {
            owner_uid,
            limits: ResourceLimits::default(),
        }
    }

    /// Create with custom limits.
    ///
    /// # Arguments
    /// * `owner_uid` - The user ID that will be allowed access
    /// * `limits` - The resource limits to apply
    pub fn with_limits(owner_uid: u32, limits: ResourceLimits) -> Self {
        Self { owner_uid, limits }
    }

    /// Get the owner UID.
    pub const fn owner_uid(&self) -> u32 {
        self.owner_uid
    }

    /// Get a reference to the resource limits.
    ///
    /// This avoids cloning when only read access is needed.
    pub const fn limits(&self) -> &ResourceLimits {
        &self.limits
    }
}

// NOTE: DefaultPolicy intentionally does NOT implement Default because
// DefaultPolicy::new() calls ProcessCredentials::from_self() which performs
// syscalls. The Default trait should be trivial and side-effect free.

impl IamPolicy for DefaultPolicy {
    fn authorize_create(
        &self,
        credentials: &ProcessCredentials,
        _service_name: &ServiceName,
        _messaging_pattern: MessagingPatternKind,
    ) -> PolicyDecision {
        if credentials.uid() == self.owner_uid {
            PolicyDecision::allow()
        } else {
            PolicyDecision::deny(
                DenialReason::Unauthorized,
                "Only the owner can create services",
            )
        }
    }

    fn authorize_attach(
        &self,
        credentials: &ProcessCredentials,
        _service_id: &ServiceId,
        _port_type: PortType,
    ) -> PolicyDecision {
        if credentials.uid() == self.owner_uid {
            PolicyDecision::allow()
        } else {
            PolicyDecision::deny(
                DenialReason::Unauthorized,
                "Only the owner can attach to services",
            )
        }
    }

    fn authorize_add_segment(
        &self,
        credentials: &ProcessCredentials,
        _service_id: &ServiceId,
        requested_size: usize,
    ) -> PolicyDecision {
        if credentials.uid() != self.owner_uid {
            return PolicyDecision::deny(
                DenialReason::Unauthorized,
                "Only the owner can add segments",
            );
        }

        // Reject zero-size segments - they serve no purpose and may indicate a bug
        if requested_size == 0 {
            return PolicyDecision::deny(
                DenialReason::PolicyViolation,
                "Zero-size segment requests are not allowed",
            );
        }

        if requested_size > self.limits.max_segment_size {
            return PolicyDecision::deny(
                DenialReason::ResourceLimitExceeded,
                "Requested segment size exceeds maximum allowed",
            );
        }

        PolicyDecision::allow()
    }

    fn get_limits(&self, _credentials: &ProcessCredentials) -> ResourceLimits {
        self.limits
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ========================================================================
    // PolicyDecision Tests
    // ========================================================================

    #[test]
    fn test_policy_decision_allow() {
        let decision = PolicyDecision::allow();
        assert!(decision.is_allowed());
        assert!(!decision.is_denied());
        assert_eq!(decision, PolicyDecision::Allow);
    }

    #[test]
    fn test_policy_decision_deny() {
        let decision = PolicyDecision::deny(DenialReason::Unauthorized, "Test denial");
        assert!(!decision.is_allowed());
        assert!(decision.is_denied());
        match decision {
            PolicyDecision::Deny { reason, message } => {
                assert_eq!(reason, DenialReason::Unauthorized);
                assert_eq!(message, "Test denial");
            }
            _ => panic!("Expected Deny decision"),
        }
    }

    #[test]
    fn test_policy_decision_deny_with_string() {
        let decision = PolicyDecision::deny(
            DenialReason::PolicyViolation,
            String::from("Dynamic message"),
        );
        assert!(decision.is_denied());
        match decision {
            PolicyDecision::Deny { reason, message } => {
                assert_eq!(reason, DenialReason::PolicyViolation);
                assert_eq!(message, "Dynamic message");
            }
            _ => panic!("Expected Deny decision"),
        }
    }

    #[test]
    fn test_policy_decision_clone() {
        let original = PolicyDecision::deny(DenialReason::Unauthorized, "Test");
        let cloned = original.clone();
        assert_eq!(original, cloned);
    }

    #[test]
    fn test_policy_decision_debug() {
        let decision = PolicyDecision::allow();
        let debug_str = format!("{:?}", decision);
        assert!(debug_str.contains("Allow"));
    }

    // ========================================================================
    // ResourceLimits Tests
    // ========================================================================

    #[test]
    fn test_resource_limits_default() {
        let limits = ResourceLimits::default();
        assert_eq!(limits.max_publishers, 16);
        assert_eq!(limits.max_subscribers, 256);
        assert_eq!(limits.max_servers, 16);
        assert_eq!(limits.max_clients, 256);
        assert_eq!(limits.max_segments, 64);
        assert_eq!(limits.max_segment_size, 64 * 1024 * 1024);
    }

    #[test]
    fn test_resource_limits_custom() {
        let limits = ResourceLimits {
            max_publishers: 8,
            max_subscribers: 128,
            max_servers: 4,
            max_clients: 64,
            max_segments: 32,
            max_segment_size: 32 * 1024 * 1024,
        };
        assert_eq!(limits.max_publishers, 8);
        assert_eq!(limits.max_subscribers, 128);
        assert_eq!(limits.max_servers, 4);
        assert_eq!(limits.max_clients, 64);
        assert_eq!(limits.max_segments, 32);
        assert_eq!(limits.max_segment_size, 32 * 1024 * 1024);
    }

    #[test]
    fn test_resource_limits_clone() {
        let original = ResourceLimits::default();
        let cloned = original.clone();
        assert_eq!(original, cloned);
    }

    #[test]
    fn test_resource_limits_copy() {
        let original = ResourceLimits::default();
        let copied = original; // Copy, not move
        assert_eq!(original, copied); // original is still valid (Copy trait)
    }

    #[test]
    fn test_resource_limits_hash() {
        use std::collections::HashSet;
        let limits1 = ResourceLimits::default();
        let limits2 = ResourceLimits::default();
        let limits3 = ResourceLimits {
            max_publishers: 1,
            ..Default::default()
        };

        let mut set = HashSet::new();
        set.insert(limits1);
        set.insert(limits2); // Same as limits1
        set.insert(limits3); // Different

        assert_eq!(set.len(), 2); // Only 2 unique values
    }

    #[test]
    fn test_resource_limits_is_valid_default() {
        let limits = ResourceLimits::default();
        assert!(limits.is_valid());
    }

    #[test]
    fn test_resource_limits_is_valid_zero_segment_size() {
        let limits = ResourceLimits {
            max_segment_size: 0,
            ..Default::default()
        };
        assert!(!limits.is_valid());
    }

    #[test]
    fn test_resource_limits_is_valid_zero_other_limits() {
        // Zero for other limits is valid (means "none allowed")
        let limits = ResourceLimits {
            max_publishers: 0,
            max_subscribers: 0,
            max_servers: 0,
            max_clients: 0,
            max_segments: 0,
            max_segment_size: 1024, // Non-zero
        };
        assert!(limits.is_valid());
    }

    #[test]
    fn test_resource_limits_is_valid_exceeds_max_reasonable() {
        // Segment size exceeding MAX_REASONABLE_SEGMENT_SIZE (1 GB) is invalid
        let limits = ResourceLimits {
            max_segment_size: MAX_REASONABLE_SEGMENT_SIZE + 1,
            ..Default::default()
        };
        assert!(!limits.is_valid());
    }

    #[test]
    fn test_resource_limits_is_valid_at_max_reasonable() {
        // Exactly at MAX_REASONABLE_SEGMENT_SIZE is valid
        let limits = ResourceLimits {
            max_segment_size: MAX_REASONABLE_SEGMENT_SIZE,
            ..Default::default()
        };
        assert!(limits.is_valid());
    }

    #[test]
    fn test_resource_limits_new_const() {
        // Test const fn new()
        const LIMITS: ResourceLimits = ResourceLimits::new(8, 16, 4, 8, 32, 1024);
        assert_eq!(LIMITS.max_publishers, 8);
        assert_eq!(LIMITS.max_subscribers, 16);
        assert_eq!(LIMITS.max_servers, 4);
        assert_eq!(LIMITS.max_clients, 8);
        assert_eq!(LIMITS.max_segments, 32);
        assert_eq!(LIMITS.max_segment_size, 1024);
    }

    #[test]
    fn test_resource_limits_debug() {
        let limits = ResourceLimits::default();
        let debug_str = format!("{:?}", limits);
        assert!(debug_str.contains("max_publishers"));
        assert!(debug_str.contains("16"));
    }

    // ========================================================================
    // DefaultPolicy Tests
    // ========================================================================

    #[test]
    fn test_default_policy_new() {
        let policy = DefaultPolicy::new();
        let credentials = ProcessCredentials::from_self();
        assert_eq!(policy.owner_uid(), credentials.uid());
    }

    #[test]
    fn test_default_policy_with_owner() {
        let policy = DefaultPolicy::with_owner(1000);
        assert_eq!(policy.owner_uid(), 1000);
    }

    #[test]
    fn test_default_policy_with_limits() {
        let limits = ResourceLimits {
            max_publishers: 32,
            ..Default::default()
        };
        let policy = DefaultPolicy::with_limits(1000, limits);
        assert_eq!(policy.owner_uid(), 1000);
        let returned_limits = policy.get_limits(&ProcessCredentials::new(1, 1000, 1000));
        assert_eq!(returned_limits.max_publishers, 32);
    }

    // NOTE: DefaultPolicy intentionally does NOT implement Default because
    // DefaultPolicy::new() calls ProcessCredentials::from_self() which performs
    // syscalls. See the comment above the IamPolicy impl block.

    #[test]
    fn test_default_policy_debug() {
        let policy = DefaultPolicy::with_owner(1000);
        let debug_str = format!("{:?}", policy);
        assert!(debug_str.contains("DefaultPolicy"));
        assert!(debug_str.contains("1000"));
    }

    #[test]
    fn test_default_policy_clone() {
        let original = DefaultPolicy::with_owner(1000);
        let cloned = original.clone();
        assert_eq!(cloned.owner_uid(), 1000);
    }

    #[test]
    fn test_default_policy_equality() {
        let policy1 = DefaultPolicy::with_owner(1000);
        let policy2 = DefaultPolicy::with_owner(1000);
        let policy3 = DefaultPolicy::with_owner(2000);

        assert_eq!(policy1, policy2);
        assert_ne!(policy1, policy3);
    }

    #[test]
    fn test_default_policy_authorize_create_same_uid() {
        let credentials = ProcessCredentials::from_self();
        let policy = DefaultPolicy::with_owner(credentials.uid());
        let service_name = ServiceName::new("test/service").unwrap();

        let decision = policy.authorize_create(
            &credentials,
            &service_name,
            MessagingPatternKind::PublishSubscribe,
        );
        assert!(decision.is_allowed());
    }

    #[test]
    fn test_default_policy_authorize_create_different_uid() {
        let credentials = ProcessCredentials::new(1, 1000, 1000);
        let policy = DefaultPolicy::with_owner(2000); // Different UID
        let service_name = ServiceName::new("test/service").unwrap();

        let decision = policy.authorize_create(
            &credentials,
            &service_name,
            MessagingPatternKind::PublishSubscribe,
        );
        assert!(decision.is_denied());
        match decision {
            PolicyDecision::Deny { reason, .. } => {
                assert_eq!(reason, DenialReason::Unauthorized);
            }
            _ => panic!("Expected Deny decision"),
        }
    }

    #[test]
    fn test_default_policy_authorize_attach_same_uid() {
        use crate::service::messaging_pattern::MessagingPattern;
        use iceoryx2_cal::hash::sha1::Sha1;

        let credentials = ProcessCredentials::from_self();
        let policy = DefaultPolicy::with_owner(credentials.uid());
        let service_name = ServiceName::new("test/attach").unwrap();
        let service_id = ServiceId::new::<Sha1>(&service_name, MessagingPattern::PublishSubscribe);

        let decision = policy.authorize_attach(&credentials, &service_id, PortType::Publisher);
        assert!(decision.is_allowed());
    }

    #[test]
    fn test_default_policy_authorize_attach_different_uid() {
        use crate::service::messaging_pattern::MessagingPattern;
        use iceoryx2_cal::hash::sha1::Sha1;

        let credentials = ProcessCredentials::new(1, 1000, 1000);
        let policy = DefaultPolicy::with_owner(2000); // Different UID
        let service_name = ServiceName::new("test/attach").unwrap();
        let service_id = ServiceId::new::<Sha1>(&service_name, MessagingPattern::PublishSubscribe);

        let decision = policy.authorize_attach(&credentials, &service_id, PortType::Subscriber);
        assert!(decision.is_denied());
    }

    #[test]
    fn test_default_policy_authorize_add_segment_same_uid_within_limits() {
        use crate::service::messaging_pattern::MessagingPattern;
        use iceoryx2_cal::hash::sha1::Sha1;

        let credentials = ProcessCredentials::from_self();
        let policy = DefaultPolicy::with_owner(credentials.uid());
        let service_name = ServiceName::new("test/segment").unwrap();
        let service_id = ServiceId::new::<Sha1>(&service_name, MessagingPattern::PublishSubscribe);

        let decision = policy.authorize_add_segment(&credentials, &service_id, 1024);
        assert!(decision.is_allowed());
    }

    #[test]
    fn test_default_policy_authorize_add_segment_different_uid() {
        use crate::service::messaging_pattern::MessagingPattern;
        use iceoryx2_cal::hash::sha1::Sha1;

        let credentials = ProcessCredentials::new(1, 1000, 1000);
        let policy = DefaultPolicy::with_owner(2000); // Different UID
        let service_name = ServiceName::new("test/segment").unwrap();
        let service_id = ServiceId::new::<Sha1>(&service_name, MessagingPattern::PublishSubscribe);

        let decision = policy.authorize_add_segment(&credentials, &service_id, 1024);
        assert!(decision.is_denied());
        match decision {
            PolicyDecision::Deny { reason, .. } => {
                assert_eq!(reason, DenialReason::Unauthorized);
            }
            _ => panic!("Expected Deny decision"),
        }
    }

    #[test]
    fn test_default_policy_authorize_add_segment_exceeds_size() {
        use crate::service::messaging_pattern::MessagingPattern;
        use iceoryx2_cal::hash::sha1::Sha1;

        let credentials = ProcessCredentials::from_self();
        let limits = ResourceLimits {
            max_segment_size: 1024, // Only 1KB allowed
            ..Default::default()
        };
        let policy = DefaultPolicy::with_limits(credentials.uid(), limits);
        let service_name = ServiceName::new("test/segment").unwrap();
        let service_id = ServiceId::new::<Sha1>(&service_name, MessagingPattern::PublishSubscribe);

        let decision = policy.authorize_add_segment(&credentials, &service_id, 2048); // Request 2KB
        assert!(decision.is_denied());
        match decision {
            PolicyDecision::Deny { reason, .. } => {
                assert_eq!(reason, DenialReason::ResourceLimitExceeded);
            }
            _ => panic!("Expected Deny decision"),
        }
    }

    #[test]
    fn test_default_policy_authorize_add_segment_exact_max_size() {
        use crate::service::messaging_pattern::MessagingPattern;
        use iceoryx2_cal::hash::sha1::Sha1;

        let credentials = ProcessCredentials::from_self();
        let limits = ResourceLimits {
            max_segment_size: 1024, // Exactly 1KB allowed
            ..Default::default()
        };
        let policy = DefaultPolicy::with_limits(credentials.uid(), limits);
        let service_name = ServiceName::new("test/segment/exact").unwrap();
        let service_id = ServiceId::new::<Sha1>(&service_name, MessagingPattern::PublishSubscribe);

        // Request exactly max_segment_size - should be ALLOWED
        let decision = policy.authorize_add_segment(&credentials, &service_id, 1024);
        assert!(
            decision.is_allowed(),
            "Requesting exactly max_segment_size should be allowed"
        );
    }

    #[test]
    fn test_default_policy_authorize_add_segment_zero_size() {
        use crate::service::messaging_pattern::MessagingPattern;
        use iceoryx2_cal::hash::sha1::Sha1;

        let credentials = ProcessCredentials::from_self();
        let policy = DefaultPolicy::with_owner(credentials.uid());
        let service_name = ServiceName::new("test/segment").unwrap();
        let service_id = ServiceId::new::<Sha1>(&service_name, MessagingPattern::PublishSubscribe);

        // Zero-size segment should be rejected
        let decision = policy.authorize_add_segment(&credentials, &service_id, 0);
        assert!(decision.is_denied());
        match decision {
            PolicyDecision::Deny { reason, message } => {
                assert_eq!(reason, DenialReason::PolicyViolation);
                assert!(message.contains("Zero-size"));
            }
            _ => panic!("Expected Deny decision"),
        }
    }

    #[test]
    fn test_default_policy_limits_getter() {
        let limits = ResourceLimits {
            max_publishers: 42,
            max_subscribers: 84,
            ..Default::default()
        };
        let policy = DefaultPolicy::with_limits(1000, limits);

        // Test the limits() getter returns a reference
        let limits_ref = policy.limits();
        assert_eq!(limits_ref.max_publishers, 42);
        assert_eq!(limits_ref.max_subscribers, 84);
    }

    #[test]
    fn test_default_policy_get_limits() {
        let limits = ResourceLimits {
            max_publishers: 32,
            max_subscribers: 128,
            ..Default::default()
        };
        let policy = DefaultPolicy::with_limits(1000, limits);
        let credentials = ProcessCredentials::new(1, 1000, 1000);

        let returned_limits = policy.get_limits(&credentials);
        assert_eq!(returned_limits.max_publishers, 32);
        assert_eq!(returned_limits.max_subscribers, 128);
    }

    #[test]
    fn test_default_policy_authorize_connect_default() {
        let policy = DefaultPolicy::new();
        let credentials = ProcessCredentials::new(1, 9999, 9999); // Any credentials

        // Default authorize_connect should allow all
        let decision = policy.authorize_connect(&credentials);
        assert!(decision.is_allowed());
    }

    // ========================================================================
    // Send + Sync Tests
    // ========================================================================

    #[test]
    fn test_default_policy_is_send() {
        fn assert_send<T: Send>() {}
        assert_send::<DefaultPolicy>();
    }

    #[test]
    fn test_default_policy_is_sync() {
        fn assert_sync<T: Sync>() {}
        assert_sync::<DefaultPolicy>();
    }

    #[test]
    fn test_policy_decision_is_send() {
        fn assert_send<T: Send>() {}
        assert_send::<PolicyDecision>();
    }

    #[test]
    fn test_policy_decision_is_sync() {
        fn assert_sync<T: Sync>() {}
        assert_sync::<PolicyDecision>();
    }

    #[test]
    fn test_resource_limits_is_send() {
        fn assert_send<T: Send>() {}
        assert_send::<ResourceLimits>();
    }

    #[test]
    fn test_resource_limits_is_sync() {
        fn assert_sync<T: Sync>() {}
        assert_sync::<ResourceLimits>();
    }

    // ========================================================================
    // Additional Tests
    // ========================================================================

    #[test]
    fn test_all_port_types_with_same_uid() {
        use crate::service::messaging_pattern::MessagingPattern;
        use iceoryx2_cal::hash::sha1::Sha1;

        let credentials = ProcessCredentials::from_self();
        let policy = DefaultPolicy::with_owner(credentials.uid());
        let service_name = ServiceName::new("test/ports").unwrap();
        let service_id = ServiceId::new::<Sha1>(&service_name, MessagingPattern::PublishSubscribe);

        for port_type in [
            PortType::Publisher,
            PortType::Subscriber,
            PortType::Server,
            PortType::Client,
        ] {
            let decision = policy.authorize_attach(&credentials, &service_id, port_type);
            assert!(decision.is_allowed(), "Expected allow for {:?}", port_type);
        }
    }

    #[test]
    fn test_all_messaging_patterns_with_same_uid() {
        let credentials = ProcessCredentials::from_self();
        let policy = DefaultPolicy::with_owner(credentials.uid());
        let service_name = ServiceName::new("test/patterns").unwrap();

        for pattern in [
            MessagingPatternKind::PublishSubscribe,
            MessagingPatternKind::RequestResponse,
            MessagingPatternKind::Event,
        ] {
            let decision = policy.authorize_create(&credentials, &service_name, pattern);
            assert!(decision.is_allowed(), "Expected allow for {:?}", pattern);
        }
    }

    // ========================================================================
    // QosBounds Tests
    // ========================================================================

    #[test]
    fn test_qos_bounds_default_is_unbounded() {
        let bounds = QosBounds::default();
        assert_eq!(bounds.max_buffer_size, None);
        assert_eq!(bounds.max_history, None);
    }

    #[test]
    fn test_qos_bounds_unbounded_allows_all() {
        let bounds = QosBounds::unbounded();
        assert!(bounds.check_buffer_size(usize::MAX));
        assert!(bounds.check_history(usize::MAX));
    }

    #[test]
    fn test_qos_bounds_with_limits() {
        let bounds = QosBounds::new(Some(1024), Some(10));
        assert!(bounds.check_buffer_size(1024));
        assert!(!bounds.check_buffer_size(1025));
        assert!(bounds.check_history(10));
        assert!(!bounds.check_history(11));
    }

    #[test]
    fn test_qos_bounds_partial_limits() {
        let bounds = QosBounds::new(Some(512), None);
        assert!(!bounds.check_buffer_size(513));
        assert!(bounds.check_history(usize::MAX));
    }

    #[test]
    fn test_default_policy_qos_bounds_are_unbounded() {
        let policy = DefaultPolicy::with_owner(1000);
        let creds = ProcessCredentials::new(1, 1000, 100);
        let bounds = policy.get_qos_bounds(&creds);
        assert_eq!(bounds, QosBounds::unbounded());
    }
}
