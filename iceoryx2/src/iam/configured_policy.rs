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

//! TOML-based policy configuration and loading.
//!
//! This module provides types for loading authorization policies from TOML
//! files and applying them to IAM authorization decisions.
//!
//! # Overview
//!
//! - [`PolicyFile`]: Serde-deserializable TOML policy structure
//! - [`ConfiguredPolicy`]: [`IamPolicy`] implementation driven by TOML rules
//! - [`PolicyDispatch`]: Enum dispatch to avoid `dyn IamPolicy` boxing
//! - [`PolicyLoader`]: Loads policy files from a directory by service name
//!
//! # Policy File Format
//!
//! ```toml
//! [service]
//! name = "my/service"
//!
//! [[allow]]
//! principal = { uid = 1000 }
//! roles = ["publisher", "subscriber"]
//!
//! [[deny]]
//! principal = "any"
//! reason = "Default deny"
//!
//! [limits]
//! max_publishers = 4
//! max_subscribers = 16
//! max_segment_size = "64MB"
//! ```

use alloc::string::String;
use alloc::vec::Vec;

use iceoryx2_cal::security::credentials::ProcessCredentials;
use serde::Deserialize;

use crate::service::service_id::ServiceId;
use crate::service::service_name::ServiceName;

use super::policy::{DefaultPolicy, IamPolicy, PolicyDecision, ResourceLimits};
use super::protocol::{DenialReason, MessagingPatternKind, PortType};

// ============================================================================
// TOML Policy File Structs
// ============================================================================

/// Top-level TOML policy file structure.
#[derive(Debug, Clone, Deserialize)]
pub struct PolicyFile {
    /// Service identification section.
    pub service: ServiceSection,
    /// Allow rules (evaluated after deny rules).
    #[serde(default)]
    pub allow: Vec<AllowRule>,
    /// Deny rules (evaluated first).
    #[serde(default)]
    pub deny: Vec<DenyRule>,
    /// Optional resource limits.
    pub limits: Option<PolicyLimits>,
}

/// Service identification section.
#[derive(Debug, Clone, Deserialize)]
pub struct ServiceSection {
    /// The service name this policy applies to.
    pub name: String,
}

/// An allow rule that grants access to matching principals.
#[derive(Debug, Clone, Deserialize)]
pub struct AllowRule {
    /// The principal matcher for this rule.
    pub principal: PrincipalMatcher,
    /// The roles granted by this rule (e.g., "publisher", "subscriber", "server", "client").
    pub roles: Vec<String>,
}

/// A deny rule that blocks matching principals.
#[derive(Debug, Clone, Deserialize)]
pub struct DenyRule {
    /// The principal matcher for this rule.
    pub principal: PrincipalMatcher,
    /// Optional human-readable reason for the denial.
    pub reason: Option<String>,
}

/// Matcher for identifying principals in policy rules.
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum PrincipalMatcher {
    /// Match by specific UID.
    Uid {
        /// The user ID to match.
        uid: u32,
    },
    /// Match by specific GID.
    Gid {
        /// The group ID to match.
        gid: u32,
    },
    /// Match by UID range (inclusive).
    UidRange {
        /// Minimum UID (inclusive).
        min: u32,
        /// Maximum UID (inclusive).
        max: u32,
    },
    /// Match any principal. Represented as the string "any" in TOML.
    Any(AnyMarker),
}

/// Marker for the "any" principal matcher.
///
/// Deserializes from the string `"any"` in TOML.
#[derive(Debug, Clone)]
pub struct AnyMarker;

impl<'de> Deserialize<'de> for AnyMarker {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        if s == "any" {
            Ok(AnyMarker)
        } else {
            Err(serde::de::Error::custom(format!(
                "expected \"any\", got \"{}\"",
                s
            )))
        }
    }
}

impl PrincipalMatcher {
    /// Checks if the given credentials match this principal matcher.
    pub fn matches(&self, credentials: &ProcessCredentials) -> bool {
        match self {
            PrincipalMatcher::Uid { uid } => credentials.uid() == *uid,
            PrincipalMatcher::Gid { gid } => credentials.gid() == *gid,
            PrincipalMatcher::UidRange { min, max } => {
                credentials.uid() >= *min && credentials.uid() <= *max
            }
            PrincipalMatcher::Any(_) => true,
        }
    }
}

/// Resource limits from a TOML policy file.
///
/// Uses human-readable strings for sizes (e.g., "64MB").
#[derive(Debug, Clone, Deserialize)]
pub struct PolicyLimits {
    /// Maximum number of publishers.
    pub max_publishers: Option<usize>,
    /// Maximum number of subscribers.
    pub max_subscribers: Option<usize>,
    /// Maximum number of servers.
    pub max_servers: Option<usize>,
    /// Maximum number of clients.
    pub max_clients: Option<usize>,
    /// Maximum number of segments.
    pub max_segments: Option<usize>,
    /// Maximum segment size (human-readable, e.g., "64MB").
    pub max_segment_size: Option<String>,
}

impl PolicyLimits {
    /// Converts to [`ResourceLimits`], using defaults for unspecified values.
    pub fn to_resource_limits(&self) -> ResourceLimits {
        let defaults = ResourceLimits::default();
        ResourceLimits {
            max_publishers: self.max_publishers.unwrap_or(defaults.max_publishers),
            max_subscribers: self.max_subscribers.unwrap_or(defaults.max_subscribers),
            max_servers: self.max_servers.unwrap_or(defaults.max_servers),
            max_clients: self.max_clients.unwrap_or(defaults.max_clients),
            max_segments: self.max_segments.unwrap_or(defaults.max_segments),
            max_segment_size: self
                .max_segment_size
                .as_ref()
                .and_then(|s| parse_size_string(s))
                .unwrap_or(defaults.max_segment_size),
        }
    }
}

// ============================================================================
// parse_size_string
// ============================================================================

/// Parses a human-readable size string into bytes.
///
/// Supports formats like:
/// - `"64MB"` or `"64mb"` -> 64 * 1024 * 1024
/// - `"1GB"` or `"1gb"` -> 1024 * 1024 * 1024
/// - `"4096KB"` or `"4096kb"` -> 4096 * 1024
/// - `"4096"` -> 4096 (plain bytes)
///
/// Returns `None` if the string cannot be parsed.
pub fn parse_size_string(s: &str) -> Option<usize> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }

    let upper = s.to_uppercase();
    if let Some(num_str) = upper.strip_suffix("GB") {
        num_str.trim().parse::<usize>().ok().map(|n| n * 1024 * 1024 * 1024)
    } else if let Some(num_str) = upper.strip_suffix("MB") {
        num_str.trim().parse::<usize>().ok().map(|n| n * 1024 * 1024)
    } else if let Some(num_str) = upper.strip_suffix("KB") {
        num_str.trim().parse::<usize>().ok().map(|n| n * 1024)
    } else {
        s.parse::<usize>().ok()
    }
}

// ============================================================================
// ConfiguredPolicy
// ============================================================================

/// Policy implementation driven by TOML-based configuration rules.
///
/// Evaluation order: deny rules first, then allow rules. If no rule matches,
/// the request is denied by default.
#[derive(Debug, Clone)]
pub struct ConfiguredPolicy {
    /// The UID of the service owner.
    owner_uid: u32,
    /// Allow rules from the policy file.
    allow_rules: Vec<AllowRule>,
    /// Deny rules from the policy file.
    deny_rules: Vec<DenyRule>,
    /// Parsed resource limits.
    limits: ResourceLimits,
}

impl ConfiguredPolicy {
    /// Creates a new configured policy from parsed policy file components.
    pub fn new(
        owner_uid: u32,
        allow_rules: Vec<AllowRule>,
        deny_rules: Vec<DenyRule>,
        limits: ResourceLimits,
    ) -> Self {
        Self {
            owner_uid,
            allow_rules,
            deny_rules,
            limits,
        }
    }

    /// Creates a configured policy from a parsed [`PolicyFile`].
    pub fn from_policy_file(policy_file: PolicyFile, owner_uid: u32) -> Self {
        let limits = policy_file
            .limits
            .as_ref()
            .map(|l| l.to_resource_limits())
            .unwrap_or_default();

        Self::new(owner_uid, policy_file.allow, policy_file.deny, limits)
    }

    /// Checks if the credentials match any deny rule.
    /// Returns the denial reason if matched.
    fn check_deny(&self, credentials: &ProcessCredentials) -> Option<PolicyDecision> {
        for rule in &self.deny_rules {
            if rule.principal.matches(credentials) {
                let reason_msg = rule
                    .reason
                    .clone()
                    .unwrap_or_else(|| String::from("Denied by policy rule"));
                return Some(PolicyDecision::deny(
                    DenialReason::PolicyViolation,
                    reason_msg,
                ));
            }
        }
        None
    }

    /// Checks if the credentials match any allow rule with the required role.
    fn check_allow_with_role(
        &self,
        credentials: &ProcessCredentials,
        required_role: &str,
    ) -> bool {
        for rule in &self.allow_rules {
            if rule.principal.matches(credentials)
                && rule.roles.iter().any(|r| r == required_role)
            {
                return true;
            }
        }
        false
    }

    /// Checks if the credentials match any allow rule (regardless of role).
    fn check_allow_any_role(&self, credentials: &ProcessCredentials) -> bool {
        for rule in &self.allow_rules {
            if rule.principal.matches(credentials) {
                return true;
            }
        }
        false
    }
}

impl IamPolicy for ConfiguredPolicy {
    fn authorize_connect(&self, credentials: &ProcessCredentials) -> PolicyDecision {
        // Check deny rules first
        if let Some(decision) = self.check_deny(credentials) {
            return decision;
        }
        // Allow connections by default (operations are checked individually)
        PolicyDecision::Allow
    }

    fn authorize_create(
        &self,
        credentials: &ProcessCredentials,
        _service_name: &ServiceName,
        _messaging_pattern: MessagingPatternKind,
    ) -> PolicyDecision {
        // Check deny rules first
        if let Some(decision) = self.check_deny(credentials) {
            return decision;
        }

        // Must have at least one matching allow rule
        if self.check_allow_any_role(credentials) {
            PolicyDecision::Allow
        } else {
            PolicyDecision::deny(
                DenialReason::Unauthorized,
                "No matching allow rule for service creation",
            )
        }
    }

    fn authorize_attach(
        &self,
        credentials: &ProcessCredentials,
        _service_id: &ServiceId,
        port_type: PortType,
    ) -> PolicyDecision {
        // Check deny rules first
        if let Some(decision) = self.check_deny(credentials) {
            return decision;
        }

        // Map port type to required role string
        let required_role = match port_type {
            PortType::Publisher => "publisher",
            PortType::Subscriber => "subscriber",
            PortType::Server => "server",
            PortType::Client => "client",
        };

        if self.check_allow_with_role(credentials, required_role) {
            PolicyDecision::Allow
        } else {
            PolicyDecision::deny(
                DenialReason::Unauthorized,
                format!(
                    "No allow rule grants '{}' role for this principal",
                    required_role
                ),
            )
        }
    }

    fn authorize_add_segment(
        &self,
        credentials: &ProcessCredentials,
        _service_id: &ServiceId,
        requested_size: usize,
    ) -> PolicyDecision {
        // Check deny rules first
        if let Some(decision) = self.check_deny(credentials) {
            return decision;
        }

        // Same-UID check (segment operations require ownership)
        if credentials.uid() != self.owner_uid {
            return PolicyDecision::deny(
                DenialReason::Unauthorized,
                "Only the service owner can add segments",
            );
        }

        // Reject zero-size segments
        if requested_size == 0 {
            return PolicyDecision::deny(
                DenialReason::PolicyViolation,
                "Zero-size segment requests are not allowed",
            );
        }

        // Check size limit
        if requested_size > self.limits.max_segment_size {
            return PolicyDecision::deny(
                DenialReason::ResourceLimitExceeded,
                "Requested segment size exceeds maximum allowed",
            );
        }

        PolicyDecision::Allow
    }

    fn get_limits(&self, _credentials: &ProcessCredentials) -> ResourceLimits {
        self.limits
    }
}

// ============================================================================
// PolicyDispatch
// ============================================================================

/// Enum dispatch for policy implementations.
///
/// Avoids `Box<dyn IamPolicy>` by using an enum to dispatch between
/// the two built-in policy implementations.
#[derive(Debug, Clone)]
pub(crate) enum PolicyDispatch {
    /// The default UID-based policy.
    Default(DefaultPolicy),
    /// A TOML-configured policy.
    Configured(ConfiguredPolicy),
}

impl IamPolicy for PolicyDispatch {
    fn authorize_connect(&self, credentials: &ProcessCredentials) -> PolicyDecision {
        match self {
            PolicyDispatch::Default(p) => p.authorize_connect(credentials),
            PolicyDispatch::Configured(p) => p.authorize_connect(credentials),
        }
    }

    fn authorize_create(
        &self,
        credentials: &ProcessCredentials,
        service_name: &ServiceName,
        messaging_pattern: MessagingPatternKind,
    ) -> PolicyDecision {
        match self {
            PolicyDispatch::Default(p) => {
                p.authorize_create(credentials, service_name, messaging_pattern)
            }
            PolicyDispatch::Configured(p) => {
                p.authorize_create(credentials, service_name, messaging_pattern)
            }
        }
    }

    fn authorize_attach(
        &self,
        credentials: &ProcessCredentials,
        service_id: &ServiceId,
        port_type: PortType,
    ) -> PolicyDecision {
        match self {
            PolicyDispatch::Default(p) => p.authorize_attach(credentials, service_id, port_type),
            PolicyDispatch::Configured(p) => {
                p.authorize_attach(credentials, service_id, port_type)
            }
        }
    }

    fn authorize_add_segment(
        &self,
        credentials: &ProcessCredentials,
        service_id: &ServiceId,
        requested_size: usize,
    ) -> PolicyDecision {
        match self {
            PolicyDispatch::Default(p) => {
                p.authorize_add_segment(credentials, service_id, requested_size)
            }
            PolicyDispatch::Configured(p) => {
                p.authorize_add_segment(credentials, service_id, requested_size)
            }
        }
    }

    fn get_limits(&self, credentials: &ProcessCredentials) -> ResourceLimits {
        match self {
            PolicyDispatch::Default(p) => p.get_limits(credentials),
            PolicyDispatch::Configured(p) => p.get_limits(credentials),
        }
    }
}

// ============================================================================
// PolicyLoader
// ============================================================================

/// Loads policy files from a directory by service name.
pub struct PolicyLoader;

impl PolicyLoader {
    /// Loads a policy for the given service from the policy directory.
    ///
    /// Looks for `{sanitized_service_name}.toml` in the policy directory.
    /// Service name characters that are not alphanumeric or `-` are replaced
    /// with `_` to form the filename.
    ///
    /// Returns `None` if no policy file exists or if parsing fails.
    pub fn load_for_service(
        policy_dir: &std::path::Path,
        service_name: &ServiceName,
    ) -> Option<ConfiguredPolicy> {
        let sanitized = sanitize_service_name(service_name.as_str());
        let file_path = policy_dir.join(format!("{}.toml", sanitized));

        let contents = std::fs::read_to_string(&file_path).ok()?;
        let policy_file: PolicyFile = toml::from_str(&contents).ok()?;

        let owner_uid = ProcessCredentials::from_self().uid();
        Some(ConfiguredPolicy::from_policy_file(policy_file, owner_uid))
    }
}

/// Sanitizes a service name for use as a filename.
///
/// Replaces `/` and other non-alphanumeric, non-dash characters with `_`.
fn sanitize_service_name(name: &str) -> String {
    name.chars()
        .map(|c| {
            if c.is_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::iam::protocol::DenialReason;

    // ========================================================================
    // parse_size_string Tests
    // ========================================================================

    #[test]
    fn test_parse_size_string_megabytes() {
        assert_eq!(parse_size_string("64MB"), Some(64 * 1024 * 1024));
        assert_eq!(parse_size_string("1MB"), Some(1024 * 1024));
        assert_eq!(parse_size_string("64mb"), Some(64 * 1024 * 1024));
    }

    #[test]
    fn test_parse_size_string_gigabytes() {
        assert_eq!(parse_size_string("1GB"), Some(1024 * 1024 * 1024));
        assert_eq!(parse_size_string("2gb"), Some(2 * 1024 * 1024 * 1024));
    }

    #[test]
    fn test_parse_size_string_kilobytes() {
        assert_eq!(parse_size_string("4096KB"), Some(4096 * 1024));
        assert_eq!(parse_size_string("1kb"), Some(1024));
    }

    #[test]
    fn test_parse_size_string_plain_bytes() {
        assert_eq!(parse_size_string("4096"), Some(4096));
        assert_eq!(parse_size_string("0"), Some(0));
    }

    #[test]
    fn test_parse_size_string_invalid() {
        assert_eq!(parse_size_string(""), None);
        assert_eq!(parse_size_string("abc"), None);
        assert_eq!(parse_size_string("MB"), None);
    }

    // ========================================================================
    // TOML Parsing Tests
    // ========================================================================

    #[test]
    fn test_parse_valid_policy_file() {
        let toml_str = r#"
[service]
name = "test/service"

[[allow]]
principal = { uid = 1000 }
roles = ["publisher", "subscriber"]

[[allow]]
principal = { gid = 100 }
roles = ["subscriber"]

[[deny]]
principal = "any"
reason = "Default deny all"

[limits]
max_publishers = 4
max_subscribers = 16
max_segment_size = "64MB"
"#;

        let policy_file: PolicyFile = toml::from_str(toml_str).unwrap();
        assert_eq!(policy_file.service.name, "test/service");
        assert_eq!(policy_file.allow.len(), 2);
        assert_eq!(policy_file.deny.len(), 1);
        assert!(policy_file.limits.is_some());

        let limits = policy_file.limits.unwrap();
        assert_eq!(limits.max_publishers, Some(4));
        assert_eq!(limits.max_subscribers, Some(16));
        assert_eq!(
            limits.max_segment_size.as_deref(),
            Some("64MB")
        );
    }

    #[test]
    fn test_parse_policy_file_uid_range() {
        let toml_str = r#"
[service]
name = "test/range"

[[allow]]
principal = { min = 1000, max = 2000 }
roles = ["publisher"]
"#;

        let policy_file: PolicyFile = toml::from_str(toml_str).unwrap();
        let rule = &policy_file.allow[0];
        assert!(matches!(
            rule.principal,
            PrincipalMatcher::UidRange { min: 1000, max: 2000 }
        ));
    }

    // ========================================================================
    // PrincipalMatcher Tests
    // ========================================================================

    #[test]
    fn test_principal_matcher_uid() {
        let matcher = PrincipalMatcher::Uid { uid: 1000 };
        assert!(matcher.matches(&ProcessCredentials::new(1, 1000, 100)));
        assert!(!matcher.matches(&ProcessCredentials::new(1, 2000, 100)));
    }

    #[test]
    fn test_principal_matcher_gid() {
        let matcher = PrincipalMatcher::Gid { gid: 100 };
        assert!(matcher.matches(&ProcessCredentials::new(1, 1000, 100)));
        assert!(!matcher.matches(&ProcessCredentials::new(1, 1000, 200)));
    }

    #[test]
    fn test_principal_matcher_uid_range() {
        let matcher = PrincipalMatcher::UidRange { min: 1000, max: 2000 };
        assert!(matcher.matches(&ProcessCredentials::new(1, 1000, 100)));
        assert!(matcher.matches(&ProcessCredentials::new(1, 1500, 100)));
        assert!(matcher.matches(&ProcessCredentials::new(1, 2000, 100)));
        assert!(!matcher.matches(&ProcessCredentials::new(1, 999, 100)));
        assert!(!matcher.matches(&ProcessCredentials::new(1, 2001, 100)));
    }

    #[test]
    fn test_principal_matcher_any() {
        let matcher = PrincipalMatcher::Any(AnyMarker);
        assert!(matcher.matches(&ProcessCredentials::new(1, 0, 0)));
        assert!(matcher.matches(&ProcessCredentials::new(1, 9999, 9999)));
    }

    // ========================================================================
    // ConfiguredPolicy Tests
    // ========================================================================

    fn make_test_policy() -> ConfiguredPolicy {
        let toml_str = r#"
[service]
name = "test/policy"

[[allow]]
principal = { uid = 1000 }
roles = ["publisher", "subscriber"]

[[allow]]
principal = { gid = 100 }
roles = ["subscriber"]

[[deny]]
principal = { uid = 9999 }
reason = "Banned user"

[limits]
max_publishers = 4
max_segment_size = "32MB"
"#;
        let policy_file: PolicyFile = toml::from_str(toml_str).unwrap();
        ConfiguredPolicy::from_policy_file(policy_file, 1000)
    }

    #[test]
    fn test_configured_policy_deny_first() {
        let policy = make_test_policy();
        let banned_creds = ProcessCredentials::new(1, 9999, 100);

        // Even though GID 100 matches an allow rule, UID 9999 is denied
        let decision = policy.authorize_connect(&banned_creds);
        assert!(decision.is_denied());
    }

    #[test]
    fn test_configured_policy_allow_uid() {
        let policy = make_test_policy();
        let creds = ProcessCredentials::new(1, 1000, 200);
        let service_name = ServiceName::new("test/policy").unwrap();

        let decision = policy.authorize_create(
            &creds,
            &service_name,
            MessagingPatternKind::PublishSubscribe,
        );
        assert!(decision.is_allowed());
    }

    #[test]
    fn test_configured_policy_attach_with_role() {
        use crate::service::messaging_pattern::MessagingPattern;
        use iceoryx2_cal::hash::sha1::Sha1;

        let policy = make_test_policy();
        let creds = ProcessCredentials::new(1, 1000, 200);
        let service_name = ServiceName::new("test/policy").unwrap();
        let service_id = ServiceId::new::<Sha1>(&service_name, MessagingPattern::PublishSubscribe);

        // UID 1000 has publisher role
        let decision = policy.authorize_attach(&creds, &service_id, PortType::Publisher);
        assert!(decision.is_allowed());

        // UID 1000 has subscriber role
        let decision = policy.authorize_attach(&creds, &service_id, PortType::Subscriber);
        assert!(decision.is_allowed());

        // UID 1000 does NOT have server role
        let decision = policy.authorize_attach(&creds, &service_id, PortType::Server);
        assert!(decision.is_denied());
    }

    #[test]
    fn test_configured_policy_attach_gid_role() {
        use crate::service::messaging_pattern::MessagingPattern;
        use iceoryx2_cal::hash::sha1::Sha1;

        let policy = make_test_policy();
        // UID 5000 with GID 100 - matches the GID allow rule
        let creds = ProcessCredentials::new(1, 5000, 100);
        let service_name = ServiceName::new("test/policy").unwrap();
        let service_id = ServiceId::new::<Sha1>(&service_name, MessagingPattern::PublishSubscribe);

        // GID 100 only has subscriber role
        let decision = policy.authorize_attach(&creds, &service_id, PortType::Subscriber);
        assert!(decision.is_allowed());

        // GID 100 does NOT have publisher role
        let decision = policy.authorize_attach(&creds, &service_id, PortType::Publisher);
        assert!(decision.is_denied());
    }

    #[test]
    fn test_configured_policy_no_matching_rule() {
        let policy = make_test_policy();
        // UID 3000, GID 300 - matches no rules
        let creds = ProcessCredentials::new(1, 3000, 300);
        let service_name = ServiceName::new("test/policy").unwrap();

        let decision = policy.authorize_create(
            &creds,
            &service_name,
            MessagingPatternKind::PublishSubscribe,
        );
        assert!(decision.is_denied());
    }

    #[test]
    fn test_configured_policy_limits() {
        let policy = make_test_policy();
        let creds = ProcessCredentials::new(1, 1000, 100);

        let limits = policy.get_limits(&creds);
        assert_eq!(limits.max_publishers, 4);
        assert_eq!(limits.max_segment_size, 32 * 1024 * 1024);
        // Defaults for unspecified
        assert_eq!(limits.max_subscribers, 256);
    }

    #[test]
    fn test_configured_policy_add_segment_owner() {
        use crate::service::messaging_pattern::MessagingPattern;
        use iceoryx2_cal::hash::sha1::Sha1;

        let policy = make_test_policy();
        let owner_creds = ProcessCredentials::new(1, 1000, 100);
        let other_creds = ProcessCredentials::new(1, 2000, 100);
        let service_name = ServiceName::new("test/policy").unwrap();
        let service_id = ServiceId::new::<Sha1>(&service_name, MessagingPattern::PublishSubscribe);

        // Owner can add segment
        let decision = policy.authorize_add_segment(&owner_creds, &service_id, 4096);
        assert!(decision.is_allowed());

        // Non-owner cannot
        let decision = policy.authorize_add_segment(&other_creds, &service_id, 4096);
        assert!(decision.is_denied());
    }

    #[test]
    fn test_configured_policy_add_segment_size_limit() {
        use crate::service::messaging_pattern::MessagingPattern;
        use iceoryx2_cal::hash::sha1::Sha1;

        let policy = make_test_policy();
        let creds = ProcessCredentials::new(1, 1000, 100);
        let service_name = ServiceName::new("test/policy").unwrap();
        let service_id = ServiceId::new::<Sha1>(&service_name, MessagingPattern::PublishSubscribe);

        // Within limits (32MB)
        let decision = policy.authorize_add_segment(&creds, &service_id, 32 * 1024 * 1024);
        assert!(decision.is_allowed());

        // Exceeds limits
        let decision = policy.authorize_add_segment(&creds, &service_id, 33 * 1024 * 1024);
        assert!(decision.is_denied());
        match decision {
            PolicyDecision::Deny { reason, .. } => {
                assert_eq!(reason, DenialReason::ResourceLimitExceeded);
            }
            _ => panic!("Expected Deny"),
        }
    }

    // ========================================================================
    // PolicyDispatch Tests
    // ========================================================================

    #[test]
    fn test_policy_dispatch_default() {
        let dispatch = PolicyDispatch::Default(DefaultPolicy::with_owner(1000));
        let creds = ProcessCredentials::new(1, 1000, 100);
        let service_name = ServiceName::new("test/dispatch").unwrap();

        let decision = dispatch.authorize_create(
            &creds,
            &service_name,
            MessagingPatternKind::PublishSubscribe,
        );
        assert!(decision.is_allowed());
    }

    #[test]
    fn test_policy_dispatch_configured() {
        let dispatch = PolicyDispatch::Configured(make_test_policy());
        let creds = ProcessCredentials::new(1, 1000, 100);
        let service_name = ServiceName::new("test/dispatch").unwrap();

        let decision = dispatch.authorize_create(
            &creds,
            &service_name,
            MessagingPatternKind::PublishSubscribe,
        );
        assert!(decision.is_allowed());
    }

    // ========================================================================
    // PolicyLoader Tests
    // ========================================================================

    fn unique_test_dir(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir()
            .join("iceoryx2_iam_policy_tests")
            .join(name)
            .join(format!("{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn test_policy_loader_missing_file() {
        let dir = unique_test_dir("missing");
        let service_name = ServiceName::new("nonexistent/service").unwrap();
        let result = PolicyLoader::load_for_service(&dir, &service_name);
        assert!(result.is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_policy_loader_valid_file() {
        let dir = unique_test_dir("valid");
        let toml_content = r#"
[service]
name = "test/loader"

[[allow]]
principal = { uid = 1000 }
roles = ["publisher"]
"#;
        std::fs::write(dir.join("test_loader.toml"), toml_content).unwrap();

        let service_name = ServiceName::new("test/loader").unwrap();
        let result = PolicyLoader::load_for_service(&dir, &service_name);
        assert!(result.is_some());
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ========================================================================
    // sanitize_service_name Tests
    // ========================================================================

    #[test]
    fn test_sanitize_service_name() {
        assert_eq!(sanitize_service_name("test/service"), "test_service");
        assert_eq!(sanitize_service_name("my-service"), "my-service");
        assert_eq!(sanitize_service_name("a.b.c"), "a_b_c");
        assert_eq!(sanitize_service_name("simple"), "simple");
    }

    // ========================================================================
    // PolicyLimits Tests
    // ========================================================================

    #[test]
    fn test_policy_limits_to_resource_limits_full() {
        let limits = PolicyLimits {
            max_publishers: Some(8),
            max_subscribers: Some(32),
            max_servers: Some(4),
            max_clients: Some(16),
            max_segments: Some(10),
            max_segment_size: Some(String::from("128MB")),
        };

        let rl = limits.to_resource_limits();
        assert_eq!(rl.max_publishers, 8);
        assert_eq!(rl.max_subscribers, 32);
        assert_eq!(rl.max_servers, 4);
        assert_eq!(rl.max_clients, 16);
        assert_eq!(rl.max_segments, 10);
        assert_eq!(rl.max_segment_size, 128 * 1024 * 1024);
    }

    #[test]
    fn test_policy_limits_to_resource_limits_partial() {
        let limits = PolicyLimits {
            max_publishers: Some(8),
            max_subscribers: None,
            max_servers: None,
            max_clients: None,
            max_segments: None,
            max_segment_size: None,
        };

        let rl = limits.to_resource_limits();
        assert_eq!(rl.max_publishers, 8);
        // Defaults
        assert_eq!(rl.max_subscribers, 256);
        assert_eq!(rl.max_segment_size, 64 * 1024 * 1024);
    }
}
