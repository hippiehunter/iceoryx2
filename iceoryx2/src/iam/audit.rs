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

//! Audit logging for IAM authorization decisions.
//!
//! This module provides types for recording and persisting IAM authorization
//! decisions for security monitoring and compliance.
//!
//! # Overview
//!
//! - [`AuditEvent`]: Represents a single auditable event
//! - [`AuditEventKind`]: The type of event being audited
//! - [`AuditLogger`]: Trait for audit log backends
//! - [`FileAuditLogger`]: Append-only JSON Lines file logger with background writer

use alloc::string::String;
use std::io::Write;
use std::sync::mpsc;
use std::thread;
use std::time::SystemTime;

use iceoryx2_cal::security::credentials::ProcessCredentials;

use super::policy::PolicyDecision;
use super::protocol::{MessagingPatternKind, PortType};

// ============================================================================
// AuditEventKind
// ============================================================================

/// The kind of auditable IAM event.
#[derive(Debug, Clone)]
pub enum AuditEventKind {
    /// A client connected to the IAM server.
    Connect,
    /// A service creation was requested.
    Create {
        /// The messaging pattern of the service.
        messaging_pattern: MessagingPatternKind,
    },
    /// A port attachment was requested.
    Attach {
        /// The type of port being attached.
        port_type: PortType,
        /// The assigned port ID (0 if denied).
        port_id: u128,
    },
    /// A segment addition was requested.
    AddSegment {
        /// The requested segment size.
        size: usize,
    },
    /// A request was denied.
    Deny {
        /// The reason for denial.
        reason: String,
    },
    /// A port was detached.
    Detach {
        /// The port ID being detached.
        port_id: u128,
    },
}

// ============================================================================
// AuditEvent
// ============================================================================

/// A single auditable IAM event.
#[derive(Debug, Clone)]
pub struct AuditEvent {
    /// When the event occurred.
    pub timestamp: SystemTime,
    /// What kind of event occurred.
    pub kind: AuditEventKind,
    /// Credentials of the process that triggered the event.
    pub credentials: ProcessCredentials,
    /// The service name associated with this event.
    pub service_name: String,
    /// The policy decision for this event.
    pub decision: PolicyDecision,
}

impl AuditEvent {
    /// Creates a new audit event with the current timestamp.
    pub fn new(
        kind: AuditEventKind,
        credentials: ProcessCredentials,
        service_name: String,
        decision: PolicyDecision,
    ) -> Self {
        Self {
            timestamp: SystemTime::now(),
            kind,
            credentials,
            service_name,
            decision,
        }
    }
}

// ============================================================================
// SerializableAuditEvent (for JSON output)
// ============================================================================

/// Flat struct for JSON serialization of audit events.
#[derive(serde::Serialize)]
struct SerializableAuditEvent {
    timestamp_secs: u64,
    timestamp_nanos: u32,
    kind: String,
    uid: u32,
    gid: u32,
    pid: u32,
    service_name: String,
    decision: String,
    reason: String,
    message: String,
}

impl From<&AuditEvent> for SerializableAuditEvent {
    fn from(event: &AuditEvent) -> Self {
        let (secs, nanos) = event
            .timestamp
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| (d.as_secs(), d.subsec_nanos()))
            .unwrap_or((0, 0));

        let kind_str = match &event.kind {
            AuditEventKind::Connect => String::from("connect"),
            AuditEventKind::Create { messaging_pattern } => {
                format!("create:{:?}", messaging_pattern)
            }
            AuditEventKind::Attach { port_type, port_id } => {
                format!("attach:{:?}:{}", port_type, port_id)
            }
            AuditEventKind::AddSegment { size } => {
                format!("add_segment:{}", size)
            }
            AuditEventKind::Deny { reason } => {
                format!("deny:{}", reason)
            }
            AuditEventKind::Detach { port_id } => {
                format!("detach:{}", port_id)
            }
        };

        let (decision_str, reason_str, message_str) = match &event.decision {
            PolicyDecision::Allow => (
                String::from("allow"),
                String::new(),
                String::new(),
            ),
            PolicyDecision::Deny { reason, message } => (
                String::from("deny"),
                format!("{:?}", reason),
                message.clone(),
            ),
        };

        Self {
            timestamp_secs: secs,
            timestamp_nanos: nanos,
            kind: kind_str,
            uid: event.credentials.uid(),
            gid: event.credentials.gid(),
            pid: event.credentials.pid(),
            service_name: event.service_name.clone(),
            decision: decision_str,
            reason: reason_str,
            message: message_str,
        }
    }
}

// ============================================================================
// AuditLogger Trait
// ============================================================================

/// Trait for audit log backends.
///
/// Implementations must be `Send + Sync` since they may be shared across
/// threads (e.g., stored behind `Arc` or in server structs).
pub trait AuditLogger: Send + Sync {
    /// Logs a single audit event.
    fn log(&self, event: &AuditEvent);
}

// ============================================================================
// FileAuditLogger
// ============================================================================

/// Append-only JSON Lines file audit logger with background writer thread.
///
/// Uses an mpsc channel and a background writer thread to avoid blocking
/// the IAM server's processing loop. Each audit event is serialized as a
/// single JSON object on one line (JSON Lines format).
///
/// # Drop Behavior
///
/// When dropped, the sender is closed first (signaling the writer thread),
/// then the writer thread is joined to ensure all pending events are flushed.
pub struct FileAuditLogger {
    sender: Option<mpsc::Sender<AuditEvent>>,
    writer_thread: Option<thread::JoinHandle<()>>,
}

impl FileAuditLogger {
    /// Creates a new file audit logger.
    pub fn new(path: &std::path::Path) -> Result<Self, std::io::Error> {
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)?;

        let (sender, receiver) = mpsc::channel::<AuditEvent>();

        let writer_thread = thread::spawn(move || {
            let mut writer = std::io::BufWriter::new(file);
            for event in receiver {
                let serializable = SerializableAuditEvent::from(&event);
                if let Ok(json) = serde_json::to_string(&serializable) {
                    let _ = writeln!(writer, "{}", json);
                }
            }
            let _ = writer.flush();
        });

        Ok(Self {
            sender: Some(sender),
            writer_thread: Some(writer_thread),
        })
    }
}

impl AuditLogger for FileAuditLogger {
    fn log(&self, event: &AuditEvent) {
        if let Some(ref sender) = self.sender {
            let _ = sender.send(event.clone());
        }
    }
}

impl Drop for FileAuditLogger {
    fn drop(&mut self) {
        // Drop the sender first to close the channel
        self.sender.take();
        // Then join the writer thread to flush pending events
        if let Some(thread) = self.writer_thread.take() {
            let _ = thread.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::iam::protocol::DenialReason;

    fn test_credentials() -> ProcessCredentials {
        ProcessCredentials::new(1234, 1000, 1000)
    }

    #[test]
    fn test_audit_event_creation() {
        let event = AuditEvent::new(
            AuditEventKind::Connect,
            test_credentials(),
            String::from("test/service"),
            PolicyDecision::Allow,
        );

        assert_eq!(event.service_name, "test/service");
        assert!(event.decision.is_allowed());
        assert!(matches!(event.kind, AuditEventKind::Connect));
    }

    #[test]
    fn test_serializable_audit_event_from_allow() {
        let event = AuditEvent::new(
            AuditEventKind::Connect,
            test_credentials(),
            String::from("test/service"),
            PolicyDecision::Allow,
        );

        let serializable = SerializableAuditEvent::from(&event);
        assert_eq!(serializable.kind, "connect");
        assert_eq!(serializable.decision, "allow");
        assert_eq!(serializable.uid, 1000);
        assert_eq!(serializable.gid, 1000);
        assert_eq!(serializable.pid, 1234);
        assert_eq!(serializable.service_name, "test/service");
        assert!(serializable.reason.is_empty());
    }

    #[test]
    fn test_serializable_audit_event_from_deny() {
        let event = AuditEvent::new(
            AuditEventKind::Connect,
            test_credentials(),
            String::from("test/service"),
            PolicyDecision::deny(DenialReason::Unauthorized, "not allowed"),
        );

        let serializable = SerializableAuditEvent::from(&event);
        assert_eq!(serializable.decision, "deny");
        assert_eq!(serializable.reason, "Unauthorized");
        assert_eq!(serializable.message, "not allowed");
    }

    #[test]
    fn test_serializable_audit_event_json() {
        let event = AuditEvent::new(
            AuditEventKind::Attach {
                port_type: PortType::Publisher,
                port_id: 42,
            },
            test_credentials(),
            String::from("test/service"),
            PolicyDecision::Allow,
        );

        let serializable = SerializableAuditEvent::from(&event);
        let json = serde_json::to_string(&serializable).unwrap();
        assert!(json.contains("\"kind\":\"attach:Publisher:42\""));
        assert!(json.contains("\"decision\":\"allow\""));
    }

    fn unique_test_dir(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir()
            .join("iceoryx2_iam_audit_tests")
            .join(name)
            .join(format!("{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn test_file_audit_logger_writes_json_lines() {
        let dir = unique_test_dir("json_lines");
        let log_path = dir.join("audit.log");

        {
            let logger = FileAuditLogger::new(&log_path).unwrap();
            logger.log(&AuditEvent::new(
                AuditEventKind::Connect,
                test_credentials(),
                String::from("test/service"),
                PolicyDecision::Allow,
            ));
            logger.log(&AuditEvent::new(
                AuditEventKind::Deny {
                    reason: String::from("unauthorized"),
                },
                test_credentials(),
                String::from("test/service"),
                PolicyDecision::deny(DenialReason::Unauthorized, "denied"),
            ));
            // Drop triggers flush
        }

        let contents = std::fs::read_to_string(&log_path).unwrap();
        let lines: Vec<&str> = contents.lines().collect();
        assert_eq!(lines.len(), 2);

        // Verify each line is valid JSON
        for line in &lines {
            let parsed: serde_json::Value = serde_json::from_str(line).unwrap();
            assert!(parsed.get("kind").is_some());
            assert!(parsed.get("decision").is_some());
            assert!(parsed.get("uid").is_some());
        }

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_file_audit_logger_concurrent_logging() {
        let dir = unique_test_dir("concurrent");
        let log_path = dir.join("audit_concurrent.log");

        {
            let logger = std::sync::Arc::new(
                FileAuditLogger::new(&log_path).unwrap(),
            );

            let mut handles = Vec::new();
            for i in 0..10 {
                let logger_clone = std::sync::Arc::clone(&logger);
                handles.push(std::thread::spawn(move || {
                    for j in 0..10 {
                        logger_clone.log(&AuditEvent::new(
                            AuditEventKind::Connect,
                            ProcessCredentials::new((i * 10 + j) as u32, 1000, 1000),
                            String::from("test/concurrent"),
                            PolicyDecision::Allow,
                        ));
                    }
                }));
            }

            for h in handles {
                h.join().unwrap();
            }
            // Drop the Arc clones, then the logger
            drop(logger);
        }

        let contents = std::fs::read_to_string(&log_path).unwrap();
        let lines: Vec<&str> = contents.lines().filter(|l| !l.is_empty()).collect();
        assert_eq!(lines.len(), 100);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_audit_event_kind_variants() {
        // Verify all variants can be created and debug-printed
        let kinds = vec![
            AuditEventKind::Connect,
            AuditEventKind::Create {
                messaging_pattern: MessagingPatternKind::PublishSubscribe,
            },
            AuditEventKind::Attach {
                port_type: PortType::Subscriber,
                port_id: 1,
            },
            AuditEventKind::AddSegment { size: 4096 },
            AuditEventKind::Deny {
                reason: String::from("test"),
            },
            AuditEventKind::Detach { port_id: 2 },
        ];

        for kind in &kinds {
            let _debug = format!("{:?}", kind);
        }
    }
}
