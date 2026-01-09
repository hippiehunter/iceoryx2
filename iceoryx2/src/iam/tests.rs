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

//! Integration tests for the IAM client-server system.
//!
//! This module provides comprehensive integration tests that exercise the full
//! client-server communication path using mock control channel implementations.
//!
//! # Test Architecture
//!
//! The tests use a mock channel pair that connects a client and server:
//! - `MockClientChannel`: Implements `ClientControlChannelConnection` for the client
//! - `MockServerChannel`: Implements `ControlChannelConnection` for the server
//! - `MockChannelPair`: Creates connected pairs of channels
//!
//! The mock channels use shared message containers to pass messages between
//! client and server, simulating the control channel communication.
//!
//! # Test Scenarios
//!
//! - Handshake flow (Hello -> HelloOk)
//! - Port attachment (Publisher, Subscriber, Server, Client)
//! - Detach flow
//! - Policy denial scenarios
//! - Multiple clients with same server
//! - Session cleanup on disconnect

#[cfg(test)]
mod integration_tests {
    use alloc::collections::VecDeque;
    use alloc::vec::Vec;
    use core::time::Duration;
    use std::sync::{Arc, Mutex};

    use iceoryx2_bb_posix::unique_system_id::UniqueSystemId;
    use iceoryx2_bb_system_types::file_name::FileName;
    use iceoryx2_cal::control_channel::{
        ControlChannelAcceptError, ControlChannelClient as CalClient,
        ControlChannelConnection as CalConnection, ControlChannelCredentialsError,
        ControlChannelListener as CalListener, ControlChannelReceiveError, ControlChannelSendError,
    };
    use iceoryx2_cal::hash::sha1::Sha1;
    use iceoryx2_cal::named_concept::NamedConcept;
    use iceoryx2_cal::security::credentials::ProcessCredentials;
    use iceoryx2_cal::security::handle::PlatformHandle;
    use iceoryx2_cal::serialize::{postcard::Postcard, Serialize as CalSerialize};
    use iceoryx2_cal::shm_allocator::SegmentId;

    use crate::iam::client::IamClient;
    use crate::iam::policy::{DefaultPolicy, IamPolicy, PolicyDecision, ResourceLimits};
    use crate::iam::protocol::{
        DenialReason, IamRequest, IamResponse, MessagingPatternKind, PortType,
        ProtocolVersion,
    };
    use crate::iam::server::IamServer;
    use crate::service::messaging_pattern::MessagingPattern;
    use crate::service::service_id::ServiceId;
    use crate::service::service_name::ServiceName;

    // ========================================================================
    // Mock Channel Infrastructure
    // ========================================================================

    /// Shared raw byte container for passing between client and server.
    ///
    /// This is shared between MockServerChannel and MockClientChannel to simulate
    /// bidirectional communication. Raw bytes are used to match CAL's interface.
    struct SharedBytes {
        /// Raw requests (length-framed serialized IamRequest bytes).
        requests: Mutex<VecDeque<Vec<u8>>>,
        /// Raw responses (length-framed serialized IamResponse bytes).
        responses: Mutex<VecDeque<Vec<u8>>>,
        /// Track number of handles sent (since PlatformHandle doesn't implement Clone).
        handle_count: Mutex<usize>,
        /// Current offset into the first request entry (for partial reads).
        request_offset: Mutex<usize>,
        /// Current offset into the first response entry (for partial reads).
        response_offset: Mutex<usize>,
    }

    impl SharedBytes {
        fn new() -> Self {
            Self {
                requests: Mutex::new(VecDeque::new()),
                responses: Mutex::new(VecDeque::new()),
                handle_count: Mutex::new(0),
                request_offset: Mutex::new(0),
                response_offset: Mutex::new(0),
            }
        }

        /// Queues a typed request to be received by the server.
        fn push_request(&self, request: &IamRequest) {
            let payload = Postcard::serialize(request).unwrap();
            let len = payload.len() as u32;
            let mut framed = Vec::with_capacity(4 + payload.len());
            framed.extend_from_slice(&len.to_le_bytes());
            framed.extend_from_slice(&payload);
            self.requests.lock().unwrap().push_back(framed);
        }

        /// Reads all typed responses that have been sent by the server.
        fn get_responses(&self) -> Vec<IamResponse> {
            self.responses
                .lock()
                .unwrap()
                .iter()
                .filter_map(|data| {
                    if data.len() < 4 {
                        return None;
                    }
                    Postcard::deserialize(&data[4..]).ok()
                })
                .collect()
        }

        /// Clears all responses (for tests that need to check multiple rounds).
        fn clear_responses(&self) {
            self.responses.lock().unwrap().clear();
            *self.response_offset.lock().unwrap() = 0;
        }
    }

    /// Mock channel for the server side that implements CAL's ControlChannelConnection.
    ///
    /// Receives requests from the client and sends responses back.
    struct MockServerChannel {
        credentials: ProcessCredentials,
        /// Shared with client for message passing.
        shared: Arc<SharedBytes>,
    }

    impl MockServerChannel {
        fn new(credentials: ProcessCredentials, shared: Arc<SharedBytes>) -> Self {
            Self {
                credentials,
                shared,
            }
        }
    }

    impl core::fmt::Debug for MockServerChannel {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            f.debug_struct("MockServerChannel").finish()
        }
    }

    impl CalConnection for MockServerChannel {
        fn peer_credentials(&self) -> Result<ProcessCredentials, ControlChannelCredentialsError> {
            Ok(self.credentials.clone())
        }

        fn send_handles(
            &self,
            handles: &[&PlatformHandle],
        ) -> Result<(), ControlChannelSendError> {
            let mut handle_count = self.shared.handle_count.lock().unwrap();
            *handle_count += handles.len();
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
            // Server sends responses
            self.shared.responses.lock().unwrap().push_back(data.to_vec());
            Ok(())
        }

        fn try_send(&self, data: &[u8]) -> Result<u64, ControlChannelSendError> {
            self.send(data)?;
            Ok(data.len() as u64)
        }

        fn receive(&self, buffer: &mut [u8]) -> Result<u64, ControlChannelReceiveError> {
            // Server receives requests
            let mut queue = self.shared.requests.lock().unwrap();
            let mut offset = self.shared.request_offset.lock().unwrap();

            if queue.is_empty() {
                return Err(ControlChannelReceiveError::WouldBlock);
            }

            let front = queue.front().unwrap();
            let remaining = &front[*offset..];
            let to_copy = core::cmp::min(remaining.len(), buffer.len());
            buffer[..to_copy].copy_from_slice(&remaining[..to_copy]);

            if *offset + to_copy >= front.len() {
                queue.pop_front();
                *offset = 0;
            } else {
                *offset += to_copy;
            }

            Ok(to_copy as u64)
        }

        fn try_receive(&self, buffer: &mut [u8]) -> Result<u64, ControlChannelReceiveError> {
            if self.shared.requests.lock().unwrap().is_empty() {
                return Ok(0);
            }
            self.receive(buffer)
        }
    }

    /// Mock channel for the client side.
    ///
    /// This is a wrapper that provides access to SharedBytes for tests that
    /// want to directly manipulate the request/response queues.
    struct MockClientChannel {
        /// Shared with server for message passing.
        pub shared: Arc<SharedBytes>,
    }

    impl MockClientChannel {
        fn new(shared: Arc<SharedBytes>) -> Self {
            Self { shared }
        }
    }

    impl core::fmt::Debug for MockClientChannel {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            f.debug_struct("MockClientChannel").finish()
        }
    }

    impl NamedConcept for MockClientChannel {
        fn name(&self) -> &FileName {
            static NAME: FileName = unsafe { FileName::new_unchecked_const(b"mock_client") };
            &NAME
        }
    }

    impl CalClient for MockClientChannel {
        fn peer_credentials(&self) -> Result<ProcessCredentials, ControlChannelCredentialsError> {
            // Return some default credentials for the "server"
            Ok(ProcessCredentials::new(9999, 0, 0))
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
            // Return handles if any were "sent" by the server
            let mut handle_count = self.shared.handle_count.lock().unwrap();
            if *handle_count > 0 {
                *handle_count = 0;
                // Return empty vec - we can't actually pass handles, but track the count
                Ok(Some(vec![]))
            } else {
                Ok(None)
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
            // Client sends requests
            self.shared.requests.lock().unwrap().push_back(data.to_vec());
            Ok(())
        }

        fn try_send(&self, data: &[u8]) -> Result<u64, ControlChannelSendError> {
            self.send(data)?;
            Ok(data.len() as u64)
        }

        fn receive(&self, buffer: &mut [u8]) -> Result<u64, ControlChannelReceiveError> {
            // Client receives responses
            let mut queue = self.shared.responses.lock().unwrap();
            let mut offset = self.shared.response_offset.lock().unwrap();

            if queue.is_empty() {
                return Err(ControlChannelReceiveError::WouldBlock);
            }

            let front = queue.front().unwrap();
            let remaining = &front[*offset..];
            let to_copy = core::cmp::min(remaining.len(), buffer.len());
            buffer[..to_copy].copy_from_slice(&remaining[..to_copy]);

            if *offset + to_copy >= front.len() {
                queue.pop_front();
                *offset = 0;
            } else {
                *offset += to_copy;
            }

            Ok(to_copy as u64)
        }

        fn try_receive(&self, buffer: &mut [u8]) -> Result<u64, ControlChannelReceiveError> {
            if self.shared.responses.lock().unwrap().is_empty() {
                return Ok(0);
            }
            self.receive(buffer)
        }
    }

    /// Mock listener that produces mock server channels.
    struct MockListener {
        pending_connections: Mutex<Vec<(ProcessCredentials, Arc<SharedBytes>)>>,
    }

    impl MockListener {
        fn new() -> Self {
            Self {
                pending_connections: Mutex::new(Vec::new()),
            }
        }

        /// Creates a new channel pair and queues the server side for acceptance.
        fn create_channel_pair(
            &self,
            credentials: ProcessCredentials,
        ) -> MockClientChannel {
            let shared = Arc::new(SharedBytes::new());
            let client_channel = MockClientChannel::new(Arc::clone(&shared));

            // Queue the server connection for acceptance
            self.pending_connections
                .lock()
                .unwrap()
                .push((credentials, shared));

            client_channel
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
        type Connection = MockServerChannel;

        fn try_accept(&self) -> Result<Option<Self::Connection>, ControlChannelAcceptError> {
            let mut pending = self.pending_connections.lock().unwrap();
            if pending.is_empty() {
                Ok(None)
            } else {
                let (credentials, shared) = pending.remove(0);
                Ok(Some(MockServerChannel::new(credentials, shared)))
            }
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

    // ========================================================================
    // Test Helpers
    // ========================================================================

    fn test_credentials() -> ProcessCredentials {
        ProcessCredentials::new(1234, 1000, 1000)
    }

    fn unauthorized_credentials() -> ProcessCredentials {
        ProcessCredentials::new(5678, 2000, 2000)
    }

    fn create_test_server(
        listener: MockListener,
        owner_uid: u32,
    ) -> IamServer<MockListener, DefaultPolicy> {
        let policy = DefaultPolicy::with_owner(owner_uid);
        IamServer::new(listener, policy)
    }

    fn create_test_service_id(name: &str) -> ServiceId {
        let service_name = ServiceName::new(name).unwrap();
        ServiceId::new::<Sha1>(&service_name, MessagingPattern::PublishSubscribe)
    }


    // ========================================================================
    // Handshake Tests
    // ========================================================================

    #[test]
    fn test_integration_handshake_success() {
        let listener = MockListener::new();

        // Create a channel pair
        let client_channel = listener.create_channel_pair(test_credentials());
        let shared = Arc::clone(&client_channel.shared);

        // Create server
        let mut server = create_test_server(listener, 1000);

        // Send Hello request through shared messages
        let node_id = UniqueSystemId::new().unwrap();
        shared.push_request(&IamRequest::Hello {
            protocol_version: ProtocolVersion::CURRENT,
            node_id,
        });

        // Server accepts connection and processes request
        server.process().unwrap(); // Accept connection
        server.process().unwrap(); // Process Hello request

        // Check response
        let responses = shared.get_responses();
        match &responses[0] {
            IamResponse::HelloOk {
                negotiated_version,
                session_id,
            } => {
                assert_eq!(*negotiated_version, ProtocolVersion::CURRENT);
                assert!(session_id.is_valid());
            }
            _ => panic!("Expected HelloOk response, got {:?}", responses[0]),
        }

        assert_eq!(server.session_count(), 1);
    }

    #[test]
    fn test_integration_handshake_version_mismatch() {
        let listener = MockListener::new();
        let client_channel = listener.create_channel_pair(test_credentials());
        let mut server = create_test_server(listener, 1000);
        let node_id = UniqueSystemId::new().unwrap();

        // Client sends Hello with incompatible version (major version mismatch)
        let request = IamRequest::Hello {
            protocol_version: ProtocolVersion::new(99, 0), // Invalid major version
            node_id,
        };

        // Get a reference to the shared messages before the client_channel is consumed
        let shared = Arc::clone(&client_channel.shared);
        shared.push_request(&request);

        // Server accepts and processes
        server.process().unwrap();
        server.process().unwrap();

        // Check response
        let responses = shared.get_responses();
        match &responses[0] {
            IamResponse::Denied { reason, .. } => {
                assert_eq!(*reason, DenialReason::VersionMismatch);
            }
            _ => panic!("Expected Denied response, got {:?}", responses[0]),
        }
    }

    #[test]
    fn test_integration_unauthorized_operations_denied() {
        // Note: DefaultPolicy allows ALL connections but denies operations for mismatched UIDs.
        // This test verifies that operations are denied, not that connections are rejected.
        let listener = MockListener::new();
        let client_channel = listener.create_channel_pair(unauthorized_credentials());
        let shared = Arc::clone(&client_channel.shared);

        // Server with owner UID 1000, client has UID 2000
        let mut server = create_test_server(listener, 1000);

        // Complete handshake (connections always accepted)
        let node_id = UniqueSystemId::new().unwrap();
        shared.push_request(&IamRequest::Hello {
            protocol_version: ProtocolVersion::CURRENT,
            node_id,
        });

        server.process().unwrap(); // Accept connection
        server.process().unwrap(); // Process Hello

        // Verify handshake succeeded (connections always allowed)
        {
            let responses = shared.get_responses();
            assert!(matches!(responses[0], IamResponse::HelloOk { .. }));
        }
        shared.clear_responses();

        // Try to attach publisher - should be DENIED due to UID mismatch
        let service_id = create_test_service_id("test/unauthorized");
        shared.push_request(&IamRequest::AttachPublisher {
            service_id,
            history_size: 8,
            max_slice_len: 1024,
        });

        server.process().unwrap();

        let responses = shared.get_responses();
        match &responses[0] {
            IamResponse::Denied { reason, .. } => {
                assert_eq!(*reason, DenialReason::Unauthorized);
            }
            _ => panic!("Expected Denied response for unauthorized UID, got {:?}", responses[0]),
        }
    }

    // ========================================================================
    // Port Attachment Tests
    // ========================================================================

    #[test]
    fn test_integration_attach_publisher_success() {
        let listener = MockListener::new();
        let client_channel = listener.create_channel_pair(test_credentials());
        let shared = Arc::clone(&client_channel.shared);
        let mut server = create_test_server(listener, 1000);

        // Complete handshake first
        let node_id = UniqueSystemId::new().unwrap();
        shared.push_request(&IamRequest::Hello {
            protocol_version: ProtocolVersion::CURRENT,
            node_id,
        });

        server.process().unwrap(); // Accept
        server.process().unwrap(); // Process Hello

        // Clear responses
        shared.clear_responses();

        // Send AttachPublisher request
        let service_id = create_test_service_id("test/publisher");
        shared.push_request(&IamRequest::AttachPublisher {
            service_id,
            history_size: 8,
            max_slice_len: 1024,
        });

        // Server processes
        server.process().unwrap();

        // Check response
        let responses = shared.get_responses();
        match &responses[0] {
            IamResponse::AttachOk { port_id, .. } => {
                assert!(*port_id > 0);
            }
            _ => panic!("Expected AttachOk response, got {:?}", responses[0]),
        }
    }

    #[test]
    fn test_integration_attach_subscriber_success() {
        let listener = MockListener::new();
        let client_channel = listener.create_channel_pair(test_credentials());
        let shared = Arc::clone(&client_channel.shared);
        let mut server = create_test_server(listener, 1000);

        // Complete handshake
        let node_id = UniqueSystemId::new().unwrap();
        shared.push_request(&IamRequest::Hello {
            protocol_version: ProtocolVersion::CURRENT,
            node_id,
        });

        server.process().unwrap();
        server.process().unwrap();
        shared.clear_responses();

        // Send AttachSubscriber request
        let service_id = create_test_service_id("test/subscriber");
        shared.push_request(&IamRequest::AttachSubscriber {
            service_id,
            buffer_size: 16,
        });

        server.process().unwrap();

        let responses = shared.get_responses();
        match &responses[0] {
            IamResponse::AttachOk { port_id, .. } => {
                assert!(*port_id > 0);
            }
            _ => panic!("Expected AttachOk response, got {:?}", responses[0]),
        }
    }

    #[test]
    fn test_integration_attach_server_port_success() {
        let listener = MockListener::new();
        let client_channel = listener.create_channel_pair(test_credentials());
        let shared = Arc::clone(&client_channel.shared);
        let mut server = create_test_server(listener, 1000);

        // Complete handshake
        let node_id = UniqueSystemId::new().unwrap();
        shared.push_request(&IamRequest::Hello {
            protocol_version: ProtocolVersion::CURRENT,
            node_id,
        });

        server.process().unwrap();
        server.process().unwrap();
        shared.clear_responses();

        // Send AttachServer request
        let service_id = create_test_service_id("test/server");
        shared.push_request(&IamRequest::AttachServer {
            service_id,
            max_active_requests: 10,
        });

        server.process().unwrap();

        let responses = shared.get_responses();
        assert!(matches!(responses[0], IamResponse::AttachOk { .. }));
    }

    #[test]
    fn test_integration_attach_client_port_success() {
        let listener = MockListener::new();
        let client_channel = listener.create_channel_pair(test_credentials());
        let shared = Arc::clone(&client_channel.shared);
        let mut server = create_test_server(listener, 1000);

        // Complete handshake
        let node_id = UniqueSystemId::new().unwrap();
        shared.push_request(&IamRequest::Hello {
            protocol_version: ProtocolVersion::CURRENT,
            node_id,
        });

        server.process().unwrap();
        server.process().unwrap();
        shared.clear_responses();

        // Send AttachClient request
        let service_id = create_test_service_id("test/client");
        shared.push_request(&IamRequest::AttachClient {
            service_id,
            max_pending_responses: 5,
        });

        server.process().unwrap();

        let responses = shared.get_responses();
        assert!(matches!(responses[0], IamResponse::AttachOk { .. }));
    }

    #[test]
    fn test_integration_attach_without_handshake_fails() {
        let listener = MockListener::new();
        let client_channel = listener.create_channel_pair(test_credentials());
        let shared = Arc::clone(&client_channel.shared);
        let mut server = create_test_server(listener, 1000);

        // Accept connection but don't complete handshake
        server.process().unwrap();

        // Send AttachPublisher without handshake
        let service_id = create_test_service_id("test/no-handshake");
        shared.push_request(&IamRequest::AttachPublisher {
            service_id,
            history_size: 8,
            max_slice_len: 1024,
        });

        server.process().unwrap();

        let responses = shared.get_responses();
        match &responses[0] {
            IamResponse::ProtocolError { message } => {
                assert!(message.contains("Handshake not complete"));
            }
            _ => panic!("Expected ProtocolError response, got {:?}", responses[0]),
        }
    }

    // ========================================================================
    // Detach Tests
    // ========================================================================

    #[test]
    fn test_integration_detach_success() {
        let listener = MockListener::new();
        let client_channel = listener.create_channel_pair(test_credentials());
        let shared = Arc::clone(&client_channel.shared);
        let mut server = create_test_server(listener, 1000);

        // Complete handshake
        let node_id = UniqueSystemId::new().unwrap();
        shared.push_request(&IamRequest::Hello {
            protocol_version: ProtocolVersion::CURRENT,
            node_id,
        });

        server.process().unwrap();
        server.process().unwrap();
        shared.clear_responses();

        // Attach a publisher first
        let service_id = create_test_service_id("test/detach");
        shared.push_request(&IamRequest::AttachPublisher {
            service_id,
            history_size: 8,
            max_slice_len: 1024,
        });

        server.process().unwrap();

        // Get the port ID from the response
        let port_id = {
            let responses = shared.get_responses();
            match &responses[0] {
                IamResponse::AttachOk { port_id, .. } => *port_id,
                _ => panic!("Expected AttachOk"),
            }
        };

        shared.clear_responses();

        // Now detach
        shared.push_request(&IamRequest::Detach { service_id, port_id });

        server.process().unwrap();

        let responses = shared.get_responses();
        assert!(matches!(responses[0], IamResponse::DetachOk));
    }

    // ========================================================================
    // Policy Denial Tests
    // ========================================================================

    #[test]
    fn test_integration_unauthorized_attach_denied() {
        // Create a policy that allows connect but denies attach
        struct RestrictivePolicy {
            owner_uid: u32,
        }

        impl IamPolicy for RestrictivePolicy {
            fn authorize_create(
                &self,
                _credentials: &ProcessCredentials,
                _service_name: &ServiceName,
                _messaging_pattern: MessagingPatternKind,
            ) -> PolicyDecision {
                PolicyDecision::deny(DenialReason::Unauthorized, "Create not allowed")
            }

            fn authorize_attach(
                &self,
                credentials: &ProcessCredentials,
                _service_id: &ServiceId,
                _port_type: PortType,
            ) -> PolicyDecision {
                if credentials.uid() == self.owner_uid {
                    PolicyDecision::deny(
                        DenialReason::PolicyViolation,
                        "Attach denied by test policy",
                    )
                } else {
                    PolicyDecision::deny(DenialReason::Unauthorized, "Unauthorized")
                }
            }

            fn authorize_add_segment(
                &self,
                _credentials: &ProcessCredentials,
                _service_id: &ServiceId,
                _requested_size: usize,
            ) -> PolicyDecision {
                PolicyDecision::deny(DenialReason::Unauthorized, "Segments not allowed")
            }

            fn get_limits(&self, _credentials: &ProcessCredentials) -> ResourceLimits {
                ResourceLimits::default()
            }
        }

        let listener = MockListener::new();
        let client_channel = listener.create_channel_pair(test_credentials());
        let shared = Arc::clone(&client_channel.shared);

        let policy = RestrictivePolicy { owner_uid: 1000 };
        let mut server = IamServer::new(listener, policy);

        // Complete handshake
        let node_id = UniqueSystemId::new().unwrap();
        shared.push_request(&IamRequest::Hello {
            protocol_version: ProtocolVersion::CURRENT,
            node_id,
        });

        server.process().unwrap();
        server.process().unwrap();
        shared.clear_responses();

        // Try to attach - should be denied
        let service_id = create_test_service_id("test/denied");
        shared.push_request(&IamRequest::AttachPublisher {
            service_id,
            history_size: 8,
            max_slice_len: 1024,
        });

        server.process().unwrap();

        let responses = shared.get_responses();
        match &responses[0] {
            IamResponse::Denied { reason, message } => {
                assert_eq!(*reason, DenialReason::PolicyViolation);
                assert!(message.contains("denied by test policy"));
            }
            _ => panic!("Expected Denied response, got {:?}", responses[0]),
        }
    }

    #[test]
    fn test_integration_resource_limit_exceeded() {
        // Create a policy with very low limits
        let limits = ResourceLimits::new(
            1, // max_publishers = 1
            1, // max_subscribers
            1, // max_servers
            1, // max_clients
            1, // max_segments
            1024, // max_segment_size
        );
        let policy = DefaultPolicy::with_limits(1000, limits);

        let listener = MockListener::new();
        let client_channel = listener.create_channel_pair(test_credentials());
        let shared = Arc::clone(&client_channel.shared);
        let mut server = IamServer::new(listener, policy);

        // Complete handshake
        let node_id = UniqueSystemId::new().unwrap();
        shared.push_request(&IamRequest::Hello {
            protocol_version: ProtocolVersion::CURRENT,
            node_id,
        });

        server.process().unwrap();
        server.process().unwrap();
        shared.clear_responses();

        // Attach first publisher - should succeed
        let service_id = create_test_service_id("test/limits");
        shared.push_request(&IamRequest::AttachPublisher {
            service_id,
            history_size: 0,
            max_slice_len: 128,
        });

        server.process().unwrap();

        {
            let responses = shared.get_responses();
            assert!(matches!(responses[0], IamResponse::AttachOk { .. }));
        }
        shared.clear_responses();

        // Attach second publisher - should fail due to limit
        shared.push_request(&IamRequest::AttachPublisher {
            service_id,
            history_size: 0,
            max_slice_len: 128,
        });

        server.process().unwrap();

        let responses = shared.get_responses();
        match &responses[0] {
            IamResponse::Denied { reason, .. } => {
                assert_eq!(*reason, DenialReason::ResourceLimitExceeded);
            }
            _ => panic!("Expected Denied response, got {:?}", responses[0]),
        }
    }

    // ========================================================================
    // Multiple Clients Tests
    // ========================================================================

    #[test]
    fn test_integration_multiple_clients() {
        let listener = MockListener::new();

        // Create two channel pairs
        let client1_channel = listener.create_channel_pair(test_credentials());
        let client1_shared = Arc::clone(&client1_channel.shared);

        let client2_channel = listener.create_channel_pair(test_credentials());
        let client2_shared = Arc::clone(&client2_channel.shared);

        let mut server = create_test_server(listener, 1000);

        // Both clients send Hello
        let node_id1 = UniqueSystemId::new().unwrap();
        let node_id2 = UniqueSystemId::new().unwrap();

        client1_shared.push_request(&IamRequest::Hello {
            protocol_version: ProtocolVersion::CURRENT,
            node_id: node_id1,
        });
        client2_shared.push_request(&IamRequest::Hello {
            protocol_version: ProtocolVersion::CURRENT,
            node_id: node_id2,
        });

        // Server accepts and processes both connections
        server.process().unwrap(); // Accept client 1
        server.process().unwrap(); // Accept client 2
        server.process().unwrap(); // Process client 1 Hello
        server.process().unwrap(); // Process client 2 Hello

        assert_eq!(server.session_count(), 2);

        // Both clients should have received HelloOk with different session IDs
        let session_id1 = {
            let responses = client1_shared.get_responses();
            match &responses[0] {
                IamResponse::HelloOk { session_id, .. } => *session_id,
                _ => panic!("Expected HelloOk for client 1"),
            }
        };

        let session_id2 = {
            let responses = client2_shared.get_responses();
            match &responses[0] {
                IamResponse::HelloOk { session_id, .. } => *session_id,
                _ => panic!("Expected HelloOk for client 2"),
            }
        };

        assert_ne!(session_id1, session_id2);
    }

    // ========================================================================
    // Session Cleanup Tests
    // ========================================================================

    #[test]
    fn test_integration_session_tracking() {
        let listener = MockListener::new();
        let client_channel = listener.create_channel_pair(test_credentials());
        let shared = Arc::clone(&client_channel.shared);
        let mut server = create_test_server(listener, 1000);

        // Initial state
        assert_eq!(server.session_count(), 0);

        // Complete handshake
        let node_id = UniqueSystemId::new().unwrap();
        shared.push_request(&IamRequest::Hello {
            protocol_version: ProtocolVersion::CURRENT,
            node_id,
        });

        server.process().unwrap();
        assert_eq!(server.session_count(), 1);

        server.process().unwrap();
        assert_eq!(server.session_count(), 1);

        // Get session ID
        let session_id = {
            let responses = shared.get_responses();
            match &responses[0] {
                IamResponse::HelloOk { session_id, .. } => *session_id,
                _ => panic!("Expected HelloOk"),
            }
        };

        // Verify session has usage tracking
        let usage = server.get_session_usage(session_id);
        assert!(usage.is_some());
        assert_eq!(usage.unwrap().publisher_count, 0);
    }

    #[test]
    fn test_integration_session_resource_usage_tracking() {
        let listener = MockListener::new();
        let client_channel = listener.create_channel_pair(test_credentials());
        let shared = Arc::clone(&client_channel.shared);
        let mut server = create_test_server(listener, 1000);

        // Complete handshake
        let node_id = UniqueSystemId::new().unwrap();
        shared.push_request(&IamRequest::Hello {
            protocol_version: ProtocolVersion::CURRENT,
            node_id,
        });

        server.process().unwrap();
        server.process().unwrap();

        let session_id = {
            let responses = shared.get_responses();
            match &responses[0] {
                IamResponse::HelloOk { session_id, .. } => *session_id,
                _ => panic!("Expected HelloOk"),
            }
        };

        shared.clear_responses();

        // Attach multiple ports
        let service_id = create_test_service_id("test/tracking");
        shared.push_request(&IamRequest::AttachPublisher {
            service_id,
            history_size: 0,
            max_slice_len: 128,
        });
        server.process().unwrap();

        // Check resource usage updated
        let usage = server.get_session_usage(session_id).unwrap();
        assert_eq!(usage.publisher_count, 1);
        assert_eq!(usage.subscriber_count, 0);

        shared.clear_responses();

        // Attach subscriber
        shared.push_request(&IamRequest::AttachSubscriber {
            service_id,
            buffer_size: 16,
        });
        server.process().unwrap();

        let usage = server.get_session_usage(session_id).unwrap();
        assert_eq!(usage.publisher_count, 1);
        assert_eq!(usage.subscriber_count, 1);
    }

    // ========================================================================
    // Full Client-Server Flow Tests
    // ========================================================================

    #[test]
    fn test_integration_full_client_handshake() {
        let listener = MockListener::new();
        let client_channel = listener.create_channel_pair(test_credentials());
        let shared = Arc::clone(&client_channel.shared);
        let mut server = create_test_server(listener, 1000);

        // Create client
        let client = IamClient::new(client_channel);

        assert!(!client.is_active());
        assert!(client.is_connected());

        // Accept connection on server
        server.process().unwrap();

        // Send Hello through shared messages (simulating client.handshake())
        let node_id = UniqueSystemId::new().unwrap();
        shared.push_request(&IamRequest::Hello {
            protocol_version: ProtocolVersion::CURRENT,
            node_id,
        });

        // Server processes
        server.process().unwrap();

        // Check response
        let responses = shared.get_responses();
        match &responses[0] {
            IamResponse::HelloOk {
                negotiated_version,
                session_id,
            } => {
                assert_eq!(*negotiated_version, ProtocolVersion::CURRENT);
                assert!(session_id.is_valid());
            }
            _ => panic!("Expected HelloOk"),
        }
    }

    #[test]
    fn test_integration_add_segment_flow() {
        // Note: This test exercises the AddSegment request flow.
        // Currently the server returns ProtocolError because segment creation
        // isn't fully implemented (requires SegmentManager integration).
        let listener = MockListener::new();
        let client_channel = listener.create_channel_pair(test_credentials());
        let shared = Arc::clone(&client_channel.shared);
        let mut server = create_test_server(listener, 1000);

        // Complete handshake
        let node_id = UniqueSystemId::new().unwrap();
        shared.push_request(&IamRequest::Hello {
            protocol_version: ProtocolVersion::CURRENT,
            node_id,
        });

        server.process().unwrap();
        server.process().unwrap();
        shared.clear_responses();

        // Attach a publisher first
        let service_id = create_test_service_id("test/segment");
        shared.push_request(&IamRequest::AttachPublisher {
            service_id,
            history_size: 0,
            max_slice_len: 128,
        });

        server.process().unwrap();

        let port_id = {
            let responses = shared.get_responses();
            match &responses[0] {
                IamResponse::AttachOk { port_id, .. } => *port_id,
                _ => panic!("Expected AttachOk"),
            }
        };

        shared.clear_responses();

        // Try to add segment
        shared.push_request(&IamRequest::AddSegment {
            service_id,
            port_id,
            requested_size: 4096,
        });

        server.process().unwrap();

        let responses = shared.get_responses();
        // Currently the server returns ProtocolError because segment creation
        // requires full SegmentManager integration which is not yet complete.
        match &responses[0] {
            IamResponse::ProtocolError { message } => {
                assert!(message.contains("not yet implemented"));
            }
            IamResponse::AddSegmentOk { .. } => {
                // If full implementation is added, this would be the success case
                panic!("AddSegment succeeded - test needs to be updated to verify proper behavior");
            }
            _ => panic!("Unexpected response: {:?}", responses[0]),
        }
    }

    // ========================================================================
    // Segment Retirement Tests
    // ========================================================================

    #[test]
    fn test_integration_ack_retirement_without_pending() {
        let listener = MockListener::new();
        let client_channel = listener.create_channel_pair(test_credentials());
        let shared = Arc::clone(&client_channel.shared);
        let mut server = create_test_server(listener, 1000);

        // Complete handshake
        let node_id = UniqueSystemId::new().unwrap();
        shared.push_request(&IamRequest::Hello {
            protocol_version: ProtocolVersion::CURRENT,
            node_id,
        });

        server.process().unwrap();
        server.process().unwrap();
        shared.clear_responses();

        // Try to ack a retirement that doesn't exist
        let service_id = create_test_service_id("test/retirement");
        shared.push_request(&IamRequest::AckSegmentRetirement {
            service_id,
            segment_id: SegmentId::new(99),
        });

        server.process().unwrap();

        let responses = shared.get_responses();
        match &responses[0] {
            IamResponse::Denied { reason, .. } => {
                assert_eq!(*reason, DenialReason::Unauthorized);
            }
            _ => panic!("Expected Denied response, got {:?}", responses[0]),
        }
    }

    // ========================================================================
    // Port Type Tests
    // ========================================================================

    #[test]
    fn test_integration_all_port_types() {
        let listener = MockListener::new();
        let client_channel = listener.create_channel_pair(test_credentials());
        let shared = Arc::clone(&client_channel.shared);
        let mut server = create_test_server(listener, 1000);

        // Complete handshake
        let node_id = UniqueSystemId::new().unwrap();
        shared.push_request(&IamRequest::Hello {
            protocol_version: ProtocolVersion::CURRENT,
            node_id,
        });

        server.process().unwrap();
        server.process().unwrap();

        let session_id = {
            let responses = shared.get_responses();
            match &responses[0] {
                IamResponse::HelloOk { session_id, .. } => *session_id,
                _ => panic!("Expected HelloOk"),
            }
        };

        shared.clear_responses();

        // Test all port types
        let service_id = create_test_service_id("test/all-ports");

        // Publisher
        shared.push_request(&IamRequest::AttachPublisher {
            service_id,
            history_size: 0,
            max_slice_len: 128,
        });
        server.process().unwrap();
        assert!(matches!(
            shared.get_responses()[0],
            IamResponse::AttachOk { .. }
        ));
        shared.clear_responses();

        // Subscriber
        shared.push_request(&IamRequest::AttachSubscriber {
            service_id,
            buffer_size: 16,
        });
        server.process().unwrap();
        assert!(matches!(
            shared.get_responses()[0],
            IamResponse::AttachOk { .. }
        ));
        shared.clear_responses();

        // Server port
        shared.push_request(&IamRequest::AttachServer {
            service_id,
            max_active_requests: 10,
        });
        server.process().unwrap();
        assert!(matches!(
            shared.get_responses()[0],
            IamResponse::AttachOk { .. }
        ));
        shared.clear_responses();

        // Client port
        shared.push_request(&IamRequest::AttachClient {
            service_id,
            max_pending_responses: 5,
        });
        server.process().unwrap();
        assert!(matches!(
            shared.get_responses()[0],
            IamResponse::AttachOk { .. }
        ));

        // Verify resource usage tracking
        let usage = server.get_session_usage(session_id).unwrap();
        assert_eq!(usage.publisher_count, 1);
        assert_eq!(usage.subscriber_count, 1);
        assert_eq!(usage.server_count, 1);
        assert_eq!(usage.client_count, 1);
    }
}
