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
    use alloc::vec::Vec;
    use std::sync::{Arc, Mutex};

    use iceoryx2_bb_posix::unique_system_id::UniqueSystemId;
    use iceoryx2_cal::hash::sha1::Sha1;
    use iceoryx2_cal::security::credentials::ProcessCredentials;
    use iceoryx2_cal::security::handle::PlatformHandle;
    use iceoryx2_cal::shm_allocator::SegmentId;

    use crate::iam::client::{ClientControlChannelConnection, IamClient};
    use crate::iam::error::{IamClientError, IamServerError};
    use crate::iam::policy::{DefaultPolicy, IamPolicy, PolicyDecision, ResourceLimits};
    use crate::iam::protocol::{
        DenialReason, IamNotification, IamRequest, IamResponse, MessagingPatternKind, PortType,
        ProtocolVersion,
    };
    use crate::iam::server::{ControlChannelConnection, ControlChannelListener, IamServer};
    use crate::service::messaging_pattern::MessagingPattern;
    use crate::service::service_id::ServiceId;
    use crate::service::service_name::ServiceName;

    // ========================================================================
    // Mock Channel Infrastructure
    // ========================================================================

    /// Shared message container for passing between client and server.
    struct SharedMessages {
        requests: Mutex<Vec<IamRequest>>,
        responses: Mutex<Vec<IamResponse>>,
        /// Track number of handles sent (since PlatformHandle doesn't implement Clone)
        handle_count: Mutex<usize>,
    }

    impl SharedMessages {
        fn new() -> Self {
            Self {
                requests: Mutex::new(Vec::new()),
                responses: Mutex::new(Vec::new()),
                handle_count: Mutex::new(0),
            }
        }
    }

    /// Mock channel for the server side.
    ///
    /// Receives requests from the client and sends responses back.
    struct MockServerChannel {
        credentials: ProcessCredentials,
        /// Shared with client for message passing.
        shared: Arc<SharedMessages>,
        /// Closed flag (kept for potential future use in disconnect tests)
        #[allow(dead_code)]
        closed: Mutex<bool>,
    }

    impl MockServerChannel {
        fn new(credentials: ProcessCredentials, shared: Arc<SharedMessages>) -> Self {
            Self {
                credentials,
                shared,
                closed: Mutex::new(false),
            }
        }
    }

    impl ControlChannelConnection for MockServerChannel {
        fn peer_credentials(&self) -> Result<ProcessCredentials, IamServerError> {
            Ok(self.credentials.clone())
        }

        fn try_receive_request(&self) -> Result<Option<IamRequest>, IamServerError> {
            let mut requests = self.shared.requests.lock().unwrap();
            if requests.is_empty() {
                Ok(None)
            } else {
                Ok(Some(requests.remove(0)))
            }
        }

        fn send_response(&self, response: &IamResponse) -> Result<(), IamServerError> {
            let mut responses = self.shared.responses.lock().unwrap();
            responses.push(response.clone());
            Ok(())
        }

        fn send_notification(&self, _notification: &IamNotification) -> Result<(), IamServerError> {
            // For integration tests, we don't test notifications yet
            Ok(())
        }

        fn send_handles(&self, handles: &[PlatformHandle]) -> Result<(), IamServerError> {
            // In a real implementation, handles would be passed via SCM_RIGHTS or DuplicateHandle.
            // For testing, we just track the count since we don't actually need the handles.
            let mut handle_count = self.shared.handle_count.lock().unwrap();
            *handle_count += handles.len();
            Ok(())
        }
    }

    /// Mock channel for the client side.
    ///
    /// Sends requests to the server and receives responses.
    struct MockClientChannel {
        /// Shared with server for message passing.
        /// Public to allow tests to directly inject requests/read responses.
        pub shared: Arc<SharedMessages>,
        /// Closed flag
        closed: Mutex<bool>,
    }

    impl MockClientChannel {
        fn new(shared: Arc<SharedMessages>) -> Self {
            Self {
                shared,
                closed: Mutex::new(false),
            }
        }
    }

    impl ClientControlChannelConnection for MockClientChannel {
        fn send_request(&self, request: &IamRequest) -> Result<(), IamClientError> {
            let mut requests = self.shared.requests.lock().unwrap();
            requests.push(request.clone());
            Ok(())
        }

        fn receive_response(&self) -> Result<IamResponse, IamClientError> {
            // In a real implementation, this would block until a response is available
            // For testing, we expect the server to have already processed and sent a response
            let mut responses = self.shared.responses.lock().unwrap();
            if responses.is_empty() {
                Err(IamClientError::ReceiveFailed)
            } else {
                Ok(responses.remove(0))
            }
        }

        fn receive_handles(&self, count: usize) -> Result<Vec<PlatformHandle>, IamClientError> {
            // In a real implementation, handles would be received via SCM_RIGHTS or DuplicateHandle.
            // For testing, we check if enough handles were "sent" and return an empty vec.
            // The actual handles aren't needed for the integration tests.
            let mut handle_count = self.shared.handle_count.lock().unwrap();
            if *handle_count < count {
                return Err(IamClientError::HandleReceiveFailed);
            }
            *handle_count -= count;
            // Return empty vec since we can't actually pass handles in this mock
            // The tests don't verify handle contents, just the protocol flow
            Ok(Vec::new())
        }

        fn close(&self) {
            *self.closed.lock().unwrap() = true;
        }
    }

    /// Mock listener that produces mock server channels.
    struct MockListener {
        pending_connections: Mutex<Vec<(ProcessCredentials, Arc<SharedMessages>)>>,
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
            let shared = Arc::new(SharedMessages::new());
            let client_channel = MockClientChannel::new(Arc::clone(&shared));

            // Queue the server connection for acceptance
            self.pending_connections
                .lock()
                .unwrap()
                .push((credentials, shared));

            client_channel
        }
    }

    impl ControlChannelListener for MockListener {
        type Connection = MockServerChannel;

        fn try_accept(&self) -> Result<Option<Self::Connection>, IamServerError> {
            let mut pending = self.pending_connections.lock().unwrap();
            if pending.is_empty() {
                Ok(None)
            } else {
                let (credentials, shared) = pending.remove(0);
                Ok(Some(MockServerChannel::new(credentials, shared)))
            }
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
        {
            let mut requests = shared.requests.lock().unwrap();
            requests.push(IamRequest::Hello {
                protocol_version: ProtocolVersion::CURRENT,
                node_id,
            });
        }

        // Server accepts connection and processes request
        server.process().unwrap(); // Accept connection
        server.process().unwrap(); // Process Hello request

        // Check response
        let responses = shared.responses.lock().unwrap();
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
        {
            let mut requests = shared.requests.lock().unwrap();
            requests.push(request);
        }

        // Server accepts and processes
        server.process().unwrap();
        server.process().unwrap();

        // Check response
        let responses = shared.responses.lock().unwrap();
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
        {
            let mut requests = shared.requests.lock().unwrap();
            requests.push(IamRequest::Hello {
                protocol_version: ProtocolVersion::CURRENT,
                node_id,
            });
        }

        server.process().unwrap(); // Accept connection
        server.process().unwrap(); // Process Hello

        // Verify handshake succeeded (connections always allowed)
        {
            let responses = shared.responses.lock().unwrap();
            assert!(matches!(responses[0], IamResponse::HelloOk { .. }));
        }
        shared.responses.lock().unwrap().clear();

        // Try to attach publisher - should be DENIED due to UID mismatch
        let service_id = create_test_service_id("test/unauthorized");
        {
            let mut requests = shared.requests.lock().unwrap();
            requests.push(IamRequest::AttachPublisher {
                service_id,
                history_size: 8,
                max_slice_len: 1024,
            });
        }

        server.process().unwrap();

        let responses = shared.responses.lock().unwrap();
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
        {
            let mut requests = shared.requests.lock().unwrap();
            requests.push(IamRequest::Hello {
                protocol_version: ProtocolVersion::CURRENT,
                node_id,
            });
        }

        server.process().unwrap(); // Accept
        server.process().unwrap(); // Process Hello

        // Clear responses
        shared.responses.lock().unwrap().clear();

        // Send AttachPublisher request
        let service_id = create_test_service_id("test/publisher");
        {
            let mut requests = shared.requests.lock().unwrap();
            requests.push(IamRequest::AttachPublisher {
                service_id,
                history_size: 8,
                max_slice_len: 1024,
            });
        }

        // Server processes
        server.process().unwrap();

        // Check response
        let responses = shared.responses.lock().unwrap();
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
        {
            let mut requests = shared.requests.lock().unwrap();
            requests.push(IamRequest::Hello {
                protocol_version: ProtocolVersion::CURRENT,
                node_id,
            });
        }

        server.process().unwrap();
        server.process().unwrap();
        shared.responses.lock().unwrap().clear();

        // Send AttachSubscriber request
        let service_id = create_test_service_id("test/subscriber");
        {
            let mut requests = shared.requests.lock().unwrap();
            requests.push(IamRequest::AttachSubscriber {
                service_id,
                buffer_size: 16,
            });
        }

        server.process().unwrap();

        let responses = shared.responses.lock().unwrap();
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
        {
            let mut requests = shared.requests.lock().unwrap();
            requests.push(IamRequest::Hello {
                protocol_version: ProtocolVersion::CURRENT,
                node_id,
            });
        }

        server.process().unwrap();
        server.process().unwrap();
        shared.responses.lock().unwrap().clear();

        // Send AttachServer request
        let service_id = create_test_service_id("test/server");
        {
            let mut requests = shared.requests.lock().unwrap();
            requests.push(IamRequest::AttachServer {
                service_id,
                max_active_requests: 10,
            });
        }

        server.process().unwrap();

        let responses = shared.responses.lock().unwrap();
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
        {
            let mut requests = shared.requests.lock().unwrap();
            requests.push(IamRequest::Hello {
                protocol_version: ProtocolVersion::CURRENT,
                node_id,
            });
        }

        server.process().unwrap();
        server.process().unwrap();
        shared.responses.lock().unwrap().clear();

        // Send AttachClient request
        let service_id = create_test_service_id("test/client");
        {
            let mut requests = shared.requests.lock().unwrap();
            requests.push(IamRequest::AttachClient {
                service_id,
                max_pending_responses: 5,
            });
        }

        server.process().unwrap();

        let responses = shared.responses.lock().unwrap();
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
        {
            let mut requests = shared.requests.lock().unwrap();
            requests.push(IamRequest::AttachPublisher {
                service_id,
                history_size: 8,
                max_slice_len: 1024,
            });
        }

        server.process().unwrap();

        let responses = shared.responses.lock().unwrap();
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
        {
            let mut requests = shared.requests.lock().unwrap();
            requests.push(IamRequest::Hello {
                protocol_version: ProtocolVersion::CURRENT,
                node_id,
            });
        }

        server.process().unwrap();
        server.process().unwrap();
        shared.responses.lock().unwrap().clear();

        // Attach a publisher first
        let service_id = create_test_service_id("test/detach");
        {
            let mut requests = shared.requests.lock().unwrap();
            requests.push(IamRequest::AttachPublisher {
                service_id,
                history_size: 8,
                max_slice_len: 1024,
            });
        }

        server.process().unwrap();

        // Get the port ID from the response
        let port_id = {
            let responses = shared.responses.lock().unwrap();
            match &responses[0] {
                IamResponse::AttachOk { port_id, .. } => *port_id,
                _ => panic!("Expected AttachOk"),
            }
        };

        shared.responses.lock().unwrap().clear();

        // Now detach
        {
            let mut requests = shared.requests.lock().unwrap();
            requests.push(IamRequest::Detach { service_id, port_id });
        }

        server.process().unwrap();

        let responses = shared.responses.lock().unwrap();
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
        {
            let mut requests = shared.requests.lock().unwrap();
            requests.push(IamRequest::Hello {
                protocol_version: ProtocolVersion::CURRENT,
                node_id,
            });
        }

        server.process().unwrap();
        server.process().unwrap();
        shared.responses.lock().unwrap().clear();

        // Try to attach - should be denied
        let service_id = create_test_service_id("test/denied");
        {
            let mut requests = shared.requests.lock().unwrap();
            requests.push(IamRequest::AttachPublisher {
                service_id,
                history_size: 8,
                max_slice_len: 1024,
            });
        }

        server.process().unwrap();

        let responses = shared.responses.lock().unwrap();
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
        {
            let mut requests = shared.requests.lock().unwrap();
            requests.push(IamRequest::Hello {
                protocol_version: ProtocolVersion::CURRENT,
                node_id,
            });
        }

        server.process().unwrap();
        server.process().unwrap();
        shared.responses.lock().unwrap().clear();

        // Attach first publisher - should succeed
        let service_id = create_test_service_id("test/limits");
        {
            let mut requests = shared.requests.lock().unwrap();
            requests.push(IamRequest::AttachPublisher {
                service_id,
                history_size: 0,
                max_slice_len: 128,
            });
        }

        server.process().unwrap();

        {
            let responses = shared.responses.lock().unwrap();
            assert!(matches!(responses[0], IamResponse::AttachOk { .. }));
        }
        shared.responses.lock().unwrap().clear();

        // Attach second publisher - should fail due to limit
        {
            let mut requests = shared.requests.lock().unwrap();
            requests.push(IamRequest::AttachPublisher {
                service_id,
                history_size: 0,
                max_slice_len: 128,
            });
        }

        server.process().unwrap();

        let responses = shared.responses.lock().unwrap();
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

        {
            let mut requests = client1_shared.requests.lock().unwrap();
            requests.push(IamRequest::Hello {
                protocol_version: ProtocolVersion::CURRENT,
                node_id: node_id1,
            });
        }
        {
            let mut requests = client2_shared.requests.lock().unwrap();
            requests.push(IamRequest::Hello {
                protocol_version: ProtocolVersion::CURRENT,
                node_id: node_id2,
            });
        }

        // Server accepts and processes both connections
        server.process().unwrap(); // Accept client 1
        server.process().unwrap(); // Accept client 2
        server.process().unwrap(); // Process client 1 Hello
        server.process().unwrap(); // Process client 2 Hello

        assert_eq!(server.session_count(), 2);

        // Both clients should have received HelloOk with different session IDs
        let session_id1 = {
            let responses = client1_shared.responses.lock().unwrap();
            match &responses[0] {
                IamResponse::HelloOk { session_id, .. } => *session_id,
                _ => panic!("Expected HelloOk for client 1"),
            }
        };

        let session_id2 = {
            let responses = client2_shared.responses.lock().unwrap();
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
        {
            let mut requests = shared.requests.lock().unwrap();
            requests.push(IamRequest::Hello {
                protocol_version: ProtocolVersion::CURRENT,
                node_id,
            });
        }

        server.process().unwrap();
        assert_eq!(server.session_count(), 1);

        server.process().unwrap();
        assert_eq!(server.session_count(), 1);

        // Get session ID
        let session_id = {
            let responses = shared.responses.lock().unwrap();
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
        {
            let mut requests = shared.requests.lock().unwrap();
            requests.push(IamRequest::Hello {
                protocol_version: ProtocolVersion::CURRENT,
                node_id,
            });
        }

        server.process().unwrap();
        server.process().unwrap();

        let session_id = {
            let responses = shared.responses.lock().unwrap();
            match &responses[0] {
                IamResponse::HelloOk { session_id, .. } => *session_id,
                _ => panic!("Expected HelloOk"),
            }
        };

        shared.responses.lock().unwrap().clear();

        // Attach multiple ports
        let service_id = create_test_service_id("test/tracking");
        {
            let mut requests = shared.requests.lock().unwrap();
            requests.push(IamRequest::AttachPublisher {
                service_id,
                history_size: 0,
                max_slice_len: 128,
            });
        }
        server.process().unwrap();

        // Check resource usage updated
        let usage = server.get_session_usage(session_id).unwrap();
        assert_eq!(usage.publisher_count, 1);
        assert_eq!(usage.subscriber_count, 0);

        shared.responses.lock().unwrap().clear();

        // Attach subscriber
        {
            let mut requests = shared.requests.lock().unwrap();
            requests.push(IamRequest::AttachSubscriber {
                service_id,
                buffer_size: 16,
            });
        }
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
        {
            let mut requests = shared.requests.lock().unwrap();
            requests.push(IamRequest::Hello {
                protocol_version: ProtocolVersion::CURRENT,
                node_id,
            });
        }

        // Server processes
        server.process().unwrap();

        // Check response
        let responses = shared.responses.lock().unwrap();
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
        {
            let mut requests = shared.requests.lock().unwrap();
            requests.push(IamRequest::Hello {
                protocol_version: ProtocolVersion::CURRENT,
                node_id,
            });
        }

        server.process().unwrap();
        server.process().unwrap();
        shared.responses.lock().unwrap().clear();

        // Attach a publisher first
        let service_id = create_test_service_id("test/segment");
        {
            let mut requests = shared.requests.lock().unwrap();
            requests.push(IamRequest::AttachPublisher {
                service_id,
                history_size: 0,
                max_slice_len: 128,
            });
        }

        server.process().unwrap();

        let port_id = {
            let responses = shared.responses.lock().unwrap();
            match &responses[0] {
                IamResponse::AttachOk { port_id, .. } => *port_id,
                _ => panic!("Expected AttachOk"),
            }
        };

        shared.responses.lock().unwrap().clear();

        // Try to add segment
        {
            let mut requests = shared.requests.lock().unwrap();
            requests.push(IamRequest::AddSegment {
                service_id,
                port_id,
                requested_size: 4096,
            });
        }

        server.process().unwrap();

        let responses = shared.responses.lock().unwrap();
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
        {
            let mut requests = shared.requests.lock().unwrap();
            requests.push(IamRequest::Hello {
                protocol_version: ProtocolVersion::CURRENT,
                node_id,
            });
        }

        server.process().unwrap();
        server.process().unwrap();
        shared.responses.lock().unwrap().clear();

        // Try to ack a retirement that doesn't exist
        let service_id = create_test_service_id("test/retirement");
        {
            let mut requests = shared.requests.lock().unwrap();
            requests.push(IamRequest::AckSegmentRetirement {
                service_id,
                segment_id: SegmentId::new(99),
            });
        }

        server.process().unwrap();

        let responses = shared.responses.lock().unwrap();
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
        {
            let mut requests = shared.requests.lock().unwrap();
            requests.push(IamRequest::Hello {
                protocol_version: ProtocolVersion::CURRENT,
                node_id,
            });
        }

        server.process().unwrap();
        server.process().unwrap();

        let session_id = {
            let responses = shared.responses.lock().unwrap();
            match &responses[0] {
                IamResponse::HelloOk { session_id, .. } => *session_id,
                _ => panic!("Expected HelloOk"),
            }
        };

        shared.responses.lock().unwrap().clear();

        // Test all port types
        let service_id = create_test_service_id("test/all-ports");

        // Publisher
        {
            let mut requests = shared.requests.lock().unwrap();
            requests.push(IamRequest::AttachPublisher {
                service_id,
                history_size: 0,
                max_slice_len: 128,
            });
        }
        server.process().unwrap();
        assert!(matches!(
            shared.responses.lock().unwrap()[0],
            IamResponse::AttachOk { .. }
        ));
        shared.responses.lock().unwrap().clear();

        // Subscriber
        {
            let mut requests = shared.requests.lock().unwrap();
            requests.push(IamRequest::AttachSubscriber {
                service_id,
                buffer_size: 16,
            });
        }
        server.process().unwrap();
        assert!(matches!(
            shared.responses.lock().unwrap()[0],
            IamResponse::AttachOk { .. }
        ));
        shared.responses.lock().unwrap().clear();

        // Server port
        {
            let mut requests = shared.requests.lock().unwrap();
            requests.push(IamRequest::AttachServer {
                service_id,
                max_active_requests: 10,
            });
        }
        server.process().unwrap();
        assert!(matches!(
            shared.responses.lock().unwrap()[0],
            IamResponse::AttachOk { .. }
        ));
        shared.responses.lock().unwrap().clear();

        // Client port
        {
            let mut requests = shared.requests.lock().unwrap();
            requests.push(IamRequest::AttachClient {
                service_id,
                max_pending_responses: 5,
            });
        }
        server.process().unwrap();
        assert!(matches!(
            shared.responses.lock().unwrap()[0],
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
