// Copyright (c) 2026 Contributors to the Eclipse Foundation
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

//! End-to-end tests that a secured service performs the real IAM handshake and moves data through
//! IAM-brokered shared-memory segments (single process: the creator hosts the IAM server + a
//! self-client, so its own ports authorize and broker through IAM exactly like a remote opener).

#[cfg(test)]
mod secured_ipc_e2e {
    use iceoryx2::config::Config;
    use iceoryx2::node::NodeBuilder;
    use iceoryx2::port::update_connections::UpdateConnections;
    use iceoryx2::prelude::*;
    use iceoryx2_bb_posix::unique_system_id::UniqueSystemId;
    use iceoryx2_bb_testing::assert_that;
    use iceoryx2_cal::security::mode::SecurityMode;

    fn secured_config() -> Config {
        let mut config = Config::default();
        config.global.node.security.mode = SecurityMode::Secured;
        config
    }

    fn unique_service_name() -> ServiceName {
        ServiceName::new(&format!(
            "secured_e2e_{}",
            UniqueSystemId::new().unwrap().value()
        ))
        .unwrap()
    }

    #[test]
    fn secured_publish_subscribe_roundtrip() {
        let node = NodeBuilder::new()
            .config(&secured_config())
            .create::<ipc::Service>()
            .unwrap();

        let service = node
            .service_builder(&unique_service_name())
            .publish_subscribe::<u64>()
            .create()
            .unwrap();

        let publisher = service.publisher_builder().create().unwrap();
        let subscriber = service.subscriber_builder().create().unwrap();

        // connect publisher -> subscriber, then deliver a sample through the IAM-brokered segment
        publisher.update_connections().unwrap();
        publisher.send_copy(4711u64).unwrap();

        let sample = subscriber.receive().unwrap();
        assert_that!(sample, is_some);
        assert_that!(*sample.unwrap(), eq 4711u64);
    }

    // Slice/variable-length payload with a non-Static allocation strategy selects a resizable
    // data segment (DataSegmentType::Dynamic -> create_dynamic_segment_iam_managed): the
    // management segment and the initial data segment (id 0) are created anonymously and brokered
    // to the subscriber via IAM handles instead of by name.
    #[test]
    fn secured_dynamic_publish_subscribe_roundtrip() {
        let node = NodeBuilder::new()
            .config(&secured_config())
            .create::<ipc::Service>()
            .unwrap();

        let service = node
            .service_builder(&unique_service_name())
            .publish_subscribe::<[u8]>()
            .create()
            .unwrap();

        let publisher = service
            .publisher_builder()
            .initial_max_slice_len(16)
            .allocation_strategy(AllocationStrategy::PowerOfTwo)
            .create()
            .unwrap();
        let subscriber = service.subscriber_builder().create().unwrap();

        // Register the connection channel with IAM before the subscriber opens it by handle.
        publisher.update_connections().unwrap();

        // Payload stays within initial_max_slice_len -> exercises the initial segment (id 0) and
        // the management segment, both reconstructed on the subscriber from brokered handles.
        const LEN: usize = 12;
        let mut sample = publisher.loan_slice(LEN).unwrap();
        for (i, byte) in sample.payload_mut().iter_mut().enumerate() {
            *byte = (i as u8).wrapping_mul(3).wrapping_add(1);
        }
        sample.send().unwrap();

        let received = subscriber.receive().unwrap();
        assert_that!(received, is_some);
        let received = received.unwrap();
        assert_that!(received.payload(), len LEN);
        for (i, byte) in received.payload().iter().enumerate() {
            assert_that!(*byte, eq (i as u8).wrapping_mul(3).wrapping_add(1));
        }
    }

    // Forces runtime reallocations over the handle-reconstructed dynamic view: initial_max_slice_len(1)
    // with a resizable allocation strategy means every larger loan drives the producer through
    // NeedSegment -> ctx.add_segment(...) (creating segment id 1, 2, ...), and the subscriber maps
    // each new segment lazily from the brokered handle (the runtime path over the handle-opened view).
    #[test]
    fn secured_dynamic_publish_subscribe_realloc_roundtrip() {
        let node = NodeBuilder::new()
            .config(&secured_config())
            .create::<ipc::Service>()
            .unwrap();

        let service = node
            .service_builder(&unique_service_name())
            .publish_subscribe::<[u8]>()
            .create()
            .unwrap();

        let publisher = service
            .publisher_builder()
            .initial_max_slice_len(1)
            .allocation_strategy(AllocationStrategy::PowerOfTwo)
            .create()
            .unwrap();
        let subscriber = service.subscriber_builder().create().unwrap();

        publisher.update_connections().unwrap();

        const ITERATIONS: usize = 8;
        for n in 0..ITERATIONS {
            // Growing sizes exceed initial_max_slice_len(1) -> a fresh reallocation each iteration.
            let sample_size = (n + 1) * 48;
            let mut sample = publisher.loan_slice(sample_size).unwrap();
            for byte in sample.payload_mut() {
                *byte = n as u8;
            }
            sample.send().unwrap();

            let received = subscriber.receive().unwrap();
            assert_that!(received, is_some);
            let received = received.unwrap();
            assert_that!(received.payload(), len sample_size);
            for byte in received.payload() {
                assert_that!(*byte, eq n as u8);
            }
        }
    }

    #[test]
    fn secured_request_response_roundtrip() {
        let node = NodeBuilder::new()
            .config(&secured_config())
            .create::<ipc::Service>()
            .unwrap();

        let service = node
            .service_builder(&unique_service_name())
            .request_response::<u64, u64>()
            .create()
            .unwrap();

        let client = service.client_builder().create().unwrap();
        let server = service.server_builder().create().unwrap();

        let pending_response = client.send_copy(123u64).unwrap();

        let active_request = server.receive().unwrap();
        assert_that!(active_request, is_some);
        let active_request = active_request.unwrap();
        assert_that!(*active_request, eq 123u64);
        active_request.send_copy(456u64).unwrap();

        let response = pending_response.receive().unwrap();
        assert_that!(response, is_some);
        assert_that!(*response.unwrap(), eq 456u64);
    }

    #[test]
    fn secured_event_roundtrip() {
        let node = NodeBuilder::new()
            .config(&secured_config())
            .create::<ipc::Service>()
            .unwrap();

        let service = node
            .service_builder(&unique_service_name())
            .event()
            .create()
            .unwrap();

        let notifier = service.notifier_builder().create().unwrap();
        let listener = service.listener_builder().create().unwrap();

        notifier.notify_with_custom_event_id(EventId::new(7)).unwrap();

        let mut notifications = 0;
        listener.try_wait(|_id| notifications += 1).unwrap();
        assert_that!(notifications, eq 1);
    }
}
