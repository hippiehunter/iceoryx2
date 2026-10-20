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

//! Secured services with many participants and with a creator that goes away (single process,
//! single uid; every opener has its own node and therefore its own IAM sessions).

#[cfg(test)]
mod secured_scale {
    use std::time::{Duration, Instant};

    use iceoryx2::config::Config;
    use iceoryx2::node::NodeBuilder;
    use iceoryx2::prelude::*;
    use iceoryx2_bb_posix::unique_system_id::UniqueSystemId;
    use iceoryx2_bb_testing::assert_that;
    use iceoryx2_cal::security::mode::SecurityMode;

    fn secured_config() -> Config {
        let mut config = Config::default();
        config.global.node.security.mode = SecurityMode::Secured;
        // Hundreds of nodes: skip the O(nodes) dead-node scans on every creation and open.
        config.global.node.cleanup_dead_nodes_on_creation = false;
        config.global.node.cleanup_dead_nodes_on_destruction = false;
        config.global.service.cleanup_dead_nodes_on_open = false;
        config
    }

    fn unique_service_name(tag: &str) -> ServiceName {
        ServiceName::new(&format!(
            "secured_scale_{tag}_{}",
            UniqueSystemId::new().unwrap().value()
        ))
        .unwrap()
    }

    fn node() -> Node<ipc::Service> {
        NodeBuilder::new()
            .config(&secured_config())
            .create::<ipc::Service>()
            .unwrap()
    }

    // The IAM server used to hand out server-wide u8 segment ids: the 255th publisher's segment
    // registration failed, its session was dropped, and the subscriber never received from it.
    #[test]
    fn more_than_254_publishers_deliver_to_one_subscriber() {
        const PUBLISHERS: usize = 300;
        let name = unique_service_name("many_publishers");
        let creator = node();
        let service = creator
            .service_builder(&name)
            .publish_subscribe::<[u8]>()
            .max_publishers(PUBLISHERS)
            .max_nodes(PUBLISHERS + 1)
            .subscriber_max_buffer_size(4)
            .create()
            .unwrap();
        let subscriber = service.subscriber_builder().create().unwrap();

        let writers: Vec<_> = (0..PUBLISHERS)
            .map(|_| {
                let node = node();
                let service = node
                    .service_builder(&name)
                    .publish_subscribe::<[u8]>()
                    .open()
                    .unwrap();
                let publisher = service
                    .publisher_builder()
                    .initial_max_slice_len(16)
                    .allocation_strategy(AllocationStrategy::PowerOfTwo)
                    .create()
                    .unwrap();
                (node, service, publisher)
            })
            .collect();

        for (i, (_, _, publisher)) in writers.iter().enumerate() {
            let sample = publisher
                .loan_slice_uninit(8)
                .unwrap()
                .write_from_fn(|b| (i >> (8 * (b % 8))) as u8);
            assert_that!(sample.send().unwrap(), eq 1);
        }

        let mut received = vec![false; PUBLISHERS];
        let deadline = Instant::now() + Duration::from_secs(30);
        let mut count = 0;
        while count < PUBLISHERS && Instant::now() < deadline {
            match subscriber.receive().unwrap() {
                Some(sample) => {
                    let mut v = 0usize;
                    for (b, byte) in sample.payload().iter().enumerate() {
                        v |= (*byte as usize) << (8 * b);
                    }
                    assert_that!(received[v], eq false);
                    received[v] = true;
                    count += 1;
                }
                None => std::thread::sleep(Duration::from_millis(1)),
            }
        }
        assert_that!(count, eq PUBLISHERS);
    }

    // A drain of many publishers with one sample each visits them in round robin.
    #[test]
    fn receive_serves_publishers_round_robin() {
        const PUBLISHERS: usize = 8;
        let name = unique_service_name("round_robin");
        let creator = node();
        let service = creator
            .service_builder(&name)
            .publish_subscribe::<u64>()
            .max_publishers(PUBLISHERS)
            .subscriber_max_buffer_size(4)
            .create()
            .unwrap();
        let subscriber = service.subscriber_builder().create().unwrap();
        let publishers: Vec<_> = (0..PUBLISHERS)
            .map(|_| service.publisher_builder().create().unwrap())
            .collect();
        // Every publisher sends two samples; a scan that always restarted at the first
        // connection would hand out both samples of a publisher before moving on as well, so the
        // check is that every publisher's first sample arrives before any second sample of a
        // publisher further down the list... except the publisher at the cursor itself.
        for round in 0..2u64 {
            for (i, p) in publishers.iter().enumerate() {
                p.send_copy(round * 100 + i as u64).unwrap();
            }
        }
        let mut order = Vec::new();
        while let Some(sample) = subscriber.receive().unwrap() {
            order.push(*sample);
        }
        assert_that!(order.len(), eq 2 * PUBLISHERS);
        // Each publisher's samples arrive in order.
        for i in 0..PUBLISHERS as u64 {
            let first = order.iter().position(|v| *v == i).unwrap();
            let second = order.iter().position(|v| *v == 100 + i).unwrap();
            assert_that!(first < second, eq true);
        }
    }

    // The creator (IAM server host) drops the service while another participant still uses it:
    // the participant sees the service as orphaned, and a new creator of the same uid reclaims
    // it in open_or_create; the old participant's eventual drop leaves the new service intact.
    #[test]
    fn orphaned_service_is_detected_and_reclaimed() {
        let name = unique_service_name("orphaned");
        let creator = node();
        let created = creator
            .service_builder(&name)
            .publish_subscribe::<u64>()
            .create()
            .unwrap();
        assert_that!(created.is_orphaned(), eq false);

        let participant_node = node();
        let participant = participant_node
            .service_builder(&name)
            .publish_subscribe::<u64>()
            .open()
            .unwrap();
        let events_name = unique_service_name("orphaned_events");
        let created_events = creator
            .service_builder(&events_name)
            .event()
            .create()
            .unwrap();
        let participant_events = participant_node
            .service_builder(&events_name)
            .event()
            .open()
            .unwrap();
        assert_that!(participant.is_orphaned(), eq false);
        assert_that!(participant_events.is_orphaned(), eq false);

        drop(created);
        drop(created_events);
        drop(creator);
        let deadline = Instant::now() + Duration::from_secs(5);
        while !(participant.is_orphaned() && participant_events.is_orphaned())
            && Instant::now() < deadline
        {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_that!(participant.is_orphaned(), eq true);
        assert_that!(participant_events.is_orphaned(), eq true);

        // Opening the orphaned service fails fast (no IAM server), not after the connect timeout.
        let opener = node();
        let started = Instant::now();
        assert_that!(
            opener
                .service_builder(&name)
                .publish_subscribe::<u64>()
                .open()
                .is_err(),
            eq true
        );
        assert_that!(started.elapsed() < Duration::from_secs(2), eq true);

        // A new creator reclaims it (the static config must be older than 2 x creation timeout).
        std::thread::sleep(
            secured_config().global.creation_timeout * 2 + Duration::from_millis(100),
        );
        let new_creator = node();
        let recreated = new_creator
            .service_builder(&name)
            .publish_subscribe::<u64>()
            .open_or_create()
            .unwrap();
        assert_that!(recreated.is_orphaned(), eq false);
        let subscriber = recreated.subscriber_builder().create().unwrap();

        // The old participant leaves; the new incarnation stays usable.
        drop(participant);
        drop(participant_events);
        drop(participant_node);

        let writer_node = node();
        let writer_service = writer_node
            .service_builder(&name)
            .publish_subscribe::<u64>()
            .open()
            .unwrap();
        let publisher = writer_service.publisher_builder().create().unwrap();
        publisher.send_copy(42).unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut got = None;
        while got.is_none() && Instant::now() < deadline {
            got = subscriber.receive().unwrap().map(|s| *s);
            std::thread::sleep(Duration::from_millis(1));
        }
        assert_that!(got, eq Some(42));
    }

    // A writer that goes away right after sending must first let the reader take its samples:
    // dropping the publisher removes (public) or releases via IAM (secured) its data segment, and
    // a reader that had not mapped it yet loses those samples. `has_samples_in_flight` tells the
    // writer when that is safe.
    fn samples_in_flight_until_received(config: &Config) {
        let name = unique_service_name("in_flight");
        let reader_node = NodeBuilder::new()
            .config(config)
            .create::<ipc::Service>()
            .unwrap();
        let service = reader_node
            .service_builder(&name)
            .publish_subscribe::<u64>()
            .subscriber_max_buffer_size(4)
            .create()
            .unwrap();
        let subscriber = service.subscriber_builder().create().unwrap();

        let writer_node = NodeBuilder::new()
            .config(config)
            .create::<ipc::Service>()
            .unwrap();
        let writer_service = writer_node
            .service_builder(&name)
            .publish_subscribe::<u64>()
            .open()
            .unwrap();
        let publisher = writer_service.publisher_builder().create().unwrap();
        assert_that!(publisher.has_samples_in_flight(), eq false);
        publisher.send_copy(1).unwrap();
        publisher.send_copy(2).unwrap();
        assert_that!(publisher.has_samples_in_flight(), eq true);

        let first = subscriber.receive().unwrap().unwrap();
        assert_that!(*first, eq 1);
        drop(first);
        assert_that!(publisher.has_samples_in_flight(), eq true);

        let second = subscriber.receive().unwrap().unwrap();
        assert_that!(publisher.has_samples_in_flight(), eq true);
        drop(second);
        assert_that!(publisher.has_samples_in_flight(), eq false);
    }

    #[test]
    fn publisher_reports_samples_in_flight_until_received_public() {
        let mut config = Config::default();
        config.global.node.cleanup_dead_nodes_on_creation = false;
        config.global.node.cleanup_dead_nodes_on_destruction = false;
        samples_in_flight_until_received(&config);
    }

    #[test]
    fn publisher_reports_samples_in_flight_until_received_secured() {
        samples_in_flight_until_received(&secured_config());
    }

    /// Drains one sample from each of `publishers` publishers; returns the best of three
    /// drain times.
    fn drain_one_sample_per_publisher(publishers: usize) -> Duration {
        let mut config = Config::default();
        config.global.node.cleanup_dead_nodes_on_creation = false;
        config.global.node.cleanup_dead_nodes_on_destruction = false;
        let name = unique_service_name("drain_cost");
        let node = NodeBuilder::new()
            .config(&config)
            .create::<ipc::Service>()
            .unwrap();
        let service = node
            .service_builder(&name)
            .publish_subscribe::<u64>()
            .max_publishers(publishers)
            .subscriber_max_buffer_size(2)
            .create()
            .unwrap();
        let subscriber = service.subscriber_builder().create().unwrap();
        let senders: Vec<_> = (0..publishers)
            .map(|_| service.publisher_builder().create().unwrap())
            .collect();
        let mut best = Duration::MAX;
        for _ in 0..3 {
            for (i, sender) in senders.iter().enumerate() {
                sender.send_copy(i as u64).unwrap();
            }
            let started = Instant::now();
            let mut received = 0;
            while let Some(sample) = subscriber.receive().unwrap() {
                drop(sample);
                received += 1;
            }
            best = best.min(started.elapsed());
            assert_that!(received, eq publishers);
        }
        best
    }

    // Draining one sample from each of N publishers must cost O(N). The round-robin receive
    // used to walk the connection slot map up to its cursor for every sample (O(N) per sample,
    // O(N^2) per drain): at 10,000 writers the broker's throughput collapsed to about 13,000
    // samples/s under load.
    #[test]
    fn draining_many_publishers_is_linear() {
        let small = drain_one_sample_per_publisher(250);
        let large = drain_one_sample_per_publisher(1000);
        // linear: about 4x; quadratic: about 16x
        let ratio = large.as_secs_f64() / small.as_secs_f64().max(1e-6);
        assert!(
            ratio < 9.0,
            "draining 4x the publishers took {ratio:.1}x as long ({small:?} -> {large:?})"
        );
    }
}
