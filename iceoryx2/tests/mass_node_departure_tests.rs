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

//! Many nodes with publishers on one large service (`max_publishers` 10000) leave at the same
//! time. Deregistering the nodes from the service dynamic config must not starve each other and
//! the last node must remove the service.

#[cfg(test)]
mod mass_node_departure {
    use std::sync::Barrier;
    use std::time::{Duration, Instant};

    use iceoryx2::config::Config;
    use iceoryx2::prelude::*;
    use iceoryx2_bb_posix::unique_system_id::UniqueSystemId;

    const MAX_PUBLISHERS: usize = 10_000;
    const TIME_LIMIT: Duration = Duration::from_secs(5);

    fn departure_of(number_of_nodes: usize, cleanup_dead_nodes: bool) {
        let id = UniqueSystemId::new().unwrap().value();
        let mut config = Config::default();
        config.global.prefix = FileName::new(format!("md{id}_").as_bytes()).unwrap();
        // Every node scans all nodes for dead ones when it is created/destroyed (O(n) per node).
        // With many nodes leaving at once this dominates; deployments with very many short-lived
        // nodes disable it on the participants and leave dead-node cleanup to a long-lived node.
        config.global.node.cleanup_dead_nodes_on_creation = cleanup_dead_nodes;
        config.global.node.cleanup_dead_nodes_on_destruction = cleanup_dead_nodes;
        let service_name = ServiceName::new(&format!("mass_departure_{id}")).unwrap();

        let ready = Barrier::new(number_of_nodes + 1);
        let go = Barrier::new(number_of_nodes + 1);
        let mut elapsed = Duration::ZERO;

        std::thread::scope(|s| {
            let mut threads = Vec::new();
            for _ in 0..number_of_nodes {
                threads.push(s.spawn(|| {
                    let node = NodeBuilder::new()
                        .config(&config)
                        .create::<ipc::Service>()
                        .unwrap();
                    let service = node
                        .service_builder(&service_name)
                        .publish_subscribe::<u64>()
                        .max_publishers(MAX_PUBLISHERS)
                        .max_subscribers(4)
                        .max_nodes(MAX_PUBLISHERS + 16)
                        .open_or_create()
                        .unwrap();
                    let publisher = service.publisher_builder().create().unwrap();
                    ready.wait();
                    go.wait();
                    drop(publisher);
                    drop(service);
                    drop(node);
                }));
            }

            ready.wait();
            println!("{number_of_nodes} nodes ready, departing");
            let start = Instant::now();
            go.wait();
            for t in threads {
                t.join().unwrap();
            }
            elapsed = start.elapsed();
        });

        println!("{number_of_nodes} nodes departed in {elapsed:?}");
        assert!(
            elapsed < TIME_LIMIT,
            "{number_of_nodes} departing nodes took {elapsed:?} (limit {TIME_LIMIT:?})"
        );
        assert!(
            !ipc::Service::does_exist(&service_name, &config, MessagingPattern::PublishSubscribe)
                .unwrap(),
            "the last departing node did not remove the service"
        );
    }

    #[test]
    fn twenty_nodes_leaving_at_once_do_not_starve() {
        departure_of(20, true);
    }

    #[test]
    fn hundred_nodes_leaving_at_once_do_not_starve() {
        departure_of(100, true);
    }

    /// Heavy variant (1000 threads), run explicitly with `--ignored`.
    #[test]
    #[ignore]
    fn thousand_nodes_leaving_at_once_do_not_starve() {
        departure_of(1000, false);
    }
}
