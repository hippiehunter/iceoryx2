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

//! Cross-process secured-IPC test CLIENT binary.
//!
//! Plays the service **opener**: it connects an IAM client to the creator's
//! endpoint and, depending on `--pattern`, owns the producing / requesting
//! port. `open()` is retried in a loop because the creator may still be coming
//! up. State is reported via `CLIENT:`-prefixed stdout markers.

use std::time::{Duration, Instant};

use clap::Parser;
use iceoryx2::port::update_connections::UpdateConnections;
use iceoryx2::prelude::*;
use linux_e2e_tests::scenario::{secured_config, Cli, Pattern};

// Link the default console logger implementation (provides __internal_default_logger).
extern crate iceoryx2_bb_loggers;

macro_rules! mark {
    ($($arg:tt)*) => {{
        use std::io::Write;
        println!($($arg)*);
        let _ = std::io::stdout().flush();
    }};
}

/// Retries for `open()` while the creator is still coming up (~50 x 100ms).
const OPEN_ATTEMPTS: usize = 50;
const OPEN_RETRY_DELAY: Duration = Duration::from_millis(100);
/// Budget for the produce/consume milestone once the port exists.
const FLOW_TIMEOUT: Duration = Duration::from_secs(15);
/// How long a one-way producer keeps publishing AFTER a consumer first
/// connects. A producer must NOT exit the instant `send` reports delivery:
/// `delivered > 0` only means the sample reached the connection queue. If the
/// producer port drops immediately it deregisters from the service registry
/// before the consumer discovers it, opens the IAM-brokered channel and reads.
/// Staying alive this long lets the consumer discover + connect + receive.
const PRODUCE_GRACE: Duration = Duration::from_millis(1500);

fn main() {
    let cli = Cli::parse();
    mark!("CLIENT: pid={}", std::process::id());

    let result = match cli.pattern {
        Pattern::Pubsub => run_pubsub(&cli),
        Pattern::SlicePubsub => run_slice_pubsub(&cli),
        Pattern::Reqres => run_reqres(&cli),
        Pattern::Event => run_event(&cli),
    };

    match result {
        Ok(()) => {
            mark!("CLIENT: done");
            std::process::exit(0);
        }
        Err(e) => {
            eprintln!("CLIENT: ERROR {e}");
            std::process::exit(1);
        }
    }
}

fn node(cli: &Cli) -> Result<Node<ipc::Service>, String> {
    NodeBuilder::new()
        .config(&secured_config(cli.root_path.as_deref()))
        .create::<ipc::Service>()
        .map_err(|e| format!("node create failed: {e:?}"))
}

fn service_name(cli: &Cli) -> Result<ServiceName, String> {
    ServiceName::new(&cli.service_name).map_err(|e| format!("bad service name: {e:?}"))
}

/// Retry `open` until the creator's service + IAM server are up.
fn open_retry<T, E: core::fmt::Debug>(
    mut attempt: impl FnMut() -> Result<T, E>,
) -> Result<T, String> {
    let mut last = None;
    for _ in 0..OPEN_ATTEMPTS {
        match attempt() {
            Ok(v) => return Ok(v),
            Err(e) => {
                last = Some(format!("{e:?}"));
                std::thread::sleep(OPEN_RETRY_DELAY);
            }
        }
    }
    Err(format!(
        "open failed after {OPEN_ATTEMPTS} attempts: {}",
        last.unwrap_or_default()
    ))
}

/// Drive a one-way producer: keep sending until a consumer has connected and
/// been given [`PRODUCE_GRACE`] to read. `announce` is printed exactly once
/// (the first send); `send_once` performs one produce step and returns the
/// number of consumers delivered to.
fn produce_until_consumed(
    announce: String,
    mut send_once: impl FnMut() -> Result<usize, String>,
) -> Result<(), String> {
    let deadline = Instant::now() + FLOW_TIMEOUT;
    let mut announced = false;
    let mut first_delivery: Option<Instant> = None;
    while Instant::now() < deadline {
        let delivered = match send_once() {
            Ok(n) => n,
            // After we have delivered at least once, an error most likely means
            // the consumer (and, for creator-hosted IAM, its server) has gone
            // away having received the payload — treat that as success.
            Err(e) => {
                if first_delivery.is_some() {
                    return Ok(());
                }
                return Err(e);
            }
        };
        if !announced {
            mark!("{announce}");
            announced = true;
        }
        if delivered > 0 && first_delivery.is_none() {
            first_delivery = Some(Instant::now());
        }
        if let Some(t) = first_delivery {
            if t.elapsed() >= PRODUCE_GRACE {
                return Ok(());
            }
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    if first_delivery.is_some() {
        Ok(())
    } else {
        Err("consumer never connected to receive the payload".into())
    }
}

fn run_pubsub(cli: &Cli) -> Result<(), String> {
    let node = node(cli)?;
    let name = service_name(cli)?;
    let service = open_retry(|| node.service_builder(&name).publish_subscribe::<u64>().open())?;
    let publisher = service
        .publisher_builder()
        .create()
        .map_err(|e| format!("create publisher: {e:?}"))?;
    mark!("CLIENT: connected");

    let value = cli.value;
    produce_until_consumed(format!("CLIENT: sent {value}"), || {
        publisher
            .update_connections()
            .map_err(|e| format!("update_connections: {e:?}"))?;
        publisher
            .send_copy(value)
            .map_err(|e| format!("send_copy: {e:?}"))
    })
}

fn run_slice_pubsub(cli: &Cli) -> Result<(), String> {
    let node = node(cli)?;
    let name = service_name(cli)?;
    let service = open_retry(|| node.service_builder(&name).publish_subscribe::<[u8]>().open())?;
    let publisher = service
        .publisher_builder()
        .initial_max_slice_len(16)
        .allocation_strategy(AllocationStrategy::PowerOfTwo)
        .create()
        .map_err(|e| format!("create slice publisher: {e:?}"))?;
    mark!("CLIENT: connected");

    const LEN: usize = 12;
    produce_until_consumed(format!("CLIENT: sent len={LEN}"), || {
        publisher
            .update_connections()
            .map_err(|e| format!("update_connections: {e:?}"))?;
        let mut sample = publisher
            .loan_slice(LEN)
            .map_err(|e| format!("loan_slice: {e:?}"))?;
        for (i, byte) in sample.payload_mut().iter_mut().enumerate() {
            *byte = (i as u8).wrapping_mul(3).wrapping_add(1);
        }
        sample.send().map_err(|e| format!("send: {e:?}"))
    })
}

fn run_reqres(cli: &Cli) -> Result<(), String> {
    let node = node(cli)?;
    let name = service_name(cli)?;
    let service = open_retry(|| {
        node.service_builder(&name)
            .request_response::<u64, u64>()
            .open()
    })?;
    let client = service
        .client_builder()
        .create()
        .map_err(|e| format!("create client port: {e:?}"))?;
    mark!("CLIENT: connected");

    let pending = client
        .send_copy(cli.value)
        .map_err(|e| format!("send request: {e:?}"))?;
    mark!("CLIENT: sent {}", cli.value);

    let expected = cli.value.wrapping_add(1);
    let deadline = Instant::now() + FLOW_TIMEOUT;
    while Instant::now() < deadline {
        if let Some(response) = pending.receive().map_err(|e| format!("receive: {e:?}"))? {
            let got = *response;
            if got != expected {
                return Err(format!("response mismatch: got {got} want {expected}"));
            }
            mark!("CLIENT: received {got}");
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    Err("timed out waiting for response".into())
}

fn run_event(cli: &Cli) -> Result<(), String> {
    let node = node(cli)?;
    let name = service_name(cli)?;
    let service = open_retry(|| node.service_builder(&name).event().open())?;
    let notifier = service
        .notifier_builder()
        .create()
        .map_err(|e| format!("create notifier: {e:?}"))?;
    mark!("CLIENT: connected");

    // The default service caps event ids at `event_id_max_value` (255), so keep
    // the id in range regardless of `--value`.
    let id = (cli.value % 256) as usize;
    let event_id = EventId::new(id);
    produce_until_consumed(format!("CLIENT: sent {id}"), || {
        notifier
            .notify_with_custom_event_id(event_id)
            .map_err(|e| format!("notify: {e:?}"))
    })
}
