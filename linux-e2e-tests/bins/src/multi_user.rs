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

//! Multi-user secured-mode participant (`iox2-e2e-mu`).
//!
//! Plays one role of the SIP-like deployment (see
//! [`linux_e2e_tests::multi_user`]): `broker`, `writer` or `intruder`. Every
//! role reports progress via `ROLE: ...` stdout markers matched by the harness.

use std::io::BufRead;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use clap::Parser;
use iceoryx2::port::listener::ListenerCreateError;
use iceoryx2::port::notifier::NotifierCreateError;
use iceoryx2::port::publisher::PublisherCreateError;
use iceoryx2::port::subscriber::SubscriberCreateError;
use iceoryx2::prelude::*;
use linux_e2e_tests::multi_user::{
    DATA_SERVICE, EVENTS_SERVICE, MuCli, ReplicationHeader, Role, SPACE_SERVICE,
    multi_user_config, payload_for,
};

extern crate iceoryx2_bb_loggers;

macro_rules! mark {
    ($($arg:tt)*) => {{
        use std::io::Write;
        println!($($arg)*);
        let _ = std::io::stdout().flush();
    }};
}

type Data = iceoryx2::service::port_factory::publish_subscribe::PortFactory<
    ipc::Service,
    [u8],
    ReplicationHeader,
>;
type Events = iceoryx2::service::port_factory::event::PortFactory<ipc::Service>;

const RUN_TIMEOUT: Duration = Duration::from_secs(60);

fn uid() -> u32 {
    unsafe { libc::geteuid() }
}

fn main() {
    set_log_level_from_env_or(LogLevel::Warn);
    let cli = MuCli::parse();
    let result = match cli.role {
        Role::Broker => run_broker(&cli),
        Role::Writer => run_writer(&cli),
        Role::Intruder => run_intruder(&cli),
    };
    match result {
        Ok(()) => std::process::exit(0),
        Err(e) => {
            mark!("{:?}: ERROR {e}", cli.role);
            std::process::exit(1);
        }
    }
}

/// Lines written to stdin by the harness (`quit`).
fn stdin_lines() -> mpsc::Receiver<String> {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        for line in std::io::stdin().lock().lines().map_while(Result::ok) {
            if tx.send(line).is_err() {
                break;
            }
        }
    });
    rx
}

fn node(cli: &MuCli) -> Result<Node<ipc::Service>, String> {
    NodeBuilder::new()
        .config(&multi_user_config(cli))
        .create::<ipc::Service>()
        .map_err(|e| format!("node create failed: {e:?}"))
}

fn name(n: &str) -> ServiceName {
    ServiceName::new(n).expect("valid service name")
}

fn run_broker(cli: &MuCli) -> Result<(), String> {
    let node = node(cli)?;
    let data: Data = node
        .service_builder(&name(DATA_SERVICE))
        .publish_subscribe::<[u8]>()
        .user_header::<ReplicationHeader>()
        .max_publishers(cli.max_publishers)
        .subscriber_max_buffer_size(64)
        .create()
        .map_err(|e| format!("create data service: {e:?}"))?;
    let events: Events = node
        .service_builder(&name(EVENTS_SERVICE))
        .event()
        .create()
        .map_err(|e| format!("create events service: {e:?}"))?;
    let space: Events = node
        .service_builder(&name(SPACE_SERVICE))
        .event()
        .create()
        .map_err(|e| format!("create space service: {e:?}"))?;

    let subscriber = data
        .subscriber_builder()
        .buffer_size(64)
        .create()
        .map_err(|e| format!("create subscriber: {e:?}"))?;
    let listener = events
        .listener_builder()
        .create()
        .map_err(|e| format!("create listener: {e:?}"))?;
    let notifier = space
        .notifier_builder()
        .create()
        .map_err(|e| format!("create notifier: {e:?}"))?;

    let quit = stdin_lines();
    mark!("BROKER: ready pid={} uid={}", std::process::id(), uid());

    let deadline = Instant::now() + RUN_TIMEOUT;
    let mut received = 0u64;
    let mut last_publishers = usize::MAX;
    let mut notify_warnings = 0usize;
    while received < cli.count {
        if Instant::now() > deadline {
            return Err(format!("timed out after receiving {received} of {} samples", cli.count));
        }

        let mut events_seen = 0;
        listener
            .timed_wait(|_| events_seen += 1, Duration::from_millis(50))
            .map_err(|e| format!("listener wait: {e:?}"))?;

        let mut drained = 0;
        while let Some(sample) = subscriber.receive().map_err(|e| format!("receive: {e:?}"))? {
            let header = *sample.user_header();
            let payload = sample.payload();
            let expected = payload_for(header.uid, header.seq);
            if payload != expected.as_slice() || header.payload_len as usize != payload.len() {
                return Err(format!(
                    "payload of uid {} seq {} is corrupted (len {})",
                    header.uid,
                    header.seq,
                    payload.len()
                ));
            }
            received += 1;
            drained += 1;
            mark!(
                "BROKER: received uid={} seq={} len={} pid={}",
                header.uid,
                header.seq,
                payload.len(),
                header.process_id
            );
        }

        let publishers = data.dynamic_config().number_of_publishers();
        if publishers != last_publishers {
            mark!("BROKER: publishers={publishers}");
            last_publishers = publishers;
        }

        if drained > 0 || events_seen > 0 {
            // A listener of a writer that was killed may still be registered for a moment;
            // a failed notification must never take the broker down.
            if let Err(e) = notifier.notify() {
                notify_warnings += 1;
                mark!("BROKER: notify warning {e:?}");
            }
        }
    }

    mark!("BROKER: received all {received} notify_warnings={notify_warnings}");

    // keep everything alive until the harness has inspected the system
    let wait_until = Instant::now() + RUN_TIMEOUT;
    while Instant::now() < wait_until {
        if let Ok(line) = quit.recv_timeout(Duration::from_millis(50))
            && line.trim() == "quit"
        {
            break;
        }
        let publishers = data.dynamic_config().number_of_publishers();
        if publishers != last_publishers {
            mark!("BROKER: publishers={publishers}");
            last_publishers = publishers;
        }
    }
    mark!("BROKER: done");
    Ok(())
}

fn open_with_retry<T, F: FnMut() -> Result<T, String>>(mut f: F) -> Result<T, String> {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match f() {
            Ok(v) => return Ok(v),
            Err(e) if Instant::now() > deadline => return Err(e),
            Err(_) => std::thread::sleep(Duration::from_millis(50)),
        }
    }
}

fn run_writer(cli: &MuCli) -> Result<(), String> {
    let me = uid();
    let node = node(cli)?;
    let data: Data = open_with_retry(|| {
        node.service_builder(&name(DATA_SERVICE))
            .publish_subscribe::<[u8]>()
            .user_header::<ReplicationHeader>()
            .open()
            .map_err(|e| format!("open data service: {e:?}"))
    })?;
    let events: Events = open_with_retry(|| {
        node.service_builder(&name(EVENTS_SERVICE))
            .event()
            .open()
            .map_err(|e| format!("open events service: {e:?}"))
    })?;
    let space: Events = open_with_retry(|| {
        node.service_builder(&name(SPACE_SERVICE))
            .event()
            .open()
            .map_err(|e| format!("open space service: {e:?}"))
    })?;

    // Writers must never be able to read samples (their own or other writers').
    match data.subscriber_builder().create() {
        Err(SubscriberCreateError::IamAuthorizationDenied) => {
            mark!("WRITER uid={me}: subscriber denied by IAM")
        }
        Err(e) => return Err(format!("unexpected subscriber error {e:?}")),
        Ok(_) => return Err("a writer was allowed to create a subscriber".into()),
    }

    let retry_until = Instant::now() + Duration::from_secs(cli.publisher_retry_secs);
    let mut retries = 0u64;
    let publisher = loop {
        match data
            .publisher_builder()
            .initial_max_slice_len(16)
            .allocation_strategy(AllocationStrategy::PowerOfTwo)
            .create()
        {
            Ok(p) => break p,
            Err(PublisherCreateError::ExceedsMaxSupportedPublishers)
                if Instant::now() < retry_until =>
            {
                retries += 1;
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(e) => return Err(format!("create publisher: {e:?}")),
        }
    };
    mark!("WRITER uid={me}: publisher attached after {retries} retries");

    let notifier = events
        .notifier_builder()
        .create()
        .map_err(|e| format!("create notifier: {e:?}"))?;
    let listener = space
        .listener_builder()
        .create()
        .map_err(|e| format!("create listener: {e:?}"))?;

    for seq in 0..cli.count {
        let payload = payload_for(me, seq);
        let mut sample = publisher
            .loan_slice_uninit(payload.len())
            .map_err(|e| format!("loan: {e:?}"))?;
        *sample.user_header_mut() = ReplicationHeader {
            version: 2,
            op_type: 1,
            process_id: std::process::id(),
            uid: me,
            seq,
            payload_len: payload.len() as u32,
        };
        let sample = sample.write_from_slice(&payload);
        let delivered = sample.send().map_err(|e| format!("send: {e:?}"))?;
        notifier.notify().map_err(|e| format!("notify: {e:?}"))?;
        mark!("WRITER uid={me}: sent seq={seq} len={} delivered={delivered}", payload.len());

        let mut space_events = 0;
        listener
            .timed_wait(|_| space_events += 1, Duration::from_secs(5))
            .map_err(|e| format!("space wait: {e:?}"))?;
        if space_events > 0 {
            mark!("WRITER uid={me}: space seq={seq}");
        }
    }

    if cli.hang {
        mark!("WRITER uid={me}: hanging pid={}", std::process::id());
        loop {
            std::thread::sleep(Duration::from_secs(1));
        }
    }

    mark!("WRITER uid={me}: done sending");
    let quit = stdin_lines();
    let _ = quit.recv_timeout(RUN_TIMEOUT);
    mark!("WRITER uid={me}: done");
    Ok(())
}

fn run_intruder(cli: &MuCli) -> Result<(), String> {
    let me = uid();
    let node = node(cli)?;
    let data: Data = node
        .service_builder(&name(DATA_SERVICE))
        .publish_subscribe::<[u8]>()
        .user_header::<ReplicationHeader>()
        .open()
        .map_err(|e| format!("open data service: {e:?}"))?;
    let events: Events = node
        .service_builder(&name(EVENTS_SERVICE))
        .event()
        .open()
        .map_err(|e| format!("open events service: {e:?}"))?;
    let space: Events = node
        .service_builder(&name(SPACE_SERVICE))
        .event()
        .open()
        .map_err(|e| format!("open space service: {e:?}"))?;
    // the file system let us in: the static config, node and dynamic config were readable
    mark!("INTRUDER uid={me}: opened all services");

    let mut allowed = Vec::new();
    match data.publisher_builder().create() {
        Err(PublisherCreateError::IamAuthorizationDenied) => {
            mark!("INTRUDER uid={me}: publisher denied by IAM")
        }
        other => allowed.push(format!("publisher: {:?}", other.map(|_| ()))),
    }
    match data.subscriber_builder().create() {
        Err(SubscriberCreateError::IamAuthorizationDenied) => {
            mark!("INTRUDER uid={me}: subscriber denied by IAM")
        }
        other => allowed.push(format!("subscriber: {:?}", other.map(|_| ()))),
    }
    match events.notifier_builder().create() {
        Err(NotifierCreateError::IamAuthorizationDenied) => {
            mark!("INTRUDER uid={me}: notifier denied by IAM")
        }
        other => allowed.push(format!("notifier: {:?}", other.map(|_| ()))),
    }
    match space.listener_builder().create() {
        Err(ListenerCreateError::IamAuthorizationDenied) => {
            mark!("INTRUDER uid={me}: listener denied by IAM")
        }
        other => allowed.push(format!("listener: {:?}", other.map(|_| ()))),
    }

    if allowed.is_empty() {
        mark!("INTRUDER uid={me}: all ports denied");
        Ok(())
    } else {
        Err(format!("not denied by IAM: {allowed:?}"))
    }
}
