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

//! Cross-process secured-IPC test SERVER binary.
//!
//! Plays the service **creator**: it hosts the IAM server (with the segment
//! factory + policy) for the service and, depending on `--pattern`, owns the
//! consuming / responding port. State is reported via `SERVER:`-prefixed stdout
//! markers that the parent harness matches.

use std::time::{Duration, Instant};

use clap::Parser;
use iceoryx2::prelude::*;
use linux_e2e_tests::scenario::{secured_config, Cli, Pattern};

// Link the default console logger implementation (provides __internal_default_logger).
extern crate iceoryx2_bb_loggers;

/// Print a marker line and flush so the parent sees it immediately.
macro_rules! mark {
    ($($arg:tt)*) => {{
        use std::io::Write;
        println!($($arg)*);
        let _ = std::io::stdout().flush();
    }};
}

/// Overall budget for the data milestone before the server gives up.
const RECV_TIMEOUT: Duration = Duration::from_secs(15);
/// Grace period the responder stays alive after replying so the opener can read.
const REPLY_GRACE: Duration = Duration::from_secs(2);

fn main() {
    let cli = Cli::parse();
    mark!("SERVER: pid={}", std::process::id());

    let result = match cli.pattern {
        Pattern::Pubsub => run_pubsub(&cli),
        Pattern::SlicePubsub => run_slice_pubsub(&cli),
        Pattern::Reqres => run_reqres(&cli),
        Pattern::Event => run_event(&cli),
    };

    match result {
        Ok(()) => {
            mark!("SERVER: done");
            std::process::exit(0);
        }
        Err(e) => {
            eprintln!("SERVER: ERROR {e}");
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

fn run_pubsub(cli: &Cli) -> Result<(), String> {
    let node = node(cli)?;
    let service = node
        .service_builder(&service_name(cli)?)
        .publish_subscribe::<u64>()
        .create()
        .map_err(|e| format!("create pub-sub service: {e:?}"))?;
    let subscriber = service
        .subscriber_builder()
        .create()
        .map_err(|e| format!("create subscriber: {e:?}"))?;
    mark!("SERVER: listening");

    let deadline = Instant::now() + RECV_TIMEOUT;
    while Instant::now() < deadline {
        if let Some(sample) = subscriber
            .receive()
            .map_err(|e| format!("receive: {e:?}"))?
        {
            let got = *sample;
            if got != cli.value {
                return Err(format!("payload mismatch: got {got} want {}", cli.value));
            }
            mark!("SERVER: received {got}");
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    Err("timed out waiting for sample".into())
}

fn run_slice_pubsub(cli: &Cli) -> Result<(), String> {
    let node = node(cli)?;
    let service = node
        .service_builder(&service_name(cli)?)
        .publish_subscribe::<[u8]>()
        .create()
        .map_err(|e| format!("create slice pub-sub service: {e:?}"))?;
    let subscriber = service
        .subscriber_builder()
        .create()
        .map_err(|e| format!("create subscriber: {e:?}"))?;
    mark!("SERVER: listening");

    let deadline = Instant::now() + RECV_TIMEOUT;
    while Instant::now() < deadline {
        if let Some(sample) = subscriber
            .receive()
            .map_err(|e| format!("receive: {e:?}"))?
        {
            let payload = sample.payload();
            for (i, byte) in payload.iter().enumerate() {
                let want = (i as u8).wrapping_mul(3).wrapping_add(1);
                if *byte != want {
                    return Err(format!("slice byte {i} mismatch: got {byte} want {want}"));
                }
            }
            mark!("SERVER: received len={}", payload.len());
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    Err("timed out waiting for slice sample".into())
}

fn run_reqres(cli: &Cli) -> Result<(), String> {
    let node = node(cli)?;
    let service = node
        .service_builder(&service_name(cli)?)
        .request_response::<u64, u64>()
        .create()
        .map_err(|e| format!("create req-resp service: {e:?}"))?;
    let server = service
        .server_builder()
        .create()
        .map_err(|e| format!("create server port: {e:?}"))?;
    mark!("SERVER: listening");

    let deadline = Instant::now() + RECV_TIMEOUT;
    while Instant::now() < deadline {
        if let Some(active_request) = server.receive().map_err(|e| format!("receive: {e:?}"))? {
            let got = *active_request;
            if got != cli.value {
                return Err(format!("request mismatch: got {got} want {}", cli.value));
            }
            mark!("SERVER: received {got}");
            let response = got.wrapping_add(1);
            active_request
                .send_copy(response)
                .map_err(|e| format!("send response: {e:?}"))?;
            mark!("SERVER: replied {response}");
            // Stay alive briefly so the opener can read the response from the
            // still-mapped response segment before our IAM server/ports drop.
            std::thread::sleep(REPLY_GRACE);
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    Err("timed out waiting for request".into())
}

fn run_event(cli: &Cli) -> Result<(), String> {
    let node = node(cli)?;
    let service = node
        .service_builder(&service_name(cli)?)
        .event()
        .create()
        .map_err(|e| format!("create event service: {e:?}"))?;
    let listener = service
        .listener_builder()
        .create()
        .map_err(|e| format!("create listener: {e:?}"))?;
    mark!("SERVER: listening");

    let deadline = Instant::now() + RECV_TIMEOUT;
    while Instant::now() < deadline {
        let mut count = 0usize;
        listener
            .try_wait(|_id| count += 1)
            .map_err(|e| format!("try_wait: {e:?}"))?;
        if count > 0 {
            mark!("SERVER: received {count}");
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    Err("timed out waiting for notification".into())
}
