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

//! Mass-departure participant (`iox2-e2e-departure`).
//!
//! Opens (or creates) a large publish-subscribe service (sized like the SIP capture service:
//! `max_publishers` 10000), creates a publisher, prints `READY` and waits for a line on stdin.
//! Then it drops everything (deregistering its node from the service) and prints `DONE`. Many
//! of these processes leaving at once must not starve each other.

use std::io::{BufRead, Write};

use clap::Parser;
use iceoryx2::prelude::*;

extern crate iceoryx2_bb_loggers;

#[derive(Debug, Parser)]
struct Cli {
    /// iceoryx2 resource prefix, unique per test run.
    #[arg(long)]
    prefix: String,
    /// iceoryx2 root path.
    #[arg(long)]
    root_path: String,
    #[arg(long)]
    service: String,
    #[arg(long, default_value_t = 10_000)]
    max_publishers: usize,
}

fn main() {
    set_log_level_from_env_or(LogLevel::Warn);
    let cli = Cli::parse();

    let mut config = iceoryx2::config::Config::default();
    config.global.prefix = FileName::new(cli.prefix.as_bytes()).expect("valid prefix");
    config
        .global
        .set_root_path(&Path::new(cli.root_path.as_bytes()).expect("valid root path"));

    let node = NodeBuilder::new()
        .config(&config)
        .create::<ipc::Service>()
        .expect("node");
    let service = node
        .service_builder(&ServiceName::new(&cli.service).expect("service name"))
        .publish_subscribe::<u64>()
        .max_publishers(cli.max_publishers)
        .max_subscribers(4)
        .max_nodes(cli.max_publishers + 16)
        .open_or_create()
        .expect("service");
    let publisher = service.publisher_builder().create().expect("publisher");

    println!("READY");
    let _ = std::io::stdout().flush();

    let mut line = String::new();
    let _ = std::io::stdin().lock().read_line(&mut line);

    drop(publisher);
    drop(service);
    drop(node);
    println!("DONE");
    let _ = std::io::stdout().flush();
}
