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

//! Multi-user secured-mode participant for Windows (`win-e2e-mu`).
//!
//! The Windows counterpart of the Linux `iox2-e2e-mu`: plays one role of the SIP-like
//! deployment (`broker`, `writer` or `intruder`), each started under its own Windows account
//! by the harness script. Every role reports progress via `ROLE: ...` stdout markers. As the
//! roles run without a console (scheduled tasks), the broker and the writers stop when the
//! `--quit-file` appears instead of reading `quit` from stdin.

#[cfg(windows)]
extern crate iceoryx2_bb_loggers;

#[cfg(windows)]
fn main() {
    mu::main()
}

#[cfg(not(windows))]
fn main() {
    eprintln!("win-e2e-mu runs on Windows only");
    std::process::exit(2);
}

#[cfg(windows)]
mod mu {
    use std::time::{Duration, Instant};

    use clap::{Parser, ValueEnum};
    use iceoryx2::config::{Config, FileMode};
    use iceoryx2::port::listener::ListenerCreateError;
    use iceoryx2::port::notifier::NotifierCreateError;
    use iceoryx2::port::publisher::PublisherCreateError;
    use iceoryx2::port::subscriber::SubscriberCreateError;
    use iceoryx2::prelude::*;
    use iceoryx2_cal::security::mode::SecurityMode;

    const DATA_SERVICE: &str = "DeltaReplicator";
    const EVENTS_SERVICE: &str = "DeltaReplicator/events";
    const SPACE_SERVICE: &str = "DeltaReplicator/space";
    const RUN_TIMEOUT: Duration = Duration::from_secs(60);

    macro_rules! mark {
        ($($arg:tt)*) => {{
            use std::io::Write;
            println!($($arg)*);
            let _ = std::io::stdout().flush();
        }};
    }

    /// User header of every sample (shape of the SIP replication header).
    #[derive(Debug, Default, Clone, Copy, ZeroCopySend)]
    #[type_name("ReplicationHeader")]
    #[repr(C)]
    struct ReplicationHeader {
        version: u16,
        op_type: i32,
        process_id: u32,
        uid: u32,
        seq: u64,
        payload_len: u32,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
    enum Role {
        Broker,
        Writer,
        Intruder,
        /// Prints the account SIDs that policies resolve and the caller's token SIDs.
        Whoami,
    }

    #[derive(Debug, Parser)]
    struct MuCli {
        #[arg(long, value_enum)]
        role: Role,
        /// iceoryx2 root path.
        #[arg(long)]
        root_path: String,
        /// iceoryx2 resource prefix, unique per run.
        #[arg(long)]
        prefix: String,
        /// IAM policy directory.
        #[arg(long)]
        policy_dir: String,
        /// `shared-directory-mode`, e.g. 1777.
        #[arg(long)]
        shared_mode: Option<String>,
        /// `shared-group` (name).
        #[arg(long)]
        shared_group: Option<String>,
        /// `iam.endpoint-mode`, e.g. 0666.
        #[arg(long)]
        endpoint_mode: Option<String>,
        /// Absolute path of the IAM audit log (broker only).
        #[arg(long)]
        audit_log: Option<String>,
        /// Writer: samples to send. Broker: samples to receive in total.
        #[arg(long, default_value_t = 3)]
        count: u64,
        /// Writer: the id written into the header and the payload.
        #[arg(long, default_value_t = 0)]
        id: u32,
        /// Broker and writers stop when this file exists.
        #[arg(long)]
        quit_file: Option<String>,
    }

    type Data = iceoryx2::service::port_factory::publish_subscribe::PortFactory<
        ipc::Service,
        [u8],
        ReplicationHeader,
    >;
    type Events = iceoryx2::service::port_factory::event::PortFactory<ipc::Service>;

    fn account() -> String {
        format!(
            "{}\\{}",
            std::env::var("USERDOMAIN").unwrap_or_default(),
            std::env::var("USERNAME").unwrap_or_default()
        )
    }

    fn config(cli: &MuCli) -> Config {
        let mut config = Config::default();
        config.global.node.security.mode = SecurityMode::Secured;
        config
            .global
            .set_root_path(&Path::new(cli.root_path.as_bytes()).expect("valid root path"));
        config.global.prefix = FileName::new(cli.prefix.as_bytes()).expect("valid prefix");
        let security = &mut config.global.node.security;
        security.shared_directory_mode = cli
            .shared_mode
            .as_ref()
            .map(|m| FileMode::from_octal_str(m).expect("valid shared mode"));
        security.shared_group = cli
            .shared_group
            .as_ref()
            .map(|g| FileName::new(g.as_bytes()).expect("valid group"));
        security.iam.endpoint_mode = cli
            .endpoint_mode
            .as_ref()
            .map(|m| FileMode::from_octal_str(m).expect("valid endpoint mode"));
        let iam = &mut config.global.node.security.iam;
        iam.policy_dir = Path::new(cli.policy_dir.as_bytes()).expect("valid policy dir");
        iam.audit_log_path = match &cli.audit_log {
            Some(p) => Path::new(p.as_bytes()).expect("valid audit log path"),
            None => Path::new(b"").expect("empty path"),
        };
        config
    }

    /// The payload a writer sends for `seq`; its length grows with `seq` so that the
    /// PowerOfTwo strategy reallocates segments.
    fn payload_for(id: u32, seq: u64) -> Vec<u8> {
        let mut payload = format!("id={id} seq={seq};").into_bytes();
        let target = 24 + (seq as usize) * 300;
        let mut i = 0u8;
        while payload.len() < target {
            payload.push(b'a' + (i % 26));
            i = i.wrapping_add(1);
        }
        payload
    }

    fn quit_requested(cli: &MuCli) -> bool {
        cli.quit_file
            .as_ref()
            .is_some_and(|f| std::path::Path::new(f).exists())
    }

    pub fn main() {
        set_log_level_from_env_or(LogLevel::Warn);
        let cli = MuCli::parse();
        let result = match cli.role {
            Role::Broker => run_broker(&cli),
            Role::Writer => run_writer(&cli),
            Role::Intruder => run_intruder(&cli),
            Role::Whoami => run_whoami(),
        };
        match result {
            Ok(()) => std::process::exit(0),
            Err(e) => {
                mark!("{:?}: ERROR {e}", cli.role);
                std::process::exit(1);
            }
        }
    }

    fn node(cli: &MuCli) -> Result<Node<ipc::Service>, String> {
        NodeBuilder::new()
            .config(&config(cli))
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
            .max_publishers(8)
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

        mark!(
            "BROKER: ready pid={} account={}",
            std::process::id(),
            account()
        );

        let deadline = Instant::now() + RUN_TIMEOUT;
        let mut received = 0u64;
        let mut last_publishers = usize::MAX;
        while received < cli.count {
            if Instant::now() > deadline {
                return Err(format!(
                    "timed out after receiving {received} of {} samples",
                    cli.count
                ));
            }

            let mut events_seen = 0;
            listener
                .timed_wait(|_| events_seen += 1, Duration::from_millis(50))
                .map_err(|e| format!("listener wait: {e:?}"))?;

            let mut drained = 0;
            while let Some(sample) = subscriber
                .receive()
                .map_err(|e| format!("receive: {e:?}"))?
            {
                let header = *sample.user_header();
                let payload = sample.payload();
                if payload != payload_for(header.uid, header.seq).as_slice()
                    || header.payload_len as usize != payload.len()
                {
                    return Err(format!(
                        "payload of id {} seq {} is corrupted (len {})",
                        header.uid,
                        header.seq,
                        payload.len()
                    ));
                }
                received += 1;
                drained += 1;
                mark!(
                    "BROKER: received id={} seq={} len={} pid={}",
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

            if (drained > 0 || events_seen > 0)
                && let Err(e) = notifier.notify()
            {
                mark!("BROKER: notify warning {e:?}");
            }
        }

        mark!("BROKER: received all {received}");
        let wait_until = Instant::now() + RUN_TIMEOUT;
        while Instant::now() < wait_until && !quit_requested(cli) {
            std::thread::sleep(Duration::from_millis(50));
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
        let me = cli.id;
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
        mark!("WRITER {me}: opened all services as {}", account());

        // Writers must never be able to read samples (their own or other writers').
        match data.subscriber_builder().create() {
            Err(SubscriberCreateError::IamAuthorizationDenied) => {
                mark!("WRITER {me}: subscriber denied by IAM")
            }
            Err(e) => return Err(format!("unexpected subscriber error {e:?}")),
            Ok(_) => return Err("a writer was allowed to create a subscriber".into()),
        }

        let publisher = data
            .publisher_builder()
            .initial_max_slice_len(16)
            .allocation_strategy(AllocationStrategy::PowerOfTwo)
            .create()
            .map_err(|e| format!("create publisher: {e:?}"))?;
        mark!("WRITER {me}: publisher attached");

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
            mark!(
                "WRITER {me}: sent seq={seq} len={} delivered={delivered}",
                payload.len()
            );

            let mut space_events = 0;
            listener
                .timed_wait(|_| space_events += 1, Duration::from_secs(5))
                .map_err(|e| format!("space wait: {e:?}"))?;
            if space_events > 0 {
                mark!("WRITER {me}: space seq={seq}");
            }
        }

        mark!("WRITER {me}: done sending");
        let wait_until = Instant::now() + RUN_TIMEOUT;
        while Instant::now() < wait_until && !quit_requested(cli) {
            std::thread::sleep(Duration::from_millis(50));
        }
        mark!("WRITER {me}: done");
        Ok(())
    }

    fn run_whoami() -> Result<(), String> {
        use iceoryx2_pal_posix::windows::security_descriptor::Sid;

        let me = iceoryx2_cal::security::credentials::ProcessCredentials::from_self();
        let to_string = |sid: &[u8]| Sid::from_bytes(sid).to_sid_string().unwrap_or_default();
        mark!(
            "WHOAMI: {} user_sid={:?}",
            account(),
            me.user_sid().map(to_string)
        );
        for group in me.group_sids().unwrap_or_default() {
            mark!("WHOAMI: group {}", to_string(group));
        }
        for name in ["sipbroker", "SIPWriters", "writer1", "Users"] {
            match Sid::from_account_name(name) {
                Ok(sid) => mark!(
                    "WHOAMI: lookup {name} = {:?} member={}",
                    sid.to_sid_string(),
                    me.is_member_of(sid.as_bytes())
                ),
                Err(e) => mark!("WHOAMI: lookup {name} failed {e:?}"),
            }
        }
        Ok(())
    }

    fn run_intruder(cli: &MuCli) -> Result<(), String> {
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
        mark!("INTRUDER: opened all services as {}", account());

        let mut allowed = Vec::new();
        match data.publisher_builder().create() {
            Err(PublisherCreateError::IamAuthorizationDenied) => {
                mark!("INTRUDER: publisher denied by IAM")
            }
            other => allowed.push(format!("publisher: {:?}", other.map(|_| ()))),
        }
        match data.subscriber_builder().create() {
            Err(SubscriberCreateError::IamAuthorizationDenied) => {
                mark!("INTRUDER: subscriber denied by IAM")
            }
            other => allowed.push(format!("subscriber: {:?}", other.map(|_| ()))),
        }
        match events.notifier_builder().create() {
            Err(NotifierCreateError::IamAuthorizationDenied) => {
                mark!("INTRUDER: notifier denied by IAM")
            }
            other => allowed.push(format!("notifier: {:?}", other.map(|_| ()))),
        }
        match space.listener_builder().create() {
            Err(ListenerCreateError::IamAuthorizationDenied) => {
                mark!("INTRUDER: listener denied by IAM")
            }
            other => allowed.push(format!("listener: {:?}", other.map(|_| ()))),
        }

        if allowed.is_empty() {
            mark!("INTRUDER: all ports denied");
            Ok(())
        } else {
            Err(format!("not denied by IAM: {allowed:?}"))
        }
    }
}
