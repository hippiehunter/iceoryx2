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

//! Shared pieces of the multi-user (cross-uid) secured-mode scenario.
//!
//! The scenario mirrors the Synergex Integration Platform deployment: a broker
//! creates a `[u8]` publish-subscribe service with a user header and two event
//! services, and writers running as *different* Unix users publish into it.
//!
//! * [`MuCli`] / [`multi_user_config`] are used by the `iox2-e2e-mu` child binary.
//! * [`MuProcess`] spawns a child as another uid/gid/supplementary groups; it is
//!   used by the test harness which must run as root (e.g. `podman unshare`).

use std::io::{BufRead, Write};
use std::os::unix::process::CommandExt;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use clap::{Parser, ValueEnum};
use iceoryx2::config::{Config, FileMode};
use iceoryx2::prelude::*;
use iceoryx2_cal::security::mode::SecurityMode;

/// Name of the data service (pub/sub, `[u8]` payload + [`ReplicationHeader`]).
pub const DATA_SERVICE: &str = "DeltaReplicator";
/// Event service: writers notify, broker listens.
pub const EVENTS_SERVICE: &str = "DeltaReplicator/events";
/// Event service: broker notifies, writers listen.
pub const SPACE_SERVICE: &str = "DeltaReplicator/space";

/// User header of every sample (shape of the SIP replication header).
#[derive(Debug, Default, Clone, Copy, ZeroCopySend)]
#[type_name("ReplicationHeader")]
#[repr(C)]
pub struct ReplicationHeader {
    pub version: u16,
    pub op_type: i32,
    pub process_id: u32,
    pub uid: u32,
    pub seq: u64,
    pub payload_len: u32,
}

/// The role a child process plays.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Role {
    /// Creates all services, subscribes to the data, listens on `events`, notifies `space`.
    Broker,
    /// Publishes data, notifies `events`, listens on `space`.
    Writer,
    /// Has file-system access but no policy grant; every port creation must be refused by IAM.
    Intruder,
}

/// CLI of the `iox2-e2e-mu` binary.
#[derive(Debug, Parser)]
pub struct MuCli {
    #[arg(long, value_enum)]
    pub role: Role,
    /// iceoryx2 root path (created by the broker with `--shared-mode`).
    #[arg(long)]
    pub root_path: String,
    /// iceoryx2 resource prefix, unique per test run (isolates /dev/shm names).
    #[arg(long)]
    pub prefix: String,
    /// IAM policy directory.
    #[arg(long)]
    pub policy_dir: String,
    /// `shared-directory-mode`, e.g. 1777 or 2770.
    #[arg(long)]
    pub shared_mode: String,
    /// `shared-group` (name or gid).
    #[arg(long)]
    pub shared_group: Option<String>,
    /// `iam.endpoint-mode`, e.g. 0666 or 0660.
    #[arg(long)]
    pub endpoint_mode: String,
    /// `iam.endpoint-group` (name or gid).
    #[arg(long)]
    pub endpoint_group: Option<String>,
    /// Absolute path of the IAM audit log (broker only).
    #[arg(long)]
    pub audit_log: Option<String>,
    /// Writer: number of samples to send. Broker: number of samples to receive in total.
    #[arg(long, default_value_t = 3)]
    pub count: u64,
    /// Broker: `max_publishers` of the data service.
    #[arg(long, default_value_t = 8)]
    pub max_publishers: usize,
    /// Writer: block forever after sending (to be SIGKILLed).
    #[arg(long, default_value_t = false)]
    pub hang: bool,
    /// Writer: how long to retry creating the publisher (e.g. while the slot of a killed
    /// writer is still occupied).
    #[arg(long, default_value_t = 0)]
    pub publisher_retry_secs: u64,
}

/// Builds the multi-user secured config shared by all roles.
pub fn multi_user_config(cli: &MuCli) -> Config {
    let mut config = Config::default();
    config.global.node.security.mode = SecurityMode::Secured;
    config
        .global
        .set_root_path(&Path::new(cli.root_path.as_bytes()).expect("valid root path"));
    config.global.prefix = FileName::new(cli.prefix.as_bytes()).expect("valid prefix");

    let security = &mut config.global.node.security;
    security.shared_directory_mode =
        Some(FileMode::from_octal_str(&cli.shared_mode).expect("valid shared mode"));
    security.shared_group = cli
        .shared_group
        .as_ref()
        .map(|g| FileName::new(g.as_bytes()).expect("valid group"));
    security.iam.endpoint_mode =
        Some(FileMode::from_octal_str(&cli.endpoint_mode).expect("valid endpoint mode"));
    security.iam.endpoint_group = cli
        .endpoint_group
        .as_ref()
        .map(|g| FileName::new(g.as_bytes()).expect("valid group"));
    security.iam.policy_dir = Path::new(cli.policy_dir.as_bytes()).expect("valid policy dir");
    security.iam.audit_log_path = match &cli.audit_log {
        Some(p) => Path::new(p.as_bytes()).expect("valid audit log path"),
        None => Path::new(b"").expect("empty path"),
    };
    config
}

/// The payload a writer sends for `seq`: a readable prefix followed by a deterministic
/// pattern. The length grows with `seq` so that the PowerOfTwo strategy reallocates segments.
pub fn payload_for(uid: u32, seq: u64) -> Vec<u8> {
    let mut payload = format!("uid={uid} seq={seq};").into_bytes();
    let target = 24 + (seq as usize) * 300;
    let mut i = 0u8;
    while payload.len() < target {
        payload.push(b'a' + (i % 26));
        i = i.wrapping_add(1);
    }
    payload
}

/// A child process running as another user, with captured stdout and a writable stdin.
pub struct MuProcess {
    child: Child,
    stdin: Option<ChildStdin>,
    lines: Arc<Mutex<Vec<String>>>,
    label: String,
}

impl MuProcess {
    /// Spawns `exe` as `uid`/`gid` with the supplementary `groups`. The caller must be root.
    pub fn spawn(exe: &str, label: &str, uid: u32, gid: u32, groups: &[u32], args: &[String]) -> Self {
        let groups: Vec<libc::gid_t> = groups.iter().map(|g| *g as libc::gid_t).collect();
        let mut command = Command::new(exe);
        command
            .args(args)
            .env("IOX2_LOG_LEVEL", std::env::var("IOX2_LOG_LEVEL").unwrap_or("error".into()))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());
        unsafe {
            command.pre_exec(move || {
                if libc::setgroups(groups.len(), groups.as_ptr()) != 0
                    || libc::setgid(gid) != 0
                    || libc::setuid(uid) != 0
                {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let mut child = command
            .spawn()
            .unwrap_or_else(|e| panic!("failed to spawn {label} ({exe}) as uid {uid}: {e}"));

        let stdout = child.stdout.take().expect("piped stdout");
        let stdin = child.stdin.take();
        let lines: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let lines_clone = Arc::clone(&lines);
        let tag = label.to_string();
        thread::spawn(move || {
            for line in std::io::BufReader::new(stdout).lines().map_while(Result::ok) {
                println!("[{tag}] {line}");
                lines_clone.lock().unwrap().push(line);
            }
        });

        Self {
            child,
            stdin,
            lines,
            label: label.to_string(),
        }
    }

    /// Waits until a stdout line containing `pattern` appears.
    pub fn expect(&self, pattern: &str, timeout: Duration) -> String {
        let start = Instant::now();
        loop {
            if let Some(line) = self
                .lines
                .lock()
                .unwrap()
                .iter()
                .find(|l| l.contains(pattern))
            {
                return line.clone();
            }
            if start.elapsed() > timeout {
                panic!(
                    "[{}] timed out after {:?} waiting for {:?}; captured:\n{}",
                    self.label,
                    timeout,
                    pattern,
                    self.lines.lock().unwrap().join("\n")
                );
            }
            thread::sleep(Duration::from_millis(10));
        }
    }

    /// Number of captured lines containing `pattern`.
    pub fn count(&self, pattern: &str) -> usize {
        self.lines
            .lock()
            .unwrap()
            .iter()
            .filter(|l| l.contains(pattern))
            .count()
    }

    /// All captured lines.
    pub fn lines(&self) -> Vec<String> {
        self.lines.lock().unwrap().clone()
    }

    /// Asks the child to finish by writing `quit` to its stdin.
    pub fn quit(&mut self) {
        if let Some(stdin) = self.stdin.as_mut() {
            let _ = writeln!(stdin, "quit");
            let _ = stdin.flush();
        }
    }

    /// Sends SIGKILL.
    pub fn kill9(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }

    /// The child's pid.
    pub fn pid(&self) -> u32 {
        self.child.id()
    }

    /// Waits for the child to exit and returns its exit code.
    pub fn wait_exit(&mut self, timeout: Duration) -> i32 {
        let start = Instant::now();
        loop {
            if let Some(status) = self.child.try_wait().expect("try_wait") {
                return status.code().unwrap_or(-1);
            }
            if start.elapsed() > timeout {
                let _ = self.child.kill();
                panic!(
                    "[{}] did not exit within {:?}; captured:\n{}",
                    self.label,
                    timeout,
                    self.lines.lock().unwrap().join("\n")
                );
            }
            thread::sleep(Duration::from_millis(10));
        }
    }
}

impl Drop for MuProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
