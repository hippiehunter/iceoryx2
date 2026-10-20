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

//! Many publisher processes on one large service (`max_publishers` 10000) exit at the same time
//! (e.g. the end of a batch run of DBL writers). Deregistering their nodes from the service must
//! not starve: every process must be gone within a time bound and the last one must remove the
//! service. Needs no special privileges.

use std::io::{BufRead, BufReader, Write};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use iceoryx2::prelude::*;

const NUMBER_OF_PROCESSES: usize = 128;
const TIME_LIMIT: Duration = Duration::from_secs(5);

struct Participant {
    child: Child,
    stdout: BufReader<std::process::ChildStdout>,
}

impl Participant {
    fn wait_for(&mut self, marker: &str) {
        let mut line = String::new();
        loop {
            line.clear();
            let n = self.stdout.read_line(&mut line).expect("read stdout");
            assert!(n > 0, "participant exited before printing {marker:?}");
            if line.trim() == marker {
                return;
            }
        }
    }
}

impl Drop for Participant {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[test]
fn many_publisher_processes_leaving_at_once_do_not_starve() {
    let exe = env!("CARGO_BIN_EXE_iox2-e2e-departure");
    let run = format!("dep{}_", std::process::id());
    let root = std::env::temp_dir().join(format!("iox2_{run}root"));
    std::fs::create_dir_all(&root).unwrap();
    let root = format!("{}/", root.display());
    let service = format!("MassDeparture{}", std::process::id());

    let mut participants: Vec<Participant> = (0..NUMBER_OF_PROCESSES)
        .map(|_| {
            let mut child = Command::new(exe)
                .args([
                    "--prefix",
                    &run,
                    "--root-path",
                    &root,
                    "--service",
                    &service,
                ])
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::inherit())
                .spawn()
                .expect("spawn participant");
            let stdout = BufReader::new(child.stdout.take().unwrap());
            Participant { child, stdout }
        })
        .collect();

    for p in participants.iter_mut() {
        p.wait_for("READY");
    }

    // release everybody at once
    let start = Instant::now();
    for p in participants.iter_mut() {
        let stdin = p.child.stdin.as_mut().unwrap();
        writeln!(stdin, "go").unwrap();
        stdin.flush().unwrap();
    }

    for p in participants.iter_mut() {
        loop {
            if let Some(status) = p.child.try_wait().unwrap() {
                assert!(status.success(), "participant failed: {status:?}");
                break;
            }
            assert!(
                start.elapsed() < TIME_LIMIT,
                "{NUMBER_OF_PROCESSES} departing processes did not finish within {TIME_LIMIT:?}"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
    }
    let elapsed = start.elapsed();
    println!("{NUMBER_OF_PROCESSES} processes departed in {elapsed:?}");

    // the last departing node must have locked the node set and removed the service
    let mut config = iceoryx2::config::Config::default();
    config.global.prefix = FileName::new(run.as_bytes()).unwrap();
    config
        .global
        .set_root_path(&Path::new(root.as_bytes()).unwrap());
    let exists = ipc::Service::does_exist(
        &ServiceName::new(&service).unwrap(),
        &config,
        MessagingPattern::PublishSubscribe,
    )
    .unwrap();
    assert!(
        !exists,
        "the last departing node did not remove the service"
    );

    let _ = std::fs::remove_dir_all(root.trim_end_matches('/'));
}
