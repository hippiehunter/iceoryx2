// Copyright (c) 2024 Contributors to the Eclipse Foundation
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

//! End-to-end tests for Windows peer credential extraction via named pipes.

#![cfg(target_os = "windows")]

use windows_e2e_tests::coordinator::{unique_name, TestProcess, DEFAULT_TIMEOUT};

const SERVER: &str = env!("CARGO_BIN_EXE_win-e2e-server");
const CLIENT: &str = env!("CARGO_BIN_EXE_win-e2e-client");

fn spawn_server(args: &[&str]) -> TestProcess {
    TestProcess::spawn(SERVER, "server", args)
}
fn spawn_client(args: &[&str]) -> TestProcess {
    TestProcess::spawn(CLIENT, "client", args)
}

#[test]
fn peer_pid_matches_client_pid() {
    let name = unique_name("creds_pid");

    let server = spawn_server(&["pipe-creds", "--pipe-name", &name]);
    server.expect("SERVER: listening on").unwrap();

    let mut client = spawn_client(&["pipe-creds", "--pipe-name", &name]);

    // Client prints its own PID before connecting
    let client_line = client.expect("CLIENT: my_pid=").unwrap();
    let client_pid: u32 = client_line
        .split("my_pid=")
        .nth(1)
        .unwrap()
        .trim()
        .parse()
        .unwrap();

    server.expect("SERVER: client connected").unwrap();

    // Server extracts client PID via GetNamedPipeClientProcessId
    let server_line = server.expect("SERVER: client_pid=").unwrap();
    let server_reported_pid: u32 = server_line
        .split("client_pid=")
        .nth(1)
        .unwrap()
        .trim()
        .parse()
        .unwrap();

    assert_eq!(
        client_pid, server_reported_pid,
        "Server-reported PID ({}) must match client's actual PID ({})",
        server_reported_pid, client_pid
    );

    // Verify both sides complete
    server.expect("SERVER: done").unwrap();
    client.expect("CLIENT: done").unwrap();

    let code = client.wait_exit(DEFAULT_TIMEOUT).unwrap();
    assert_eq!(code, 0);
}

#[test]
fn user_sid_is_valid() {
    let name = unique_name("creds_sid");

    let server = spawn_server(&["pipe-creds", "--pipe-name", &name]);
    server.expect("SERVER: listening on").unwrap();

    let mut client = spawn_client(&["pipe-creds", "--pipe-name", &name]);
    client.expect("CLIENT: connected").unwrap();

    let sid_line = server.expect("SERVER: user_sid=").unwrap();
    let sid = sid_line.split("user_sid=").nth(1).unwrap().trim();

    // SID extraction should succeed — the user SID must be a valid Windows SID
    assert!(
        sid.starts_with("S-1-"),
        "Expected valid SID starting with 'S-1-', got: '{}'. \
         Token impersonation via ImpersonateNamedPipeClient may be failing.",
        sid
    );

    server.expect("SERVER: done").unwrap();
    let code = client.wait_exit(DEFAULT_TIMEOUT).unwrap();
    assert_eq!(code, 0);
}

#[test]
fn group_sids_present() {
    let name = unique_name("creds_grp");

    let server = spawn_server(&["pipe-creds", "--pipe-name", &name]);
    server.expect("SERVER: listening on").unwrap();

    let mut client = spawn_client(&["pipe-creds", "--pipe-name", &name]);
    client.expect("CLIENT: connected").unwrap();

    let group_line = server.expect("SERVER: group_count=").unwrap();
    let count: usize = group_line
        .split("group_count=")
        .nth(1)
        .unwrap()
        .trim()
        .parse()
        .unwrap();

    // Every Windows user belongs to at least one group
    assert!(
        count > 0,
        "Expected at least one group SID, got 0. \
         Token impersonation via ImpersonateNamedPipeClient may be failing."
    );

    server.expect("SERVER: done").unwrap();
    let code = client.wait_exit(DEFAULT_TIMEOUT).unwrap();
    assert_eq!(code, 0);
}
