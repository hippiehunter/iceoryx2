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

//! End-to-end tests for the CAL control channel over Windows named pipes.

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
fn cal_connect_and_credentials() {
    let name = unique_name("cal_creds");

    let server = spawn_server(&["cal-listener", "--channel-name", &name]);
    server.expect("SERVER: cal listening on").unwrap();

    let mut client = spawn_client(&["cal-connector", "--channel-name", &name]);

    let client_pid_line = client.expect("CLIENT: my_pid=").unwrap();
    let client_pid: u32 = client_pid_line
        .split("my_pid=")
        .nth(1)
        .unwrap()
        .trim()
        .parse()
        .unwrap();

    server.expect("SERVER: cal client connected").unwrap();
    client.expect("CLIENT: cal connected").unwrap();

    let server_pid_line = server.expect("SERVER: cal client_pid=").unwrap();
    let server_reported_pid: u32 = server_pid_line
        .split("client_pid=")
        .nth(1)
        .unwrap()
        .trim()
        .parse()
        .unwrap();

    assert_eq!(
        client_pid, server_reported_pid,
        "CAL credential PID mismatch: client={}, server={}",
        client_pid, server_reported_pid
    );

    client.expect("CLIENT: cal done").unwrap();
    let code = client.wait_exit(DEFAULT_TIMEOUT).unwrap();
    assert_eq!(code, 0);
}

#[test]
fn cal_data_transfer() {
    let name = unique_name("cal_data");

    let server = spawn_server(&["cal-listener", "--channel-name", &name]);
    server.expect("SERVER: cal listening on").unwrap();

    let mut client = spawn_client(&["cal-connector", "--channel-name", &name]);
    client.expect("CLIENT: cal connected").unwrap();

    server.expect("SERVER: cal sent data").unwrap();
    client
        .expect("CLIENT: cal received 'hello from server'")
        .unwrap();

    client.expect("CLIENT: cal done").unwrap();
    let code = client.wait_exit(DEFAULT_TIMEOUT).unwrap();
    assert_eq!(code, 0);
}

#[test]
fn cal_client_connect_nonexistent_fails() {
    let name = unique_name("cal_noserver");

    // Client tries to connect to non-existent listener
    // The client retries up to 50 times with 100ms delay, so it should fail after ~5s
    let mut client = spawn_client(&["cal-connector", "--channel-name", &name]);

    let code = client
        .wait_exit(std::time::Duration::from_secs(15))
        .unwrap();
    assert_ne!(code, 0, "Client should fail when no listener exists");
}
