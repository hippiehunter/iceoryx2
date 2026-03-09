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

//! End-to-end tests for Windows named pipe server/client lifecycle and data transfer.

#![cfg(target_os = "windows")]

use std::time::Duration;
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
fn basic_connect_and_echo() {
    let name = unique_name("pipe_echo");

    let server = spawn_server(&["pipe-echo", "--pipe-name", &name]);
    server.expect("SERVER: listening on").unwrap();

    let mut client = spawn_client(&["pipe-echo", "--pipe-name", &name, "--rounds", "1"]);

    server.expect("SERVER: client connected").unwrap();
    client.expect("CLIENT: connected to").unwrap();

    client.expect("CLIENT: sent 'ping_0'").unwrap();
    server.expect("SERVER: received 'ping_0'").unwrap();
    server.expect("SERVER: sent 'ping_0'").unwrap();
    client.expect("CLIENT: received 'ping_0'").unwrap();
    client.expect("CLIENT: done").unwrap();

    let code = client.wait_exit(DEFAULT_TIMEOUT).unwrap();
    assert_eq!(code, 0, "Client should exit cleanly");
}

#[test]
fn bidirectional_ping_pong_three_rounds() {
    let name = unique_name("pipe_pong");

    let server = spawn_server(&["pipe-echo", "--pipe-name", &name]);
    server.expect("SERVER: listening on").unwrap();

    let mut client = spawn_client(&["pipe-echo", "--pipe-name", &name, "--rounds", "3"]);

    server.expect("SERVER: client connected").unwrap();

    for i in 0..3 {
        let msg = format!("ping_{}", i);
        client.expect(&format!("CLIENT: sent '{}'", msg)).unwrap();
        server
            .expect(&format!("SERVER: received '{}'", msg))
            .unwrap();
        server.expect(&format!("SERVER: sent '{}'", msg)).unwrap();
        client
            .expect(&format!("CLIENT: received '{}'", msg))
            .unwrap();
    }

    client.expect("CLIENT: done").unwrap();
    let code = client.wait_exit(DEFAULT_TIMEOUT).unwrap();
    assert_eq!(code, 0);
}

#[test]
fn large_message_transfer() {
    let name = unique_name("pipe_large");
    let size = 32768; // 32KB — within the 64KB pipe buffer

    let server = spawn_server(&["pipe-echo", "--pipe-name", &name]);
    server.expect("SERVER: listening on").unwrap();

    let mut client = spawn_client(&[
        "pipe-echo",
        "--pipe-name",
        &name,
        "--large-bytes",
        &size.to_string(),
    ]);

    server.expect("SERVER: client connected").unwrap();
    client.expect("CLIENT: connected to").unwrap();

    let sent_line = client
        .expect_output("CLIENT: large sent", Duration::from_secs(15))
        .unwrap();
    assert!(
        sent_line.contains(&format!("{} bytes", size)),
        "Expected {} bytes sent, got: {}",
        size,
        sent_line
    );

    client
        .expect_output("CLIENT: large transfer verified", Duration::from_secs(15))
        .unwrap();
    client.expect("CLIENT: done").unwrap();

    let code = client.wait_exit(DEFAULT_TIMEOUT).unwrap();
    assert_eq!(code, 0);
}

#[test]
fn server_detects_client_disconnect() {
    let name = unique_name("pipe_disc");

    let server = spawn_server(&["pipe-echo", "--pipe-name", &name]);
    server.expect("SERVER: listening on").unwrap();

    let mut client = spawn_client(&["pipe-echo", "--pipe-name", &name, "--rounds", "1"]);

    server.expect("SERVER: client connected").unwrap();
    client.expect("CLIENT: done").unwrap();

    // Client exits, server should detect broken pipe
    let code = client.wait_exit(DEFAULT_TIMEOUT).unwrap();
    assert_eq!(code, 0);

    server.expect("SERVER: client disconnected").unwrap();
}

#[test]
fn server_broken_pipe_on_client_kill() {
    let name = unique_name("pipe_kill");

    let server = spawn_server(&["pipe-echo", "--pipe-name", &name]);
    server.expect("SERVER: listening on").unwrap();

    let mut client = spawn_client(&["pipe-echo", "--pipe-name", &name, "--rounds", "100"]);
    server.expect("SERVER: client connected").unwrap();
    client.expect("CLIENT: connected to").unwrap();

    // Give client time to start a round, then kill it
    client.expect("CLIENT: sent 'ping_0'").unwrap();
    client.terminate();

    // Server should detect the broken pipe
    server
        .expect_output("SERVER: client disconnected", Duration::from_secs(15))
        .unwrap();
}

#[test]
fn client_connect_before_server_fails() {
    let name = unique_name("pipe_noserver");

    // Client tries to connect to non-existent pipe
    let mut client = spawn_client(&["pipe-echo", "--pipe-name", &name, "--rounds", "1"]);

    let code = client.wait_exit(DEFAULT_TIMEOUT).unwrap();
    assert_ne!(code, 0, "Client should fail when server doesn't exist");
}

#[test]
fn timed_accept_timeout() {
    let name = unique_name("pipe_taccept");

    let mut server = spawn_server(&[
        "pipe-echo",
        "--pipe-name",
        &name,
        "--timed-accept-ms",
        "200",
    ]);

    server.expect("SERVER: listening on").unwrap();
    // No client connects - should timeout
    server
        .expect_output("SERVER: timed_accept timeout", Duration::from_secs(5))
        .unwrap();

    let code = server.wait_exit(DEFAULT_TIMEOUT).unwrap();
    assert_eq!(code, 0, "Server should exit cleanly after timeout");
}
