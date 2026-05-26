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

//! End-to-end tests for cross-process Windows handle duplication.

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
fn cross_process_handle_duplication() {
    let name = unique_name("handle_dup");

    let server = spawn_server(&["handle-send", "--pipe-name", &name]);
    server.expect("SERVER: listening on").unwrap();

    let mut client = spawn_client(&["handle-receive", "--pipe-name", &name]);
    client.expect("CLIENT: connected").unwrap();

    // Server reads client PID, creates mapping, duplicates handle
    server.expect("SERVER: read client_pid=").unwrap();
    server.expect("SERVER: duplicated handle=").unwrap();
    server.expect("SERVER: handle sent").unwrap();

    // Client receives handle, maps it, reads magic bytes
    client.expect("CLIENT: received handle=").unwrap();
    client.expect("CLIENT: read magic=0xDEADBEEF").unwrap();
    client.expect("CLIENT: handle verified").unwrap();
    client.expect("CLIENT: done").unwrap();

    let code = client.wait_exit(DEFAULT_TIMEOUT).unwrap();
    assert_eq!(
        code, 0,
        "Client should exit successfully after handle verification"
    );

    let mut server = server;
    server.expect("SERVER: done").unwrap();
    let server_code = server.wait_exit(DEFAULT_TIMEOUT).unwrap();
    assert_eq!(server_code, 0, "Server should exit successfully");
}

#[test]
fn handle_survives_server_exit() {
    // This test verifies that once a handle is duplicated to the client's
    // process, the client can use it even after the server process exits.
    // DuplicateHandle creates an independent entry in the target process's
    // handle table.
    let name = unique_name("handle_surv");

    let server = spawn_server(&["handle-send", "--pipe-name", &name]);
    server.expect("SERVER: listening on").unwrap();

    let mut client = spawn_client(&["handle-receive", "--pipe-name", &name]);
    client.expect("CLIENT: connected").unwrap();

    server.expect("SERVER: handle sent").unwrap();

    // Client verifies the handle before server has fully cleaned up
    client.expect("CLIENT: handle verified").unwrap();
    client.expect("CLIENT: done").unwrap();

    let code = client.wait_exit(DEFAULT_TIMEOUT).unwrap();
    assert_eq!(code, 0);
}

#[test]
fn pid_exchange_is_correct() {
    // Verify the PID that the client sends matches what the server reads
    let name = unique_name("handle_pid");

    let server = spawn_server(&["handle-send", "--pipe-name", &name]);
    server.expect("SERVER: listening on").unwrap();

    let mut client = spawn_client(&["handle-receive", "--pipe-name", &name]);

    let client_pid_line = client.expect("CLIENT: my_pid=").unwrap();
    let client_pid: u32 = client_pid_line
        .split("my_pid=")
        .nth(1)
        .unwrap()
        .trim()
        .parse()
        .unwrap();

    let server_pid_line = server.expect("SERVER: read client_pid=").unwrap();
    let server_read_pid: u32 = server_pid_line
        .split("client_pid=")
        .nth(1)
        .unwrap()
        .trim()
        .parse()
        .unwrap();

    assert_eq!(
        client_pid, server_read_pid,
        "PID mismatch: client={}, server read={}",
        client_pid, server_read_pid
    );

    // Let both finish
    client.expect("CLIENT: done").unwrap();
    let code = client.wait_exit(DEFAULT_TIMEOUT).unwrap();
    assert_eq!(code, 0);
}
