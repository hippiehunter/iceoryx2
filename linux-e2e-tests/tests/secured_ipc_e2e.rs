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

//! Cross-process end-to-end tests for secured iceoryx2 IPC.
//!
//! Each test spawns two **real OS processes** — a SERVER (service creator, which
//! hosts the IAM server) and a CLIENT (service opener) — that perform secured
//! IPC across a genuine process boundary: real `fork`/`exec`, real `SO_PEERCRED`
//! credentials over the IAM Unix-domain socket, and real `SCM_RIGHTS` file
//! descriptor passing between distinct PIDs.
//!
//! Rendezvous is by *matching inputs only*: both processes build the identical
//! [`secured_config`](linux_e2e_tests::scenario::secured_config) and are given
//! the same `--service-name` and `--pattern`. The IAM endpoint (a Unix-domain
//! socket) is derived deterministically from the service hash + `endpoint_base`,
//! so identical inputs land both ends on the same socket. A fresh service name
//! and a fresh per-run `root_path` isolate every test.

use std::path::PathBuf;
use std::time::Duration;

use linux_e2e_tests::coordinator::{unique_name, TestProcess};

const SERVER_EXE: &str = env!("CARGO_BIN_EXE_iox2-e2e-server");
const CLIENT_EXE: &str = env!("CARGO_BIN_EXE_iox2-e2e-client");

/// Generous ceiling for a whole cross-process exchange (spawn + IAM handshake +
/// connect-retry + data flow). The happy path is far quicker.
const EXIT_TIMEOUT: Duration = Duration::from_secs(30);

/// Create a fresh iceoryx2 `root_path` directory for one test run and return it
/// with a trailing separator (matching the default `/tmp/iceoryx2/` shape). The
/// directory is created up-front so the IAM Unix socket can bind inside it;
/// iceoryx2 creates the `services`/`nodes` sub-directories itself.
fn make_root(tag: &str) -> String {
    let mut dir: PathBuf = std::env::temp_dir();
    dir.push(unique_name(tag));
    std::fs::create_dir_all(&dir).expect("create per-run root_path directory");
    let mut s = dir.to_string_lossy().into_owned();
    if !s.ends_with('/') {
        s.push('/');
    }
    s
}

/// Extract the numeric pid a child printed in its `... pid=<n>` marker line.
fn parse_pid(line: &str) -> u32 {
    line.rsplit("pid=")
        .next()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or_else(|| panic!("could not parse pid from line: {line:?}"))
}

/// Drive one pattern end-to-end across two processes.
///
/// `expect_client_received` is set for request-response, where the opener also
/// consumes a response.
fn run_case(pattern: &str, expect_client_received: bool) {
    let service_name = unique_name(pattern);
    let root = make_root(pattern);

    let server_args = [
        "--pattern",
        pattern,
        "--service-name",
        &service_name,
        "--root-path",
        &root,
    ];
    let client_args = server_args;

    // 1) Creator comes up and hosts the IAM server.
    let mut server = TestProcess::spawn(SERVER_EXE, "server", &server_args);
    let server_pid_line = server
        .expect("SERVER: pid=")
        .unwrap_or_else(|e| panic!("{e}"));
    server
        .expect("SERVER: listening")
        .unwrap_or_else(|e| panic!("{e}"));

    // 2) Opener connects to the same IAM endpoint and drives the data flow.
    let mut client = TestProcess::spawn(CLIENT_EXE, "client", &client_args);
    let client_pid_line = client
        .expect("CLIENT: pid=")
        .unwrap_or_else(|e| panic!("{e}"));

    // 3) Data actually crosses the boundary through IAM-brokered shared memory.
    client
        .expect("CLIENT: sent")
        .unwrap_or_else(|e| panic!("{e}"));
    server
        .expect("SERVER: received")
        .unwrap_or_else(|e| panic!("{e}"));
    if expect_client_received {
        client
            .expect("CLIENT: received")
            .unwrap_or_else(|e| panic!("{e}"));
    }
    server.expect("SERVER: done").unwrap_or_else(|e| panic!("{e}"));
    client.expect("CLIENT: done").unwrap_or_else(|e| panic!("{e}"));

    // 4) Both processes finished cleanly.
    let server_code = server.wait_exit(EXIT_TIMEOUT).unwrap_or_else(|e| panic!("{e}"));
    let client_code = client.wait_exit(EXIT_TIMEOUT).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(server_code, 0, "server should exit 0");
    assert_eq!(client_code, 0, "client should exit 0");

    // 5) Evidence: two genuinely distinct PIDs did real cross-process IPC.
    let server_pid = parse_pid(&server_pid_line);
    let client_pid = parse_pid(&client_pid_line);
    assert_ne!(
        server_pid, client_pid,
        "server and client must be distinct processes"
    );
    assert_eq!(server_pid, server.pid(), "server printed pid matches spawned pid");
    assert_eq!(client_pid, client.pid(), "client printed pid matches spawned pid");

    // Best-effort cleanup of the per-run root directory.
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn secured_publish_subscribe_cross_process() {
    run_case("pubsub", false);
}

#[test]
fn secured_dynamic_publish_subscribe_cross_process() {
    run_case("slice-pubsub", false);
}

#[test]
fn secured_request_response_cross_process() {
    run_case("reqres", true);
}

#[test]
fn secured_event_cross_process() {
    run_case("event", false);
}

// ============================================================================
// Cross-UID test (privileged)
// ============================================================================

/// Proves that a **different-user** opener is refused, which is what actually
/// demonstrates cross-*user* isolation — as opposed to the same-uid tests
/// above, which prove the *mechanism* (endpoint rendezvous, SO_PEERCRED,
/// SCM_RIGHTS fd passing, handle-based segment reconstruction) works end-to-end
/// across two processes but NOT that the name path is denied to another user.
///
/// This is `#[ignore]` because it needs elevated privilege that a normal
/// single-uid host / CI lane does not have:
///   * run as `root` (or with `CAP_SETUID`) so the harness can `setuid()` the
///     child to a *second* uid, **or**
///   * a provisioned second test uid launched via `sudo -u`.
///
/// Enable it in a dedicated privileged CI job:
///   `sudo -E cargo test -p linux-e2e-tests --test secured_ipc_e2e -- --ignored`
/// optionally choosing the second uid with `IOX2_E2E_CROSS_UID=<uid>`
/// (defaults to 65534 / `nobody`).
///
/// Honesty note: when the opener runs as a different uid the refusal may come
/// from the IAM [`DefaultPolicy`] (`authorize_attach` denies `uid != owner`)
/// *or* from filesystem permissions on the root-owned socket/shm — both enforce
/// isolation. Distinguishing the two, and proving an IAM-level (rather than
/// fs-level) denial, requires a second uid that shares filesystem access with
/// the creator; that is environment specific and out of scope for this default
/// harness. This test asserts only the observable, correct outcome: the
/// different-uid opener does NOT complete the data flow.
#[test]
#[ignore = "requires root/CAP_SETUID or a provisioned second uid; see doc comment"]
fn secured_cross_uid_opener_is_denied() {
    use std::io::{BufRead, BufReader};
    use std::os::unix::process::CommandExt;
    use std::process::{Command, Stdio};
    use std::sync::{Arc, Mutex};
    use std::time::Instant;

    let euid = unsafe { libc::geteuid() };
    if euid != 0 {
        eprintln!(
            "SKIP secured_cross_uid_opener_is_denied: needs root to setuid the child \
             (current euid={euid}). Run under `sudo -E ... -- --ignored`."
        );
        return;
    }

    let target_uid: u32 = std::env::var("IOX2_E2E_CROSS_UID")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(65534); // nobody

    let service_name = unique_name("crossuid");
    let root = make_root("crossuid");
    // Make the per-run root traversable so the second uid can at least attempt
    // to reach the socket (so any refusal is more likely policy-driven).
    let _ = std::fs::set_permissions(
        root.trim_end_matches('/'),
        std::os::unix::fs::PermissionsExt::from_mode(0o777),
    );

    let args = [
        "--pattern",
        "pubsub",
        "--service-name",
        service_name.as_str(),
        "--root-path",
        root.as_str(),
    ];

    // Creator runs as root and owns the service (owner_uid == 0).
    let mut server = TestProcess::spawn(SERVER_EXE, "server", &args);
    server
        .expect("SERVER: listening")
        .unwrap_or_else(|e| panic!("{e}"));

    // Opener runs as a DIFFERENT uid. Use a raw Command (the verbatim
    // coordinator has no uid hook) so we can call CommandExt::uid.
    let mut child = Command::new(CLIENT_EXE)
        .args(args)
        .uid(target_uid)
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn cross-uid client");

    let stdout = child.stdout.take().expect("piped stdout");
    let lines: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let lines_c = Arc::clone(&lines);
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            lines_c.lock().unwrap().push(line);
        }
    });

    // Wait (bounded) for the different-uid opener to exit. Its own bounded retry
    // loops guarantee termination.
    let deadline = Instant::now() + Duration::from_secs(40);
    let status = loop {
        if let Some(s) = child.try_wait().expect("try_wait cross-uid client") {
            break s;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            break child.wait().expect("wait killed cross-uid client");
        }
        std::thread::sleep(Duration::from_millis(50));
    };

    let captured = lines.lock().unwrap().clone();
    let completed = captured.iter().any(|l| l.contains("CLIENT: done"));

    assert!(
        !completed && status.code() != Some(0),
        "a different-uid opener must be DENIED and must not complete the data flow \
         (exit={:?}, captured={captured:?})",
        status.code()
    );

    let _ = std::fs::remove_dir_all(&root);
}
