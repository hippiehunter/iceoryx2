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

//! Cross-uid end-to-end tests for multi-user secured mode.
//!
//! A broker (uid A) creates `DeltaReplicator` (`[u8]` + user header, PowerOfTwo),
//! `DeltaReplicator/events` and `DeltaReplicator/space`; writers run as *other*
//! users (B, C, members of a writers group) and an intruder (uid D) has file
//! system access but no policy grant. Authorization comes from the IAM policy
//! (kernel-verified `SO_PEERCRED`/`SO_PEERGROUPS`), not from file permissions.
//!
//! The tests switch uids and therefore need root. They are `#[ignore]`d; run them
//! as root or - without real root - inside a user namespace:
//!
//! ```text
//! podman unshare cargo test -p linux-e2e-tests --test multi_user_e2e -- --ignored --test-threads=1
//! ```
//!
//! The uids/gid can be changed with `IOX2_MU_BROKER_UID` (2000),
//! `IOX2_MU_WRITER_UIDS` (2001,2002), `IOX2_MU_INTRUDER_UID` (2003) and
//! `IOX2_MU_WRITERS_GID` (3000). Under `podman unshare` these must be mapped in
//! `/etc/subuid` / `/etc/subgid`.

use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::Duration;

use linux_e2e_tests::coordinator::unique_name;
use linux_e2e_tests::multi_user::MuProcess;

const MU_EXE: &str = env!("CARGO_BIN_EXE_iox2-e2e-mu");
const STEP: Duration = Duration::from_secs(30);

fn env_u32(name: &str, default: u32) -> u32 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

struct Ids {
    broker: u32,
    writers: [u32; 2],
    intruder: u32,
    writers_gid: u32,
}

fn ids() -> Ids {
    let writers: Vec<u32> = std::env::var("IOX2_MU_WRITER_UIDS")
        .unwrap_or_else(|_| "2001,2002".into())
        .split(',')
        .filter_map(|v| v.trim().parse().ok())
        .collect();
    assert!(writers.len() >= 2, "IOX2_MU_WRITER_UIDS needs two uids");
    Ids {
        broker: env_u32("IOX2_MU_BROKER_UID", 2000),
        writers: [writers[0], writers[1]],
        intruder: env_u32("IOX2_MU_INTRUDER_UID", 2003),
        writers_gid: env_u32("IOX2_MU_WRITERS_GID", 3000),
    }
}

fn require_root() {
    let euid = unsafe { libc::geteuid() };
    assert_eq!(
        euid, 0,
        "multi-user e2e tests switch uids and must run as root, e.g.\n  \
         podman unshare cargo test -p linux-e2e-tests --test multi_user_e2e -- --ignored --test-threads=1"
    );
}

/// The per-test file system layout. The root path itself is NOT created here: the broker
/// creates it (and the node/service directories) with the configured shared mode.
struct Layout {
    base: PathBuf,
    /// copy of the child binary that every test uid can execute (the build directory is
    /// usually inside a private home directory)
    exe: String,
    root: String,
    policy_dir: String,
    audit_log: String,
    prefix: String,
}

impl Layout {
    fn new(tag: &str, broker_uid: u32) -> Self {
        // every test uid must be able to traverse the base directory, so do not use $TMPDIR
        // (which may be private to the invoking user)
        let tmp = std::env::var("IOX2_MU_TMP").unwrap_or_else(|_| "/tmp".into());
        let base = Path::new(&tmp).join(unique_name(tag));
        std::fs::create_dir_all(&base).unwrap();
        std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o755)).unwrap();
        // the broker creates the iceoryx2 root path inside the base directory
        std::os::unix::fs::chown(&base, Some(broker_uid), None).unwrap();

        let policy_dir = base.join("policies");
        std::fs::create_dir_all(&policy_dir).unwrap();
        std::fs::set_permissions(&policy_dir, std::fs::Permissions::from_mode(0o755)).unwrap();

        let audit_dir = base.join("audit");
        std::fs::create_dir_all(&audit_dir).unwrap();
        std::os::unix::fs::chown(&audit_dir, Some(broker_uid), None).unwrap();

        let exe = base.join("iox2-e2e-mu");
        std::fs::copy(MU_EXE, &exe).unwrap();
        std::fs::set_permissions(&exe, std::fs::Permissions::from_mode(0o755)).unwrap();

        let n = base.file_name().unwrap().to_string_lossy().len();
        Self {
            exe: exe.display().to_string(),
            root: format!("{}/root/", base.display()),
            policy_dir: policy_dir.display().to_string(),
            audit_log: audit_dir.join("audit.log").display().to_string(),
            prefix: format!("mu{}x{}_", std::process::id(), n),
            base,
        }
    }

    fn write_policy(&self, file: &str, contents: &str) {
        let path = Path::new(&self.policy_dir).join(file);
        std::fs::write(&path, contents).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    }

    /// The SIP policy: the broker subscribes / listens on `events` / notifies `space`; the
    /// writers group publishes / notifies `events` / listens on `space`.
    fn write_sip_policies(&self, broker: u32, writers_gid: u32) {
        self.write_policy(
            "DeltaReplicator.toml",
            &format!(
                r#"[service]
name = "DeltaReplicator"

[[allow]]
principal = {{ uid = {broker} }}
roles = ["subscriber"]

[[allow]]
principal = {{ gid = {writers_gid} }}
roles = ["publisher"]
"#
            ),
        );
        self.write_policy(
            "DeltaReplicator_events.toml",
            &format!(
                r#"[service]
name = "DeltaReplicator/events"

[[allow]]
principal = {{ uid = {broker} }}
roles = ["listener"]

[[allow]]
principal = {{ gid = {writers_gid} }}
roles = ["notifier"]
"#
            ),
        );
        self.write_policy(
            "DeltaReplicator_space.toml",
            &format!(
                r#"[service]
name = "DeltaReplicator/space"

[[allow]]
principal = {{ uid = {broker} }}
roles = ["notifier"]

[[allow]]
principal = {{ gid = {writers_gid} }}
roles = ["listener"]
"#
            ),
        );
    }

    fn args(&self, role: &str, mode: &Mode, extra: &[&str]) -> Vec<String> {
        let mut args: Vec<String> = [
            "--role",
            role,
            "--root-path",
            &self.root,
            "--prefix",
            &self.prefix,
            "--policy-dir",
            &self.policy_dir,
            "--shared-mode",
            mode.shared_mode,
            "--endpoint-mode",
            mode.endpoint_mode,
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        if let Some(group) = &mode.group {
            args.extend(["--shared-group".into(), group.clone()]);
            args.extend(["--endpoint-group".into(), group.clone()]);
        }
        if role == "broker" {
            args.extend(["--audit-log".into(), self.audit_log.clone()]);
        }
        args.extend(extra.iter().map(|s| s.to_string()));
        args
    }

    fn audit_entries(&self) -> Vec<serde_json::Value> {
        std::fs::read_to_string(&self.audit_log)
            .unwrap_or_default()
            .lines()
            .filter_map(|l| serde_json::from_str(l).ok())
            .collect()
    }
}

impl Drop for Layout {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.base);
        // anything a killed process left in /dev/shm
        if let Ok(entries) = std::fs::read_dir("/dev/shm") {
            for entry in entries.flatten() {
                if entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(&self.prefix)
                {
                    let _ = std::fs::remove_file(entry.path());
                }
            }
        }
    }
}

struct Mode {
    shared_mode: &'static str,
    endpoint_mode: &'static str,
    group: Option<String>,
}

fn sticky_mode() -> Mode {
    Mode {
        shared_mode: "1777",
        endpoint_mode: "0666",
        group: None,
    }
}

fn group_mode(gid: u32) -> Mode {
    Mode {
        shared_mode: "2770",
        endpoint_mode: "0660",
        group: Some(gid.to_string()),
    }
}

/// The POSIX shared memory objects of the run: `(name, mode)`.
fn shm_objects(prefix: &str) -> Vec<(String, u32)> {
    std::fs::read_dir("/dev/shm")
        .unwrap()
        .flatten()
        .filter_map(|e| {
            let name = e.file_name().to_string_lossy().to_string();
            if !name.starts_with(prefix) {
                return None;
            }
            let mode = e.metadata().ok()?.permissions().mode() & 0o7777;
            Some((name, mode))
        })
        .collect()
}

/// Requirement: metadata is shared, but no data segment or connection channel exists as a
/// named (and thus openable) object - those are anonymous memfds brokered by IAM.
fn assert_no_named_data_plane(prefix: &str) {
    let objects = shm_objects(prefix);
    assert!(
        !objects.is_empty(),
        "expected the dynamic configs in /dev/shm"
    );
    for (name, mode) in &objects {
        assert!(
            !name.ends_with(".data") && !name.ends_with(".connection"),
            "named data-plane object {name} (mode {mode:o}) exists in secured mode"
        );
        println!("shm object {name} mode {mode:o}");
    }
}

/// How the broker is deployed.
struct BrokerSetup {
    /// uid the broker runs as (SIP: root today, `sip-service` in the RPM)
    uid: u32,
    /// the iceoryx2 root path exists before anything starts (SIP: `/tmp/iceoryx2`,
    /// root:root 1777, recreated by tmpfiles.d)
    precreated_root: bool,
}

fn run_allow(mode: Mode, tag: &str) {
    let ids = ids();
    run_allow_with(
        mode,
        tag,
        BrokerSetup {
            uid: ids.broker,
            precreated_root: false,
        },
    );
}

fn run_allow_with(mode: Mode, tag: &str, setup: BrokerSetup) {
    require_root();
    let mut ids = ids();
    ids.broker = setup.uid;
    let layout = Layout::new(tag, ids.broker);
    layout.write_sip_policies(ids.broker, ids.writers_gid);
    if setup.precreated_root {
        std::fs::create_dir_all(&layout.root).unwrap();
        std::os::unix::fs::chown(&layout.root, Some(0), Some(0)).unwrap();
        std::fs::set_permissions(&layout.root, std::fs::Permissions::from_mode(0o1777)).unwrap();
    }

    let per_writer = 3u64;
    let total = (per_writer * 2).to_string();
    let count = per_writer.to_string();

    // In group mode the broker must be a member of the shared group to hand the
    // directories to it.
    let broker_groups: Vec<u32> = if mode.group.is_some() {
        vec![ids.writers_gid]
    } else {
        vec![]
    };
    let mut broker = MuProcess::spawn(
        &layout.exe,
        "broker",
        ids.broker,
        ids.broker,
        &broker_groups,
        &layout.args("broker", &mode, &["--count", &total]),
    );
    broker.expect("BROKER: ready", STEP);

    // requirement 1: shared directories with the configured mode (and group)
    let expected_mode = u32::from_str_radix(mode.shared_mode, 8).unwrap();
    for dir in ["", "nodes", "services"] {
        let path = format!("{}{}", layout.root, dir);
        let meta = std::fs::metadata(&path).unwrap();
        assert_eq!(meta.mode() & 0o7777, expected_mode, "mode of {path}");
        if dir.is_empty() && setup.precreated_root {
            // an existing root (installer / tmpfiles.d) is left untouched
            assert_eq!(meta.uid(), 0, "owner of {path}");
            continue;
        }
        assert_eq!(meta.uid(), ids.broker, "owner of {path}");
        if mode.group.is_some() {
            assert_eq!(meta.gid(), ids.writers_gid, "group of {path}");
        }
    }

    assert!(
        ids.writers.iter().all(|uid| *uid != ids.writers_gid),
        "the writers' primary group must differ from the writers group for this test"
    );
    let mut writers: Vec<MuProcess> = ids
        .writers
        .iter()
        .map(|&uid| {
            MuProcess::spawn(
                &layout.exe,
                &format!("writer{uid}"),
                uid,
                uid,                // primary group is the user's own ...
                &[ids.writers_gid], // ... the grant comes from the SUPPLEMENTARY writers group
                &layout.args("writer", &mode, &["--count", &count]),
            )
        })
        .collect();

    broker.expect("BROKER: received all", Duration::from_secs(60));
    for (writer, uid) in writers.iter().zip(ids.writers) {
        writer.expect(&format!("WRITER uid={uid}: done sending"), STEP);
        // writers cannot read anyone's samples
        writer.expect(&format!("WRITER uid={uid}: subscriber denied by IAM"), STEP);
        // event direction broker -> writer (`space`)
        assert!(
            writer.count(&format!("WRITER uid={uid}: space")) > 0,
            "writer {uid} never received a space notification"
        );
        for seq in 0..per_writer {
            broker.expect(&format!("BROKER: received uid={uid} seq={seq} "), STEP);
        }
    }

    // requirement 3: metadata shared, data plane anonymous
    assert_no_named_data_plane(&layout.prefix);
    let services = std::fs::read_dir(format!("{}services", layout.root)).unwrap();
    for entry in services.flatten() {
        let mode_bits = entry.metadata().unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode_bits & 0o022,
            0,
            "static config {:?} is writable by others",
            entry.path()
        );
        assert_ne!(
            mode_bits & 0o044,
            0,
            "static config {:?} not shared",
            entry.path()
        );
    }

    for writer in writers.iter_mut() {
        writer.quit();
        assert_eq!(writer.wait_exit(STEP), 0);
    }
    broker.quit();
    assert_eq!(broker.wait_exit(STEP), 0, "broker failed");

    // every grant was decided by the policy and is visible in the audit log
    let audit = layout.audit_entries();
    for uid in ids.writers {
        assert!(
            audit.iter().any(|e| e["uid"] == uid
                && e["kind"]
                    .as_str()
                    .unwrap_or("")
                    .starts_with("attach:Publisher")
                && e["decision"] == "allow"),
            "no allowed publisher attach of uid {uid} in the audit log: {audit:?}"
        );
        assert!(
            audit.iter().any(|e| e["uid"] == uid
                && e["kind"]
                    .as_str()
                    .unwrap_or("")
                    .starts_with("attach:Subscriber")
                && e["decision"] == "deny"),
            "no denied subscriber attach of uid {uid} in the audit log"
        );
    }
}

/// (i) cross-uid ALLOW: broker uid A, writers uid B and C (members of the writers group),
/// `[u8]` pub/sub with a user header and both event directions; sticky 1777 directories.
#[test]
#[ignore = "needs root: podman unshare cargo test -p linux-e2e-tests --test multi_user_e2e -- --ignored"]
fn multi_user_cross_uid_allow_sticky_world_mode() {
    run_allow(sticky_mode(), "mu_allow_sticky");
}

/// (i) cross-uid ALLOW, SIP deployment shape: the broker runs as root and the iceoryx2 root
/// path already exists as root:root 1777 (tmpfiles.d); writers are granted through a
/// supplementary group only.
#[test]
#[ignore = "needs root: podman unshare cargo test -p linux-e2e-tests --test multi_user_e2e -- --ignored"]
fn multi_user_cross_uid_allow_root_broker_preexisting_root() {
    run_allow_with(
        sticky_mode(),
        "mu_allow_rootbroker",
        BrokerSetup {
            uid: 0,
            precreated_root: true,
        },
    );
}

/// (i) cross-uid ALLOW with group-shared set-group-id directories (2770 + chgrp) and a
/// group-only (0660) IAM endpoint.
#[test]
#[ignore = "needs root: podman unshare cargo test -p linux-e2e-tests --test multi_user_e2e -- --ignored"]
fn multi_user_cross_uid_allow_setgid_group_mode() {
    let gid = ids().writers_gid;
    run_allow(group_mode(gid), "mu_allow_group");
}

/// (ii) IAM-level DENY: uid D can reach every file (sticky 1777 directories, 0666 endpoint)
/// and opens all services, but holds no policy grant. Every port creation is refused by the IAM
/// server (`IamAuthorizationDenied`), and the audit log records the denials for uid D.
#[test]
#[ignore = "needs root: podman unshare cargo test -p linux-e2e-tests --test multi_user_e2e -- --ignored"]
fn multi_user_unauthorized_uid_is_denied_by_iam() {
    require_root();
    let ids = ids();
    let mode = sticky_mode();
    let layout = Layout::new("mu_deny", ids.broker);
    layout.write_sip_policies(ids.broker, ids.writers_gid);

    let mut broker = MuProcess::spawn(
        &layout.exe,
        "broker",
        ids.broker,
        ids.broker,
        &[],
        &layout.args("broker", &mode, &["--count", "1"]),
    );
    broker.expect("BROKER: ready", STEP);

    let mut intruder = MuProcess::spawn(
        &layout.exe,
        "intruder",
        ids.intruder,
        ids.intruder,
        &[],
        &layout.args("intruder", &mode, &[]),
    );
    // file-system access works: the denial below is not an EACCES
    intruder.expect("INTRUDER", STEP);
    assert_eq!(
        intruder.wait_exit(STEP),
        0,
        "intruder was not denied everything"
    );
    intruder.expect("opened all services", STEP);
    for port in ["publisher", "subscriber", "notifier", "listener"] {
        intruder.expect(&format!("{port} denied by IAM"), STEP);
    }

    // a legitimate writer still works afterwards
    let mut writer = MuProcess::spawn(
        &layout.exe,
        "writer",
        ids.writers[0],
        ids.writers[0],
        &[ids.writers_gid],
        &layout.args("writer", &mode, &["--count", "1"]),
    );
    broker.expect("BROKER: received all", STEP);
    writer.quit();
    assert_eq!(writer.wait_exit(STEP), 0);
    broker.quit();
    assert_eq!(broker.wait_exit(STEP), 0);

    let audit = layout.audit_entries();
    for kind in [
        "attach:Publisher",
        "attach:Subscriber",
        "attach:Notifier",
        "attach:Listener",
    ] {
        assert!(
            audit.iter().any(|e| e["uid"] == ids.intruder
                && e["kind"].as_str().unwrap_or("").starts_with(kind)
                && e["decision"] == "deny"
                && e["reason"] == "Unauthorized"),
            "no IAM denial `{kind}` for uid {} in the audit log: {audit:?}",
            ids.intruder
        );
    }
    assert!(
        !audit.iter().any(|e| e["uid"] == ids.intruder
            && e["decision"] == "allow"
            && e["kind"] != "connect"),
        "uid {} was granted something: {audit:?}",
        ids.intruder
    );
}

/// (iii) dead writer: writer B (uid B) is SIGKILLed while the broker keeps running. The broker
/// does not fail, the IAM server of the broker releases B's ports (the data service allows only
/// ONE publisher, so writer C can only attach once B's slot is free) and writer C (another
/// uid) attaches and delivers. Nobody needs write access to B's files.
#[test]
#[ignore = "needs root: podman unshare cargo test -p linux-e2e-tests --test multi_user_e2e -- --ignored"]
fn multi_user_killed_writer_is_released_and_replaced() {
    require_root();
    let ids = ids();
    let mode = sticky_mode();
    let layout = Layout::new("mu_kill", ids.broker);
    layout.write_sip_policies(ids.broker, ids.writers_gid);

    let mut broker = MuProcess::spawn(
        &layout.exe,
        "broker",
        ids.broker,
        ids.broker,
        &[],
        &layout.args("broker", &mode, &["--count", "6", "--max-publishers", "1"]),
    );
    broker.expect("BROKER: ready", STEP);

    let [b, c] = ids.writers;
    let mut writer_b = MuProcess::spawn(
        &layout.exe,
        "writerB",
        b,
        b,
        &[ids.writers_gid],
        &layout.args("writer", &mode, &["--count", "3", "--hang"]),
    );
    writer_b.expect(&format!("WRITER uid={b}: hanging"), STEP);
    for seq in 0..3 {
        broker.expect(&format!("BROKER: received uid={b} seq={seq} "), STEP);
    }

    writer_b.kill9();

    let mut writer_c = MuProcess::spawn(
        &layout.exe,
        "writerC",
        c,
        c,
        &[ids.writers_gid],
        &layout.args(
            "writer",
            &mode,
            &["--count", "3", "--publisher-retry-secs", "30"],
        ),
    );
    writer_c.expect(&format!("WRITER uid={c}: publisher attached"), STEP);
    broker.expect("BROKER: received all 6", STEP);
    for seq in 0..3 {
        broker.expect(&format!("BROKER: received uid={c} seq={seq} "), STEP);
    }
    writer_c.expect(&format!("WRITER uid={c}: space"), STEP);

    // B's private files are left for its owner; nobody else could (or had to) remove them
    let b_files = std::fs::read_dir(format!("{}nodes", layout.root))
        .unwrap()
        .flatten()
        .filter(|e| e.metadata().map(|m| m.uid() == b).unwrap_or(false))
        .count();
    println!("files of the killed writer left in the node directory: {b_files}");

    writer_c.quit();
    assert_eq!(writer_c.wait_exit(STEP), 0);
    broker.quit();
    assert_eq!(
        broker.wait_exit(STEP),
        0,
        "broker failed after the writer was killed"
    );
}
