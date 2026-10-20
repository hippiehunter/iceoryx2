# Multi-user secured mode

Secured mode (`[global.node.security] mode = "secured"`) normally assumes that every
participant of a service runs as the same Unix user: the IAM control socket, the service
metadata and the node directories are owner-only. Multi-user secured mode lets processes of
*different* Unix users take part in one service that a third user created, without giving up
the secured-mode guarantees:

* **Who may do what** is decided by the per-service IAM policy, using the peer credentials the
  kernel reports for the IAM control socket (`SO_PEERCRED` for uid/gid/pid, `SO_PEERGROUPS` for
  the supplementary groups). File modes only decide who can *reach* the IAM server.
* **Payload data** never becomes a named, file-system visible object. Data segments,
  management segments and connection channels stay anonymous (`memfd`) and are handed out by
  the IAM server over `SCM_RIGHTS` to authorized peers only.
* Only the **metadata** that other users need to open a service and to observe nodes (static
  service config, service dynamic config / port registry, node details, node monitor files,
  service and port tags, event sockets and their counter shared memory) is shared with the
  group and/or others, as far as the configured mode allows.

Single-user behavior is unchanged unless `shared-directory-mode` is set.

## Configuration keys

All keys live in the iceoryx2 config file (every section has defaults, so a file may contain
only the keys it changes). **Every participant - creator and openers - must use the same
`root-path`, `prefix` and security settings.**

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `[global] root-path` | path | `/tmp/iceoryx2/` | Root of all iceoryx2 files. |
| `[global.node.security] mode` | `"public"` / `"secured"` | `"public"` | Multi-user mode needs `"secured"`. |
| `[global.node.security] shared-directory-mode` | octal string (`"1777"`, `"2770"`) or integer | unset | Enables multi-user mode (only with `mode = "secured"`). Mode used to create the root, `nodes/` and `services/` directories **if they do not exist** (existing directories are never touched). Must grant the owner `rwx`. Its group/others bits are mirrored onto the shared metadata (see below). |
| `[global.node.security] shared-group` | group name or numeric gid | unset | Group the created shared directories and the shared POSIX shared memory (dynamic config, event counters) are `chown`ed to. Required when the mode grants group access and the files must belong to a specific group. Node creation fails if the group does not exist; the creating process must be root or a member of the group. |
| `[global.node.security.iam] endpoint-mode` | octal string or integer | unset (owner only, `0600`-like) | Mode of the per-service IAM control socket. Connecting needs write access, so `"0660"` lets the endpoint group in, `"0666"` everybody. Ignored unless secured. |
| `[global.node.security.iam] endpoint-group` | group name or numeric gid | unset | Group the IAM socket is `chown`ed to after creation (a failure is logged as a warning). |
| `[global.node.security.iam] policy-dir` | path | `iam/policies` | Directory of the per-service policy files. **Use an absolute path**: a relative path is resolved against the *current working directory* of the creating process. Only the creator reads it. |
| `[global.node.security.iam] audit-log-path` | path | `iam/audit.log` | JSON-lines audit log of IAM decisions, written by the creator. Relative paths are resolved against `root-path`. Empty disables it; a missing parent directory disables it with a debug message. Flushed after every event. |

Semantics of the mirrored permissions (`SharedAccess` in `iceoryx2-cal`):

* Files: the group/others bits copy the *owner* bits of the resource as far as the mode's
  group/others bits allow. With `"1777"` a `0600` dynamic config becomes `0666`, a `0400` static
  config becomes `0444`; with `"2770"` they become `0660` / `0440`.
* Directories created for metadata only receive the `r-x` group/others bits.
* Node monitor (file lock) files only gain *read* access for group/others; the monitor query
  falls back to a read-only open, which is sufficient for `F_GETLK`.
* Not mirrored, ever: data segments, resizable segments, connection channels, blackboard
  segments (all anonymous and IAM-brokered in secured mode).

`dev_permissions` (the development "world-writable everything" feature) remains mutually
exclusive with secured mode; multi-user secured mode does not relax that check.

## Required iceoryx2.toml for a multi-user deployment (SIP)

Variant A - world-sticky root, matching the existing `/tmp/iceoryx2` created by
`tmpfiles.d` as `root:root 1777`:

```toml
[global]
root-path = "/tmp/iceoryx2/"
prefix = "iox2_"

[global.node.security]
mode = "secured"
shared-directory-mode = "1777"

[global.node.security.iam]
endpoint-mode = "0666"
policy-dir = "/etc/iceoryx2/policies"
audit-log-path = "/var/log/sip/iceoryx2-iam-audit.log"
```

Variant B - group-shared root (recommended when all participants are in `sipwriters` or are
the broker): nothing outside the group can even open the metadata.

```toml
[global]
root-path = "/tmp/iceoryx2/"
prefix = "iox2_"

[global.node.security]
mode = "secured"
shared-directory-mode = "2770"
shared-group = "sipwriters"

[global.node.security.iam]
endpoint-mode = "0660"
endpoint-group = "sipwriters"
policy-dir = "/etc/iceoryx2/policies"
audit-log-path = "/var/log/sip/iceoryx2-iam-audit.log"
```

In variant B the broker user (`sip-service`) must be a member of `sipwriters` (or root), since
it has to `chown` its shared memory and socket to that group and traverse the group-only
directories.

Even in variant A an `endpoint-mode = "0666"` socket does not grant anything: an unknown uid
can connect, but every attach/handle request is evaluated against the policy, denied and
audited.

## Policy files for the SIP services

Policy files are named after the service with every character that is not alphanumeric, `-`
or `_` replaced by `_`, and are loaded once when the service is created. **A policy file
replaces the default same-uid policy completely, so the creator needs explicit roles as well.**

Roles: `publisher`, `subscriber`, `server`, `client`, `notifier`, `listener`.
Principals: `{ uid = N }`, `{ gid = N }` (primary **or supplementary** group),
`{ group = "name" }` / `{ user = "name" }` (resolved through NSS when evaluated),
`{ uid_range = [min, max] }`, `{ min = .., max = .. }`, `"any"`. `[[deny]]` rules are
evaluated before `[[allow]]` rules.

Writers added with `usermod -aG sipwriters <user>` are matched through their *supplementary*
groups (kernel-reported via `SO_PEERGROUPS`), so their primary group does not matter.

`/etc/iceoryx2/policies/DeltaReplicator.toml`:

```toml
[service]
name = "DeltaReplicator"

[[allow]]
principal = { user = "sip-service" }   # RPM deployment; use { uid = 0 } when the broker runs as root
roles = ["subscriber"]

[[allow]]
principal = { group = "sipwriters" }   # or { gid = <sipwriters gid> }
roles = ["publisher"]

# optional; defaults: 16 publishers, 256 subscribers, 64 segments, 64MB per segment
# (counted per IAM session, i.e. per participating process)
[limits]
max_publishers = 16
max_segments = 64
max_segment_size = "64MB"
```

`/etc/iceoryx2/policies/DeltaReplicator_events.toml` (writers notify, broker listens):

```toml
[service]
name = "DeltaReplicator/events"

[[allow]]
principal = { user = "sip-service" }
roles = ["listener"]

[[allow]]
principal = { group = "sipwriters" }
roles = ["notifier"]
```

`/etc/iceoryx2/policies/DeltaReplicator_space.toml` (broker notifies, writers listen):

```toml
[service]
name = "DeltaReplicator/space"

[[allow]]
principal = { user = "sip-service" }
roles = ["notifier"]

[[allow]]
principal = { group = "sipwriters" }
roles = ["listener"]
```

If the broker should also be able to run as root (test harness), add a second allow rule
with `{ uid = 0 }` and the same roles.

## Directory ownership expectations for an installer

| Path | Owner / mode | Notes |
| --- | --- | --- |
| `/tmp/iceoryx2/` (root path) | `root:root 1777` (variant A) or `root:sipwriters 2770` (variant B), recreated by `tmpfiles.d` | If it exists, iceoryx2 leaves it alone. If missing, the first node creates it with `shared-directory-mode`/`shared-group`. |
| `/tmp/iceoryx2/nodes/`, `/tmp/iceoryx2/services/` | Created on demand by the first node with the configured mode/group | May be pre-created by `tmpfiles.d` with the same mode as the root. With `2770` they must belong to `sipwriters`. |
| `/etc/iceoryx2/policies/` | `root:root 0755`, files `root:root 0644` | Only the broker reads it. Must not be writable by writers. |
| Audit log directory | writable by the broker user | Missing directory silently disables auditing. |
| Broker user | `sip-service`, member of `sipwriters` in variant B | Creates all three services before writers start; writers retry opening until the services exist. |
| Writer users | members of `sipwriters` (supplementary membership is enough) | Need execute access on the root path and its subdirectories. |

Verified on a kernel with `fs.protected_regular = 2`: no participant opens another user's
existing file in the sticky directories with `O_CREAT`, so the sticky-directory protections do
not get in the way.

## What the IAM server enforces (behavioral changes in secured mode)

* Handle requests for data segments, management segments and connection channels require a
  consumer attach (`subscriber`/`server`/`client`) in the same session; they are audited
  (`access_handle:<port>`).
* A producer port id is bound to the session that first registered handles for it
  (`register_handle:<port>`); other sessions cannot register under or detach it.
* Port drop detaches the IAM port (refunding session limits), so long-running processes that
  re-create ports do not exhaust their limits.
* Notifier and listener creation now requires the `notifier` / `listener` role
  (new `NotifierCreateError::IamAuthorizationDenied` / `IamConnectionFailed`,
  `ListenerCreateError::IamAuthorizationDenied` / `IamConnectionFailed`; C FFI enums updated).
* When a peer's control socket hits EOF its producer handles are retained for 2 s, then the
  departure handler checks the peer's node: if the node is dead and its node details record the
  same pid as the peer credentials, the node's ports are removed from the service's dynamic
  config and the handles are reaped; if the node is still alive the check is retried until a
  10 s grace period expires, after which the handles are reaped anyway. Another node of another
  uid can then create a publisher in the freed slot.

## Many nodes leaving at once (end of a batch run)

Two effects made mass departure slow; only the first one is a defect:

1. **Fixed - node-set lock starvation.** Deregistering a node from a service releases its index
   in the service's node set with `ReleaseMode::LockIfLastIndex`. `RobustUniqueIndexSet::lock()`
   used to take a full-capacity snapshot that *incremented* the shared generation counter and
   retried whenever any other thread did the same, so concurrent releasers invalidated each
   other's snapshots (a livelock that grows with capacity and number of releasers: 20 nodes on a
   `max_publishers` 10000 service took 10 s, 120 bare releasers 56 s). `lock()` now stops at the
   first borrowed index (the owner of that index will lock later), validates without modifying
   the counter, and releases use an `AcqRel` counter increment so that the last releaser is
   guaranteed to see every cleared cell. `borrowed_indices()` validates its snapshot the same
   non-perturbing way. After the fix: 20 nodes 33 ms, 100 nodes 0.65 s, 128 processes 1.2 s,
   1000 nodes 0.28 s (debug build, dead-node scans disabled, see 2).
2. **By design - dead-node scans are O(nodes) per node.** With the defaults
   `[global.node] cleanup-dead-nodes-on-creation = true` and
   `cleanup-dead-nodes-on-destruction = true`, every node creation and destruction lists *all*
   nodes and queries each node monitor (several file opens per node). N nodes leaving at once
   therefore cost O(N^2) file operations: 1000 nodes needed 86 s even with fix 1. For SIP,
   disable both in the configuration the **writers** use and let the long-lived broker keep
   them enabled (and call `Node::try_cleanup_dead_nodes()` periodically if desired):

   ```toml
   [global.node]
   cleanup-dead-nodes-on-creation = false
   cleanup-dead-nodes-on-destruction = false
   ```

   `[global.service] cleanup-dead-nodes-on-open` only inspects the nodes of the opened service
   and can stay enabled; note that in multi-user mode a writer cannot remove another user's
   files anyway, so it gains little there either. The IAM departure handling of secured services
   (see above) does not depend on these settings.

## Tests

The cross-user tests need root (or a user namespace with mapped uids 2000-2003 and gid 3000):

```sh
podman unshare cargo test -p linux-e2e-tests --test multi_user_e2e -- --ignored
podman unshare cargo test -p linux-e2e-tests --test secured_ipc_e2e -- --ignored
```

Mass departure (no privileges needed):

```sh
cargo test -p iceoryx2-bb-lock-free mass_release           # 120 releasers, capacity 10000, < 5 s
cargo test -p iceoryx2 --test mass_node_departure_tests     # 20 / 100 threads with nodes, < 5 s
cargo test -p iceoryx2 --test mass_node_departure_tests -- --ignored   # 1000 nodes, scans off
cargo test -p linux-e2e-tests --test mass_departure_e2e     # 128 processes, < 5 s
```

`multi_user_e2e` covers: cross-uid allow with `1777` and with `2770`+group (broker A, writers
B and C publishing a `[u8]` + header slice service, notifying `events`, listening on `space`;
writer primary groups differ from the writers group, which is supplementary only), a root
broker with a pre-existing `root:root 1777` root path, an IAM-level deny of a uid with file
system access but no grant (asserted via the audit log), and a SIGKILLed writer whose slot is
released and taken over by a writer of another uid. Uids/gids can be overridden with
`IOX2_MU_BROKER_UID`, `IOX2_MU_WRITER_UIDS`, `IOX2_MU_INTRUDER_UID`, `IOX2_MU_WRITERS_GID`.

## Remaining limitations

* **Kernel-side group set:** supplementary groups come from `SO_PEERGROUPS` (Linux >= 4.13).
  There is no `/proc/<pid>/status` fallback; if `SO_PEERGROUPS` fails the supplementary set is
  empty, i.e. group rules only match the primary gid (fail closed). Group membership is the one
  captured at `connect()` time; a user added to `sipwriters` must start a new login session.
* **Graceful drop before delivery:** a publisher that sends and is dropped before the
  subscriber connected loses those samples (upstream iceoryx2 semantics, independent of
  multi-user mode). Writers should keep their publisher alive.
* **Foreign stale files:** files of a dead node belonging to another user remain until that
  user (or root) cleans them up; in sticky directories other users cannot remove them.
  Cleanup attempts by other nodes log warnings and continue.
* **Shared metadata is writable:** the dynamic config shared memory and the event
  sockets/counters are group (`2770`) or world (`1777`) writable, because openers must register
  ports and notify. A malicious member of that set can corrupt the port registry or spam events
  (denial of service), but cannot read or inject payload data. Prefer variant B to limit this
  to `sipwriters`.
* **Departure cleanup requires the same PID namespace:** if the peer's pid from
  `SO_PEERCRED` does not match the pid recorded in its node details (e.g. different PID
  namespaces), the dynamic-config cleanup is skipped (logged) and only the IAM handles are
  reaped after the 2 s retention; the dead node's port entries then stay until a regular
  dead-node cleanup by a user that may remove them. Retention (2 s) and grace (10 s) are
  compile-time defaults (`IamServerBuilder::peer_departure_timing`).
* **No dead-notifier signal:** removing a dead node's ports from IAM cleanup does not emit the
  "notifier dead" event to listeners.
* **Broker crash:** the IAM socket and the creator's files of a crashed broker cannot be removed
  by the writers (other users); the restarted broker (same user) has to perform the usual
  dead-node cleanup before it re-creates the services. A stale IAM socket file of a crashed
  creator is not removed automatically (not covered by a test).
* **pidfd / PR_SET_DUMPABLE:** departure detection uses EOF on the control socket plus the
  node monitor (file lock) and pid binding, not pidfds. `PR_SET_DUMPABLE` is not set by
  iceoryx2; set it in the application if `/proc/<pid>/mem` access by same-uid processes is a
  concern.
* **C++ bindings** do not yet expose the new IAM error variants of notifier/listener creation
  (nor the existing publisher IAM errors).
* Limits (`max_*`) are enforced per IAM session (per participating process), not per service.
