# RFC: ACL + IAM Security for iceoryx2

## Status

Draft. Design in progress; no implementation yet. This document tracks ongoing
decisions and organizes implementation into sub-projects.

## Summary

This RFC defines a security model for iceoryx2 that combines OS-level ACLs
(user/group/SID) with a per-service Identity and Access Management (IAM)
control plane and handle-passing for data-plane resources. OS ACLs alone cannot
isolate processes that share the same user/SID, so secured services must use
an IAM-mediated attach flow that authenticates clients and passes OS handles
(Linux file descriptors, Windows HANDLEs). A minimal OS control channel is
required for authentication and handle passing; shared memory remains the
data plane for bulk data transfer.

## Decisions So Far

- Same-UID/SID clients must not be able to read each other's data.
- Metadata visibility is acceptable; data-plane access must be protected.
- Secured services are required to use IAM; no fallback path.
- IAM is per secured service.
- Dynamic/resizable shared memory segments must be supported from day one.
- Resource cleanup is performed by the server/manager, not by clients.
- Security mode is configured at Node level, enforced at Service level.
- Handle-passing model is essentially capability-based (aligned with seL4/Capsicum patterns).

## Goals

- Prevent client A from snooping on client B even when both share the same
  user/SID.
- Support Linux and Windows.
- Keep zero-copy data paths; avoid copy-based gateways.
- Allow dynamic segment growth in secured mode.
- Plan for runtime IAM from the start.

## Non-goals

- MAC frameworks (SELinux/AppArmor) integration.
- Cross-host security; tunnels/gateways are out of scope.
- Per-message encryption (local shared memory is trusted once authenticated).

## Current Baseline

- Owner-only permissions by default; optional `dev_permissions` enables
  world access.
- Resource names are derived from public IDs.
- Port creation and attachment are decentralized (no authorization hook).

---

# Part I: Design Overview

## Security Modes

- `Public`: existing behavior, name-based open.
- `Secured`: IAM required for create/open/attach; no direct open-by-name for
  data-plane resources.

Services inherit security mode from their Node's configuration. A Node in
`Secured` mode cannot open `Public` services and vice versa, preventing
confused deputy attacks.

## IAM Per Secured Service

Each secured service has a dedicated IAM endpoint (per-service control plane).
IAM responsibilities:

- Authenticate clients using OS-verified credentials (kernel-mediated).
- Authorize create and attach requests based on policy.
- Create or broker data-plane resources and pass handles.
- Own and clean up resources.
- Notify clients of dynamic segment updates.

## Control Channel (OS IPC)

Shared memory alone cannot authenticate peers or transfer OS handles. A minimal
control channel is required:

- **Linux**: Unix domain socket (stream) with `SCM_CREDENTIALS` and `SCM_RIGHTS`.
- **Windows**: Named pipe with `ImpersonateNamedPipeClient` + `DuplicateHandle`.

The control channel is used only for authentication and handle passing. Bulk
data stays in shared memory.

## Threat Model

### Threats Mitigated

| Threat | Mitigation |
|--------|------------|
| Same-UID process snooping | Handle-passing; no name-based segment access |
| Identity spoofing | Kernel-verified credentials (SCM_CREDENTIALS / named pipe impersonation) |
| Unauthorized attachment | IAM policy gate at Attach* operations |
| Resource tampering by clients | Clients receive read-only or scoped handles; IAM owns deletion |
| Credential replay | Per-connection authentication; no tokens |

### Threats NOT Mitigated (Accepted Risks)

| Threat | Notes |
|--------|-------|
| Root/CAP_SYS_ADMIN attacks | Privileged processes can bypass any user-space security |
| Handle re-sharing via fork()/dup() | FDs can be passed to child processes; accepted architecturally |
| `/proc/<pid>/fd` access | Same-UID attacker can steal FDs; mitigate with `PR_SET_DUMPABLE` |
| Compromised IAM process | IAM compromise = full service compromise; run IAM with minimal privileges |
| DMA/physical memory attacks | Out of scope |

### Critical Security Requirements

1. **`dev_permissions` feature must be disabled** in secured mode (compile-time or runtime gate)
2. **Use `pidfd_open()`** on Linux 5.3+ to prevent PID reuse attacks
3. **Anonymous segments** (`memfd_create` / unnamed `CreateFileMapping`) for data-plane resources

## ACL Scope

ACLs apply to OS principals (user/group/SID) and map to native ACLs. ACLs do
not provide process-level isolation. Process-level isolation is enforced by IAM
and handle passing.

## Data-Plane Handle Passing

All data-plane objects that could leak data must be opened by handle, not by
name:

- Shared memory segments (static and dynamic)
- Zero-copy connections
- Event channels (if applicable)
- Blackboard segments

Named resources may still exist for metadata and discovery but must not be
sufficient to access data. Data-plane resources should use:
- Linux: `memfd_create()` for anonymous segments
- Windows: `CreateFileMapping()` with `lpName=NULL`

## Dynamic Segment Support

Dynamic segments are required in secured mode:

- IAM (or the server under IAM policy) creates new segments during resize.
- IAM notifies authorized clients and passes new handles.
- Clients register new segment IDs in their local view.
- Old segments remain valid until all authorized clients have acknowledged; IAM
  decides when to release them.

## Resource Ownership and Cleanup

- IAM/server owns all data-plane resources and deletes them.
- Clients never receive delete permission.
- IAM tracks active attachments and cleans stale resources.
- **Service creator hosts IAM**: The process that creates a secured service also
  hosts its IAM endpoint. If that process dies, the service and IAM die together.
- **No orphan recovery**: Clients detect service death via existing mechanisms
  (connection close, monitoring) and must reconnect to a newly created service.
  There is no attempt to recover client state across IAM restarts.

## Metadata Visibility

- Service and port metadata may remain readable.
- Metadata must never contain secrets or handles required to access data.

---

# Part II: Sub-Project Organization

This implementation is organized into **7 sub-projects** that can be developed
with some parallelism. Dependencies are noted.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        SP1: Core Security Infrastructure                     │
│                    (PlatformHandle, HandleBundle, traits)                    │
└─────────────────────────────────────────────────────────────────────────────┘
                                      │
                 ┌────────────────────┼────────────────────┐
                 ▼                    ▼                    ▼
┌─────────────────────────┐ ┌─────────────────────┐ ┌─────────────────────────┐
│ SP2: Linux Control      │ │ SP3: Windows Control│ │ SP4: Handle-Based       │
│      Channel            │ │      Channel        │ │      Resource Access    │
│ (UDS + SCM_*)           │ │ (Named Pipes)       │ │ (SharedMemory, ZCC)     │
└─────────────────────────┘ └─────────────────────┘ └─────────────────────────┘
                 │                    │                    │
                 └────────────────────┼────────────────────┘
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                          SP5: IAM Service Core                               │
│              (Protocol, authentication, authorization, handle broker)        │
└─────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                      SP6: Service Builder Integration                        │
│            (Config, builder hooks, port factory secured paths)               │
└─────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                          SP7: Policy & Audit System                          │
│                 (Declarative policies, enforcement, logging)                 │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## SP1: Core Security Infrastructure

**Location**: `iceoryx2-cal/src/security/`

**Purpose**: Define platform-agnostic types and traits for security primitives.

### Deliverables

#### 1.1 Platform Handle Types

```rust
// iceoryx2-cal/src/security/handle.rs

/// Platform-specific handle with RAII semantics
#[derive(Debug)]
pub struct PlatformHandle {
    #[cfg(unix)]
    inner: std::os::unix::io::OwnedFd,
    #[cfg(windows)]
    inner: std::os::windows::io::OwnedHandle,
}

impl PlatformHandle {
    /// Create from raw handle (unsafe: caller must ensure validity and ownership)
    #[cfg(unix)]
    pub unsafe fn from_raw_fd(fd: std::os::unix::io::RawFd) -> Self;

    #[cfg(windows)]
    pub unsafe fn from_raw_handle(handle: std::os::windows::io::RawHandle) -> Self;

    /// Duplicate the handle (creates independent ownership)
    pub fn try_clone(&self) -> Result<Self, HandleError>;
}

/// Bundle of handles for a data-plane resource
#[derive(Debug)]
pub struct HandleBundle {
    /// Primary segment handle
    pub segment: PlatformHandle,
    /// Segment identifier for dynamic segment tracking
    pub segment_id: SegmentId,
    /// Access rights granted
    pub access: AccessRights,
    /// Size of the segment in bytes
    pub size: usize,
}

/// Numeric segment identifier (supports up to 256 segments per resource)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SegmentId(pub u8);

/// Access rights for a handle
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AccessRights {
    pub read: bool,
    pub write: bool,
}
```

#### 1.2 Handle-Based Concept Trait

```rust
// iceoryx2-cal/src/security/traits.rs

/// Trait for resources that can be opened from an OS handle
pub trait HandleBasedConcept: Debug + Sized {
    type Configuration;
    type OpenError;

    /// Open the resource from a platform handle
    fn open_from_handle(
        handle: PlatformHandle,
        config: &Self::Configuration,
    ) -> Result<Self, Self::OpenError>;
}

/// Builder trait for handle-based resources
pub trait HandleBasedConceptBuilder<T: HandleBasedConcept> {
    fn from_handle(handle: PlatformHandle) -> Self;
    fn config(self, config: &T::Configuration) -> Self;
    fn open(self) -> Result<T, T::OpenError>;
}
```

#### 1.3 Security Mode Types

```rust
// iceoryx2-cal/src/security/mode.rs

/// Security mode for a node/service
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SecurityMode {
    /// Existing behavior: name-based open, no IAM
    #[default]
    Public,
    /// IAM required: handle-based open only
    Secured,
}

/// Process credentials obtained from OS
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessCredentials {
    pub pid: u32,
    pub uid: u32,
    pub gid: u32,
    #[cfg(unix)]
    pub start_time: Option<u64>,  // For PID reuse detection
}
```

### Dependencies

- None (foundation layer)

### Estimated Scope

- ~500-800 lines of Rust
- Platform-specific conditional compilation
- Unit tests for handle operations

---

## SP2: Linux Control Channel

**Location**: `iceoryx2-cal/src/control_channel/unix_stream.rs`

**Purpose**: Implement Unix domain socket control channel with credential and
handle passing.

### Deliverables

#### 2.1 Stream Socket Extension

Extend existing `UnixDatagramSocket` implementation to support stream sockets:

```rust
// iceoryx2-bb/posix/src/unix_stream_socket.rs

pub struct UnixStreamListener { /* ... */ }
pub struct UnixStreamConnection { /* ... */ }

impl UnixStreamListener {
    pub fn bind(path: &FilePath) -> Result<Self, Error>;
    pub fn accept(&self) -> Result<UnixStreamConnection, Error>;
}

impl UnixStreamConnection {
    pub fn connect(path: &FilePath) -> Result<Self, Error>;

    /// Get peer credentials via SO_PEERCRED (one-time, at connection)
    pub fn peer_credentials(&self) -> Result<ProcessCredentials, Error>;

    /// Send message with optional handles
    pub fn send_with_handles(
        &self,
        data: &[u8],
        handles: &[PlatformHandle]
    ) -> Result<(), Error>;

    /// Receive message with handles
    pub fn receive_with_handles(
        &self,
        buffer: &mut [u8]
    ) -> Result<(usize, Vec<PlatformHandle>), Error>;
}
```

#### 2.2 Anonymous Shared Memory (memfd)

```rust
// iceoryx2-bb/posix/src/anonymous_memory.rs

pub struct AnonymousSharedMemory {
    file_descriptor: FileDescriptor,
    size: usize,
}

impl AnonymousSharedMemory {
    /// Create anonymous memory via memfd_create (Linux 3.17+)
    pub fn create(name: &str, size: usize) -> Result<Self, Error>;

    /// Create with sealing to prevent size changes
    pub fn create_sealed(name: &str, size: usize) -> Result<Self, Error>;

    /// Get handle for passing to another process
    pub fn handle(&self) -> PlatformHandle;
}
```

#### 2.3 PID Stability (pidfd)

```rust
// iceoryx2-bb/posix/src/process.rs (extension)

impl Process {
    /// Open a pidfd for stable process reference (Linux 5.3+)
    pub fn open_pidfd(&self) -> Result<PidFd, Error>;
}

pub struct PidFd { /* ... */ }

impl PidFd {
    /// Check if the process is still alive
    pub fn is_alive(&self) -> bool;

    /// Get the process start time for verification
    pub fn start_time(&self) -> Result<u64, Error>;
}
```

#### 2.4 Control Channel Trait Implementation

```rust
// iceoryx2-cal/src/control_channel/unix_stream.rs

pub struct UnixStreamControlChannel { /* ... */ }

impl ControlChannel for UnixStreamControlChannel {
    fn connect(endpoint: &ControlEndpoint) -> Result<Self, ControlChannelError>;
    fn authenticate(&self) -> Result<ProcessCredentials, ControlChannelError>;
    fn send_handles(&self, handles: &[PlatformHandle]) -> Result<(), ControlChannelError>;
    fn receive_handles(&self, count: usize) -> Result<Vec<PlatformHandle>, ControlChannelError>;
    fn send_message(&self, msg: &[u8]) -> Result<(), ControlChannelError>;
    fn receive_message(&self, buffer: &mut [u8]) -> Result<usize, ControlChannelError>;
}
```

### Dependencies

- SP1 (PlatformHandle, traits)

### Estimated Scope

- ~1500-2000 lines of Rust
- Extension of existing socket_ancillary.rs patterns
- Integration tests with FD passing

---

## SP3: Windows Control Channel

**Location**: `iceoryx2-cal/src/control_channel/named_pipe.rs`

**Purpose**: Implement named pipe control channel with credential verification
and handle passing.

### Deliverables

#### 3.1 Named Pipe Server/Client

```rust
// iceoryx2-pal/posix/src/windows/named_pipe.rs

pub struct NamedPipeServer {
    handle: HANDLE,
    // ...
}

impl NamedPipeServer {
    /// Create a named pipe server
    pub fn create(name: &str, security: &SecurityDescriptor) -> Result<Self, Error>;

    /// Wait for and accept a client connection
    pub fn accept(&self) -> Result<NamedPipeConnection, Error>;
}

pub struct NamedPipeConnection { /* ... */ }

impl NamedPipeConnection {
    /// Connect to a named pipe server
    pub fn connect(name: &str) -> Result<Self, Error>;

    /// Get client credentials via impersonation
    pub fn peer_credentials(&self) -> Result<ProcessCredentials, Error>;

    /// Get client process ID
    pub fn client_process_id(&self) -> Result<u32, Error>;
}
```

#### 3.2 Handle Duplication

```rust
// iceoryx2-pal/posix/src/windows/handle_passing.rs

/// Duplicate a handle into another process
pub fn duplicate_handle_to_process(
    source_handle: &PlatformHandle,
    target_process_id: u32,
    access: AccessRights,
) -> Result<HANDLE, Error>;  // Returns the handle value for the target process

/// Send handle value over pipe (after duplication)
pub fn send_duplicated_handle(
    pipe: &NamedPipeConnection,
    handle_value: HANDLE,
) -> Result<(), Error>;
```

#### 3.3 Anonymous Section Creation

```rust
// iceoryx2-pal/posix/src/windows/mman.rs (extension)

/// Create anonymous file mapping (no name, only accessible via handle)
pub fn create_anonymous_mapping(
    size: usize,
    access: AccessRights,
    security: Option<&SecurityDescriptor>,
) -> Result<PlatformHandle, Error>;
```

#### 3.4 Security Descriptor Helpers

```rust
// iceoryx2-pal/posix/src/windows/security.rs

pub struct SecurityDescriptor { /* ... */ }

impl SecurityDescriptor {
    /// Create SD allowing only owner full access
    pub fn owner_only() -> Result<Self, Error>;

    /// Create SD with specific DACL
    pub fn with_dacl(entries: &[AclEntry]) -> Result<Self, Error>;
}

pub struct AclEntry {
    pub sid: Sid,
    pub access_mask: u32,
    pub access_mode: AclAccessMode,  // Allow/Deny
}
```

#### 3.5 Control Channel Trait Implementation

```rust
// iceoryx2-cal/src/control_channel/named_pipe.rs

pub struct NamedPipeControlChannel { /* ... */ }

impl ControlChannel for NamedPipeControlChannel {
    fn connect(endpoint: &ControlEndpoint) -> Result<Self, ControlChannelError>;
    fn authenticate(&self) -> Result<ProcessCredentials, ControlChannelError>;
    fn send_handles(&self, handles: &[PlatformHandle]) -> Result<(), ControlChannelError>;
    fn receive_handles(&self, count: usize) -> Result<Vec<PlatformHandle>, ControlChannelError>;
    fn send_message(&self, msg: &[u8]) -> Result<(), ControlChannelError>;
    fn receive_message(&self, buffer: &mut [u8]) -> Result<usize, ControlChannelError>;
}
```

### Dependencies

- SP1 (PlatformHandle, traits)

### Estimated Scope

- ~2000-2500 lines of Rust
- New Windows-specific code (named pipes not currently in codebase)
- Win32 API integration via windows-sys

---

## SP4: Handle-Based Resource Access

**Location**: `iceoryx2-cal/src/shared_memory/`, `iceoryx2-cal/src/zero_copy_connection/`

**Purpose**: Add handle-based open paths to existing CAL resources.

### Deliverables

#### 4.1 SharedMemory Handle Support

```rust
// iceoryx2-cal/src/shared_memory/mod.rs (extension)

pub trait SharedMemoryBuilder<Allocator, Shm>: NamedConceptBuilder<Shm> {
    // Existing methods...
    fn create(self, allocator_config: &Allocator::Configuration)
        -> Result<Shm, SharedMemoryCreateError>;
    fn open(self) -> Result<Shm, SharedMemoryOpenError>;

    // New handle-based method
    fn open_from_handle(
        handle: PlatformHandle,
        config: &SharedMemoryConfiguration,
    ) -> Result<Shm, SharedMemoryOpenFromHandleError>;
}

#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
pub enum SharedMemoryOpenFromHandleError {
    InvalidHandle,
    MappingFailed,
    WrongAllocatorSelected,
    InsufficientPermissions,
    InternalError,
}
```

#### 4.2 ZeroCopyConnection Handle Support

```rust
// iceoryx2-cal/src/zero_copy_connection/mod.rs (extension)

pub trait ZeroCopyConnectionBuilder<C: ZeroCopyConnection> {
    // Existing methods...

    // New handle-based method
    fn open_from_handle(
        handle: PlatformHandle,
        segment_id: SegmentId,
    ) -> Result<C, ZeroCopyConnectionOpenFromHandleError>;
}
```

#### 4.3 ResizableSharedMemory Handle Support

```rust
// iceoryx2-cal/src/resizable_shared_memory/mod.rs (extension)

pub trait ResizableSharedMemoryView {
    /// Add a new segment from a handle received via IAM
    fn add_segment_from_handle(
        &mut self,
        segment_id: SegmentId,
        handle: PlatformHandle,
    ) -> Result<(), ResizableSharedMemoryError>;

    /// Remove a segment (for retirement)
    fn retire_segment(&mut self, segment_id: SegmentId) -> Result<(), ResizableSharedMemoryError>;
}
```

#### 4.4 Anonymous Creation Paths

Modify existing creation code to use anonymous segments when in secured mode:

```rust
// In shared memory builders
impl SharedMemoryBuilder for PosixSharedMemoryBuilder {
    fn create_anonymous(
        self,
        allocator_config: &Allocator::Configuration,
    ) -> Result<(Shm, PlatformHandle), SharedMemoryCreateError> {
        // Use memfd_create on Linux, anonymous CreateFileMapping on Windows
        // Return both the mapped memory AND the handle for passing to clients
    }
}
```

### Dependencies

- SP1 (PlatformHandle, HandleBasedConcept trait)
- SP2 or SP3 (for anonymous memory creation functions)

### Estimated Scope

- ~1000-1500 lines of Rust
- Modifications to existing CAL modules
- Conformance tests for handle-based operations

---

## SP5: IAM Service Core

**Location**: `iceoryx2/src/iam/`

**Purpose**: Implement the IAM service that authenticates clients, enforces
policy, and brokers handles.

### Deliverables

#### 5.1 IAM Protocol Definition

```rust
// iceoryx2/src/iam/protocol.rs

/// Protocol version for IAM communication
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtocolVersion {
    pub major: u16,
    pub minor: u16,
}

impl ProtocolVersion {
    pub const CURRENT: Self = Self { major: 1, minor: 0 };
}

/// All IAM request types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IamRequest {
    Hello {
        protocol_version: ProtocolVersion,
        node_id: NodeId,
    },
    CreateService {
        service_name: ServiceName,
        messaging_pattern: MessagingPatternKind,
    },
    AttachPublisher {
        service_id: ServiceId,
        qos_caps: QosCaps,
    },
    AttachSubscriber {
        service_id: ServiceId,
        qos_caps: QosCaps,
    },
    AttachServer {
        service_id: ServiceId,
        qos_caps: QosCaps,
    },
    AttachClient {
        service_id: ServiceId,
        qos_caps: QosCaps,
    },
    AddSegment {
        service_id: ServiceId,
        port_id: PortId,
        requested_size: usize,
    },
    Detach {
        service_id: ServiceId,
        port_id: PortId,
    },
    AckSegmentRetirement {
        service_id: ServiceId,
        segment_id: SegmentId,
    },
}

/// IAM response types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IamResponse {
    HelloOk {
        negotiated_version: ProtocolVersion,
    },
    AttachOk {
        port_id: PortId,
        segment_info: Vec<SegmentInfo>,
        negotiated_qos: NegotiatedQos,
        // Actual handles sent via control channel ancillary data
        handle_count: usize,
    },
    CreateServiceOk {
        service_id: ServiceId,
    },
    AddSegmentOk {
        segment_id: SegmentId,
        handle_count: usize,
    },
    Denied {
        reason: DenialReason,
        message: String,
    },
}

/// Asynchronous notifications from IAM to clients
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IamNotification {
    SegmentUpdate {
        segment_id: SegmentId,
        size: usize,
        handle_count: usize,
    },
    SegmentRetiring {
        segment_id: SegmentId,
    },
    PortJoined {
        port_id: PortId,
        port_type: PortType,
    },
    PortLeft {
        port_id: PortId,
    },
    ServiceStopping,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DenialReason {
    Unauthorized,
    ServiceNotFound,
    ServiceAlreadyExists,
    ResourceLimitExceeded,
    IncompatibleQos,
    PolicyViolation,
    InternalError,
}
```

#### 5.2 IAM Server Implementation

```rust
// iceoryx2/src/iam/server.rs

pub struct IamServer<C: ControlChannel> {
    service_id: ServiceId,
    control_channel: C,
    sessions: HashMap<SessionId, ClientSession>,
    segments: SegmentManager,
    policy: Box<dyn IamPolicy>,
}

impl<C: ControlChannel> IamServer<C> {
    /// Create IAM server for a secured service
    pub fn new(
        service_id: ServiceId,
        endpoint: ControlEndpoint,
        policy: Box<dyn IamPolicy>,
    ) -> Result<Self, IamServerError>;

    /// Run the IAM server (blocking)
    pub fn run(&mut self) -> Result<(), IamServerError>;

    /// Process a single client request
    fn handle_request(
        &mut self,
        session: &mut ClientSession,
        request: IamRequest,
    ) -> IamResponse;

    /// Create a segment and return handle for the creator
    fn create_segment(&mut self, size: usize) -> Result<HandleBundle, IamServerError>;

    /// Notify all clients of a segment update
    fn broadcast_segment_update(&mut self, segment_id: SegmentId);
}

struct ClientSession {
    id: SessionId,
    credentials: ProcessCredentials,
    authenticated_at: Instant,
    attached_ports: Vec<PortId>,
    granted_segments: HashSet<SegmentId>,
}

struct SegmentManager {
    segments: HashMap<SegmentId, ManagedSegment>,
    next_id: SegmentId,
}

struct ManagedSegment {
    handle: PlatformHandle,
    size: usize,
    authorized_clients: HashSet<SessionId>,
    retiring: bool,
    pending_acks: HashSet<SessionId>,
}
```

#### 5.3 IAM Client Library

```rust
// iceoryx2/src/iam/client.rs

pub struct IamClient<C: ControlChannel> {
    service_id: ServiceId,
    connection: C,
    session_id: SessionId,
}

impl<C: ControlChannel> IamClient<C> {
    /// Connect to IAM for a service
    pub fn connect(endpoint: &ControlEndpoint) -> Result<Self, IamClientError>;

    /// Send Hello and complete handshake
    pub fn handshake(&mut self, node_id: NodeId) -> Result<(), IamClientError>;

    /// Request attachment (returns handles via callback)
    pub fn attach(
        &mut self,
        request: AttachRequest,
    ) -> Result<AttachResponse, IamClientError>;

    /// Request a new segment
    pub fn add_segment(&mut self, port_id: PortId, size: usize) -> Result<HandleBundle, IamClientError>;

    /// Acknowledge segment retirement
    pub fn ack_retirement(&mut self, segment_id: SegmentId) -> Result<(), IamClientError>;

    /// Poll for notifications
    pub fn poll_notification(&mut self) -> Option<IamNotification>;

    /// Detach from service
    pub fn detach(&mut self, port_id: PortId) -> Result<(), IamClientError>;
}
```

#### 5.4 IAM Policy Trait

```rust
// iceoryx2/src/iam/policy.rs

pub trait IamPolicy: Send + Sync {
    /// Check if credentials are allowed to create the service
    fn authorize_create(
        &self,
        credentials: &ProcessCredentials,
        service_name: &ServiceName,
    ) -> PolicyDecision;

    /// Check if credentials are allowed to attach with given role
    fn authorize_attach(
        &self,
        credentials: &ProcessCredentials,
        service_id: &ServiceId,
        port_type: PortType,
    ) -> PolicyDecision;

    /// Get resource limits for a principal
    fn get_limits(&self, credentials: &ProcessCredentials) -> ResourceLimits;

    /// Negotiate QoS within allowed bounds
    fn negotiate_qos(
        &self,
        credentials: &ProcessCredentials,
        requested: &QosCaps,
    ) -> Result<NegotiatedQos, PolicyViolation>;
}

#[derive(Debug)]
pub enum PolicyDecision {
    Allow,
    Deny { reason: String },
}

/// Default policy: allow all same-UID processes
pub struct DefaultPolicy;

/// Policy loaded from configuration
pub struct ConfiguredPolicy {
    rules: Vec<PolicyRule>,
}
```

### Dependencies

- SP1 (PlatformHandle, SecurityMode)
- SP2 or SP3 (ControlChannel trait implementation)
- SP4 (HandleBasedConcept for segment creation)

### Estimated Scope

- ~3000-4000 lines of Rust
- Core IAM logic
- Extensive integration tests

---

## SP6: Service Builder Integration

**Location**: `iceoryx2/src/service/`, `iceoryx2/src/config.rs`

**Purpose**: Integrate security mode into configuration and service builders.

### Deliverables

#### 6.1 Configuration Extension

```rust
// iceoryx2/src/config.rs (extension)

#[derive(Serialize, Deserialize, Debug, Clone, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub struct Node {
    // Existing fields...
    pub directory: Path,
    pub monitor_suffix: FileName,

    // New security configuration
    pub security: NodeSecurity,
}

#[derive(Serialize, Deserialize, Debug, Clone, Eq, PartialEq, Default)]
#[serde(rename_all = "kebab-case")]
pub struct NodeSecurity {
    /// Security mode for all services created by this node
    #[serde(default)]
    pub mode: SecurityMode,

    /// IAM endpoint configuration
    #[serde(default)]
    pub iam: IamConfig,
}

#[derive(Serialize, Deserialize, Debug, Clone, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub struct IamConfig {
    /// Base path for IAM endpoints
    #[serde(default = "default_iam_endpoint_base")]
    pub endpoint_base: Path,

    /// Connection timeout
    #[serde(default = "default_iam_timeout")]
    pub connect_timeout: Duration,
}
```

**TOML Example:**
```toml
[global.node.security]
mode = "secured"

[global.node.security.iam]
endpoint-base = "/run/iceoryx2/iam"
connect-timeout = "5s"
```

#### 6.2 Static Config Extension

```rust
// iceoryx2/src/service/static_config/mod.rs (extension)

#[derive(Debug, Eq, PartialEq, Clone, ZeroCopySend, Serialize, Deserialize)]
pub struct StaticConfig {
    // Existing fields...
    service_id: ServiceId,
    service_name: ServiceName,
    attributes: AttributeSet,
    messaging_pattern: MessagingPattern,

    // New field
    security_mode: SecurityMode,
}
```

#### 6.3 Service Builder Security Hooks

```rust
// iceoryx2/src/service/builder/mod.rs (extension)

impl<ServiceType: service::Service> Builder<ServiceType> {
    pub fn publish_subscribe<PayloadType>(self) -> publish_subscribe::Builder<...> {
        let security_mode = self.shared_node.config().global.node.security.mode;

        BuilderWithServiceType::new(/* ... */)
            .with_security_mode(security_mode)
            .publish_subscribe()
    }
}

// In publish_subscribe builder
impl<...> publish_subscribe::Builder<...> {
    fn create_internal(&self) -> Result<PortFactory, CreateError> {
        match self.security_mode {
            SecurityMode::Public => self.create_public(),
            SecurityMode::Secured => self.create_secured(),
        }
    }

    fn create_secured(&self) -> Result<PortFactory, CreateError> {
        // 1. Connect to or create IAM
        // 2. Authenticate
        // 3. CreateService request
        // 4. Store IAM connection for port creation
    }

    fn open_internal(&self) -> Result<PortFactory, OpenError> {
        // Check security mode compatibility
        let service_mode = self.read_static_config()?.security_mode;
        let node_mode = self.security_mode;

        if service_mode != node_mode {
            return Err(OpenError::SecurityModeIncompatible);
        }

        match service_mode {
            SecurityMode::Public => self.open_public(),
            SecurityMode::Secured => self.open_secured(),
        }
    }
}
```

#### 6.4 Port Creation with IAM

```rust
// iceoryx2/src/port/publisher.rs (conceptual extension)

impl<...> Publisher<...> {
    fn create_secured(
        service: &Service,
        iam_client: &mut IamClient,
        config: &PublisherConfig,
    ) -> Result<Self, PublisherCreateError> {
        // 1. Request AttachPublisher from IAM
        let response = iam_client.attach(AttachRequest::Publisher {
            service_id: service.id(),
            qos_caps: config.to_qos_caps(),
        })?;

        // 2. Receive handles from IAM
        let handles = iam_client.receive_handles(response.handle_count)?;

        // 3. Map segments from handles
        let data_segment = DataSegment::open_from_handle(handles[0], response.segment_info[0])?;

        // 4. Create publisher with secured data segment
        Ok(Self {
            data_segment,
            port_id: response.port_id,
            // ...
        })
    }
}
```

### Dependencies

- SP5 (IAM client library)
- SP4 (Handle-based resource opening)

### Estimated Scope

- ~1500-2000 lines of Rust
- Modifications to existing builders
- Configuration parsing/validation

---

## SP7: Policy & Audit System

**Location**: `iceoryx2/src/iam/policy/`

**Purpose**: Implement declarative policy system and audit logging.

### Deliverables

#### 7.1 Policy File Format

```toml
# Example: /etc/iceoryx2/policies/my-service.toml

[service]
name = "my-secured-service"

# Allow rules
[[allow]]
principal = { uid = 1000 }
roles = ["publisher", "subscriber"]

[[allow]]
principal = { gid = 100 }  # Group-based
roles = ["subscriber"]

[[allow]]
principal = { uid_range = [2000, 2999] }
roles = ["subscriber"]

# Deny rules (evaluated first)
[[deny]]
principal = { uid = 1001 }
reason = "Explicitly blocked user"

# Resource limits
[limits]
max_publishers = 1
max_subscribers = 100
max_segments = 16
max_segment_size = "64MB"

# QoS bounds
[qos]
max_buffer_size = 1024
max_history = 10
```

#### 7.2 Policy Loader

```rust
// iceoryx2/src/iam/policy/loader.rs

pub struct PolicyLoader {
    policy_dir: Path,
}

impl PolicyLoader {
    pub fn load_for_service(&self, service_name: &ServiceName) -> Result<ConfiguredPolicy, PolicyLoadError>;
}

pub struct ConfiguredPolicy {
    allow_rules: Vec<AllowRule>,
    deny_rules: Vec<DenyRule>,
    limits: ResourceLimits,
    qos_bounds: QosBounds,
}

impl IamPolicy for ConfiguredPolicy {
    // Implementation...
}
```

#### 7.3 Audit Logger

```rust
// iceoryx2/src/iam/audit.rs

pub trait AuditLogger: Send + Sync {
    fn log_create(&self, event: &CreateEvent);
    fn log_attach(&self, event: &AttachEvent);
    fn log_deny(&self, event: &DenyEvent);
    fn log_detach(&self, event: &DetachEvent);
}

#[derive(Debug, Serialize)]
pub struct AttachEvent {
    pub timestamp: SystemTime,
    pub service_id: ServiceId,
    pub credentials: ProcessCredentials,
    pub port_type: PortType,
    pub port_id: PortId,
    pub decision: PolicyDecision,
}

/// File-based audit logger
pub struct FileAuditLogger {
    path: Path,
    // Append-only, JSON lines format
}

/// Syslog audit logger (optional)
#[cfg(feature = "syslog")]
pub struct SyslogAuditLogger { /* ... */ }
```

### Dependencies

- SP5 (IamPolicy trait)

### Estimated Scope

- ~1000-1500 lines of Rust
- TOML parsing for policies
- Audit log format and rotation

---

# Part III: Attach-Flow Details

## Publish/Subscribe (1 publisher, N subscribers)

```
┌───────────┐          ┌───────────┐          ┌───────────┐
│ Publisher │          │    IAM    │          │Subscriber │
└─────┬─────┘          └─────┬─────┘          └─────┬─────┘
      │                      │                      │
      │ 1. Connect (UDS)     │                      │
      │─────────────────────>│                      │
      │                      │                      │
      │ 2. Hello + CreateService                    │
      │─────────────────────>│                      │
      │                      │                      │
      │    CreateServiceOk   │                      │
      │<─────────────────────│                      │
      │                      │                      │
      │ 3. AttachPublisher   │                      │
      │─────────────────────>│                      │
      │                      │                      │
      │  AttachOk + handles  │                      │
      │<═══════════════════════ (SCM_RIGHTS)       │
      │                      │                      │
      │ 4. Map segments      │                      │
      │                      │                      │
      │                      │  5. Connect (UDS)    │
      │                      │<─────────────────────│
      │                      │                      │
      │                      │ 6. Hello + AttachSubscriber
      │                      │<─────────────────────│
      │                      │                      │
      │                      │   AttachOk + handles │
      │                      │═════════════════════>│ (SCM_RIGHTS)
      │                      │                      │
      │ 7. PortJoined        │                      │
      │<─────────────────────│                      │
      │                      │                      │
      │ 8. Map segments      │                      │
      │                      │                      │
      │ ═══════════════════════════════════════════>│
      │         Zero-copy data transfer             │
      │                      │                      │
```

## Dynamic Segment Update

```
┌───────────┐          ┌───────────┐          ┌───────────┐
│ Publisher │          │    IAM    │          │Subscriber │
└─────┬─────┘          └─────┬─────┘          └─────┬─────┘
      │                      │                      │
      │ 1. AddSegment        │                      │
      │─────────────────────>│                      │
      │                      │                      │
      │ 2. Create segment    │                      │
      │                      │                      │
      │  AddSegmentOk+handle │                      │
      │<═════════════════════│                      │
      │                      │                      │
      │ 3. Map new segment   │                      │
      │                      │                      │
      │                      │ 4. SegmentUpdate+handle
      │                      │═════════════════════>│
      │                      │                      │
      │                      │ 5. Map new segment   │
      │                      │                      │
      │                      │  AckSegmentRetirement│
      │                      │<─────────────────────│
      │                      │                      │
```

---

# Part IV: Configuration Reference

## Node Configuration (iceoryx2.toml)

```toml
[global]

[global.node]
directory = "/tmp/iceoryx2/"
monitor-suffix = ".node_monitor"

[global.node.security]
# Options: "public" (default), "secured"
mode = "secured"

[global.node.security.iam]
# Base path for IAM control sockets/pipes
# Linux: /run/iceoryx2/iam/<service-id>.sock
# Windows: \\.\pipe\iceoryx2_iam_<service-id>
endpoint-base = "/run/iceoryx2/iam"

# Timeout for IAM connection attempts
connect-timeout = "5s"

# Maximum retries for IAM operations
max-retries = 3
```

## Policy Configuration

Policies are stored in a directory structure:
```
/etc/iceoryx2/policies/
├── default.toml           # Default policy for unspecified services
├── my-service.toml        # Policy for "my-service"
└── another-service.toml   # Policy for "another-service"
```

---

# Part V: Open Questions

## Resolved

| Question | Resolution |
|----------|------------|
| Windows control channel choice | Named Pipes (preferred over AF_UNIX due to native credential support) |
| Security mode scope | Node-level configuration, Service-level enforcement |
| Handle re-sharing risk | Accepted; focus on authorization at grant time |
| `dev_permissions` compatibility | Must be disabled/gated in secured mode |
| IAM process model | **In-process, hosted by service creator**. Service creator owns IAM; if it dies, service dies. No daemon extraction planned. |
| IAM crash recovery | **Not needed**. Service is authoritative; all clients die with service. Clean reconnection on service restart. |
| Handle revocation | **Not supported**. OS cannot forcibly revoke handles. Rely on segment retirement protocol for cooperative cleanup. |
| Minimum kernel version | **Not a blocker**. Use available features; graceful fallback where needed. |

## Still Open

| Question | Options | Notes |
|----------|---------|-------|
| Policy hot-reload | Supported vs restart required | Nice-to-have; defer to later phase |
| Discovery in secured mode | Show all vs filter by authorization | TBD based on use cases |
| Event pattern security | Full IAM vs lightweight auth | Events don't carry data; may simplify |

---

# Part VI: Implementation Phases

## Phase 1: Foundation (SP1 + SP4 partial)

**Goal**: Establish core types and handle-based resource access without IAM.

- PlatformHandle, HandleBundle, AccessRights types
- SecurityMode enum
- `open_from_handle()` on SharedMemory (Linux only)
- Unit tests

**No behavioral change** to existing code.

## Phase 2: Linux Control Channel (SP2)

**Goal**: Working credential and handle passing on Linux.

- Unix stream socket with SO_PEERCRED
- SCM_RIGHTS handle passing
- memfd_create for anonymous segments
- Control channel trait

**No behavioral change** to existing code.

## Phase 3: IAM Core (SP5 partial)

**Goal**: Basic IAM server/client with authentication.

- Protocol definition
- IAM server skeleton
- IAM client library
- DefaultPolicy (allow all same-UID)

**Testable** in isolation.

## Phase 4: Service Integration (SP6)

**Goal**: Secured services work end-to-end on Linux.

- Config extension
- Service builder hooks
- Publisher/Subscriber secured paths
- Integration tests

**Secured mode functional** on Linux.

## Phase 5: Windows Support (SP3)

**Goal**: Full Windows parity.

- Named pipe server/client
- Handle duplication
- Anonymous sections
- Control channel implementation

**Cross-platform** secured services.

## Phase 6: Polish (SP4 complete, SP7)

**Goal**: Production readiness.

- All messaging patterns secured
- Policy file system
- Audit logging
- Performance optimization
- Documentation

---

# Part VII: References

- POSIX: `SCM_CREDENTIALS`, `SCM_RIGHTS`, `memfd_create(2)`, `pidfd_open(2)`
- Windows: `DuplicateHandle`, `CreateNamedPipe`, `ImpersonateNamedPipeClient`
- Android Binder: Kernel-verified credentials + handle passing model
- D-Bus: Policy-based authorization separation
- seL4/Capsicum: Capability-based security patterns
- iceoryx v1: RouDi + group-based access control

---

# Appendix A: Security Checklist

Before declaring secured mode production-ready:

- [ ] `dev_permissions` feature disabled or gated
- [ ] Anonymous segments used for all data-plane resources
- [ ] PID stability via pidfd or starttime verification
- [ ] `/proc/<pid>/fd` risk documented; optional `PR_SET_DUMPABLE` mitigation
- [ ] Handle re-sharing risk documented
- [ ] Policy denial logging enabled
- [ ] Windows credential verification validated
- [ ] Cross-namespace behavior documented

# Appendix B: Performance Expectations

| Operation | Public Mode | Secured Mode | Notes |
|-----------|-------------|--------------|-------|
| Connection setup | ~10µs | ~30µs | One-time per port |
| Per-message send | ~500ns | ~500ns | Zero impact |
| Per-message receive | ~500ns | ~500ns | Zero impact |
| Dynamic segment | ~15µs | ~25µs + 8µs/client | Notification overhead |
| IAM memory | 0 | ~100KB/1000 clients | Tracking overhead |
