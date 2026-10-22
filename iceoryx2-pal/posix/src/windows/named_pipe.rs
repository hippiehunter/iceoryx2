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

//! Windows Named Pipe primitives for inter-process communication.
//!
//! This module provides a safe abstraction over Windows Named Pipes, suitable for
//! implementing control channels with peer credential verification.
//!
//! # Features
//!
//! - Server-side pipe creation with security attributes
//! - Client connection with blocking, non-blocking, and timed variants
//! - Peer process identification via `GetNamedPipeClientProcessId`
//! - Bidirectional message-mode communication
//!
//! # Example
//!
//! ```ignore
//! use iceoryx2_pal_posix::windows::named_pipe::*;
//!
//! // Server
//! let mut server = NamedPipeServer::create(b"my_pipe", 0o600)?;
//! let conn = server.blocking_accept()?;
//! let creds = conn.peer_credentials()?;
//!
//! // Client (in another process)
//! let client = NamedPipeConnection::connect(b"my_pipe")?;
//! ```

// NOTE: non_camel_case_types is needed for Windows API type compatibility
#![allow(non_camel_case_types)]
#![allow(clippy::missing_safety_doc)]

extern crate alloc;
extern crate std;

use core::fmt::{self, Display, Formatter};
use core::time::Duration;

// Windows API imports
#[cfg(windows)]
use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_ACCESS_DENIED, ERROR_ALREADY_EXISTS, ERROR_BROKEN_PIPE,
    ERROR_FILE_NOT_FOUND, ERROR_HANDLE_EOF, ERROR_INVALID_HANDLE, ERROR_IO_PENDING,
    ERROR_MORE_DATA, ERROR_NO_DATA, ERROR_PIPE_BUSY, ERROR_PIPE_CONNECTED, ERROR_PIPE_LISTENING,
    ERROR_PIPE_NOT_CONNECTED, FALSE, GetLastError, HANDLE, INVALID_HANDLE_VALUE, TRUE,
    WAIT_ABANDONED, WAIT_OBJECT_0, WAIT_TIMEOUT,
};

#[cfg(windows)]
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_FLAG_OVERLAPPED, FILE_SHARE_READ,
    FILE_SHARE_WRITE, FlushFileBuffers, OPEN_EXISTING, PIPE_ACCESS_DUPLEX, ReadFile,
    SECURITY_IDENTIFICATION, SECURITY_SQOS_PRESENT, WriteFile,
};

#[cfg(windows)]
use windows_sys::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, GetNamedPipeClientProcessId, GetNamedPipeServerProcessId,
    PIPE_READMODE_MESSAGE, PIPE_TYPE_MESSAGE, PIPE_UNLIMITED_INSTANCES, PIPE_WAIT, PeekNamedPipe,
    SetNamedPipeHandleState, WaitNamedPipeW,
};

#[cfg(windows)]
use windows_sys::Win32::System::Threading::{GetCurrentProcessId, INFINITE, WaitForSingleObject};

#[cfg(windows)]
use windows_sys::Win32::System::IO::{CancelIo, GetOverlappedResult, OVERLAPPED};

#[cfg(windows)]
use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;

// ============================================================================
// Constants
// ============================================================================

/// Maximum length of a named pipe name (including null terminator).
pub const MAX_PIPE_NAME_LENGTH: usize = 256;

/// Prefix for all Windows named pipes.
pub const PIPE_NAME_PREFIX: &str = r"\\.\pipe\";

/// Default buffer size for pipe read/write operations.
pub const DEFAULT_PIPE_BUFFER_SIZE: u32 = 65536;

/// Default timeout for pipe operations in milliseconds.
pub const DEFAULT_PIPE_TIMEOUT_MS: u32 = 5000;

/// The first message of every client. The server reads it while accepting the connection so
/// that it may impersonate the client to learn its identity.
#[cfg(windows)]
const IDENTITY_HANDSHAKE: &[u8; 8] = b"IOX2IDNT";

/// How long accepting a connection waits for the client's [`IDENTITY_HANDSHAKE`].
#[cfg(windows)]
const IDENTITY_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(2);

// ============================================================================
// Error Types
// ============================================================================

/// Errors that can occur during named pipe operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NamedPipeError {
    /// The pipe name exceeds the maximum allowed length.
    NameTooLong,
    /// Access to the pipe was denied.
    AccessDenied,
    /// A pipe with the specified name already exists.
    AlreadyExists,
    /// The specified pipe does not exist.
    DoesNotExist,
    /// All pipe instances are busy.
    PipeBusy,
    /// The pipe has been closed by the other end.
    BrokenPipe,
    /// The operation would block (non-blocking mode).
    WouldBlock,
    /// The handle is invalid.
    InvalidHandle,
    /// Insufficient system resources.
    InsufficientResources,
    /// The pipe is not connected.
    NotConnected,
    /// The pipe is already connected.
    AlreadyConnected,
    /// The connection was reset.
    ConnectionReset,
    /// The operation timed out.
    TimedOut,
    /// The operation was interrupted.
    Interrupted,
    /// An unknown error occurred.
    UnknownError(u32),
}

impl NamedPipeError {
    /// Converts a Win32 error code to a [`NamedPipeError`].
    #[cfg(windows)]
    pub fn from_win32(error_code: u32) -> Self {
        match error_code {
            ERROR_ACCESS_DENIED => NamedPipeError::AccessDenied,
            ERROR_ALREADY_EXISTS => NamedPipeError::AlreadyExists,
            ERROR_FILE_NOT_FOUND => NamedPipeError::DoesNotExist,
            ERROR_PIPE_BUSY => NamedPipeError::PipeBusy,
            ERROR_BROKEN_PIPE | ERROR_NO_DATA => NamedPipeError::BrokenPipe,
            ERROR_PIPE_LISTENING => NamedPipeError::WouldBlock,
            ERROR_INVALID_HANDLE => NamedPipeError::InvalidHandle,
            ERROR_PIPE_NOT_CONNECTED => NamedPipeError::NotConnected,
            ERROR_PIPE_CONNECTED => NamedPipeError::AlreadyConnected,
            ERROR_IO_PENDING => NamedPipeError::WouldBlock,
            ERROR_HANDLE_EOF => NamedPipeError::BrokenPipe,
            _ => NamedPipeError::UnknownError(error_code),
        }
    }

    /// Stub implementation for non-Windows platforms.
    #[cfg(not(windows))]
    pub fn from_win32(error_code: u32) -> Self {
        NamedPipeError::UnknownError(error_code)
    }
}

impl Display for NamedPipeError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            NamedPipeError::NameTooLong => write!(f, "Pipe name exceeds maximum length"),
            NamedPipeError::AccessDenied => write!(f, "Access denied"),
            NamedPipeError::AlreadyExists => write!(f, "Pipe already exists"),
            NamedPipeError::DoesNotExist => write!(f, "Pipe does not exist"),
            NamedPipeError::PipeBusy => write!(f, "All pipe instances are busy"),
            NamedPipeError::BrokenPipe => write!(f, "Pipe has been closed"),
            NamedPipeError::WouldBlock => write!(f, "Operation would block"),
            NamedPipeError::InvalidHandle => write!(f, "Invalid handle"),
            NamedPipeError::InsufficientResources => write!(f, "Insufficient system resources"),
            NamedPipeError::NotConnected => write!(f, "Pipe is not connected"),
            NamedPipeError::AlreadyConnected => write!(f, "Pipe is already connected"),
            NamedPipeError::ConnectionReset => write!(f, "Connection was reset"),
            NamedPipeError::TimedOut => write!(f, "Operation timed out"),
            NamedPipeError::Interrupted => write!(f, "Operation was interrupted"),
            NamedPipeError::UnknownError(code) => write!(f, "Unknown error (code: {})", code),
        }
    }
}

impl core::error::Error for NamedPipeError {}

// ============================================================================
// Helper Functions
// ============================================================================

/// Converts a pipe name (as bytes) to a wide string with the pipe prefix.
///
/// # Arguments
/// * `name` - The pipe name as a byte slice (without prefix)
///
/// # Returns
/// * `Ok((buffer, len))` - The wide string buffer and its length (excluding null)
/// * `Err(NamedPipeError::NameTooLong)` - If the resulting name is too long
pub fn pipe_name_to_wide(
    name: &[u8],
) -> Result<([u16; MAX_PIPE_NAME_LENGTH], usize), NamedPipeError> {
    let mut buffer = [0u16; MAX_PIPE_NAME_LENGTH];
    let prefix = PIPE_NAME_PREFIX;

    // Calculate total length needed
    let total_len = prefix.len() + name.len();
    if total_len >= MAX_PIPE_NAME_LENGTH {
        return Err(NamedPipeError::NameTooLong);
    }

    // Copy prefix
    let mut pos = 0;
    for byte in prefix.bytes() {
        buffer[pos] = byte as u16;
        pos += 1;
    }

    // Copy name
    for &byte in name {
        buffer[pos] = byte as u16;
        pos += 1;
    }

    // Null terminator
    buffer[pos] = 0;

    Ok((buffer, pos))
}

// ============================================================================
// PipeProcessCredentials
// ============================================================================

/// Process credentials obtained from a named pipe connection.
///
/// On Windows, only the process ID is available directly from the pipe.
/// UID and GID are set to default values as Windows uses a different
/// security model (SIDs instead of numeric UIDs/GIDs).
///
/// For proper Windows identity information, use the [`user_sid()`](Self::user_sid) and
/// [`group_sids()`](Self::group_sids) methods which return the actual Windows Security
/// Identifiers when available.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PipeProcessCredentials {
    /// Process ID of the connected peer.
    pid: u32,
    /// User ID (always 0 on Windows - use Windows SID APIs for actual identity).
    uid: u32,
    /// Group ID (always 0 on Windows - use Windows SID APIs for actual identity).
    gid: u32,
    /// The user's Security Identifier (SID) if available.
    user_sid: Option<super::security_descriptor::Sid>,
    /// The group SIDs the user belongs to, if available.
    group_sids: Option<alloc::vec::Vec<super::security_descriptor::Sid>>,
}

impl PipeProcessCredentials {
    /// Creates new process credentials with the specified PID.
    ///
    /// UID and GID are set to 0 as Windows doesn't use numeric IDs.
    /// SIDs are set to None. Use [`with_sids`](Self::with_sids) to include SID information.
    pub fn new(pid: u32) -> Self {
        Self {
            pid,
            uid: 0,
            gid: 0,
            user_sid: None,
            group_sids: None,
        }
    }

    /// Creates new process credentials with the specified PID and SIDs.
    ///
    /// # Arguments
    /// * `pid` - Process ID of the connected peer
    /// * `user_sid` - The user's Security Identifier
    /// * `group_sids` - The group SIDs the user belongs to
    pub fn with_sids(
        pid: u32,
        user_sid: super::security_descriptor::Sid,
        group_sids: alloc::vec::Vec<super::security_descriptor::Sid>,
    ) -> Self {
        Self {
            pid,
            uid: 0,
            gid: 0,
            user_sid: Some(user_sid),
            group_sids: Some(group_sids),
        }
    }

    /// Returns the process ID of the connected peer.
    pub fn pid(&self) -> u32 {
        self.pid
    }

    /// Returns the user ID (always 0 on Windows).
    ///
    /// Windows uses SIDs instead of numeric UIDs. Use [`user_sid()`](Self::user_sid)
    /// for actual identity information.
    pub fn uid(&self) -> u32 {
        self.uid
    }

    /// Returns the group ID (always 0 on Windows).
    ///
    /// Windows uses SIDs instead of numeric GIDs. Use [`group_sids()`](Self::group_sids)
    /// for actual identity information.
    pub fn gid(&self) -> u32 {
        self.gid
    }

    /// Returns the user's Security Identifier (SID) if available.
    ///
    /// Returns `None` if SID extraction failed during credential retrieval.
    pub fn user_sid(&self) -> Option<&super::security_descriptor::Sid> {
        self.user_sid.as_ref()
    }

    /// Returns the group SIDs the user belongs to, if available.
    ///
    /// Returns `None` if SID extraction failed during credential retrieval.
    pub fn group_sids(&self) -> Option<&[super::security_descriptor::Sid]> {
        self.group_sids.as_deref()
    }
}

// ============================================================================
// NamedPipeServer
// ============================================================================

/// Server-side named pipe that listens for incoming connections.
///
/// The server creates a named pipe instance and waits for clients to connect.
/// Once a client connects, the connected instance is handed over to the returned
/// [`NamedPipeConnection`] and the server immediately creates a fresh instance with
/// the same name, so any number of clients can connect over the lifetime of the
/// server.
///
/// Every instance is created with `FILE_FLAG_OVERLAPPED` to support non-blocking
/// accept operations. A persistent overlapped accept state is maintained so the
/// listening instance stays in listening mode between `try_accept()` calls,
/// allowing clients to connect at any time.
#[cfg(windows)]
pub struct NamedPipeServer {
    /// Null-terminated wide pipe name, used to create new listening instances.
    name_wide: [u16; MAX_PIPE_NAME_LENGTH],
    /// Handle to the listening pipe instance. `INVALID_HANDLE_VALUE` if creating the
    /// replacement instance after a hand-off failed; the next accept retries.
    handle: HANDLE,
    /// Event handle for the persistent overlapped accept.
    /// 0 means no accept is pending; non-zero means ConnectNamedPipe is pending.
    accept_event: HANDLE,
    /// Overlapped structure for the persistent accept operation.
    /// Only valid when accept_event != 0.
    accept_overlapped: OVERLAPPED,
    /// DACL of every instance, derived from the creation mode. `None` keeps the default
    /// DACL (creator, SYSTEM and administrators full access, everybody else read only).
    security: Option<super::security_descriptor::SecurityDescriptor>,
}

// SAFETY: NamedPipeServer contains raw handles (isize) and an OVERLAPPED struct
// which is a plain data struct. All fields are safe to send between threads.
// The pipe handle is not accessed concurrently - it's protected by Mutex in the
// CAL layer.
#[cfg(windows)]
unsafe impl Send for NamedPipeServer {}

#[cfg(windows)]
impl fmt::Debug for NamedPipeServer {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("NamedPipeServer")
            .field("accept_pending", &(self.accept_event != 0))
            .finish_non_exhaustive()
    }
}

/// Outcome of issuing or polling an overlapped `ConnectNamedPipe`.
#[cfg(windows)]
enum AcceptState {
    /// A client is connected to the listening instance.
    Connected,
    /// The accept is pending; the listening instance waits for a client.
    Pending,
}

/// The rights a client needs to connect, exchange messages and switch to message-read mode:
/// FILE_READ_DATA | FILE_WRITE_DATA | FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES |
/// READ_CONTROL | SYNCHRONIZE. Deliberately without FILE_APPEND_DATA, which for a pipe is
/// FILE_CREATE_PIPE_INSTANCE: a client must not be able to serve instances of the pipe.
#[cfg(windows)]
const PIPE_CLIENT_ACCESS: u32 = 0x0012_0183;

/// Builds the DACL of a pipe created with `mode`: the creating user, SYSTEM and the
/// administrators get full access; when the group or others bits grant read and write access,
/// everybody may connect as a client. Returns `None` (default DACL) otherwise.
#[cfg(windows)]
fn pipe_security_descriptor(
    mode: u64,
) -> Result<Option<super::security_descriptor::SecurityDescriptor>, NamedPipeError> {
    use super::security_descriptor::SecurityDescriptor;

    const GROUP_RW: u64 = 0o060;
    const OTHERS_RW: u64 = 0o006;
    if mode & GROUP_RW != GROUP_RW && mode & OTHERS_RW != OTHERS_RW {
        return Ok(None);
    }

    let me = super::process_token::get_process_token_sids(unsafe { GetCurrentProcessId() })
        .map_err(|_| NamedPipeError::UnknownError(0))?;
    let me = me
        .user_sid
        .to_sid_string()
        .ok_or(NamedPipeError::UnknownError(0))?;
    let sddl = alloc::format!(
        "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;{me})(A;;0x{PIPE_CLIENT_ACCESS:x};;;WD)\0"
    );
    SecurityDescriptor::from_sddl(sddl.as_bytes())
        .map(Some)
        .map_err(|_| NamedPipeError::UnknownError(0))
}

#[cfg(windows)]
impl NamedPipeServer {
    /// Creates a new named pipe server.
    ///
    /// # Arguments
    /// * `name` - The pipe name (without the `\\.\pipe\` prefix)
    /// * `mode` - Unix-style permission mode. When it grants the group or others read and
    ///   write access, everybody may connect (see [`pipe_security_descriptor`]); otherwise
    ///   the default DACL lets only the creator, SYSTEM and administrators connect.
    ///
    /// # Returns
    /// * `Ok(NamedPipeServer)` - The created server
    /// * `Err(NamedPipeError)` - If creation failed, [`NamedPipeError::AccessDenied`] in
    ///   particular when another process already serves a pipe of that name
    pub fn create(name: &[u8], mode: u64) -> Result<Self, NamedPipeError> {
        let (name_wide, _name_len) = pipe_name_to_wide(name)?;
        let security = pipe_security_descriptor(mode)?;
        // The first instance must be ours: otherwise a process that created the pipe first
        // would receive the connections of our clients.
        let handle = Self::create_instance(&name_wide, security.as_ref(), true)?;

        Ok(Self {
            name_wide,
            handle,
            accept_event: 0,
            accept_overlapped: unsafe { core::mem::zeroed() },
            security,
        })
    }

    /// Creates a new listening instance of the pipe.
    fn create_instance(
        name_wide: &[u16; MAX_PIPE_NAME_LENGTH],
        security: Option<&super::security_descriptor::SecurityDescriptor>,
        first_instance: bool,
    ) -> Result<HANDLE, NamedPipeError> {
        let security_attrs = match security {
            Some(sd) => sd.as_security_attributes(),
            None => SECURITY_ATTRIBUTES {
                nLength: core::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: core::ptr::null_mut(),
                bInheritHandle: FALSE,
            },
        };
        let first_instance_flag = if first_instance {
            FILE_FLAG_FIRST_PIPE_INSTANCE
        } else {
            0
        };

        // Create the named pipe with FILE_FLAG_OVERLAPPED so that
        // ConnectNamedPipe can be used in non-blocking/timed modes.
        // All I/O on this handle (reads, writes, accepts) must use OVERLAPPED structures.
        // SAFETY: We're calling the Windows API with valid parameters.
        // The name_wide buffer is properly null-terminated.
        let handle = unsafe {
            CreateNamedPipeW(
                name_wide.as_ptr(),
                PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | first_instance_flag, // Bidirectional + overlapped
                PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
                PIPE_UNLIMITED_INSTANCES,
                DEFAULT_PIPE_BUFFER_SIZE,
                DEFAULT_PIPE_BUFFER_SIZE,
                DEFAULT_PIPE_TIMEOUT_MS,
                &security_attrs,
            )
        };

        if handle == INVALID_HANDLE_VALUE {
            let error = unsafe { GetLastError() };
            return Err(NamedPipeError::from_win32(error));
        }

        Ok(handle)
    }

    /// Attempts to accept a connection without blocking.
    ///
    /// Uses persistent overlapped I/O state so the pipe remains in listening
    /// mode between calls. On the first call, `ConnectNamedPipe` is issued and
    /// the overlapped state is stored. Subsequent calls check if a client has
    /// connected without re-issuing the syscall.
    ///
    /// # Returns
    /// * `Ok(Some(connection))` - A client connected
    /// * `Ok(None)` - No client is waiting to connect
    /// * `Err(NamedPipeError)` - An error occurred
    pub fn try_accept(&mut self) -> Result<Option<NamedPipeConnection>, NamedPipeError> {
        self.accept_with_timeout(0)
    }

    /// Waits for a connection with a timeout.
    ///
    /// If a persistent accept is already pending (from a previous `try_accept()` call),
    /// this method reuses it and waits with the given timeout. Otherwise, it starts
    /// a new overlapped accept.
    ///
    /// # Arguments
    /// * `timeout` - Maximum time to wait for a connection
    ///
    /// # Returns
    /// * `Ok(Some(connection))` - A client connected
    /// * `Ok(None)` - Timeout expired without a connection
    /// * `Err(NamedPipeError)` - An error occurred
    pub fn timed_accept(
        &mut self,
        timeout: Duration,
    ) -> Result<Option<NamedPipeConnection>, NamedPipeError> {
        // INFINITE is u32::MAX, so clamp just below it to keep the wait finite.
        let timeout_ms = u32::try_from(timeout.as_millis())
            .unwrap_or(INFINITE - 1)
            .min(INFINITE - 1);
        self.accept_with_timeout(timeout_ms)
    }

    /// Blocks until a client connects.
    ///
    /// If a persistent accept is already pending, waits on it with INFINITE timeout.
    /// Otherwise, starts a new overlapped accept and waits.
    ///
    /// # Returns
    /// * `Ok(connection)` - A client connected
    /// * `Err(NamedPipeError)` - An error occurred
    pub fn blocking_accept(&mut self) -> Result<NamedPipeConnection, NamedPipeError> {
        match self.accept_with_timeout(INFINITE)? {
            Some(connection) => Ok(connection),
            // An INFINITE wait only returns once the accept completed or failed.
            None => Err(NamedPipeError::UnknownError(WAIT_TIMEOUT)),
        }
    }

    /// Returns the raw handle of the listening pipe instance.
    ///
    /// # Safety
    /// The caller must ensure the handle is not closed while still in use.
    pub fn raw_handle(&self) -> HANDLE {
        self.handle
    }

    /// Starts an accept if none is pending and waits up to `timeout_ms` for a client.
    /// On success the connected instance is handed off to the returned connection.
    fn accept_with_timeout(
        &mut self,
        timeout_ms: u32,
    ) -> Result<Option<NamedPipeConnection>, NamedPipeError> {
        if self.handle == INVALID_HANDLE_VALUE {
            self.handle = Self::create_instance(&self.name_wide, self.security.as_ref(), false)?;
        }

        let state = if self.accept_event == 0 {
            self.start_accept()?
        } else {
            AcceptState::Pending
        };

        let state = match state {
            AcceptState::Connected => AcceptState::Connected,
            AcceptState::Pending => self.wait_for_pending_accept(timeout_ms)?,
        };

        match state {
            AcceptState::Connected => Ok(Some(self.hand_off_connected_instance())),
            AcceptState::Pending => Ok(None),
        }
    }

    /// Issues an overlapped `ConnectNamedPipe` on the listening instance.
    fn start_accept(&mut self) -> Result<AcceptState, NamedPipeError> {
        use windows_sys::Win32::System::Threading::CreateEventW;

        let event = unsafe { CreateEventW(core::ptr::null(), TRUE, FALSE, core::ptr::null()) };
        if event == 0 {
            let error = unsafe { GetLastError() };
            return Err(NamedPipeError::from_win32(error));
        }

        self.accept_overlapped = unsafe { core::mem::zeroed() };
        self.accept_overlapped.hEvent = event;
        self.accept_event = event;

        // SAFETY: ConnectNamedPipe with overlapped structure for async operation.
        // The pipe stays in listening state until a client connects or we cancel.
        let result = unsafe { ConnectNamedPipe(self.handle, &mut self.accept_overlapped) };
        if result != 0 {
            // Completed synchronously - nothing is outstanding.
            self.release_accept_event();
            return Ok(AcceptState::Connected);
        }

        let error = unsafe { GetLastError() };
        match error {
            ERROR_IO_PENDING => Ok(AcceptState::Pending),
            ERROR_PIPE_CONNECTED => {
                // The client connected between CreateNamedPipeW and ConnectNamedPipe.
                // No I/O was queued, so the event will never be signaled.
                self.release_accept_event();
                Ok(AcceptState::Connected)
            }
            _ => {
                self.release_accept_event();
                Err(NamedPipeError::from_win32(error))
            }
        }
    }

    /// Waits up to `timeout_ms` for the pending accept to complete.
    fn wait_for_pending_accept(&mut self, timeout_ms: u32) -> Result<AcceptState, NamedPipeError> {
        let wait_result = unsafe { WaitForSingleObject(self.accept_event, timeout_ms) };

        match wait_result {
            WAIT_OBJECT_0 => {
                let mut bytes_transferred: u32 = 0;
                let overlapped_result = unsafe {
                    GetOverlappedResult(
                        self.handle,
                        &self.accept_overlapped,
                        &mut bytes_transferred,
                        FALSE,
                    )
                };
                let error = unsafe { GetLastError() };
                // The accept completed - nothing is outstanding anymore.
                self.release_accept_event();

                if overlapped_result != 0 {
                    Ok(AcceptState::Connected)
                } else {
                    Err(NamedPipeError::from_win32(error))
                }
            }
            // Keep the accept pending - the instance stays in listening state.
            WAIT_TIMEOUT => Ok(AcceptState::Pending),
            WAIT_ABANDONED => {
                self.cancel_pending_accept();
                Err(NamedPipeError::Interrupted)
            }
            _ => {
                let error = unsafe { GetLastError() };
                self.cancel_pending_accept();
                Err(NamedPipeError::from_win32(error))
            }
        }
    }

    /// Transfers ownership of the connected instance to a [`NamedPipeConnection`] and
    /// replaces it with a fresh listening instance so further clients can connect.
    fn hand_off_connected_instance(&mut self) -> NamedPipeConnection {
        let connected = self.handle;
        // If the replacement cannot be created now, the next accept retries.
        self.handle = Self::create_instance(&self.name_wide, self.security.as_ref(), false)
            .unwrap_or(INVALID_HANDLE_VALUE);
        NamedPipeConnection::from_server(connected)
    }

    /// Closes the accept event handle. Must only be used when no overlapped accept is
    /// outstanding: after `ConnectNamedPipe` completed synchronously, failed without
    /// `ERROR_IO_PENDING`, reported `ERROR_PIPE_CONNECTED`, or after the pending accept
    /// completed.
    fn release_accept_event(&mut self) {
        if self.accept_event != 0 {
            unsafe { CloseHandle(self.accept_event) };
            self.accept_event = 0;
            self.accept_overlapped = unsafe { core::mem::zeroed() };
        }
    }

    /// Cancels an outstanding overlapped accept, waits for the cancellation to complete
    /// and closes the event handle. Waiting is only valid while `ConnectNamedPipe` is
    /// pending; otherwise the event is never signaled and the wait never returns.
    fn cancel_pending_accept(&mut self) {
        if self.accept_event != 0 {
            unsafe { CancelIo(self.handle) };
            let mut bytes_transferred: u32 = 0;
            unsafe {
                GetOverlappedResult(
                    self.handle,
                    &self.accept_overlapped,
                    &mut bytes_transferred,
                    TRUE,
                )
            };
            self.release_accept_event();
        }
    }
}

#[cfg(windows)]
impl Drop for NamedPipeServer {
    fn drop(&mut self) {
        // Cancel any pending accept operation first
        self.cancel_pending_accept();

        // SAFETY: CloseHandle is called with a valid handle that we own.
        if self.handle != INVALID_HANDLE_VALUE {
            unsafe { CloseHandle(self.handle) };
        }
    }
}

// Non-Windows stub implementation
#[cfg(not(windows))]
#[derive(Debug)]
pub struct NamedPipeServer {
    _marker: core::marker::PhantomData<()>,
}

#[cfg(not(windows))]
impl NamedPipeServer {
    pub fn create(_name: &[u8], _mode: u64) -> Result<Self, NamedPipeError> {
        Err(NamedPipeError::UnknownError(0))
    }

    pub fn try_accept(&mut self) -> Result<Option<NamedPipeConnection>, NamedPipeError> {
        Err(NamedPipeError::UnknownError(0))
    }

    pub fn timed_accept(
        &mut self,
        _timeout: Duration,
    ) -> Result<Option<NamedPipeConnection>, NamedPipeError> {
        Err(NamedPipeError::UnknownError(0))
    }

    pub fn blocking_accept(&mut self) -> Result<NamedPipeConnection, NamedPipeError> {
        Err(NamedPipeError::UnknownError(0))
    }
}

// ============================================================================
// Overlapped I/O Helpers
// ============================================================================

/// Performs a blocking read on an overlapped pipe handle.
///
/// Creates a temporary OVERLAPPED structure with an event, issues the ReadFile,
/// and waits for completion. This is required because handles opened with
/// FILE_FLAG_OVERLAPPED must always use OVERLAPPED structures for I/O.
#[cfg(windows)]
fn overlapped_read_blocking(handle: HANDLE, buffer: &mut [u8]) -> Result<usize, NamedPipeError> {
    use windows_sys::Win32::System::Threading::CreateEventW;

    let event = unsafe { CreateEventW(core::ptr::null(), TRUE, FALSE, core::ptr::null()) };
    if event == 0 {
        return Err(NamedPipeError::from_win32(unsafe { GetLastError() }));
    }

    let mut overlapped: OVERLAPPED = unsafe { core::mem::zeroed() };
    overlapped.hEvent = event;

    // Note: With overlapped I/O, lpNumberOfBytesRead is unreliable.
    // Always use GetOverlappedResult to get the actual byte count.
    let result = unsafe {
        ReadFile(
            handle,
            buffer.as_mut_ptr() as *mut core::ffi::c_void,
            buffer.len() as u32,
            core::ptr::null_mut(), // Don't use lpNumberOfBytesRead with overlapped
            &mut overlapped,
        )
    };

    let io_result = if result != 0 {
        // Completed synchronously - get byte count from overlapped result
        let mut bytes_transferred: u32 = 0;
        unsafe { GetOverlappedResult(handle, &overlapped, &mut bytes_transferred, FALSE) };
        Ok(bytes_transferred as usize)
    } else {
        let error = unsafe { GetLastError() };
        match error {
            ERROR_IO_PENDING => {
                // Pending - wait for completion
                let mut bytes_transferred: u32 = 0;
                let get_result = unsafe {
                    GetOverlappedResult(handle, &overlapped, &mut bytes_transferred, TRUE)
                };
                if get_result != 0 {
                    Ok(bytes_transferred as usize)
                } else {
                    let error = unsafe { GetLastError() };
                    if error == ERROR_MORE_DATA {
                        // Buffer too small for message, but partial data was read
                        Ok(bytes_transferred as usize)
                    } else {
                        Err(NamedPipeError::from_win32(error))
                    }
                }
            }
            ERROR_MORE_DATA => {
                // Completed synchronously but buffer too small for the full message.
                // The buffer has been filled. Use GetOverlappedResult for byte count.
                let mut bytes_transferred: u32 = 0;
                // GetOverlappedResult will return FALSE with ERROR_MORE_DATA
                unsafe { GetOverlappedResult(handle, &overlapped, &mut bytes_transferred, FALSE) };
                Ok(bytes_transferred as usize)
            }
            _ => Err(NamedPipeError::from_win32(error)),
        }
    };

    unsafe { CloseHandle(event) };
    io_result
}

/// Performs a blocking write on an overlapped pipe handle.
///
/// Creates a temporary OVERLAPPED structure with an event, issues the WriteFile,
/// and waits for completion.
#[cfg(windows)]
fn overlapped_write_blocking(handle: HANDLE, data: &[u8]) -> Result<usize, NamedPipeError> {
    use windows_sys::Win32::System::Threading::CreateEventW;

    let event = unsafe { CreateEventW(core::ptr::null(), TRUE, FALSE, core::ptr::null()) };
    if event == 0 {
        return Err(NamedPipeError::from_win32(unsafe { GetLastError() }));
    }

    let mut overlapped: OVERLAPPED = unsafe { core::mem::zeroed() };
    overlapped.hEvent = event;

    let result = unsafe {
        WriteFile(
            handle,
            data.as_ptr(),
            data.len() as u32,
            core::ptr::null_mut(),
            &mut overlapped,
        )
    };

    let io_result = if result != 0 {
        // Synchronous completion - use GetOverlappedResult for reliable byte count
        let mut bytes_transferred: u32 = 0;
        unsafe {
            GetOverlappedResult(handle, &overlapped, &mut bytes_transferred, FALSE);
        }
        Ok(bytes_transferred as usize)
    } else {
        let error = unsafe { GetLastError() };
        match error {
            ERROR_IO_PENDING => {
                // Wait for the write to complete
                let mut bytes_transferred: u32 = 0;
                let get_result = unsafe {
                    GetOverlappedResult(handle, &overlapped, &mut bytes_transferred, TRUE)
                };
                if get_result != 0 {
                    Ok(bytes_transferred as usize)
                } else {
                    Err(NamedPipeError::from_win32(unsafe { GetLastError() }))
                }
            }
            _ => Err(NamedPipeError::from_win32(error)),
        }
    };

    unsafe { CloseHandle(event) };
    io_result
}

// ============================================================================
// NamedPipeConnection
// ============================================================================

/// A connection to a named pipe, used for bidirectional communication.
///
/// This struct represents either:
/// - The server side of a connection (after accepting a client)
/// - The client side of a connection (after connecting to a server)
#[cfg(windows)]
pub struct NamedPipeConnection {
    /// Handle to the connected pipe.
    handle: HANDLE,
    /// Whether this is the server side of the connection.
    is_server_side: bool,
    /// Whether the handle was opened with FILE_FLAG_OVERLAPPED.
    /// Server-side connections use overlapped I/O; client-side do not.
    is_overlapped: bool,
    /// Cached client process ID (lazily fetched).
    cached_client_pid: Option<u32>,
    /// Server side: the client's user and group SIDs, taken from its identity handshake.
    client_sids: Option<super::process_token::TokenSids>,
}

#[cfg(windows)]
impl fmt::Debug for NamedPipeConnection {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("NamedPipeConnection")
            .field("is_server_side", &self.is_server_side)
            .field("is_overlapped", &self.is_overlapped)
            .field("cached_client_pid", &self.cached_client_pid)
            .finish_non_exhaustive()
    }
}

#[cfg(windows)]
impl NamedPipeConnection {
    /// Creates a connection from the server side (internal use).
    ///
    /// # Arguments
    /// * `handle` - The pipe handle from the server
    ///
    /// # Handle Ownership Warning
    /// The handle is NOT owned by this connection when created from server.
    /// The server retains ownership of the underlying handle.
    ///
    /// **IMPORTANT:** This connection holds a reference to the server's handle. If the server
    /// calls `disconnect()` or is dropped, this connection's handle becomes invalid (stale).
    /// Callers must ensure the server outlives any connections returned from `accept()` methods.
    ///
    /// A future improvement could use `DuplicateHandle` to create an independent handle copy
    /// for each server-side connection, but this would require additional cleanup logic.
    fn from_server(handle: HANDLE) -> Self {
        let mut connection = Self {
            handle,
            is_server_side: true,
            is_overlapped: true, // Server pipes are created with FILE_FLAG_OVERLAPPED
            cached_client_pid: None,
            client_sids: None,
        };
        connection.receive_identity_handshake();
        connection
    }

    /// Reads the server's answer to the [`IDENTITY_HANDSHAKE`], which carries the server's user
    /// SID, and allows that user to duplicate handles out of and into this process: handles
    /// are exchanged by the server alone, which cannot open the process of another user
    /// otherwise.
    fn allow_server_handle_duplication(&self) {
        let mut buffer = [0u8; IDENTITY_HANDSHAKE.len() + 68];
        let n = match self.timed_read(&mut buffer, IDENTITY_HANDSHAKE_TIMEOUT) {
            Ok(n)
                if n > IDENTITY_HANDSHAKE.len()
                    && buffer[..IDENTITY_HANDSHAKE.len()] == *IDENTITY_HANDSHAKE =>
            {
                n
            }
            other => {
                std::eprintln!(
                    "iceoryx2: the pipe server did not answer the identity handshake ({other:?})."
                );
                return;
            }
        };
        let server =
            super::security_descriptor::Sid::from_bytes(&buffer[IDENTITY_HANDSHAKE.len()..n]);
        let me = super::process_token::get_process_token_sids(unsafe {
            windows_sys::Win32::System::Threading::GetCurrentProcessId()
        });
        if me.is_ok_and(|me| me.user_sid == server) {
            return;
        }
        if let Err(e) = super::handle_passing::allow_handle_duplication_by(&server) {
            std::eprintln!(
                "iceoryx2: allowing the pipe server to exchange handles failed (Win32 error {e})."
            );
        }
    }

    /// Reads the client's [`IDENTITY_HANDSHAKE`] and impersonates the client to learn its user
    /// and group SIDs. Windows only allows impersonating a pipe client after something was
    /// read from the pipe; impersonation works for every client, whereas opening the client's
    /// process token works only for processes of the same user (or for administrators).
    fn receive_identity_handshake(&mut self) {
        let mut buffer = [0u8; IDENTITY_HANDSHAKE.len()];
        match self.timed_read(&mut buffer, IDENTITY_HANDSHAKE_TIMEOUT) {
            Ok(n) if n == buffer.len() && buffer == *IDENTITY_HANDSHAKE => {
                match super::process_token::get_client_token_sids(self.handle) {
                    Ok(sids) => self.client_sids = Some(sids),
                    Err(e) => std::eprintln!(
                        "iceoryx2: impersonating the pipe client failed ({e}); falling back to its process token."
                    ),
                }
                // Answer with our user SID, so that a client of another user can allow us
                // to exchange handles with it.
                let mut reply = IDENTITY_HANDSHAKE.to_vec();
                if let Ok(me) = super::process_token::get_process_token_sids(unsafe {
                    windows_sys::Win32::System::Threading::GetCurrentProcessId()
                }) {
                    reply.extend_from_slice(me.user_sid.as_bytes());
                }
                if let Err(e) = self.write(&reply) {
                    std::eprintln!("iceoryx2: answering the identity handshake failed ({e:?}).");
                }
            }
            other => std::eprintln!(
                "iceoryx2: the pipe client sent no identity handshake ({other:?}); falling back to its process token."
            ),
        }
    }

    /// Connects to an existing named pipe server.
    ///
    /// # Arguments
    /// * `name` - The pipe name (without the `\\.\pipe\` prefix)
    ///
    /// # Returns
    /// * `Ok(NamedPipeConnection)` - Successfully connected
    /// * `Err(NamedPipeError)` - Connection failed
    pub fn connect(name: &[u8]) -> Result<Self, NamedPipeError> {
        let (name_wide, _) = pipe_name_to_wide(name)?;

        // The server keeps one listening instance; while it hands a connected instance off and
        // creates the next one, concurrent clients get ERROR_PIPE_BUSY and wait for it.
        const BUSY_RETRIES: u32 = 10;
        let mut attempt = 0;
        let handle = loop {
            // SAFETY: CreateFileW is called with valid parameters to open the named pipe.
            let handle = unsafe {
                CreateFileW(
                    name_wide.as_ptr(),
                    PIPE_CLIENT_ACCESS,
                    FILE_SHARE_READ | FILE_SHARE_WRITE,
                    core::ptr::null(),
                    OPEN_EXISTING,
                    // Synchronous I/O; the server may identify us but not act as us.
                    SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
                    0, // No template file
                )
            };
            if handle != INVALID_HANDLE_VALUE {
                break handle;
            }

            let error = unsafe { GetLastError() };
            attempt += 1;
            if error != ERROR_PIPE_BUSY || attempt > BUSY_RETRIES {
                return Err(NamedPipeError::from_win32(error));
            }
            // SAFETY: the name is NUL-terminated. A failed wait (e.g. the pipe vanished) is
            // reported by the next CreateFileW.
            unsafe { WaitNamedPipeW(name_wide.as_ptr(), DEFAULT_PIPE_TIMEOUT_MS) };
        };

        // Set the pipe to message-read mode
        let mode: u32 = PIPE_READMODE_MESSAGE;
        // SAFETY: SetNamedPipeHandleState is called with a valid handle.
        let result = unsafe {
            SetNamedPipeHandleState(handle, &mode, core::ptr::null_mut(), core::ptr::null_mut())
        };

        if result == 0 {
            let error = unsafe { GetLastError() };
            unsafe { CloseHandle(handle) };
            return Err(NamedPipeError::from_win32(error));
        }

        let connection = Self {
            handle,
            is_server_side: false,
            is_overlapped: false, // Client connections use synchronous I/O
            cached_client_pid: None,
            client_sids: None,
        };
        connection.write(IDENTITY_HANDSHAKE)?;
        connection.allow_server_handle_duplication();
        Ok(connection)
    }

    /// Returns the process ID of the connected client.
    ///
    /// This is only valid when called from the server side.
    ///
    /// # Returns
    /// * `Ok(pid)` - The client's process ID
    /// * `Err(NamedPipeError)` - Failed to get the PID
    pub fn client_process_id(&mut self) -> Result<u32, NamedPipeError> {
        // Return cached value if available
        if let Some(pid) = self.cached_client_pid {
            return Ok(pid);
        }

        let mut pid: u32 = 0;

        // SAFETY: GetNamedPipeClientProcessId is called with a valid handle.
        let result = unsafe { GetNamedPipeClientProcessId(self.handle, &mut pid) };

        if result != 0 {
            self.cached_client_pid = Some(pid);
            Ok(pid)
        } else {
            let error = unsafe { GetLastError() };
            Err(NamedPipeError::from_win32(error))
        }
    }

    /// Returns the process ID of the server the client is connected to.
    ///
    /// This is only valid when called from the client side.
    ///
    /// # Returns
    /// * `Ok(pid)` - The server's process ID
    /// * `Err(NamedPipeError)` - Failed to get the PID
    pub fn server_process_id(&self) -> Result<u32, NamedPipeError> {
        let mut pid: u32 = 0;

        // SAFETY: GetNamedPipeServerProcessId is called with a valid handle.
        let result = unsafe { GetNamedPipeServerProcessId(self.handle, &mut pid) };

        if result != 0 {
            Ok(pid)
        } else {
            let error = unsafe { GetLastError() };
            Err(NamedPipeError::from_win32(error))
        }
    }

    /// Returns the credentials of the connected peer.
    ///
    /// On Windows, this retrieves the process ID via `GetNamedPipeClientProcessId` and
    /// extracts the client's Security Identifiers (SIDs) by opening the client's process
    /// token directly. If SID extraction fails (e.g., due to insufficient privileges),
    /// credentials are returned with PID only.
    ///
    /// # Returns
    /// * `Ok(credentials)` - The peer's credentials (with or without SIDs)
    /// * `Err(NamedPipeError)` - Failed to get basic credentials (PID)
    pub fn peer_credentials(&mut self) -> Result<PipeProcessCredentials, NamedPipeError> {
        let pid = self.client_process_id()?;

        if let Some(sids) = &self.client_sids {
            return Ok(PipeProcessCredentials::with_sids(
                pid,
                sids.user_sid.clone(),
                sids.group_sids.clone(),
            ));
        }

        // Extract SIDs by opening the client's process token directly.
        // This avoids ImpersonateNamedPipeClient which requires a read from the
        // pipe before it can be called (Windows error 1368).
        match super::process_token::get_process_token_sids(pid) {
            Ok(token_sids) => Ok(PipeProcessCredentials::with_sids(
                pid,
                token_sids.user_sid,
                token_sids.group_sids,
            )),
            Err(e) => {
                // SID extraction failed — log the specific error for diagnostics.
                // Common cause: insufficient privileges to open client's process token.
                std::eprintln!(
                    "iceoryx2: peer_credentials SID extraction failed (pid={}): {}. \
                     Falling back to PID-only credentials.",
                    pid,
                    e
                );
                Ok(PipeProcessCredentials::new(pid))
            }
        }
    }

    /// Writes data to the pipe (blocking).
    ///
    /// # Arguments
    /// * `data` - The data to write
    ///
    /// # Returns
    /// * `Ok(bytes_written)` - Number of bytes written
    /// * `Err(NamedPipeError)` - Write failed
    pub fn write(&self, data: &[u8]) -> Result<usize, NamedPipeError> {
        if self.is_overlapped {
            return overlapped_write_blocking(self.handle, data);
        }

        let mut bytes_written: u32 = 0;

        // SAFETY: WriteFile is called with valid parameters.
        let result = unsafe {
            WriteFile(
                self.handle,
                data.as_ptr(),
                data.len() as u32,
                &mut bytes_written,
                core::ptr::null_mut(),
            )
        };

        if result != 0 {
            Ok(bytes_written as usize)
        } else {
            let error = unsafe { GetLastError() };
            Err(NamedPipeError::from_win32(error))
        }
    }

    /// Attempts to write data without blocking.
    ///
    /// # Arguments
    /// * `data` - The data to write
    ///
    /// # Returns
    /// * `Ok(bytes_written)` - Number of bytes written (may be 0 if would block)
    /// * `Err(NamedPipeError)` - Write failed
    pub fn try_write(&self, data: &[u8]) -> Result<usize, NamedPipeError> {
        if self.is_overlapped {
            // For overlapped handles, writes to named pipes with sufficient buffer
            // typically complete immediately, so blocking write is acceptable here.
            return overlapped_write_blocking(self.handle, data);
        }

        // For non-blocking write, we use the same approach but check for would-block errors
        let mut bytes_written: u32 = 0;

        // SAFETY: WriteFile is called with valid parameters.
        let result = unsafe {
            WriteFile(
                self.handle,
                data.as_ptr(),
                data.len() as u32,
                &mut bytes_written,
                core::ptr::null_mut(),
            )
        };

        if result != 0 {
            Ok(bytes_written as usize)
        } else {
            let error = unsafe { GetLastError() };
            if error == ERROR_IO_PENDING {
                Ok(0)
            } else {
                Err(NamedPipeError::from_win32(error))
            }
        }
    }

    /// Reads data from the pipe (blocking).
    ///
    /// # Arguments
    /// * `buffer` - Buffer to read into
    ///
    /// # Returns
    /// * `Ok(bytes_read)` - Number of bytes read
    /// * `Err(NamedPipeError)` - Read failed
    pub fn read(&self, buffer: &mut [u8]) -> Result<usize, NamedPipeError> {
        if self.is_overlapped {
            return overlapped_read_blocking(self.handle, buffer);
        }

        let mut bytes_read: u32 = 0;

        // SAFETY: ReadFile is called with valid parameters.
        let result = unsafe {
            ReadFile(
                self.handle,
                buffer.as_mut_ptr() as *mut core::ffi::c_void,
                buffer.len() as u32,
                &mut bytes_read,
                core::ptr::null_mut(),
            )
        };

        if result != 0 {
            Ok(bytes_read as usize)
        } else {
            let error = unsafe { GetLastError() };
            if error == ERROR_MORE_DATA {
                // Message was larger than buffer, but we got some data
                Ok(bytes_read as usize)
            } else {
                Err(NamedPipeError::from_win32(error))
            }
        }
    }

    /// Attempts to read data without blocking.
    ///
    /// # Arguments
    /// * `buffer` - Buffer to read into
    ///
    /// # Returns
    /// * `Ok(bytes_read)` - Number of bytes read (0 if no data available)
    /// * `Err(NamedPipeError)` - Read failed
    pub fn try_read(&self, buffer: &mut [u8]) -> Result<usize, NamedPipeError> {
        // First, peek to see if data is available
        let mut bytes_available: u32 = 0;

        // SAFETY: PeekNamedPipe is called with valid parameters.
        let peek_result = unsafe {
            PeekNamedPipe(
                self.handle,
                core::ptr::null_mut(),
                0,
                core::ptr::null_mut(),
                &mut bytes_available,
                core::ptr::null_mut(),
            )
        };

        if peek_result == 0 {
            let error = unsafe { GetLastError() };
            return Err(NamedPipeError::from_win32(error));
        }

        if bytes_available == 0 {
            return Ok(0);
        }

        // Data is available, read it (for overlapped handles, this uses overlapped I/O)
        self.read(buffer)
    }

    /// Reads data from the pipe with a timeout.
    ///
    /// # Arguments
    /// * `buffer` - Buffer to read into
    /// * `timeout` - Maximum time to wait for data
    ///
    /// # Returns
    /// * `Ok(bytes_read)` - Number of bytes read
    /// * `Err(NamedPipeError::TimedOut)` - Timeout expired
    /// * `Err(NamedPipeError)` - Read failed
    ///
    /// # Implementation Note
    /// **TODO:** This implementation uses busy-waiting with `std::thread::sleep` polling,
    /// which is not optimal for performance. A better implementation would use overlapped
    /// I/O with `WaitForSingleObject` similar to `timed_accept()`. The current approach
    /// polls every 10ms which adds latency and consumes CPU cycles unnecessarily.
    ///
    /// The use of `std::time::Instant` and `std::thread::sleep` is acceptable because
    /// the PAL crate enables std on Windows platforms.
    pub fn timed_read(
        &self,
        buffer: &mut [u8],
        timeout: Duration,
    ) -> Result<usize, NamedPipeError> {
        use std::time::Instant;

        let deadline = Instant::now() + timeout;
        let poll_interval = Duration::from_millis(10);

        loop {
            match self.try_read(buffer) {
                Ok(0) => {
                    // No data available, check timeout
                    if Instant::now() >= deadline {
                        return Err(NamedPipeError::TimedOut);
                    }
                    std::thread::sleep(poll_interval.min(deadline - Instant::now()));
                }
                Ok(n) => return Ok(n),
                Err(e) => return Err(e),
            }
        }
    }

    /// Reads data from the pipe, blocking until data is available.
    ///
    /// # Arguments
    /// * `buffer` - Buffer to read into
    ///
    /// # Returns
    /// * `Ok(bytes_read)` - Number of bytes read
    /// * `Err(NamedPipeError)` - Read failed
    pub fn blocking_read(&self, buffer: &mut [u8]) -> Result<usize, NamedPipeError> {
        // The default read is already blocking
        self.read(buffer)
    }

    /// Flushes the pipe, ensuring all written data is sent.
    ///
    /// # Returns
    /// * `Ok(())` - Flush successful
    /// * `Err(NamedPipeError)` - Flush failed
    pub fn flush(&self) -> Result<(), NamedPipeError> {
        // SAFETY: FlushFileBuffers is called with a valid handle.
        let result = unsafe { FlushFileBuffers(self.handle) };

        if result != 0 {
            Ok(())
        } else {
            let error = unsafe { GetLastError() };
            Err(NamedPipeError::from_win32(error))
        }
    }

    /// Returns the raw handle to the pipe.
    ///
    /// # Safety
    /// The caller must ensure the handle is not closed while still in use.
    pub fn raw_handle(&self) -> HANDLE {
        self.handle
    }

    /// Returns whether this is the server side of the connection.
    pub fn is_server_side(&self) -> bool {
        self.is_server_side
    }
}

#[cfg(windows)]
impl Drop for NamedPipeConnection {
    fn drop(&mut self) {
        if self.handle == INVALID_HANDLE_VALUE {
            return;
        }

        // Server-side connections own the pipe instance handed off by the server, which is
        // never reused, so it is closed and not disconnected: DisconnectNamedPipe would
        // discard what the client has not read yet (e.g. the last response).
        // SAFETY: CloseHandle is called with a valid handle that we own.
        unsafe { CloseHandle(self.handle) };
    }
}

// Non-Windows stub implementation
#[cfg(not(windows))]
#[derive(Debug)]
pub struct NamedPipeConnection {
    _marker: core::marker::PhantomData<()>,
}

#[cfg(not(windows))]
impl NamedPipeConnection {
    fn from_server(_handle: isize) -> Self {
        Self {
            _marker: core::marker::PhantomData,
        }
    }

    pub fn connect(_name: &[u8]) -> Result<Self, NamedPipeError> {
        Err(NamedPipeError::UnknownError(0))
    }

    pub fn client_process_id(&mut self) -> Result<u32, NamedPipeError> {
        Err(NamedPipeError::UnknownError(0))
    }

    pub fn server_process_id(&self) -> Result<u32, NamedPipeError> {
        Err(NamedPipeError::UnknownError(0))
    }

    pub fn peer_credentials(&mut self) -> Result<PipeProcessCredentials, NamedPipeError> {
        Err(NamedPipeError::UnknownError(0))
    }

    pub fn write(&self, _data: &[u8]) -> Result<usize, NamedPipeError> {
        Err(NamedPipeError::UnknownError(0))
    }

    pub fn try_write(&self, _data: &[u8]) -> Result<usize, NamedPipeError> {
        Err(NamedPipeError::UnknownError(0))
    }

    pub fn read(&self, _buffer: &mut [u8]) -> Result<usize, NamedPipeError> {
        Err(NamedPipeError::UnknownError(0))
    }

    pub fn try_read(&self, _buffer: &mut [u8]) -> Result<usize, NamedPipeError> {
        Err(NamedPipeError::UnknownError(0))
    }

    pub fn timed_read(
        &self,
        _buffer: &mut [u8],
        _timeout: Duration,
    ) -> Result<usize, NamedPipeError> {
        Err(NamedPipeError::UnknownError(0))
    }

    pub fn blocking_read(&self, _buffer: &mut [u8]) -> Result<usize, NamedPipeError> {
        Err(NamedPipeError::UnknownError(0))
    }

    pub fn flush(&self) -> Result<(), NamedPipeError> {
        Err(NamedPipeError::UnknownError(0))
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[cfg(windows)]
mod tests {
    extern crate std;
    use super::*;
    use alloc::format;
    use alloc::vec;

    #[test]
    fn test_pipe_name_to_wide_basic() {
        let name = b"test_pipe";
        let result = pipe_name_to_wide(name);
        assert!(result.is_ok());

        let (buffer, len) = result.unwrap();
        assert_eq!(len, PIPE_NAME_PREFIX.len() + name.len());

        // Verify the prefix
        for (i, c) in PIPE_NAME_PREFIX.chars().enumerate() {
            assert_eq!(buffer[i], c as u16);
        }

        // Verify the name
        for (i, &c) in name.iter().enumerate() {
            assert_eq!(buffer[PIPE_NAME_PREFIX.len() + i], c as u16);
        }

        // Verify null terminator
        assert_eq!(buffer[len], 0);
    }

    #[test]
    fn test_pipe_name_to_wide_too_long() {
        let name = [b'a'; MAX_PIPE_NAME_LENGTH];
        let result = pipe_name_to_wide(&name);
        assert!(matches!(result, Err(NamedPipeError::NameTooLong)));
    }

    #[test]
    fn test_pipe_process_credentials_new() {
        let creds = PipeProcessCredentials::new(1234);
        assert_eq!(creds.pid(), 1234);
        assert_eq!(creds.uid(), 0);
        assert_eq!(creds.gid(), 0);
        assert!(creds.user_sid().is_none());
        assert!(creds.group_sids().is_none());
    }

    #[test]
    fn test_pipe_process_credentials_with_sids() {
        use super::super::security_descriptor::Sid;

        let user_sid = Sid::everyone();
        let group_sids = vec![Sid::local_system()];

        let creds = PipeProcessCredentials::with_sids(1234, user_sid.clone(), group_sids.clone());
        assert_eq!(creds.pid(), 1234);
        assert_eq!(creds.uid(), 0);
        assert_eq!(creds.gid(), 0);
        assert_eq!(creds.user_sid(), Some(&user_sid));
        assert_eq!(creds.group_sids(), Some(group_sids.as_slice()));
    }

    #[test]
    fn test_named_pipe_error_display() {
        assert_eq!(
            format!("{}", NamedPipeError::NameTooLong),
            "Pipe name exceeds maximum length"
        );
        assert_eq!(format!("{}", NamedPipeError::AccessDenied), "Access denied");
        assert_eq!(
            format!("{}", NamedPipeError::UnknownError(42)),
            "Unknown error (code: 42)"
        );
    }

    #[test]
    fn test_named_pipe_error_from_win32() {
        assert_eq!(
            NamedPipeError::from_win32(ERROR_ACCESS_DENIED),
            NamedPipeError::AccessDenied
        );
        assert_eq!(
            NamedPipeError::from_win32(ERROR_FILE_NOT_FOUND),
            NamedPipeError::DoesNotExist
        );
        assert_eq!(
            NamedPipeError::from_win32(ERROR_PIPE_BUSY),
            NamedPipeError::PipeBusy
        );
        assert_eq!(
            NamedPipeError::from_win32(ERROR_BROKEN_PIPE),
            NamedPipeError::BrokenPipe
        );
    }

    // Integration tests would require actual Windows pipes
    // These are stubs for the test framework

    #[test]
    #[ignore] // Requires Windows
    fn test_server_create_and_accept() {
        // This test would create a server and accept a connection
        // Requires running on Windows
    }

    #[test]
    #[ignore] // Requires Windows
    fn test_client_connect() {
        // This test would connect to a server
        // Requires running on Windows
    }

    #[test]
    #[ignore] // Requires Windows
    fn test_read_write() {
        // This test would verify read/write operations
        // Requires running on Windows
    }

    #[test]
    #[ignore] // Requires Windows
    fn test_peer_credentials() {
        // This test would verify credential retrieval
        // Requires running on Windows
    }
}

#[cfg(test)]
#[cfg(not(windows))]
mod tests {
    extern crate std;
    use super::*;
    use alloc::format;

    #[test]
    fn test_pipe_name_to_wide_basic() {
        let name = b"test_pipe";
        let result = pipe_name_to_wide(name);
        assert!(result.is_ok());

        let (buffer, len) = result.unwrap();
        assert_eq!(len, PIPE_NAME_PREFIX.len() + name.len());
    }

    #[test]
    fn test_pipe_name_to_wide_too_long() {
        let name = [b'a'; MAX_PIPE_NAME_LENGTH];
        let result = pipe_name_to_wide(&name);
        assert!(matches!(result, Err(NamedPipeError::NameTooLong)));
    }

    #[test]
    fn test_pipe_process_credentials_new() {
        let creds = PipeProcessCredentials::new(1234);
        assert_eq!(creds.pid(), 1234);
        assert_eq!(creds.uid(), 0);
        assert_eq!(creds.gid(), 0);
        assert!(creds.user_sid().is_none());
        assert!(creds.group_sids().is_none());
    }

    #[test]
    fn test_named_pipe_error_display() {
        assert_eq!(
            format!("{}", NamedPipeError::NameTooLong),
            "Pipe name exceeds maximum length"
        );
    }

    #[test]
    fn test_stub_implementations_return_errors() {
        let mut server = NamedPipeServer {
            _marker: core::marker::PhantomData,
        };

        assert!(server.try_accept().is_err());
        assert!(server.timed_accept(Duration::from_secs(1)).is_err());
        assert!(server.blocking_accept().is_err());

        assert!(NamedPipeServer::create(b"test", 0).is_err());
        assert!(NamedPipeConnection::connect(b"test").is_err());
    }
}
