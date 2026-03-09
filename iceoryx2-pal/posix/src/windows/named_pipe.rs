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
    CloseHandle, GetLastError, ERROR_ACCESS_DENIED, ERROR_ALREADY_EXISTS, ERROR_BROKEN_PIPE,
    ERROR_FILE_NOT_FOUND, ERROR_HANDLE_EOF, ERROR_INVALID_HANDLE, ERROR_IO_PENDING,
    ERROR_MORE_DATA, ERROR_NO_DATA, ERROR_PIPE_BUSY, ERROR_PIPE_CONNECTED, ERROR_PIPE_LISTENING,
    ERROR_PIPE_NOT_CONNECTED, FALSE, GENERIC_READ, GENERIC_WRITE, HANDLE, INVALID_HANDLE_VALUE,
    TRUE, WAIT_ABANDONED, WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT,
};

#[cfg(windows)]
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FlushFileBuffers, ReadFile, WriteFile, FILE_FLAG_OVERLAPPED, FILE_SHARE_READ,
    FILE_SHARE_WRITE, OPEN_EXISTING, PIPE_ACCESS_DUPLEX,
};

#[cfg(windows)]
use windows_sys::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, GetNamedPipeClientProcessId,
    PeekNamedPipe, SetNamedPipeHandleState, PIPE_READMODE_MESSAGE, PIPE_TYPE_MESSAGE,
    PIPE_UNLIMITED_INSTANCES, PIPE_WAIT,
};

#[cfg(windows)]
use windows_sys::Win32::System::Threading::{WaitForSingleObject, INFINITE};

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
/// The server creates a named pipe and waits for clients to connect.
/// Once a client connects, a [`NamedPipeConnection`] is returned for
/// bidirectional communication.
///
/// The pipe is created with `FILE_FLAG_OVERLAPPED` to support non-blocking
/// accept operations. A persistent overlapped accept state is maintained
/// so the pipe stays in listening mode between `try_accept()` calls,
/// allowing clients to connect at any time.
#[cfg(windows)]
pub struct NamedPipeServer {
    /// Handle to the named pipe instance.
    handle: HANDLE,
    /// Whether a client is currently connected.
    is_connected: bool,
    /// Event handle for persistent overlapped accept.
    /// 0 means no accept is pending; non-zero means ConnectNamedPipe is pending.
    accept_event: HANDLE,
    /// Overlapped structure for persistent accept operation.
    /// Only valid when accept_event != 0.
    accept_overlapped: OVERLAPPED,
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
            .field("is_connected", &self.is_connected)
            .field("accept_pending", &(self.accept_event != 0))
            .finish_non_exhaustive()
    }
}

#[cfg(windows)]
impl NamedPipeServer {
    /// Creates a new named pipe server.
    ///
    /// # Arguments
    /// * `name` - The pipe name (without the `\\.\pipe\` prefix)
    /// * `mode` - Unix-style permission mode (currently ignored - see note below)
    ///
    /// # Returns
    /// * `Ok(NamedPipeServer)` - The created server
    /// * `Err(NamedPipeError)` - If creation failed
    ///
    /// # Note on Security
    /// **TODO:** Windows security descriptors are not yet implemented. The `mode` parameter
    /// is currently ignored and a NULL security descriptor is used, which grants default
    /// access permissions. To implement proper security:
    /// - Convert Unix-style mode bits to Windows DACLs
    /// - Use `InitializeSecurityDescriptor` and `SetSecurityDescriptorDacl`
    /// - Consider using `ConvertStringSecurityDescriptorToSecurityDescriptor` for simpler cases
    ///
    /// # Safety
    /// This function calls Windows API functions internally.
    #[allow(unused_variables)] // mode parameter is not yet implemented
    pub fn create(name: &[u8], mode: u64) -> Result<Self, NamedPipeError> {
        let (name_wide, _name_len) = pipe_name_to_wide(name)?;

        // TODO: Implement proper security descriptor based on mode parameter.
        // Currently using NULL security descriptor which grants default access.
        // Windows uses DACLs/SACLs instead of Unix permission bits, so a proper
        // implementation would need to translate mode bits to appropriate ACEs.
        let security_attrs = SECURITY_ATTRIBUTES {
            nLength: core::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: core::ptr::null_mut(),
            bInheritHandle: FALSE,
        };

        // Create the named pipe with FILE_FLAG_OVERLAPPED so that
        // ConnectNamedPipe can be used in non-blocking/timed modes.
        // All I/O on this handle (reads, writes, accepts) must use OVERLAPPED structures.
        // SAFETY: We're calling the Windows API with valid parameters.
        // The name_wide buffer is properly null-terminated.
        let handle = unsafe {
            CreateNamedPipeW(
                name_wide.as_ptr(),
                PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED, // Bidirectional + overlapped
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

        Ok(Self {
            handle,
            is_connected: false,
            accept_event: 0,
            accept_overlapped: unsafe { core::mem::zeroed() },
        })
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
        if self.is_connected {
            return Err(NamedPipeError::AlreadyConnected);
        }

        // If no accept is pending, start one
        if self.accept_event == 0 {
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
                // Immediate success
                self.cleanup_accept_state();
                self.is_connected = true;
                return Ok(Some(NamedPipeConnection::from_server(self.handle)));
            }

            let error = unsafe { GetLastError() };
            match error {
                ERROR_IO_PENDING => {
                    // Accept is now pending - fall through to check below
                }
                ERROR_PIPE_CONNECTED => {
                    // Client already connected
                    self.cleanup_accept_state();
                    self.is_connected = true;
                    return Ok(Some(NamedPipeConnection::from_server(self.handle)));
                }
                _ => {
                    self.cleanup_accept_state();
                    return Err(NamedPipeError::from_win32(error));
                }
            }
        }

        // Check if the pending accept has completed (non-blocking)
        let wait_result = unsafe { WaitForSingleObject(self.accept_event, 0) };

        match wait_result {
            WAIT_OBJECT_0 => {
                // Client connected
                let mut bytes_transferred: u32 = 0;
                let overlapped_result = unsafe {
                    GetOverlappedResult(
                        self.handle,
                        &self.accept_overlapped,
                        &mut bytes_transferred,
                        FALSE,
                    )
                };

                self.cleanup_accept_state();

                if overlapped_result != 0 {
                    self.is_connected = true;
                    Ok(Some(NamedPipeConnection::from_server(self.handle)))
                } else {
                    let error = unsafe { GetLastError() };
                    Err(NamedPipeError::from_win32(error))
                }
            }
            WAIT_TIMEOUT => {
                // No client yet - keep the accept pending (pipe stays in listening state)
                Ok(None)
            }
            _ => {
                let error = unsafe { GetLastError() };
                self.cleanup_accept_state();
                Err(NamedPipeError::from_win32(error))
            }
        }
    }

    /// Cancels any pending overlapped accept and cleans up the event handle.
    fn cleanup_accept_state(&mut self) {
        if self.accept_event != 0 {
            // Cancel any pending I/O before closing the event
            unsafe { CancelIo(self.handle) };
            // Wait for the cancellation to complete
            let mut bytes_transferred: u32 = 0;
            unsafe {
                GetOverlappedResult(
                    self.handle,
                    &self.accept_overlapped,
                    &mut bytes_transferred,
                    TRUE,
                )
            };
            unsafe { CloseHandle(self.accept_event) };
            self.accept_event = 0;
            self.accept_overlapped = unsafe { core::mem::zeroed() };
        }
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
        if self.is_connected {
            return Err(NamedPipeError::AlreadyConnected);
        }

        // If no accept is pending, start one
        if self.accept_event == 0 {
            use windows_sys::Win32::System::Threading::CreateEventW;

            let event = unsafe { CreateEventW(core::ptr::null(), TRUE, FALSE, core::ptr::null()) };
            if event == 0 {
                let error = unsafe { GetLastError() };
                return Err(NamedPipeError::from_win32(error));
            }

            self.accept_overlapped = unsafe { core::mem::zeroed() };
            self.accept_overlapped.hEvent = event;
            self.accept_event = event;

            let result = unsafe { ConnectNamedPipe(self.handle, &mut self.accept_overlapped) };

            if result != 0 {
                self.cleanup_accept_state();
                self.is_connected = true;
                return Ok(Some(NamedPipeConnection::from_server(self.handle)));
            }

            let error = unsafe { GetLastError() };
            match error {
                ERROR_IO_PENDING => { /* fall through to wait */ }
                ERROR_PIPE_CONNECTED => {
                    self.cleanup_accept_state();
                    self.is_connected = true;
                    return Ok(Some(NamedPipeConnection::from_server(self.handle)));
                }
                _ => {
                    self.cleanup_accept_state();
                    return Err(NamedPipeError::from_win32(error));
                }
            }
        }

        // Wait for the pending accept with timeout
        let timeout_ms = timeout.as_millis() as u32;
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

                self.cleanup_accept_state();

                if overlapped_result != 0 {
                    self.is_connected = true;
                    Ok(Some(NamedPipeConnection::from_server(self.handle)))
                } else {
                    let error = unsafe { GetLastError() };
                    Err(NamedPipeError::from_win32(error))
                }
            }
            WAIT_TIMEOUT => {
                // Keep the accept pending - don't cancel it
                Ok(None)
            }
            WAIT_ABANDONED => {
                self.cleanup_accept_state();
                Err(NamedPipeError::Interrupted)
            }
            WAIT_FAILED => {
                let error = unsafe { GetLastError() };
                self.cleanup_accept_state();
                Err(NamedPipeError::from_win32(error))
            }
            _ => {
                let error = unsafe { GetLastError() };
                self.cleanup_accept_state();
                Err(NamedPipeError::from_win32(error))
            }
        }
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
        if self.is_connected {
            return Err(NamedPipeError::AlreadyConnected);
        }

        // If no accept is pending, start one
        if self.accept_event == 0 {
            use windows_sys::Win32::System::Threading::CreateEventW;

            let event = unsafe { CreateEventW(core::ptr::null(), TRUE, FALSE, core::ptr::null()) };
            if event == 0 {
                let error = unsafe { GetLastError() };
                return Err(NamedPipeError::from_win32(error));
            }

            self.accept_overlapped = unsafe { core::mem::zeroed() };
            self.accept_overlapped.hEvent = event;
            self.accept_event = event;

            let result = unsafe { ConnectNamedPipe(self.handle, &mut self.accept_overlapped) };

            if result != 0 {
                self.cleanup_accept_state();
                self.is_connected = true;
                return Ok(NamedPipeConnection::from_server(self.handle));
            }

            let error = unsafe { GetLastError() };
            match error {
                ERROR_IO_PENDING => { /* fall through to wait */ }
                ERROR_PIPE_CONNECTED => {
                    self.cleanup_accept_state();
                    self.is_connected = true;
                    return Ok(NamedPipeConnection::from_server(self.handle));
                }
                _ => {
                    self.cleanup_accept_state();
                    return Err(NamedPipeError::from_win32(error));
                }
            }
        }

        // Wait indefinitely for the connection
        let wait_result = unsafe { WaitForSingleObject(self.accept_event, INFINITE) };

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

                self.cleanup_accept_state();

                if overlapped_result != 0 {
                    self.is_connected = true;
                    Ok(NamedPipeConnection::from_server(self.handle))
                } else {
                    Err(NamedPipeError::from_win32(unsafe { GetLastError() }))
                }
            }
            WAIT_ABANDONED => {
                self.cleanup_accept_state();
                Err(NamedPipeError::Interrupted)
            }
            WAIT_FAILED => {
                self.cleanup_accept_state();
                Err(NamedPipeError::from_win32(unsafe { GetLastError() }))
            }
            _ => {
                self.cleanup_accept_state();
                Err(NamedPipeError::from_win32(unsafe { GetLastError() }))
            }
        }
    }

    /// Disconnects the current client and prepares for a new connection.
    ///
    /// After calling this method, the server can accept new connections.
    ///
    /// # Returns
    /// * `Ok(())` - Disconnection successful
    /// * `Err(NamedPipeError)` - An error occurred
    pub fn disconnect(&mut self) -> Result<(), NamedPipeError> {
        if !self.is_connected {
            return Ok(());
        }

        // SAFETY: DisconnectNamedPipe is called with a valid pipe handle.
        let result = unsafe { DisconnectNamedPipe(self.handle) };

        if result != 0 {
            self.is_connected = false;
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
}

#[cfg(windows)]
impl Drop for NamedPipeServer {
    fn drop(&mut self) {
        // Cancel any pending accept operation first
        self.cleanup_accept_state();

        // Disconnect any connected client
        if self.is_connected {
            let _ = self.disconnect();
        }

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

    pub fn disconnect(&mut self) -> Result<(), NamedPipeError> {
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
        Self {
            handle,
            is_server_side: true,
            is_overlapped: true, // Server pipes are created with FILE_FLAG_OVERLAPPED
            cached_client_pid: None,
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

        // SAFETY: CreateFileW is called with valid parameters to open the named pipe.
        let handle = unsafe {
            CreateFileW(
                name_wide.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                core::ptr::null(),
                OPEN_EXISTING,
                0, // No special flags for synchronous I/O
                0, // No template file
            )
        };

        if handle == INVALID_HANDLE_VALUE {
            let error = unsafe { GetLastError() };
            return Err(NamedPipeError::from_win32(error));
        }

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

        Ok(Self {
            handle,
            is_server_side: false,
            is_overlapped: false, // Client connections use synchronous I/O
            cached_client_pid: None,
        })
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

    /// Returns the credentials of the connected peer.
    ///
    /// On Windows, this retrieves the process ID and attempts to extract the client's
    /// Security Identifiers (SIDs) via token impersonation. If SID extraction fails,
    /// credentials are returned with PID only (graceful fallback).
    ///
    /// # Returns
    /// * `Ok(credentials)` - The peer's credentials (with or without SIDs)
    /// * `Err(NamedPipeError)` - Failed to get basic credentials (PID)
    pub fn peer_credentials(&mut self) -> Result<PipeProcessCredentials, NamedPipeError> {
        let pid = self.client_process_id()?;

        // Attempt to get SIDs via token impersonation.
        // If this fails, we gracefully fall back to PID-only credentials.
        match super::process_token::get_client_token_sids(self.handle) {
            Ok(token_sids) => Ok(PipeProcessCredentials::with_sids(
                pid,
                token_sids.user_sid,
                token_sids.group_sids,
            )),
            Err(_e) => {
                // SID extraction failed, return PID-only credentials.
                // TODO: Add logging once iceoryx2_bb_log is available in PAL crate.
                // This would help diagnose issues like:
                // - Insufficient privileges for impersonation
                // - Token access failures
                // - Invalid SID structures
                // For now, the failure is silent and we fall back to PID-only credentials.
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
        // Only close the handle if this is the client side
        // Server-side connections don't own the handle
        if !self.is_server_side && self.handle != INVALID_HANDLE_VALUE {
            // SAFETY: CloseHandle is called with a valid handle that we own.
            unsafe { CloseHandle(self.handle) };
        }
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
        assert!(server.disconnect().is_err());

        assert!(NamedPipeServer::create(b"test", 0).is_err());
        assert!(NamedPipeConnection::connect(b"test").is_err());
    }
}
