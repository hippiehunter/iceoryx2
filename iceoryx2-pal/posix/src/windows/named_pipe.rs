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

use core::fmt::{self, Display, Formatter};
use core::time::Duration;

// Windows API imports
#[cfg(windows)]
use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, SetLastError, BOOL, FALSE, HANDLE, INVALID_HANDLE_VALUE, TRUE,
    ERROR_ACCESS_DENIED, ERROR_ALREADY_EXISTS, ERROR_BROKEN_PIPE, ERROR_FILE_NOT_FOUND,
    ERROR_HANDLE_EOF, ERROR_INVALID_HANDLE, ERROR_IO_PENDING, ERROR_MORE_DATA,
    ERROR_NO_DATA, ERROR_PIPE_BUSY, ERROR_PIPE_CONNECTED, ERROR_PIPE_LISTENING,
    ERROR_PIPE_NOT_CONNECTED, ERROR_SUCCESS,
};

#[cfg(windows)]
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FlushFileBuffers, ReadFile, WriteFile,
    FILE_FLAG_OVERLAPPED, FILE_SHARE_READ, FILE_SHARE_WRITE,
    GENERIC_READ, GENERIC_WRITE, OPEN_EXISTING,
};

#[cfg(windows)]
use windows_sys::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, GetNamedPipeClientProcessId,
    PeekNamedPipe, SetNamedPipeHandleState,
    PIPE_ACCESS_DUPLEX, PIPE_READMODE_MESSAGE, PIPE_TYPE_MESSAGE,
    PIPE_UNLIMITED_INSTANCES, PIPE_WAIT, PIPE_NOWAIT,
};

#[cfg(windows)]
use windows_sys::Win32::System::Threading::{
    WaitForSingleObject, INFINITE, WAIT_ABANDONED, WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT,
};

#[cfg(windows)]
use windows_sys::Win32::System::IO::{
    CancelIo, GetOverlappedResult, OVERLAPPED,
};

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
pub fn pipe_name_to_wide(name: &[u8]) -> Result<([u16; MAX_PIPE_NAME_LENGTH], usize), NamedPipeError> {
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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PipeProcessCredentials {
    /// Process ID of the connected peer.
    pub pid: u32,
    /// User ID (always 0 on Windows - use Windows SID APIs for actual identity).
    pub uid: u32,
    /// Group ID (always 0 on Windows - use Windows SID APIs for actual identity).
    pub gid: u32,
}

impl PipeProcessCredentials {
    /// Creates new process credentials with the specified PID.
    ///
    /// UID and GID are set to 0 as Windows doesn't use numeric IDs.
    pub fn new(pid: u32) -> Self {
        Self {
            pid,
            uid: 0,
            gid: 0,
        }
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
#[cfg(windows)]
pub struct NamedPipeServer {
    /// Handle to the named pipe instance.
    handle: HANDLE,
    /// Wide string buffer containing the pipe name.
    name_wide: [u16; MAX_PIPE_NAME_LENGTH],
    /// Length of the pipe name (excluding null terminator).
    name_len: usize,
    /// Whether a client is currently connected.
    is_connected: bool,
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
        let (name_wide, name_len) = pipe_name_to_wide(name)?;

        // TODO: Implement proper security descriptor based on mode parameter.
        // Currently using NULL security descriptor which grants default access.
        // Windows uses DACLs/SACLs instead of Unix permission bits, so a proper
        // implementation would need to translate mode bits to appropriate ACEs.
        let security_attrs = SECURITY_ATTRIBUTES {
            nLength: core::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: core::ptr::null_mut(),
            bInheritHandle: FALSE,
        };

        // Create the named pipe
        // SAFETY: We're calling the Windows API with valid parameters.
        // The name_wide buffer is properly null-terminated.
        let handle = unsafe {
            CreateNamedPipeW(
                name_wide.as_ptr(),
                PIPE_ACCESS_DUPLEX,  // Bidirectional pipe
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
            name_wide,
            name_len,
            is_connected: false,
        })
    }

    /// Attempts to accept a connection without blocking.
    ///
    /// # Returns
    /// * `Ok(Some(connection))` - A client connected
    /// * `Ok(None)` - No client is waiting to connect
    /// * `Err(NamedPipeError)` - An error occurred
    pub fn try_accept(&mut self) -> Result<Option<NamedPipeConnection>, NamedPipeError> {
        if self.is_connected {
            return Err(NamedPipeError::AlreadyConnected);
        }

        // SAFETY: We're calling ConnectNamedPipe with a valid handle.
        // NULL for lpOverlapped means synchronous operation.
        let result = unsafe { ConnectNamedPipe(self.handle, core::ptr::null_mut()) };

        if result != 0 {
            // Connection successful
            self.is_connected = true;
            return Ok(Some(NamedPipeConnection::from_server(self.handle)));
        }

        let error = unsafe { GetLastError() };
        match error {
            ERROR_PIPE_CONNECTED => {
                // Client connected between CreateNamedPipe and ConnectNamedPipe
                self.is_connected = true;
                Ok(Some(NamedPipeConnection::from_server(self.handle)))
            }
            ERROR_IO_PENDING | ERROR_PIPE_LISTENING => {
                // No client waiting
                Ok(None)
            }
            _ => Err(NamedPipeError::from_win32(error)),
        }
    }

    /// Waits for a connection with a timeout.
    ///
    /// # Arguments
    /// * `timeout` - Maximum time to wait for a connection
    ///
    /// # Returns
    /// * `Ok(Some(connection))` - A client connected
    /// * `Ok(None)` - Timeout expired without a connection
    /// * `Err(NamedPipeError)` - An error occurred
    pub fn timed_accept(&mut self, timeout: Duration) -> Result<Option<NamedPipeConnection>, NamedPipeError> {
        if self.is_connected {
            return Err(NamedPipeError::AlreadyConnected);
        }

        // For timed accept, we need to use overlapped I/O
        // Create an event for the overlapped structure
        use windows_sys::Win32::System::Threading::CreateEventW;

        // SAFETY: CreateEventW with NULL security attrs and name creates a manual-reset event
        let event = unsafe { CreateEventW(core::ptr::null(), TRUE, FALSE, core::ptr::null()) };
        if event == 0 {
            let error = unsafe { GetLastError() };
            return Err(NamedPipeError::from_win32(error));
        }

        // SAFETY: OVERLAPPED is a POD (Plain Old Data) struct as defined by MSDN.
        // Zero-initialization is valid and creates a properly initialized OVERLAPPED
        // structure where all fields (Internal, InternalHigh, Offset, OffsetHigh, Pointer)
        // are set to zero/null, which is the correct initial state before use.
        let mut overlapped: OVERLAPPED = unsafe { core::mem::zeroed() };
        overlapped.hEvent = event;

        // SAFETY: ConnectNamedPipe with overlapped structure for async operation
        let result = unsafe { ConnectNamedPipe(self.handle, &mut overlapped) };

        let connect_result = if result != 0 {
            // Immediate success (shouldn't happen with overlapped I/O, but handle it)
            self.is_connected = true;
            Ok(Some(NamedPipeConnection::from_server(self.handle)))
        } else {
            let error = unsafe { GetLastError() };
            match error {
                ERROR_IO_PENDING => {
                    // Wait for the connection with timeout
                    let timeout_ms = timeout.as_millis() as u32;
                    let wait_result = unsafe { WaitForSingleObject(event, timeout_ms) };

                    match wait_result {
                        WAIT_OBJECT_0 => {
                            // Event signaled - check if connection succeeded
                            let mut bytes_transferred: u32 = 0;
                            let overlapped_result = unsafe {
                                GetOverlappedResult(
                                    self.handle,
                                    &overlapped,
                                    &mut bytes_transferred,
                                    FALSE,
                                )
                            };

                            if overlapped_result != 0 {
                                self.is_connected = true;
                                Ok(Some(NamedPipeConnection::from_server(self.handle)))
                            } else {
                                let error = unsafe { GetLastError() };
                                Err(NamedPipeError::from_win32(error))
                            }
                        }
                        WAIT_TIMEOUT => {
                            // Timeout - cancel the pending I/O
                            unsafe { CancelIo(self.handle) };
                            // IMPORTANT: After CancelIo, we must wait for the operation to
                            // actually complete/cancel before cleaning up the OVERLAPPED structure.
                            // GetOverlappedResult with bWait=TRUE ensures the I/O has finished.
                            let mut bytes_transferred: u32 = 0;
                            unsafe {
                                GetOverlappedResult(
                                    self.handle,
                                    &overlapped,
                                    &mut bytes_transferred,
                                    TRUE, // bWait=TRUE: block until operation completes/cancels
                                )
                            };
                            // We ignore the result - whether it succeeded or was cancelled,
                            // we're returning None for timeout anyway
                            Ok(None)
                        }
                        WAIT_ABANDONED => {
                            Err(NamedPipeError::Interrupted)
                        }
                        WAIT_FAILED | _ => {
                            let error = unsafe { GetLastError() };
                            Err(NamedPipeError::from_win32(error))
                        }
                    }
                }
                ERROR_PIPE_CONNECTED => {
                    self.is_connected = true;
                    Ok(Some(NamedPipeConnection::from_server(self.handle)))
                }
                _ => Err(NamedPipeError::from_win32(error)),
            }
        };

        // Clean up the event handle
        unsafe { CloseHandle(event) };

        connect_result
    }

    /// Blocks until a client connects.
    ///
    /// # Returns
    /// * `Ok(connection)` - A client connected
    /// * `Err(NamedPipeError)` - An error occurred
    pub fn blocking_accept(&mut self) -> Result<NamedPipeConnection, NamedPipeError> {
        if self.is_connected {
            return Err(NamedPipeError::AlreadyConnected);
        }

        // SAFETY: ConnectNamedPipe blocks until a client connects when called
        // without overlapped I/O on a pipe created with PIPE_WAIT.
        let result = unsafe { ConnectNamedPipe(self.handle, core::ptr::null_mut()) };

        if result != 0 {
            self.is_connected = true;
            return Ok(NamedPipeConnection::from_server(self.handle));
        }

        let error = unsafe { GetLastError() };
        if error == ERROR_PIPE_CONNECTED {
            // Client already connected
            self.is_connected = true;
            return Ok(NamedPipeConnection::from_server(self.handle));
        }

        Err(NamedPipeError::from_win32(error))
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
        // Disconnect any connected client first
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

    pub fn timed_accept(&mut self, _timeout: Duration) -> Result<Option<NamedPipeConnection>, NamedPipeError> {
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
    /// Cached client process ID (lazily fetched).
    cached_client_pid: Option<u32>,
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
        let mut mode: u32 = PIPE_READMODE_MESSAGE;
        // SAFETY: SetNamedPipeHandleState is called with a valid handle.
        let result = unsafe {
            SetNamedPipeHandleState(
                handle,
                &mut mode,
                core::ptr::null_mut(),
                core::ptr::null_mut(),
            )
        };

        if result == 0 {
            let error = unsafe { GetLastError() };
            unsafe { CloseHandle(handle) };
            return Err(NamedPipeError::from_win32(error));
        }

        Ok(Self {
            handle,
            is_server_side: false,
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
    /// On Windows, only the process ID is available. UID and GID are set to 0.
    ///
    /// # Returns
    /// * `Ok(credentials)` - The peer's credentials
    /// * `Err(NamedPipeError)` - Failed to get credentials
    pub fn peer_credentials(&mut self) -> Result<PipeProcessCredentials, NamedPipeError> {
        let pid = self.client_process_id()?;
        Ok(PipeProcessCredentials::new(pid))
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
        let mut bytes_read: u32 = 0;

        // SAFETY: ReadFile is called with valid parameters.
        let result = unsafe {
            ReadFile(
                self.handle,
                buffer.as_mut_ptr(),
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
    ///
    /// # Implementation Note
    /// This implementation uses two syscalls: `PeekNamedPipe` to check for available data,
    /// followed by `ReadFile` if data is present. This is a known limitation - a more
    /// efficient implementation could use overlapped I/O with immediate completion check,
    /// but that would require the pipe to be opened with `FILE_FLAG_OVERLAPPED`.
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

        // Data is available, read it
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
    pub fn timed_read(&self, buffer: &mut [u8], timeout: Duration) -> Result<usize, NamedPipeError> {
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

    pub fn timed_read(&self, _buffer: &mut [u8], _timeout: Duration) -> Result<usize, NamedPipeError> {
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
    use super::*;

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
        assert_eq!(creds.pid, 1234);
        assert_eq!(creds.uid, 0);
        assert_eq!(creds.gid, 0);
    }

    #[test]
    fn test_named_pipe_error_display() {
        assert_eq!(
            format!("{}", NamedPipeError::NameTooLong),
            "Pipe name exceeds maximum length"
        );
        assert_eq!(
            format!("{}", NamedPipeError::AccessDenied),
            "Access denied"
        );
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
    use super::*;

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
        assert_eq!(creds.pid, 1234);
        assert_eq!(creds.uid, 0);
        assert_eq!(creds.gid, 0);
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
