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

//! [`ControlChannel`] implementation based on Windows Named Pipes.
//!
//! This implementation uses [`NamedPipeServer`] and [`NamedPipeConnection`] from
//! the posix building blocks to provide a secure control channel with:
//! - Peer credential verification via `GetNamedPipeClientProcessId`
//! - Handle passing via `DuplicateHandle` to inject handles into client process
//!
//! # Handle Transfer Protocol
//!
//! Unlike Unix SCM_RIGHTS which passes file descriptors in-band, Windows requires
//! the server to duplicate handles directly into the client's process using
//! `DuplicateHandle`. The protocol works as follows:
//!
//! 1. Server calls `peer_credentials()` to get client's PID
//! 2. Server duplicates handles to client's process using `duplicate_handle_to_process()`
//! 3. Server sends message with magic header + handle count + handle values
//! 4. Client receives message and uses the handles directly (they're already in its table)
//!
//! # Message Format
//!
//! Handle transfer messages use the following format:
//! - Magic header: 0x494F5832 ("IOX2" in ASCII)
//! - Handle count: u32 (max 16)
//! - Handle values: u64 each (handle value in client's process)
//!
//! # Example
//!
//! ```ignore
//! use iceoryx2_bb_system_types::file_name::FileName;
//! use iceoryx2_bb_container::semantic_string::SemanticString;
//! use iceoryx2_cal::control_channel::named_pipe::*;
//! use iceoryx2_cal::control_channel::*;
//! use iceoryx2_cal::named_concept::*;
//!
//! let name = FileName::new(b"my_control").unwrap();
//!
//! // Server
//! let listener = ListenerBuilder::new(&name).create().unwrap();
//! let connection = listener.blocking_accept().unwrap();
//! let creds = connection.peer_credentials().unwrap();
//!
//! // Client (in another process)
//! let client = ClientBuilder::new(&name).connect().unwrap();
//! ```

#![cfg(windows)]

use core::cell::RefCell;
use core::fmt::Debug;
use core::time::Duration;

use alloc::format;
use alloc::vec;
use alloc::vec::Vec;

use iceoryx2_bb_system_types::file_name::FileName;
use iceoryx2_bb_system_types::path::Path;
use iceoryx2_log::{fail, trace, warn};
use iceoryx2_pal_posix::windows::handle_passing::{
    duplicate_handle_to_process, DuplicateOptions, HandleDuplicationError,
};
use iceoryx2_pal_posix::windows::named_pipe::{
    NamedPipeConnection, NamedPipeError, NamedPipeServer,
};

use crate::named_concept::{
    NamedConcept, NamedConceptBuilder, NamedConceptMgmt, NamedConceptPathHintRemoveError,
};
use crate::security::{PlatformHandle, ProcessCredentials};
use crate::static_storage::file::{
    NamedConceptConfiguration, NamedConceptDoesExistError, NamedConceptListError,
    NamedConceptRemoveError,
};

use super::{
    ControlChannel, ControlChannelAcceptError, ControlChannelClient, ControlChannelClientBuilder,
    ControlChannelConnectError, ControlChannelConnection, ControlChannelCredentialsError,
    ControlChannelListener, ControlChannelListenerBuilder, ControlChannelListenerCreateError,
    ControlChannelReceiveError, ControlChannelSendError,
};

use std::os::windows::io::{AsRawHandle, FromRawHandle};

// ============================================================================
// Constants
// ============================================================================

/// Magic header for handle transfer messages: "IOX2" in ASCII (0x49 0x4F 0x58 0x32).
const HANDLE_MSG_MAGIC: u32 = 0x494F5832;

/// Maximum number of handles that can be sent in a single message.
const MAX_HANDLES_PER_MESSAGE: usize = 16;

/// Size of the message header: magic (4 bytes) + handle_count (4 bytes).
const HANDLE_MSG_HEADER_SIZE: usize = 8;

/// Maximum message size for handle transfer.
const HANDLE_MSG_MAX_SIZE: usize = HANDLE_MSG_HEADER_SIZE + MAX_HANDLES_PER_MESSAGE * 8;

// ============================================================================
// Configuration
// ============================================================================

/// Configuration for the Windows named pipe control channel.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Configuration {
    suffix: FileName,
    prefix: FileName,
    path_hint: Path,
}

impl Default for Configuration {
    fn default() -> Self {
        Self {
            suffix: Channel::default_suffix(),
            prefix: Channel::default_prefix(),
            path_hint: Channel::default_path_hint(),
        }
    }
}

impl NamedConceptConfiguration for Configuration {
    fn prefix(mut self, value: &FileName) -> Self {
        self.prefix = *value;
        self
    }

    fn get_prefix(&self) -> &FileName {
        &self.prefix
    }

    fn suffix(mut self, value: &FileName) -> Self {
        self.suffix = *value;
        self
    }

    fn path_hint(mut self, value: &Path) -> Self {
        self.path_hint = *value;
        self
    }

    fn get_suffix(&self) -> &FileName {
        &self.suffix
    }

    fn get_path_hint(&self) -> &Path {
        &self.path_hint
    }
}

// ============================================================================
// Channel
// ============================================================================

/// The control channel type implementing [`ControlChannel`] using Windows Named Pipes.
#[derive(Debug)]
pub struct Channel;

impl NamedConceptMgmt for Channel {
    type Configuration = Configuration;

    fn does_exist_cfg(
        name: &FileName,
        cfg: &Self::Configuration,
    ) -> Result<bool, NamedConceptDoesExistError> {
        let msg = format!("Unable to check if control_channel::named_pipe \"{name}\" exists");
        let origin = "control_channel::named_pipe::Channel::does_exist_cfg()";

        // On Windows, named pipes exist in a kernel namespace, not as files.
        // We attempt to connect to check existence.
        let pipe_name = build_pipe_name(name, cfg);

        match NamedPipeConnection::connect(pipe_name.as_bytes()) {
            Ok(_) => {
                // Connection succeeded, pipe exists
                Ok(true)
            }
            Err(NamedPipeError::DoesNotExist) => Ok(false),
            Err(NamedPipeError::PipeBusy) => {
                // Pipe exists but all instances are busy
                Ok(true)
            }
            Err(e) => {
                fail!(from origin,
                    with NamedConceptDoesExistError::UnderlyingResourcesCorrupted,
                    "{} due to an internal failure ({:?}), is the control channel in a corrupted state?", msg, e);
            }
        }
    }

    fn list_cfg(config: &Self::Configuration) -> Result<Vec<FileName>, NamedConceptListError> {
        // Windows named pipes cannot be enumerated without special privileges.
        // We return an empty list as a fallback.
        let _ = config;
        Ok(vec![])
    }

    unsafe fn remove_cfg(
        name: &FileName,
        config: &Self::Configuration,
    ) -> Result<bool, NamedConceptRemoveError> {
        // Windows named pipes are automatically removed when all handles are closed.
        // There's nothing to remove explicitly.
        let _ = (name, config);
        Ok(false)
    }

    fn remove_path_hint(_value: &Path) -> Result<(), NamedConceptPathHintRemoveError> {
        // Windows named pipes don't use path hints.
        Ok(())
    }
}

impl ControlChannel for Channel {
    type Listener = Listener;
    type Connection = Connection;
    type Client = Client;
    type ListenerBuilder = ListenerBuilder;
    type ClientBuilder = ClientBuilder;
}

// ============================================================================
// ListenerBuilder
// ============================================================================

/// Builder for creating a [`Listener`].
#[derive(Debug)]
pub struct ListenerBuilder {
    name: FileName,
    config: Configuration,
}

impl NamedConceptBuilder<Channel> for ListenerBuilder {
    fn new(name: &FileName) -> Self {
        Self {
            name: *name,
            config: Configuration::default(),
        }
    }

    fn config(mut self, config: &Configuration) -> Self {
        self.config = config.clone();
        self
    }
}

impl ControlChannelListenerBuilder<Channel> for ListenerBuilder {
    fn create(self) -> Result<Listener, ControlChannelListenerCreateError> {
        let msg = "Unable to create control channel listener";
        let pipe_name = build_pipe_name(&self.name, &self.config);

        // Create the named pipe server
        // Mode 0o600 is passed but currently ignored by the Windows implementation
        let server = match NamedPipeServer::create(pipe_name.as_bytes(), 0o600) {
            Ok(s) => s,
            Err(e) => {
                return map_pipe_error_to_create(&self, msg, e);
            }
        };

        trace!(from self, "created");

        Ok(Listener {
            name: self.name,
            inner: RefCell::new(server),
        })
    }
}

// ============================================================================
// Listener
// ============================================================================

/// Server-side listener that accepts incoming connections.
///
/// # Thread Safety
///
/// This struct is NOT thread-safe. It uses [`RefCell`] internally to allow
/// mutable access through shared references for the accept methods. Using this
/// struct from multiple threads without external synchronization will cause
/// a panic at runtime. If thread-safe access is required, wrap the Listener
/// in a `Mutex` or use separate Listener instances per thread.
#[derive(Debug)]
pub struct Listener {
    name: FileName,
    inner: RefCell<NamedPipeServer>,
}

impl NamedConcept for Listener {
    fn name(&self) -> &FileName {
        &self.name
    }
}

impl ControlChannelListener for Listener {
    type Connection = Connection;

    fn try_accept(&self) -> Result<Option<Connection>, ControlChannelAcceptError> {
        let mut server = self.inner.borrow_mut();
        match server.try_accept() {
            Ok(Some(mut conn)) => {
                // Get client credentials including PID and SIDs
                let creds = conn
                    .peer_credentials()
                    .map_err(map_pipe_error_to_accept_inner)?;
                let (user_sid, group_sids) = extract_sids_from_pipe_creds(&creds);
                Ok(Some(Connection {
                    inner: conn,
                    client_pid: creds.pid(),
                    user_sid,
                    group_sids,
                }))
            }
            Ok(None) => Ok(None),
            Err(e) => map_pipe_error_to_accept(e),
        }
    }

    fn timed_accept(
        &self,
        timeout: Duration,
    ) -> Result<Option<Connection>, ControlChannelAcceptError> {
        let mut server = self.inner.borrow_mut();
        match server.timed_accept(timeout) {
            Ok(Some(mut conn)) => {
                // Get client credentials including PID and SIDs
                let creds = conn
                    .peer_credentials()
                    .map_err(map_pipe_error_to_accept_inner)?;
                let (user_sid, group_sids) = extract_sids_from_pipe_creds(&creds);
                Ok(Some(Connection {
                    inner: conn,
                    client_pid: creds.pid(),
                    user_sid,
                    group_sids,
                }))
            }
            Ok(None) => Ok(None),
            Err(e) => map_pipe_error_to_accept(e),
        }
    }

    fn blocking_accept(&self) -> Result<Connection, ControlChannelAcceptError> {
        let mut server = self.inner.borrow_mut();
        match server.blocking_accept() {
            Ok(mut conn) => {
                // Get client credentials including PID and SIDs
                let creds = conn
                    .peer_credentials()
                    .map_err(map_pipe_error_to_accept_inner)?;
                let (user_sid, group_sids) = extract_sids_from_pipe_creds(&creds);
                trace!(from self, "accepted connection from pid {}", creds.pid());
                Ok(Connection {
                    inner: conn,
                    client_pid: creds.pid(),
                    user_sid,
                    group_sids,
                })
            }
            Err(e) => map_pipe_error_to_accept(e),
        }
    }
}

// ============================================================================
// Connection
// ============================================================================

/// Server-side connection after accepting a client.
///
/// # SID Caching
///
/// User and group SIDs are extracted once during connection acceptance and cached
/// in this struct. This avoids repeated token impersonation calls when `peer_credentials()`
/// is called multiple times. The SIDs are stored as raw bytes (`Vec<u8>`) to decouple from
/// the PAL-layer `Sid` type.
///
/// If SID extraction fails during acceptance (e.g., due to insufficient privileges),
/// the connection is still established but `user_sid` and `group_sids` will be `None`.
/// In this case, `peer_credentials()` returns credentials with PID only.
#[derive(Debug)]
pub struct Connection {
    inner: NamedPipeConnection,
    client_pid: u32,
    /// Cached user SID (as bytes) if available.
    user_sid: Option<Vec<u8>>,
    /// Cached group SIDs (as bytes) if available.
    group_sids: Option<Vec<Vec<u8>>>,
}

impl ControlChannelConnection for Connection {
    fn peer_credentials(&self) -> Result<ProcessCredentials, ControlChannelCredentialsError> {
        // On Windows, we have PID and optionally SIDs. UID/GID are set to 0.
        match (&self.user_sid, &self.group_sids) {
            (Some(user_sid), Some(group_sids)) => Ok(ProcessCredentials::with_sids(
                self.client_pid,
                user_sid.clone(),
                group_sids.clone(),
            )),
            _ => Ok(ProcessCredentials::new(self.client_pid, 0, 0)),
        }
    }

    fn send_handles(&self, handles: &[&PlatformHandle]) -> Result<(), ControlChannelSendError> {
        send_handles_to_process(&self.inner, handles, self.client_pid)
    }

    fn try_send_handles(
        &self,
        handles: &[&PlatformHandle],
    ) -> Result<bool, ControlChannelSendError> {
        // For Windows, we don't have a true non-blocking send for this protocol.
        // We'll attempt the send and return success/failure.
        match send_handles_to_process(&self.inner, handles, self.client_pid) {
            Ok(()) => Ok(true),
            Err(ControlChannelSendError::WouldBlock) => Ok(false),
            Err(e) => Err(e),
        }
    }

    fn receive_handles(&self) -> Result<Option<Vec<PlatformHandle>>, ControlChannelReceiveError> {
        receive_handles_from_pipe(&self.inner)
    }

    fn try_receive_handles(
        &self,
    ) -> Result<Option<Vec<PlatformHandle>>, ControlChannelReceiveError> {
        try_receive_handles_from_pipe(&self.inner)
    }

    fn timed_receive_handles(
        &self,
        timeout: Duration,
    ) -> Result<Option<Vec<PlatformHandle>>, ControlChannelReceiveError> {
        timed_receive_handles_from_pipe(&self.inner, timeout)
    }

    fn blocking_receive_handles(&self) -> Result<Vec<PlatformHandle>, ControlChannelReceiveError> {
        blocking_receive_handles_from_pipe(&self.inner)
    }

    fn send(&self, data: &[u8]) -> Result<(), ControlChannelSendError> {
        match self.inner.write(data) {
            Ok(_) => Ok(()),
            Err(e) => map_pipe_error_to_send(e),
        }
    }

    fn try_send(&self, data: &[u8]) -> Result<u64, ControlChannelSendError> {
        match self.inner.try_write(data) {
            Ok(written) => Ok(written as u64),
            Err(e) => map_pipe_error_to_send(e),
        }
    }

    fn receive(&self, buffer: &mut [u8]) -> Result<u64, ControlChannelReceiveError> {
        match self.inner.blocking_read(buffer) {
            Ok(read) => Ok(read as u64),
            Err(e) => map_pipe_error_to_receive(e),
        }
    }

    fn try_receive(&self, buffer: &mut [u8]) -> Result<u64, ControlChannelReceiveError> {
        match self.inner.try_read(buffer) {
            Ok(read) => Ok(read as u64),
            Err(e) => map_pipe_error_to_receive(e),
        }
    }
}

// ============================================================================
// ClientBuilder
// ============================================================================

/// Builder for creating a [`Client`].
#[derive(Debug)]
pub struct ClientBuilder {
    name: FileName,
    config: Configuration,
}

impl NamedConceptBuilder<Channel> for ClientBuilder {
    fn new(name: &FileName) -> Self {
        Self {
            name: *name,
            config: Configuration::default(),
        }
    }

    fn config(mut self, config: &Configuration) -> Self {
        self.config = config.clone();
        self
    }
}

impl ControlChannelClientBuilder<Channel> for ClientBuilder {
    fn connect(self) -> Result<Client, ControlChannelConnectError> {
        let msg = "Unable to connect to control channel";
        let pipe_name = build_pipe_name(&self.name, &self.config);

        match NamedPipeConnection::connect(pipe_name.as_bytes()) {
            Ok(conn) => {
                trace!(from self, "connected");
                Ok(Client {
                    name: self.name,
                    inner: conn,
                })
            }
            Err(NamedPipeError::DoesNotExist) => {
                fail!(from self, with ControlChannelConnectError::DoesNotExist,
                    "{} since the listener does not exist.", msg);
            }
            Err(e) => map_pipe_error_to_connect(&self, msg, e),
        }
    }

    fn try_connect(self) -> Result<Client, ControlChannelConnectError> {
        let pipe_name = build_pipe_name(&self.name, &self.config);

        match NamedPipeConnection::connect(pipe_name.as_bytes()) {
            Ok(conn) => {
                trace!(from self, "connected");
                Ok(Client {
                    name: self.name,
                    inner: conn,
                })
            }
            Err(e) => map_pipe_error_to_connect_silent(e),
        }
    }
}

// ============================================================================
// Client
// ============================================================================

/// Client-side connection after connecting to a listener.
#[derive(Debug)]
pub struct Client {
    name: FileName,
    inner: NamedPipeConnection,
}

impl NamedConcept for Client {
    fn name(&self) -> &FileName {
        &self.name
    }
}

impl ControlChannelClient for Client {
    fn peer_credentials(&self) -> Result<ProcessCredentials, ControlChannelCredentialsError> {
        // On the client side, we can't easily get server credentials on Windows.
        // Return an error indicating this isn't supported.
        Err(ControlChannelCredentialsError::InternalFailure)
    }

    fn send_handles(&self, handles: &[&PlatformHandle]) -> Result<(), ControlChannelSendError> {
        // Client sending handles to server is not the primary use case.
        // The server would need to know our PID to receive them.
        // For now, we don't support this direction.
        warn!(from self, "Client-to-server handle passing is not supported on Windows");
        Err(ControlChannelSendError::InternalFailure)
    }

    fn try_send_handles(
        &self,
        _handles: &[&PlatformHandle],
    ) -> Result<bool, ControlChannelSendError> {
        Err(ControlChannelSendError::InternalFailure)
    }

    fn receive_handles(&self) -> Result<Option<Vec<PlatformHandle>>, ControlChannelReceiveError> {
        receive_handles_from_pipe(&self.inner)
    }

    fn try_receive_handles(
        &self,
    ) -> Result<Option<Vec<PlatformHandle>>, ControlChannelReceiveError> {
        try_receive_handles_from_pipe(&self.inner)
    }

    fn timed_receive_handles(
        &self,
        timeout: Duration,
    ) -> Result<Option<Vec<PlatformHandle>>, ControlChannelReceiveError> {
        timed_receive_handles_from_pipe(&self.inner, timeout)
    }

    fn blocking_receive_handles(&self) -> Result<Vec<PlatformHandle>, ControlChannelReceiveError> {
        blocking_receive_handles_from_pipe(&self.inner)
    }

    fn send(&self, data: &[u8]) -> Result<(), ControlChannelSendError> {
        match self.inner.write(data) {
            Ok(_) => Ok(()),
            Err(e) => map_pipe_error_to_send(e),
        }
    }

    fn try_send(&self, data: &[u8]) -> Result<u64, ControlChannelSendError> {
        match self.inner.try_write(data) {
            Ok(written) => Ok(written as u64),
            Err(e) => map_pipe_error_to_send(e),
        }
    }

    fn receive(&self, buffer: &mut [u8]) -> Result<u64, ControlChannelReceiveError> {
        match self.inner.blocking_read(buffer) {
            Ok(read) => Ok(read as u64),
            Err(e) => map_pipe_error_to_receive(e),
        }
    }

    fn try_receive(&self, buffer: &mut [u8]) -> Result<u64, ControlChannelReceiveError> {
        match self.inner.try_read(buffer) {
            Ok(read) => Ok(read as u64),
            Err(e) => map_pipe_error_to_receive(e),
        }
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

use iceoryx2_pal_posix::windows::named_pipe::PipeProcessCredentials;

/// Extracts SIDs from PipeProcessCredentials and converts to byte vectors.
///
/// Returns a tuple of (user_sid, group_sids) where each is an Option containing
/// the SID data as bytes.
fn extract_sids_from_pipe_creds(
    creds: &PipeProcessCredentials,
) -> (Option<Vec<u8>>, Option<Vec<Vec<u8>>>) {
    let user_sid = creds.user_sid().map(|sid| sid.as_bytes().to_vec());
    let group_sids = creds
        .group_sids()
        .map(|sids| sids.iter().map(|sid| sid.as_bytes().to_vec()).collect());
    (user_sid, group_sids)
}

/// Builds the full pipe name from the FileName and configuration.
fn build_pipe_name(name: &FileName, config: &Configuration) -> String {
    // Named pipes on Windows use a different namespace than files.
    // The path_for() method isn't suitable, so we construct the name directly.
    let prefix = config.get_prefix();
    let suffix = config.get_suffix();

    // Convert FileName bytes to string
    let name_str = core::str::from_utf8(name.as_bytes()).unwrap_or("unknown");
    let prefix_str = core::str::from_utf8(prefix.as_bytes()).unwrap_or("");
    let suffix_str = core::str::from_utf8(suffix.as_bytes()).unwrap_or("");

    format!("{}{}{}", prefix_str, name_str, suffix_str)
}

/// Sends handles to a target process.
///
/// This function:
/// 1. Duplicates each handle into the target process
/// 2. Constructs a message with the duplicated handle values
/// 3. Sends the message over the pipe
///
/// # Note
///
/// TODO: If handle duplication fails partway through, already-duplicated handles
/// in the remote process will leak. Cleaning up these handles would require
/// injecting code into the remote process or using a more complex protocol.
/// For now, this is an accepted limitation as partial failures are rare in practice.
fn send_handles_to_process(
    conn: &NamedPipeConnection,
    handles: &[&PlatformHandle],
    target_pid: u32,
) -> Result<(), ControlChannelSendError> {
    if handles.len() > MAX_HANDLES_PER_MESSAGE {
        return Err(ControlChannelSendError::MessageTooLarge);
    }

    if handles.is_empty() {
        // Send empty handle message
        let mut buffer = [0u8; HANDLE_MSG_HEADER_SIZE];
        buffer[0..4].copy_from_slice(&HANDLE_MSG_MAGIC.to_le_bytes());
        buffer[4..8].copy_from_slice(&0u32.to_le_bytes());

        return match conn.write(&buffer) {
            Ok(_) => Ok(()),
            Err(e) => map_pipe_error_to_send(e),
        };
    }

    // Duplicate handles to target process using stack-allocated array
    let mut duplicated_handles = [0u64; MAX_HANDLES_PER_MESSAGE];
    let mut handle_count = 0;
    let options = DuplicateOptions::same_access();

    for handle in handles {
        let raw_handle = handle.as_raw_handle() as isize;
        match duplicate_handle_to_process(raw_handle, target_pid, options) {
            Ok(new_handle) => {
                duplicated_handles[handle_count] = new_handle as u64;
                handle_count += 1;
            }
            Err(e) => {
                warn!(from "control_channel::named_pipe",
                    "Failed to duplicate handle to process {}: {:?}", target_pid, e);
                return Err(map_duplication_error_to_send(e));
            }
        }
    }

    // Build message: magic + count + handle values using stack-allocated buffer
    let msg_size = HANDLE_MSG_HEADER_SIZE + handle_count * 8;
    let mut buffer = [0u8; HANDLE_MSG_MAX_SIZE];

    // Magic header
    buffer[0..4].copy_from_slice(&HANDLE_MSG_MAGIC.to_le_bytes());
    // Handle count
    buffer[4..8].copy_from_slice(&(handle_count as u32).to_le_bytes());
    // Handle values
    for i in 0..handle_count {
        let offset = HANDLE_MSG_HEADER_SIZE + i * 8;
        buffer[offset..offset + 8].copy_from_slice(&duplicated_handles[i].to_le_bytes());
    }

    match conn.write(&buffer[..msg_size]) {
        Ok(_) => Ok(()),
        Err(e) => map_pipe_error_to_send(e),
    }
}

/// Receives handles from the pipe (blocking).
fn receive_handles_from_pipe(
    conn: &NamedPipeConnection,
) -> Result<Option<Vec<PlatformHandle>>, ControlChannelReceiveError> {
    let mut buffer = [0u8; HANDLE_MSG_MAX_SIZE];

    match conn.blocking_read(&mut buffer) {
        Ok(0) => Ok(None),
        Ok(n) => parse_handle_message(&buffer[..n]),
        Err(e) => map_pipe_error_to_receive(e),
    }
}

/// Tries to receive handles without blocking.
fn try_receive_handles_from_pipe(
    conn: &NamedPipeConnection,
) -> Result<Option<Vec<PlatformHandle>>, ControlChannelReceiveError> {
    let mut buffer = [0u8; HANDLE_MSG_MAX_SIZE];

    match conn.try_read(&mut buffer) {
        Ok(0) => Ok(None),
        Ok(n) => parse_handle_message(&buffer[..n]),
        Err(NamedPipeError::WouldBlock) => Ok(None),
        Err(e) => map_pipe_error_to_receive(e),
    }
}

/// Receives handles with timeout.
fn timed_receive_handles_from_pipe(
    conn: &NamedPipeConnection,
    timeout: Duration,
) -> Result<Option<Vec<PlatformHandle>>, ControlChannelReceiveError> {
    let mut buffer = [0u8; HANDLE_MSG_MAX_SIZE];

    match conn.timed_read(&mut buffer, timeout) {
        Ok(0) => Ok(None),
        Ok(n) => parse_handle_message(&buffer[..n]),
        Err(NamedPipeError::TimedOut) => Ok(None),
        Err(e) => map_pipe_error_to_receive(e),
    }
}

/// Blocks until handles are received.
fn blocking_receive_handles_from_pipe(
    conn: &NamedPipeConnection,
) -> Result<Vec<PlatformHandle>, ControlChannelReceiveError> {
    let mut buffer = [0u8; HANDLE_MSG_MAX_SIZE];

    match conn.blocking_read(&mut buffer) {
        Ok(0) => Ok(vec![]),
        Ok(n) => match parse_handle_message(&buffer[..n])? {
            Some(handles) => Ok(handles),
            None => Ok(vec![]),
        },
        Err(e) => map_pipe_error_to_receive(e),
    }
}

/// Parses a handle transfer message.
fn parse_handle_message(
    buffer: &[u8],
) -> Result<Option<Vec<PlatformHandle>>, ControlChannelReceiveError> {
    if buffer.len() < HANDLE_MSG_HEADER_SIZE {
        warn!(from "control_channel::named_pipe",
            "Received message too short for handle transfer header");
        return Err(ControlChannelReceiveError::InternalFailure);
    }

    // Check magic header
    let magic = u32::from_le_bytes([buffer[0], buffer[1], buffer[2], buffer[3]]);
    if magic != HANDLE_MSG_MAGIC {
        warn!(from "control_channel::named_pipe",
            "Received message with invalid magic header: 0x{:08X}", magic);
        return Err(ControlChannelReceiveError::InternalFailure);
    }

    // Get handle count
    let handle_count = u32::from_le_bytes([buffer[4], buffer[5], buffer[6], buffer[7]]) as usize;

    if handle_count == 0 {
        return Ok(Some(vec![]));
    }

    if handle_count > MAX_HANDLES_PER_MESSAGE {
        warn!(from "control_channel::named_pipe",
            "Received message with too many handles: {}", handle_count);
        return Err(ControlChannelReceiveError::InternalFailure);
    }

    let expected_size = HANDLE_MSG_HEADER_SIZE + handle_count * 8;
    if buffer.len() < expected_size {
        warn!(from "control_channel::named_pipe",
            "Received message too short for {} handles", handle_count);
        return Err(ControlChannelReceiveError::InternalFailure);
    }

    // Extract handle values and create PlatformHandles
    let mut handles = Vec::with_capacity(handle_count);
    for i in 0..handle_count {
        let offset = HANDLE_MSG_HEADER_SIZE + i * 8;
        let handle_val = u64::from_le_bytes([
            buffer[offset],
            buffer[offset + 1],
            buffer[offset + 2],
            buffer[offset + 3],
            buffer[offset + 4],
            buffer[offset + 5],
            buffer[offset + 6],
            buffer[offset + 7],
        ]);

        // SAFETY: The handle value was duplicated into our process by the sender
        // using DuplicateHandle. The sender is trusted (server process) and the
        // protocol ensures handle values received are valid in our process space.
        // We now take ownership and are responsible for closing the handle.
        let handle = unsafe { PlatformHandle::from_raw_handle(handle_val as *mut _) };
        handles.push(handle);
    }

    Ok(Some(handles))
}

// ============================================================================
// Error Mapping Functions
// ============================================================================

fn map_pipe_error_to_create<T>(
    origin: &ListenerBuilder,
    msg: &str,
    e: NamedPipeError,
) -> Result<T, ControlChannelListenerCreateError> {
    match e {
        NamedPipeError::AlreadyExists => {
            fail!(from origin, with ControlChannelListenerCreateError::AlreadyExists,
                "{} since a listener with that name already exists.", msg);
        }
        NamedPipeError::AccessDenied => {
            fail!(from origin, with ControlChannelListenerCreateError::InsufficientPermissions,
                "{} due to insufficient permissions.", msg);
        }
        NamedPipeError::InsufficientResources => {
            fail!(from origin, with ControlChannelListenerCreateError::InsufficientResources,
                "{} due to insufficient resources.", msg);
        }
        _ => {
            fail!(from origin, with ControlChannelListenerCreateError::InternalFailure,
                "{} due to an internal error ({:?}).", msg, e);
        }
    }
}

fn map_pipe_error_to_accept<T>(e: NamedPipeError) -> Result<T, ControlChannelAcceptError> {
    Err(map_pipe_error_to_accept_inner(e))
}

fn map_pipe_error_to_accept_inner(e: NamedPipeError) -> ControlChannelAcceptError {
    match e {
        NamedPipeError::WouldBlock => ControlChannelAcceptError::WouldBlock,
        NamedPipeError::BrokenPipe => ControlChannelAcceptError::ConnectionAborted,
        NamedPipeError::Interrupted => ControlChannelAcceptError::Interrupt,
        NamedPipeError::InsufficientResources => ControlChannelAcceptError::InsufficientResources,
        NamedPipeError::AccessDenied => ControlChannelAcceptError::InsufficientPermissions,
        _ => ControlChannelAcceptError::InternalFailure,
    }
}

fn map_pipe_error_to_connect<T>(
    origin: &ClientBuilder,
    msg: &str,
    e: NamedPipeError,
) -> Result<T, ControlChannelConnectError> {
    match e {
        NamedPipeError::DoesNotExist => {
            fail!(from origin, with ControlChannelConnectError::DoesNotExist,
                "{} since the listener does not exist.", msg);
        }
        NamedPipeError::AccessDenied => {
            fail!(from origin, with ControlChannelConnectError::InsufficientPermissions,
                "{} due to insufficient permissions.", msg);
        }
        NamedPipeError::InsufficientResources => {
            fail!(from origin, with ControlChannelConnectError::InsufficientResources,
                "{} due to insufficient resources.", msg);
        }
        NamedPipeError::PipeBusy => {
            fail!(from origin, with ControlChannelConnectError::ConnectionRefused,
                "{} since all pipe instances are busy.", msg);
        }
        NamedPipeError::ConnectionReset | NamedPipeError::BrokenPipe => {
            fail!(from origin, with ControlChannelConnectError::ConnectionReset,
                "{} since the connection was reset.", msg);
        }
        NamedPipeError::Interrupted => {
            fail!(from origin, with ControlChannelConnectError::Interrupt,
                "{} due to an interrupt.", msg);
        }
        NamedPipeError::TimedOut => {
            fail!(from origin, with ControlChannelConnectError::WouldBlock,
                "{} since it timed out.", msg);
        }
        _ => {
            fail!(from origin, with ControlChannelConnectError::InternalFailure,
                "{} due to an internal error ({:?}).", msg, e);
        }
    }
}

fn map_pipe_error_to_connect_silent<T>(e: NamedPipeError) -> Result<T, ControlChannelConnectError> {
    match e {
        NamedPipeError::DoesNotExist => Err(ControlChannelConnectError::DoesNotExist),
        NamedPipeError::AccessDenied => Err(ControlChannelConnectError::InsufficientPermissions),
        NamedPipeError::InsufficientResources => {
            Err(ControlChannelConnectError::InsufficientResources)
        }
        NamedPipeError::PipeBusy => Err(ControlChannelConnectError::ConnectionRefused),
        NamedPipeError::ConnectionReset | NamedPipeError::BrokenPipe => {
            Err(ControlChannelConnectError::ConnectionReset)
        }
        NamedPipeError::Interrupted => Err(ControlChannelConnectError::Interrupt),
        NamedPipeError::TimedOut | NamedPipeError::WouldBlock => {
            Err(ControlChannelConnectError::WouldBlock)
        }
        _ => Err(ControlChannelConnectError::InternalFailure),
    }
}

fn map_pipe_error_to_send<T>(e: NamedPipeError) -> Result<T, ControlChannelSendError> {
    match e {
        NamedPipeError::BrokenPipe => Err(ControlChannelSendError::BrokenPipe),
        NamedPipeError::ConnectionReset => Err(ControlChannelSendError::ConnectionReset),
        NamedPipeError::Interrupted => Err(ControlChannelSendError::Interrupt),
        NamedPipeError::NotConnected => Err(ControlChannelSendError::NotConnected),
        NamedPipeError::WouldBlock => Err(ControlChannelSendError::WouldBlock),
        NamedPipeError::AccessDenied => Err(ControlChannelSendError::InsufficientPermissions),
        NamedPipeError::InsufficientResources => {
            Err(ControlChannelSendError::InsufficientResources)
        }
        _ => Err(ControlChannelSendError::InternalFailure),
    }
}

fn map_pipe_error_to_receive<T>(e: NamedPipeError) -> Result<T, ControlChannelReceiveError> {
    match e {
        NamedPipeError::BrokenPipe => Err(ControlChannelReceiveError::ConnectionReset),
        NamedPipeError::ConnectionReset => Err(ControlChannelReceiveError::ConnectionReset),
        NamedPipeError::Interrupted => Err(ControlChannelReceiveError::Interrupt),
        NamedPipeError::NotConnected => Err(ControlChannelReceiveError::NotConnected),
        NamedPipeError::WouldBlock => Err(ControlChannelReceiveError::WouldBlock),
        NamedPipeError::InsufficientResources => {
            Err(ControlChannelReceiveError::InsufficientResources)
        }
        _ => Err(ControlChannelReceiveError::InternalFailure),
    }
}

fn map_duplication_error_to_send(e: HandleDuplicationError) -> ControlChannelSendError {
    match e {
        HandleDuplicationError::AccessDenied => ControlChannelSendError::InsufficientPermissions,
        HandleDuplicationError::ProcessNotFound => ControlChannelSendError::NotConnected,
        HandleDuplicationError::InvalidSourceHandle => ControlChannelSendError::InternalFailure,
        HandleDuplicationError::InvalidParameter => ControlChannelSendError::InternalFailure,
        HandleDuplicationError::InternalError(_) => ControlChannelSendError::InternalFailure,
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_configuration_default() {
        let config = Configuration::default();
        assert_eq!(config.get_suffix(), &Channel::default_suffix());
        assert_eq!(config.get_prefix(), &Channel::default_prefix());
    }

    #[test]
    fn test_configuration_builder() {
        let suffix = unsafe { FileName::new_unchecked(b".test") };
        let prefix = unsafe { FileName::new_unchecked(b"prefix_") };
        let path = unsafe { Path::new_unchecked(b"/tmp") };

        let config = Configuration::default()
            .suffix(&suffix)
            .prefix(&prefix)
            .path_hint(&path);

        assert_eq!(config.get_suffix(), &suffix);
        assert_eq!(config.get_prefix(), &prefix);
        assert_eq!(config.get_path_hint(), &path);
    }

    #[test]
    fn test_build_pipe_name() {
        let name = unsafe { FileName::new_unchecked(b"test_channel") };
        let config = Configuration::default();

        let pipe_name = build_pipe_name(&name, &config);
        assert!(pipe_name.contains("test_channel"));
        // The pipe name is constructed from prefix + name + suffix
        // The prefix is provided by the configuration, not hardcoded
    }

    #[test]
    fn test_handle_message_constants() {
        // Verify message size calculations
        assert_eq!(HANDLE_MSG_HEADER_SIZE, 8);
        assert_eq!(HANDLE_MSG_MAX_SIZE, 8 + 16 * 8); // header + 16 handles
        assert_eq!(MAX_HANDLES_PER_MESSAGE, 16);
    }

    #[test]
    fn test_magic_header() {
        // Verify magic header is "IOX2" in little-endian
        let magic_bytes = HANDLE_MSG_MAGIC.to_le_bytes();
        assert_eq!(magic_bytes, [0x32, 0x58, 0x4F, 0x49]); // "2XOI" reversed = "IOX2"
    }

    #[test]
    fn test_parse_empty_handle_message() {
        let mut buffer = [0u8; HANDLE_MSG_HEADER_SIZE];
        buffer[0..4].copy_from_slice(&HANDLE_MSG_MAGIC.to_le_bytes());
        buffer[4..8].copy_from_slice(&0u32.to_le_bytes());

        let result = parse_handle_message(&buffer);
        assert!(result.is_ok());
        let handles = result.unwrap();
        assert!(handles.is_some());
        assert_eq!(handles.unwrap().len(), 0);
    }

    #[test]
    fn test_parse_invalid_magic() {
        let mut buffer = [0u8; HANDLE_MSG_HEADER_SIZE];
        buffer[0..4].copy_from_slice(&0xDEADBEEFu32.to_le_bytes());
        buffer[4..8].copy_from_slice(&0u32.to_le_bytes());

        let result = parse_handle_message(&buffer);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_too_short_message() {
        let buffer = [0u8; 4]; // Too short for header
        let result = parse_handle_message(&buffer);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_too_many_handles() {
        let mut buffer = [0u8; HANDLE_MSG_HEADER_SIZE];
        buffer[0..4].copy_from_slice(&HANDLE_MSG_MAGIC.to_le_bytes());
        buffer[4..8].copy_from_slice(&(MAX_HANDLES_PER_MESSAGE as u32 + 1).to_le_bytes());

        let result = parse_handle_message(&buffer);
        assert!(result.is_err());
    }

    // NOTE: Integration tests requiring Windows are located in the integration
    // test suite. Tests for listener/client creation, connection, data transfer,
    // handle transfer, and peer credentials require running on Windows with
    // appropriate privileges.
}
