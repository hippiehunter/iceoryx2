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

//! A [`ControlChannel`] provides a secure, connection-oriented communication channel
//! between processes with support for credential verification and file descriptor passing.
//!
//! Unlike the datagram-based [`crate::communication_channel::CommunicationChannel`], a
//! [`ControlChannel`] uses stream sockets which provide:
//! - Connection-oriented semantics with accept/connect handshake
//! - Peer credential verification via SO_PEERCRED
//! - File descriptor (handle) passing via SCM_RIGHTS
//!
//! The control channel is designed for the IAM (Identity and Access Management) security model
//! where a server authenticates clients and passes shared memory handles to authorized clients.
//!
//! # Architecture
//!
//! - [`ControlChannelListener`] - Server-side listener that accepts incoming connections
//! - [`ControlChannelConnection`] - Server-side accepted connection with peer credentials
//! - [`ControlChannelClient`] - Client-side connection after connecting to a listener
//!
//! # Example
//!
//! ```ignore
//! use iceoryx2_bb_system_types::file_name::FileName;
//! use iceoryx2_bb_container::semantic_string::SemanticString;
//! use iceoryx2_cal::control_channel::*;
//! use iceoryx2_cal::named_concept::*;
//!
//! // Server side
//! fn server<CC: ControlChannel>() {
//!     let name = FileName::new(b"my_control_channel").unwrap();
//!     let listener = CC::ListenerBuilder::new(&name).create().unwrap();
//!
//!     // Accept a connection
//!     let connection = listener.blocking_accept().unwrap();
//!
//!     // Verify peer credentials
//!     let creds = connection.peer_credentials().unwrap();
//!     println!("Connected by pid={}, uid={}", creds.pid(), creds.uid());
//! }
//!
//! // Client side
//! fn client<CC: ControlChannel>() {
//!     let name = FileName::new(b"my_control_channel").unwrap();
//!     let client = CC::ClientBuilder::new(&name).connect().unwrap();
//! }
//! ```

pub mod recommended;
pub mod unix_stream;

#[cfg(windows)]
pub mod named_pipe;

use core::fmt::Debug;
use core::time::Duration;

use iceoryx2_bb_system_types::file_name::FileName;

use crate::named_concept::{NamedConcept, NamedConceptBuilder, NamedConceptMgmt};
use crate::security::{PlatformHandle, ProcessCredentials};

/// Error when creating a control channel listener.
#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
pub enum ControlChannelListenerCreateError {
    /// A listener with this name already exists.
    AlreadyExists,
    /// Insufficient permissions to create the listener.
    InsufficientPermissions,
    /// Insufficient system resources.
    InsufficientResources,
    /// The path for the socket does not exist.
    PathDoesNotExist,
    /// An internal error occurred.
    InternalFailure,
}

impl core::fmt::Display for ControlChannelListenerCreateError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "ControlChannelListenerCreateError::{self:?}")
    }
}

impl core::error::Error for ControlChannelListenerCreateError {}

/// Error when accepting a connection on a control channel listener.
#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
pub enum ControlChannelAcceptError {
    /// The accept operation would block (non-blocking mode).
    WouldBlock,
    /// The connection was aborted.
    ConnectionAborted,
    /// An interrupt signal was received.
    Interrupt,
    /// Insufficient system resources.
    InsufficientResources,
    /// Insufficient memory.
    InsufficientMemory,
    /// Insufficient permissions.
    InsufficientPermissions,
    /// Per-process file handle limit reached.
    PerProcessFileHandleLimitReached,
    /// System-wide file handle limit reached.
    SystemWideFileHandleLimitReached,
    /// An internal error occurred.
    InternalFailure,
}

impl core::fmt::Display for ControlChannelAcceptError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "ControlChannelAcceptError::{self:?}")
    }
}

impl core::error::Error for ControlChannelAcceptError {}

/// Error when connecting to a control channel listener.
#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
pub enum ControlChannelConnectError {
    /// The listener does not exist.
    DoesNotExist,
    /// Insufficient permissions to connect.
    InsufficientPermissions,
    /// Insufficient system resources.
    InsufficientResources,
    /// The connection was refused.
    ConnectionRefused,
    /// The connection was reset.
    ConnectionReset,
    /// An interrupt signal was received.
    Interrupt,
    /// The operation would block (non-blocking mode).
    WouldBlock,
    /// An internal error occurred.
    InternalFailure,
}

impl core::fmt::Display for ControlChannelConnectError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "ControlChannelConnectError::{self:?}")
    }
}

impl core::error::Error for ControlChannelConnectError {}

/// Error when sending data or handles over a control channel.
#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
pub enum ControlChannelSendError {
    /// The message is too large to send.
    MessageTooLarge,
    /// The connection was reset by the peer.
    ConnectionReset,
    /// An interrupt signal was received.
    Interrupt,
    /// An I/O error occurred.
    IoError,
    /// Insufficient permissions.
    InsufficientPermissions,
    /// Insufficient system resources.
    InsufficientResources,
    /// Insufficient memory.
    InsufficientMemory,
    /// The socket is not connected.
    NotConnected,
    /// The connection has been broken.
    BrokenPipe,
    /// The operation would block (non-blocking mode).
    WouldBlock,
    /// An internal error occurred.
    InternalFailure,
}

impl core::fmt::Display for ControlChannelSendError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "ControlChannelSendError::{self:?}")
    }
}

impl core::error::Error for ControlChannelSendError {}

/// Error when receiving data or handles over a control channel.
#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
pub enum ControlChannelReceiveError {
    /// The connection was reset by the peer.
    ConnectionReset,
    /// An interrupt signal was received.
    Interrupt,
    /// An I/O error occurred.
    IoError,
    /// Insufficient system resources.
    InsufficientResources,
    /// Insufficient memory.
    InsufficientMemory,
    /// The socket is not connected.
    NotConnected,
    /// The operation would block (non-blocking mode).
    WouldBlock,
    /// Received an invalid file descriptor.
    ReceivedInvalidFileDescriptor,
    /// An internal error occurred.
    InternalFailure,
}

impl core::fmt::Display for ControlChannelReceiveError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "ControlChannelReceiveError::{self:?}")
    }
}

impl core::error::Error for ControlChannelReceiveError {}

/// Error when getting peer credentials.
#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
pub enum ControlChannelCredentialsError {
    /// Insufficient permissions to get credentials.
    InsufficientPermissions,
    /// Insufficient system resources.
    InsufficientResources,
    /// The socket has been shut down.
    SocketHasBeenShutDown,
    /// The socket is not connected.
    NotConnected,
    /// An internal error occurred.
    InternalFailure,
}

impl core::fmt::Display for ControlChannelCredentialsError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "ControlChannelCredentialsError::{self:?}")
    }
}

impl core::error::Error for ControlChannelCredentialsError {}

/// Builder for creating a [`ControlChannelListener`].
pub trait ControlChannelListenerBuilder<C: ControlChannel>: NamedConceptBuilder<C> + Debug {
    /// Creates the listener.
    fn create(self) -> Result<C::Listener, ControlChannelListenerCreateError>;
}

/// Builder for creating a [`ControlChannelClient`].
pub trait ControlChannelClientBuilder<C: ControlChannel>: NamedConceptBuilder<C> + Debug {
    /// Connects to an existing listener.
    fn connect(self) -> Result<C::Client, ControlChannelConnectError>;

    /// Tries to connect to an existing listener without logging on failure.
    fn try_connect(self) -> Result<C::Client, ControlChannelConnectError>;
}

/// Server-side listener that accepts incoming connections.
///
/// Created by [`ControlChannelListenerBuilder::create()`].
pub trait ControlChannelListener: Debug + NamedConcept + Sized {
    /// The connection type returned by accept operations.
    type Connection: ControlChannelConnection;

    /// Tries to accept a connection without blocking.
    ///
    /// Returns `Ok(None)` if no connection is pending.
    fn try_accept(&self) -> Result<Option<Self::Connection>, ControlChannelAcceptError>;

    /// Blocks until a connection is accepted or the timeout expires.
    ///
    /// Returns `Ok(None)` if the timeout expired.
    fn timed_accept(
        &self,
        timeout: Duration,
    ) -> Result<Option<Self::Connection>, ControlChannelAcceptError>;

    /// Blocks until a connection is accepted.
    fn blocking_accept(&self) -> Result<Self::Connection, ControlChannelAcceptError>;
}

/// Server-side connection after accepting a client.
///
/// Provides access to peer credentials and can send/receive handles.
pub trait ControlChannelConnection: Debug + Sized {
    /// Returns the credentials of the connected peer.
    ///
    /// Uses SO_PEERCRED to get the peer's pid, uid, and gid. This is
    /// race-free as the credentials are captured at connection time.
    fn peer_credentials(&self) -> Result<ProcessCredentials, ControlChannelCredentialsError>;

    /// Sends platform handles (file descriptors) to the peer.
    ///
    /// The handles are transferred using SCM_RIGHTS ancillary messages.
    /// Ownership of the handles is transferred to the receiving process.
    fn send_handles(&self, handles: &[&PlatformHandle]) -> Result<(), ControlChannelSendError>;

    /// Tries to send platform handles without blocking.
    fn try_send_handles(
        &self,
        handles: &[&PlatformHandle],
    ) -> Result<bool, ControlChannelSendError>;

    /// Receives platform handles (file descriptors) from the peer.
    ///
    /// The handles are received using SCM_RIGHTS ancillary messages.
    /// Ownership of the handles is transferred to this process.
    fn receive_handles(&self) -> Result<Option<Vec<PlatformHandle>>, ControlChannelReceiveError>;

    /// Tries to receive platform handles without blocking.
    fn try_receive_handles(
        &self,
    ) -> Result<Option<Vec<PlatformHandle>>, ControlChannelReceiveError>;

    /// Blocks until platform handles are received or the timeout expires.
    fn timed_receive_handles(
        &self,
        timeout: Duration,
    ) -> Result<Option<Vec<PlatformHandle>>, ControlChannelReceiveError>;

    /// Blocks until platform handles are received.
    fn blocking_receive_handles(&self) -> Result<Vec<PlatformHandle>, ControlChannelReceiveError>;

    /// Sends raw bytes to the peer.
    fn send(&self, data: &[u8]) -> Result<(), ControlChannelSendError>;

    /// Tries to send raw bytes without blocking.
    fn try_send(&self, data: &[u8]) -> Result<u64, ControlChannelSendError>;

    /// Receives raw bytes from the peer.
    fn receive(&self, buffer: &mut [u8]) -> Result<u64, ControlChannelReceiveError>;

    /// Tries to receive raw bytes without blocking.
    fn try_receive(&self, buffer: &mut [u8]) -> Result<u64, ControlChannelReceiveError>;
}

/// Client-side connection after connecting to a listener.
///
/// Provides the same capabilities as [`ControlChannelConnection`] but
/// from the client's perspective.
pub trait ControlChannelClient: Debug + NamedConcept + Sized {
    /// Returns the credentials of the connected peer (the server).
    fn peer_credentials(&self) -> Result<ProcessCredentials, ControlChannelCredentialsError>;

    /// Sends platform handles (file descriptors) to the server.
    fn send_handles(&self, handles: &[&PlatformHandle]) -> Result<(), ControlChannelSendError>;

    /// Tries to send platform handles without blocking.
    fn try_send_handles(
        &self,
        handles: &[&PlatformHandle],
    ) -> Result<bool, ControlChannelSendError>;

    /// Receives platform handles (file descriptors) from the server.
    fn receive_handles(&self) -> Result<Option<Vec<PlatformHandle>>, ControlChannelReceiveError>;

    /// Tries to receive platform handles without blocking.
    fn try_receive_handles(
        &self,
    ) -> Result<Option<Vec<PlatformHandle>>, ControlChannelReceiveError>;

    /// Blocks until platform handles are received or the timeout expires.
    fn timed_receive_handles(
        &self,
        timeout: Duration,
    ) -> Result<Option<Vec<PlatformHandle>>, ControlChannelReceiveError>;

    /// Blocks until platform handles are received.
    fn blocking_receive_handles(&self) -> Result<Vec<PlatformHandle>, ControlChannelReceiveError>;

    /// Sends raw bytes to the server.
    fn send(&self, data: &[u8]) -> Result<(), ControlChannelSendError>;

    /// Tries to send raw bytes without blocking.
    fn try_send(&self, data: &[u8]) -> Result<u64, ControlChannelSendError>;

    /// Receives raw bytes from the server.
    fn receive(&self, buffer: &mut [u8]) -> Result<u64, ControlChannelReceiveError>;

    /// Tries to receive raw bytes without blocking.
    fn try_receive(&self, buffer: &mut [u8]) -> Result<u64, ControlChannelReceiveError>;
}

/// Bundles all control channel traits together.
///
/// A [`ControlChannel`] implementation ties together the listener, connection,
/// client, and their respective builders.
pub trait ControlChannel: Sized + Debug + NamedConceptMgmt {
    /// The listener type for accepting connections.
    type Listener: ControlChannelListener;
    /// The connection type for accepted connections.
    type Connection: ControlChannelConnection;
    /// The client type for connecting to listeners.
    type Client: ControlChannelClient;
    /// The builder for creating listeners.
    type ListenerBuilder: ControlChannelListenerBuilder<Self>;
    /// The builder for creating clients.
    type ClientBuilder: ControlChannelClientBuilder<Self>;

    /// The default suffix for control channel socket files.
    fn default_suffix() -> FileName {
        unsafe { FileName::new_unchecked_const(b".ctrl") }
    }
}

use alloc::vec::Vec;
