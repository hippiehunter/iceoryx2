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

//! [`ControlChannel`] implementation based on Unix stream sockets.
//!
//! This implementation uses [`UnixStreamListener`] and [`UnixStreamConnection`] from
//! the posix building blocks to provide a secure control channel with:
//! - Peer credential verification via SO_PEERCRED
//! - File descriptor passing via SCM_RIGHTS
//!
//! # Example
//!
//! ```ignore
//! use iceoryx2_bb_system_types::file_name::FileName;
//! use iceoryx2_bb_container::semantic_string::SemanticString;
//! use iceoryx2_cal::control_channel::unix_stream::*;
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

use core::fmt::Debug;
use core::time::Duration;

use alloc::format;
use alloc::vec;
use alloc::vec::Vec;

use iceoryx2_bb_posix::directory::*;
use iceoryx2_bb_posix::file::*;
use iceoryx2_bb_posix::file_descriptor::FileDescriptor;
use iceoryx2_bb_posix::socket_ancillary::{
    SocketAncillary, SocketCred, MAX_FILE_DESCRIPTORS_PER_MESSAGE,
};
use iceoryx2_bb_posix::unix_stream_socket::*;
use iceoryx2_bb_system_types::file_name::FileName;
use iceoryx2_bb_system_types::path::Path;
use iceoryx2_log::{fail, trace};

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

#[cfg(not(feature = "dev_permissions"))]
use iceoryx2_bb_posix::permission::Permission;

#[cfg(not(feature = "dev_permissions"))]
const SOCKET_PERMISSIONS: Permission = Permission::OWNER_ALL;

#[cfg(feature = "dev_permissions")]
use iceoryx2_bb_posix::permission::Permission;

#[cfg(feature = "dev_permissions")]
const SOCKET_PERMISSIONS: Permission = Permission::ALL;

/// Configuration for the Unix stream control channel.
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

/// The control channel type implementing [`ControlChannel`] using Unix stream sockets.
#[derive(Debug)]
pub struct Channel;

impl NamedConceptMgmt for Channel {
    type Configuration = Configuration;

    fn does_exist_cfg(
        name: &FileName,
        cfg: &Self::Configuration,
    ) -> Result<bool, NamedConceptDoesExistError> {
        let msg = format!("Unable to check if control_channel::unix_stream \"{name}\" exists");

        let full_path = cfg.path_for(name);

        match File::does_exist(&full_path) {
            Ok(v) => Ok(v),
            Err(v) => {
                fail!(from "control_channel::unix_stream::Channel::does_exist_cfg()",
                        with NamedConceptDoesExistError::UnderlyingResourcesCorrupted,
                    "{} due to an internal failure ({:?}), is the control channel in a corrupted state?", msg, v);
            }
        }
    }

    fn list_cfg(config: &Self::Configuration) -> Result<Vec<FileName>, NamedConceptListError> {
        let msg = "Unable to list all control_channel::unix_stream";
        let origin = "control_channel::unix_stream::Channel::list_cfg()";

        let directory = fail!(from origin, when Directory::new(&config.path_hint),
            map DirectoryOpenError::InsufficientPermissions => NamedConceptListError::InsufficientPermissions,
            unmatched NamedConceptListError::InternalError,
            "{} due to a failure while reading the directory (\"{}\").", msg, config.path_hint);

        let entries = fail!(from origin,
                            when directory.contents(),
                            map DirectoryReadError::InsufficientPermissions => NamedConceptListError::InsufficientPermissions,
                            unmatched NamedConceptListError::InternalError,
                            "{} due to a failure while reading the directory (\"{}\") contents.", msg, config.path_hint);

        let mut result = vec![];
        for entry in &entries {
            if let Some(entry_name) = config.extract_name_from_file(entry.name()) {
                result.push(entry_name);
            }
        }

        Ok(result)
    }

    unsafe fn remove_cfg(
        name: &FileName,
        config: &Self::Configuration,
    ) -> Result<bool, NamedConceptRemoveError> {
        let msg = format!("Unable to release control_channel::unix_stream \"{name}\"");
        let origin = "control_channel::unix_stream::Channel::remove_cfg()";
        let file_path = config.path_for(name);

        match File::remove(&file_path) {
            Ok(v) => Ok(v),
            Err(FileRemoveError::InsufficientPermissions)
            | Err(FileRemoveError::PartOfReadOnlyFileSystem) => {
                fail!(from origin, with NamedConceptRemoveError::InsufficientPermissions,
                        "{} due to insufficient permissions.", msg);
            }
            Err(v) => {
                fail!(from origin, with NamedConceptRemoveError::InternalError,
                        "{} due to unknown failure ({:?}).", msg, v);
            }
        }
    }

    fn remove_path_hint(value: &Path) -> Result<(), NamedConceptPathHintRemoveError> {
        crate::named_concept::remove_path_hint(value)
    }
}

impl ControlChannel for Channel {
    type Listener = Listener;
    type Connection = Connection;
    type Client = Client;
    type ListenerBuilder = ListenerBuilder;
    type ClientBuilder = ClientBuilder;
}

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
        let full_path = self.config.path_for(&self.name);

        let listener = UnixStreamListenerBuilder::new(&full_path)
            .creation_mode(CreationMode::CreateExclusive)
            .permission(SOCKET_PERMISSIONS)
            .create();

        let inner = match listener {
            Ok(l) => l,
            Err(UnixStreamListenerCreationError::SocketFileAlreadyExists)
            | Err(UnixStreamListenerCreationError::AddressAlreadyInUse) => {
                fail!(from self, with ControlChannelListenerCreateError::AlreadyExists,
                    "{} since a listener with that name already exists.", msg);
            }
            Err(UnixStreamListenerCreationError::InsufficientPermissions) => {
                fail!(from self, with ControlChannelListenerCreateError::InsufficientPermissions,
                    "{} due to insufficient permissions.", msg);
            }
            Err(UnixStreamListenerCreationError::InsufficientResources) => {
                fail!(from self, with ControlChannelListenerCreateError::InsufficientResources,
                    "{} due to insufficient resources.", msg);
            }
            Err(UnixStreamListenerCreationError::PathDoesNotExist) => {
                fail!(from self, with ControlChannelListenerCreateError::PathDoesNotExist,
                    "{} since the path does not exist.", msg);
            }
            Err(e) => {
                fail!(from self, with ControlChannelListenerCreateError::InternalFailure,
                    "{} due to an internal error ({:?}).", msg, e);
            }
        };

        trace!(from self, "created");

        Ok(Listener {
            name: self.name,
            inner,
        })
    }
}

/// Server-side listener that accepts incoming connections.
#[derive(Debug)]
pub struct Listener {
    name: FileName,
    inner: UnixStreamListener,
}

impl NamedConcept for Listener {
    fn name(&self) -> &FileName {
        &self.name
    }
}

impl ControlChannelListener for Listener {
    type Connection = Connection;

    fn try_accept(&self) -> Result<Option<Connection>, ControlChannelAcceptError> {
        match self.inner.try_accept() {
            Ok(Some(conn)) => Ok(Some(Connection { inner: conn })),
            Ok(None) => Ok(None),
            Err(e) => map_accept_error(e),
        }
    }

    fn timed_accept(
        &self,
        timeout: Duration,
    ) -> Result<Option<Connection>, ControlChannelAcceptError> {
        match self.inner.timed_accept(timeout) {
            Ok(Some(conn)) => Ok(Some(Connection { inner: conn })),
            Ok(None) => Ok(None),
            Err(e) => map_accept_error(e),
        }
    }

    fn blocking_accept(&self) -> Result<Connection, ControlChannelAcceptError> {
        match self.inner.blocking_accept() {
            Ok(conn) => {
                trace!(from self, "accepted connection");
                Ok(Connection { inner: conn })
            }
            Err(e) => map_accept_error(e),
        }
    }
}

fn map_accept_error<T>(e: UnixStreamAcceptError) -> Result<T, ControlChannelAcceptError> {
    match e {
        UnixStreamAcceptError::WouldBlock => Err(ControlChannelAcceptError::WouldBlock),
        UnixStreamAcceptError::ConnectionAborted => {
            Err(ControlChannelAcceptError::ConnectionAborted)
        }
        UnixStreamAcceptError::Interrupt => Err(ControlChannelAcceptError::Interrupt),
        UnixStreamAcceptError::InsufficientResources => {
            Err(ControlChannelAcceptError::InsufficientResources)
        }
        UnixStreamAcceptError::InsufficientMemory => {
            Err(ControlChannelAcceptError::InsufficientMemory)
        }
        UnixStreamAcceptError::InsufficientPermissions => {
            Err(ControlChannelAcceptError::InsufficientPermissions)
        }
        UnixStreamAcceptError::PerProcessFileHandleLimitReached => {
            Err(ControlChannelAcceptError::PerProcessFileHandleLimitReached)
        }
        UnixStreamAcceptError::SystemWideFileHandleLimitReached => {
            Err(ControlChannelAcceptError::SystemWideFileHandleLimitReached)
        }
        _ => Err(ControlChannelAcceptError::InternalFailure),
    }
}

/// Server-side connection after accepting a client.
#[derive(Debug)]
pub struct Connection {
    inner: UnixStreamConnection,
}

impl ControlChannelConnection for Connection {
    fn peer_credentials(&self) -> Result<ProcessCredentials, ControlChannelCredentialsError> {
        match self.inner.peer_credentials() {
            Ok(cred) => Ok(socket_cred_to_process_credentials(&cred)),
            Err(e) => map_credentials_error(e),
        }
    }

    fn send_handles(&self, handles: &[&PlatformHandle]) -> Result<(), ControlChannelSendError> {
        send_handles_impl(&self.inner, handles)
    }

    fn try_send_handles(
        &self,
        handles: &[&PlatformHandle],
    ) -> Result<bool, ControlChannelSendError> {
        try_send_handles_impl(&self.inner, handles)
    }

    fn receive_handles(&self) -> Result<Option<Vec<PlatformHandle>>, ControlChannelReceiveError> {
        receive_handles_impl(&self.inner)
    }

    fn try_receive_handles(
        &self,
    ) -> Result<Option<Vec<PlatformHandle>>, ControlChannelReceiveError> {
        try_receive_handles_impl(&self.inner)
    }

    fn timed_receive_handles(
        &self,
        timeout: Duration,
    ) -> Result<Option<Vec<PlatformHandle>>, ControlChannelReceiveError> {
        timed_receive_handles_impl(&self.inner, timeout)
    }

    fn blocking_receive_handles(&self) -> Result<Vec<PlatformHandle>, ControlChannelReceiveError> {
        blocking_receive_handles_impl(&self.inner)
    }

    fn send(&self, data: &[u8]) -> Result<(), ControlChannelSendError> {
        match self.inner.blocking_send(data) {
            Ok(()) => Ok(()),
            Err(e) => map_send_error(e),
        }
    }

    fn try_send(&self, data: &[u8]) -> Result<u64, ControlChannelSendError> {
        match self.inner.try_send(data) {
            Ok(sent) => Ok(sent),
            Err(e) => map_send_error(e),
        }
    }

    fn receive(&self, buffer: &mut [u8]) -> Result<u64, ControlChannelReceiveError> {
        match self.inner.blocking_receive(buffer) {
            Ok(received) => Ok(received),
            Err(e) => map_receive_error(e),
        }
    }

    fn try_receive(&self, buffer: &mut [u8]) -> Result<u64, ControlChannelReceiveError> {
        match self.inner.try_receive(buffer) {
            Ok(received) => Ok(received),
            Err(e) => map_receive_error(e),
        }
    }
}

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
        let full_path = self.config.path_for(&self.name);

        match UnixStreamClientBuilder::new(&full_path).connect() {
            Ok(conn) => {
                trace!(from self, "connected");
                Ok(Client {
                    name: self.name,
                    inner: conn,
                })
            }
            Err(UnixStreamClientCreationError::DoesNotExist) => {
                fail!(from self, with ControlChannelConnectError::DoesNotExist,
                    "{} since the listener does not exist.", msg);
            }
            Err(e) => map_connect_error_with_context(&self, msg, e),
        }
    }

    fn try_connect(self) -> Result<Client, ControlChannelConnectError> {
        let full_path = self.config.path_for(&self.name);

        match UnixStreamClientBuilder::new(&full_path).connect() {
            Ok(conn) => {
                trace!(from self, "connected");
                Ok(Client {
                    name: self.name,
                    inner: conn,
                })
            }
            Err(e) => map_connect_error(e),
        }
    }
}

fn map_connect_error_with_context<T>(
    origin: &ClientBuilder,
    msg: &str,
    e: UnixStreamClientCreationError,
) -> Result<T, ControlChannelConnectError> {
    match e {
        UnixStreamClientCreationError::DoesNotExist => {
            fail!(from origin, with ControlChannelConnectError::DoesNotExist,
                "{} since the listener does not exist.", msg);
        }
        UnixStreamClientCreationError::InsufficientPermissions => {
            fail!(from origin, with ControlChannelConnectError::InsufficientPermissions,
                "{} due to insufficient permissions.", msg);
        }
        UnixStreamClientCreationError::InsufficientResources => {
            fail!(from origin, with ControlChannelConnectError::InsufficientResources,
                "{} due to insufficient resources.", msg);
        }
        UnixStreamClientCreationError::ConnectionRefused => {
            fail!(from origin, with ControlChannelConnectError::ConnectionRefused,
                "{} since the connection was refused.", msg);
        }
        UnixStreamClientCreationError::ConnectionReset => {
            fail!(from origin, with ControlChannelConnectError::ConnectionReset,
                "{} since the connection was reset.", msg);
        }
        UnixStreamClientCreationError::Interrupt => {
            fail!(from origin, with ControlChannelConnectError::Interrupt,
                "{} due to an interrupt.", msg);
        }
        UnixStreamClientCreationError::WouldBlock => {
            fail!(from origin, with ControlChannelConnectError::WouldBlock,
                "{} since it would block.", msg);
        }
        _ => {
            fail!(from origin, with ControlChannelConnectError::InternalFailure,
                "{} due to an internal error ({:?}).", msg, e);
        }
    }
}

fn map_connect_error<T>(e: UnixStreamClientCreationError) -> Result<T, ControlChannelConnectError> {
    match e {
        UnixStreamClientCreationError::DoesNotExist => {
            Err(ControlChannelConnectError::DoesNotExist)
        }
        UnixStreamClientCreationError::InsufficientPermissions => {
            Err(ControlChannelConnectError::InsufficientPermissions)
        }
        UnixStreamClientCreationError::InsufficientResources => {
            Err(ControlChannelConnectError::InsufficientResources)
        }
        UnixStreamClientCreationError::ConnectionRefused => {
            Err(ControlChannelConnectError::ConnectionRefused)
        }
        UnixStreamClientCreationError::ConnectionReset => {
            Err(ControlChannelConnectError::ConnectionReset)
        }
        UnixStreamClientCreationError::Interrupt => Err(ControlChannelConnectError::Interrupt),
        UnixStreamClientCreationError::WouldBlock => Err(ControlChannelConnectError::WouldBlock),
        _ => Err(ControlChannelConnectError::InternalFailure),
    }
}

/// Client-side connection after connecting to a listener.
#[derive(Debug)]
pub struct Client {
    name: FileName,
    inner: UnixStreamConnection,
}

impl NamedConcept for Client {
    fn name(&self) -> &FileName {
        &self.name
    }
}

impl ControlChannelClient for Client {
    fn peer_credentials(&self) -> Result<ProcessCredentials, ControlChannelCredentialsError> {
        match self.inner.peer_credentials() {
            Ok(cred) => Ok(socket_cred_to_process_credentials(&cred)),
            Err(e) => map_credentials_error(e),
        }
    }

    fn send_handles(&self, handles: &[&PlatformHandle]) -> Result<(), ControlChannelSendError> {
        send_handles_impl(&self.inner, handles)
    }

    fn try_send_handles(
        &self,
        handles: &[&PlatformHandle],
    ) -> Result<bool, ControlChannelSendError> {
        try_send_handles_impl(&self.inner, handles)
    }

    fn receive_handles(&self) -> Result<Option<Vec<PlatformHandle>>, ControlChannelReceiveError> {
        receive_handles_impl(&self.inner)
    }

    fn try_receive_handles(
        &self,
    ) -> Result<Option<Vec<PlatformHandle>>, ControlChannelReceiveError> {
        try_receive_handles_impl(&self.inner)
    }

    fn timed_receive_handles(
        &self,
        timeout: Duration,
    ) -> Result<Option<Vec<PlatformHandle>>, ControlChannelReceiveError> {
        timed_receive_handles_impl(&self.inner, timeout)
    }

    fn blocking_receive_handles(&self) -> Result<Vec<PlatformHandle>, ControlChannelReceiveError> {
        blocking_receive_handles_impl(&self.inner)
    }

    fn send(&self, data: &[u8]) -> Result<(), ControlChannelSendError> {
        match self.inner.blocking_send(data) {
            Ok(()) => Ok(()),
            Err(e) => map_send_error(e),
        }
    }

    fn try_send(&self, data: &[u8]) -> Result<u64, ControlChannelSendError> {
        match self.inner.try_send(data) {
            Ok(sent) => Ok(sent),
            Err(e) => map_send_error(e),
        }
    }

    fn receive(&self, buffer: &mut [u8]) -> Result<u64, ControlChannelReceiveError> {
        match self.inner.blocking_receive(buffer) {
            Ok(received) => Ok(received),
            Err(e) => map_receive_error(e),
        }
    }

    fn try_receive(&self, buffer: &mut [u8]) -> Result<u64, ControlChannelReceiveError> {
        match self.inner.try_receive(buffer) {
            Ok(received) => Ok(received),
            Err(e) => map_receive_error(e),
        }
    }
}

// ============================================================================
// Helper functions
// ============================================================================

/// Converts a [`SocketCred`] to [`ProcessCredentials`].
fn socket_cred_to_process_credentials(cred: &SocketCred) -> ProcessCredentials {
    ProcessCredentials::new(
        cred.get_pid().value() as u32,
        cred.get_uid().value(),
        cred.get_gid().value(),
    )
}

fn map_credentials_error<T>(
    e: UnixStreamGetPeerCredentialsError,
) -> Result<T, ControlChannelCredentialsError> {
    match e {
        UnixStreamGetPeerCredentialsError::InsufficientPermissions => {
            Err(ControlChannelCredentialsError::InsufficientPermissions)
        }
        UnixStreamGetPeerCredentialsError::InsufficientResources => {
            Err(ControlChannelCredentialsError::InsufficientResources)
        }
        UnixStreamGetPeerCredentialsError::SocketHasBeenShutDown => {
            Err(ControlChannelCredentialsError::SocketHasBeenShutDown)
        }
        UnixStreamGetPeerCredentialsError::NotConnected => {
            Err(ControlChannelCredentialsError::NotConnected)
        }
        _ => Err(ControlChannelCredentialsError::InternalFailure),
    }
}

fn map_send_error<T>(e: UnixStreamSendError) -> Result<T, ControlChannelSendError> {
    match e {
        UnixStreamSendError::MessageTooLarge => Err(ControlChannelSendError::MessageTooLarge),
        UnixStreamSendError::ConnectionReset => Err(ControlChannelSendError::ConnectionReset),
        UnixStreamSendError::Interrupt => Err(ControlChannelSendError::Interrupt),
        UnixStreamSendError::IOerror => Err(ControlChannelSendError::IoError),
        UnixStreamSendError::InsufficientPermissions => {
            Err(ControlChannelSendError::InsufficientPermissions)
        }
        UnixStreamSendError::InsufficientResources => {
            Err(ControlChannelSendError::InsufficientResources)
        }
        UnixStreamSendError::InsufficientMemory => Err(ControlChannelSendError::InsufficientMemory),
        UnixStreamSendError::NotConnected => Err(ControlChannelSendError::NotConnected),
        UnixStreamSendError::BrokenPipe => Err(ControlChannelSendError::BrokenPipe),
        _ => Err(ControlChannelSendError::InternalFailure),
    }
}

fn map_send_msg_error<T>(e: UnixStreamSendMsgError) -> Result<T, ControlChannelSendError> {
    match e {
        UnixStreamSendMsgError::MessageTooLarge => Err(ControlChannelSendError::MessageTooLarge),
        UnixStreamSendMsgError::ConnectionReset => Err(ControlChannelSendError::ConnectionReset),
        UnixStreamSendMsgError::Interrupt => Err(ControlChannelSendError::Interrupt),
        UnixStreamSendMsgError::IOerror => Err(ControlChannelSendError::IoError),
        UnixStreamSendMsgError::InsufficientPermissions => {
            Err(ControlChannelSendError::InsufficientPermissions)
        }
        UnixStreamSendMsgError::InsufficientResources => {
            Err(ControlChannelSendError::InsufficientResources)
        }
        UnixStreamSendMsgError::InsufficientMemory => {
            Err(ControlChannelSendError::InsufficientMemory)
        }
        UnixStreamSendMsgError::NotConnected => Err(ControlChannelSendError::NotConnected),
        UnixStreamSendMsgError::BrokenPipe => Err(ControlChannelSendError::BrokenPipe),
        _ => Err(ControlChannelSendError::InternalFailure),
    }
}

fn map_receive_error<T>(e: UnixStreamReceiveError) -> Result<T, ControlChannelReceiveError> {
    match e {
        UnixStreamReceiveError::ConnectionReset => Err(ControlChannelReceiveError::ConnectionReset),
        UnixStreamReceiveError::Interrupt => Err(ControlChannelReceiveError::Interrupt),
        UnixStreamReceiveError::IOerror => Err(ControlChannelReceiveError::IoError),
        UnixStreamReceiveError::InsufficientResources => {
            Err(ControlChannelReceiveError::InsufficientResources)
        }
        UnixStreamReceiveError::InsufficientMemory => {
            Err(ControlChannelReceiveError::InsufficientMemory)
        }
        UnixStreamReceiveError::NotConnected => Err(ControlChannelReceiveError::NotConnected),
        _ => Err(ControlChannelReceiveError::InternalFailure),
    }
}

fn map_receive_msg_error<T>(e: UnixStreamReceiveMsgError) -> Result<T, ControlChannelReceiveError> {
    match e {
        UnixStreamReceiveMsgError::WouldBlock => Err(ControlChannelReceiveError::WouldBlock),
        UnixStreamReceiveMsgError::ConnectionReset => {
            Err(ControlChannelReceiveError::ConnectionReset)
        }
        UnixStreamReceiveMsgError::Interrupt => Err(ControlChannelReceiveError::Interrupt),
        UnixStreamReceiveMsgError::IOerror => Err(ControlChannelReceiveError::IoError),
        UnixStreamReceiveMsgError::InsufficientResources => {
            Err(ControlChannelReceiveError::InsufficientResources)
        }
        UnixStreamReceiveMsgError::InsufficientMemory => {
            Err(ControlChannelReceiveError::InsufficientMemory)
        }
        UnixStreamReceiveMsgError::NotConnected => Err(ControlChannelReceiveError::NotConnected),
        UnixStreamReceiveMsgError::ReceivedInvalidFileDescriptor => {
            Err(ControlChannelReceiveError::ReceivedInvalidFileDescriptor)
        }
        _ => Err(ControlChannelReceiveError::InternalFailure),
    }
}

/// Sends platform handles via SCM_RIGHTS.
fn send_handles_impl(
    conn: &UnixStreamConnection,
    handles: &[&PlatformHandle],
) -> Result<(), ControlChannelSendError> {
    // Validate handle count upfront
    if handles.len() > MAX_FILE_DESCRIPTORS_PER_MESSAGE {
        return Err(ControlChannelSendError::MessageTooLarge);
    }

    let mut ancillary = SocketAncillary::new();

    // Add all file descriptors to the ancillary message using non-owning wrappers.
    // The PlatformHandle remains the owner, and the kernel copies the fd during sendmsg.
    // Using non_owning ensures we don't double-close when ancillary is dropped.
    for handle in handles {
        let fd = unsafe { FileDescriptor::non_owning_new_unchecked(handle.as_raw_fd()) };
        if !ancillary.add_fd(fd) {
            return Err(ControlChannelSendError::MessageTooLarge);
        }
    }

    match conn.blocking_send_msg(&mut ancillary) {
        Ok(()) => Ok(()),
        Err(e) => map_send_msg_error(e),
    }
}

/// Tries to send platform handles without blocking.
fn try_send_handles_impl(
    conn: &UnixStreamConnection,
    handles: &[&PlatformHandle],
) -> Result<bool, ControlChannelSendError> {
    // Validate handle count upfront
    if handles.len() > MAX_FILE_DESCRIPTORS_PER_MESSAGE {
        return Err(ControlChannelSendError::MessageTooLarge);
    }

    let mut ancillary = SocketAncillary::new();

    // Use non-owning wrappers to avoid double-close
    for handle in handles {
        let fd = unsafe { FileDescriptor::non_owning_new_unchecked(handle.as_raw_fd()) };
        if !ancillary.add_fd(fd) {
            return Err(ControlChannelSendError::MessageTooLarge);
        }
    }

    match conn.try_send_msg(&mut ancillary) {
        Ok(sent) => Ok(sent),
        Err(e) => map_send_msg_error(e),
    }
}

/// Receives platform handles via SCM_RIGHTS.
fn receive_handles_impl(
    conn: &UnixStreamConnection,
) -> Result<Option<Vec<PlatformHandle>>, ControlChannelReceiveError> {
    let mut ancillary = SocketAncillary::new();

    match conn.blocking_receive_msg(&mut ancillary) {
        Ok(true) => Ok(Some(extract_handles_from_ancillary(ancillary))),
        Ok(false) => Ok(None),
        Err(e) => map_receive_msg_error(e),
    }
}

/// Tries to receive platform handles without blocking.
fn try_receive_handles_impl(
    conn: &UnixStreamConnection,
) -> Result<Option<Vec<PlatformHandle>>, ControlChannelReceiveError> {
    let mut ancillary = SocketAncillary::new();

    match conn.try_receive_msg(&mut ancillary) {
        Ok(true) => Ok(Some(extract_handles_from_ancillary(ancillary))),
        Ok(false) => Ok(None),
        Err(e) => map_receive_msg_error(e),
    }
}

/// Receives platform handles with timeout.
///
/// Uses a polling approach since UnixStreamConnection doesn't expose
/// a timed_receive_msg method. This polls every 10ms until timeout.
fn timed_receive_handles_impl(
    conn: &UnixStreamConnection,
    timeout: Duration,
) -> Result<Option<Vec<PlatformHandle>>, ControlChannelReceiveError> {
    use std::time::Instant;

    const POLL_INTERVAL: Duration = Duration::from_millis(10);

    let deadline = Instant::now() + timeout;

    loop {
        // Try non-blocking receive
        match try_receive_handles_impl(conn) {
            Ok(Some(handles)) => return Ok(Some(handles)),
            Ok(None) => {
                // No data yet, check if we've timed out
                let now = Instant::now();
                if now >= deadline {
                    return Ok(None); // Timeout
                }
                // Sleep for a short interval before retrying
                let remaining = deadline - now;
                let sleep_time = remaining.min(POLL_INTERVAL);
                std::thread::sleep(sleep_time);
            }
            Err(ControlChannelReceiveError::WouldBlock) => {
                // Same as Ok(None) - no data available
                let now = Instant::now();
                if now >= deadline {
                    return Ok(None);
                }
                let remaining = deadline - now;
                let sleep_time = remaining.min(POLL_INTERVAL);
                std::thread::sleep(sleep_time);
            }
            Err(e) => return Err(e),
        }
    }
}

/// Blocks until platform handles are received.
fn blocking_receive_handles_impl(
    conn: &UnixStreamConnection,
) -> Result<Vec<PlatformHandle>, ControlChannelReceiveError> {
    let mut ancillary = SocketAncillary::new();

    match conn.blocking_receive_msg(&mut ancillary) {
        Ok(true) => Ok(extract_handles_from_ancillary(ancillary)),
        Ok(false) => Ok(vec![]),
        Err(e) => map_receive_msg_error(e),
    }
}

/// Extracts platform handles from a received ancillary message.
fn extract_handles_from_ancillary(ancillary: SocketAncillary) -> Vec<PlatformHandle> {
    let fds = ancillary.extract_fds();
    let mut handles = Vec::with_capacity(fds.len());

    for fd in fds {
        // Transfer ownership from FileDescriptor to PlatformHandle
        let raw_fd = unsafe { fd.native_handle() };
        // Forget the FileDescriptor to prevent double-close
        core::mem::forget(fd);
        // Create PlatformHandle with ownership
        let handle = unsafe { PlatformHandle::from_raw_fd(raw_fd) };
        handles.push(handle);
    }

    handles
}
