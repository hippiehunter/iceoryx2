// Copyright (c) 2023 Contributors to the Eclipse Foundation
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

//! Abstraction of stream-based unix domain sockets. The [`UnixStreamListener`] creates a
//! socket, binds, and listens. The [`UnixStreamClientBuilder`] connects to it, and
//! [`UnixStreamConnection`] represents the bidirectional stream after accept/connect.
//!
//! # Example
//!
//! ## Transfer data
//!
//! ```ignore
//! use iceoryx2_bb_posix::unix_stream_socket::*;
//! use iceoryx2_bb_posix::permission::*;
//! use iceoryx2_bb_system_types::file_path::FilePath;
//! use iceoryx2_bb_container::semantic_string::SemanticString;
//!
//! let socket_name = FilePath::new(b"/tmp/myStreamSocket").unwrap();
//! let listener = UnixStreamListenerBuilder::new(&socket_name)
//!                         .permission(Permission::OWNER_ALL)
//!                         .creation_mode(CreationMode::PurgeAndCreate)
//!                         .create().unwrap();
//!
//! // In another thread/process:
//! let connection = UnixStreamClientBuilder::new(&socket_name)
//!                         .connect().unwrap();
//!
//! // send some data
//! let data: Vec<u8> = vec![1u8, 2u8, 3u8, 4u8, 5u8];
//! connection.blocking_send(data.as_slice()).unwrap();
//!
//! // On the listener side, accept and receive
//! let accepted = listener.blocking_accept().unwrap();
//! let mut recv_data: Vec<u8> = vec![0u8; 5];
//! accepted.blocking_receive(recv_data.as_mut_slice()).unwrap();
//! ```
//!
//! ## Transfer [`FileDescriptor`]s
//!
//! ```ignore
//! use iceoryx2_bb_posix::unix_stream_socket::*;
//! use iceoryx2_bb_posix::socket_ancillary::*;
//! use iceoryx2_bb_posix::file::*;
//! use iceoryx2_bb_posix::file_descriptor::*;
//! use iceoryx2_bb_system_types::file_path::FilePath;
//! use iceoryx2_bb_container::semantic_string::SemanticString;
//!
//! let socket_name = FilePath::new(b"/tmp/myStreamSocket").unwrap();
//! let listener = UnixStreamListenerBuilder::new(&socket_name)
//!                         .creation_mode(CreationMode::PurgeAndCreate)
//!                         .create().unwrap();
//!
//! let client = UnixStreamClientBuilder::new(&socket_name)
//!                         .connect().unwrap();
//!
//! let server_conn = listener.blocking_accept().unwrap();
//!
//! let file_name = FilePath::new(b"/tmp/udsStreamExampleFile").unwrap();
//! let file = FileBuilder::new(&file_name)
//!                     .creation_mode(CreationMode::PurgeAndCreate)
//!                     .create().unwrap();
//!
//! // Send file descriptor
//! let mut msg = SocketAncillary::new();
//! msg.add_fd(file.file_descriptor().clone());
//! client.blocking_send_msg(&mut msg).unwrap();
//!
//! // Receive file descriptor
//! let mut recv_msg = SocketAncillary::new();
//! server_conn.blocking_receive_msg(&mut recv_msg).unwrap();
//!
//! let mut fd_vec = recv_msg.extract_fds();
//! let recv_file = File::from_file_descriptor(fd_vec.remove(0));
//!
//! // cleanup
//! File::remove(&file_name);
//! ```

use core::mem::MaybeUninit;
use core::{mem::size_of, time::Duration};

use alloc::format;

use iceoryx2_bb_concurrency::atomic::AtomicBool;
use iceoryx2_bb_concurrency::atomic::Ordering;
use iceoryx2_bb_container::semantic_string::*;
use iceoryx2_bb_elementary::enum_gen;
use iceoryx2_bb_elementary::scope_guard::ScopeGuardBuilder;
use iceoryx2_bb_system_types::file_path::FilePath;
use iceoryx2_log::{fail, fatal_panic, trace, warn};
use iceoryx2_pal_posix::posix::{errno::Errno, MemZeroedStruct};

use crate::clock::AsTimeval;
use crate::file_descriptor::{FileDescriptor, FileDescriptorBased, FileDescriptorManagement};
use crate::file_descriptor_set::SynchronousMultiplexing;
use crate::socket_ancillary::*;
use crate::{config::UNIX_DOMAIN_SOCKET_PATH_LENGTH, file::*, permission::Permission};

pub use crate::creation_mode::CreationMode;
use iceoryx2_pal_posix::*;

/// Error that can occur when creating a Unix stream socket.
#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
pub enum UnixStreamCreationError {
    SocketNameTooLong,
    InsufficientPermissions,
    InsufficientResources,
    InsufficientMemory,
    PerProcessFileHandleLimitReached,
    SystemWideFileHandleLimitReached,
    StreamProtocolNotSupported,
    UnixDomainSocketsNotSupported,
    InvalidFileDescriptor,
    UnknownError(i32),
}

enum_gen! {
    /// Error that can occur when creating a [`UnixStreamListener`].
    UnixStreamListenerCreationError
  entry:
    SocketFileAlreadyExists,
    InsufficientResources,
    InsufficientPermissions,
    AddressAlreadyInUse,
    PathDoesNotExist,
    ReadOnlyFileSytem,
    UnknownError(i32)
  mapping:
    UnixStreamSetSocketOptionError,
    UnixStreamCreationError,
    FileAccessError,
    FileRemoveError
}

enum_gen! {
    /// Error that can occur when creating a client connection.
    UnixStreamClientCreationError
  entry:
    InsufficientPermissions,
    InsufficientResources,
    AlreadyConnected,
    ConnectionRefused,
    Interrupt,
    ConnectionReset,
    WouldBlock,
    DoesNotExist,
    UnknownError(i32)
  mapping:
    UnixStreamCreationError
}

enum_gen! {
    /// Error that can occur when accepting a connection.
    UnixStreamAcceptError
  entry:
    ConnectionAborted,
    Interrupt,
    InsufficientResources,
    InsufficientMemory,
    InsufficientPermissions,
    WouldBlock,
    PerProcessFileHandleLimitReached,
    SystemWideFileHandleLimitReached,
    UnknownError(i32)
  mapping:
    UnixStreamSetPropertyError,
    UnixStreamSetSocketOptionError
}

enum_gen! {
    /// Error that can occur when sending data.
    UnixStreamSendError
  entry:
    MessageTooLarge,
    ConnectionReset,
    ConnectionRefused,
    Interrupt,
    IOerror,
    InsufficientPermissions,
    InsufficientResources,
    InsufficientMemory,
    NotConnected,
    BrokenPipe,
    MessagePartiallySend(u64),
    UnknownError(i32)
  mapping:
    UnixStreamSetPropertyError,
    UnixStreamSetSocketOptionError
}

enum_gen! {
    /// Error that can occur when sending a message with ancillary data.
    UnixStreamSendMsgError
  entry:
    MessageTooLarge,
    ConnectionReset,
    Interrupt,
    IOerror,
    InsufficientPermissions,
    InsufficientResources,
    InsufficientMemory,
    NotConnected,
    BrokenPipe,
    MaximumSupportedMessagesExceeded,
    MessagePartiallySend(u64),
    UnknownError(i32)
  mapping:
    UnixStreamSetPropertyError,
    UnixStreamSetSocketOptionError
}

enum_gen! {
    /// Error that can occur when receiving data.
    UnixStreamReceiveError
  entry:
    ConnectionReset,
    Interrupt,
    NotConnected,
    IOerror,
    InsufficientResources,
    InsufficientMemory,
    UnknownError(i32)
  mapping:
    UnixStreamSetPropertyError,
    UnixStreamSetSocketOptionError
}

enum_gen! {
    /// Error that can occur when receiving a message with ancillary data.
    UnixStreamReceiveMsgError
  entry:
    WouldBlock,
    ConnectionReset,
    Interrupt,
    NotConnected,
    IOerror,
    InsufficientResources,
    InsufficientMemory,
    ReceivedUnexpectedMessage,
    ReceivedInvalidFileDescriptor,
    UnknownError(i32)
  mapping:
    UnixStreamSetPropertyError,
    UnixStreamSetSocketOptionError
}

/// Error when setting socket options.
#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
pub enum UnixStreamSetSocketOptionError {
    InsufficientMemory,
    InsufficientResources,
    UnknownError(i32),
}

/// Error when getting socket options.
#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
pub enum UnixStreamGetSocketOptionError {
    InsufficientPermissions,
    InsufficientResources,
    SocketHasBeenShutDown,
    UnknownError(i32),
}

/// Error when setting properties via fcntl.
#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
pub enum UnixStreamSetPropertyError {
    Interrupt,
    WouldCauseOverflow,
    UnknownError(i32),
}

/// Error when getting peer credentials via SO_PEERCRED.
#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
pub enum UnixStreamGetPeerCredentialsError {
    InsufficientPermissions,
    InsufficientResources,
    SocketHasBeenShutDown,
    NotConnected,
    UnknownError(i32),
}

enum_gen! {
    /// The UnixStreamError enum is a generalization when one doesn't require the fine-grained error
    /// handling enums. One can forward UnixStreamError as more generic return value when a method
    /// returns a UnixStream***Error.
    /// On a higher level it is again convertable to [`crate::Error`].
    UnixStreamError
  generalization:
    CreationFailed <= UnixStreamClientCreationError; UnixStreamListenerCreationError,
    AcceptFailed <= UnixStreamAcceptError,
    SetupFailure <= UnixStreamSetSocketOptionError; UnixStreamSetPropertyError,
    SendFailed <= UnixStreamSendError,
    ReceiveFailed <= UnixStreamReceiveError
}

const BLOCKING_TIMEOUT: Duration = Duration::from_secs(i16::MAX as _);

/// Internal socket wrapper for SOCK_STREAM sockets.
#[derive(Debug)]
struct UnixStreamSocket {
    name: FilePath,
    is_non_blocking: AtomicBool,
    file_descriptor: FileDescriptor,
}

impl UnixStreamSocket {
    fn fcntl(
        &self,
        command: i32,
        value: i32,
        msg: &str,
    ) -> Result<i32, UnixStreamSetPropertyError> {
        let result =
            unsafe { posix::fcntl_int(self.file_descriptor.native_handle(), command, value) };

        if result >= 0 {
            return Ok(result);
        }

        handle_errno!(UnixStreamSetPropertyError, from self,
            fatal Errno::EBADF => ("This should never happen! {} since the file descriptor is invalid.", msg);
            fatal Errno::EINVAL => ("This should never happen! {} since an internal argument was invalid.", msg),
            Errno::EOVERFLOW => (WouldCauseOverflow, "{} since the operation would cause an overflow.", msg),
            Errno::EINTR => (Interrupt, "{} due to an interrupt signal.", msg),
            v => (UnknownError(v as i32), "{} since an unknown error occurred ({}).", msg, v)
        );
    }

    fn set_non_blocking(&self, value: bool) -> Result<(), UnixStreamSetPropertyError> {
        if self.is_non_blocking.load(Ordering::Relaxed) == value {
            return Ok(());
        }

        let current_flags = self.fcntl(
            posix::F_GETFL,
            0,
            "Unable to acquire current socket filedescriptor flags",
        )?;
        let new_flags = match value {
            true => current_flags | posix::O_NONBLOCK,
            false => current_flags & !posix::O_NONBLOCK,
        };

        self.fcntl(posix::F_SETFL, new_flags, "Unable to set blocking mode")?;
        self.is_non_blocking.store(value, Ordering::Relaxed);
        Ok(())
    }

    fn set_socket_option<T>(
        &self,
        msg: &str,
        value: &T,
        socket_option: posix::int,
    ) -> Result<(), UnixStreamSetSocketOptionError> {
        if unsafe {
            posix::setsockopt(
                self.file_descriptor.native_handle(),
                CMSG_SOCKET_LEVEL,
                socket_option,
                (value as *const T) as *const posix::void,
                core::mem::size_of::<T>() as u32,
            )
        } == 0
        {
            return Ok(());
        }

        handle_errno!(UnixStreamSetSocketOptionError, from self,
            Errno::ENOMEM => (InsufficientMemory, "{} due to insufficient memory.", msg),
            Errno::ENOBUFS => (InsufficientResources, "{} due to insufficient resources.", msg),
            v => (UnknownError(v as i32), "{} caused by an unknown error ({}).", msg, v)
        );
    }

    fn get_socket_option<T>(
        &self,
        msg: &str,
        socket_option: posix::int,
    ) -> Result<T, UnixStreamGetSocketOptionError> {
        let mut value: MaybeUninit<T> = MaybeUninit::uninit();
        let mut value_len: posix::socklen_t = core::mem::size_of::<T>() as posix::socklen_t;

        if unsafe {
            posix::getsockopt(
                self.file_descriptor.native_handle(),
                CMSG_SOCKET_LEVEL,
                socket_option,
                value.as_mut_ptr() as *mut posix::void,
                &mut value_len,
            )
        } == 0
        {
            return Ok(unsafe { value.assume_init() });
        }

        handle_errno!(UnixStreamGetSocketOptionError, from self,
            Errno::EACCES => (InsufficientPermissions, "{} due to insufficient permissions.", msg),
            Errno::ENOBUFS => (InsufficientResources, "{} due to insufficient resources.", msg),
            Errno::EINVAL => (SocketHasBeenShutDown, "{} since the socket has been shut down.", msg),
            v => (UnknownError(v as i32), "{} caused by an unknown error ({}).", msg, v)
        );
    }

    fn create_socket_address(&self) -> posix::sockaddr_un {
        let mut socket_address = posix::sockaddr_un::new_zeroed();
        socket_address.sun_family = posix::AF_UNIX;

        unsafe {
            posix::strncpy(
                socket_address.sun_path.as_mut_ptr(),
                self.name.as_c_str(),
                self.name.len(),
            );
        }

        socket_address
    }

    fn bind(&self, permission: Permission) -> Result<(), UnixStreamListenerCreationError> {
        let socket_address = self.create_socket_address();
        let ptr: *const posix::sockaddr_un = &socket_address;

        {
            let _mask = ScopeGuardBuilder::new(0 as posix::mode_t)
                .on_init(|mask| -> Result<(), ()> {
                    *mask = unsafe { posix::umask((!permission).bits()) };
                    Ok(())
                })
                .on_drop(|mask| unsafe {
                    posix::umask(*mask);
                })
                .create();

            if unsafe {
                posix::bind(
                    self.file_descriptor.native_handle(),
                    ptr as *const posix::sockaddr,
                    size_of::<posix::sockaddr_un>() as u32,
                )
            } == 0
            {
                return Ok(());
            }
        }

        let msg = "Failed to bind socket";
        handle_errno!(UnixStreamListenerCreationError, from self,
            Errno::EACCES => (InsufficientPermissions, "{} due to insufficient permissions.", msg),
            Errno::EADDRINUSE => (AddressAlreadyInUse, "{} since the address is already in use.", msg),
            Errno::ENOENT => (PathDoesNotExist, "{} since the path does not exist.", msg),
            Errno::ENOTDIR => (PathDoesNotExist, "{} since the path does not exist.", msg),
            Errno::ENOBUFS => (InsufficientResources, "{} due to insufficient resources.", msg),
            Errno::EROFS => (ReadOnlyFileSytem, "{} since it would reside on an read-only file system.", msg),
            v => (UnknownError(v as i32), "{} since an unknown error has occurred ({}).", msg, v)
        );
    }

    fn listen(&self, backlog: i32) -> Result<(), UnixStreamListenerCreationError> {
        if unsafe { posix::listen(self.file_descriptor.native_handle(), backlog) } == 0 {
            return Ok(());
        }

        let msg = "Failed to listen on socket";
        handle_errno!(UnixStreamListenerCreationError, from self,
            Errno::EADDRINUSE => (AddressAlreadyInUse, "{} since another socket is already listening on this address.", msg),
            Errno::ENOBUFS => (InsufficientResources, "{} due to insufficient resources.", msg),
            v => (UnknownError(v as i32), "{} since an unknown error has occurred ({}).", msg, v)
        );
    }

    fn connect(&self) -> Result<(), UnixStreamClientCreationError> {
        let socket_address = self.create_socket_address();
        let ptr: *const posix::sockaddr_un = &socket_address;
        if unsafe {
            posix::connect(
                self.file_descriptor.native_handle(),
                ptr as *const posix::sockaddr,
                size_of::<posix::sockaddr_un>() as u32,
            )
        } == 0
        {
            return Ok(());
        }

        let msg = "Failed to connect";
        handle_errno!(UnixStreamClientCreationError, from self,
            Errno::ENOENT => (DoesNotExist, "{} since the unix stream listener does not exist.", msg),
            Errno::EACCES => (InsufficientPermissions, "{} due to insufficient permissions.", msg),
            Errno::EADDRINUSE => (AlreadyConnected, "{} since it is already connected.", msg),
            Errno::ECONNREFUSED => (ConnectionRefused, "{} since the connection was refused.", msg),
            Errno::EINTR => (Interrupt, "{} since an interrupt was received.", msg),
            Errno::ECONNRESET => (ConnectionReset, "{} since the host reset the connection request.", msg),
            Errno::ENOBUFS => (InsufficientResources, "{} since there is no buffer space available.", msg),
            Errno::EINPROGRESS => (WouldBlock, "{} since the operation would block the process. Allow blocking and the connection can may be established.", msg),
            v => (UnknownError(v as i32), "{} caused by an unknown error ({}).", msg, v)
        );
    }

    fn new(name: &FilePath) -> Result<Self, UnixStreamCreationError> {
        if name.len() > UNIX_DOMAIN_SOCKET_PATH_LENGTH {
            fail!(with UnixStreamCreationError::SocketNameTooLong,
                "The name \"{}\" is too long for a UnixStreamSocket name. Maximum supported length is {}.", name, UNIX_DOMAIN_SOCKET_PATH_LENGTH);
        }

        let raw_fd = unsafe { posix::socket(posix::PF_UNIX as posix::int, posix::SOCK_STREAM, 0) };

        let msg = format!("Unable to create UnixStreamSocket named \"{name}\"");
        if raw_fd < 0 {
            handle_errno!(UnixStreamCreationError, from "UnixStreamSocket::new",
                Errno::EACCES => (InsufficientPermissions, "{} due to insufficient permissions.", msg),
                Errno::EMFILE => (PerProcessFileHandleLimitReached, "{} since the per-process limit of file descriptors was reached.", msg),
                Errno::ENFILE => (SystemWideFileHandleLimitReached, "{} since system-wide limit of file descriptors was reached.", msg),
                Errno::ENOBUFS => (InsufficientResources, "{} due to insufficient resources.", msg),
                Errno::ENOMEM => (InsufficientMemory, "{} due to insufficient memory.", msg),
                Errno::EPROTONOSUPPORT => (StreamProtocolNotSupported, "{} since the stream protocol is not supported by the system.", msg),
                Errno::EPROTOTYPE => (UnixDomainSocketsNotSupported, "{} since UnixDomainSockets are not supported by the system.", msg),
                v => (UnknownError(v as i32), "Unable to create socket since an unknown error occurred ({}).", v)
            );
        }

        Ok(Self {
            name: *name,
            is_non_blocking: AtomicBool::new(false),
            file_descriptor: FileDescriptor::new(raw_fd).unwrap(),
        })
    }

    fn from_fd(name: &FilePath, fd: FileDescriptor) -> Self {
        // Note: This is an internal function called only from accept(), which guarantees
        // the returned FD is a SOCK_STREAM socket when the listener is SOCK_STREAM.
        // Socket type validation would require SO_TYPE which isn't exposed in the PAL.
        Self {
            name: *name,
            is_non_blocking: AtomicBool::new(false),
            file_descriptor: fd,
        }
    }
}

/// Builder for creating a [`UnixStreamListener`].
#[derive(Debug)]
pub struct UnixStreamListenerBuilder {
    name: FilePath,
    permission: Permission,
    creation_mode: CreationMode,
    backlog: i32,
}

impl UnixStreamListenerBuilder {
    /// Creates a new builder for the given socket path.
    pub fn new(name: &FilePath) -> Self {
        Self {
            name: *name,
            permission: Permission::OWNER_ALL,
            creation_mode: CreationMode::CreateExclusive,
            backlog: 128,
        }
    }

    /// Sets the permission of the socket file.
    pub fn permission(mut self, permission: Permission) -> Self {
        self.permission = permission;
        self
    }

    /// Defines the creation mode.
    pub fn creation_mode(mut self, value: CreationMode) -> Self {
        self.creation_mode = value;
        self
    }

    /// Sets the listen backlog (max pending connections).
    pub fn backlog(mut self, value: i32) -> Self {
        self.backlog = value;
        self
    }

    /// Creates the listener.
    pub fn create(self) -> Result<UnixStreamListener, UnixStreamListenerCreationError> {
        UnixStreamListener::new(self)
    }
}

/// A Unix stream socket listener that accepts incoming connections.
/// Created by [`UnixStreamListenerBuilder`].
#[derive(Debug)]
pub struct UnixStreamListener {
    socket: UnixStreamSocket,
}

impl Drop for UnixStreamListener {
    fn drop(&mut self) {
        fatal_panic!(from self, when File::remove(&self.socket.name), "Failed to remove socket file.");
        trace!(from self, "stop listening and remove");
    }
}

impl UnixStreamListener {
    fn new(config: UnixStreamListenerBuilder) -> Result<Self, UnixStreamListenerCreationError> {
        let msg = "Unable to create new socket";
        let new_socket = Self {
            socket: fail!(from config, when UnixStreamSocket::new(&config.name), "{}.", msg),
        };

        let does_file_exist = fail!(from new_socket, when File::does_exist(&config.name), "Unable to determine if socket exists.");

        if config.creation_mode == CreationMode::PurgeAndCreate && does_file_exist {
            fail!(from new_socket, when File::remove(&config.name), "{} since the already existing socket could not be removed.", msg);
        } else if config.creation_mode == CreationMode::CreateExclusive && does_file_exist {
            fail!(from new_socket, with UnixStreamListenerCreationError::SocketFileAlreadyExists, "{} since it already exists.", msg);
        }

        fail!(from new_socket, when new_socket.socket.bind(config.permission), "{} since the socket could not be bound.", msg);
        fail!(from new_socket, when new_socket.socket.listen(config.backlog), "{} since the socket could not listen.", msg);

        if posix::POSIX_SUPPORT_UNIX_DATAGRAM_SOCKETS_ANCILLARY_DATA {
            fail!(from new_socket, when new_socket.socket.set_socket_option("Unable to activate credential support", &1u32, posix::SO_PASSCRED),
                "{} since the credential support could not be activated.", msg);
        }

        trace!(from new_socket, "create and listening");
        Ok(new_socket)
    }

    /// Returns the name (path) of the socket.
    pub fn name(&self) -> &FilePath {
        &self.socket.name
    }

    fn set_non_blocking(&self, value: bool) -> Result<(), UnixStreamSetPropertyError> {
        self.socket.set_non_blocking(value)
    }

    fn set_timeout(&self, timeout: Duration) -> Result<(), UnixStreamSetSocketOptionError> {
        self.socket.set_socket_option(
            "Unable to set receive timeout",
            &timeout.as_timeval(),
            posix::SO_RCVTIMEO,
        )
    }

    fn accept_internal(&self) -> Result<Option<UnixStreamConnection>, UnixStreamAcceptError> {
        let mut client_addr = posix::sockaddr_un::new_zeroed();
        let mut addr_len: posix::socklen_t = size_of::<posix::sockaddr_un>() as posix::socklen_t;

        let client_fd = unsafe {
            posix::accept(
                self.socket.file_descriptor.native_handle(),
                (&mut client_addr as *mut posix::sockaddr_un) as *mut posix::sockaddr,
                &mut addr_len,
            )
        };

        if client_fd >= 0 {
            let fd = FileDescriptor::new(client_fd).unwrap();
            let conn_socket = UnixStreamSocket::from_fd(&self.socket.name, fd);

            // Enable SO_PASSCRED on accepted socket for credential passing
            if posix::POSIX_SUPPORT_UNIX_DATAGRAM_SOCKETS_ANCILLARY_DATA {
                if let Err(e) =
                    conn_socket.set_socket_option("Enable SO_PASSCRED", &1u32, posix::SO_PASSCRED)
                {
                    warn!(from self, "Failed to enable SO_PASSCRED on accepted socket: {:?}", e);
                }
            }

            return Ok(Some(UnixStreamConnection {
                socket: conn_socket,
            }));
        }

        let msg = "Unable to accept connection";
        handle_errno!(UnixStreamAcceptError, from self,
            success Errno::EAGAIN => None;
            success Errno::ETIMEDOUT => None,
            Errno::ECONNABORTED => (ConnectionAborted, "{} since the connection was aborted.", msg),
            Errno::EINTR => (Interrupt, "{} since an interrupt signal was received.", msg),
            Errno::ENOBUFS => (InsufficientResources, "{} due to insufficient resources.", msg),
            Errno::ENOMEM => (InsufficientMemory, "{} due to insufficient memory.", msg),
            Errno::EMFILE => (PerProcessFileHandleLimitReached, "{} since the per-process limit of file descriptors was reached.", msg),
            Errno::ENFILE => (SystemWideFileHandleLimitReached, "{} since system-wide limit of file descriptors was reached.", msg),
            Errno::EPERM => (InsufficientPermissions, "{} due to firewall rules.", msg),
            v => (UnknownError(v as i32), "{} due to an unknown error ({}).", msg, v)
        );
    }

    /// Tries to accept a connection without blocking. Returns `None` if no connection is pending.
    pub fn try_accept(&self) -> Result<Option<UnixStreamConnection>, UnixStreamAcceptError> {
        fail!(from self, when self.set_non_blocking(true),
                "Unable to try accept since the socket could not be set into non-blocking state.");
        self.accept_internal()
    }

    /// Blocks until a connection is accepted or the timeout expires.
    pub fn timed_accept(
        &self,
        timeout: Duration,
    ) -> Result<Option<UnixStreamConnection>, UnixStreamAcceptError> {
        let msg = "Unable to timed accept";
        fail!(from self, when self.set_non_blocking(false),
                "{} since the socket could not be set into blocking state.", msg);
        fail!(from self, when self.set_timeout(timeout),
                "{} since the socket timeout could not be set.", msg);
        self.accept_internal()
    }

    /// Blocks until a connection is accepted.
    pub fn blocking_accept(&self) -> Result<UnixStreamConnection, UnixStreamAcceptError> {
        let msg = "Unable to blocking accept";

        // Setup ONCE before the loop
        fail!(from self, when self.set_non_blocking(false),
            "{} since the socket could not be set into blocking state.", msg);
        fail!(from self, when self.set_timeout(BLOCKING_TIMEOUT),
            "{} since the socket blocking timeout could not be set.", msg);

        loop {
            match self.accept_internal() {
                Ok(Some(conn)) => return Ok(conn),
                Ok(None) => continue,
                Err(e) => return Err(e),
            }
        }
    }
}

impl FileDescriptorBased for UnixStreamListener {
    fn file_descriptor(&self) -> &FileDescriptor {
        &self.socket.file_descriptor
    }
}

impl FileDescriptorManagement for UnixStreamListener {}

impl SynchronousMultiplexing for UnixStreamListener {}

/// Builder for creating a client connection to a Unix stream socket.
#[derive(Debug)]
pub struct UnixStreamClientBuilder {
    name: FilePath,
}

impl UnixStreamClientBuilder {
    /// Creates a new builder for connecting to the given socket path.
    pub fn new(name: &FilePath) -> Self {
        Self { name: *name }
    }

    /// Connects to the server.
    pub fn connect(self) -> Result<UnixStreamConnection, UnixStreamClientCreationError> {
        let msg = "Failed to create UnixStreamConnection";
        let socket = fail!(from self, when UnixStreamSocket::new(&self.name), "{}.", msg);

        match socket.connect() {
            Err(UnixStreamClientCreationError::DoesNotExist) => {
                fail!(from self, with UnixStreamClientCreationError::DoesNotExist,
                    "{} since the connection could not be established.", msg);
            }
            Err(v) => {
                return Err(v);
            }
            Ok(_) => (),
        };

        // Enable SO_PASSCRED for credential passing
        if posix::POSIX_SUPPORT_UNIX_DATAGRAM_SOCKETS_ANCILLARY_DATA {
            if let Err(e) =
                socket.set_socket_option("Enable SO_PASSCRED", &1u32, posix::SO_PASSCRED)
            {
                warn!(from self, "Failed to enable SO_PASSCRED on client socket: {:?}", e);
            }
        }

        trace!(from self, "connected");

        Ok(UnixStreamConnection { socket })
    }
}

/// A bidirectional Unix stream socket connection.
/// Can be obtained by accepting on a [`UnixStreamListener`] or connecting via [`UnixStreamClientBuilder`].
#[derive(Debug)]
pub struct UnixStreamConnection {
    socket: UnixStreamSocket,
}

impl Drop for UnixStreamConnection {
    fn drop(&mut self) {
        trace!(from self, "disconnected");
    }
}

impl UnixStreamConnection {
    /// Returns the name of the socket.
    pub fn name(&self) -> &FilePath {
        &self.socket.name
    }

    fn set_non_blocking(&self, value: bool) -> Result<(), UnixStreamSetPropertyError> {
        self.socket.set_non_blocking(value)
    }

    fn set_send_timeout(&self, timeout: Duration) -> Result<(), UnixStreamSetSocketOptionError> {
        self.socket.set_socket_option(
            "Unable to set send timeout",
            &timeout.as_timeval(),
            posix::SO_SNDTIMEO,
        )
    }

    fn set_recv_timeout(&self, timeout: Duration) -> Result<(), UnixStreamSetSocketOptionError> {
        self.socket.set_socket_option(
            "Unable to set receive timeout",
            &timeout.as_timeval(),
            posix::SO_RCVTIMEO,
        )
    }

    /// Sets the send buffer minimum size.
    pub fn set_send_buffer_min_size(
        &mut self,
        value: usize,
    ) -> Result<(), UnixStreamSetSocketOptionError> {
        let temp = value as posix::int;
        self.socket
            .set_socket_option("Unable to set send buffer size", &temp, posix::SO_SNDBUF)
    }

    /// Sets the receive buffer minimum size.
    pub fn set_receive_buffer_min_size(
        &mut self,
        value: usize,
    ) -> Result<(), UnixStreamSetSocketOptionError> {
        let temp = value as posix::int;
        self.socket
            .set_socket_option("Unable to set receive buffer size", &temp, posix::SO_RCVBUF)
    }

    /// Returns the send buffer size.
    pub fn get_send_buffer_size(&self) -> Result<usize, UnixStreamGetSocketOptionError> {
        Ok(self.socket.get_socket_option::<posix::int>(
            "Unable to acquire send buffer size",
            posix::SO_SNDBUF,
        )? as usize)
    }

    /// Returns the receive buffer size.
    pub fn get_receive_buffer_size(&self) -> Result<usize, UnixStreamGetSocketOptionError> {
        Ok(self.socket.get_socket_option::<posix::int>(
            "Unable to acquire receive buffer size",
            posix::SO_RCVBUF,
        )? as usize)
    }

    // ---- Send Methods ----

    fn send(&self, data: &[u8]) -> Result<u64, UnixStreamSendError> {
        let bytes_sent = unsafe {
            posix::send(
                self.socket.file_descriptor.native_handle(),
                data.as_ptr() as *const posix::void,
                data.len(),
                0,
            )
        };

        let msg = "Unable to send data";
        if bytes_sent < 0 {
            handle_errno!(UnixStreamSendError, from self,
                success Errno::EAGAIN => 0,
                Errno::ECONNRESET => (ConnectionReset, "{} since the connection was reset by peer.", msg),
                Errno::ECONNREFUSED => (ConnectionRefused, "{} since the connection was refused by peer.", msg),
                Errno::EINTR => (Interrupt, "{} since an interrupt signal was received.", msg),
                Errno::EMSGSIZE => (MessageTooLarge, "{} since the message size of {} bytes is too large to be sent.", msg, data.len()),
                Errno::EIO => (IOerror, "{} since an I/O error occurred.", msg),
                Errno::EACCES => (InsufficientPermissions, "{} due to insufficient permissions.", msg),
                Errno::ENOBUFS => (InsufficientResources, "{} due to insufficient resources.", msg),
                Errno::ENOMEM => (InsufficientMemory, "{} due to insufficient memory.", msg),
                Errno::ENOTCONN => (NotConnected, "{} since the socket is not yet connected.", msg),
                Errno::EPIPE => (BrokenPipe, "{} since the connection has been broken.", msg),
                v => (UnknownError(v as i32), "{} since an unknown error occurred ({}).", msg, v)
            );
        }

        Ok(bytes_sent as u64)
    }

    /// Tries to send data in a non-blocking way. Returns the number of bytes sent.
    pub fn try_send(&self, data: &[u8]) -> Result<u64, UnixStreamSendError> {
        fail!(from self, when self.set_non_blocking(true),
                "Unable to try send data since the socket could not be set into non-blocking state.");
        self.send(data)
    }

    /// Blocks until the data is sent or the timeout expires.
    pub fn timed_send(&self, data: &[u8], timeout: Duration) -> Result<u64, UnixStreamSendError> {
        let msg = "Unable to timed send data";
        fail!(from self, when self.set_non_blocking(false),
                "{} since the socket could not be set into blocking state.", msg);
        fail!(from self, when self.set_send_timeout(timeout),
                "{} since the socket timeout could not be set.", msg);
        self.send(data)
    }

    /// Blocks until all data is sent.
    pub fn blocking_send(&self, data: &[u8]) -> Result<(), UnixStreamSendError> {
        let msg = "Unable to blocking send data";
        fail!(from self, when self.set_non_blocking(false),
                "{} since the socket could not be set into blocking state.", msg);
        fail!(from self, when self.set_send_timeout(BLOCKING_TIMEOUT),
                "{} since the socket blocking timeout could not be set.", msg);

        let mut total_sent = 0usize;
        while total_sent < data.len() {
            let sent = self.send(&data[total_sent..])?;
            if sent == 0 {
                // Would block, just retry
                continue;
            }
            total_sent += sent as usize;
        }

        Ok(())
    }

    // ---- Receive Methods ----

    fn receive(&self, buffer: &mut [u8], flags: posix::int) -> Result<u64, UnixStreamReceiveError> {
        let bytes_received = unsafe {
            posix::recv(
                self.socket.file_descriptor.native_handle(),
                buffer.as_mut_ptr() as *mut posix::void,
                buffer.len(),
                flags,
            )
        };

        if bytes_received >= 0 {
            return Ok(bytes_received as u64);
        }

        let msg = "Unable to receive data";
        handle_errno!(UnixStreamReceiveError, from self,
            success Errno::ETIMEDOUT => 0;
            success Errno::EAGAIN => 0,
            Errno::ECONNRESET => (ConnectionReset, "{} since connection was forcibly closed.", msg),
            Errno::EINTR => (Interrupt, "{} since an interrupt signal was received.", msg),
            Errno::EIO => (IOerror, "{} since an I/O error occurred.", msg),
            Errno::ENOBUFS => (InsufficientResources, "{} due to insufficient resources.", msg),
            Errno::ENOMEM => (InsufficientMemory, "{} due to insufficient memory.", msg),
            Errno::ENOTCONN => (NotConnected, "{} since the socket is not connected.", msg),
            v => (UnknownError(v as i32), "{} due to an unknown error ({}).", msg, v)
        );
    }

    /// Tries to receive data without blocking. Returns the number of bytes received (0 if no data available).
    pub fn try_receive(&self, buffer: &mut [u8]) -> Result<u64, UnixStreamReceiveError> {
        fail!(from self, when self.set_non_blocking(true),
                "Unable to try receive data since the socket could not be set into non-blocking state.");
        self.receive(buffer, 0)
    }

    /// Blocks until data is received or the timeout expires.
    pub fn timed_receive(
        &self,
        buffer: &mut [u8],
        timeout: Duration,
    ) -> Result<u64, UnixStreamReceiveError> {
        let msg = "Unable to timed receive data";
        fail!(from self, when self.set_non_blocking(false),
                "{} since the socket could not be set into blocking state.", msg);
        fail!(from self, when self.set_recv_timeout(timeout),
                "{} since the socket timeout could not be set.", msg);
        self.receive(buffer, 0)
    }

    /// Blocks until data is received.
    pub fn blocking_receive(&self, buffer: &mut [u8]) -> Result<u64, UnixStreamReceiveError> {
        let msg = "Unable to blocking receive data";

        // Setup ONCE before the loop
        fail!(from self, when self.set_non_blocking(false),
            "{} since the socket could not be set into blocking state.", msg);
        fail!(from self, when self.set_recv_timeout(BLOCKING_TIMEOUT),
            "{} since the socket blocking timeout could not be set.", msg);

        loop {
            match self.receive(buffer, 0) {
                Ok(0) => continue,
                Ok(v) => return Ok(v),
                Err(e) => return Err(e),
            }
        }
    }

    /// Peeks at incoming data without removing it from the queue.
    pub fn try_peek(&self, buffer: &mut [u8]) -> Result<u64, UnixStreamReceiveError> {
        fail!(from self, when self.set_non_blocking(true),
                "Unable to try peek data since the socket could not be set into non-blocking state.");
        self.receive(buffer, posix::MSG_PEEK)
    }

    // ---- Send/Receive Message Methods (for SocketAncillary) ----

    fn send_msg(&self, uds_msg: &mut SocketAncillary) -> Result<bool, UnixStreamSendMsgError> {
        uds_msg.prepare_for_send();

        let msg = "Unable to send unix domain socket message";
        const FLAGS: i32 = 0;
        let bytes_sent = unsafe {
            posix::sendmsg(
                self.socket.file_descriptor.native_handle(),
                uds_msg.get(),
                FLAGS,
            )
        };

        if bytes_sent > 0 {
            // A `SocketAncillary` message carries fds/credentials plus a single dummy data byte.
            // The SCM_RIGHTS / SCM_CREDENTIALS control payload travels atomically with that byte,
            // so any positive return means the ancillary message (and its handles) were sent.
            return Ok(true);
        }

        // For EAGAIN, return false (nothing sent)
        if bytes_sent == 0 {
            return Ok(false);
        }

        handle_errno!(UnixStreamSendMsgError, from self,
            success Errno::EAGAIN => false,
            fatal Errno::EINVAL => ("{} {} due to an implementation error. The msghdr.msg_controllen size does not fit the used cmsghdrs.", msg, uds_msg),
            Errno::ECONNRESET => (ConnectionReset, "{} {} since the connection was reset by peer.", msg, uds_msg),
            Errno::EINTR => (Interrupt, "{} {} since an interrupt signal was received.", msg, uds_msg),
            Errno::EMSGSIZE => (MessageTooLarge, "{} {} since the message size of {} bytes is too large to be sent in one package.", msg, uds_msg, uds_msg.len()),
            Errno::EIO => (IOerror, "{} {} since an I/O error occurred while writing.", msg, uds_msg),
            Errno::EACCES => (InsufficientPermissions, "{} {} due to insufficient permissions.", msg, uds_msg),
            Errno::EPERM => (InsufficientPermissions, "{} {} due to insufficient permissions.", msg, uds_msg),
            Errno::ENOBUFS => (InsufficientResources, "{} {} due to insufficient resources.", msg, uds_msg),
            Errno::ENOMEM => (InsufficientMemory, "{} {} due to insufficient memory.", msg, uds_msg),
            Errno::ENOTCONN => (NotConnected, "{} {} since the socket is not yet connected.", msg, uds_msg),
            Errno::EPIPE => (BrokenPipe, "{} {} since the connection has been broken.", msg, uds_msg),
            v => (UnknownError(v as i32), "{} {} since an unknown error occurred ({}).", msg, uds_msg, v)
        );
    }

    /// Tries to send a [`SocketAncillary`] message (for file descriptor passing).
    pub fn try_send_msg(
        &self,
        uds_msg: &mut SocketAncillary,
    ) -> Result<bool, UnixStreamSendMsgError> {
        fail!(from self, when self.set_non_blocking(true),
                "Unable to try send message since the socket could not be set into non-blocking state.");
        self.send_msg(uds_msg)
    }

    /// Blocks until the [`SocketAncillary`] message is sent.
    pub fn blocking_send_msg(
        &self,
        uds_msg: &mut SocketAncillary,
    ) -> Result<(), UnixStreamSendMsgError> {
        let msg = "Unable to blocking send message";
        fail!(from self, when self.set_non_blocking(false),
                "{} since the socket could not be set into blocking state.", msg);
        fail!(from self, when self.set_send_timeout(BLOCKING_TIMEOUT),
                "{} since the socket blocking timeout could not be set.", msg);
        self.send_msg(uds_msg)?;
        Ok(())
    }

    fn receive_msg(
        &self,
        socket_msg: &mut SocketAncillary,
    ) -> Result<bool, UnixStreamReceiveMsgError> {
        socket_msg.clear();

        let msg = "Unable to receive message";
        match unsafe {
            posix::recvmsg(
                self.socket.file_descriptor.native_handle(),
                socket_msg.get_mut(),
                0,
            )
        } {
            1..=isize::MAX => {
                socket_msg.extract_received_data_for_stream(self);
                Ok(true)
            }
            _ => {
                handle_errno!(UnixStreamReceiveMsgError, from self,
                    success Errno::ETIMEDOUT => false;
                    success Errno::EAGAIN => false,
                    Errno::ECONNRESET => (ConnectionReset, "{} since connection was forcibly closed.", msg),
                    Errno::EINTR => (Interrupt, "{} since an interrupt signal was received.", msg),
                    Errno::ENOTCONN => (NotConnected, "{} since socket is not connected.", msg),
                    Errno::EIO => (IOerror, "{} since an I/O error occurred.", msg),
                    Errno::ENOBUFS => (InsufficientResources, "{} due to insufficient resources.", msg),
                    Errno::ENOMEM => (InsufficientMemory, "{} due to insufficient memory.", msg),
                    v => (UnknownError(v as i32), "{} due to an unknown error ({}).", msg, v)
                )
            }
        }
    }

    /// Tries to receive a [`SocketAncillary`] message without blocking.
    pub fn try_receive_msg(
        &self,
        socket_msg: &mut SocketAncillary,
    ) -> Result<bool, UnixStreamReceiveMsgError> {
        fail!(from self, when self.set_non_blocking(true),
                "Unable to try receive message since the socket could not be set into non-blocking state.");
        self.receive_msg(socket_msg)
    }

    /// Blocks until a [`SocketAncillary`] message is received.
    pub fn blocking_receive_msg(
        &self,
        socket_msg: &mut SocketAncillary,
    ) -> Result<bool, UnixStreamReceiveMsgError> {
        let msg = "Unable to blocking receive message";
        fail!(from self, when self.set_non_blocking(false),
                "{} since the socket could not be set into blocking state.", msg);
        fail!(from self, when self.set_recv_timeout(BLOCKING_TIMEOUT),
                "{} since the socket blocking timeout could not be set.", msg);
        self.receive_msg(socket_msg)
    }

    /// Returns the credentials of the connected peer via SO_PEERCRED.
    /// This provides a race-free way to get the peer's pid, uid, and gid.
    pub fn peer_credentials(&self) -> Result<SocketCred, UnixStreamGetPeerCredentialsError> {
        let mut cred: posix::ucred = unsafe { core::mem::zeroed() };
        let mut len: posix::socklen_t = core::mem::size_of::<posix::ucred>() as posix::socklen_t;

        if unsafe {
            posix::getsockopt(
                self.socket.file_descriptor.native_handle(),
                CMSG_SOCKET_LEVEL,
                posix::SO_PEERCRED,
                (&mut cred as *mut posix::ucred) as *mut posix::void,
                &mut len,
            )
        } != 0
        {
            let msg = "Unable to get peer credentials";
            handle_errno!(UnixStreamGetPeerCredentialsError, from self,
                Errno::EACCES => (InsufficientPermissions, "{} due to insufficient permissions.", msg),
                Errno::ENOBUFS => (InsufficientResources, "{} due to insufficient resources.", msg),
                Errno::EINVAL => (SocketHasBeenShutDown, "{} since the socket has been shut down.", msg),
                Errno::ENOTCONN => (NotConnected, "{} since the socket is not connected.", msg),
                v => (UnknownError(v as i32), "{} caused by an unknown error ({}).", msg, v)
            );
        }

        Ok(SocketCred::from_ucred(cred))
    }
}

impl FileDescriptorBased for UnixStreamConnection {
    fn file_descriptor(&self) -> &FileDescriptor {
        &self.socket.file_descriptor
    }
}

impl FileDescriptorManagement for UnixStreamConnection {}

impl SynchronousMultiplexing for UnixStreamConnection {}
