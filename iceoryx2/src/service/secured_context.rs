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

//! Secured service context for IAM-protected services.
//!
//! This module provides [`SecuredServiceContext`] which wraps an IAM client
//! and manages the lifecycle of secured service connections.
//!
//! # Overview
//!
//! When a service is created or opened in [`SecurityMode::Secured`] mode,
//! a `SecuredServiceContext` is created to manage:
//! - IAM client connection to the service's IAM server
//! - Port attachment and detachment operations
//! - Segment handle management
//!
//! # Usage
//!
//! The `SecuredServiceContext` is stored in the [`ServiceState`] as the
//! additional resource, implementing [`ServiceResource`] for proper cleanup.
//!
//! ```ignore
//! // Created automatically by service builder for secured services
//! let context = SecuredServiceContext::new(iam_client, service_id);
//!
//! // Attach a publisher and receive handles
//! let (port_id, segments, handles) = context.attach_publisher(history_size, max_slice_len)?;
//!
//! // Use handles to open shared memory segments
//! ```
//!
//! [`SecurityMode::Secured`]: iceoryx2_cal::security::mode::SecurityMode::Secured
//! [`ServiceState`]: super::ServiceState
//! [`ServiceResource`]: super::ServiceResource

use alloc::boxed::Box;
use alloc::vec::Vec;
use std::sync::Mutex;

use iceoryx2_cal::security::handle::PlatformHandle;

use iceoryx2_cal::control_channel::ControlChannelClient as CalClient;

use iceoryx2_cal::shm_allocator::SegmentId;

use crate::iam::client::IamClient;
use crate::iam::error::IamClientError;
use crate::iam::protocol::{SegmentInfo, SessionId};
use crate::service::service_id::ServiceId;

use super::ServiceResource;

// ============================================================================
// Type-Erased Secured Context
// ============================================================================

/// Trait for type-erasing the control channel connection generic parameter.
///
/// This trait allows `SecuredServiceContext<C>` to be stored without the
/// control channel type being visible in the `ServiceState` type signature.
///
/// # Safety
///
/// Implementations must be `Send + Sync` since they are stored in `Arc<ServiceState>`.
/// Interior mutability must use thread-safe synchronization (Mutex, not RefCell).
pub(crate) trait ErasedSecuredContext: Send + Sync {
    /// Attaches as a publisher to the service.
    fn attach_publisher(
        &self,
        history_size: usize,
        max_slice_len: usize,
    ) -> Result<(u128, Vec<SegmentInfo>, Vec<PlatformHandle>), IamClientError>;

    /// Attaches as a subscriber to the service.
    fn attach_subscriber(
        &self,
        buffer_size: usize,
    ) -> Result<(u128, Vec<SegmentInfo>, Vec<PlatformHandle>), IamClientError>;

    /// Attaches as a server to a request-response service.
    fn attach_server(
        &self,
        max_active_requests: usize,
    ) -> Result<(u128, Vec<SegmentInfo>, Vec<PlatformHandle>), IamClientError>;

    /// Attaches as a client to a request-response service.
    fn attach_client(
        &self,
        max_pending_responses: usize,
    ) -> Result<(u128, Vec<SegmentInfo>, Vec<PlatformHandle>), IamClientError>;

    /// Returns true if the IAM client is active.
    fn is_active(&self) -> bool;

    /// Returns the session ID.
    fn session_id(&self) -> SessionId;

    /// Disconnects from the IAM server.
    fn disconnect(&self);

    /// Returns the service ID this context is associated with.
    fn service_id(&self) -> &ServiceId;

    /// Registers a producer's segment handle with the IAM server.
    fn register_segment(
        &self,
        port_id: u128,
        segment_size: usize,
        handle: &PlatformHandle,
    ) -> Result<SegmentId, IamClientError>;

    /// Requests a segment handle for a sender port's data segment.
    fn request_segment_handle(
        &self,
        sender_port_id: u128,
    ) -> Result<Option<(SegmentInfo, PlatformHandle)>, IamClientError>;

    /// Registers a dynamic segment handle at a specific index with the IAM server.
    fn register_dynamic_segment(
        &self,
        port_id: u128,
        segment_index: u8,
        segment_size: usize,
        handle: &PlatformHandle,
    ) -> Result<u8, IamClientError>;

    /// Requests a specific dynamic segment handle by index from a sender port.
    fn request_dynamic_segment_handle(
        &self,
        sender_port_id: u128,
        segment_index: u8,
    ) -> Result<Option<(SegmentInfo, PlatformHandle)>, IamClientError>;

    /// Requests a new segment to be created by the IAM server.
    ///
    /// Called by producers when they receive a [`NeedSegment`] error during allocation.
    /// The IAM server creates an anonymous segment and returns a handle for it.
    ///
    /// # Arguments
    ///
    /// * `port_id` - The port requesting the segment
    /// * `requested_size` - The minimum requested size for the new segment
    ///
    /// # Returns
    ///
    /// On success, returns a tuple of:
    /// - The assigned segment ID
    /// - The actual size allocated
    /// - Platform handles for the segment
    ///
    /// [`NeedSegment`]: crate::port::details::data_segment::DataSegmentAllocationError::NeedSegment
    fn add_segment(
        &self,
        port_id: u128,
        requested_size: usize,
        bucket_size: usize,
        bucket_align: usize,
    ) -> Result<(SegmentId, usize, Vec<PlatformHandle>), IamClientError>;

    /// Tries to receive a pending notification without blocking.
    ///
    /// This is used by consumers to proactively receive segment handles
    /// pushed by the IAM server when producers add new segments.
    ///
    /// # Returns
    ///
    /// * `Ok(Some((notification, handles)))` - A notification was received
    /// * `Ok(None)` - No notification is pending
    fn try_receive_notification(
        &self,
    ) -> Result<Option<(crate::iam::protocol::IamNotification, Vec<PlatformHandle>)>, IamClientError>;
}

/// Type-erased wrapper for `SecuredServiceContext`.
///
/// This struct hides the control channel generic parameter, allowing
/// `SecuredServiceContext` to be stored in `ServiceState` without
/// propagating the generic parameter through the entire type hierarchy.
///
/// # Example
///
/// ```ignore
/// // Create a SecuredServiceContext with a specific control channel type
/// let ctx: SecuredServiceContext<UnixStreamConnection> = ...;
///
/// // Wrap in type-erased container
/// let erased = TypeErasedSecuredContext::new(ctx);
///
/// // Now can be stored without the generic parameter
/// let resource = SecurityResource::SecuredClient(erased);
/// ```
pub(crate) struct TypeErasedSecuredContext {
    inner: Box<dyn ErasedSecuredContext>,
}

impl TypeErasedSecuredContext {
    /// Creates a new type-erased secured context from a concrete implementation.
    pub fn new<C>(ctx: SecuredServiceContext<C>) -> Self
    where
        C: CalClient + Send + 'static,
    {
        Self {
            inner: Box::new(ctx),
        }
    }

    /// Attaches as a publisher to the service.
    pub fn attach_publisher(
        &self,
        history_size: usize,
        max_slice_len: usize,
    ) -> Result<(u128, Vec<SegmentInfo>, Vec<PlatformHandle>), IamClientError> {
        self.inner.attach_publisher(history_size, max_slice_len)
    }

    /// Attaches as a subscriber to the service.
    pub fn attach_subscriber(
        &self,
        buffer_size: usize,
    ) -> Result<(u128, Vec<SegmentInfo>, Vec<PlatformHandle>), IamClientError> {
        self.inner.attach_subscriber(buffer_size)
    }

    /// Attaches as a server to a request-response service.
    pub fn attach_server(
        &self,
        max_active_requests: usize,
    ) -> Result<(u128, Vec<SegmentInfo>, Vec<PlatformHandle>), IamClientError> {
        self.inner.attach_server(max_active_requests)
    }

    /// Attaches as a client to a request-response service.
    pub fn attach_client(
        &self,
        max_pending_responses: usize,
    ) -> Result<(u128, Vec<SegmentInfo>, Vec<PlatformHandle>), IamClientError> {
        self.inner.attach_client(max_pending_responses)
    }

    /// Disconnects from the IAM server.
    pub fn disconnect(&self) {
        self.inner.disconnect();
    }

    /// Registers a producer's segment handle with the IAM server.
    pub fn register_segment(
        &self,
        port_id: u128,
        segment_size: usize,
        handle: &PlatformHandle,
    ) -> Result<SegmentId, IamClientError> {
        self.inner.register_segment(port_id, segment_size, handle)
    }

    /// Requests a segment handle for a sender port's data segment.
    pub fn request_segment_handle(
        &self,
        sender_port_id: u128,
    ) -> Result<Option<(SegmentInfo, PlatformHandle)>, IamClientError> {
        self.inner.request_segment_handle(sender_port_id)
    }

    /// Registers a dynamic segment handle at a specific index with the IAM server.
    pub fn register_dynamic_segment(
        &self,
        port_id: u128,
        segment_index: u8,
        segment_size: usize,
        handle: &PlatformHandle,
    ) -> Result<u8, IamClientError> {
        self.inner
            .register_dynamic_segment(port_id, segment_index, segment_size, handle)
    }

    /// Requests a specific dynamic segment handle by index from a sender port.
    pub fn request_dynamic_segment_handle(
        &self,
        sender_port_id: u128,
        segment_index: u8,
    ) -> Result<Option<(SegmentInfo, PlatformHandle)>, IamClientError> {
        self.inner
            .request_dynamic_segment_handle(sender_port_id, segment_index)
    }

    /// Requests a new segment to be created by the IAM server.
    pub fn add_segment(
        &self,
        port_id: u128,
        requested_size: usize,
        bucket_size: usize,
        bucket_align: usize,
    ) -> Result<(SegmentId, usize, Vec<PlatformHandle>), IamClientError> {
        self.inner.add_segment(port_id, requested_size, bucket_size, bucket_align)
    }

    /// Tries to receive a pending notification without blocking.
    pub fn try_receive_notification(
        &self,
    ) -> Result<Option<(crate::iam::protocol::IamNotification, Vec<PlatformHandle>)>, IamClientError> {
        self.inner.try_receive_notification()
    }
}

impl core::fmt::Debug for TypeErasedSecuredContext {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TypeErasedSecuredContext")
            .field("service_id", self.inner.service_id())
            .field("session_id", &self.inner.session_id())
            .field("is_active", &self.inner.is_active())
            .finish()
    }
}

// ============================================================================
// SecuredServiceContext
// ============================================================================

/// Context for managing IAM-secured service operations.
///
/// This struct wraps an [`IamClient`] and provides methods for port
/// attachment operations. It implements [`ServiceResource`] so it can
/// be used with [`ServiceState`] for automatic cleanup on drop.
///
/// # Thread Safety
///
/// `SecuredServiceContext` uses interior mutability (`Mutex`) to allow
/// mutable access to the IAM client from immutable references. This is
/// necessary because port factories hold immutable references to the service.
///
/// `SecuredServiceContext` is `Send + Sync` because `Mutex` provides
/// thread-safe interior mutability, allowing safe sharing across threads.
pub struct SecuredServiceContext<C: CalClient> {
    /// The IAM client connection. Uses Mutex for interior mutability
    /// since IamClient operations require &mut self.
    client: Mutex<IamClient<C>>,
    /// The service ID this context is associated with.
    service_id: ServiceId,
}

impl<C: CalClient> core::fmt::Debug for SecuredServiceContext<C> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SecuredServiceContext")
            .field("service_id", &self.service_id)
            .field("session_id", &self.client.lock().unwrap().session_id())
            .field("is_active", &self.client.lock().unwrap().is_active())
            .finish()
    }
}

impl<C: CalClient> SecuredServiceContext<C> {
    /// Creates a new secured service context.
    ///
    /// # Arguments
    ///
    /// * `client` - The IAM client connected to the service's IAM server
    /// * `service_id` - The service ID this context is associated with
    ///
    /// # Returns
    ///
    /// A new `SecuredServiceContext` instance.
    #[must_use]
    pub fn new(client: IamClient<C>, service_id: ServiceId) -> Self {
        Self {
            client: Mutex::new(client),
            service_id,
        }
    }

    /// Returns the session ID from the IAM client.
    pub fn session_id(&self) -> SessionId {
        self.client.lock().unwrap().session_id()
    }

    /// Returns the service ID this context is associated with.
    pub fn service_id(&self) -> &ServiceId {
        &self.service_id
    }

    /// Returns true if the IAM client is active.
    pub fn is_active(&self) -> bool {
        self.client.lock().unwrap().is_active()
    }

    // ========================================================================
    // Port Attachment Operations
    // ========================================================================

    /// Attaches as a publisher to the service.
    ///
    /// Sends an AttachPublisher request to the IAM server and receives
    /// handles for the publisher's segments.
    ///
    /// # Arguments
    ///
    /// * `history_size` - The history size for the publisher
    /// * `max_slice_len` - The maximum slice length for samples
    ///
    /// # Returns
    ///
    /// On success, returns a tuple of:
    /// - Port ID assigned by the IAM server
    /// - Segment information for the publisher's segments
    /// - Platform handles for the segments
    ///
    /// # Errors
    ///
    /// Returns [`IamClientError`] if the operation fails, including:
    /// - `RequestDenied` - The IAM policy denied the attach request
    /// - `HandleReceiveFailed` - Failed to receive segment handles
    /// - `SessionInvalid` - The IAM session is no longer valid
    pub fn attach_publisher(
        &self,
        history_size: usize,
        max_slice_len: usize,
    ) -> Result<(u128, Vec<SegmentInfo>, Vec<PlatformHandle>), IamClientError> {
        self.client
            .lock().unwrap()
            .attach_publisher(&self.service_id, history_size, max_slice_len)
    }

    /// Attaches as a subscriber to the service.
    ///
    /// Sends an AttachSubscriber request to the IAM server and receives
    /// handles for the service's segments.
    ///
    /// # Arguments
    ///
    /// * `buffer_size` - The buffer size for the subscriber
    ///
    /// # Returns
    ///
    /// On success, returns a tuple of:
    /// - Port ID assigned by the IAM server
    /// - Segment information for the service's segments
    /// - Platform handles for the segments
    ///
    /// # Errors
    ///
    /// Returns [`IamClientError`] if the operation fails.
    pub fn attach_subscriber(
        &self,
        buffer_size: usize,
    ) -> Result<(u128, Vec<SegmentInfo>, Vec<PlatformHandle>), IamClientError> {
        self.client
            .lock().unwrap()
            .attach_subscriber(&self.service_id, buffer_size)
    }

    /// Attaches as a server to a request-response service.
    ///
    /// # Arguments
    ///
    /// * `max_active_requests` - The maximum number of active requests
    ///
    /// # Returns
    ///
    /// On success, returns a tuple of:
    /// - Port ID assigned by the IAM server
    /// - Segment information for the service's segments
    /// - Platform handles for the segments
    ///
    /// # Errors
    ///
    /// Returns [`IamClientError`] if the operation fails.
    pub fn attach_server(
        &self,
        max_active_requests: usize,
    ) -> Result<(u128, Vec<SegmentInfo>, Vec<PlatformHandle>), IamClientError> {
        self.client
            .lock().unwrap()
            .attach_server(&self.service_id, max_active_requests)
    }

    /// Attaches as a client to a request-response service.
    ///
    /// # Arguments
    ///
    /// * `max_pending_responses` - The maximum number of pending responses
    ///
    /// # Returns
    ///
    /// On success, returns a tuple of:
    /// - Port ID assigned by the IAM server
    /// - Segment information for the service's segments
    /// - Platform handles for the segments
    ///
    /// # Errors
    ///
    /// Returns [`IamClientError`] if the operation fails.
    pub fn attach_client(
        &self,
        max_pending_responses: usize,
    ) -> Result<(u128, Vec<SegmentInfo>, Vec<PlatformHandle>), IamClientError> {
        self.client
            .lock().unwrap()
            .attach_client(&self.service_id, max_pending_responses)
    }

    /// Disconnects from the IAM server.
    ///
    /// This is called automatically on drop, but can be called explicitly
    /// if early disconnection is needed.
    pub fn disconnect(&self) {
        self.client.lock().unwrap().disconnect();
    }

    /// Registers a producer's segment handle with the IAM server.
    pub fn register_segment(
        &self,
        port_id: u128,
        segment_size: usize,
        handle: &PlatformHandle,
    ) -> Result<SegmentId, IamClientError> {
        self.client
            .lock()
            .unwrap()
            .register_segment(&self.service_id, port_id, segment_size, handle)
    }

    /// Requests a segment handle for a sender port's data segment.
    pub fn request_segment_handle(
        &self,
        sender_port_id: u128,
    ) -> Result<Option<(SegmentInfo, PlatformHandle)>, IamClientError> {
        self.client
            .lock()
            .unwrap()
            .request_segment_handle(&self.service_id, sender_port_id)
    }

    /// Registers a dynamic segment handle at a specific index with the IAM server.
    pub fn register_dynamic_segment(
        &self,
        port_id: u128,
        segment_index: u8,
        segment_size: usize,
        handle: &PlatformHandle,
    ) -> Result<u8, IamClientError> {
        self.client.lock().unwrap().register_dynamic_segment(
            &self.service_id,
            port_id,
            segment_index,
            segment_size,
            handle,
        )
    }

    /// Requests a specific dynamic segment handle by index from a sender port.
    pub fn request_dynamic_segment_handle(
        &self,
        sender_port_id: u128,
        segment_index: u8,
    ) -> Result<Option<(SegmentInfo, PlatformHandle)>, IamClientError> {
        self.client.lock().unwrap().request_dynamic_segment_handle(
            &self.service_id,
            sender_port_id,
            segment_index,
        )
    }

    /// Requests a new segment to be created by the IAM server.
    ///
    /// Called by producers when they receive a `NeedSegment` error during allocation.
    /// The IAM server creates an anonymous segment and returns a handle for it.
    pub fn add_segment(
        &self,
        port_id: u128,
        requested_size: usize,
        bucket_size: usize,
        bucket_align: usize,
    ) -> Result<(SegmentId, usize, Vec<PlatformHandle>), IamClientError> {
        self.client
            .lock()
            .unwrap()
            .add_segment(&self.service_id, port_id, requested_size, bucket_size, bucket_align)
    }

    /// Tries to receive a pending notification without blocking.
    pub fn try_receive_notification(
        &self,
    ) -> Result<Option<(crate::iam::protocol::IamNotification, Vec<PlatformHandle>)>, IamClientError> {
        self.client.lock().unwrap().try_receive_notification()
    }
}

impl<C: CalClient> ServiceResource for SecuredServiceContext<C> {
    fn acquire_ownership(&self) {
        // When the service is being cleaned up (last owner), disconnect from IAM.
        // The IAM server will clean up any resources associated with this session.
        self.disconnect();
    }
}

// Implement ErasedSecuredContext for SecuredServiceContext to enable type erasure
impl<C: CalClient + Send + 'static> ErasedSecuredContext
    for SecuredServiceContext<C>
{
    fn attach_publisher(
        &self,
        history_size: usize,
        max_slice_len: usize,
    ) -> Result<(u128, Vec<SegmentInfo>, Vec<PlatformHandle>), IamClientError> {
        SecuredServiceContext::attach_publisher(self, history_size, max_slice_len)
    }

    fn attach_subscriber(
        &self,
        buffer_size: usize,
    ) -> Result<(u128, Vec<SegmentInfo>, Vec<PlatformHandle>), IamClientError> {
        SecuredServiceContext::attach_subscriber(self, buffer_size)
    }

    fn attach_server(
        &self,
        max_active_requests: usize,
    ) -> Result<(u128, Vec<SegmentInfo>, Vec<PlatformHandle>), IamClientError> {
        SecuredServiceContext::attach_server(self, max_active_requests)
    }

    fn attach_client(
        &self,
        max_pending_responses: usize,
    ) -> Result<(u128, Vec<SegmentInfo>, Vec<PlatformHandle>), IamClientError> {
        SecuredServiceContext::attach_client(self, max_pending_responses)
    }

    fn is_active(&self) -> bool {
        SecuredServiceContext::is_active(self)
    }

    fn session_id(&self) -> SessionId {
        SecuredServiceContext::session_id(self)
    }

    fn disconnect(&self) {
        SecuredServiceContext::disconnect(self);
    }

    fn service_id(&self) -> &ServiceId {
        SecuredServiceContext::service_id(self)
    }

    fn register_segment(
        &self,
        port_id: u128,
        segment_size: usize,
        handle: &PlatformHandle,
    ) -> Result<SegmentId, IamClientError> {
        SecuredServiceContext::register_segment(self, port_id, segment_size, handle)
    }

    fn request_segment_handle(
        &self,
        sender_port_id: u128,
    ) -> Result<Option<(SegmentInfo, PlatformHandle)>, IamClientError> {
        SecuredServiceContext::request_segment_handle(self, sender_port_id)
    }

    fn register_dynamic_segment(
        &self,
        port_id: u128,
        segment_index: u8,
        segment_size: usize,
        handle: &PlatformHandle,
    ) -> Result<u8, IamClientError> {
        SecuredServiceContext::register_dynamic_segment(self, port_id, segment_index, segment_size, handle)
    }

    fn request_dynamic_segment_handle(
        &self,
        sender_port_id: u128,
        segment_index: u8,
    ) -> Result<Option<(SegmentInfo, PlatformHandle)>, IamClientError> {
        SecuredServiceContext::request_dynamic_segment_handle(self, sender_port_id, segment_index)
    }

    fn add_segment(
        &self,
        port_id: u128,
        requested_size: usize,
        bucket_size: usize,
        bucket_align: usize,
    ) -> Result<(SegmentId, usize, Vec<PlatformHandle>), IamClientError> {
        SecuredServiceContext::add_segment(self, port_id, requested_size, bucket_size, bucket_align)
    }

    fn try_receive_notification(
        &self,
    ) -> Result<Option<(crate::iam::protocol::IamNotification, Vec<PlatformHandle>)>, IamClientError> {
        SecuredServiceContext::try_receive_notification(self)
    }
}

impl<C: CalClient> Drop for SecuredServiceContext<C> {
    fn drop(&mut self) {
        // disconnect() is idempotent - safe to call even if already disconnected.
        // We unconditionally call it rather than checking first.
        self.disconnect();
    }
}

// ============================================================================
// IAM Endpoint Naming
// ============================================================================

/// Generates the IAM control channel endpoint name for a service.
///
/// The endpoint name is derived from the service ID to ensure a unique
/// endpoint per service. This allows the IAM server (service creator) to
/// be found by IAM clients (service openers).
///
/// # Arguments
///
/// * `service_id` - The service ID to generate the endpoint name for
/// * `endpoint_base` - The base path for IAM endpoints (from config)
///
/// # Returns
///
/// A `FileName` suitable for use with `ControlChannelListenerBuilder`.
///
/// # Format
///
/// The format is: `{endpoint_base}_iam_{service_id_prefix}`
/// where `service_id_prefix` is the first 16 characters of the service ID
/// to keep the filename within system limits.
pub fn iam_endpoint_name(
    service_id: &ServiceId,
    endpoint_base: &iceoryx2_bb_system_types::path::Path,
) -> iceoryx2_bb_system_types::file_name::FileName {
    use iceoryx2_bb_container::semantic_string::SemanticString;

    // Take prefix of service_id to keep filename short (max 255 chars typically)
    let id_str = service_id.as_str();
    let prefix = if id_str.len() > 16 {
        &id_str[..16]
    } else {
        id_str
    };

    // Format: "{base}_iam_{id_prefix}"
    // Note: Using underscore as separator since it's safe in file names
    let mut name_bytes = [0u8; 64];
    let base_bytes = endpoint_base.as_bytes();
    let iam_marker = b"_iam_";
    let prefix_bytes = prefix.as_bytes();

    let total_len = base_bytes.len() + iam_marker.len() + prefix_bytes.len();
    if total_len <= name_bytes.len() {
        name_bytes[..base_bytes.len()].copy_from_slice(base_bytes);
        name_bytes[base_bytes.len()..base_bytes.len() + iam_marker.len()]
            .copy_from_slice(iam_marker);
        name_bytes[base_bytes.len() + iam_marker.len()..total_len].copy_from_slice(prefix_bytes);

        iceoryx2_bb_system_types::file_name::FileName::new(&name_bytes[..total_len])
            .expect("IAM endpoint name should be valid")
    } else {
        // Fallback: just use service ID prefix
        iceoryx2_bb_system_types::file_name::FileName::new(prefix_bytes)
            .expect("Service ID prefix should be a valid filename")
    }
}

// Integration tests for SecuredServiceContext are in iceoryx2/tests/iam_integration_tests.rs
// since they require actual control channel infrastructure.
