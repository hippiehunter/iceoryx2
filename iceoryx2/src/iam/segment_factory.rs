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

//! Segment factory trait for IAM-managed segment creation.
//!
//! This module provides the [`SegmentFactory`] trait that abstracts shared memory
//! segment creation, allowing the IAM server to create segments without being
//! generic over the specific `SharedMemory` implementation.
//!
//! # Design
//!
//! The IAM server needs to create shared memory segments in response to `AddSegment`
//! requests from producers. However, `IamServer` is not generic over the `Service`
//! type, so it cannot directly use `Service::SharedMemory::create_anonymous()`.
//!
//! The `SegmentFactory` trait provides an abstraction that:
//! - Allows the service builder to provide a concrete implementation
//! - Enables IAM to create properly initialized segments with allocators
//! - Keeps the IAM server decoupled from specific `SharedMemory` types
//!
//! # Usage
//!
//! The service builder creates a [`ServiceSegmentFactory`] that captures the
//! necessary configuration and passes it to the `IamServer` constructor.

use alloc::sync::Arc;
use core::alloc::Layout;
use core::any::Any;
use std::sync::Mutex;

use iceoryx2_bb_container::semantic_string::SemanticString;
use iceoryx2_bb_system_types::file_name::FileName;
use iceoryx2_cal::named_concept::NamedConceptBuilder;
use iceoryx2_cal::security::PlatformHandle;
use iceoryx2_cal::shared_memory::{SharedMemory, SharedMemoryBuilder};
use iceoryx2_cal::shm_allocator::pool_allocator::PoolAllocator;
use iceoryx2_cal::shm_allocator::SegmentId;

use crate::service::config_scheme::data_segment_config;
use crate::{config, service};

use super::error::IamServerError;

// ============================================================================
// SegmentFactory Trait
// ============================================================================

/// Factory for creating shared memory segments in IAM-managed mode.
///
/// This trait abstracts the creation of shared memory segments, allowing the
/// IAM server to create segments without knowing the specific `SharedMemory`
/// implementation being used.
///
/// # Thread Safety
///
/// Implementations must be `Send + Sync` as they are stored in the IAM server
/// which may be accessed from multiple threads.
pub trait SegmentFactory: Send + Sync {
    /// Creates an anonymous shared memory segment.
    ///
    /// The segment is created with the specified size and allocator configuration.
    /// The returned handle can be passed to clients for mapping.
    ///
    /// # Arguments
    ///
    /// * `segment_id` - The segment ID assigned by IAM
    /// * `size` - Minimum payload size for the segment
    /// * `bucket_size` - Size of each allocation bucket (for pool allocator)
    /// * `bucket_align` - Alignment for allocation buckets
    ///
    /// # Returns
    ///
    /// On success, returns a tuple of:
    /// - `PlatformHandle` - Handle to the segment for passing to clients
    /// - `usize` - Actual allocated size
    ///
    /// # Errors
    ///
    /// Returns an error if segment creation fails.
    fn create_segment(
        &self,
        segment_id: SegmentId,
        size: usize,
        bucket_size: usize,
        bucket_align: usize,
    ) -> Result<(PlatformHandle, usize), IamServerError>;

    /// Returns the stored segment to keep it alive.
    ///
    /// Segments created by the factory are stored internally to prevent them
    /// from being dropped. This method allows the factory to be used as a
    /// segment storage.
    fn get_stored_segment(&self, segment_id: SegmentId) -> Option<Arc<dyn Any + Send + Sync>>;
}

// ============================================================================
// NoSegmentFactory
// ============================================================================

/// A null implementation of [`SegmentFactory`] that always fails.
///
/// Used for services that don't support dynamic segments (e.g., event services).
#[derive(Debug, Default)]
pub struct NoSegmentFactory;

impl SegmentFactory for NoSegmentFactory {
    fn create_segment(
        &self,
        _segment_id: SegmentId,
        _size: usize,
        _bucket_size: usize,
        _bucket_align: usize,
    ) -> Result<(PlatformHandle, usize), IamServerError> {
        Err(IamServerError::SegmentCreationNotSupported)
    }

    fn get_stored_segment(&self, _segment_id: SegmentId) -> Option<Arc<dyn Any + Send + Sync>> {
        None
    }
}

// ============================================================================
// ServiceSegmentFactory
// ============================================================================

/// Concrete implementation of [`SegmentFactory`] for a specific service type.
///
/// This factory is created by the service builder and captures the necessary
/// configuration to create segments using the service's `SharedMemory` type.
///
/// # Thread Safety
///
/// This struct is `Send + Sync` regardless of whether `Service` is, because:
/// - `Config` is `Clone` (no thread-unsafe state)
/// - `Mutex<T>` provides thread-safe interior mutability
/// - `PhantomData<fn() -> Service>` is used instead of `PhantomData<Service>`,
///   which doesn't require `Service` to be `Send + Sync`
pub struct ServiceSegmentFactory<Service: service::Service> {
    /// The global configuration for segment creation.
    global_config: config::Config,
    /// Counter for generating unique segment names.
    segment_counter: Mutex<u64>,
    /// Storage for created segments to keep them alive.
    /// Maps segment_id -> Arc<SharedMemory>
    segments: Mutex<std::collections::HashMap<u8, Arc<dyn Any + Send + Sync>>>,
    /// Phantom data for the service type.
    /// Using fn() -> Service to avoid requiring Service: Send + Sync.
    _phantom: core::marker::PhantomData<fn() -> Service>,
}

impl<Service: service::Service> ServiceSegmentFactory<Service> {
    /// Creates a new segment factory with the given configuration.
    pub fn new(global_config: config::Config) -> Self {
        Self {
            global_config,
            segment_counter: Mutex::new(0),
            segments: Mutex::new(std::collections::HashMap::new()),
            _phantom: core::marker::PhantomData,
        }
    }

    /// Generates a unique segment name for IAM-created segments.
    fn generate_segment_name(&self) -> FileName {
        let mut counter = self.segment_counter.lock().unwrap();
        *counter += 1;
        let name = alloc::format!("iam_seg_{}", *counter);
        FileName::new(name.as_bytes())
            .unwrap_or_else(|_| unsafe { FileName::new_unchecked(b"iam_segment") })
    }
}

// Safety: ServiceSegmentFactory only contains Send+Sync types
// - Mutex<T> is Send+Sync when T is Send
// - Config is Clone (implying no thread-unsafe state)
// - PhantomData<fn() -> Service> doesn't require Service to be Send+Sync
unsafe impl<Service: service::Service> Send for ServiceSegmentFactory<Service> {}
unsafe impl<Service: service::Service> Sync for ServiceSegmentFactory<Service> {}

impl<Service> SegmentFactory for ServiceSegmentFactory<Service>
where
    Service: service::Service,
    Service::SharedMemory: Send + Sync + 'static,
{
    fn create_segment(
        &self,
        segment_id: SegmentId,
        size: usize,
        bucket_size: usize,
        bucket_align: usize,
    ) -> Result<(PlatformHandle, usize), IamServerError> {
        // Create the allocator configuration
        let bucket_layout = Layout::from_size_align(bucket_size, bucket_align)
            .map_err(|_| IamServerError::InvalidConfiguration)?;

        let allocator_config =
            iceoryx2_cal::shm_allocator::pool_allocator::Config { bucket_layout };

        // Generate a unique segment name
        let segment_name = self.generate_segment_name();

        // Get the segment configuration
        let segment_config = data_segment_config::<Service>(&self.global_config);

        // Create the anonymous segment
        let (memory, handle) = <<Service::SharedMemory as SharedMemory<PoolAllocator>>::Builder
            as NamedConceptBuilder<Service::SharedMemory>>::new(&segment_name)
            .config(&segment_config)
            .size(size)
            .has_ownership(true) // IAM owns the segment
            .create_anonymous(&allocator_config)
            .map_err(|e| {
                iceoryx2_log::error!("Failed to create anonymous segment: {:?}", e);
                IamServerError::SegmentCreationFailed
            })?;

        // Get actual size using the SharedMemory trait method
        let actual_size = <Service::SharedMemory as SharedMemory<PoolAllocator>>::size(&memory);

        // Store the memory object to keep the segment alive
        let memory_arc: Arc<dyn Any + Send + Sync> = Arc::new(memory);
        self.segments
            .lock()
            .unwrap()
            .insert(segment_id.value(), memory_arc);

        Ok((handle, actual_size))
    }

    fn get_stored_segment(&self, segment_id: SegmentId) -> Option<Arc<dyn Any + Send + Sync>> {
        self.segments
            .lock()
            .unwrap()
            .get(&segment_id.value())
            .cloned()
    }
}

impl<Service: service::Service + Send + Sync> core::fmt::Debug for ServiceSegmentFactory<Service> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ServiceSegmentFactory")
            .field("segment_count", &self.segments.lock().unwrap().len())
            .finish()
    }
}
