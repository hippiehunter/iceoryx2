// Copyright (c) 2023 - 2024 Contributors to the Eclipse Foundation
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

use core::alloc::Layout;
use core::ptr::NonNull;

use iceoryx2_bb_derive_macros::ZeroCopySend;
use iceoryx2_bb_elementary_traits::non_null::NonNullCompat;
use iceoryx2_bb_elementary_traits::testing::abandonable::Abandonable;
use iceoryx2_bb_elementary_traits::zero_copy_send::ZeroCopySend;
use iceoryx2_bb_posix::file::AccessMode;
use iceoryx2_bb_system_types::file_name::FileName;
use iceoryx2_cal::{
    event::NamedConceptBuilder,
    resizable_shared_memory::*,
    security::{handle::PlatformHandle, AccessRights, HandleBasedOpenError},
    shared_memory::{
        SharedMemory, SharedMemoryBuilder, SharedMemoryCreateError, SharedMemoryForPoolAllocator,
        SharedMemoryOpenError, ShmPointer,
    },
    shm_allocator::{
        self, AllocationError, AllocationStrategy, PointerOffset, SegmentId, ShmAllocationError,
        pool_allocator::PoolAllocator,
    },
};
use iceoryx2_log::fail;

use crate::{
    config,
    service::{
        self,
        config_scheme::{data_segment_config, resizable_data_segment_config},
    },
};

/// Defines the data segment type of a zero copy capable sender port.
#[repr(C)]
#[derive(Debug, Clone, Copy, Eq, PartialEq, ZeroCopySend)]
pub enum DataSegmentType {
    /// The data segment can be resized if no more memory is available.
    Dynamic,
    /// The data segment is allocated once. If it is out-of-memory no reallocation will occur.
    Static,
}

impl DataSegmentType {
    pub(crate) fn new_from_allocation_strategy(v: AllocationStrategy) -> Self {
        match v {
            AllocationStrategy::Static => DataSegmentType::Static,
            _ => DataSegmentType::Dynamic,
        }
    }
}

/// Error type for data segment allocation operations.
///
/// This error type unifies allocation errors from both static and dynamic segments,
/// and includes the `NeedSegment` variant for IAM-managed dynamic segments.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataSegmentAllocationError {
    /// The underlying allocator returned an error.
    AllocationError(AllocationError),
    /// The alignment requirement exceeds the maximum supported by the memory.
    ExceedsMaxSupportedAlignment,
    /// The maximum number of segment reallocations has been reached.
    MaxReallocationsReached,
    /// An error occurred creating a new shared memory segment during reallocation.
    SharedMemoryCreateError,
    /// IAM-managed allocation strategy requires external segment creation.
    /// The caller should request a segment of the specified size from IAM
    /// and add it via [`DataSegment::add_segment()`].
    NeedSegment {
        /// The recommended minimum size for the new segment.
        requested_size: usize,
    },
}

impl From<ShmAllocationError> for DataSegmentAllocationError {
    fn from(e: ShmAllocationError) -> Self {
        match e {
            ShmAllocationError::AllocationError(e) => {
                DataSegmentAllocationError::AllocationError(e)
            }
            ShmAllocationError::ExceedsMaxSupportedAlignment => {
                DataSegmentAllocationError::ExceedsMaxSupportedAlignment
            }
        }
    }
}

impl core::fmt::Display for DataSegmentAllocationError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "DataSegmentAllocationError::{self:?}")
    }
}

impl core::error::Error for DataSegmentAllocationError {}

#[derive(Debug)]
enum MemoryType<Service: service::Service> {
    Static(Service::SharedMemory),
    Dynamic(Service::ResizableSharedMemory),
}

#[derive(Debug)]
pub(crate) struct DataSegment<Service: service::Service> {
    memory: MemoryType<Service>,
}

impl<Service: service::Service> Abandonable for DataSegment<Service> {
    unsafe fn abandon_in_place(mut this: NonNull<Self>) {
        let this = unsafe { this.as_mut() };
        match &mut this.memory {
            MemoryType::Static(shm) => {
                unsafe { Service::SharedMemory::abandon_in_place(NonNull::iox2_from_mut(shm)) };
            }
            MemoryType::Dynamic(shm) => unsafe {
                Service::ResizableSharedMemory::abandon_in_place(NonNull::iox2_from_mut(shm));
            },
        }
    }
}

impl<Service: service::Service> DataSegment<Service> {
    pub(crate) fn create_static_segment(
        segment_name: &FileName,
        chunk_layout: Layout,
        global_config: &config::Config,
        number_of_chunks: usize,
    ) -> Result<Self, SharedMemoryCreateError> {
        let allocator_config = shm_allocator::pool_allocator::Config {
            bucket_layout: chunk_layout,
        };
        let msg = "Unable to create the static data segment since the underlying shared memory could not be created.";
        let origin = "DataSegment::create_static_segment()";

        let segment_config = data_segment_config::<Service>(global_config);
        let memory = fail!(from origin,
                                when <<Service::SharedMemory as SharedMemory<PoolAllocator>>::Builder as NamedConceptBuilder<
                                Service::SharedMemory,
                                    >>::new(segment_name)
                                    .config(&segment_config)
                                    .size(chunk_layout.size() * number_of_chunks + chunk_layout.align() - 1)
                                    .create(&allocator_config),
                                "{msg}");

        Ok(Self {
            memory: MemoryType::Static(memory),
        })
    }

    pub(crate) fn create_dynamic_segment(
        segment_name: &FileName,
        chunk_layout: Layout,
        global_config: &config::Config,
        number_of_chunks: usize,
        allocation_strategy: AllocationStrategy,
    ) -> Result<Self, SharedMemoryCreateError> {
        let msg = "Unable to create the dynamic data segment since the underlying shared memory could not be created.";
        let origin = "DataSegment::create_dynamic_segment()";

        let segment_config = resizable_data_segment_config::<Service>(global_config);
        let memory = fail!(from origin,
                    when <<Service::ResizableSharedMemory as ResizableSharedMemory<
                        PoolAllocator,
                        Service::SharedMemory,
                    >>::MemoryBuilder as NamedConceptBuilder<Service::ResizableSharedMemory>>::new(
                        segment_name,
                    )
                    .config(&segment_config)
                    .max_number_of_chunks_hint(number_of_chunks)
                    .max_chunk_layout_hint(chunk_layout)
                    .allocation_strategy(allocation_strategy)
                    .create(),
                    "{msg}");

        Ok(Self {
            memory: MemoryType::Dynamic(memory),
        })
    }

    /// Creates an anonymous static data segment not visible on the filesystem.
    ///
    /// The segment is created via `memfd_create` (Linux) or equivalent, and a
    /// `PlatformHandle` is returned for sharing through the IAM server.
    ///
    /// The `segment_name` is used only as a debug label (e.g. for memfd), not
    /// for filesystem visibility.
    pub(crate) fn create_anonymous_static_segment(
        segment_name: &FileName,
        chunk_layout: Layout,
        global_config: &config::Config,
        number_of_chunks: usize,
    ) -> Result<(Self, PlatformHandle), SharedMemoryCreateError> {
        let allocator_config = shm_allocator::pool_allocator::Config {
            bucket_layout: chunk_layout,
        };
        let msg = "Unable to create the anonymous static data segment.";
        let origin = "DataSegment::create_anonymous_static_segment()";

        let segment_config = data_segment_config::<Service>(global_config);
        let (memory, handle) = fail!(from origin,
                                when <<Service::SharedMemory as SharedMemory<PoolAllocator>>::Builder as NamedConceptBuilder<
                                Service::SharedMemory,
                                    >>::new(segment_name)
                                    .config(&segment_config)
                                    .size(chunk_layout.size() * number_of_chunks + chunk_layout.align() - 1)
                                    .create_anonymous(&allocator_config),
                                "{msg}");

        Ok((
            Self {
                memory: MemoryType::Static(memory),
            },
            handle,
        ))
    }

    /// Creates an anonymous (memfd-backed) dynamic data segment with the IAM-managed
    /// allocation strategy, returning it together with the [`PlatformHandle`]s (and sizes)
    /// for its management segment and initial data segment (segment id 0) so they can be
    /// brokered to consumers via IAM.
    ///
    /// The management segment and the initial data segment are created anonymously and are
    /// therefore not visible on the filesystem. Consumers reconstruct the read-only view via
    /// [`DataSegmentView::open_dynamic_from_handle`].
    ///
    /// When using this method, allocations that exceed the current segment capacity
    /// will return [`DataSegmentAllocationError::NeedSegment`] instead of automatically
    /// creating new segments. The caller is responsible for:
    /// 1. Requesting a new segment from the IAM server
    /// 2. Calling [`add_segment()`] with the received handle
    /// 3. Retrying the allocation
    ///
    /// This ensures all segment creation goes through the IAM server for proper
    /// authorization in secured mode.
    pub(crate) fn create_dynamic_segment_iam_managed(
        segment_name: &FileName,
        chunk_layout: Layout,
        global_config: &config::Config,
        number_of_chunks: usize,
    ) -> Result<(Self, ResizableSharedMemoryHandles), SharedMemoryCreateError> {
        let msg = "Unable to create the IAM-managed dynamic data segment.";
        let origin = "DataSegment::create_dynamic_segment_iam_managed()";

        let segment_config = resizable_data_segment_config::<Service>(global_config);
        let (memory, handles) = fail!(from origin,
                    when <<Service::ResizableSharedMemory as ResizableSharedMemory<
                        PoolAllocator,
                        Service::SharedMemory,
                    >>::MemoryBuilder as NamedConceptBuilder<Service::ResizableSharedMemory>>::new(
                        segment_name,
                    )
                    .config(&segment_config)
                    .max_number_of_chunks_hint(number_of_chunks)
                    .max_chunk_layout_hint(chunk_layout)
                    .allocation_strategy(AllocationStrategy::IamManaged)
                    .create_and_extract_handles(),
                    "{msg}");

        Ok((
            Self {
                memory: MemoryType::Dynamic(memory),
            },
            handles,
        ))
    }

    /// Adds an externally created segment (from IAM) to this dynamic data segment.
    ///
    /// This method should be called after receiving a [`DataSegmentAllocationError::NeedSegment`]
    /// error and obtaining a segment handle from the IAM server.
    ///
    /// # Arguments
    ///
    /// * `segment_id` - The segment ID assigned by the IAM server
    /// * `handle` - The platform handle to the shared memory segment
    /// * `_config` - The allocator configuration (currently unused, reserved for future use)
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// * The segment is static (not dynamic)
    /// * The segment ID is already in use
    /// * The handle is invalid or cannot be opened
    pub(crate) fn add_segment(
        &self,
        segment_id: SegmentId,
        handle: PlatformHandle,
        config: &shm_allocator::pool_allocator::Config,
    ) -> Result<(), ResizableSharedMemoryError> {
        match &self.memory {
            MemoryType::Dynamic(memory) => memory.add_segment(segment_id, handle, config),
            MemoryType::Static(_) => Err(ResizableSharedMemoryError::InternalError),
        }
    }

    pub(crate) fn allocate(
        &self,
        layout: Layout,
    ) -> Result<ShmPointer, DataSegmentAllocationError> {
        let msg = "Unable to allocate memory from the data segment";
        match &self.memory {
            MemoryType::Static(memory) => memory.allocate(layout).map_err(|e| {
                iceoryx2_log::error!(from self, "{msg} caused by {:?}.", e);
                DataSegmentAllocationError::from(e)
            }),
            MemoryType::Dynamic(memory) => match memory.allocate(layout) {
                Ok(ptr) => Ok(ptr),
                Err(ResizableShmAllocationError::ShmAllocationError(e)) => {
                    fail!(from self, with DataSegmentAllocationError::from(e),
                        "{msg} caused by {:?}.", e);
                }
                Err(ResizableShmAllocationError::MaxReallocationsReached) => {
                    fail!(from self,
                        with DataSegmentAllocationError::MaxReallocationsReached,
                        "{msg} since the maxmimum number of reallocations was reached. Try to provide initial_max_slice_len({}) as hint when creating the publisher to have a more fitting initial setup.", layout.size());
                }
                Err(ResizableShmAllocationError::SharedMemoryCreateError(e)) => {
                    fail!(from self,
                        with DataSegmentAllocationError::SharedMemoryCreateError,
                        "{msg} since the shared memory segment creation failed while resizing the memory due to ({:?}).", e);
                }
                Err(ResizableShmAllocationError::NeedSegment { requested_size }) => {
                    fail!(from self,
                        with DataSegmentAllocationError::NeedSegment { requested_size },
                        "{msg} since the allocation strategy requires external segment creation. \
                         Request a segment of at least {} bytes from the IAM server.", requested_size);
                }
            },
        }
    }

    pub(crate) unsafe fn deallocate_bucket(&self, offset: PointerOffset) {
        unsafe {
            match &self.memory {
                MemoryType::Static(memory) => memory.deallocate_bucket(offset),
                MemoryType::Dynamic(memory) => memory.deallocate_bucket(offset),
            }
        }
    }

    pub(crate) fn bucket_size(&self, segment_id: SegmentId) -> usize {
        match &self.memory {
            MemoryType::Static(memory) => memory.bucket_size(),
            MemoryType::Dynamic(memory) => memory.bucket_size(segment_id),
        }
    }

    pub(crate) fn max_number_of_segments(data_segment_type: DataSegmentType) -> u8 {
        match data_segment_type {
            DataSegmentType::Static => 1,
            DataSegmentType::Dynamic => {
                (Service::ResizableSharedMemory::max_number_of_reallocations() - 1) as u8
            }
        }
    }
}

#[derive(Debug)]
enum MemoryViewType<Service: service::Service> {
    Static(Service::SharedMemory),
    Dynamic(
        <Service::ResizableSharedMemory as ResizableSharedMemory<
            PoolAllocator,
            Service::SharedMemory,
        >>::View,
    ),
}

#[derive(Debug)]
pub(crate) struct DataSegmentView<Service: service::Service> {
    memory: MemoryViewType<Service>,
}

impl<Service: service::Service> Abandonable for DataSegmentView<Service> {
    unsafe fn abandon_in_place(mut this: NonNull<Self>) {
        let this = unsafe { this.as_mut() };
        match &mut this.memory {
            MemoryViewType::Dynamic(shm) => unsafe {
                <Service::ResizableSharedMemory as ResizableSharedMemory<
                    PoolAllocator,
                    Service::SharedMemory,
                >>::View::abandon_in_place(NonNull::iox2_from_mut(shm))
            },
            MemoryViewType::Static(shm) => unsafe {
                Service::SharedMemory::abandon_in_place(NonNull::iox2_from_mut(shm));
            },
        }
    }
}

impl<Service: service::Service> DataSegmentView<Service> {
    pub(crate) fn open_static_segment(
        segment_name: &FileName,
        global_config: &config::Config,
    ) -> Result<Self, SharedMemoryOpenError> {
        let origin = "DataSegment::open()";
        let msg =
            "Unable to open data segment since the underlying shared memory could not be opened.";

        let segment_config = data_segment_config::<Service>(global_config);
        let memory = fail!(from origin,
                            when <Service::SharedMemory as SharedMemory<PoolAllocator>>::
                                Builder::new(segment_name)
                                .config(&segment_config)
                                .timeout(global_config.global.creation_timeout)
                                .open(AccessMode::Read),
                            "{msg}");

        Ok(Self {
            memory: MemoryViewType::Static(memory),
        })
    }

    pub(crate) fn open_dynamic_segment(
        segment_name: &FileName,
        global_config: &config::Config,
    ) -> Result<Self, SharedMemoryOpenError> {
        let origin = "DataSegment::open()";
        let msg =
            "Unable to open data segment since the underlying shared memory could not be opened.";

        let segment_config = resizable_data_segment_config::<Service>(global_config);
        let memory = fail!(from origin,
                    when <<Service::ResizableSharedMemory as ResizableSharedMemory<
                        PoolAllocator,
                        Service::SharedMemory,
                    >>::ViewBuilder as NamedConceptBuilder<Service::ResizableSharedMemory>>::new(
                        segment_name,
                    )
                    .config(&segment_config)
                    .open(AccessMode::Read),
                    "{msg}");

        Ok(Self {
            memory: MemoryViewType::Dynamic(memory),
        })
    }

    /// Opens a static data segment from a platform handle received via IAM.
    ///
    /// This is the consumer-side counterpart to
    /// [`DataSegment::create_anonymous_static_segment`]. The handle is
    /// received from the IAM server after authorization.
    pub(crate) fn open_static_from_handle(
        handle: PlatformHandle,
        global_config: &config::Config,
    ) -> Result<Self, HandleBasedOpenError> {
        let origin = "DataSegmentView::open_static_from_handle()";
        let msg = "Unable to open data segment from handle.";

        use iceoryx2_bb_container::semantic_string::SemanticString;
        // The name is for debug/identification only — the segment was created anonymously
        let dummy_name = FileName::new(b"iam_handle_segment").expect("dummy name should be valid");

        let segment_config = data_segment_config::<Service>(global_config);

        let memory = fail!(from origin,
                            when <<Service::SharedMemory as SharedMemory<PoolAllocator>>::Builder as NamedConceptBuilder<
                            Service::SharedMemory,
                                >>::new(&dummy_name)
                                .open_from_handle(handle, AccessRights::read_only(), &segment_config),
                            "{msg}");

        Ok(Self {
            memory: MemoryViewType::Static(memory),
        })
    }

    /// Opens a dynamic (resizable) data segment from the management-segment and initial
    /// data-segment handles received via IAM.
    ///
    /// This is the consumer-side counterpart to
    /// [`DataSegment::create_dynamic_segment_iam_managed`]. Both handles are received from
    /// the IAM server after authorization (the producer created both segments anonymously
    /// and registered their handles). The management segment is mapped but never read; the
    /// initial data segment is registered (pinned) at segment id 0. Both are opened
    /// read-only — the receiver only reads payloads. Runtime growth segments (id 1+) are
    /// added lazily via [`add_segment_from_handle`] as they are encountered.
    pub(crate) fn open_dynamic_from_handle(
        mgmt_handle: PlatformHandle,
        initial_segment_id: SegmentId,
        initial_segment_handle: PlatformHandle,
        global_config: &config::Config,
    ) -> Result<Self, HandleBasedOpenError> {
        let origin = "DataSegmentView::open_dynamic_from_handle()";
        let msg = "Unable to open dynamic data segment from handle.";

        use iceoryx2_bb_container::semantic_string::SemanticString;
        // The name is for debug/identification only — the segments were created anonymously.
        let dummy_name =
            FileName::new(b"iam_handle_dynamic_segment").expect("dummy name should be valid");

        let segment_config = resizable_data_segment_config::<Service>(global_config);

        let memory = fail!(from origin,
                    when <<Service::ResizableSharedMemory as ResizableSharedMemory<
                        PoolAllocator,
                        Service::SharedMemory,
                    >>::ViewBuilder as NamedConceptBuilder<Service::ResizableSharedMemory>>::new(
                        &dummy_name,
                    )
                    .config(&segment_config)
                    .open_from_handle(
                        mgmt_handle,
                        initial_segment_id,
                        initial_segment_handle,
                        AccessRights::read_only(),
                    ),
                    "{msg}");

        Ok(Self {
            memory: MemoryViewType::Dynamic(memory),
        })
    }

    pub(crate) fn register_and_translate_offset(
        &self,
        offset: PointerOffset,
    ) -> Result<usize, SharedMemoryOpenError> {
        match &self.memory {
            MemoryViewType::Static(memory) => Ok(offset.offset() + memory.payload_start_address()),
            MemoryViewType::Dynamic(memory) => unsafe {
                match memory.register_and_translate_offset(offset) {
                    Ok(ptr) => Ok(ptr as usize),
                    Err(e) => {
                        fail!(from self, with e,
                            "Failed to register and translate pointer due to a failure while opening the corresponding shared memory segment ({:?}).",
                            e);
                    }
                }
            },
        }
    }

    pub(crate) unsafe fn unregister_offset(&self, offset: PointerOffset) {
        unsafe {
            if let MemoryViewType::Dynamic(memory) = &self.memory {
                memory.unregister_offset(offset);
            }
        }
    }

    pub(crate) fn is_dynamic(&self) -> bool {
        matches!(&self.memory, MemoryViewType::Dynamic(_))
    }

    /// Adds a segment from a handle received via IAM at the specified index.
    ///
    /// This is used for dynamic segments when the consumer needs to map a new
    /// segment that was created by the producer during reallocation. The segment
    /// is added at the specified `segment_id` index.
    ///
    /// For dynamic segments in secured mode:
    /// - The initial segment is opened by name (using `open_dynamic_segment`)
    /// - Subsequent segments (from reallocation) use this method with handles
    ///   received from the IAM server
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying view cannot add the segment or if
    /// this is called on a static segment view.
    /// Adds a segment from a handle received via IAM.
    ///
    /// This method takes `&self` because the underlying `ResizableSharedMemoryView`
    /// uses interior mutability, allowing segment addition from shared references.
    /// This is necessary in the receiver path where only shared access to connections
    /// is available.
    pub(crate) fn add_segment_from_handle(
        &self,
        segment_id: SegmentId,
        handle: PlatformHandle,
        access: AccessRights,
    ) -> Result<(), SharedMemoryOpenError> {
        match &self.memory {
            MemoryViewType::Dynamic(memory) => memory
                .add_segment_from_handle(segment_id, handle, access)
                .map_err(|e| {
                    iceoryx2_log::error!("Failed to add segment from handle: {:?}", e);
                    SharedMemoryOpenError::DoesNotExist
                }),
            MemoryViewType::Static(_) => {
                // Static segments don't support adding segments
                iceoryx2_log::error!(
                    "Cannot add segment from handle to a static data segment view"
                );
                Err(SharedMemoryOpenError::DoesNotExist)
            }
        }
    }
}
