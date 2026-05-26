// Copyright (c) 2026 Contributors to the Eclipse Foundation
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

extern crate iceoryx2_bb_loggers;

mod resizable_shared_memory_dynamic_tests {
    use core::alloc::Layout;

    use iceoryx2_bb_container::semantic_string::SemanticString;
    use iceoryx2_bb_elementary::math::ToB64;
    use iceoryx2_bb_posix::file::AccessMode;
    use iceoryx2_bb_posix::unique_system_id::UniqueSystemId;
    use iceoryx2_bb_system_types::file_name::FileName;
    use iceoryx2_bb_testing::assert_that;

    use iceoryx2_cal::named_concept::*;
    use iceoryx2_cal::resizable_shared_memory::dynamic::DynamicMemory;
    use iceoryx2_cal::resizable_shared_memory::*;
    use iceoryx2_cal::security::{AccessRights, PlatformHandle};
    use iceoryx2_cal::shared_memory::*;
    use iceoryx2_cal::shm_allocator::pool_allocator;
    use iceoryx2_cal::shm_allocator::pool_allocator::PoolAllocator;

    type Shm = iceoryx2_cal::shared_memory::posix::Memory<PoolAllocator>;
    type Sut = DynamicMemory<PoolAllocator, Shm>;

    fn generate_name() -> FileName {
        let mut file = FileName::new(b"test_resizable_handle_").unwrap();
        file.push_bytes(UniqueSystemId::new().unwrap().value().to_b64().as_bytes())
            .unwrap();
        file
    }

    // Producer creates the management + initial data segment anonymously, extracts both handles,
    // and a view is reconstructed purely from those handles (no name-based rendezvous). The value
    // written by the producer into the initial data segment is read back through the view's offset
    // translation.
    #[test]
    fn create_and_extract_handles_and_open_from_handle_round_trip() {
        let storage_name = generate_name();
        let config = <Sut as NamedConceptMgmt>::Configuration::default();

        // Size segment 0 so both allocations below fit without triggering a reallocation, keeping
        // the whole round-trip on the brokered initial segment (segment id 0).
        let (producer, handles) = <Sut as ResizableSharedMemory<PoolAllocator, Shm>>::MemoryBuilder::new(&storage_name)
            .config(&config)
            .max_chunk_layout_hint(Layout::new::<u64>())
            .max_number_of_chunks_hint(4)
            .allocation_strategy(AllocationStrategy::Static)
            .create_and_extract_handles()
            .unwrap();

        assert_that!(handles.initial_segment_id, eq SegmentId::new(0));
        assert_that!(handles.mgmt_size, gt 0);
        assert_that!(handles.initial_segment_size, gt 0);

        // producer writes two payloads into the initial (segment id 0) data segment
        let test_value_1: u64 = 0x0BADC0DE_DEADBEEF;
        let test_value_2: u32 = 0xFEEDFACE;
        let ptr_1 = producer.allocate(Layout::new::<u64>()).unwrap();
        let ptr_2 = producer.allocate(Layout::new::<u32>()).unwrap();
        unsafe { (ptr_1.data_ptr as *mut u64).write(test_value_1) };
        unsafe { (ptr_2.data_ptr as *mut u32).write(test_value_2) };
        assert_that!(ptr_1.offset.segment_id(), eq SegmentId::new(0));
        assert_that!(producer.number_of_active_segments(), eq 1);

        // consumer reconstructs the view from the brokered handles only
        let ResizableSharedMemoryHandles {
            mgmt_handle,
            initial_segment_id,
            initial_segment_handle,
            ..
        } = handles;

        let view = <Sut as ResizableSharedMemory<PoolAllocator, Shm>>::ViewBuilder::new(&storage_name)
            .config(&config)
            .open_from_handle(
                mgmt_handle,
                initial_segment_id,
                initial_segment_handle,
                AccessRights::read_write(),
            )
            .unwrap();

        // the initial segment was registered pinned at index 0
        assert_that!(view.number_of_active_segments(), eq 1);

        let view_ptr_1 =
            unsafe { view.register_and_translate_offset(ptr_1.offset).unwrap() as *const u64 };
        let view_ptr_2 =
            unsafe { view.register_and_translate_offset(ptr_2.offset).unwrap() as *const u32 };

        assert_that!(unsafe { *view_ptr_1 }, eq test_value_1);
        assert_that!(unsafe { *view_ptr_2 }, eq test_value_2);

        // the shared mapping is live: an update on the producer side is visible in the view
        let test_value_3: u64 = 0x1234_5678_9ABC_DEF0;
        unsafe { (ptr_1.data_ptr as *mut u64).write(test_value_3) };
        assert_that!(unsafe { *view_ptr_1 }, eq test_value_3);
    }

    // Exercises the runtime reallocation path on a handle-reconstructed view: after the initial
    // segment fills up under `IamManaged`, `allocate` reports `NeedSegment`. We simulate the IAM
    // server's anonymous segment factory, hand the fd to both producer (`add_segment`) and view
    // (`add_segment_from_handle`), then round-trip a payload through the newly added segment 1.
    #[test]
    fn open_from_handle_view_maps_runtime_segment_by_handle() {
        let storage_name = generate_name();
        let config = <Sut as NamedConceptMgmt>::Configuration::default();

        let (producer, handles) = <Sut as ResizableSharedMemory<PoolAllocator, Shm>>::MemoryBuilder::new(&storage_name)
            .config(&config)
            .max_chunk_layout_hint(Layout::new::<u8>())
            .max_number_of_chunks_hint(1)
            .allocation_strategy(AllocationStrategy::IamManaged)
            .create_and_extract_handles()
            .unwrap();

        // fill segment 0 and round-trip a value through the reconstructed view
        let value_seg0: u8 = 0xA5;
        let ptr_seg0 = producer.allocate(Layout::new::<u8>()).unwrap();
        unsafe { ptr_seg0.data_ptr.write(value_seg0) };
        assert_that!(ptr_seg0.offset.segment_id(), eq SegmentId::new(0));

        let view = <Sut as ResizableSharedMemory<PoolAllocator, Shm>>::ViewBuilder::new(&storage_name)
            .config(&config)
            .open_from_handle(
                handles.mgmt_handle,
                handles.initial_segment_id,
                handles.initial_segment_handle,
                AccessRights::read_write(),
            )
            .unwrap();

        let view_ptr_seg0 =
            unsafe { view.register_and_translate_offset(ptr_seg0.offset).unwrap() };
        assert_that!(unsafe { *view_ptr_seg0 }, eq value_seg0);

        // the next allocation cannot be served by segment 0 -> IamManaged requests a new segment
        let requested_size = match producer.allocate(Layout::new::<u8>()) {
            Err(ResizableShmAllocationError::NeedSegment { requested_size }) => requested_size,
            other => panic!("expected NeedSegment, got {other:?}"),
        };

        // simulate the IAM server's anonymous segment factory creating runtime segment 1
        let anon_size = requested_size.max(64);
        let anon_allocator_config = pool_allocator::Config {
            bucket_layout: Layout::new::<u8>(),
        };
        let (_iam_segment, runtime_handle) =
            <Shm as SharedMemory<PoolAllocator>>::Builder::new(&generate_name())
                .size(anon_size)
                .has_ownership(false)
                .create_anonymous(&anon_allocator_config)
                .unwrap();

        // the producer opens the runtime segment from its handle; the view opens a clone
        let producer_handle: PlatformHandle = runtime_handle.try_clone().unwrap();
        let view_handle: PlatformHandle = runtime_handle;

        producer
            .add_segment(SegmentId::new(1), producer_handle, &anon_allocator_config)
            .unwrap();

        let value_seg1: u8 = 0x3C;
        let ptr_seg1 = producer.allocate(Layout::new::<u8>()).unwrap();
        unsafe { ptr_seg1.data_ptr.write(value_seg1) };
        assert_that!(ptr_seg1.offset.segment_id(), eq SegmentId::new(1));

        view.add_segment_from_handle(SegmentId::new(1), view_handle, AccessRights::read_write())
            .unwrap();

        let view_ptr_seg1 =
            unsafe { view.register_and_translate_offset(ptr_seg1.offset).unwrap() };
        assert_that!(unsafe { *view_ptr_seg1 }, eq value_seg1);
    }

    // F1 regression: a handle-brokered (secured) view built via `open_from_handle` MUST NOT
    // fall back to a name-based `open` for an unmapped segment. The segment name is fixed and
    // guessable, so a name-based rendezvous is a cross-uid segment-spoofing vector: an attacker
    // could pre-plant a valid segment under the guessable name and be mapped in place of the
    // authentic producer segment. This test proves that even when a real, openable named
    // `<name>__1` segment exists on disk, the handle-brokered view refuses to name-open it
    // (returns Err, maps nothing) while a public name-based view opened via `open` still
    // performs the name-based open for the same unmapped segment id. Removing the flag check in
    // `register_and_translate_offset` makes the first assertion fail (the hole reopens).
    #[test]
    fn handle_brokered_view_refuses_name_based_open_but_public_view_allows_it() {
        let config = <Sut as NamedConceptMgmt>::Configuration::default();

        // --- handle-brokered producer: auto-grows BY NAME (PowerOfTwo) so `<name>__1` is a real,
        // openable segment on disk, making the "refuses even a valid name" proof unambiguous. ---
        let brokered_name = generate_name();
        let (brokered_producer, handles) = <Sut as ResizableSharedMemory<PoolAllocator, Shm>>::MemoryBuilder::new(&brokered_name)
            .config(&config)
            .max_chunk_layout_hint(Layout::new::<u8>())
            .max_number_of_chunks_hint(1)
            .allocation_strategy(AllocationStrategy::PowerOfTwo)
            .create_and_extract_handles()
            .unwrap();

        // fill segment 0, forcing creation of a named growth segment (id 1)
        let _p0 = brokered_producer.allocate(Layout::new::<u8>()).unwrap();
        let p1 = brokered_producer.allocate(Layout::new::<u8>()).unwrap();
        unsafe { p1.data_ptr.write(0x7Eu8) };
        assert_that!(p1.offset.segment_id(), eq SegmentId::new(1));
        assert_that!(brokered_producer.number_of_active_segments(), eq 2);

        let brokered_view = <Sut as ResizableSharedMemory<PoolAllocator, Shm>>::ViewBuilder::new(&brokered_name)
            .config(&config)
            .open_from_handle(
                handles.mgmt_handle,
                handles.initial_segment_id,
                handles.initial_segment_handle,
                AccessRights::read_only(),
            )
            .unwrap();
        // only the pinned initial segment (id 0) is mapped
        assert_that!(brokered_view.number_of_active_segments(), eq 1);

        // The unmapped growth segment (id 1) EXISTS by name on disk, yet the handle-brokered view
        // refuses to open it by name -> Err, and nothing is mapped.
        let brokered_result = unsafe { brokered_view.register_and_translate_offset(p1.offset) };
        assert_that!(brokered_result, is_err);
        assert_that!(brokered_view.number_of_active_segments(), eq 1);

        // --- public contrast: a normally-created producer whose segments are name-visible ---
        let public_name = generate_name();
        let public_producer = <Sut as ResizableSharedMemory<PoolAllocator, Shm>>::MemoryBuilder::new(&public_name)
            .config(&config)
            .max_chunk_layout_hint(Layout::new::<u8>())
            .max_number_of_chunks_hint(1)
            .allocation_strategy(AllocationStrategy::PowerOfTwo)
            .create()
            .unwrap();

        let _q0 = public_producer.allocate(Layout::new::<u8>()).unwrap();
        let q1 = public_producer.allocate(Layout::new::<u8>()).unwrap();
        let public_seg1_value: u8 = 0x2D;
        unsafe { q1.data_ptr.write(public_seg1_value) };
        assert_that!(q1.offset.segment_id(), eq SegmentId::new(1));

        let public_view = <Sut as ResizableSharedMemory<PoolAllocator, Shm>>::ViewBuilder::new(&public_name)
            .config(&config)
            .open(AccessMode::Read)
            .unwrap();

        // The public (name-based) view resolves the unmapped growth segment BY NAME -> Ok, and
        // reads back the real value the producer wrote. This confirms public mode is unchanged.
        let public_ptr = unsafe { public_view.register_and_translate_offset(q1.offset) };
        assert_that!(public_ptr, is_ok);
        assert_that!(unsafe { *public_ptr.unwrap() }, eq public_seg1_value);
        assert_that!(public_view.number_of_active_segments(), eq 1);
    }
}
