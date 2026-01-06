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

extern crate iceoryx2_loggers;

mod shared_memory_posix_shared_memory_tests {
    use core::alloc::Layout;
    use core::time::Duration;
    use iceoryx2_bb_posix::creation_mode::CreationMode;
    use iceoryx2_bb_posix::permission::Permission;
    use iceoryx2_bb_testing::assert_that;
    use iceoryx2_cal::named_concept::*;
    use iceoryx2_cal::security::AccessRights;
    use iceoryx2_cal::shared_memory::*;
    use iceoryx2_cal::shm_allocator::pool_allocator;
    use iceoryx2_cal::shm_allocator::pool_allocator::PoolAllocator;
    use iceoryx2_cal::testing::generate_name;

    const TIMEOUT: Duration = Duration::from_millis(100);

    #[test]
    fn waiting_for_initialization_works() {
        type Sut = iceoryx2_cal::shared_memory::posix::Memory<PoolAllocator>;
        let storage_name = generate_name();
        let file_name = <Sut as NamedConceptMgmt>::Configuration::default()
            .path_for(&storage_name)
            .file_name();

        let _raw_shm = iceoryx2_bb_posix::shared_memory::SharedMemoryBuilder::new(&file_name)
            .creation_mode(CreationMode::PurgeAndCreate)
            .size(1234)
            .has_ownership(true)
            .permission(Permission::OWNER_WRITE)
            .create()
            .unwrap();

        let start = std::time::SystemTime::now();
        let sut = <Sut as SharedMemory<PoolAllocator>>::Builder::new(&storage_name)
            .timeout(TIMEOUT)
            .open();

        assert_that!(sut, is_err);
        assert_that!(sut.err().unwrap(), eq SharedMemoryOpenError::InitializationNotYetFinalized);
        assert_that!(start.elapsed().unwrap(), ge TIMEOUT);
    }

    #[test]
    fn create_anonymous_and_open_from_handle_works() {
        type Sut = iceoryx2_cal::shared_memory::posix::Memory<PoolAllocator>;
        let storage_name = generate_name();
        let allocator_config = pool_allocator::Config {
            bucket_layout: Layout::new::<u64>(),
        };

        let (creator, handle) = <Sut as SharedMemory<PoolAllocator>>::Builder::new(&storage_name)
            .size(1024)
            .create_anonymous(&allocator_config)
            .unwrap();

        unsafe {
            (creator.payload_start_address() as *mut u64).write(0xDEAD_BEEF);
        }

        let config = <Sut as NamedConceptMgmt>::Configuration::default();
        let opened = <Sut as SharedMemory<PoolAllocator>>::Builder::new(&storage_name)
            .size(1024)
            .open_from_handle(handle, AccessRights::read_only(), &config)
            .unwrap();

        let value = unsafe { *(opened.payload_start_address() as *const u64) };
        assert_that!(value, eq 0xDEAD_BEEF);
    }
}
