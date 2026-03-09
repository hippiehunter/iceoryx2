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

extern crate iceoryx2_bb_loggers;

mod zero_copy_connection_posix_shared_memory_tests {
    use core::time::Duration;
    use iceoryx2_bb_elementary::math::ToB64;
    use iceoryx2_bb_posix::creation_mode::CreationMode;
    use iceoryx2_bb_posix::permission::Permission;
    #[cfg(unix)]
    use iceoryx2_bb_posix::file_descriptor::FileDescriptorBased;
    #[cfg(unix)]
    use iceoryx2_bb_posix::shared_memory::AccessMode;
    use iceoryx2_bb_posix::unique_system_id::UniqueSystemId;
    use iceoryx2_bb_system_types::file_name::*;
    use iceoryx2_bb_testing::assert_that;
    use iceoryx2_cal::named_concept::*;
    #[cfg(unix)]
    use iceoryx2_cal::security::AccessRights;
    #[cfg(unix)]
    use iceoryx2_cal::security::HandleBasedOpenError;
    #[cfg(unix)]
    use iceoryx2_cal::security::PlatformHandle;
    use iceoryx2_cal::zero_copy_connection::*;
    #[cfg(unix)]
    use iceoryx2_pal_posix::posix;

    const TIMEOUT: Duration = Duration::from_millis(100);

    fn generate_name() -> FileName {
        let mut file = FileName::new(b"test_").unwrap();
        file.push_bytes(UniqueSystemId::new().unwrap().value().to_b64().as_bytes())
            .unwrap();
        file
    }

    #[test]
    fn waiting_for_initialization_works() {
        type Sut = iceoryx2_cal::zero_copy_connection::posix_shared_memory::Connection;
        let storage_name = generate_name();
        let file_name = <Sut as NamedConceptMgmt>::Configuration::default()
            .path_for(&storage_name)
            .file_name();

        let _raw_shm = iceoryx2_bb_posix::shared_memory::SharedMemoryBuilder::new(&file_name)
            .creation_mode(CreationMode::PurgeAndCreate)
            .size(4096)
            .has_ownership(true)
            .permission(Permission::OWNER_WRITE)
            .create()
            .unwrap();

        let start = std::time::SystemTime::now();
        let sut = <Sut as ZeroCopyConnection>::Builder::new(&storage_name)
            .timeout(TIMEOUT)
            .number_of_samples_per_segment(1)
            .receiver_max_borrowed_samples_per_channel(1)
            .create_sender();

        assert_that!(sut, is_err);
        assert_that!(sut.err().unwrap(), eq ZeroCopyCreationError::InitializationNotYetFinalized);
        assert_that!(start.elapsed().unwrap(), ge TIMEOUT);
    }

    #[cfg(unix)]
    #[test]
    fn open_receiver_from_handle_works() {
        type Sut = iceoryx2_cal::zero_copy_connection::posix_shared_memory::Connection;
        let storage_name = generate_name();
        let buffer_size = 8;
        let number_of_samples = 4;
        let max_borrowed = 2;
        let number_of_segments = 1;
        let number_of_channels = 1;

        let _sender = <Sut as ZeroCopyConnection>::Builder::new(&storage_name)
            .buffer_size(buffer_size)
            .number_of_samples_per_segment(number_of_samples)
            .receiver_max_borrowed_samples_per_channel(max_borrowed)
            .number_of_channels(number_of_channels)
            .max_supported_shared_memory_segments(number_of_segments)
            .create_sender()
            .unwrap();

        let file_name = <Sut as NamedConceptMgmt>::Configuration::default()
            .path_for(&storage_name)
            .file_name();
        let raw_shm = iceoryx2_bb_posix::shared_memory::SharedMemoryBuilder::new(&file_name)
            .open_existing(AccessMode::ReadWrite)
            .unwrap();

        let raw_fd = unsafe { posix::dup(raw_shm.file_descriptor().native_handle()) };
        assert_that!(raw_fd, ge 0);

        let handle = unsafe { PlatformHandle::from_raw_fd(raw_fd) };
        let receiver = <Sut as ZeroCopyConnection>::Builder::new(&storage_name)
            .buffer_size(buffer_size)
            .number_of_samples_per_segment(number_of_samples)
            .receiver_max_borrowed_samples_per_channel(max_borrowed)
            .number_of_channels(number_of_channels)
            .max_supported_shared_memory_segments(number_of_segments)
            .open_receiver_from_handle(handle, AccessRights::read_write())
            .unwrap();

        assert_that!(receiver.buffer_size(), eq buffer_size);
    }

    #[cfg(unix)]
    #[test]
    fn open_receiver_from_handle_requires_write_access() {
        type Sut = iceoryx2_cal::zero_copy_connection::posix_shared_memory::Connection;
        let storage_name = generate_name();
        let buffer_size = 8;
        let number_of_samples = 4;
        let max_borrowed = 2;
        let number_of_segments = 1;
        let number_of_channels = 1;

        let _sender = <Sut as ZeroCopyConnection>::Builder::new(&storage_name)
            .buffer_size(buffer_size)
            .number_of_samples_per_segment(number_of_samples)
            .receiver_max_borrowed_samples_per_channel(max_borrowed)
            .number_of_channels(number_of_channels)
            .max_supported_shared_memory_segments(number_of_segments)
            .create_sender()
            .unwrap();

        let file_name = <Sut as NamedConceptMgmt>::Configuration::default()
            .path_for(&storage_name)
            .file_name();
        let raw_shm = iceoryx2_bb_posix::shared_memory::SharedMemoryBuilder::new(&file_name)
            .open_existing(AccessMode::ReadWrite)
            .unwrap();

        let raw_fd = unsafe { posix::dup(raw_shm.file_descriptor().native_handle()) };
        assert_that!(raw_fd, ge 0);

        let handle = unsafe { PlatformHandle::from_raw_fd(raw_fd) };
        let receiver = <Sut as ZeroCopyConnection>::Builder::new(&storage_name)
            .buffer_size(buffer_size)
            .number_of_samples_per_segment(number_of_samples)
            .receiver_max_borrowed_samples_per_channel(max_borrowed)
            .number_of_channels(number_of_channels)
            .max_supported_shared_memory_segments(number_of_segments)
            .open_receiver_from_handle(handle, AccessRights::read_only());

        assert_that!(receiver, is_err);
        assert_that!(
            receiver.err().unwrap(),
            eq HandleBasedOpenError::InsufficientPermissions
        );
    }
}
