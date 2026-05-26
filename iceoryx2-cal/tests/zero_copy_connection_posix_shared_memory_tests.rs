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
    #[cfg(unix)]
    use iceoryx2_bb_posix::file_descriptor::FileDescriptorBased;
    use iceoryx2_bb_posix::permission::Permission;
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
    fn create_sender_anonymous_and_open_receiver_from_handle_works() {
        type Sut = iceoryx2_cal::zero_copy_connection::posix_shared_memory::Connection;
        let storage_name = generate_name();
        let buffer_size = 8;
        let number_of_samples = 4;
        let max_borrowed = 2;
        let number_of_segments = 1;
        let number_of_channels = 1;
        let sample_size = 128;

        // (a) create_sender_anonymous() yields a sender + a valid handle
        let (sender, handle) = <Sut as ZeroCopyConnection>::Builder::new(&storage_name)
            .buffer_size(buffer_size)
            .number_of_samples_per_segment(number_of_samples)
            .receiver_max_borrowed_samples_per_channel(max_borrowed)
            .number_of_channels(number_of_channels)
            .max_supported_shared_memory_segments(number_of_segments)
            .create_sender_anonymous()
            .unwrap();

        assert_that!(sender.buffer_size(), eq buffer_size);
        // A valid handle can be duplicated.
        let handle_for_receiver = handle.try_clone().unwrap();

        // (b) open_receiver_from_handle(handle, read+write) opens a working receiver end
        let receiver = <Sut as ZeroCopyConnection>::Builder::new(&storage_name)
            .buffer_size(buffer_size)
            .number_of_samples_per_segment(number_of_samples)
            .receiver_max_borrowed_samples_per_channel(max_borrowed)
            .number_of_channels(number_of_channels)
            .max_supported_shared_memory_segments(number_of_segments)
            .open_receiver_from_handle(handle_for_receiver, AccessRights::read_write())
            .unwrap();

        assert_that!(receiver.buffer_size(), eq buffer_size);

        // submission/completion round-trip over the handle-brokered connection
        let id = ChannelId::new(0);
        let sample_offset = sample_size * 2;

        let send_result = sender
            .try_send(PointerOffset::new(sample_offset), sample_size, id)
            .unwrap();
        assert_that!(send_result, is_none);

        let sample = receiver.receive(id).unwrap();
        assert_that!(sample, is_some);
        let sample = sample.unwrap();
        assert_that!(sample.offset(), eq sample_offset);

        assert_that!(receiver.release(sample, id), is_ok);

        let retrieval = sender.reclaim(id).unwrap();
        assert_that!(retrieval, is_some);
        assert_that!(retrieval.unwrap().offset(), eq sample_offset);

        assert_that!(sender.reclaim(id).unwrap(), is_none);
    }

    // R3 regression: over a handle-brokered connection (the transport used in secured mode), a
    // sample returned by `receive()` holds a borrow until `release()` is called. iceoryx2's
    // secured dynamic-segment retry branches previously took early `return Ok(None)` exits WITHOUT
    // releasing the borrow they had just taken; this test documents the failure mode those exits
    // caused and proves that `release()` — the call the fix now issues on every lost-chunk exit —
    // is the antidote. Direct injection of the secured not-yet-registered race requires the full
    // IAM stack plus a forced producer/consumer timing race, so the release-path property is
    // pinned here at the transport layer and the three fixed branches are covered by inspection.
    #[cfg(unix)]
    #[test]
    fn received_but_not_released_samples_exhaust_borrow_budget_until_released() {
        type Sut = iceoryx2_cal::zero_copy_connection::posix_shared_memory::Connection;
        let storage_name = generate_name();
        let buffer_size = 8;
        let number_of_samples = 8;
        let max_borrowed = 2;
        let number_of_segments = 1;
        let number_of_channels = 1;
        let sample_size = 128;

        let (sender, handle) = <Sut as ZeroCopyConnection>::Builder::new(&storage_name)
            .buffer_size(buffer_size)
            .number_of_samples_per_segment(number_of_samples)
            .receiver_max_borrowed_samples_per_channel(max_borrowed)
            .number_of_channels(number_of_channels)
            .max_supported_shared_memory_segments(number_of_segments)
            .create_sender_anonymous()
            .unwrap();

        let receiver = <Sut as ZeroCopyConnection>::Builder::new(&storage_name)
            .buffer_size(buffer_size)
            .number_of_samples_per_segment(number_of_samples)
            .receiver_max_borrowed_samples_per_channel(max_borrowed)
            .number_of_channels(number_of_channels)
            .max_supported_shared_memory_segments(number_of_segments)
            .open_receiver_from_handle(handle.try_clone().unwrap(), AccessRights::read_write())
            .unwrap();

        let id = ChannelId::new(0);

        // Queue three samples on the producer side.
        for i in 1..=3 {
            assert_that!(
                sender
                    .try_send(PointerOffset::new(sample_size * i), sample_size, id)
                    .unwrap(),
                is_none
            );
        }

        // Receive `max_borrowed` samples WITHOUT releasing them. This is exactly what a leaked
        // borrow looks like: each `receive()` that returns `Some` increments the borrow counter.
        let mut borrowed = Vec::new();
        for _ in 0..max_borrowed {
            let sample = receiver.receive(id).unwrap();
            assert_that!(sample, is_some);
            borrowed.push(sample.unwrap());
        }
        assert_that!(receiver.borrow_count(id), eq max_borrowed);

        // A further sample IS queued, but the receiver now refuses to hand it out because the
        // borrow budget is exhausted — the permanent stall a leaked borrow causes.
        let stalled = receiver.receive(id);
        assert_that!(stalled, is_err);
        assert_that!(
            stalled.err().unwrap(),
            eq ZeroCopyReceiveError::ReceiveWouldExceedMaxBorrowValue
        );

        // Releasing the borrows (the antidote the R3 fix applies on every lost-chunk exit) brings
        // the counter back to baseline and lets the receiver make progress again.
        for sample in borrowed {
            assert_that!(receiver.release(sample, id), is_ok);
        }
        assert_that!(receiver.borrow_count(id), eq 0);

        let sample = receiver.receive(id).unwrap();
        assert_that!(sample, is_some);
        assert_that!(sample.unwrap().offset(), eq sample_size * 3);
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
