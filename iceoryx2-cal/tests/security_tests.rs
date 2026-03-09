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

//! Tests for the security module.

// Only compile tests when std feature is enabled
#![cfg(feature = "std")]

extern crate iceoryx2_bb_loggers;

use iceoryx2_bb_testing::assert_that;
use iceoryx2_cal::security::*;
use iceoryx2_cal::shm_allocator::SegmentId;
use std::fs::File;
#[cfg(unix)]
use std::os::unix::io::{FromRawFd, IntoRawFd};
#[cfg(windows)]
use std::os::windows::io::{AsRawHandle, FromRawHandle, IntoRawHandle};

#[cfg(unix)]
mod platform_handle_tests {
    use super::*;

    fn create_test_handle() -> PlatformHandle {
        // Create a temporary file and use its fd as our test handle
        let file = File::open("/dev/null").expect("Failed to open /dev/null");
        let fd = file.into_raw_fd();
        unsafe { PlatformHandle::from_raw_fd(fd) }
    }

    #[test]
    fn try_clone_creates_independent_handle() {
        let handle = create_test_handle();
        let original_fd = handle.as_raw_fd();

        let cloned = handle.try_clone().expect("clone should succeed");

        assert_that!(cloned.as_raw_fd(), ne original_fd);
        assert_that!(cloned.as_raw_fd(), ge 0);
    }

    #[test]
    fn as_raw_fd_returns_valid_fd() {
        let handle = create_test_handle();
        let fd = handle.as_raw_fd();

        assert_that!(fd, ge 0);
    }

    #[test]
    fn into_raw_fd_transfers_ownership() {
        let handle = create_test_handle();
        let fd = handle.into_raw_fd();

        assert_that!(fd, ge 0);

        // Clean up manually since we took ownership - reconstruct File and drop it
        unsafe { drop(File::from_raw_fd(fd)) };
    }
}

#[cfg(windows)]
mod platform_handle_tests {
    use super::*;

    fn create_test_handle() -> PlatformHandle {
        // Create a temporary file and use its handle as our test handle
        let file = File::open("NUL").expect("Failed to open NUL");
        let handle = file.into_raw_handle();
        unsafe { PlatformHandle::from_raw_handle(handle) }
    }

    #[test]
    fn try_clone_creates_independent_handle() {
        let handle = create_test_handle();
        let original_handle = handle.as_raw_handle();

        let cloned = handle.try_clone().expect("clone should succeed");

        assert_that!(cloned.as_raw_handle(), ne original_handle);
        assert_that!(cloned.as_raw_handle().is_null(), eq false);
    }

    #[test]
    fn as_raw_handle_returns_valid_handle() {
        let handle = create_test_handle();
        let raw = handle.as_raw_handle();

        assert_that!(raw.is_null(), eq false);
    }

    #[test]
    fn into_raw_handle_transfers_ownership() {
        let handle = create_test_handle();
        let raw = handle.into_raw_handle();

        assert_that!(raw.is_null(), eq false);

        // Clean up manually since we took ownership - reconstruct File and drop it
        unsafe { drop(File::from_raw_handle(raw)) };
    }
}

mod access_rights_tests {
    use super::*;

    #[test]
    fn none_has_no_permissions() {
        let rights = AccessRights::none();

        assert_that!(rights.read, eq false);
        assert_that!(rights.write, eq false);
        assert_that!(rights.has_any(), eq false);
    }

    #[test]
    fn read_only_has_read_permission() {
        let rights = AccessRights::read_only();

        assert_that!(rights.read, eq true);
        assert_that!(rights.write, eq false);
        assert_that!(rights.can_read(), eq true);
        assert_that!(rights.can_write(), eq false);
    }

    #[test]
    fn read_write_has_both_permissions() {
        let rights = AccessRights::read_write();

        assert_that!(rights.read, eq true);
        assert_that!(rights.write, eq true);
        assert_that!(rights.can_read(), eq true);
        assert_that!(rights.can_write(), eq true);
        assert_that!(rights.has_any(), eq true);
    }

    #[test]
    fn default_is_none() {
        let rights = AccessRights::default();

        assert_that!(rights, eq AccessRights::none());
    }
}

#[cfg(unix)]
mod handle_bundle_tests {
    use super::*;

    fn create_test_handle() -> PlatformHandle {
        let file = File::open("/dev/null").expect("Failed to open /dev/null");
        let fd = file.into_raw_fd();
        unsafe { PlatformHandle::from_raw_fd(fd) }
    }

    #[test]
    fn new_creates_bundle_with_correct_fields() {
        let handle = create_test_handle();
        let segment_id = SegmentId::new(42);
        let access = AccessRights::read_only();
        let size = 4096usize;

        let bundle = HandleBundle::new(handle, segment_id, access, size);

        assert_that!(bundle.segment_id().value(), eq 42);
        assert_that!(bundle.access(), eq AccessRights::read_only());
        assert_that!(bundle.size(), eq 4096);
    }

    #[test]
    fn into_handle_returns_platform_handle() {
        let handle = create_test_handle();
        let original_fd = handle.as_raw_fd();
        let bundle = HandleBundle::new(handle, SegmentId::new(0), AccessRights::none(), 0);

        let recovered_handle = bundle.into_handle();

        assert_that!(recovered_handle.as_raw_fd(), eq original_fd);
    }
}

#[cfg(windows)]
mod handle_bundle_tests {
    use super::*;

    fn create_test_handle() -> PlatformHandle {
        let file = File::open("NUL").expect("Failed to open NUL");
        let handle = file.into_raw_handle();
        unsafe { PlatformHandle::from_raw_handle(handle) }
    }

    #[test]
    fn new_creates_bundle_with_correct_fields() {
        let handle = create_test_handle();
        let segment_id = SegmentId::new(42);
        let access = AccessRights::read_only();
        let size = 4096usize;

        let bundle = HandleBundle::new(handle, segment_id, access, size);

        assert_that!(bundle.segment_id().value(), eq 42);
        assert_that!(bundle.access(), eq AccessRights::read_only());
        assert_that!(bundle.size(), eq 4096);
    }

    #[test]
    fn into_handle_returns_platform_handle() {
        let handle = create_test_handle();
        let original_handle = handle.as_raw_handle();
        let bundle = HandleBundle::new(handle, SegmentId::new(0), AccessRights::none(), 0);

        let recovered_handle = bundle.into_handle();

        assert_that!(recovered_handle.as_raw_handle(), eq original_handle);
    }
}

mod error_tests {
    use super::*;

    #[test]
    fn handle_error_display() {
        let error = HandleError::DuplicationFailed;
        let display = format!("{}", error);

        assert_that!(display.contains("DuplicationFailed"), eq true);
    }

    #[test]
    fn handle_based_open_error_display() {
        let error = HandleBasedOpenError::MappingFailed;
        let display = format!("{}", error);

        assert_that!(display.contains("MappingFailed"), eq true);
    }

    #[test]
    fn handle_error_converts_to_handle_based_open_error() {
        let error = HandleError::InvalidHandle;
        let converted: HandleBasedOpenError = error.into();

        assert_that!(converted, eq HandleBasedOpenError::InvalidHandle);
    }

    #[test]
    fn duplication_failed_converts_to_internal_error() {
        let error = HandleError::DuplicationFailed;
        let converted: HandleBasedOpenError = error.into();

        assert_that!(converted, eq HandleBasedOpenError::InternalError);
    }
}

mod security_mode_tests {
    use super::*;

    #[test]
    fn default_is_public() {
        let mode = SecurityMode::default();

        assert_that!(mode, eq SecurityMode::Public);
    }

    #[test]
    fn public_does_not_require_iam() {
        let mode = SecurityMode::Public;

        assert_that!(mode.requires_iam(), eq false);
    }

    #[test]
    fn secured_requires_iam() {
        let mode = SecurityMode::Secured;

        assert_that!(mode.requires_iam(), eq true);
    }

    #[test]
    fn is_public_returns_true_for_public() {
        let mode = SecurityMode::Public;

        assert_that!(mode.is_public(), eq true);
        assert_that!(mode.is_secured(), eq false);
    }

    #[test]
    fn is_secured_returns_true_for_secured() {
        let mode = SecurityMode::Secured;

        assert_that!(mode.is_secured(), eq true);
        assert_that!(mode.is_public(), eq false);
    }

    #[test]
    fn display_public() {
        let mode = SecurityMode::Public;
        let display = format!("{}", mode);

        assert_that!(display, eq "public");
    }

    #[test]
    fn display_secured() {
        let mode = SecurityMode::Secured;
        let display = format!("{}", mode);

        assert_that!(display, eq "secured");
    }

    #[test]
    fn clone_preserves_value() {
        let mode = SecurityMode::Secured;
        let cloned = mode.clone();

        assert_that!(cloned, eq mode);
    }

    #[test]
    fn serde_roundtrip_public() {
        #[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug)]
        struct Wrapper {
            mode: SecurityMode,
        }
        let wrapper = Wrapper {
            mode: SecurityMode::Public,
        };
        let toml_str = toml::to_string(&wrapper).expect("serialize should succeed");
        let deserialized: Wrapper = toml::from_str(&toml_str).expect("deserialize should succeed");

        assert_that!(deserialized.mode, eq wrapper.mode);
    }

    #[test]
    fn serde_roundtrip_secured() {
        #[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug)]
        struct Wrapper {
            mode: SecurityMode,
        }
        let wrapper = Wrapper {
            mode: SecurityMode::Secured,
        };
        let toml_str = toml::to_string(&wrapper).expect("serialize should succeed");
        let deserialized: Wrapper = toml::from_str(&toml_str).expect("deserialize should succeed");

        assert_that!(deserialized.mode, eq wrapper.mode);
    }
}

mod process_credentials_tests {
    use super::*;

    #[test]
    fn new_creates_with_correct_values() {
        let creds = ProcessCredentials::new(123, 456, 789);

        assert_that!(creds.pid(), eq 123);
        assert_that!(creds.uid(), eq 456);
        assert_that!(creds.gid(), eq 789);
    }

    #[test]
    fn from_self_returns_current_process_credentials() {
        let creds = ProcessCredentials::from_self();

        // Should match current process values
        assert_that!(creds.pid(), eq std::process::id());
    }

    #[test]
    fn equality_works() {
        let creds1 = ProcessCredentials::new(1, 2, 3);
        let creds2 = ProcessCredentials::new(1, 2, 3);
        let creds3 = ProcessCredentials::new(1, 2, 4);

        assert_that!(creds1, eq creds2);
        assert_that!(creds1, ne creds3);
    }

    #[test]
    fn clone_preserves_values() {
        let creds = ProcessCredentials::new(100, 200, 300);
        let cloned = creds.clone();

        assert_that!(cloned, eq creds);
    }

    #[test]
    fn debug_format_contains_fields() {
        let creds = ProcessCredentials::new(111, 222, 333);
        let debug = format!("{:?}", creds);

        assert_that!(debug.contains("111"), eq true);
        assert_that!(debug.contains("222"), eq true);
        assert_that!(debug.contains("333"), eq true);
    }

    #[test]
    fn display_format_contains_fields() {
        let creds = ProcessCredentials::new(111, 222, 333);
        let display = format!("{}", creds);

        assert_that!(display.contains("pid: 111"), eq true);
        assert_that!(display.contains("uid: 222"), eq true);
        assert_that!(display.contains("gid: 333"), eq true);
    }

    #[test]
    fn hash_is_consistent() {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let creds1 = ProcessCredentials::new(1, 2, 3);
        let creds2 = ProcessCredentials::new(1, 2, 3);

        let mut hasher1 = DefaultHasher::new();
        let mut hasher2 = DefaultHasher::new();
        creds1.hash(&mut hasher1);
        creds2.hash(&mut hasher2);

        assert_that!(hasher1.finish(), eq hasher2.finish());
    }

    #[cfg(unix)]
    #[test]
    fn with_start_time_stores_start_time() {
        let creds = ProcessCredentials::with_start_time(100, 200, 300, 12345);

        assert_that!(creds.pid(), eq 100);
        assert_that!(creds.uid(), eq 200);
        assert_that!(creds.gid(), eq 300);
        assert_that!(creds.start_time(), eq Some(12345));
    }

    #[cfg(unix)]
    #[test]
    fn start_time_is_none_without_explicit_set() {
        let creds = ProcessCredentials::new(100, 200, 300);

        assert_that!(creds.start_time(), eq None);
    }

    #[test]
    fn is_same_process_without_start_time_returns_true() {
        let creds = ProcessCredentials::new(100, 200, 300);

        assert_that!(creds.is_same_process(), eq true);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn from_self_with_start_time_returns_credentials() {
        let creds = ProcessCredentials::from_self_with_start_time();

        assert_that!(creds.is_some(), eq true);
        let creds = creds.unwrap();
        assert_that!(creds.pid(), eq std::process::id());
        assert_that!(creds.start_time().is_some(), eq true);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn is_same_process_returns_true_for_current_process() {
        let creds = ProcessCredentials::from_self_with_start_time();

        assert_that!(creds.is_some(), eq true);
        let creds = creds.unwrap();
        assert_that!(creds.is_same_process(), eq true);
    }
}

mod trait_tests {
    use super::*;

    // Test that traits are properly exported
    #[test]
    fn traits_are_exported() {
        // Just verify the trait types exist and are usable
        fn _accepts_handle_based_concept<T: HandleBasedConcept>() {}
        fn _accepts_builder<T: HandleBasedConcept, B: HandleBasedConceptBuilder<T>>() {}
    }
}
