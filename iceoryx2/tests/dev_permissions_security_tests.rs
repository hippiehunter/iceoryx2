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

//! Tests verifying that the `dev_permissions` feature cannot be used with `SecurityMode::Secured`.
//!
//! The `dev_permissions` feature sets world-readable permissions (Permission::ALL) on shared memory,
//! sockets, and files. This directly conflicts with `SecurityMode::Secured` which relies on OS-level
//! isolation for security.
//!
//! These tests only run when the `dev_permissions` feature is enabled.

#![cfg(all(test, feature = "dev_permissions"))]

mod dev_permissions_security {
    use iceoryx2::config::Config;
    use iceoryx2::node::NodeBuilder;
    use iceoryx2::prelude::*;
    use iceoryx2::service::builder::event::{EventCreateError, EventOpenError};
    use iceoryx2::service::builder::publish_subscribe::{
        PublishSubscribeCreateError, PublishSubscribeOpenError,
    };
    use iceoryx2::service::builder::request_response::{
        RequestResponseCreateError, RequestResponseOpenError,
    };
    use iceoryx2_bb_testing::assert_that;
    use iceoryx2_cal::security::mode::SecurityMode;

    fn generate_unique_service_name() -> ServiceName {
        use iceoryx2_bb_posix::unique_system_id::UniqueSystemId;
        let id = UniqueSystemId::new().unwrap();
        ServiceName::new(&format!("test_dev_permissions_{}", id.value())).unwrap()
    }

    fn create_secured_config() -> Config {
        let mut config = Config::default();
        config.global.node.security.mode = SecurityMode::Secured;
        config
    }

    fn create_secured_node() -> iceoryx2::node::Node<ipc::Service> {
        NodeBuilder::new()
            .config(&create_secured_config())
            .create::<ipc::Service>()
            .expect("Failed to create secured node")
    }

    // ============================================================================
    // Publish-Subscribe Tests
    // ============================================================================

    #[test]
    fn publish_subscribe_create_fails_with_dev_permissions_and_secured_mode() {
        let service_name = generate_unique_service_name();
        let node = create_secured_node();

        let result = node
            .service_builder(&service_name)
            .publish_subscribe::<u64>()
            .create();

        assert_that!(result, is_err);
        let err = result.unwrap_err();
        assert_that!(
            err,
            eq PublishSubscribeCreateError::DevPermissionsIncompatibleWithSecuredMode
        );
    }

    #[test]
    fn publish_subscribe_open_fails_with_dev_permissions_and_secured_mode() {
        let service_name = generate_unique_service_name();
        let node = create_secured_node();

        // Even opening should fail early before checking if service exists
        let result = node
            .service_builder(&service_name)
            .publish_subscribe::<u64>()
            .open();

        assert_that!(result, is_err);
        let err = result.unwrap_err();
        assert_that!(
            err,
            eq PublishSubscribeOpenError::DevPermissionsIncompatibleWithSecuredMode
        );
    }

    #[test]
    fn publish_subscribe_open_or_create_fails_with_dev_permissions_and_secured_mode() {
        let service_name = generate_unique_service_name();
        let node = create_secured_node();

        let result = node
            .service_builder(&service_name)
            .publish_subscribe::<u64>()
            .open_or_create();

        assert_that!(result, is_err);
    }

    #[test]
    fn publish_subscribe_works_with_dev_permissions_and_public_mode() {
        let service_name = generate_unique_service_name();

        // Public mode is the default
        let config = Config::default();
        assert_that!(config.global.node.security.mode, eq SecurityMode::Public);

        let node = NodeBuilder::new()
            .config(&config)
            .create::<ipc::Service>()
            .expect("Failed to create public node");

        // With dev_permissions + public mode, service creation should succeed
        let result = node
            .service_builder(&service_name)
            .publish_subscribe::<u64>()
            .create();

        assert_that!(result, is_ok);
    }

    // ============================================================================
    // Request-Response Tests
    // ============================================================================

    #[test]
    fn request_response_create_fails_with_dev_permissions_and_secured_mode() {
        let service_name = generate_unique_service_name();
        let node = create_secured_node();

        let result = node
            .service_builder(&service_name)
            .request_response::<u64, u64>()
            .create();

        assert_that!(result, is_err);
        let err = result.unwrap_err();
        assert_that!(
            err,
            eq RequestResponseCreateError::DevPermissionsIncompatibleWithSecuredMode
        );
    }

    #[test]
    fn request_response_open_fails_with_dev_permissions_and_secured_mode() {
        let service_name = generate_unique_service_name();
        let node = create_secured_node();

        let result = node
            .service_builder(&service_name)
            .request_response::<u64, u64>()
            .open();

        assert_that!(result, is_err);
        let err = result.unwrap_err();
        assert_that!(
            err,
            eq RequestResponseOpenError::DevPermissionsIncompatibleWithSecuredMode
        );
    }

    #[test]
    fn request_response_open_or_create_fails_with_dev_permissions_and_secured_mode() {
        let service_name = generate_unique_service_name();
        let node = create_secured_node();

        let result = node
            .service_builder(&service_name)
            .request_response::<u64, u64>()
            .open_or_create();

        assert_that!(result, is_err);
    }

    #[test]
    fn request_response_works_with_dev_permissions_and_public_mode() {
        let service_name = generate_unique_service_name();

        let config = Config::default();
        let node = NodeBuilder::new()
            .config(&config)
            .create::<ipc::Service>()
            .expect("Failed to create public node");

        let result = node
            .service_builder(&service_name)
            .request_response::<u64, u64>()
            .create();

        assert_that!(result, is_ok);
    }

    // ============================================================================
    // Event Tests
    // ============================================================================

    #[test]
    fn event_create_fails_with_dev_permissions_and_secured_mode() {
        let service_name = generate_unique_service_name();
        let node = create_secured_node();

        let result = node.service_builder(&service_name).event().create();

        assert_that!(result, is_err);
        let err = result.unwrap_err();
        assert_that!(
            err,
            eq EventCreateError::DevPermissionsIncompatibleWithSecuredMode
        );
    }

    #[test]
    fn event_open_fails_with_dev_permissions_and_secured_mode() {
        let service_name = generate_unique_service_name();
        let node = create_secured_node();

        let result = node.service_builder(&service_name).event().open();

        assert_that!(result, is_err);
        let err = result.unwrap_err();
        assert_that!(
            err,
            eq EventOpenError::DevPermissionsIncompatibleWithSecuredMode
        );
    }

    #[test]
    fn event_open_or_create_fails_with_dev_permissions_and_secured_mode() {
        let service_name = generate_unique_service_name();
        let node = create_secured_node();

        let result = node.service_builder(&service_name).event().open_or_create();

        assert_that!(result, is_err);
    }

    #[test]
    fn event_works_with_dev_permissions_and_public_mode() {
        let service_name = generate_unique_service_name();

        let config = Config::default();
        let node = NodeBuilder::new()
            .config(&config)
            .create::<ipc::Service>()
            .expect("Failed to create public node");

        let result = node.service_builder(&service_name).event().create();

        assert_that!(result, is_ok);
    }
}
