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

//! Integration tests for IAM security mode in service builder.
//!
//! These tests verify:
//! - Security mode validation when opening services
//! - Secured node cannot open public service
//! - Public node cannot open secured service
//! - Configuration serialization with security mode

#[cfg(test)]
mod security_mode_validation {
    use iceoryx2::config::Config;
    use iceoryx2::node::NodeBuilder;
    use iceoryx2::prelude::*;
    use iceoryx2::service::builder::publish_subscribe::PublishSubscribeOpenError;
    use iceoryx2_bb_testing::assert_that;
    use iceoryx2_cal::security::mode::SecurityMode;

    fn generate_unique_service_name() -> ServiceName {
        use iceoryx2_bb_posix::unique_system_id::UniqueSystemId;
        let id = UniqueSystemId::new().unwrap();
        ServiceName::new(&format!("test_iam_integration_{}", id.value())).unwrap()
    }

    #[test]
    fn public_node_can_create_public_service() {
        let service_name = generate_unique_service_name();

        let config = Config::default();
        assert_that!(config.global.node.security.mode, eq SecurityMode::Public);

        let node = NodeBuilder::new()
            .config(&config)
            .create::<ipc::Service>()
            .expect("Failed to create public node");

        let result = node
            .service_builder(&service_name)
            .publish_subscribe::<u64>()
            .create();

        assert_that!(result, is_ok);
    }

    #[test]
    fn secured_node_can_create_secured_service() {
        let service_name = generate_unique_service_name();

        let mut config = Config::default();
        config.global.node.security.mode = SecurityMode::Secured;

        let node = NodeBuilder::new()
            .config(&config)
            .create::<ipc::Service>()
            .expect("Failed to create secured node");

        let result = node
            .service_builder(&service_name)
            .publish_subscribe::<u64>()
            .create();

        // Service creation should succeed (IAM server not implemented yet,
        // so this tests the config path)
        assert_that!(result, is_ok);
    }

    #[test]
    fn secured_node_cannot_open_public_service() {
        let service_name = generate_unique_service_name();

        // Create a public service first
        let public_config = Config::default();
        let public_node = NodeBuilder::new()
            .config(&public_config)
            .create::<ipc::Service>()
            .expect("Failed to create public node");

        let _service = public_node
            .service_builder(&service_name)
            .publish_subscribe::<u64>()
            .create()
            .expect("Failed to create public service");

        // Try to open with a secured node
        let mut secured_config = Config::default();
        secured_config.global.node.security.mode = SecurityMode::Secured;

        let secured_node = NodeBuilder::new()
            .config(&secured_config)
            .create::<ipc::Service>()
            .expect("Failed to create secured node");

        let result = secured_node
            .service_builder(&service_name)
            .publish_subscribe::<u64>()
            .open();

        match result {
            Err(PublishSubscribeOpenError::IncompatibleSecurityMode) => {
                // Expected error
            }
            Err(e) => {
                panic!("Expected IncompatibleSecurityMode, got: {:?}", e);
            }
            Ok(_) => {
                panic!("Expected error, but service was opened successfully");
            }
        }
    }

    #[test]
    fn public_node_cannot_open_secured_service() {
        let service_name = generate_unique_service_name();

        // Create a secured service first
        let mut secured_config = Config::default();
        secured_config.global.node.security.mode = SecurityMode::Secured;

        let secured_node = NodeBuilder::new()
            .config(&secured_config)
            .create::<ipc::Service>()
            .expect("Failed to create secured node");

        let _service = secured_node
            .service_builder(&service_name)
            .publish_subscribe::<u64>()
            .create()
            .expect("Failed to create secured service");

        // Try to open with a public node
        let public_config = Config::default();
        let public_node = NodeBuilder::new()
            .config(&public_config)
            .create::<ipc::Service>()
            .expect("Failed to create public node");

        let result = public_node
            .service_builder(&service_name)
            .publish_subscribe::<u64>()
            .open();

        match result {
            Err(PublishSubscribeOpenError::IncompatibleSecurityMode) => {
                // Expected error
            }
            Err(e) => {
                panic!("Expected IncompatibleSecurityMode, got: {:?}", e);
            }
            Ok(_) => {
                panic!("Expected error, but service was opened successfully");
            }
        }
    }

    #[test]
    fn public_node_can_open_public_service() {
        let service_name = generate_unique_service_name();

        // Create a public service
        let config = Config::default();
        let node1 = NodeBuilder::new()
            .config(&config)
            .create::<ipc::Service>()
            .expect("Failed to create node 1");

        let _service1 = node1
            .service_builder(&service_name)
            .publish_subscribe::<u64>()
            .create()
            .expect("Failed to create service");

        // Open with another public node
        let node2 = NodeBuilder::new()
            .config(&config)
            .create::<ipc::Service>()
            .expect("Failed to create node 2");

        let result = node2
            .service_builder(&service_name)
            .publish_subscribe::<u64>()
            .open();

        assert_that!(result, is_ok);
    }

    #[test]
    fn secured_node_can_open_secured_service() {
        let service_name = generate_unique_service_name();

        // Create a secured service
        let mut config = Config::default();
        config.global.node.security.mode = SecurityMode::Secured;

        let node1 = NodeBuilder::new()
            .config(&config)
            .create::<ipc::Service>()
            .expect("Failed to create node 1");

        let _service1 = node1
            .service_builder(&service_name)
            .publish_subscribe::<u64>()
            .create()
            .expect("Failed to create service");
        // Open with another secured node
        let node2 = NodeBuilder::new()
            .config(&config)
            .create::<ipc::Service>()
            .expect("Failed to create node 2");

        let result = node2
            .service_builder(&service_name)
            .publish_subscribe::<u64>()
            .open();

        assert_that!(result, is_ok);
    }

    #[test]
    fn open_or_create_with_mismatched_security_modes_returns_error() {
        let service_name = generate_unique_service_name();

        // Create a public service
        let public_config = Config::default();
        let public_node = NodeBuilder::new()
            .config(&public_config)
            .create::<ipc::Service>()
            .expect("Failed to create public node");

        let _service = public_node
            .service_builder(&service_name)
            .publish_subscribe::<u64>()
            .create()
            .expect("Failed to create public service");

        // Try open_or_create with a secured node
        let mut secured_config = Config::default();
        secured_config.global.node.security.mode = SecurityMode::Secured;

        let secured_node = NodeBuilder::new()
            .config(&secured_config)
            .create::<ipc::Service>()
            .expect("Failed to create secured node");

        let result = secured_node
            .service_builder(&service_name)
            .publish_subscribe::<u64>()
            .open_or_create();

        // Should get IncompatibleSecurityMode wrapped in the OpenOrCreate error
        assert_that!(result, is_err);
    }
}

#[cfg(test)]
mod config_serialization {
    use iceoryx2::config::{Config, NodeSecurity};
    use iceoryx2_bb_testing::assert_that;
    use iceoryx2_cal::security::mode::SecurityMode;
    use std::time::Duration;

    #[test]
    fn node_security_has_correct_defaults() {
        let security = NodeSecurity::default();

        assert_that!(security.mode, eq SecurityMode::Public);
        assert_that!(security.iam.connect_timeout, eq Duration::from_secs(5));
    }

    #[test]
    fn config_default_security_mode_is_public() {
        let config = Config::default();

        assert_that!(config.global.node.security.mode, eq SecurityMode::Public);
    }

    #[test]
    fn config_serialization_roundtrip_preserves_security_mode() {
        let mut config = Config::default();
        config.global.node.security.mode = SecurityMode::Secured;
        config.global.node.security.iam.connect_timeout = Duration::from_millis(2500);

        // Serialize to TOML
        let toml_string = toml::to_string(&config).expect("Failed to serialize config");

        // Deserialize back
        let deserialized: Config =
            toml::from_str(&toml_string).expect("Failed to deserialize config");

        assert_that!(deserialized.global.node.security.mode, eq SecurityMode::Secured);
        assert_that!(
            deserialized.global.node.security.iam.connect_timeout,
            eq Duration::from_millis(2500)
        );
    }

    #[test]
    fn old_config_without_security_deserializes_with_default() {
        // Simulate an old config that doesn't have the security field
        let old_toml = r#"
[defaults]

[global.node]
cleanup-dead-nodes-on-creation = true
cleanup-dead-nodes-on-destruction = true

[global.service]
directory = "services"
creation-timeout-ms = 500
"#;

        let config: Config = toml::from_str(old_toml).expect("Failed to deserialize old config");

        // Should have default security mode
        assert_that!(config.global.node.security.mode, eq SecurityMode::Public);
    }
}

#[cfg(test)]
mod static_config_security_mode {
    use iceoryx2::config::Config;
    use iceoryx2::node::NodeBuilder;
    use iceoryx2::prelude::*;
    use iceoryx2::service::Service;
    use iceoryx2_bb_testing::assert_that;
    use iceoryx2_cal::security::mode::SecurityMode;
    use std::cell::RefCell;

    fn generate_unique_service_name() -> ServiceName {
        use iceoryx2_bb_posix::unique_system_id::UniqueSystemId;
        let id = UniqueSystemId::new().unwrap();
        ServiceName::new(&format!("test_static_config_{}", id.value())).unwrap()
    }

    #[test]
    fn listed_service_shows_correct_security_mode_public() {
        let service_name = generate_unique_service_name();

        let config = Config::default();
        let node = NodeBuilder::new()
            .config(&config)
            .create::<ipc::Service>()
            .expect("Failed to create node");

        let _service = node
            .service_builder(&service_name)
            .publish_subscribe::<u64>()
            .create()
            .expect("Failed to create service");

        // List services and find ours using callback
        let found_mode: RefCell<Option<SecurityMode>> = RefCell::new(None);
        let service_name_clone = service_name.clone();
        ipc::Service::list(&config, |details| {
            if details.static_details.name() == &service_name_clone {
                *found_mode.borrow_mut() = Some(details.static_details.security_mode());
            }
            CallbackProgression::Continue
        })
        .expect("Failed to list services");

        assert_that!(found_mode.borrow().unwrap(), eq SecurityMode::Public);
    }

    #[test]
    fn listed_service_shows_correct_security_mode_secured() {
        let service_name = generate_unique_service_name();

        let mut config = Config::default();
        config.global.node.security.mode = SecurityMode::Secured;

        let node = NodeBuilder::new()
            .config(&config)
            .create::<ipc::Service>()
            .expect("Failed to create node");

        let _service = node
            .service_builder(&service_name)
            .publish_subscribe::<u64>()
            .create()
            .expect("Failed to create service");

        // List services and find ours using callback
        let found_mode: RefCell<Option<SecurityMode>> = RefCell::new(None);
        let service_name_clone = service_name.clone();
        ipc::Service::list(&config, |details| {
            if details.static_details.name() == &service_name_clone {
                *found_mode.borrow_mut() = Some(details.static_details.security_mode());
            }
            CallbackProgression::Continue
        })
        .expect("Failed to list services");

        assert_that!(found_mode.borrow().unwrap(), eq SecurityMode::Secured);
    }
}
