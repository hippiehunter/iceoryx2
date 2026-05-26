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

//! Establishes the IAM handshake for secured services during service create/open. The service
//! creator hosts an [`IamServer`](crate::iam::server::IamServer) (with the service segment
//! factory) and also connects a self-client so its own ports authorize and broker segments
//! through IAM just like any opener; an opener connects an
//! [`IamClient`](crate::iam::client::IamClient) and performs the handshake.

use std::sync::Arc;
use std::time::Instant;

use iceoryx2_bb_container::semantic_string::SemanticString;
use iceoryx2_bb_system_types::file_name::FileName;
use iceoryx2_cal::control_channel::{
    ControlChannel, ControlChannelClientBuilder, ControlChannelListenerBuilder,
};
use iceoryx2_cal::named_concept::{NamedConceptBuilder, NamedConceptMgmt};
use iceoryx2_log::debug;

use crate::iam::client::IamClient;
use crate::iam::configured_policy::{PolicyDispatch, PolicyLoadError, PolicyLoader};
use crate::iam::policy::DefaultPolicy;
use crate::iam::segment_factory::{SegmentFactory, ServiceSegmentFactory};
use crate::iam::server::{IamServerBuilder, TypeErasedIamServer};
use crate::node::SharedNode;
use crate::service::config_scheme::control_channel_config;
use crate::service::secured_context::{
    iam_endpoint_name, SecuredServiceContext, TypeErasedSecuredContext,
};
use crate::service::static_config::StaticConfig;
use crate::service::{self, SecurityResource};

use super::{ServiceCreateError, ServiceOpenError};

type CcConfig<Service> =
    <<Service as service::Service>::ControlChannel as NamedConceptMgmt>::Configuration;

/// Derives the IAM control-channel endpoint name + configuration for a service. Both the creator's
/// listener and every opener's client resolve to the same endpoint from the same service hash.
fn endpoint_of<Service: service::Service>(
    shared_node: &SharedNode<Service>,
    static_config: &StaticConfig,
) -> (FileName, CcConfig<Service>) {
    let config = shared_node.config();
    let name = iam_endpoint_name(
        static_config.service_hash(),
        &config.global.node.security.iam.endpoint_base,
    );
    (name, control_channel_config::<Service>(config))
}

/// Creator side: start the IAM server (with the service segment factory) then connect a
/// self-client. Returns [`SecurityResource::SecuredServer`].
pub(crate) fn create_secured_resource<Service: service::Service>(
    shared_node: &SharedNode<Service>,
    static_config: &StaticConfig,
) -> Result<SecurityResource, ServiceCreateError> {
    let origin = "create_secured_resource";
    let config = shared_node.config();

    // Public services carry no IAM machinery at all — no server, no handshake.
    if !config.global.node.security.mode.is_secured() {
        return Ok(SecurityResource::None);
    }

    let (endpoint, cc_config) = endpoint_of(shared_node, static_config);

    // Load the per-service authorization policy; fall back to a same-uid DefaultPolicy when no
    // policy file exists for this service.
    let policy_dir_bytes = config.global.node.security.iam.policy_dir.as_bytes();
    let policy_dir_str = core::str::from_utf8(policy_dir_bytes).unwrap_or("");
    let policy = match PolicyLoader::load_for_service(
        std::path::Path::new(policy_dir_str),
        static_config.name(),
    ) {
        Ok(p) => PolicyDispatch::Configured(p),
        Err(PolicyLoadError::NotFound) => PolicyDispatch::Default(DefaultPolicy::new()),
        Err(e) => {
            debug!(from origin, "Unable to load the IAM policy for the secured service ({:?}).", e);
            return Err(ServiceCreateError::InternalFailure);
        }
    };

    let listener = <Service::ControlChannel as ControlChannel>::ListenerBuilder::new(&endpoint)
        .config(&cc_config)
        .create()
        .map_err(|e| {
            debug!(from origin, "Unable to create the IAM control-channel listener ({:?}).", e);
            ServiceCreateError::InternalFailure
        })?;

    let factory: Arc<dyn SegmentFactory> =
        Arc::new(ServiceSegmentFactory::<Service>::new(config.clone()));
    let server = IamServerBuilder::new(listener, policy)
        .service_name(static_config.name().as_str())
        .segment_factory(factory)
        .build();
    let server = TypeErasedIamServer::new(server);

    // The server now has a running poll thread; connect our own client to it so creator-side
    // ports go through IAM like any opener.
    let client = connect_client(shared_node, static_config, &endpoint, &cc_config).map_err(|_| {
        debug!(from origin, "Unable to connect the creator's self-client to the IAM server.");
        ServiceCreateError::InternalFailure
    })?;

    Ok(SecurityResource::SecuredServer { server, client })
}

/// Opener side: connect an IAM client to the creator's server, handshake, and wrap it.
/// Returns [`SecurityResource::SecuredClient`].
pub(crate) fn open_secured_resource<Service: service::Service>(
    shared_node: &SharedNode<Service>,
    static_config: &StaticConfig,
) -> Result<SecurityResource, ServiceOpenError> {
    let origin = "open_secured_resource";

    // Public services carry no IAM machinery at all — no client connection, no handshake.
    if !shared_node.config().global.node.security.mode.is_secured() {
        return Ok(SecurityResource::None);
    }

    let (endpoint, cc_config) = endpoint_of(shared_node, static_config);
    let client = connect_client(shared_node, static_config, &endpoint, &cc_config).map_err(|_| {
        debug!(from origin, "Unable to connect to the secured service's IAM server.");
        ServiceOpenError::InternalFailure
    })?;
    Ok(SecurityResource::SecuredClient(client))
}

/// Connects a control-channel client to `endpoint`, performs the IAM handshake and wraps it in a
/// type-erased secured context. The connect is retried within `iam.connect_timeout` to tolerate
/// the server's poll thread still coming up.
fn connect_client<Service: service::Service>(
    shared_node: &SharedNode<Service>,
    static_config: &StaticConfig,
    endpoint: &FileName,
    cc_config: &CcConfig<Service>,
) -> Result<TypeErasedSecuredContext, ()> {
    let origin = "connect_client";
    let timeout = shared_node.config().global.node.security.iam.connect_timeout;
    let start = Instant::now();

    let connection = loop {
        match <Service::ControlChannel as ControlChannel>::ClientBuilder::new(endpoint)
            .config(cc_config)
            .try_connect()
        {
            Ok(connection) => break connection,
            Err(e) => {
                if start.elapsed() >= timeout {
                    debug!(from origin, "IAM connect to {:?} timed out ({:?}).", endpoint, e);
                    return Err(());
                }
                std::thread::sleep(core::time::Duration::from_millis(2));
            }
        }
    };

    let mut client = IamClient::new(connection);
    if let Err(e) = client.handshake(shared_node.id().unique_system_id()) {
        debug!(from origin, "IAM handshake failed ({:?}).", e);
        return Err(());
    }

    let ctx = SecuredServiceContext::new(client, *static_config.service_hash());
    Ok(TypeErasedSecuredContext::new(ctx))
}
