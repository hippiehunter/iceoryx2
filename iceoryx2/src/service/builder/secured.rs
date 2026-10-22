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
    ControlChannel, ControlChannelClientBuilder, ControlChannelConnectError,
    ControlChannelListenerBuilder,
};
use iceoryx2_cal::monitoring::State;
use iceoryx2_cal::named_concept::NamedConceptConfiguration;
use iceoryx2_cal::named_concept::{NamedConceptBuilder, NamedConceptMgmt};
use iceoryx2_cal::security::credentials::ProcessCredentials;
use iceoryx2_log::{debug, warn};

use crate::iam::audit::{AuditLogger, FileAuditLogger};
use crate::iam::server::{PeerDepartureHandler, PeerDepartureOutcome};
use crate::identifiers::UniqueNodeId;
use crate::node::Node;
use crate::service::remove_departed_node_from_service;
use crate::service::service_hash::ServiceHash;
use crate::unique_id_generator::UniqueId;

use crate::iam::client::IamClient;
use crate::iam::configured_policy::{PolicyDispatch, PolicyLoadError, PolicyLoader};
use crate::iam::policy::DefaultPolicy;
use crate::iam::segment_factory::{SegmentFactory, ServiceSegmentFactory};
use crate::iam::server::{IamServerBuilder, TypeErasedIamServer};
use crate::node::SharedNode;
use crate::service::config_scheme::control_channel_config;
use crate::service::secured_context::{
    SecuredServiceContext, TypeErasedSecuredContext, iam_endpoint_name,
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

    let create_listener = || {
        <Service::ControlChannel as ControlChannel>::ListenerBuilder::new(&endpoint)
            .config(&cc_config)
            .create()
    };
    let listener = match create_listener() {
        Ok(listener) => listener,
        // This process just created the static config exclusively, so an endpoint of that name
        // is a leftover of an earlier incarnation whose creator died (the socket file of a
        // crashed process stays). Replace it unless somebody still answers on it.
        Err(iceoryx2_cal::control_channel::ControlChannelListenerCreateError::AlreadyExists)
            if endpoint_is_dead::<Service>(&endpoint, &cc_config) =>
        {
            warn!(from origin, "Removing the stale IAM endpoint {:?} of a previous creator of {:?}.",
                endpoint, static_config.name());
            let _ = unsafe {
                <Service::ControlChannel as NamedConceptMgmt>::remove_cfg(&endpoint, &cc_config)
            };
            create_listener().map_err(|e| {
                debug!(from origin, "Unable to create the IAM control-channel listener ({:?}).", e);
                ServiceCreateError::InternalFailure
            })?
        }
        Err(e) => {
            debug!(from origin, "Unable to create the IAM control-channel listener ({:?}).", e);
            return Err(ServiceCreateError::InternalFailure);
        }
    };

    // Multi-user: hand the control socket to the configured endpoint group. The socket is not
    // the security boundary (the policy is), so a failure only limits who can connect.
    #[cfg(unix)]
    if let Some(gid) = config.global.node.security.endpoint_access().group() {
        let socket_path = cc_config.path_for(&endpoint);
        let socket_path = core::str::from_utf8(socket_path.as_bytes()).unwrap_or("");
        if let Err(e) = std::os::unix::fs::chown(socket_path, None, Some(gid)) {
            warn!(from origin,
                "Unable to hand the IAM control socket \"{}\" to the group {} ({}).", socket_path, gid, e);
        }
    }

    let factory: Arc<dyn SegmentFactory> =
        Arc::new(ServiceSegmentFactory::<Service>::new(config.clone()));
    let mut builder = IamServerBuilder::new(listener, policy)
        .service_name(static_config.name().as_str())
        .segment_factory(factory)
        .peer_departure_handler(departure_handler::<Service>(
            config.clone(),
            *static_config.service_hash(),
        ));
    if let Some(logger) = audit_logger(config) {
        builder = builder.audit_logger(logger);
    }
    let server = builder.build();
    let server = TypeErasedIamServer::new(server);

    // The server now has a running poll thread; connect our own client to it so creator-side
    // ports go through IAM like any opener.
    let client =
        connect_client(shared_node, static_config, &endpoint, &cc_config).map_err(|_| {
            debug!(from origin, "Unable to connect the creator's self-client to the IAM server.");
            ServiceCreateError::InternalFailure
        })?;

    Ok(SecurityResource::SecuredServer { server, client })
}

/// Opens the audit log configured in `iam.audit-log-path`. Relative paths are resolved against
/// the iceoryx2 root path; an empty path disables auditing. Failing to open the log (e.g. its
/// directory does not exist) disables auditing for this service with a warning.
fn audit_logger(config: &crate::config::Config) -> Option<Box<dyn AuditLogger>> {
    let origin = "audit_logger";
    let configured =
        core::str::from_utf8(config.global.node.security.iam.audit_log_path.as_bytes())
            .unwrap_or("");
    if configured.is_empty() {
        return None;
    }

    let path = std::path::Path::new(configured);
    let path = if path.is_absolute() {
        path.to_path_buf()
    } else {
        let root = core::str::from_utf8(config.global.root_path().as_bytes()).unwrap_or("");
        std::path::Path::new(root).join(path)
    };

    if !path.parent().is_some_and(|p| p.is_dir()) {
        debug!(from origin, "IAM audit logging disabled since the directory of {:?} does not exist.", path);
        return None;
    }

    match FileAuditLogger::new(&path) {
        Ok(logger) => Some(Box::new(logger)),
        Err(e) => {
            warn!(from origin, "IAM audit logging disabled since {:?} could not be opened ({}).", path, e);
            None
        }
    }
}

/// Creates the handler the IAM server invokes when the last session of a peer node closed.
///
/// A peer that is killed never deregisters its ports. The creator (which owns the service's
/// dynamic config) removes them once the peer's node is verifiably dead: its monitor reports
/// `Dead` and the node details record the very process the kernel reported for the session
/// (`SO_PEERCRED` pid), so a peer can neither evict nor resurrect another node. A node that is
/// still alive closed its connection gracefully and deregistered its ports itself.
fn departure_handler<Service: service::Service>(
    config: crate::config::Config,
    service_hash: ServiceHash,
) -> PeerDepartureHandler {
    Box::new(move |node_value: u128, credentials: &ProcessCredentials| {
        let origin = "IamServer::peer_departure";
        let node_id = UniqueNodeId(unsafe { UniqueId::from_raw_id(node_value) });

        match Node::<Service>::get_node_state(&config, &node_id) {
            Ok(State::Alive) => PeerDepartureOutcome::Retry,
            Ok(State::DoesNotExist) => PeerDepartureOutcome::Completed,
            Ok(State::Dead) => {
                match Node::<Service>::get_node_details(&config, &node_id) {
                    Ok(Some(details))
                        if details.process_id().value() as u32 == credentials.pid() => {}
                    Ok(Some(details)) => {
                        warn!(from origin,
                            "Ignoring the departure of node {node_id} since it belongs to process {} and not to the peer process {}.",
                            details.process_id().value(), credentials.pid());
                        return PeerDepartureOutcome::Completed;
                    }
                    Ok(None) => return PeerDepartureOutcome::Completed,
                    Err(e) => {
                        debug!(from origin,
                            "Unable to read the details of the departed node {node_id} ({e:?}).");
                        return PeerDepartureOutcome::Completed;
                    }
                }

                let removed =
                    remove_departed_node_from_service::<Service>(&node_id, &service_hash, &config);
                debug!(from origin,
                    "Removed {removed} port(s) of the dead node {node_id} (uid {}, pid {}) from the service.",
                    credentials.uid(), credentials.pid());
                PeerDepartureOutcome::Completed
            }
            Err(e) => {
                debug!(from origin, "Unable to acquire the state of the departed node {node_id} ({e:?}).");
                PeerDepartureOutcome::Retry
            }
        }
    })
}

/// Opener side: connect an IAM client to the creator's server, handshake, and wrap it.
/// Returns [`SecurityResource::SecuredClient`].
/// Whether nobody listens on the IAM endpoint (connection refused or no socket file).
fn endpoint_is_dead<Service: service::Service>(
    endpoint: &FileName,
    cc_config: &CcConfig<Service>,
) -> bool {
    matches!(
        <Service::ControlChannel as ControlChannel>::ClientBuilder::new(endpoint)
            .config(cc_config)
            .try_connect(),
        Err(ControlChannelConnectError::ConnectionRefused)
            | Err(ControlChannelConnectError::DoesNotExist)
    )
}

/// Reclaims a secured service whose IAM server is gone (orphaned): its creator exited or
/// crashed while other processes still had the service open, so the service can neither be
/// opened (no IAM server to connect to) nor created (its static config still exists) until every
/// participant has left. Called by `open_or_create` of a process that may take the creator's
/// place, i.e. one whose effective uid owns the static config.
///
/// The service is reclaimed when
/// * it is secured and its static config exists, belongs to this process's effective uid and is
///   older than twice the creation timeout (a service being created right now is never touched),
/// * and its IAM endpoint refuses connections or does not exist.
///
/// Then the endpoint, the dynamic config's name and the static config are removed, so that the
/// caller can create the service anew. Remaining participants keep their mappings of the old
/// (now nameless) resources; [`is_orphaned`](crate::service::port_factory::publish_subscribe::PortFactory::is_orphaned)
/// tells them to drop the service and open it again. Returns whether the service was reclaimed.
/// Returns true when the static config of the service belongs to our user and is older than
/// twice the creation timeout.
fn created_by_us_long_ago<Service: service::Service>(
    config: &crate::config::Config,
    static_config: &StaticConfig,
) -> bool {
    let storage_config =
        crate::service::config_scheme::static_config_storage_config::<Service>(config);
    let name = crate::service::naming_scheme::static_config_name(static_config.service_hash());
    let path = storage_config.path_for(&name);
    let path = core::str::from_utf8(path.as_bytes()).unwrap_or("");
    let Ok(metadata) = std::fs::metadata(path) else {
        return false;
    };
    if !owned_by_us(path, &metadata) {
        return false;
    }
    let min_age = config.global.creation_timeout * 2;
    metadata
        .modified()
        .ok()
        .and_then(|m| m.elapsed().ok())
        .is_some_and(|age| age >= min_age)
}

#[cfg(unix)]
fn owned_by_us(_path: &str, metadata: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    // SAFETY: geteuid has no preconditions.
    metadata.uid() == unsafe { iceoryx2_pal_posix::posix::geteuid() }
}

/// The file's owner is our user SID. Files created by an elevated administrator may be owned
/// by the Administrators group instead; those are not ours.
#[cfg(windows)]
fn owned_by_us(path: &str, _metadata: &std::fs::Metadata) -> bool {
    use iceoryx2_pal_posix::windows::security_descriptor::Sid;
    let me = ProcessCredentials::from_self();
    match (me.user_sid(), Sid::file_owner(path)) {
        (Some(me), Ok(owner)) => owner.as_bytes() == me,
        _ => false,
    }
}

#[cfg(not(any(unix, windows)))]
fn owned_by_us(_path: &str, _metadata: &std::fs::Metadata) -> bool {
    false
}

pub(crate) fn reclaim_orphaned_service<Service: service::Service>(
    shared_node: &SharedNode<Service>,
    static_config: &StaticConfig,
) -> bool {
    let origin = "reclaim_orphaned_service";
    let config = shared_node.config();
    if !config.global.node.security.mode.is_secured() {
        return false;
    }

    if !created_by_us_long_ago::<Service>(config, static_config) {
        return false;
    }

    let (endpoint, cc_config) = endpoint_of(shared_node, static_config);
    // Somebody hosting the IAM server, or an endpoint in an unknown state: not orphaned.
    if !endpoint_is_dead::<Service>(&endpoint, &cc_config) {
        return false;
    }

    warn!(from origin,
        "Reclaiming the secured service {:?}: its creator is gone (IAM endpoint unreachable) but processes still use it. They have to open it again.",
        static_config.name());
    if let Err(e) =
        unsafe { <Service::ControlChannel as NamedConceptMgmt>::remove_cfg(&endpoint, &cc_config) }
    {
        debug!(from origin, "Unable to remove the stale IAM endpoint ({:?}).", e);
    }
    match unsafe {
        <Service as crate::service::internal::ServiceInternal<Service>>::__internal_remove_service(
            static_config,
            config,
        )
    } {
        Ok(()) => true,
        Err(e) => {
            warn!(from origin, "Unable to reclaim the orphaned service {:?} ({:?}).",
                static_config.name(), e);
            false
        }
    }
}

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
    let client =
        connect_client(shared_node, static_config, &endpoint, &cc_config).map_err(|_| {
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
    let timeout = shared_node
        .config()
        .global
        .node
        .security
        .iam
        .connect_timeout;
    let start = Instant::now();

    let connection = loop {
        match <Service::ControlChannel as ControlChannel>::ClientBuilder::new(endpoint)
            .config(cc_config)
            .try_connect()
        {
            Ok(connection) => break connection,
            // The listener is created before the dynamic config, so an opener that got this far
            // finds it unless the creator is gone (orphaned service): do not wait for it.
            Err(e @ ControlChannelConnectError::ConnectionRefused)
            | Err(e @ ControlChannelConnectError::DoesNotExist) => {
                debug!(from origin, "The IAM server at {:?} is gone ({:?}).", endpoint, e);
                return Err(());
            }
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
