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

extern crate alloc;

pub mod blackboard;
pub mod publish_subscribe;

use alloc::string::ToString;
use core::fmt::Debug;
use core::ptr::NonNull;
use iceoryx2_bb_container::semantic_string::SemanticString;
use iceoryx2_bb_elementary::enum_gen;
use iceoryx2_bb_elementary_traits::non_null::NonNullCompat;
use iceoryx2_bb_elementary_traits::testing::abandonable::Abandonable;
use iceoryx2_bb_system_types::path::Path;
use iceoryx2_log::fatal_panic;

use crate::{
    config,
    service::{
        self, SecurityResource,
        builder::{ServiceCreateError, ServiceOpenError},
        resource::{blackboard::BlackboardResources, publish_subscribe::PublishSubscribeResources},
        secured_context::TypeErasedSecuredContext,
        static_config::{StaticConfig, messaging_pattern::MessagingPattern},
    },
};

pub unsafe fn remove_stale_service_resources<ServiceType: service::Service>(
    config: &config::Config,
    static_config: &StaticConfig,
) -> Result<(), RemoveStaleResourcesError> {
    match static_config.messaging_pattern() {
        MessagingPattern::Blackboard(_) => unsafe {
            BlackboardResources::<ServiceType>::remove_stale_resources(config, static_config)
        },
        MessagingPattern::RequestResponse(_) => Ok(()),
        MessagingPattern::Event(_) => Ok(()),
        MessagingPattern::PublishSubscribe(_) => unsafe {
            PublishSubscribeResources::<ServiceType>::remove_stale_resources(config, static_config)
        },
    }
}

enum_gen! {
    RemoveStaleResourcesError
  entry:
    InsufficientPermissions,
    InterruptedBySignal,
    InternalFailure
}

/// Represents resources a service could use and have to be cleaned up when no owners
/// are left
pub trait ServiceResource: Abandonable + Debug + Send {
    type Config;

    fn service_resource_directory(config: &config::Config, static_config: &StaticConfig) -> Path {
        let origin = "ServiceResource::service_resource_directory()";
        let mut root = config.global.service_dir();
        let id = fatal_panic!(from origin,
               when Path::new(static_config.unique_service_id().value().to_string().as_bytes()),
               "This should never happen! The service id is always a valid path name.");
        fatal_panic!(from origin,
                when root.add_path_entry(&id),
                "This should never happen! The full service directory is too long. A shorter iceoryx2 root path might solve the issue.");
        root
    }

    fn create(
        static_config: &StaticConfig,
        resource_config: &Self::Config,
    ) -> Result<Self, ServiceCreateError>;

    fn open(
        static_config: &StaticConfig,
        resource_config: &Self::Config,
    ) -> Result<Self, ServiceOpenError>;

    unsafe fn remove_stale_resources(
        config: &config::Config,
        static_config: &StaticConfig,
    ) -> Result<(), RemoveStaleResourcesError>;

    /// Acquires the ownership of the additional resources. When the objects go out of scope the
    /// underlying resources will be removed.
    fn acquire_ownership(&self);

    /// Returns the secured client context when this resource carries an active IAM client
    /// connection. Defaults to `None` for unsecured resources; overridden by [`Secured`] to
    /// expose the wrapped [`SecurityResource`]'s client context.
    ///
    /// `TypeErasedSecuredContext` is deliberately `pub(crate)`: this accessor is an internal
    /// security hook consumed by the ports, not part of the public `ServiceResource` contract.
    #[allow(private_interfaces)]
    fn as_client(&self) -> Option<&TypeErasedSecuredContext> {
        None
    }
}

#[derive(Debug)]
pub struct NoResource;
impl ServiceResource for NoResource {
    type Config = ();

    fn create(
        _static_config: &StaticConfig,
        _resource_config: &Self::Config,
    ) -> Result<Self, ServiceCreateError> {
        Ok(Self {})
    }

    fn open(
        _static_config: &StaticConfig,
        _resource_config: &Self::Config,
    ) -> Result<Self, ServiceOpenError> {
        Ok(Self {})
    }

    fn acquire_ownership(&self) {}

    unsafe fn remove_stale_resources(
        _config: &config::Config,
        _static_config: &StaticConfig,
    ) -> Result<(), RemoveStaleResourcesError> {
        Ok(())
    }
}

impl Abandonable for NoResource {
    unsafe fn abandon_in_place(_this: NonNull<Self>) {}
}

/// A [`ServiceResource`] wrapper that composes an inner per-service resource `R` with an
/// optional [`SecurityResource`] (IAM client/server context).
///
/// This is the single `R` slot used by every secured-capable service: the inner resource keeps
/// upstream's create / open / `remove_stale_resources` / ownership / abandon semantics, while the
/// security context rides alongside and is surfaced through [`ServiceResource::as_client`]. Both
/// lifecycles are driven together by this one trait implementation, so a secured service's IAM
/// context is acquired, abandoned, and cleaned up in lockstep with its regular resources.
///
/// The wrapped [`SecurityResource`] is currently always [`SecurityResource::None`] on the
/// create/open path; the IAM wiring that populates `SecuredClient` / `SecuredServer` is
/// established separately by the service builders while the connection/server is set up.
#[derive(Debug)]
pub(crate) struct Secured<R: ServiceResource> {
    pub(crate) inner: R,
    pub(crate) security: SecurityResource,
}

impl<R: ServiceResource> Secured<R> {
    /// Wraps `inner` without an active security context (public service access).
    pub(crate) fn public(inner: R) -> Self {
        Self {
            inner,
            security: SecurityResource::None,
        }
    }

    /// Wraps `inner` together with an established security context (secured service).
    pub(crate) fn new(inner: R, security: SecurityResource) -> Self {
        Self { inner, security }
    }
}

impl<R: ServiceResource> ServiceResource for Secured<R> {
    type Config = R::Config;

    fn create(
        static_config: &StaticConfig,
        resource_config: &Self::Config,
    ) -> Result<Self, ServiceCreateError> {
        Ok(Self::public(R::create(static_config, resource_config)?))
    }

    fn open(
        static_config: &StaticConfig,
        resource_config: &Self::Config,
    ) -> Result<Self, ServiceOpenError> {
        Ok(Self::public(R::open(static_config, resource_config)?))
    }

    fn acquire_ownership(&self) {
        self.inner.acquire_ownership();
        self.security.acquire_ownership();
    }

    unsafe fn remove_stale_resources(
        config: &config::Config,
        static_config: &StaticConfig,
    ) -> Result<(), RemoveStaleResourcesError> {
        unsafe { R::remove_stale_resources(config, static_config) }
    }

    fn as_client(&self) -> Option<&TypeErasedSecuredContext> {
        self.security.as_client()
    }
}

impl<R: ServiceResource> Abandonable for Secured<R> {
    unsafe fn abandon_in_place(mut this: NonNull<Self>) {
        let this = unsafe { this.as_mut() };
        unsafe { R::abandon_in_place(NonNull::iox2_from_mut(&mut this.inner)) };
        unsafe { SecurityResource::abandon_in_place(NonNull::iox2_from_mut(&mut this.security)) };
    }
}
