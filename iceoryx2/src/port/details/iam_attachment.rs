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

//! RAII detach of a port's IAM attachment.
//!
//! In secured mode every port attaches to the service's IAM server (which counts the attached
//! ports against the principal's limits) and producers additionally register handles under
//! their port id. [`IamPortAttachment`] detaches all of them when the port goes away - also when
//! the port creation fails after a successful attach - so that the IAM server's per-session
//! accounting and handle tables do not grow with every port a long-living process creates.

use alloc::vec::Vec;
use core::fmt::Debug;
use core::ptr::NonNull;

use iceoryx2_bb_elementary_traits::testing::abandonable::Abandonable;

use crate::service::{self, SharedServiceState, resource::ServiceResource};

pub(crate) struct IamPortAttachment<Service: service::Service, Resource: ServiceResource> {
    service_state: SharedServiceState<Service, Resource>,
    port_ids: Vec<u128>,
}

impl<Service: service::Service, Resource: ServiceResource> Debug
    for IamPortAttachment<Service, Resource>
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("IamPortAttachment")
            .field("port_ids", &self.port_ids)
            .finish()
    }
}

impl<Service: service::Service, Resource: ServiceResource> IamPortAttachment<Service, Resource> {
    pub(crate) fn new(service_state: SharedServiceState<Service, Resource>) -> Self {
        Self {
            service_state,
            port_ids: Vec::new(),
        }
    }

    /// Adds a port id (the IAM-assigned attach id or the producer's own port id under which it
    /// registers handles) that is detached when this object is dropped.
    pub(crate) fn add(&mut self, port_id: u128) {
        self.port_ids.push(port_id);
    }
}

impl<Service: service::Service, Resource: ServiceResource> Drop
    for IamPortAttachment<Service, Resource>
{
    fn drop(&mut self) {
        if self.port_ids.is_empty() {
            return;
        }
        if let Some(ctx) = self.service_state.additional_resource().as_client() {
            for port_id in self.port_ids.drain(..) {
                // best effort: the IAM server also releases everything when the session ends
                let _ = ctx.detach(port_id);
            }
        }
    }
}

impl<Service: service::Service, Resource: ServiceResource> Abandonable
    for IamPortAttachment<Service, Resource>
{
    /// Simulates a crash: nothing is detached (the IAM server has to recover on its own) and the
    /// reference to the service state is released so that the port's own reference can abandon
    /// the service. Must be called before the port abandons its service state.
    unsafe fn abandon_in_place(mut this: NonNull<Self>) {
        let this = unsafe { this.as_mut() };
        this.port_ids.clear();
        unsafe { core::ptr::drop_in_place(&mut this.port_ids) };
        unsafe { SharedServiceState::abandon_in_place(NonNull::from_mut(&mut this.service_state)) };
    }
}
