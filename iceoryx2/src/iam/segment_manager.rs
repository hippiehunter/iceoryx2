// Copyright (c) 2023 Contributors to the Eclipse Foundation
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

//! Segment lifecycle management for IAM server.
//!
//! This module provides types for managing shared memory segments within the IAM server.
//! The [`SegmentManager`] tracks all segments, their authorization state, and handles
//! the retirement protocol for safe segment removal.
//!
//! # Segment Lifecycle
//!
//! 1. **Creation**: Segments are created with a unique ID and platform handle
//! 2. **Authorization**: Sessions are granted access to segments
//! 3. **Active Use**: Segments are used for data transfer
//! 4. **Retirement**: When a segment needs to be removed:
//!    - All authorized sessions are notified
//!    - Sessions must acknowledge before the segment can be removed
//!    - Once all acks are received, the segment is destroyed
//!
//! # Example
//!
//! ```ignore
//! use iceoryx2::iam::segment_manager::SegmentManager;
//! use iceoryx2_cal::security::AccessRights;
//!
//! let mut manager = SegmentManager::new();
//!
//! // Create a segment (in real code, this would create actual shared memory)
//! let segment_id = manager.create_segment(4096, AccessRights::read_write())?;
//!
//! // Authorize a session
//! let handle = manager.authorize_session(segment_id, session_id)?;
//!
//! // Begin retirement (returns sessions needing to ack)
//! let sessions = manager.begin_retirement(segment_id);
//!
//! // Process acks
//! manager.ack_retirement(segment_id, session_id);
//! ```

use std::collections::{BTreeMap, HashSet};

use iceoryx2_cal::security::handle::PlatformHandle;
use iceoryx2_cal::security::AccessRights;
use iceoryx2_cal::shm_allocator::SegmentId;

/// Type alias for segment ID underlying value used as map key.
type SegmentIdKey = u8;

use super::error::IamServerError;
use super::protocol::{SegmentInfo, SessionId};

// ============================================================================
// ManagedSegment
// ============================================================================

/// State of a managed shared memory segment.
///
/// Tracks the segment handle, metadata, authorization state, and retirement status.
#[derive(Debug)]
pub struct ManagedSegment {
    /// The unique segment identifier.
    id: SegmentId,
    /// The platform handle for the segment.
    ///
    /// This is the authoritative handle that is cloned when granting access.
    handle: PlatformHandle,
    /// The size of the segment in bytes.
    size: usize,
    /// The access rights granted for this segment.
    access: AccessRights,
    /// Sessions that have been authorized to access this segment.
    authorized_sessions: HashSet<SessionId>,
    /// Whether the segment is in the process of being retired.
    retiring: bool,
    /// Sessions that still need to acknowledge retirement.
    ///
    /// Only populated when `retiring` is true.
    pending_acks: HashSet<SessionId>,
}

impl ManagedSegment {
    /// Creates a new managed segment with the given parameters.
    ///
    /// The segment starts in the active (non-retiring) state with no authorized sessions.
    fn new(id: SegmentId, handle: PlatformHandle, size: usize, access: AccessRights) -> Self {
        Self {
            id,
            handle,
            size,
            access,
            authorized_sessions: HashSet::new(),
            retiring: false,
            pending_acks: HashSet::new(),
        }
    }

    /// Returns the segment identifier.
    pub fn id(&self) -> SegmentId {
        self.id
    }

    /// Returns a reference to the platform handle.
    pub fn handle(&self) -> &PlatformHandle {
        &self.handle
    }

    /// Returns the size of the segment in bytes.
    pub fn size(&self) -> usize {
        self.size
    }

    /// Returns the access rights for this segment.
    pub fn access(&self) -> AccessRights {
        self.access
    }

    /// Returns `true` if the segment is being retired.
    pub fn is_retiring(&self) -> bool {
        self.retiring
    }

    /// Returns the number of authorized sessions.
    pub fn authorized_session_count(&self) -> usize {
        self.authorized_sessions.len()
    }

    /// Returns the number of pending retirement acknowledgments.
    pub fn pending_ack_count(&self) -> usize {
        self.pending_acks.len()
    }

    /// Converts this segment to a [`SegmentInfo`] for protocol messages.
    pub fn to_segment_info(&self) -> SegmentInfo {
        SegmentInfo::new(self.id, self.size, self.access)
    }
}

// ============================================================================
// SegmentManager
// ============================================================================

/// Manages the lifecycle of shared memory segments.
///
/// The segment manager is responsible for:
/// - Creating new segments with unique IDs
/// - Tracking which sessions have access to which segments
/// - Managing the retirement protocol for safe segment removal
/// - Providing cloned handles for session authorization
///
/// # Thread Safety
///
/// `SegmentManager` is not `Sync` - it is designed to be owned by a single
/// server instance. The server is responsible for synchronizing access if needed.
#[derive(Debug)]
pub struct SegmentManager {
    /// All managed segments indexed by their ID value.
    /// We use BTreeMap with the underlying u8 value since SegmentId doesn't implement Hash.
    segments: BTreeMap<SegmentIdKey, ManagedSegment>,
    /// Mapping from producer port ID to the segment IDs it has registered.
    port_segments: BTreeMap<u128, Vec<SegmentId>>,
    /// Connection channels brokered by handle, keyed by (sender_port_id, receiver_port_id).
    ///
    /// Channels are granted **read+write** access (the consumer's receiver end writes the
    /// completion ring). They are NOT part of the SegmentId space or the `port_segments`
    /// index space — a distinct producer connection channel exists per (sender, receiver).
    channels: BTreeMap<(u128, u128), ManagedSegment>,
    /// Resizable-memory management segments brokered by handle, keyed by the producer
    /// `port_id`.
    ///
    /// A producer's resizable shared memory owns exactly one management segment, so this is
    /// keyed by a single `u128` (like data segments, unlike the pair-keyed `channels`). It is
    /// granted **read-only** access: the consumer's `DynamicView` maps it purely as a
    /// keep-alive token and never reads or writes it. Management segments are NOT part of the
    /// SegmentId space or the `port_segments` index space.
    mgmt_segments: BTreeMap<u128, ManagedSegment>,
    /// Counter for generating unique segment IDs.
    ///
    /// Uses u8 since SegmentId is based on u8.
    next_id: u8,
}

impl Default for SegmentManager {
    fn default() -> Self {
        Self::new()
    }
}

impl SegmentManager {
    /// Creates a new empty segment manager.
    pub const fn new() -> Self {
        Self {
            segments: BTreeMap::new(),
            port_segments: BTreeMap::new(),
            channels: BTreeMap::new(),
            mgmt_segments: BTreeMap::new(),
            next_id: 0,
        }
    }

    /// Returns the number of managed segments.
    pub fn segment_count(&self) -> usize {
        self.segments.len()
    }

    /// Checks if a segment exists.
    pub fn has_segment(&self, segment_id: SegmentId) -> bool {
        self.segments.contains_key(&segment_id.value())
    }

    /// Gets a reference to a managed segment.
    pub fn get(&self, segment_id: SegmentId) -> Option<&ManagedSegment> {
        self.segments.get(&segment_id.value())
    }

    /// Returns an iterator over all segment IDs.
    pub fn segment_ids(&self) -> impl Iterator<Item = SegmentId> + '_ {
        self.segments.values().map(|s| s.id)
    }

    // ========================================================================
    // Segment Creation
    // ========================================================================

    /// Registers a segment with an existing handle.
    ///
    /// This is used when the caller has already created the shared memory and
    /// has a platform handle for it. The segment manager takes ownership of the
    /// handle and will manage the segment's lifecycle.
    ///
    /// # Arguments
    ///
    /// * `handle` - The platform handle for the segment
    /// * `size` - The size of the segment in bytes
    /// * `access` - The access rights for the segment
    ///
    /// # Returns
    ///
    /// The unique segment ID assigned to this segment.
    ///
    /// # Errors
    ///
    /// Returns [`IamServerError::ResourceLimitExceeded`] if the segment ID counter
    /// would overflow (after 256 segments created without any being removed).
    pub fn register_segment(
        &mut self,
        handle: PlatformHandle,
        size: usize,
        access: AccessRights,
    ) -> Result<SegmentId, IamServerError> {
        // Validate segment size to prevent resource accounting corruption
        if size == 0 {
            return Err(IamServerError::InvalidSegmentSize);
        }

        // Find an available segment ID
        let segment_id = self.allocate_segment_id()?;

        let segment = ManagedSegment::new(segment_id, handle, size, access);
        self.segments.insert(segment_id.value(), segment);

        Ok(segment_id)
    }

    /// Registers a segment with a pre-allocated ID and existing handle.
    ///
    /// This is used when the segment ID has already been allocated (e.g., by
    /// the IAM server during AddSegment processing) and the shared memory
    /// has been created externally.
    ///
    /// # Arguments
    ///
    /// * `segment_id` - The pre-allocated segment ID
    /// * `handle` - The platform handle for the segment
    /// * `size` - The size of the segment in bytes
    /// * `access` - The access rights for the segment
    ///
    /// # Errors
    ///
    /// Returns [`IamServerError::InvalidSegmentSize`] if size is zero.
    pub fn register_segment_with_id(
        &mut self,
        segment_id: SegmentId,
        handle: PlatformHandle,
        size: usize,
        access: AccessRights,
    ) -> Result<(), IamServerError> {
        // Validate segment size to prevent resource accounting corruption
        if size == 0 {
            return Err(IamServerError::InvalidSegmentSize);
        }

        let segment = ManagedSegment::new(segment_id, handle, size, access);
        self.segments.insert(segment_id.value(), segment);

        Ok(())
    }

    /// Associates a segment with a producer port.
    ///
    /// This adds the segment to the port's segment list, allowing consumers
    /// to retrieve handles via [`get_segment_handle_for_consumer`].
    ///
    /// # Arguments
    ///
    /// * `segment_id` - The segment to associate
    /// * `port_id` - The producer port to associate with
    ///
    /// # Errors
    ///
    /// Returns [`IamServerError::SegmentNotFound`] if the segment doesn't exist.
    pub fn associate_segment_with_port(
        &mut self,
        segment_id: SegmentId,
        port_id: u128,
    ) -> Result<(), IamServerError> {
        // Verify the segment exists
        if !self.segments.contains_key(&segment_id.value()) {
            return Err(IamServerError::SegmentNotFound);
        }

        self.port_segments
            .entry(port_id)
            .or_default()
            .push(segment_id);

        Ok(())
    }

    /// Associates a segment with a producer port at an **explicit** index within the port's
    /// dynamic segment vector, rather than appending it.
    ///
    /// The producer's resizable memory inserts an IAM-returned segment into its slotmap at
    /// `key = segment_id.value()` and stamps that value into every `PointerOffset` produced
    /// from that segment. Consumers therefore request the handle by
    /// `offset.segment_id().value()`. Placing the segment at `port_segments[index]` (with
    /// `index == segment_id.value()`) keeps [`get_dynamic_segment_handle`] aligned with the
    /// producer's segment id for every producer — including multi-producer services, where
    /// the global [`allocate_segment_id`] counter diverges from per-port push order.
    ///
    /// Gaps are filled with the placeholder marker `SegmentId::new(255)`, exactly like
    /// [`register_dynamic_segment_for_port`], so an out-of-order or non-contiguous index does
    /// not shift the meaning of already-placed slots.
    ///
    /// # Errors
    ///
    /// Returns [`IamServerError::SegmentNotFound`] if the segment doesn't exist.
    ///
    /// [`get_dynamic_segment_handle`]: Self::get_dynamic_segment_handle
    /// [`allocate_segment_id`]: Self::allocate_segment_id
    /// [`register_dynamic_segment_for_port`]: Self::register_dynamic_segment_for_port
    pub fn associate_segment_with_port_at_index(
        &mut self,
        segment_id: SegmentId,
        port_id: u128,
        index: u8,
    ) -> Result<(), IamServerError> {
        // Verify the segment exists
        if !self.segments.contains_key(&segment_id.value()) {
            return Err(IamServerError::SegmentNotFound);
        }

        let segments = self.port_segments.entry(port_id).or_default();

        // Ensure the vector is large enough to hold this index, filling any gap with the
        // placeholder marker (SegmentId::new(255)).
        while segments.len() <= index as usize {
            if segments.len() == index as usize {
                segments.push(segment_id);
            } else {
                segments.push(SegmentId::new(255));
            }
        }

        // If the slot already existed (not just grown above), overwrite it.
        if segments.len() > index as usize {
            segments[index as usize] = segment_id;
        }

        Ok(())
    }

    /// Allocates the next available segment ID.
    ///
    /// This handles wrapping and checking for ID collisions.
    ///
    /// `SegmentId` values `0` and `255` are permanently **reserved** and are never handed out, so
    /// the usable id range is `1..=254` (254 ids):
    ///   * `255` (`SegmentId::max_segment_id()`) is the gap/placeholder marker in `port_segments`
    ///     (see `register_dynamic_segment_for_port` / `associate_segment_with_port_at_index`), and
    ///     `get_dynamic_segment_handle` treats it as "no segment". Keeping it out of the allocation
    ///     range means a real segment can never collide with the sentinel and be silently dropped,
    ///     and — because the largest handed-out id is `254` — a producer can never index its
    ///     `segment_states` (length `max_number_of_segments` == 255, valid indices `0..=254`) out
    ///     of bounds.
    ///   * `0` is reserved for each port's **initial** dynamic segment. The initial is stored at
    ///     the fixed slot `port_segments[port][0]` (`register_dynamic_segment_for_port` with
    ///     `segment_index == 0`) and its offsets carry the *local* id `0`, whereas **growth**
    ///     segments are stored at `port_segments[port][global_id]`
    ///     (`associate_segment_with_port_at_index`) and their offsets carry the adopted
    ///     *server-global* id. If a growth segment were ever handed global id `0` it would be
    ///     placed at index `0` and overwrite the initial's slot — a later consumer requesting
    ///     index `0` would then map the differently-sized growth segment and read out of bounds.
    ///     Reserving `0` keeps growth ids in `1..=254`, disjoint from the initial's fixed
    ///     index-`0` slot.
    pub fn allocate_segment_id(&mut self) -> Result<SegmentId, IamServerError> {
        // 0 and 255 are reserved (see the doc comment); the usable id range is 1..=254.
        const RESERVED_SENTINEL: u8 = 255;
        const RESERVED_INITIAL: u8 = 0;
        let start_id = self.next_id;

        loop {
            let candidate = self.next_id;
            self.next_id = self.next_id.wrapping_add(1);

            // The candidate is usable if it is neither reserved value nor already in use.
            if candidate != RESERVED_SENTINEL
                && candidate != RESERVED_INITIAL
                && !self.segments.contains_key(&candidate)
            {
                return Ok(SegmentId::new(candidate));
            }

            // If we've wrapped around completely, we're out of IDs. The scan advances `next_id` by
            // one every iteration and stops when it returns to `start_id`, so it always terminates
            // after at most 256 iterations regardless of how many values are reserved or in use.
            if self.next_id == start_id {
                return Err(IamServerError::ResourceLimitExceeded);
            }
        }
    }

    /// Removes a segment without the retirement protocol.
    ///
    /// This should only be used for segments that have no authorized sessions,
    /// or when forcing removal regardless of session state.
    ///
    /// # Arguments
    ///
    /// * `segment_id` - The segment to remove
    ///
    /// # Returns
    ///
    /// The removed segment if it existed, or `None` if not found.
    pub fn remove_segment(&mut self, segment_id: SegmentId) -> Option<ManagedSegment> {
        // Clean up port_segments mapping
        for seg_ids in self.port_segments.values_mut() {
            seg_ids.retain(|id| id.value() != segment_id.value());
        }
        self.segments.remove(&segment_id.value())
    }

    /// Reaps **all** data segments registered for a producer `port_id`.
    ///
    /// Data segments are the only segments that consume the global [`SegmentId`] space (unlike
    /// connection channels and management segments, which live in their own maps). Each producer
    /// port dup's one fd per data segment into the server; without reaping them on teardown, every
    /// producer create/drop cycle leaks those fds and monotonically consumes ids until the
    /// `u8` id space is exhausted at 255 live segments — after which [`allocate_segment_id`]
    /// returns [`IamServerError::ResourceLimitExceeded`] and all secured brokering dies
    /// server-wide.
    ///
    /// This removes every real [`SegmentId`] currently associated with `port_id` from
    /// `self.segments` (dropping the owned [`PlatformHandle`], which closes the underlying fd) and
    /// clears the port's `port_segments` entry. Because [`allocate_segment_id`] considers an id
    /// free exactly when it is absent from `self.segments`, the removed ids become immediately
    /// reusable — no separate free list is needed.
    ///
    /// Placeholder gap markers (`SegmentId::new(255)`) in the port's vector are skipped: they are
    /// the reserved sentinel and never correspond to a live entry in `self.segments`.
    ///
    /// Called on producer-port teardown (Detach / session removal). Consumer ports own no entry in
    /// `self.segments` or `port_segments` — they only hold cloned handles in their own address
    /// space plus `authorized_sessions` bookkeeping (cleared by [`revoke_session`]) — so no
    /// data-segment reaping is required on the consumer side.
    ///
    /// [`allocate_segment_id`]: Self::allocate_segment_id
    /// [`revoke_session`]: Self::revoke_session
    pub fn remove_all_segments_for_port(&mut self, port_id: u128) {
        if let Some(segment_ids) = self.port_segments.remove(&port_id) {
            for segment_id in segment_ids {
                // Skip the reserved gap sentinel; it is never a live segment.
                if segment_id.value() == 255 {
                    continue;
                }
                // Dropping the removed ManagedSegment drops its PlatformHandle → closes the fd.
                self.segments.remove(&segment_id.value());
            }
        }
    }

    // ========================================================================
    // Port-to-Segment Mapping
    // ========================================================================

    /// Registers a segment and associates it with a producer port.
    ///
    /// The handle is stored in the segment manager for later brokering
    /// to authorized consumers via [`get_segment_handle_for_consumer`].
    ///
    /// # Arguments
    ///
    /// * `port_id` - The producer port that owns the segment
    /// * `handle` - The platform handle for the anonymous segment
    /// * `size` - The size of the segment in bytes
    /// * `access` - The access rights for the segment
    ///
    /// # Returns
    ///
    /// The segment ID assigned to the registered segment.
    pub fn register_segment_for_port(
        &mut self,
        port_id: u128,
        handle: PlatformHandle,
        size: usize,
        access: AccessRights,
    ) -> Result<SegmentId, IamServerError> {
        let segment_id = self.register_segment(handle, size, access)?;
        self.port_segments
            .entry(port_id)
            .or_default()
            .push(segment_id);
        Ok(segment_id)
    }

    /// Returns the segment IDs registered for a given port.
    pub fn get_segments_for_port(&self, port_id: u128) -> &[SegmentId] {
        self.port_segments
            .get(&port_id)
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }

    /// Retrieves a cloned segment handle for a consumer to use.
    ///
    /// Looks up the first segment registered for `port_id`, authorizes the
    /// given session, and returns the segment info plus a cloned handle.
    ///
    /// # Arguments
    ///
    /// * `port_id` - The producer port whose segment is requested
    /// * `consumer_session_id` - The session ID of the requesting consumer
    ///
    /// # Returns
    ///
    /// `Some((SegmentInfo, PlatformHandle))` if the port has a registered segment
    /// and the handle can be cloned, or `None` otherwise.
    pub fn get_segment_handle_for_consumer(
        &mut self,
        port_id: u128,
        consumer_session_id: SessionId,
    ) -> Option<(SegmentInfo, PlatformHandle)> {
        let segment_ids = self.port_segments.get(&port_id)?;
        let segment_id = segment_ids.first()?;
        let segment_id_key = segment_id.value();

        // Authorize the session and get a cloned handle
        let handle = self
            .authorize_session(SegmentId::new(segment_id_key), consumer_session_id)
            .ok()?;
        let segment = self.segments.get(&segment_id_key)?;
        let info = SegmentInfo::new(SegmentId::new(segment_id_key), segment.size, segment.access);
        Some((info, handle))
    }

    /// Registers a dynamic segment at a specific index for a port.
    ///
    /// Dynamic segments are indexed (0 for initial, 1+ for reallocations).
    /// This method ensures the segment is stored at the correct position
    /// in the port's segment list.
    ///
    /// # Arguments
    ///
    /// * `port_id` - The producer port that owns the segment
    /// * `segment_index` - The index within the dynamic segment set (0-based)
    /// * `handle` - The platform handle for the anonymous segment
    /// * `size` - The size of the segment in bytes
    /// * `access` - The access rights for the segment
    ///
    /// # Returns
    ///
    /// The segment ID assigned to the registered segment.
    pub fn register_dynamic_segment_for_port(
        &mut self,
        port_id: u128,
        segment_index: u8,
        handle: PlatformHandle,
        size: usize,
        access: AccessRights,
    ) -> Result<SegmentId, IamServerError> {
        let segment_id = self.register_segment(handle, size, access)?;

        let segments = self.port_segments.entry(port_id).or_default();

        // Ensure the vector is large enough to hold this index
        while segments.len() <= segment_index as usize {
            // Use a placeholder ID that will be replaced or ignored
            // We push the actual segment_id at the target index
            if segments.len() == segment_index as usize {
                segments.push(segment_id);
            } else {
                // Push a placeholder (SegmentId::new(255) as invalid marker)
                // This handles gaps if segments are registered out of order
                segments.push(SegmentId::new(255));
            }
        }

        // If the slot already exists (not a placeholder), update it
        if segments.len() > segment_index as usize {
            segments[segment_index as usize] = segment_id;
        }

        Ok(segment_id)
    }

    /// Retrieves a cloned dynamic segment handle for a consumer by index.
    ///
    /// Looks up the segment at the specified index within a port's dynamic
    /// segment set, authorizes the given session, and returns the segment
    /// info plus a cloned handle.
    ///
    /// # Arguments
    ///
    /// * `port_id` - The producer port whose segment is requested
    /// * `segment_index` - The index of the dynamic segment (0-based)
    /// * `consumer_session_id` - The session ID of the requesting consumer
    ///
    /// # Returns
    ///
    /// `Some((SegmentInfo, PlatformHandle))` if the port has a segment at the
    /// given index and the handle can be cloned, or `None` otherwise.
    pub fn get_dynamic_segment_handle(
        &mut self,
        port_id: u128,
        segment_index: u8,
        consumer_session_id: SessionId,
    ) -> Option<(SegmentInfo, PlatformHandle)> {
        let segment_ids = self.port_segments.get(&port_id)?;
        let segment_id = segment_ids.get(segment_index as usize)?;

        // Check for placeholder (invalid segment ID 255)
        if segment_id.value() == 255 {
            return None;
        }

        let segment_id_key = segment_id.value();

        // Authorize the session and get a cloned handle
        let handle = self
            .authorize_session(SegmentId::new(segment_id_key), consumer_session_id)
            .ok()?;
        let segment = self.segments.get(&segment_id_key)?;
        let info = SegmentInfo::new(SegmentId::new(segment_id_key), segment.size, segment.access);
        Some((info, handle))
    }

    // ========================================================================
    // Connection Channels (2B)
    // ========================================================================

    /// Registers a connection-channel handle for a `(sender, receiver)` port pair.
    ///
    /// Channels are granted **read+write** access (unlike data segments, which are
    /// read-only) because the consumer's receiver end writes the zero-copy connection's
    /// completion ring — see `zero_copy_connection`'s `open_shm_from_handle`, which
    /// rejects handles that are not both readable and writable.
    ///
    /// Channels do **not** consume a [`SegmentId`] and are not part of the `port_segments`
    /// index space; a placeholder `SegmentId::new(0)` is stored in the [`ManagedSegment`]
    /// (unused by `open_receiver_from_handle`, which derives the layout from the handle).
    ///
    /// # Arguments
    ///
    /// * `sender_port_id` - The producer port that owns the connection channel
    /// * `receiver_port_id` - The consumer port the channel is for
    /// * `handle` - The platform handle for the anonymous connection channel
    /// * `size` - The size of the channel in bytes (advisory; stored as `size.max(1)`)
    pub fn register_channel(
        &mut self,
        sender_port_id: u128,
        receiver_port_id: u128,
        handle: PlatformHandle,
        size: usize,
    ) -> Result<(), IamServerError> {
        self.channels.insert(
            (sender_port_id, receiver_port_id),
            ManagedSegment::new(
                SegmentId::new(0),
                handle,
                size.max(1),
                AccessRights::read_write(),
            ),
        );
        Ok(())
    }

    /// Retrieves a cloned connection-channel handle for a consumer.
    ///
    /// Looks up the channel registered for the `(sender, receiver)` pair, authorizes the
    /// given session (recording it in `authorized_sessions` for reaping symmetry), and
    /// returns the channel info plus a cloned handle. The returned info carries
    /// read+write access rights.
    ///
    /// # Returns
    ///
    /// `Some((SegmentInfo, PlatformHandle))` if the channel exists and the handle can be
    /// cloned, or `None` otherwise (producer has not registered it yet).
    pub fn get_channel_handle_for_consumer(
        &mut self,
        sender_port_id: u128,
        receiver_port_id: u128,
        consumer_session_id: SessionId,
    ) -> Option<(SegmentInfo, PlatformHandle)> {
        let channel = self.channels.get_mut(&(sender_port_id, receiver_port_id))?;
        let handle = channel.handle.try_clone().ok()?;
        // Reuse authorized_sessions for reaping symmetry with data segments.
        channel.authorized_sessions.insert(consumer_session_id);
        Some((channel.to_segment_info(), handle))
    }

    /// Reaps all connection channels whose sender is `sender_port_id`.
    ///
    /// Called on producer-port teardown (Detach / session removal) so the brokered
    /// channel handles do not leak.
    pub fn remove_channels_for_sender_port(&mut self, sender_port_id: u128) {
        self.channels.retain(|(s, _), _| *s != sender_port_id);
    }

    /// Reaps all connection channels whose receiver is `receiver_port_id`.
    ///
    /// Called on consumer-port teardown (Detach / session removal) so the brokered
    /// channel handles do not leak.
    pub fn remove_channels_for_receiver_port(&mut self, receiver_port_id: u128) {
        self.channels.retain(|(_, r), _| *r != receiver_port_id);
    }

    /// Returns the number of registered connection channels.
    pub fn channel_count(&self) -> usize {
        self.channels.len()
    }

    // ========================================================================
    // Management Segments (F2)
    // ========================================================================

    /// Registers a resizable-memory management-segment handle for a producer `port_id`.
    ///
    /// Management segments are granted **read-only** access (unlike connection channels, which
    /// are read+write). The consumer's `DynamicView` maps the management segment purely as a
    /// keep-alive token and never reads or writes it, and
    /// `SharedMemory::open_from_handle` requires only `AccessRights::can_read()`. A producer
    /// owns exactly one management segment, so this is keyed by the single `port_id`.
    ///
    /// Management segments do **not** consume a [`SegmentId`] and are not part of the
    /// `port_segments` index space; a placeholder `SegmentId::new(0)` is stored in the
    /// [`ManagedSegment`] (unused — the consumer derives the mapping from the handle).
    ///
    /// # Arguments
    ///
    /// * `port_id` - The producer port that owns the management segment
    /// * `handle` - The platform handle for the anonymous management segment
    /// * `size` - The size of the management segment in bytes (stored as `size.max(1)`)
    pub fn register_mgmt_segment(
        &mut self,
        port_id: u128,
        handle: PlatformHandle,
        size: usize,
    ) -> Result<(), IamServerError> {
        self.mgmt_segments.insert(
            port_id,
            ManagedSegment::new(
                SegmentId::new(0),
                handle,
                size.max(1),
                AccessRights::read_only(),
            ),
        );
        Ok(())
    }

    /// Retrieves a cloned management-segment handle for a consumer.
    ///
    /// Looks up the management segment registered for `port_id`, authorizes the given session
    /// (recording it in `authorized_sessions` for reaping symmetry), and returns the segment
    /// info plus a cloned handle. The returned info carries read-only access rights.
    ///
    /// # Returns
    ///
    /// `Some((SegmentInfo, PlatformHandle))` if the management segment exists and the handle
    /// can be cloned, or `None` otherwise (producer has not registered it yet).
    pub fn get_mgmt_segment_handle_for_consumer(
        &mut self,
        port_id: u128,
        consumer_session_id: SessionId,
    ) -> Option<(SegmentInfo, PlatformHandle)> {
        let mgmt = self.mgmt_segments.get_mut(&port_id)?;
        let handle = mgmt.handle.try_clone().ok()?;
        // Reuse authorized_sessions for reaping symmetry with data segments.
        mgmt.authorized_sessions.insert(consumer_session_id);
        Some((mgmt.to_segment_info(), handle))
    }

    /// Reaps the management segment registered for `port_id`.
    ///
    /// Called on producer-port teardown (Detach / session removal) so the brokered management
    /// segment handle does not leak in the server's maps.
    pub fn remove_mgmt_segment_for_port(&mut self, port_id: u128) {
        self.mgmt_segments.remove(&port_id);
    }

    /// Returns the number of registered management segments.
    pub fn mgmt_segment_count(&self) -> usize {
        self.mgmt_segments.len()
    }

    // ========================================================================
    // Session Authorization
    // ========================================================================

    /// Authorizes a session to access a segment.
    ///
    /// Creates a cloned handle for the session and marks them as authorized.
    ///
    /// # Arguments
    ///
    /// * `segment_id` - The segment to authorize access to
    /// * `session_id` - The session to grant access
    ///
    /// # Returns
    ///
    /// A cloned platform handle for the session to use.
    ///
    /// # Errors
    ///
    /// - [`IamServerError::SegmentNotFound`] if the segment doesn't exist
    /// - [`IamServerError::HandlePassingFailed`] if handle cloning fails
    pub fn authorize_session(
        &mut self,
        segment_id: SegmentId,
        session_id: SessionId,
    ) -> Result<PlatformHandle, IamServerError> {
        let segment = self
            .segments
            .get_mut(&segment_id.value())
            .ok_or(IamServerError::SegmentNotFound)?;

        // Don't authorize access to retiring segments
        if segment.retiring {
            return Err(IamServerError::SegmentNotFound);
        }

        // Clone the handle for the session
        let cloned_handle = segment
            .handle
            .try_clone()
            .map_err(|_| IamServerError::HandlePassingFailed)?;

        // Mark the session as authorized
        segment.authorized_sessions.insert(session_id);

        Ok(cloned_handle)
    }

    /// Revokes a session's access to a segment.
    ///
    /// Also removes the session from pending acks if the segment is retiring.
    ///
    /// # Arguments
    ///
    /// * `segment_id` - The segment to revoke access from
    /// * `session_id` - The session to revoke
    ///
    /// # Returns
    ///
    /// `true` if the session was authorized and is now revoked, `false` otherwise.
    pub fn revoke_session_from_segment(
        &mut self,
        segment_id: SegmentId,
        session_id: SessionId,
    ) -> bool {
        if let Some(segment) = self.segments.get_mut(&segment_id.value()) {
            let was_authorized = segment.authorized_sessions.remove(&session_id);
            segment.pending_acks.remove(&session_id);
            was_authorized
        } else {
            false
        }
    }

    /// Revokes a session's access from all segments.
    ///
    /// This is typically called when a session disconnects.
    ///
    /// # Arguments
    ///
    /// * `session_id` - The session to revoke from all segments
    pub fn revoke_session(&mut self, session_id: SessionId) {
        for segment in self.segments.values_mut() {
            segment.authorized_sessions.remove(&session_id);
            segment.pending_acks.remove(&session_id);
        }
    }

    /// Checks if a session is authorized for a segment.
    pub fn is_session_authorized(&self, segment_id: SegmentId, session_id: SessionId) -> bool {
        self.segments
            .get(&segment_id.value())
            .map(|s| s.authorized_sessions.contains(&session_id))
            .unwrap_or(false)
    }

    // ========================================================================
    // Segment Retirement
    // ========================================================================

    /// Begins the retirement process for a segment.
    ///
    /// Marks the segment as retiring and returns the set of sessions that need
    /// to acknowledge the retirement before the segment can be removed.
    ///
    /// # Arguments
    ///
    /// * `segment_id` - The segment to retire
    ///
    /// # Returns
    ///
    /// The set of session IDs that need to acknowledge the retirement,
    /// or `None` if the segment doesn't exist.
    pub fn begin_retirement(&mut self, segment_id: SegmentId) -> Option<HashSet<SessionId>> {
        let segment = self.segments.get_mut(&segment_id.value())?;

        // Already retiring
        if segment.retiring {
            return Some(segment.pending_acks.clone());
        }

        segment.retiring = true;
        segment.pending_acks = segment.authorized_sessions.clone();

        Some(segment.pending_acks.clone())
    }

    /// Acknowledges retirement from a session.
    ///
    /// If all sessions have acknowledged, the segment is removed.
    ///
    /// # Arguments
    ///
    /// * `segment_id` - The segment being retired
    /// * `session_id` - The session acknowledging retirement
    ///
    /// # Returns
    ///
    /// `true` if this was the last ack and the segment was removed,
    /// `false` otherwise (including if segment not found, not retiring, or
    /// session was not authorized for this segment).
    pub fn ack_retirement(&mut self, segment_id: SegmentId, session_id: SessionId) -> bool {
        let should_remove = if let Some(segment) = self.segments.get_mut(&segment_id.value()) {
            if !segment.retiring {
                return false;
            }

            // Security check: only accept acks from sessions that were authorized
            if !segment.authorized_sessions.contains(&session_id) {
                return false;
            }

            segment.pending_acks.remove(&session_id);
            segment.pending_acks.is_empty()
        } else {
            return false;
        };

        if should_remove {
            self.segments.remove(&segment_id.value());
            true
        } else {
            false
        }
    }

    /// Checks if a segment is retiring.
    pub fn is_retiring(&self, segment_id: SegmentId) -> bool {
        self.segments
            .get(&segment_id.value())
            .map(|s| s.retiring)
            .unwrap_or(false)
    }

    /// Gets the pending ack count for a retiring segment.
    pub fn pending_ack_count(&self, segment_id: SegmentId) -> usize {
        self.segments
            .get(&segment_id.value())
            .map(|s| s.pending_acks.len())
            .unwrap_or(0)
    }

    // ========================================================================
    // Segment Info
    // ========================================================================

    /// Gets segment info for a single segment.
    pub fn get_segment_info(&self, segment_id: SegmentId) -> Option<SegmentInfo> {
        self.segments
            .get(&segment_id.value())
            .map(|s| s.to_segment_info())
    }

    /// Gets segment info for all segments a session is authorized for.
    pub fn get_session_segments(&self, session_id: SessionId) -> Vec<SegmentInfo> {
        self.segments
            .values()
            .filter(|s| s.authorized_sessions.contains(&session_id) && !s.retiring)
            .map(|s| s.to_segment_info())
            .collect()
    }

    /// Gets all non-retiring segments.
    pub fn get_active_segments(&self) -> Vec<SegmentInfo> {
        self.segments
            .values()
            .filter(|s| !s.retiring)
            .map(|s| s.to_segment_info())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Helper to create a test handle (using dup of stdout for simplicity)
    #[cfg(unix)]
    fn create_test_handle() -> PlatformHandle {
        use std::os::unix::io::AsRawFd;
        let raw_fd = unsafe { iceoryx2_pal_posix::posix::dup(std::io::stdout().as_raw_fd()) };
        unsafe { PlatformHandle::from_raw_fd(raw_fd) }
    }

    #[cfg(windows)]
    fn create_test_handle() -> PlatformHandle {
        use std::os::windows::io::AsRawHandle;
        use std::os::windows::io::FromRawHandle;
        let raw_handle = std::io::stdout().as_raw_handle();
        let mut dup_handle: isize = 0;
        unsafe {
            let current_process = windows_sys::Win32::System::Threading::GetCurrentProcess();
            windows_sys::Win32::Foundation::DuplicateHandle(
                current_process,
                raw_handle as isize,
                current_process,
                &mut dup_handle,
                0,
                0,
                windows_sys::Win32::Foundation::DUPLICATE_SAME_ACCESS,
            );
            PlatformHandle::from_raw_handle(dup_handle as *mut _)
        }
    }

    // ========================================================================
    // ManagedSegment Tests
    // ========================================================================

    #[test]
    fn test_managed_segment_new() {
        let handle = create_test_handle();
        let segment =
            ManagedSegment::new(SegmentId::new(0), handle, 4096, AccessRights::read_write());

        assert_eq!(segment.id().value(), 0);
        assert_eq!(segment.size(), 4096);
        assert!(segment.access().can_read());
        assert!(segment.access().can_write());
        assert!(!segment.is_retiring());
        assert_eq!(segment.authorized_session_count(), 0);
        assert_eq!(segment.pending_ack_count(), 0);
    }

    #[test]
    fn test_managed_segment_to_segment_info() {
        let handle = create_test_handle();
        let segment =
            ManagedSegment::new(SegmentId::new(5), handle, 8192, AccessRights::read_only());

        let info = segment.to_segment_info();
        assert_eq!(info.segment_id().value(), 5);
        assert_eq!(info.size(), 8192);
        assert!(info.access().can_read());
        assert!(!info.access().can_write());
    }

    // ========================================================================
    // SegmentManager Tests
    // ========================================================================

    #[test]
    fn test_manager_new() {
        let manager = SegmentManager::new();
        assert_eq!(manager.segment_count(), 0);
    }

    #[test]
    fn test_manager_default() {
        let manager = SegmentManager::default();
        assert_eq!(manager.segment_count(), 0);
    }

    #[test]
    fn test_manager_register_segment() {
        let mut manager = SegmentManager::new();
        let handle = create_test_handle();

        let segment_id = manager
            .register_segment(handle, 4096, AccessRights::read_write())
            .unwrap();

        assert!(manager.has_segment(segment_id));
        assert_eq!(manager.segment_count(), 1);

        let segment = manager.get(segment_id).unwrap();
        assert_eq!(segment.size(), 4096);
    }

    #[test]
    fn test_manager_register_multiple_segments() {
        let mut manager = SegmentManager::new();

        for i in 0..5 {
            let handle = create_test_handle();
            let segment_id = manager
                .register_segment(handle, (i + 1) * 1024, AccessRights::read_write())
                .unwrap();
            // Id 0 is reserved, so the sequence starts at 1: 1, 2, 3, 4, 5.
            assert_eq!(segment_id.value(), i as u8 + 1);
        }

        assert_eq!(manager.segment_count(), 5);
    }

    #[test]
    fn test_manager_remove_segment() {
        let mut manager = SegmentManager::new();
        let handle = create_test_handle();
        let segment_id = manager
            .register_segment(handle, 4096, AccessRights::read_write())
            .unwrap();

        let removed = manager.remove_segment(segment_id);
        assert!(removed.is_some());
        assert!(!manager.has_segment(segment_id));
        assert_eq!(manager.segment_count(), 0);

        // Remove again should return None
        assert!(manager.remove_segment(segment_id).is_none());
    }

    #[test]
    fn test_manager_authorize_session() {
        let mut manager = SegmentManager::new();
        let handle = create_test_handle();
        let segment_id = manager
            .register_segment(handle, 4096, AccessRights::read_write())
            .unwrap();

        let session_id = SessionId::from_value(100);
        let cloned_handle = manager.authorize_session(segment_id, session_id).unwrap();

        // Verify handle was cloned (different raw value on Unix)
        #[cfg(unix)]
        {
            let segment = manager.get(segment_id).unwrap();
            assert_ne!(cloned_handle.as_raw_fd(), segment.handle().as_raw_fd());
        }

        assert!(manager.is_session_authorized(segment_id, session_id));
    }

    #[test]
    fn test_manager_authorize_session_not_found() {
        let mut manager = SegmentManager::new();
        let session_id = SessionId::from_value(100);
        let segment_id = SegmentId::new(99);

        let result = manager.authorize_session(segment_id, session_id);
        assert!(matches!(result, Err(IamServerError::SegmentNotFound)));
    }

    #[test]
    fn test_manager_revoke_session_from_segment() {
        let mut manager = SegmentManager::new();
        let handle = create_test_handle();
        let segment_id = manager
            .register_segment(handle, 4096, AccessRights::read_write())
            .unwrap();

        let session_id = SessionId::from_value(100);
        manager.authorize_session(segment_id, session_id).unwrap();

        assert!(manager.revoke_session_from_segment(segment_id, session_id));
        assert!(!manager.is_session_authorized(segment_id, session_id));

        // Revoking again should return false
        assert!(!manager.revoke_session_from_segment(segment_id, session_id));
    }

    #[test]
    fn test_manager_revoke_session() {
        let mut manager = SegmentManager::new();
        let session_id = SessionId::from_value(100);

        // Create multiple segments and authorize session for all
        for _ in 0..3 {
            let handle = create_test_handle();
            let segment_id = manager
                .register_segment(handle, 4096, AccessRights::read_write())
                .unwrap();
            manager.authorize_session(segment_id, session_id).unwrap();
        }

        // Revoke session from all segments
        manager.revoke_session(session_id);

        // Verify revoked from all
        for segment_id in manager.segment_ids().collect::<Vec<_>>() {
            assert!(!manager.is_session_authorized(segment_id, session_id));
        }
    }

    #[test]
    fn test_manager_begin_retirement() {
        let mut manager = SegmentManager::new();
        let handle = create_test_handle();
        let segment_id = manager
            .register_segment(handle, 4096, AccessRights::read_write())
            .unwrap();

        let session1 = SessionId::from_value(100);
        let session2 = SessionId::from_value(200);
        manager.authorize_session(segment_id, session1).unwrap();
        manager.authorize_session(segment_id, session2).unwrap();

        let pending = manager.begin_retirement(segment_id).unwrap();
        assert_eq!(pending.len(), 2);
        assert!(pending.contains(&session1));
        assert!(pending.contains(&session2));
        assert!(manager.is_retiring(segment_id));
        assert_eq!(manager.pending_ack_count(segment_id), 2);
    }

    #[test]
    fn test_manager_begin_retirement_not_found() {
        let mut manager = SegmentManager::new();
        let result = manager.begin_retirement(SegmentId::new(99));
        assert!(result.is_none());
    }

    #[test]
    fn test_manager_begin_retirement_already_retiring() {
        let mut manager = SegmentManager::new();
        let handle = create_test_handle();
        let segment_id = manager
            .register_segment(handle, 4096, AccessRights::read_write())
            .unwrap();

        let session_id = SessionId::from_value(100);
        manager.authorize_session(segment_id, session_id).unwrap();

        manager.begin_retirement(segment_id);
        let pending = manager.begin_retirement(segment_id).unwrap();

        // Should still return the pending acks
        assert_eq!(pending.len(), 1);
    }

    #[test]
    fn test_manager_ack_retirement() {
        let mut manager = SegmentManager::new();
        let handle = create_test_handle();
        let segment_id = manager
            .register_segment(handle, 4096, AccessRights::read_write())
            .unwrap();

        let session1 = SessionId::from_value(100);
        let session2 = SessionId::from_value(200);
        manager.authorize_session(segment_id, session1).unwrap();
        manager.authorize_session(segment_id, session2).unwrap();

        manager.begin_retirement(segment_id);

        // First ack - not complete yet
        assert!(!manager.ack_retirement(segment_id, session1));
        assert!(manager.has_segment(segment_id));
        assert_eq!(manager.pending_ack_count(segment_id), 1);

        // Second ack - should remove segment
        assert!(manager.ack_retirement(segment_id, session2));
        assert!(!manager.has_segment(segment_id));
    }

    #[test]
    fn test_manager_ack_retirement_not_retiring() {
        let mut manager = SegmentManager::new();
        let handle = create_test_handle();
        let segment_id = manager
            .register_segment(handle, 4096, AccessRights::read_write())
            .unwrap();

        let session_id = SessionId::from_value(100);
        manager.authorize_session(segment_id, session_id).unwrap();

        // Ack without begin_retirement should return false
        assert!(!manager.ack_retirement(segment_id, session_id));
    }

    #[test]
    fn test_manager_authorize_retiring_segment() {
        let mut manager = SegmentManager::new();
        let handle = create_test_handle();
        let segment_id = manager
            .register_segment(handle, 4096, AccessRights::read_write())
            .unwrap();

        manager.begin_retirement(segment_id);

        let session_id = SessionId::from_value(100);
        let result = manager.authorize_session(segment_id, session_id);
        assert!(matches!(result, Err(IamServerError::SegmentNotFound)));
    }

    #[test]
    fn test_manager_get_segment_info() {
        let mut manager = SegmentManager::new();
        let handle = create_test_handle();
        let segment_id = manager
            .register_segment(handle, 4096, AccessRights::read_only())
            .unwrap();

        let info = manager.get_segment_info(segment_id).unwrap();
        assert_eq!(info.segment_id(), segment_id);
        assert_eq!(info.size(), 4096);
        assert!(info.access().can_read());
        assert!(!info.access().can_write());

        assert!(manager.get_segment_info(SegmentId::new(99)).is_none());
    }

    #[test]
    fn test_manager_get_session_segments() {
        let mut manager = SegmentManager::new();
        let session_id = SessionId::from_value(100);

        // Create segments and authorize for some
        let handle1 = create_test_handle();
        let segment1 = manager
            .register_segment(handle1, 4096, AccessRights::read_write())
            .unwrap();
        manager.authorize_session(segment1, session_id).unwrap();

        let handle2 = create_test_handle();
        let segment2 = manager
            .register_segment(handle2, 8192, AccessRights::read_only())
            .unwrap();
        manager.authorize_session(segment2, session_id).unwrap();

        let handle3 = create_test_handle();
        let _segment3 = manager
            .register_segment(handle3, 2048, AccessRights::read_write())
            .unwrap();
        // Not authorized for session

        let segments = manager.get_session_segments(session_id);
        assert_eq!(segments.len(), 2);
    }

    #[test]
    fn test_manager_get_session_segments_excludes_retiring() {
        let mut manager = SegmentManager::new();
        let session_id = SessionId::from_value(100);

        let handle1 = create_test_handle();
        let segment1 = manager
            .register_segment(handle1, 4096, AccessRights::read_write())
            .unwrap();
        manager.authorize_session(segment1, session_id).unwrap();

        let handle2 = create_test_handle();
        let segment2 = manager
            .register_segment(handle2, 8192, AccessRights::read_write())
            .unwrap();
        manager.authorize_session(segment2, session_id).unwrap();

        // Retire segment2
        manager.begin_retirement(segment2);

        let segments = manager.get_session_segments(session_id);
        assert_eq!(segments.len(), 1);
        assert_eq!(segments[0].segment_id(), segment1);
    }

    #[test]
    fn test_manager_get_active_segments() {
        let mut manager = SegmentManager::new();

        let handle1 = create_test_handle();
        let segment1 = manager
            .register_segment(handle1, 4096, AccessRights::read_write())
            .unwrap();

        let handle2 = create_test_handle();
        let segment2 = manager
            .register_segment(handle2, 8192, AccessRights::read_write())
            .unwrap();

        // Retire segment2
        manager.begin_retirement(segment2);

        let active = manager.get_active_segments();
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].segment_id(), segment1);
    }

    #[test]
    fn test_manager_segment_ids_iterator() {
        let mut manager = SegmentManager::new();

        for _ in 0..3 {
            let handle = create_test_handle();
            manager
                .register_segment(handle, 4096, AccessRights::read_write())
                .unwrap();
        }

        let ids: Vec<SegmentId> = manager.segment_ids().collect();
        assert_eq!(ids.len(), 3);
    }

    #[test]
    fn test_manager_id_reuse_after_removal() {
        let mut manager = SegmentManager::new();

        // Create and remove the first segment. Id 0 is reserved, so allocation starts at 1.
        let handle1 = create_test_handle();
        let segment1 = manager
            .register_segment(handle1, 4096, AccessRights::read_write())
            .unwrap();
        assert_eq!(segment1.value(), 1);
        manager.remove_segment(segment1);

        // Create more segments - the monotonic counter continues (2, 3, ...).
        let handle2 = create_test_handle();
        let segment2 = manager
            .register_segment(handle2, 4096, AccessRights::read_write())
            .unwrap();
        assert_eq!(segment2.value(), 2);

        // If we remove segment2 and create another, next_id continues
        manager.remove_segment(segment2);
        let handle3 = create_test_handle();
        let segment3 = manager
            .register_segment(handle3, 4096, AccessRights::read_write())
            .unwrap();
        assert_eq!(segment3.value(), 3);
    }

    // ========================================================================
    // Port-to-Segment Mapping Tests
    // ========================================================================

    #[test]
    fn test_manager_register_segment_for_port() {
        let mut manager = SegmentManager::new();
        let handle = create_test_handle();
        let port_id: u128 = 0xABCD;

        let segment_id = manager
            .register_segment_for_port(port_id, handle, 4096, AccessRights::read_write())
            .unwrap();

        assert!(manager.has_segment(segment_id));
        let segments = manager.get_segments_for_port(port_id);
        assert_eq!(segments.len(), 1);
        assert_eq!(segments[0].value(), segment_id.value());
    }

    #[test]
    fn test_manager_register_multiple_segments_for_port() {
        let mut manager = SegmentManager::new();
        let port_id: u128 = 0x1234;

        let handle1 = create_test_handle();
        let seg1 = manager
            .register_segment_for_port(port_id, handle1, 4096, AccessRights::read_write())
            .unwrap();

        let handle2 = create_test_handle();
        let seg2 = manager
            .register_segment_for_port(port_id, handle2, 8192, AccessRights::read_write())
            .unwrap();

        let segments = manager.get_segments_for_port(port_id);
        assert_eq!(segments.len(), 2);
        assert_eq!(segments[0].value(), seg1.value());
        assert_eq!(segments[1].value(), seg2.value());
    }

    #[test]
    fn test_manager_get_segments_for_unknown_port() {
        let manager = SegmentManager::new();
        let segments = manager.get_segments_for_port(0xFFFF);
        assert!(segments.is_empty());
    }

    #[test]
    fn test_manager_remove_segment_cleans_port_mapping() {
        let mut manager = SegmentManager::new();
        let port_id: u128 = 0x5678;
        let handle = create_test_handle();

        let segment_id = manager
            .register_segment_for_port(port_id, handle, 4096, AccessRights::read_write())
            .unwrap();

        manager.remove_segment(segment_id);

        let segments = manager.get_segments_for_port(port_id);
        assert!(segments.is_empty());
    }

    #[test]
    fn test_manager_get_segment_handle_for_consumer() {
        let mut manager = SegmentManager::new();
        let port_id: u128 = 0xAAAA;
        let consumer_session = SessionId::from_value(42);
        let handle = create_test_handle();

        manager
            .register_segment_for_port(port_id, handle, 4096, AccessRights::read_only())
            .unwrap();

        let result = manager.get_segment_handle_for_consumer(port_id, consumer_session);
        assert!(result.is_some());

        let (info, _handle) = result.unwrap();
        assert_eq!(info.size(), 4096);
        assert!(info.access().can_read());
    }

    #[test]
    fn test_manager_get_segment_handle_for_consumer_unknown_port() {
        let mut manager = SegmentManager::new();
        let consumer_session = SessionId::from_value(99);

        let result = manager.get_segment_handle_for_consumer(0xBBBB, consumer_session);
        assert!(result.is_none());
    }

    // ========================================================================
    // Connection Channel Tests (2B)
    // ========================================================================

    #[test]
    fn test_manager_register_and_get_channel_grants_read_write() {
        let mut manager = SegmentManager::new();
        let sender: u128 = 0x1111;
        let receiver: u128 = 0x2222;
        let consumer_session = SessionId::from_value(7);
        let handle = create_test_handle();

        manager
            .register_channel(sender, receiver, handle, 4096)
            .unwrap();
        assert_eq!(manager.channel_count(), 1);

        let (info, _handle) = manager
            .get_channel_handle_for_consumer(sender, receiver, consumer_session)
            .expect("channel must be found for the registered (sender, receiver) pair");

        // Access-rights hazard: channels MUST be read+write (the receiver end writes the
        // completion ring); data segments are read-only.
        assert!(info.access().can_read());
        assert!(info.access().can_write());
        assert_eq!(info.size(), 4096);
    }

    #[test]
    fn test_manager_channel_keyed_by_sender_receiver_pair() {
        let mut manager = SegmentManager::new();
        let sender: u128 = 0xAAAA;
        let receiver_a: u128 = 0x1;
        let receiver_b: u128 = 0x2;
        let session = SessionId::from_value(1);

        manager
            .register_channel(sender, receiver_a, create_test_handle(), 4096)
            .unwrap();
        manager
            .register_channel(sender, receiver_b, create_test_handle(), 8192)
            .unwrap();
        assert_eq!(manager.channel_count(), 2);

        // Each (sender, receiver) pair is an independent channel.
        assert!(manager
            .get_channel_handle_for_consumer(sender, receiver_a, session)
            .is_some());
        assert!(manager
            .get_channel_handle_for_consumer(sender, receiver_b, session)
            .is_some());
        // A pair that was never registered is not found.
        assert!(manager
            .get_channel_handle_for_consumer(sender, 0x3, session)
            .is_none());
    }

    #[test]
    fn test_manager_reap_channels_for_sender_port() {
        let mut manager = SegmentManager::new();
        let sender: u128 = 0xAAAA;
        let other_sender: u128 = 0xBBBB;

        manager
            .register_channel(sender, 0x1, create_test_handle(), 4096)
            .unwrap();
        manager
            .register_channel(sender, 0x2, create_test_handle(), 4096)
            .unwrap();
        manager
            .register_channel(other_sender, 0x3, create_test_handle(), 4096)
            .unwrap();
        assert_eq!(manager.channel_count(), 3);

        // Reaping the producer port drops only its channels (fd cleanup on teardown).
        manager.remove_channels_for_sender_port(sender);
        assert_eq!(manager.channel_count(), 1);
        let session = SessionId::from_value(1);
        assert!(manager
            .get_channel_handle_for_consumer(other_sender, 0x3, session)
            .is_some());
    }

    #[test]
    fn test_manager_reap_channels_for_receiver_port() {
        let mut manager = SegmentManager::new();
        let receiver: u128 = 0x2222;

        manager
            .register_channel(0xA, receiver, create_test_handle(), 4096)
            .unwrap();
        manager
            .register_channel(0xB, receiver, create_test_handle(), 4096)
            .unwrap();
        manager
            .register_channel(0xC, 0x9999, create_test_handle(), 4096)
            .unwrap();
        assert_eq!(manager.channel_count(), 3);

        // Reaping the consumer port drops only the channels brokered to it.
        manager.remove_channels_for_receiver_port(receiver);
        assert_eq!(manager.channel_count(), 1);
    }

    // ========================================================================
    // Management Segment Tests (F2)
    // ========================================================================

    #[test]
    fn test_manager_register_and_get_mgmt_segment_grants_read_only() {
        let mut manager = SegmentManager::new();
        let port_id: u128 = 0xF00D;
        let consumer_session = SessionId::from_value(7);
        let handle = create_test_handle();

        manager.register_mgmt_segment(port_id, handle, 4096).unwrap();
        assert_eq!(manager.mgmt_segment_count(), 1);

        let (info, _handle) = manager
            .get_mgmt_segment_handle_for_consumer(port_id, consumer_session)
            .expect("management segment must be found for the registered producer port");

        // Access-rights: the management segment is a never-read keep-alive token, so it is
        // brokered read-only (like data segments, unlike the read+write connection channels).
        assert!(info.access().can_read());
        assert!(!info.access().can_write());
        assert_eq!(info.size(), 4096);
    }

    #[test]
    fn test_manager_mgmt_segment_keyed_by_port() {
        let mut manager = SegmentManager::new();
        let port_a: u128 = 0xAAAA;
        let port_b: u128 = 0xBBBB;
        let session = SessionId::from_value(1);

        manager
            .register_mgmt_segment(port_a, create_test_handle(), 4096)
            .unwrap();
        manager
            .register_mgmt_segment(port_b, create_test_handle(), 8192)
            .unwrap();
        assert_eq!(manager.mgmt_segment_count(), 2);

        // Each producer port has an independent management segment.
        assert!(manager
            .get_mgmt_segment_handle_for_consumer(port_a, session)
            .is_some());
        assert!(manager
            .get_mgmt_segment_handle_for_consumer(port_b, session)
            .is_some());
        // A port that never registered a management segment is not found.
        assert!(manager
            .get_mgmt_segment_handle_for_consumer(0xCCCC, session)
            .is_none());
    }

    #[test]
    fn test_manager_mgmt_segment_size_floored_to_one() {
        let mut manager = SegmentManager::new();
        let port_id: u128 = 0x1;
        let session = SessionId::from_value(1);

        // A zero advisory size is stored as 1 (the consumer derives the true mapping from the
        // handle), so registration and lookup still succeed.
        manager.register_mgmt_segment(port_id, create_test_handle(), 0).unwrap();
        let (info, _handle) = manager
            .get_mgmt_segment_handle_for_consumer(port_id, session)
            .expect("management segment must be found");
        assert_eq!(info.size(), 1);
    }

    #[test]
    fn test_manager_reap_mgmt_segment_for_port() {
        let mut manager = SegmentManager::new();
        let port_a: u128 = 0xAAAA;
        let port_b: u128 = 0xBBBB;
        let session = SessionId::from_value(1);

        manager
            .register_mgmt_segment(port_a, create_test_handle(), 4096)
            .unwrap();
        manager
            .register_mgmt_segment(port_b, create_test_handle(), 4096)
            .unwrap();
        assert_eq!(manager.mgmt_segment_count(), 2);

        // Reaping the producer port drops only its management segment (fd cleanup on teardown).
        manager.remove_mgmt_segment_for_port(port_a);
        assert_eq!(manager.mgmt_segment_count(), 1);
        assert!(manager
            .get_mgmt_segment_handle_for_consumer(port_a, session)
            .is_none());
        assert!(manager
            .get_mgmt_segment_handle_for_consumer(port_b, session)
            .is_some());
    }

    // ========================================================================
    // Explicit-Index Placement Tests (multi-producer index-bug fix)
    // ========================================================================

    #[test]
    fn test_manager_associate_at_index_aligns_with_segment_id() {
        let mut manager = SegmentManager::new();
        let port_id: u128 = 0x1234;
        let session = SessionId::from_value(1);

        // The initial data segment is registered at explicit index 0. Its global id is opaque to
        // consumers (they always request the initial by local index 0); with id 0 reserved the
        // first allocated global id is 1.
        let seg_initial = manager
            .register_dynamic_segment_for_port(
                port_id,
                0,
                create_test_handle(),
                4096,
                AccessRights::read_only(),
            )
            .unwrap();
        assert_eq!(seg_initial.value(), 1);

        // Simulate the multi-producer case: the global segment-id counter is shared, so this
        // producer's two runtime (growth) segments end up with the non-contiguous ids 3 and 5 (a
        // co-located producer took the interleaved ids 2 and 4). The producer stamps its adopted
        // global id into its offsets, so the server must place each growth segment at that
        // explicit index.
        let _seg_other = manager
            .register_segment(create_test_handle(), 1024, AccessRights::read_write())
            .unwrap(); // id 2, belongs to another producer
        let seg_a = manager
            .register_segment(create_test_handle(), 8192, AccessRights::read_write())
            .unwrap(); // id 3, this producer
        let _seg_other2 = manager
            .register_segment(create_test_handle(), 1024, AccessRights::read_write())
            .unwrap(); // id 4, belongs to another producer
        let seg_b = manager
            .register_segment(create_test_handle(), 16384, AccessRights::read_write())
            .unwrap(); // id 5, this producer
        assert_eq!(seg_a.value(), 3);
        assert_eq!(seg_b.value(), 5);

        manager
            .associate_segment_with_port_at_index(seg_a, port_id, seg_a.value())
            .unwrap();
        manager
            .associate_segment_with_port_at_index(seg_b, port_id, seg_b.value())
            .unwrap();

        // port_segments must be aligned so that port_segments[i] holds the segment whose id
        // value is what the producer stamps into offset.segment_id() (== the explicit index).
        let segments = manager.get_segments_for_port(port_id);
        assert_eq!(segments.len(), 6);
        assert_eq!(segments[0].value(), seg_initial.value()); // initial data segment (id 1)
        assert_eq!(segments[1].value(), 255); // gap placeholder
        assert_eq!(segments[2].value(), 255); // gap placeholder (another producer's id 2)
        assert_eq!(segments[3].value(), 3); // runtime segment id 3
        assert_eq!(segments[4].value(), 255); // gap placeholder (another producer's id 4)
        assert_eq!(segments[5].value(), 5); // runtime segment id 5

        // A consumer requesting by offset.segment_id().value() resolves the correct handle.
        assert!(manager
            .get_dynamic_segment_handle(port_id, 3, session)
            .is_some());
        assert!(manager
            .get_dynamic_segment_handle(port_id, 5, session)
            .is_some());
        // Gap indices resolve to the placeholder and yield no handle.
        assert!(manager
            .get_dynamic_segment_handle(port_id, 2, session)
            .is_none());
    }

    #[test]
    fn test_manager_associate_at_index_segment_not_found() {
        let mut manager = SegmentManager::new();
        let result =
            manager.associate_segment_with_port_at_index(SegmentId::new(3), 0xABCD, 3);
        assert!(matches!(result, Err(IamServerError::SegmentNotFound)));
    }

    #[test]
    fn test_manager_associate_at_index_overwrites_existing_slot() {
        let mut manager = SegmentManager::new();
        let port_id: u128 = 0x9;

        let seg0 = manager
            .register_segment(create_test_handle(), 4096, AccessRights::read_write())
            .unwrap();
        // Place seg0 at index 0.
        manager
            .associate_segment_with_port_at_index(seg0, port_id, 0)
            .unwrap();
        // Overwriting the same explicit index does not grow or shift the vector.
        manager
            .associate_segment_with_port_at_index(seg0, port_id, 0)
            .unwrap();

        let segments = manager.get_segments_for_port(port_id);
        assert_eq!(segments.len(), 1);
        assert_eq!(segments[0].value(), seg0.value());
    }

    // ========================================================================
    // Data-Segment Reaping Tests (F2 — data-segment fd leak on teardown)
    // ========================================================================

    #[test]
    fn test_remove_all_segments_for_port_reaps_and_frees_ids() {
        let mut manager = SegmentManager::new();
        let port_id: u128 = 0xD00D;

        // Register several data segments for the producer port.
        let mut ids = Vec::new();
        for _ in 0..4 {
            let id = manager
                .register_segment_for_port(
                    port_id,
                    create_test_handle(),
                    4096,
                    AccessRights::read_write(),
                )
                .unwrap();
            ids.push(id);
        }
        assert_eq!(manager.segment_count(), 4);
        assert_eq!(manager.get_segments_for_port(port_id).len(), 4);
        for id in &ids {
            assert!(manager.has_segment(*id));
        }

        // Reap every data segment owned by the port (fd cleanup on producer teardown).
        manager.remove_all_segments_for_port(port_id);

        // All segments are gone and the port's mapping is cleared.
        assert_eq!(manager.segment_count(), 0);
        assert!(manager.get_segments_for_port(port_id).is_empty());
        for id in &ids {
            assert!(!manager.has_segment(*id));
        }

        // The freed ids are immediately reusable: allocation considers an id free exactly when
        // it is absent from `self.segments`. Rewinding next_id to 0 hands out 1 (id 0 is
        // reserved), the lowest usable id.
        manager.next_id = 0;
        let reused = manager
            .register_segment_for_port(
                port_id,
                create_test_handle(),
                4096,
                AccessRights::read_write(),
            )
            .unwrap();
        assert_eq!(reused.value(), 1);
        assert!(manager.has_segment(reused));
    }

    #[test]
    fn test_remove_all_segments_for_port_isolated_to_that_port() {
        let mut manager = SegmentManager::new();
        let port_a: u128 = 0xAAAA;
        let port_b: u128 = 0xBBBB;
        let session = SessionId::from_value(1);

        let a1 = manager
            .register_segment_for_port(port_a, create_test_handle(), 4096, AccessRights::read_write())
            .unwrap();
        let a2 = manager
            .register_segment_for_port(port_a, create_test_handle(), 4096, AccessRights::read_write())
            .unwrap();
        let b1 = manager
            .register_segment_for_port(port_b, create_test_handle(), 4096, AccessRights::read_write())
            .unwrap();

        // A connection channel and a management segment for port_a must NOT be affected: those
        // live in separate maps and are reaped by their own teardown calls.
        manager
            .register_channel(port_a, 0x1, create_test_handle(), 4096)
            .unwrap();
        manager
            .register_mgmt_segment(port_a, create_test_handle(), 4096)
            .unwrap();

        assert_eq!(manager.segment_count(), 3);

        manager.remove_all_segments_for_port(port_a);

        // Only port_a's data segments were reaped.
        assert!(!manager.has_segment(a1));
        assert!(!manager.has_segment(a2));
        assert!(manager.has_segment(b1));
        assert_eq!(manager.segment_count(), 1);
        assert!(manager.get_segments_for_port(port_a).is_empty());
        assert_eq!(manager.get_segments_for_port(port_b).len(), 1);

        // Channels and management segments are untouched by data-segment reaping.
        assert_eq!(manager.channel_count(), 1);
        assert_eq!(manager.mgmt_segment_count(), 1);
        assert!(manager
            .get_channel_handle_for_consumer(port_a, 0x1, session)
            .is_some());
        assert!(manager
            .get_mgmt_segment_handle_for_consumer(port_a, session)
            .is_some());
    }

    #[test]
    fn test_remove_all_segments_for_port_skips_gap_sentinel() {
        let mut manager = SegmentManager::new();
        let port_id: u128 = 0x1234;

        // Registering a runtime segment at index 2 leaves gap sentinels (255) at indices 0 and 1.
        let seg = manager
            .register_dynamic_segment_for_port(
                port_id,
                2,
                create_test_handle(),
                4096,
                AccessRights::read_only(),
            )
            .unwrap();
        let segments = manager.get_segments_for_port(port_id);
        assert_eq!(segments.len(), 3);
        assert_eq!(segments[0].value(), 255);
        assert_eq!(segments[1].value(), 255);
        assert_eq!(segments[2].value(), seg.value());

        // Reaping must skip the 255 gap markers and only remove the real segment.
        manager.remove_all_segments_for_port(port_id);
        assert_eq!(manager.segment_count(), 0);
        assert!(!manager.has_segment(seg));
        assert!(manager.get_segments_for_port(port_id).is_empty());
    }

    #[test]
    fn test_remove_all_segments_for_unknown_port_is_noop() {
        let mut manager = SegmentManager::new();
        // No panic and no state change when the port has no segments.
        manager.remove_all_segments_for_port(0xDEAD);
        assert_eq!(manager.segment_count(), 0);
    }

    // ========================================================================
    // Segment-Id Sentinel Tests (F3/F4 — 255 is the gap sentinel, never a real id)
    // ========================================================================

    #[test]
    fn test_allocate_segment_id_never_returns_255_across_wrap() {
        let mut manager = SegmentManager::new();
        // Drive the monotonic counter right up to the wrap point so the sequence crosses 255.
        manager.next_id = 250;

        let mut allocated = Vec::new();
        for _ in 0..12 {
            let id = manager.allocate_segment_id().unwrap();
            // 255 is the reserved gap sentinel and must never be handed out.
            assert_ne!(id.value(), 255);
            allocated.push(id.value());
        }

        // The sequence crosses the wrap point: 250..=254, then 255 AND 0 are SKIPPED, then 1, 2...
        assert_eq!(allocated, vec![250, 251, 252, 253, 254, 1, 2, 3, 4, 5, 6, 7]);
    }

    // R2: neither reserved id (0 or 255) may ever be handed out across a full wrap of the id
    // space. 0 is reserved because the initial dynamic segment occupies each port's fixed
    // port_segments index 0; a growth segment handed id 0 would overwrite that slot and a fresh
    // consumer requesting index 0 would map the wrong-sized segment and read out of bounds.
    #[test]
    fn test_allocate_segment_id_never_returns_0_or_255_across_full_wrap() {
        let mut manager = SegmentManager::new();
        manager.next_id = 0;

        // A full wrap yields exactly the 254 usable ids 1..=254, each exactly once, never 0/255.
        let mut allocated = Vec::new();
        loop {
            let id = manager
                .allocate_segment_id()
                .expect("254 ids must be allocatable before exhaustion");
            assert_ne!(id.value(), 0, "id 0 is reserved for the initial-segment slot");
            assert_ne!(id.value(), 255, "id 255 is the reserved gap sentinel");
            // Occupy the id so the allocator advances and eventually exhausts.
            manager.segments.insert(
                id.value(),
                ManagedSegment::new(id, create_test_handle(), 4096, AccessRights::read_write()),
            );
            allocated.push(id.value());
            if allocated.len() == 254 {
                break;
            }
        }
        allocated.sort_unstable();
        let expected: Vec<u8> = (1..=254).collect();
        assert_eq!(allocated, expected);

        // With all 254 usable ids occupied the allocator reports exhaustion rather than looping
        // forever or returning a reserved value.
        assert!(matches!(
            manager.allocate_segment_id(),
            Err(IamServerError::ResourceLimitExceeded)
        ));
    }

    // R2: a growth segment can never overwrite a port's initial (index-0) slot, because growth
    // ids are drawn from 1..=254 and the initial always lives at the fixed index 0. This models
    // the server placement: initial via register_dynamic_segment_for_port(_, 0), growth via
    // associate_segment_with_port_at_index(seg, _, seg.value()).
    #[test]
    fn test_growth_segment_never_overwrites_initial_index_0_slot() {
        let mut manager = SegmentManager::new();
        let port_id: u128 = 0xC0FFEE;
        let session = SessionId::from_value(7);

        // Register the initial dynamic segment at index 0.
        let initial = manager
            .register_dynamic_segment_for_port(
                port_id,
                0,
                create_test_handle(),
                4096,
                AccessRights::read_only(),
            )
            .unwrap();
        assert_ne!(initial.value(), 0, "initial's global id is reserved-0-free (>=1)");

        // Drive the global counter across the wrap point and place many growth segments at
        // index == their global id. No growth id is ever 0, so index 0 is never targeted.
        manager.next_id = 250;
        for _ in 0..20 {
            let seg = manager
                .register_segment(create_test_handle(), 4096, AccessRights::read_write())
                .unwrap();
            assert_ne!(seg.value(), 0, "growth ids must never be 0");
            manager
                .associate_segment_with_port_at_index(seg, port_id, seg.value())
                .unwrap();
        }

        // The initial's slot at index 0 is intact and still resolves to the initial's handle.
        let segments = manager.get_segments_for_port(port_id);
        assert_eq!(segments[0].value(), initial.value());
        let (info, _handle) = manager
            .get_dynamic_segment_handle(port_id, 0, session)
            .expect("index 0 must still resolve to the initial segment");
        assert_eq!(info.segment_id().value(), initial.value());
    }

    #[test]
    fn test_register_segment_skips_255_across_wrap() {
        let mut manager = SegmentManager::new();
        manager.next_id = 252;

        // register_segment allocates through allocate_segment_id, so real registrations must also
        // skip 255 (and 0) while crossing the wrap point.
        let mut ids = Vec::new();
        for _ in 0..6 {
            let id = manager
                .register_segment(create_test_handle(), 4096, AccessRights::read_write())
                .unwrap();
            assert_ne!(id.value(), 255, "255 is reserved and must never be allocated");
            assert_ne!(id.value(), 0, "0 is reserved and must never be allocated");
            ids.push(id.value());
        }
        // 252, 253, 254, (255 skipped), (0 skipped), 1, 2, 3
        assert_eq!(ids, vec![252, 253, 254, 1, 2, 3]);
    }

    #[test]
    fn test_get_dynamic_segment_handle_round_trips_high_id_254() {
        let mut manager = SegmentManager::new();
        let port_id: u128 = 0x2A;
        let session = SessionId::from_value(1);

        // Force the next allocated id to 254 — the highest usable id, one below the sentinel.
        manager.next_id = 254;
        let seg = manager
            .register_dynamic_segment_for_port(
                port_id,
                254,
                create_test_handle(),
                4096,
                AccessRights::read_only(),
            )
            .unwrap();
        assert_eq!(seg.value(), 254);

        // A real id-254 segment must round-trip (it is NOT the sentinel 255, so it is not
        // silently rejected as a gap placeholder).
        let (info, _handle) = manager
            .get_dynamic_segment_handle(port_id, 254, session)
            .expect("a real id-254 segment must resolve to a handle");
        assert_eq!(info.segment_id().value(), 254);
    }

    // ========================================================================
    // Send Tests
    // ========================================================================

    #[test]
    fn test_manager_is_send() {
        fn assert_send<T: Send>() {}
        assert_send::<SegmentManager>();
    }

    #[test]
    fn test_managed_segment_is_send() {
        fn assert_send<T: Send>() {}
        assert_send::<ManagedSegment>();
    }
}
