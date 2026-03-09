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

    /// Allocates the next available segment ID.
    ///
    /// This handles wrapping and checking for ID collisions.
    pub fn allocate_segment_id(&mut self) -> Result<SegmentId, IamServerError> {
        let start_id = self.next_id;

        loop {
            let candidate = SegmentId::new(self.next_id);
            self.next_id = self.next_id.wrapping_add(1);

            // If this ID is not in use, we can use it
            if !self.segments.contains_key(&candidate.value()) {
                return Ok(candidate);
            }

            // If we've wrapped around completely, we're out of IDs
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
        let info = SegmentInfo::new(
            SegmentId::new(segment_id_key),
            segment.size,
            segment.access,
        );
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
        let info = SegmentInfo::new(
            SegmentId::new(segment_id_key),
            segment.size,
            segment.access,
        );
        Some((info, handle))
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
        self.segments.get(&segment_id.value()).map(|s| s.to_segment_info())
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
        let raw_fd = unsafe {
            iceoryx2_pal_posix::posix::dup(std::io::stdout().as_raw_fd())
        };
        unsafe { PlatformHandle::from_raw_fd(raw_fd) }
    }

    #[cfg(windows)]
    fn create_test_handle() -> PlatformHandle {
        use std::os::windows::io::FromRawHandle;
        use std::os::windows::io::AsRawHandle;
        let raw_handle = std::io::stdout().as_raw_handle();
        let mut dup_handle = std::ptr::null_mut();
        unsafe {
            let current_process = windows_sys::Win32::System::Threading::GetCurrentProcess();
            windows_sys::Win32::Foundation::DuplicateHandle(
                current_process,
                raw_handle as *mut _,
                current_process,
                &mut dup_handle,
                0,
                0,
                windows_sys::Win32::Foundation::DUPLICATE_SAME_ACCESS,
            );
            PlatformHandle::from_raw_handle(dup_handle)
        }
    }

    // ========================================================================
    // ManagedSegment Tests
    // ========================================================================

    #[test]
    fn test_managed_segment_new() {
        let handle = create_test_handle();
        let segment = ManagedSegment::new(SegmentId::new(0), handle, 4096, AccessRights::read_write());

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
        let segment = ManagedSegment::new(SegmentId::new(5), handle, 8192, AccessRights::read_only());

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
            assert_eq!(segment_id.value(), i as u8);
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

        // Create and remove segment 0
        let handle1 = create_test_handle();
        let segment0 = manager
            .register_segment(handle1, 4096, AccessRights::read_write())
            .unwrap();
        assert_eq!(segment0.value(), 0);
        manager.remove_segment(segment0);

        // Create more segments - should get 1, 2, etc.
        let handle2 = create_test_handle();
        let segment1 = manager
            .register_segment(handle2, 4096, AccessRights::read_write())
            .unwrap();
        assert_eq!(segment1.value(), 1);

        // If we remove segment1 and create another, next_id continues
        manager.remove_segment(segment1);
        let handle3 = create_test_handle();
        let segment2 = manager
            .register_segment(handle3, 4096, AccessRights::read_write())
            .unwrap();
        assert_eq!(segment2.value(), 2);
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
