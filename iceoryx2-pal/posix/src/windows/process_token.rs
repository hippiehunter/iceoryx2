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

//! Windows process token impersonation and SID extraction.
//!
//! This module provides safe abstractions for extracting Windows Security Identifiers (SIDs)
//! from named pipe client connections via token impersonation.
//!
//! # Overview
//!
//! On Windows, user and group identity is represented by Security Identifiers (SIDs) rather
//! than numeric UIDs/GIDs as on Unix systems. To obtain the SIDs of a connected named pipe
//! client, the server must:
//!
//! 1. Impersonate the client using `ImpersonateNamedPipeClient`
//! 2. Open the impersonation token with `OpenThreadToken`
//! 3. Query the token for `TokenUser` and `TokenGroups` information
//! 4. Revert to self using `RevertToSelf`
//!
//! # Safety
//!
//! This module uses RAII patterns to ensure impersonation is always properly reverted.
//! The [`ImpersonationGuard`] struct panics if `RevertToSelf` fails, as leaving a thread
//! impersonating another user is a critical security violation.
//!
//! # Example
//!
//! ```ignore
//! use iceoryx2_pal_posix::windows::process_token::get_client_token_sids;
//!
//! // After accepting a named pipe connection...
//! let sids = get_client_token_sids(pipe_handle)?;
//! println!("User SID: {:?}", sids.user_sid.as_bytes());
//! for group in &sids.group_sids {
//!     println!("Group SID: {:?}", group.as_bytes());
//! }
//! ```

#![cfg(windows)]
#![allow(non_camel_case_types)]
#![allow(clippy::missing_safety_doc)]

use core::fmt::{self, Display, Formatter};
use core::hash::Hash;

use super::security_descriptor::Sid;

// Windows API imports
use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, ERROR_ACCESS_DENIED, ERROR_INVALID_HANDLE, ERROR_NO_TOKEN, FALSE,
    HANDLE,
};

use windows_sys::Win32::Security::{
    GetTokenInformation, ImpersonateNamedPipeClient, RevertToSelf, TokenGroups, TokenUser,
    SID_AND_ATTRIBUTES, TOKEN_GROUPS, TOKEN_QUERY, TOKEN_USER,
};

use windows_sys::Win32::System::Threading::{GetCurrentThread, OpenThreadToken};

use alloc::vec::Vec;

extern crate alloc;

// ============================================================================
// Error Types
// ============================================================================

/// Errors that can occur during token operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TokenError {
    /// Failed to impersonate the named pipe client.
    ImpersonationFailed,
    /// Failed to revert impersonation (critical security error).
    RevertFailed,
    /// Failed to open the thread token.
    OpenTokenFailed,
    /// Failed to get token information.
    GetTokenInfoFailed,
    /// The token user information is invalid.
    InvalidTokenUser,
    /// An internal Windows error occurred.
    InternalError(u32),
}

impl TokenError {
    /// Converts a Win32 error code to a [`TokenError`].
    pub fn from_win32(error_code: u32) -> Self {
        match error_code {
            ERROR_ACCESS_DENIED => TokenError::OpenTokenFailed,
            ERROR_INVALID_HANDLE => TokenError::OpenTokenFailed,
            ERROR_NO_TOKEN => TokenError::OpenTokenFailed,
            _ => TokenError::InternalError(error_code),
        }
    }
}

impl Display for TokenError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            TokenError::ImpersonationFailed => {
                write!(f, "Failed to impersonate named pipe client")
            }
            TokenError::RevertFailed => {
                write!(
                    f,
                    "Failed to revert impersonation (critical security error)"
                )
            }
            TokenError::OpenTokenFailed => {
                write!(f, "Failed to open thread token")
            }
            TokenError::GetTokenInfoFailed => {
                write!(f, "Failed to get token information")
            }
            TokenError::InvalidTokenUser => {
                write!(f, "Invalid token user information")
            }
            TokenError::InternalError(code) => {
                write!(f, "Internal error (code: {})", code)
            }
        }
    }
}

impl core::error::Error for TokenError {}

// ============================================================================
// ImpersonationGuard
// ============================================================================

/// RAII guard ensuring `RevertToSelf()` is always called.
///
/// This guard is created when impersonating a named pipe client and ensures
/// that the impersonation is properly reverted when the guard is dropped.
///
/// # Panics
///
/// If `RevertToSelf()` fails during drop, this guard will panic. This is
/// intentional as leaving a thread impersonating another user is a critical
/// security violation that could lead to privilege escalation vulnerabilities.
///
/// # Example
///
/// ```ignore
/// let _guard = ImpersonationGuard::impersonate(pipe_handle)?;
/// // Thread is now impersonating the pipe client
/// // ... do work with client's credentials ...
/// // Guard is dropped here, RevertToSelf is called automatically
/// ```
pub struct ImpersonationGuard {
    /// Whether impersonation is currently active.
    active: bool,
}

impl ImpersonationGuard {
    /// Creates a new impersonation guard by impersonating the named pipe client.
    ///
    /// # Arguments
    /// * `pipe_handle` - Handle to a connected named pipe instance
    ///
    /// # Returns
    /// * `Ok(ImpersonationGuard)` - Successfully impersonating the client
    /// * `Err(TokenError::ImpersonationFailed)` - Failed to impersonate
    ///
    /// # Safety
    ///
    /// The pipe handle must be valid and connected to a client.
    pub fn impersonate(pipe_handle: HANDLE) -> Result<Self, TokenError> {
        // SAFETY: ImpersonateNamedPipeClient is called with a valid pipe handle.
        // The function will fail if the handle is invalid or not connected.
        let result = unsafe { ImpersonateNamedPipeClient(pipe_handle) };

        if result == FALSE {
            let error = unsafe { GetLastError() };
            return Err(TokenError::InternalError(error));
        }

        Ok(Self { active: true })
    }

    /// Manually reverts the impersonation.
    ///
    /// This can be called to revert impersonation before the guard is dropped.
    /// Subsequent calls have no effect.
    ///
    /// # Returns
    /// * `Ok(())` - Successfully reverted or already inactive
    /// * `Err(TokenError::RevertFailed)` - Failed to revert (critical error)
    pub fn revert(&mut self) -> Result<(), TokenError> {
        if !self.active {
            return Ok(());
        }

        // SAFETY: RevertToSelf reverts the impersonation context of the calling thread.
        let result = unsafe { RevertToSelf() };

        if result == FALSE {
            return Err(TokenError::RevertFailed);
        }

        self.active = false;
        Ok(())
    }
}

impl Drop for ImpersonationGuard {
    fn drop(&mut self) {
        if self.active {
            // SAFETY: RevertToSelf is safe to call and reverts impersonation.
            let result = unsafe { RevertToSelf() };

            if result == FALSE {
                // PANIC: Failing to revert impersonation is a critical security error.
                // The thread would continue running with elevated/different privileges,
                // which could lead to privilege escalation vulnerabilities.
                panic!(
                    "CRITICAL SECURITY ERROR: RevertToSelf() failed with error {}. \
                     Thread remains impersonating another user!",
                    unsafe { GetLastError() }
                );
            }
        }
    }
}

// ============================================================================
// TokenSids
// ============================================================================

/// Combined user and group SIDs extracted from a token.
///
/// This struct contains the identity information extracted from a Windows
/// access token, including the user's SID and all group SIDs the user belongs to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenSids {
    /// The user's Security Identifier.
    pub user_sid: Sid,
    /// The group SIDs the user belongs to.
    pub group_sids: Vec<Sid>,
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Copies a SID from a raw pointer.
///
/// # Safety
///
/// The `psid` pointer must be a valid pointer to a SID structure.
unsafe fn copy_sid_from_ptr(psid: *const core::ffi::c_void) -> Option<Sid> {
    if psid.is_null() {
        return None;
    }

    // Validate the SID before dereferencing
    use windows_sys::Win32::Security::{GetLengthSid, IsValidSid};

    // SAFETY: IsValidSid validates that the memory pointed to by psid
    // contains a properly formatted SID structure before we read from it.
    if IsValidSid(psid) == FALSE {
        return None;
    }

    // SAFETY: GetLengthSid is safe because we validated the SID above.
    let sid_len = GetLengthSid(psid) as usize;

    if sid_len == 0 {
        return None;
    }

    // SAFETY: We validated the SID is well-formed, so reading sid_len bytes is safe.
    let sid_bytes = core::slice::from_raw_parts(psid as *const u8, sid_len);
    Some(Sid::from_bytes(sid_bytes))
}

/// Opens the thread token for the current thread.
///
/// # Returns
/// * `Ok(HANDLE)` - The token handle (caller must close it)
/// * `Err(TokenError)` - Failed to open the token
fn open_thread_token() -> Result<HANDLE, TokenError> {
    let mut token_handle: HANDLE = 0;

    // SAFETY: GetCurrentThread returns a pseudo-handle that is always valid.
    // OpenThreadToken opens the token of the current thread.
    let result = unsafe {
        OpenThreadToken(
            GetCurrentThread(),
            TOKEN_QUERY,
            FALSE, // Use impersonation context, not process context
            &mut token_handle,
        )
    };

    if result == FALSE {
        let error = unsafe { GetLastError() };
        return Err(TokenError::from_win32(error));
    }

    Ok(token_handle)
}

/// Extracts the user SID from a token.
///
/// # Arguments
/// * `token_handle` - Handle to an access token
///
/// # Returns
/// * `Ok(Sid)` - The user's SID
/// * `Err(TokenError)` - Failed to extract the SID
fn get_token_user(token_handle: HANDLE) -> Result<Sid, TokenError> {
    // First call to get the required buffer size
    let mut return_length: u32 = 0;

    // SAFETY: GetTokenInformation with NULL buffer returns required size.
    let _ = unsafe {
        GetTokenInformation(
            token_handle,
            TokenUser,
            core::ptr::null_mut(),
            0,
            &mut return_length,
        )
    };

    if return_length == 0 {
        return Err(TokenError::GetTokenInfoFailed);
    }

    // Allocate buffer with proper alignment for TOKEN_USER.
    // TOKEN_USER contains pointers, so it requires pointer alignment (8 bytes on x64).
    // Vec<u64> provides natural 8-byte alignment.
    let num_u64s = (return_length as usize + 7) / 8;
    let mut buffer: Vec<u64> = vec![0u64; num_u64s];
    let buffer_ptr = buffer.as_mut_ptr() as *mut u8;

    // SAFETY: GetTokenInformation is called with a properly sized and aligned buffer.
    let result = unsafe {
        GetTokenInformation(
            token_handle,
            TokenUser,
            buffer_ptr as *mut _,
            return_length,
            &mut return_length,
        )
    };

    if result == FALSE {
        return Err(TokenError::GetTokenInfoFailed);
    }

    // SAFETY: The buffer now contains a valid TOKEN_USER structure with proper alignment.
    let token_user = unsafe { &*(buffer_ptr as *const TOKEN_USER) };

    // SAFETY: token_user.User.Sid is a valid PSID if GetTokenInformation succeeded.
    unsafe { copy_sid_from_ptr(token_user.User.Sid) }.ok_or(TokenError::InvalidTokenUser)
}

/// Extracts the group SIDs from a token.
///
/// # Arguments
/// * `token_handle` - Handle to an access token
///
/// # Returns
/// * `Ok(Vec<Sid>)` - The group SIDs
/// * `Err(TokenError)` - Failed to extract the SIDs
fn get_token_groups(token_handle: HANDLE) -> Result<Vec<Sid>, TokenError> {
    // First call to get the required buffer size
    let mut return_length: u32 = 0;

    // SAFETY: GetTokenInformation with NULL buffer returns required size.
    let _ = unsafe {
        GetTokenInformation(
            token_handle,
            TokenGroups,
            core::ptr::null_mut(),
            0,
            &mut return_length,
        )
    };

    if return_length == 0 {
        // No groups is valid, return empty vec
        return Ok(Vec::new());
    }

    // Allocate buffer with proper alignment for TOKEN_GROUPS.
    // TOKEN_GROUPS contains pointers, so it requires pointer alignment (8 bytes on x64).
    // Vec<u64> provides natural 8-byte alignment.
    let num_u64s = (return_length as usize + 7) / 8;
    let mut buffer: Vec<u64> = vec![0u64; num_u64s];
    let buffer_ptr = buffer.as_mut_ptr() as *mut u8;

    // SAFETY: GetTokenInformation is called with a properly sized and aligned buffer.
    let result = unsafe {
        GetTokenInformation(
            token_handle,
            TokenGroups,
            buffer_ptr as *mut _,
            return_length,
            &mut return_length,
        )
    };

    if result == FALSE {
        return Err(TokenError::GetTokenInfoFailed);
    }

    // SAFETY: The buffer now contains a valid TOKEN_GROUPS structure with proper alignment.
    let token_groups = unsafe { &*(buffer_ptr as *const TOKEN_GROUPS) };

    let group_count = token_groups.GroupCount as usize;

    // Verify buffer is large enough for the flexible array.
    // TOKEN_GROUPS has a fixed header with GroupCount and one SID_AND_ATTRIBUTES element,
    // plus additional elements for groups beyond the first.
    let expected_size = core::mem::size_of::<TOKEN_GROUPS>()
        + group_count.saturating_sub(1) * core::mem::size_of::<SID_AND_ATTRIBUTES>();
    if (return_length as usize) < expected_size {
        return Err(TokenError::GetTokenInfoFailed);
    }

    let mut groups = Vec::with_capacity(group_count);

    if group_count > 0 {
        // SAFETY: Groups is a flexible array member, we access GroupCount elements.
        // We verified above that the buffer is large enough for all elements.
        let groups_ptr = token_groups.Groups.as_ptr();

        for i in 0..group_count {
            // SAFETY: We're accessing elements within the valid range (verified above).
            let group: &SID_AND_ATTRIBUTES = unsafe { &*groups_ptr.add(i) };

            // SAFETY: group.Sid is a valid PSID if GetTokenInformation succeeded.
            if let Some(sid) = unsafe { copy_sid_from_ptr(group.Sid) } {
                groups.push(sid);
            }
        }
    }

    Ok(groups)
}

// ============================================================================
// Public API
// ============================================================================

/// Extracts client's user and group SIDs from a named pipe via impersonation.
///
/// This function:
/// 1. Impersonates the connected named pipe client
/// 2. Opens the impersonation token
/// 3. Extracts the user SID (TokenUser)
/// 4. Extracts the group SIDs (TokenGroups)
/// 5. Reverts to self (automatically via RAII guard)
///
/// # Arguments
/// * `pipe_handle` - Handle to a connected named pipe instance
///
/// # Returns
/// * `Ok(TokenSids)` - The extracted user and group SIDs
/// * `Err(TokenError)` - If any step fails
///
/// # Safety
///
/// The pipe handle must be valid and connected to a client. The function uses
/// RAII to ensure impersonation is always properly reverted.
///
/// # Example
///
/// ```ignore
/// use iceoryx2_pal_posix::windows::process_token::get_client_token_sids;
///
/// // After accepting a connection on a named pipe...
/// match get_client_token_sids(pipe_handle) {
///     Ok(sids) => {
///         println!("Client user SID: {} bytes", sids.user_sid.as_bytes().len());
///         println!("Client belongs to {} groups", sids.group_sids.len());
///     }
///     Err(e) => eprintln!("Failed to get client SIDs: {}", e),
/// }
/// ```
pub fn get_client_token_sids(pipe_handle: HANDLE) -> Result<TokenSids, TokenError> {
    // Create impersonation guard - this impersonates the client
    let mut guard = ImpersonationGuard::impersonate(pipe_handle)?;

    // Open the thread token (now impersonating the client)
    let token_handle = match open_thread_token() {
        Ok(h) => h,
        Err(e) => {
            // Ensure we revert before returning
            let _ = guard.revert();
            return Err(e);
        }
    };

    // Use scopeguard pattern to ensure token handle is closed
    struct TokenGuard(HANDLE);
    impl Drop for TokenGuard {
        fn drop(&mut self) {
            if self.0 != 0 {
                // SAFETY: CloseHandle is safe with a valid handle.
                unsafe { CloseHandle(self.0) };
            }
        }
    }
    let _token_guard = TokenGuard(token_handle);

    // Extract user SID
    let user_sid = match get_token_user(token_handle) {
        Ok(sid) => sid,
        Err(e) => {
            let _ = guard.revert();
            return Err(e);
        }
    };

    // Extract group SIDs
    let group_sids = match get_token_groups(token_handle) {
        Ok(sids) => sids,
        Err(e) => {
            let _ = guard.revert();
            return Err(e);
        }
    };

    // Explicitly revert impersonation (guard will also do this in drop)
    guard.revert()?;

    Ok(TokenSids {
        user_sid,
        group_sids,
    })
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_token_error_display() {
        assert_eq!(
            format!("{}", TokenError::ImpersonationFailed),
            "Failed to impersonate named pipe client"
        );
        assert_eq!(
            format!("{}", TokenError::RevertFailed),
            "Failed to revert impersonation (critical security error)"
        );
        assert_eq!(
            format!("{}", TokenError::OpenTokenFailed),
            "Failed to open thread token"
        );
        assert_eq!(
            format!("{}", TokenError::GetTokenInfoFailed),
            "Failed to get token information"
        );
        assert_eq!(
            format!("{}", TokenError::InvalidTokenUser),
            "Invalid token user information"
        );
        assert_eq!(
            format!("{}", TokenError::InternalError(42)),
            "Internal error (code: 42)"
        );
    }

    #[test]
    fn test_token_error_traits() {
        // Test Clone
        let error = TokenError::ImpersonationFailed;
        let cloned = error.clone();
        assert_eq!(error, cloned);

        // Test Copy
        let copied = error;
        assert_eq!(error, copied);

        // Test Hash
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(TokenError::ImpersonationFailed);
        set.insert(TokenError::RevertFailed);
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn test_token_error_from_win32() {
        assert_eq!(
            TokenError::from_win32(ERROR_ACCESS_DENIED),
            TokenError::OpenTokenFailed
        );
        assert_eq!(
            TokenError::from_win32(ERROR_INVALID_HANDLE),
            TokenError::OpenTokenFailed
        );
        assert_eq!(
            TokenError::from_win32(ERROR_NO_TOKEN),
            TokenError::OpenTokenFailed
        );
        assert_eq!(
            TokenError::from_win32(12345),
            TokenError::InternalError(12345)
        );
    }

    #[test]
    fn test_token_sids_clone_and_eq() {
        let sids1 = TokenSids {
            user_sid: Sid::everyone(),
            group_sids: vec![Sid::local_system()],
        };

        let sids2 = sids1.clone();
        assert_eq!(sids1, sids2);
    }

    #[test]
    fn test_impersonation_guard_revert_when_not_active() {
        // Create a guard that is not active
        let mut guard = ImpersonationGuard { active: false };

        // Revert should succeed immediately
        assert!(guard.revert().is_ok());
    }

    // NOTE: Integration tests requiring actual named pipe connections are
    // located in the integration test suite. Tests for impersonation,
    // token extraction, and SID retrieval require:
    // - A named pipe server accepting connections
    // - A client connecting from a different security context
    // - Running on Windows with appropriate privileges
}
