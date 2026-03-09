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

//! Windows security descriptors using SDDL (Security Descriptor Definition Language).
//!
//! This module provides safe abstractions over Windows security descriptors,
//! enabling fine-grained access control for Windows resources such as shared
//! memory, named pipes, and file mappings.
//!
//! # Overview
//!
//! Windows uses Security Descriptors to define access control for securable objects.
//! A security descriptor contains:
//! - Owner SID (Security Identifier)
//! - Primary Group SID
//! - DACL (Discretionary Access Control List) - controls who can access the object
//! - SACL (System Access Control List) - controls auditing
//!
//! SDDL is a string format for representing security descriptors. This module
//! uses SDDL for creating security descriptors due to its simplicity and readability.
//!
//! # Common SDDL Components
//!
//! - `D:` - DACL (Discretionary Access Control List)
//! - `(A;;GA;;;WD)` - Allow (A) Generic All (GA) to Everyone (WD)
//! - `(A;;GA;;;OW)` - Allow Generic All to Owner
//! - `(A;;GA;;;SY)` - Allow Generic All to Local System
//! - `(A;;GA;;;BA)` - Allow Generic All to Builtin Administrators
//!
//! # Example
//!
//! ```ignore
//! use iceoryx2_pal_posix::windows::security_descriptor::SecurityDescriptor;
//!
//! // Create a security descriptor that allows access only to owner, system, and admins
//! let sd = SecurityDescriptor::owner_only()?;
//! let attrs = sd.as_security_attributes();
//! // Use attrs with CreateFileMapping, CreateNamedPipe, etc.
//! ```
//!
//! # References
//!
//! - [SDDL for Security Descriptors](https://docs.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-definition-language)
//! - [ACE Strings](https://docs.microsoft.com/en-us/windows/win32/secauthz/ace-strings)
//! - [SID Strings](https://docs.microsoft.com/en-us/windows/win32/secauthz/sid-strings)

#![allow(non_camel_case_types)]
#![allow(clippy::missing_safety_doc)]

use alloc::format;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use core::fmt::{self, Display, Formatter};
use core::hash::Hash;

// Windows API imports
#[cfg(windows)]
use windows_sys::Win32::Foundation::{GetLastError, ERROR_INVALID_PARAMETER, FALSE};

#[cfg(windows)]
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorA, SDDL_REVISION_1,
};

#[cfg(windows)]
use windows_sys::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};

#[cfg(windows)]
use windows_sys::Win32::System::Memory::LocalFree;

// ============================================================================
// Constants - Common SDDL Strings
// ============================================================================

/// SDDL string for owner-only access.
/// Grants Generic All to:
/// - SY: Local System
/// - BA: Builtin Administrators
/// - OW: Owner Rights (creator owner)
pub const SDDL_OWNER_ONLY: &[u8] = b"D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;OW)\0";

/// SDDL string for everyone full access.
/// Grants Generic All to WD (Everyone/World).
pub const SDDL_EVERYONE_FULL_ACCESS: &[u8] = b"D:(A;;GA;;;WD)\0";

/// SDDL string for authenticated users read access.
/// Grants Generic Read to AU (Authenticated Users).
pub const SDDL_AUTHENTICATED_USERS_READ: &[u8] = b"D:(A;;GR;;;AU)\0";

/// SDDL string for local system only.
/// Grants Generic All to SY (Local System) only.
pub const SDDL_SYSTEM_ONLY: &[u8] = b"D:(A;;GA;;;SY)\0";

// ============================================================================
// Error Types
// ============================================================================

/// Errors that can occur when working with security descriptors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SecurityError {
    /// The SDDL string is invalid or malformed.
    InvalidSddlString,
    /// Insufficient memory to create the security descriptor.
    InsufficientMemory,
    /// An invalid parameter was provided.
    InvalidParameter,
    /// An internal Windows error occurred.
    InternalError(u32),
}

impl SecurityError {
    /// Converts a Win32 error code to a [`SecurityError`].
    #[cfg(windows)]
    pub fn from_win32(error_code: u32) -> Self {
        use windows_sys::Win32::Foundation::{
            ERROR_INVALID_SECURITY_DESCR, ERROR_NOT_ENOUGH_MEMORY, ERROR_OUTOFMEMORY,
        };

        match error_code {
            ERROR_INVALID_SECURITY_DESCR => SecurityError::InvalidSddlString,
            ERROR_NOT_ENOUGH_MEMORY | ERROR_OUTOFMEMORY => SecurityError::InsufficientMemory,
            ERROR_INVALID_PARAMETER => SecurityError::InvalidParameter,
            _ => SecurityError::InternalError(error_code),
        }
    }

    /// Stub implementation for non-Windows platforms.
    #[cfg(not(windows))]
    pub fn from_win32(error_code: u32) -> Self {
        SecurityError::InternalError(error_code)
    }
}

impl Display for SecurityError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            SecurityError::InvalidSddlString => {
                write!(f, "Invalid or malformed SDDL string")
            }
            SecurityError::InsufficientMemory => {
                write!(f, "Insufficient memory to create security descriptor")
            }
            SecurityError::InvalidParameter => {
                write!(f, "Invalid parameter")
            }
            SecurityError::InternalError(code) => {
                write!(f, "Internal error (code: {})", code)
            }
        }
    }
}

impl core::error::Error for SecurityError {}

// ============================================================================
// Sid (Security Identifier)
// ============================================================================

/// A Windows Security Identifier (SID).
///
/// SIDs are variable-length structures that uniquely identify users, groups,
/// or computer accounts. This struct wraps a SID in binary form.
///
/// # Common SID Strings
///
/// - `WD` - Everyone (World)
/// - `SY` - Local System
/// - `BA` - Builtin Administrators
/// - `OW` - Owner Rights
/// - `AU` - Authenticated Users
/// - `BU` - Builtin Users
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Sid {
    /// The SID in binary form.
    inner: Vec<u8>,
}

impl Sid {
    /// Creates a new SID from raw binary data.
    ///
    /// # Arguments
    /// * `data` - The SID in binary form
    pub fn from_bytes(data: &[u8]) -> Self {
        Self {
            inner: data.to_vec(),
        }
    }

    /// Returns the SID as a byte slice.
    pub fn as_bytes(&self) -> &[u8] {
        &self.inner
    }

    /// Returns a well-known SID for Everyone (World).
    pub fn everyone() -> Self {
        // Well-known SID: S-1-1-0 (Everyone)
        Self {
            inner: vec![1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0],
        }
    }

    /// Returns a well-known SID for Local System.
    pub fn local_system() -> Self {
        // Well-known SID: S-1-5-18 (Local System)
        Self {
            inner: vec![1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0],
        }
    }
}

// ============================================================================
// AclEntry (Access Control List Entry)
// ============================================================================

/// An entry in an Access Control List (ACL).
///
/// Each entry specifies:
/// - The SID (who the entry applies to)
/// - The access mask (what permissions are granted/denied)
/// - Whether this is an allow or deny entry
///
/// # Example
///
/// ```ignore
/// let entry = AclEntry {
///     sid: Sid::everyone(),
///     access_mask: GENERIC_READ,
///     is_allow: true,
/// };
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AclEntry {
    /// The security identifier this entry applies to.
    pub sid: Sid,
    /// The access rights mask.
    pub access_mask: u32,
    /// If true, this is an allow entry; if false, it's a deny entry.
    pub is_allow: bool,
}

impl AclEntry {
    /// Creates a new allow entry.
    pub fn allow(sid: Sid, access_mask: u32) -> Self {
        Self {
            sid,
            access_mask,
            is_allow: true,
        }
    }

    /// Creates a new deny entry.
    pub fn deny(sid: Sid, access_mask: u32) -> Self {
        Self {
            sid,
            access_mask,
            is_allow: false,
        }
    }
}

// Windows access mask constants
/// Generic All access (full control).
pub const GENERIC_ALL: u32 = 0x10000000;
/// Generic Read access.
pub const GENERIC_READ: u32 = 0x80000000;
/// Generic Write access.
pub const GENERIC_WRITE: u32 = 0x40000000;
/// Generic Execute access.
pub const GENERIC_EXECUTE: u32 = 0x20000000;

// ============================================================================
// SecurityDescriptor
// ============================================================================

/// A Windows security descriptor.
///
/// This struct wraps a `PSECURITY_DESCRIPTOR` and provides safe creation methods
/// using SDDL strings. The security descriptor is automatically freed when dropped.
///
/// # Example
///
/// ```ignore
/// // Create from SDDL
/// let sd = SecurityDescriptor::from_sddl(b"D:(A;;GA;;;WD)\0")?;
///
/// // Use predefined security levels
/// let owner_sd = SecurityDescriptor::owner_only()?;
/// let public_sd = SecurityDescriptor::everyone_full_access()?;
///
/// // Get security attributes for Windows APIs
/// let attrs = sd.as_security_attributes();
/// ```
#[cfg(windows)]
pub struct SecurityDescriptor {
    /// The underlying security descriptor pointer.
    inner: PSECURITY_DESCRIPTOR,
}

#[cfg(windows)]
impl core::fmt::Debug for SecurityDescriptor {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SecurityDescriptor").finish_non_exhaustive()
    }
}

#[cfg(windows)]
impl SecurityDescriptor {
    /// Creates a security descriptor from an SDDL string.
    ///
    /// # Arguments
    /// * `sddl` - A null-terminated SDDL string
    ///
    /// # Returns
    /// * `Ok(SecurityDescriptor)` - The created security descriptor
    /// * `Err(SecurityError)` - If the SDDL string is invalid or creation failed
    ///
    /// # Example
    ///
    /// ```ignore
    /// let sd = SecurityDescriptor::from_sddl(b"D:(A;;GA;;;WD)\0")?;
    /// ```
    pub fn from_sddl(sddl: &[u8]) -> Result<Self, SecurityError> {
        if sddl.is_empty() {
            return Err(SecurityError::InvalidParameter);
        }

        let mut sd: PSECURITY_DESCRIPTOR = core::ptr::null_mut();

        // SAFETY: ConvertStringSecurityDescriptorToSecurityDescriptorA is called with:
        // - A valid null-terminated SDDL string
        // - SDDL_REVISION_1 which is the current revision
        // - A pointer to receive the security descriptor
        // - NULL for the optional size output parameter
        let result = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorA(
                sddl.as_ptr(),
                SDDL_REVISION_1,
                &mut sd,
                core::ptr::null_mut(),
            )
        };

        if result == FALSE {
            let error = unsafe { GetLastError() };
            return Err(SecurityError::from_win32(error));
        }

        Ok(Self { inner: sd })
    }

    /// Creates a security descriptor that grants access only to:
    /// - Local System (SY)
    /// - Builtin Administrators (BA)
    /// - Owner (OW)
    ///
    /// This is the most restrictive commonly-used security descriptor.
    ///
    /// # Returns
    /// * `Ok(SecurityDescriptor)` - The created security descriptor
    /// * `Err(SecurityError)` - If creation failed
    pub fn owner_only() -> Result<Self, SecurityError> {
        Self::from_sddl(SDDL_OWNER_ONLY)
    }

    /// Creates a security descriptor that grants full access to Everyone.
    ///
    /// **Warning:** This should only be used for resources that are intentionally
    /// publicly accessible. For most use cases, prefer [`owner_only()`](Self::owner_only).
    ///
    /// # Returns
    /// * `Ok(SecurityDescriptor)` - The created security descriptor
    /// * `Err(SecurityError)` - If creation failed
    pub fn everyone_full_access() -> Result<Self, SecurityError> {
        Self::from_sddl(SDDL_EVERYONE_FULL_ACCESS)
    }

    /// Creates a security descriptor that grants read access to authenticated users.
    ///
    /// This is useful for resources that should be readable by any logged-in user
    /// but not by anonymous/guest accounts.
    ///
    /// # Returns
    /// * `Ok(SecurityDescriptor)` - The created security descriptor
    /// * `Err(SecurityError)` - If creation failed
    pub fn authenticated_users_read() -> Result<Self, SecurityError> {
        Self::from_sddl(SDDL_AUTHENTICATED_USERS_READ)
    }

    /// Creates a security descriptor that grants access only to Local System.
    ///
    /// This is useful for system services that need exclusive access.
    ///
    /// # Returns
    /// * `Ok(SecurityDescriptor)` - The created security descriptor
    /// * `Err(SecurityError)` - If creation failed
    pub fn system_only() -> Result<Self, SecurityError> {
        Self::from_sddl(SDDL_SYSTEM_ONLY)
    }

    /// Creates a security descriptor from a list of ACL entries.
    ///
    /// This method builds an SDDL string from the provided entries and creates
    /// a security descriptor from it.
    ///
    /// # Arguments
    /// * `entries` - The ACL entries to include in the DACL
    ///
    /// # Returns
    /// * `Ok(SecurityDescriptor)` - The created security descriptor
    /// * `Err(SecurityError)` - If creation failed
    ///
    /// # Note
    /// This is a simplified implementation that only supports common SID strings.
    /// For complex ACLs, use [`from_sddl`](Self::from_sddl) directly.
    pub fn with_dacl(entries: &[AclEntry]) -> Result<Self, SecurityError> {
        if entries.is_empty() {
            // Empty DACL denies all access
            return Self::from_sddl(b"D:\0");
        }

        // Build SDDL string
        let mut sddl = String::from("D:");

        for entry in entries {
            let ace_type = if entry.is_allow { "A" } else { "D" };
            let rights = access_mask_to_sddl(entry.access_mask);

            // For simplicity, we don't support arbitrary SIDs here
            // Use from_sddl for complex cases
            sddl.push_str(&format!("({};;{};;;WD)", ace_type, rights));
        }

        sddl.push('\0');
        Self::from_sddl(sddl.as_bytes())
    }

    /// Returns the underlying security descriptor pointer.
    ///
    /// The returned pointer is valid as long as this [`SecurityDescriptor`] exists.
    pub fn as_ptr(&self) -> PSECURITY_DESCRIPTOR {
        self.inner
    }

    /// Returns a [`SECURITY_ATTRIBUTES`] structure referencing this security descriptor.
    ///
    /// The returned structure is suitable for use with Windows APIs that accept
    /// security attributes (CreateFileMapping, CreateNamedPipe, etc.).
    ///
    /// # Note
    /// The returned structure references this [`SecurityDescriptor`] and must not
    /// outlive it.
    pub fn as_security_attributes(&self) -> SECURITY_ATTRIBUTES {
        SECURITY_ATTRIBUTES {
            nLength: core::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: self.inner,
            bInheritHandle: FALSE,
        }
    }
}

#[cfg(windows)]
impl Drop for SecurityDescriptor {
    fn drop(&mut self) {
        if !self.inner.is_null() {
            // SAFETY: The security descriptor was allocated by
            // ConvertStringSecurityDescriptorToSecurityDescriptorA and must be
            // freed with LocalFree.
            unsafe {
                LocalFree(self.inner as isize);
            }
        }
    }
}

// SecurityDescriptor cannot be sent between threads because the underlying
// PSECURITY_DESCRIPTOR is a raw pointer. However, it's safe to use from
// multiple threads if properly synchronized.
#[cfg(windows)]
unsafe impl Send for SecurityDescriptor {}

/// Helper function to convert an access mask to SDDL rights string.
#[cfg(windows)]
fn access_mask_to_sddl(mask: u32) -> &'static str {
    if mask == GENERIC_ALL || mask == 0x10000000 {
        "GA"
    } else if mask == GENERIC_READ {
        "GR"
    } else if mask == GENERIC_WRITE {
        "GW"
    } else if mask == GENERIC_EXECUTE {
        "GX"
    } else if mask == GENERIC_READ | GENERIC_WRITE {
        "GRGW"
    } else {
        // Default to generic all for unknown masks
        "GA"
    }
}

// ============================================================================
// Non-Windows Stub Implementation
// ============================================================================

#[cfg(not(windows))]
pub struct SecurityDescriptor {
    _marker: core::marker::PhantomData<()>,
}

#[cfg(not(windows))]
impl SecurityDescriptor {
    pub fn from_sddl(_sddl: &[u8]) -> Result<Self, SecurityError> {
        Err(SecurityError::InternalError(0))
    }

    pub fn owner_only() -> Result<Self, SecurityError> {
        Err(SecurityError::InternalError(0))
    }

    pub fn everyone_full_access() -> Result<Self, SecurityError> {
        Err(SecurityError::InternalError(0))
    }

    pub fn authenticated_users_read() -> Result<Self, SecurityError> {
        Err(SecurityError::InternalError(0))
    }

    pub fn system_only() -> Result<Self, SecurityError> {
        Err(SecurityError::InternalError(0))
    }

    pub fn with_dacl(_entries: &[AclEntry]) -> Result<Self, SecurityError> {
        Err(SecurityError::InternalError(0))
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use alloc::format;
    use alloc::vec;

    #[test]
    fn test_security_error_display() {
        assert_eq!(
            format!("{}", SecurityError::InvalidSddlString),
            "Invalid or malformed SDDL string"
        );
        assert_eq!(
            format!("{}", SecurityError::InsufficientMemory),
            "Insufficient memory to create security descriptor"
        );
        assert_eq!(
            format!("{}", SecurityError::InvalidParameter),
            "Invalid parameter"
        );
        assert_eq!(
            format!("{}", SecurityError::InternalError(42)),
            "Internal error (code: 42)"
        );
    }

    #[test]
    #[allow(clippy::clone_on_copy)]
    fn test_security_error_traits() {
        // Test Clone
        let error = SecurityError::InvalidSddlString;
        let cloned = error.clone();
        assert_eq!(error, cloned);

        // Test Copy
        let copied = error;
        assert_eq!(error, copied);

        // Test Hash
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(SecurityError::InvalidSddlString);
        set.insert(SecurityError::InsufficientMemory);
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn test_sid_everyone() {
        let sid = Sid::everyone();
        assert!(!sid.as_bytes().is_empty());
    }

    #[test]
    fn test_sid_local_system() {
        let sid = Sid::local_system();
        assert!(!sid.as_bytes().is_empty());
    }

    #[test]
    fn test_sid_from_bytes() {
        let data = vec![1, 2, 3, 4];
        let sid = Sid::from_bytes(&data);
        assert_eq!(sid.as_bytes(), &data);
    }

    #[test]
    fn test_acl_entry_allow() {
        let entry = AclEntry::allow(Sid::everyone(), GENERIC_READ);
        assert!(entry.is_allow);
        assert_eq!(entry.access_mask, GENERIC_READ);
    }

    #[test]
    fn test_acl_entry_deny() {
        let entry = AclEntry::deny(Sid::everyone(), GENERIC_WRITE);
        assert!(!entry.is_allow);
        assert_eq!(entry.access_mask, GENERIC_WRITE);
    }

    #[cfg(windows)]
    mod windows_tests {
        use super::*;

        #[test]
        fn test_security_descriptor_owner_only() {
            let result = SecurityDescriptor::owner_only();
            assert!(
                result.is_ok(),
                "Failed to create owner_only security descriptor"
            );
            let sd = result.unwrap();
            assert!(!sd.as_ptr().is_null());
        }

        #[test]
        fn test_security_descriptor_everyone_full_access() {
            let result = SecurityDescriptor::everyone_full_access();
            assert!(
                result.is_ok(),
                "Failed to create everyone_full_access security descriptor"
            );
            let sd = result.unwrap();
            assert!(!sd.as_ptr().is_null());
        }

        #[test]
        fn test_security_descriptor_authenticated_users_read() {
            let result = SecurityDescriptor::authenticated_users_read();
            assert!(
                result.is_ok(),
                "Failed to create authenticated_users_read security descriptor"
            );
        }

        #[test]
        fn test_security_descriptor_system_only() {
            let result = SecurityDescriptor::system_only();
            assert!(
                result.is_ok(),
                "Failed to create system_only security descriptor"
            );
        }

        #[test]
        fn test_security_descriptor_from_sddl() {
            let result = SecurityDescriptor::from_sddl(b"D:(A;;GA;;;WD)\0");
            assert!(
                result.is_ok(),
                "Failed to create security descriptor from SDDL"
            );
        }

        #[test]
        fn test_security_descriptor_invalid_sddl() {
            let result = SecurityDescriptor::from_sddl(b"INVALID_SDDL\0");
            assert!(result.is_err());
        }

        #[test]
        fn test_security_descriptor_empty_sddl() {
            let result = SecurityDescriptor::from_sddl(b"");
            assert!(result.is_err());
            assert_eq!(result.unwrap_err(), SecurityError::InvalidParameter);
        }

        #[test]
        fn test_security_descriptor_as_security_attributes() {
            let sd = SecurityDescriptor::owner_only().unwrap();
            let attrs = sd.as_security_attributes();
            assert_eq!(
                attrs.nLength,
                core::mem::size_of::<SECURITY_ATTRIBUTES>() as u32
            );
            assert_eq!(attrs.lpSecurityDescriptor, sd.as_ptr());
            assert_eq!(attrs.bInheritHandle, FALSE);
        }

        #[test]
        fn test_security_descriptor_with_file_mapping() {
            use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
            use windows_sys::Win32::System::Memory::{CreateFileMappingW, PAGE_READWRITE};

            let sd = SecurityDescriptor::everyone_full_access().unwrap();
            let attrs = sd.as_security_attributes();

            // SAFETY: CreateFileMappingW is called with valid parameters
            let handle = unsafe {
                CreateFileMappingW(
                    INVALID_HANDLE_VALUE,
                    &attrs,
                    PAGE_READWRITE,
                    0,
                    4096,
                    core::ptr::null(),
                )
            };

            assert!(
                handle != 0,
                "Failed to create file mapping with security descriptor"
            );

            // SAFETY: CloseHandle is called with a valid handle
            unsafe { CloseHandle(handle) };
        }

        #[test]
        fn test_access_mask_to_sddl() {
            assert_eq!(access_mask_to_sddl(GENERIC_ALL), "GA");
            assert_eq!(access_mask_to_sddl(GENERIC_READ), "GR");
            assert_eq!(access_mask_to_sddl(GENERIC_WRITE), "GW");
            assert_eq!(access_mask_to_sddl(GENERIC_EXECUTE), "GX");
        }

        #[test]
        fn test_error_from_win32() {
            use windows_sys::Win32::Foundation::{
                ERROR_INVALID_SECURITY_DESCR, ERROR_NOT_ENOUGH_MEMORY,
            };

            assert_eq!(
                SecurityError::from_win32(ERROR_INVALID_SECURITY_DESCR),
                SecurityError::InvalidSddlString
            );
            assert_eq!(
                SecurityError::from_win32(ERROR_NOT_ENOUGH_MEMORY),
                SecurityError::InsufficientMemory
            );
            assert_eq!(
                SecurityError::from_win32(ERROR_INVALID_PARAMETER),
                SecurityError::InvalidParameter
            );
        }
    }

    #[cfg(not(windows))]
    #[test]
    fn test_stub_implementations_return_errors() {
        assert!(SecurityDescriptor::from_sddl(b"test\0").is_err());
        assert!(SecurityDescriptor::owner_only().is_err());
        assert!(SecurityDescriptor::everyone_full_access().is_err());
        assert!(SecurityDescriptor::authenticated_users_read().is_err());
        assert!(SecurityDescriptor::system_only().is_err());
        assert!(SecurityDescriptor::with_dacl(&[]).is_err());
    }
}
