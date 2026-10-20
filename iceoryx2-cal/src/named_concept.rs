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

use core::fmt::Debug;

use alloc::format;
use alloc::vec::Vec;

use iceoryx2_bb_container::semantic_string::SemanticString;
use iceoryx2_bb_posix::config::TEMP_DIRECTORY;
use iceoryx2_bb_posix::directory::{Directory, DirectoryRemoveError};
use iceoryx2_bb_posix::permission::Permission;
pub use iceoryx2_bb_system_types::file_name::FileName;
pub use iceoryx2_bb_system_types::file_path::FilePath;
pub use iceoryx2_bb_system_types::path::Path;
use iceoryx2_log::{fail, fatal_panic};

#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
pub enum NamedConceptDoesExistError {
    InsufficientPermissions,
    Interrupt,
    UnderlyingResourcesBeingSetUp,
    UnderlyingResourcesCorrupted,
    InternalError,
}

impl core::fmt::Display for NamedConceptDoesExistError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "NamedConceptDoesExistError::{self:?}")
    }
}

impl core::error::Error for NamedConceptDoesExistError {}

#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
pub enum NamedConceptRemoveError {
    InsufficientPermissions,
    Interrupt,
    InternalError,
}

impl core::fmt::Display for NamedConceptRemoveError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "NamedConceptRemoveError::{self:?}")
    }
}

impl core::error::Error for NamedConceptRemoveError {}

#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
pub enum NamedConceptListError {
    InsufficientPermissions,
    InternalError,
}

impl core::fmt::Display for NamedConceptListError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "NamedConceptListError::{self:?}")
    }
}

impl core::error::Error for NamedConceptListError {}

#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
pub enum NamedConceptPathHintRemoveError {
    InsufficientPermissions,
    InternalError,
}

impl core::fmt::Display for NamedConceptPathHintRemoveError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "NamedConceptPathHintRemoveError::{self:?}")
    }
}

impl core::error::Error for NamedConceptPathHintRemoveError {}

/// Describes whether, and with whom, a [`NamedConcept`] shares the file-system resources it
/// creates (files, directories, sockets, named shared memory) with users other than the creating
/// one.
///
/// The default, [`SharedAccess::owner_only()`], keeps the historical single-user behavior: every
/// resource is accessible only by the creating user. A shared access is derived from a mode such
/// as `0o2770` or `0o1777` via [`SharedAccess::from_mode()`]: the group (respectively others) bits
/// of that mode act as a *mask* that limits which of the owner bits of a resource are mirrored to
/// the group (respectively others).
///
/// * [`SharedAccess::file_permission()`] mirrors the owner bits of a file-like resource, e.g. a
///   read-only static config (`0o400`) becomes `0o440`/`0o444` and a read-write dynamic config
///   (`0o600`) becomes `0o660`/`0o666`.
/// * [`SharedAccess::directory_permission()`] only ever mirrors read + traverse (never write) so
///   that per-owner directories stay owned and writable by their owner alone.
///
/// The optional [`SharedAccess::group()`] names the group that resources outside of a set-group-id
/// directory (e.g. POSIX shared memory) are handed to when they are shared with the group.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct SharedAccess {
    group_mask: u32,
    others_mask: u32,
    group: Option<u32>,
}

impl SharedAccess {
    /// Resources are accessible only by the creating user (default, single-user behavior).
    pub const fn owner_only() -> Self {
        Self {
            group_mask: 0,
            others_mask: 0,
            group: None,
        }
    }

    /// Derives the shared access from a mode. The group bits (`0o070`) of `mode` limit what is
    /// mirrored to the group, the others bits (`0o007`) what is mirrored to everyone else. The
    /// owner and special bits of `mode` are ignored.
    pub fn from_mode(mode: Permission, group: Option<u32>) -> Self {
        let bits = mode.bits() as u32;
        Self {
            group_mask: (bits >> 3) & 0o7,
            others_mask: bits & 0o7,
            group,
        }
    }

    /// Returns `true` when nothing is shared with other users.
    pub fn is_owner_only(&self) -> bool {
        self.group_mask == 0 && self.others_mask == 0
    }

    /// Returns `true` when resources are shared with the group.
    pub fn shares_with_group(&self) -> bool {
        self.group_mask != 0
    }

    /// Returns `true` when resources are shared with everyone.
    pub fn shares_with_others(&self) -> bool {
        self.others_mask != 0
    }

    /// The group that shared resources shall be handed to, if any.
    pub fn group(&self) -> Option<u32> {
        if self.shares_with_group() {
            self.group
        } else {
            None
        }
    }

    /// Mirrors the owner bits of `base` to the group/others as far as the masks allow.
    pub fn file_permission(&self, base: Permission) -> Permission {
        let bits = base.bits() as u32;
        let owner = (bits >> 6) & 0o7;
        let mirrored = ((owner & self.group_mask) << 3) | (owner & self.others_mask);
        Permission::from_bits(bits | mirrored)
    }

    /// Adds read + traverse permissions for the group/others to the directory permission `base`
    /// as far as the masks allow. Write access is never mirrored.
    pub fn directory_permission(&self, base: Permission) -> Permission {
        let bits = base.bits() as u32;
        let mirrored = ((0o5 & self.group_mask) << 3) | (0o5 & self.others_mask);
        Permission::from_bits(bits | mirrored)
    }
}

/// Every [`NamedConcept`] must have a custom configuration that at least allows the user to define
/// a custom [`NamedConceptConfiguration::suffix()`] for all file names that are transparent during
/// usage as well as a [`NamedConceptConfiguration::path_hint()`] that can be ignored if the
/// underlying resource does not support it.
pub trait NamedConceptConfiguration: Default + Clone + Debug + Send {
    /// Defines the prefix that the concept will use.
    fn prefix(self, value: &FileName) -> Self;

    /// Returns the configurations prefix.
    fn get_prefix(&self) -> &FileName;

    /// Defines the suffix that the concept will use.
    fn suffix(self, value: &FileName) -> Self;

    /// Sets a path hint under which the underlying resources shall be stored. When the concept
    /// uses resources like [`iceoryx2_bb_posix::shared_memory::SharedMemory`] the path will be
    /// ignored.
    fn path_hint(self, value: &Path) -> Self;

    /// Returns the configurations suffix.
    fn get_suffix(&self) -> &FileName;

    /// Returns the configurations path hint.
    fn get_path_hint(&self) -> &Path;

    /// Defines with whom the resources created under this configuration are shared. Concepts
    /// that do not create shareable file-system resources ignore this setting.
    fn shared_access(self, _value: &SharedAccess) -> Self {
        self
    }

    /// Returns the [`SharedAccess`] of the configuration, [`SharedAccess::owner_only()`] for
    /// concepts that do not support it.
    fn get_shared_access(&self) -> SharedAccess {
        SharedAccess::owner_only()
    }

    /// Returns the full path for a given value under the given configuration.
    fn path_for(&self, value: &FileName) -> FilePath {
        let mut path = *self.get_path_hint();
        fatal_panic!(from self, when path.add_path_entry(&self.get_prefix().into()),
                    "The path hint \"{}\" in combination with the prefix \"{}\" exceed the maximum supported path length of {} of the operating system.",
                    path, value, Path::max_len());
        fatal_panic!(from self, when path.push_bytes(value.as_string()),
                    "The path hint \"{}\" in combination with the file name \"{}\" exceed the maximum supported path length of {} of the operating system.",
                    path, value, Path::max_len());
        fatal_panic!(from self, when path.push_bytes(self.get_suffix()),
                    "The path hint \"{}\" in combination with the file name \"{}\" and the suffix \"{}\" exceed the maximum supported path length of {} of the operating system.",
                    path, value, self.get_suffix(), Path::max_len());

        unsafe { FilePath::new_unchecked(path.as_bytes()) }
    }

    /// Extracts the name from a full path under a given configuration.
    fn extract_name_from_path(&self, value: &FilePath) -> Option<FileName> {
        if *self.get_path_hint() != value.path() {
            return None;
        }

        self.extract_name_from_file(&value.file_name())
    }

    /// Extracts the name from a file name under a given configuration.
    fn extract_name_from_file(&self, value: &FileName) -> Option<FileName> {
        let mut file = *value;

        if !fatal_panic!(from self, when file.strip_prefix(self.get_prefix().as_bytes()),
                    "Stripping the prefix \"{}\" from the file name \"{}\" leads to invalid content.",
                    self.get_prefix(), file)
        {
            return None;
        }

        if !fatal_panic!(from self, when file.strip_suffix(self.get_suffix().as_bytes()),
                    "Stripping the suffix \"{}\" from the file name \"{}\" leads to invalid content.",
                    self.get_suffix(), file)
        {
            return None;
        }

        Some(file)
    }
}

/// Builder trait to create new [`NamedConcept`]s.
pub trait NamedConceptBuilder<T: NamedConceptMgmt> {
    /// Defines the name of the newly created [`NamedConcept`].
    fn new(name: &FileName) -> Self;

    /// Sets the custom configuration of the concept.
    fn config(self, config: &T::Configuration) -> Self;
}

/// Every concept that is uniquely identified by a [`FileName`] and corresponds to some kind of
/// file in the file system is a [`NamedConcept`]. This trait provides the essential property of
/// these concepts [`NamedConcept::name()`]
pub trait NamedConcept: Debug {
    /// Returns the name of the concept
    fn name(&self) -> &FileName;
}

/// Every concept that is uniquely identified by a [`FileName`] and corresponds to some kind of
/// file in the file system is a [`NamedConcept`]. This trait provides common management methods
/// for such concepts, like
///  * [`NamedConceptMgmt::remove()`]
///  * [`NamedConceptMgmt::does_exist()`]
///  * [`NamedConceptMgmt::list()`]
pub trait NamedConceptMgmt: Debug {
    type Configuration: NamedConceptConfiguration;

    /// Removes an existing concept. Returns true if the concepts existed and was removed,
    /// if the concept did not exist it returns false.
    ///
    /// # Safety
    ///
    ///  * It must be ensured that no other process is using the concept.
    ///
    unsafe fn remove(name: &FileName) -> Result<bool, NamedConceptRemoveError> {
        unsafe { Self::remove_cfg(name, &Self::Configuration::default()) }
    }

    /// Returns true if a concept with that name exists, otherwise false
    fn does_exist(name: &FileName) -> Result<bool, NamedConceptDoesExistError> {
        Self::does_exist_cfg(name, &Self::Configuration::default())
    }

    /// Returns a list of all available concepts with the default configuration.
    fn list() -> Result<Vec<FileName>, NamedConceptListError> {
        Self::list_cfg(&Self::Configuration::default())
    }

    /// Removes an existing concept under a custom configuration. Returns true if the concepts
    /// existed and was removed, if the concept did not exist it returns false.
    ///
    /// # Safety
    ///
    ///  * It must be ensured that no other process is using the concept.
    ///
    unsafe fn remove_cfg(
        name: &FileName,
        cfg: &Self::Configuration,
    ) -> Result<bool, NamedConceptRemoveError>;

    /// Returns true if a concept with that name exists under a custom configuration, otherwise false
    fn does_exist_cfg(
        name: &FileName,
        cfg: &Self::Configuration,
    ) -> Result<bool, NamedConceptDoesExistError>;

    /// Returns a list of all available concepts with a custom configuration.
    fn list_cfg(cfg: &Self::Configuration) -> Result<Vec<FileName>, NamedConceptListError>;

    /// The default prefix of every zero copy connection
    fn default_prefix() -> FileName {
        unsafe { FileName::new_unchecked(b"iox2_") }
    }

    /// The default path hint for every zero copy connection
    fn default_path_hint() -> Path {
        TEMP_DIRECTORY
    }

    /// Removes the path hint directory. Will be realized only when the concept actually uses
    /// the path hint.
    fn remove_path_hint(value: &Path) -> Result<(), NamedConceptPathHintRemoveError>;
}

pub(crate) fn remove_path_hint(value: &Path) -> Result<(), NamedConceptPathHintRemoveError> {
    let origin = format!("remove_path_hint({value:?})");
    let msg = "Unable to remove path hint";
    match Directory::remove_empty(value) {
        Ok(()) | Err(DirectoryRemoveError::DirectoryDoesNotExist) => Ok(()),
        Err(DirectoryRemoveError::InsufficientPermissions) => {
            fail!(from origin, with NamedConceptPathHintRemoveError::InsufficientPermissions,
                "{} due to insufficient permissions.", msg);
        }
        Err(e) => {
            fail!(from origin, with NamedConceptPathHintRemoveError::InternalError,
                "{} due to an internal error ({:?}).", msg, e);
        }
    }
}

#[cfg(test)]
mod shared_access_tests {
    use super::*;

    fn bits(p: Permission) -> u32 {
        p.bits() as u32
    }

    #[test]
    fn owner_only_keeps_permissions() {
        let a = SharedAccess::owner_only();
        assert!(a.is_owner_only());
        assert_eq!(bits(a.file_permission(Permission::OWNER_READ)), 0o400);
        assert_eq!(
            bits(a.directory_permission(Permission::from_bits(0o750))),
            0o750
        );
        assert_eq!(a.group(), None);
    }

    #[test]
    fn sticky_world_mode_mirrors_to_everyone() {
        let a = SharedAccess::from_mode(Permission::from_bits(0o1777), None);
        assert_eq!(bits(a.file_permission(Permission::OWNER_READ)), 0o444);
        assert_eq!(bits(a.file_permission(Permission::OWNER_READ_WRITE)), 0o666);
        // directories never become writable for others
        assert_eq!(
            bits(a.directory_permission(Permission::from_bits(0o750))),
            0o755
        );
    }

    #[test]
    fn group_mode_mirrors_to_group_only() {
        let a = SharedAccess::from_mode(Permission::from_bits(0o2770), Some(3000));
        assert_eq!(bits(a.file_permission(Permission::OWNER_READ)), 0o440);
        assert_eq!(bits(a.file_permission(Permission::OWNER_READ_WRITE)), 0o660);
        assert_eq!(bits(a.directory_permission(Permission::OWNER_ALL)), 0o750);
        assert_eq!(a.group(), Some(3000));
    }

    #[test]
    fn endpoint_mode_limits_mirrored_bits() {
        let a = SharedAccess::from_mode(Permission::from_bits(0o660), None);
        assert_eq!(bits(a.file_permission(Permission::OWNER_ALL)), 0o760);
    }
}
