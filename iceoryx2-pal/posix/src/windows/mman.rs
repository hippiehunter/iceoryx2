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

#![allow(non_camel_case_types)]
#![allow(clippy::missing_safety_doc)]
#![allow(unused_variables)]

use crate::posix::{
    Errno, MemZeroedStruct, constants::*, settings::*, to_dir_search_string, types::*,
};
use crate::win32call;

use iceoryx2_pal_concurrency_sync::WaitAction;
use iceoryx2_pal_concurrency_sync::atomic::AtomicU64;
use iceoryx2_pal_concurrency_sync::cell::UnsafeCell;
use iceoryx2_pal_concurrency_sync::strategy::mutex::Mutex;
use iceoryx2_pal_configuration::PATH_SEPARATOR;
use windows_sys::Win32::Foundation::ERROR_FILE_EXISTS;
use windows_sys::Win32::Storage::FileSystem::{
    FILE_ATTRIBUTE_DIRECTORY, FindClose, FindFirstFileA, FindNextFileA, WIN32_FIND_DATAA,
};
use windows_sys::Win32::System::Threading::{INFINITE, WaitOnAddress, WakeByAddressSingle};
use windows_sys::Win32::{
    Foundation::{
        CloseHandle, ERROR_ACCESS_DENIED, ERROR_ALREADY_EXISTS, ERROR_FILE_NOT_FOUND, FALSE,
        GENERIC_READ, GENERIC_WRITE, HANDLE, INVALID_HANDLE_VALUE,
    },
    Security::SECURITY_ATTRIBUTES,
    Storage::FileSystem::{
        CREATE_NEW, CreateFileA, DeleteFileA, FILE_ATTRIBUTE_NORMAL, FILE_BEGIN, FILE_SHARE_DELETE,
        FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING, ReadFile, SetFilePointer, WriteFile,
    },
    System::{IO::OVERLAPPED, Memory::*},
};

use alloc::vec;
use alloc::vec::Vec;

use super::win32_handle_translator::{FdHandleEntry, FileHandle, HandleTranslator, ShmHandle};

struct FileMappingsSet {
    mappings: UnsafeCell<[(isize, HANDLE); 1024]>,
    mtx: Mutex,
}

unsafe impl Send for FileMappingsSet {}
unsafe impl Sync for FileMappingsSet {}

impl FileMappingsSet {
    const fn new() -> Self {
        Self {
            mappings: UnsafeCell::new([(0, 0); 1024]),
            mtx: Mutex::new(),
        }
    }

    fn lock(&self) {
        self.mtx.lock(|atomic, value| {
            unsafe {
                WaitOnAddress(
                    (atomic as *const AtomicU64).cast(),
                    (value as *const u64).cast(),
                    4,
                    INFINITE,
                );
            }
            WaitAction::Continue
        });
    }

    fn unlock(&self) {
        self.mtx.unlock(|atomic| unsafe {
            WakeByAddressSingle((atomic as *const AtomicU64).cast());
        });
    }

    fn get_instance() -> &'static Self {
        static MAPPING: FileMappingsSet = FileMappingsSet::new();
        &MAPPING
    }

    fn insert(&self, value: isize, handle: HANDLE) -> bool {
        self.lock();
        let mappings_ref = unsafe { &mut *self.mappings.get() };
        for element in mappings_ref {
            if element.0 == 0 {
                element.0 = value;
                element.1 = handle;
                self.unlock();
                return true;
            }
        }

        self.unlock();
        false
    }

    fn remove(&self, value: isize) -> Option<(isize, HANDLE)> {
        self.lock();
        let mappings_ref = unsafe { &mut *self.mappings.get() };
        for element in mappings_ref {
            if element.0 == value {
                let ret_val = *element;
                element.0 = 0;
                element.1 = 0;
                self.unlock();
                return Some(ret_val);
            }
        }

        self.unlock();
        None
    }
}

const MAX_SUPPORTED_SHM_SIZE: u64 = 128 * 1024 * 1024 * 1024;

pub unsafe fn mlock(addr: *const void, len: size_t) -> int {
    -1
}

pub unsafe fn munlock(addr: *const void, len: size_t) -> int {
    -1
}

pub unsafe fn mlockall(flags: int) -> int {
    -1
}

pub unsafe fn munlockall() -> int {
    -1
}

unsafe fn remove_leading_path_separator(value: *const c_char) -> *const c_char {
    unsafe {
        if *value as u8 == PATH_SEPARATOR {
            value.offset(1)
        } else {
            value
        }
    }
}

unsafe fn trim_ascii(value: &[u8]) -> &[u8] {
    for i in 0..value.len() {
        if value[i] == 0 {
            return value.split_at(i).0;
        }
    }

    value
}

pub unsafe fn shm_list() -> Vec<[i8; 256]> {
    let mut result = vec![];
    let mut search_path = SHM_STATE_DIRECTORY.to_vec();
    search_path.push(0);
    unsafe {
        let search_path = to_dir_search_string(search_path.as_ptr().cast());

        //SHM_STATE_SUFFIX
        let mut data = WIN32_FIND_DATAA::new_zeroed();
        let (handle, _) = win32call! { FindFirstFileA(search_path.as_ptr().cast(), &mut data), ignore ERROR_FILE_NOT_FOUND };

        if handle == INVALID_HANDLE_VALUE {
            return result;
        }

        loop {
            if data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY == 0 {
                let file_name = trim_ascii(&data.cFileName);
                if file_name.ends_with(SHM_STATE_SUFFIX) {
                    let name = file_name
                        .split_at(file_name.len() - SHM_STATE_SUFFIX.len())
                        .0;

                    let mut shm_name = [0i8; 256];
                    for i in 0..core::cmp::min(shm_name.len(), name.len()) {
                        shm_name[i] = name[i] as _;
                    }
                    result.push(shm_name);
                }
            }

            let (file_found, _) = win32call! { FindNextFileA(handle, &mut data) };
            if file_found == FALSE {
                break;
            }
        }

        win32call! { FindClose(handle) };

        result
    }
}

pub unsafe fn shm_open(name: *const c_char, oflag: int, mode: mode_t) -> int {
    unsafe {
        let name = remove_leading_path_separator(name.cast());
        let handle: HANDLE = 0;
        let shm_handle;
        let mut shm_state_handle;

        if oflag & O_CREAT != 0 {
            shm_state_handle = create_state_handle(name);
            if shm_state_handle == INVALID_HANDLE_VALUE {
                if oflag & O_EXCL != 0 {
                    Errno::set(Errno::EEXIST);
                    return -1;
                }

                shm_state_handle = open_state_handle(name);

                if shm_state_handle == INVALID_HANDLE_VALUE {
                    Errno::set(Errno::ENOENT);
                    return -1;
                }
            }
            shm_set_size(shm_state_handle, 0);

            const MAX_SIZE_LOW: u32 = (MAX_SUPPORTED_SHM_SIZE & 0xFFFFFFFF) as u32;
            const MAX_SIZE_HIGH: u32 = ((MAX_SUPPORTED_SHM_SIZE >> 32) & 0xFFFFFFFF) as u32;

            let last_mapping_error;
            (shm_handle, last_mapping_error) = win32call! {CreateFileMappingA(
                handle,
                core::ptr::null::<SECURITY_ATTRIBUTES>(),
                PAGE_READWRITE | SEC_RESERVE,
                MAX_SIZE_HIGH,
                MAX_SIZE_LOW,
                name as *const u8,
            ), ignore ERROR_ALREADY_EXISTS};

            if shm_handle == 0 {
                Errno::set(Errno::EACCES);
                CloseHandle(shm_state_handle);
                return -1;
            }

            if oflag & O_EXCL != 0 && last_mapping_error == ERROR_ALREADY_EXISTS {
                CloseHandle(shm_handle);
                CloseHandle(shm_state_handle);
                return -1;
            }
        } else {
            shm_state_handle = open_state_handle(name);

            if shm_state_handle == INVALID_HANDLE_VALUE {
                Errno::set(Errno::ENOENT);
                return -1;
            }

            let last_mapping_error;
            (shm_handle, last_mapping_error) = win32call! {OpenFileMappingA(FILE_MAP_ALL_ACCESS, false as i32, name as *const u8), ignore ERROR_FILE_NOT_FOUND};

            if shm_handle == 0 {
                Errno::set(Errno::ENOENT);
                shm_unlink(name);
                win32call! {CloseHandle(shm_state_handle)};
                return -1;
            }

            if last_mapping_error != 0 {
                Errno::set(Errno::EACCES);
                win32call! {CloseHandle(shm_handle)};
                win32call! {CloseHandle(shm_state_handle)};
                return -1;
            }
        }

        HandleTranslator::get_instance().add(FdHandleEntry::SharedMemory(ShmHandle {
            handle: FileHandle {
                handle: shm_handle,
                lock_state: F_UNLCK,
            },
            state_handle: shm_state_handle,
        }))
    }
}

unsafe fn shm_file_path(name: *const c_char, suffix: &[u8]) -> [u8; MAX_PATH_LENGTH] {
    unsafe {
        let name = remove_leading_path_separator(name);

        let mut state_file_path = [0u8; MAX_PATH_LENGTH];

        // path
        state_file_path[..SHM_STATE_DIRECTORY.len()].copy_from_slice(SHM_STATE_DIRECTORY);

        // name
        let mut name_len = 0;
        for i in 0..usize::MAX {
            let c = *(name.add(i) as *const u8);

            state_file_path[i + SHM_STATE_DIRECTORY.len()] = if c == b'/' { b'\\' } else { c };
            if *(name.add(i)) == 0i8 {
                name_len = i;
                break;
            }
        }

        // suffix
        for i in 0..suffix.len() {
            state_file_path[i + SHM_STATE_DIRECTORY.len() + name_len] = suffix[i];
        }

        state_file_path
    }
}

unsafe fn create_state_handle(name: *const c_char) -> HANDLE {
    unsafe {
        let name = remove_leading_path_separator(name);

        let create_file = || {
            let (handle, last_error) = win32call! {CreateFileA(
                shm_file_path(name, SHM_STATE_SUFFIX).as_ptr(),
                GENERIC_WRITE | GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                core::ptr::null::<SECURITY_ATTRIBUTES>(),
                CREATE_NEW,
                FILE_ATTRIBUTE_NORMAL,
                0,
            ), ignore ERROR_FILE_EXISTS};
            (handle, last_error)
        };

        let (mut handle, last_error) = create_file();
        if handle == INVALID_HANDLE_VALUE
            && last_error == ERROR_FILE_EXISTS
            && !does_shm_exist(name)
        {
            remove_state_handle(name);
            (handle, _) = create_file();
        }

        handle
    }
}

unsafe fn open_state_handle(name: *const c_char) -> HANDLE {
    unsafe {
        let name = remove_leading_path_separator(name);

        let (handle, _) = win32call! {CreateFileA(
            shm_file_path(name, SHM_STATE_SUFFIX).as_ptr(),
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            core::ptr::null::<SECURITY_ATTRIBUTES>(),
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            0,
        ), ignore ERROR_FILE_NOT_FOUND };
        handle
    }
}

unsafe fn remove_state_handle(name: *const c_char) -> int {
    unsafe {
        let name = remove_leading_path_separator(name);

        let (has_deleted_file, error_code) = win32call! { DeleteFileA(shm_file_path(name, SHM_STATE_SUFFIX).as_ptr()),
        ignore ERROR_FILE_NOT_FOUND, ERROR_ACCESS_DENIED};
        if has_deleted_file == FALSE {
            // TODO: [#9]
            Errno::set(Errno::ENOENT);
            return -1;
        }
        0
    }
}

unsafe fn does_shm_exist(name: *const c_char) -> bool {
    unsafe {
        let (shm_handle, last_error) = win32call! {OpenFileMappingA(FILE_MAP_ALL_ACCESS, false as i32, name as *const u8), ignore ERROR_FILE_NOT_FOUND};
        !(shm_handle == 0 && last_error == ERROR_FILE_NOT_FOUND)
    }
}

pub(crate) unsafe fn shm_set_size(fd_handle: HANDLE, shm_size: u64) {
    if fd_handle == INVALID_HANDLE_VALUE {
        return;
    }

    if shm_size > MAX_SUPPORTED_SHM_SIZE {
        #[cfg(feature = "std")]
        {
            extern crate std;
            std::eprintln!("Trying to allocate {shm_size} which is larger than the maximum supported shared memory size of {MAX_SUPPORTED_SHM_SIZE}");
        }
    }

    let mut bytes_written = 0;
    unsafe {
        win32call! {SetFilePointer(fd_handle, 0, core::ptr::null_mut::<i32>(), FILE_BEGIN)};
        win32call! { WriteFile(
            fd_handle,
            (&shm_size as *const u64) as *const u8,
            8,
            &mut bytes_written,
            core::ptr::null_mut::<OVERLAPPED>(),
        )};
    }
}

pub(crate) unsafe fn shm_get_size(fd_handle: HANDLE) -> u64 {
    if fd_handle == INVALID_HANDLE_VALUE {
        return 0;
    }

    let mut read_buffer: u64 = 0;
    let mut bytes_read = 0;
    unsafe {
        win32call! {SetFilePointer(fd_handle, 0, core::ptr::null_mut::<i32>(), FILE_BEGIN)};
        let (has_read_file, _) = win32call! { ReadFile(
            fd_handle,
            (&mut read_buffer as *mut u64) as *mut void,
            8,
            &mut bytes_read,
            core::ptr::null_mut::<OVERLAPPED>(),
        )};
        if has_read_file == FALSE || bytes_read != 8 {
            read_buffer = 0;
        }

        read_buffer
    }
}

pub unsafe fn shm_unlink(name: *const c_char) -> int {
    unsafe { remove_state_handle(name) }
}

pub unsafe fn mmap(
    addr: *mut void,
    len: size_t,
    prot: int,
    flags: int,
    fd: int,
    off: off_t,
) -> *mut void {
    if len == 0 {
        Errno::set(Errno::EINVAL);
        return core::ptr::null_mut::<void>();
    }
    unsafe {
        if fd == -1 {
            if flags == MAP_ANONYMOUS | MAP_PRIVATE {
                let addr =
                    win32call! { VirtualAlloc(core::ptr::null(), len, MEM_COMMIT, PAGE_READWRITE) }
                        .0;
                if addr.is_null() {
                    Errno::set(Errno::ENOMEM);
                    return core::ptr::null_mut::<void>();
                }
                return addr as *mut void;
            } else {
                Errno::set(Errno::EINVAL);
                return core::ptr::null_mut::<void>();
            }
        }

        match HandleTranslator::get_instance().get(fd) {
            Some(FdHandleEntry::SharedMemory(win_handle)) => {
                let (map_result, _) = win32call! { MapViewOfFile(win_handle.handle.handle, FILE_MAP_ALL_ACCESS, 0, 0, len)};
                match map_result {
                    0 => {
                        Errno::set(Errno::ENOMEM);
                        core::ptr::null_mut::<void>()
                    }
                    lpaddress => {
                        if win32call!{  VirtualAlloc(lpaddress as *const void, len, MEM_COMMIT, PAGE_READWRITE)}.0
                        .is_null()
                    {
                        win32call! { UnmapViewOfFile(lpaddress) };
                        Errno::set(Errno::ENOMEM);
                        return core::ptr::null_mut::<void>();
                    }

                        if !FileMappingsSet::get_instance().insert(lpaddress, 0) {
                            win32call! { UnmapViewOfFile(lpaddress) };
                            Errno::set(Errno::EMFILE);
                            return core::ptr::null_mut::<void>();
                        }

                        lpaddress as *mut void
                    }
                }
            }
            Some(FdHandleEntry::File(fd)) => {
                let max_size_low: u32 = (len & 0xFFFFFFFF) as u32;
                let max_size_high: u32 = (len.overflowing_shr(32).0 & 0xFFFFFFFF) as u32;
                let file_view = win32call! { CreateFileMappingA(
                    fd.handle,
                    core::ptr::null(),
                    PAGE_READWRITE | SEC_RESERVE,
                    max_size_high,
                    max_size_low,
                    core::ptr::null(),
                ) }
                .0;

                let lpaddress =
                    win32call! { MapViewOfFile(file_view, FILE_MAP_ALL_ACCESS, 0, 0, len)}.0;
                if lpaddress == 0 {
                    return core::ptr::null_mut();
                }

                if !FileMappingsSet::get_instance().insert(lpaddress, file_view) {
                    win32call! { UnmapViewOfFile(lpaddress) };
                    Errno::set(Errno::EMFILE);
                    return core::ptr::null_mut::<void>();
                }

                lpaddress as *mut void
            }
            _ => {
                Errno::set(Errno::EINVAL);
                core::ptr::null_mut::<void>()
            }
        }
    }
}

pub unsafe fn munmap(addr: *mut void, len: size_t) -> int {
    unsafe {
        if let Some((addr, handle)) = FileMappingsSet::get_instance().remove(addr as isize) {
            let (has_unmapped, _) = win32call! { UnmapViewOfFile(addr as _) };
            if has_unmapped == FALSE {
                Errno::set(Errno::EINVAL);
                return -1;
            }

            if handle != 0 && win32call! { CloseHandle(handle)}.0 == FALSE {
                Errno::set(Errno::EINVAL);
                return -1;
            }
        } else if win32call! {VirtualFree(addr, len, MEM_DECOMMIT)}.0 == 0 {
            return -1;
        }

        0
    }
}

pub unsafe fn mprotect(addr: *mut void, len: size_t, prot: int) -> int {
    if unsafe {
        win32call! { VirtualProtect(addr.cast(), len, prot as _, core::ptr::null_mut()) }.0
    } == 0
    {
        0
    } else {
        -1
    }
}

// ============================================================================
// Anonymous Memory Mapping for Control Channel
// ============================================================================

use super::security_descriptor::SecurityDescriptor;
use core::fmt::{self, Display, Formatter};
use core::hash::Hash;

/// Errors that can occur when creating an anonymous memory mapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AnonymousMappingError {
    /// The requested size is invalid (zero or too large).
    InvalidSize,
    /// Insufficient system resources (handles, kernel objects).
    InsufficientResources,
    /// Insufficient memory to create the mapping.
    InsufficientMemory,
    /// Access was denied (security descriptor rejected access).
    AccessDenied,
    /// An internal Windows error occurred.
    InternalError(u32),
}

impl AnonymousMappingError {
    /// Converts a Win32 error code to an [`AnonymousMappingError`].
    pub fn from_win32(error_code: u32) -> Self {
        use windows_sys::Win32::Foundation::{
            ERROR_ACCESS_DENIED, ERROR_COMMITMENT_LIMIT, ERROR_NOT_ENOUGH_MEMORY,
            ERROR_NO_SYSTEM_RESOURCES, ERROR_OUTOFMEMORY,
        };

        match error_code {
            ERROR_ACCESS_DENIED => AnonymousMappingError::AccessDenied,
            ERROR_NOT_ENOUGH_MEMORY | ERROR_OUTOFMEMORY | ERROR_COMMITMENT_LIMIT => {
                AnonymousMappingError::InsufficientMemory
            }
            ERROR_NO_SYSTEM_RESOURCES => AnonymousMappingError::InsufficientResources,
            _ => AnonymousMappingError::InternalError(error_code),
        }
    }
}

impl Display for AnonymousMappingError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            AnonymousMappingError::InvalidSize => {
                write!(f, "Invalid mapping size")
            }
            AnonymousMappingError::InsufficientResources => {
                write!(f, "Insufficient system resources")
            }
            AnonymousMappingError::InsufficientMemory => {
                write!(f, "Insufficient memory")
            }
            AnonymousMappingError::AccessDenied => {
                write!(f, "Access denied")
            }
            AnonymousMappingError::InternalError(code) => {
                write!(f, "Internal error (code: {})", code)
            }
        }
    }
}

impl core::error::Error for AnonymousMappingError {}

/// Creates an anonymous (unnamed) memory mapping.
///
/// This function creates a file mapping object backed by the system paging file,
/// not associated with any file on disk. This is equivalent to POSIX `shm_open`
/// with `O_CREAT` but without a name.
///
/// Anonymous mappings are useful for control channels where:
/// - The memory doesn't need to be discoverable by name
/// - The handle will be passed directly to clients via handle duplication
/// - Stronger security is desired (no race conditions with named objects)
///
/// # Arguments
///
/// * `size` - The size of the mapping in bytes (must be > 0)
/// * `read_write` - If true, the mapping is read-write; otherwise read-only
/// * `security` - Optional security descriptor; if None, uses default security
///
/// # Returns
///
/// * `Ok(HANDLE)` - The handle to the file mapping object
/// * `Err(AnonymousMappingError)` - If creation failed
///
/// # Example
///
/// ```ignore
/// use iceoryx2_pal_posix::windows::mman::create_anonymous_mapping;
/// use iceoryx2_pal_posix::windows::security_descriptor::SecurityDescriptor;
///
/// // Create with default security
/// let handle = create_anonymous_mapping(4096, true, None)?;
///
/// // Create with custom security
/// let sd = SecurityDescriptor::owner_only()?;
/// let handle = create_anonymous_mapping(4096, true, Some(&sd))?;
/// ```
///
/// # Safety
///
/// The caller is responsible for:
/// - Closing the returned handle with `CloseHandle` when done
/// - Ensuring the handle is not used after being closed
pub fn create_anonymous_mapping(
    size: usize,
    read_write: bool,
    security: Option<&SecurityDescriptor>,
) -> Result<HANDLE, AnonymousMappingError> {
    if size == 0 {
        return Err(AnonymousMappingError::InvalidSize);
    }

    // Calculate high and low parts of size for 64-bit support
    let size_low: u32 = (size & 0xFFFFFFFF) as u32;
    let size_high: u32 = (size.overflowing_shr(32).0 & 0xFFFFFFFF) as u32;

    // Determine protection flags
    let protect = if read_write {
        PAGE_READWRITE
    } else {
        PAGE_READONLY
    };

    // Get security attributes pointer
    let security_attrs = security.map(|sd| sd.as_security_attributes());
    let security_ptr = match &security_attrs {
        Some(attrs) => attrs as *const SECURITY_ATTRIBUTES,
        None => core::ptr::null(),
    };

    // SAFETY: CreateFileMappingW is called with:
    // - INVALID_HANDLE_VALUE to create a mapping backed by the system paging file
    // - Valid (or null) security attributes pointer
    // - Valid protection flags
    // - Valid size parameters
    // - NULL for the name (anonymous mapping)
    let handle = unsafe {
        CreateFileMappingW(
            INVALID_HANDLE_VALUE,
            security_ptr,
            protect,
            size_high,
            size_low,
            core::ptr::null(), // Anonymous - no name
        )
    };

    if handle == 0 {
        let error = unsafe { windows_sys::Win32::Foundation::GetLastError() };
        return Err(AnonymousMappingError::from_win32(error));
    }

    Ok(handle)
}

#[cfg(test)]
mod anonymous_mapping_tests {
    extern crate std;
    use super::*;
    use alloc::format;

    #[test]
    fn test_anonymous_mapping_error_display() {
        assert_eq!(
            format!("{}", AnonymousMappingError::InvalidSize),
            "Invalid mapping size"
        );
        assert_eq!(
            format!("{}", AnonymousMappingError::InsufficientResources),
            "Insufficient system resources"
        );
        assert_eq!(
            format!("{}", AnonymousMappingError::InsufficientMemory),
            "Insufficient memory"
        );
        assert_eq!(
            format!("{}", AnonymousMappingError::AccessDenied),
            "Access denied"
        );
        assert_eq!(
            format!("{}", AnonymousMappingError::InternalError(42)),
            "Internal error (code: 42)"
        );
    }

    #[test]
    #[allow(clippy::clone_on_copy)]
    fn test_anonymous_mapping_error_traits() {
        // Test Clone
        let error = AnonymousMappingError::InvalidSize;
        let cloned = error.clone();
        assert_eq!(error, cloned);

        // Test Copy
        let copied = error;
        assert_eq!(error, copied);

        // Test Hash
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(AnonymousMappingError::InvalidSize);
        set.insert(AnonymousMappingError::AccessDenied);
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn test_create_anonymous_mapping_zero_size() {
        let result = create_anonymous_mapping(0, true, None);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), AnonymousMappingError::InvalidSize);
    }

    #[test]
    fn test_create_anonymous_mapping_basic() {
        let result = create_anonymous_mapping(4096, true, None);
        assert!(result.is_ok(), "Failed to create anonymous mapping");

        let handle = result.unwrap();
        assert!(handle != 0);

        // Clean up
        unsafe { CloseHandle(handle) };
    }

    #[test]
    fn test_create_anonymous_mapping_read_only() {
        let result = create_anonymous_mapping(4096, false, None);
        assert!(
            result.is_ok(),
            "Failed to create read-only anonymous mapping"
        );

        let handle = result.unwrap();
        assert!(handle != 0);

        // Clean up
        unsafe { CloseHandle(handle) };
    }

    #[test]
    fn test_create_anonymous_mapping_with_security() {
        let sd = SecurityDescriptor::everyone_full_access()
            .expect("Failed to create security descriptor");
        let result = create_anonymous_mapping(4096, true, Some(&sd));
        assert!(
            result.is_ok(),
            "Failed to create anonymous mapping with security"
        );

        let handle = result.unwrap();
        assert!(handle != 0);

        // Clean up
        unsafe { CloseHandle(handle) };
    }

    #[test]
    fn test_create_anonymous_mapping_large_size() {
        // 1 GB mapping - should succeed as it's just reserving address space
        let result = create_anonymous_mapping(1024 * 1024 * 1024, true, None);

        // This might fail on systems with low resources, so we just check it doesn't panic
        if let Ok(handle) = result {
            unsafe { CloseHandle(handle) };
        }
    }

    #[test]
    fn test_create_anonymous_mapping_can_map_view() {
        let result = create_anonymous_mapping(4096, true, None);
        assert!(result.is_ok());

        let handle = result.unwrap();

        // Map a view of the file mapping
        let view = unsafe { MapViewOfFile(handle, FILE_MAP_ALL_ACCESS, 0, 0, 4096) };
        assert!(view != 0, "Failed to map view of anonymous mapping");

        // Write to the mapping to verify it works
        unsafe {
            let ptr = view as *mut u8;
            *ptr = 42;
            assert_eq!(*ptr, 42);
        }

        // Clean up
        unsafe {
            UnmapViewOfFile(view);
            CloseHandle(handle);
        }
    }

    #[test]
    fn test_error_from_win32() {
        use windows_sys::Win32::Foundation::{
            ERROR_ACCESS_DENIED, ERROR_NOT_ENOUGH_MEMORY, ERROR_NO_SYSTEM_RESOURCES,
        };

        assert_eq!(
            AnonymousMappingError::from_win32(ERROR_ACCESS_DENIED),
            AnonymousMappingError::AccessDenied
        );
        assert_eq!(
            AnonymousMappingError::from_win32(ERROR_NOT_ENOUGH_MEMORY),
            AnonymousMappingError::InsufficientMemory
        );
        assert_eq!(
            AnonymousMappingError::from_win32(ERROR_NO_SYSTEM_RESOURCES),
            AnonymousMappingError::InsufficientResources
        );
        assert!(matches!(
            AnonymousMappingError::from_win32(9999),
            AnonymousMappingError::InternalError(9999)
        ));
    }
}
