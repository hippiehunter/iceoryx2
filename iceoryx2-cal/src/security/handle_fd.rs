// Copyright (c) 2025 Contributors to the Eclipse Foundation
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

//! Internal helpers for converting platform handles into POSIX file descriptors.

use iceoryx2_bb_posix::file_descriptor::FileDescriptor;

use super::{HandleBasedOpenError, PlatformHandle};

#[cfg(unix)]
pub(crate) fn platform_handle_into_fd(
    handle: PlatformHandle,
) -> Result<FileDescriptor, HandleBasedOpenError> {
    let raw_fd = handle.into_raw_fd();
    let fd = FileDescriptor::new(raw_fd);
    if let Some(fd) = fd {
        return Ok(fd);
    }

    unsafe {
        iceoryx2_pal_posix::posix::close(raw_fd);
    }

    Err(HandleBasedOpenError::InvalidHandle)
}

#[cfg(windows)]
pub(crate) fn platform_handle_into_fd(
    handle: PlatformHandle,
) -> Result<FileDescriptor, HandleBasedOpenError> {
    use iceoryx2_pal_posix::posix::F_UNLCK;
    use iceoryx2_pal_posix::windows::win32_handle_translator::{
        FdHandleEntry, FileHandle, HandleTranslator, ShmHandle,
    };
    use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};

    let raw_handle = handle.into_raw_handle();
    if raw_handle.is_null() {
        return Err(HandleBasedOpenError::InvalidHandle);
    }

    let handle_value = raw_handle as isize;
    let raw_fd = HandleTranslator::get_instance().add(FdHandleEntry::SharedMemory(ShmHandle {
        handle: FileHandle {
            handle: handle_value,
            lock_state: F_UNLCK,
        },
        state_handle: INVALID_HANDLE_VALUE,
    }));

    if raw_fd < 0 {
        unsafe {
            CloseHandle(handle_value);
        }
        return Err(HandleBasedOpenError::InternalError);
    }

    let fd = FileDescriptor::new(raw_fd);
    match fd {
        Some(fd) => Ok(fd),
        None => {
            unsafe {
                iceoryx2_pal_posix::posix::close(raw_fd);
            }
            Err(HandleBasedOpenError::InvalidHandle)
        }
    }
}
