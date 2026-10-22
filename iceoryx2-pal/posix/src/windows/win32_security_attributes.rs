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

#![allow(dead_code)]
#![allow(unused_variables)]

use windows_sys::Win32::Foundation::{ERROR_SUCCESS, FALSE, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Security::Authorization::{
    ConvertSecurityDescriptorToStringSecurityDescriptorA,
    ConvertStringSecurityDescriptorToSecurityDescriptorA,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidA, GetSecurityInfo, SDDL_REVISION_1, SE_FILE_OBJECT,
};
use windows_sys::Win32::Security::{
    ACL, DACL_SECURITY_INFORMATION, GetSecurityDescriptorOwner, OWNER_SECURITY_INFORMATION,
    PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES,
};
use windows_sys::Win32::System::Memory::LocalFree;

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use std::sync::{OnceLock, RwLock};

use crate::posix::{S_IRGRP, S_IROTH, S_IWGRP, S_IWOTH, S_IXGRP, S_IXOTH, mode_t};
use crate::posix::{S_IRUSR, S_IWUSR, S_IXUSR, types::*};

// SID String Mappings
// syntax:
// ace_type;ace_flags;rights;object_guid;inherit_object_guid;account_sid
// ace_type:
//     A = allow
//     D = deny
// ace_flags:
//     OI = OBJECT_INHERIT_ACE
//     CI = CONTAINER_INHERIT_ACE
// rights:
//     GA = Generic All
//     GR = Generic Read
//     GW = Generic Write
//     GX = Generic Execute
//     SD = Delete permission
// object_guid:
//     empty
// inherit_object_guid:
//     empty
// account_sid:
//     WD - Everyone (posix: others)
//     SY - Local System
//     SU - Service Logon User (group) (posix: group)
//     PS - Principal Self
//     OW - Owner Rights (posix: owner)
//     CO - Creator Owner
//     CG - Creator Group
//     BA - Builtin Administrator
//     BG - Builtin Guests
//     BU - Builtin Users

// https://learn.microsoft.com/en-us/windows/win32/secauthz/ace-strings
// https://learn.microsoft.com/en-us/windows/win32/secauthz/sid-strings
const SID_LENGTH: usize = 255;
const GENERIC_PERM_ALL: &[u8] = b"GA";
const GENERIC_PERM_READ: &[u8] = b"GR";
const GENERIC_PERM_WRITE: &[u8] = b"GW";
const GENERIC_PERM_EXECUTE: &[u8] = b"GX";
const FILE_PERM_ALL: &[u8] = b"FA";
const FILE_PERM_READ: &[u8] = b"FR";
const FILE_PERM_WRITE: &[u8] = b"FW";
const FILE_PERM_EXECUTE: &[u8] = b"FX";
const ACE_INHERITANCE: &[u8] = b"OICI";
const DELETE: &[u8] = b"SD";

const IDENT_OTHERS: &[u8] = b"WD";
const IDENT_GROUP: &[u8] = b"SU";
const IDENT_OWNER: &[u8] = b"BU";

/// The SID (string form) that the POSIX group class names in the DACLs this process creates.
/// `None` keeps the single-user mapping, where the group class is `SU` and the owner class
/// `BU`.
static SHARED_GROUP: RwLock<Option<String>> = RwLock::new(None);

/// Makes the POSIX group class of every DACL this process creates from a mode name `group`
/// (a SID string such as `S-1-5-21-...-1001`), and the owner class the process's own user,
/// so that a mode like `0660` admits the owner and the members of `group` only. Windows
/// objects have no owning group, so this stands in for handing objects to a group (and for
/// the set-group-id directories that do so on POSIX): multi-user secured mode sets it from
/// `shared-group` before it creates anything. It applies to the whole process.
pub fn set_shared_group(group: Option<&str>) {
    let canonical = group.map(|sid| sddl_account(sid).unwrap_or_else(|| String::from(sid)));
    let mut shared = SHARED_GROUP.write().unwrap_or_else(|e| e.into_inner());
    *shared = canonical;
}

/// How SDDL renders the account `sid` in an ACE: well-known SIDs as their two-letter alias
/// (`S-1-5-20` as `NS`, `S-1-5-32-545` as `BU`), all others as `S-...`. DACLs read back are
/// compared in this form.
fn sddl_account(sid: &str) -> Option<String> {
    let sddl = alloc::format!("D:(A;;GA;;;{sid})\0");
    let mut descriptor: PSECURITY_DESCRIPTOR = core::ptr::null_mut::<void>();
    let (converted, _) = unsafe {
        win32call! { ConvertStringSecurityDescriptorToSecurityDescriptorA(
            sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut descriptor,
            core::ptr::null_mut::<u32>(),
        ) }
    };
    if converted == FALSE {
        return None;
    }
    let mut raw: *mut u8 = core::ptr::null_mut();
    let mut raw_length = 0;
    let (rendered, _) = unsafe {
        win32call! { ConvertSecurityDescriptorToStringSecurityDescriptorA(
            descriptor,
            SDDL_REVISION_1,
            DACL_SECURITY_INFORMATION,
            &mut raw,
            &mut raw_length,
        ) }
    };
    let account = if rendered == FALSE {
        None
    } else {
        let text = unsafe { core::slice::from_raw_parts(raw, raw_length as usize) };
        let account = extract_ace_entries(text)
            .first()
            .map(|entry| extract_ace_entry_sections(entry).2)
            .and_then(|account| core::str::from_utf8(account).ok())
            .map(|account| String::from(account.trim_end_matches('\0')));
        unsafe {
            win32call! { LocalFree(raw as isize) }
        };
        account
    };
    unsafe {
        win32call! { LocalFree(descriptor as isize) }
    };
    account
}

/// The SID string set with [`set_shared_group`], if any.
pub fn shared_group() -> Option<String> {
    SHARED_GROUP
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .clone()
}

/// This process's user as SDDL names it (see [`sddl_account`]), read from its token once.
fn process_user_sid() -> Option<&'static str> {
    static USER: OnceLock<Option<String>> = OnceLock::new();
    USER.get_or_init(|| {
        let pid = unsafe { windows_sys::Win32::System::Threading::GetCurrentProcessId() };
        let sid = super::process_token::get_process_token_sids(pid)
            .ok()
            .and_then(|sids| sids.user_sid.to_sid_string())?;
        Some(sddl_account(&sid).unwrap_or(sid))
    })
    .as_deref()
}

/// The identities the owner and group classes of a mode name: the process's user and the
/// shared group when one is set, `BU` and `SU` otherwise.
fn class_identities() -> (Vec<u8>, Vec<u8>) {
    match (shared_group(), process_user_sid()) {
        (Some(group), Some(user)) => (user.as_bytes().to_vec(), group.into_bytes()),
        _ => (IDENT_OWNER.to_vec(), IDENT_GROUP.to_vec()),
    }
}

#[derive(Clone, Copy)]
enum Class {
    Owner,
    Group,
    Others,
}

// Windows access rights constants as HEX
// https://learn.microsoft.com/en-us/windows/win32/fileio/file-access-rights-constants
// https://learn.microsoft.com/en-us/windows/win32/secauthz/access-mask
const FILE_READ_DATA_HEX: u32 = 0x1;
const FILE_WRITE_DATA_HEX: u32 = 0x2;
const FILE_EXECUTE_HEX: u32 = 0x20;
const FILE_READ_ATTRIBUTES_HEX: u32 = 0x80;
const FILE_WRITE_ATTRIBUTES_HEX: u32 = 0x100;
const DELETE_HEX: u32 = 0x10000;

fn add_to_sd_string(data: &mut [u8], add: &[u8]) {
    let mut start_adding = false;
    let mut start = 0;

    for i in 0..data.len() {
        if data[i] == b'\0' && !start_adding {
            start_adding = true;
            start = i;
        }

        if start_adding {
            if i - start >= add.len() {
                data[i] = b'\0';
                break;
            } else {
                data[i] = add[i - start];
            }
        }
    }
}

macro_rules! add_to_ace_string {
    ($data:expr, $($value:expr),*) => {
        $(add_to_sd_string($data, ($value)));*
    };
}

fn get_owner_sid(handle: HANDLE) -> [u8; SID_LENGTH] {
    let mut sid = [0u8; SID_LENGTH];
    if handle == INVALID_HANDLE_VALUE {
        sid[0] = IDENT_OWNER[0];
        sid[1] = IDENT_OWNER[1];
        return sid;
    }

    let mut security_descriptor: PSECURITY_DESCRIPTOR = core::ptr::null_mut::<void>();

    if unsafe {
        GetSecurityInfo(
            handle,
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION,
            core::ptr::null_mut::<*mut void>(),
            core::ptr::null_mut::<*mut void>(),
            core::ptr::null_mut::<*mut ACL>(),
            core::ptr::null_mut::<*mut ACL>(),
            &mut security_descriptor,
        )
    } != ERROR_SUCCESS
    {
        return sid;
    }

    let mut owner_sid = core::ptr::null_mut::<void>();
    let mut owner_defaulted = FALSE;

    let (has_read_owner, _) = unsafe {
        win32call! {GetSecurityDescriptorOwner(security_descriptor, &mut owner_sid, &mut owner_defaulted)}
    };
    if has_read_owner == FALSE {
        unsafe {
            win32call! {LocalFree(security_descriptor as isize) }
        };
        return sid;
    }

    let mut owner_str = core::ptr::null_mut::<u8>();

    let (convert_result, _) = unsafe {
        win32call! {ConvertSidToStringSidA(owner_sid, &mut owner_str)}
    };
    if convert_result == FALSE {
        unsafe {
            win32call! {LocalFree(security_descriptor as isize) }
        };
        return sid;
    }

    unsafe {
        win32call! {LocalFree(security_descriptor as isize)}
    };
    unsafe {
        win32call! {LocalFree(owner_str as isize)}
    };

    for (i, sid_element) in sid.iter_mut().enumerate().take(SID_LENGTH) {
        let c = unsafe { *owner_str.add(i) };
        if c == b'\0' {
            break;
        }
        *sid_element = c;
    }

    sid
}

pub fn from_mode_to_security_attributes(mode: mode_t) -> SECURITY_ATTRIBUTES {
    let mut attr = SECURITY_ATTRIBUTES {
        nLength: core::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: core::ptr::null_mut::<void>(),
        bInheritHandle: FALSE,
    };

    // SIDs in string form make the ACEs long; the buffer holds every ACE below with room.
    let mut buffer = [0u8; 4096];
    let (owner_ident, group_ident) = class_identities();

    // deny everything; with a shared group the DACL is protected, so that ACEs inherited from
    // the parent directory do not grant more than the mode does
    if shared_group().is_some() {
        add_to_ace_string!(&mut buffer, b"D:P");
    } else {
        add_to_ace_string!(&mut buffer, b"D:");
    }

    // local system allow everything
    add_to_ace_string!(
        &mut buffer,
        b"(A;",
        ACE_INHERITANCE,
        b";",
        GENERIC_PERM_ALL,
        b";;;SY)"
    );

    // builtin administrator allow everything
    add_to_ace_string!(
        &mut buffer,
        b"(A;",
        ACE_INHERITANCE,
        b";",
        GENERIC_PERM_ALL,
        b";;;BA)"
    );

    let add_permissions = |buffer: &mut [u8], class: Class, ident: &[u8]| {
        // determine which permissions to set based on the class
        let (read_bit, write_bit, exec_bit) = match class {
            Class::Others => (S_IROTH, S_IWOTH, S_IXOTH),
            Class::Group => (S_IRGRP, S_IWGRP, S_IXGRP),
            Class::Owner => (S_IRUSR, S_IWUSR, S_IXUSR),
        };

        let has_read = mode & read_bit != 0;
        let has_write = mode & write_bit != 0;
        let has_exec = mode & exec_bit != 0;

        if has_read && has_write && has_exec {
            // all permissions, including delete
            add_to_ace_string!(
                buffer,
                b"(A;",
                ACE_INHERITANCE,
                b";",
                GENERIC_PERM_ALL,
                DELETE,
                b";;;",
                ident,
                b")"
            );
        } else {
            // individual permissions - use separate ACEs for each
            if has_read {
                add_to_ace_string!(
                    buffer,
                    b"(A;",
                    ACE_INHERITANCE,
                    b";",
                    GENERIC_PERM_READ,
                    b";;;",
                    ident,
                    b")"
                );
            }
            if has_write {
                // include delete permissions with write permissions
                add_to_ace_string!(
                    buffer,
                    b"(A;",
                    ACE_INHERITANCE,
                    b";",
                    GENERIC_PERM_WRITE,
                    DELETE,
                    b";;;",
                    ident,
                    b")"
                );
            }
            if has_exec {
                add_to_ace_string!(
                    buffer,
                    b"(A;",
                    ACE_INHERITANCE,
                    b";",
                    GENERIC_PERM_EXECUTE,
                    b";;;",
                    ident,
                    b")"
                );
            }
        }
    };

    // add permissions for each category
    add_permissions(&mut buffer, Class::Others, IDENT_OTHERS);
    add_permissions(&mut buffer, Class::Group, group_ident.as_slice());
    add_permissions(&mut buffer, Class::Owner, owner_ident.as_slice());

    // A read-only file must stay deletable by its owner: Windows requires DELETE on the object itself.
    add_to_ace_string!(
        &mut buffer,
        b"(A;",
        ACE_INHERITANCE,
        b";",
        DELETE,
        b";;;",
        owner_ident.as_slice(),
        b")"
    );

    let (convert_result, _) = unsafe {
        win32call! { ConvertStringSecurityDescriptorToSecurityDescriptorA(
            buffer.as_ptr(),
            SDDL_REVISION_1,
            &mut attr.lpSecurityDescriptor,
            core::ptr::null_mut::<u32>(),
        ) }
    };

    if convert_result == FALSE {
        return SECURITY_ATTRIBUTES {
            nLength: 0,
            lpSecurityDescriptor: core::ptr::null_mut::<void>(),
            bInheritHandle: FALSE,
        };
    }

    attr
}

fn extract_ace_entry_sections(entry: &[u8]) -> (&[u8], &[u8], &[u8]) {
    let mut iter = entry.split(|c| *c == b';');

    let ace_type = iter.next().unwrap();

    // ace flags
    iter.next();

    let ace_rights = iter.next().unwrap();

    // object guid
    iter.next();
    // inherit object guid
    iter.next();

    let account_sid = iter.next().unwrap();

    (ace_type, ace_rights, account_sid)
}

fn extract_ace_entries(value: &[u8]) -> Vec<&[u8]> {
    let mut ace_entries: Vec<&[u8]> = vec![];

    let mut bracket_counter = 0;
    let mut entry_start = 0;
    for i in 0..value.len() {
        if value[i] == b'(' {
            bracket_counter += 1;
            if bracket_counter == 1 {
                entry_start = i + 1;
            }
        }
        if value[i] == b')' && bracket_counter > 0 {
            bracket_counter -= 1;
            if bracket_counter == 0 {
                ace_entries.push(&value[entry_start..i])
            }
        }
    }

    ace_entries
}

fn parse_hex_rights(hex_str: &str) -> u8 {
    let mut ret_val = 0;
    if let Ok(hex_val) = u32::from_str_radix(hex_str, 16) {
        if (hex_val & FILE_READ_DATA_HEX) != 0 || (hex_val & FILE_READ_ATTRIBUTES_HEX) != 0 {
            ret_val |= 4;
        }
        // `DELETE` is granted on its own, because the POSIX mode cannot express
        // it: only the write bit maps to the POSIX write mode.
        if (hex_val & FILE_WRITE_DATA_HEX) != 0 || (hex_val & FILE_WRITE_ATTRIBUTES_HEX) != 0 {
            ret_val |= 2;
        }
        if (hex_val & FILE_EXECUTE_HEX) != 0 {
            ret_val |= 1;
        }
    }
    ret_val
}

fn parse_ace_string_rights(ace_rights: &[u8]) -> u8 {
    let mut i = 0;
    let mut ret_val = 0;

    while i < ace_rights.len() {
        if i + 2 > ace_rights.len() {
            break;
        }

        let right = &ace_rights[i..i + 2];

        if right == GENERIC_PERM_ALL || right == FILE_PERM_ALL {
            ret_val = 7;
        }
        if right == GENERIC_PERM_READ || right == FILE_PERM_READ {
            ret_val |= 4;
        }
        // `DELETE` is granted on its own, because the POSIX mode cannot express
        // it: only the write bit maps to the POSIX write mode.
        if right == GENERIC_PERM_WRITE || right == FILE_PERM_WRITE {
            ret_val |= 2;
        }
        if right == GENERIC_PERM_EXECUTE || right == FILE_PERM_EXECUTE {
            ret_val |= 1;
        }

        i += 2;
    }

    ret_val
}

fn ace_rights_to_bits(ace_rights: &[u8]) -> u8 {
    if ace_rights.starts_with(b"0x")
        && let Ok(hex_str) = core::str::from_utf8(&ace_rights[2..])
    {
        return parse_hex_rights(hex_str);
    }
    parse_ace_string_rights(ace_rights)
}

fn is_owner(account_sid: &[u8]) -> bool {
    account_sid == IDENT_OWNER
        || (account_sid.len() >= 2 && &account_sid[0..2] == b"S-")
        || (shared_group().is_some() && process_user_sid().map(str::as_bytes) == Some(account_sid))
}

pub fn from_security_attributes_to_mode(value: &SECURITY_ATTRIBUTES) -> mode_t {
    let mut mode: mode_t = 0;
    let mut raw_string: *mut u8 = core::ptr::null_mut();
    let mut raw_string_length = 0;
    let (convert_result, _) = unsafe {
        win32call! { ConvertSecurityDescriptorToStringSecurityDescriptorA(
                value.lpSecurityDescriptor,
                SDDL_REVISION_1,
                DACL_SECURITY_INFORMATION,
                &mut raw_string,
                &mut raw_string_length,
            )
        }
    };
    if convert_result == FALSE {
        return mode;
    }

    let raw_string = unsafe { core::slice::from_raw_parts(raw_string, raw_string_length as usize) };
    let ace_entries = extract_ace_entries(raw_string);

    // group ACEs by identity
    let group_ident = shared_group();
    let mut others_perms = 0u8;
    let mut group_perms = 0u8;
    let mut owner_perms = 0u8;

    for entry in ace_entries {
        let (ace_type, ace_rights, account_sid) = extract_ace_entry_sections(entry);

        if ace_type == b"D" {
            continue;
        }

        let rights_bits = ace_rights_to_bits(ace_rights);

        if account_sid == IDENT_OTHERS {
            others_perms |= rights_bits;
        } else if account_sid == IDENT_GROUP
            || group_ident.as_deref().map(str::as_bytes) == Some(account_sid)
        {
            group_perms |= rights_bits;
        } else if is_owner(account_sid) {
            owner_perms |= rights_bits;
        }
    }

    // consolidate permissions into single POSIX mode
    mode |= others_perms as u64;
    mode |= (group_perms as u64) << 3;
    mode |= (owner_perms as u64) << 6;

    mode
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The shared group applies to the whole process: tests that depend on it run one at a time.
    static SHARED_GROUP_TESTS: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Runs `body` with the shared group set to `group`, then clears it.
    fn with_shared_group(group: Option<&str>, body: impl FnOnce()) {
        let _serial = SHARED_GROUP_TESTS.lock().unwrap_or_else(|e| e.into_inner());
        set_shared_group(group);
        let result = std::panic::catch_unwind(core::panic::AssertUnwindSafe(body));
        set_shared_group(None);
        if let Err(panic) = result {
            std::panic::resume_unwind(panic);
        }
    }

    /// A group SID with no SDDL alias, as a local group's SID would be.
    const SOME_GROUP: &str = "S-1-5-21-1004336348-1177238915-682003330-1001";

    fn with_dacl_string(attr: &SECURITY_ATTRIBUTES, check: impl FnOnce(&str)) {
        let mut raw: *mut u8 = core::ptr::null_mut();
        let mut raw_length = 0;
        let (converted, _) = unsafe {
            win32call! { ConvertSecurityDescriptorToStringSecurityDescriptorA(
                attr.lpSecurityDescriptor,
                SDDL_REVISION_1,
                DACL_SECURITY_INFORMATION,
                &mut raw,
                &mut raw_length,
            ) }
        };
        assert_ne!(converted, FALSE, "the descriptor must render as SDDL");
        let bytes = unsafe { core::slice::from_raw_parts(raw, raw_length as usize) };
        check(core::str::from_utf8(bytes).expect("SDDL is an ASCII string"));
    }

    #[test]
    fn a_read_only_mode_still_grants_delete_to_its_owner() {
        with_shared_group(None, || {
            with_dacl_string(&from_mode_to_security_attributes(S_IRUSR), |dacl| {
                assert!(
                    dacl.contains("SD;;;BU)"),
                    "the POSIX owner identity must be able to delete: {dacl}"
                );
            });
        });
    }

    #[test]
    fn with_a_shared_group_the_group_class_names_it_and_the_owner_class_the_user() {
        with_shared_group(Some(SOME_GROUP), || {
            let user = process_user_sid().expect("the process token names its user");
            let mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP;
            with_dacl_string(&from_mode_to_security_attributes(mode), |dacl| {
                assert!(dacl.contains(&alloc::format!(";;;{SOME_GROUP})")), "{dacl}");
                assert!(dacl.contains(&alloc::format!(";;;{user})")), "{dacl}");
                assert!(!dacl.contains(";;;BU)"), "no access for all users: {dacl}");
                assert!(!dacl.contains(";;;SU)"), "{dacl}");
                assert!(!dacl.contains(";;;WD)"), "{dacl}");
                assert!(dacl.starts_with("D:P"), "nothing is inherited: {dacl}");
            });
        });
    }

    #[test]
    fn with_a_shared_group_the_mode_round_trip_holds() {
        with_shared_group(Some(SOME_GROUP), || {
            for mode in [
                S_IRUSR | S_IWUSR,
                S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP,
                S_IRUSR | S_IWUSR | S_IXUSR | S_IRGRP | S_IWGRP | S_IXGRP,
                S_IRUSR | S_IRGRP | S_IROTH,
            ] {
                let attr = from_mode_to_security_attributes(mode);
                assert_eq!(
                    from_security_attributes_to_mode(&attr),
                    mode,
                    "mode {mode:o} must survive the round trip"
                );
            }
        });
    }

    #[test]
    fn a_shared_group_with_an_sddl_alias_is_recognized_when_read_back() {
        // BUILTIN\Users renders as `BU`, which is also how the owner class reads without a group.
        with_shared_group(Some("S-1-5-32-545"), || {
            let mode = S_IRUSR | S_IWUSR | S_IRGRP;
            let attr = from_mode_to_security_attributes(mode);
            assert_eq!(from_security_attributes_to_mode(&attr), mode);
        });
    }

    #[test]
    fn the_mode_round_trip_survives_the_owner_delete_ace() {
        let _serial = SHARED_GROUP_TESTS.lock().unwrap_or_else(|e| e.into_inner());
        for mode in [
            S_IRUSR,
            S_IWUSR,
            S_IXUSR,
            S_IRUSR | S_IWUSR,
            S_IRUSR | S_IXUSR,
            S_IRGRP | S_IROTH,
            S_IRUSR | S_IWUSR | S_IXUSR,
        ] {
            let attr = from_mode_to_security_attributes(mode);
            assert_eq!(
                from_security_attributes_to_mode(&attr),
                mode,
                "mode {mode:o} must survive the round trip"
            );
        }
    }
}
