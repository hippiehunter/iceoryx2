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

//! Windows E2E test server binary.
//!
//! Provides multiple subcommands for different test scenarios.
//! Communicates state via stdout markers that the test coordinator matches.

use clap::{Parser, Subcommand};

// Link in the logger implementation (provides __internal_default_logger)
#[cfg(target_os = "windows")]
extern crate iceoryx2_bb_loggers;

#[derive(Parser)]
#[command(about = "Windows e2e test server")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Named pipe echo server: accept, read, echo back
    PipeEcho {
        #[arg(long)]
        pipe_name: String,
        /// Use timed accept with this timeout in ms (omit for blocking accept)
        #[arg(long)]
        timed_accept_ms: Option<u64>,
    },
    /// Named pipe credential extraction server
    PipeCreds {
        #[arg(long)]
        pipe_name: String,
    },
    /// Handle duplication sender: create mapping, dup to client, send handle
    HandleSend {
        #[arg(long)]
        pipe_name: String,
    },
    /// CAL control channel listener
    CalListener {
        #[arg(long)]
        channel_name: String,
    },
}

fn main() {
    let cli = Cli::parse();
    match cli.command {
        Commands::PipeEcho {
            pipe_name,
            timed_accept_ms,
        } => {
            #[cfg(target_os = "windows")]
            cmd_pipe_echo(&pipe_name, timed_accept_ms);
            #[cfg(not(target_os = "windows"))]
            {
                let _ = (pipe_name, timed_accept_ms);
                eprintln!("This binary only runs on Windows");
                std::process::exit(1);
            }
        }
        Commands::PipeCreds { pipe_name } => {
            #[cfg(target_os = "windows")]
            cmd_pipe_creds(&pipe_name);
            #[cfg(not(target_os = "windows"))]
            {
                let _ = pipe_name;
                eprintln!("This binary only runs on Windows");
                std::process::exit(1);
            }
        }
        Commands::HandleSend { pipe_name } => {
            #[cfg(target_os = "windows")]
            cmd_handle_send(&pipe_name);
            #[cfg(not(target_os = "windows"))]
            {
                let _ = pipe_name;
                eprintln!("This binary only runs on Windows");
                std::process::exit(1);
            }
        }
        Commands::CalListener { channel_name } => {
            #[cfg(target_os = "windows")]
            cmd_cal_listener(&channel_name);
            #[cfg(not(target_os = "windows"))]
            {
                let _ = channel_name;
                eprintln!("This binary only runs on Windows");
                std::process::exit(1);
            }
        }
    }
}

// ============================================================================
// Windows implementations
// ============================================================================

#[cfg(target_os = "windows")]
fn cmd_pipe_echo(pipe_name: &str, timed_accept_ms: Option<u64>) {
    use iceoryx2_pal_posix::windows::named_pipe::{NamedPipeError, NamedPipeServer};
    use std::time::Duration;

    let mut server = match NamedPipeServer::create(pipe_name.as_bytes(), 0o600) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("SERVER: failed to create pipe: {:?}", e);
            std::process::exit(1);
        }
    };
    println!("SERVER: listening on {}", pipe_name);

    let conn = if let Some(ms) = timed_accept_ms {
        match server.timed_accept(Duration::from_millis(ms)) {
            Ok(Some(c)) => c,
            Ok(None) => {
                println!("SERVER: timed_accept timeout");
                return;
            }
            Err(e) => {
                eprintln!("SERVER: timed_accept error: {:?}", e);
                std::process::exit(1);
            }
        }
    } else {
        match server.blocking_accept() {
            Ok(c) => c,
            Err(e) => {
                eprintln!("SERVER: blocking_accept error: {:?}", e);
                std::process::exit(1);
            }
        }
    };
    println!("SERVER: client connected");

    let mut buf = vec![0u8; 65536];
    loop {
        match conn.blocking_read(&mut buf) {
            Ok(n) if n > 0 => {
                let data = String::from_utf8_lossy(&buf[..n]);
                println!("SERVER: received '{}'", data);

                match conn.write(&buf[..n]) {
                    Ok(written) => {
                        let _ = conn.flush();
                        println!("SERVER: sent '{}' ({} bytes)", data, written);
                    }
                    Err(NamedPipeError::BrokenPipe) => {
                        println!("SERVER: client disconnected");
                        return;
                    }
                    Err(e) => {
                        eprintln!("SERVER: write error: {:?}", e);
                        std::process::exit(1);
                    }
                }
            }
            Ok(_) => {
                println!("SERVER: client disconnected");
                return;
            }
            Err(NamedPipeError::BrokenPipe) => {
                println!("SERVER: client disconnected");
                return;
            }
            Err(e) => {
                eprintln!("SERVER: read error: {:?}", e);
                std::process::exit(1);
            }
        }
    }
}

#[cfg(target_os = "windows")]
fn cmd_pipe_creds(pipe_name: &str) {
    use iceoryx2_pal_posix::windows::named_pipe::NamedPipeServer;

    let mut server = match NamedPipeServer::create(pipe_name.as_bytes(), 0o600) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("SERVER: failed to create pipe: {:?}", e);
            std::process::exit(1);
        }
    };
    println!("SERVER: listening on {}", pipe_name);

    let mut conn = match server.blocking_accept() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("SERVER: blocking_accept error: {:?}", e);
            std::process::exit(1);
        }
    };
    println!("SERVER: client connected");

    match conn.client_process_id() {
        Ok(pid) => println!("SERVER: client_pid={}", pid),
        Err(e) => {
            eprintln!("SERVER: client_process_id error: {:?}", e);
            std::process::exit(1);
        }
    }

    match conn.peer_credentials() {
        Ok(creds) => {
            let sid_str = match creds.user_sid() {
                Some(sid) => format_sid(sid),
                None => "None".to_string(),
            };
            println!("SERVER: user_sid={}", sid_str);

            let group_count = match creds.group_sids() {
                Some(groups) => groups.len(),
                None => 0,
            };
            println!("SERVER: group_count={}", group_count);
        }
        Err(e) => {
            eprintln!("SERVER: peer_credentials error: {:?}", e);
            std::process::exit(1);
        }
    }

    // Signal completion to client by writing a byte
    let _ = conn.write(b"done");
    let _ = conn.flush();
    println!("SERVER: done");
}

#[cfg(target_os = "windows")]
fn format_sid(sid: &iceoryx2_pal_posix::windows::security_descriptor::Sid) -> String {
    use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
    use windows_sys::Win32::System::Memory::LocalFree;

    let raw = sid.as_bytes().as_ptr();
    let mut string_sid: *mut u16 = std::ptr::null_mut();
    unsafe {
        if ConvertSidToStringSidW(raw as *mut _, &mut string_sid) != 0 {
            let len = {
                let mut l = 0;
                while *string_sid.add(l) != 0 {
                    l += 1;
                }
                l
            };
            let s = String::from_utf16_lossy(std::slice::from_raw_parts(string_sid, len));
            LocalFree(string_sid as isize);
            s
        } else {
            // Fallback: hex dump
            let bytes = sid.as_bytes();
            bytes
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect::<Vec<_>>()
                .join("")
        }
    }
}

#[cfg(target_os = "windows")]
fn cmd_handle_send(pipe_name: &str) {
    use iceoryx2_pal_posix::windows::handle_passing::{
        duplicate_handle_to_process, DuplicateOptions,
    };
    use iceoryx2_pal_posix::windows::named_pipe::NamedPipeServer;
    use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
    use windows_sys::Win32::System::Memory::{
        CreateFileMappingW, MapViewOfFile, UnmapViewOfFile, FILE_MAP_WRITE, PAGE_READWRITE,
    };

    let mut server = match NamedPipeServer::create(pipe_name.as_bytes(), 0o600) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("SERVER: failed to create pipe: {:?}", e);
            std::process::exit(1);
        }
    };
    println!("SERVER: listening on {}", pipe_name);

    let conn = match server.blocking_accept() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("SERVER: blocking_accept error: {:?}", e);
            std::process::exit(1);
        }
    };
    println!("SERVER: client connected");

    // Read client PID
    let mut pid_buf = [0u8; 4];
    match conn.blocking_read(&mut pid_buf) {
        Ok(4) => {}
        Ok(n) => {
            eprintln!("SERVER: expected 4 bytes for PID, got {}", n);
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("SERVER: read PID error: {:?}", e);
            std::process::exit(1);
        }
    }
    let client_pid = u32::from_le_bytes(pid_buf);
    println!("SERVER: read client_pid={}", client_pid);

    // Create a file mapping with magic bytes
    let magic: u32 = 0xDEADBEEF;
    let mapping_handle = unsafe {
        CreateFileMappingW(
            INVALID_HANDLE_VALUE,
            std::ptr::null(),
            PAGE_READWRITE,
            0,
            4096,
            std::ptr::null(),
        )
    };
    if mapping_handle == 0 {
        eprintln!("SERVER: CreateFileMappingW failed");
        std::process::exit(1);
    }

    // Write magic bytes into the mapping
    let view = unsafe { MapViewOfFile(mapping_handle, FILE_MAP_WRITE, 0, 0, 4096) };
    if view == 0 {
        eprintln!("SERVER: MapViewOfFile failed");
        std::process::exit(1);
    }
    unsafe {
        std::ptr::write(view as *mut u32, magic);
        UnmapViewOfFile(view);
    }

    // Duplicate handle to client process
    let dup_handle = match duplicate_handle_to_process(
        mapping_handle as isize,
        client_pid,
        DuplicateOptions::same_access(),
    ) {
        Ok(h) => h,
        Err(e) => {
            eprintln!("SERVER: duplicate_handle_to_process error: {:?}", e);
            std::process::exit(1);
        }
    };
    println!("SERVER: duplicated handle={}", dup_handle);

    // Send the duplicated handle value to client over pipe
    let handle_bytes = (dup_handle as u64).to_le_bytes();
    match conn.write(&handle_bytes) {
        Ok(_) => {
            let _ = conn.flush();
            println!("SERVER: handle sent");
        }
        Err(e) => {
            eprintln!("SERVER: write handle error: {:?}", e);
            std::process::exit(1);
        }
    }

    // Wait for client ack before exiting (so mapping stays alive)
    let mut ack = [0u8; 4];
    let _ = conn.blocking_read(&mut ack);
    println!("SERVER: done");

    unsafe {
        windows_sys::Win32::Foundation::CloseHandle(mapping_handle);
    }
}

#[cfg(target_os = "windows")]
fn cmd_cal_listener(channel_name: &str) {
    use iceoryx2_bb_system_types::base64url::SemanticString;
    use iceoryx2_bb_system_types::file_name::FileName;
    use iceoryx2_cal::control_channel::named_pipe::ListenerBuilder;
    use iceoryx2_cal::control_channel::{
        ControlChannelConnection, ControlChannelListener, ControlChannelListenerBuilder,
    };
    use iceoryx2_cal::named_concept::NamedConceptBuilder;

    let name = unsafe { FileName::new_unchecked(channel_name.as_bytes()) };
    let listener = match ListenerBuilder::new(&name).create() {
        Ok(l) => l,
        Err(e) => {
            eprintln!("SERVER: cal listener create error: {:?}", e);
            std::process::exit(1);
        }
    };
    println!("SERVER: cal listening on {}", channel_name);

    let conn = match listener.blocking_accept() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("SERVER: cal blocking_accept error: {:?}", e);
            std::process::exit(1);
        }
    };
    println!("SERVER: cal client connected");

    // Extract credentials
    match conn.peer_credentials() {
        Ok(creds) => {
            println!("SERVER: cal client_pid={}", creds.pid());
        }
        Err(e) => {
            eprintln!("SERVER: cal peer_credentials error: {:?}", e);
            std::process::exit(1);
        }
    }

    // Send data
    match conn.send(b"hello from server") {
        Ok(()) => println!("SERVER: cal sent data"),
        Err(e) => {
            eprintln!("SERVER: cal send error: {:?}", e);
            std::process::exit(1);
        }
    }

    println!("SERVER: cal done");
}
