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

//! Windows E2E test client binary.
//!
//! Provides multiple subcommands for different test scenarios.
//! Communicates state via stdout markers that the test coordinator matches.

use clap::{Parser, Subcommand};

// Link in the logger implementation (provides __internal_default_logger)
#[cfg(target_os = "windows")]
extern crate iceoryx2_bb_loggers;

#[derive(Parser)]
#[command(about = "Windows e2e test client")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Named pipe echo client: connect, send, receive echo
    PipeEcho {
        #[arg(long)]
        pipe_name: String,
        /// Send a large message of this many bytes instead of a small string
        #[arg(long)]
        large_bytes: Option<usize>,
        /// Number of ping-pong rounds
        #[arg(long, default_value = "1")]
        rounds: usize,
    },
    /// Named pipe credential client: connect so server can extract creds
    PipeCreds {
        #[arg(long)]
        pipe_name: String,
    },
    /// Handle duplication receiver: send PID, receive handle, verify mapping
    HandleReceive {
        #[arg(long)]
        pipe_name: String,
    },
    /// CAL control channel connector
    CalConnector {
        #[arg(long)]
        channel_name: String,
    },
}

fn main() {
    let cli = Cli::parse();
    match cli.command {
        Commands::PipeEcho {
            pipe_name,
            large_bytes,
            rounds,
        } => {
            #[cfg(target_os = "windows")]
            cmd_pipe_echo(&pipe_name, large_bytes, rounds);
            #[cfg(not(target_os = "windows"))]
            {
                let _ = (pipe_name, large_bytes, rounds);
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
        Commands::HandleReceive { pipe_name } => {
            #[cfg(target_os = "windows")]
            cmd_handle_receive(&pipe_name);
            #[cfg(not(target_os = "windows"))]
            {
                let _ = pipe_name;
                eprintln!("This binary only runs on Windows");
                std::process::exit(1);
            }
        }
        Commands::CalConnector { channel_name } => {
            #[cfg(target_os = "windows")]
            cmd_cal_connector(&channel_name);
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
fn cmd_pipe_echo(pipe_name: &str, large_bytes: Option<usize>, rounds: usize) {
    use iceoryx2_pal_posix::windows::named_pipe::NamedPipeConnection;

    let conn = match NamedPipeConnection::connect(pipe_name.as_bytes()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("CLIENT: connect error: {:?}", e);
            std::process::exit(1);
        }
    };
    println!("CLIENT: connected to {}", pipe_name);

    if let Some(size) = large_bytes {
        // Large transfer mode
        let data: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();
        match conn.write(&data) {
            Ok(written) => {
                let _ = conn.flush();
                println!("CLIENT: large sent {} bytes", written);
            }
            Err(e) => {
                eprintln!("CLIENT: large write error: {:?}", e);
                std::process::exit(1);
            }
        }

        let mut buf = vec![0u8; size];
        let mut total_read = 0;
        while total_read < size {
            match conn.blocking_read(&mut buf[total_read..]) {
                Ok(n) if n > 0 => total_read += n,
                Ok(_) => break,
                Err(e) => {
                    eprintln!("CLIENT: large read error: {:?}", e);
                    std::process::exit(1);
                }
            }
        }
        println!("CLIENT: large received {} bytes", total_read);

        if buf[..total_read] == data[..total_read] {
            println!("CLIENT: large transfer verified");
        } else {
            eprintln!("CLIENT: large transfer data mismatch!");
            std::process::exit(1);
        }
    } else {
        // Normal echo rounds
        for round in 0..rounds {
            let msg = format!("ping_{}", round);
            match conn.write(msg.as_bytes()) {
                Ok(_) => {
                    let _ = conn.flush();
                    println!("CLIENT: sent '{}'", msg);
                }
                Err(e) => {
                    eprintln!("CLIENT: write error: {:?}", e);
                    std::process::exit(1);
                }
            }

            let mut buf = [0u8; 1024];
            match conn.blocking_read(&mut buf) {
                Ok(n) => {
                    let data = String::from_utf8_lossy(&buf[..n]);
                    println!("CLIENT: received '{}'", data);
                }
                Err(e) => {
                    eprintln!("CLIENT: read error: {:?}", e);
                    std::process::exit(1);
                }
            }
        }
    }

    println!("CLIENT: done");
}

#[cfg(target_os = "windows")]
fn cmd_pipe_creds(pipe_name: &str) {
    use iceoryx2_pal_posix::windows::named_pipe::NamedPipeConnection;

    println!("CLIENT: my_pid={}", std::process::id());

    let conn = match NamedPipeConnection::connect(pipe_name.as_bytes()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("CLIENT: connect error: {:?}", e);
            std::process::exit(1);
        }
    };
    println!("CLIENT: connected");

    // Wait for server to signal completion
    let mut buf = [0u8; 64];
    let _ = conn.blocking_read(&mut buf);
    println!("CLIENT: done");
}

#[cfg(target_os = "windows")]
fn cmd_handle_receive(pipe_name: &str) {
    use iceoryx2_pal_posix::windows::named_pipe::NamedPipeConnection;
    use windows_sys::Win32::System::Memory::{MapViewOfFile, UnmapViewOfFile, FILE_MAP_READ};

    println!("CLIENT: my_pid={}", std::process::id());

    let conn = match NamedPipeConnection::connect(pipe_name.as_bytes()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("CLIENT: connect error: {:?}", e);
            std::process::exit(1);
        }
    };
    println!("CLIENT: connected");

    // Send our PID to server
    let pid_bytes = std::process::id().to_le_bytes();
    match conn.write(&pid_bytes) {
        Ok(_) => {
            let _ = conn.flush();
        }
        Err(e) => {
            eprintln!("CLIENT: write PID error: {:?}", e);
            std::process::exit(1);
        }
    }
    println!("CLIENT: sent pid");

    // Read duplicated handle value from server
    let mut handle_buf = [0u8; 8];
    match conn.blocking_read(&mut handle_buf) {
        Ok(8) => {}
        Ok(n) => {
            eprintln!("CLIENT: expected 8 bytes for handle, got {}", n);
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("CLIENT: read handle error: {:?}", e);
            std::process::exit(1);
        }
    }
    let handle_value = u64::from_le_bytes(handle_buf);
    println!("CLIENT: received handle={}", handle_value);

    // Map the duplicated handle and read magic
    let view = unsafe { MapViewOfFile(handle_value as isize, FILE_MAP_READ, 0, 0, 4096) };
    if view == 0 {
        eprintln!("CLIENT: MapViewOfFile failed");
        std::process::exit(1);
    }

    let magic = unsafe { std::ptr::read(view as *const u32) };
    unsafe {
        UnmapViewOfFile(view);
    }
    println!("CLIENT: read magic=0x{:08X}", magic);

    if magic == 0xDEADBEEF {
        println!("CLIENT: handle verified");
    } else {
        eprintln!(
            "CLIENT: magic mismatch! expected 0xDEADBEEF, got 0x{:08X}",
            magic
        );
        std::process::exit(1);
    }

    // Send ack to server so it can clean up
    let _ = conn.write(b"ack");
    let _ = conn.flush();

    // Close the duplicated handle
    unsafe {
        windows_sys::Win32::Foundation::CloseHandle(handle_value as isize);
    }
    println!("CLIENT: done");
}

#[cfg(target_os = "windows")]
fn cmd_cal_connector(channel_name: &str) {
    use iceoryx2_bb_system_types::base64url::SemanticString;
    use iceoryx2_bb_system_types::file_name::FileName;
    use iceoryx2_cal::control_channel::named_pipe::ClientBuilder;
    use iceoryx2_cal::control_channel::{ControlChannelClient, ControlChannelClientBuilder};
    use iceoryx2_cal::named_concept::NamedConceptBuilder;
    use std::time::Duration;

    println!("CLIENT: my_pid={}", std::process::id());

    let name = unsafe { FileName::new_unchecked(channel_name.as_bytes()) };

    // Retry connection with a short delay since listener may not be ready
    let client = {
        let mut attempts = 0;
        loop {
            match ClientBuilder::new(&name).connect() {
                Ok(c) => break c,
                Err(e) => {
                    attempts += 1;
                    if attempts > 50 {
                        eprintln!(
                            "CLIENT: cal connect failed after {} attempts: {:?}",
                            attempts, e
                        );
                        std::process::exit(1);
                    }
                    std::thread::sleep(Duration::from_millis(100));
                }
            }
        }
    };
    println!("CLIENT: cal connected");

    // Receive data
    let mut buf = [0u8; 1024];
    match client.receive(&mut buf) {
        Ok(n) => {
            let data = String::from_utf8_lossy(&buf[..n as usize]);
            println!("CLIENT: cal received '{}'", data);
        }
        Err(e) => {
            eprintln!("CLIENT: cal receive error: {:?}", e);
            std::process::exit(1);
        }
    }

    println!("CLIENT: cal done");
}
