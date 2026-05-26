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

//! Test process coordinator for Windows end-to-end tests.
//!
//! Provides `TestProcess`, a Rust replacement for the `expect` scripting
//! framework used by Unix e2e tests. It spawns child processes, captures
//! stdout on a background thread, and provides pattern-matching output
//! assertions with configurable timeouts.
//!
//! # Usage from integration tests
//!
//! ```ignore
//! // In tests/*.rs — env!() resolves at compile time in integration tests
//! const SERVER_EXE: &str = env!("CARGO_BIN_EXE_win-e2e-server");
//! const CLIENT_EXE: &str = env!("CARGO_BIN_EXE_win-e2e-client");
//!
//! let server = TestProcess::spawn(SERVER_EXE, "server", &["pipe-echo", "--pipe-name", "test"]);
//! ```

use std::io::BufRead;
use std::process::{Child, Command, Stdio};
#[allow(clippy::disallowed_types)]
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

/// Default timeout for expect_output calls.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);

/// Generate a unique pipe/channel name for test isolation.
///
/// Each call returns a distinct name incorporating the process ID and an
/// atomic counter, preventing collisions between parallel tests.
pub fn unique_name(prefix: &str) -> String {
    #[allow(clippy::disallowed_types)]
    static COUNTER: AtomicU32 = AtomicU32::new(0);
    let id = COUNTER.fetch_add(1, Ordering::SeqCst);
    format!("iox2_e2e_{}_{}_{}", prefix, std::process::id(), id)
}

/// A spawned test process with captured stdout.
///
/// Stdout is read line-by-line on a background thread and buffered.
/// `expect_output` searches the buffer for matching lines with a timeout.
/// The process is killed on drop to prevent orphaned children.
pub struct TestProcess {
    child: Child,
    stdout_lines: Arc<Mutex<Vec<String>>>,
    _reader: Option<JoinHandle<()>>,
    name: String,
}

impl TestProcess {
    /// Spawn a binary at `exe_path` with the given arguments.
    ///
    /// `label` is a human-readable name used in error messages (e.g., "server", "client").
    ///
    /// In integration tests, use `env!("CARGO_BIN_EXE_<name>")` to obtain `exe_path`:
    /// ```ignore
    /// TestProcess::spawn(env!("CARGO_BIN_EXE_win-e2e-server"), "server", &["pipe-echo"])
    /// ```
    pub fn spawn(exe_path: &str, label: &str, args: &[&str]) -> Self {
        let mut child = Command::new(exe_path)
            .args(args)
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap_or_else(|e| panic!("Failed to spawn {label} ({exe_path}): {e}"));

        let stdout = child.stdout.take().expect("stdout must be piped");
        let lines: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let lines_clone = Arc::clone(&lines);

        let reader = thread::spawn(move || {
            let reader = std::io::BufReader::new(stdout);
            for line in reader.lines() {
                match line {
                    Ok(l) => {
                        lines_clone.lock().unwrap().push(l);
                    }
                    Err(_) => break,
                }
            }
        });

        TestProcess {
            child,
            stdout_lines: lines,
            _reader: Some(reader),
            name: label.to_string(),
        }
    }

    /// Block until a stdout line containing `pattern` appears, or timeout.
    ///
    /// Returns the full matching line on success. On timeout, returns an error
    /// with all captured lines for debugging.
    pub fn expect_output(&self, pattern: &str, timeout: Duration) -> Result<String, String> {
        let start = Instant::now();
        let mut last_checked = 0;

        loop {
            {
                let lines = self.stdout_lines.lock().unwrap();
                for line in lines.iter().skip(last_checked) {
                    if line.contains(pattern) {
                        return Ok(line.clone());
                    }
                }
                last_checked = lines.len();
            }

            if start.elapsed() >= timeout {
                let lines = self.stdout_lines.lock().unwrap();
                return Err(format!(
                    "[{}] Timed out after {:?} waiting for pattern '{}'. Captured {} lines:\n{}",
                    self.name,
                    timeout,
                    pattern,
                    lines.len(),
                    lines.join("\n"),
                ));
            }

            thread::sleep(Duration::from_millis(10));
        }
    }

    /// Convenience wrapper using the default timeout.
    pub fn expect(&self, pattern: &str) -> Result<String, String> {
        self.expect_output(pattern, DEFAULT_TIMEOUT)
    }

    /// Kill the process immediately.
    pub fn terminate(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }

    /// Wait for the process to exit naturally within `timeout`.
    /// Returns the exit code on success.
    pub fn wait_exit(&mut self, timeout: Duration) -> Result<i32, String> {
        let start = Instant::now();
        loop {
            match self.child.try_wait() {
                Ok(Some(status)) => {
                    return Ok(status.code().unwrap_or(-1));
                }
                Ok(None) => {
                    if start.elapsed() >= timeout {
                        let _ = self.child.kill();
                        let _ = self.child.wait();
                        return Err(format!(
                            "[{}] Process did not exit within {:?}",
                            self.name, timeout
                        ));
                    }
                    thread::sleep(Duration::from_millis(10));
                }
                Err(e) => {
                    return Err(format!("[{}] Error waiting for process: {}", self.name, e));
                }
            }
        }
    }

    /// Get the OS process ID.
    pub fn pid(&self) -> u32 {
        self.child.id()
    }

    /// Get all captured stdout lines so far.
    pub fn captured_lines(&self) -> Vec<String> {
        self.stdout_lines.lock().unwrap().clone()
    }
}

impl Drop for TestProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unique_name_generates_distinct_names() {
        let a = unique_name("test");
        let b = unique_name("test");
        assert_ne!(a, b);
        assert!(a.starts_with("iox2_e2e_test_"));
        assert!(b.starts_with("iox2_e2e_test_"));
    }
}
