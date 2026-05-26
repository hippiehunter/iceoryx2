// Copyright (c) 2026 Contributors to the Eclipse Foundation
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

//! Shared harness for the Linux cross-process secured-IPC end-to-end tests.
//!
//! * [`coordinator`] is copied verbatim from `windows-e2e-tests` (it is 100%
//!   `std`-only and portable). Unlike the Windows crate it is **not** gated
//!   behind `#[cfg(target_os = "windows")]` because it runs on Linux here.
//! * [`scenario`] holds the code that MUST be identical in both child binaries:
//!   the `secured_config()` builder (so the server and client rendezvous on the
//!   same IAM endpoint) and the shared CLI definition.

pub mod coordinator;
pub mod scenario;
