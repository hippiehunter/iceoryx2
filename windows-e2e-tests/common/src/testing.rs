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

/// Print success marker and exit. Used by test binaries to signal pass.
#[allow(dead_code)]
pub fn pass_test() {
    println!("TEST SUCCEEDED!");
    std::process::exit(0);
}

/// Print failure marker and exit. Used by test binaries to signal failure.
#[allow(dead_code)]
pub fn fail_test(message: &str) -> ! {
    eprintln!("TEST FAILED: {}", message);
    std::process::exit(-128_i32);
}
