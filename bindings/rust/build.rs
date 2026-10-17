// MIT License
//
// Copyright (c) 2026 ActivationSystem Contributors
//
// Zero-dependency build: compile the vendored C99 core with the
// system toolchain ($CC / cc / clang / gcc). No cc crate, no network
// access, no cargo build-dependencies.

use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    let manifest = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let vendor = manifest.join("vendor");
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());

    let src = vendor.join("activation.c");

    // Pick a C compiler: $CC, then common defaults.
    let cc = env::var("CC").unwrap_or_default();
    let cc = if !cc.is_empty() {
        cc
    } else {
        ["cc", "clang", "gcc"]
            .iter()
            .find(|c| Command::new(c).arg("--version").output().is_ok())
            .expect("no C compiler found (set $CC)")
            .to_string()
    };

    let obj = out_dir.join("activation.o");
    let status = Command::new(&cc)
        .args([
            "-O2",
            "-Wall",
            "-Wextra",
            "-std=c99",
            "-I",
        ])
        .arg(&vendor)
        .arg("-c")
        .arg(&src)
        .arg("-o")
        .arg(&obj)
        .status()
        .expect("failed to spawn the C compiler");
    assert!(status.success(), "C compilation failed");

    // Bundle the object into a static library with ar.
    let lib = out_dir.join("libactivation.a");
    let ar = env::var("AR").unwrap_or_else(|_| "ar".to_string());
    let status = Command::new(&ar)
        .arg("rcs")
        .arg(&lib)
        .arg(&obj)
        .status()
        .expect("failed to spawn ar");
    assert!(status.success(), "ar failed");

    println!("cargo:rustc-link-search=native={}", out_dir.display());
    println!("cargo:rustc-link-lib=static=activation");
    println!("cargo:rerun-if-changed={}", src.display());
    println!("cargo:rerun-if-changed={}", vendor.join("activation.h").display());
    println!("cargo:rerun-if-env-changed=CC");
}
