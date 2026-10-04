//! FFI surface for the QUIP node.
//!
//! The `api` module is the only thing FRB scans. Everything the
//! Dart side sees comes from there.
//!
//! # Regenerating the Dart bindings
//!
//! ```text
//! cd quip-node-ffi
//! flutter_rust_bridge_codegen generate
//! ```
//!
//! Generated Dart code lands in `lib/src/rust/`.
//!
//! # Loading the native library from Dart
//!
//! In a Flutter app, FRB's loader finds the bundled library
//! automatically. In a pure Dart CLI (M10.1's smoke test), pass the
//! path explicitly:
//!
//! ```dart
//! await RustLib.init(
//!   externalLibrary: ExternalLibrary.open('../target/debug/libquip_node_ffi.so'),
//! );
//! ```

pub mod api;

mod frb_generated;