//! M10.1 acceptance test: bind a QUIP node through the FFI boundary
//! and print its identity.
//!
//! Run from the `quip-node-ffi/` directory:
//!
//! ```text
//! dart run bin/smoke.dart
//! ```
//!
//! Requires the native library to be built first:
//!
//! ```text
//! cargo build
//! ```

import 'dart:io';
import 'dart:typed_data';

import 'package:quip_node_ffi/src/rust/api.dart';
import 'package:quip_node_ffi/src/rust/frb_generated.dart';
import 'package:flutter_rust_bridge/flutter_rust_bridge_for_generated.dart';

Future<void> main() async {
  // In a Flutter app, FRB finds the bundled library automatically. In a
  // pure Dart CLI, we tell it where cargo placed the .so.
  final repoRoot = Directory.current.parent.path;
  final libPath = '$repoRoot/target/debug/libquip_node_ffi.so';

  if (!File(libPath).existsSync()) {
    stderr.writeln('Native library not found at $libPath');
    stderr.writeln('Run `cargo build` from the workspace root first.');
    exit(1);
  }

  print('Loading native library: $libPath');
  await RustLib.init(externalLibrary: ExternalLibrary.open(libPath));

  // A deterministic seed. In production this comes from the platform
  // keystore; M10.1 only proves the boundary works.
  final seed = Uint8List.fromList(List<int>.generate(32, (i) => i));

  print('Binding node on 127.0.0.1:0 ...');
  final NodeHandle node;
  try {
    node = await NodeHandle.bind(bindAddr: '127.0.0.1:0', seed: seed);
  } on FfiError catch (e) {
    stderr.writeln('Bind failed: ${e.message}');
    exit(1);
  }
  print('Node bound.');

  final addr = await node.localAddr();
  print('Local address: $addr');

  final nodeId = await node.localNodeId();
  print('NodeId: ${_hex(nodeId)}');

  print('Shutting down ...');
  await node.shutdown();
  print('Done.');
}

String _hex(List<int> bytes) =>
    bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();