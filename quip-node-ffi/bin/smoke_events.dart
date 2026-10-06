//! M10.2 acceptance test: subscribe to a node's event stream.
//!
//! Two nodes are bound; the first dials the second; both subscribe to
//! their event streams and print whatever arrives.

import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_rust_bridge/flutter_rust_bridge_for_generated.dart';
import 'package:quip_node_ffi/src/rust/api.dart';
import 'package:quip_node_ffi/src/rust/frb_generated.dart';

Future<void> main() async {
  final repoRoot = Directory.current.parent.path;
  final libPath = '$repoRoot/target/debug/libquip_node_ffi.so';

  if (!File(libPath).existsSync()) {
    stderr.writeln('Native library not found at $libPath');
    stderr.writeln('Run `cargo build` from the workspace root first.');
    exit(1);
  }

  await RustLib.init(externalLibrary: ExternalLibrary.open(libPath));

  final seedA = Uint8List.fromList(List<int>.generate(32, (i) => i));
  final seedB = Uint8List.fromList(List<int>.generate(32, (i) => i + 100));

  print('Binding node A ...');
  final nodeA = await NodeHandle.bind(bindAddr: '127.0.0.1:0', seed: seedA);
  print('Binding node B ...');
  final nodeB = await NodeHandle.bind(bindAddr: '127.0.0.1:0', seed: seedB);

  final addrA = await nodeA.localAddr();
  final addrB = await nodeB.localAddr();
  print('A: $addrA');
  print('B: $addrB');

  final eventsA = nodeA.subscribeEvents();
  final eventsB = nodeB.subscribeEvents();

  final subA = eventsA.listen((e) => print('A: $e'));
  final subB = eventsB.listen((e) => print('B: $e'));

  await Future.delayed(const Duration(milliseconds: 100));

  print('A dials B ...');
  final peerId = await nodeA.connect(addr: addrB, serverName: 'localhost');
  print('A learned peer: ${_hex(peerId)}');

  await Future.delayed(const Duration(seconds: 3));

  print('Shutting down ...');
  await subA.cancel();
  await subB.cancel();
  await nodeA.shutdown();
  await nodeB.shutdown();
  print('Done.');
}

String _hex(List<int> bytes) =>
    bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();