//! M10.3 acceptance test: the trust policy across the FFI boundary.

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

  final addrB = await nodeB.localAddr();
  print('B bound at $addrB');

  // Subscribe before dialing so we don't miss the Connected event.
  final eventsA = nodeA.subscribeEvents();
  final subA = eventsA.listen((event) => print('A: $event'));

  await Future.delayed(const Duration(milliseconds: 100));

  print('A dials B ...');
  final peerId =
      await nodeA.connect(addr: addrB, serverName: 'localhost');
  print('A learned peer: ${_hex(peerId)}');

  await Future.delayed(const Duration(seconds: 1));

  // --- Trust before the application's decision. ---
  final trustBefore = await nodeA.peerTrust(peer: peerId);
  print('trust before decision: $trustBefore');
  if (trustBefore != PeerTrustFfi.unknown) {
    stderr.writeln('expected Unknown, got $trustBefore');
    exit(1);
  }

  // --- The application accepts the peer. ---
  print('A trusts B ...');
  final accepted =
      await nodeA.trustPeer(peer: peerId, decision: PeerTrustFfi.trusted);
  print('trustPeer returned: $accepted');
  if (!accepted) {
    stderr.writeln('trustPeer returned false; expected true');
    exit(1);
  }

  await Future.delayed(const Duration(milliseconds: 200));

  // --- Trust after the decision. ---
  final trustAfter = await nodeA.peerTrust(peer: peerId);
  print('trust after decision: $trustAfter');
  if (trustAfter != PeerTrustFfi.trusted) {
    stderr.writeln('expected Trusted, got $trustAfter');
    exit(1);
  }

  // --- Verified is not settable. ---
  final verifiedAttempt =
      await nodeA.trustPeer(peer: peerId, decision: PeerTrustFfi.verified);
  print('trustPeer(Verified) returned: $verifiedAttempt');
  if (verifiedAttempt) {
    stderr.writeln('the application should not be able to set Verified');
    exit(1);
  }

  // --- Revocation is terminal. ---
  final revoked =
      await nodeA.trustPeer(peer: peerId, decision: PeerTrustFfi.revoked);
  print('trustPeer(Revoked) returned: $revoked');
  if (!revoked) {
    stderr.writeln('revocation should have been accepted');
    exit(1);
  }

  final trustAfterRevoke = await nodeA.peerTrust(peer: peerId);
  print('trust after revoke: $trustAfterRevoke');
  if (trustAfterRevoke != PeerTrustFfi.revoked) {
    stderr.writeln('expected Revoked, got $trustAfterRevoke');
    exit(1);
  }

  // --- Re-trusting does not lift a tombstone. ---
  final retrust =
      await nodeA.trustPeer(peer: peerId, decision: PeerTrustFfi.trusted);
  print('trustPeer(Trusted) after revocation returned: $retrust');
  final trustFinal = await nodeA.peerTrust(peer: peerId);
  print('trust after re-trust attempt: $trustFinal');
  if (trustFinal != PeerTrustFfi.revoked) {
    stderr.writeln('revocation should be terminal; got $trustFinal');
    exit(1);
  }

  await Future.delayed(const Duration(milliseconds: 200));

  print('Shutting down ...');
  await subA.cancel();
  await nodeA.shutdown();
  await nodeB.shutdown();
  print('All assertions passed. Done.');
}

String _hex(List<int> bytes) =>
    bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();