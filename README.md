# QUIP

QUIP (QUIC Identity Protocol) is a brokerless federation protocol for
peer-to-peer networks, operating directly over QUIC. It provides
portable Ed25519 identities, causal consistency via Dotted Version
Vectors, explicit backpressure through four transport tiers,
content-addressed storage via CIDs, and decentralised persistence via
resource pinning.

QUIP does not depend on DNS, WebPKI, or any domain-based authority.
Trust is established through a distributed witness network using
Coral DHT-based discovery.

This repository is the reference implementation of
[draft-mututi-quip-03](./draft-mututi-quip-03.xml).

## Workspace layout

| Crate | Purpose |
|---|---|
| `quip-core` | Wire message types, canonical CBOR, CIDs, DVVs, error codes, time |
| `quip-net` | Framing, handshake, transport tiers, NAT traversal, Coral DHT, BFT consensus, range fetch |
| `quip-storage` | Blob store, pin table, quarantine store, snapshots |
| `quip-node` | A running node: endpoint, peer table, event stream, trust policy |
| `quip-node-ffi` | Dart-facing FFI surface via `flutter_rust_bridge` |
| `xtask` | Test-vector generator (`cargo xtask generate-vectors`) |

## Building

Requires Rust 1.75 or newer. The workspace pins Rust 1.99.0 via
`rust-toolchain.toml`, and CI uses the pin.

```bash
cargo build --workspace --all-features
```

The workspace is `no_std + alloc` by default for `quip-core` and
`quip-net`. The `std` feature is enabled through the default feature
set; `crypto` and `quic` are opt-in. `full` enables everything.

For Android targets:

```bash
export ANDROID_NDK_HOME=/opt/android-sdk/ndk/26.1.10909125
cargo ndk -t arm64-v8a -t armeabi-v7a -o ./jniLibs build --release
```

Requires `cargo-ndk` and the corresponding `rustup target add`
invocations for the active toolchain (1.99.0, per the pin).

## Testing

```bash
cargo test --workspace --all-features
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo doc --workspace --all-features --no-deps
RUSTDOCFLAGS='-D warnings' cargo doc --workspace --all-features --no-deps
cargo build -p quip-core -p quip-storage -p quip-net --no-default-features
```

All five commands run in CI on every push, plus a `vectors` job that
regenerates `test-vectors/` and fails if the working tree changed. See
`.github/workflows/ci.yml`.

## Status

The protocol layer (M1–M8) is complete: framing, handshake, transport
tiers, NAT traversal, Coral DHT state, BFT consensus, range fetch, and
the §16 establishment flow all run end-to-end through step 8. The
application layer (M9.x) and interface layer (M10.x) are in progress:
a running `Node` composes the protocol crates into a peer, and a Dart
client can bind it, subscribe to its event stream, and make explicit
trust decisions.

See [CHANGELOG.md](./CHANGELOG.md) for the milestone history, the
current state, and the outstanding work. The file was named
`ROADMAP.md` through the M9 series; it was renamed when its shape
changed from a forward-looking plan into a record of landed work.

## Feature flags

| Feature | Enables |
|---|---|
| `std` | Wall-clock helpers, `alloc`, `quip-storage/std`. On by default. |
| `crypto` | `sha2`, `blake3`, `ed25519-dalek`, `bao`. Content hashing, Ed25519 identities, bao verified streaming. |
| `quic` | `quinn`, `rustls`, `tokio`. The QUIC runtime binding (`transport` module). |
| `hpke` | `hpke-rs` (RustCrypto backend), `curve25519-dalek`. Relay-hop HPKE sealing (§12.2). Implies `crypto`. |
| `full` | `crypto` + `quic` + `hpke`. |

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](./LICENSE-APACHE))
- MIT License ([LICENSE-MIT](./LICENSE-MIT))

at your option.

## Contributing

The draft and the code must not drift. When a milestone lands, update
`CHANGELOG.md` in the same commit: the status table, the milestone's
section, and the tag index. Commit messages follow the form
`<area>: <summary>` with the milestone tag in parentheses, e.g.
`net: BFT view change (M4b.2)`.