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
| `xtask` | Test-vector generator (`cargo xtask generate-vectors`) |

## Building

Requires Rust 1.75 or newer.

```bash
cargo build --workspace --all-features
```

The workspace is `no_std + alloc` by default for `quip-core` and
`quip-net`. The `std` feature is enabled through the default feature
set; `crypto` and `quic` are opt-in. `full` enables everything.

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

Every code milestone is landed. §16 (connection establishment) runs
end-to-end through step 8. See [ROADMAP.md](./ROADMAP.md) for the
milestone plan, the tag index, and the small set of open items.

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
`ROADMAP.md` in the same commit: the status table, the milestone's
section, and the tag index. Commit messages follow the form
`<area>: <summary>` with the milestone tag in parentheses, e.g.
`net: BFT view change (M4b.2)`.