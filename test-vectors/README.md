# QUIP signing test vectors

These vectors exercise the signing convention defined in §10.1 of
draft-mututi-quip-03. Every file has the same shape:

    {
      "description": "...",
      "message":         { "cbor_bytes_hex": "..." },
      "signing_payload": { "cbor_bytes_hex": "..." },
      "signature":       { ... }
    }

An implementation confirms conformance by:

1. Decoding `message.cbor_bytes_hex` into the message struct named in
   `description`.
2. Re-deriving the signing payload per §10.1 (remove the signature
   field, re-encode with QUIP-CBOR canonical rules).
3. Asserting the result equals `signing_payload.cbor_bytes_hex`
   byte-for-byte.
4. Verifying `signature` over that payload against the named public key.

Step 3 is the part that catches interoperability bugs: a differing
canonical encoder will produce a different payload, and the signature
will not verify.

## Regenerating

    cargo xtask generate-vectors

Output is deterministic. Regenerating on an unchanged codebase produces
byte-identical files. CI checks this.

## Vectors

| File | Message | Signer |
|---|---|---|
| `key_claim.json` | `KeyClaim` | self |
| `witness_statement.json` | `WitnessStatement` | witness |
| `individual_ring_sig.json` | `IndividualRingSig` | 5 signers |
| `frost_ring_sig.json` | `FrostRingSig` | 5-of-7 FROST group |

The ring-signature vectors sign a fixed payload that is not itself a
QUIP message. Real ring signatures cover the enclosing message's
signing payload; the fixed payload keeps the vector focused on the
signature primitive.