# p2p-radio Wire Protocol — V0.1

This document is the authoritative spec of what's on the wire. If code and
this document disagree, file an issue — and assume the document is right
until the code is fixed.

Transport: UDP datagrams, max 2048 bytes. No server, no relay in V0.1 —
both peers address each other directly.

## 1. Packet header (35 bytes, big-endian)

```
 0      1 byte   version       = 1
 1      1 byte   ptype         0=HELLO  1=HELLO_ACK  2=VOICE  3=BYE
 2      8 bytes  session_id    random u64, chosen by the initiator
10      4 bytes  seq           VOICE: per-direction sequence, starts at 0,
                               strictly increasing. Handshake/BYE: 0.
14      1 byte   ttl           reserved for multi-hop; V0.1 direct = 4
15      8 bytes  timestamp_ms  sender unix millis (replay/jitter heuristics)
23     12 bytes  nonce         VOICE: ChaCha20-Poly1305 nonce (see §4).
                               handshake/BYE: all zeros
```

Decoding rules (all enforced, never panic on malformed input):

- shorter than 35 bytes → reject
- `version != 1` → reject
- unknown `ptype` → reject

## 2. Handshake

Purpose: exchange identity + ephemeral keys, mutually authenticated.

```
HELLO      initiator -> responder   payload = handshake struct (160 B)
HELLO_ACK  responder -> initiator   payload = handshake struct (160 B)
```

Handshake struct (plaintext, 160 bytes):

```
 0     32 bytes  X25519 identity public key
32     32 bytes  Ed25519 identity public key
64     32 bytes  X25519 ephemeral public key (fresh per session)
96     64 bytes  Ed25519 signature over  session_id(8, big-endian)
                                            || ephemeral_pubkey(32)
```

Verification (both sides, both directions):

1. payload length ≥ 160 → else reject (extra trailing bytes ignored)
2. Ed25519 `verify_strict` over `session_id || eph_pub` with the claimed
   Ed25519 key → reject on failure. Strict mode also rejects weak
   (low-order) public keys — a weak key can forge signatures for almost
   any message under non-strict verification.
3. X25519 peer keys (identity + ephemeral) → reject if all-zero or
   low-order. A low-order peer key would collapse the DH output to ≤ 8
   possibilities, making the session key brute-forceable (8³ = 512).
4. Fingerprint check (out of band): `SHA256(X25519 identity pubkey)`,
   displayed as 4 groups of 4 hex chars. **This is the root of trust.**
   The signature does not cover the X25519 identity key; substituting it
   passes signature verification but changes the fingerprint, which the
   human verification step catches.

Retransmission: initiator re-sends HELLO up to 3 times waiting for
HELLO_ACK; a HELLO_ACK that fails verification is ignored (not fatal).

## 3. Session keys

Three DHs, X3DH-style (no new protocol invented, just composed):

```
s1 = DH(identity_initiator, ephemeral_responder)
s2 = DH(ephemeral_initiator, identity_responder)
s3 = DH(ephemeral_initiator, ephemeral_responder)
master = HKDF-SHA256(salt = session_id, ikm = s1 || s2 || s3)
k_a2b  = HKDF-expand(master, "p2p-radio-v1/a-to-b")
k_b2a  = HKDF-expand(master, "p2p-radio-v1/b-to-a")
```

Initiator sends with `k_a2b`, receives with `k_b2a`; responder mirrored.
Keys live only in memory and are dropped when the session closes.

## 4. Voice packets

- Codec: Opus, 48 kHz mono, 20 ms frames, 24 kbps.
- Encryption: ChaCha20-Poly1305, per packet.
  - `nonce` = 4-byte random session prefix || 8-byte big-endian `seq`.
    `seq` strictly increases per direction → nonces never repeat.
  - AAD = the 35-byte header. Header tampering breaks decryption.
  - Payload = ciphertext || 16-byte tag.
- Receiver: anti-replay window (rejects `seq` older than `high - 1024`),
  jitter buffer reorders and declares loss after 8 buffered frames,
  lost frames are concealed by the Opus PLC.

## 5. Teardown

`BYE` — empty payload, header only. Either side may also just stop;
the peer times out after 600 s of silence.

## 6. Known limitations (V0.1)

- No forward secrecy for the *identity* keys (they're long-term by
  design); session keys are ephemeral per call.
- Traffic analysis is NOT protected: an observer sees who talks to whom,
  when, and how much. Voice content is encrypted; metadata is not.
- Responder does not retransmit HELLO_ACK (initiator retries cover
  normal loss; pathological loss may need a redial).
- No multi-party, no relay, no NAT traversal yet — see roadmap issues.
