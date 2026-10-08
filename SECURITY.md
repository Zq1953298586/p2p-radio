# Security Policy

## Threat model

p2p-radio protects **voice content** between two peers who have verified
each other's fingerprint. It assumes:

- The attacker can observe, delay, replay, and inject UDP traffic.
- The attacker cannot break X25519, Ed25519, ChaCha20-Poly1305,
  HKDF-SHA256, or SHA-256.
- The two humans verify fingerprints **out of band** (in person, QR
  code, trusted channel) before sensitive conversation. This step is
  the root of trust — do not skip it.

What is NOT protected (by design, V0.1):

- **Traffic metadata.** Who talks to whom, when, for how long, and how
  much data moves — all visible to a network observer.
- **Endpoint compromise.** If a device is compromised, its identity keys
  and live session keys are exposed. There is no remote attestation.
- **Denial of service.** Anyone who knows your UDP port can flood it.

## Hardening already in place

- Handshake signatures use Ed25519 `verify_strict` (rejects weak /
  low-order public keys that could forge signatures).
- X25519 peer keys are rejected if all-zero or low-order (prevents DH
  output collapse → session-key brute force).
- Packet headers are bound as AEAD associated data; nonces never repeat
  per direction; anti-replay window on receive.
- The parser is fuzz-tested against malformed/truncated/forged input:
  it rejects without panicking.

## Reporting a vulnerability

**Do not open a public issue** for a suspected vulnerability.

Email the maintainer privately (see the GitHub profile). Include:

1. What you believe is broken, and the attacker's capabilities.
2. Steps to reproduce, or a proof of concept.
3. What you think the impact is (content leak? impersonation? DoS?).

We will acknowledge within 7 days, fix, and credit you in the release
notes unless you prefer to stay anonymous.

## Status

This is a **prototype**. The cryptography composes audited primitives
via audited Rust crates, but the protocol logic has not had an
independent third-party review. Do not rely on it for safety-critical
communication yet.
