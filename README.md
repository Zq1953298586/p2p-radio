# p2p-radio

**Where there is network, there is freedom.** （有网络就有自由）

A peer-to-peer, serverless voice walkie-talkie. No servers, no accounts, no
registration, no logs. Two devices, one encrypted radio channel — that's the
whole product.

## Status

🚧 **Prototype — Phase 0 complete, Phase 1 (real-device testing) in progress.**

The Rust core is implemented and tested: protocol, cryptography, UDP transport,
and the Opus audio pipeline all pass unit + end-to-end tests. It has **not**
been independently security-audited. Do not rely on it for safety-critical
communication yet.

## How it works

```
┌──────────┐   UDP, no server   ┌──────────┐
│ Device A │ ◄───────────────► │ Device B │
│  Rust    │  X25519 + Ed25519 │  Rust    │
│  core    │  ChaCha20-Poly1305│  core    │
└──────────┘   Opus @ 24 kbps  └──────────┘
```

- **Identity**: each device generates a dual keypair — X25519 (key agreement)
  + Ed25519 (signing). Your fingerprint is `SHA256(X25519 public key)`.
- **Handshake**: `HELLO` / `HELLO_ACK` carrying both public keys, each side
  signed with Ed25519. Triple-DH → HKDF-SHA256 → session keys.
  A forged or tampered handshake packet is rejected, never retried-blindly.
- **Voice**: 35-byte packet header (bound as AEAD associated data),
  ChaCha20-Poly1305 per packet, nonces never reused, anti-replay window,
  jitter buffer with packet-loss concealment.
- **Trust model**: verify the peer's fingerprint once, out of band (in person,
  QR code). That single check pins both keys.

## Repository layout

```
crates/
  p2p-proto      # wire protocol: 35-byte header, packet types, handshake payload
  p2p-crypto     # dual identity keys, triple-DH session derivation, AEAD
  p2p-transport  # UDP sessions: signed handshake, jitter buffer, anti-replay
  p2p-audio      # Opus encode/decode, 48 kHz mono, 20 ms frames @ 24 kbps
  p2p-jni        # JNI bridge: the same Rust core, callable from Android/Kotlin
apps/
  cli            # reference CLI: keygen / tx / rx  (+ end-to-end test)
  android        # Android app skeleton (Kotlin), speaks to the core via JNI
docs/            # project docs (Chinese): master plan, Phase 1/2 guides
scripts/         # one-shot Android NDK/SDK environment setup
```

One core, every platform: the desktop CLI, the Android app, and the future
hardware device all link the same `crates/`.

## Build & test

Requires Rust (stable) and libopus (`-dev`/`-devel` package, or build from
source — see `docs/`).

```sh
cargo test --workspace        # 10 tests: crypto, protocol, audio, transport, e2e
cargo build --release         # -> target/release/p2p-radio
```

The end-to-end test pushes 250 voice frames through encode → encrypt →
simulated reorder + loss → decrypt → jitter buffer → decode, and asserts all
250 frames come out audible (2 covered by packet-loss concealment).

## Try it (two terminals, same machine)

```sh
# test-voice.wav is git-ignored; generate it if missing:
python3 phase1-kit/make-test-voice.py
./target/release/p2p-radio keygen
# Terminal 1 (receiver):
./target/release/p2p-radio rx --listen 0.0.0.0:9001 --out out.wav
# Terminal 2 (sender):
./target/release/p2p-radio tx --peer 127.0.0.1:9001 --in test-voice.wav
```

Compare the fingerprints printed on both sides — they must match. Then play
`out.wav`.

## Roadmap

- [x] Phase 0 — Rust core: protocol, crypto, transport, audio, CLI
- [ ] Phase 1 — real-device LAN testing (in progress)
- [ ] Phase 2 — Android app (JNI bridge ready, Kotlin skeleton ready)
- [ ] Phase 3 — NAT traversal (hole punching)
- [ ] Phase 4 — peer relay for unreachable NATs
- [ ] Phase 5 — multi-party channels, PTT discipline
- [ ] Phase 6 — dedicated hardware device (reuses 80%+ of this core)

## Security notes

- Prototype cryptography code: X25519 / Ed25519 / ChaCha20-Poly1305 via
  audited crates (`x25519-dalek`, `ed25519-dalek`, `chacha20poly1305`), but the
  protocol logic around them has not had a third-party review.
- Voice is encrypted; traffic *patterns* (who talks to whom, when, how much)
  are not hidden. That is a known limitation, not an oversight.
- Issues about the threat model are welcome — please open a GitHub issue
  rather than a PR for design-level security questions.

## Contributing

PRs welcome. Keep the core `no_std`-friendly where possible, keep the wire
protocol documented in `crates/p2p-proto`, and add a test for every behavior
change. Big changes: open an issue first.

## License

GPL-3.0-or-later — see [LICENSE](LICENSE). If you build a product on this
code, your product stays open too. No one gets to put a central off-switch
on freedom.

---

*Built on a simple axiom: freedom is the one thing no being can refuse —
the ability to not have your choices taken away unilaterally. No central
server means no central off-switch.*
