# Contributing to p2p-radio

## Ground rules

- **No new crypto primitives.** Compose audited building blocks
  (X25519, Ed25519, ChaCha20-Poly1305, HKDF, SHA-256). If you think a
  new primitive is needed, open an issue first.
- **Wire protocol changes need a spec update.** `PROTOCOL.md` is
  authoritative; code follows the document, not the other way around.
- **Every behavior change needs a test.** Adversarial inputs especially:
  the parser must reject malformed/truncated/forged data without
  panicking (see the `adversarial_*` tests).
- **Keep the core portable.** `crates/` is shared by the CLI, the
  Android app (via JNI), and future hardware. Avoid platform-specific
  code in the core; put it in `apps/`.

## Workflow

1. Open an issue for anything non-trivial, or pick one from the
   Phase 1–6 roadmap issues.
2. Fork, branch, commit. One logical change per commit.
3. `cargo test --workspace` and `cargo clippy --workspace -- -D warnings`
   must both pass. (CI enforces this.)
4. Open a pull request against `main`. Describe what changed and why,
   and note any protocol or security implications.

## Security

Found a vulnerability? **Do not open a public issue or PR.**
See `SECURITY.md` for how to report it privately.

## License

By contributing, you agree that your contributions are licensed under
GPL-3.0-or-later, like the rest of the project.
