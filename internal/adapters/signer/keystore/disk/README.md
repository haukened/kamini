# Disk keystore (CA key source)

Purpose
- Provides CA private key material to the signer through the `usecase.CAKeySource` port.
- Loads an ed25519 CA key from disk and returns a `crypto.Signer` for certificate issuance.

Why separate from other storage
- “Storage” in this repo is for application state (e.g., serial counters, audit records) with durability and concurrency semantics.
- CA keys are operational secrets with different concerns: key formats, crypto APIs, permissions/ACLs, rotation, and KMS custody.
- Keeping keystore adapters separate preserves clean boundaries and lets us add KMS backends without mixing with app-state persistence.

Behavior
- Supported formats (unencrypted only for MVP):
  - PEM (PKCS#8 ed25519 private key)
  - OpenSSH private key (ed25519)
- On load, it logs a structured `loaded_ca_key` event (path, format) via the injected logger.
- Returns a `crypto.Signer` suitable for use by the SSH certificate signer adapter.

Security notes
- Enforces strict file permissions on Unix-like systems (require owner-only: 0400/0600; reject if any group/other bits set).
- Future hardening: ownership checks, parent directory perms, Windows DACL validation, encrypted key support with passphrase sources.

Future backends
- Disk (this adapter) for dev and simple deployments.
- KMS-backed sources next (Azure Key Vault, HashiCorp Vault, AWS/GCP KMS) under the same `CAKeySource` port.