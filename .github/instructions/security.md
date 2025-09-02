# Kamini Security Posture (MVP)

Kamini’s design prefers **ephemeral credentials**, minimal state, and server-side policy control.

## Core Assumptions

- Short-lived **SSH user certificates** replace long-lived keys.
- Private keys are generated **client-side** and not written to disk unless `--persist`.
- The server **never sees** private keys; it only signs public keys.
- Revocation model is **time-based** (short TTLs), not CRLs.

## Policy Guardrails

- TTL defaults to 1h; server caps (e.g., 8h). Deny requests that exceed caps.
- Principals are computed by the **Authorizer** from IdP identity; client hints are not trusted.
- Disallow `root` principals by default. If ever allowed, require:
  - Dedicated role (e.g., ssh.breakglass)
  - TTL ≤ 15m
  - `source-address=` restriction to a bastion subnet
- Include extensions like:
  - `"permit-pty": ""`
  - Add critical options like `source-address` for sensitive roles.

## Token Handling

- Prefer access tokens with `aud=api://kamini`.
- Support refresh tokens for silent re-issue; cache locally (encrypted if platform keychain available).
- `whoami` reads token claims **locally**; no server call.

## Host Configuration (minimal)

- Install CA public key on hosts:

      TrustedUserCAKeys /etc/ssh/trusted-user-ca-keys.pub

- Start simple: avoid `AuthorizedPrincipalsFile` unless you need role-based mapping.

## Audit

- Log: serial, subject, principals, key fp, validity, requester IP, decision outcome.
- Send to stdout by default; later to SQLite/Postgres.

## Out of Scope (MVP)

- Host certificates
- Hardware-backed private keys (FIDO/U2F/HSM)
- PoP/DPoP binding for bearer tokens

These can be revisited based on user demand.