# TODO (High-Level Development Plan)

This plan tracks the first iterations of **Kamini**. Check items off as they land; open issues for anything that needs discussion.

---

## 0. Repo Bootstrap
- [x] Initialize module: `go mod init github.com/haukened/kamini`
- [x] Create base layout:
  - [x] `cmd/kamini/` (CLI)
  - [x] `cmd/kamini-server/` (server)
  - [x] `internal/{domain,usecase,adapters,config,bootstrap}/`
  - [x] Adapters live under `internal/adapters/*`; avoid public `pkg/*` for now
  - [x] `.github/instructions/` (seeded docs)
- [x] Add LICENSE (AGPL-3.0) + README

---

## 1. Domain & Interfaces
- [x] Define `internal/domain` types:
  - [x] Identity (subject, username, email, roles, groups, claims)
  - [x] Cert entity (serial, validity, principals)
  - [x] Policy models
- [x] Define `internal/usecase` ports (interfaces):
  - [x] Authenticator, Authorizer, Signer, SerialStore, AuditSink, AgentLoader, Clock
- [ ] Adapter implementations in `internal/adapters/*`
  - [x] auth (OIDC via discovery; provider-agnostic)
  - [x] authorize (static rules v0; later CEL/OPA)
  - [x] signer backends (disk now; AKV/Vault later)
  - [x] storage (serials)
  - [x] audit sink (stdout)

### CA Key Management (blocking for signing)
- [ ] Define signer adapter abstraction for CA key custody
  - [x] Disk-based CA key (ed25519) for dev (PEM path, permissions)
  - [ ] Azure Key Vault signer (future)
  - [ ] HashiCorp Vault signer (future)
  - [ ] Other KMS (AWS/GCP) (future)
 
---

## 2. Minimal Server (MVP Skeleton)
- [x] Config loader (`internal/config`)
- [ ] HTTP server adapter:
  - [ ] Routing + middleware (request ID, logging, error envelope)
  - [ ] `POST /v1/ssh/sign-user` (happy-path only)
  - [ ] `GET /v1/healthz`
- [x] OIDC token verification adapter (go-oidc):
  - [ ] Issuer, audience, `tid` checks
  - [x] Parse claims → domain Identity
- [x] Authorizer (static rules v0):
  - [x] Map IdP claims → principals (normalize usernames, alias map)
  - [x] TTL cap enforcement
- [X] Signer:
  - [x] File-based CA key (ed25519 preferred)
  - [x] User cert signing (serial, keyid, principals, extensions)
- [x] Storage:
  - [x] Serial counter (file+memory for MVP)
  - [x] Audit sink → stdout (structure logged)

**Acceptance (server MVP):**
- `curl` with valid bearer + public key returns a signed user cert JSON
- Logs show serial, subject, principals, validity

---

## 3. CLI MVP
- [ ] Cobra skeleton (`kamini` root)
- [ ] `kamini login`
  - [ ] Generate ephemeral ed25519 keypair (in-memory)
  - [ ] Token cache + MSAL device-code (or stub for now)
  - [ ] POST public key to server with requested TTL
  - [ ] Load private key + cert into ssh-agent with lifetime
  - [ ] Output: user, principals, ttl, serial, not_after
- [ ] `kamini whoami`
  - [ ] Read token cache (JWT parse only; offline)
  - [ ] Inspect ssh-agent entries with `kamini:` comment prefix
  - [ ] Show identity, cert status (expires_in), token validity
  - [ ] Exit codes: 0 ok, 10 no cert, 11 token expired
- [ ] `kamini logout`
  - [ ] Delete token cache
  - [ ] Remove persisted keys/certs under `~/.kamini/` (if any)
  - [ ] Optionally purge Kamini keys from agent

**Acceptance (CLI MVP):**
- `kamini login` loads a short-lived cert into agent; `ssh` works on a host trusting the CA
- `kamini whoami` shows identity + cert expiry without network calls
- `kamini logout` removes local state

---

## 4. Security & Policy Hardening
- [ ] TTL policy: default 1h; cap 8h; reject above-cap requests
- [ ] Principal rules:
  - [ ] Normalize to lowercase; charset guard; max length
  - [ ] Server-controlled only (ignore client-supplied principals except as hints)
  - [ ] Alias map support (yaml)
  - [ ] Ban `root` by default (feature-flag guarded)
- [ ] Extensions:
  - [ ] `permit-pty` on by default
  - [ ] Optional `source-address` for privileged roles (configurable)
- [ ] Error taxonomy (consistent codes + JSON envelope)
- [ ] K-PoP (Kamini Proof-of-Possession) headers and middleware (device key, nonce, proof signature)
- [ ] CLI support for K-PoP: generate/store device key, sign requests
- [ ] Sealed-box encrypted responses: client ephemeral X25519 key, server sealed-box cert JSON
- [ ] CLI support for sealed-box: unseal response, validate SSH cert with pinned CA
- [ ] TOFU pinning of SSH CA public key on first login, client-side trust file

---

## 5. Observability & DX
- [ ] Structured logs (JSON) with trace IDs
- [ ] Prometheus metrics (basic counters, latency histograms)
- [ ] `GET /v1/healthz` wired into readiness probe
- [ ] Improve CLI messages (clear remediation)

---

## 6. Packaging & Dev Ergonomics (Day 9–10)
- [ ] Dockerfile(s) for server
- [ ] Example config (server.yaml), env var table
- [ ] Dev script: bring up local server + example OIDC (or stub) + test host
- [ ] Optional: basic Helm chart scaffold

---

## 7. Documentation Pass (continuous; checkpoint at Day 10)
- [ ] README: updated features + quickstart
- [ ] `.github/instructions/` kept in sync:
  - [ ] overview, architecture, cli, api, plugins, config, errors, contributing, security
- [ ] Add ADRs:
  - [ ] 0001: License = AGPL-3.0
  - [ ] 0002: Clean Architecture boundaries
  - [ ] 0003: OIDC-first, refresh-token support
  - [ ] 0004: Principals mapping approach

---

## 8. MVP Release Criteria (v0.1.0)
- [ ] Server issues user certs with enforced TTL cap and policy-based principals
- [ ] CLI `login`, `whoami`, `logout` fully functional
- [ ] End-to-end demo: trust CA on a test VM, `kamini login`, `ssh` succeeds, cert expires automatically
- [ ] CI green: unit tests for domain/usecases; adapter happy-path tests
- [ ] Tagged release binaries for darwin/linux (amd64, arm64)

---

## 9. Post-MVP Backlog
- [ ] SQLite audit store + query CLI (`kamini audit list`)
- [ ] Postgres storage option
- [ ] OIDC provider matrix (Okta/Auth0/Google) validations
- [ ] Policy plugins (CEL/OPA) option
- [ ] KMS-backed signer (AWS → GCP → Azure)
- [ ] Helm chart polish (values schema, secrets, probes)
- [ ] Rate limiting + per-subject quotas
- [ ] Web UI (read-only audit view)
- [ ] Host certificates (only if requested by users)
- [ ] DPoP/PoP token binding (advanced)
- [ ] Windows agent support notes (OpenSSH/Pageant)
- [ ] Dual-signing/rotation support for SSH CA pinning

---

## Nice-to-Haves (as time allows)
- [ ] `kamini login --persist` paths and safe perms
- [ ] `kamini whoami --json` for scripts
- [ ] Colored terminal output with TTY detection
- [ ] Sample `sshd_config` snippets and Ansible example
- [ ] Sample policy.yaml with alias table and role mapping

---

## Risk & Mitigation Notes
- OIDC refresh flows vary per IdP → start with Entra ID using MSAL; abstract token cache
- ssh-agent availability on servers → detect; print clear startup hint; fall back to temp agent if needed
- Principals drift vs. Unix accounts → alias map + normalization; document expectations early

---

## Tracking Conventions
- Use labels: `area/cli`, `area/server`, `area/policy`, `area/auth`, `area/signer`, `area/storage`, `type/bug`, `type/feat`, `good-first-issue`
- Keep PRs small; reference this TODO section or open issues