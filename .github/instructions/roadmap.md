# Kamini Roadmap

## MVP (v0.1)
- Minimal CA server with file-based private key.
- OIDC authentication (Entra ID example).
- CLI with `login`, `whoami`, `logout`.
- Issue short-lived user certs, load into ssh-agent.
- Audit logging to stdout.
- `/v1/ssh/sign-user`, `/v1/healthz` endpoints.

## Near Term (v0.2–v0.3)
- Configurable policy engine (roles → principals).
- Persist audit logs (SQLite/Postgres).
- Prometheus metrics.
- Helm chart for Kubernetes deployment.

## Future
- KMS/HSM support (AWS, GCP, Azure).
- Optional host certificates (if requested).
- Policy plugins via OPA/CEL.
- Web UI for viewing audit logs.