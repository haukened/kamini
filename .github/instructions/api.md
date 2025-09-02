# Kamini API Specification

The server exposes a minimal REST API over HTTPS.

## Endpoints

### `POST /v1/ssh/sign-user`
Request a short-lived SSH user certificate.

**Headers:**
- `Authorization: Bearer <OIDC token>`

**Request JSON:**

    {
      "public_key": "ssh-ed25519 AAAAC3...",
      "ttl_seconds": 3600
    }

**Response JSON:**

    {
      "certificate_authorized_key": "ssh-ed25519-cert-v01@openssh.com AAAA...",
      "serial": 123456,
      "not_before": 1699999999,
      "not_after": 1700003599
    }

### `GET /v1/healthz`
Health check endpoint for probes.