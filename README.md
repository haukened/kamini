# Kamini

**Kamini** is a pluggable, open-source **SSH Certificate Authority** that issues short-lived user and host certificates after modern identity authentication.  

The name comes from the Greek word *καμίνι (kamíni)* — forge, furnace — a nod to ephemeral keys hammered out in fire and fading quickly.

## Why Kamini?

Managing long-lived SSH keys is brittle and dangerous. Kamini replaces static keys with **short-lived SSH certificates** tied to real identity systems like Entra ID, Okta, or any OIDC/SAML provider.  
This means:
- **Ephemeral access**: keys expire in hours, not months or years.
- **Centralized trust**: hosts trust the CA, not individual keys.
- **Pluggable identity**: choose your authentication backend.
- **Auditability**: every cert issued is logged with who, when, and why.

## Features (planned / in progress)

- Issue **SSH user certificates** (ed25519, ECDSA, RSA).  
- **Pluggable authentication backends** (OIDC, SAML, mock/dev, custom).  
- **Policy engine**: map identity claims → SSH principals, critical options, extensions.  
- **Audit logging**: serial, subject, key fingerprint, validity window.  
- **Short-lived certs** as the revocation model (default 4–12 hours).  
- **Lightweight deployment**: single Go binary, Docker image, Helm chart.  
- **REST API + CLI**: request certs, check status, fetch CA keys.  

## Why AGPL-3.0?

Kamini is licensed under the GNU Affero General Public License v3.0.
That means:
	•	You can use and modify Kamini freely.
	•	If you distribute or host it as a service, you must also share your changes.
This ensures Kamini remains free and open, protecting against closed-source forks.

## Roadmap
	•	Minimal CA server with file-based key backend.
	•	OIDC plugin (Entra ID example).
	•	CLI with login + sign-user.
	•	Audit logging + Prometheus metrics.
	•	Helm chart for Kubernetes deployment.
	•	Optional KMS/HSM key storage (AWS/GCP/Azure).

## Status

🚧 Early stage. Kamini is under active design and development. Expect rapid changes.

⸻

Kamini — ephemeral keys, forged in fire, gone in hours.
Copyright (C) 2025, David Haukeness (@haukened on GitHub)