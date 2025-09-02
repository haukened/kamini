# Kamini Overview

Kamini is a pluggable, open-source **SSH Certificate Authority** written in Go.  
It issues **short-lived SSH certificates** after authenticating users against modern identity providers (Entra ID, Okta, OIDC, SAML, etc.).

The goal is to replace brittle long-lived SSH keys with **ephemeral credentials**:
- Certificates expire in hours, so revocation is automatic.
- Authentication and authorization are driven by external IdPs.
- Operators configure trust by installing the CA’s public key on hosts.

## Core CLI Commands
- `kamini login` → Authenticate and issue a cert (default 1h TTL).
- `kamini whoami` → Show identity and cert status.
- `kamini logout` → Remove all tokens, keys, and certs locally.

## License
Kamini is licensed under **AGPL-3.0** to ensure forks and hosted services share their modifications.