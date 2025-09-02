# Kamini Architecture

Kamini follows **Clean Architecture**. Dependencies always point inward:

adapters (http, oidc, signer, storage, agent)
        ↘
       usecase (IssueUserCert, WhoAmI, Logout)
            ↘
            domain (Identity, Cert, Policy)

## Repo Layout

    kamini/
    ├─ cmd/                 # entrypoints
    │  ├─ kamini/           # CLI binary
    │  └─ kamini-server/    # API server binary
    ├─ internal/            # implementation (not public)
    │  ├─ domain/           # core entities (identity, cert, policy)
    │  ├─ usecase/          # business logic, depends only on domain
    │  ├─ adapters/         # IO implementations (http, oidc, ssh, storage)
    │  ├─ config/           # config loader
    │  └─ bootstrap/        # composition root (DI)
    ├─ pkg/                 # public plugin SDK (stable)
    │  └─ plugin/           # auth, authorize, signer interfaces
    └─ api/                 # REST contracts (OpenAPI, examples)

## Design Principles
- **Domain**: pure Go, no external deps.
- **Usecase**: orchestrates flows via interfaces.
- **Adapters**: implement interfaces, depend outward (http, db, oidc, ssh).
- **cmd/**: wires everything together.
- **pkg/**: contains only stable plugin interfaces for external use.