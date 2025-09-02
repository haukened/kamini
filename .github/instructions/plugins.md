# Kamini Plugin Interfaces

Kamini supports pluggable backends for authentication, authorization, and signing.  
Interfaces live under `pkg/plugin/`.

## Authenticator

    type Identity struct {
        Subject  string
        Username string
        Email    string
        Roles    []string
        Groups   []string
        Claims   map[string]any
    }

    type Authenticator interface {
        Authenticate(ctx context.Context, token string) (Identity, error)
    }

## Authorizer

    type SignRequest struct {
        RequestedPrincipals []string
        RequestedTTLSeconds int64
        SourceIP            string
    }

    type Decision struct {
        Principals      []string
        TTLSeconds      int64
        CriticalOptions map[string]string
        Extensions      map[string]string
    }

    type Authorizer interface {
        Authorize(ctx context.Context, id Identity, req SignRequest) (Decision, error)
    }

## Signer

    type PublicKey []byte
    type SignedCert struct {
        AuthorizedKeyLine []byte
        Serial            uint64
        NotBefore         int64
        NotAfter          int64
    }

    type Signer interface {
        SignUser(ctx context.Context, pub PublicKey, principals []string,
                 opts map[string]string, exts map[string]string,
                 ttlSeconds int64) (SignedCert, error)
    }

## Principals

Principals are the **login names** that an SSH certificate will authorize on a host.  
They form the bridge between **IdP identity** (e.g. `john.doe@contoso.com`) and **Unix accounts** (e.g. `john.doe`, `jdoe`).

### Rules for handling principals
- Principals must always be set **by the server policy**, never trusted from the client.
- Include **all valid aliases** for a user:
  - Canonical Unix username (e.g., `john.doe`)
  - Short aliases if used (e.g., `jdoe`)
  - IdP identity form (e.g., `john.doe@contoso.com`) if useful with AuthorizedPrincipalsFile
- Normalize usernames: lowercase, strip/replace invalid chars, enforce a max length (≤64 chars).
- Never issue `root` unless policy explicitly allows it with extra safeguards (short TTL, source-address restriction).
- Key IDs are for audit/search only, not for authorization.
- Start simple: put Unix usernames in certs and configure only `TrustedUserCAKeys`. Use AuthorizedPrincipalsFile/Command later if role principals are needed.

### Example Decision
The Authorizer plugin might return:

    Decision{
      Principals: []string{
        "john.doe",
        "jdoe",
        "john.doe@contoso.com",
      },
      TTLSeconds: 28800,
      Extensions: map[string]string{"permit-pty": ""},
    }

This way, the cert works seamlessly whether you log in as `ssh john.doe@host` or `ssh jdoe@host`.