# Kamini Error Taxonomy

Consistent, machine-readable errors make the CLI and integrations predictable.

## JSON Error Envelope

All non-200 responses use this structure:

    {
      "error": {
        "code": "string-machine-code",
        "message": "human friendly detail",
        "retryable": false,
        "trace_id": "abcd-1234",
        "details": { "optional": "object" }
      }
    }

## Standard Codes

Authentication / Authorization:
- AUTH_MISSING_BEARER      → No Authorization header
- AUTH_INVALID_TOKEN       → Signature/claims invalid
- AUTH_EXPIRED_TOKEN       → Token expired; try refresh
- AUTH_TENANT_MISMATCH     → Token tenant not allowed
- AUTH_FORBIDDEN_ROLE      → Caller lacks required role

Input / Policy:
- INPUT_BAD_REQUEST        → Malformed JSON or fields
- POLICY_DENIED            → Authorizer refused issuance
- POLICY_TTL_EXCEEDS_MAX   → Requested TTL > server cap
- POLICY_INVALID_PRINCIPAL → Principal normalization failed

Signer / Storage:
- SIGNER_FAILURE           → Couldn’t sign certificate
- STORAGE_FAILURE          → Audit/serial store error

Server:
- RATE_LIMITED             → Too many requests
- INTERNAL_ERROR           → Unhandled server error

## HTTP Status Mapping

    400 → INPUT_BAD_REQUEST, POLICY_* invalid inputs
    401 → AUTH_* (missing/invalid/expired token)
    403 → AUTH_FORBIDDEN_ROLE, POLICY_DENIED
    409 → POLICY_TTL_EXCEEDS_MAX (when explicit conflict helps)
    429 → RATE_LIMITED
    500 → SIGNER_FAILURE, STORAGE_FAILURE, INTERNAL_ERROR