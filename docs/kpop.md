# K-PoP (Kamini Proof-of-Possession)


## What is PoP (Proof of Possession)

Proof of Possession (PoP) is a security concept where a client must demonstrate that it holds a private cryptographic key corresponding to a public key that is bound to a token (such as an access token or credential). In identity systems, this means that simply possessing the token is not enough to use it; the client must also prove, usually by cryptographically signing something with its private key, that it is the legitimate holder of the key pair associated with the token.

This mechanism defends against replay attacks and theft of tokens: even if an attacker steals a token, they cannot use it without also having the corresponding private key. Each request requires the client to provide cryptographic proof of possession, ensuring that tokens cannot be reused by unauthorized parties.

## Problems PoP Solves

- **Bearer Token Theft Under TLS Inspection:** Traditional bearer tokens can be vulnerable when TLS traffic is inspected or intercepted, allowing attackers to steal tokens and impersonate users.
- **Request Tampering:** Without proof of possession, tokens can be used in unauthorized requests, leading to potential security breaches.
- **Replay Attacks:** Attackers might reuse captured tokens in replay attacks; PoP mitigates this by binding tokens to a client’s cryptographic key and requiring per-request proofs.

## What is K-PoP?

K-PoP, or Kamini Proof-of-Possession, is a security mechanism designed to enhance the protection of bearer tokens used in authentication and authorization processes. It ensures that tokens are bound to a specific client device, preventing misuse if the token is intercepted or stolen.

## Basis of K-PoP

K-PoP is based on the [DPoP RFC 9449](https://datatracker.ietf.org/doc/html/rfc9449), which defines a method for proof-of-possession tokens. DPoP is also part of the emerging OpenID Connect (OIDC) standards aimed at improving token security, but it is not yet universally supported by Identity Providers. This gap in adoption reinforces the need for Kamini to implement its own version of PoP to ensure robust and consistent security across its platform.

## Why Kamini is Implementing Its Own K-PoP

- **Lack of Universal Support:** Existing Identity Providers (IdPs) do not universally support Demonstration of Proof-of-Possession (DPoP) tokens yet.
- **Tailored Security Needs:** Kamini requires a solution that integrates seamlessly with its platform and provides robust security guarantees.
- **Control Over Features:** Implementing K-PoP internally allows Kamini to iterate quickly and add features such as toggles and rollout strategies suited to its user base.

## How K-PoP Works at a High Level

- **Device Keypair:** Each client device generates a cryptographic key pair.
- **Client Registration / First Login:** The client submits its public key during initial login, which the server stores (binding it to the subject/session).
- **Per-Request Proof Headers:** For every API request, the client includes a proof header signed with its private key, demonstrating possession.
- **Server Verification:** The server verifies the proof header against the stored public key associated with the token, ensuring the request is legitimate and originated from the rightful client. Subsequent requests use that stored key to validate proofs.

## How K-PoP Complements Sealed-Box Encrypted Responses

K-PoP enhances security by complementing Kamini’s sealed-box encrypted responses. While sealed-box encryption protects the confidentiality and integrity of response data, K-PoP ensures that only the legitimate client holding the correct key pair can use the associated tokens to access resources, providing end-to-end security.

## Rollout Strategy

- **Minimum Viable Product (MVP):** K-PoP will be introduced as an MVP in a later phase, allowing for testing and feedback.
- **Feature Toggles:** The system will include toggles such as `require_kpop` to enable or disable K-PoP enforcement per client or environment.
- **Gradual Adoption:** Kamini plans a phased rollout to minimize disruption and ensure compatibility with existing clients and IdPs.
