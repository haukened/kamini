# Sealed Box Encryption

## What is Sealed-Box Encryption?

Sealed-box encryption is a cryptographic technique that allows a sender to encrypt a message to a recipient using the recipient's public key, without requiring any prior exchange of keys or interaction. The message is encrypted in such a way that only the recipient can decrypt it using their private key. This approach ensures both confidentiality and integrity of the message.

## Problems Sealed-Box Encryption Solves

- **Payload Snooping Under TLS Inspection:** Even when using TLS, some network intermediaries or proxies might inspect encrypted payloads, potentially exposing sensitive information. Sealed-box encryption adds an additional layer of confidentiality, protecting the payload from such inspection.

- **Tampering:** Sealed-box encryption provides cryptographic guarantees that the message has not been altered in transit. Any tampering with the encrypted message will result in decryption failure, preventing malicious modifications.

## Why Kamini is Implementing Sealed-Box Encryption

- **Lightweight:** The sealed-box approach implemented in Kamini is designed to be lightweight, minimizing performance overhead while enhancing security.

- **No Reliance on Identity Provider (IdP) Features:** Unlike some encryption schemes that depend on IdP capabilities or configurations, Kamini's sealed-box encryption operates independently, simplifying deployment and increasing compatibility.

## What Sealed-Box Encryption is Based On

Kamini's sealed-box encryption is based on the well-established NaCl (Networking and Cryptography library) box construction, specifically the `libsodium` sealed box implementation. This foundation provides:

- Strong public-key authenticated encryption using X25519 keys.
- Proven security guarantees and wide adoption in the cryptographic community.

## How Sealed-Box Encryption Works at a High Level

1. **Client Sends Ephemeral X25519 Public Key:** The client generates an ephemeral X25519 key pair and sends the public key as part of the request.

2. **Server Encrypts Response:** Using the client's ephemeral public key and its own private key, the server encrypts the response payload with the sealed-box method.

3. **Client Unseals and Validates:** Upon receiving the encrypted response, the client uses its ephemeral private key and the server's public key to decrypt (unseal) the message and validate its integrity.

This process ensures that only the intended client can decrypt the server's response, protecting the payload from eavesdropping and tampering.

## How Sealed-Box Encryption Complements K-PoP

- **Privacy + Integrity:** While K-PoP focuses on preventing replay attacks and token theft by guaranteeing token freshness and validity, sealed-box encryption enhances the privacy and integrity of the payload itself.

- **Combined Security:** Together, these mechanisms provide a comprehensive security model—K-PoP ensures token authenticity and replay resistance, and sealed-box encryption ensures that the message content remains confidential and untampered.

## Rollout Strategy

- **Optional Negotiation Header:** Initially, sealed-box encryption support can be negotiated via an optional HTTP header, allowing clients and servers to opt-in without disruption.

- **Enforcement via Configuration:** After a period of optional use and testing, sealed-box encryption can be enforced through server configuration, requiring all clients to support and use it for enhanced security.

This phased rollout ensures smooth adoption and compatibility while progressively strengthening the security posture.
