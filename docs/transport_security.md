# Transport Security Risks in Kamini

Transport security is crucial for protecting data as it moves between clients and servers in Kamini. Understanding the risks and challenges helps us choose the right security measures.

## Risks in Transport Security

- Data in transit can be intercepted or modified by attackers.
- Sensitive information like tokens and SSH private keys can be exposed if not properly protected.
- Workplace policies often enforce TLS inspection, which can break some security protocols.

## Why mTLS Fails in TLS Inspection Environments

Mutual TLS (mTLS) requires both client and server to authenticate each other using certificates. However:

- TLS inspection tools act as intermediaries, decrypting and re-encrypting traffic.
- This breaks the direct trust relationship needed for mTLS.
- As a result, mTLS connections fail or are bypassed in environments with TLS inspection (e.g., corporate networks with security boxes).

## Operational Challenges of mTLS

Even without TLS inspection, mTLS is difficult to manage because:

- Certificates must be provisioned to every client and server.
- Rotating certificates regularly is complex and error-prone.
- Managing certificate lifecycles increases operational overhead.
- Mistakes can lead to service outages or security gaps.

## How TLS Inspection Exposes Payloads and Tokens

TLS inspection decrypts traffic to scan for threats or enforce policies, which means:

- Payloads and tokens are visible in plaintext inside the inspection device.
- Even if inspection is done for legitimate reasons, it increases the risk of exposure.
- Sensitive data like authentication tokens or SSH keys can be compromised if the inspection device is breached or misconfigured.

## Protecting SSH Private Keys and Certificate Payloads

SSH private keys and certificate payloads are highly sensitive because:

- They grant access to critical systems.
- If intercepted in transit, attackers can impersonate users or services.
- Ensuring these are encrypted and protected during transport is essential.

## How Sealed-Box + K-PoP Protects Payloads and Tokens

Kamini uses a combination of sealed-box encryption and Key Proof-of-Possession (K-PoP) to secure data:

- **Sealed-box encryption** encrypts payloads end-to-end, so only the intended recipient can decrypt them.
- **K-PoP** ensures that tokens are bound to the rightful holder, preventing misuse if intercepted.
- This approach allows payloads and tokens to remain protected even when TLS inspection is in place.
- It maintains compatibility with workplace policies while enhancing security.

By combining these technologies, Kamini ensures strong transport security without the operational and compatibility issues of mTLS.
