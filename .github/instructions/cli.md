# Kamini CLI Specification

The CLI is built with **urfave/cli/v3**. Only three core commands are needed:

## Commands

### `kamini login`
- Authenticate with IdP (OIDC/SAML).
- Generate ephemeral keypair in memory.
- Request certificate from Kamini server.
- Load private key + cert into ssh-agent.
- Default TTL = 1h (server may cap).
- Flags:
  - `--ttl <duration>`: request cert lifetime (e.g., 30m, 4h).
  - `--persist`: also write key + cert to `~/.kamini/`.

### `kamini whoami`
- Show current identity and certificate state.
- Example output:

      identity: dave@contoso roles=ssh.admin,dev
      cert: present serial=123456 principals=dave expires_in=57m
      token: valid expires_in=3h42m

### `kamini logout`
- Remove all local user data:
  - Token cache.
  - Persisted keys and certs.
  - Optionally purge Kamini’s keys from ssh-agent.
- Output:  

      logged out: local tokens and persisted keys removed