# Security Policy

## Reporting a Vulnerability

Please do not report security vulnerabilities through public issues.

Send a private report to the repository owner with:

- affected version or commit
- operating system and shell
- reproduction steps
- expected and actual behavior
- any logs with secrets removed

Use fake values in examples. Do not include real `.kagi/` directories, master
keys, decrypted secrets, or production `.env` files in reports.

## Scope

Security-sensitive areas include encryption, authenticated data handling,
master-key loading, file permissions, non-interactive secret output, command
execution through `kagi run`, and path handling for nested projects.

## Server compromise impact

If a Kagi server is fully compromised, an attacker can:

- Delete or rollback encrypted project state (availability and integrity impact)
- Capture future project tokens or admin tokens from incoming requests
- Learn project metadata (project IDs, service names, member names, public recipients)

The attacker **cannot**:

- Decrypt env values without also stealing a member's private age identity or project key
- Decrypt past request/response bodies without the server's age private key

The server stores only encrypted state, token hashes, and public metadata. It
does not store the plaintext project key, member private identities, or token
plaintext. This is by design: the server is a sync broker, not a trusted secret
holder.

## Sensitive data

Treat the following as sensitive and limit access:

- Server key file (`server.key.json`) — contains the age identity and token pepper
- SQLite database and WAL files
- Server logs (may contain request IDs, member metadata, IP addresses)
- Admin token plaintext
- Project token plaintext
- Member private age identities
- Project keys

## Recommended reporting and rotation

If you suspect a server compromise:

1. Stop the server immediately.
2. Rotate the server key file (generate a new one). This invalidates all existing
   tokens pinned to the old fingerprint.
3. Re-create admin tokens and project tokens.
4. Distribute new project tokens to all members.
5. Review audit logs for unauthorized operations.

If you suspect a leaked token:

1. Revoke the token server-side (`kagi project del` or token revocation).
2. Rotate the project key if the token may have been used maliciously.
3. Issue a new token for the affected member.
