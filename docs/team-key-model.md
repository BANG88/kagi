# Kagi V2 Key Model

Kagi v2 is team-ready by default. A solo user is just the first active member.
There is no separate team mode, no `team` command, no `doctor` command, and no
compatibility path for v1 repositories.

## Repository Layout

The shareable `.kagi/` layout is intentionally small:

```text
.kagi/
  kagi.json
  access.json
  secrets/
    api/
      development.enc
      production.enc
    development.enc
```

`kagi.json` is public project config:

```json
{
  "version": "2",
  "project_id": "kgp_x7Hn2Qa9Lm4P",
  "services": {},
  "settings": {
    "nested": false,
    "envs": ["development"],
    "default_env": "development"
  }
}
```

`access.json` is public member/access metadata:

```json
{
  "version": "2",
  "members": [
    {
      "member_id": "kgm_L9a2Qf7xVb3K",
      "name": "alice",
      "recipient": "age1...",
      "signing_public_key": "base64-ed25519-public-key",
      "status": "active",
      "wrapped_key": "base64-age-encrypted-project-key"
    }
  ]
}
```

`signing_public_key` is an Ed25519 public key used to verify client-signed state
manifests on pull. It is generated when a member is approved and stored in
`access.json` alongside the member's public recipient.

Local private material is never written under `.kagi/`. It lives in the OS
keychain when available, or the trusted-device local store under the platform
data directory. CI and container-only environments use `KAGI_PROJECT_KEY` or
`KAGI_PROJECT_KEY_FILE`.

## Commands

```bash
kagi init
kagi member join
kagi member list
kagi member approve <member_id>
kagi member del <member_id>

# Remote sync (requires server feature)
kagi project join --remote <url>
kagi project list --remote <url>
kagi project approve <project_id> --remote <url>
kagi project del <project_id> --remote <url>
kagi push
kagi pull
kagi status
```

`kagi init` creates `kagi.json`, `access.json`, `secrets/`, one local identity,
one active member, and one project key.

`kagi member join` appends a pending member entry to `access.json`. The requester
commits or opens a PR with that change. Multiple pending requests can coexist;
concurrent PRs may need a normal JSON merge that keeps every pending member.

`kagi member approve <member_id>` encrypts the project key to the pending
member's public recipient and marks that member active.

`kagi member del <member_id>` removes that member's wrapped key, marks the
member removed, and rotates the project key so future secrets are only available
to active members. It cannot revoke secrets the removed member already had from
old Git history.

## Commit Policy

Commit:

```text
.kagi/kagi.json
.kagi/access.json
.kagi/secrets/**/*.enc
.env.example
```

Do not commit:

```text
local project keys
local age identities / private keys
KAGI_PROJECT_KEY values
.env
.env.*
```

`kagi init` removes old broad `.kagi/` ignore rules and adds `.env` patterns,
so the encrypted `.kagi/` metadata can be shared normally.

## Remote Sync

When a project is linked to a remote server, the local `.kagi/` directory
remains the source of truth. The server stores encrypted state, revision
metadata, and audit logs. It does not store plaintext secrets or project keys.

Server-side authentication uses HMAC-SHA256 token hashes with a server-side
pepper. Project tokens are scoped to a single project and carry capabilities
such as `pull`, `push`, `join`, and `rotate`. Admin tokens are scoped to the
entire server and carry the `admin` capability.

On every `push`, the client sends a signed state manifest covering the project
id, revision, previous manifest hash, hashes of `kagi.json` and `access.json`,
file content hashes, timestamp, and signer identity. The server verifies the
manifest before storing the state. On `pull`, the client verifies the manifest
signature, hash chain, and file set before applying the state locally.

## Commit Policy

Commit:

```text
.kagi/kagi.json
.kagi/access.json
.kagi/secrets/**/*.enc
.env.example
```

Do not commit:

```text
local project keys
local age identities / private keys
local signing keys
KAGI_PROJECT_KEY values
KAGI_ADMIN_TOKEN values
project tokens
.env
.env.*
```

`kagi init` removes old broad `.kagi/` ignore rules and adds `.env` patterns,
so the encrypted `.kagi/` metadata can be shared normally.

The `project_id`, public recipients, encrypted wrapped keys, signing public
keys, and encrypted secret stores are safe to share in the repository. Raw
project keys, private identity keys, signing private keys, real `.env` files,
shell history, and logs are not.
