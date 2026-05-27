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
      "status": "active",
      "wrapped_key": "base64-age-encrypted-project-key"
    }
  ]
}
```

Local private material is never written under `.kagi/`. It lives in the OS
keychain when available, or the trusted-device local store under the platform
data directory. CI and container-only environments use `KAGI_PROJECT_KEY` or
`KAGI_PROJECT_KEY_FILE`.

## Commands

```bash
kagi init
kagi join
kagi member list
kagi member approve <member_id>
kagi member remove <member_id>
kagi key rotate
```

`kagi init` creates `kagi.json`, `access.json`, `secrets/`, one local identity,
one active member, and one project key.

`kagi join` appends a pending member entry to `access.json`. The requester
commits or opens a PR with that change.

`kagi member approve <member_id>` encrypts the project key to the pending
member's public recipient and marks that member active.

`kagi member remove <member_id>` removes that member's wrapped key, marks the
member removed, and rotates the project key so future secrets are only available
to active members. It cannot revoke secrets the removed member already had from
old Git history.

`kagi key rotate` re-encrypts every secret store and rewrites wrapped keys for
active members.

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

The `project_id`, public recipients, encrypted wrapped keys, and encrypted
secret stores are safe to share in the repository. Raw project keys, private
identity keys, real `.env` files, shell history, and logs are not.
