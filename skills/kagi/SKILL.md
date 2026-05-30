---
name: kagi
description: Work safely with the kagi encrypted environment variable CLI and repositories that contain `.kagi/` metadata. Use when the user asks about installing, initializing, configuring, troubleshooting, documenting, testing, or using kagi commands such as `init`, `set`, `get`, `run`, `import`, `export`, `sync`, `member`, `project`, `remote`, or `serve`; when editing a repository that stores encrypted env vars with kagi; or when handling secret-management workflows, remote sync, team access, and non-interactive secret disclosure rules for kagi.
---

# Kagi

Use this skill to help with kagi, a Rust CLI for encrypted environment
variables with per-service and per-environment isolation.

## Safety Rules

- Treat decrypted values, project keys, admin tokens, project tokens, and real
  `.env` contents as secrets.
- Do not print, log, commit, or summarize decrypted secret values unless the
  user explicitly asks and the command itself confirms interactively.
- Prefer `kagi run` for scripts and app launches. Use `get --show` or `export`
  only for deliberate reveal/export workflows.
- Commit `.kagi/kagi.json`, `.kagi/access.json`, `.kagi/secrets/**/*.enc`, and
  `.env.example` when the project uses Git-backed sharing.
- Do not commit real `.env`, `.env.*`, local project keys, admin tokens,
  project tokens, or server key files.
- In server mode, keep `.kagi/` local and out of Git unless the project
  intentionally uses Git-backed sharing.

## Command Patterns

Initialize a project:

```bash
kagi init --nested --envs
```

Set secrets from the repository root:

```bash
kagi set api DATABASE_URL postgres://localhost/api
kagi set api production DATABASE_URL postgres://db/prod
```

Set secrets from inside a nested service directory:

```bash
kagi set DATABASE_URL postgres://localhost/api
kagi set production DATABASE_URL postgres://db/prod
```

Inspect masked values before revealing anything:

```bash
kagi get
kagi get api
kagi get api production
```

Run commands with injected environment variables:

```bash
kagi run api bun dev
kagi run api production bun start
kagi run bun dev
```

Use a shell explicitly when the child command needs pipes, redirects, globs, or
environment-variable expansion:

```bash
kagi run api sh -c 'echo "$DATABASE_URL" | wc -c'
```

Import and export env files:

```bash
kagi import api --file .env.development
kagi import api production --file .env.production
kagi export api --out .
```

Sync missing keys from examples without overwriting existing values:

```bash
kagi sync --service api
```

## Team Access

For Git-backed access requests, keep pending entries in `.kagi/access.json`
when merging concurrent teammate requests.

New member or device:

```bash
kagi member join --name alice
git add .kagi/access.json
git commit -m "chore: request kagi access"
```

Existing member approval:

```bash
kagi member list
kagi member approve <member_id>
git add .kagi/access.json
git commit -m "chore: approve kagi member"
```

Removing a member rotates the project key and re-encrypts active secrets:

```bash
kagi member del <member_id>
git add .kagi
git commit -m "chore: remove kagi member"
```

## Remote Server

Prefer Git-backed `.kagi/` sharing unless the team explicitly wants a
self-hosted remote.

Start a local development server:

```bash
kagi serve --db ./kagi.db --key-file ./server.key.json --bind 127.0.0.1:8787
```

Register and sync a project:

```bash
kagi remote login --remote http://127.0.0.1:8787 --token kagi_admin_v1_...
kagi init --nested --envs
kagi project join --remote http://127.0.0.1:8787
kagi project list --remote http://127.0.0.1:8787
kagi project approve --remote http://127.0.0.1:8787 <project_id>
kagi pull <project-token>
kagi push
kagi status
```

Use HTTPS for public or LAN remotes. Non-localhost HTTP requires
`--allow-insecure-http` or `KAGI_ALLOW_INSECURE_HTTP=1` and should be limited
to development.

## Repository Development

When editing kagi itself, keep behavior in the owning layer:

- `crates/kagi-domain/`: entities, config, parsers, traits, and domain errors.
- `crates/kagi-cli/src/application/`: use-case services such as `init`, `set`, `get`, `run`,
  `export`, `import`, `sync`, and `list`.
- `crates/kagi-store/`: filesystem storage, key management, and environment injection.
- `crates/kagi-crypto/`: XChaCha20-Poly1305 encryption.
- `crates/kagi-sync/`: remote sync protocol and HTTP client.
- `crates/kagi-server/`: Axum server and SQLite backend.
- `crates/kagi-cli/`: Clap arguments, command dispatch, and terminal styling.

For user-visible CLI behavior, add or update integration coverage in
`tests/integration_tests.rs`.

Before finishing Rust code changes in the kagi repository, run:

```bash
cargo fmt -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test
cargo install --path .
```
