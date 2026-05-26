# kagi

![kagi README banner](docs/kagi-readme-banner.png)

A CLI tool for managing encrypted environment variables with per-service isolation.

**kagi** (鍵, Japanese for "key") keeps your secrets encrypted at rest using XChaCha20-Poly1305 while making them easy to inject into applications during development and deployment.

---

## Features

- **XChaCha20-Poly1305 encryption** — Every secret is authenticated and encrypted with a master key before touching disk.
- **Environment-oriented** — Store secrets by environment (`dev`, `staging`, `prod`) with optional service scopes (`api/dev`, `web/prod`).
- **Opt-in nested project support** — Infer the current service from your directory structure when enabled.
- **Shell-safe export** — Emit `KEY=value` lines for sourcing or Docker `--env-file`.
- **Non-interactive safety** — `get`, `export`, and value listing require explicit opt-in when stdout is not a TTY; scripts should prefer `kagi run`.
- **Import from `.env`** — Bulk-import existing `.env` files with overwrite protection.
- **Sync from `.env.example`** — Propagate keys across environments without losing existing values.
- **Zero default environments** — Create only what you need via `--envs`.
- **Clean Architecture** — Domain, Application, Infrastructure, and CLI layers are fully separated.

---

## Installation

### From Git

```bash
cargo install --git https://github.com/BANG88/kagi.git
```

Requires Rust 1.85+ (2024 edition).

### From a local checkout

```bash
git clone https://github.com/BANG88/kagi.git
cd kagi
cargo install --path .
```

---

## Quick Start

```bash
# 1. Initialize a repository in the current directory
kagi init

# 2. Create environments on init (optional)
kagi init --envs dev,test

# 3. Store a secret
kagi set dev DATABASE_URL postgres://localhost/dev

# 4. Retrieve it
kagi get dev DATABASE_URL
# → postgres://localhost/dev

# 5. Run a command with injected env vars
kagi run dev node server.js

# 6. Export for Docker or shell sourcing
kagi export --allow-non-interactive dev > .env.dev
```

---

## Commands

### `init`

Create a `.kagi/` directory in the current project. This stores the master key, config, and encrypted services.

```bash
kagi init
kagi init --envs dev,staging,prod
kagi init --nested             # enable service inference from subdirectories
kagi init --force              # overwrite existing .kagi/
```

**Note:** If `kagi init` runs inside a Git repository, `.kagi/` is added to the repository `.gitignore`. Do **not** commit it.

---

### `set`

Store an encrypted secret.

```bash
kagi set <env> <key> <value>
kagi set dev STRIPE_KEY fake_stripe_key
kagi set --service api prod DATABASE_URL postgres://prod/db
```

With **nested inference** enabled via `kagi init --nested`, `kagi` infers the service from the child directory. You can either use the service-only shorthand or include an environment:

```bash
# You are in ./api/
kagi set API_KEY abc123          # stored under "api"
kagi set dev API_KEY abc123      # stored under "api/dev"
```

---

### `get`

Retrieve and decrypt a secret value.

```bash
kagi get <env> <key>
kagi get dev DATABASE_URL
kagi get --service api prod DATABASE_URL
```

Also supports opt-in nested inference:

```bash
# inside ./api/
kagi get API_KEY             # reads from "api"
kagi get dev API_KEY         # reads from "api/dev"
```

When stdout is not an interactive TTY, add `--allow-non-interactive` explicitly. Prefer `kagi run` for scripts.

---

### `run`

Execute a command with all secrets for a service injected as environment variables.

```bash
kagi run <env> <command> [args...]
kagi run dev npm start
kagi run test cargo test
kagi run --service api prod bun start
```

Inside a nested service directory, the first argument is treated as an environment only if that scoped store exists. Otherwise the command runs with the inferred service-only store. If nested mode is disabled and no scope is provided, `kagi run <command>` runs the command without injected variables and prints a `kagi: notice:` line.

```bash
# inside ./api/
kagi run bun dev             # runs with "api" secrets injected when nested is enabled
kagi run dev bun start       # runs with "api/dev" secrets injected
```

---

### `export`

Print secrets as `KEY=value` lines. Suitable for shell sourcing or Docker `--env-file`.

```bash
kagi export dev
kagi export --service api prod
# DATABASE_URL=postgres://localhost/dev
# STRIPE_KEY=fake_stripe_key
```

Use `--allow-non-interactive` when redirecting or piping output.

---

### `import`

Import secrets from a `.env` file.

```bash
kagi import <env> --file .env.local
kagi import dev --file dev.env
kagi import dev --file dev.env --force   # skip overwrite prompt
kagi import --service api prod --file prod.env
```

If a key already exists, `kagi` warns and asks for confirmation unless `--force` is used.

---

### `list`

List all scopes, or list keys within a scope. Values are masked by default.

```bash
kagi list                  # shows all scopes
kagi list dev              # shows keys with masked values
kagi list --service api prod
```

`kagi list --show-values <env>` prints decrypted values and requires an interactive TTY.

---

### `sync`

Synchronize keys from `.env.example` across environments. Useful when you add a new required variable and want every environment to have it (commented if it has no default value).

```bash
kagi sync
```

Options:

- `--service <service>` — scope synced environments under a service (also inferred in nested directories)
- `--example <path>` — template file (default: `.env.example`)
- `--sources <files>` — additional `.env` files to merge (comma-separated, later overrides earlier)
- `--envs <envs>` — environments to sync (default: `dev,test,staging,prod`)

**Behavior:**

- Keys with values in `.env.example` are added with those defaults.
- Keys that are commented out in `.env.example` (e.g. `# WEBHOOK_SECRET=`) are added as empty strings.
- Existing keys are never overwritten.

---

## Nested Project Support

When multiple services live in subdirectories under a single repository, **nested mode** lets `kagi` infer the service name from your current directory. Nested mode is off by default so nested scripts can still call `kagi run bun dev` without creating or requiring an `api` service.

```bash
# In the root
kagi init --nested

# Or allow only specific paths
echo '{"version":"1","services":{},"settings":{"nested":["api","web"]}}' > .kagi/kagi.json
```

Directory structure:

```
project/
  .kagi/
  api/
    src/
  web/
    src/
```

Working inside `project/api/src/`:

```bash
kagi set DB_HOST localhost       # stored under "api"
kagi set dev DB_HOST localhost   # stored under "api/dev"
kagi get DB_HOST                 # retrieved from "api"
kagi get dev DB_HOST             # retrieved from "api/dev"
kagi run cargo test              # runs with "api" secrets
kagi run dev cargo test          # runs with "api/dev" secrets
```

You can still override inference by providing the service explicitly:

```bash
kagi set --service web DB_HOST localhost        # stored under "web"
kagi set --service web dev DB_HOST localhost    # stored under "web/dev"
```

---

## Security

### Encryption

- Algorithm: **XChaCha20-Poly1305** for new writes
- Key: 256-bit master key
- Nonce: random 192-bit generated per encryption
- Tag: 128-bit authentication tag
- Associated data: format version, algorithm, and scope name are authenticated so encrypted stores cannot be silently moved between scopes

The master key is stored as hex in `.kagi/key/master.key` with file mode `0o600` (read/write owner only). `.kagi/`, `.kagi/key/`, and `.kagi/services/` are created with owner-only directory permissions on Unix. The key is loaded into a `zeroize::Zeroizing` buffer that scrubs memory on drop.

Encrypted stores use a versioned XChaCha20-Poly1305 format so future format changes can be detected explicitly.

### Non-interactive Access

`kagi get`, `kagi export`, and `kagi list --show-values` reveal decrypted secrets. They require an interactive TTY by default; add `--allow-non-interactive` only when you intentionally need machine-readable output. For application scripts, prefer:

```bash
kagi run dev bun dev
```

This prevents accidental secret dumps in logs, but it is not a sandbox. A process running as the same OS user and able to read `.kagi/key/master.key` can still access the same secrets. For stronger isolation, keep the key in an OS keychain, password manager, or external secret manager and avoid exposing it broadly to untrusted processes.

### Master Key Loss

If the master key is lost, **all encrypted secrets are permanently unrecoverable**. There is no backdoor, escrow, or recovery mechanism by design.

Ways to mitigate:

- Back up `.kagi/key/master.key` in a password manager or HSM.
- Share the key with teammates via a secure channel (1Password, Vault, etc.).
- Set `KAGI_MASTER_KEY` as an environment variable to avoid relying on the file.

### What to Commit

| Commit | Do **not** commit |
|--------|-------------------|
| `.env.example` | `.kagi/` |
| Application code | `.kagi/key/master.key` |
| Documentation | Encrypted `.enc` files |

When `kagi init` runs inside a Git repository, `.kagi/` is appended to that repository's `.gitignore`.

The only repository exception is `tests/.kagi/`, which is a fake fixture with a fixed test master key and no real secrets. It exists so examples under `tests/api` can exercise kagi behavior consistently.

---

## Architecture

kagi follows **Clean Architecture** with four layers:

| Layer | Responsibility |
|-------|----------------|
| **Domain** | Entities (`Service`, `Secret`), repository traits, error types, parsers |
| **Application** | Use cases: `InitService`, `SetSecretService`, `GetSecretService`, `RunCommandService`, etc. |
| **Infrastructure** | Concrete implementations: `FileStore`, `XChaChaEncryptor`, `KeyManager`, `SystemCommandRunner` |
| **CLI** | Argument parsing (`clap`), command dispatch, terminal styling |

This makes it trivial to swap the file-based store for a remote backend or replace the crypto implementation without touching business logic.

---

## Development

```bash
# Run all tests
cargo test

# Run integration tests only
cargo test --test integration_tests

# Try the Bun fixture
cd tests/api
bun dev

# Install locally
cargo install --path .
```

The test suite covers unit tests for every layer and full CLI integration tests using temporary directories.

---

## License

MIT
