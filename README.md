# kagi

A CLI tool for managing encrypted environment variables with per-service isolation.

**kagi** (鍵, Japanese for "key") keeps your secrets encrypted at rest using AES-256-GCM while making them easy to inject into applications during development and deployment.

---

## Features

- **AES-256-GCM encryption** — Every secret is encrypted with a master key before touching disk.
- **Service-oriented** — Group secrets by service (`api`, `db`, `stripe`, etc.).
- **Nested project support** — Automatically infer the current service from your directory structure.
- **Shell-safe export** — Emit `KEY=value` lines for sourcing or Docker `--env-file`.
- **Import from `.env`** — Bulk-import existing `.env` files with overwrite protection.
- **Sync from `.env.example`** — Propagate keys across environments without losing existing values.
- **Zero default environments** — Create only what you need via `--envs`.
- **Clean Architecture** — Domain, Application, Infrastructure, and CLI layers are fully separated.

---

## Installation

```bash
cargo install --path .
```

Requires Rust 1.85+ (2024 edition).

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
kagi export dev > .env.dev
```

---

## Commands

### `init`

Create a `.kagi/` directory in the current project. This stores the master key, config, and encrypted services.

```bash
kagi init
kagi init --envs dev,staging,prod
kagi init --force              # overwrite existing .kagi/
```

**Note:** `.kagi/` is automatically added to `.gitignore`. Do **not** commit it.

---

### `set`

Store an encrypted secret.

```bash
kagi set <service> <key> <value>
kagi set dev STRIPE_KEY sk_live_xxx
```

With **nested inference** enabled, you can omit the service name when inside a child directory:

```bash
# .kagi/kagi.json has "nested": true
# You are in ./api/
kagi set API_KEY abc123      # stored under "api" service
```

---

### `get`

Retrieve and decrypt a secret value.

```bash
kagi get <service> <key>
kagi get dev DATABASE_URL
```

Also supports nested inference:

```bash
# inside ./api/
kagi get API_KEY             # reads from "api" service
```

---

### `run`

Execute a command with all secrets for a service injected as environment variables.

```bash
kagi run <service> <command> [args...]
kagi run dev npm start
kagi run test cargo test
```

If the first argument matches a known service name, it is treated as the service. Otherwise the service is inferred from the nested directory (if enabled).

```bash
# inside ./api/
kagi run node server.js      # runs with "api" secrets injected
```

---

### `export`

Print secrets as `KEY=value` lines. Suitable for shell sourcing or Docker `--env-file`.

```bash
kagi export dev
# DATABASE_URL=postgres://localhost/dev
# STRIPE_KEY=sk_live_xxx
```

---

### `import`

Import secrets from a `.env` file.

```bash
kagi import <service> --file .env.local
kagi import dev --file dev.env
kagi import dev --file dev.env --force   # skip overwrite prompt
```

If a key already exists, `kagi` warns and asks for confirmation unless `--force` is used.

---

### `list`

List all services, or list all keys within a specific service.

```bash
kagi list                  # shows all services
kagi list dev              # shows keys in a table
```

---

### `sync`

Synchronize keys from `.env.example` across environments. Useful when you add a new required variable and want every environment to have it (commented if it has no default value).

```bash
kagi sync
```

Options:

- `--example <path>` — template file (default: `.env.example`)
- `--sources <files>` — additional `.env` files to merge (comma-separated, later overrides earlier)
- `--envs <envs>` — environments to sync (default: `dev,test,staging,prod`)

**Behavior:**

- Keys with values in `.env.example` are added with those defaults.
- Keys that are commented out in `.env.example` (e.g. `# WEBHOOK_SECRET=`) are added as empty strings.
- Existing keys are never overwritten.

---

## Nested Project Support

When multiple services live in subdirectories under a single repository, you can enable **nested mode** so `kagi` automatically infers the service name from your current directory.

```bash
# In the root
kagi init

# Enable nested access
echo '{"version":"1","services":{},"settings":{"nested":true}}' > .kagi/kagi.json

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
kagi get DB_HOST                  # retrieved from "api"
kagi run cargo test               # runs with "api" secrets
```

You can still override inference by providing the service explicitly:

```bash
kagi set web DB_HOST localhost    # stored under "web", despite being in api/
```

---

## Security

### Encryption

- Algorithm: **AES-256-GCM**
- Key: 256-bit master key
- Nonce: random 96-bit generated per encryption
- Tag: 128-bit authentication tag

The master key is stored as hex in `.kagi/key/master.key` with file mode `0o600` (read/write owner only). The key is loaded into a `zeroize::Zeroizing` buffer that scrubs memory on drop.

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

The `.kagi/` directory is automatically appended to `.gitignore` during `kagi init`.

---

## Architecture

kagi follows **Clean Architecture** with four layers:

| Layer | Responsibility |
|-------|----------------|
| **Domain** | Entities (`Service`, `Secret`), repository traits, error types, parsers |
| **Application** | Use cases: `InitService`, `SetSecretService`, `GetSecretService`, `RunCommandService`, etc. |
| **Infrastructure** | Concrete implementations: `FileStore`, `AesGcmEncryptor`, `KeyManager`, `SystemCommandRunner` |
| **CLI** | Argument parsing (`clap`), command dispatch, terminal styling |

This makes it trivial to swap the file-based store for a remote backend or replace the crypto implementation without touching business logic.

---

## Development

```bash
# Run all tests
cargo test

# Run integration tests only
cargo test --test integration_tests

# Build release binary
cargo build --release

# Install locally
cargo install --path .
```

The test suite covers unit tests for every layer and full CLI integration tests using temporary directories.

---

## License

MIT
