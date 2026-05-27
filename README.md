# kagi

![kagi README banner](docs/kagi-readme-banner.png)

A CLI tool for managing encrypted environment variables with per-service isolation.

**kagi** (鍵, Japanese for "key") keeps your secrets encrypted at rest using XChaCha20-Poly1305 while making them easy to inject into applications during development and deployment.

---

## Features

- **XChaCha20-Poly1305 encryption** — Every secret is authenticated and encrypted with a master key before touching disk.
- **Service-first environments** — Store secrets per service and environment (`api/development`, `web/production`), with `development` as the default environment.
- **Opt-in nested project support** — Infer the current service from your directory structure when enabled.
- **Shell-safe export** — Emit `KEY=value` lines for sourcing or Docker `--env-file`.
- **Non-interactive safety** — `get`, `export`, and value listing require explicit opt-in when stdout is not a TTY; scripts should prefer `kagi run`.
- **Import from `.env`** — Bulk-import existing `.env` files with overwrite protection.
- **Sync from `.env.example`** — Propagate keys across environments without losing existing values.
- **Configurable default environments** — `--envs` defines the environment set each service should get; `development` is always available by default.
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

# 2. Configure default environments on init (optional)
kagi init --envs development,test,production

# 3. Store a service secret in the default development environment
kagi set api DATABASE_URL postgres://localhost/development

# 4. Retrieve it
kagi get api DATABASE_URL
# → postgres://localhost/development

# 5. Run a command with injected env vars
kagi run api node server.js

# 6. Inspect masked keys
kagi get api
```

---

## Commands

### `init`

Create a `.kagi/` directory in the current project. This stores the master key, config, encrypted root environments, and encrypted service environments.

```bash
kagi init
kagi init --envs development,staging,production
kagi init --nested             # enable service inference from subdirectories
kagi init --force              # overwrite existing .kagi/
```

`--envs` records the default environments for every service. It does not create `development`, `test`, or `production` as services. If `development` is omitted, kagi still adds it so service commands can use the default environment. Passing `--envs` without a value initializes the standard set: `development`, `test`, and `production`.

**Note:** If `kagi init` runs inside a Git repository, `.kagi/` is added to the repository `.gitignore`. Do **not** commit it.

---

### `set`

Store an encrypted secret.

```bash
kagi set <service> <key> <value>              # stores under <service>/development
kagi set <service> <env> <key> <value>
kagi set api STRIPE_KEY fake_stripe_key
kagi set --service api production DATABASE_URL postgres://production/db
```

The first positional argument is treated as an environment only when it matches a configured environment such as `development`, `test`, or `production`. Otherwise it is treated as a service and defaults to `development`.
If an environment name conflicts with a service name, use `--service <service>` to make the service explicit.

If a value contains spaces or shell-special characters, quote or escape it for
your shell so it reaches `kagi` as one argument:

```bash
kagi set api DATABASE_URL 'postgres://u:p@localhost/db?name=development app&sslmode=disable'
```

For multi-line values or large `.env` files, prefer `kagi import <service> --file
.env.local`.

With **nested inference** enabled via `kagi init --nested`, `kagi` infers the service from the child directory. You can omit the environment to use `development`, or include an environment explicitly:

```bash
# You are in ./api/
kagi set API_KEY abc123          # stored under "api/development"
kagi set development API_KEY abc123      # stored under "api/development"
kagi set production API_KEY abc123     # stored under "api/production"
```

---

### `get`

Show services, environments, and keys. Values are masked by default. Use `--show-values` to reveal values after interactive confirmation, or provide a key to print one decrypted value.

```bash
kagi get                            # shows service/env layout
kagi get api                        # shows api/* environments and masked keys
kagi get api production             # shows masked keys in api/production
kagi get --service api production
kagi get api --show-values          # shows decrypted values after confirmation
kagi get <service> <key>              # reads from <service>/development
kagi get <service> <env> <key>
kagi get api DATABASE_URL
kagi get --service api production DATABASE_URL
```

Also supports opt-in nested inference:

```bash
# inside ./api/
kagi get API_KEY             # reads from "api/development"
kagi get development API_KEY         # reads from "api/development"
```

`kagi get <key>` and `kagi get --show-values` print decrypted data, so they require an interactive terminal and a `y` confirmation. Plain `kagi get` and `kagi get <service>` only show masked keys and do not require confirmation.

---

### `run`

Execute a command with all secrets for a service environment injected as environment variables.

```bash
kagi run <service> <command> [args...]        # uses <service>/development
kagi run <service> <env> <command> [args...]
kagi run api npm start
kagi run api test cargo test
kagi run --service api production bun start
```

Inside a nested service directory, the service is inferred from the path. The first argument is treated as an environment when it matches a configured environment or an existing scoped store. Otherwise the command runs with the inferred service and the default `development` environment. If nested mode is disabled and no scope is provided, `kagi run <command>` runs the command without injected variables and prints a `kagi: notice:` line.

```bash
# inside ./api/
kagi run bun dev             # runs with "api/development" secrets injected
kagi run development bun dev # also runs with "api/development" secrets injected
kagi run production bun start      # runs with "api/production" secrets injected
```

Because nested mode gives the first argument two possible meanings, configured environment names win over command names. For example, if `bun` is configured as an environment, `kagi run bun dev` inside `./api/` means env `bun`, command `dev`.

`kagi run` starts the command directly with Rust's process API, so executable
launch and environment injection work across Linux, macOS, and Windows. It does
not parse shell syntax itself. For pipes, redirects, `$VAR` expansion, or
platform-specific shell built-ins, run the shell explicitly (`sh -c`,
`cmd /C`, or PowerShell).

---

### `export`

Print secrets as `KEY=value` lines. Suitable for shell sourcing or Docker `--env-file`.

```bash
kagi export api --out .             # writes .env.development, .env.production, etc.
kagi export api development         # exports only api/development
kagi export api production --out .  # writes .env.production
kagi export --service api production
# DATABASE_URL=postgres://localhost/development
# STRIPE_KEY=fake_stripe_key
```

`kagi export <service> --out <dir>` writes one file per environment using common runtime names: `development` becomes `.env.development`, `production` becomes `.env.production`, `test` becomes `.env.test`, and custom names become `.env.<name>`. Exporting a single environment without `--out` prints decrypted data to stdout. Both forms require an interactive terminal and a `y` confirmation.

---

### `import`

Import secrets from a `.env` file.

```bash
kagi import <service> --file .env.local
kagi import api --file .env.development
kagi import api --file .env.development --force   # skip overwrite prompt
kagi import --service api production --file .env.production
```

If a key already exists, `kagi` warns and asks for confirmation unless `--force` is used.

---

### `env`

Manage the default environment set used by every service.

```bash
kagi env list
kagi env add staging
kagi env rename staging qa
kagi env del qa
```

`kagi env add <env>` records the environment and creates empty stores for existing services. `kagi env rename <old> <new>` renames that environment across all services and re-encrypts stores under the new scope name. `kagi env del <env>` deletes the environment across all services and requires an interactive confirmation where you type the environment name.

The default environment is `development`; kagi prevents deleting it. Environment names cannot conflict with existing service names because that would make shorthand commands ambiguous.

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
- `--envs <envs>` — environments to sync (default: `development,test,staging,production`)

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
echo '{"version":"1","services":{},"settings":{"nested":["api","web"],"envs":["development","test","production"],"default_env":"development"}}' > .kagi/kagi.json
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
kagi set DB_HOST localhost       # stored under "api/development"
kagi set development DB_HOST localhost   # stored under "api/development"
kagi get DB_HOST                 # retrieved from "api/development"
kagi get development DB_HOST             # retrieved from "api/development"
kagi run cargo test              # runs with "api/development" secrets
kagi run development cargo test          # runs with "api/development" secrets
```

You can still override inference by providing the service explicitly:

```bash
kagi set --service web DB_HOST localhost        # stored under "web/development"
kagi set --service web development DB_HOST localhost    # stored under "web/development"
```

---

## Security

### Encryption

- Algorithm: **XChaCha20-Poly1305** for new writes
- Key: 256-bit master key
- Nonce: random 192-bit generated per encryption
- Tag: 128-bit authentication tag
- Associated data: format version, algorithm, and scope name are authenticated so encrypted stores cannot be silently moved between scopes

The master key is stored as hex in `.kagi/key/master.key` with file mode `0o600` (read/write owner only). `.kagi/`, `.kagi/key/`, `.kagi/envs/`, and `.kagi/services/` are created with owner-only directory permissions on Unix. The key is loaded into a `zeroize::Zeroizing` buffer that scrubs memory on drop.

Encrypted stores use a versioned XChaCha20-Poly1305 format so future format changes can be detected explicitly.

### Non-interactive Access

`kagi get <key>`, `kagi get --show-values`, and `kagi export` reveal decrypted
secrets. They require an interactive terminal and a `y` confirmation. For
application scripts, prefer:

```bash
kagi run api bun dev
```

This prevents accidental direct secret dumps in logs, but it is not a sandbox. A
process launched through `kagi run` receives the selected secrets as environment
variables and can print or exfiltrate them. A process running as the same OS user
and able to read `.kagi/key/master.key` can also access the same secrets. For
stronger isolation, keep the key in an OS keychain, password manager, or external
secret manager and avoid running untrusted code with `kagi run`.

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
