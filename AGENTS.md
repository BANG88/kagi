# Repository Guidelines

## Project Structure & Module Organization

`kagi` is a Rust 2024 CLI for encrypted environment variables. It is organized as a Cargo workspace with 6 crates:

- `crates/kagi-domain/`: core domain — entities, config, parsers, repository traits, crypto traits, and domain errors.
- `crates/kagi-crypto/`: XChaCha20-Poly1305 encryption implementation.
- `crates/kagi-store/`: local storage (`FileStore`), key manager, and environment injection.
- `crates/kagi-sync/`: sync protocol types and remote HTTP client (`age`-encrypted transport).
- `crates/kagi-server/`: Axum HTTP server and SQLite remote backend.
- `crates/kagi-cli/`: CLI application — Clap argument definitions, command dispatch, TUI, and use-case services.
- `kagi-vault` (root): meta-package that provides the `kagi` binary by re-exporting `kagi-cli`.
- `tests/integration_tests.rs`: end-to-end CLI tests using temporary directories.
- `docs/`: docs and README assets.

Keep code in the layer that owns the behavior. Domain code should not depend on CLI or filesystem details.

## Build, Test, and Development Commands

- `cargo build`: compile the debug binary.
- `cargo run -- <command>`: run the CLI locally, for example `cargo run -- init --envs dev,test`.
- `cargo test`: run unit and integration tests.
- `cargo fmt`: format Rust code before committing.
- `cargo clippy --all-targets --all-features`: run lints.
- `cargo install --path .`: install the local `kagi` binary for manual testing.

After completing code changes, run `cargo fmt -- --check`, `cargo clippy --all-targets --all-features -- -D warnings`, and `cargo test`. If all pass, finish by running `cargo install --path .` so the global `kagi` binary matches the workspace.

## Coding Style & Naming Conventions

Use `rustfmt` with 4-space indentation. Name modules and files in `snake_case`, types and traits in `PascalCase`, and functions, variables, and tests in `snake_case`. Prefer clear domain/application/infrastructure boundaries over passing filesystem or CLI concepts into core logic. Use `thiserror` for typed errors and `anyhow` where command-level context is appropriate.

## Testing Guidelines

Add integration coverage in `tests/integration_tests.rs` for user-visible CLI behavior, especially command parsing, `.kagi/` storage effects, nested-service inference, non-interactive guards, overwrite handling, and error messages. Use `assert_cmd`, `predicates`, and `tempfile` as existing tests do. Run `cargo test` before opening a PR; run targeted tests with `cargo test <test_name>`.

## Commit & Pull Request Guidelines

Recent history uses Conventional Commit prefixes such as `feat:`, `fix:`, `test:`, and `docs:`. Keep commit subjects imperative and scoped to one behavior, for example `feat: add nested service inference`.

Pull requests should include a short summary, test results, and any security implications for secret handling, encryption, or filesystem permissions. Link related issues when available. Include terminal output or screenshots only when CLI formatting or help text changes.

## Security & Configuration Tips

Never commit real `.kagi/`, master keys, generated secret stores, or real `.env` files. The exception is `tests/.kagi/`, which is a fixed fake fixture for CLI examples and tests. Inside Git repositories, the CLI updates `.gitignore` on init, but verify changes before committing. Prefer fake values in tests and examples, avoid logging decrypted secrets, and use `kagi run` rather than `get`/`export` in scripts.
