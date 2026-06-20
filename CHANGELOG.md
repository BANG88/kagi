# Changelog

All notable changes to this project are documented in this file.

## Unreleased

### Added

- Add `kagi-store` vault config constructors for embedding vault config in a caller-managed project config without changing Kagi CLI defaults.
- Add `kagi uninit` for removing local `.kagi/` metadata with confirmation.

### Changed

- Keep `kagi init` migration interactive while showing inferred migration targets and template priority.
- Treat `.env.<name>` files as their own environments during init migration discovery, even when the environment was not preconfigured.
- Make `kagi get` TUI reveal all values after a single confirmation and add `Tab` / `Shift-Tab` scope switching.

### Fixed

- Prevent `.env.example`, `.env.sample`, and `.env.template` migration from overwriting real `.env` values by importing templates as missing-key defaults only.

## 0.1.6 - 2026-06-02

### Added

- Add `kagi file add --external` for encrypted home-directory file artifacts.
- Add path-based file artifact identity with `repo:<path>` and `home:<path>` locators so common file names like `settings.json` do not collide.
- Add `kagi file restore --all --dry-run` to preview every restore target without writing files.
- Add `kagi file restore --all` restore planning with an interactive confirmation gate before batch writes.

### Changed

- External file restores now create a timestamped `*.kagi.bak.*` backup before overwriting an existing different file.
- `kagi file list` now shows explicit file locators and optional aliases.

### Fixed

- Allow external file restores when a trusted home or temporary-directory prefix canonicalizes through a platform symlink, such as `/var` on macOS.
- Fall back to environment-provided home directories when platform home discovery is unavailable, covering Windows CI and other constrained environments.
- Normalize displayed restore paths on Windows so previews do not show verbatim `\\?\` path prefixes.

### Security

- External file artifacts are limited to files under the current user's home directory.
- External file add and restore paths reject symlinks and sensitive home directories such as `.ssh` and `.gnupg`.

## 0.1.5 - 2026-06-01

### Added

- Add the encrypted `kagi file` command for storing, listing, showing, restoring, and removing small encrypted file artifacts.
- Add monorepo `.env` migration and service mapping support for nested project layouts.
- Add the full TUI suite with layout support for interactive workflows.
- Add shell completion generation.
- Add consolidated remote command surfaces for server-backed sync and team workflows.

### Changed

- Keep TUI-specific help text internal unless TUI support is enabled.
- Remove local `.kagi` metadata from the release branch.

## 0.1.4 - 2026-05-30

### Fixed

- Rename the application crate from `kagi-cli` to `kagi-app` for crates.io availability.
