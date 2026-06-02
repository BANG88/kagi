# Changelog

All notable changes to this project are documented in this file.

## Unreleased

### Added

- Add `kagi file add --external` for encrypted home-directory file artifacts.
- Add path-based file artifact identity with `repo:<path>` and `home:<path>` locators so common file names like `settings.json` do not collide.
- Add `kagi file restore --all --dry-run` to preview every restore target without writing files.
- Add `kagi file restore --all` restore planning with an interactive confirmation gate before batch writes.

### Changed

- External file restores now create a timestamped `*.kagi.bak.*` backup before overwriting an existing different file.
- `kagi file list` now shows explicit file locators and optional aliases.

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
