# Kagi Release Automation
# Requires: cargo install cargo-release

.PHONY: help tag release dry-run publish status install

help: ## Show this help
	@echo "Kagi Release Commands"
	@echo "====================="
	@echo ""
	@echo "  make dry-run    Preview version bump (no changes)"
	@echo "  make tag        Create git tag and push (triggers CI release)"
	@echo "  make release    Bump version, commit, tag, push (uses cargo-release)"
	@echo "  make publish    Bump version and publish to crates.io (local)"
	@echo "  make status     Check which crates are unpublished"
	@echo "  make install    Install cargo-release"
	@echo ""
	@echo "Override version: VERSION=0.1.3 make tag"
	@echo ""

VERSION ?= patch

install: ## Install cargo-release
	cargo install cargo-release

dry-run: ## Preview what release would do (no changes)
	@echo "=== Dry run for version: $(VERSION) ==="
	cargo release $(VERSION) --workspace

tag: ## Create git tag and push (triggers GitHub Actions release)
	@echo "=== Tagging version: $(VERSION) ==="
	git tag -a "v$(VERSION)" -m "Release v$(VERSION)"
	git push origin "v$(VERSION)"

release: ## Bump version, commit, tag, and push (uses cargo-release)
	@echo "=== Releasing version: $(VERSION) ==="
	cargo release $(VERSION) --execute --workspace --no-publish

publish: ## Bump version and publish all crates to crates.io (local)
	@echo "=== Publishing version: $(VERSION) ==="
	cargo release $(VERSION) --execute --publish --workspace

status: ## Check which crates need publishing
	@echo "=== Unpublished crates ==="
	cargo release --unpublished --workspace
