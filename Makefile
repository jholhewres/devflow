# CI calls these same targets: a command CI runs is a command anyone can run.
.PHONY: help fmt lint test check build sync-version

help:
	@echo "fmt           rustfmt over the workspace"
	@echo "lint          rustfmt --check and clippy, warnings as errors"
	@echo "test          the workspace's tests"
	@echo "check         lint, test and the versions (what CI runs)"
	@echo "build         the release binary"
	@echo "sync-version  write VERSION into every manifest"

fmt:
	cargo fmt --all

lint:
	cargo fmt --all -- --check
	cargo clippy --workspace --all-targets --locked -- -D warnings

test:
	cargo test --workspace --locked

check: lint test
	cargo xtask version-sync --check
	sh -n install.sh

build:
	cargo build --release --locked -p devflow-mcp

sync-version:
	cargo xtask version-sync
	cargo update --workspace --offline
