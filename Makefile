# CI calls these same targets: a command CI runs is a command anyone can run.
.PHONY: help fmt lint test check build

help:
	@echo "fmt    rustfmt over the workspace"
	@echo "lint   rustfmt --check and clippy, warnings as errors"
	@echo "test   the workspace's tests"
	@echo "check  lint, then test (what CI runs)"
	@echo "build  the release binary"

fmt:
	cargo fmt --all

lint:
	cargo fmt --all -- --check
	cargo clippy --workspace --all-targets --locked -- -D warnings

test:
	cargo test --workspace --locked

check: lint test

build:
	cargo build --release --locked -p stagegate
