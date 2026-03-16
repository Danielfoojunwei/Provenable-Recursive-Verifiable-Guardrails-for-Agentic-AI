.PHONY: build test install lint fmt clean help

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}'

build: ## Build all crates (release mode)
	cargo build --workspace --release

test: ## Run all tests
	cargo test --workspace

lint: ## Run clippy with warnings as errors
	cargo clippy --workspace -- -D warnings

fmt: ## Check formatting
	cargo fmt --check

fmt-fix: ## Fix formatting
	cargo fmt

install: ## Install aegx binary to ~/.cargo/bin
	cargo install --path crates/aegx-cli --locked

clean: ## Remove build artifacts
	cargo clean

check: lint fmt test ## Run lint, format check, and tests
