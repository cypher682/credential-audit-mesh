.PHONY: build test fmt clippy run smoke up down

build:
	cargo build --release

test:
	cargo test

fmt:
	cargo fmt --all

clippy:
	cargo clippy --all-targets -- -D warnings

run:
	cargo run

smoke:
	./scripts/smoke.sh

up:
	docker compose -f deploy/docker-compose.yml up -d

down:
	docker compose -f deploy/docker-compose.yml down -v
