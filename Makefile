.PHONY: build test test-integration lint fmt clean install

build:
	cargo build --release

test:
	cargo test --lib --bins

test-integration:
	sudo -E cargo test --test '*' -- --test-threads=1

lint:
	cargo clippy --all-targets -- -D warnings

fmt:
	cargo fmt --all

fmt-check:
	cargo fmt --all -- --check

clean:
	cargo clean

install: build
	install -m 0755 target/release/crate /usr/local/bin/crate
