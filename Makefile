.PHONY: test rust python

test: rust python

rust:
	cargo fmt --check
	cargo test --all

python:
	PYTHONPATH=python pytest -q
