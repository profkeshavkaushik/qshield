SHELL := /bin/bash

.PHONY: setup test bench ids tables figures paper all

setup:
	bash scripts/setup_liboqs.sh

test:
	. scripts/env.sh && python tests/test_protocol.py

bench:
	. scripts/env.sh && python -m qshield.crypto_bench --out results && python -m qshield.handshake_bench --out results && python -m qshield.pipeline_bench --out results && python -m qshield.overhead --out results

ids:
	bash scripts/run_ids.sh

tables:
	. scripts/env.sh && python scripts/make_tables.py

figures:
	. scripts/env.sh && python scripts/make_figures.py

paper: tables figures
	cd paper && pdflatex -interaction=nonstopmode main.tex && pdflatex -interaction=nonstopmode main.tex

all:
	bash scripts/run_all.sh
