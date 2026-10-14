#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
. "$ROOT/scripts/env.sh"
cd "$ROOT"
python -m qshield.ids --config configs/dataset.json --out results --root "$ROOT" --name ids
python -m qshield.ids --config configs/dataset_single.json --out results --root "$ROOT" --name ids_single
python scripts/make_tables.py
python scripts/make_figures.py
