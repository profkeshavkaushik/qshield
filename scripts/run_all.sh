#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
. "$ROOT/scripts/env.sh"
cd "$ROOT"
python tests/test_protocol.py
python -m qshield.crypto_bench --out results
python -m qshield.handshake_bench --out results
python -m qshield.pipeline_bench --out results
python -m qshield.overhead --out results
if [ -f "$(python - <<'PY'
import json
print(json.load(open("configs/dataset.json"))["path"])
PY
)" ]; then
  python -m qshield.ids --config configs/dataset.json --out results --root "$ROOT" --name ids
  python -m qshield.ids --config configs/dataset_single.json --out results --root "$ROOT" --name ids_single
else
  echo "dataset not found: skipping IDS (see data/README.md)"
fi
python scripts/make_tables.py
python scripts/make_figures.py
cd paper
pdflatex -interaction=nonstopmode main.tex >/dev/null
pdflatex -interaction=nonstopmode main.tex >/dev/null
echo "built paper/main.pdf"
