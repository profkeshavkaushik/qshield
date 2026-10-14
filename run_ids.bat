@echo off
python -m venv .venv_ids
call .venv_ids\Scripts\activate
python -m pip install --upgrade pip
pip install -r requirements-ids.txt
set PYTHONPATH=%CD%\src
python -m qshield.ids --config configs\dataset.json --out results --root %CD% --name ids
python -m qshield.ids --config configs\dataset_single.json --out results --root %CD% --name ids_single
echo Done. Results are in results\ids_results.json, results\ids_single_results.json and the matching _roc_curves.npz files
pause
