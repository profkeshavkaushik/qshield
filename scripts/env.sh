ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export OQS_INSTALL_PATH="$ROOT/third_party/install"
export LD_LIBRARY_PATH="$ROOT/third_party/install/lib:${LD_LIBRARY_PATH:-}"
export PYTHONPATH="$ROOT/src:${PYTHONPATH:-}"
if [ -f "$ROOT/.venv/bin/activate" ]; then
  . "$ROOT/.venv/bin/activate"
fi
