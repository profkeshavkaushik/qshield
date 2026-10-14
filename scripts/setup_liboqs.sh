#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LIBOQS_TAG="0.16.0"
cd "$ROOT"
mkdir -p third_party
if [ ! -d third_party/liboqs ]; then
  git clone --depth 1 --branch "$LIBOQS_TAG" https://github.com/open-quantum-safe/liboqs third_party/liboqs
fi
cmake -S third_party/liboqs -B third_party/liboqs/build \
  -DCMAKE_BUILD_TYPE=Release \
  -DBUILD_SHARED_LIBS=ON \
  -DOQS_BUILD_ONLY_LIB=ON \
  -DCMAKE_INSTALL_PREFIX="$ROOT/third_party/install"
cmake --build third_party/liboqs/build -j"$(nproc)"
cmake --install third_party/liboqs/build
python3 -m venv .venv
. .venv/bin/activate
pip install --upgrade pip
OQS_INSTALL_PATH="$ROOT/third_party/install" LD_LIBRARY_PATH="$ROOT/third_party/install/lib" pip install -r requirements.txt
echo "setup complete"
