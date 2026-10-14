import json
import os
import platform
import subprocess
import sys


def _cpu_model():
    try:
        with open("/proc/cpuinfo") as f:
            for line in f:
                if line.startswith("model name"):
                    return line.split(":", 1)[1].strip()
    except OSError:
        pass
    return platform.processor() or "unknown"


def _liboqs_version():
    try:
        import oqs
        return oqs.oqs_version()
    except Exception:
        return "unknown"


def capture(include_oqs=True):
    try:
        import cryptography
        crypto_v = cryptography.__version__
    except Exception:
        crypto_v = "unknown"
    oqs_py = "unknown"
    liboqs_v = "unknown"
    if include_oqs:
        try:
            import oqs
            oqs_py = getattr(oqs, "oqs_python_version", lambda: "unknown")()
            liboqs_v = _liboqs_version()
        except Exception:
            pass
    return {
        "python": sys.version.split()[0],
        "platform": platform.platform(),
        "machine": platform.machine(),
        "cpu_model": _cpu_model(),
        "cpu_count": os.cpu_count(),
        "cryptography": crypto_v,
        "liboqs": liboqs_v,
        "liboqs_python": oqs_py,
    }


def write_json(path, obj):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        json.dump(obj, f, indent=1, sort_keys=True)
