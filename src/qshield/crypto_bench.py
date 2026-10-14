import argparse
import os
import time

import numpy as np

from . import env
from .suites import MLKEM768, ECDHP256, MLDSA65, ECDSAP256, RSA3072PSS, RSA3072OAEP

MSG = bytes(range(256)) * 1


def timeit(fn, n, warmup):
    for _ in range(warmup):
        fn()
    out = np.empty(n)
    for i in range(n):
        t = time.perf_counter_ns()
        fn()
        out[i] = (time.perf_counter_ns() - t) / 1e6
    return out


def summarize(x):
    return {
        "n": int(len(x)),
        "mean_ms": float(np.mean(x)),
        "median_ms": float(np.median(x)),
        "std_ms": float(np.std(x, ddof=1)),
        "p95_ms": float(np.percentile(x, 95)),
        "ci95_ms": float(1.96 * np.std(x, ddof=1) / np.sqrt(len(x))),
    }


def bench_kem(cls, n, warmup, n_keygen):
    kem = cls()
    pk, sk = kem.keygen()
    ct, ss = kem.encaps(pk)
    assert kem.decaps(sk, ct) == ss
    raw = {
        "keygen": timeit(kem.keygen, n_keygen, min(warmup, 2) if n_keygen < 100 else warmup),
        "encaps": timeit(lambda: kem.encaps(pk), n, warmup),
        "decaps": timeit(lambda: kem.decaps(sk, ct), n, warmup),
    }
    return raw, {"pk": len(pk), "ct": len(ct), "ss": len(ss)}


def bench_sig(cls, n, warmup, n_keygen):
    s = cls()
    vk, sk = s.keygen()
    sig = s.sign(sk, MSG)
    assert s.verify(vk, MSG, sig)
    assert not s.verify(vk, MSG + b"x", sig)
    raw = {
        "keygen": timeit(s.keygen, n_keygen, min(warmup, 2) if n_keygen < 100 else warmup),
        "sign": timeit(lambda: s.sign(sk, MSG), n, warmup),
        "verify": timeit(lambda: s.verify(vk, MSG, sig), n, warmup),
    }
    sig_len = max(len(s.sign(sk, MSG)) for _ in range(300))
    return raw, {"vk": len(vk), "sig": sig_len}


PRIMITIVES = [
    (MLKEM768, "kem", False), (ECDHP256, "kem", False), (RSA3072OAEP, "kem", True),
    (MLDSA65, "sig", False), (ECDSAP256, "sig", False), (RSA3072PSS, "sig", True),
]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=2000)
    ap.add_argument("--n-rsa-keygen", type=int, default=30)
    ap.add_argument("--warmup", type=int, default=100)
    ap.add_argument("--out", default="results")
    a = ap.parse_args()

    os.makedirs(a.out, exist_ok=True)
    result = {"env": env.capture(), "params": vars(a), "ops": {}, "sizes": {}}
    raw_all = {}
    for cls, kind, slow_keygen in PRIMITIVES:
        n_keygen = a.n_rsa_keygen if slow_keygen else a.n
        fn = bench_kem if kind == "kem" else bench_sig
        raw, sizes = fn(cls, a.n, a.warmup, n_keygen)
        result["ops"][cls.name] = {op: summarize(v) for op, v in raw.items()}
        result["sizes"][cls.name] = sizes
        for op, v in raw.items():
            raw_all[cls.name + "|" + op] = v
        print(cls.name, {op: round(result["ops"][cls.name][op]["median_ms"], 4) for op in raw})
    env.write_json(os.path.join(a.out, "crypto_bench.json"), result)
    np.savez_compressed(os.path.join(a.out, "crypto_bench_raw.npz"), **raw_all)


if __name__ == "__main__":
    main()
