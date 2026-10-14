import argparse
import os
import time

import numpy as np

from . import env, protocol as P
from .crypto_bench import summarize
from .suites import SUITES


def one_run(veh, rsu):
    t = {}
    c = time.perf_counter_ns
    t0 = c(); m1 = veh.msg1(rsu.ident); t1 = c()
    m2 = rsu.msg2(m1); t2 = c()
    m3 = veh.finish(m2); t3 = c()
    rsu.confirm(m3); t4 = c()
    t["obu_ms"] = ((t1 - t0) + (t3 - t2)) / 1e6
    t["rsu_ms"] = ((t2 - t1) + (t4 - t3)) / 1e6
    t["total_ms"] = (t4 - t0) / 1e6
    sizes = {
        "m1": m1["cert"].size() + len(m1["pk_e"]) + len(m1["eta_v"]) + len(m1["sig"]),
        "m2": m2["cert"].size() + len(m2["ct"]) + len(m2["eta_r"]) + len(m2["sig"]) + len(m2["tag"]),
        "m3": len(m3["tag"]),
    }
    return t, sizes


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=1000)
    ap.add_argument("--warmup", type=int, default=50)
    ap.add_argument("--out", default="results")
    a = ap.parse_args()

    result = {"env": env.capture(), "params": vars(a), "suites": {}}
    raw_all = {}
    for key in SUITES:
        suite, ca, veh, rsu = P.setup(key)
        for _ in range(a.warmup):
            one_run(veh, rsu)
        runs = {"obu_ms": [], "rsu_ms": [], "total_ms": []}
        sizes = {}
        for _ in range(a.n):
            t, sz = one_run(veh, rsu)
            sizes = {k: max(sizes.get(k, 0), v) for k, v in sz.items()}
            for k in runs:
                runs[k].append(t[k])
        result["suites"][key] = {k: summarize(np.array(v)) for k, v in runs.items()}
        result["suites"][key]["bytes"] = sizes
        result["suites"][key]["bytes"]["total"] = sum(sizes.values())
        result["suites"][key]["cert_bytes"] = veh.cert.size()
        for k, v in runs.items():
            raw_all[key + "|" + k] = np.array(v)
        print(key, "total median ms", round(result["suites"][key]["total_ms"]["median_ms"], 3),
              "bytes", result["suites"][key]["bytes"]["total"])
    env.write_json(os.path.join(a.out, "handshake_bench.json"), result)
    np.savez_compressed(os.path.join(a.out, "handshake_bench_raw.npz"), **raw_all)


if __name__ == "__main__":
    main()
