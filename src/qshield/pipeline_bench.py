import argparse
import os
import time

import numpy as np

from . import env, protocol as P
from .crypto_bench import summarize
from .suites import SUITES


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=5000)
    ap.add_argument("--out", default="results")
    a = ap.parse_args()
    res = {"env": env.capture(), "params": vars(a), "suites": {}}
    for key in SUITES:
        suite, ca, veh, rsu = P.setup(key)
        payload = os.urandom(38)
        ver = P.BsmVerifier(suite)
        now = time.time()
        msgs = [P.bsm_sign(suite, veh.sk, payload, i + 1, now=now + i * 1e-6) for i in range(a.n)]
        lat = np.empty(a.n)
        ok = 0
        t_all = time.perf_counter()
        for i, m in enumerate(msgs):
            t = time.perf_counter_ns()
            ok += ver.accept("s0", veh.cert.vk, m, now=now + i * 1e-6)
            lat[i] = (time.perf_counter_ns() - t) / 1e6
        wall = time.perf_counter() - t_all
        assert ok == a.n
        res["suites"][key] = {"verify_pipeline": summarize(lat), "throughput_msgs_per_s": a.n / wall}
        print(key, "msgs/s", round(a.n / wall), "median ms", round(float(np.median(lat)), 4))
    env.write_json(os.path.join(a.out, "pipeline_bench.json"), res)


if __name__ == "__main__":
    main()
