import json
import os
import sys

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
RES = os.path.join(ROOT, "results")
OUT = os.path.join(ROOT, "paper", "figures")
os.makedirs(OUT, exist_ok=True)

C = {"qshield": "#0072B2", "ecdhe-ecdsa": "#E69F00", "ecdhe-rsa3072": "#009E73"}
LAB = {"qshield": "Q-SHIELD (ML-KEM-768 / ML-DSA-65)", "ecdhe-ecdsa": "ECDHE-ECDSA (P-256)",
       "ecdhe-rsa3072": "ECDHE-RSA (3072-bit)"}
MK = {"qshield": "o", "ecdhe-ecdsa": "s", "ecdhe-rsa3072": "^"}
LS = {"qshield": "-", "ecdhe-ecdsa": "--", "ecdhe-rsa3072": "-."}

plt.rcParams.update({"font.family": "serif", "font.size": 9, "axes.labelsize": 9, "axes.titlesize": 9,
                     "legend.fontsize": 8, "xtick.labelsize": 8, "ytick.labelsize": 8,
                     "axes.spines.top": False, "axes.spines.right": False,
                     "axes.grid": True, "grid.alpha": 0.25, "grid.linewidth": 0.6,
                     "figure.dpi": 100, "savefig.dpi": 300})


def load(name):
    p = os.path.join(RES, name)
    return json.load(open(p)) if os.path.exists(p) else None


def fig_latency():
    cb = load("crypto_bench.json")
    hb = load("handshake_bench.json")
    if not cb or not hb:
        print("skip fig_latency: run crypto_bench and handshake_bench first")
        return
    fig, ax = plt.subplots(1, 3, figsize=(7.2, 2.7), gridspec_kw={"width_ratios": [1.1, 1.1, 0.8]})
    sig = [("ML-DSA-65", "qshield"), ("ECDSA-P256", "ecdhe-ecdsa"), ("RSA-3072-PSS", "ecdhe-rsa3072")]
    kem = [("ML-KEM-768", "qshield"), ("ECDH-P256", "ecdhe-ecdsa"), ("RSA-3072-OAEP", "ecdhe-rsa3072")]
    for a, items, ops, title in [(ax[0], sig, ["sign", "verify"], "(a) Signatures"),
                                 (ax[1], kem, ["keygen", "encaps", "decaps"], "(b) Key establishment")]:
        w = 0.26
        x = np.arange(len(ops))
        for i, (n, k) in enumerate(items):
            v = [cb["ops"][n][o]["median_ms"] for o in ops]
            e = [cb["ops"][n][o]["p95_ms"] - cb["ops"][n][o]["median_ms"] for o in ops]
            a.bar(x + (i - 1) * w, v, w * 0.88, color=C[k], label=LAB[k] if a is ax[0] else None,
                  yerr=[np.zeros(len(e)), e], error_kw={"elinewidth": 0.7, "capsize": 1.5})
        a.set_xticks(x)
        a.set_xticklabels(ops)
        a.set_yscale("log")
        a.set_title(title)
    ax[0].set_ylabel("Median latency (ms, log scale)")
    ax[1].set_ylim(0.005, 1500)
    ax[0].set_ylim(0.005, 10)
    keys = ["qshield", "ecdhe-ecdsa", "ecdhe-rsa3072"]
    vals = [hb["suites"][k]["total_ms"]["median_ms"] for k in keys]
    err = [hb["suites"][k]["total_ms"]["p95_ms"] - hb["suites"][k]["total_ms"]["median_ms"] for k in keys]
    ax[2].bar(range(3), vals, 0.6, color=[C[k] for k in keys], yerr=[np.zeros(3), err],
              error_kw={"elinewidth": 0.7, "capsize": 1.5})
    ax[2].set_xticks(range(3))
    ax[2].set_xticklabels(["Q-SH.", "ECDSA", "RSA"])
    ax[2].set_title("(c) Full handshake")
    ax[2].set_ylabel("Median (ms)")
    fig.legend(loc="lower center", ncol=3, frameon=False, bbox_to_anchor=(0.5, -0.02))
    fig.tight_layout(rect=(0, 0.1, 1, 1))
    fig.savefig(os.path.join(OUT, "fig4_latency.png"), bbox_inches="tight")
    plt.close(fig)


def fig_channel():
    ov = load("overhead.json")
    if not ov:
        print("skip fig_channel: run overhead first")
        return
    veh = np.array(ov["vehicles"])
    fig, ax = plt.subplots(1, 2, figsize=(7.2, 2.8), sharey=True)
    for a, rate, title in [(ax[0], "6", "(a) 6 Mb/s (802.11p default)"), (ax[1], "27", "(b) 27 Mb/s")]:
        for k in ["ecdhe-ecdsa", "ecdhe-rsa3072", "qshield"]:
            y = np.array(ov["schemes"][k]["by_rate"][rate]["channel_load"]) * 100
            a.plot(veh, y, color=C[k], ls=LS[k], marker=MK[k], ms=3.2, lw=1.4,
                   markevery=4, label=LAB[k])
        a.axhline(100, color="#444444", lw=0.9)
        a.set_xlabel("Vehicles within range")
        a.set_title(title)
        a.set_xlim(0, veh.max())
        a.set_ylim(0, 150)
    ax[1].text(veh.max() * 0.99, 103, "channel capacity (100%)", ha="right", va="bottom", fontsize=7.5, color="#444444")
    ax[0].set_ylabel("Offered airtime load (% of channel)")
    h, l = ax[0].get_legend_handles_labels()
    fig.legend(h, l, loc="lower center", ncol=3, frameon=False, bbox_to_anchor=(0.5, -0.02))
    fig.tight_layout(rect=(0, 0.1, 1, 1))
    fig.savefig(os.path.join(OUT, "fig5_channel_load.png"), bbox_inches="tight")
    plt.close(fig)


def fig_roc():
    r = load("ids_results.json")
    p = os.path.join(RES, "ids_roc_curves.npz")
    if not r or not os.path.exists(p):
        print("skip fig_roc: run ids first (needs the real dataset)")
        return
    d = dict(np.load(p))
    ps = os.path.join(RES, "ids_single_roc_curves.npz")
    if os.path.exists(ps):
        ds = np.load(ps)
        d["single_fpr"], d["single_tpr"] = ds["ensemble_fpr"], ds["ensemble_tpr"]
    fig, ax = plt.subplots(1, 2, figsize=(7.2, 2.9))
    spec = [("ensemble", "Ensemble (with history)", "#0072B2", "-"), ("rf", "Random forest", "#D55E00", "--"),
            ("xgb", "XGBoost", "#009E73", "-."), ("lr", "Logistic regression", "#666666", ":")]
    if "single_fpr" in d:
        spec.append(("single", "Ensemble (per-message only)", "#CC79A7", (0, (5, 1, 1, 1))))
    for a, zoom in [(ax[0], False), (ax[1], True)]:
        for k, lab, col, ls in spec:
            a.plot(d[k + "_fpr"], d[k + "_tpr"], color=col, ls=ls, lw=1.4, label=lab)
        a.plot([0, 1], [0, 1], color="#999999", lw=0.8)
        a.set_xlabel("False positive rate")
        if zoom:
            a.set_xlim(0, 0.05)
            lows = [np.interp(0.05, d[k + "_fpr"], d[k + "_tpr"]) for k, _, _, _ in spec]
            a.set_ylim(max(0.0, np.floor((min(lows) - 0.02) * 20) / 20), 1.005)
            a.set_title("(b) Low-FPR region")
        else:
            a.set_title("(a) Full ROC")
            a.set_ylabel("True positive rate")
            a.set_xlim(0, 1)
            a.set_ylim(0, 1.02)
    h, l = ax[0].get_legend_handles_labels()
    fig.legend(h, l, loc="lower center", ncol=3, frameon=False, bbox_to_anchor=(0.5, -0.03))
    fig.tight_layout(rect=(0, 0.14, 1, 1))
    fig.savefig(os.path.join(OUT, "fig6_roc.png"), bbox_inches="tight")
    plt.close(fig)


if __name__ == "__main__":
    fig_latency()
    fig_channel()
    fig_roc()
