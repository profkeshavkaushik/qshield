import argparse
import json
import os
import re
import time

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (accuracy_score, confusion_matrix, f1_score, precision_score,
                             recall_score, roc_auc_score, roc_curve)
from sklearn.model_selection import GroupShuffleSplit, train_test_split
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.tree import DecisionTreeClassifier
from xgboost import XGBClassifier

from . import env


_VEC = re.compile(r"^\s*[\[\(]\s*-?[\d.eE+-]+(\s*,\s*-?[\d.eE+-]+)+\s*[\]\)]\s*$")


def expand_vectors(df, skip):
    for c in list(df.columns):
        if c in skip or pd.api.types.is_numeric_dtype(df[c]):
            continue
        head = df[c].dropna().astype(str).head(50)
        if len(head) and head.map(lambda v: bool(_VEC.match(v))).all():
            parts = df[c].astype(str).str.strip("[]() ").str.split(",", expand=True).apply(pd.to_numeric, errors="coerce")
            for i in parts.columns:
                df[f"{c}_{i}"] = parts[i]
            df = df.drop(columns=[c])
    return df


LABEL_CANDIDATES = ["class", "Class", "label", "Label", "attackerType", "attacker_type", "AttackerType", "target", "Target"]
GROUP_CANDIDATES = ["sender", "Sender", "senderPseudo", "sender_id", "senderID", "vehicle_id", "vehicle"]


def resolve(cfg, df):
    lab = cfg["label_column"]
    if lab in (None, "auto"):
        hits = [c for c in LABEL_CANDIDATES if c in df.columns]
        if not hits:
            raise SystemExit("could not detect the label column; set label_column in the config. Columns: %s" % list(df.columns))
        cfg["label_column"] = hits[0]
    grp = cfg.get("group_column")
    if grp == "auto":
        hits = [c for c in GROUP_CANDIDATES if c in df.columns]
        cfg["group_column"] = hits[0] if hits else None
    print("label column:", cfg["label_column"], "| group column:", cfg.get("group_column"))


def load(cfg, root):
    path = cfg["path"] if os.path.isabs(cfg["path"]) else os.path.join(root, cfg["path"])
    df = pd.read_csv(path)
    resolve(cfg, df)
    if cfg.get("history"):
        from .features import add_history_features
        df = add_history_features(df, cfg["history"])
    df = expand_vectors(df, {cfg["label_column"]})
    n_total = len(df)
    lab = cfg["label_column"]
    if lab not in df.columns:
        raise SystemExit("label column '%s' not found; columns are: %s" % (lab, list(df.columns)))
    benign = set(map(str, cfg["benign_values"]))
    raw = df[lab].astype(str).to_numpy()
    y = (~df[lab].astype(str).isin(benign)).astype(int).to_numpy()
    if cfg.get("group_column") and cfg["group_column"] not in df.columns:
        raise SystemExit("group column '%s' not found; set group_column to a vehicle/simulation id column or null. Columns: %s"
                         % (cfg["group_column"], list(df.columns)))
    groups = df[cfg["group_column"]].to_numpy() if cfg.get("group_column") else None
    drop = set(cfg.get("drop_columns") or []) | {lab}
    if cfg.get("group_column"):
        drop.add(cfg["group_column"])
    cols = cfg.get("feature_columns")
    if cols is None:
        cols = [c for c in df.columns if c not in drop and pd.api.types.is_numeric_dtype(df[c])]
    X = df[cols].replace([np.inf, -np.inf], np.nan).fillna(0.0).to_numpy(dtype=np.float32)
    if cfg.get("max_rows") and len(y) > cfg["max_rows"]:
        rng = np.random.RandomState(0)
        idx = []
        for c in (0, 1):
            ci = np.where(y == c)[0]
            k = int(round(cfg["max_rows"] * len(ci) / len(y)))
            idx.append(rng.choice(ci, size=min(k, len(ci)), replace=False))
        idx = np.sort(np.concatenate(idx))
        X, y, raw = X[idx], y[idx], raw[idx]
        groups = groups[idx] if groups is not None else None
    return X, y, groups, cols, raw, n_total


def split(X, y, groups, fr, seed):
    n = len(y)
    if groups is not None:
        gss = GroupShuffleSplit(n_splits=1, test_size=fr["test"], random_state=seed)
        trv, te = next(gss.split(X, y, groups))
        gss2 = GroupShuffleSplit(n_splits=1, test_size=fr["val"] / (1 - fr["test"]), random_state=seed)
        tr, va = next(gss2.split(X[trv], y[trv], groups[trv]))
        return trv[tr], trv[va], te
    idx = np.arange(n)
    trv, te = train_test_split(idx, test_size=fr["test"], stratify=y, random_state=seed)
    tr, va = train_test_split(trv, test_size=fr["val"] / (1 - fr["test"]), stratify=y[trv], random_state=seed)
    return tr, va, te


def metrics(y, score, thr=0.5):
    pred = (score >= thr).astype(int)
    tn, fp, fn, tp = confusion_matrix(y, pred, labels=[0, 1]).ravel()
    return {"accuracy": accuracy_score(y, pred), "precision": precision_score(y, pred, zero_division=0),
            "recall": recall_score(y, pred, zero_division=0), "f1": f1_score(y, pred, zero_division=0),
            "auc": roc_auc_score(y, score), "fpr": fp / max(fp + tn, 1),
            "tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)}


def run_seed(X, y, groups, raw, cfg, seed):
    tr, va, te = split(X, y, groups, cfg["split"], seed)
    rf = RandomForestClassifier(random_state=seed, **cfg["rf"]).fit(X[tr], y[tr])
    xg = XGBClassifier(random_state=seed, eval_metric="logloss", tree_method="hist", **cfg["xgb"]).fit(X[tr], y[tr])
    dt = DecisionTreeClassifier(random_state=seed).fit(X[tr], y[tr])
    lr = make_pipeline(StandardScaler(), LogisticRegression(max_iter=1000, random_state=seed)).fit(X[tr], y[tr])
    p = {"rf": rf.predict_proba, "xgb": xg.predict_proba, "dt": dt.predict_proba, "lr": lr.predict_proba}
    sv = {k: f(X[va])[:, 1] for k, f in p.items()}
    best_a, best_auc = None, -1
    for a in cfg["alpha_grid"]:
        auc = roc_auc_score(y[va], a * sv["rf"] + (1 - a) * sv["xgb"])
        if auc > best_auc:
            best_a, best_auc = a, auc
    st = {k: f(X[te])[:, 1] for k, f in p.items()}
    st["ensemble"] = best_a * st["rf"] + (1 - best_a) * st["xgb"]
    out = {k: metrics(y[te], v) for k, v in st.items()}
    t = time.perf_counter()
    for _ in range(3):
        rf.predict_proba(X[te][:1000]); xg.predict_proba(X[te][:1000])
    lat_ms = (time.perf_counter() - t) / 3 / min(1000, len(te)) * 1e3
    fi = {"rf": rf.feature_importances_.tolist(), "xgb": xg.feature_importances_.tolist()}
    per_type = {}
    pred = (st["ensemble"] >= 0.5).astype(int)
    for t in np.unique(raw[te]):
        m = raw[te] == t
        per_type[str(t)] = {"n": int(m.sum()), "ensemble_flagged": float(pred[m].mean()),
                            "rf_flagged": float((st["rf"][m] >= 0.5).mean()),
                            "xgb_flagged": float((st["xgb"][m] >= 0.5).mean())}
    return out, best_a, lat_ms, st, y[te], fi, per_type


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default="configs/dataset.json")
    ap.add_argument("--out", default="results")
    ap.add_argument("--root", default=".")
    ap.add_argument("--name", default="ids")
    a = ap.parse_args()
    cfg = json.load(open(a.config))
    X, y, groups, cols, raw, n_total = load(cfg, a.root)
    print("rows", len(y), "features", len(cols), "attack fraction", round(float(y.mean()), 4))
    res = {"env": env.capture(include_oqs=False), "config": cfg, "n_rows": int(len(y)), "n_rows_total": int(n_total), "n_features": len(cols),
           "feature_names": cols, "attack_fraction": float(y.mean()), "seeds": {},
           "label_counts": {str(k): int((raw == k).sum()) for k in np.unique(raw)},
           "split_kind": "group:" + cfg["group_column"] if cfg.get("group_column") else "stratified-random"}
    curves = {}
    for seed in cfg["seeds"]:
        out, alpha, lat, st, yt, fi, per_type = run_seed(X, y, groups, raw, cfg, seed)
        res["seeds"][str(seed)] = {"metrics": out, "alpha": alpha, "latency_ms_per_sample": lat,
                                   "importance": fi, "per_type": per_type}
        if seed == cfg["seeds"][0]:
            for k, v in st.items():
                fpr, tpr, _ = roc_curve(yt, v)
                curves[k + "_fpr"], curves[k + "_tpr"] = fpr.astype(np.float32), tpr.astype(np.float32)
        print("seed", seed, "alpha", alpha, {k: round(v["f1"], 4) for k, v in out.items()})
    models = list(next(iter(res["seeds"].values()))["metrics"])
    mets = ["accuracy", "precision", "recall", "f1", "auc", "fpr"]
    res["summary"] = {m: {k: {"mean": float(np.mean([res["seeds"][s]["metrics"][m][k] for s in res["seeds"]])),
                              "std": float(np.std([res["seeds"][s]["metrics"][m][k] for s in res["seeds"]], ddof=1))
                              if len(res["seeds"]) > 1 else 0.0}
                          for k in mets} for m in models}
    env.write_json(os.path.join(a.out, a.name + "_results.json"), res)
    np.savez_compressed(os.path.join(a.out, a.name + "_roc_curves.npz"), **curves)


if __name__ == "__main__":
    main()
