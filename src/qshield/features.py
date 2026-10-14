import numpy as np
import pandas as pd

EPS_T = 1e-3


def _prev(a, same):
    out = np.zeros_like(a)
    out[1:] = a[:-1]
    out[1:][~same] = 0.0
    return out


def _angle(ax, ay, bx, by):
    na = np.hypot(ax, ay)
    nb = np.hypot(bx, by)
    den = np.maximum(na * nb, 1e-12)
    c = np.clip((ax * bx + ay * by) / den, -1.0, 1.0)
    ang = np.arccos(c)
    ang[(na < 1e-9) | (nb < 1e-9)] = 0.0
    return ang


def add_history_features(df, spec):
    idc, tc = spec["id_column"], spec["time_column"]
    px, py = spec["pos"]
    sx, sy = spec["spd"]
    ax_, ay_ = spec["acl"]
    hx, hy = spec["hed"]
    ident = df[idc].to_numpy()
    t = df[tc].to_numpy(dtype=np.float64)
    order = np.lexsort((t, ident))
    inv = np.empty_like(order)
    inv[order] = np.arange(len(order))
    g = lambda c: df[c].to_numpy(dtype=np.float64)[order]
    idr, tr = ident[order], t[order]
    pxr, pyr, sxr, syr, axr, ayr, hxr, hyr = (g(c) for c in (px, py, sx, sy, ax_, ay_, hx, hy))
    same = idr[1:] == idr[:-1]
    has_prev = np.zeros(len(order))
    has_prev[1:] = same.astype(float)
    pt, ppx, ppy = _prev(tr, same), _prev(pxr, same), _prev(pyr, same)
    psx, psy, phx, phy = _prev(sxr, same), _prev(syr, same), _prev(hxr, same), _prev(hyr, same)
    hp = has_prev > 0
    dt = np.where(hp, tr - pt, 0.0)
    dx, dy = np.where(hp, pxr - ppx, 0.0), np.where(hp, pyr - ppy, 0.0)
    dist = np.hypot(dx, dy)
    dts = np.maximum(np.abs(dt), EPS_T)
    spd = np.hypot(sxr, syr)
    pspd = np.where(hp, np.hypot(psx, psy), 0.0)
    implied = np.where(hp, dist / dts, 0.0)
    acl = np.hypot(axr, ayr)
    spd_change = np.where(hp, spd - pspd, 0.0)
    acl_impl = np.where(hp, spd_change / dts, 0.0)
    pred_err = np.where(hp, np.hypot(pxr - (ppx + psx * dt), pyr - (ppy + psy * dt)), 0.0)
    feats = {
        "h_has_prev": has_prev,
        "h_dt": dt,
        "h_dist": dist,
        "h_implied_speed": implied,
        "h_speed_mag": spd,
        "h_speed_gap": np.where(hp, implied - spd, 0.0),
        "h_speed_change": spd_change,
        "h_accel_mag": acl,
        "h_accel_gap": np.where(hp, acl_impl - acl, 0.0),
        "h_heading_change": np.where(hp, _angle(hxr, hyr, phx, phy), 0.0),
        "h_disp_vs_heading": np.where(hp & (dist > 1e-9), _angle(dx, dy, hxr, hyr), 0.0),
        "h_spd_vs_heading": _angle(sxr, syr, hxr, hyr),
        "h_pred_err": pred_err,
        "h_same_pos": (hp & (dist < 1e-9)).astype(float),
        "h_same_speed": (hp & (np.abs(spd_change) < 1e-9)).astype(float),
    }
    out = df.copy()
    for k, v in feats.items():
        out[k] = v[inv].astype(np.float32)
    return out
