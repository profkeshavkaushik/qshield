import json
import os

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
RES = os.path.join(ROOT, "results")
OUT = os.path.join(ROOT, "paper", "generated")
os.makedirs(OUT, exist_ok=True)


def load(n):
    p = os.path.join(RES, n)
    return json.load(open(p)) if os.path.exists(p) else None


def w(name, text):
    if name == "tab_ids.tex" and "Pending" not in text:
        text = text.replace("\\begin{table}[!t]", "\\begin{table*}[!t]", 1).replace("\\end{table}", "\\end{table*}", 1)
        text = text.replace("\\setlength{\\tabcolsep}{2.5pt}", "\\setlength{\\tabcolsep}{6pt}", 1)
    elif name.startswith("tab_") and "Pending" not in text:
        text = text.replace("\\begin{tabular}", "\\resizebox{\\ifdim\\width>\\columnwidth\\columnwidth\\else\\width\\fi}{!}{\\begin{tabular}", 1)
        text = text.replace("\\end{tabular}", "\\end{tabular}}", 1)
    with open(os.path.join(OUT, name), "w") as f:
        f.write(text)


def fmt(x, d=3):
    return ("{:,.%df}" % d).format(x).replace(",", "{,}") if abs(x) >= 1000 else ("{:.%df}" % d).format(x)


def ms(x):
    if x >= 100:
        return "%.0f" % x
    if x >= 10:
        return "%.1f" % x
    if x >= 1:
        return "%.2f" % x
    return "%.3f" % x


def num(x):
    return "{:,}".format(int(round(x))).replace(",", "{,}")


mac = []


def macro(n, v):
    mac.append("\\newcommand{\\%s}{%s}" % (n, v))


cb, hb, ov, ids = load("crypto_bench.json"), load("handshake_bench.json"), load("overhead.json"), load("ids_results.json")
pb = load("pipeline_bench.json")
if pb:
    for k, t in [("qshield", "Q"), ("ecdhe-ecdsa", "E"), ("ecdhe-rsa3072", "R")]:
        macro("pipe%sRate" % t, num(pb["suites"][k]["throughput_msgs_per_s"]))
        macro("pipe%sMs" % t, ms(pb["suites"][k]["verify_pipeline"]["median_ms"]))

CAMEL = {"ML-DSA-65": "Mldsa", "ECDSA-P256": "Ecdsa", "RSA-3072-PSS": "RsaPss", "ML-KEM-768": "Mlkem",
         "ECDH-P256": "Ecdh", "RSA-3072-OAEP": "RsaOaep"}
OPN = {"keygen": "Kg", "sign": "Sign", "verify": "Verify", "encaps": "Enc", "decaps": "Dec"}
if cb:
    for n, op_d in cb["ops"].items():
        for op, d in op_d.items():
            macro("med%s%s" % (CAMEL[n], OPN[op]), ms(d["median_ms"]))
    macro("cpuModel", cb["env"]["cpu_model"].replace("(R)", "").replace("(TM)", "").replace("@", "at"))
    macro("liboqsVer", cb["env"]["liboqs"])
    macro("pyVer", cb["env"]["python"])
    macro("cryptoVer", cb["env"]["cryptography"])
    macro("benchN", num(cb["params"]["n"]))
    rows = [("Signatures", None),
            ("ML-DSA-65", [("keygen", None), ("sign", None), ("verify", None)]),
            ("ECDSA-P256", None), ("RSA-3072-PSS", None),
            ("Key establishment", None), ("ML-KEM-768", None), ("ECDH-P256", None), ("RSA-3072-OAEP", None)]
    L = ["\\begin{table}[!t]", "\\renewcommand{\\arraystretch}{1.15}",
         "\\caption{Measured latency of the cryptographic primitives (ms, median with 95th percentile in parentheses) and object sizes (bytes).}",
         "\\label{tab:crypto}", "\\centering", "\\footnotesize", "\\setlength{\\tabcolsep}{2.5pt}",
         "\\begin{tabular}{@{}lcccrr@{}}", "\\toprule",
         "\\textbf{Primitive} & \\textbf{KeyGen} & \\textbf{Sign / Encaps} & \\textbf{Verify / Decaps} & \\textbf{Key} & \\textbf{Sig. / CT} \\\\",
         "\\midrule"]

    def cell(n, op):
        d = cb["ops"][n][op]
        return "%s (%s)" % (ms(d["median_ms"]), ms(d["p95_ms"]))
    for n in ["ML-DSA-65", "ECDSA-P256", "RSA-3072-PSS"]:
        sz = cb["sizes"][n]
        L.append("%s & %s & %s & %s & %s & %s \\\\" % (n, cell(n, "keygen"), cell(n, "sign"), cell(n, "verify"),
                                                      num(sz["vk"]), num(sz["sig"])))
    L.append("\\midrule")
    for n in ["ML-KEM-768", "ECDH-P256", "RSA-3072-OAEP"]:
        sz = cb["sizes"][n]
        L.append("%s & %s & %s & %s & %s & %s \\\\" % (n, cell(n, "keygen"), cell(n, "encaps"), cell(n, "decaps"),
                                                      num(sz["pk"]), num(sz["ct"])))
    L += ["\\bottomrule", "\\end{tabular}", "\\end{table}"]
    w("tab_crypto.tex", "\n".join(L) + "\n")

if hb:
    names = {"qshield": "Q-SHIELD", "ecdhe-ecdsa": "ECDHE-ECDSA", "ecdhe-rsa3072": "ECDHE-RSA-3072"}
    macro("hsN", num(hb["params"]["n"]))
    L = ["\\begin{table}[!t]", "\\renewcommand{\\arraystretch}{1.15}",
         "\\caption{Full mutual-authentication handshake: measured compute time (ms, median with 95th percentile) and bytes on the wire.}",
         "\\label{tab:handshake}", "\\centering", "\\footnotesize", "\\setlength{\\tabcolsep}{2.5pt}",
         "\\begin{tabular}{@{}lccccr@{}}", "\\toprule",
         "\\textbf{Suite} & \\textbf{OBU} & \\textbf{RSU} & \\textbf{Total} & \\textbf{Cert.\\,(B)} & \\textbf{Wire\\,(B)} \\\\", "\\midrule"]
    for k in ["ecdhe-ecdsa", "ecdhe-rsa3072", "qshield"]:
        s = hb["suites"][k]
        c = lambda m: "%s (%s)" % (ms(s[m]["median_ms"]), ms(s[m]["p95_ms"]))
        L.append("%s & %s & %s & %s & %s & %s \\\\" % (names[k], c("obu_ms"), c("rsu_ms"), c("total_ms"),
                                                      num(s["cert_bytes"]), num(s["bytes"]["total"])))
        macro("hs" + {"qshield": "Q", "ecdhe-ecdsa": "E", "ecdhe-rsa3072": "R"}[k] + "Ms", ms(s["total_ms"]["median_ms"]))
        macro("hs" + {"qshield": "Q", "ecdhe-ecdsa": "E", "ecdhe-rsa3072": "R"}[k] + "Bytes", num(s["bytes"]["total"]))
    L += ["\\bottomrule", "\\end{tabular}", "\\end{table}"]
    macro("hsWireRatio", "%.1f" % (hb["suites"]["qshield"]["bytes"]["total"] / hb["suites"]["ecdhe-ecdsa"]["bytes"]["total"]))
    macro("hsTimeRatioE", "%.2f" % (hb["suites"]["qshield"]["total_ms"]["median_ms"] / hb["suites"]["ecdhe-ecdsa"]["total_ms"]["median_ms"]))
    macro("hsTimeRatioR", "%.2f" % (hb["suites"]["ecdhe-rsa3072"]["total_ms"]["median_ms"] / hb["suites"]["qshield"]["total_ms"]["median_ms"]))
    w("tab_handshake.tex", "\n".join(L) + "\n")

if ov:
    names = {"qshield": "Q-SHIELD (ML-DSA-65)", "ecdhe-ecdsa": "ECDSA P-256", "ecdhe-rsa3072": "RSA-3072-PSS"}
    a = ov["assumptions"]
    macro("bsmPayload", str(a["bsm_payload_bytes"]))
    L = ["\\begin{table}[!t]", "\\renewcommand{\\arraystretch}{1.15}",
         "\\caption{Per-BSM size and the number of vehicles whose beacons alone fill one 802.11p channel (offered airtime load of 100\\%).}",
         "\\label{tab:overhead}", "\\centering", "\\footnotesize", "\\setlength{\\tabcolsep}{2.5pt}",
         "\\begin{tabular}{@{}lrrrrrr@{}}", "\\toprule",
         "\\textbf{Scheme} & \\textbf{Sig.} & \\textbf{Cert.} & \\textbf{BSM+cert} & \\textbf{BSM+dig.} & \\multicolumn{2}{c}{\\textbf{Max.\\ vehicles}} \\\\",
         " & (B) & (B) & (B) & (B) & 6\\,Mb/s & 27\\,Mb/s \\\\", "\\midrule"]
    for k in ["ecdhe-ecdsa", "ecdhe-rsa3072", "qshield"]:
        s = ov["schemes"][k]
        L.append("%s & %s & %s & %s & %s & %s & %s \\\\" % (
            names[k], num(s["sig_bytes"]), num(s["cert_bytes"]), num(s["with_cert"]), num(s["with_digest"]),
            num(s["by_rate"]["6"]["max_vehicles_at_100pct"]), num(s["by_rate"]["27"]["max_vehicles_at_100pct"])))
        t = {"qshield": "Q", "ecdhe-ecdsa": "E", "ecdhe-rsa3072": "R"}[k]
        macro("ov%sCap" % t, num(s["by_rate"]["6"]["max_vehicles_at_100pct"]))
        macro("ov%sCapHi" % t, num(s["by_rate"]["27"]["max_vehicles_at_100pct"]))
        macro("ov%sBSM" % t, num(s["with_cert"]))
        macro("ov%sBSMd" % t, num(s["with_digest"]))
        macro("ov%sKbps" % t, "%.1f" % (s["bytes_per_vehicle_per_s"] * 8 / 1000))
        macro("ov%sFrames" % t, str(s["by_rate"]["6"]["frames_with_cert"]))
    L += ["\\bottomrule", "\\end{tabular}", "\\end{table}"]
    macro("ovRatioE", "%.1f" % (ov["schemes"]["qshield"]["bytes_per_vehicle_per_s"] / ov["schemes"]["ecdhe-ecdsa"]["bytes_per_vehicle_per_s"]))
    macro("ovCertFrames", str(ov["schemes"]["qshield"]["by_rate"]["6"]["frames_with_cert"]))
    macro("ovDigFrames", str(ov["schemes"]["qshield"]["by_rate"]["6"]["frames_with_digest"]))
    macro("ovQAirCertMs", "%.1f" % (ov["schemes"]["qshield"]["by_rate"]["6"]["airtime_cert_us"] / 1000))
    macro("ovQAirDigMs", "%.1f" % (ov["schemes"]["qshield"]["by_rate"]["6"]["airtime_digest_us"] / 1000))
    w("tab_overhead.tex", "\n".join(L) + "\n")

FEAT_DESC = {
    "h_has_prev": "a previous message from this pseudonym exists",
    "h_dt": "time since the previous message (s)",
    "h_dist": "distance moved since the previous message (m)",
    "h_implied_speed": "distance divided by elapsed time (m/s)",
    "h_speed_mag": "reported speed magnitude (m/s)",
    "h_speed_gap": "implied speed minus reported speed",
    "h_speed_change": "reported speed minus previous reported speed",
    "h_accel_mag": "reported acceleration magnitude",
    "h_accel_gap": "acceleration implied by speed change minus reported",
    "h_heading_change": "angle between consecutive headings (rad)",
    "h_disp_vs_heading": "angle between displacement and reported heading",
    "h_spd_vs_heading": "angle between reported speed and heading vectors",
    "h_pred_err": "distance from the position predicted by the previous message",
    "h_same_pos": "position identical to the previous message",
    "h_same_speed": "speed identical to the previous message",
}


def feat_desc(n):
    if n in FEAT_DESC:
        return FEAT_DESC[n]
    base = n[:-2] if n.endswith("_n") else n
    kind = {"pos": "position", "spd": "speed", "acl": "acceleration", "hed": "heading"}.get(base[:3], n)
    axis = base[3:]
    return ("reported noise of %s %s" if n.endswith("_n") else "reported %s %s") % (kind, axis)


IDS_NAMES = [("dt", "Decision tree"), ("lr", "Logistic regression"), ("rf", "Random forest"),
             ("xgb", "XGBoost"), ("ensemble", "RF+XGBoost ensemble")]
if ids:
    S = ids["summary"]
    macro("idsRows", num(ids["n_rows"]))
    macro("idsRowsTotal", num(ids["n_rows_total"]))
    if ids["n_rows"] < ids["n_rows_total"]:
        macro("idsSubsample", "To keep run time practical, a stratified random subsample of %s of the %s messages was used (fixed seed)." % (num(ids["n_rows"]), num(ids["n_rows_total"])))
    else:
        macro("idsSubsample", "All messages were used.")
    macro("idsFeatures", str(ids["n_features"]))
    macro("idsAttackPct", "%.1f" % (100 * ids["attack_fraction"]))
    macro("idsSeeds", str(len(ids["seeds"])))
    macro("idsSplit", "grouped by \\texttt{%s}" % ids["split_kind"][6:].replace("_", "\\_") if ids["split_kind"].startswith("group:") else "stratified random")
    L = ["\\begin{table}[!t]", "\\renewcommand{\\arraystretch}{1.15}",
         "\\caption{Binary misbehavior detection on the held-out test split (mean $\\pm$ std over %d seeds)." % len(ids["seeds"]) + "}",
         "\\label{tab:ids}", "\\centering", "\\footnotesize", "\\setlength{\\tabcolsep}{2.5pt}", "\\begin{tabular}{@{}lccccc@{}}", "\\toprule",
         "\\textbf{Model} & \\textbf{Acc.} & \\textbf{Prec.} & \\textbf{Rec.} & \\textbf{F1} & \\textbf{AUC} \\\\", "\\midrule"]
    for k, n in IDS_NAMES:
        r = S[k]
        cells = ["%.4f $\\pm$ %.4f" % (r[m]["mean"], r[m]["std"]) for m in ["accuracy", "precision", "recall", "f1", "auc"]]
        L.append("%s & %s \\\\" % (n, " & ".join(cells)))
    L += ["\\bottomrule", "\\end{tabular}", "\\end{table}"]
    w("tab_ids.tex", "\n".join(L) + "\n")
    e, rf, xg = S["ensemble"]["f1"], S["rf"]["f1"], S["xgb"]["f1"]
    best_single = max(rf["mean"], xg["mean"])
    gap = e["mean"] - best_single
    tol = max(e["std"], rf["std"], xg["std"])
    if gap > tol:
        verdict = "The ensemble improves on the better single model by %.4f F1, which exceeds the seed-to-seed standard deviation." % gap
    elif gap < -tol:
        verdict = "The ensemble is %.4f F1 below the better single model, a difference larger than the seed-to-seed standard deviation." % (-gap)
    else:
        verdict = "The ensemble differs from the better single model by %.4f F1, within the seed-to-seed standard deviation, so we do not claim an improvement." % abs(gap)
    w("ids_sentence.tex", "The ensemble reaches an F1 score of %.4f, against %.4f for the random forest and %.4f for XGBoost. %s\n" % (e["mean"], rf["mean"], xg["mean"], verdict))
    macro("idsEnsF", "%.4f" % e["mean"])
    macro("idsEnsAUC", "%.4f" % S["ensemble"]["auc"]["mean"])
    macro("idsEnsFPR", "%.4f" % S["ensemble"]["fpr"]["mean"])
    lat = sum(v["latency_ms_per_sample"] for v in ids["seeds"].values()) / len(ids["seeds"])
    macro("idsLatUs", "%.1f" % (lat * 1000))
    import numpy as np
    imp = np.mean([[ (a + b) / 2 for a, b in zip(v["importance"]["rf"], v["importance"]["xgb"])] for v in ids["seeds"].values()], axis=0)
    order = np.argsort(-imp)[:8]
    L = ["\\begin{table}[!t]", "\\renewcommand{\\arraystretch}{1.15}",
         "\\caption{The eight features with the highest mean importance (average of RF and XGBoost importances, mean over seeds).}",
         "\\label{tab:features}", "\\centering", "\\footnotesize", "\\setlength{\\tabcolsep}{2.5pt}", "\\begin{tabular}{@{}lp{3.6cm}r@{}}", "\\toprule",
         "\\textbf{Feature} & \\textbf{Description} & \\textbf{Importance} \\\\", "\\midrule"]
    for i in order:
        L.append("\\texttt{%s} & %s & %.4f \\\\" % (ids["feature_names"][i].replace("_", "\\_"), feat_desc(ids["feature_names"][i]), imp[i]))
    L += ["\\bottomrule", "\\end{tabular}", "\\end{table}"]
    w("tab_features.tex", "\n".join(L) + "\n")
    seeds = sorted(ids["seeds"])
    classes = sorted(ids["seeds"][seeds[0]]["per_type"], key=lambda z: (len(z), z))
    mean_t = {}
    for t in classes:
        rows_t = [ids["seeds"][sd]["per_type"][t] for sd in seeds if t in ids["seeds"][sd]["per_type"]]
        mean_t[t] = {k: float(np.mean([r[k] for r in rows_t])) for k in ["n", "rf_flagged", "xgb_flagged", "ensemble_flagged"]}
    L = ["\\begin{table}[!t]", "\\renewcommand{\\arraystretch}{1.1}",
         "\\caption{Fraction of test messages of each ground-truth class flagged as misbehavior (mean over %d seeds). The class~0 row is the false-positive rate; classes 1--19 are the attack types of the dataset.}" % len(seeds),
         "\\label{tab:idstypes}", "\\centering", "\\footnotesize", "\\setlength{\\tabcolsep}{6pt}", "\\begin{tabular}{@{}lrccc@{}}", "\\toprule",
         "\\textbf{Class} & \\textbf{Test msgs.} & \\textbf{RF} & \\textbf{XGBoost} & \\textbf{Ensemble} \\\\", "\\midrule"]
    for t in classes:
        d = mean_t[t]
        L.append("%s & %s & %.3f & %.3f & %.3f \\\\" % (t, num(d["n"]), d["rf_flagged"], d["xgb_flagged"], d["ensemble_flagged"]))
    L += ["\\bottomrule", "\\end{tabular}", "\\end{table}"]
    w("tab_idstypes.tex", "\n".join(L) + "\n")
    att = [(t, mean_t[t]["ensemble_flagged"]) for t in classes if t != "0"]
    att_sorted = sorted(att, key=lambda z: z[1])
    n90 = sum(1 for _, v in att if v >= 0.9)
    low = ", ".join("%s (%.2f)" % (t, v) for t, v in att_sorted[:3])
    high = ", ".join("%s (%.2f)" % (t, v) for t, v in att_sorted[::-1][:3])
    w("ids_types_sentence.tex", "The ensemble flags at least 90\\%% of the messages in %d of the %d attack classes. The hardest classes are %s, and the easiest are %s. Benign messages are flagged at a rate of %.3f.\n" % (n90, len(att), low, high, mean_t["0"]["ensemble_flagged"]))
    macro("idsClasses", str(len(classes)))
    sg = load("ids_single_results.json")
    if sg:
        SS = sg["summary"]
        macro("idsSingleFeatures", str(sg["n_features"]))
        macro("idsSingleF", "%.4f" % SS["ensemble"]["f1"]["mean"])
        macro("idsSingleAUC", "%.4f" % SS["ensemble"]["auc"]["mean"])
        L = ["\\begin{table}[!t]", "\\renewcommand{\\arraystretch}{1.15}",
             "\\caption{Effect of the feature set on the ensemble (mean $\\pm$ std over %d seeds, same splits)." % len(seeds) + "}",
             "\\label{tab:ablation}", "\\centering", "\\footnotesize", "\\setlength{\\tabcolsep}{2.5pt}", "\\begin{tabular}{@{}lcccc@{}}", "\\toprule",
             "\\textbf{Feature set} & \\textbf{Features} & \\textbf{F1} & \\textbf{AUC} & \\textbf{FPR} \\\\", "\\midrule"]
        for lab, R, nf in [("Per-message fields only", SS, sg["n_features"]), ("Per-message fields + history", S, ids["n_features"])]:
            e_ = R["ensemble"]
            L.append("%s & %d & %.4f $\\pm$ %.4f & %.4f $\\pm$ %.4f & %.4f $\\pm$ %.4f \\\\" % (
                lab, nf, e_["f1"]["mean"], e_["f1"]["std"], e_["auc"]["mean"], e_["auc"]["std"], e_["fpr"]["mean"], e_["fpr"]["std"]))
        L += ["\\bottomrule", "\\end{tabular}", "\\end{table}"]
        w("tab_ablation.tex", "\n".join(L) + "\n")
    else:
        w("tab_ablation.tex", "")
else:
    for n, lab in [("tab_ids.tex", "tab:ids"), ("tab_idstypes.tex", "tab:idstypes"), ("tab_features.tex", "tab:features"), ("tab_ablation.tex", "tab:ablation")]:
        w(n, "\\begin{table}[!t]\n\\caption{IDS results (not yet generated: run \\texttt{scripts/run\\_ids.sh} on the dataset).}\n\\label{%s}\n\\centering\n\\begin{tabular}{@{}l@{}}\n\\toprule\nPending\\\\\n\\bottomrule\n\\end{tabular}\n\\end{table}\n" % lab)
    w("ids_sentence.tex", "IDS results pending.\n")
    w("ids_types_sentence.tex", "IDS results pending.\n")
    for n, v in [("idsClasses", "--"), ("idsSingleFeatures", "--"), ("idsSingleF", "--"), ("idsSingleAUC", "--")]:
        macro(n, v)
    for n, v in [("idsRowsTotal", "--"), ("idsSubsample", "--"), ("idsRows", "--"), ("idsFeatures", "--"), ("idsAttackPct", "--"), ("idsSeeds", "--"), ("idsSplit", "--"),
                 ("idsEnsF", "--"), ("idsEnsAUC", "--"), ("idsEnsFPR", "--"), ("idsLatUs", "--")]:
        macro(n, v)
w("macros.tex", "\n".join(mac) + "\n")
print("wrote", sorted(os.listdir(OUT)))
