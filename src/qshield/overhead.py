import argparse
import math
import os

from . import env, protocol as P

BSM_PAYLOAD_B = 38
TAU_B = 8
CTR_B = 4
DIGEST_B = 8
FRAG_PAYLOAD_B = 1400
MAC_LLC_FCS_B = 24 + 8 + 4
WSMP_HDR_B = 10
PHY_PREAMBLE_US = 32.0
PHY_SIGNAL_US = 8.0
SYMBOL_US = 8.0
RATES_MBPS = {6: 48, 12: 96, 27: 216}
BEACON_HZ = 10
CERT_PERIOD_S = 1.0
SCHEMES = ["ecdhe-ecdsa", "ecdhe-rsa3072", "qshield"]


def airtime_us(app_bytes, bits_per_symbol=48):
    n_frag = math.ceil(app_bytes / FRAG_PAYLOAD_B)
    total = 0.0
    left = app_bytes
    for _ in range(n_frag):
        chunk = min(left, FRAG_PAYLOAD_B)
        left -= chunk
        psdu_bits = 8 * (chunk + WSMP_HDR_B + MAC_LLC_FCS_B) + 16 + 6
        total += PHY_PREAMBLE_US + PHY_SIGNAL_US + math.ceil(psdu_bits / bits_per_symbol) * SYMBOL_US
    return total, n_frag


def bsm_sizes(key):
    suite, ca, veh, rsu = P.setup(key)
    sig = max(len(P.bsm_sign(suite, veh.sk, b"\x00" * BSM_PAYLOAD_B, i)["sig"]) for i in range(300))
    cert = veh.cert.size() - len(veh.cert.sig) + sig
    base = BSM_PAYLOAD_B + TAU_B + CTR_B + sig
    return {"sig_bytes": sig, "cert_bytes": cert,
            "with_cert": base + cert, "with_digest": base + DIGEST_B}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="results")
    ap.add_argument("--max-vehicles", type=int, default=400)
    ap.add_argument("--step", type=int, default=10)
    a = ap.parse_args()

    res = {"env": env.capture(),
           "assumptions": {"bsm_payload_bytes": BSM_PAYLOAD_B, "timestamp_bytes": TAU_B,
                           "counter_bytes": CTR_B, "digest_bytes": DIGEST_B,
                           "beacon_hz": BEACON_HZ, "cert_period_s": CERT_PERIOD_S,
                           "frag_payload_bytes": FRAG_PAYLOAD_B,
                           "phy": "802.11p 10 MHz, 6 Mbps (QPSK 1/2), 48 data bits per 8 us symbol",
                           "mac_llc_fcs_bytes": MAC_LLC_FCS_B, "wsmp_header_bytes": WSMP_HDR_B},
           "schemes": {}}
    vehicles = list(range(a.step, a.max_vehicles + 1, a.step))
    res["vehicles"] = vehicles
    res["rates_mbps"] = sorted(RATES_MBPS)
    for key in SCHEMES:
        s = bsm_sizes(key)
        mean_bytes = BEACON_HZ * s["with_digest"] + (s["with_cert"] - s["with_digest"]) / CERT_PERIOD_S
        s["bytes_per_vehicle_per_s"] = mean_bytes
        s["by_rate"] = {}
        for mbps, bps in sorted(RATES_MBPS.items()):
            t_cert, f_cert = airtime_us(s["with_cert"], bps)
            t_dig, f_dig = airtime_us(s["with_digest"], bps)
            frac = 1 / (CERT_PERIOD_S * BEACON_HZ)
            per_veh = BEACON_HZ * (t_dig * (1 - frac) + t_cert * frac) / 1e6
            s["by_rate"][str(mbps)] = {
                "frames_with_cert": f_cert, "frames_with_digest": f_dig,
                "airtime_cert_us": t_cert, "airtime_digest_us": t_dig,
                "airtime_per_vehicle_s_per_s": per_veh,
                "channel_load": [n * per_veh for n in vehicles],
                "max_vehicles_at_100pct": math.floor(1 / per_veh)}
        res["schemes"][key] = s
        print(key, s["with_cert"], s["with_digest"],
              {r: v["max_vehicles_at_100pct"] for r, v in s["by_rate"].items()})
    env.write_json(os.path.join(a.out, "overhead.json"), res)


if __name__ == "__main__":
    main()
