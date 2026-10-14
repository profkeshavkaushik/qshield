import copy
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from qshield import protocol as P
from qshield.suites import SUITES


def expect_fail(fn, label):
    try:
        fn()
    except P.HandshakeError:
        return
    raise AssertionError("tamper not detected: " + label)


def run(key):
    suite, ca, veh, rsu = P.setup(key)
    m1, m2, m3 = P.run_handshake(veh, rsu)
    blob = P.seal(veh.k_enc, b"misbehavior report")
    assert P.unseal(rsu.k_enc, blob) == b"misbehavior report"

    suite, ca, veh, rsu = P.setup(key)
    m1 = veh.msg1(rsu.ident)
    bad = dict(m1); bad["eta_v"] = os.urandom(16)
    expect_fail(lambda: rsu.msg2(bad), "M1 nonce modified")

    suite, ca, veh, rsu = P.setup(key)
    m1 = veh.msg1(rsu.ident)
    m2 = rsu.msg2(m1)
    bad = dict(m2); ct = bytearray(m2["ct"]); ct[0] ^= 1; bad["ct"] = bytes(ct)
    expect_fail(lambda: veh.finish(bad), "ciphertext modified")

    suite, ca, veh, rsu = P.setup(key)
    other = P.Authority(suite)
    rogue_cert, rogue_sk = other.issue(b"OBU-ROGUE")
    rogue = P.Vehicle(suite, ca.vk, rogue_cert, rogue_sk)
    expect_fail(lambda: rsu.msg2(rogue.msg1(rsu.ident)), "certificate from untrusted CA")

    suite, ca, veh, rsu = P.setup(key)
    old_cert, old_sk = ca.issue(b"OBU-OLD", now=int(time.time()) - 10 * 24 * 3600)
    old = P.Vehicle(suite, ca.vk, old_cert, old_sk)
    expect_fail(lambda: rsu.msg2(old.msg1(rsu.ident)), "expired certificate")

    suite, ca, veh, rsu = P.setup(key)
    m1 = veh.msg1(b"RSU-OTHER")
    expect_fail(lambda: rsu.msg2(m1), "RSU identity mismatch")

    suite, ca, veh, rsu = P.setup(key)
    ver = P.BsmVerifier(suite)
    b1 = P.bsm_sign(suite, veh.sk, b"x" * 64, 1)
    assert ver.accept(b"v", veh.cert.vk, b1)
    assert not ver.accept(b"v", veh.cert.vk, b1)
    b2 = P.bsm_sign(suite, veh.sk, b"x" * 64, 2, now=time.time() - 5)
    assert not ver.accept(b"v", veh.cert.vk, b2)
    b3 = P.bsm_sign(suite, veh.sk, b"x" * 64, 3)
    b3["payload"] = b"y" * 64
    assert not ver.accept(b"v", veh.cert.vk, b3)
    b4 = P.bsm_sign(suite, veh.sk, b"x" * 64, 4)
    assert ver.accept(b"v", veh.cert.vk, b4)


if __name__ == "__main__":
    for key in SUITES:
        run(key)
        print("PASS", key)
