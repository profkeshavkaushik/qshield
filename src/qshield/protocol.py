import hashlib
import hmac
import os
import struct
import time
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .suites import SUITES

NONCE_LEN = 16
CERT_VALIDITY_S = 72 * 3600
BSM_WINDOW_S = 0.2


def _lp(*parts):
    out = b""
    for p in parts:
        out += struct.pack(">I", len(p)) + p
    return out


@dataclass
class Cert:
    ident: bytes
    exp: int
    vk: bytes
    sig: bytes

    def tbs(self):
        return _lp(b"QS-CERT-v1", self.ident, struct.pack(">Q", self.exp), self.vk)

    def encode(self):
        return _lp(self.ident, struct.pack(">Q", self.exp), self.vk, self.sig)

    def size(self):
        return len(self.encode())


class Suite:
    def __init__(self, key):
        kem_cls, sig_cls = SUITES[key]
        self.key = key
        self.kem = kem_cls()
        self.sig = sig_cls()


class Authority:
    def __init__(self, suite):
        self.suite = suite
        self.vk, self._sk = suite.sig.keygen()

    def issue(self, ident, now=None, validity=CERT_VALIDITY_S):
        now = int(time.time()) if now is None else now
        vk, sk = self.suite.sig.keygen()
        cert = Cert(ident=ident, exp=now + validity, vk=vk, sig=b"")
        cert.sig = self.suite.sig.sign(self._sk, cert.tbs())
        return cert, sk


class HandshakeError(Exception):
    pass


def verify_cert(suite, ca_vk, cert, now=None):
    now = int(time.time()) if now is None else now
    if cert.exp < now:
        raise HandshakeError("certificate expired")
    if not suite.sig.verify(ca_vk, cert.tbs(), cert.sig):
        raise HandshakeError("certificate signature invalid")


def _transcript(*parts):
    return hashlib.sha3_256(_lp(*parts)).digest()


def _derive(ss, eta_v, eta_r, th):
    okm = HKDF(algorithm=hashes.SHA256(), length=96, salt=eta_v + eta_r, info=b"QS-KDF-v1" + th).derive(ss)
    return okm[:32], okm[32:64], okm[64:96]


class Vehicle:
    def __init__(self, suite, ca_vk, cert, sk):
        self.s, self.ca_vk, self.cert, self.sk = suite, ca_vk, cert, sk

    def msg1(self, rsu_id):
        pk_e, self._sk_e = self.s.kem.keygen()
        self._eta_v = os.urandom(NONCE_LEN)
        self._rsu_id = rsu_id
        body = _lp(b"M1", rsu_id, pk_e, self._eta_v)
        sig = self.s.sig.sign(self.sk, body)
        self._pk_e = pk_e
        return {"cert": self.cert, "pk_e": pk_e, "eta_v": self._eta_v, "sig": sig}

    def finish(self, m2, now=None):
        verify_cert(self.s, self.ca_vk, m2["cert"], now)
        th = _transcript(b"TH", self._rsu_id, self._pk_e, self._eta_v, m2["ct"], m2["eta_r"])
        body = _lp(b"M2", th)
        if not self.s.sig.verify(m2["cert"].vk, body, m2["sig"]):
            raise HandshakeError("RSU signature invalid")
        ss = self.s.kem.decaps(self._sk_e, m2["ct"])
        self._sk_e = None
        k_enc, k_mac_r, k_mac_v = _derive(ss, self._eta_v, m2["eta_r"], th)
        if not hmac.compare_digest(hmac.new(k_mac_r, b"R" + th, "sha256").digest(), m2["tag"]):
            raise HandshakeError("key confirmation failed")
        self.k_enc = k_enc
        return {"tag": hmac.new(k_mac_v, b"V" + th, "sha256").digest()}


class RSU:
    def __init__(self, suite, ca_vk, cert, sk, ident):
        self.s, self.ca_vk, self.cert, self.sk, self.ident = suite, ca_vk, cert, sk, ident

    def msg2(self, m1, now=None):
        verify_cert(self.s, self.ca_vk, m1["cert"], now)
        body = _lp(b"M1", self.ident, m1["pk_e"], m1["eta_v"])
        if not self.s.sig.verify(m1["cert"].vk, body, m1["sig"]):
            raise HandshakeError("vehicle signature invalid")
        ct, ss = self.s.kem.encaps(m1["pk_e"])
        eta_r = os.urandom(NONCE_LEN)
        th = _transcript(b"TH", self.ident, m1["pk_e"], m1["eta_v"], ct, eta_r)
        sig = self.s.sig.sign(self.sk, _lp(b"M2", th))
        k_enc, k_mac_r, k_mac_v = _derive(ss, m1["eta_v"], eta_r, th)
        self._k_enc, self._k_mac_v, self._th = k_enc, k_mac_v, th
        return {"cert": self.cert, "ct": ct, "eta_r": eta_r, "sig": sig,
                "tag": hmac.new(k_mac_r, b"R" + th, "sha256").digest()}

    def confirm(self, m3):
        if not hmac.compare_digest(hmac.new(self._k_mac_v, b"V" + self._th, "sha256").digest(), m3["tag"]):
            raise HandshakeError("vehicle key confirmation failed")
        self.k_enc = self._k_enc


def seal(k_enc, plaintext, aad=b""):
    n = os.urandom(12)
    return n + AESGCM(k_enc).encrypt(n, plaintext, aad)


def unseal(k_enc, blob, aad=b""):
    return AESGCM(k_enc).decrypt(blob[:12], blob[12:], aad)


def bsm_sign(suite, sk, payload, counter, now=None):
    tau = struct.pack(">d", time.time() if now is None else now)
    body = _lp(b"BSM", payload, tau, struct.pack(">I", counter))
    return {"payload": payload, "tau": tau, "ctr": counter, "sig": suite.sig.sign(sk, body)}


class BsmVerifier:
    def __init__(self, suite):
        self.s = suite
        self.last_ctr = {}

    def accept(self, sender, vk, bsm, now=None):
        now = time.time() if now is None else now
        tau = struct.unpack(">d", bsm["tau"])[0]
        if abs(now - tau) > BSM_WINDOW_S:
            return False
        if bsm["ctr"] <= self.last_ctr.get(sender, -1):
            return False
        body = _lp(b"BSM", bsm["payload"], bsm["tau"], struct.pack(">I", bsm["ctr"]))
        if not self.s.sig.verify(vk, body, bsm["sig"]):
            return False
        self.last_ctr[sender] = bsm["ctr"]
        return True


def setup(key):
    suite = Suite(key)
    ca = Authority(suite)
    cert_v, sk_v = ca.issue(b"OBU-0001")
    cert_r, sk_r = ca.issue(b"RSU-0001")
    veh = Vehicle(suite, ca.vk, cert_v, sk_v)
    rsu = RSU(suite, ca.vk, cert_r, sk_r, b"RSU-0001")
    return suite, ca, veh, rsu


def run_handshake(veh, rsu):
    m1 = veh.msg1(rsu.ident)
    m2 = rsu.msg2(m1)
    m3 = veh.finish(m2)
    rsu.confirm(m3)
    assert veh.k_enc == rsu.k_enc
    return m1, m2, m3
