import os
import oqs
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding


class MLKEM768:
    name = "ML-KEM-768"

    def keygen(self):
        k = oqs.KeyEncapsulation("ML-KEM-768")
        pk = k.generate_keypair()
        return pk, k

    def encaps(self, pk):
        k = oqs.KeyEncapsulation("ML-KEM-768")
        ct, ss = k.encap_secret(pk)
        return ct, ss

    def decaps(self, sk, ct):
        return sk.decap_secret(ct)


class ECDHP256:
    name = "ECDH-P256"

    def keygen(self):
        sk = ec.generate_private_key(ec.SECP256R1())
        pk = sk.public_key().public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
        )
        return pk, sk

    def encaps(self, pk):
        eph = ec.generate_private_key(ec.SECP256R1())
        peer = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), pk)
        ss = eph.exchange(ec.ECDH(), peer)
        ct = eph.public_key().public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
        )
        return ct, ss

    def decaps(self, sk, ct):
        peer = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), ct)
        return sk.exchange(ec.ECDH(), peer)


class MLDSA65:
    name = "ML-DSA-65"

    def keygen(self):
        s = oqs.Signature("ML-DSA-65")
        vk = s.generate_keypair()
        return vk, s

    def sign(self, sk, msg):
        return sk.sign(msg)

    def verify(self, vk, msg, sig):
        v = oqs.Signature("ML-DSA-65")
        return bool(v.verify(msg, sig, vk))


class ECDSAP256:
    name = "ECDSA-P256"

    def keygen(self):
        sk = ec.generate_private_key(ec.SECP256R1())
        vk = sk.public_key().public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
        )
        return vk, sk

    def sign(self, sk, msg):
        return sk.sign(msg, ec.ECDSA(hashes.SHA256()))

    def verify(self, vk, msg, sig):
        pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), vk)
        try:
            pub.verify(sig, msg, ec.ECDSA(hashes.SHA256()))
            return True
        except Exception:
            return False


class RSA3072PSS:
    name = "RSA-3072-PSS"

    def keygen(self):
        sk = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        vk = sk.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return vk, sk

    def _pad(self):
        return padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32)

    def sign(self, sk, msg):
        return sk.sign(msg, self._pad(), hashes.SHA256())

    def verify(self, vk, msg, sig):
        pub = serialization.load_der_public_key(vk)
        try:
            pub.verify(sig, msg, self._pad(), hashes.SHA256())
            return True
        except Exception:
            return False


class RSA3072OAEP:
    name = "RSA-3072-OAEP"

    def keygen(self):
        sk = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        pk = sk.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return pk, sk

    def _pad(self):
        return padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)

    def encaps(self, pk):
        ss = os.urandom(32)
        pub = serialization.load_der_public_key(pk)
        return pub.encrypt(ss, self._pad()), ss

    def decaps(self, sk, ct):
        return sk.decrypt(ct, self._pad())


SUITES = {
    "qshield": (MLKEM768, MLDSA65),
    "ecdhe-ecdsa": (ECDHP256, ECDSAP256),
    "ecdhe-rsa3072": (ECDHP256, RSA3072PSS),
}
