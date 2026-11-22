"""Library-backed NIST P-256 signatures, RFC6979 and ECDH.

Never use these prototype keys or in-memory HSM substitutes in a real vehicle.
"""
from __future__ import annotations
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils

CURVE = ec.SECP256R1()


def generate_private() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(CURVE)


def public_bytes(key: ec.EllipticCurvePublicKey) -> bytes:
    return key.public_bytes(encoding=serialization.Encoding.X962,
                            format=serialization.PublicFormat.UncompressedPoint)


def load_public(data: bytes) -> ec.EllipticCurvePublicKey:
    return ec.EllipticCurvePublicKey.from_encoded_point(CURVE, data)


def sign(key: ec.EllipticCurvePrivateKey, payload: bytes) -> bytes:
    """Deterministic ECDSA/SHA256 (RFC 6979), P1363 r||s signature, 64 B."""
    der = key.sign(payload, ec.ECDSA(hashes.SHA256(), deterministic_signing=True))
    r, s = utils.decode_dss_signature(der)
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def verify(key: ec.EllipticCurvePublicKey, payload: bytes, raw_sig: bytes) -> bool:
    if len(raw_sig) != 64:
        return False
    r, s = int.from_bytes(raw_sig[:32], "big"), int.from_bytes(raw_sig[32:], "big")
    if not (r > 0 and s > 0):
        return False
    try:
        key.verify(utils.encode_dss_signature(r, s), payload, ec.ECDSA(hashes.SHA256()))
        return True
    except (InvalidSignature, ValueError):
        return False


def ecdh(private: ec.EllipticCurvePrivateKey, public: ec.EllipticCurvePublicKey) -> bytes:
    return private.exchange(ec.ECDH(), public)
