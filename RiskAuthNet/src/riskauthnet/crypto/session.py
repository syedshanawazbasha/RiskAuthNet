
from __future__ import annotations
from dataclasses import dataclass
import hashlib
import hmac
import secrets

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from ..models import canonical, b64, unb64
from .certificates import CertificateAuthority, Identity
from .ecc import generate_private, ecdh, public_bytes, load_public, sign, verify


@dataclass
class Session:
    pseudonym: str
    rsu_id: str
    key: bytes
    started_ms: int
    expires_ms: int
    transcript_hash: str

    def expired(self, now_ms: int) -> bool:
        return now_ms >= self.expires_ms

    def ratchet(self, now_ms: int) -> None:
        if self.expired(now_ms):
            raise ValueError("must rekey by authenticated ECDH after expiration")
        new = HKDF(algorithm=hashes.SHA256(), length=32, salt=self.key,
                   info=b"RiskAuthNet/session-ratchet/v1"+now_ms.to_bytes(8,"big")).derive(self.key)
        self.key = new


def mutual_handshake(vehicle: Identity, rsu: Identity, authority: CertificateAuthority,
                     now_ms: int, lifetime_ms: int = 60000) -> tuple[Session, Session]:
    """Runs and validates all three handshake messages, returning both session views."""
    if not authority.verify_certificate(vehicle.certificate, now_ms):
        raise ValueError("vehicle certificate invalid")
    if not authority.verify_certificate(rsu.certificate, now_ms):
        raise ValueError("RSU certificate invalid")
    a, b = generate_private(), generate_private()
    A, B = public_bytes(a.public_key()), public_bytes(b.public_key())
    nv, nr = secrets.token_hex(16), secrets.token_hex(16)
    first = canonical({"v":vehicle.pseudonym,"rsu":rsu.pseudonym,"A":b64(A),
                       "ts1":now_ms,"nonce_v":nv})
    signature1 = sign(vehicle.private_key, first)
    if not verify(vehicle.private_key.public_key(), first, signature1):
        raise ValueError("vehicle authentication failed")
    second = canonical({"v":vehicle.pseudonym,"rsu":rsu.pseudonym,"A":b64(A),
                        "B":b64(B),"ts1":now_ms,"ts2":now_ms,
                        "nonce_v":nv,"nonce_r":nr})
    signature2 = sign(rsu.private_key, second)
    if not verify(rsu.private_key.public_key(), second, signature2):
        raise ValueError("RSU authentication failed")
    # Four DH terms are listed in precisely the same order on each side.
    kv = b"".join((ecdh(a, b.public_key()), ecdh(a, rsu.private_key.public_key()),
                   ecdh(vehicle.private_key, b.public_key()),
                   ecdh(vehicle.private_key, rsu.private_key.public_key())))
    kr = b"".join((ecdh(b, a.public_key()), ecdh(rsu.private_key, a.public_key()),
                   ecdh(b, vehicle.private_key.public_key()),
                   ecdh(rsu.private_key, vehicle.private_key.public_key())))
    info = b"RiskAuthNet/V2I/v1/" + second
    salt = hashlib.sha256(first+second+signature1+signature2).digest()
    def derive(material: bytes) -> bytes:
        return HKDF(algorithm=hashes.SHA256(), length=32,
                    salt=salt, info=info).derive(material)
    skv, skr = derive(kv), derive(kr)
    if not hmac.compare_digest(skv, skr):
        raise ValueError("key agreement mismatch")
    cr = hmac.new(skr, b"R"+second, hashlib.sha256).digest()
    if not hmac.compare_digest(cr, hmac.new(skv, b"R"+second, hashlib.sha256).digest()):
        raise ValueError("RSU key confirmation failed")
    cv = hmac.new(skv, b"V"+second+cr, hashlib.sha256).digest()
    if not hmac.compare_digest(cv, hmac.new(skr, b"V"+second+cr, hashlib.sha256).digest()):
        raise ValueError("vehicle key confirmation failed")
    transcript = hashlib.sha256(first+second+cr+cv).hexdigest()
    return (Session(vehicle.pseudonym,rsu.pseudonym,skv,now_ms,now_ms+lifetime_ms,transcript),
            Session(vehicle.pseudonym,rsu.pseudonym,skr,now_ms,now_ms+lifetime_ms,transcript))
