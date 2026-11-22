"""Research-grade pseudonym certificate authority and signed revocation deltas."""
from __future__ import annotations
from dataclasses import dataclass
import secrets
from typing import Any

from ..models import Certificate, Message, b64, unb64, canonical
from .ecc import generate_private, public_bytes, load_public, sign, verify


@dataclass
class Identity:
    private_key: Any
    certificate: Certificate
    real_id: str = ""  # Local test fixture only; never transmitted on the V2X wire.
    next_sequence: int = 1

    @property
    def pseudonym(self) -> str:
        return self.certificate.pseudonym

    def create_message(self, *, timestamp_ms: int, kind: str = "BSM", x: float = 0.0,
                       y: float = 0.0, speed: float = 0.0, heading: float = 0.0,
                       seq: int | None = None, event_code: str = "",
                       include_certificate: bool = True) -> Message:
        if seq is None:
            seq = self.next_sequence
            self.next_sequence += 1
        else:
            self.next_sequence = max(self.next_sequence, seq + 1)
        message = Message(pseudonym=self.pseudonym, timestamp_ms=int(timestamp_ms),
                          seq=int(seq), kind=kind, x=float(x), y=float(y),
                          speed=float(speed), heading=float(heading),
                          event_code=event_code, cert_digest=self.certificate.digest,
                          certificate=self.certificate if include_certificate else None)
        message.signature_b64 = b64(sign(self.private_key, message.signing_bytes()))
        return message


class CertificateAuthority:
    def __init__(self, issuer: str = "RiskAuthNet-TA") -> None:
        self.issuer = issuer
        self._key = generate_private()
        self._real_id_by_serial: dict[str, str] = {}
        self._cert_by_serial: dict[str, Certificate] = {}
        self._revoked: set[str] = set()
        self._rsu_cert_by_pseudonym: dict[str, Certificate] = {}
        self.crl_version = 0

    @property
    def public_key(self) -> Any:
        return self._key.public_key()

    def issue(self, real_id: str, now_ms: int = 0, lifetime_ms: int = 300000,
              *, is_rsu: bool = False) -> Identity:
        if lifetime_ms <= 0:
            raise ValueError("certificate lifetime must be positive")
        key = generate_private()
        pseudo = ("RSU-" if is_rsu else "P-") + secrets.token_hex(12)
        serial = secrets.token_hex(12)
        unsigned = Certificate(pseudonym=pseudo, serial=serial,
                               public_key_b64=b64(public_bytes(key.public_key())),
                               not_before_ms=int(now_ms),
                               not_after_ms=int(now_ms + lifetime_ms), issuer=self.issuer)
        cert = Certificate(**{**unsigned.unsigned(),
                              "signature_b64": b64(sign(self._key, canonical(unsigned.unsigned())))})
        self._real_id_by_serial[serial] = real_id
        self._cert_by_serial[serial] = cert
        if is_rsu:
            self._rsu_cert_by_pseudonym[pseudo] = cert
        return Identity(key, cert, real_id=real_id)

    def verify_certificate(self, cert: Certificate, now_ms: int) -> bool:
        if not (cert.issuer == self.issuer and cert.not_before_ms <= now_ms < cert.not_after_ms):
            return False
        try:
            load_public(unb64(cert.public_key_b64))
            return verify(self.public_key, canonical(cert.unsigned()), unb64(cert.signature_b64))
        except (ValueError, TypeError):
            return False

    def revoke(self, serial: str) -> None:
        if serial not in self._cert_by_serial:
            raise KeyError("unknown certificate serial")
        self._revoked.add(serial)
        self.crl_version += 1

    def revoke_real_identity(self, real_id: str) -> None:
        for serial, rid in list(self._real_id_by_serial.items()):
            if rid == real_id and serial not in self._revoked:
                self.revoke(serial)

    def crl_update(self) -> dict[str, Any]:
        data = {"issuer": self.issuer, "version": self.crl_version,
                "revoked_serials": sorted(self._revoked)}
        return {**data, "signature_b64": b64(sign(self._key, canonical(data)))}

    def rsu_certificate(self, pseudonym: str) -> Certificate | None:
        """Authenticated public RSU certificate directory; no real identities exposed."""
        return self._rsu_cert_by_pseudonym.get(pseudonym)

    def trace(self, serial: str) -> str | None:
        """TA-only resolution; RSUs and receivers must not call in their decision loop."""
        return self._real_id_by_serial.get(serial)


def verify_crl_update(update: dict[str, Any], ta_public_key: Any,
                      expected_issuer: str = "RiskAuthNet-TA") -> bool:
    try:
        data = {k: update[k] for k in ("issuer", "version", "revoked_serials")}
        return (data["issuer"] == expected_issuer and
                isinstance(data["version"], int) and
                verify(ta_public_key, canonical(data), unb64(update["signature_b64"])))
    except (KeyError, ValueError, TypeError):
        return False
