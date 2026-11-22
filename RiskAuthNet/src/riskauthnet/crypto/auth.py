"""Algorithm 1, authenticated signer cache and replay/nonce overrides."""
from __future__ import annotations
from collections import OrderedDict
from dataclasses import dataclass
import math
from typing import Any

from ..config import Settings
from ..models import Certificate, Message, unb64
from .certificates import CertificateAuthority, verify_crl_update
from .ecc import load_public, verify


@dataclass
class AuthResult:
    valid: bool
    reason: str
    certificate: Certificate | None = None
    override: str | None = None


class CryptoGate:
    def __init__(self, authority: CertificateAuthority, config: Settings) -> None:
        self.authority = authority
        self.config = config
        self.cert_cache: dict[tuple[str, str], Certificate] = {}
        self.highest_seq: dict[str, int] = {}
        self.recent_seqs: dict[str, OrderedDict[int,str]] = {}
        self.recent_r: dict[str, OrderedDict[int,str]] = {}
        self.revoked: set[str] = set()
        self.crl_version: int = -1
        self.load_crl(authority.crl_update())

    def load_crl(self, update: dict[str, Any]) -> bool:
        if not verify_crl_update(update, self.authority.public_key, self.authority.issuer):
            return False
        if int(update["version"]) < self.crl_version:
            return False
        self.crl_version = int(update["version"])
        self.revoked = set(update["revoked_serials"])
        return True

    def check_chain(self, cert: Certificate, now_ms: int) -> bool:
        return self.authority.verify_certificate(cert, now_ms) and cert.serial not in self.revoked

    def _resolve_certificate(self, m: Message, now_ms: int) -> Certificate | None:
        if len(m.cert_digest) != 16:
            return None
        key = (m.pseudonym, m.cert_digest)
        cert = self.cert_cache.get(key)
        if m.certificate is not None:
            offered = m.certificate
            if offered.pseudonym != m.pseudonym or offered.digest != m.cert_digest:
                return None
            # No unverified certificate can populate a trusted cache.
            if cert is None and self.authority.verify_certificate(offered, now_ms):
                if len(self.cert_cache) >= self.config.max_active_senders:
                    return None  # fail closed against pseudonym churn
                self.cert_cache[key] = offered
                cert = offered
            elif cert is not None and cert != offered:
                return None
        if cert is not None and not (cert.not_before_ms <= now_ms < cert.not_after_ms):
            return None
        return cert

    def authenticate(self, m: Message, now_ms: int, *, full_chain: bool = False) -> AuthResult:
        try:
            malformed = (not isinstance(m.seq,int) or not isinstance(m.timestamp_ms,int)
                    or m.seq < 0 or m.timestamp_ms < 0
                    or m.kind not in ("BSM","CAM","DENM","EMERGENCY")
                    or not all(isinstance(x,(int,float)) and math.isfinite(x)
                               for x in (m.x,m.y,m.speed,m.heading))
                    or not isinstance(m.pseudonym,str) or len(m.pseudonym)>128
                    or not isinstance(m.event_code,str) or len(m.event_code)>64)
        except (TypeError,ValueError):
            malformed = True
        if malformed:
            return AuthResult(False,"MALFORMED")
        if abs(now_ms - m.timestamp_ms) > self.config.freshness_ms:
            return AuthResult(False, "STALE_OR_FUTURE")
        cert = self._resolve_certificate(m, now_ms)
        if cert is None:
            return AuthResult(False, "UNKNOWN_OR_INVALID_CERT")
        if full_chain and not self.authority.verify_certificate(cert, now_ms):
            return AuthResult(False, "CERT_CHAIN_FAILURE", cert)
        try:
            raw = unb64(m.signature_b64)
            pub = load_public(unb64(cert.public_key_b64))
            if not verify(pub, m.signing_bytes(), raw):
                return AuthResult(False, "INVALID_SIGNATURE", cert)
        except (ValueError, TypeError):
            return AuthResult(False, "INVALID_SIGNATURE", cert)
        if cert.serial in self.revoked:
            return AuthResult(False, "REVOKED", cert, override="CRL_HIT")
        r = int.from_bytes(raw[:32], "big")
        fp = m.fingerprint
        history_r = self.recent_r.setdefault(m.pseudonym, OrderedDict())
        history_seq = self.recent_seqs.setdefault(m.pseudonym, OrderedDict())
        if r in history_r and history_r[r] != fp:
            return AuthResult(False, "REUSED_ECDSA_NONCE", cert, override="NONCE_REUSE")
        if m.seq in history_seq and history_seq[m.seq] != fp:
            return AuthResult(False, "SEQUENCE_CONFLICT", cert, override="CONFLICTING_SEQUENCE")
        if m.seq <= self.highest_seq.get(m.pseudonym, -1):
            return AuthResult(False, "REPLAY", cert)
        # Commit state only after full signature+certificate+freshness validation.
        self.highest_seq[m.pseudonym] = m.seq
        history_seq[m.seq] = fp
        history_r[r] = fp
        while len(history_seq) > 32:
            history_seq.popitem(last=False)
        while len(history_r) > 32:
            history_r.popitem(last=False)
        return AuthResult(True, "AUTHENTICATED", cert)
