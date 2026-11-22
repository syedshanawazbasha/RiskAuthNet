"""RSU escalation, re-verification and short-lived signed trust tokens."""
from __future__ import annotations
from dataclasses import dataclass
from typing import Any
import secrets

from ..config import Settings
from ..models import Message, Context, canonical, b64, unb64
from ..crypto.auth import CryptoGate
from ..crypto.certificates import CertificateAuthority, Identity
from ..crypto.ecc import sign, verify, load_public
from ..crypto.session import Session, mutual_handshake
from ..models import Certificate
from .load_control import EscalationLimiter


@dataclass
class EscalationVerdict:
    status: str  # ACCEPT_MONITOR / REJECT / HOLD
    reason: str
    token: dict[str,Any] | None = None


class RoadsideUnit:
    def __init__(self, authority: CertificateAuthority, config: Settings, *,
                 identity: Identity | None = None) -> None:
        self.authority = authority
        self.config = config
        self.identity = identity or authority.issue("roadside-unit", 0, 10**12, is_rsu=True)
        self.gate = CryptoGate(authority, config)
        self.limiter = EscalationLimiter(config)
        self.sessions: dict[str, Session] = {}
        self.verdicts: dict[str, EscalationVerdict] = {}

    def ensure_session(self, vehicle: Identity, now_ms: int) -> None:
        session = self.sessions.get(vehicle.pseudonym)
        if session is None or session.expired(now_ms):
            v, r = mutual_handshake(vehicle, self.identity, self.authority,
                                    now_ms, self.config.session_lifetime_ms)
            if v.key != r.key:
                raise RuntimeError("failed mutual session confirmation")
            self.sessions[vehicle.pseudonym]=r

    def issue_token(self, pseudonym: str, trust: float, now_ms: int) -> dict[str,Any]:
        if pseudonym not in self.sessions or self.sessions[pseudonym].expired(now_ms):
            raise PermissionError("no authenticated V2I session")
        quant = 0.9 if trust>=0.8 else 0.7 if trust>=0.6 else 0.5
        content={"pseudonym": pseudonym,"trust_quantized":quant,
                 "issued_ms": now_ms,"expires_ms":now_ms+self.config.token_lifetime_ms,
                 "rsu":self.identity.pseudonym}
        return {**content,"signature_b64":b64(sign(self.identity.private_key,canonical(content)))}

    def verify_token(self, token: dict[str,Any], cert: Certificate, now_ms: int,
                     expected_pseudonym: str) -> float | None:
        try:
            body={k:token[k] for k in ("pseudonym","trust_quantized","issued_ms","expires_ms","rsu")}
            issuer_cert=self.authority.rsu_certificate(str(body["rsu"]))
            if (body["pseudonym"]!=expected_pseudonym or issuer_cert is None
                or not body["issued_ms"] <= now_ms < body["expires_ms"]
                or body["expires_ms"]-body["issued_ms"]>self.config.token_lifetime_ms
                or float(body["trust_quantized"]) not in (0.5,0.7,0.9)
                or not self.authority.verify_certificate(cert,now_ms)
                or not self.authority.verify_certificate(issuer_cert,now_ms)
                or issuer_cert.serial in self.gate.revoked):
                return None
            issuer_key=load_public(unb64(issuer_cert.public_key_b64))
            if verify(issuer_key,canonical(body),unb64(token["signature_b64"])):
                return float(body["trust_quantized"])
        except (TypeError,KeyError,ValueError):
            pass
        return None

    def sign_misbehaviour_notice(self, target_pseudonym: str, now_ms: int,
                                reason: str = "RSU_CONFIRMED_ANOMALY") -> dict[str,Any]:
        body={"target_pseudonym":target_pseudonym,"issued_ms":now_ms,
              "rsu":self.identity.pseudonym,"reason":reason,
              "notice_id":secrets.token_hex(12)}
        return {**body,"signature_b64":b64(sign(self.identity.private_key,canonical(body)))}

    def escalate(self, m: Message, now_ms: int, trust: float, score: float,
                 context: Context, *, identity: Identity | None = None,
                 override: str | None = None) -> EscalationVerdict:
        admission=self.limiter.admit(m,now_ms)
        if not admission.accepted:
            return EscalationVerdict("HOLD",admission.reason)
        if identity is None:
            # Offline trace evaluation can reverify an enrolled pseudonym, but cannot
            # claim an authenticated V2I handshake when no matching identity exists.
            return EscalationVerdict("HOLD","NO_V2I_IDENTITY")
        try:
            self.ensure_session(identity,now_ms)
        except (ValueError,PermissionError):
            return EscalationVerdict("REJECT","V2I_HANDSHAKE_FAILURE")
        # RSU has a separate replay cache from OBU and verifies the complete chain.
        self.gate.load_crl(self.authority.crl_update())
        auth=self.gate.authenticate(m,now_ms,full_chain=True)
        if override:
            return EscalationVerdict("REJECT",f"OVERRIDE_{override}")
        if not auth.valid:
            return EscalationVerdict("REJECT",f"RSU_{auth.reason}")
        if score < self.config.anomaly_threshold or trust < self.config.min_trust:
            return EscalationVerdict("REJECT","CONFIRMED_ANOMALY")
        if m.kind in ("DENM","EMERGENCY") and context.corroborators < 2:
            return EscalationVerdict("HOLD","INSUFFICIENT_EVENT_CORROBORATION")
        token=self.issue_token(m.pseudonym,trust,now_ms)
        return EscalationVerdict("ACCEPT_MONITOR","RSU_VERIFIED",token)
