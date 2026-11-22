
from __future__ import annotations
from time import perf_counter_ns
from typing import Mapping
import secrets
from dataclasses import replace

from .config import Settings
from .models import Message, Context, Decision
from .crypto.auth import CryptoGate
from .crypto.certificates import CertificateAuthority, Identity
from .crypto.ecc import load_public, verify
from .models import canonical, unb64
from .risk.policy import RiskPolicy
from .trust.trust_engine import TrustEngine
from .rsu.rsu import RoadsideUnit

METHODS = ("riskauthnet", "crypto_only", "static_strict", "multi_tier", "dynamic_trust")
ABLATIONS = ("no_context", "no_neighbor", "no_channel", "no_cold_start",
             "no_penalty_recovery", "no_hysteresis", "no_rsu_limits")


def _safe_size(message: Message) -> int:
    try:
        return len(message.to_bytes())
    except (TypeError,ValueError,OverflowError):
        return 0


class Receiver:
    def __init__(self, authority: CertificateAuthority, config: Settings | None = None,
                 *, method: str = "riskauthnet", identities: Mapping[str,Identity] | None = None,
                 rsu: RoadsideUnit | None = None,
                 ablations: frozenset[str] = frozenset()) -> None:
        if method not in METHODS:
            raise ValueError(f"unknown baseline: {method}")
        if not ablations.issubset(ABLATIONS):
            raise ValueError(f"unknown ablations: {sorted(ablations-set(ABLATIONS))}")
        self.ablations=ablations
        self.p = config or Settings()
        self.method = method
        self.gate = CryptoGate(authority, self.p)
        self.trust = TrustEngine(self.p,
                         channel_aware="no_channel" not in ablations,
                         penalty_recovery="no_penalty_recovery" not in ablations)
        self.risk = RiskPolicy(self.p,cold_start="no_cold_start" not in ablations,
                               hysteresis="no_hysteresis" not in ablations)
        self.rsu = rsu or RoadsideUnit(authority, self.p)
        if "no_rsu_limits" in ablations:
            self.rsu.limiter.enabled=False
        self.identities = identities or {}
        self.baseline_snapshot: dict[str,float] = {}
        self.received_notice_ids: set[str] = set()

    def refresh_crl(self) -> bool:
        return self.gate.load_crl(self.gate.authority.crl_update())

    def accept_rsu_notice(self, notice: dict, now_ms: int) -> bool:
        """Authenticated, fresh RSU misbehaviour notice forces immediate quarantine."""
        try:
            fields=("target_pseudonym","issued_ms","rsu","reason","notice_id")
            body={k:notice[k] for k in fields}
            if (body["notice_id"] in self.received_notice_ids
                or abs(now_ms-int(body["issued_ms"]))>5000
                or not isinstance(body["target_pseudonym"],str)):
                return False
            cert=self.gate.authority.rsu_certificate(body["rsu"])
            if (cert is None or cert.serial in self.gate.revoked
                or not self.gate.authority.verify_certificate(cert,now_ms)):
                return False
            pub=load_public(unb64(cert.public_key_b64))
            if not verify(pub,canonical(body),unb64(notice["signature_b64"])):
                return False
            self.trust.force_quarantine(body["target_pseudonym"])
            self.received_notice_ids.add(body["notice_id"])
            if len(self.received_notice_ids)>self.p.max_active_senders*10:
                self.received_notice_ids.clear() # bounded-memory notice anti-replay; TTL provides freshness
            return True
        except (KeyError,ValueError,TypeError,OverflowError):
            return False

    def process(self, m: Message, now_ms: int, c: Context | None = None,
                *, trust_token: dict | None = None) -> Decision:
        c = c or Context()
        start = perf_counter_ns()
        def out(action: str, status: str, level: int, reason: str,
                trust: float | None = None, score: float | None = None,
                risk: float | None = None, features: dict | None = None) -> Decision:
            return Decision(pseudonym=m.pseudonym, seq=m.seq, action=action,
                            final_status=status, level=level, reason=reason,
                            trust=trust,
                            confidence=(min(1.0,self.trust.states[m.pseudonym].seen/self.p.window_size)
                                        if trust is not None and m.pseudonym in self.trust.states else None),
                            behavior_score=score, risk=risk,
                            processing_ms=(perf_counter_ns()-start)/1e6,
                            arrival_ms=now_ms, wire_bytes=_safe_size(m),
                            components={k:float(v) for k,v in (features or {}).items()
                                        if v is not None})
        auth = self.gate.authenticate(m, now_ms, full_chain=self.method=="static_strict")
        if not auth.valid:
            if auth.override:
                try:
                    self.trust.force_quarantine(m.pseudonym)
                except OverflowError:
                    return out("REJECT","REJECT",3,"STATE_CAPACITY")
                if c.rsu_reachable:
                    verdict = self.rsu.escalate(m, now_ms, 0.0, 0.0, c,
                           identity=self.identities.get(m.pseudonym), override=auth.override)
                    return out("ESCALATE","REJECT",3, f"{auth.override};{verdict.reason}",0.0,0.0,1.0)
                return out("ESCALATE","REJECT",3,auth.override+";RSU_UNAVAILABLE",0.0,0.0,1.0)
            return out("REJECT","REJECT",0,auth.reason)
        if self.method == "crypto_only":
            return out("ACCEPT","ACCEPT",0,"CRYPTO_ONLY")
        if trust_token is not None and m.pseudonym not in self.trust.states:
            # A trusted RSU-signed, pseudonym-bound token may initialise confidence;
            # it never exempts the current packet from cryptographic verification.
            inherited=self.rsu.verify_token(trust_token,auth.certificate,now_ms,m.pseudonym)
            if inherited is not None:
                try:
                    self.trust.get(m.pseudonym,token_trust=inherited)
                except OverflowError:
                    return out("REJECT","REJECT",3,"STATE_CAPACITY")
        feature_context = replace(c,neighbor_speeds=()) if "no_neighbor" in self.ablations else c
        try:
            state, score, features=self.trust.update(m,feature_context)
        except OverflowError:
            return out("REJECT","REJECT",3,"STATE_CAPACITY")
        if self.method == "static_strict":
            if score < self.p.anomaly_threshold or float(features["plaus"]) < 0.5:
                return out("REJECT","REJECT",2,"STATIC_STRICT_ANOMALY",state.trust,score,None,features)
            if m.kind in ("DENM","EMERGENCY") and c.corroborators < 2:
                return out("MONITOR","HOLD",2,"NO_CORROBORATION",state.trust,score,None,features)
            return out("ACCEPT_MONITOR","ACCEPT_MONITOR",2,"STATIC_STRICT",state.trust,score,None,features)
        if self.method in ("multi_tier","dynamic_trust"):
            # Transparent *approximations*: periodic trust snapshot every W messages.
            if m.pseudonym not in self.baseline_snapshot:
                self.baseline_snapshot[m.pseudonym]=self.p.initial_trust
            if state.seen % self.p.window_size == 0:
                self.baseline_snapshot[m.pseudonym]=state.trust
            snapshot=self.baseline_snapshot[m.pseudonym]
            threshold = 0.5 if self.method == "multi_tier" else 0.6
            if snapshot < threshold or (score < 0.3 and self.method=="multi_tier"):
                return out("REJECT","REJECT",2,"PERIODIC_TRUST_REJECT",snapshot,score,None,features)
            return out("ACCEPT_MONITOR","ACCEPT_MONITOR",1,"PERIODIC_TRUST_ACCEPT",snapshot,score,None,features)
        risk_context = (replace(c,vehicle_count=0,channel_busy=0,rsu_reachable=True,recent_alerts=0)
                        if "no_context" in self.ablations else c)
        policy=self.risk.evaluate(m,state,risk_context)
        level=policy.level
        if level == 0:
            return out("ACCEPT","ACCEPT",level,"RISK_LOW",state.trust,score,policy.risk,features)
        # L1 plausibility checks must have an operational effect, not just be reported.
        if level == 1:
            if float(features["plaus"]) < 0.5:
                return out("REJECT","REJECT",level,"L1_KINEMATIC_FAILURE",state.trust,score,policy.risk,features)
            return out("ACCEPT_MONITOR","ACCEPT_MONITOR",level,"L1_MONITOR",state.trust,score,policy.risk,features)
        if level == 2:
            if not self.gate.check_chain(auth.certificate, now_ms):
                return out("REJECT","REJECT",level,"L2_CERT_CHAIN_FAILURE",state.trust,score,policy.risk,features)
            if (score < self.p.anomaly_threshold or float(features["plaus"]) < 0.3
                    or float(features["cons"]) < 0.3):
                return out("REJECT","REJECT",level,"L2_ANOMALY",state.trust,score,policy.risk,features)
            if m.kind in ("DENM","EMERGENCY") and c.corroborators < 2:
                return out("MONITOR","HOLD",level,"L2_NO_CORROBORATION",state.trust,score,policy.risk,features)
            return out("ACCEPT_MONITOR","ACCEPT_MONITOR",level,"L2_MONITOR",state.trust,score,policy.risk,features)
        # L3 never disseminates locally while waiting on an RSU.
        if not c.rsu_reachable:
            return out("ESCALATE","HOLD",3,"RSU_UNAVAILABLE",state.trust,score,policy.risk,features)
        verdict=self.rsu.escalate(m,now_ms,state.trust,score,c,
                                 identity=self.identities.get(m.pseudonym))
        if verdict.status == "HOLD" and verdict.reason in ("PSEUDONYM_BUDGET","RSU_OVERLOAD"):
            # Fail closed for low trust or positive anomaly evidence, otherwise quarantine.
            if score < self.p.anomaly_threshold or state.trust < self.p.min_trust:
                return out("ESCALATE","REJECT",3,verdict.reason+";L2_FALLBACK",state.trust,score,policy.risk,features)
        return out("ESCALATE",verdict.status,3,verdict.reason,state.trust,score,policy.risk,features)
