"""Canonical, explicitly serialised message and outcome types."""
from __future__ import annotations
from dataclasses import dataclass, field
import base64
import hashlib
import json
from typing import Any


def canonical(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      allow_nan=False).encode("utf-8")


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def unb64(text: str) -> bytes:
    return base64.b64decode(text, validate=True)


@dataclass(frozen=True)
class Certificate:
    pseudonym: str
    serial: str
    public_key_b64: str
    not_before_ms: int
    not_after_ms: int
    issuer: str = "RiskAuthNet-TA"
    signature_b64: str = ""

    def unsigned(self) -> dict[str, Any]:
        return {"issuer": self.issuer, "not_after_ms": self.not_after_ms,
                "not_before_ms": self.not_before_ms, "pseudonym": self.pseudonym,
                "public_key_b64": self.public_key_b64, "serial": self.serial}

    def to_dict(self) -> dict[str, Any]:
        return {**self.unsigned(), "signature_b64": self.signature_b64}

    @property
    def digest(self) -> str:
        # Eight-byte truncated certificate digest, not an authentication primitive.
        return hashlib.sha256(canonical(self.to_dict())).digest()[:8].hex()

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Certificate":
        return cls(**{k: data[k] for k in cls.__dataclass_fields__ if k in data})


@dataclass
class Message:
    pseudonym: str
    timestamp_ms: int
    seq: int
    kind: str
    x: float
    y: float
    speed: float
    heading: float
    event_code: str = ""
    cert_digest: str = ""
    signature_b64: str = ""
    certificate: Certificate | None = None

    def body(self) -> dict[str, Any]:
        # Include signer identity and certificate digest in the signed transcript.
        return {"cert_digest": self.cert_digest, "event_code": self.event_code,
                "heading": self.heading, "kind": self.kind, "pseudonym": self.pseudonym,
                "seq": self.seq, "speed": self.speed, "timestamp_ms": self.timestamp_ms,
                "x": self.x, "y": self.y}

    def signing_bytes(self) -> bytes:
        return canonical(self.body())

    @property
    def fingerprint(self) -> str:
        return hashlib.sha256(self.signing_bytes()).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        return {**self.body(), "signature_b64": self.signature_b64,
                "certificate": self.certificate.to_dict() if self.certificate else None}

    def to_bytes(self) -> bytes:
        return canonical(self.to_dict())

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Message":
        d = dict(data)
        if d.get("certificate"):
            d["certificate"] = Certificate.from_dict(d["certificate"])
        allowed = cls.__dataclass_fields__
        return cls(**{k:v for k,v in d.items() if k in allowed})

    @classmethod
    def from_bytes(cls, raw: bytes) -> "Message":
        if len(raw) > 65536:
            raise ValueError("oversized message")
        return cls.from_dict(json.loads(raw))


@dataclass
class Context:
    vehicle_count: int = 50
    channel_busy: float = 0.30
    rsu_reachable: bool = True
    recent_alerts: int = 0
    neighbor_pdr: float | None = None
    neighbor_speeds: tuple[float, ...] = ()
    corroborators: int = 0


@dataclass
class Decision:
    pseudonym: str
    seq: int
    action: str
    final_status: str
    level: int
    reason: str
    trust: float | None = None
    confidence: float | None = None
    behavior_score: float | None = None
    risk: float | None = None
    processing_ms: float = 0.0
    arrival_ms: int = 0
    wire_bytes: int = 0
    components: dict[str, float] = field(default_factory=dict)

    @property
    def admitted(self) -> bool:
        return self.final_status in ("ACCEPT", "ACCEPT_MONITOR")

    def to_dict(self) -> dict[str, Any]:
        return {"pseudonym": self.pseudonym, "seq": self.seq, "action": self.action,
                "final_status": self.final_status, "level": self.level,
                "reason": self.reason, "trust": self.trust,
                "confidence": self.confidence, "behavior_score": self.behavior_score, "risk": self.risk,
                "processing_ms": self.processing_ms, "arrival_ms": self.arrival_ms,
                "wire_bytes": self.wire_bytes, **{f"feature_{k}": v for k,v in self.components.items()}}
