"""Algorithm 3: convex contextual risk + mandatory security floors."""
from __future__ import annotations
from dataclasses import dataclass

from ..config import Settings, clamp
from ..models import Context, Message
from ..trust.trust_engine import TrustState


@dataclass
class PolicyResult:
    risk: float
    level: int
    criticality: float
    context_stress: float


class RiskPolicy:
    def __init__(self, config: Settings, *, cold_start: bool = True,
                 hysteresis: bool = True) -> None:
        self.p = config
        self.cold_start = cold_start
        self.hysteresis = hysteresis

    @staticmethod
    def criticality(m: Message) -> float:
        if m.kind == "EMERGENCY":
            return 0.9
        if m.kind == "DENM":
            return 0.6
        return 0.3

    def context_stress(self, c: Context) -> float:
        density = clamp(c.vehicle_count/self.p.reference_density_vehicles)
        channel = clamp(c.channel_busy)
        unavailability = float(not c.rsu_reachable)
        alerts = clamp(c.recent_alerts / self.p.alert_normalization_count)
        return (density + channel + unavailability + alerts) / 4.0

    def evaluate(self, m: Message, s: TrustState, c: Context) -> PolicyResult:
        wc = self.criticality(m)
        stress = self.context_stress(c)
        tw, cw, sw = self.p.risk_weights
        risk = clamp(tw*(1-s.trust)+cw*wc+sw*stress)
        t1,t2,t3 = self.p.risk_thresholds
        level = 0 if risk < t1 else 1 if risk < t2 else 2 if risk < t3 else 3
        if s.trust < self.p.min_trust or s.quarantined:
            level = 3
        # Safety-critical conservative guard: the paper's trust-only risk score
        # can still map a single grossly impossible signed packet to L0.
        # Current-message positive anomaly evidence therefore forces L2.
        if (s.last_score < self.p.anomaly_threshold
            or s.last_features.get("plaus",1.0) is not None and s.last_features.get("plaus",1.0) < 0.3
            or s.last_features.get("cons",1.0) is not None and s.last_features.get("cons",1.0) < 0.3):
            level = max(level, 2)
        if m.kind in ("DENM","EMERGENCY") and c.corroborators < 2:
            level = max(level, 2)
        if (self.cold_start and s.seen <= self.p.probation_messages) or s.probation:
            level = max(level, 1)
        if wc >= 0.9:
            level = max(level, 2)
        # Lower strictness by max one level *per observation window*. Raising is immediate.
        if self.hysteresis and level < s.last_level:
            if s.seen - s.last_level_reduction_at < self.p.hysteresis_messages:
                level = s.last_level
            else:
                level = max(level, s.last_level-1)
                s.last_level_reduction_at = s.seen
        s.last_level = level
        return PolicyResult(risk, level, wc, stress)
