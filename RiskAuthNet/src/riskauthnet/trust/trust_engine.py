"""Algorithm 2: bounded sender history, cold-start, penalties and slow recovery."""
from __future__ import annotations
from collections import deque
from dataclasses import dataclass, field

from ..config import Settings, clamp
from ..models import Context, Message
from .features import compute_features, weighted_score


@dataclass
class TrustState:
    trust: float
    seen: int = 0
    history: deque[Message] = field(default_factory=deque)
    consecutive_anomalies: int = 0
    clean_streak: int = 0
    probation: bool = False
    quarantined: bool = False
    last_level: int = 0
    last_level_reduction_at: int = 0
    last_score: float = 1.0
    last_features: dict[str, float | None] = field(default_factory=dict)


class TrustEngine:
    def __init__(self, config: Settings, *, channel_aware: bool = True,
                 penalty_recovery: bool = True) -> None:
        self.config = config
        self.channel_aware = channel_aware
        self.penalty_recovery = penalty_recovery
        self.states: dict[str, TrustState] = {}

    def get(self, pseudonym: str, *, token_trust: float | None = None) -> TrustState:
        state = self.states.get(pseudonym)
        if state is None:
            if len(self.states) >= self.config.max_active_senders:
                raise OverflowError("sender-state cap exceeded; fail closed")
            initial = self.config.initial_trust if token_trust is None else clamp(token_trust)
            state = TrustState(initial, history=deque(maxlen=self.config.window_size))
            self.states[pseudonym] = state
        return state

    def force_quarantine(self, pseudonym: str) -> TrustState:
        s = self.get(pseudonym)
        s.trust, s.last_level, s.quarantined, s.probation = 0.0, 3, True, True
        return s

    def update(self, m: Message, context: Context) -> tuple[TrustState, float, dict[str,float|None]]:
        s = self.get(m.pseudonym)
        if s.quarantined:
            return s, 0.0, {"rate":0.,"time":0.,"plaus":0.,"cons":0.,"neigh":None}
        f = compute_features(s.history, m, context, self.config,
                             channel_aware=self.channel_aware)
        score = weighted_score(f, self.config)
        s.seen += 1
        s.history.append(m)
        anomaly = score < self.config.anomaly_threshold
        previous = s.trust
        updated = clamp(self.config.trust_lambda*previous+(1-self.config.trust_lambda)*score)
        if not self.penalty_recovery:
            s.trust=updated
            s.last_score, s.last_features=score,f
            return s,score,f
        if anomaly:
            s.consecutive_anomalies += 1
            s.clean_streak = 0
            # On-off defence: a probationary sender never rapidly recovers by EWMA.
            s.trust = min(updated, previous)
            if s.consecutive_anomalies >= 2:
                s.trust = clamp(s.trust - self.config.anomaly_penalty)
                s.probation = True
        else:
            s.consecutive_anomalies = 0
            if s.probation:
                s.clean_streak += 1
                if s.clean_streak >= self.config.window_size:
                    s.trust = clamp(previous + self.config.trust_recovery)
                    s.clean_streak = 0
                if s.trust >= 0.783:
                    s.probation = False
            else:
                s.trust = updated
                s.clean_streak += 1
        s.last_score, s.last_features = score, f
        return s, score, f
