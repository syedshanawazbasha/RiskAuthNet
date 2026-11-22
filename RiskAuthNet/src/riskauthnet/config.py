"""Explicit, validated model parameters (no train/test-dependent defaults)."""
from __future__ import annotations
from dataclasses import dataclass, fields
from pathlib import Path
from typing import Any
import yaml


@dataclass(frozen=True)
class Settings:
    window_size: int = 10
    trust_lambda: float = 0.80
    trust_recovery: float = 0.05
    anomaly_penalty: float = 0.10
    initial_trust: float = 0.60
    min_trust: float = 0.40
    anomaly_threshold: float = 0.50
    risk_thresholds: tuple[float, float, float] = (0.25, 0.50, 0.75)
    risk_weights: tuple[float, float, float] = (0.60, 0.20, 0.20)
    feature_weights: tuple[float, float, float, float, float] = (0.20, 0.15, 0.30, 0.25, 0.10)
    probation_messages: int = 3
    hysteresis_messages: int = 10
    channel_tolerance: float = 0.70
    freshness_ms: int = 100
    pseudonym_lifetime_ms: int = 300000
    session_lifetime_ms: int = 60000
    token_lifetime_ms: int = 30000
    beacon_interval_ms: int = 100
    max_speed_mps: float = 60.0
    max_accel_mps2: float = 9.0
    max_yaw_rate_rad_s: float = 1.0
    position_tolerance_m: float = 5.0
    max_active_senders: int = 5000
    rsu_per_sender_interval_ms: int = 2000
    rsu_max_per_second: int = 400
    rsu_radius_m: int = 300
    reference_density_vehicles: int = 200
    alert_normalization_count: int = 20
    neighbor_speed_tolerance_mps: float = 15.0

    def __post_init__(self) -> None:
        if not (0 < self.trust_lambda < 1 and self.window_size >= 2):
            raise ValueError("trust_lambda must be in (0,1) and window_size >= 2")
        if not (0 < self.trust_recovery <= 1 and 0 <= self.anomaly_penalty <= 1):
            raise ValueError("recovery/penalty outside acceptable bounds")
        if not (0 <= self.initial_trust <= 1 and 0 <= self.min_trust <= 1):
            raise ValueError("trust levels outside [0,1]")
        if any(not (0 <= x <= 1) for x in self.risk_thresholds) or list(self.risk_thresholds) != sorted(self.risk_thresholds):
            raise ValueError("risk thresholds must be ordered and in [0,1]")
        for name, weights in (("risk",self.risk_weights),("feature",self.feature_weights)):
            if any(x < 0 for x in weights) or abs(sum(weights)-1) > 1e-9:
                raise ValueError(f"{name} weights must be nonnegative and sum to 1")
        if min(self.probation_messages, self.hysteresis_messages, self.freshness_ms, self.max_active_senders) <= 0:
            raise ValueError("positive counts/windows required")

    @classmethod
    def load(cls, path: str | Path | None = None, **overrides: Any) -> "Settings":
        raw = yaml.safe_load(Path(path).read_text(encoding="utf-8")) if path else {}
        raw = {**(raw or {}), **overrides}
        allowed = {f.name for f in fields(cls)}
        unknown = set(raw) - allowed
        if unknown:
            raise ValueError(f"Unknown configuration keys: {sorted(unknown)}")
        for k in ("risk_thresholds","risk_weights","feature_weights"):
            if k in raw:
                raw[k] = tuple(map(float, raw[k]))
        return cls(**raw)


def clamp(x: float, low: float = 0.0, high: float = 1.0) -> float:
    return max(low, min(high, x))
