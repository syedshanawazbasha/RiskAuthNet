"""Bounded five-group behavioural features. All normalisers are documented
engineering definitions, as raw normalisation equations are incomplete in the manuscript.
"""
from __future__ import annotations
from collections import deque
import math
import statistics

from ..config import Settings, clamp
from ..models import Context, Message


def angular_delta(a: float, b: float) -> float:
    return abs(math.atan2(math.sin(a-b), math.cos(a-b)))


def compute_features(history: deque[Message], m: Message, c: Context,
                     p: Settings, *, channel_aware: bool = True) -> dict[str, float | None]:
    if not history:
        return {"rate": 1.0, "time": 1.0,
                "plaus": float(0 <= m.speed <= p.max_speed_mps),
                "cons": 1.0, "neigh": None}
    prev = history[-1]
    samples = list(history) + [m]
    times = [v.timestamp_ms for v in samples]
    intervals = [(b-a) / 1000.0 for a,b in zip(times[:-1], times[1:]) if b > a]
    # A gap of two sequence numbers can mean one radio loss, not timing jitter.
    # Divide by the sequence gap to reconstruct per-transmission cadence.
    gaps = [max(1, b.seq-a.seq) for a,b in zip(samples[:-1],samples[1:]) if b.timestamp_ms > a.timestamp_ms]
    normalized_intervals = ([dt/gap for dt,gap in zip(intervals,gaps)]
                            if channel_aware else intervals)
    if not intervals:
        return {"rate": 0.0, "time": 0.0, "plaus": 0.0, "cons": 0.0, "neigh": None}
    nominal_rate = 1000.0 / p.beacon_interval_ms
    received_rate = 1.0 / statistics.mean(intervals)
    # When comparable neighbours have low PDR, penalise only unexplained excess rate.
    effective_nominal = nominal_rate * (c.neighbor_pdr if c.neighbor_pdr is not None else 1.0)
    if received_rate <= effective_nominal * 1.2:
        rate = 1.0 if channel_aware else clamp(received_rate/nominal_rate)
    else:
        rate = clamp((effective_nominal*1.2)/received_rate)
    if len(intervals) == 1:
        timing = 1.0
    else:
        jitter = statistics.pstdev(normalized_intervals)
        timing = clamp(1.0 - jitter / (p.beacon_interval_ms / 1000.0))
    dt = (m.timestamp_ms - prev.timestamp_ms) / 1000.0
    if dt <= 0:
        plaus = cons = 0.0
    else:
        accel = abs(m.speed - prev.speed) / dt
        yaw_rate = angular_delta(m.heading, prev.heading)/dt
        plaus = 1.0
        if not (0 <= m.speed <= p.max_speed_mps):
            plaus *= 0.0
        if accel > p.max_accel_mps2:
            plaus *= max(0.0, p.max_accel_mps2 / max(accel, 1e-9))
        if yaw_rate > p.max_yaw_rate_rad_s and prev.speed > 3.0:
            plaus *= max(0.0, p.max_yaw_rate_rad_s / yaw_rate)
        # A bicycle-motion first-order predictor. Position residual > tolerance is anomalous.
        predicted_x = prev.x + prev.speed * dt * math.cos(prev.heading)
        predicted_y = prev.y + prev.speed * dt * math.sin(prev.heading)
        residual = math.hypot(m.x - predicted_x, m.y - predicted_y)
        cons = math.exp(-max(0.0, residual-p.position_tolerance_m) / 15.0)
    if c.neighbor_speeds and len(c.neighbor_speeds) >= 2:
        deviation = abs(m.speed - statistics.median(c.neighbor_speeds))
        neighbor = math.exp(-max(0.0, deviation-p.neighbor_speed_tolerance_mps)/15.0)
    else:
        neighbor = None
    # Only flag selective shortfall when comparable neighbours are known and delivery
    # ratio is substantially below theirs (manuscript's eta_min=0.7).
    if channel_aware and c.neighbor_pdr is not None and c.neighbor_pdr > 0:
        expected_tx = max(1, m.seq - samples[0].seq + 1)
        sender_pdr = min(1.0, len(samples)/expected_tx)
        if sender_pdr/c.neighbor_pdr < p.channel_tolerance:
            rate = min(rate, 0.4)
    return {"rate": clamp(rate), "time": clamp(timing),
            "plaus": clamp(plaus), "cons": clamp(cons),
            "neigh": None if neighbor is None else clamp(neighbor)}


def weighted_score(features: dict[str, float | None], p: Settings) -> float:
    names = ("rate","time","plaus","cons","neigh")
    available = [(p.feature_weights[i],float(features[k])) for i,k in enumerate(names)
                 if features[k] is not None]
    denom = sum(w for w,v in available)
    return clamp(sum(w*v for w,v in available) / denom)
