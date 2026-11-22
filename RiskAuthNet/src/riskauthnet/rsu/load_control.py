"""Token buckets and coalescing bound RSU work under escalation floods."""
from __future__ import annotations
from collections import deque
from dataclasses import dataclass
from ..config import Settings
from ..models import Message


@dataclass
class Admission:
    accepted: bool
    reason: str


class EscalationLimiter:
    def __init__(self, p: Settings) -> None:
        self.p = p
        self.enabled = True
        self.last_by_sender: dict[str,int] = {}
        self.arrivals: deque[int] = deque()
        self.events: dict[tuple[str,int,int,int], int] = {}
        self.admitted = 0
        self.shed = 0
        self.coalesced = 0

    def admit(self, m: Message, now_ms: int) -> Admission:
        if not self.enabled:
            self.admitted+=1
            return Admission(True,"LIMITS_DISABLED")
        last = self.last_by_sender.get(m.pseudonym)
        if last is not None and now_ms-last < self.p.rsu_per_sender_interval_ms:
            self.shed += 1
            return Admission(False, "PSEUDONYM_BUDGET")
        # A correlated event coalesces witnesses, but is never automatically accepted.
        if m.event_code:
            key=(m.event_code, int(m.x//50), int(m.y//50), now_ms//2000)
            if key in self.events:
                self.coalesced += 1
                self.last_by_sender[m.pseudonym] = now_ms
                return Admission(False, "EVENT_COALESCED")
        while self.arrivals and now_ms-self.arrivals[0] >= 1000:
            self.arrivals.popleft()
        if len(self.arrivals) >= self.p.rsu_max_per_second:
            self.shed += 1
            return Admission(False, "RSU_OVERLOAD")
        self.arrivals.append(now_ms)
        self.last_by_sender[m.pseudonym]=now_ms
        if m.event_code:
            self.events[key]=now_ms
            if len(self.events)>5000:
                self.events={k:v for k,v in self.events.items() if now_ms-v<=2000}
        self.admitted += 1
        return Admission(True,"ADMITTED")
