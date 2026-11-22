"""Research metrics with explicit benign/attack semantics (no fabricated values)."""
from __future__ import annotations
from dataclasses import dataclass
import math
import statistics
from typing import Iterable

from ..models import Decision
from ..simulation.synthetic import TraceEvent


@dataclass
class ResultRow:
    name: str
    seed: int
    n: int
    accuracy: float
    far: float
    frr: float
    precision: float
    recall: float
    f1: float
    mean_processing_ms: float
    p95_processing_ms: float
    mean_end_to_end_ms: float
    mean_wire_bytes: float
    escalation_rate: float
    hold_rate: float
    rejected_rate: float
    tp: int
    tn: int
    fp: int
    fn: int

    def to_dict(self) -> dict:
        return vars(self).copy()


def summarize(name: str, seed: int, pairs: Iterable[tuple[TraceEvent,Decision]]) -> ResultRow:
    records=list(pairs)
    if not records:
        raise ValueError("no records to evaluate")
    tp=tn=fp=fn=0
    processing=[]; end_to_end=[]; bytes_wire=[]
    escalations=holds=rejects=0
    for ev, d in records:
        accepted=d.admitted
        if not ev.malicious and accepted: tp+=1
        elif not ev.malicious: fn+=1
        elif ev.malicious and accepted: fp+=1
        else: tn+=1
        escalations+=(d.action=="ESCALATE")
        holds+=(d.final_status=="HOLD")
        rejects+=(d.final_status=="REJECT")
        processing.append(d.processing_ms)
        end_to_end.append(max(0,ev.arrival_ms-ev.message.timestamp_ms)+d.processing_ms)
        bytes_wire.append(d.wire_bytes)
    n=len(records)
    safe=lambda a,b: a/b if b else 0.0
    precision=safe(tp,tp+fp)
    recall=safe(tp,tp+fn)
    f1=safe(2*precision*recall,precision+recall)
    ordered=sorted(processing)
    p95=ordered[max(0,math.ceil(0.95*n)-1)]
    return ResultRow(name,seed,n,safe(tp+tn,n),safe(fp,fp+tn),safe(fn,fn+tp),
                     precision,recall,f1,statistics.mean(processing),p95,
                     statistics.mean(end_to_end),statistics.mean(bytes_wire),
                     safe(escalations,n),safe(holds,n),safe(rejects,n),tp,tn,fp,fn)
