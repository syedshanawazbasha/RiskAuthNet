"""Resign VeReMi events with study-generated credentials for controlled evaluation.

A behavioural dataset label is never treated as an original cryptographic label.
Original simulation sender, not per-pseudonym records, is the enrollment identity.
"""
from __future__ import annotations
import json
from pathlib import Path
from typing import Iterator

from ..config import Settings
from ..models import Context
from ..simulation.synthetic import Trace, TraceEvent
from ..crypto.certificates import CertificateAuthority


def from_prepared(path: str | Path, *, limit: int = 10000,
                  config: Settings | None = None) -> Trace:
    p=config or Settings()
    ca=CertificateAuthority()
    ids={}; records=[]; source_labels={}
    with Path(path).open("r",encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue
            row=json.loads(line)
            if row["malicious"] is None:
                raise ValueError("VeReMi contains missing attack labels; provide ground truth before evaluating")
            records.append(row)
            if len(records)>=limit:
                break
    if not records:
        raise ValueError("prepared file is empty")
    # Timestamp origin zeroed within this particular prepared split. Simulated certificates
    # remain valid for the entire trace, even if the record timestamps are large.
    origin=min(r["send_ms"] for r in records)
    end=max(r["send_ms"] for r in records)-origin
    events=[]
    # Each pseudonym is signed by its own locally generated key.
    for row in sorted(records,key=lambda r:(r["receive_ms"],r["send_ms"],r["pseudonym"])):
        pseudo=str(row["pseudonym"])
        if pseudo not in ids:
            ident=ca.issue(str(row.get("sender",pseudo)),0,end+1000000)
            ids[pseudo]=ident
        ident=ids[pseudo]
        stamp=row["send_ms"]-origin
        recv=max(stamp,row["receive_ms"]-origin)
        # VeReMi message IDs may not be unique per pseudonym across receivers.
        # They are preserved for replay evidence, rather than silently renumbered.
        msg=ident.create_message(timestamp_ms=stamp,seq=int(row["seq"]),
                  kind="BSM",x=row["x"],y=row["y"],speed=row["speed"],
                  heading=row["heading"],include_certificate=True)
        events.append(TraceEvent(msg,recv,bool(row["malicious"]),
                   "veremi_behavioral" if row["malicious"] else "none",
                   Context(vehicle_count=50,channel_busy=0.3,neighbor_pdr=None)))
    # Duplicated observations from multiple receivers are not automatically new
    # authentication attempts for a *single* receiver; deduplicate by sender/seq/time.
    unique={}
    for e in events:
        key=(e.message.pseudonym,e.message.seq,e.message.timestamp_ms)
        unique.setdefault(key,e)
    mapping={v.pseudonym:v for v in ids.values()}
    return Trace(sorted(unique.values(),key=lambda e:(e.arrival_ms,e.message.pseudonym)),
                 ca,mapping,0,"veremi-trace-replay")
