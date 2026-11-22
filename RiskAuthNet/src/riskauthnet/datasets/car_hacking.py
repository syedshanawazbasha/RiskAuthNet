"""Streaming HCRL Car-Hacking timing profiles by arbitration ID.

Handles the raw no-header, variable-DLC data files and T/R flags.
CAN data are NEVER emitted as V2X packets; only timing profiles are exported.
"""
from __future__ import annotations
from collections import defaultdict
import csv
import json
import statistics
from pathlib import Path
from typing import Iterator,Any


def rows(path: str | Path) -> Iterator[tuple[float,str,bool]]:
    path=Path(path)
    if path.is_dir():
        for f in sorted(path.rglob("*")):
            if f.is_file() and f.suffix.lower() in (".csv",".txt"):
                yield from rows(f)
        return
    is_normal_capture = "normal" in path.name.lower()
    with path.open("r",encoding="utf-8-sig",errors="replace") as f:
        reader=csv.reader(f)
        for cells in reader:
            if len(cells)<3:
                continue
            try:
                t=float(cells[0].strip()); can_id=cells[1].strip().upper()
                dlc=int(cells[2].strip())
            except ValueError:
                continue # header
            if not (0<=dlc<=8 and can_id):
                continue
            flag = cells[-1].strip().upper()
            if flag in ("T","R"):
                malicious=flag=="T"
            elif is_normal_capture:
                malicious=False
            else:
                # A headerless attack file without labels cannot be labelled.
                continue
            yield t,can_id,malicious


def timing_profiles(path: str | Path, *, max_intervals_per_id: int = 20000) -> dict[str,Any]:
    prior:dict[str,float]={}
    normal=defaultdict(list); injected=defaultdict(list)
    frames=0
    for t,can_id,malicious in rows(path):
        frames+=1
        previous=prior.get(can_id)
        prior[can_id]=t
        if previous is None or t<=previous:
            continue
        dt=t-previous
        target=injected[can_id] if malicious else normal[can_id]
        if len(target)<max_intervals_per_id:
            target.append(dt)
    profiles={}
    for can_id in sorted(set(normal)|set(injected)):
        b=normal[can_id]; a=injected[can_id]
        if not b:
            continue
        benign_period=statistics.median(b)
        if benign_period<=0:
            continue
        profiles[can_id]={"normal_samples":len(b),"injected_samples":len(a),
             "normal_median_s":benign_period,
             "normal_jitter_s":statistics.pstdev(b) if len(b)>1 else 0,
             "injected_median_s":statistics.median(a) if a else None,
             "v2x_nominal_period_s":0.100,
             "attack_rate_multiplier":round(benign_period/statistics.median(a),3) if a and statistics.median(a)>0 else None}
    return {"data_source":str(path),"total_frames":frames,"stream_count":len(profiles),
            "role":"offline timing calibration only; NOT a V2X or cryptographic test",
            "profiles":profiles}


def save_profiles(source: str | Path, output: str | Path) -> dict:
    out=timing_profiles(source)
    path=Path(output); path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(out,indent=2),encoding="utf-8")
    return out
