"""SUMO FCD -> mobility CSV; replay genuine NS-3 802.11p RX records.

The NS-3 bridge is offline trace coupling, NOT a live Python/ns-3 interface.
Radio losses and receive times originate from the simulator, when it is run.
"""
from __future__ import annotations
import csv
from pathlib import Path
import math
import xml.etree.ElementTree as ET
from collections import defaultdict

from ..crypto.certificates import CertificateAuthority
from ..models import Context
from .synthetic import Trace, TraceEvent


def export_sumo_fcd(xml_path: str | Path, csv_path: str | Path) -> dict:
    target=Path(csv_path);target.parent.mkdir(parents=True,exist_ok=True)
    count=0;latest_ms=0
    with target.open("w",newline="",encoding="utf-8") as out:
        writer=csv.writer(out)
        writer.writerow(("send_ms","vehicle_id","x","y","speed","heading"))
        # Iterative parsing avoids retaining the entire SUMO output in RAM.
        for _,elem in ET.iterparse(xml_path,events=("end",)):
            if elem.tag=="timestep":
                ms=int(round(float(elem.attrib["time"])*1000))
                latest_ms=max(latest_ms,ms)
                for v in elem.findall("vehicle"):
                    heading=math.radians(90-float(v.get("angle","0")))
                    writer.writerow((ms,v.attrib["id"],v.attrib["x"],v.attrib["y"],
                                     v.get("speed","0"),heading))
                    count+=1
                elem.clear()
    return {"input":str(xml_path),"output":str(target),"records":count,
            "last_timestamp_ms":latest_ms,
            "purpose":"SUMO mobility input for ns3/v2x-replay.cc"}


def replay_ns3(mobility: str | Path, receptions: str | Path,
               *, limit: int = 50000, receiver_node: int = 0) -> Trace:
    if limit<1:raise ValueError("limit must be >=1")
    points={}
    with Path(mobility).open(newline="",encoding="utf-8") as f:
        for row in csv.DictReader(f):
            points[(row["vehicle_id"],int(row["send_ms"]))]=row
    ca=CertificateAuthority(); ids={}; events=[]
    with Path(receptions).open(newline="",encoding="utf-8") as f:
        for row in csv.DictReader(f):
            if "receiver_node" in row and int(row["receiver_node"]) != receiver_node:
                continue
            vid=row["vehicle_id"]
            ts=int(row["send_ms"]);rx=int(row["receive_ms"])
            point=points.get((vid,ts))
            if point is None:continue
            if vid not in ids:
                ids[vid]=ca.issue(vid,0,10**12)
            ident=ids[vid]
            # NS-3 schedule sequence is global per vehicle. Receiver log repeats
            # must not inflate a single logical receiver's beacon count.
            message=ident.create_message(timestamp_ms=ts,seq=int(row["seq"]),
                  x=float(point["x"]),y=float(point["y"]),
                  speed=float(point["speed"]),heading=float(point["heading"]),
                  include_certificate=True)
            events.append(TraceEvent(message,rx,False,"none",Context(vehicle_count=len(ids),
                                        channel_busy=0.3,neighbor_pdr=None)))
            if len(events)>=limit:break
    if not events:raise ValueError("No matching NS-3 RX and SUMO mobility records")
    unique={}
    for event in events:
        unique.setdefault((event.message.pseudonym,event.message.seq,event.message.timestamp_ms),event)
    return Trace(sorted(unique.values(),key=lambda e:(e.arrival_ms,e.message.pseudonym)),
                 ca,{i.pseudonym:i for i in ids.values()},0,"ns3-80211p")
