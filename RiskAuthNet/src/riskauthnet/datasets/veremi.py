"""Stream VeReMi/VeReMi Extension receiver JSON logs, including ZIP archives.

These records DO NOT contain ECDSA signatures, and labels may be absent. The
converter never infers 'benign' from absence of an explicit annotation.
"""
from __future__ import annotations
import io
import json
import math
from pathlib import Path
import random
import csv
import zipfile
from typing import Iterator, Any


def _documents(path: Path) -> Iterator[tuple[str, Iterator[str]]]:
    paths = list(path.rglob("*")) if path.is_dir() else [path]
    for item in sorted(paths):
        if not item.is_file():
            continue
        if item.suffix.lower()==".zip":
            with zipfile.ZipFile(item) as z:
                for member in z.namelist():
                    if member.lower().endswith((".json",".jsonl",".log")) and not member.endswith("/"):
                        with z.open(member) as raw:
                            for line in io.TextIOWrapper(raw, encoding="utf-8-sig",errors="replace"):
                                yield f"{item.name}/{member}",line
        elif item.suffix.lower() in (".json",".jsonl",".log"):
            with item.open("r",encoding="utf-8-sig",errors="replace") as f:
                for line in f:
                    yield item.as_posix(),line


def record_to_event(record: dict[str,Any], source: str) -> dict[str,Any] | None:
    # VeReMi Extension type=3 is a received beacon; type=2 is ego GPS.
    if record.get("type",3) not in (3,"3"):
        return None
    if "senderPseudo" not in record and "pseudonym" not in record:
        return None
    if "sendTime" not in record and "timestamp_ms" not in record:
        return None
    p=record.get("pos", record.get("position"))
    if p is None:
        return None
    if isinstance(p,dict):
        x,y=p.get("x"),p.get("y")
    elif isinstance(p,(tuple,list)) and len(p)>=2:
        x,y=p[:2]
    else:
        return None
    if x is None or y is None:
        return None
    velocity=record.get("spd",record.get("speed",0.0))
    if isinstance(velocity,(tuple,list)):
        speed=math.hypot(float(velocity[0]),float(velocity[1]))
        heading=math.atan2(float(velocity[1]),float(velocity[0]))
    else:
        speed=float(velocity)
        heading=math.radians(float(record["hed"])) if "hed" in record else float(record.get("heading",0))
    send_ms = int(round(float(record["sendTime"])*1000)) if "sendTime" in record else int(record["timestamp_ms"])
    receive_ms = int(round(float(record.get("rcvTime",record.get("sendTime",0)))*1000)) if "rcvTime" in record else send_ms
    explicit = next((record[k] for k in ("isMalicious", "isAttack", "attackLabel", "misbehaviorLabel", "attacker", "attackerType", "misbehaviorType") if k in record),None)
    if explicit is None:
        label=None
    elif isinstance(explicit,str):
        label=explicit.lower() not in ("0","false","normal","benign","none")
    else:
        label=bool(explicit)
    # Group by whole simulation archive/run, never shuffle individual receivers/packets.
    parts=source.replace("\\","/").split("/")
    group = parts[0] if source.lower().endswith(".zip") else (parts[-2] if len(parts)>1 else source)
    if ".zip/" in source:
        group=source.split(".zip/")[0]+".zip"
    return {"source":source,"run_id":group,
            "sender":str(record.get("sender","")),
            "pseudonym":str(record.get("senderPseudo",record.get("pseudonym"))),
            "send_ms":send_ms,"receive_ms":receive_ms,
            "seq":int(record.get("messageID",record.get("seq",0))),
            "x":float(x),"y":float(y),"speed":float(speed),
            "heading":heading,"kind":str(record.get("kind","BSM")),
            "malicious":label}


def load_veremi(path: str | Path, *, limit: int | None = None) -> Iterator[dict[str,Any]]:
    count=0
    for source,line in _documents(Path(path)):
        if not line.lstrip().startswith("{"):
            continue
        try:
            data=json.loads(line)
            item=record_to_event(data,source)
            if item is None:
                continue
            yield item
            count+=1
            if limit is not None and count>=limit:
                return
        except (TypeError,ValueError,KeyError,IndexError):
            continue


def split_by_run(records: list[dict[str,Any]], *, calibration_fraction: float = 0.7,
                 seed: int = 42) -> tuple[list[dict],list[dict]]:
    runs=sorted({r["run_id"] for r in records})
    if len(runs)<2:
        raise ValueError("At least two distinct simulation runs are required for leak-free split")
    if not 0 < calibration_fraction < 1:
        raise ValueError("split fraction must be between 0 and 1")
    random.Random(seed).shuffle(runs)
    n=max(1,min(len(runs)-1,round(len(runs)*calibration_fraction)))
    calibration=set(runs[:n])
    return ([r for r in records if r["run_id"] in calibration],
            [r for r in records if r["run_id"] not in calibration])


def _read_annotations(path: str | Path | None) -> dict[tuple[str,str,int],bool]:
    """Optional explicit GT CSV: run_id,pseudonym,seq,malicious (never a feature)."""
    if path is None:
        return {}
    out={}
    with Path(path).open(newline="",encoding="utf-8") as f:
        reader=csv.DictReader(f)
        for row in reader:
            key=(row["run_id"],row["pseudonym"],int(row["seq"]))
            out[key]=row["malicious"].strip().lower() in ("1","true","attack","malicious")
    return out


def prepare_veremi(source: str | Path, output: str | Path, *, seed: int = 42,
                   limit: int | None = None, labels_csv: str | Path | None = None) -> dict[str,Any]:
    """Two-pass streaming split; bounded memory even for 20 GB source archives.

    Archives are conservative run groups. If multiple archives are derived from
    the same original simulation run, users must provide a shared run mapping.
    """
    groups=set(); count=0
    for rec in load_veremi(source,limit=limit):
        groups.add(rec["run_id"]);count+=1
    if count==0:
        raise ValueError("no VeReMi BSM receiver messages found; check source schema")
    if len(groups)<2:
        raise ValueError("At least two independent simulation runs required (no record-level leakage)")
    shuffled=sorted(groups);random.Random(seed).shuffle(shuffled)
    n=max(1,min(len(shuffled)-1,round(len(shuffled)*0.7)))
    calibration=set(shuffled[:n])
    out=Path(output);out.mkdir(parents=True,exist_ok=True)
    annotations=_read_annotations(labels_csv)
    known=0;counts={"calibration":0,"test":0}
    with (out/"calibration.jsonl").open("w",encoding="utf-8") as cf,\
         (out/"test.jsonl").open("w",encoding="utf-8") as tf:
        for rec in load_veremi(source,limit=limit):
            key=(rec["run_id"],rec["pseudonym"],rec["seq"])
            if key in annotations:
                rec["malicious"]=annotations[key]
            if rec["malicious"] is not None:
                known+=1
            split="calibration" if rec["run_id"] in calibration else "test"
            f=cf if split=="calibration" else tf
            f.write(json.dumps(rec,sort_keys=True)+"\n")
            counts[split]+=1
    metadata={"source":str(source),"records":count,
              "calibration_records":counts["calibration"],"test_records":counts["test"],
              "run_groups_calibration":sorted(calibration),
              "run_groups_test":sorted(groups-calibration),
              "known_labels":known,"seed":seed,
              "split":"whole independent run/ZIP group, never per-message",
              "authenticity":"Signatures absent; cryptographic results require re-signing/injection"}
    (out/"manifest.json").write_text(json.dumps(metadata,indent=2),encoding="utf-8")
    return metadata
