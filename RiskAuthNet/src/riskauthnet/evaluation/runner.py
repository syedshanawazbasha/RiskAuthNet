"""Paired multi-method evaluation on identical signed trace records."""
from __future__ import annotations
import csv
import json
from pathlib import Path

from ..config import Settings
from ..pipeline import Receiver, METHODS
from ..simulation.synthetic import generate_trace, SCENARIOS
from .metrics import summarize, ResultRow


def run_trace(trace, *, config: Settings | None = None,
              methods: tuple[str,...] = METHODS,
              detail_path: str | Path | None = None) -> list[ResultRow]:
    p=config or Settings()
    rows=[]
    all_detail=[]
    for method in methods:
        rx=Receiver(trace.authority,p,method=method,identities=trace.identities)
        pairs=[]
        for ev in trace.events:
            result=rx.process(ev.message,ev.arrival_ms,ev.context)
            pairs.append((ev,result))
            if detail_path is not None:
                all_detail.append({"method":method,"seed":trace.seed,"truth_malicious":ev.malicious,
                                   "attack":ev.attack,"sender":ev.message.pseudonym,
                                   "send_ms":ev.message.timestamp_ms,**result.to_dict()})
        rows.append(summarize(method,trace.seed,pairs))
    if detail_path is not None:
        path=Path(detail_path)
        path.parent.mkdir(parents=True,exist_ok=True)
        with path.open("w",encoding="utf-8") as f:
            for item in all_detail:
                f.write(json.dumps(item,sort_keys=True)+"\n")
    return rows


def run_experiment(*, output: str | Path, scenario: str = "s7", runs: int = 3,
                   duration_seconds: float = 8, vehicles: int | None = None,
                   config: Settings | None = None, base_seed: int = 42,
                   methods: tuple[str,...] = METHODS,
                   details: bool = False) -> list[ResultRow]:
    if scenario not in SCENARIOS:
        raise ValueError(f"scenario must be one of {sorted(SCENARIOS)}")
    if runs < 1:
        raise ValueError("runs must be at least 1")
    env, n, attack=SCENARIOS[scenario]
    n=vehicles or n
    p=config or Settings()
    out=Path(output)
    out.mkdir(parents=True,exist_ok=True)
    outputs=[]
    for i in range(runs):
        trace=generate_trace(config=p,seed=base_seed+i,vehicles=n,
                             duration_seconds=duration_seconds,environment=env,attack=attack)
        outputs += run_trace(trace,config=p,methods=methods,
              detail_path=out/f"{scenario}_seed_{base_seed+i}_events.jsonl" if details else None)
    with (out/"runs.csv").open("w",newline="",encoding="utf-8") as f:
        writer=csv.DictWriter(f,fieldnames=list(outputs[0].to_dict()))
        writer.writeheader()
        for row in outputs: writer.writerow(row.to_dict())
    (out/"manifest.json").write_text(json.dumps({"dataset":"synthetic-python-trace (NOT ns-3)",
       "scenario":scenario,"duration_seconds":duration_seconds,"vehicles":n,
       "runs":runs,"seeds":[base_seed+i for i in range(runs)],
       "methods":list(methods),"manuscript_metrics_are_not_assumed":True},indent=2),encoding="utf-8")
    return outputs
