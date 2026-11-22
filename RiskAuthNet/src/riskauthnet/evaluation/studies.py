"""Reproducible ablations and sensitivity with per-seed outputs."""
from __future__ import annotations
from dataclasses import replace
import csv
import json
from pathlib import Path

from ..config import Settings
from ..simulation.synthetic import generate_trace, SCENARIOS
from ..pipeline import Receiver, ABLATIONS
from .metrics import summarize, ResultRow


def _write(rows: list[dict], output: Path, manifest: dict) -> None:
    output.mkdir(parents=True,exist_ok=True)
    if rows:
        with (output/"runs.csv").open("w",newline="",encoding="utf-8") as f:
            w=csv.DictWriter(f,fieldnames=list(rows[0]))
            w.writeheader();w.writerows(rows)
    (output/"manifest.json").write_text(json.dumps(manifest,indent=2),encoding="utf-8")


def ablation_study(*, scenario: str = "s7", runs: int = 3,
                   seconds: float = 8, vehicles: int = 12, seed: int = 42,
                   output: str | Path = "results/ablation", config: Settings | None = None) -> list[dict]:
    if scenario not in SCENARIOS:raise ValueError("unknown scenario")
    if runs<=0:raise ValueError("runs must be positive")
    env,_,attack=SCENARIOS[scenario]
    p=config or Settings()
    rows=[]
    for trial in range(runs):
        t=generate_trace(config=p,seed=seed+trial,vehicles=vehicles,
                         duration_seconds=seconds,environment=env,attack=attack)
        for name in ("full",)+ABLATIONS:
            flags=frozenset() if name=="full" else frozenset((name,))
            rx=Receiver(t.authority,p,identities=t.identities,ablations=flags)
            result=summarize(name,seed+trial,
                  ((e,rx.process(e.message,e.arrival_ms,e.context)) for e in t.events))
            rows.append(result.to_dict())
    _write(rows,Path(output),{"type":"ablation on Python signed traces",
            "scenario":scenario,"vehicles":vehicles,"seconds":seconds,
            "runs":runs,"seeds":list(range(seed,seed+runs)),
            "ablations":list(ABLATIONS),"baseline":"full"})
    return rows


def sensitivity_study(*, parameter: str = "trust_lambda",
                      values: list[float] | None = None, scenario: str = "s7",
                      runs: int = 3, seconds: float = 8, vehicles: int = 12,
                      seed: int = 42, output: str | Path = "results/sensitivity",
                      config: Settings | None = None) -> list[dict]:
    if scenario not in SCENARIOS:raise ValueError("unknown scenario")
    if runs<=0:raise ValueError("runs must be positive")
    accepted={"trust_lambda","trust_recovery","anomaly_penalty",
              "initial_trust","min_trust","window_size","attacker_fraction"}
    if parameter not in accepted:
        raise ValueError(f"parameter must be one of {sorted(accepted)}")
    p=config or Settings();values=values or [0.6,0.8,0.9]
    env,_,attack=SCENARIOS[scenario]
    rows=[]
    for trial in range(runs):
        for value in values:
            effective = int(value) if parameter=="window_size" else float(value)
            setting=p if parameter=="attacker_fraction" else replace(p,**{parameter:effective})
            t=generate_trace(config=setting,seed=seed+trial,vehicles=vehicles,
                    duration_seconds=seconds,environment=env,attack=attack,
                    attacker_fraction=float(value) if parameter=="attacker_fraction" else 0.10)
            rx=Receiver(t.authority,setting,identities=t.identities)
            result=summarize("riskauthnet",seed+trial,
                    ((e,rx.process(e.message,e.arrival_ms,e.context)) for e in t.events))
            rows.append({"parameter":parameter,"value":value,**result.to_dict()})
    _write(rows,Path(output),{"type":"one-factor-at-a-time sensitivity",
           "parameter":parameter,"values":values,"runs":runs,
           "seeds":list(range(seed,seed+runs)),"scenario":scenario,
           "seconds":seconds,"vehicles":vehicles})
    return rows
