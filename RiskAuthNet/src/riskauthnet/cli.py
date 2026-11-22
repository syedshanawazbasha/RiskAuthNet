
from __future__ import annotations
import argparse
import csv
import json
from pathlib import Path

from . import __version__
from .config import Settings
from .crypto.certificates import CertificateAuthority
from .crypto.ecc import sign, verify
from .datasets.veremi import prepare_veremi
from .datasets.car_hacking import save_profiles
from .datasets.replay import from_prepared
from .evaluation.runner import run_trace, run_experiment
from .evaluation.report import create_report
from .pipeline import METHODS
from .simulation.synthetic import SCENARIOS, generate_trace


def save_rows(rows, output: Path) -> None:
    output.parent.mkdir(parents=True,exist_ok=True)
    with output.open("w",newline="",encoding="utf-8") as f:
        writer=csv.DictWriter(f,fieldnames=list(rows[0].to_dict()))
        writer.writeheader()
        for item in rows:writer.writerow(item.to_dict())


def main(argv: list[str] | None = None) -> None:
    a=argparse.ArgumentParser(prog="riskauthnet",description="RiskAuthNet authentication and research evaluation")
    a.add_argument("--version",action="version",version=f"RiskAuthNet {__version__}")
    sp=a.add_subparsers(dest="command",required=True)
    d=sp.add_parser("demo",help="run all five methods on the same small offline signed trace")
    d.add_argument("--vehicles",type=int,default=12)
    d.add_argument("--seconds",type=float,default=8.0)
    d.add_argument("--attack",choices=("none","spoof","replay","sybil","tamper","position","speed","flood","mixed"),default="mixed")
    d.add_argument("--environment",choices=("urban","highway"),default="urban")
    d.add_argument("--seed",type=int,default=42)
    d.add_argument("--output",default="results/demo")
    d.add_argument("--config",default=None)
    e=sp.add_parser("experiment",help="run the manuscript S1-S8 scenarios")
    e.add_argument("--scenario",choices=tuple(SCENARIOS),default="s7")
    e.add_argument("--runs",type=int,default=3)
    e.add_argument("--seconds",type=float,default=8.0,
                   help="set 600 to reproduce reference-duration runs")
    e.add_argument("--vehicles",type=int,default=None,help="overrides manuscript count for smoke tests")
    e.add_argument("--seed",type=int,default=42)
    e.add_argument("--config",default=None)
    e.add_argument("--details",action="store_true",help="write per-packet JSONL evidence")
    e.add_argument("--output",default="results/experiment")
    v=sp.add_parser("prepare-veremi",help="group split VeReMi receiver logs; requires independent runs")
    v.add_argument("--input",required=True)
    v.add_argument("--output",required=True)
    v.add_argument("--limit",type=int,default=None)
    v.add_argument("--seed",type=int,default=42)
    v.add_argument("--labels-csv",default=None,
                   help="optional explicit GT CSV columns run_id,pseudonym,seq,malicious")
    c=sp.add_parser("prepare-can",help="extract CAN arbitration-ID timing profiles (offline only)")
    c.add_argument("--input",required=True)
    c.add_argument("--output",required=True)
    r=sp.add_parser("replay-veremi",help="evaluate labelled, independently split VeReMi events")
    r.add_argument("--input",required=True)
    r.add_argument("--output",default="results/veremi")
    r.add_argument("--limit",type=int,default=10000)
    r.add_argument("--config",default=None)
    ab=sp.add_parser("ablation",help="run per-component RiskAuthNet ablations")
    ab.add_argument("--scenario",choices=tuple(SCENARIOS),default="s7")
    ab.add_argument("--runs",type=int,default=3)
    ab.add_argument("--seconds",type=float,default=8.0)
    ab.add_argument("--vehicles",type=int,default=12)
    ab.add_argument("--seed",type=int,default=42)
    ab.add_argument("--output",default="results/ablation")
    sn=sp.add_parser("sensitivity",help="run one-factor-at-a-time parameter sensitivity")
    sn.add_argument("--parameter",default="trust_lambda")
    sn.add_argument("--values",type=float,nargs="+",default=[0.6,0.8,0.9])
    sn.add_argument("--scenario",choices=tuple(SCENARIOS),default="s7")
    sn.add_argument("--runs",type=int,default=3)
    sn.add_argument("--seconds",type=float,default=8)
    sn.add_argument("--vehicles",type=int,default=12)
    sn.add_argument("--seed",type=int,default=42)
    sn.add_argument("--output",default="results/sensitivity")
    n=sp.add_parser("report",help="generate plots and paired statistics from experiment runs.csv")
    n.add_argument("--input",required=True)
    n.add_argument("--output",default="results/report")
    b=sp.add_parser("benchmark-crypto",help="measure real P-256 sign/verify on the executing machine")
    b.add_argument("--iterations",type=int,default=100)
    s=sp.add_parser("export-sumo",help="stream SUMO FCD XML to mobility CSV")
    s.add_argument("--input",required=True)
    s.add_argument("--output",required=True)
    q=sp.add_parser("replay-ns3",help="re-sign ns-3 RX packet CSV with mobility trace and evaluate")
    q.add_argument("--mobility",required=True)
    q.add_argument("--rx",required=True)
    q.add_argument("--output",default="results/ns3")
    q.add_argument("--limit",type=int,default=50000)
    q.add_argument("--receiver-node",type=int,default=0,
                   help="evaluate one receiver node to avoid cross-receiver leakage")
    args=a.parse_args(argv)
    if args.command=="demo":
        p=Settings.load(args.config)
        trace=generate_trace(config=p,seed=args.seed,vehicles=args.vehicles,
                             duration_seconds=args.seconds,environment=args.environment,
                             attack=args.attack)
        out=Path(args.output)
        rows=run_trace(trace,config=p,detail_path=out/"events.jsonl")
        save_rows(rows,out/"runs.csv")
        (out/"manifest.json").write_text(json.dumps({"type":"synthetic Python trace, NOT ns-3",
            "seed":args.seed,"vehicles":args.vehicles,"seconds":args.seconds,
            "environment":args.environment,"attack":args.attack},indent=2),encoding="utf-8")
        print(f"Saved: {out.resolve()} (events={len(trace.events)})")
        for row in rows:
            print(f"{row.name:16} acc={row.accuracy:.3f} FAR={row.far:.3f} FRR={row.frr:.3f} "
                  f"latency={row.mean_processing_ms:.3f}ms")
    elif args.command=="experiment":
        rows=run_experiment(output=args.output,scenario=args.scenario,runs=args.runs,
             duration_seconds=args.seconds,vehicles=args.vehicles,base_seed=args.seed,
             config=Settings.load(args.config),details=args.details)
        print(f"Saved {len(rows)} run rows to {Path(args.output).resolve() / 'runs.csv'}")
    elif args.command=="ablation":
        from .evaluation.studies import ablation_study
        rows=ablation_study(scenario=args.scenario,runs=args.runs,seconds=args.seconds,
                     vehicles=args.vehicles,seed=args.seed,output=args.output)
        print(f"Saved {len(rows)} ablation measurements to {Path(args.output).resolve()}")
    elif args.command=="sensitivity":
        from .evaluation.studies import sensitivity_study
        rows=sensitivity_study(parameter=args.parameter,values=args.values,
                     scenario=args.scenario,runs=args.runs,seconds=args.seconds,
                     vehicles=args.vehicles,seed=args.seed,output=args.output)
        print(f"Saved {len(rows)} sensitivity measurements to {Path(args.output).resolve()}")
    elif args.command=="prepare-veremi":
        print(json.dumps(prepare_veremi(args.input,args.output,seed=args.seed,
                                       limit=args.limit,labels_csv=args.labels_csv),indent=2))
    elif args.command=="prepare-can":
        out=save_profiles(args.input,args.output)
        print(f"Analyzed {out['total_frames']} frames across {out['stream_count']} CAN identifiers")
    elif args.command=="replay-veremi":
        trace=from_prepared(args.input,limit=args.limit,config=Settings.load(args.config))
        out=Path(args.output)
        rows=run_trace(trace,config=Settings.load(args.config),
                       detail_path=out/"events.jsonl")
        save_rows(rows,out/"runs.csv")
        print(f"Processed {len(trace.events)} distinct VeReMi messages into {out.resolve()}")
    elif args.command=="report":
        print(json.dumps(create_report(args.input,args.output),indent=2))
    elif args.command=="benchmark-crypto":
        from time import perf_counter_ns
        import statistics
        if args.iterations<1:a.error("iterations must be positive")
        ca=CertificateAuthority(); id=ca.issue("bench",0,10000)
        data=b"RiskAuthNet benchmark message"
        sign_times=[];verify_times=[]
        for _ in range(args.iterations):
            st=perf_counter_ns(); sig=sign(id.private_key,data)
            sign_times.append((perf_counter_ns()-st)/1e6)
            st=perf_counter_ns();ok=verify(id.private_key.public_key(),data,sig)
            verify_times.append((perf_counter_ns()-st)/1e6)
            if not ok:raise RuntimeError("unexpected signature failure")
        print(json.dumps({"iterations":args.iterations,"mean_sign_ms":statistics.mean(sign_times),
              "mean_verify_ms":statistics.mean(verify_times),"signature_bytes":64},indent=2))
    elif args.command=="export-sumo":
        from .simulation.mobility import export_sumo_fcd
        print(json.dumps(export_sumo_fcd(args.input,args.output),indent=2))
    elif args.command=="replay-ns3":
        from .simulation.mobility import replay_ns3
        out=Path(args.output)
        trace=replay_ns3(args.mobility,args.rx,limit=args.limit,receiver_node=args.receiver_node)
        rows=run_trace(trace,detail_path=out/"events.jsonl")
        save_rows(rows,out/"runs.csv")
        (out/"manifest.json").write_text(json.dumps({"type":"network reception replay from ns-3",
            "crypto_timing":"Python monotonic clock after network replay",
            "ground_truth":"all benign unless a separate attack annotation is supplied"},indent=2),encoding="utf-8")
        print(f"Imported {len(trace.events)} NS-3 receiver packets to {out.resolve()}")


if __name__=="__main__":
    main()
