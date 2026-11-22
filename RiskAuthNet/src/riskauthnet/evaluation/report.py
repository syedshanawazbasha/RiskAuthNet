"""Per-seed inference and reproducible publication-quality graphics."""
from __future__ import annotations
import csv
import json
from pathlib import Path
import math
import statistics


def create_report(source: str | Path, output: str | Path) -> dict:
    try:
        import numpy as np
        import scipy.stats as stats
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError as exc:
        raise RuntimeError("Install optional analysis dependencies: pip install -e '.[analysis]'") from exc
    records=[]
    with Path(source).open(newline="",encoding="utf-8") as f:
        for row in csv.DictReader(f):
            records.append({**row,"seed":int(row["seed"])})
    methods=sorted(set(r["name"] for r in records))
    out=Path(output); out.mkdir(parents=True,exist_ok=True)
    metrics=("accuracy","far","frr","mean_processing_ms","mean_end_to_end_ms","escalation_rate","mean_wire_bytes")
    summary=[]
    for method in methods:
        rows=[r for r in records if r["name"]==method]
        item={"method":method,"n_runs":len(rows)}
        for metric in metrics:
            values=[float(r[metric]) for r in rows]
            mean=statistics.mean(values)
            sd=statistics.stdev(values) if len(values)>1 else 0
            margin=stats.t.ppf(0.975,len(values)-1)*sd/math.sqrt(len(values)) if len(values)>1 else float("nan")
            item[metric]={"mean":float(mean),"sd":float(sd),
                          "ci95_low":float(mean-margin) if len(values)>1 else None,
                          "ci95_high":float(mean+margin) if len(values)>1 else None}
        summary.append(item)
    (out/"summary.json").write_text(json.dumps(summary,indent=2),encoding="utf-8")
    reference={r["seed"]:r for r in records if r["name"]=="riskauthnet"}
    tests=[]
    for method in methods:
        if method=="riskauthnet":continue
        comparison={r["seed"]:r for r in records if r["name"]==method}
        seeds=sorted(set(reference)&set(comparison))
        if len(seeds)<2: continue
        for metric in ("accuracy","far","mean_processing_ms"):
            a=np.array([float(reference[s][metric]) for s in seeds])
            b=np.array([float(comparison[s][metric]) for s in seeds])
            diff=a-b
            if np.allclose(diff,0):
                p_t=p_w=1.0
                effect=0.0
            else:
                p_t=float(stats.ttest_rel(a,b).pvalue)
                try:p_w=float(stats.wilcoxon(a,b,zero_method="wilcox",alternative="two-sided").pvalue)
                except ValueError:p_w=1.0
                dsd=float(np.std(diff,ddof=1))
                effect=float(np.mean(diff)/dsd) if dsd>0 else None
            tests.append({"baseline":method,"metric":metric,"n":len(seeds),
                          "wilcoxon_p":p_w,"paired_t_p":p_t,
                          "wilcoxon_bonferroni_p":min(1,p_w*4),
                          "paired_t_bonferroni_p":min(1,p_t*4),
                          "paired_cohen_dz":effect})
    (out/"paired_tests.json").write_text(json.dumps(tests,indent=2),encoding="utf-8")
    # SD bars, no title embedded in the image, labelled x-axis as requested.
    for metric,ylabel in (("accuracy","Authentication accuracy"),("far","False acceptance rate"),
                         ("mean_processing_ms","Processing latency (ms)"),
                         ("mean_wire_bytes","Wire message size (bytes)")):
        means=[next(s for s in summary if s["method"]==m)[metric]["mean"] for m in methods]
        sds=[next(s for s in summary if s["method"]==m)[metric]["sd"] for m in methods]
        fig,ax=plt.subplots(figsize=(9.2,4.8))
        ax.bar(range(len(methods)),means,yerr=sds,capsize=5)
        ax.set_xticks(range(len(methods)),[m.replace("_","\n") for m in methods])
        ax.set_xlabel("Compared method")
        ax.set_ylabel(ylabel)
        ax.grid(axis="y",alpha=0.25)
        fig.tight_layout()
        fig.savefig(out/f"{metric}.png",dpi=600,bbox_inches="tight")
        plt.close(fig)
    return {"methods":methods,"runs":len(records),"summary":str(out/"summary.json"),
            "significance":str(out/"paired_tests.json")}
