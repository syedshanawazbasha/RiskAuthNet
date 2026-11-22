from pathlib import Path
import csv
import json
import pytest
from riskauthnet.datasets.veremi import load_veremi,prepare_veremi,split_by_run
from riskauthnet.datasets.car_hacking import timing_profiles
from riskauthnet.datasets.replay import from_prepared
from riskauthnet.simulation.mobility import export_sumo_fcd,replay_ns3
from riskauthnet.simulation.synthetic import generate_trace
from riskauthnet.evaluation.runner import run_trace,run_experiment
from riskauthnet.evaluation.report import create_report

ROOT=Path(__file__).resolve().parents[1]


def test_veremi_preprocess_grouped_and_replay(tmp_path):
    path=ROOT/"examples/veremi"
    data=list(load_veremi(path))
    assert len(data)==6
    meta=prepare_veremi(path,tmp_path)
    assert meta["records"]==6 and meta["known_labels"]==6
    assert set(meta["run_groups_calibration"]).isdisjoint(meta["run_groups_test"])
    trace=from_prepared(tmp_path/"calibration.jsonl")
    assert len(trace.events)==3
    results=run_trace(trace,methods=("riskauthnet","crypto_only"))
    assert len(results)==2
    assert results[0].n==3


def test_single_run_refuses_leaky_split():
    with pytest.raises(ValueError,match="two distinct"):
        split_by_run([{"run_id":"one"}])


def test_can_variable_dlc():
    profiles=timing_profiles(ROOT/"examples/sample_can.csv")
    assert profiles["total_frames"]==8
    assert "043F" in profiles["profiles"]
    assert profiles["profiles"]["043F"]["injected_samples"]==2
    assert profiles["profiles"]["00FF"]["normal_samples"]==1


def test_synthetic_execution_and_reporting(tmp_path):
    trace=generate_trace(seed=20,vehicles=10,duration_seconds=2.0,attack="mixed")
    assert trace.events
    rows=run_trace(trace,methods=("riskauthnet","crypto_only","static_strict"))
    assert all(0 <= r.accuracy <= 1 and r.n == len(trace.events) for r in rows)
    results=run_experiment(output=tmp_path/"experiment",scenario="s7",runs=2,
                           duration_seconds=1.5,vehicles=8)
    assert len(results)==10
    summary=create_report(tmp_path/"experiment/runs.csv",tmp_path/"report")
    assert (tmp_path/"report/accuracy.png").exists()
    assert (tmp_path/"report/paired_tests.json").exists()


def test_fcd_export_and_ns3_ingest(tmp_path):
    path=tmp_path/"mobility.csv"
    info=export_sumo_fcd(ROOT/"examples/sample_fcd.xml",path)
    assert info["records"]==6
    rx=tmp_path/"rx.csv"
    rx.write_text("vehicle_id,seq,send_ms,receive_ms,receiver_node\n"
                  "carB,1,0,10,0\ncarB,2,100,110,0\ncarB,3,200,210,0\n"
                  "carA,1,0,9,1\n",encoding="utf-8")
    trace=replay_ns3(path,rx)
    assert len(trace.events)==3
    assert all(e.arrival_ms-e.message.timestamp_ms==10 for e in trace.events)
