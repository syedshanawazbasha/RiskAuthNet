# Reproducibility protocol

## Paper-to-code mapping

| Manuscript element | Executable implementation |
|---|---|
| Alg. 1 ECC + pseudonym + time/sequence | `crypto/ecc.py`, `crypto/auth.py` |
| Alg. 2 bounded feature window + trust | `trust/features.py`, `trust/trust_engine.py` |
| Alg. 3 risk-adaptive L0–L3 | `risk/policy.py`, `pipeline.py` |
| Section 4.10 registration/handshake/tokens | `crypto/certificates.py`, `crypto/session.py`, `rsu/rsu.py` |
| Section 4.11 escalation bounds | `rsu/load_control.py` |
| Section 4.2 VeReMi/CAN | `datasets/veremi.py`, `datasets/car_hacking.py`, `datasets/replay.py` |
| Table 4 S1–S8 | `simulation/synthetic.py`, `evaluation/runner.py` |
| Section 4.8 metrics/statistics | `evaluation/metrics.py`, `evaluation/report.py` |
| Ablation/sensitivity | `evaluation/studies.py`, CLI `ablation`, `sensitivity` |
| SUMO/NS-3 integration | `simulation/mobility.py`, `ns3/riskauthnet-v2x.cc` |

## Reference study protocol

1. Record Python version, OS, `pip freeze`, cryptography provider, CPU, and external simulator versions. Run `pytest -q` before each release.
2. Download data from official original publishers. Preserve checksums, archive names, simulator run IDs, original ground truth and provenance.
3. Split VeReMi by independently generated simulation run, never by received packet. Use the calibration split to set feature bounds/risk weights and freeze parameters before evaluating test records.
4. Extract CAN timing profiles offline. Never confuse vehicle-internal CAN frames with V2X packets. Calibrate timing bounds only using the appropriate labelled calibration examples.
5. Create 10 independent seeded runs per S1–S8 scenario, 600 simulated seconds per run. Use paired seeds and identical signed inputs across baselines.
6. Report both synthetic-Python traces and actual ns-3 RX experiments as **different** evidence groups. The 802.11p sidecar is optional and not locally validated by this release.
7. Store confusion matrix plus accepted/monitor/reject/held counts for each run. Record sign/verify benchmark and Python receiver processing latency separately from network delay.
8. Run `riskauthnet report ...` and audit statistical assumptions. Report all confidence intervals and adjusted p values; do not compare the results to the abstract as if they were automatically reproduced.

## Seeds

Experiment generator uses `random.Random(seed)` for attacker placement, packet drops and receiver timestamps. Test protocol uses integer seeds starting at 42. ECDSA pseudonym private keys and identifiers are generated from cryptographically secure randomness and intentionally do not have reproducible deterministic secrets. Therefore, security-sensitive bytes and single-message cryptographic timing are not bit-for-bit reproducible even when attack placement is.

## Operational scope

The main Python package runs on a CPU without CUDA. For large 600s/200-car traces, real ECDSA verification across all five comparators may require significant memory and computation. Begin with short smoke tests and scale gradually; memory depends on runtime objects and can substantially exceed the analytical manuscript's 352 bytes per neighbour. Run the provided ns-3 C++ source externally before attributing radio metrics to ns-3.

## Example quick tests

```bash
python -m pytest -q
python -m riskauthnet demo --vehicles 8 --seconds 2 --output results/smoke
python -m riskauthnet experiment --scenario s3 --vehicles 12 --seconds 5 --runs 2 --output results/s3_short
python -m riskauthnet prepare-veremi --input examples/veremi --output results/prepared
python -m riskauthnet prepare-can --input examples/sample_can.csv --output results/can.json
python -m riskauthnet ablation --runs 2 --seconds 5 --vehicles 12
python -m riskauthnet sensitivity --parameter window_size --values 5 10 20 --runs 2 --seconds 5
```
