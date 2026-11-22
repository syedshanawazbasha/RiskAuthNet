[![DOI](https://zenodo.org/badge/1467391512.svg)](https://doi.org/10.5281/zenodo.24438127)
[![GitHub Repository](https://img.shields.io/badge/GitHub-RiskAuthNet-blue?logo=github)](https://github.com/syedshanawazbasha/RiskAuthNet)

# RiskAuthNet

## Risk-Adaptive Lightweight Authentication and Trust-Scoring Framework for Secure Vehicle-to-Everything Data Dissemination in Vehicular Ad Hoc Networks

RiskAuthNet is a lightweight security framework for Vehicle-to-Everything (V2X) communication in Vehicular Ad Hoc Networks (VANETs). It combines elliptic-curve pseudonym authentication, online behavioural trust evaluation, and contextual risk-adaptive verification to secure vehicle communication and identify suspicious activities.

The framework integrates cryptographic authentication, behavioural monitoring, dynamic verification levels, and Roadside Unit (RSU)-assisted trust management.

## Key Features

- **P-256 Pseudonym Authentication:** Provides vehicle message authentication using ECDSA with the NIST P-256 elliptic curve.
- **Online Behavioural Trust:** Evaluates vehicle behaviour using multiple feature groups, sliding-window analysis, trust decay, penalties, and recovery mechanisms.
- **Risk-Adaptive Validation:** Dynamically selects verification levels (L0–L3) according to contextual risk.
- **V2I Authentication:** Implements a four-term Diffie–Hellman handshake with HKDF and HMAC session authentication.
- **RSU Trust Management:** Supports RSU re-verification, signed trust tokens, and escalation control.
- **Certificate Revocation:** Supports certificate revocation lists (CRLs) and signed revocation updates.
- **Attack Detection:** Evaluates suspicious vehicle activities and different attack scenarios.
- **Dataset Integration:** Supports VeReMi Extension and Car-Hacking dataset processing.
- **Baseline Comparison:** Includes four controlled baseline methods.
- **Performance Evaluation:** Provides accuracy, FAR, FRR, precision, recall, F1-score, latency, escalation rate, hold rate, and communication-size measurements.
- **Ablation Analysis:** Evaluates the contribution of individual framework components.
- **Sensitivity Analysis:** Studies the impact of different parameter settings.
- **Statistical Analysis:** Includes paired statistical tests and confidence intervals.
- **SUMO and NS-3 Integration:** Provides mobility trace export and NS-3.47 reception trace integration.

## System Architecture

RiskAuthNet consists of three main security layers.

### 1. P-256 Pseudonym Authentication

This layer verifies the authenticity and validity of vehicle messages using:

- ECDSA P-256 digital signatures.
- SHA-256 message hashing.
- Pseudonym-based authentication.
- Certificate validation.
- Certificate revocation checking.
- Message freshness verification.
- Sequence-number validation.

### 2. Online Behavioural Trust Evaluation

This layer continuously evaluates vehicle behaviour using:

- Five behavioural feature groups.
- Sliding-window trust evaluation.
- Trust decay.
- Behavioural penalties.
- Trust recovery.
- Historical behavioural information.

### 3. Contextual Risk-Adaptive Validation

This layer dynamically determines the required verification level based on the assessed risk.

| Level | Verification |
|---|---|
| L0 | Signature, freshness, and sequence validation |
| L1 | Additional conditional plausibility checks |
| L2 | Certificate-chain verification and corroboration |
| L3 | Quarantine and RSU-assisted escalation |

Higher verification levels introduce additional security checks when required.

## Project Structure

```text
RiskAuthNet/
│
├── src/
│   └── riskauthnet/
│       ├── crypto/
│       │   ├── ECDSA P-256
│       │   ├── Certificates and CRL
│       │   ├── V2I Four-DH Handshake
│       │   └── HKDF and HMAC
│       │
│       ├── trust/
│       │   ├── Behavioural Features
│       │   ├── Sliding Window
│       │   ├── Trust Decay
│       │   └── Penalties and Recovery
│       │
│       ├── risk/
│       │   ├── Risk Fusion
│       │   ├── Verification Levels
│       │   ├── Cold-Start Floors
│       │   └── Hysteresis
│       │
│       ├── rsu/
│       │   ├── RSU Re-verification
│       │   ├── Trust Tokens
│       │   └── Escalation Limits
│       │
│       ├── datasets/
│       │   ├── VeReMi Processing
│       │   └── Car-Hacking Processing
│       │
│       ├── simulation/
│       │   ├── Attack Simulation
│       │   └── SUMO and NS-3 Integration
│       │
│       └── evaluation/
│           ├── Baseline Comparisons
│           ├── Experiments
│           ├── Performance Metrics
│           ├── Ablation Studies
│           ├── Sensitivity Analysis
│           └── Statistical Evaluation
│
├── configs/
│   └── Configuration Parameters
│
├── datasets/
│   ├── raw/
│   └── processed/
│
├── examples/
│   ├── veremi/
│   ├── sample_can.csv
│   ├── sample_fcd.xml
│   └── protocol_walkthrough.py
│
├── scripts/
│   ├── run_sumo.sh
│   └── run_ns3.sh
│
├── ns3/
│   └── riskauthnet-v2x.cc
│
├── tests/
│
├── results/
│
└── requirements
```

## Installation

### Requirements

- Python 3.11 or later
- pip
- Git

Optional integrations:

- SUMO
- NS-3.47
- Linux environment for the external SUMO/NS-3 execution scripts

### 1. Clone the Repository

```bash
git clone https://github.com/syedshanawazbasha/RiskAuthNet.git
```

```bash
cd RiskAuthNet
```

### 2. Create a Virtual Environment

```bash
python -m venv .venv
```

### 3. Activate the Environment

**Windows PowerShell:**

```powershell
.venv\Scripts\Activate.ps1
```

**Linux/macOS:**

```bash
source .venv/bin/activate
```

### 4. Install Dependencies

```bash
python -m pip install -e ".[all]"
```

### 5. Run Automated Tests

```bash
python -m pytest -q
```

## Running RiskAuthNet

### 1. Basic Demonstration

Run the framework with 12 vehicles for 8 seconds:

```bash
python -m riskauthnet demo --vehicles 12 --seconds 8 --attack mixed --output results/demo
```

Generate evaluation reports:

```bash
python -m riskauthnet report --input results/demo/runs.csv --output results/demo/figures
```

### 2. Main Experiment

Run scenario S7 with 10 runs and 600 simulated seconds:

```bash
riskauthnet experiment --scenario s7 --runs 10 --seconds 600 --output results/s7 --details
```

### 3. Short Experiment

```bash
riskauthnet experiment --scenario s2 --runs 2 --seconds 5 --vehicles 12 --output results/s2_smoke
```

### 4. Ablation Study

```bash
riskauthnet ablation --scenario s7 --vehicles 12 --seconds 8 --runs 3 --output results/ablation
```

### 5. Sensitivity Analysis

```bash
riskauthnet sensitivity --parameter trust_lambda --values 0.6 0.7 0.8 0.9 --runs 3 --output results/sensitivity
```

### 6. Performance and Statistical Reports

```bash
riskauthnet report --input results/s7/runs.csv --output results/s7/report
```

### 7. Cryptographic Benchmarking

```bash
riskauthnet benchmark-crypto --iterations 1000
```

### 8. Cryptographic Protocol Walkthrough

```bash
python examples/protocol_walkthrough.py
```

## Dataset Integration

### 1. VeReMi Extension Dataset

VeReMi Extension is used for V2X behavioural evaluation.

**Official Dataset:** https://veremi-dataset.github.io/veremi-extension

**Dataset Download:** https://zenodo.org/records/20090854

Supported input formats:

- JSON
- JSONL
- LOG
- ZIP

The parser supports the following fields:

- senderPseudo
- messageID
- sendTime
- rcvTime
- pos
- spd
- Optional ground-truth labels

#### Prepare VeReMi Data

```bash
riskauthnet prepare-veremi --input data/raw/veremi --output data/processed/veremi
```

#### Prepare Data with Ground-Truth Annotations

```bash
riskauthnet prepare-veremi --input data/raw/veremi --labels-csv data/raw/annotations.csv --output data/processed/veremi
```

The optional annotation CSV supports:

```text
run_id,pseudonym,seq,malicious
```

#### Replay Processed VeReMi Data

```bash
riskauthnet replay-veremi --input data/processed/veremi/test.jsonl --limit 50000 --output results/veremi
```

The dataset preparation process separates complete run/ZIP groups into training and testing groups using a 70%/30% group-level split.

Unknown ground-truth labels are not automatically treated as benign.

### 2. Car-Hacking Dataset

The Car-Hacking dataset is used for offline CAN timing feature calibration.

**Dataset Source:** https://ocslab.hksecurity.net/Datasets/car-hacking-dataset/

#### Prepare CAN Data

```bash
riskauthnet prepare-can --input data/raw/car_hacking --output data/processed/car_timing.json
```

#### Process a Sample CAN File

```bash
riskauthnet prepare-can --input examples/sample_can.csv --output results/sample_can.json
```

The parser supports:

- Headerless CAN logs.
- Variable Data Length Code (DLC).
- Transmission and Reception flags.
- CAN arbitration IDs.
- Inter-arrival timing sequences.
- Relative message-rate analysis.

## SUMO and NS-3 Integration

RiskAuthNet provides an external mobility and network-trace integration workflow.

### Step 1. Generate SUMO Mobility Data

```bash
scripts/run_sumo.sh /path/to/network.sumocfg results/sumo/mobility.csv
```

Alternatively, convert an existing SUMO FCD file:

```bash
riskauthnet export-sumo --input examples/sample_fcd.xml --output results/sumo/mobility.csv
```

### Step 2. Run NS-3.47

After installing and building NS-3.47:

```bash
NS3_HOME=/path/to/ns-3.47 scripts/run_ns3.sh results/sumo/mobility.csv results/sumo/ns3-received.csv
```

The integration uses 802.11p communication with:

- 10 MHz channel bandwidth.
- 6 Mbps nominal data rate.
- 23 dBm transmission power.
- Log-distance propagation.
- Nakagami-m fading.

The Nakagami parameter can be configured for different scenarios:

- `--nakagamiM=1` for urban NLOS.
- `--nakagamiM=3` for highway.

### Step 3. Replay NS-3 Reception Traces

```bash
riskauthnet replay-ns3 --mobility results/sumo/mobility.csv --rx results/sumo/ns3-received.csv --receiver-node 0 --output results/ns3
```

The replay process evaluates authentication and behavioural trust processing while retaining the network arrival information from the NS-3 reception traces.

## Performance Evaluation

RiskAuthNet supports the following evaluation metrics:

| Metric | Description |
|---|---|
| Accuracy | Overall classification accuracy |
| FAR | False Acceptance Rate |
| FRR | False Rejection Rate |
| Precision | Correctness of positive predictions |
| Recall | Detection rate of malicious activity |
| F1-score | Harmonic mean of precision and recall |
| Latency | Processing time |
| Escalation Rate | Frequency of RSU escalation |
| Hold Rate | Frequency of pending verification decisions |
| Wire Size | Communication payload size |

### Statistical Analysis

The reporting module includes:

- Paired two-sided Wilcoxon signed-rank test.
- Paired t-test.
- Bonferroni-adjusted p-values.
- Paired Cohen's d_z.
- 95% Student-t confidence intervals.
- Standard-deviation error bars.

### Ablation Analysis

The ablation module evaluates seven component-removal configurations to study the contribution of individual framework components.

### Sensitivity Analysis

The sensitivity module evaluates selected parameter values and measures their impact on framework performance.

## Security Mechanisms

RiskAuthNet incorporates the following security mechanisms:

| Security Component | Technology |
|---|---|
| Digital Signatures | ECDSA P-256 |
| Message Hashing | SHA-256 |
| Deterministic Signing | RFC6979 |
| Key Agreement | ECDH |
| Key Derivation | HKDF |
| Message Authentication | HMAC |
| Certificate Management | Certificates and CRL |
| Trust Management | Behavioural Trust Scoring |
| Risk Assessment | L0–L3 Adaptive Verification |
| RSU Authentication | Signed Trust Tokens |

The implementation uses the Python `cryptography` library (version 43 or later).

The four-term ECDH/HKDF/HMAC session binds both communication parties, their ephemeral values, and the handshake transcript.

## Expected Outputs

The experiment and evaluation modules produce the following outputs:

| Output File | Description |
|---|---|
| `runs.csv` | Experiment measurements |
| `manifest.json` | Experiment configuration and source information |
| `*_events.jsonl` | Optional event-level records |
| `summary.json` | Aggregated evaluation results |
| `paired_tests.json` | Statistical comparison results |
| PNG Figures | Performance visualization figures |

The report module generates four high-resolution PNG figures with labelled axes.

The ablation and sensitivity modules produce measurements for each evaluated configuration and parameter value.

## Acknowledgement

RiskAuthNet integrates cryptographic authentication, behavioural trust evaluation, contextual risk assessment, and RSU-assisted verification to support secure and adaptive V2X data dissemination in vehicular ad hoc networks.
