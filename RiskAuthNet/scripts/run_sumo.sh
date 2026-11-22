#!/usr/bin/env bash
# Usage: scripts/run_sumo.sh network.sumocfg [mobility.csv]
set -euo pipefail
CONFIG="${1:?SUMO .sumocfg required}"
OUTPUT="${2:-results/sumo/mobility.csv}"
mkdir -p "$(dirname "$OUTPUT")"
XML="$(dirname "$OUTPUT")/fcd.xml"
sumo -c "$CONFIG" --step-length 0.1 --fcd-output "$XML" --fcd-output.geo false
python -m riskauthnet export-sumo --input "$XML" --output "$OUTPUT"
