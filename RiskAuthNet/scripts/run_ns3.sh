#!/usr/bin/env bash
# Usage: NS3_HOME=/path/to/ns-3.47 scripts/run_ns3.sh mobility.csv output.csv
set -euo pipefail
: "${NS3_HOME:?set NS3_HOME to an installed ns-3.47 source directory}"
MOBILITY="$(realpath "${1:?mobility CSV required}")"
OUTPUT="$(realpath -m "${2:-ns3-received.csv}")"
cp "$(dirname "$0")/../ns3/riskauthnet-v2x.cc" "$NS3_HOME/scratch/riskauthnet-v2x.cc"
(cd "$NS3_HOME" && ./ns3 run "scratch/riskauthnet-v2x --mobilityCsv=$MOBILITY --outputCsv=$OUTPUT")
echo "Radio receptions: $OUTPUT"
