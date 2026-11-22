
set -euo pipefail
for scenario in s1 s2 s3 s4 s5 s6 s7 s8; do
  echo "[RiskAuthNet] Scenario $scenario"
  python -m riskauthnet experiment --scenario "$scenario" --runs 10 --seconds 600 \
    --seed 42 --output "results/full/$scenario" --details
  python -m riskauthnet report --input "results/full/$scenario/runs.csv" \
    --output "results/full/$scenario/report"
done
