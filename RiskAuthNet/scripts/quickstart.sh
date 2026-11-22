
set -euo pipefail
python -m pip install -e '.[all]'
python -m pytest -q
python -m riskauthnet demo --vehicles 12 --seconds 8 --output results/demo
python -m riskauthnet report --input results/demo/runs.csv --output results/demo/figures
