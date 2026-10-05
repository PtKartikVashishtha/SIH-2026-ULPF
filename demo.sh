#!/usr/bin/env bash
set -euo pipefail

echo "=========================================================="
echo "  Universal Log Pre-processing Framework (ULPF)"
echo "  SIH26156 Evaluator One-Command Automated Demo"
echo "=========================================================="

python3 demo.py "$@" || python demo.py "$@"
