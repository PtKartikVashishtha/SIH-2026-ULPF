#!/usr/bin/env python3
"""
ULPF — One-Command Automated Evaluator Demo Entrypoint.
Run:
    python demo.py
"""

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(REPO_ROOT / "tools"))

from evaluator_demo import run_demo

if __name__ == "__main__":
    ok = run_demo()
    sys.exit(0 if ok else 1)
