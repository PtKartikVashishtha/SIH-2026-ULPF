#!/usr/bin/env python3
"""Generate Pydantic v2 models from JSON Schema source of truth.

Usage:
    python scripts/generate.py

Reads all *.schema.json from packages/contracts/schemas/ and writes
Pydantic models to ulpf_contracts/models.py.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
PACKAGE_DIR = SCRIPT_DIR.parent
SCHEMA_DIR = PACKAGE_DIR.parent / "schemas"
OUT_FILE = PACKAGE_DIR / "ulpf_contracts" / "models.py"


def main() -> None:
    schema_files = sorted(SCHEMA_DIR.glob("*.schema.json"))
    if not schema_files:
        print(f"No schemas found in {SCHEMA_DIR}", file=sys.stderr)
        sys.exit(1)

    # datamodel-codegen can take multiple inputs via a directory
    cmd = [
        sys.executable,
        "-m",
        "datamodel_code_generator",
        "--input", str(SCHEMA_DIR),
        "--input-file-type", "jsonschema",
        "--output", str(OUT_FILE),
        "--output-model-type", "pydantic_v2.BaseModel",
        "--target-python-version", "3.11",
        "--use-standard-collections",
        "--use-union-operator",
        "--field-constraints",
        "--snake-case-field",
        "--collapse-root-models",
        "--use-annotated",
    ]

    print(f"Running: {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True)

    if result.returncode != 0:
        print(f"STDERR:\n{result.stderr}", file=sys.stderr)
        sys.exit(result.returncode)

    print(f"Generated {OUT_FILE} from {len(schema_files)} schemas.")
    if result.stdout:
        print(result.stdout)


if __name__ == "__main__":
    main()
