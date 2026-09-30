#!/usr/bin/env python
"""Repo-root entry point: python start.py

Always uses backend/venv when it exists, even if you typed plain `python`.
"""
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
if os.name == "nt":
    VENV_PYTHON = ROOT / "backend" / "venv" / "Scripts" / "python.exe"
else:
    VENV_PYTHON = ROOT / "backend" / "venv" / "bin" / "python"

RUN_DEV = ROOT / "backend" / "run_dev.py"

if VENV_PYTHON.exists() and Path(sys.executable).resolve() != VENV_PYTHON.resolve():
    os.execv(str(VENV_PYTHON), [str(VENV_PYTHON), str(Path(__file__).resolve()), *sys.argv[1:]])

import runpy

runpy.run_path(str(RUN_DEV), run_name="__main__")
