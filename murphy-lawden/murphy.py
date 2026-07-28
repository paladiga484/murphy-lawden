#!/usr/bin/env python3
"""Run Murphy Lawden directly:  python murphy.py [args]   (or just: murphy)."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from murphy_lawden.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
