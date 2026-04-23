"""Adds the source folders to sys.path so unittest discovery keeps working."""

import os
import sys

# Path Setup
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MINIMAL = os.path.join(ROOT, "src", "minimal")
EXTENSIONS = os.path.join(ROOT, "src", "extensions")

for path in (ROOT, MINIMAL, EXTENSIONS):
    if path not in sys.path:
        sys.path.insert(0, path)
