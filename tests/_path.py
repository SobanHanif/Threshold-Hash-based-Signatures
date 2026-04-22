"""Adds the source folders to sys.path so unittest discovery keeps working."""

import os
import sys

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_MINIMAL = os.path.join(_ROOT, "src", "minimal")
_EXTENSIONS = os.path.join(_ROOT, "src", "extensions")

for path in (_ROOT, _MINIMAL, _EXTENSIONS):
    if path not in sys.path:
        sys.path.insert(0, path)
