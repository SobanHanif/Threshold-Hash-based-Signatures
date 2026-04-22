"""Adds the project root to sys.path so `python -m unittest discover tests`
works from inside the Threshold-Hash-based-Signatures directory regardless
of how the test runner was invoked."""

import os
import sys

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)
