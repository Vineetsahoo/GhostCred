"""
Pytest configuration for GhostCred tests.
Ensures the package root is on sys.path when tests are run from the repo root.
"""
import sys
from pathlib import Path

# Add the repo root so `ghostcred.*` imports resolve without pip install.
sys.path.insert(0, str(Path(__file__).parent.parent))
