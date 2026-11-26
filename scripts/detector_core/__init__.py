"""
scripts/detector_core/__init__.py
Modular 3-layer npm supply chain detector internals.
"""

from .models import (
    SignalTier,
    Finding,
    CommandClassification,
    Layer1ManifestResult,
)

__all__ = [
    "SignalTier",
    "Finding",
    "CommandClassification",
    "Layer1ManifestResult",
]
