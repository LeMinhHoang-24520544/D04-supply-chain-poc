"""
scripts/detector_core/models.py
Structured signal tiers, findings, and cross-layer contract models.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Set, Tuple, Any


class SignalTier(str, Enum):
    HARD_EVIDENCE = "HARD_EVIDENCE"
    CAPABILITY = "CAPABILITY"
    WEAK_ANOMALY = "WEAK_ANOMALY"
    INFO = "INFO"


@dataclass
class Finding:
    layer: str
    rule: str
    severity: str
    detail: str
    tier: SignalTier = SignalTier.HARD_EVIDENCE
    points: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "layer": self.layer,
            "rule": self.rule,
            "severity": self.severity,
            "detail": self.detail,
        }


@dataclass
class CommandClassification:
    """Result of structural classification for a lifecycle/bridged command."""
    kind: str  # "whitelisted_build", "github_release_download", "benign_banner", "local_script", "capability_other", "malicious_inline"
    hard_patterns: List[str] = field(default_factory=list)
    local_js_targets: List[str] = field(default_factory=list)
    local_aux_targets: List[str] = field(default_factory=list)
    inline_js_snippets: List[Tuple[str, str]] = field(default_factory=list)
    detail: str = ""


@dataclass
class Layer1ManifestResult:
    """Structured Layer 1A output carrying both scores/findings and the L1->L2 contract."""
    score: int
    hard_score: int
    capability_score: int
    weak_score: int
    findings: List[Dict[str, Any]]
    has_hard_evidence: bool
    has_install_capability: bool
    has_suspicious_install_hook: bool
    install_entry_files: Set[str] = field(default_factory=set)
    inline_js_snippets: List[Tuple[str, str]] = field(default_factory=list)
    all_hook_commands: List[str] = field(default_factory=list)
    gyp_malicious: bool = False
