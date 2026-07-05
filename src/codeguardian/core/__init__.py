"""CodeGuardian core module — trust engine, review engine, scanner, dependency analyzer, and trust scorer."""

from codeguardian.core.models import (
    TrustScore,
    Vulnerability,
    VulnerabilityCategory,
    Severity,
    ReviewFinding,
    ReviewCategory,
    ReviewReport,
    FileLanguage,
)
from codeguardian.core.scanner import SecurityScanner
from codeguardian.core.trust_scorer import TrustScorer
from codeguardian.core.reviewer import CodeReviewer
from codeguardian.core.dependency_analyzer import (
    DependencyAnalyzer,
    DependencyReport,
    DependencyEntry,
    DependencyIssue,
    DependencyRisk,
)
from codeguardian.core.trust_engine import TrustEngine, VerificationResult, verify_code

__all__ = [
    # Models
    "TrustScore",
    "Vulnerability",
    "VulnerabilityCategory",
    "Severity",
    "ReviewFinding",
    "ReviewCategory",
    "ReviewReport",
    "FileLanguage",
    # Engines
    "SecurityScanner",
    "TrustScorer",
    "CodeReviewer",
    "DependencyAnalyzer",
    "TrustEngine",
    # Results
    "VerificationResult",
    "DependencyReport",
    "DependencyEntry",
    "DependencyIssue",
    "DependencyRisk",
    # Convenience
    "verify_code",
]
