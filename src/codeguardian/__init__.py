"""
CodeGuardian — AI Code Trust Verification Platform.

Provides multi-model consensus review, AI trust scoring (0-100),
hallucination detection, security vulnerability scanning, and CI/CD
integration for AI-generated code.

Quick start:
    from codeguardian import TrustScorer, CodeReviewer

    reviewer = CodeReviewer()
    report = await reviewer.review("path/to/file.py")
    print(f"Trust Score: {report.trust_score}/100")
"""

__version__ = "0.1.0"
__author__ = "lanekingkong"

from codeguardian.core.models import ReviewReport, TrustScore, Vulnerability, ScanResult
from codeguardian.core.scanner import SecurityScanner
from codeguardian.core.reviewer import CodeReviewer
from codeguardian.core.trust_scorer import TrustScorer

__all__ = [
    "ReviewReport",
    "TrustScore",
    "Vulnerability",
    "ScanResult",
    "SecurityScanner",
    "CodeReviewer",
    "TrustScorer",
]
