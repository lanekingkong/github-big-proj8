"""
CodeGuardian Trust Engine — unified trust verification pipeline.

The TrustEngine orchestrates the full verification pipeline:
  1. Dependency analysis (known vulnerability checks)
  2. Static security scanning (SAST)
  3. Multi-model AI code review
  4. Composite trust scoring

It is the primary entry point for CI/CD integration and batch operations,
providing a single `verify()` call that returns a complete TrustReport.
"""

from __future__ import annotations

import asyncio
import hashlib
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from codeguardian.core.models import (
    FileLanguage,
    ReviewReport,
    Severity,
    TrustScore,
    Vulnerability,
)
from codeguardian.core.scanner import SecurityScanner
from codeguardian.core.trust_scorer import TrustScorer
from codeguardian.core.reviewer import CodeReviewer
from codeguardian.core.dependency_analyzer import DependencyAnalyzer, DependencyReport


@dataclass
class VerificationResult:
    """Complete result of a trust verification run."""

    file_path: str
    file_hash: str
    language: FileLanguage
    code_length: int

    # Sub-results
    dependency_report: Optional[DependencyReport] = None
    vulnerabilities: list[Vulnerability] = field(default_factory=list)
    review_report: Optional[ReviewReport] = None

    # Scoring
    trust_score: Optional[TrustScore] = None

    # Metadata
    duration_ms: float = 0.0
    engine_version: str = "1.0.0"
    verified_at: str = ""

    @property
    def is_trusted(self) -> bool:
        """Whether the code passes the minimum trust threshold (>= 70)."""
        if self.trust_score is None:
            return False
        return self.trust_score.overall >= 70

    @property
    def critical_count(self) -> int:
        return sum(1 for v in self.vulnerabilities if v.severity == Severity.CRITICAL)

    @property
    def summary(self) -> dict:
        return {
            "file": self.file_path,
            "language": self.language.value if self.language else "unknown",
            "trust_score": self.trust_score.overall if self.trust_score else None,
            "grade": self.trust_score.grade if self.trust_score else "N/A",
            "vulnerabilities": len(self.vulnerabilities),
            "critical": self.critical_count,
            "duration_ms": self.duration_ms,
        }


class TrustEngine:
    """Unified trust verification pipeline for AI-generated code.

    The TrustEngine runs all verification stages in sequence:
      1. Dependency analysis — checks known-vulnerable packages
      2. Security scanning — SAST pattern matching
      3. Multi-model review — AI consensus code review
      4. Trust scoring — composite 0-100 score

    Each stage can be independently enabled/disabled via the config.

    Usage:
        engine = TrustEngine()
        result = await engine.verify(Path("src/app.py"))
        print(f"Trust: {result.trust_score.overall}/100")
        if not result.is_trusted:
            print("Code requires manual review before deployment.")
    """

    def __init__(
        self,
        *,
        enable_dependency_check: bool = True,
        enable_security_scan: bool = True,
        enable_ai_review: bool = True,
        ai_models: Optional[list[str]] = None,
        api_key: Optional[str] = None,
        min_trust_threshold: float = 70.0,
    ):
        self.enable_dependency_check = enable_dependency_check
        self.enable_security_scan = enable_security_scan
        self.enable_ai_review = enable_ai_review
        self.min_trust_threshold = min_trust_threshold

        # Lazy-initialized sub-engines
        self._dep_analyzer: Optional[DependencyAnalyzer] = None
        self._scanner: Optional[SecurityScanner] = None
        self._reviewer: Optional[CodeReviewer] = None
        self._scorer = TrustScorer()
        self._ai_models = ai_models
        self._api_key = api_key

    # ── Public API ──────────────────────────────────────────────────

    async def verify(self, file_path: Path) -> VerificationResult:
        """Run the full trust verification pipeline on a single file.

        Args:
            file_path: Path to source code file to verify.

        Returns:
            VerificationResult with all sub-results and composite trust score.
        """
        start = time.perf_counter()

        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")

        content = file_path.read_text(encoding="utf-8", errors="replace")
        file_hash = hashlib.sha256(content.encode()).hexdigest()
        lang = self._detect_language(file_path)

        result = VerificationResult(
            file_path=str(file_path),
            file_hash=file_hash,
            language=lang,
            code_length=len(content.splitlines()),
            verified_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        )

        # Stage 1: Dependency analysis
        if self.enable_dependency_check:
            result.dependency_report = await self._run_dependency_check(file_path, content)

        # Stage 2: Security scanning
        if self.enable_security_scan:
            result.vulnerabilities = self._run_security_scan(file_path, content)

        # Stage 3: Multi-model AI review
        if self.enable_ai_review:
            result.review_report = await self._run_ai_review(file_path, content, lang)

        # Stage 4: Composite trust scoring
        result.trust_score = self._scorer.compute(
            findings=result.review_report.findings if result.review_report else [],
            vulnerabilities=result.vulnerabilities,
            code_length=result.code_length,
        )

        result.duration_ms = (time.perf_counter() - start) * 1000
        return result

    async def verify_batch(
        self, directory: Path, *, glob_pattern: str = "**/*.py"
    ) -> list[VerificationResult]:
        """Run trust verification on all matching files in a directory.

        Args:
            directory: Root directory to scan.
            glob_pattern: Glob pattern to match files.

        Returns:
            List of VerificationResult sorted by trust score (lowest first).
        """
        files = sorted(directory.glob(glob_pattern))
        results: list[VerificationResult] = []

        for fp in files:
            if fp.is_file():
                try:
                    r = await self.verify(fp)
                    results.append(r)
                except Exception as e:
                    # Log and continue on individual file errors
                    print(f"[WARN] Failed to verify {fp}: {e}")

        # Sort by trust score ascending (riskiest first)
        results.sort(key=lambda r: r.trust_score.overall if r.trust_score else 0)
        return results

    # ── Internal stages ─────────────────────────────────────────────

    def _detect_language(self, file_path: Path) -> FileLanguage:
        """Detect programming language from file extension."""
        ext = file_path.suffix.lower()
        mapping = {
            ".py": FileLanguage.PYTHON,
            ".js": FileLanguage.JAVASCRIPT,
            ".ts": FileLanguage.TYPESCRIPT,
            ".tsx": FileLanguage.TYPESCRIPT,
            ".jsx": FileLanguage.JAVASCRIPT,
            ".go": FileLanguage.GO,
            ".rs": FileLanguage.RUST,
            ".java": FileLanguage.JAVA,
            ".rb": FileLanguage.RUBY,
            ".php": FileLanguage.PHP,
            ".cs": FileLanguage.CSHARP,
            ".c": FileLanguage.C,
            ".cpp": FileLanguage.CPP,
            ".h": FileLanguage.C,
            ".hpp": FileLanguage.CPP,
            ".sql": FileLanguage.SQL,
            ".sh": FileLanguage.SHELL,
            ".bash": FileLanguage.SHELL,
            ".ps1": FileLanguage.SHELL,
            ".yaml": FileLanguage.YAML,
            ".yml": FileLanguage.YAML,
            ".json": FileLanguage.JSON,
            ".toml": FileLanguage.TOML,
            ".dockerfile": FileLanguage.DOCKERFILE,
        }
        return mapping.get(ext, FileLanguage.UNKNOWN)

    async def _run_dependency_check(
        self, file_path: Path, content: str
    ) -> Optional[DependencyReport]:
        """Run dependency vulnerability analysis."""
        if self._dep_analyzer is None:
            self._dep_analyzer = DependencyAnalyzer()
        try:
            return await self._dep_analyzer.analyze(file_path, content)
        except Exception as e:
            print(f"[WARN] Dependency check failed for {file_path}: {e}")
            return None

    def _run_security_scan(
        self, file_path: Path, content: str
    ) -> list[Vulnerability]:
        """Run static security analysis."""
        if self._scanner is None:
            self._scanner = SecurityScanner()
        try:
            return self._scanner.scan_file(file_path, content)
        except Exception as e:
            print(f"[WARN] Security scan failed for {file_path}: {e}")
            return []

    async def _run_ai_review(
        self, file_path: Path, content: str, language: FileLanguage
    ) -> Optional[ReviewReport]:
        """Run multi-model AI code review."""
        if self._reviewer is None:
            self._reviewer = CodeReviewer(
                models=self._ai_models,
                api_key=self._api_key,
            )
        try:
            return await self._reviewer.review(
                file_path=file_path,
                content=content,
                language=language,
            )
        except Exception as e:
            print(f"[WARN] AI review failed for {file_path}: {e}")
            return None


# ── Convenience function ─────────────────────────────────────────

async def verify_code(
    file_path: Path,
    *,
    enable_ai: bool = True,
    api_key: Optional[str] = None,
) -> VerificationResult:
    """Quick one-shot trust verification for a single file.

    Args:
        file_path: Source file to verify.
        enable_ai: Whether to run multi-model AI review.
        api_key: API key for AI review (OpenRouter-compatible).

    Returns:
        VerificationResult with trust score and findings.
    """
    engine = TrustEngine(
        enable_dependency_check=True,
        enable_security_scan=True,
        enable_ai_review=enable_ai,
        api_key=api_key,
    )
    return await engine.verify(file_path)
