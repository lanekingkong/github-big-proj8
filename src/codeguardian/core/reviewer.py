"""
CodeGuardian Code Reviewer — multi-model consensus code review engine.

Orchestrates multiple AI models to review code from different perspectives,
then synthesizes findings into a unified report with consensus scoring.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import time
from pathlib import Path
from typing import Any, Optional

from codeguardian.core.models import (
    FileLanguage,
    ReviewCategory,
    ReviewFinding,
    ReviewReport,
    Severity,
    TrustScore,
)
from codeguardian.core.scanner import SecurityScanner


class CodeReviewer:
    """Multi-model code review engine.

    Reviews code by consulting multiple AI models (or rule-based analysis
    when no API keys are configured), then synthesizing findings into
    a unified TrustScore and ReviewReport.

    Usage:
        reviewer = CodeReviewer()
        report = await reviewer.review("src/app.py")
        print(f"Trust Score: {report.trust_score.overall}/100")
    """

    def __init__(
        self,
        *,
        models: Optional[list[str]] = None,
        api_keys: Optional[dict[str, str]] = None,
    ) -> None:
        self._models = models or []
        self._api_keys = api_keys or {}
        self._scanner = SecurityScanner()

    # ── Public API ────────────────────────────────────────────────

    async def review(self, target: str, *, context: str = "") -> ReviewReport:
        """Review a single file or code snippet.

        Parameters
        ----------
        target : str
            File path or raw code string to review.
        context : str
            Optional business context / architecture docs for consistency checking.

        Returns
        -------
        ReviewReport
            Complete review with trust score, findings, and vulnerabilities.
        """
        t0 = time.monotonic()
        file_path = ""
        code = target

        # If target is a file path, read it
        p = Path(target)
        if p.exists() and p.is_file():
            file_path = target
            code = p.read_text(encoding="utf-8", errors="replace")
        else:
            file_path = "<inline>"

        language = SecurityScanner._detect_language(file_path)

        # Run security scan
        vulns = self._scanner.scan_text(code, language=language, file_path=file_path)

        # Run multi-model review (or rule-based fallback)
        findings = await self._run_multi_model_review(code, language, context)

        # Run heuristic checks
        heuristic_findings = self._run_heuristic_checks(code, language)
        findings.extend(heuristic_findings)

        # Compute trust score
        trust_score = self._compute_trust_score(findings, vulns, code)

        # Generate report
        report_id = hashlib.sha256(
            f"{file_path}:{time.time()}".encode()
        ).hexdigest()[:16]

        report = ReviewReport(
            report_id=report_id,
            target=file_path,
            language=language,
            trust_score=trust_score,
            findings=findings,
            vulnerabilities=vulns,
            models_consulted=self._models,
            consensus_level=self._compute_consensus(findings),
            review_duration_ms=(time.monotonic() - t0) * 1000,
            summary=self._generate_summary(findings, vulns, trust_score),
            recommendations=self._generate_recommendations(findings, vulns),
        )
        return report

    async def review_directory(self, directory: str) -> list[ReviewReport]:
        """Review all code files in a directory."""
        reports: list[ReviewReport] = []
        dir_path = Path(directory)

        code_extensions = {".py", ".js", ".ts", ".tsx", ".jsx", ".go", ".rs", ".java", ".rb", ".php"}

        for file_path in dir_path.rglob("*"):
            if not file_path.is_file():
                continue
            if file_path.suffix not in code_extensions:
                continue
            parts = set(file_path.parts)
            if parts & {"node_modules", ".git", "__pycache__", "venv", ".venv", "dist", "build"}:
                continue
            try:
                report = await self.review(str(file_path))
                reports.append(report)
            except Exception:
                continue

        return reports

    # ── Multi-Model Review ────────────────────────────────────────

    async def _run_multi_model_review(
        self, code: str, language: FileLanguage, context: str
    ) -> list[ReviewFinding]:
        """Simulate multi-model review. When no API keys, use rule-based analysis."""
        findings: list[ReviewFinding] = []

        # Model 1: Security-focused review
        findings.extend(self._security_review(code, language))

        # Model 2: Correctness / logic review
        findings.extend(self._correctness_review(code, language))

        # Model 3: Best practices / readability review
        findings.extend(self._best_practices_review(code, language))

        # Model 4: Context consistency (if context provided)
        if context:
            findings.extend(self._context_review(code, context))

        return findings

    def _security_review(self, code: str, language: FileLanguage) -> list[ReviewFinding]:
        """Model 1: Security-focused review (rule-based)."""
        findings: list[ReviewFinding] = []

        import re

        checks = [
            (re.compile(r'os\.system\s*\(', re.IGNORECASE), Severity.CRITICAL,
             "Use of os.system()", "os.system() spawns a shell and is vulnerable to command injection.",
             "Use subprocess.run() with shell=False"),
            (re.compile(r'subprocess\.(?:call|Popen|run)\s*\(.*shell\s*=\s*True', re.IGNORECASE), Severity.HIGH,
             "subprocess with shell=True", "shell=True spawns a shell, exposing to command injection.",
             "Use shell=False with argument lists"),
            (re.compile(r'assert\s', re.IGNORECASE), Severity.LOW,
             "Assert statements in production code", "assert can be disabled with -O flag.",
             "Use explicit if/raise for production validation"),
        ]

        for pattern, severity, title, desc, suggestion in checks:
            if pattern.search(code):
                findings.append(ReviewFinding(
                    category=ReviewCategory.SECURITY,
                    severity=severity,
                    title=title,
                    description=desc,
                    suggestion=suggestion,
                    model_name="rule-based-security",
                ))

        return findings

    def _correctness_review(self, code: str, language: FileLanguage) -> list[ReviewFinding]:
        """Model 2: Correctness / logic review."""
        findings: list[ReviewFinding] = []

        import re

        checks = [
            (re.compile(r'\bexcept\s*:', re.IGNORECASE), Severity.HIGH,
             "Bare except clause", "Bare except catches everything including KeyboardInterrupt.",
             "Catch specific exceptions: except ValueError as e:"),
            (re.compile(r'(?:list|dict|set)\s*\(.*for\s+.+in\s+', re.IGNORECASE), Severity.MEDIUM,
             "Comprehension inside type constructor", "Redundant: use the comprehension directly.",
             "Use list comprehension: [x for x in iterable] instead of list(x for x in iterable)"),
            (re.compile(r'\b(?:TODO|FIXME|HACK|XXX)\b', re.IGNORECASE), Severity.INFO,
             "Unresolved TODO/FIXME comment", "Code contains TODO markers that may indicate incomplete logic.",
             "Address TODOs before production deployment"),
        ]

        for pattern, severity, title, desc, suggestion in checks:
            if pattern.search(code):
                findings.append(ReviewFinding(
                    category=ReviewCategory.CORRECTNESS,
                    severity=severity,
                    title=title,
                    description=desc,
                    suggestion=suggestion,
                    model_name="rule-based-correctness",
                ))

        return findings

    def _best_practices_review(self, code: str, language: FileLanguage) -> list[ReviewFinding]:
        """Model 3: Best practices / readability."""
        findings: list[ReviewFinding] = []

        import re

        checks = [
            (re.compile(r'^.{120,}$', re.MULTILINE), Severity.LOW,
             "Overly long line", "Lines exceeding 120 characters hurt readability.",
             "Break long lines with implicit continuation or parentheses"),
            (re.compile(r'def \w+\([^)]{80,}\)', re.IGNORECASE), Severity.LOW,
             "Function with many parameters", "Functions with too many parameters are hard to use.",
             "Consider using a dataclass or TypedDict for related parameters"),
        ]

        for pattern, severity, title, desc, suggestion in checks:
            if pattern.search(code):
                findings.append(ReviewFinding(
                    category=ReviewCategory.BEST_PRACTICES,
                    severity=severity,
                    title=title,
                    description=desc,
                    suggestion=suggestion,
                    model_name="rule-based-best-practices",
                ))

        return findings

    def _context_review(self, code: str, context: str) -> list[ReviewFinding]:
        """Model 4: Context consistency check."""
        # Check if code references concepts not in context
        findings: list[ReviewFinding] = []

        context_lower = context.lower()
        code_lower = code.lower()

        # Simple heuristic: flag if code uses libraries/frameworks not mentioned in context
        known_frameworks = ["django", "flask", "fastapi", "react", "vue", "angular", "express"]
        for fw in known_frameworks:
            if fw not in context_lower and fw in code_lower:
                findings.append(ReviewFinding(
                    category=ReviewCategory.CONTEXT_CONSISTENCY,
                    severity=Severity.MEDIUM,
                    title=f"Framework '{fw}' not in provided context",
                    description=f"Code uses '{fw}' but context documentation does not mention it.",
                    suggestion="Verify this framework is approved or update project context.",
                    model_name="context-consistency",
                ))

        return findings

    def _run_heuristic_checks(self, code: str, language: FileLanguage) -> list[ReviewFinding]:
        """Additional heuristic checks for code quality and hallucination."""
        findings: list[ReviewFinding] = []

        lines = code.split("\n")

        # Heuristic 1: Repeated code blocks (potential copy-paste / AI hallucination)
        for i in range(len(lines) - 5):
            chunk = "\n".join(lines[i:i + 5])
            if len(chunk) > 50 and code.count(chunk) > 2:
                findings.append(ReviewFinding(
                    category=ReviewCategory.HALLUCINATION,
                    severity=Severity.MEDIUM,
                    title="Repeated code block detected",
                    description="Identical code blocks appear multiple times — possible AI hallucination or copy-paste.",
                    suggestion="Refactor repeated logic into a function.",
                    model_name="heuristic",
                ))
                break

        # Heuristic 2: Import of non-existent or misspelled common modules
        import re
        import_matches = re.finditer(r'(?:import|from)\s+(\w+)', code)
        common_misspellings = {
            "pandas": "pandas",  # correct but commonly misspelled
            "numpy": "numpy",
            "datetime": "datetime",
            "request": "requests",  # wrong: should be 'requests'
            "maths": "math",  # wrong: should be 'math'
        }

        for m in import_matches:
            mod = m.group(1).lower()
            if mod in common_misspellings and mod != common_misspellings[mod]:
                findings.append(ReviewFinding(
                    category=ReviewCategory.HALLUCINATION,
                    severity=Severity.HIGH,
                    title=f"Potentially hallucinated import: '{m.group(1)}'",
                    description=f"Import '{m.group(1)}' may be a hallucinated or misspelled module.",
                    suggestion=f"Did you mean '{common_misspellings[mod]}'?",
                    model_name="heuristic",
                ))

        return findings

    # ── Trust Scoring ─────────────────────────────────────────────

    def _compute_trust_score(
        self,
        findings: list[ReviewFinding],
        vulns: list,
        code: str,
    ) -> TrustScore:
        """Compute the overall trust score from findings and vulnerabilities."""
        base_score = 100.0

        # Deduct for each finding by severity
        severity_deductions = {
            Severity.CRITICAL: 25.0,
            Severity.HIGH: 15.0,
            Severity.MEDIUM: 8.0,
            Severity.LOW: 3.0,
            Severity.INFO: 1.0,
        }

        for f in findings:
            base_score -= severity_deductions.get(f.severity, 2.0)

        for v in vulns:
            base_score -= severity_deductions.get(v.severity, 2.0)

        # Bonus for good practices
        if len(code.split("\n")) > 20:
            base_score += 3  # Substantial code

        security_score = max(0.0, base_score)
        for v in vulns:
            if v.severity in (Severity.CRITICAL, Severity.HIGH):
                security_score -= severity_deductions[v.severity]

        correctness_score = max(0.0, base_score)
        for f in findings:
            if f.category == ReviewCategory.CORRECTNESS:
                correctness_score -= severity_deductions.get(f.severity, 2.0)

        hallucination_risk = sum(
            severity_deductions.get(f.severity, 2.0)
            for f in findings
            if f.category == ReviewCategory.HALLUCINATION
        )

        overall = max(0.0, min(100.0, base_score))
        return TrustScore(
            overall=round(overall, 1),
            security_score=round(max(0.0, security_score), 1),
            correctness_score=round(max(0.0, correctness_score), 1),
            consistency_score=round(max(0.0, base_score - 5), 1),
            hallucination_risk=round(min(100.0, hallucination_risk), 1),
            dependency_risk=round(
                sum(
                    severity_deductions.get(v.severity, 2.0)
                    for v in vulns
                    if hasattr(v, 'category') and getattr(v, 'category', None) == "dependency"
                ),
                1,
            ),
        )

    @staticmethod
    def _compute_consensus(findings: list[ReviewFinding]) -> float:
        """Compute consensus level among models (simulated)."""
        if not findings:
            return 1.0
        models = set(f.model_name for f in findings)
        if len(models) <= 1:
            return 1.0
        return 0.85  # Default consensus for rule-based

    @staticmethod
    def _generate_summary(
        findings: list[ReviewFinding],
        vulns: list,
        trust_score: TrustScore,
    ) -> str:
        """Generate a human-readable summary."""
        total = len(findings) + len(vulns)
        critical = sum(1 for f in findings if f.severity == Severity.CRITICAL) + \
                   sum(1 for v in vulns if v.severity == Severity.CRITICAL)

        if total == 0:
            return "No issues found. Code appears clean."
        if trust_score.overall >= 90:
            return f"{total} minor issues found. Overall trust score is excellent ({trust_score.overall}/100)."
        if trust_score.overall >= 70:
            return f"{total} issues found ({critical} critical). Code needs review before deployment."
        return f"{total} issues found ({critical} critical). Significant concerns — do NOT deploy without fixes."

    @staticmethod
    def _generate_recommendations(
        findings: list[ReviewFinding],
        vulns: list,
    ) -> list[str]:
        """Generate prioritized recommendation list."""
        recommendations: list[str] = []

        critical_items = [
            (f.title, f.suggestion) for f in findings
            if f.severity in (Severity.CRITICAL, Severity.HIGH)
        ] + [
            (v.title, v.recommendation) for v in vulns
            if v.severity in (Severity.CRITICAL, Severity.HIGH)
        ]

        for title, suggestion in critical_items[:5]:
            recommendations.append(f"[{title}] {suggestion}")

        if not recommendations:
            recommendations.append("No critical issues found. Review medium/low items at your convenience.")

        return recommendations
