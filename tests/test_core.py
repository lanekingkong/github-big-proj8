"""Tests for CodeGuardian core modules."""

import json
import tempfile
from pathlib import Path

import pytest

from codeguardian.core.models import (
    Severity,
    TrustScore,
    Vulnerability,
    VulnerabilityCategory,
    ReviewFinding,
    ReviewCategory,
    ReviewReport,
    FileLanguage,
)
from codeguardian.core.scanner import SecurityScanner
from codeguardian.core.trust_scorer import TrustScorer
from codeguardian.core.reviewer import CodeReviewer


# ── Model Tests ─────────────────────────────────────────────────

class TestModels:
    def test_trust_score_grade(self):
        assert TrustScore(overall=95).grade == "A"
        assert TrustScore(overall=85).grade == "B"
        assert TrustScore(overall=70).grade == "C"
        assert TrustScore(overall=50).grade == "D"
        assert TrustScore(overall=30).grade == "F"

    def test_trust_score_bounds(self):
        ts = TrustScore(overall=100, security_score=90, hallucination_risk=5)
        assert 0 <= ts.overall <= 100

    def test_review_report_passed(self):
        report = ReviewReport(
            report_id="test-001",
            target="test.py",
            trust_score=TrustScore(overall=85),
            findings=[],
            vulnerabilities=[],
        )
        assert report.passed is True

        report_fail = ReviewReport(
            report_id="test-002",
            target="test.py",
            trust_score=TrustScore(overall=50),
            findings=[],
            vulnerabilities=[
                Vulnerability(
                    id="v1",
                    category=VulnerabilityCategory.INJECTION,
                    severity=Severity.CRITICAL,
                    title="SQL Injection",
                )
            ],
        )
        assert report_fail.passed is False

    def test_vulnerability_serialization(self):
        v = Vulnerability(
            id="V-001",
            category=VulnerabilityCategory.SENSITIVE_DATA,
            severity=Severity.HIGH,
            title="Hardcoded API Key",
            file_path="config.py",
            line_start=42,
        )
        d = v.model_dump()
        assert d["severity"] == "high"
        assert d["category"] == "sensitive_data"


# ── Scanner Tests ────────────────────────────────────────────────

class TestSecurityScanner:
    def test_detect_sql_injection(self):
        scanner = SecurityScanner()
        code = 'cursor = db.cursor()\ncursor.execute(f"SELECT * FROM users WHERE id = {user_id}")'
        vulns = scanner.scan_text(code, language=FileLanguage.PYTHON, file_path="test.py")
        sql_vulns = [v for v in vulns if "SQL" in v.title]
        assert len(sql_vulns) > 0
        assert sql_vulns[0].severity == Severity.CRITICAL

    def test_detect_hardcoded_secret(self):
        scanner = SecurityScanner()
        code = 'API_KEY = "sk-abc123def456"'
        vulns = scanner.scan_text(code, language=FileLanguage.PYTHON, file_path="config.py")
        secrets = [v for v in vulns if "Hardcoded" in v.title or "Secret" in v.title]
        assert len(secrets) > 0

    def test_detect_eval(self):
        scanner = SecurityScanner()
        code = 'result = eval(user_input)'
        vulns = scanner.scan_text(code, language=FileLanguage.PYTHON, file_path="app.py")
        eval_vulns = [v for v in vulns if "eval" in v.title.lower()]
        assert len(eval_vulns) > 0

    def test_detect_xss(self):
        scanner = SecurityScanner()
        code = 'document.getElementById("output").innerHTML = userInput;'
        vulns = scanner.scan_text(code, language=FileLanguage.JAVASCRIPT, file_path="app.js")
        xss_vulns = [v for v in vulns if "XSS" in v.title.upper() or "Cross-Site" in v.title]
        assert len(xss_vulns) > 0

    def test_detect_pickle(self):
        scanner = SecurityScanner()
        code = 'import pickle\ndata = pickle.loads(untrusted_data)'
        vulns = scanner.scan_text(code, language=FileLanguage.PYTHON, file_path="loader.py")
        deser = [v for v in vulns if "Deserializ" in v.title]
        assert len(deser) > 0

    def test_clean_code_no_vulns(self):
        scanner = SecurityScanner()
        code = '''
def add(a: int, b: int) -> int:
    """Add two numbers."""
    return a + b

def greet(name: str) -> str:
    return f"Hello, {name}!"
'''
        vulns = scanner.scan_text(code, language=FileLanguage.PYTHON, file_path="utils.py")
        critical_high = [v for v in vulns if v.severity in (Severity.CRITICAL, Severity.HIGH)]
        assert len(critical_high) == 0

    def test_scan_file(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write('password = "super_secret_123"')
            f.flush()
            scanner = SecurityScanner()
            vulns = scanner.scan_file(f.name)
            assert len(vulns) > 0
        Path(f.name).unlink(missing_ok=True)

    def test_language_detection(self):
        assert SecurityScanner._detect_language("app.py") == FileLanguage.PYTHON
        assert SecurityScanner._detect_language("script.js") == FileLanguage.JAVASCRIPT
        assert SecurityScanner._detect_language("main.go") == FileLanguage.GO
        assert SecurityScanner._detect_language("Dockerfile") == FileLanguage.DOCKERFILE

    def test_severity_ordering(self):
        scanner = SecurityScanner()
        code = 'password = "secret123"\nexpected = eval(user_input)'
        vulns = scanner.scan_text(code, language=FileLanguage.PYTHON, file_path="bad.py")
        severities = [v.severity.value for v in vulns]
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        for i in range(len(severities) - 1):
            assert order[severities[i]] <= order[severities[i + 1]]


# ── Trust Scorer Tests ───────────────────────────────────────────

class TestTrustScorer:
    def test_perfect_score(self):
        scorer = TrustScorer()
        score = scorer.compute(findings=[], vulnerabilities=[], code_length=100, has_tests=True, has_docs=True)
        assert score.overall > 90
        assert score.grade == "A"

    def test_critical_vuln_drops_score(self):
        scorer = TrustScorer()
        findings = [
            ReviewFinding(
                category=ReviewCategory.SECURITY,
                severity=Severity.CRITICAL,
                title="Critical issue",
                description="Bad",
            )
        ]
        score = scorer.compute(findings=findings, vulnerabilities=[], code_length=100)
        assert score.overall < 75

    def test_multiple_findings(self):
        scorer = TrustScorer()
        findings = [
            ReviewFinding(category=ReviewCategory.CORRECTNESS, severity=Severity.MEDIUM, title="Issue 1"),
            ReviewFinding(category=ReviewCategory.BEST_PRACTICES, severity=Severity.LOW, title="Issue 2"),
            ReviewFinding(category=ReviewCategory.BEST_PRACTICES, severity=Severity.LOW, title="Issue 3"),
        ]
        score = scorer.compute(findings=findings, vulnerabilities=[], code_length=200)
        assert 50 < score.overall < 90

    def test_long_code_penalty(self):
        scorer = TrustScorer()
        score_short = scorer.compute(findings=[], vulnerabilities=[], code_length=30)
        score_long = scorer.compute(findings=[], vulnerabilities=[], code_length=2000)
        assert score_short.overall > score_long.overall

    def test_compare_scores(self):
        scorer = TrustScorer()
        scores = [
            scorer.compute(findings=[], vulnerabilities=[], code_length=50),
            scorer.compute(
                findings=[
                    ReviewFinding(category=ReviewCategory.SECURITY, severity=Severity.CRITICAL, title="Bad")
                ],
                vulnerabilities=[],
                code_length=50,
            ),
        ]
        result = scorer.compare(scores, labels=["Good", "Bad"])
        assert result["best"] == 0
        assert result["average"] < 100


# ── Code Reviewer Tests ──────────────────────────────────────────

class TestCodeReviewer:
    @pytest.mark.asyncio
    async def test_review_clean_code(self):
        reviewer = CodeReviewer()
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write('''
def fibonacci(n: int) -> int:
    """Return the nth Fibonacci number."""
    if n <= 1:
        return n
    return fibonacci(n - 1) + fibonacci(n - 2)
''')
            f.flush()
            report = await reviewer.review(f.name)
            assert report.trust_score.overall >= 60
            assert len(report.findings) >= 0
        Path(f.name).unlink(missing_ok=True)

    @pytest.mark.asyncio
    async def test_review_inline_code(self):
        reviewer = CodeReviewer()
        code = 'password = "admin123"\neval(user_input)'
        report = await reviewer.review(code)
        assert report.trust_score.overall < 80
        assert report.finding_count > 0

    @pytest.mark.asyncio
    async def test_review_context_consistency(self):
        reviewer = CodeReviewer()
        code = "import django\nfrom django.db import models"
        context = "This project uses FastAPI"
        report = await reviewer.review(code, context=context)
        assert report.trust_score.consistency_score < 100

    @pytest.mark.asyncio
    async def test_review_report_structure(self):
        reviewer = CodeReviewer()
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write('print("Hello World")')
            f.flush()
            report = await reviewer.review(f.name)
            assert report.report_id
            assert report.trust_score is not None
            assert isinstance(report.models_consulted, list)
            assert report.review_duration_ms >= 0
        Path(f.name).unlink(missing_ok=True)

    @pytest.mark.asyncio
    async def test_review_nonexistent_file(self):
        reviewer = CodeReviewer()
        report = await reviewer.review("nonexistent_file_12345.py")
        assert report is not None
        assert report.target == "<inline>"
