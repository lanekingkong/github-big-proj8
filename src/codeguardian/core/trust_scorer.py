"""
CodeGuardian Trust Scorer — quantitative AI code trust scoring engine.

Computes a multidimensional trust score (0-100) for AI-generated code
based on security, correctness, context consistency, dependency health,
and hallucination risk indicators.
"""

from __future__ import annotations

from codeguardian.core.models import (
    ReviewFinding,
    Severity,
    TrustScore,
    Vulnerability,
)


class TrustScorer:
    """Computes quantitative trust scores for code submissions.

    Usage:
        scorer = TrustScorer()
        score = scorer.compute(findings=findings, vulnerabilities=vulns, code_length=200)
        print(f"Trust: {score.overall}/100, Grade: {score.grade}")
    """

    # Scoring weights
    WEIGHTS = {
        "security": 0.35,
        "correctness": 0.25,
        "consistency": 0.15,
        "hallucination": 0.15,
        "dependencies": 0.10,
    }

    SEVERITY_DEDUCTION = {
        Severity.CRITICAL: 25.0,
        Severity.HIGH: 15.0,
        Severity.MEDIUM: 8.0,
        Severity.LOW: 3.0,
        Severity.INFO: 1.0,
    }

    def compute(
        self,
        *,
        findings: list[ReviewFinding],
        vulnerabilities: list[Vulnerability],
        code_length: int = 0,
        has_tests: bool = False,
        has_docs: bool = False,
    ) -> TrustScore:
        """Compute a comprehensive trust score.

        Parameters
        ----------
        findings : list[ReviewFinding]
            Review findings from all models.
        vulnerabilities : list[Vulnerability]
            Security vulnerabilities found.
        code_length : int
            Number of lines of code.
        has_tests : bool
            Whether tests exist for this code.
        has_docs : bool
            Whether documentation exists for this code.
        """
        # Security sub-score
        security_deduct = sum(
            self.SEVERITY_DEDUCTION.get(v.severity, 2.0)
            for v in vulnerabilities
        )
        security_deduct += sum(
            self.SEVERITY_DEDUCTION.get(f.severity, 2.0)
            for f in findings
            if f.category.value == "security"
        )
        security_score = max(0.0, 100.0 - security_deduct)

        # Correctness sub-score
        correctness_deduct = sum(
            self.SEVERITY_DEDUCTION.get(f.severity, 2.0)
            for f in findings
            if f.category.value in ("correctness", "logic_flaw")
        )
        correctness_score = max(0.0, 100.0 - correctness_deduct)

        # Consistency sub-score
        consistency_deduct = sum(
            self.SEVERITY_DEDUCTION.get(f.severity, 2.0)
            for f in findings
            if f.category.value == "context_consistency"
        )
        consistency_score = max(0.0, 100.0 - consistency_deduct)

        # Hallucination risk
        hallucination_deduct = sum(
            self.SEVERITY_DEDUCTION.get(f.severity, 2.0)
            for f in findings
            if f.category.value == "hallucination"
        )
        # Bonus for having tests/documents (they reduce hallucination risk perception)
        if has_tests:
            hallucination_deduct = max(0.0, hallucination_deduct - 5.0)
        if has_docs:
            hallucination_deduct = max(0.0, hallucination_deduct - 3.0)

        # Dependency risk
        dependency_deduct = sum(
            self.SEVERITY_DEDUCTION.get(v.severity, 2.0)
            for v in vulnerabilities
            if hasattr(v, "category") and getattr(v, "category", None) and
            getattr(v, "category").value == "dependency"
        )

        # Code length bonus: small code is easier to review, large code is riskier
        length_bonus = 0.0
        if code_length > 0:
            if code_length < 50:
                length_bonus = 5.0
            elif code_length > 1000:
                length_bonus = -3.0

        # Weighted overall
        sub_scores = {
            "security": security_score,
            "correctness": correctness_score,
            "consistency": consistency_score,
            "hallucination": max(0.0, 100.0 - hallucination_deduct),
            "dependencies": max(0.0, 100.0 - dependency_deduct),
        }

        overall = sum(
            sub_scores[k] * self.WEIGHTS[k]
            for k in self.WEIGHTS
        ) + length_bonus

        overall = max(0.0, min(100.0, overall))

        # Generate comment
        comment = self._generate_comment(overall, security_score, hallucination_deduct)

        return TrustScore(
            overall=round(overall, 1),
            security_score=round(security_score, 1),
            correctness_score=round(correctness_score, 1),
            consistency_score=round(consistency_score, 1),
            hallucination_risk=round(min(100.0, hallucination_deduct), 1),
            dependency_risk=round(min(100.0, dependency_deduct), 1),
            comment=comment,
        )

    @staticmethod
    def _generate_comment(overall: float, security: float, hallucination: float) -> str:
        """Generate a human-readable comment for the trust score."""
        if overall >= 95:
            return "Excellent. Code is production-ready with minimal risk."
        if overall >= 85:
            return "Good. Code is safe to deploy with minor improvements recommended."
        if overall >= 70:
            return "Fair. Review recommended — some issues need attention before production."
        if overall >= 50:
            return "Concerning. Multiple issues detected; not recommended for production without fixes."
        return "Unsafe. Critical issues found. Do NOT deploy. Requires major refactoring."

    def compare(
        self,
        scores: list[TrustScore],
        labels: list[str] = None,
    ) -> dict:
        """Compare multiple trust scores side by side."""
        result = {
            "scores": [
                {"label": labels[i] if labels else f"Submission {i+1}", "score": s}
                for i, s in enumerate(scores)
            ],
            "best": max(
                range(len(scores)),
                key=lambda i: scores[i].overall,
            ),
            "average": sum(s.overall for s in scores) / len(scores) if scores else 0.0,
        }
        return result
