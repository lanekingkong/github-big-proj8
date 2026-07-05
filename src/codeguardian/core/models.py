"""
CodeGuardian Domain Models — core data structures for code review and trust scoring.

Defines the canonical schemas for vulnerabilities, trust scores,
review reports, and scan results.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field, field_validator


class Severity(str, Enum):
    """Vulnerability severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class VulnerabilityCategory(str, Enum):
    """Categories of code vulnerabilities."""
    INJECTION = "injection"
    AUTHENTICATION = "authentication"
    SENSITIVE_DATA = "sensitive_data"
    XXE = "xxe"
    ACCESS_CONTROL = "access_control"
    SECURITY_MISCONFIG = "security_misconfig"
    XSS = "xss"
    DESERIALIZATION = "deserialization"
    KNOWN_CVE = "known_cve"
    DEPENDENCY = "dependency"
    HALLUCINATION = "hallucination"
    LOGIC_FLAW = "logic_flaw"
    OTHER = "other"


class ReviewCategory(str, Enum):
    """Aspects of code review."""
    SECURITY = "security"
    PERFORMANCE = "performance"
    READABILITY = "readability"
    MAINTAINABILITY = "maintainability"
    CORRECTNESS = "correctness"
    BEST_PRACTICES = "best_practices"
    HALLUCINATION = "hallucination"
    CONTEXT_CONSISTENCY = "context_consistency"


class FileLanguage(str, Enum):
    """Programming languages supported for review."""
    PYTHON = "python"
    JAVASCRIPT = "javascript"
    TYPESCRIPT = "typescript"
    GO = "go"
    RUST = "rust"
    JAVA = "java"
    CPP = "cpp"
    CSHARP = "csharp"
    RUBY = "ruby"
    PHP = "php"
    SWIFT = "swift"
    KOTLIN = "kotlin"
    SQL = "sql"
    SHELL = "shell"
    YAML = "yaml"
    DOCKERFILE = "dockerfile"
    OTHER = "other"


class Vulnerability(BaseModel):
    """A single detected vulnerability or code issue."""

    id: str = Field(..., description="Unique vulnerability identifier")
    category: VulnerabilityCategory
    severity: Severity
    title: str = Field(..., min_length=1, max_length=256)
    description: str = Field(default="", max_length=2048)
    file_path: str = ""
    line_start: int = 0
    line_end: int = 0
    code_snippet: str = ""
    recommendation: str = ""
    cwe_id: Optional[str] = None
    cve_id: Optional[str] = None
    cvss_score: Optional[float] = None
    false_positive_probability: float = Field(default=0.0, ge=0.0, le=1.0)
    references: list[str] = Field(default_factory=list)

    @field_validator("cvss_score")
    @classmethod
    def cvss_range(cls, v: Optional[float]) -> Optional[float]:
        if v is not None and not (0.0 <= v <= 10.0):
            raise ValueError("CVSS score must be between 0.0 and 10.0")
        return v


class TrustScore(BaseModel):
    """AI-generated code trust score (0-100) with breakdown."""

    overall: float = Field(..., ge=0.0, le=100.0, description="Overall trust score")
    security_score: float = Field(default=0.0, ge=0.0, le=100.0)
    correctness_score: float = Field(default=0.0, ge=0.0, le=100.0)
    consistency_score: float = Field(default=0.0, ge=0.0, le=100.0)
    hallucination_risk: float = Field(default=0.0, ge=0.0, le=100.0, description="Hallucination risk (lower is better)")
    dependency_risk: float = Field(default=0.0, ge=0.0, le=100.0)
    comment: str = ""

    @property
    def grade(self) -> str:
        if self.overall >= 90:
            return "A"
        if self.overall >= 75:
            return "B"
        if self.overall >= 60:
            return "C"
        if self.overall >= 40:
            return "D"
        return "F"


class ReviewFinding(BaseModel):
    """A single finding from a code review."""

    category: ReviewCategory
    severity: Severity
    title: str
    description: str = ""
    file_path: str = ""
    line_range: str = ""
    suggestion: str = ""
    model_name: str = ""  # Which AI model generated this finding


class ReviewReport(BaseModel):
    """Complete code review report for a single file or changeset."""

    report_id: str
    target: str = Field(..., description="File path or changeset identifier")
    language: FileLanguage = FileLanguage.OTHER
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    trust_score: TrustScore
    findings: list[ReviewFinding] = Field(default_factory=list)
    vulnerabilities: list[Vulnerability] = Field(default_factory=list)
    models_consulted: list[str] = Field(default_factory=list, description="AI models that participated")
    consensus_level: float = Field(default=0.0, ge=0.0, le=1.0, description="Consensus among models")
    review_duration_ms: float = 0.0
    summary: str = ""
    recommendations: list[str] = Field(default_factory=list)

    @property
    def finding_count(self) -> int:
        return len(self.findings) + len(self.vulnerabilities)

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL) + \
               sum(1 for v in self.vulnerabilities if v.severity == Severity.CRITICAL)

    @property
    def passed(self) -> bool:
        return self.trust_score.overall >= 70 and self.critical_count == 0


class ScanResult(BaseModel):
    """Aggregated scan result for a repository or batch of files."""

    scan_id: str
    target_path: str
    files_scanned: int = 0
    files_reviewed: int = 0
    total_findings: int = 0
    critical_count: int = 0
    high_count: int = 0
    average_trust_score: float = 0.0
    reports: list[ReviewReport] = Field(default_factory=list)
    started_at: str = ""
    completed_at: str = ""
    duration_seconds: float = 0.0

    @property
    def summary_dict(self) -> dict[str, Any]:
        return {
            "files_scanned": self.files_scanned,
            "files_reviewed": self.files_reviewed,
            "total_findings": self.total_findings,
            "critical": self.critical_count,
            "high": self.high_count,
            "avg_trust_score": round(self.average_trust_score, 1),
            "duration_seconds": round(self.duration_seconds, 1),
        }
